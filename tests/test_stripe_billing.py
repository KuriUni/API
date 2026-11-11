import hashlib
import hmac
import io
import os
import pathlib
import sys
import unittest
import urllib.error
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'xrea-source'))

import stripe_billing


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def read(self, size=-1):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _secret(value_map):
    def read(name):
        return value_map.get(name, '')
    return read


class CheckoutAmountTests(unittest.TestCase):
    def test_units_round_up_to_yen(self):
        cases = {1: 1, 499: 1, 500: 1, 501: 1, 1000: 1, 1001: 2, 1234567: 1235}
        for units, yen in cases.items():
            self.assertEqual(stripe_billing.checkout_amount_yen(units), yen)

    def test_invalid_amounts_are_rejected(self):
        for value in (0, -1, None, 'abc', True):
            with self.assertRaises(stripe_billing.StripeError):
                stripe_billing.checkout_amount_yen(value)


class WebhookSignatureTests(unittest.TestCase):
    payload = b'{"id":"evt_test_1","type":"checkout.session.completed"}'
    secret = 'whsec_test_secret'

    def _header(self, timestamp):
        signed = str(timestamp).encode('ascii') + b'.' + self.payload
        digest = hmac.new(self.secret.encode('utf-8'), signed, hashlib.sha256).hexdigest()
        return 't=%d,v1=%s' % (timestamp, digest)

    def test_valid_signature(self):
        timestamp = 1700000000
        self.assertTrue(stripe_billing.verify_webhook_signature(
            self.payload, self._header(timestamp), self.secret, now=timestamp))

    def test_multiple_v1_values_accept_a_match(self):
        timestamp = 1700000000
        header = 't=%d,v1=deadbeef,' % timestamp + 'v1=' + self._header(timestamp).split('v1=')[1]
        self.assertTrue(stripe_billing.verify_webhook_signature(
            self.payload, header, self.secret, now=timestamp))

    def test_stale_timestamp_is_rejected(self):
        timestamp = 1700000000
        self.assertFalse(stripe_billing.verify_webhook_signature(
            self.payload, self._header(timestamp), self.secret, now=timestamp + 301))

    def test_tampered_payload_is_rejected(self):
        timestamp = 1700000000
        self.assertFalse(stripe_billing.verify_webhook_signature(
            self.payload + b' ', self._header(timestamp), self.secret, now=timestamp))

    def test_missing_header_or_secret_is_rejected(self):
        self.assertFalse(stripe_billing.verify_webhook_signature(self.payload, '', self.secret))
        self.assertFalse(stripe_billing.verify_webhook_signature(self.payload, 't=1,v1=x', ''))
        self.assertFalse(stripe_billing.verify_webhook_signature(b'', 't=1,v1=x', self.secret))


class SettingsTests(unittest.TestCase):
    def test_test_key_enables_test_mode(self):
        with mock.patch.object(stripe_billing, 'secret_value', _secret({
                'stripe_secret_key': 'sk_test_abc', 'stripe_webhook_secret': 'whsec_abc'})):
            config = stripe_billing.settings()
            public = stripe_billing.public_settings()
        self.assertTrue(config['enabled'])
        self.assertEqual(config['mode'], 'test')
        self.assertTrue(public['test_mode'])

    def test_live_key_requires_explicit_enable_flag(self):
        secrets = _secret({'stripe_secret_key': 'sk_live_abc', 'stripe_webhook_secret': 'whsec_abc'})
        with mock.patch.object(stripe_billing, 'secret_value', secrets):
            with mock.patch.dict(os.environ, {'PYTHON_MIGRATION_STRIPE_ENABLE_LIVE': '0'}):
                config = stripe_billing.settings()
            self.assertEqual(config['mode'], 'live')
            self.assertFalse(config['enabled'])
            with mock.patch.dict(os.environ, {'PYTHON_MIGRATION_STRIPE_ENABLE_LIVE': '1'}):
                self.assertTrue(stripe_billing.settings()['enabled'])

    def test_webhook_secret_is_required(self):
        with mock.patch.object(stripe_billing, 'secret_value', _secret({
                'stripe_secret_key': 'sk_test_abc'})):
            self.assertFalse(stripe_billing.settings()['enabled'])

    def test_live_can_be_enabled_from_runtime_secret(self):
        secrets = _secret({'stripe_secret_key': 'sk_live_abc', 'stripe_webhook_secret': 'whsec_abc',
                           'stripe_enable_live': '1'})
        with mock.patch.object(stripe_billing, 'secret_value', secrets),                 mock.patch.dict(os.environ, {'PYTHON_MIGRATION_STRIPE_ENABLE_LIVE': ''}):
            config = stripe_billing.settings()
        self.assertTrue(config['enabled'])

    def test_public_settings_hide_keys(self):
        with mock.patch.object(stripe_billing, 'secret_value', _secret({
                'stripe_secret_key': 'sk_test_abc', 'stripe_webhook_secret': 'whsec_abc'})):
            public = stripe_billing.public_settings()
        self.assertNotIn('secret_key', public)
        self.assertNotIn('webhook_secret', public)


class StripeApiTests(unittest.TestCase):
    def test_form_body_and_idempotency_are_sent(self):
        captured = {}

        def fake_urlopen(request, timeout=None, context=None):
            captured['url'] = request.full_url
            captured['headers'] = {key.lower(): value for key, value in request.header_items()}
            captured['body'] = request.data
            return FakeResponse(b'{"id":"cs_test_1","url":"https://checkout.stripe.com/c/pay/1"}')

        with mock.patch.object(stripe_billing, 'urlopen', fake_urlopen):
            result = stripe_billing._api(
                'POST', 'checkout/sessions',
                {'mode': 'payment', 'line_items[0][price_data][unit_amount]': '500'},
                config={'secret_key': 'sk_test_abc'}, idempotency_key='tuti-1')

        self.assertEqual(result['id'], 'cs_test_1')
        self.assertEqual(captured['url'], 'https://api.stripe.com/v1/checkout/sessions')
        self.assertEqual(captured['headers']['authorization'], 'Bearer sk_test_abc')
        self.assertEqual(captured['headers']['idempotency-key'], 'tuti-1')
        self.assertIn(b'mode=payment', captured['body'])
        self.assertIn(b'unit_amount%5D=500', captured['body'])

    def test_http_error_is_mapped(self):
        def fake_urlopen(request, timeout=None, context=None):
            raise urllib.error.HTTPError(request.full_url, 402, 'card declined', {}, io.BytesIO(b'{"error":{"code":"card_declined"}}'))

        with mock.patch.object(stripe_billing, 'urlopen', fake_urlopen):
            with self.assertRaises(stripe_billing.StripeError) as caught:
                stripe_billing._api('POST', 'checkout/sessions', {'mode': 'payment'},
                                    config={'secret_key': 'sk_test_abc'})
        self.assertIn('stripe_api_error', str(caught.exception))

    def test_network_error_is_mapped(self):
        def fake_urlopen(request, timeout=None, context=None):
            raise urllib.error.URLError('dns failure')

        with mock.patch.object(stripe_billing, 'urlopen', fake_urlopen):
            with self.assertRaises(stripe_billing.StripeError) as caught:
                stripe_billing._api('GET', 'checkout/sessions/cs_1', config={'secret_key': 'sk_test_abc'})
        self.assertIn('stripe_unreachable', str(caught.exception))

    def test_redirect_base_url_ignores_untrusted_request_host(self):
        with mock.patch.dict(os.environ, {'PYTHON_MIGRATION_STRIPE_RETURN_BASE_URL': ''}), \
                mock.patch.object(stripe_billing, 'secret_value', _secret({})):
            expected = 'https://2415.jp' + stripe_billing.site_url('/license/python-migration')
            for context in (
                {'header:host': '2415.jp', 'https': 'on'},
                {'header:host': 'evil.example', 'https': 'on'},
                {'header:host': '2415.jp.evil.example', 'https': 'on'},
                {'header:host': 'evil.example:443', 'https': 'on'},
                {'server_name': 'evil.example'},
            ):
                self.assertEqual(stripe_billing._portal_base(context), expected)

    def test_runtime_secret_return_base_url_is_used(self):
        with mock.patch.object(stripe_billing, 'secret_value',
                               _secret({'stripe_return_base_url': 'https://2415.jp/license'})):
            self.assertEqual(stripe_billing._portal_base({'header:host': 'localhost'}),
                             'https://2415.jp/license')

    def test_insecure_return_base_url_is_rejected(self):
        with mock.patch.object(stripe_billing, 'secret_value',
                               _secret({'stripe_return_base_url': 'http://evil.example/license'})):
            with self.assertRaises(stripe_billing.StripeError):
                stripe_billing._portal_base({'header:host': '2415.jp'})

    def test_explicit_return_base_url_wins(self):
        with mock.patch.dict(os.environ, {'PYTHON_MIGRATION_STRIPE_RETURN_BASE_URL': 'https://2415.jp/license/'}):
            self.assertEqual(stripe_billing._portal_base({'header:host': 'localhost'}),
                             'https://2415.jp/license')


if __name__ == '__main__':
    unittest.main()


class StripeSecurityRegressionTests(unittest.TestCase):
    def test_api_error_does_not_expose_stripe_response_body(self):
        secret_detail = 'customer@example.invalid sensitive-response-detail'

        def fake_urlopen(request, timeout=None, context=None):
            body = ('{"error":{"message":"' + secret_detail + '"}}').encode()
            raise urllib.error.HTTPError(request.full_url, 402, 'payment failed', {}, io.BytesIO(body))

        with mock.patch.object(stripe_billing, 'urlopen', fake_urlopen):
            with self.assertRaises(stripe_billing.StripeError) as caught:
                stripe_billing._api('POST', 'checkout/sessions', {'mode': 'payment'},
                                    config={'secret_key': 'sk_test_abc'})
        self.assertEqual(str(caught.exception), 'stripe_api_error:402')
        self.assertNotIn(secret_detail, str(caught.exception))

    def test_webhook_event_record_uses_atomic_upsert(self):
        connection = FakeConnection([])
        stripe_billing._record_event(connection, 'evt_test_12345678',
                                     'checkout.session.completed', 'test',
                                     'processed', 'paid', 11, 42, True)
        sql = connection.statements[-1][0].upper()
        self.assertIn('INSERT INTO STRIPE_WEBHOOK_EVENTS', sql)
        self.assertIn('ON DUPLICATE KEY UPDATE', sql)
        self.assertNotIn('SELECT EVENT_ID', sql)

    def test_expired_payment_cannot_be_completed_by_late_webhook(self):
        expired = dict(CompletePaymentTests.payment, status='expired')
        connection = FakeConnection([
            ('FROM api_billing_invoices WHERE id', [{'id': 11, 'status': 'issued',
                                                     'account_tenant_id': 7}]),
            ('FROM stripe_invoice_payments WHERE id', [expired]),
        ])
        with mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}):
            result = stripe_billing._complete_payment(
                connection, expired, CompletePaymentTests.session, {})
        self.assertEqual(result, 'payment_not_open')
        self.assertFalse([sql for sql, _ in connection.statements
                          if 'api_billing_invoices SET status' in sql])

    def test_mismatched_checkout_session_cannot_settle_payment(self):
        payment = dict(CompletePaymentTests.payment)
        session = dict(CompletePaymentTests.session, id='cs_attacker_controlled')
        connection = FakeConnection([
            ('FROM api_billing_invoices WHERE id', [{'id': 11, 'status': 'issued',
                                                     'account_tenant_id': 7}]),
            ('FROM stripe_invoice_payments WHERE id', [payment]),
        ])
        with mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}):
            with self.assertRaises(stripe_billing.StripeError) as caught:
                stripe_billing._complete_payment(connection, payment, session, {})
        self.assertEqual(str(caught.exception), 'stripe_session_mismatch')
        self.assertFalse([sql for sql, _ in connection.statements
                          if 'api_billing_invoices SET status' in sql])

    def test_checkout_does_not_create_second_session_while_first_is_initializing(self):
        connection = FakeConnection([
            ('FROM api_billing_invoices', [{'id': 11, 'invoice_number': 'API-202611-000007',
                                            'account_tenant_id': 7, 'total_units': 500500,
                                            'status': 'issued'}]),
            ('FROM stripe_invoice_payments WHERE invoice_id', [{
                'id': 41, 'invoice_id': 11, 'account_tenant_id': 7, 'payer_tenant_id': 7,
                'amount_yen': 501, 'mode': 'test', 'status': 'creating',
                'checkout_session_id': None, 'expires_at': None,
            }]),
        ])
        config = {'enabled': True, 'mode': 'test', 'secret_key': 'sk_test_x',
                  'webhook_secret': 'whsec_x'}
        with mock.patch.object(stripe_billing, 'settings', return_value=config), \
                mock.patch.object(stripe_billing, 'ensure_schema'), \
                mock.patch.object(stripe_billing, '_api') as api_mock, \
                mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}):
            with self.assertRaises(stripe_billing.StripeError) as caught:
                stripe_billing.create_checkout(
                    connection, CreateCheckoutTests()._client(), {'invoice_id': '11'},
                    {'header:host': '2415.jp', 'https': 'on'})
        self.assertEqual(str(caught.exception), 'stripe_checkout_initializing')
        api_mock.assert_not_called()
        self.assertFalse([sql for sql, _ in connection.statements
                          if sql.startswith('INSERT INTO stripe_invoice_payments')])


class FakeCursor:
    def __init__(self, owner):
        self.owner = owner
        self._rows = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=()):
        self.owner.statements.append((sql, tuple(params)))
        for marker, rows in self.owner.responses:
            if marker in sql:
                self._rows = list(rows)
                return
        self._rows = []
        if sql.lstrip().upper().startswith('UPDATE'):
            self.rowcount = 1
        return

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class FakeConnection:
    def __init__(self, responses):
        self.responses = responses
        self.statements = []
        self.committed = 0
        self._insert_id = 42

    def cursor(self):
        return FakeCursor(self)

    def begin(self):
        pass

    def commit(self):
        self.committed += 1

    def rollback(self):
        pass

    def insert_id(self):
        return self._insert_id


class CreateCheckoutTests(unittest.TestCase):
    def _client(self, environment='production'):
        return {'key_kind': 'tenant_sso', 'tenant_sso_session_id': 'x' * 43, 'tenant_id': 7,
                'parent_tenant_id': None, 'tenant_environment': environment}

    def _run(self, responses, environment='production', api_result=None):
        connection = FakeConnection(responses)
        config = {'enabled': True, 'mode': 'test', 'secret_key': 'sk_test_x', 'webhook_secret': 'whsec_x'}
        result = api_result or {'id': 'cs_test_1', 'url': 'https://checkout.stripe.com/c/pay/1', 'expires_at': 1900000000}
        with mock.patch.object(stripe_billing, 'settings', return_value=config), \
                mock.patch.object(stripe_billing, 'ensure_schema'), \
                mock.patch.object(stripe_billing, '_api', return_value=result), \
                mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}):
            created = stripe_billing.create_checkout(connection, self._client(environment), {'invoice_id': '11'},
                                                     {'header:host': '2415.jp', 'https': 'on'})
        return connection, created

    def test_creates_checkout_session_and_records_payment(self):
        connection, created = self._run([
            ('FROM api_billing_invoices', [{'id': 11, 'invoice_number': 'API-202611-000007', 'account_tenant_id': 7,
                                            'total_units': 500500, 'status': 'issued'}]),
            ('FROM stripe_invoice_payments WHERE invoice_id', []),
        ])
        self.assertEqual(created['checkout_url'], 'https://checkout.stripe.com/c/pay/1')
        self.assertEqual(created['amount_yen'], 501)
        self.assertFalse(created['reused'])
        insert = [params for sql, params in connection.statements if sql.startswith('INSERT INTO stripe_invoice_payments')]
        self.assertEqual(insert[0][:4], (11, 7, 7, 501))
        update = [params for sql, params in connection.statements if 'SET checkout_session_id' in sql]
        self.assertEqual(update[0][3], 42)

    def test_live_mode_is_blocked_for_sandbox_tenant(self):
        connection = FakeConnection([])
        config = {'enabled': True, 'mode': 'live', 'secret_key': 'sk_live_x', 'webhook_secret': 'whsec_x'}
        with mock.patch.object(stripe_billing, 'settings', return_value=config), \
                mock.patch.object(stripe_billing, 'ensure_schema'), \
                mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}):
            with self.assertRaises(stripe_billing.StripeError) as caught:
                stripe_billing.create_checkout(connection, self._client('sandbox'), {'invoice_id': '11'},
                                               {'header:host': '2415.jp'})
        self.assertEqual(str(caught.exception), 'stripe_live_sandbox_blocked')

    def test_invoice_of_another_account_is_rejected(self):
        with self.assertRaises(stripe_billing.StripeError) as caught:
            self._run([
                ('FROM api_billing_invoices', [{'id': 11, 'account_tenant_id': 99, 'total_units': 500500, 'status': 'issued'}]),
            ])
        self.assertEqual(str(caught.exception), 'invoice_not_found')


class CompletePaymentTests(unittest.TestCase):
    payment = {'id': 42, 'invoice_id': 11, 'account_tenant_id': 7, 'amount_yen': 501, 'status': 'open', 'mode': 'test', 'checkout_session_id': 'cs_test_1'}
    session = {'id': 'cs_test_1', 'payment_intent': 'pi_test_1', 'amount_total': 501, 'currency': 'jpy', 'payment_status': 'paid'}

    def test_completing_marks_invoice_paid(self):
        connection = FakeConnection([
            ('FROM api_billing_invoices WHERE id', [{'id': 11, 'status': 'issued', 'account_tenant_id': 7}]),
            ('FROM stripe_invoice_payments WHERE id', [self.payment]),
        ])
        with mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}):
            self.assertEqual(stripe_billing._complete_payment(connection, self.payment, self.session, {}), 'paid')
        updates = [sql for sql, _ in connection.statements if sql.startswith('UPDATE')]
        self.assertTrue(any('api_billing_invoices SET status' in sql for sql in updates))
        self.assertTrue(any('status=\'completed\'' in sql for sql in updates))

    def test_completed_payment_is_not_counted_twice(self):
        already = dict(self.payment, status='completed')
        connection = FakeConnection([
            ('FROM api_billing_invoices WHERE id', [{'id': 11, 'status': 'issued', 'account_tenant_id': 7}]),
            ('FROM stripe_invoice_payments WHERE id', [already]),
        ])
        with mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}):
            self.assertEqual(stripe_billing._complete_payment(connection, already, self.session, {}), 'already_completed')
        self.assertFalse([sql for sql, _ in connection.statements if 'api_billing_invoices SET status' in sql])

    def test_voided_invoice_is_not_paid(self):
        connection = FakeConnection([
            ('FROM api_billing_invoices WHERE id', [{'id': 11, 'status': 'void', 'account_tenant_id': 7}]),
            ('FROM stripe_invoice_payments WHERE id', [self.payment]),
        ])
        with mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}):
            self.assertEqual(stripe_billing._complete_payment(connection, self.payment, self.session, {}), 'invoice_not_issued')
        self.assertFalse([sql for sql, _ in connection.statements if 'api_billing_invoices SET status' in sql])


class KeyReissueCheckoutTests(unittest.TestCase):
    def _client(self):
        return {'key_kind': 'tenant_sso', 'tenant_sso_session_id': 'x' * 43, 'tenant_id': 7,
                'parent_tenant_id': None, 'tenant_environment': 'production',
                'sso_subject_hash': 'a' * 64, 'sso_oidc_sid': 'sid'}

    def test_creates_500_yen_checkout_for_reissue(self):
        connection = FakeConnection([
            ('FROM tenants WHERE id IN', [{'id': 7}]),
            ('FROM stripe_key_reissue_payments WHERE tenant_id', []),
            ('FROM tenant_sso_memberships', [{'source_client_id': 3, 'scopes_json': '["tenant:read","products:write"]'}]),
            ('FROM tenant_api_clients WHERE id', [{'id': 3, 'tenant_id': 7, 'name': 'key', 'status': 'active',
                                                   'key_kind': 'standard', 'scopes_json': '["tenant:read","products:write"]',
                                                   'rate_limit_per_minute': 100, 'expires_at': None}]),
        ])
        config = {'enabled': True, 'mode': 'test', 'secret_key': 'sk_test_x', 'webhook_secret': 'whsec_x'}
        session = {'id': 'cs_test_9', 'url': 'https://checkout.stripe.com/c/pay/9', 'expires_at': 1900000000}
        with mock.patch.object(stripe_billing, 'settings', return_value=config), \
                mock.patch.object(stripe_billing, 'ensure_schema'), \
                mock.patch.object(stripe_billing, '_api', return_value=session) as api_mock, \
                mock.patch.object(stripe_billing, 'session_status', return_value={'auth_time': 1700000000}, create=True), \
                mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}), \
                mock.patch('admin_oidc.session_status', return_value={'auth_time': int(__import__('time').time())}):
            result = stripe_billing.create_key_reissue_checkout(
                connection, self._client(), {'confirm_fee_yen': 500},
                {'header:host': '2415.jp', 'https': 'on', 'header:idempotency-key': 'A' * 40})
        self.assertEqual(result['checkout_url'], 'https://checkout.stripe.com/c/pay/9')
        params = api_mock.call_args[0][2]
        self.assertEqual(params['line_items[0][price_data][unit_amount]'], '500')
        self.assertEqual(params['metadata[kind]'], 'key_reissue')
        self.assertEqual(params['metadata[tenant_id]'], '7')
        self.assertIn('#sso_ticket=', params['success_url'])
        self.assertIn('stripe=success', params['success_url'])
        self.assertTrue(any(sql.startswith('INSERT INTO tenant_sso_bootstrap_tickets') for sql, _ in connection.statements))

    def test_wrong_fee_is_rejected(self):
        config = {'enabled': True, 'mode': 'test', 'secret_key': 'sk_test_x', 'webhook_secret': 'whsec_x'}
        with mock.patch.object(stripe_billing, 'settings', return_value=config),                 mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}),                 mock.patch('admin_oidc.session_status', return_value={'auth_time': int(__import__('time').time())}):
            with self.assertRaises(stripe_billing.StripeError) as caught:
                stripe_billing.create_key_reissue_checkout(
                    FakeConnection([]), self._client(), {'confirm_fee_yen': 499},
                    {'header:host': '2415.jp', 'header:idempotency-key': 'A' * 40})
        self.assertEqual(str(caught.exception), 'key_reissue_fee_confirmation_required')

    def test_result_returns_deterministic_key(self):
        from datetime import datetime, timezone
        request = 'B' * 40
        request_hash = stripe_billing._key_reissue_hash('a' * 64, request)
        row = {'id': 5, 'tenant_id': 7, 'passkey_id': 0, 'request_hash': request_hash,
               'environment': 'production', 'status': 'issued', 'mode': 'test',
               'scopes_json': '["tenant:read"]', 'grace_expires_at': '2026-11-10 23:00:00',
               'completed_at': datetime.now(timezone.utc).replace(tzinfo=None)}
        connection = FakeConnection([('FROM stripe_key_reissue_payments WHERE tenant_id', [row])])
        with mock.patch.object(stripe_billing, 'ensure_schema'), \
                mock.patch('portal_key_policy.secret_value', _secret({'token_secret': 's' * 32})):
            result = stripe_billing.key_reissue_result(
                connection, self._client(), {'request_id': request}, {'method': 'POST'})
        self.assertEqual(result['fee_yen'], 500)
        self.assertTrue(result['paid_immediately'])
        self.assertEqual(len(result['api_key']), 53)
        self.assertTrue(result['api_key'].startswith('baas_prod_'))

    def test_pending_result_is_reported(self):
        request = 'C' * 40
        request_hash = stripe_billing._key_reissue_hash('a' * 64, request)
        row = {'id': 6, 'tenant_id': 7, 'status': 'pending', 'request_hash': request_hash}
        with mock.patch.object(stripe_billing, 'ensure_schema'):
            with self.assertRaises(stripe_billing.StripeError) as caught:
                stripe_billing.key_reissue_result(FakeConnection([
                    ('FROM stripe_key_reissue_payments WHERE tenant_id', [row])]),
                    self._client(), {'request_id': request}, {'method': 'POST'})
        self.assertEqual(str(caught.exception), 'key_reissue_pending')


class ReconcileReissueTests(unittest.TestCase):
    def test_paid_session_is_reconciled_without_webhook(self):
        row = {'id': 3, 'tenant_id': 7, 'checkout_session_id': 'cs_test_1', 'amount_yen': 500,
               'status': 'pending', 'mode': 'test', 'source_client_id': 5, 'environment': 'production',
               'request_hash': 'a' * 64, 'scopes_json': '["tenant:read"]'}
        connection = FakeConnection([
            ('UPDATE stripe_key_reissue_payments', []),
            ('SELECT * FROM stripe_key_reissue_payments WHERE id', [dict(row, status='issued')]),
        ])
        session = {'id': 'cs_test_1', 'status': 'complete', 'payment_status': 'paid',
                   'amount_total': 500, 'currency': 'jpy', 'payment_intent': 'pi_test_1'}
        with mock.patch.object(stripe_billing, '_api', return_value=session), \
                mock.patch.object(stripe_billing, '_issue_key_reissue', return_value='issued') as issue:
            refreshed = stripe_billing._reconcile_key_reissue(connection, row, {'enabled': True})
        self.assertEqual(refreshed['status'], 'issued')
        issue.assert_called_once()
        updates = [sql for sql, _ in connection.statements if sql.startswith('UPDATE')]
        self.assertTrue(any("status='paid'" in sql for sql in updates))

    def test_open_session_stays_pending(self):
        row = {'id': 4, 'amount_yen': 500, 'checkout_session_id': 'cs_test_2', 'status': 'pending'}
        connection = FakeConnection([('SELECT * FROM stripe_key_reissue_payments WHERE id', [row])])
        with mock.patch.object(stripe_billing, '_api', return_value={'id': 'cs_test_2', 'status': 'open'}):
            refreshed = stripe_billing._reconcile_key_reissue(connection, row, {'enabled': True})
        self.assertEqual(refreshed['status'], 'pending')


class KeyReissuePaymentGateTests(unittest.TestCase):
    def test_pending_checkout_cannot_issue_replacement_key(self):
        pending = {'id': 9, 'tenant_id': 7, 'source_client_id': 3,
                   'environment': 'production', 'status': 'pending'}
        connection = FakeConnection([
            ('SELECT id,status FROM tenants WHERE id', [{'id': 7, 'status': 'active'}]),
            ('SELECT * FROM stripe_key_reissue_payments WHERE id', [pending]),
        ])
        with mock.patch.dict(sys.modules, {'v3_handlers': mock.MagicMock()}):
            result = stripe_billing._issue_key_reissue(
                connection, pending, {'payment_intent': 'pi_unpaid'}, {})
        self.assertEqual(result, 'ignored')
        self.assertFalse([sql for sql, _ in connection.statements
                          if sql.startswith('INSERT INTO tenant_api_clients')])
