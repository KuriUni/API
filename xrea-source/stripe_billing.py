"""Stripe Checkout payments for issued BaaS invoices.

The first target is a sandbox / test-mode end-to-end billing test: a tenant
opens the portal with an SSO session, starts a Stripe Checkout Session for an
issued invoice, and the signed Stripe webhook marks the invoice paid.

No third-party SDK is used: the Stripe REST API is called with urllib and the
webhook signature is verified with hmac/hashlib, matching this deployment's
stdlib-only runtime.
"""
from native_http import legacy_compatible
import hashlib
import hmac
import json
import os
import re
import secrets
import ssl
import time
import urllib.error
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen
from datetime import datetime, timedelta, timezone
import database
from deployment_settings import site_url
from http_utils import json_response, read_bounded_body
from migration_config import secret_value

STRIPE_API_BASE = 'https://api.stripe.com/v1/'
SIGNATURE_TOLERANCE_SECONDS = 300
MAX_WEBHOOK_BYTES = 65536
MIN_CHECKOUT_YEN = 50
CHECKOUT_TTL_MINUTES = 30
KEY_REISSUE_YEN = 500
KEY_REISSUE_RESULT_MINUTES = 10
KEY_REISSUE_GRACE_HOURS = 1


class StripeError(RuntimeError):
    """Raised for handled payment failures mapped to a public error code."""


def _now():
    return datetime.now(timezone.utc)


def _utc_text(value):
    return value.strftime('%Y-%m-%d %H:%M:%S') if isinstance(value, datetime) else str(value or '')


def settings():
    """Resolve Stripe configuration without exposing key material."""
    secret_key = str(secret_value('stripe_secret_key') or '').strip()
    webhook_secret = str(secret_value('stripe_webhook_secret') or '').strip()
    mode = ''
    if secret_key.startswith('sk_test_'):
        mode = 'test'
    elif secret_key.startswith('sk_live_'):
        mode = 'live'
    live_enabled = (str(os.environ.get('PYTHON_MIGRATION_STRIPE_ENABLE_LIVE', '')) == '1'
                    or str(secret_value('stripe_enable_live') or '').strip() == '1')
    enabled = bool(secret_key and webhook_secret and mode and (mode == 'test' or live_enabled))
    return {'enabled': enabled, 'mode': mode, 'live_enabled': live_enabled,
            'secret_key': secret_key, 'webhook_secret': webhook_secret}


def public_settings():
    """Strip secrets so callers can expose the state to the portal."""
    config = settings()
    return {'configured': bool(config['secret_key'] and config['webhook_secret']),
            'enabled': config['enabled'], 'mode': config['mode'],
            'test_mode': config['mode'] == 'test'}


def ensure_schema(connection):
    """Create the payment tables; they stay outside the schema 039 plan."""
    with connection.cursor() as cursor:
        cursor.execute("""CREATE TABLE IF NOT EXISTS stripe_invoice_payments (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            invoice_id BIGINT UNSIGNED NOT NULL,
            account_tenant_id BIGINT UNSIGNED NOT NULL,
            payer_tenant_id BIGINT UNSIGNED NOT NULL,
            checkout_session_id VARCHAR(120) NULL DEFAULT NULL,
            payment_intent_id VARCHAR(120) NULL DEFAULT NULL,
            amount_yen INT UNSIGNED NOT NULL,
            currency CHAR(3) NOT NULL DEFAULT 'jpy',
            mode VARCHAR(8) NOT NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'creating',
            checkout_url VARCHAR(512) NOT NULL DEFAULT '',
            expires_at DATETIME NULL DEFAULT NULL,
            completed_at DATETIME NULL DEFAULT NULL,
            failure_code VARCHAR(64) NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_stripe_checkout_session (checkout_session_id),
            KEY idx_stripe_payment_invoice (invoice_id, status),
            KEY idx_stripe_payment_account (account_tenant_id, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS stripe_webhook_events (
            event_id VARCHAR(120) NOT NULL,
            event_type VARCHAR(80) NOT NULL,
            mode VARCHAR(8) NOT NULL DEFAULT '',
            status VARCHAR(16) NOT NULL DEFAULT 'received',
            invoice_id BIGINT UNSIGNED NULL DEFAULT NULL,
            payment_id BIGINT UNSIGNED NULL DEFAULT NULL,
            message VARCHAR(255) NOT NULL DEFAULT '',
            received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            processed_at DATETIME NULL DEFAULT NULL,
            PRIMARY KEY (event_id),
            KEY idx_stripe_event_status (status, received_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS stripe_billing_key_suspensions (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            invoice_id BIGINT UNSIGNED NOT NULL,
            tenant_id BIGINT UNSIGNED NOT NULL,
            client_id BIGINT UNSIGNED NOT NULL,
            previous_status VARCHAR(16) NOT NULL DEFAULT 'active',
            suspended_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            restored_at DATETIME NULL DEFAULT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY uq_stripe_billing_suspension (invoice_id, client_id),
            KEY idx_stripe_billing_suspension_client (client_id, restored_at),
            KEY idx_stripe_billing_suspension_invoice (invoice_id, restored_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""")
        cursor.execute("SHOW COLUMNS FROM stripe_billing_key_suspensions LIKE 'previous_status'")
        if not cursor.fetchone():
            cursor.execute("ALTER TABLE stripe_billing_key_suspensions ADD COLUMN previous_status VARCHAR(16) NOT NULL DEFAULT 'active' AFTER client_id")
        cursor.execute("""CREATE TABLE IF NOT EXISTS stripe_key_reissue_payments (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            tenant_id BIGINT UNSIGNED NOT NULL,
            account_tenant_id BIGINT UNSIGNED NOT NULL,
            payer_tenant_id BIGINT UNSIGNED NOT NULL,
            passkey_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
            request_hash CHAR(64) NOT NULL,
            source_client_id BIGINT UNSIGNED NOT NULL,
            scopes_json LONGTEXT NOT NULL,
            environment VARCHAR(16) NOT NULL,
            mode VARCHAR(8) NOT NULL,
            amount_yen INT UNSIGNED NOT NULL,
            currency CHAR(3) NOT NULL DEFAULT 'jpy',
            checkout_session_id VARCHAR(120) NULL DEFAULT NULL,
            payment_intent_id VARCHAR(120) NULL DEFAULT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'creating',
            new_client_id BIGINT UNSIGNED NULL DEFAULT NULL,
            checkout_url VARCHAR(512) NOT NULL DEFAULT '',
            grace_expires_at DATETIME NULL DEFAULT NULL,
            expires_at DATETIME NULL DEFAULT NULL,
            completed_at DATETIME NULL DEFAULT NULL,
            failure_code VARCHAR(64) NOT NULL DEFAULT '',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_key_reissue_session (checkout_session_id),
            KEY idx_key_reissue_request (tenant_id, request_hash),
            KEY idx_key_reissue_status (status, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""")
    connection.commit()


def checkout_amount_yen(total_units):
    """Convert invoice units (0.001 JPY) to an integer JPY Stripe amount."""
    if isinstance(total_units, bool):
        raise StripeError('invoice_amount_invalid')
    try:
        units = int(total_units)
    except (TypeError, ValueError):
        raise StripeError('invoice_amount_invalid')
    if units <= 0:
        raise StripeError('invoice_amount_invalid')
    return (units + 999) // 1000


def verify_webhook_signature(payload, header, secret, tolerance=SIGNATURE_TOLERANCE_SECONDS, now=None):
    """Verify a Stripe-Signature header against the raw request body."""
    if not isinstance(payload, bytes) or not secret or not header:
        return False
    timestamp = ''
    signatures = []
    for item in str(header).split(','):
        name, _, value = item.strip().partition('=')
        if name == 't':
            timestamp = value
        elif name == 'v1' and value:
            signatures.append(value)
    if not re.fullmatch(r'[0-9]{1,12}', timestamp) or not signatures:
        return False
    current = int(now) if now is not None else int(time.time())
    if abs(current - int(timestamp)) > int(tolerance):
        return False
    signed = timestamp.encode('ascii') + b'.' + payload
    expected = hmac.new(str(secret).encode('utf-8'), signed, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(expected, value) for value in signatures)


def _api(method, path, params=None, config=None, idempotency_key=''):
    config = config or settings()
    if not config.get('secret_key'):
        raise StripeError('stripe_not_configured')
    body = urlencode(params, doseq=True).encode('utf-8') if params is not None else None
    headers = {'Authorization': 'Bearer ' + config['secret_key'], 'Accept': 'application/json'}
    if body is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    if idempotency_key:
        headers['Idempotency-Key'] = idempotency_key
    request = Request(STRIPE_API_BASE + path, data=body, headers=headers, method=method)
    try:
        with urlopen(request, timeout=20, context=ssl.create_default_context()) as response:
            raw = response.read(1024 * 1024 + 1)
    except urllib.error.HTTPError as exc:
        detail = ''
        try:
            detail = str(exc.read(4096).decode('utf-8', 'replace'))
        except Exception:
            detail = ''
        raise StripeError('stripe_api_error:' + str(getattr(exc, 'code', '')) + ':' + detail[:200])
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise StripeError('stripe_unreachable:' + str(exc)[:120])
    if len(raw) > 1024 * 1024:
        raise StripeError('stripe_response_too_large')
    try:
        result = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        raise StripeError('stripe_response_invalid')
    if not isinstance(result, dict):
        raise StripeError('stripe_response_invalid')
    return result


def _return_base():
    explicit = (str(os.environ.get('PYTHON_MIGRATION_STRIPE_RETURN_BASE_URL', '')).strip()
                or str(secret_value('stripe_return_base_url') or '').strip())
    if not explicit:
        return ''
    parsed = urlsplit(explicit)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        if not (parsed.scheme == 'http' and parsed.hostname in ('localhost', '127.0.0.1', '::1')):
            raise StripeError('stripe_return_base_url_invalid')
    return explicit.rstrip('/')


def _portal_base(request_context):
    """Return a trusted, configured portal URL; never derive it from Host.

    Host and forwarded-host headers are attacker-controlled unless a trusted
    proxy validates them. Stripe redirect URLs must therefore use an explicit
    HTTPS base URL or the canonical production origin.
    """
    explicit = _return_base()
    if explicit:
        return explicit
    return 'https://2415.jp' + site_url('/license/python-migration')


def _payment_row(row):
    return dict(row) if row else None


def _open_payment(connection, invoice_id):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM stripe_invoice_payments WHERE invoice_id=%s AND status IN ('creating','open') ORDER BY id DESC LIMIT 1", (int(invoice_id),))
        return _payment_row(cursor.fetchone())


def _expired(row):
    expires = row.get('expires_at') if row else None
    if not isinstance(expires, datetime):
        return False
    return expires.replace(tzinfo=timezone.utc) <= _now()


@legacy_compatible(callback_index=None, request_index=0)
def create_checkout(connection, client, data, request_context):
    """Create a Stripe-hosted invoice without collecting or sending an email address."""
    from v3_handlers import _assert_write_fence
    config = settings()
    if not config['enabled']:
        raise StripeError('stripe_not_configured')
    if str(client.get('key_kind') or '') != 'tenant_sso' or not client.get('tenant_sso_session_id'):
        raise StripeError('tenant_sso_session_required')
    raw_invoice = data.get('invoice_id')
    if isinstance(raw_invoice, bool) or not str(raw_invoice).isdigit():
        raise StripeError('invalid_invoice')
    invoice_id = int(raw_invoice)
    if invoice_id < 1:
        raise StripeError('invalid_invoice')
    tenant_id = int(client['tenant_id'])
    account_id = int(client.get('parent_tenant_id') or tenant_id)
    environment = str(client.get('tenant_environment') or '')
    if config['mode'] == 'live' and environment != 'production':
        raise StripeError('stripe_live_sandbox_blocked')
    _assert_write_fence(connection)
    ensure_schema(connection)
    with connection.cursor() as cursor:
        cursor.execute('SELECT id,invoice_number,account_tenant_id,total_units,status,due_date FROM api_billing_invoices WHERE id=%s LIMIT 1', (invoice_id,))
        invoice = cursor.fetchone()
    if not invoice or int(invoice.get('account_tenant_id') or 0) != account_id:
        raise StripeError('invoice_not_found')
    if str(invoice.get('status')) != 'issued':
        raise StripeError('invoice_not_payable')
    amount_yen = checkout_amount_yen(invoice.get('total_units'))
    if amount_yen < MIN_CHECKOUT_YEN:
        raise StripeError('invoice_amount_too_small')

    existing = _open_payment(connection, invoice_id)
    payment_id = None
    if existing:
        if str(existing.get('mode') or '') != config['mode']:
            raise StripeError('stripe_mode_mismatch')
        if int(existing.get('amount_yen') or 0) != amount_yen:
            raise StripeError('invoice_amount_changed')
        payment_id = int(existing['id'])
        stripe_invoice_id = str(existing.get('checkout_session_id') or '')
        if stripe_invoice_id:
            # Never create a replacement invoice when Stripe cannot be reached:
            # the previous request may have succeeded before the connection failed.
            try:
                remote = _api('GET', 'invoices/' + stripe_invoice_id, config=config)
            except StripeError:
                raise StripeError('stripe_invoice_status_unavailable')
            remote_status = str(remote.get('status') or '')
            if remote_status == 'paid':
                raise StripeError('stripe_invoice_paid_pending_webhook')
            if remote_status == 'open' and remote.get('hosted_invoice_url'):
                url = str(remote['hosted_invoice_url'])
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE stripe_invoice_payments SET checkout_url=%s,updated_at=UTC_TIMESTAMP() WHERE id=%s', (url[:512], payment_id))
                connection.commit()
                return {'ok': True, 'checkout_url': url, 'payment_id': payment_id,
                        'invoice_id': invoice_id, 'amount_yen': int(existing['amount_yen']),
                        'mode': config['mode'], 'expires_at_utc': _utc_text(existing.get('expires_at')), 'reused': True}
            if remote_status in ('void', 'uncollectible'):
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE stripe_invoice_payments SET status='expired',updated_at=UTC_TIMESTAMP() WHERE id=%s AND status IN ('creating','open')", (payment_id,))
                connection.commit()
                payment_id = None
            elif remote_status not in ('draft',):
                raise StripeError('stripe_invoice_status_unavailable')
        # A 'creating' row without a remote ID is an interrupted operation.
        # Reuse its primary key so all Stripe requests retain their idempotency keys.

    if payment_id is None:
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO stripe_invoice_payments(invoice_id,account_tenant_id,payer_tenant_id,amount_yen,currency,mode,status) VALUES(%s,%s,%s,%s,%s,%s,%s)', (invoice_id, account_id, tenant_id, amount_yen, 'jpy', config['mode'], 'creating'))
            payment_id = int(connection.insert_id())
        connection.commit()

    try:
        # Deliberately omit email, phone, address, and customer shipping details.
        customer = _api('POST', 'customers', {
            'metadata[account_tenant_id]': str(account_id),
            'metadata[privacy_profile]': 'no_email',
        }, config=config, idempotency_key='tuti-invoice-customer-%d' % payment_id)
        customer_id = str(customer.get('id') or '')
        if not re.fullmatch(r'cus_[A-Za-z0-9]+', customer_id):
            raise StripeError('stripe_response_invalid')

        _api('POST', 'invoiceitems', {
            'customer': customer_id,
            'amount': str(amount_yen),
            'currency': 'jpy',
            'description': ('TUTI BaaS 請求書 ' + str(invoice.get('invoice_number') or invoice_id))[:250],
            'metadata[invoice_id]': str(invoice_id),
            'metadata[payment_id]': str(payment_id),
            'metadata[account_tenant_id]': str(account_id),
        }, config=config, idempotency_key='tuti-invoice-item-%d' % payment_id)

        due = invoice.get('due_date')
        if isinstance(due, datetime):
            due_timestamp = int(due.replace(tzinfo=timezone.utc).timestamp())
        else:
            try:
                due_timestamp = int(datetime.strptime(str(due), '%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp())
            except (TypeError, ValueError):
                due_timestamp = int((_now() + timedelta(days=30)).timestamp())
        remote = _api('POST', 'invoices', {
            'customer': customer_id,
            'collection_method': 'send_invoice',
            'due_date': str(due_timestamp),
            'auto_advance': 'false',
            'pending_invoice_items_behavior': 'include',
            'metadata[invoice_id]': str(invoice_id),
            'metadata[payment_id]': str(payment_id),
            'metadata[account_tenant_id]': str(account_id),
            'metadata[privacy_profile]': 'no_email',
        }, config=config, idempotency_key='tuti-invoice-%d-payment-%d' % (invoice_id, payment_id))
        stripe_invoice_id = str(remote.get('id') or '')
        if not re.fullmatch(r'in_[A-Za-z0-9]+', stripe_invoice_id):
            raise StripeError('stripe_response_invalid')
        if remote.get('status') == 'draft':
            remote = _api('POST', 'invoices/' + stripe_invoice_id + '/finalize', {
                'auto_advance': 'false',
            }, config=config, idempotency_key='tuti-invoice-finalize-%d' % payment_id)
        url = str(remote.get('hosted_invoice_url') or '')
        if not url.startswith('https://'):
            raise StripeError('stripe_response_invalid')
        expires_at = _now() + timedelta(days=30)
        with connection.cursor() as cursor:
            # Legacy column name retained for compatibility with existing installations.
            cursor.execute("UPDATE stripe_invoice_payments SET checkout_session_id=%s,checkout_url=%s,payment_intent_id=%s,expires_at=%s,status='open',updated_at=UTC_TIMESTAMP() WHERE id=%s",
                           (stripe_invoice_id[:120], url[:512], str(remote.get('payment_intent') or '')[:120],
                            expires_at.strftime('%Y-%m-%d %H:%M:%S'), payment_id))
        connection.commit()
    except Exception as exc:
        # A timeout, 5xx, or malformed response may occur after Stripe has
        # committed the object. Keep the row retryable so the same payment ID
        # and Stripe idempotency keys can safely resume the operation.
        error_text = str(exc)
        retryable = (error_text.startswith('stripe_unreachable:')
                     or error_text.startswith('stripe_response_invalid')
                     or error_text.startswith('stripe_response_too_large')
                     or error_text.startswith('stripe_api_error:429:')
                     or any(error_text.startswith('stripe_api_error:%d:' % code)
                            for code in range(500, 600)))
        next_status = 'creating' if retryable else 'failed'
        with connection.cursor() as cursor:
            cursor.execute("UPDATE stripe_invoice_payments SET status=%s,failure_code=%s,updated_at=UTC_TIMESTAMP() WHERE id=%s",
                           (next_status, error_text[:64], payment_id))
        connection.commit()
        raise
    return {'ok': True, 'checkout_url': url, 'payment_id': payment_id, 'invoice_id': invoice_id,
            'amount_yen': int(amount_yen), 'mode': config['mode'],
            'expires_at_utc': expires_at.strftime('%Y-%m-%d %H:%M:%S'), 'reused': False}

def suspend_overdue_invoices(connection, limit=200):
    """Suspend tenant API keys for issued invoices past their inclusive due date.

    The due date remains payable through that calendar day. Suspension begins
    at 00:00 JST on the following date. Only keys that were active at suspension time
    are recorded, and a distinct billing_hold state prevents accidental
    reactivation of keys disabled for another reason.
    """
    from v3_handlers import _assert_write_fence
    _assert_write_fence(connection)
    ensure_schema(connection)
    try:
        batch_limit = max(1, min(1000, int(limit)))
    except (TypeError, ValueError):
        batch_limit = 200
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id,account_tenant_id FROM api_billing_invoices "
            "WHERE status='issued' AND due_date<DATE(UTC_TIMESTAMP() + INTERVAL 9 HOUR) "
            "ORDER BY due_date,id LIMIT %s",
            (batch_limit,),
        )
        invoices = list(cursor.fetchall() or [])
    suspended = 0
    for invoice in invoices:
        invoice_id = int(invoice['id'])
        tenant_id = int(invoice['account_tenant_id'])
        connection.begin()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT id,account_tenant_id,status,due_date FROM api_billing_invoices "
                    "WHERE id=%s AND status='issued' AND due_date<DATE(UTC_TIMESTAMP() + INTERVAL 9 HOUR) FOR UPDATE", (invoice_id,))
                current = cursor.fetchone()
                if (not current or int(current.get('account_tenant_id') or 0) != tenant_id
                        or str(current.get('status') or '') != 'issued'):
                    connection.commit()
                    continue
                cursor.execute(
                    "INSERT IGNORE INTO stripe_billing_key_suspensions(invoice_id,tenant_id,client_id,previous_status) "
                    "SELECT %s,c.tenant_id,c.id,COALESCE((SELECT s0.previous_status "
                    "FROM stripe_billing_key_suspensions s0 WHERE s0.client_id=c.id "
                    "AND s0.restored_at IS NULL ORDER BY s0.id LIMIT 1),c.status) "
                    "FROM tenant_api_clients c "
                    "WHERE c.tenant_id=%s AND c.status IN ('active','retiring','billing_hold') "
                    "AND c.revoked_at IS NULL",
                    (invoice_id, tenant_id),
                )
                cursor.execute(
                    "UPDATE tenant_api_clients c "
                    "JOIN stripe_billing_key_suspensions s ON s.client_id=c.id AND s.invoice_id=%s "
                    "SET c.status='billing_hold' "
                    "WHERE c.tenant_id=%s AND c.status IN ('active','retiring') AND c.revoked_at IS NULL",
                    (invoice_id, tenant_id),
                )
                suspended += int(cursor.rowcount or 0)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return {'overdue_invoices_checked': len(invoices), 'keys_suspended': suspended}


def restore_billing_suspended_keys(connection, invoice_id):
    """Restore only keys suspended by billing when no other overdue invoice remains."""
    try:
        invoice_id = int(invoice_id)
    except (TypeError, ValueError):
        return 0
    if invoice_id < 1:
        return 0
    from v3_handlers import _assert_write_fence
    _assert_write_fence(connection)
    ensure_schema(connection)
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE stripe_billing_key_suspensions SET restored_at=UTC_TIMESTAMP() "
                "WHERE invoice_id=%s AND restored_at IS NULL", (invoice_id,))
            cursor.execute(
                "UPDATE tenant_api_clients c "
                "JOIN stripe_billing_key_suspensions s ON s.client_id=c.id AND s.invoice_id=%s "
                "SET c.status=s.previous_status "
                "WHERE c.status='billing_hold' AND c.revoked_at IS NULL "
                "AND NOT EXISTS ("
                " SELECT 1 FROM stripe_billing_key_suspensions s2 "
                " JOIN api_billing_invoices i2 ON i2.id=s2.invoice_id "
                " WHERE s2.client_id=c.id AND s2.restored_at IS NULL "
                " AND i2.status='issued' AND i2.due_date<DATE(UTC_TIMESTAMP() + INTERVAL 9 HOUR)"
                ")",
                (invoice_id,),
            )
            restored = int(cursor.rowcount or 0)
        connection.commit()
        return restored
    except Exception:
        connection.rollback()
        raise


def restore_paid_invoice_keys(connection, limit=1000):
    """Restore billing-held keys for invoices paid through any supported path."""
    ensure_schema(connection)
    try:
        batch_limit = max(1, min(1000, int(limit)))
    except (TypeError, ValueError):
        batch_limit = 1000
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT DISTINCT s.invoice_id FROM stripe_billing_key_suspensions s "
            "JOIN api_billing_invoices i ON i.id=s.invoice_id "
            "WHERE i.status='paid' AND s.restored_at IS NULL "
            "ORDER BY s.invoice_id LIMIT %s",
            (batch_limit,),
        )
        invoice_ids = [int(row['invoice_id']) for row in (cursor.fetchall() or [])]
    restored = 0
    for invoice_id in invoice_ids:
        restored += restore_billing_suspended_keys(connection, invoice_id)
    return {'paid_invoices_checked': len(invoice_ids), 'keys_restored': restored}


def _record_event(connection, event_id, event_type, mode, status='received', message='', invoice_id=None, payment_id=None, processed=False):
    with connection.cursor() as cursor:
        cursor.execute('SELECT event_id FROM stripe_webhook_events WHERE event_id=%s LIMIT 1', (event_id,))
        if cursor.fetchone():
            cursor.execute('UPDATE stripe_webhook_events SET status=%s,message=%s,invoice_id=%s,payment_id=%s,processed_at=UTC_TIMESTAMP() WHERE event_id=%s', (status, message[:255], invoice_id, payment_id, event_id))
        else:
            cursor.execute('INSERT INTO stripe_webhook_events(event_id,event_type,mode,status,message,invoice_id,payment_id,processed_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)', (event_id, event_type[:80], mode, status, message[:255], invoice_id, payment_id, (_now().strftime('%Y-%m-%d %H:%M:%S') if processed else None)))


def _complete_payment(connection, payment, session, request_context):
    """Mark the invoice paid inside one locked transaction; return a status message."""
    from v3_handlers import _assert_write_fence
    _assert_write_fence(connection)
    invoice_id = int(payment['invoice_id'])
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT id,status,total_units,account_tenant_id FROM api_billing_invoices WHERE id=%s FOR UPDATE', (invoice_id,))
            invoice = cursor.fetchone()
            cursor.execute('SELECT * FROM stripe_invoice_payments WHERE id=%s FOR UPDATE', (int(payment['id']),))
            current = cursor.fetchone()
            if not invoice or not current:
                raise StripeError('invoice_not_found')
            if str(current.get('status')) == 'completed':
                connection.commit()
                return 'already_completed'
            if str(invoice.get('status')) == 'paid':
                cursor.execute("UPDATE stripe_invoice_payments SET status='completed',completed_at=COALESCE(completed_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=%s", (int(payment['id']),))
                connection.commit()
                return 'invoice_already_paid'
            if str(invoice.get('status')) != 'issued':
                cursor.execute("UPDATE stripe_invoice_payments SET status='skipped',failure_code='invoice_not_issued',updated_at=UTC_TIMESTAMP() WHERE id=%s", (int(payment['id']),))
                connection.commit()
                return 'invoice_not_issued'
            if int(invoice.get('account_tenant_id') or 0) != int(current.get('account_tenant_id') or 0):
                raise StripeError('invoice_not_found')
            cursor.execute("UPDATE stripe_invoice_payments SET payment_intent_id=%s,status='completed',completed_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=%s", (str(session.get('payment_intent') or '')[:120], int(payment['id'])))
            cursor.execute("UPDATE api_billing_invoices SET status='paid',paid_at=COALESCE(paid_at,UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=%s AND status='issued'", (invoice_id,))
            if int(cursor.rowcount or 0) != 1:
                raise StripeError('invoice_state_changed')
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return 'paid'


def _key_reissue_hash(subject, request):
    return hashlib.sha256(('sso|%s|%s' % (subject, request)).encode()).hexdigest()


def _key_pepper_hash(token):
    pepper = secret_value('key_pepper')
    if not pepper:
        raise StripeError('key_reissue_not_available')
    return hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()


def _reissue_identity(connection, client):
    """Return the active source key and the scopes the session may reissue."""
    from portal_key_policy import scope_subset
    tenant = int(client['tenant_id'])
    subject = str(client.get('sso_subject_hash') or '')
    with connection.cursor() as cursor:
        cursor.execute('SELECT source_client_id,scopes_json FROM tenant_sso_memberships WHERE subject_hash=%s AND tenant_id=%s LIMIT 1', (subject, tenant))
        membership = cursor.fetchone()
        if not membership:
            raise StripeError('key_reissue_not_available')
        cursor.execute("SELECT * FROM tenant_api_clients WHERE id=%s AND tenant_id=%s AND status='active' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP()) FOR UPDATE", (int(membership['source_client_id']), tenant))
        source = cursor.fetchone()
    if not source or (source.get('key_kind') or 'standard') != 'standard':
        raise StripeError('key_reissue_not_available')
    scopes = scope_subset(source['scopes_json'])
    allowed = scope_subset(membership['scopes_json'])
    try:
        original = json.loads(str(source['scopes_json']))
    except (TypeError, ValueError):
        original = None
    if (not isinstance(original, list) or len(scopes) != len(original)
            or any(scope not in allowed for scope in scopes) or 'tenant:read' not in scopes):
        raise StripeError('key_reissue_scope_mismatch')
    return source, scopes


@legacy_compatible(callback_index=None, request_index=0)
def create_key_reissue_checkout(connection, client, data, request_context):
    """Charge the 500 JPY reissue fee immediately and issue the key after payment."""
    from admin_oidc import session_status
    from v3_handlers import _assert_write_fence
    config = settings()
    if not config['enabled']:
        raise StripeError('stripe_not_configured')
    if str(client.get('key_kind') or '') != 'tenant_sso' or not client.get('tenant_sso_session_id'):
        raise StripeError('tenant_sso_session_required')
    status = session_status(str(client.get('sso_oidc_sid') or ''))
    authenticated = int((status or {}).get('auth_time') or 0)
    if not status or authenticated < int(time.time()) - 300 or authenticated > int(time.time()) + 30:
        raise StripeError('sso_reauthentication_required')
    fee = data.get('confirm_fee_yen')
    if isinstance(fee, bool) or not isinstance(fee, int) or fee != KEY_REISSUE_YEN:
        raise StripeError('key_reissue_fee_confirmation_required')
    request = str(request_context.get('header:idempotency-key') or '')
    if re.fullmatch('[A-Za-z0-9_-]{32,80}', request) is None:
        raise StripeError('key_reissue_request_id_required')
    tenant = int(client['tenant_id'])
    subject = str(client.get('sso_subject_hash') or '')
    account = int(client.get('parent_tenant_id') or tenant)
    environment = str(client.get('tenant_environment') or '')
    if config['mode'] == 'live' and environment != 'production':
        raise StripeError('stripe_live_sandbox_blocked')
    request_hash = _key_reissue_hash(subject, request)
    _assert_write_fence(connection)
    ensure_schema(connection)
    connection.begin()
    row_id = 0
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT id FROM tenants WHERE id IN (%s,%s) ORDER BY id FOR UPDATE', (account, tenant))
            cursor.fetchall()
            cursor.execute('SELECT * FROM stripe_key_reissue_payments WHERE tenant_id=%s AND request_hash=%s ORDER BY id DESC LIMIT 1 FOR UPDATE', (tenant, request_hash))
            existing = cursor.fetchone()
        if existing and str(existing.get('status')) == 'issued':
            raise StripeError('key_reissue_result_ready')
        if existing and str(existing.get('status')) == 'paid':
            raise StripeError('key_reissue_pending')
        if existing and str(existing.get('status')) == 'paid_unissued':
            raise StripeError('key_reissue_failed')
        source, scopes = _reissue_identity(connection, client)
        if (existing and str(existing.get('status')) in ('creating', 'pending')
                and str(existing.get('mode')) == config['mode']
                and existing.get('checkout_session_id') and not _expired(existing)):
            try:
                session = _api('GET', 'checkout/sessions/' + str(existing['checkout_session_id']), config=config)
            except StripeError:
                session = None
            if session and session.get('status') == 'open' and session.get('url'):
                connection.commit()
                return {'ok': True, 'checkout_url': str(session['url']), 'request_id': request,
                        'amount_yen': KEY_REISSUE_YEN, 'mode': config['mode'], 'reused': True}
            if session and session.get('status') == 'complete':
                raise StripeError('key_reissue_pending')
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO stripe_key_reissue_payments(tenant_id,account_tenant_id,payer_tenant_id,passkey_id,request_hash,source_client_id,scopes_json,environment,mode,amount_yen,currency,status) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', (tenant, account, tenant, 0, request_hash, int(source['id']), json.dumps(scopes, ensure_ascii=False, separators=(',', ':')), environment, config['mode'], KEY_REISSUE_YEN, 'jpy', 'creating'))
            row_id = int(connection.insert_id())
        return_ticket = secrets.token_urlsafe(32)
        with connection.cursor() as cursor:
            cursor.execute('DELETE FROM tenant_sso_bootstrap_tickets WHERE expires_at<UTC_TIMESTAMP() OR used_at IS NOT NULL')
            cursor.execute('INSERT INTO tenant_sso_bootstrap_tickets(ticket_hash,subject_hash,oidc_sid,created_at,expires_at) VALUES(%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP()+INTERVAL 30 MINUTE)', (hashlib.sha256(return_ticket.encode()).hexdigest(), subject, str(client.get('sso_oidc_sid') or '')))
        base = _portal_base(request_context)
        params = {
            # Stripe Adaptive Pricing keeps JPY 500 as the base price and lets
            # the customer choose JPY or an available local presentment currency.
            'adaptive_pricing[enabled]': 'true',
            'mode': 'payment',
            'line_items[0][price_data][currency]': 'jpy',
            'line_items[0][price_data][unit_amount]': str(KEY_REISSUE_YEN),
            'line_items[0][price_data][product_data][name]': 'APIキー再発行料（税込）',
            'line_items[0][quantity]': '1',
            'client_reference_id': 'reissue-%d' % row_id,
            'metadata[kind]': 'key_reissue',
            'metadata[reissue_id]': str(row_id),
            'metadata[tenant_id]': str(tenant),
            'metadata[request_hash]': request_hash,
            'success_url': base + '/tenant-portal/#sso_ticket=' + return_ticket + '&stripe=success&reissue=' + request,
            'cancel_url': base + '/tenant-portal/#sso_ticket=' + return_ticket + '&stripe=cancel&reissue=' + request,
            'locale': 'ja',
        }
        try:
            session = _api('POST', 'checkout/sessions', params, config=config,
                           idempotency_key='tuti-reissue-%d' % row_id)
        except StripeError as exc:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE stripe_key_reissue_payments SET status='failed',failure_code=%s,updated_at=UTC_TIMESTAMP() WHERE id=%s", (str(exc)[:64], row_id))
            connection.commit()
            raise
        url = str(session.get('url') or '')
        if not url.startswith('https://'):
            raise StripeError('stripe_response_invalid')
        expires = session.get('expires_at')
        expires_at = datetime.fromtimestamp(int(expires), timezone.utc) if expires else (_now() + timedelta(minutes=CHECKOUT_TTL_MINUTES))
        with connection.cursor() as cursor:
            cursor.execute("UPDATE stripe_key_reissue_payments SET checkout_session_id=%s,checkout_url=%s,expires_at=%s,status='pending',updated_at=UTC_TIMESTAMP() WHERE id=%s", (str(session.get('id') or '')[:120], url[:512], expires_at.strftime('%Y-%m-%d %H:%M:%S'), row_id))
        connection.commit()
    except Exception:
        try:
            connection.rollback()
        except Exception:
            pass
        raise
    return {'ok': True, 'checkout_url': url, 'request_id': request, 'amount_yen': KEY_REISSUE_YEN,
            'mode': config['mode'], 'expires_at_utc': expires_at.strftime('%Y-%m-%d %H:%M:%S'), 'reused': False}


@legacy_compatible(callback_index=None, request_index=0)
def key_reissue_result(connection, client, data, request_context):
    """Return the replacement key once the immediate payment is confirmed."""
    from portal_key_policy import reissued_token
    request = str(data.get('request_id') or '')
    if re.fullmatch('[A-Za-z0-9_-]{32,80}', request) is None:
        raise StripeError('key_reissue_request_id_required')
    if str(client.get('key_kind') or '') != 'tenant_sso':
        raise StripeError('tenant_sso_session_required')
    tenant = int(client['tenant_id'])
    subject = str(client.get('sso_subject_hash') or '')
    request_hash = _key_reissue_hash(subject, request)
    ensure_schema(connection)
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM stripe_key_reissue_payments WHERE tenant_id=%s AND request_hash=%s ORDER BY id DESC LIMIT 1', (tenant, request_hash))
        row = cursor.fetchone()
    if not row:
        raise StripeError('key_reissue_not_available')
    status_text = str(row.get('status'))
    if status_text in ('creating', 'pending'):
        row = _reconcile_key_reissue(connection, row, settings()) or row
        status_text = str(row.get('status'))
    if status_text == 'paid':
        try:
            _issue_key_reissue(connection, dict(row), {'payment_intent': row.get('payment_intent_id')}, request_context)
        except Exception:
            pass
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM stripe_key_reissue_payments WHERE id=%s LIMIT 1', (int(row['id']),))
            row = cursor.fetchone()
        status_text = str((row or {}).get('status'))
    if status_text != 'issued':
        if status_text in ('creating', 'pending', 'paid'):
            raise StripeError('key_reissue_pending')
        raise StripeError('key_reissue_result_expired' if status_text in ('expired', 'failed') else 'key_reissue_failed')
    completed = row.get('completed_at')
    if isinstance(completed, datetime) and completed.replace(tzinfo=timezone.utc) < _now() - timedelta(minutes=KEY_REISSUE_RESULT_MINUTES):
        raise StripeError('key_reissue_result_expired')
    token = reissued_token(dict(row), str(row.get('environment') or ''))
    try:
        scopes = json.loads(str(row.get('scopes_json') or '[]'))
    except ValueError:
        scopes = []
    return {'ok': True, 'api_key': token, 'scopes': scopes, 'fee_yen': KEY_REISSUE_YEN,
            'fee_tax_included': True, 'paid_immediately': True, 'mode': str(row.get('mode') or ''),
            'old_key_expires_at_utc': _utc_text(row.get('grace_expires_at'))}


def _reconcile_key_reissue(connection, row, config):
    """Confirm a paid Checkout Session when no webhook has arrived yet."""
    if not row or not config.get('enabled'):
        return row
    session_id = str(row.get('checkout_session_id') or '')
    if not session_id:
        return row
    try:
        session = _api('GET', 'checkout/sessions/' + session_id, config=config)
    except StripeError:
        return row
    status = str(session.get('status') or '')
    if status == 'expired':
        with connection.cursor() as cursor:
            cursor.execute("UPDATE stripe_key_reissue_payments SET status='expired',updated_at=UTC_TIMESTAMP() WHERE id=%s AND status IN ('creating','pending')", (int(row['id']),))
        connection.commit()
    elif status == 'complete' and str(session.get('payment_status') or '') == 'paid':
        if _key_reissue_session_matches(row, session):
            with connection.cursor() as cursor:
                cursor.execute("UPDATE stripe_key_reissue_payments SET status='paid',payment_intent_id=%s,updated_at=UTC_TIMESTAMP() WHERE id=%s AND status IN ('creating','pending')", (str(session.get('payment_intent') or '')[:120], int(row['id'])))
            connection.commit()
            try:
                _issue_key_reissue(connection, dict(row), session, {})
            except Exception:
                pass
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM stripe_key_reissue_payments WHERE id=%s LIMIT 1', (int(row['id']),))
        refreshed = cursor.fetchone()
    return refreshed or row


def _issue_key_reissue(connection, row, session, request_context):
    """Create the replacement key and retire the old one after payment."""
    from portal_key_policy import reissued_token
    from v3_handlers import _assert_write_fence
    _assert_write_fence(connection)
    tenant = int(row['tenant_id'])
    row_id = int(row['id'])
    source_id = int(row['source_client_id'])
    environment = str(row['environment'])
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT id,status FROM tenants WHERE id=%s FOR UPDATE', (tenant,))
            owner = cursor.fetchone()
            if not owner or owner.get('status') != 'active':
                raise StripeError('tenant_not_found')
            cursor.execute('SELECT * FROM stripe_key_reissue_payments WHERE id=%s FOR UPDATE', (row_id,))
            current = cursor.fetchone()
            if not current:
                raise StripeError('key_reissue_not_available')
            if str(current.get('status')) == 'issued':
                connection.commit()
                return 'already_issued'
            if str(current.get('status')) not in ('paid', 'pending', 'creating'):
                connection.commit()
                return 'ignored'
            cursor.execute("SELECT * FROM tenant_api_clients WHERE id=%s AND tenant_id=%s AND status='active' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP()) FOR UPDATE", (source_id, tenant))
            old = cursor.fetchone()
            if not old:
                cursor.execute("UPDATE stripe_key_reissue_payments SET status='paid_unissued',failure_code='source_key_inactive',updated_at=UTC_TIMESTAMP() WHERE id=%s", (row_id,))
                connection.commit()
                return 'source_key_inactive'
            token = reissued_token({'tenant_id': tenant, 'passkey_id': int(current.get('passkey_id') or 0), 'request_hash': str(current['request_hash'])}, environment)
            scopes = json.loads(str(current.get('scopes_json') or '[]'))
            grace = _now() + timedelta(hours=KEY_REISSUE_GRACE_HOURS)
            key_hash = _key_pepper_hash(token)
            cursor.execute('SELECT id FROM tenant_api_clients WHERE tenant_id=%s AND key_hash=%s LIMIT 1', (tenant, key_hash))
            existing_client = cursor.fetchone()
            if existing_client:
                new_id = int(existing_client['id'])
            else:
                cursor.execute('INSERT INTO tenant_api_clients(tenant_id,name,key_prefix,key_hash,scopes_json,rate_limit_per_minute,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s)', (tenant, str(old['name'])[:120], token[:12], key_hash, json.dumps(scopes), min(600, int(old['rate_limit_per_minute'])), old['expires_at']))
                new_id = int(connection.insert_id())
            cursor.execute("UPDATE tenant_api_clients SET status='retiring',replacement_client_id=%s,grace_expires_at=%s WHERE id=%s AND tenant_id=%s", (new_id, grace.strftime('%Y-%m-%d %H:%M:%S'), source_id, tenant))
            cursor.execute("UPDATE stripe_key_reissue_payments SET status='issued',new_client_id=%s,payment_intent_id=%s,grace_expires_at=%s,completed_at=UTC_TIMESTAMP(),updated_at=UTC_TIMESTAMP() WHERE id=%s", (new_id, str(session.get('payment_intent') or '')[:120], grace.strftime('%Y-%m-%d %H:%M:%S'), row_id))
            cursor.execute('UPDATE tenant_sso_memberships SET source_client_id=%s WHERE tenant_id=%s AND source_client_id=%s', (new_id, tenant, source_id))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    return 'issued'


def _key_reissue_by_session(connection, session_id):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM stripe_key_reissue_payments WHERE checkout_session_id=%s LIMIT 1', (str(session_id)[:120],))
        found = cursor.fetchone()
    return dict(found) if found else None


def _key_reissue_session_matches(row, session):
    """Bind a Stripe Session to the exact server-created 500 JPY reissue request.

    Adaptive Pricing changes the presentment currency and amount, so the
    original JPY amount cannot be compared with amount_total after conversion.
    The persisted Checkout Session ID and immutable server-created metadata
    identify the exact 500 JPY base-price session instead.
    """
    metadata = session.get('metadata') if isinstance(session.get('metadata'), dict) else {}
    try:
        row_id = int(row.get('id') or 0)
        tenant_id = int(row.get('tenant_id') or 0)
    except (TypeError, ValueError):
        return False
    expected_hash = str(row.get('request_hash') or '')
    actual_hash = str(metadata.get('request_hash') or '')
    return bool(
        row_id > 0 and tenant_id > 0
        and str(session.get('id') or '') == str(row.get('checkout_session_id') or '')
        and str(session.get('client_reference_id') or '') == 'reissue-%d' % row_id
        and str(metadata.get('kind') or '') == 'key_reissue'
        and str(metadata.get('reissue_id') or '') == str(row_id)
        and str(metadata.get('tenant_id') or '') == str(tenant_id)
        and expected_hash and actual_hash
        and hmac.compare_digest(expected_hash, actual_hash)
    )


def _handle_key_reissue_completed(connection, config, mode, event_id, event_type, session, request_context):
    row = _key_reissue_by_session(connection, str(session.get('id') or ''))
    if not row:
        _record_event(connection, event_id, event_type, mode, 'ignored', 'reissue_payment_not_found', processed=True)
        connection.commit()
        return json_response('200 OK', {'ok': True, 'received': True, 'ignored': True})
    if str(row.get('mode')) != mode:
        raise StripeError('stripe_mode_mismatch')
    if not _key_reissue_session_matches(row, session):
        _record_event(connection, event_id, event_type, mode, 'failed', 'session_identity_mismatch', None, int(row['id']), processed=True)
        connection.commit()
        raise StripeError('stripe_session_mismatch')
    if str(session.get('payment_status') or '') != 'paid':
        _record_event(connection, event_id, event_type, mode, 'pending', 'payment_status_' + str(session.get('payment_status'))[:32], None, int(row['id']), processed=True)
        connection.commit()
        return json_response('200 OK', {'ok': True, 'received': True, 'pending': True})
    with connection.cursor() as cursor:
        cursor.execute("UPDATE stripe_key_reissue_payments SET status='paid',payment_intent_id=%s,updated_at=UTC_TIMESTAMP() WHERE id=%s AND status IN ('creating','pending')", (str(session.get('payment_intent') or '')[:120], int(row['id'])))
    connection.commit()
    message = _issue_key_reissue(connection, row, session, request_context)
    _record_event(connection, event_id, event_type, mode, 'processed' if message == 'issued' else 'ignored', 'reissue_' + message, None, int(row['id']), processed=True)
    connection.commit()
    if message == 'issued':
        from ha_handlers import _append_ha_audit, ha_sync_peer
        _append_ha_audit('tenant_portal_api_key_reissued', {'tenant_id': int(row['tenant_id']), 'reissue_id': int(row['id']), 'new_client_id': int(row.get('new_client_id') or 0), 'fee_yen': KEY_REISSUE_YEN, 'provider': 'stripe', 'mode': mode}, request_context)
        ha_sync_peer('tenant_portal_api_key_reissued', request_context)
    return json_response('200 OK', {'ok': True, 'received': True, 'result': message})


def _handle_key_reissue_expired(connection, mode, event_id, event_type, session):
    row = _key_reissue_by_session(connection, str(session.get('id') or ''))
    if row and str(row.get('mode')) == mode:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE stripe_key_reissue_payments SET status='expired',updated_at=UTC_TIMESTAMP() WHERE id=%s AND status IN ('creating','pending')", (int(row['id']),))
        _record_event(connection, event_id, event_type, mode, 'processed', 'reissue_expired', None, int(row['id']), processed=True)
    else:
        _record_event(connection, event_id, event_type, mode, 'ignored', 'reissue_payment_not_found', processed=True)
    connection.commit()
    return json_response('200 OK', {'ok': True, 'received': True})


@legacy_compatible(callback_index=1, request_index=0)
def webhook(request_context):
    """Handle signed Stripe Invoice and legacy Checkout webhooks."""
    config = settings()
    if not config.get('webhook_secret'):
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'stripe_webhook_not_configured'})
    if str(request_context.get('method', 'GET')) != 'POST':
        return json_response('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
    try:
        raw = read_bounded_body(request_context, MAX_WEBHOOK_BYTES)
    except Exception:
        return json_response('400 Bad Request', {'ok': False, 'error': 'invalid_payload'})
    if not verify_webhook_signature(raw, request_context.get('header:stripe-signature', ''), config['webhook_secret']):
        return json_response('400 Bad Request', {'ok': False, 'error': 'invalid_signature'})
    try:
        event = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        return json_response('400 Bad Request', {'ok': False, 'error': 'invalid_payload'})
    if not isinstance(event, dict) or not isinstance(event.get('data'), dict):
        return json_response('400 Bad Request', {'ok': False, 'error': 'invalid_payload'})
    event_id = str(event.get('id') or '')
    event_type = str(event.get('type') or '')
    if re.fullmatch(r'[A-Za-z0-9_]{8,120}', event_id) is None:
        return json_response('400 Bad Request', {'ok': False, 'error': 'invalid_event_id'})
    event_object = event['data'].get('object')
    if not isinstance(event_object, dict):
        event_object = {}
    mode = 'live' if event.get('livemode') is True else 'test'
    connection = None
    try:
        connection = database.connect()
        ensure_schema(connection)
        metadata = event_object.get('metadata') if isinstance(event_object.get('metadata'), dict) else {}
        if str(metadata.get('kind') or '') == 'key_reissue':
            if event_type == 'checkout.session.expired':
                return _handle_key_reissue_expired(connection, mode, event_id, event_type, event_object)
            if event_type == 'checkout.session.completed':
                return _handle_key_reissue_completed(connection, config, mode, event_id, event_type, event_object, request_context)
        if event_type == 'invoice.paid':
            return _handle_invoice_paid(connection, mode, event_id, event_type, event_object, request_context)
        if event_type == 'invoice.payment_failed':
            return _handle_invoice_payment_failed(connection, mode, event_id, event_type, event_object)
        if event_type == 'invoice.overdue':
            return _handle_invoice_overdue(connection, mode, event_id, event_type, event_object)
        if event_type == 'checkout.session.expired':
            return _handle_expired(connection, config, mode, event_id, event_type, event_object, request_context)
        if event_type == 'payment_intent.payment_failed':
            return _handle_payment_failed(connection, config, mode, event_id, event_type, event_object, request_context)
        if event_type != 'checkout.session.completed':
            _record_event(connection, event_id, event_type, mode, 'ignored', 'unsupported_event', processed=True)
            connection.commit()
            return json_response('200 OK', {'ok': True, 'received': True, 'ignored': True})
        return _handle_completed(connection, config, mode, event_id, event_type, event_object, request_context)
    except StripeError as exc:
        # Invalid or mismatched events are recorded and acknowledged to avoid endless retries.
        if connection is not None:
            try:
                connection.rollback()
                _record_event(connection, event_id, event_type, mode, 'failed', str(exc), processed=True)
                connection.commit()
            except Exception:
                try:
                    connection.rollback()
                except Exception:
                    pass
        return json_response('200 OK', {'ok': True, 'received': True, 'rejected': str(exc)[:120]})
    except database.DatabaseConfigurationError:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'stripe_webhook_unavailable'})
    except Exception:
        if connection is not None:
            connection.rollback()
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'stripe_webhook_unavailable'})
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def _payment_by_session(connection, session_id):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM stripe_invoice_payments WHERE checkout_session_id=%s LIMIT 1', (str(session_id)[:120],))
        return _payment_row(cursor.fetchone())


def _handle_invoice_paid(connection, mode, event_id, event_type, invoice, request_context):
    """Accept only the exact server-created Stripe invoice and amount."""
    metadata = invoice.get('metadata') if isinstance(invoice.get('metadata'), dict) else {}
    try:
        payment_id = int(metadata.get('payment_id') or 0)
        invoice_id = int(metadata.get('invoice_id') or 0)
        account_id = int(metadata.get('account_tenant_id') or 0)
    except (TypeError, ValueError):
        payment_id = invoice_id = account_id = 0
    stripe_invoice_id = str(invoice.get('id') or '')
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM stripe_invoice_payments WHERE id=%s AND invoice_id=%s AND account_tenant_id=%s AND checkout_session_id=%s LIMIT 1',
                       (payment_id, invoice_id, account_id, stripe_invoice_id[:120]))
        payment = _payment_row(cursor.fetchone())
    if not payment:
        _record_event(connection, event_id, event_type, mode, 'ignored', 'invoice_payment_not_found', invoice_id or None, payment_id or None, processed=True)
        connection.commit()
        return json_response('200 OK', {'ok': True, 'received': True, 'ignored': True})
    if str(payment.get('mode')) != mode:
        raise StripeError('stripe_mode_mismatch')
    if str(invoice.get('status') or '') != 'paid':
        _record_event(connection, event_id, event_type, mode, 'pending', 'invoice_not_paid', invoice_id, payment_id, processed=True)
        connection.commit()
        return json_response('200 OK', {'ok': True, 'received': True, 'pending': True})
    try:
        amount_paid = int(invoice.get('amount_paid'))
    except (TypeError, ValueError):
        amount_paid = -1
    if str(invoice.get('currency') or '').lower() != 'jpy' or amount_paid != int(payment['amount_yen']):
        _record_event(connection, event_id, event_type, mode, 'failed', 'amount_mismatch', invoice_id, payment_id, processed=True)
        connection.commit()
        raise StripeError('stripe_amount_mismatch')
    normalized = {'amount_total': amount_paid, 'currency': invoice.get('currency'), 'payment_intent': invoice.get('payment_intent')}
    message = _complete_payment(connection, payment, normalized, request_context)
    if message in ('paid', 'invoice_already_paid'):
        # Register any other overdue invoices before deciding whether keys
        # can safely be restored.
        suspend_overdue_invoices(connection, limit=1000)
        restore_billing_suspended_keys(connection, invoice_id)
    _record_event(connection, event_id, event_type, mode, 'processed' if message == 'paid' else 'ignored', message, invoice_id, payment_id, processed=True)
    connection.commit()
    if message in ('paid', 'invoice_already_paid'):
        from ha_handlers import _append_ha_audit, ha_sync_peer
        _append_ha_audit('api_billing_invoice_paid', {'invoice_id': invoice_id, 'payment_id': payment_id, 'provider': 'stripe_invoice', 'mode': mode, 'amount_yen': amount_paid}, request_context)
        ha_sync_peer('api_billing_invoice_paid', request_context)
    return json_response('200 OK', {'ok': True, 'received': True, 'result': message})


def _handle_invoice_overdue(connection, mode, event_id, event_type, invoice):
    """Suspend the billed tenant's active API keys after the invoice due date."""
    metadata = invoice.get('metadata') if isinstance(invoice.get('metadata'), dict) else {}
    try:
        payment_id = int(metadata.get('payment_id') or 0)
        invoice_id = int(metadata.get('invoice_id') or 0)
        account_id = int(metadata.get('account_tenant_id') or 0)
    except (TypeError, ValueError):
        payment_id = invoice_id = account_id = 0
    stripe_invoice_id = str(invoice.get('id') or '')
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM stripe_invoice_payments WHERE id=%s AND invoice_id=%s "
            "AND account_tenant_id=%s AND checkout_session_id=%s LIMIT 1",
            (payment_id, invoice_id, account_id, stripe_invoice_id[:120]),
        )
        payment = cursor.fetchone()
    if not payment or str(payment.get('mode') or '') != mode:
        _record_event(connection, event_id, event_type, mode, 'ignored',
                      'invoice_payment_not_found', invoice_id or None, payment_id or None, processed=True)
        connection.commit()
        return json_response('200 OK', {'ok': True, 'received': True, 'ignored': True})
    if str(invoice.get('status') or '') == 'paid':
        _record_event(connection, event_id, event_type, mode, 'ignored',
                      'paid_invoice_waiting_for_invoice_paid_event', invoice_id, payment_id, processed=True)
        connection.commit()
        return json_response('200 OK', {'ok': True, 'received': True, 'ignored': True})
    result = suspend_overdue_invoices(connection, limit=200)
    _record_event(connection, event_id, event_type, mode, 'processed',
                  'overdue_keys_suspended_%d' % int(result['keys_suspended']), invoice_id, payment_id, processed=True)
    connection.commit()
    return json_response('200 OK', {'ok': True, 'received': True,
                                    'keys_suspended': int(result['keys_suspended'])})


def _handle_invoice_payment_failed(connection, mode, event_id, event_type, invoice):
    metadata = invoice.get('metadata') if isinstance(invoice.get('metadata'), dict) else {}
    try:
        payment_id = int(metadata.get('payment_id') or 0)
        invoice_id = int(metadata.get('invoice_id') or 0)
    except (TypeError, ValueError):
        payment_id = invoice_id = 0
    stripe_invoice_id = str(invoice.get('id') or '')
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM stripe_invoice_payments WHERE id=%s AND invoice_id=%s AND checkout_session_id=%s LIMIT 1',
                       (payment_id, invoice_id, stripe_invoice_id[:120]))
        payment = cursor.fetchone()
        if payment and str(payment.get('mode')) == mode:
            cursor.execute("UPDATE stripe_invoice_payments SET status='failed',failure_code='invoice_payment_failed',updated_at=UTC_TIMESTAMP() WHERE id=%s AND status<>'completed'",
                           (payment_id,))
    if payment and str(payment.get('mode')) == mode:
        _record_event(connection, event_id, event_type, mode, 'processed', 'invoice_payment_failed', invoice_id, payment_id, processed=True)
    else:
        _record_event(connection, event_id, event_type, mode, 'ignored', 'invoice_payment_not_found', processed=True)
    connection.commit()
    return json_response('200 OK', {'ok': True, 'received': True})


def _handle_completed(connection, config, mode, event_id, event_type, session, request_context):
    session_id = str(session.get('id') or '')
    payment = _payment_by_session(connection, session_id) if session_id else None
    if not payment:
        _record_event(connection, event_id, event_type, mode, 'ignored', 'payment_not_found', processed=True)
        connection.commit()
        return json_response('200 OK', {'ok': True, 'received': True, 'ignored': True})
    if str(payment.get('mode')) != mode:
        raise StripeError('stripe_mode_mismatch')
    if str(session.get('payment_status') or '') != 'paid':
        _record_event(connection, event_id, event_type, mode, 'pending', 'payment_status_' + str(session.get('payment_status'))[:32], int(payment['invoice_id']), int(payment['id']), processed=True)
        connection.commit()
        return json_response('200 OK', {'ok': True, 'received': True, 'pending': True})
    try:
        paid_total = int(session.get('amount_total'))
    except (TypeError, ValueError):
        paid_total = -1
    if str(session.get('currency') or '').lower() != 'jpy' or paid_total != int(payment['amount_yen']):
        _record_event(connection, event_id, event_type, mode, 'failed', 'amount_mismatch', int(payment['invoice_id']), int(payment['id']), processed=True)
        connection.commit()
        raise StripeError('stripe_amount_mismatch')
    message = _complete_payment(connection, payment, session, request_context)
    _record_event(connection, event_id, event_type, mode, 'processed' if message == 'paid' else 'ignored', message, int(payment['invoice_id']), int(payment['id']), processed=True)
    connection.commit()
    if message in ('paid', 'invoice_already_paid'):
        from ha_handlers import _append_ha_audit, ha_sync_peer
        _append_ha_audit('api_billing_invoice_paid', {'invoice_id': int(payment['invoice_id']), 'payment_id': int(payment['id']), 'provider': 'stripe', 'mode': mode, 'amount_yen': int(payment['amount_yen'])}, request_context)
        ha_sync_peer('api_billing_invoice_paid', request_context)
    return json_response('200 OK', {'ok': True, 'received': True, 'result': message})


def _handle_expired(connection, config, mode, event_id, event_type, session, request_context):
    payment = _payment_by_session(connection, str(session.get('id') or ''))
    if payment and str(payment.get('mode')) == mode:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE stripe_invoice_payments SET status='expired',updated_at=UTC_TIMESTAMP() WHERE id=%s AND status IN ('creating','open')", (int(payment['id']),))
        _record_event(connection, event_id, event_type, mode, 'processed', 'expired', int(payment['invoice_id']), int(payment['id']), processed=True)
    else:
        _record_event(connection, event_id, event_type, mode, 'ignored', 'payment_not_found', processed=True)
    connection.commit()
    return json_response('200 OK', {'ok': True, 'received': True})


def _handle_payment_failed(connection, config, mode, event_id, event_type, intent, request_context):
    intent_id = str(intent.get('id') or '')
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM stripe_invoice_payments WHERE payment_intent_id=%s LIMIT 1', (intent_id[:120],))
        payment = _payment_row(cursor.fetchone())
        if not payment:
            cursor.execute('SELECT * FROM stripe_key_reissue_payments WHERE payment_intent_id=%s LIMIT 1', (intent_id[:120],))
            failed_reissue = cursor.fetchone()
            if failed_reissue:
                failed_code = 'payment_failed'
                error_detail = intent.get('last_payment_error')
                if isinstance(error_detail, dict) and error_detail.get('code'):
                    failed_code = str(error_detail['code'])
                cursor.execute("UPDATE stripe_key_reissue_payments SET failure_code=%s,updated_at=UTC_TIMESTAMP() WHERE id=%s AND status <> 'issued'", (failed_code[:64], int(failed_reissue['id'])))
                _record_event(connection, event_id, event_type, mode, 'processed', 'reissue_payment_failed', None, int(failed_reissue['id']), processed=True)
                connection.commit()
                return json_response('200 OK', {'ok': True, 'received': True})
    if not payment:
        _record_event(connection, event_id, event_type, mode, 'ignored', 'payment_not_found', processed=True)
        connection.commit()
        return json_response('200 OK', {'ok': True, 'received': True, 'ignored': True})
    if str(payment.get('mode')) != mode:
        raise StripeError('stripe_mode_mismatch')
    failure = intent.get('last_payment_error')
    code = failure.get('code') if isinstance(failure, dict) else None
    with connection.cursor() as cursor:
        cursor.execute("UPDATE stripe_invoice_payments SET status='failed',failure_code=%s,updated_at=UTC_TIMESTAMP() WHERE id=%s AND status<>'completed'", (str(code or 'payment_failed')[:64], int(payment['id'])))
    _record_event(connection, event_id, event_type, mode, 'processed', 'payment_failed', int(payment['invoice_id']), int(payment['id']), processed=True)
    connection.commit()
    return json_response('200 OK', {'ok': True, 'received': True})