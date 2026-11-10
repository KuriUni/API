"""Fresh tenant OIDC -> native proof-key grant -> authorized single-key issue/activate.

No API keys or passwords are accepted by this workflow. Issuance delegates to the
existing V6 service, retaining its scopes, quota, billing and idempotency rules.
"""
import base64
import hashlib
import hmac
import html
import io
import json
import re
import secrets
import time
from urllib.parse import parse_qs

import database
from app_sso import FlowError, _b64, _body, _cipher, _host, _reply, _store
from deployment_settings import site_url
from native_http import add_headers

PATH = '/license/python-migration/mobile-manager/admin-auth.php'
KIND = 'mnsl-issuer'
TTL = 300
OPERATION = 'mnsl_sso_issue_activate'
TERMS_VERSION = '2.0'
TERMS_SHA256 = '65279a71618c5e09771dbad6bfef1a5c87bb4a1096b2222b4172f99164d910fb'


def _endpoint(host):
    return 'https://' + host + site_url(PATH)


def _seal(value, aad):
    nonce = secrets.token_bytes(12)
    return _b64(nonce + _cipher().encrypt(nonce, json.dumps(value, separators=(',', ':')).encode(), aad.encode()))


def _open(value, aad):
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    return json.loads(_cipher().decrypt(raw[:12], raw[12:], aad.encode()).decode())


def _row(rows, ticket, host):
    row = rows.get(ticket)
    if not isinstance(row, dict) or row.get('kind') != KIND or row.get('host') != host:
        raise FlowError(400, 'mnsl_login_expired')
    return row


def valid_ticket(ticket, host):
    if not re.fullmatch('[A-Za-z0-9_-]{32}', str(ticket)):
        return False
    with _store() as rows:
        try:
            _row(rows, ticket, host)
            return True
        except FlowError:
            return False


def complete_login(context, flow, claims, session, clear):
    """Called only after admin_oidc has verified state, PKCE, ID token and SSO sid."""
    from admin_oidc import ISSUER
    host, ticket = _host(context), str(flow['app_ticket'])
    auth_time = int(claims.get('auth_time') or 0)
    if auth_time < int(flow['created']) or auth_time > int(time.time()) + 60:
        raise FlowError(401, 'sso_reauthentication_required')
    cookie = _b64(secrets.token_bytes(32))
    now = int(time.time())
    identity = {'subject_hash': hashlib.sha256((ISSUER + '\0' + str(claims['sub'])).encode()).hexdigest(),
                'oidc_sid': str(claims['sid']), 'auth_time': auth_time,
                'expires': min(now + TTL, int(session['expires_at'])), 'host': host,
                'display_name': str(session.get('display_name') or 'SSO ID')[:200]}
    if type(claims.get('tenant_id')) is int and 0 < claims['tenant_id'] < 2**63:
        identity['tenant_id'] = claims['tenant_id']
    with _store() as rows:
        row = _row(rows, ticket, host)
        identity['expires'] = min(row['expires'], identity['expires'])
        row.update(identity=_seal(identity, host + ':' + ticket), browser_hash=hashlib.sha256(cookie.encode()).hexdigest(),
                   csrf=_b64(secrets.token_bytes(32)), expires=min(row['expires'], identity['expires']))
    from admin_oidc import _redirect
    return _redirect(_endpoint(host) + '?action=mnsl_authorize&ticket=' + ticket, headers=[clear,
        ('Set-Cookie', 'tuti_mnsl_' + ticket + '=' + cookie + '; Path=' + site_url(PATH) + '; Max-Age=300; Secure; HttpOnly; SameSite=Lax'),
        ('Referrer-Policy', 'no-referrer')])


def _provider(identity):
    from admin_oidc import session_active, TENANT_CLIENT_ID
    if int(identity['expires']) <= int(time.time()) or not session_active(identity['oidc_sid'], TENANT_CLIENT_ID):
        raise FlowError(401, 'mnsl_sso_expired')


def _identity(context):
    host = _host(context)
    if any(context.get('header:' + name) for name in ('authorization', 'x-api-key', 'x-ha-session', 'x-tenant-sso-session')):
        raise FlowError(401, 'mnsl_sso_only')
    token = str(context.get('header:x-mnsl-sso-session') or '')
    if not re.fullmatch('[A-Za-z0-9_-]{43}', token):
        raise FlowError(401, 'mnsl_sso_required')
    hashed = hashlib.sha256(token.encode()).hexdigest()
    with _store() as rows:
        found = [(ticket, dict(row)) for ticket, row in rows.items() if row.get('kind') == KIND and
                 row.get('host') == host and row.get('consumed') and hmac.compare_digest(str(row.get('token_hash') or ''), hashed)]
    if len(found) != 1:
        raise FlowError(401, 'mnsl_sso_expired')
    ticket, row = found[0]
    identity = _open(row['identity'], host + ':' + ticket)
    _provider(identity)
    return identity


def _account(identity):
    return hashlib.sha256((identity['host'] + '\0' + identity['subject_hash']).encode()).hexdigest()


def _contracts(connection, identity):
    from mobile_admin_auth import _principal
    from baas_handlers import _role_allows_scope
    role = _principal(identity['subject_hash'])
    if _role_allows_scope(role, 'licenses:write') and _role_allows_scope(role, 'tenant:read'):
        with connection.cursor() as cursor:
            cursor.execute("SELECT id tenant_id,slug,name,environment,parent_tenant_id FROM tenants WHERE status='active' AND environment='production' AND parent_tenant_id IS NULL ORDER BY slug LIMIT 200")
            return [dict(row, source='administrator') for row in cursor.fetchall()]
    from tenant_sso_contracts import memberships
    result = [dict(row, source='membership') for row in memberships(connection, identity['subject_hash'])
              if row['environment'] == 'production' and 'licenses:write' in row['scopes'] and 'tenant:read' in row['scopes']]
    invited_tenant = identity.get('tenant_id')
    if type(invited_tenant) is int and 0 < invited_tenant < 2**63 and not any(int(row['tenant_id']) == invited_tenant for row in result):
        with connection.cursor() as cursor:
            cursor.execute("SELECT t.id tenant_id,t.slug,t.name,t.environment,t.parent_tenant_id,c.id source_client_id,c.scopes_json "
                           "FROM tenants t JOIN tenant_api_clients c ON c.tenant_id=t.id "
                           "WHERE t.id=%s AND t.status='active' AND t.environment='production' AND t.parent_tenant_id IS NULL "
                           "AND c.key_hash IS NOT NULL AND c.key_hash<>'' AND c.status='active' AND c.revoked_at IS NULL "
                           "AND (c.expires_at IS NULL OR c.expires_at>UTC_TIMESTAMP()) ORDER BY c.id LIMIT 100", (invited_tenant,))
            candidates = cursor.fetchall()
        from baas_handlers import _auth_scopes
        candidate = next((row for row in candidates if {'tenant:read', 'licenses:write'}.issubset(set(_auth_scopes(row.get('scopes_json'))))), None)
        if candidate:
            result.append(dict(candidate, source='invitation'))
    return result


def _contract(connection, identity, tenant):
    result = next((row for row in _contracts(connection, identity) if int(row['tenant_id']) == tenant), None)
    if not result:
        raise FlowError(403, 'mnsl_contract_or_scope_denied')
    return result


def _products(connection, tenant):
    with connection.cursor() as cursor:
        cursor.execute("SELECT id,code,name FROM products WHERE tenant_id=%s AND status='active' ORDER BY id LIMIT 1000", (tenant,))
        return [{'id': int(row['id']), 'code': str(row['code']), 'name': str(row.get('name') or row['code'])} for row in cursor.fetchall()]


def _context(context, data):
    raw = json.dumps(data, separators=(',', ':')).encode()
    result = {key: value for key, value in context.items() if not key.startswith('header:')}
    result.update(method='POST', content_type='application/json', content_length=str(len(raw)), body_stream=io.BytesIO(raw))
    result['header:host'] = _host(context)
    result['header:x-baas-environment'] = 'production'
    return result


def _delegation(connection, context, identity, contract):
    if contract['source'] == 'administrator':
        from app_sso import _issue_token
        context['header:x-ha-session'] = _issue_token({'credential_id_hash': identity['subject_hash'],
            'oidc_sid': identity['oidc_sid'], 'expires': identity['expires'], 'reauthenticated_at': identity['auth_time']}, tenant_session=True)
        context['header:x-tenant-id'] = str(contract['tenant_id'])
        return None
    if contract.get('source') == 'invitation':
        # The signed, validated ID token binds this user to this tenant. Persist only
        # the explicitly granted minimum scopes, still intersected with the live API key.
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO tenant_sso_memberships(subject_hash,tenant_id,source_client_id,scopes_json) VALUES(%s,%s,%s,%s) ON DUPLICATE KEY UPDATE source_client_id=VALUES(source_client_id),scopes_json=VALUES(scopes_json),updated_at=UTC_TIMESTAMP()',
                           (identity['subject_hash'], int(contract['tenant_id']), int(contract['source_client_id']), json.dumps(['tenant:read', 'licenses:write'], separators=(',', ':'))))
        connection.commit()
    token = _b64(secrets.token_bytes(32))
    hashed = hashlib.sha256(token.encode()).hexdigest()
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO tenant_sso_sessions(token_hash,subject_hash,oidc_sid,tenant_id,created_at,expires_at,sso_checked_at) VALUES(%s,%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP()+INTERVAL 5 MINUTE,UTC_TIMESTAMP())',
                       (hashed, identity['subject_hash'], identity['oidc_sid'], int(contract['tenant_id'])))
    connection.commit()
    context['header:x-tenant-sso-session'] = token
    return hashed


def _integer(value):
    if type(value) is not int or not 0 < value < 2**63:
        raise FlowError(400, 'mnsl_invalid_selection')
    return value


def _issue(context, identity, data):
    tenant, product = _integer(data.get('tenant_id')), _integer(data.get('product_id'))
    request_id, fingerprint = str(data.get('request_id') or ''), str(data.get('device_fingerprint') or '')
    if not re.fullmatch('[A-Za-z0-9_-]{32,80}', request_id) or not re.fullmatch('[a-fA-F0-9]{64}', fingerprint):
        raise FlowError(400, 'mnsl_invalid_request')
    if data.get('confirm_issue') is not True:
        raise FlowError(400, 'mnsl_issue_confirmation_required')
    if data.get('confirm_terms') is not True or data.get('terms_version') != TERMS_VERSION or not hmac.compare_digest(str(data.get('terms_sha256') or '').lower(), TERMS_SHA256):
        raise FlowError(400, 'mnsl_terms_confirmation_required')
    app_version = data.get('app_version', '1.0.0')
    if not isinstance(app_version, str) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+-]{0,39}', app_version):
        raise FlowError(400, 'mnsl_invalid_app_version')
    fingerprint = fingerprint.lower()
    key = 'mnsl-' + hashlib.sha256((identity['host'] + '\0' + identity['subject_hash'] + '\0' + request_id).encode()).hexdigest()
    canonical = {'tenant_id': tenant, 'product_id': product, 'device_fingerprint': fingerprint,
                 'app_version': app_version, 'terms_version': TERMS_VERSION, 'terms_sha256': TERMS_SHA256}
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()
    connection = database.connect()
    delegated = None
    locked = False
    try:
        contract = _contract(connection, identity, tenant)
        if not any(row['id'] == product for row in _products(connection, tenant)):
            raise FlowError(403, 'mnsl_product_denied')
        from v3_handlers import _assert_write_fence
        _assert_write_fence(connection)
        with connection.cursor() as cursor:
            cursor.execute('SELECT GET_LOCK(%s,0) AS acquired', ('mnsl:' + key[5:55],))
            locked = int((cursor.fetchone() or {}).get('acquired') or 0) == 1
        if not locked:
            raise FlowError(409, 'mnsl_request_in_progress')
        with connection.cursor() as cursor:
            cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s LIMIT 1', (tenant, OPERATION, key))
            saved = cursor.fetchone()
            receipt = json.loads(saved['response_json']) if saved else None
            if receipt and not hmac.compare_digest(str(receipt.get('digest') or ''), digest):
                raise FlowError(409, 'mnsl_request_changed')
            if receipt and receipt.get('sealed') and int(receipt.get('response_expires') or 0) > int(time.time()):
                result = _open(receipt['sealed'], key)
                result['replayed'] = True
                return _reply(200, result)
            if not receipt:
                cursor.execute('INSERT INTO idempotency_keys(tenant_id,operation,request_key,response_json) VALUES(%s,%s,%s,%s)', (tenant, OPERATION, key, json.dumps({'digest': digest})))
        connection.commit()
        if receipt and receipt.get('issued'):
            item = _open(receipt['issued'], key + ':issued')
        else:
            from baas_issuance_handlers import _pricing_payload
            if str(data.get('confirmed_charge_credit') or '') != str(_pricing_payload(1, 'production')['charge_credit']):
                raise FlowError(409, 'mnsl_price_confirmation_required')
            submit = _context(context, {'product_id': product, 'count': 1, 'license_mode': 'single',
                                      'execution_mode': 'direct', 'atomicity': 'atomic', 'label': 'MNSL SSO enrollment'})
            submit['header:idempotency-key'] = key
            delegated = _delegation(connection, submit, identity, contract)
            from baas_issuance_handlers import issuance_submit
            response = issuance_submit(submit)
            issued = json.loads(response.body)
            if response.status_code >= 400:
                raise FlowError(response.status_code, str(issued.get('error') or 'mnsl_issue_failed'))
            items = issued.get('items') or []
            if len(items) != 1:
                raise FlowError(409, 'mnsl_request_in_progress')
            item = items[0]
            receipt = {'digest': digest, 'issued': _seal(item, key + ':issued')}
            with connection.cursor() as cursor:
                cursor.execute('UPDATE idempotency_keys SET response_json=%s WHERE tenant_id=%s AND operation=%s AND request_key=%s',
                               (json.dumps(receipt), tenant, OPERATION, key))
            connection.commit()
        if not re.fullmatch('[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}', str(item.get('product_key') or '')):
            raise FlowError(503, 'mnsl_issue_result_invalid')
        _provider(identity)  # Do not continue activation after SSO logout/expiry.
        activation_context = _context(context, {'api_action': 'activate', 'license_key': item['product_key'],
            'device_fingerprint': fingerprint, 'device_label': str(data.get('device_label') or 'MNSL device')[:100],
            'app_version': canonical['app_version']})
        from v2_handlers import _v2_activate
        activated_response = _v2_activate(activation_context, secrets.token_hex(16))
        activation = json.loads(activated_response.body)
        activated = activated_response.status_code < 400 and activation.get('success') is True
        result = {'ok': True, 'issued': True, 'activated': activated, 'product_key': item['product_key'],
                  'request_id': request_id, 'tenant_id': tenant, 'product_id': product,
                  'account_reference': _account(identity), 'activation': activation}
        if activated:
            receipt.update(sealed=_seal(result, key), response_expires=int(time.time()) + 300)
            with connection.cursor() as cursor:
                cursor.execute('UPDATE idempotency_keys SET response_json=%s WHERE tenant_id=%s AND operation=%s AND request_key=%s',
                               (json.dumps(receipt), tenant, OPERATION, key))
            connection.commit()
        return _reply(200, result)
    finally:
        try:
            if delegated:
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE tenant_sso_sessions SET revoked_at=UTC_TIMESTAMP() WHERE token_hash=%s', (delegated,))
                connection.commit()
        finally:
            try:
                if locked:
                    with connection.cursor() as cursor:
                        cursor.execute('SELECT RELEASE_LOCK(%s)', ('mnsl:' + key[5:55],))
            finally:
                connection.close()


def handle(context):
    try:
        host = _host(context)
        action = parse_qs(context.get('query', '')).get('action', [''])[-1]
        method = context.get('method', 'GET')
        if action == 'mnsl_start' and method == 'POST':
            challenge = _body(context).get('code_challenge', '')
            if not isinstance(challenge, str) or not re.fullmatch('[A-Za-z0-9_-]{43}', challenge):
                raise FlowError(400, 'invalid_code_challenge')
            now, ticket, polling = int(time.time()), _b64(secrets.token_bytes(24)), _b64(secrets.token_bytes(32))
            address = hashlib.sha256(str(context.get('client_address') or '').encode()).hexdigest()
            with _store() as rows:
                if len(rows) >= 1000 or sum(row.get('address') == address for row in rows.values()) >= 30:
                    raise FlowError(429, 'app_login_rate_limited')
                rows[ticket] = {'kind': KIND, 'host': host, 'created': now, 'expires': now+TTL, 'address': address,
                                'challenge': challenge, 'poll_hash': hashlib.sha256(polling.encode()).hexdigest()}
            return _reply(200, {'ok': True, 'ticket': ticket, 'poll_token': polling, 'expires_in': TTL,
                                'url': _endpoint(host)+'?action=mnsl_authorize&ticket='+ticket})
        if action == 'mnsl_poll' and method == 'POST':
            body = _body(context)
            ticket, polling, verifier = (body.get(k, '') for k in ('ticket', 'poll_token', 'code_verifier'))
            if not all(isinstance(v, str) for v in (ticket, polling, verifier)) or not re.fullmatch('[A-Za-z0-9._~-]{43,128}', verifier):
                raise FlowError(400, 'invalid_app_proof')
            with _store() as rows:
                row = _row(rows, ticket, host)
                if not hmac.compare_digest(row['poll_hash'], hashlib.sha256(polling.encode()).hexdigest()) or not hmac.compare_digest(row['challenge'], _b64(hashlib.sha256(verifier.encode()).digest())):
                    raise FlowError(401, 'invalid_app_proof')
                if row.get('consumed'):
                    raise FlowError(409, 'mnsl_grant_already_used')
                if not row.get('grant'):
                    return _reply(202, {'ok': True, 'pending': True})
                identity = _open(row['identity'], host+':'+ticket)
                grant = row['grant']
            _provider(identity)
            with _store() as rows:
                row = _row(rows, ticket, host)
                if row.get('consumed'):
                    raise FlowError(409, 'mnsl_grant_already_used')
                row.update(consumed=True)
                row.pop('grant', None)
            result = _open(grant, host+':'+ticket)
            result['account_reference'] = _account(identity)
            result['display_name'] = identity['display_name']
            return _reply(200, result)
        if action == 'mnsl_authorize' and method in ('GET', 'POST'):
            from mobile_admin_auth import _cookies
            ticket = parse_qs(context.get('query', '')).get('ticket', [''])[-1]
            with _store() as rows:
                row = dict(_row(rows, ticket, host))
            cookie = _cookies(context).get('tuti_mnsl_'+ticket, '')
            if not row.get('identity') or not row.get('browser_hash') or not hmac.compare_digest(row['browser_hash'], hashlib.sha256(cookie.encode()).hexdigest()):
                if method != 'GET':
                    raise FlowError(403, 'mnsl_browser_proof_required')
                from admin_oidc import start_tenant
                return start_tenant(dict(context, query='app_ticket='+ticket))
            identity = _open(row['identity'], host+':'+ticket)
            _provider(identity)
            if method == 'POST':
                body = _body(context)
                if context.get('header:origin') != 'https://'+host or not hmac.compare_digest(str(body.get('csrf') or ''), row['csrf']):
                    raise FlowError(403, 'csrf_rejected')
                token = _b64(secrets.token_bytes(32))
                with _store() as rows:
                    current = _row(rows, ticket, host)
                    if current.get('approved'):
                        raise FlowError(409, 'app_login_already_approved')
                    current.update(approved=True, token_hash=hashlib.sha256(token.encode()).hexdigest(),
                        grant=_seal({'ok': True, 'session_token': token, 'authenticated_until': identity['expires'],
                                     'auth_method': 'oidc_sso', 'purpose': KIND}, host+':'+ticket))
                return _reply(200, '<!doctype html><html lang="ja"><meta charset="utf-8"><title>MNSL SSO完了</title><h1>MNSLへ戻ってください</h1><p>ログインを許可しました。発行はソフト側で契約・製品を確認して実行します。</p></html>', True)
            page = '<!doctype html><html lang="ja"><meta charset="utf-8"><title>MNSLへのSSOログイン</title><h1>MNSLへのSSOログイン</h1><p>接続先：'+html.escape(host)+'</p><p>既存の契約・権限内でキー発行と端末のオンライン認証を行うための、5分間のログインです。この操作だけではキーを発行しません。</p><form method="post"><input type="hidden" name="csrf" value="'+html.escape(row['csrf'], quote=True)+'"><button>このMNSLへのログインを許可</button></form></html>'
            return _reply(200, page, True)
        if action in {'mnsl_contracts', 'mnsl_products', 'mnsl_issue'} and method == 'POST':
            identity = _identity(context)
            data = _body(context)
            if action == 'mnsl_issue':
                return _issue(context, identity, data)
            connection = database.connect()
            try:
                if action == 'mnsl_contracts':
                    contracts = [{'tenant_id': int(r['tenant_id']), 'name': str(r['name']), 'slug': str(r['slug']), 'environment': 'production'} for r in _contracts(connection, identity)]
                    return _reply(200, {'ok': True, 'contracts': contracts, 'account_reference': _account(identity)})
                tenant = _integer(data.get('tenant_id'))
                _contract(connection, identity, tenant)
                from baas_issuance_handlers import _pricing_payload
                return _reply(200, {'ok': True, 'products': _products(connection, tenant), 'pricing': _pricing_payload(1, 'production')})
            finally:
                connection.close()
        raise FlowError(405, 'mnsl_method_not_allowed')
    except FlowError as error:
        return _reply(error.status, {'ok': False, 'error': error.code})
    except Exception:
        return _reply(503, {'ok': False, 'error': 'mnsl_sso_service_unavailable'})
