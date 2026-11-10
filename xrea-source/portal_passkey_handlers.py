"""BaaS tenant portal WebAuthn and passkey session endpoints."""
from native_http import make_response, add_headers, legacy_compatible
from py36_compat import parse_iso_datetime
import hashlib
import json
import re
import secrets
import time
from datetime import datetime, timezone
import database
from core import PHP_TRIM_CHARS, php_int_cast
from http_utils import json_response
from v3_handlers import _assert_write_fence
RP_ID = '2415.jp'
ORIGINS = {'https://2415.jp', 'https://backup.2415.jp', 'https://sso.2415.jp'}
SCOPES = ['tenant:read', 'products:write', 'licenses:read', 'licenses:write']
REISSUE_FEE_UNITS = 500000

class PortalReissueError(Exception):
    pass

def _php_string(value):
    if value is None or value is False:
        return ''
    if value is True:
        return '1'
    if isinstance(value, (list, dict)):
        return 'Array'
    return str(value)

def _php_trim(value):
    return _php_string(value).strip(PHP_TRIM_CHARS)

def _registration_label(data):
    value = data.get('label')
    return _php_trim('Passkey' if value is None else value)[:80]

def _php_non_empty(value):
    """Match PHP !empty() for JSON values used as boolean flags."""
    if value is None or value is False or value == 0 or (value == 0.0) or (value == '') or (value == '0'):
        return False
    if isinstance(value, (list, dict)) and (not value):
        return False
    return True

def _scope_subset(raw):
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except (TypeError, ValueError):
        return []
    if not isinstance(value, list):
        return []
    return [scope for scope in SCOPES if scope in value]

def _management_key_allowed(client):
    key_kind = client.get('key_kind', 'standard')
    if key_kind is None:
        key_kind = 'standard'
    return key_kind == 'standard' and 'licenses:write' in _scope_subset(client.get('scopes_json'))

def _decode_json_or_empty(raw):
    """Match PHP json_decode(..., true) ?: [] used in portal responses."""
    try:
        value = json.loads(raw or 'null')
    except (TypeError, ValueError):
        return []
    return value if value else []

def _date(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=value.tzinfo or timezone.utc).astimezone(timezone.utc).timestamp()
    if not value:
        return 0
    try:
        parsed = parse_iso_datetime(str(value).replace('Z', '+00:00'))
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).timestamp()
    except ValueError:
        return 0

@legacy_compatible(callback_index=None, request_index=0)
def _body(request_context):
    from baas_handlers import _baas_json_input
    return _baas_json_input(request_context)

def _b64e(data):
    import base64
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

def _b64d(value):
    import base64
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]+', value):
        return None
    try:
        return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except Exception:
        return None

def _portal_passkey_session_recent(client):
    """Match PHP's five-minute age and 30-second future clock-skew gate."""
    if not _php_non_empty(client.get('portal_session_id')):
        return True
    authenticated_at = _date(client.get('portal_session_created_at'))
    if not authenticated_at:
        return False
    issued = int(authenticated_at)
    now = int(time.time())
    return issued >= now - 300 and issued <= now + 30

@legacy_compatible(callback_index=None, request_index=4)
def _challenge(connection, purpose, client=None, user_handle=None, request_context=None):
    from baas_handlers import _client_ip_hash
    token = _b64e(secrets.token_bytes(32))
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO tenant_portal_passkey_challenges(challenge_hash,purpose,tenant_id,client_id,user_handle,ip_hash,expires_at) VALUES(%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP()+INTERVAL 5 MINUTE)', (hashlib.sha256(token.encode()).hexdigest(), purpose, client.get('tenant_id') if client else None, client.get('id') if client else None, user_handle, _client_ip_hash(request_context or {})))
    return token

def _consume_challenge(connection, token, purpose):
    if not re.fullmatch('[A-Za-z0-9_-]{43}', token):
        raise ValueError('challenge_expired')
    digest = hashlib.sha256(token.encode()).hexdigest()
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT purpose,tenant_id,client_id,user_handle,expires_at FROM tenant_portal_passkey_challenges WHERE challenge_hash=%s LIMIT 1 FOR UPDATE', (digest,))
            row = cursor.fetchone()
            if not row or row.get('purpose') != purpose or int(_date(row.get('expires_at'))) < int(time.time()):
                raise ValueError('challenge_expired')
            cursor.execute('DELETE FROM tenant_portal_passkey_challenges WHERE challenge_hash=%s', (digest,))
        connection.commit()
        return row
    except Exception:
        connection.rollback()
        raise

def _client_data(encoded, expected, challenge):
    raw = _b64d(encoded)
    if raw is None or len(raw) > 16384:
        raise ValueError('invalid_client_data')
    try:
        value = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError('invalid_client_data') from exc
    if not isinstance(value, dict) or value.get('type') != expected or value.get('challenge') != challenge or (value.get('origin') not in ORIGINS) or (value.get('crossOrigin', False) is not False):
        raise ValueError('invalid_client_data')
    return raw

def _auth_data(raw, registration):
    from passkey_handlers import _authenticator_data
    if len(raw) < 37 or len(raw) > 8192 or hashlib.sha256(RP_ID.encode()).digest() != raw[:32]:
        raise ValueError('invalid_authenticator_data')
    if not raw[32] & 1 or not raw[32] & 4:
        raise ValueError('user_verification_required')
    if registration:
        if not raw[32] & 64 or len(raw) < 55:
            raise ValueError('invalid_attestation')
        credential_length = int.from_bytes(raw[53:55], 'big')
        if credential_length < 16 or credential_length > 1024 or 55 + credential_length >= len(raw):
            raise ValueError('invalid_attestation')
    try:
        result = _authenticator_data(raw, registration)
    except Exception as exc:
        message = str(exc)
        if message in {'user_verification_required', 'cbor_bounds', 'cbor_length', 'unsupported_cbor'}:
            raise ValueError(message) from exc
        if message in {'unsupported_key', 'invalid_key'}:
            raise ValueError('unsupported_credential') from exc
        if registration:
            raise ValueError('invalid_attestation') from exc
        raise ValueError('invalid_authenticator_data') from exc
    if registration:
        result['credential_id'] = result.pop('id')
        result['public_key_pem'] = result.pop('pem')
    return result

@legacy_compatible(callback_index=None, request_index=1)
def _rate_limit(connection, request_context):
    from baas_handlers import _client_ip_hash
    ip_hash = _client_ip_hash(request_context)
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM tenant_portal_passkey_attempts WHERE attempted_at<UTC_TIMESTAMP()-INTERVAL 1 HOUR')
        cursor.execute('DELETE FROM tenant_portal_passkey_challenges WHERE expires_at<UTC_TIMESTAMP()')
        cursor.execute('DELETE FROM tenant_portal_sessions WHERE expires_at<UTC_TIMESTAMP()-INTERVAL 30 DAY OR revoked_at<UTC_TIMESTAMP()-INTERVAL 30 DAY')
        cursor.execute('SELECT COUNT(*) AS n FROM tenant_portal_passkey_attempts WHERE ip_hash=%s AND attempted_at>=UTC_TIMESTAMP()-INTERVAL 1 MINUTE', (ip_hash,))
        row = cursor.fetchone() or {}
        if int(row.get('n') or 0) >= 20:
            raise PermissionError('rate_limited')
        cursor.execute('INSERT INTO tenant_portal_passkey_attempts(ip_hash) VALUES(%s)', (ip_hash,))

@legacy_compatible(callback_index=None, request_index=1)
def _portal_auth(connection, request_context, scope, operation):
    from baas_handlers import _authorize_key, _client_ip_hash
    token = _php_trim(request_context.get('header:x-tenant-portal-session'))
    if token:
        from baas_handlers import _authorize_portal_session
        return _authorize_portal_session(connection, request_context, scope, operation, _client_ip_hash(request_context), token)
    return _authorize_key(connection, request_context, scope, operation, secrets.token_hex(8))

@legacy_compatible(callback_index=None, request_index=1)
def _authorize_link_api_key(connection, request_context):
    """Match PHP's explicit removal of the portal-session header for link_tenant."""
    from baas_handlers import _authorize_key
    api_environ = dict(request_context)
    api_environ.pop('header:x-tenant-portal-session', None)
    return _authorize_key(connection, api_environ, 'tenant:read', 'portal_common_id.link_tenant', secrets.token_hex(8))

def _is_writable():
    role = str(__import__('os').environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    try:
        from ha_handlers import _effective_role
        effective = _effective_role()
    except Exception:
        effective = role
    return role == 'primary' and effective != 'maintenance' or (role == 'standby' and effective == 'promoted')

@legacy_compatible(callback_index=None, request_index=3)
def _reissue_key(connection, client, data, request_context):
    if not client.get('portal_session_id') or not client.get('portal_passkey_id'):
        raise PortalReissueError('passkey_session_required')
    if int(_date(client.get('portal_session_created_at'))) < int(time.time()) - 300:
        raise PortalReissueError('passkey_reauthentication_required')
    if not _is_writable():
        raise PortalReissueError('server_not_writable')
    fee_confirmation = data.get('confirm_fee_yen')
    if type(fee_confirmation) is not int or fee_confirmation != 500:
        raise PortalReissueError('key_reissue_fee_confirmation_required')
    request_key = str(request_context.get('header:idempotency-key', ''))
    if not re.fullmatch('[A-Za-z0-9_-]{32,80}', request_key):
        raise PortalReissueError('key_reissue_request_id_required')
    tenant_id, passkey_id = (int(client['tenant_id']), int(client['portal_passkey_id']))
    request_hash = hashlib.sha256(request_key.encode()).hexdigest()
    account_id = int(client.get('parent_tenant_id') or tenant_id)
    env = str(client.get('tenant_environment') or 'production')
    from v2_handlers import _runtime_config
    from core import key_pepper, token_secret
    config = _runtime_config()
    pepper = key_pepper(config).encode()
    secret = token_secret(config).encode()
    token = None
    replayed = False
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT id,status FROM tenants WHERE id=%s FOR UPDATE', (account_id,))
            account = cursor.fetchone()
            cursor.execute('SELECT id,status FROM tenants WHERE id=%s FOR UPDATE', (tenant_id,))
            owner = cursor.fetchone()
            if not account or account.get('status') != 'active' or (not owner) or (owner.get('status') != 'active'):
                raise PortalReissueError('key_reissue_not_available')
            cursor.execute('SELECT m.source_client_id,m.scopes_json,s.created_at FROM tenant_portal_sessions s JOIN tenant_portal_passkeys p ON p.id=s.passkey_id AND p.revoked_at IS NULL JOIN tenant_portal_memberships m ON m.passkey_id=s.passkey_id AND m.tenant_id=s.tenant_id WHERE s.token_hash=%s AND s.passkey_id=%s AND s.tenant_id=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP() FOR UPDATE', (client['portal_session_id'], passkey_id, tenant_id))
            credential = cursor.fetchone()
            if not credential:
                raise PortalReissueError('invalid_portal_session')
            if int(_date(credential.get('created_at'))) < int(time.time()) - 300:
                raise PortalReissueError('passkey_reauthentication_required')
            cursor.execute('SELECT * FROM tenant_portal_key_reissues WHERE tenant_id=%s AND request_hash=%s FOR UPDATE', (tenant_id, request_hash))
            receipt = cursor.fetchone()
            if receipt:
                if int(receipt['passkey_id']) != passkey_id:
                    raise PortalReissueError('key_reissue_request_owner_mismatch')
                if int(_date(receipt.get('response_expires_at'))) <= int(time.time()):
                    raise PortalReissueError('key_reissue_result_expired')
                cursor.execute("SELECT * FROM tenant_api_clients WHERE id=%s AND tenant_id=%s AND status='active' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP()) FOR UPDATE", (receipt['new_client_id'], tenant_id))
                replacement = cursor.fetchone()
                if not replacement:
                    raise PortalReissueError('key_reissue_result_expired')
                context = f'TUTI-PORTAL-KEY-REISSUE-V1|{tenant_id}|{passkey_id}|{request_hash}'
                key = ('baas_sandbox_' if env == 'sandbox' else 'baas_prod_') + _b64e(__import__('hmac').new(secret, context.encode(), hashlib.sha256).digest())
                expected = __import__('hmac').new(pepper, key.encode(), hashlib.sha256).hexdigest()
                if not __import__('hmac').compare_digest(str(replacement['key_hash']), expected):
                    raise PortalReissueError('key_reissue_result_expired')
                scopes = _scope_subset(replacement.get('scopes_json'))
                replayed = True
            else:
                source_id = int(credential['source_client_id'])
                cursor.execute("SELECT * FROM tenant_api_clients WHERE id=%s AND tenant_id=%s AND status='active' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP()) FOR UPDATE", (source_id, tenant_id))
                old = cursor.fetchone()
                if not old or old.get('key_kind', 'standard') != 'standard':
                    raise PortalReissueError('key_reissue_not_available')
                old_scopes = _scope_subset(old.get('scopes_json'))
                allowed = _scope_subset(credential.get('scopes_json'))
                try:
                    original_scopes = json.loads(old.get('scopes_json') or '[]')
                except ValueError:
                    original_scopes = []
                if not isinstance(original_scopes, list) or len(old_scopes) != len(original_scopes) or (not set(old_scopes).issubset(allowed)) or ('tenant:read' not in old_scopes):
                    raise PortalReissueError('key_reissue_scope_mismatch')
                period = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
                for _ in range(120):
                    bill_period = period.strftime('%Y-%m')
                    cursor.execute('SELECT status FROM api_billing_invoices WHERE account_tenant_id=%s AND billing_period=%s', (account_id, bill_period))
                    invoice = cursor.fetchone()
                    if not invoice or invoice.get('status') == 'draft':
                        break
                    period = (period.replace(day=28) + __import__('datetime').timedelta(days=4)).replace(day=1)
                else:
                    raise PortalReissueError('key_reissue_billing_unavailable')
                grace = datetime.fromtimestamp(time.time() + 3600, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                retry_until = datetime.fromtimestamp(time.time() + 600, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                context = f'TUTI-PORTAL-KEY-REISSUE-V1|{tenant_id}|{passkey_id}|{request_hash}'
                key = ('baas_sandbox_' if env == 'sandbox' else 'baas_prod_') + _b64e(__import__('hmac').new(secret, context.encode(), hashlib.sha256).digest())
                key_hash = __import__('hmac').new(pepper, key.encode(), hashlib.sha256).hexdigest()
                cursor.execute('INSERT INTO tenant_api_clients(tenant_id,name,key_prefix,key_hash,scopes_json,rate_limit_per_minute,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s)', (tenant_id, str(old['name'])[:120], key[:12], key_hash, json.dumps(old_scopes), min(600, int(old['rate_limit_per_minute'])), old.get('expires_at')))
                new_id = cursor.lastrowid
                cursor.execute("UPDATE tenant_api_clients SET status='retiring',replacement_client_id=%s,grace_expires_at=%s WHERE id=%s AND tenant_id=%s", (new_id, grace, source_id, tenant_id))
                cursor.execute('INSERT INTO tenant_portal_key_reissues(tenant_id,account_tenant_id,passkey_id,request_hash,source_client_id,new_client_id,amount_units,billing_period,grace_expires_at,response_expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', (tenant_id, account_id, passkey_id, request_hash, source_id, new_id, REISSUE_FEE_UNITS, bill_period, grace, retry_until))
                receipt_id = cursor.lastrowid
                for table in ('tenant_portal_memberships', 'tenant_portal_passkeys', 'tenant_portal_sessions'):
                    cursor.execute(f'UPDATE `{table}` SET source_client_id=%s WHERE tenant_id=%s AND source_client_id=%s', (new_id, tenant_id, source_id))
                receipt = {'id': receipt_id, 'new_client_id': new_id, 'billing_period': bill_period, 'grace_expires_at': grace, 'response_expires_at': retry_until}
                scopes = old_scopes
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    if not replayed:
        from ha_handlers import _append_ha_audit
        _append_ha_audit('tenant_portal_api_key_reissued', {'tenant_id': tenant_id, 'reissue_id': int(receipt['id']), 'new_client_id': int(receipt['new_client_id']), 'fee_yen': 500, 'billing_period': receipt['billing_period']}, request_context)
    from ha_handlers import ha_sync_peer
    sync = ha_sync_peer('tenant_portal_api_key_reissued', request_context)
    return {'ok': True, 'api_key': key, 'client_id': int(receipt['new_client_id']), 'scopes': scopes, 'fee_yen': 500, 'fee_tax_included': True, 'billing_period': receipt['billing_period'], 'old_key_expires_at_utc': receipt['grace_expires_at'], 'retry_until_utc': receipt['response_expires_at'], 'replayed': replayed, 'peer_synced': bool(sync.get('ok'))}

@legacy_compatible(callback_index=1, request_index=0)
def portal_passkey(request_context):
    from baas_handlers import BaaSError, _auth_scopes, _reply
    from ha_handlers import ha_sync_peer
    method = str(request_context.get('method', 'GET'))
    connection = None
    try:
        connection = database.connect()
        if method != 'POST':
            return json_response('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
        data = _body(request_context)
        action = str(data.get('action', ''))
        if action == 'sso_login':
            token = str(request_context.get('header:cookie', ''))
            match = re.search('(?:^|;\\s*)__Host-baas_common_id=([A-Za-z0-9_-]{43})(?:;|$)', token)
            if not match:
                return json_response('401 Unauthorized', {'ok': False, 'error': 'sso_login_required'})
            browser = match.group(1)
            try:
                with connection.cursor() as cursor:
                    for table in ('common_id_sso_browser_sessions', 'tenant_portal_memberships'):
                        cursor.execute('SELECT 1 FROM `' + table + '` LIMIT 0')
            except Exception:
                return json_response('503 Service Unavailable', {'ok': False, 'error': 'common_id_sso_not_ready'})
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('SELECT s.passkey_id,s.created_at FROM common_id_sso_browser_sessions s JOIN tenant_portal_passkeys p ON p.id=s.passkey_id AND p.revoked_at IS NULL WHERE s.session_hash=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP() LIMIT 1 FOR UPDATE', (hashlib.sha256(browser.encode()).hexdigest(),))
                identity = cursor.fetchone()
                if not identity:
                    connection.rollback()
                    return json_response('401 Unauthorized', {'ok': False, 'error': 'sso_login_required'})
                cursor.execute("SELECT m.tenant_id,m.source_client_id,m.scopes_json,t.slug,t.environment,t.parent_tenant_id FROM tenant_portal_memberships m JOIN tenants t ON t.id=m.tenant_id WHERE m.passkey_id=%s AND t.status='active' ORDER BY m.created_at,m.tenant_id", (identity['passkey_id'],))
                memberships = cursor.fetchall()
                if not memberships:
                    connection.rollback()
                    return json_response('403 Forbidden', {'ok': False, 'error': 'tenant_membership_required'})
                member = memberships[0]
                session = _b64e(secrets.token_bytes(32))
                cursor.execute('INSERT INTO tenant_portal_sessions(token_hash,passkey_id,tenant_id,source_client_id,created_at,expires_at) VALUES(%s,%s,%s,%s,%s,UTC_TIMESTAMP()+INTERVAL 12 HOUR)', (hashlib.sha256(session.encode()).hexdigest(), identity['passkey_id'], member['tenant_id'], member['source_client_id'], identity['created_at']))
            connection.commit()
            choices = [{'tenant_id': int(m['tenant_id']), 'slug': m['slug'], 'environment': 'sandbox' if m.get('parent_tenant_id') or str(m.get('environment')).lower() == 'sandbox' else 'production'} for m in memberships]
            environment = choices[0]['environment']
            return json_response('200 OK', {'ok': True, 'session_token': session, 'expires_in': 43200, 'tenant': {'slug': member['slug'], 'environment': environment}, 'memberships': choices, 'scopes': _decode_json_or_empty(member.get('scopes_json'))})
        if action == 'login_options':
            _rate_limit(connection, request_context)
            challenge = _challenge(connection, 'login', environ=request_context)
            return json_response('200 OK', {'ok': True, 'challenge': challenge, 'publicKey': {'challenge': challenge, 'rpId': RP_ID, 'timeout': 300000, 'userVerification': 'required'}})
        if action in {'register_options', 'register_finish', 'list', 'revoke', 'revoke_current', 'link_tenant', 'reissue_api_key'}:
            scope = 'tenant:read'
            client, headers = _portal_auth(connection, request_context, scope, 'portal_passkey.' + action)
        else:
            client, headers = (None, [])
        if action == 'register_options':
            if client.get('key_kind') in {'operator_admin', 'sample_sdk'}:
                return json_response('403 Forbidden', {'ok': False, 'error': 'api_key_cannot_register_portal_passkey'}, headers)
            if not _portal_passkey_session_recent(client):
                return json_response('428 Precondition Required', {'ok': False, 'error': 'passkey_reauthentication_required'}, headers)
            scopes = _scope_subset(client.get('scopes_json'))
            if 'tenant:read' not in scopes:
                return json_response('403 Forbidden', {'ok': False, 'error': 'tenant_read_scope_required'}, headers)
            with connection.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) AS n FROM tenant_portal_passkeys WHERE tenant_id=%s AND revoked_at IS NULL', (client['tenant_id'],))
                if int((cursor.fetchone() or {}).get('n') or 0) >= 25:
                    return json_response('409 Conflict', {'ok': False, 'error': 'passkey_limit_reached'}, headers)
            user = _b64e(secrets.token_bytes(32))
            challenge = _challenge(connection, 'register', client, user, request_context)
            return json_response('200 OK', {'ok': True, 'challenge': challenge, 'publicKey': {'challenge': challenge, 'rp': {'id': RP_ID, 'name': 'TUTI BaaS'}, 'user': {'id': user, 'name': 'tenant-' + str(client['tenant_id']), 'displayName': client.get('tenant_slug') or 'BaaS契約者'}, 'pubKeyCredParams': [{'type': 'public-key', 'alg': -7}], 'timeout': 300000, 'attestation': 'none', 'authenticatorSelection': {'residentKey': 'required', 'requireResidentKey': True, 'userVerification': 'required'}}}, headers)
        if action == 'register_finish':
            if client.get('key_kind') in {'operator_admin', 'sample_sdk'}:
                return json_response('403 Forbidden', {'ok': False, 'error': 'api_key_cannot_register_portal_passkey'}, headers)
            if not _portal_passkey_session_recent(client):
                return json_response('428 Precondition Required', {'ok': False, 'error': 'passkey_reauthentication_required'}, headers)
            if not _is_writable():
                return json_response('503 Service Unavailable', {'ok': False, 'error': 'server_not_writable'}, headers)
            challenge = _php_trim(data.get('challenge'))
            owner = _consume_challenge(connection, challenge, 'register')
            if int(owner.get('tenant_id') or 0) != int(client['tenant_id']) or int(owner.get('client_id') or 0) != int(client['id']):
                raise ValueError('challenge_owner_mismatch')
            response = data.get('response')
            if not isinstance(response, dict):
                raise ValueError('invalid_attestation')
            _client_data(response.get('clientDataJSON', ''), 'webauthn.create', challenge)
            encoded = _b64d(response.get('attestationObject', ''))
            if encoded is None:
                raise ValueError('invalid_attestation')
            from passkey_handlers import _cbor
            try:
                obj, _ = _cbor(encoded)
            except Exception as exc:
                raise ValueError('invalid_attestation') from exc
            if not isinstance(obj, dict) or obj.get('fmt') != 'none' or obj.get('attStmt') or (not isinstance(obj.get('authData'), bytes)):
                raise ValueError('invalid_attestation')
            auth = _auth_data(obj['authData'], True)
            raw_id = _b64d(data.get('id', ''))
            if raw_id is None or raw_id != auth['credential_id']:
                raise ValueError('credential_id_mismatch')
            handle = _b64d(owner.get('user_handle', ''))
            if handle is None:
                raise ValueError('invalid_user_handle')
            scopes = _scope_subset(client.get('scopes_json'))
            try:
                with connection.cursor() as cursor:
                    cursor.execute('INSERT INTO tenant_portal_passkeys(tenant_id,source_client_id,credential_id_hash,user_handle,public_key_pem,sign_count,scopes_json,label) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)', (client['tenant_id'], client['id'], hashlib.sha256(raw_id).hexdigest(), handle, auth['public_key_pem'], auth['count'], json.dumps(scopes), _registration_label(data)))
                    passkey_id = cursor.lastrowid
                    cursor.execute('INSERT INTO tenant_portal_memberships(passkey_id,tenant_id,source_client_id,scopes_json) VALUES(%s,%s,%s,%s)', (passkey_id, client['tenant_id'], client['id'], json.dumps(scopes)))
                connection.commit()
            except Exception as exc:
                connection.rollback()
                if getattr(exc, 'args', ()) and exc.args[0] == 1062:
                    return json_response('409 Conflict', {'ok': False, 'error': 'credential_already_registered'}, headers)
                raise
            from ha_handlers import _append_ha_audit
            _append_ha_audit('tenant_portal_passkey_registered', {'tenant_id': int(client['tenant_id']), 'credential_id_hash': hashlib.sha256(raw_id).hexdigest()}, request_context)
            sync = ha_sync_peer('tenant_portal_passkey_registered', request_context)
            return json_response('201 Created', {'ok': True, 'peer_synced': bool(sync.get('ok')), 'message': 'Passkeyを登録しました。次回からPasskeyで接続できます。'}, headers)
        if action == 'login_finish':
            _rate_limit(connection, request_context)
            create_sso = _php_non_empty(data.get('create_common_id_sso'))
            if create_sso:
                try:
                    with connection.cursor() as cursor:
                        for table in ('common_id_sso_browser_sessions', 'common_id_sso_requests', 'common_id_sso_codes', 'common_id_sso_tokens'):
                            cursor.execute('SELECT 1 FROM `' + table + '` LIMIT 0')
                except Exception:
                    return json_response('503 Service Unavailable', {'ok': False, 'error': 'common_id_sso_not_ready'})
            challenge = _php_trim(data.get('challenge'))
            raw_id = _b64d(data.get('id', ''))
            response = data.get('response')
            if raw_id is None or not isinstance(response, dict):
                raise ValueError('invalid_assertion')
            row = _consume_challenge(connection, challenge, 'login')
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM tenant_portal_passkeys WHERE credential_id_hash=%s AND revoked_at IS NULL LIMIT 1 FOR UPDATE', (hashlib.sha256(raw_id).hexdigest(),))
                key = cursor.fetchone()
                if not key:
                    raise ValueError('unknown_credential')
                client_data = _client_data(response.get('clientDataJSON', ''), 'webauthn.get', challenge)
                auth_raw = _b64d(response.get('authenticatorData', ''))
                signature = _b64d(response.get('signature', ''))
                if auth_raw is None or signature is None:
                    raise ValueError('invalid_assertion')
                auth = _auth_data(auth_raw, False)
                user = _b64d(response.get('userHandle', ''))
                if user is None or user != bytes(key['user_handle']):
                    raise ValueError('invalid_user_handle')
                if int(key['sign_count'] or 0) > 0 and auth['count'] > 0 and (auth['count'] <= int(key['sign_count'])):
                    raise ValueError('sign_count_invalid')
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import ec
                public = serialization.load_pem_public_key(key['public_key_pem'].encode() if isinstance(key['public_key_pem'], str) else key['public_key_pem'])
                try:
                    public.verify(signature, auth_raw + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
                except Exception as exc:
                    raise ValueError('signature_invalid') from exc
                cursor.execute('UPDATE tenant_portal_passkeys SET sign_count=%s,last_used_at=UTC_TIMESTAMP() WHERE id=%s', (auth['count'], key['id']))
                cursor.execute("SELECT m.tenant_id,m.source_client_id,m.scopes_json,t.slug,t.status,t.environment,t.parent_tenant_id FROM tenant_portal_memberships m JOIN tenants t ON t.id=m.tenant_id WHERE m.passkey_id=%s AND t.status='active' ORDER BY m.created_at,m.tenant_id", (key['id'],))
                memberships = cursor.fetchall()
                if not memberships:
                    raise ValueError('unknown_credential')
                member = memberships[0]
                token = _b64e(secrets.token_bytes(32))
                cursor.execute('INSERT INTO tenant_portal_sessions(token_hash,passkey_id,tenant_id,source_client_id,created_at,expires_at) VALUES(%s,%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP()+INTERVAL 12 HOUR)', (hashlib.sha256(token.encode()).hexdigest(), key['id'], member['tenant_id'], member['source_client_id']))
                sso_token = _b64e(secrets.token_bytes(32)) if create_sso else None
                if sso_token:
                    cursor.execute('INSERT INTO common_id_sso_browser_sessions(session_hash,passkey_id,expires_at) VALUES(%s,%s,UTC_TIMESTAMP()+INTERVAL 12 HOUR)', (hashlib.sha256(sso_token.encode()).hexdigest(), key['id']))
                cursor.execute('UPDATE tenant_portal_passkey_challenges SET expires_at=UTC_TIMESTAMP() WHERE challenge_hash=%s', (hashlib.sha256(challenge.encode()).hexdigest(),))
            connection.commit()
            choices = [{'tenant_id': int(m['tenant_id']), 'slug': m['slug'], 'environment': 'sandbox' if m.get('parent_tenant_id') or str(m.get('environment')).lower() == 'sandbox' else 'production'} for m in memberships]
            extra_headers = [('Set-Cookie', '__Host-baas_common_id=' + sso_token + '; Path=/; Max-Age=43200; Secure; HttpOnly; SameSite=Lax')] if sso_token else []
            return json_response('200 OK', {'ok': True, 'session_token': token, 'expires_in': 43200, 'tenant': {'slug': member['slug'], 'environment': choices[0]['environment']}, 'memberships': choices, 'scopes': _decode_json_or_empty(member.get('scopes_json'))}, extra_headers)
        if action == 'list':
            if not _management_key_allowed(client):
                return json_response('403 Forbidden', {'ok': False, 'error': 'passkey_management_key_required'}, headers)
            with connection.cursor() as cursor:
                cursor.execute('SELECT p.id,p.label,p.created_at,p.last_used_at FROM tenant_portal_memberships m JOIN tenant_portal_passkeys p ON p.id=m.passkey_id WHERE m.tenant_id=%s AND p.revoked_at IS NULL ORDER BY p.created_at DESC LIMIT 25', (client['tenant_id'],))
                rows = cursor.fetchall()
            from ha_handlers import _json_value
            return json_response('200 OK', {'ok': True, 'passkeys': _json_value(rows)}, headers)
        if action == 'reissue_api_key':
            try:
                result = _reissue_key(connection, client, data, request_context)
            except PortalReissueError:
                raise
            except Exception as exc:
                raise PortalReissueError('key_reissue_failed') from exc
            return json_response('200 OK', result, headers)
        if action == 'logout':
            token = _php_trim(request_context.get('header:x-tenant-portal-session'))
            if token:
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE tenant_portal_sessions SET revoked_at=UTC_TIMESTAMP() WHERE token_hash=%s AND revoked_at IS NULL', (hashlib.sha256(token.encode()).hexdigest(),))
            headers = []
            if _php_non_empty(data.get('end_common_id')):
                cookie = str(request_context.get('header:cookie', ''))
                match = re.search('(?:^|;\\s*)__Host-baas_common_id=([A-Za-z0-9_-]{43})(?:;|$)', cookie)
                if match:
                    with connection.cursor() as cursor:
                        cursor.execute('UPDATE common_id_sso_browser_sessions SET revoked_at=UTC_TIMESTAMP() WHERE session_hash=%s AND revoked_at IS NULL', (hashlib.sha256(match.group(1).encode()).hexdigest(),))
                headers.append(('Set-Cookie', '__Host-baas_common_id=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax'))
            return json_response('200 OK', {'ok': True}, headers)
        if action == 'revoke':
            if not _management_key_allowed(client):
                return json_response('403 Forbidden', {'ok': False, 'error': 'passkey_management_key_required'}, headers)
            if not _is_writable():
                return json_response('503 Service Unavailable', {'ok': False, 'error': 'server_not_writable'}, headers)
            passkey_id = php_int_cast(data.get('passkey_id'))
            if passkey_id < 1:
                return json_response('400 Bad Request', {'ok': False, 'error': 'invalid_passkey_id'}, headers)
            cookie = str(request_context.get('header:cookie', ''))
            match = re.search('(?:^|;\\s*)__Host-baas_common_id=([A-Za-z0-9_-]{43})(?:;|$)', cookie)
            clear_sso = False
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('UPDATE tenant_portal_passkeys p JOIN tenant_portal_memberships m ON m.passkey_id=p.id SET p.revoked_at=UTC_TIMESTAMP() WHERE p.id=%s AND m.tenant_id=%s AND p.revoked_at IS NULL', (passkey_id, client['tenant_id']))
                affected = int(cursor.rowcount or 0)
                if match:
                    cursor.execute('SELECT 1 FROM common_id_sso_browser_sessions WHERE session_hash=%s AND passkey_id=%s LIMIT 1', (hashlib.sha256(match.group(1).encode()).hexdigest(), passkey_id))
                    clear_sso = bool(cursor.fetchone())
                if affected:
                    cursor.execute('UPDATE tenant_portal_sessions SET revoked_at=UTC_TIMESTAMP() WHERE passkey_id=%s AND revoked_at IS NULL', (passkey_id,))
                    cursor.execute('UPDATE common_id_sso_browser_sessions SET revoked_at=UTC_TIMESTAMP() WHERE passkey_id=%s AND revoked_at IS NULL', (passkey_id,))
            connection.commit()
            sync = ha_sync_peer('tenant_portal_passkey_revoked', request_context)
            if clear_sso:
                headers.append(('Set-Cookie', '__Host-baas_common_id=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax'))
            return json_response('200 OK', {'ok': True, 'revoked': affected > 0, 'peer_synced': bool(sync.get('ok'))}, headers)
        if action == 'revoke_current':
            if not client.get('portal_passkey_id'):
                return json_response('403 Forbidden', {'ok': False, 'error': 'passkey_session_required'}, headers)
            if not _portal_passkey_session_recent(client):
                return json_response('428 Precondition Required', {'ok': False, 'error': 'passkey_reauthentication_required'}, headers)
            if not _is_writable():
                return json_response('503 Service Unavailable', {'ok': False, 'error': 'server_not_writable'}, headers)
            passkey_id = int(client['portal_passkey_id'])
            cookie = str(request_context.get('header:cookie', ''))
            match = re.search('(?:^|;\\s*)__Host-baas_common_id=([A-Za-z0-9_-]{43})(?:;|$)', cookie)
            clear_sso = False
            connection.begin()
            with connection.cursor() as cursor:
                if match:
                    cursor.execute('SELECT 1 FROM common_id_sso_browser_sessions WHERE session_hash=%s AND passkey_id=%s LIMIT 1', (hashlib.sha256(match.group(1).encode()).hexdigest(), passkey_id))
                    clear_sso = bool(cursor.fetchone())
                cursor.execute('UPDATE tenant_portal_passkeys SET revoked_at=UTC_TIMESTAMP() WHERE id=%s AND revoked_at IS NULL', (passkey_id,))
                cursor.execute('UPDATE tenant_portal_sessions SET revoked_at=UTC_TIMESTAMP() WHERE passkey_id=%s AND revoked_at IS NULL', (passkey_id,))
                cursor.execute('UPDATE common_id_sso_browser_sessions SET revoked_at=UTC_TIMESTAMP() WHERE passkey_id=%s AND revoked_at IS NULL', (passkey_id,))
            connection.commit()
            sync = ha_sync_peer('tenant_portal_passkey_revoked', request_context)
            if clear_sso:
                headers.append(('Set-Cookie', '__Host-baas_common_id=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax'))
            return json_response('200 OK', {'ok': True, 'peer_synced': bool(sync.get('ok'))}, headers)
        if action == 'switch_tenant':
            old_token = _php_trim(request_context.get('header:x-tenant-portal-session'))
            target = php_int_cast(data.get('tenant_id'))
            if not re.fullmatch('[A-Za-z0-9_-]{40,60}', old_token) or target < 1:
                return json_response('400 Bad Request', {'ok': False, 'error': 'invalid_tenant_selection'})
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('SELECT s.passkey_id,s.created_at FROM tenant_portal_sessions s JOIN tenant_portal_passkeys p ON p.id=s.passkey_id AND p.revoked_at IS NULL WHERE s.token_hash=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP() LIMIT 1 FOR UPDATE', (hashlib.sha256(old_token.encode()).hexdigest(),))
                old = cursor.fetchone()
                if not old:
                    raise ValueError('invalid_portal_session')
                cursor.execute('SELECT m.source_client_id,m.scopes_json,t.slug,t.status,t.environment,t.parent_tenant_id FROM tenant_portal_memberships m JOIN tenants t ON t.id=m.tenant_id WHERE m.passkey_id=%s AND m.tenant_id=%s LIMIT 1', (old['passkey_id'], target))
                member = cursor.fetchone()
                if not member or member.get('status') != 'active':
                    raise ValueError('tenant_membership_required')
                new_token = _b64e(secrets.token_bytes(32))
                cursor.execute('INSERT INTO tenant_portal_sessions(token_hash,passkey_id,tenant_id,source_client_id,created_at,expires_at) VALUES(%s,%s,%s,%s,%s,UTC_TIMESTAMP()+INTERVAL 12 HOUR)', (hashlib.sha256(new_token.encode()).hexdigest(), old['passkey_id'], target, member['source_client_id'], old['created_at']))
                cursor.execute('UPDATE tenant_portal_sessions SET revoked_at=UTC_TIMESTAMP() WHERE token_hash=%s', (hashlib.sha256(old_token.encode()).hexdigest(),))
            connection.commit()
            env = 'sandbox' if member.get('parent_tenant_id') or str(member.get('environment')).lower() == 'sandbox' else 'production'
            return json_response('200 OK', {'ok': True, 'session_token': new_token, 'expires_in': 43200, 'tenant': {'slug': member['slug'], 'environment': env}, 'scopes': _decode_json_or_empty(member.get('scopes_json'))})
        if action == 'link_tenant':
            token = _php_trim(request_context.get('header:x-tenant-portal-session'))
            if not re.fullmatch('[A-Za-z0-9_-]{40,60}', token):
                return json_response('401 Unauthorized', {'ok': False, 'error': 'invalid_portal_session'})
            with connection.cursor() as cursor:
                cursor.execute('SELECT s.passkey_id,s.created_at FROM tenant_portal_sessions s JOIN tenant_portal_passkeys p ON p.id=s.passkey_id AND p.revoked_at IS NULL WHERE s.token_hash=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP() LIMIT 1', (hashlib.sha256(token.encode()).hexdigest(),))
                identity = cursor.fetchone()
            if not identity:
                return json_response('401 Unauthorized', {'ok': False, 'error': 'invalid_portal_session'})
            if int(_date(identity.get('created_at'))) < int(time.time()) - 300:
                return json_response('428 Precondition Required', {'ok': False, 'error': 'passkey_reauthentication_required'})
            client, headers = _authorize_link_api_key(connection, request_context)
            if client.get('key_kind') != 'standard' or 'tenant:read' not in _scope_subset(client.get('scopes_json')):
                return json_response('403 Forbidden', {'ok': False, 'error': 'tenant_api_key_required'}, headers)
            if not _is_writable():
                return json_response('503 Service Unavailable', {'ok': False, 'error': 'server_not_writable'}, headers)
            try:
                with connection.cursor() as cursor:
                    cursor.execute('INSERT INTO tenant_portal_memberships(passkey_id,tenant_id,source_client_id,scopes_json) VALUES(%s,%s,%s,%s)', (identity['passkey_id'], client['tenant_id'], client['id'], json.dumps(_scope_subset(client.get('scopes_json')))))
                connection.commit()
            except Exception as exc:
                connection.rollback()
                if getattr(exc, 'args', ()) and exc.args[0] == 1062:
                    return json_response('409 Conflict', {'ok': False, 'error': 'tenant_already_linked'}, headers)
                raise
            from ha_handlers import _append_ha_audit
            _append_ha_audit('tenant_common_id_membership_added', {'tenant_id': int(client['tenant_id']), 'passkey_id': int(identity['passkey_id'])}, request_context)
            sync = ha_sync_peer('tenant_common_id_membership_added', request_context)
            return json_response('201 Created', {'ok': True, 'tenant': {'tenant_id': int(client['tenant_id']), 'slug': client['tenant_slug'], 'environment': client['tenant_environment']}, 'peer_synced': bool(sync.get('ok'))}, headers)
        return json_response('400 Bad Request', {'ok': False, 'error': 'invalid_action'})
    except PortalReissueError as exc:
        status = 403 if str(exc) in {'passkey_session_required', 'key_reissue_request_owner_mismatch', 'key_reissue_scope_mismatch'} else 428 if str(exc) == 'passkey_reauthentication_required' else 409
        allowed = {'passkey_session_required', 'passkey_reauthentication_required', 'server_not_writable', 'key_reissue_fee_confirmation_required', 'key_reissue_request_id_required', 'key_reissue_not_available', 'invalid_portal_session', 'key_reissue_request_owner_mismatch', 'key_reissue_result_expired', 'key_reissue_scope_mismatch', 'key_reissue_billing_unavailable'}
        return json_response(f"{status} {('Forbidden' if status == 403 else 'Precondition Required' if status == 428 else 'Conflict')}", {'ok': False, 'error': str(exc) if str(exc) in allowed else 'key_reissue_failed'})
    except BaaSError as exc:
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except PermissionError:
        return json_response('429 Too Many Requests', {'ok': False, 'error': 'rate_limited'}, [('Retry-After', '60')])
    except ValueError as exc:
        code = str(exc)
        if code == 'request_too_large':
            return json_response('413 Payload Too Large', {'ok': False, 'error': code})
        if code == 'invalid_portal_session':
            return json_response('401 Unauthorized', {'ok': False, 'error': code})
        if code == 'tenant_membership_required':
            return json_response('403 Forbidden', {'ok': False, 'error': code})
        return json_response('400 Bad Request', {'ok': False, 'error': code})
    except database.DatabaseConfigurationError:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'passkey_operation_failed'})
    finally:
        if connection:
            connection.close()
