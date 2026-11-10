"""Python ports of selected BaaS v1 routes and API-key authorization."""
from native_http import make_response, add_headers, legacy_compatible
from py36_compat import parse_iso_datetime
import hashlib
import hmac
import ipaddress
import base64
import json
import os
import re
import secrets
import ssl
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen
import database
from core import key_pepper, parse_utc_datetime
from http_utils import RequestError, json_response
from migration_config import secret_value
from v3_handlers import _assert_write_fence
_MAX_CLIENT_REQUESTS_PER_MINUTE = 600
_MAX_TENANT_REQUESTS_PER_MINUTE = 3000

class BaaSError(Exception):

    def __init__(self, status, error, extra=None):
        super().__init__(error)
        self.status = status
        self.error = error
        self.extra = extra or {}

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status, payload, headers=()):
    status_text = {200: '200 OK', 201: '201 Created', 202: '202 Accepted', 400: '400 Bad Request', 401: '401 Unauthorized', 403: '403 Forbidden', 404: '404 Not Found', 409: '409 Conflict', 410: '410 Gone', 405: '405 Method Not Allowed', 413: '413 Payload Too Large', 415: '415 Unsupported Media Type', 207: '207 Multi-Status', 429: '429 Too Many Requests', 500: '500 Internal Server Error', 501: '501 Not Implemented', 503: '503 Service Unavailable'}.get(status, '%d Error' % status)

    def json_safe(value):
        if isinstance(value, dict):
            return {key: json_safe(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [json_safe(item) for item in value]
        if isinstance(value, datetime):
            return value.strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(value, date):
            return value.isoformat()
        if isinstance(value, Decimal):
            return int(value) if value == value.to_integral_value() else float(value)
        return value
    body = json_safe(dict(payload))
    body.setdefault('request_id', uuid.uuid4().hex[:16])
    body.setdefault('api_version', 'baas-v1.1')
    if status >= 400:
        body['ok'] = False
        body.setdefault('error_code', str(body.get('error', 'request_failed')).upper())
    return json_response(status_text, body, headers)

@legacy_compatible(callback_index=None, request_index=0)
def _client_ip_hash(request_context):
    return hashlib.sha256(str(request_context.get('client_address', '')).encode('utf-8')).hexdigest()

def _attempt(connection, client, prefix, operation, outcome, status, ip_hash, issuance_session=None):
    try:
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO tenant_api_attempts(tenant_id,client_id,key_prefix,operation,outcome,status_code,ip_hash,issuance_session_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)', (int(client['tenant_id']) if client else None, int(client['id']) if client else None, prefix[:12], operation[:64], outcome, status, ip_hash, issuance_session))
        connection.commit()
    except Exception:
        connection.rollback()

def _column_value(row):
    if isinstance(row, dict) and row:
        return next(iter(row.values()))
    return 0

@legacy_compatible(callback_index=None, request_index=1)
def _environment(client, request_context, connection, operation, prefix, ip_hash):
    stored = str(client.get('tenant_environment') or '').strip().lower()
    environment = 'sandbox' if client.get('parent_tenant_id') or stored == 'sandbox' else 'production' if stored == 'production' else 'unknown'
    if environment == 'unknown':
        _attempt(connection, client, prefix, operation, 'tenant_environment_invalid', 409, ip_hash)
        raise BaaSError(409, 'tenant_environment_invalid')
    requested = str(request_context.get('header:x-baas-environment', 'production')).strip().lower()
    if requested not in ('production', 'sandbox'):
        raise BaaSError(400, 'invalid_environment')
    if requested != environment:
        _attempt(connection, client, prefix, operation, 'environment_mismatch', 409, ip_hash)
        raise BaaSError(409, 'environment_mismatch', {'requested_environment': requested, 'key_environment': environment})
    return environment

@legacy_compatible(callback_index=None, request_index=1)
def _auth_environment(client, request_context, connection, operation, prefix, ip_hash):
    stored = str(client.get('tenant_environment', client.get('environment')) or '').strip().lower()
    environment = 'sandbox' if client.get('parent_tenant_id') or stored == 'sandbox' else 'production' if stored == 'production' else 'unknown'
    if environment == 'unknown':
        _attempt(connection, client, prefix, operation, 'tenant_environment_invalid', 409, ip_hash)
        raise BaaSError(409, 'tenant_environment_invalid')
    requested = str(request_context.get('header:x-baas-environment', 'production')).strip().lower()
    if requested not in ('production', 'sandbox'):
        raise BaaSError(400, 'invalid_environment')
    if requested != environment:
        _attempt(connection, client, prefix, operation, 'environment_mismatch', 409, ip_hash)
        raise BaaSError(409, 'environment_mismatch', {'requested_environment': requested, 'tenant_environment': environment})
    return (environment, [('X-BaaS-Auth-Mode', ''), ('X-BaaS-Environment', requested)])

def _decode_admin_session(session):
    if not isinstance(session, str):
        return None
    if re.fullmatch('([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)', session) is None:
        return None
    encoded, signature = session.split('.', 1)
    sync_token = secret_value('ha_sync_token')
    if len(sync_token.strip()) < 32:
        return None
    try:
        payload = base64.urlsafe_b64decode(encoded + '=' * ((4 - len(encoded) % 4) % 4))
        provided_signature = base64.urlsafe_b64decode(signature + '=' * ((4 - len(signature) % 4) % 4))
        derived_key = hmac.new(sync_token.encode(), b'tuti-license-ha/admin-session/v1', hashlib.sha256).digest()
        expected = hmac.new(derived_key, encoded.encode('ascii'), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, provided_signature):
            return None
        claims = json.loads(payload.decode('utf-8'))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(claims, dict) or claims.get('purpose') != 'ha_admin':
        return None
    try:
        if int(claims.get('expires') or 0) < int(time.time()):
            return None
    except (TypeError, ValueError):
        return None
    if claims.get('auth_source') != 'oidc_sso':
        return None
    from admin_oidc import session_active
    if claims.get('source') == 'mnsl_sso':
        from admin_oidc import TENANT_CLIENT_ID
        active = session_active(str(claims.get('oidc_sid') or ''), TENANT_CLIENT_ID)
    else:
        active = session_active(str(claims.get('oidc_sid') or ''))
    if not active:
        return None
    return claims

def _admin_role(connection, claims):
    credential_hash = str(claims.get('credential_id_hash') or '').lower()
    if re.fullmatch('[a-f0-9]{64}', credential_hash):
        with connection.cursor() as cursor:
            cursor.execute("SELECT role_name FROM admin_principals WHERE credential_id_hash=%s AND status='active' AND revoked_at IS NULL LIMIT 1", (credential_hash,))
            row = cursor.fetchone()
        return str(row.get('role_name')) if row and row.get('role_name') else None
    if claims.get('recovery_code_auth') and claims.get('client') == 'ha':
        return 'ha-admin'
    if claims.get('source') == 'admin_api' and claims.get('admin_role') in ('viewer', 'operator', 'security-admin', 'ha-admin'):
        return str(claims['admin_role'])
    return None

def _role_allows_scope(role, scope):
    allowed = {'license:read': {'viewer', 'operator', 'security-admin', 'ha-admin'}, 'audit:read': {'viewer', 'operator', 'security-admin', 'ha-admin'}, 'license:write': {'operator', 'security-admin', 'ha-admin'}, 'phone:manage': {'operator', 'security-admin', 'ha-admin'}, 'license:manage': {'security-admin', 'ha-admin'}, 'admin:manage': {'security-admin', 'ha-admin'}, 'intake:manage': {'operator', 'security-admin', 'ha-admin'}, 'passkey:manage': {'security-admin', 'ha-admin'}, 'offline:issue': {'security-admin', 'ha-admin'}, 'ha:operate': {'ha-admin'}, 'ha:promote': {'ha-admin'}, 'tenant:read': {'operator', 'security-admin', 'ha-admin'}, 'licenses:read': {'operator', 'security-admin', 'ha-admin'}, 'licenses:write': {'operator', 'security-admin', 'ha-admin'}, 'products:write': {'security-admin', 'ha-admin'}}
    return role in allowed.get(scope, set())

@legacy_compatible(callback_index=None, request_index=1)
def _authorize_admin_session(connection, request_context, scope, operation, ip_hash, session):
    claims = _decode_admin_session(session)
    session_id = hashlib.sha256(session.encode()).hexdigest()[:32]
    prefix = 'admin-passkey'
    if claims is None:
        _attempt(connection, None, prefix, operation, 'invalid_admin_session', 401, ip_hash, session_id)
        raise BaaSError(401, 'invalid_admin_session')
    claim_scopes = claims.get('scope', [])
    if not isinstance(claim_scopes, list):
        claim_scopes = [claim_scopes]
    if claims.get('client') not in ('desktop', 'admin_mobile') or 'tenant:api' not in claim_scopes:
        _attempt(connection, None, prefix, operation, 'admin_scope_required', 403, ip_hash, session_id)
        raise BaaSError(403, 'admin_scope_required')
    tenant_text = str(request_context.get('header:x-tenant-id', '')).strip()
    if re.fullmatch('[1-9][0-9]{0,18}', tenant_text) is None:
        _attempt(connection, None, prefix, operation, 'tenant_id_required', 400, ip_hash, session_id)
        raise BaaSError(400, 'tenant_id_required')
    tenant_id = int(tenant_text)
    with connection.cursor() as cursor:
        cursor.execute('SELECT id,slug,status,environment,parent_tenant_id FROM tenants WHERE id=%s LIMIT 1', (tenant_id,))
        tenant = cursor.fetchone()
    if not tenant or tenant.get('status') != 'active':
        _attempt(connection, {'id': 0, 'tenant_id': tenant_id}, prefix, operation, 'tenant_not_found', 404, ip_hash, session_id)
        raise BaaSError(404, 'tenant_not_found')
    environment, response_headers = _auth_environment(tenant, request_context, connection, operation, prefix, ip_hash)
    role = _admin_role(connection, claims)
    admin_scopes = {'tenant:read', 'products:write', 'licenses:read', 'licenses:write'}
    if scope not in admin_scopes or scope not in claim_scopes or (not _role_allows_scope(role, scope)):
        client = {'id': 0, 'tenant_id': tenant_id}
        _attempt(connection, client, prefix, operation, 'admin_scope_required', 403, ip_hash, session_id)
        raise BaaSError(403, 'admin_scope_required', {'required_scope': scope})
    client = {'id': 0, 'tenant_id': tenant_id, 'tenant_slug': str(tenant['slug']), 'tenant_status': 'active', 'tenant_environment': environment, 'parent_tenant_id': tenant.get('parent_tenant_id'), 'status': 'active', 'revoked_at': None, 'key_hash': 'admin-session', 'key_prefix': prefix, 'rate_limit_per_minute': 300, 'key_kind': 'operator_admin', 'policy_json': None, 'scopes_json': json.dumps(sorted(admin_scopes)), 'expires_at': None, 'admin_session_id': session_id}
    response_headers[0] = ('X-BaaS-Auth-Mode', 'admin-passkey')
    _attempt(connection, client, prefix, operation, 'authorized_admin', 200, ip_hash, session_id)
    return (client, response_headers)

def _auth_scopes(raw):
    try:
        scopes = json.loads(str(raw or '[]'))
    except (TypeError, json.JSONDecodeError):
        return []
    return scopes if isinstance(scopes, list) else []

@legacy_compatible(callback_index=None, request_index=1)
def _authorize_portal_session(connection, request_context, scope, operation, ip_hash, session_token):
    prefix = 'portal-passkey'
    if re.fullmatch('[A-Za-z0-9_-]{40,60}', session_token) is None:
        _attempt(connection, None, prefix, operation, 'invalid_portal_session', 401, ip_hash)
        raise BaaSError(401, 'invalid_portal_session')
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    with connection.cursor() as cursor:
        cursor.execute('SELECT s.passkey_id,s.tenant_id,m.source_client_id,s.expires_at,s.created_at,m.scopes_json,p.revoked_at AS passkey_revoked,t.slug AS tenant_slug,t.status AS tenant_status,t.environment AS tenant_environment,t.parent_tenant_id FROM tenant_portal_sessions s JOIN tenant_portal_passkeys p ON p.id=s.passkey_id JOIN tenant_portal_memberships m ON m.passkey_id=s.passkey_id AND m.tenant_id=s.tenant_id JOIN tenants t ON t.id=s.tenant_id WHERE s.token_hash=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP() LIMIT 1', (token_hash,))
        row = cursor.fetchone()
    if not row or row.get('passkey_revoked') or row.get('tenant_status') != 'active':
        _attempt(connection, None, prefix, operation, 'invalid_portal_session', 401, ip_hash)
        raise BaaSError(401, 'invalid_portal_session')
    environment, response_headers = _auth_environment(row, request_context, connection, operation, prefix, ip_hash)
    scopes = _auth_scopes(row.get('scopes_json'))
    if scope not in scopes:
        client = {'id': int(row['source_client_id']), 'tenant_id': int(row['tenant_id'])}
        _attempt(connection, client, prefix, operation, 'insufficient_scope', 403, ip_hash)
        raise BaaSError(403, 'insufficient_scope', {'required_scope': scope})
    with connection.cursor() as cursor:
        cursor.execute('UPDATE tenant_portal_sessions SET last_used_at=UTC_TIMESTAMP() WHERE token_hash=%s', (token_hash,))
    connection.commit()
    client = {'id': int(row['source_client_id']), 'tenant_id': int(row['tenant_id']), 'tenant_slug': str(row['tenant_slug']), 'tenant_status': 'active', 'tenant_environment': environment, 'parent_tenant_id': row.get('parent_tenant_id'), 'status': 'active', 'revoked_at': None, 'key_hash': 'portal-passkey', 'key_prefix': prefix, 'rate_limit_per_minute': 300, 'key_kind': 'portal_user', 'policy_json': None, 'scopes_json': json.dumps(scopes), 'expires_at': None, 'portal_session_id': token_hash, 'portal_passkey_id': int(row['passkey_id']), 'portal_session_created_at': str(row['created_at'])}
    response_headers[0] = ('X-BaaS-Auth-Mode', 'tenant-passkey')
    _attempt(connection, client, prefix, operation, 'authorized_passkey', 200, ip_hash)
    return (client, response_headers)

def _oidc_session_active(session_id):
    secret = secret_value('admin_oidc_sso_client_secret')
    if len(secret) < 32 or re.fullmatch('[a-f0-9]{64}', str(session_id)) is None:
        return False
    credentials = base64.b64encode(('tuti-admin-portal:' + secret).encode()).decode('ascii')
    request = Request('https://sso.2415.jp/session/introspect', data=urlencode({'sid': session_id}).encode('ascii'), headers={'Authorization': 'Basic ' + credentials, 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json'}, method='POST')
    try:
        with urlopen(request, timeout=15, context=ssl.create_default_context()) as response:
            if not 200 <= response.status < 300:
                return False
            result = json.loads(response.read(65536).decode('utf-8'))
        return isinstance(result, dict) and result.get('active') is True and (int(result.get('expires_at') or 0) > int(time.time()))
    except Exception:
        return False

@legacy_compatible(callback_index=None, request_index=1)
def _authorize_sso_session(connection, request_context, scope, operation, ip_hash, session_token):
    prefix = 'tenant-sso'
    if re.fullmatch('[A-Za-z0-9_-]{43}', session_token) is None:
        _attempt(connection, None, prefix, operation, 'invalid_tenant_sso_session', 401, ip_hash)
        raise BaaSError(401, 'tenant_sso_session_required')
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    with connection.cursor() as cursor:
        # A one-time grant supplies its own fixed scopes; the linked standard key must still be live.
        cursor.execute("SELECT s.subject_hash,s.oidc_sid,s.sso_checked_at,s.tenant_id,s.expires_at,s.created_at,COALESCE(g.source_client_id,m.source_client_id) source_client_id,COALESCE(g.scopes_json,m.scopes_json) scopes_json,COALESCE(g.scopes_json,linked_key.scopes_json) AS linked_scopes_json,t.slug AS tenant_slug,t.status AS tenant_status,t.environment AS tenant_environment,t.parent_tenant_id FROM tenant_sso_sessions s LEFT JOIN tenant_sso_memberships m ON m.subject_hash=s.subject_hash AND m.tenant_id=s.tenant_id LEFT JOIN tenant_sso_temporary_grants g ON g.session_token_hash=s.token_hash AND g.subject_hash=s.subject_hash AND g.tenant_id=s.tenant_id AND g.expires_at>UTC_TIMESTAMP() AND g.revoked_at IS NULL JOIN tenant_api_clients linked_key ON linked_key.id=COALESCE(g.source_client_id,m.source_client_id) AND linked_key.tenant_id=s.tenant_id AND linked_key.key_hash IS NOT NULL AND linked_key.key_hash<>'' AND linked_key.status IN ('active','retiring') AND linked_key.revoked_at IS NULL AND (linked_key.expires_at IS NULL OR linked_key.expires_at>UTC_TIMESTAMP()) AND (linked_key.status='active' OR linked_key.grace_expires_at>UTC_TIMESTAMP()) JOIN tenants t ON t.id=s.tenant_id WHERE s.token_hash=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP() AND (m.subject_hash IS NOT NULL OR g.grant_id IS NOT NULL) LIMIT 1", (token_hash,))
        row = cursor.fetchone()
    if not row or row.get('tenant_status') != 'active':
        _attempt(connection, None, prefix, operation, 'invalid_tenant_sso_session', 401, ip_hash)
        raise BaaSError(401, 'tenant_sso_session_required')
    checked = parse_utc_datetime(str(row.get('sso_checked_at') or ''))
    if checked is None or checked < datetime.now(timezone.utc) - timedelta(seconds=30):
        if not _oidc_session_active(str(row.get('oidc_sid') or '')):
            with connection.cursor() as cursor:
                cursor.execute('UPDATE tenant_sso_sessions SET revoked_at=UTC_TIMESTAMP() WHERE token_hash=%s', (token_hash,))
            connection.commit()
            _attempt(connection, None, prefix, operation, 'sso_session_revoked', 401, ip_hash)
            raise BaaSError(401, 'tenant_sso_session_required')
        with connection.cursor() as cursor:
            cursor.execute('UPDATE tenant_sso_sessions SET sso_checked_at=UTC_TIMESTAMP() WHERE token_hash=%s', (token_hash,))
        connection.commit()
    environment, response_headers = _auth_environment(row, request_context, connection, operation, prefix, ip_hash)
    scopes = [scope for scope in _auth_scopes(row.get('scopes_json')) if scope in _auth_scopes(row.get('linked_scopes_json'))]
    if scope not in scopes:
        client = {'id': int(row['source_client_id']), 'tenant_id': int(row['tenant_id'])}
        _attempt(connection, client, prefix, operation, 'insufficient_scope', 403, ip_hash)
        raise BaaSError(403, 'insufficient_scope', {'required_scope': scope})
    with connection.cursor() as cursor:
        cursor.execute('UPDATE tenant_sso_sessions SET last_used_at=UTC_TIMESTAMP() WHERE token_hash=%s', (token_hash,))
    connection.commit()
    client = {'id': int(row['source_client_id']), 'tenant_id': int(row['tenant_id']), 'tenant_slug': str(row['tenant_slug']), 'tenant_status': 'active', 'tenant_environment': environment, 'parent_tenant_id': row.get('parent_tenant_id'), 'status': 'active', 'revoked_at': None, 'key_hash': 'tenant-sso-session', 'key_prefix': prefix, 'rate_limit_per_minute': 300, 'key_kind': 'tenant_sso', 'policy_json': None, 'scopes_json': json.dumps(scopes), 'expires_at': None, 'portal_session_id': token_hash, 'portal_session_created_at': str(row['created_at']), 'tenant_sso_session_id': token_hash, 'sso_oidc_sid': str(row.get('oidc_sid') or ''), 'sso_subject_hash': str(row.get('subject_hash') or '')}
    response_headers[0] = ('X-BaaS-Auth-Mode', 'tenant-sso')
    _attempt(connection, client, prefix, operation, 'authorized_tenant_sso', 200, ip_hash)
    return (client, response_headers)

@legacy_compatible(callback_index=None, request_index=1)
def _authorize_key(connection, request_context, scope, operation, request_id, monthly_charge_units=None):
    ip_hash = _client_ip_hash(request_context)
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) AS n FROM tenant_api_attempts WHERE ip_hash=%s AND attempted_at>=UTC_TIMESTAMP()-INTERVAL 1 MINUTE', (ip_hash,))
        ip_attempts = int(_column_value(cursor.fetchone()) or 0)
    if ip_attempts >= 300:
        raise BaaSError(429, 'rate_limited')
    admin_session = str(request_context.get('header:x-ha-session', '')).strip()
    if admin_session:
        client, headers = _authorize_admin_session(connection, request_context, scope, operation, ip_hash, admin_session)
        return (client, headers, ip_hash)
    portal_session = str(request_context.get('header:x-tenant-portal-session', '')).strip()
    if portal_session:
        raise BaaSError(410, 'site_passkeys_retired', {'sso_url': 'https://sso.2415.jp'})
    sso_session = str(request_context.get('header:x-tenant-sso-session', '')).strip()
    if sso_session:
        client, headers = _authorize_sso_session(connection, request_context, scope, operation, ip_hash, sso_session)
        return (client, headers, ip_hash)
    token = str(request_context.get('header:x-tenant-api-key', '')).strip()
    authorization = str(request_context.get('header:authorization', request_context.get('REDIRECT_HTTP_AUTHORIZATION', ''))).strip()
    if not token:
        bearer = re.fullmatch('(?i:Bearer)\\s+(baas_(?:live|prod|sandbox|sdk)_[A-Za-z0-9_-]{32,120})', authorization)
        if bearer:
            token = bearer.group(1)
    prefix = token[:12]
    token_pattern = re.compile('baas_(?:live|prod|sandbox|sdk)_[A-Za-z0-9_-]{32,120}')
    if token_pattern.fullmatch(token) is None:
        _attempt(connection, None, prefix, operation, 'invalid_key', 401, ip_hash)
        raise BaaSError(401, 'invalid_api_key')
    key_hash = hmac.new(key_pepper({'key_pepper': secret_value('key_pepper')}).encode('utf-8'), token.encode('utf-8'), hashlib.sha256).hexdigest()
    with connection.cursor() as cursor:
        cursor.execute('SELECT c.*,t.slug AS tenant_slug,t.status AS tenant_status,t.environment AS tenant_environment,t.parent_tenant_id FROM tenant_api_clients c JOIN tenants t ON t.id=c.tenant_id WHERE c.key_hash=%s LIMIT 1', (key_hash,))
        client = cursor.fetchone()
    now = datetime.now(timezone.utc)
    status = str((client or {}).get('status') or '')
    grace = parse_utc_datetime(str((client or {}).get('grace_expires_at') or ''))
    expires = parse_utc_datetime(str((client or {}).get('expires_at') or ''))
    usable = bool(client and client.get('tenant_status') == 'active' and client.get('key_hash') and (status in ('active', 'retiring')) and (not client.get('revoked_at')) and (status != 'retiring' or (grace is not None and grace >= now)) and (expires is None or expires >= now))
    if not usable:
        _attempt(connection, client, prefix, operation, 'invalid_key', 401, ip_hash)
        raise BaaSError(401, 'invalid_api_key')
    environment = _environment(client, request_context, connection, operation, prefix, ip_hash)
    issuance_session = str(request_context.get('header:x-baas-issuance-session', '')).strip().lower()
    if re.fullmatch('[0-9a-f]{32}', issuance_session) is None:
        issuance_session = ''
    # Count every HTTP request. Grouping by the caller-supplied issuance session
    # let a key reuse one session ID to evade the configured request limit.
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) AS n FROM tenant_api_attempts WHERE client_id=%s AND attempted_at>=UTC_TIMESTAMP()-INTERVAL 1 MINUTE', (int(client['id']),))
        rate_count = int(_column_value(cursor.fetchone()) or 0)
        cursor.execute('SELECT COUNT(*) AS n FROM tenant_api_attempts WHERE tenant_id=%s AND attempted_at>=UTC_TIMESTAMP()-INTERVAL 1 MINUTE', (int(client['tenant_id']),))
        tenant_rate_count = int(_column_value(cursor.fetchone()) or 0)
    configured_limit = int(client.get('rate_limit_per_minute') or 0)
    limit = min(_MAX_CLIENT_REQUESTS_PER_MINUTE, max(1, configured_limit))
    if tenant_rate_count >= _MAX_TENANT_REQUESTS_PER_MINUTE:
        # Do not persist each rejected request: the already-recorded requests
        # keep the window closed and avoid turning a flood into log-table growth.
        raise BaaSError(429, 'tenant_rate_limited', {'retry_after_seconds': 60})
    if rate_count >= limit:
        raise BaaSError(429, 'rate_limited', {'retry_after_seconds': 60, 'rate_limit_per_minute': limit})
    try:
        scopes = json.loads(str(client.get('scopes_json') or '[]'))
    except (TypeError, json.JSONDecodeError):
        scopes = []
    if not isinstance(scopes, list) or scope not in scopes:
        _attempt(connection, client, prefix, operation, 'insufficient_scope', 403, ip_hash, issuance_session or None)
        raise BaaSError(403, 'insufficient_scope', {'required_scope': scope})
    kind = str(client.get('key_kind') or 'standard').strip().lower()
    if kind == 'sample_sdk':
        if environment != 'sandbox':
            _attempt(connection, client, prefix, operation, 'sample_sdk_sandbox_required', 403, ip_hash, issuance_session or None)
            raise BaaSError(403, 'sample_sdk_sandbox_only')
        try:
            policy = json.loads(str(client.get('policy_json') or ''))
        except (TypeError, json.JSONDecodeError):
            policy = {}
        if not isinstance(policy, dict):
            policy = {}
        allowed_operations = policy.get('allowed_operations') or ['status', 'products.get', 'products.post', 'licenses.v3.post', 'audit.list', 'billing.summary']
        if operation not in allowed_operations:
            _attempt(connection, client, prefix, operation, 'sample_sdk_api_not_allowed', 403, ip_hash, issuance_session or None)
            raise BaaSError(403, 'sample_sdk_api_not_allowed', {'key_class': 'sample_sdk', 'attempted_operation': operation})
        path = str(request_context.get('path', ''))
        marker = path.find('/api/baas/')
        if marker >= 0:
            path = path[marker:]
        route = request_context.get('method', 'GET').upper() + ' ' + path
        allowed_routes = policy.get('allowed_routes') or ['GET /api/baas/v1/status.php', 'GET /api/baas/v1/products.php', 'POST /api/baas/v1/products.php', 'POST /api/baas/v3/licenses.php', 'GET /api/baas/v1/audit.php', 'GET /api/baas/v1/billing.php']
        if route not in allowed_routes:
            _attempt(connection, client, prefix, operation, 'sample_sdk_route_not_allowed', 403, ip_hash, issuance_session or None)
            raise BaaSError(403, 'sample_sdk_route_not_allowed', {'key_class': 'sample_sdk', 'attempted_route': route})
    from api_usage_limits import check_monthly_limit, request_charge_units
    estimate = request_charge_units(operation, environment) if monthly_charge_units is None else int(monthly_charge_units)
    check_monthly_limit(connection, int(client['tenant_id']), environment, estimate, request_id)
    _attempt(connection, client, prefix, operation, 'authorized', 200, ip_hash, issuance_session or None)
    with connection.cursor() as cursor:
        cursor.execute('UPDATE tenant_api_clients SET last_used_at=UTC_TIMESTAMP() WHERE id=%s', (int(client['id']),))
    connection.commit()
    response_headers = [('X-BaaS-Environment', environment)]
    if kind == 'sample_sdk':
        response_headers.append(('X-BaaS-Key-Class', 'sample_sdk'))
    return (client, response_headers, ip_hash)

def _usage(connection, client, operation, status, request_id, ip_hash):
    try:
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO tenant_api_usage(tenant_id,client_id,operation,status_code,request_id,ip_hash) VALUES(%s,%s,%s,%s,%s,%s)', (int(client['tenant_id']), int(client['id']), operation, status, request_id, ip_hash))
            try:
                cursor.execute('DELETE FROM tenant_api_usage_reservations WHERE request_id=%s AND tenant_id=%s', (request_id, int(client['tenant_id'])))
            except Exception as exc:
                if not (getattr(exc, 'args', ()) and exc.args[0] == 1146):
                    raise
        connection.commit()
    except Exception:
        connection.rollback()

@legacy_compatible(callback_index=1, request_index=0)
def status(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'tenant:read', 'status', rid)
        tenant_id = int(client['tenant_id'])
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS products FROM products WHERE tenant_id=%s AND status<>'deleted'", (tenant_id,))
            product_count = int(cursor.fetchone()['products'] or 0)
            cursor.execute('SELECT COUNT(*) AS licenses,SUM(active=1) AS active FROM licenses WHERE tenant_id=%s AND deleted_at IS NULL', (tenant_id,))
            license_row = cursor.fetchone()
        _usage(connection, client, 'status', 200, rid, ip_hash)
        return _reply(200, {'ok': True, 'api_version': 'baas-v1', 'request_id': rid, 'tenant': {'slug': client['tenant_slug']}, 'usage': {'products': product_count, 'licenses': int(license_row['licenses'] or 0), 'active_licenses': int(license_row['active'] or 0)}}, headers)
    except BaaSError as exc:
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'server_not_writable'})
    finally:
        if connection:
            connection.close()
_TENANT_SSO_ORIGINS = {'https://2415.jp', 'https://backup.2415.jp', 'https://main.2415.jp'}
_TENANT_SSO_SCOPES = ('tenant:read', 'products:write', 'licenses:read', 'licenses:write')

@legacy_compatible(callback_index=0, request_index=None)
def _tenant_sso_reply(status, payload):
    phrases = {200: '200 OK', 400: '400 Bad Request', 401: '401 Unauthorized', 403: '403 Forbidden', 405: '405 Method Not Allowed', 409: '409 Conflict', 428: '428 Precondition Required', 503: '503 Service Unavailable'}
    return json_response(phrases.get(status, '%d Error' % status), payload)

def _tenant_sso_memberships(connection, subject_hash):
    from tenant_sso_contracts import memberships
    return memberships(connection, subject_hash)

@legacy_compatible(callback_index=1, request_index=0)
def tenant_sso(request_context):
    """Manage short-lived tenant sessions created by the Common ID SSO callback."""
    method = str(request_context.get('method', 'GET'))
    origin = str(request_context.get('header:origin', '')).rstrip('/')
    if method != 'POST' or origin not in _TENANT_SSO_ORIGINS:
        return _tenant_sso_reply(403, {'ok': False, 'error': 'origin_rejected'})
    connection = None
    try:
        data = _baas_json_input(request_context)
        action = str(data.get('action') or '')
        connection = database.connect()
        session_token = str(request_context.get('header:x-tenant-sso-session', '')).strip()
        token_hash = hashlib.sha256(session_token.encode('utf-8')).hexdigest()
        if action == 'bootstrap':
            ticket = str(data.get('ticket') or '').strip()
            if re.fullmatch('[A-Za-z0-9_-]{43}', ticket) is None:
                return _tenant_sso_reply(400, {'ok': False, 'error': 'tenant_sso_ticket_invalid'})
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    cursor.execute('SELECT subject_hash,oidc_sid FROM tenant_sso_bootstrap_tickets WHERE ticket_hash=%s AND used_at IS NULL AND expires_at>UTC_TIMESTAMP() LIMIT 1 FOR UPDATE', (hashlib.sha256(ticket.encode()).hexdigest(),))
                    row = cursor.fetchone()
                from tenant_sso_contracts import provider_active, initial_contract
                if not row or not provider_active(str(row.get('oidc_sid') or '')):
                    raise ValueError('ticket')
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1 FROM admin_principals WHERE credential_id_hash=%s AND status='active' AND revoked_at IS NULL LIMIT 1", (str(row['subject_hash']),))
                    is_admin_identity = cursor.fetchone() is not None
                if is_admin_identity:
                    with connection.cursor() as cursor:
                        cursor.execute('UPDATE tenant_sso_bootstrap_tickets SET used_at=UTC_TIMESTAMP() WHERE ticket_hash=%s AND used_at IS NULL', (hashlib.sha256(ticket.encode()).hexdigest(),))
                    connection.commit()
                    return _tenant_sso_reply(403, {'ok': False, 'error': 'tenant_sso_admin_identity'})
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE tenant_sso_bootstrap_tickets SET used_at=UTC_TIMESTAMP() WHERE ticket_hash=%s AND used_at IS NULL', (hashlib.sha256(ticket.encode()).hexdigest(),))
                session_token = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii')
                memberships = _tenant_sso_memberships(connection, str(row['subject_hash']))
                if not memberships:
                    with connection.cursor() as cursor:
                        cursor.execute('SELECT 1 FROM tenant_sso_memberships WHERE subject_hash=%s LIMIT 1', (str(row['subject_hash']),))
                        if cursor.fetchone():
                            connection.commit()
                            return _tenant_sso_reply(403, {'ok': False, 'error': 'tenant_api_key_required'})
                initial = initial_contract(memberships)
                tenant_id = initial['tenant_id'] if initial else None
                with connection.cursor() as cursor:
                    cursor.execute('INSERT INTO tenant_sso_sessions(token_hash,subject_hash,oidc_sid,tenant_id,created_at,expires_at,sso_checked_at) VALUES(%s,%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP()+INTERVAL 12 HOUR,UTC_TIMESTAMP())', (hashlib.sha256(session_token.encode()).hexdigest(), str(row['subject_hash']), str(row['oidc_sid']), tenant_id))
                connection.commit()
                return _tenant_sso_reply(200, {'ok': True, 'session_token': session_token, 'memberships': memberships, 'tenant': initial, 'selection_required': len(memberships) > 1})
            except Exception:
                connection.rollback()
                return _tenant_sso_reply(401, {'ok': False, 'error': 'tenant_sso_ticket_invalid'})
        if re.fullmatch('[A-Za-z0-9_-]{43}', session_token) is None:
            return _tenant_sso_reply(401, {'ok': False, 'error': 'tenant_sso_session_required'})
        with connection.cursor() as cursor:
            cursor.execute('SELECT subject_hash,tenant_id,oidc_sid FROM tenant_sso_sessions WHERE token_hash=%s AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP() LIMIT 1', (token_hash,))
            session = cursor.fetchone()
        if not session:
            return _tenant_sso_reply(401, {'ok': False, 'error': 'tenant_sso_session_required'})
        subject_hash = str(session['subject_hash'])
        if action == 'logout':
            with connection.cursor() as cursor:
                cursor.execute('UPDATE tenant_sso_sessions SET revoked_at=UTC_TIMESTAMP() WHERE token_hash=%s AND revoked_at IS NULL', (token_hash,))
            connection.commit()
            return _tenant_sso_reply(200, {'ok': True})
        from tenant_sso_contracts import validate_provider
        if not validate_provider(connection, session, token_hash):
            return _tenant_sso_reply(401, {'ok': False, 'error': 'tenant_sso_session_required'})
        if action == 'memberships':
            current_memberships = _tenant_sso_memberships(connection, subject_hash)
            if not current_memberships:
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE tenant_sso_sessions SET revoked_at=UTC_TIMESTAMP() WHERE token_hash=%s', (token_hash,))
                connection.commit()
                return _tenant_sso_reply(403, {'ok': False, 'error': 'tenant_api_key_required'})
            return _tenant_sso_reply(200, {'ok': True, 'memberships': _tenant_sso_memberships(connection, subject_hash), 'tenant_id': int(session['tenant_id']) if session.get('tenant_id') is not None else None})
        if action == 'switch_tenant':
            try:
                tenant_id = int(data.get('tenant_id') or 0)
            except (TypeError, ValueError):
                tenant_id = 0
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1 FROM tenant_sso_memberships WHERE subject_hash=%s AND tenant_id=%s', (subject_hash, tenant_id))
                found = cursor.fetchone()
            if tenant_id < 1 or not found or tenant_id not in {item['tenant_id'] for item in _tenant_sso_memberships(connection, subject_hash)}:
                return _tenant_sso_reply(403, {'ok': False, 'error': 'tenant_membership_required'})
            with connection.cursor() as cursor:
                cursor.execute('UPDATE tenant_sso_sessions SET tenant_id=%s,last_used_at=UTC_TIMESTAMP() WHERE token_hash=%s AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP()', (tenant_id, token_hash))
                cursor.execute('SELECT 1 FROM tenant_sso_sessions WHERE token_hash=%s AND tenant_id=%s AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP()', (token_hash, tenant_id))
                if not cursor.fetchone():
                    connection.rollback()
                    return _tenant_sso_reply(401, {'ok': False, 'error': 'tenant_sso_session_required'})
            connection.commit()
            return _tenant_sso_reply(200, {'ok': True, 'tenant_id': tenant_id, 'memberships': _tenant_sso_memberships(connection, subject_hash)})
        if action == 'link_tenant':
            if 'select_tenant' in data and (not isinstance(data['select_tenant'], bool)):
                return _tenant_sso_reply(400, {'ok': False, 'error': 'invalid_request'})
            select_tenant = data.get('select_tenant', True)
            auth_environ = dict(request_context)
            auth_environ.pop('header:x-tenant-sso-session', None)
            client, _, _ = _authorize_key(connection, auth_environ, 'tenant:read', 'tenant_sso.link_tenant', uuid.uuid4().hex[:16])
            if str(client.get('key_kind') or 'standard') != 'standard':
                return _tenant_sso_reply(403, {'ok': False, 'error': 'tenant_api_key_required'})
            scopes = [scope for scope in _auth_scopes(client.get('scopes_json')) if scope in _TENANT_SSO_SCOPES]
            if 'tenant:read' not in scopes:
                return _tenant_sso_reply(403, {'ok': False, 'error': 'tenant_api_key_required'})
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('SELECT subject_hash FROM tenant_sso_sessions WHERE token_hash=%s AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP() LIMIT 1 FOR UPDATE', (token_hash,))
                locked = cursor.fetchone()
                if not locked or not hmac.compare_digest(str(locked['subject_hash']), subject_hash):
                    connection.rollback()
                    return _tenant_sso_reply(401, {'ok': False, 'error': 'tenant_sso_session_required'})
                cursor.execute("SELECT scopes_json FROM tenant_api_clients WHERE id=%s AND tenant_id=%s AND key_hash IS NOT NULL AND key_hash<>'' AND status IN ('active','retiring') AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP()) AND (status='active' OR grace_expires_at>UTC_TIMESTAMP()) LIMIT 1 FOR UPDATE", (int(client['id']), int(client['tenant_id'])))
                current_key = cursor.fetchone()
                current_scopes = _auth_scopes(current_key.get('scopes_json')) if current_key else []
                if 'tenant:read' not in current_scopes:
                    connection.rollback()
                    return _tenant_sso_reply(401, {'ok': False, 'error': 'tenant_api_key_required'})
                scopes = [s for s in scopes if s in current_scopes]
                cursor.execute('INSERT INTO tenant_sso_memberships(subject_hash,tenant_id,source_client_id,scopes_json) VALUES(%s,%s,%s,%s) ON DUPLICATE KEY UPDATE source_client_id=VALUES(source_client_id),scopes_json=VALUES(scopes_json),updated_at=UTC_TIMESTAMP()', (subject_hash, int(client['tenant_id']), int(client['id']), json.dumps(scopes, ensure_ascii=False, separators=(',', ':'))))
                if select_tenant:
                    cursor.execute('UPDATE tenant_sso_sessions SET tenant_id=%s,last_used_at=UTC_TIMESTAMP() WHERE token_hash=%s AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP()', (int(client['tenant_id']), token_hash))
            connection.commit()
            memberships = _tenant_sso_memberships(connection, subject_hash)
            tenant = next((item for item in memberships if item['tenant_id'] == int(client['tenant_id'])), None)
            try:
                from ha_handlers import _append_ha_audit
                _append_ha_audit('tenant_sso_api_key_linked', {'tenant_id': int(client['tenant_id']), 'source_client_id': int(client['id'])}, request_context)
            except Exception:
                pass
            return _tenant_sso_reply(200, {'ok': True, 'tenant': tenant, 'memberships': memberships, 'selection_required': not select_tenant})
        if action == 'reissue_api_key':
            from portal_key_policy import reissue_key
            try:
                client, _, _ = _authorize_key(connection, request_context, 'tenant:read', 'tenant_sso.reissue_api_key', uuid.uuid4().hex[:16])
                return _tenant_sso_reply(200, reissue_key(connection, client, data, request_context))
            except Exception as exc:
                allowed = {'sso_reauthentication_required', 'tenant_sso_session_required', 'server_not_writable', 'key_reissue_fee_confirmation_required', 'key_reissue_request_id_required', 'key_reissue_not_available', 'invalid_portal_session', 'key_reissue_request_owner_mismatch', 'key_reissue_result_expired', 'key_reissue_scope_mismatch', 'key_reissue_billing_unavailable'}
                error = str(exc) if str(exc) in allowed else 'key_reissue_failed'
                return _tenant_sso_reply(428 if error == 'sso_reauthentication_required' else 409, {'ok': False, 'error': error})
        if action == 'billing_methods':
            try:
                from stripe_billing import public_settings
                stripe = public_settings()
            except Exception:
                stripe = {'configured': False, 'enabled': False, 'mode': '', 'test_mode': False}
            return _tenant_sso_reply(200, {'ok': True, 'stripe': stripe,
                                           'key_reissue': {'amount_yen': 500, 'immediate': bool(stripe.get('enabled'))}})
        if action == 'create_key_reissue_checkout':
            from stripe_billing import StripeError as ReissueStripeError, create_key_reissue_checkout
            try:
                client, _, _ = _authorize_key(connection, request_context, 'tenant:read', 'tenant_sso.create_key_reissue_checkout', uuid.uuid4().hex[:16])
                return _tenant_sso_reply(200, create_key_reissue_checkout(connection, client, data, request_context))
            except ReissueStripeError as exc:
                allowed = {'stripe_not_configured', 'tenant_sso_session_required', 'sso_reauthentication_required', 'key_reissue_fee_confirmation_required', 'key_reissue_request_id_required', 'key_reissue_not_available', 'key_reissue_scope_mismatch', 'key_reissue_result_ready', 'key_reissue_pending', 'stripe_live_sandbox_blocked', 'stripe_checkout_failed', 'server_not_writable'}
                error = str(exc) if str(exc) in allowed else 'stripe_checkout_failed'
                status = 428 if error == 'sso_reauthentication_required' else (503 if error in ('stripe_not_configured', 'server_not_writable', 'stripe_checkout_failed') else 409)
                return _tenant_sso_reply(status, {'ok': False, 'error': error})
        if action == 'key_reissue_result':
            from stripe_billing import StripeError as ResultStripeError, key_reissue_result
            try:
                client, _, _ = _authorize_key(connection, request_context, 'tenant:read', 'tenant_sso.key_reissue_result', uuid.uuid4().hex[:16])
                return _tenant_sso_reply(200, key_reissue_result(connection, client, data, request_context))
            except ResultStripeError as exc:
                allowed = {'tenant_sso_session_required', 'key_reissue_request_id_required', 'key_reissue_not_available', 'key_reissue_pending', 'key_reissue_result_expired', 'key_reissue_failed'}
                error = str(exc) if str(exc) in allowed else 'key_reissue_failed'
                return _tenant_sso_reply(409 if error != 'key_reissue_failed' else 503, {'ok': False, 'error': error})
        if action == 'create_invoice_checkout':
            from stripe_billing import StripeError, create_checkout
            try:
                client, _, _ = _authorize_key(connection, request_context, 'tenant:read', 'billing.checkout', uuid.uuid4().hex[:16])
                return _tenant_sso_reply(200, create_checkout(connection, client, data, request_context))
            except StripeError as exc:
                allowed = {'stripe_not_configured', 'tenant_sso_session_required', 'invalid_invoice', 'invoice_not_found', 'invoice_not_payable', 'invoice_amount_invalid', 'invoice_amount_too_small', 'stripe_checkout_completed', 'stripe_live_sandbox_blocked', 'server_not_writable'}
                error = str(exc) if str(exc) in allowed else 'stripe_checkout_failed'
                status = 503 if error in ('stripe_not_configured',) else (409 if error != 'stripe_checkout_failed' else 503)
                return _tenant_sso_reply(status, {'ok': False, 'error': error})
        return _tenant_sso_reply(400, {'ok': False, 'error': 'invalid_action'})
    except BaaSError as exc:
        return _tenant_sso_reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        return _tenant_sso_reply(400, {'ok': False, 'error': str(exc)})
    except database.DatabaseConfigurationError:
        return _tenant_sso_reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _tenant_sso_reply(503, {'ok': False, 'error': 'tenant_sso_unavailable'})
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=None, request_index=0)
def _query_limit(request_context):
    from http_utils import php_parse_query as parse_qs
    raw = parse_qs(request_context.get('query', ''), keep_blank_values=True).get('limit', ['50'])[-1]
    return max(1, min(200, _php_query_int(raw)))

@legacy_compatible(callback_index=None, request_index=0)
def _query_int(request_context, name):
    from http_utils import php_parse_query as parse_qs
    raw = parse_qs(request_context.get('query', ''), keep_blank_values=True).get(name, ['0'])[-1]
    return max(0, _php_query_int(raw))

def _php_query_int(value):
    """Match PHP's (int) cast for query strings, including numeric prefixes."""
    from core import php_int_cast
    return php_int_cast(value)

@legacy_compatible(callback_index=1, request_index=0)
def audit(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'tenant:read', 'audit.list', rid)
        from http_utils import php_parse_query as parse_qs
        query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
        cursor_id = _query_int(request_context, 'cursor')
        client_id = _query_int(request_context, 'client_id')
        operation = query.get('operation', [''])[-1].strip()[:80]
        status_group = query.get('status', [''])[-1].strip()
        sql = 'SELECT id,client_id,operation,status_code,request_id,used_at FROM tenant_api_usage WHERE tenant_id=%s'
        args = [int(client['tenant_id'])]
        if cursor_id:
            sql += ' AND id<%s'
            args.append(cursor_id)
        if operation:
            sql += " AND operation LIKE %s ESCAPE '\\\\'"
            escaped = operation.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
            args.append('%' + escaped + '%')
        if client_id:
            sql += ' AND client_id=%s'
            args.append(client_id)
        ranges = {'success': (200, 299), 'client_error': (400, 499), 'server_error': (500, 599)}
        if status_group in ranges:
            sql += ' AND status_code BETWEEN %s AND %s'
            args.extend(ranges[status_group])
        limit = _query_limit(request_context)
        sql += ' ORDER BY id DESC LIMIT ' + str(limit)
        with connection.cursor() as db_cursor:
            db_cursor.execute(sql, tuple(args))
            rows = db_cursor.fetchall()
        _usage(connection, client, 'audit.list', 200, rid, ip_hash)
        return _reply(200, {'ok': True, 'request_id': rid, 'events': rows, 'next_cursor': int(rows[-1]['id']) if len(rows) == limit else None}, headers)
    except BaaSError as exc:
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'server_not_writable'})
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def billing(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        if str(request_context.get('method', 'GET')) != 'GET':
            raise BaaSError(405, 'method_not_allowed')
        from http_utils import php_parse_query as parse_qs
        from billing_policy import RULES, period_bounds, summarize_rows, credit
        query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
        period_input = query.get('period', [datetime.now(timezone.utc).strftime('%Y-%m')])[-1]
        try:
            period, start, end = period_bounds(period_input)
        except ValueError:
            raise BaaSError(400, 'invalid_period')
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'tenant:read', 'billing.summary', rid)
        tenant_id = int(client['tenant_id'])
        with connection.cursor() as cursor:
            cursor.execute('SELECT environment FROM tenants WHERE id=%s LIMIT 1', (tenant_id,))
            tenant_row = cursor.fetchone()
            if not tenant_row or tenant_row.get('environment') != client.get('tenant_environment'):
                raise BaaSError(409, 'tenant_environment_mismatch')
            cursor.execute('SELECT operation,status_code,COUNT(*) AS request_count FROM tenant_api_usage WHERE tenant_id=%s AND used_at>=%s AND used_at<%s GROUP BY operation,status_code ORDER BY operation,status_code', (tenant_id, start, end))
            usage_rows = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='tenant_portal_key_reissues'")
            reissue_table = int(_column_value(cursor.fetchone()) or 0) > 0
            if reissue_table:
                cursor.execute('SELECT COUNT(*) AS quantity,COALESCE(SUM(amount_units),0) AS amount FROM tenant_portal_key_reissues WHERE tenant_id=%s AND billing_period=%s', (tenant_id, period))
                fee_row = cursor.fetchone() or {}
            else:
                fee_row = {'quantity': 0, 'amount': 0}
        try:
            summary = summarize_rows(tenant_id, str(client.get('tenant_environment') or ''), usage_rows, RULES)
        except ValueError as exc:
            raise BaaSError(409, str(exc))
        _usage(connection, client, 'billing.summary', 200, rid, ip_hash)
        return _reply(200, {'ok': True, 'request_id': rid, 'mode': RULES['mode'], 'production_ready': RULES['production_ready'], 'currency': RULES['currency'], 'credit_definition': RULES['credit_definition'], 'api_pricing_models': RULES['api_pricing_models'], 'period': period, 'api_key_reissue_fees': {'count': int(fee_row.get('quantity') or 0), 'amount_units': int(fee_row.get('amount') or 0), 'amount_yen': credit(int(fee_row.get('amount') or 0))}, 'period_start_utc': start, 'period_end_utc': end, **summary}, headers)
    except BaaSError as exc:
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'billing_summary_unavailable'})
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def invoices(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        if str(request_context.get('method', 'GET')) != 'GET':
            raise BaaSError(405, 'method_not_allowed')
        from http_utils import php_parse_query as parse_qs
        from billing_policy import RULES, period_bounds, credit
        query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
        period = query.get('period', [''])[-1].strip()
        if period:
            try:
                period_bounds(period)
            except ValueError:
                raise BaaSError(400, 'invalid_period')
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'tenant:read', 'billing.invoices', rid)
        tenant_id = int(client['tenant_id'])
        account_id = int(client.get('parent_tenant_id') or tenant_id)
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='api_billing_invoices'")
            if int(_column_value(cursor.fetchone()) or 0) == 0:
                invoice_rows, periods = ([], [])
            else:
                sql = "SELECT id,invoice_number,billing_period,customer_name,issuer_name,issuer_registration_number,issue_date,due_date,tax_rate_basis_points,subtotal_units,tax_units,adjustment_units,total_units,status,notes,snapshot_json,issued_at,paid_at FROM api_billing_invoices WHERE account_tenant_id=%s AND status IN ('issued','paid')"
                args = [account_id]
                if period:
                    sql += ' AND billing_period=%s'
                    args.append(period)
                sql += ' ORDER BY billing_period DESC,id DESC LIMIT 120'
                cursor.execute(sql, tuple(args))
                invoice_rows = cursor.fetchall()
                cursor.execute("SELECT DISTINCT billing_period FROM api_billing_invoices WHERE account_tenant_id=%s AND status IN ('issued','paid') ORDER BY billing_period DESC LIMIT 120", (account_id,))
                period_rows = cursor.fetchall()
                periods = [row.get('billing_period') for row in period_rows]
        converted = []
        for source in invoice_rows:
            row = dict(source)
            try:
                snapshot = json.loads(str(row.pop('snapshot_json', '')))
            except (TypeError, json.JSONDecodeError):
                snapshot = None
            if not isinstance(snapshot, (dict, list)):
                snapshot = []
            for field in ('id', 'tax_rate_basis_points', 'subtotal_units', 'tax_units', 'adjustment_units', 'total_units'):
                row[field] = int(row.get(field) or 0)
            row['subtotal_yen'] = credit(row['subtotal_units'])
            row['tax_yen'] = credit(row['tax_units'])
            row['adjustment_yen'] = credit(row['adjustment_units'])
            row['total_yen'] = credit(row['total_units'])
            row['snapshot'] = snapshot
            converted.append(row)
        try:
            from stripe_billing import public_settings
            stripe = public_settings()
        except Exception:
            stripe = {'configured': False, 'enabled': False, 'mode': ''}
        payments = {}
        if stripe.get('configured'):
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT invoice_id,status,mode,expires_at FROM stripe_invoice_payments WHERE account_tenant_id=%s ORDER BY id DESC LIMIT 240", (account_id,))
                    for item in cursor.fetchall():
                        payments.setdefault(int(item['invoice_id']), {'status': str(item['status']), 'mode': str(item['mode']), 'expires_at_utc': str(item.get('expires_at') or '')})
            except Exception:
                payments = {}
        for row in converted:
            row['stripe_payment'] = payments.get(int(row['id']))
        _usage(connection, client, 'billing.invoices', 200, rid, ip_hash)
        return _reply(200, {'ok': True, 'request_id': rid, 'currency': 'JPY', 'unit_definition': '1 credit = 1 JPY equivalent; amount precision is 0.001 JPY', 'mode': RULES['mode'], 'production_ready': RULES['production_ready'], 'invoices': converted, 'periods': periods, 'stripe': stripe}, headers)
    except BaaSError as exc:
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'invoice_list_unavailable'})
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def export_tenant(request_context):
    """Export the tenant's products, licenses, and device inventory."""
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'tenant:read', 'tenant.export', rid)
        tenant_id = int(client['tenant_id'])
        queries = {'products': 'SELECT id,code,name,status,created_at,updated_at FROM products WHERE tenant_id=%s', 'licenses': 'SELECT id,product_id,label,active,max_devices,evaluation_days,expires_at,revoked_at,created_at,updated_at FROM licenses WHERE tenant_id=%s AND deleted_at IS NULL', 'devices': 'SELECT d.id,d.license_id,d.device_label,d.first_activated_at,d.last_seen_at,d.revoked_at,d.app_version FROM license_devices d JOIN licenses l ON l.id=d.license_id WHERE l.tenant_id=%s AND l.deleted_at IS NULL'}
        tables = {}
        for name, sql in queries.items():
            with connection.cursor() as cursor:
                cursor.execute(sql, (tenant_id,))
                tables[name] = cursor.fetchall()
        _usage(connection, client, 'tenant.export', 200, rid, ip_hash)
        return _reply(200, {'ok': True, 'schema': 1, 'exported_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'request_id': rid, 'tenant': {'id': tenant_id, 'slug': client['tenant_slug']}, 'data': tables}, headers)
    except BaaSError as exc:
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'tenant_export_unavailable'})
    finally:
        if connection:
            connection.close()

def _webhook_url_allowed(url):
    try:
        parts = urlsplit(url)
        host = (parts.hostname or '').lower()
        if parts.scheme.lower() != 'https' or not host or parts.username is not None or (parts.password is not None) or parts.fragment:
            return False
        if host == 'localhost' or host.endswith('.local'):
            return False
        try:
            address = ipaddress.ip_address(host)
            return address.is_global
        except ValueError:
            return re.fullmatch('[a-z0-9.-]+', host) is not None
    except ValueError:
        return False

@legacy_compatible(callback_index=None, request_index=0)
def _baas_json_input(request_context):
    from core import php_int_cast
    length = php_int_cast(request_context.get('content_length') or 0)
    if length > 131072:
        raise RequestError('request_too_large')
    stream = request_context.get('body_stream')
    raw = stream.read(131073) if stream is not None else b''
    if len(raw) > 131072:
        raise RequestError('request_too_large')
    try:
        text = raw.decode('utf-8')
        value = json.loads(text, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_json'))) if raw else {}
        depth = 0
        in_string = escaped = False
        for char in text:
            if in_string:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char in '[{':
                depth += 1
                if depth > 32:
                    raise ValueError('invalid_json')
            elif char in ']}':
                depth -= 1
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise RequestError('invalid_json')
    if isinstance(value, list):
        return {}
    if not isinstance(value, dict):
        raise RequestError('invalid_request')
    return value

@legacy_compatible(callback_index=1, request_index=0)
def webhooks(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    method = str(request_context.get('method', 'GET'))
    operation = 'webhooks.' + method.lower()
    try:
        connection = database.connect()
        scope = 'tenant:read' if method == 'GET' else 'licenses:write'
        client, headers, ip_hash = _authorize_key(connection, request_context, scope, operation, rid)
        tenant_id = int(client['tenant_id'])
        if method == 'GET':
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,url,events_json,status,failure_count,created_at,updated_at FROM tenant_webhooks WHERE tenant_id=%s ORDER BY id DESC', (tenant_id,))
                rows = cursor.fetchall()
            _usage(connection, client, 'webhooks.list', 200, rid, ip_hash)
            return _reply(200, {'ok': True, 'request_id': rid, 'webhooks': rows}, headers)
        if method != 'POST':
            raise BaaSError(405, 'method_not_allowed')
        _baas_require_writable()
        _assert_write_fence(connection)
        data = _baas_json_input(request_context)
        action = str(data.get('action', 'create'))
        if action == 'delete':
            try:
                webhook_id = int(data.get('webhook_id') or 0)
            except (TypeError, ValueError):
                webhook_id = 0
            with connection.cursor() as cursor:
                cursor.execute("UPDATE tenant_webhooks SET status='deleted' WHERE id=%s AND tenant_id=%s", (webhook_id, tenant_id))
            connection.commit()
            _usage(connection, client, 'webhooks.delete', 200, rid, ip_hash)
            return _reply(200, {'ok': True, 'request_id': rid}, headers)
        raw_events = data.get('events', [])
        if not isinstance(raw_events, list):
            raw_events = [raw_events]
        allowed = {'license.issued', 'license.updated', 'license.activated', 'license.revoked', 'license.bulk_job_completed', 'device.revoked', 'device.restored'}
        events = list(dict.fromkeys((item for item in raw_events if isinstance(item, str) and item in allowed)))
        if not events:
            raise BaaSError(400, 'invalid_webhook_events')
        if action == 'update':
            try:
                webhook_id = int(data.get('webhook_id') or 0)
            except (TypeError, ValueError):
                webhook_id = 0
            if webhook_id < 1:
                raise BaaSError(400, 'invalid_webhook_id')
            with connection.cursor() as cursor:
                cursor.execute("SELECT id FROM tenant_webhooks WHERE id=%s AND tenant_id=%s AND status='active'", (webhook_id, tenant_id))
                if not cursor.fetchone():
                    raise BaaSError(404, 'webhook_not_found')
                cursor.execute("UPDATE tenant_webhooks SET events_json=%s WHERE id=%s AND tenant_id=%s AND status='active'", (json.dumps(events, separators=(',', ':')), webhook_id, tenant_id))
            connection.commit()
            _usage(connection, client, 'webhooks.update', 200, rid, ip_hash)
            return _reply(200, {'ok': True, 'request_id': rid, 'webhook_id': webhook_id, 'events': events}, headers)
        if action not in ('create', 'create_line'):
            raise BaaSError(400, 'invalid_webhook_action')
        token_secret = secret_value('token_secret')
        from core import ConfigurationError, _aes_gcm_encrypt, token_secret as normalize_token_secret
        try:
            encryption_secret = normalize_token_secret({'token_secret': token_secret})
            encrypted_secret = lambda secret: _aes_gcm_encrypt(encryption_secret, b'offline-storage|', b'TUTI-OFFLINE-V1', secret.encode('utf-8'))
        except ConfigurationError:
            raise
        if action == 'create_line':
            access_token = str(data.get('channel_access_token', '')).strip()
            recipient = str(data.get('recipient_id', '')).strip()
            if not access_token or len(access_token.encode('utf-8')) > 4096 or '\r' in access_token or ('\n' in access_token):
                raise BaaSError(400, 'invalid_line_channel_access_token')
            if re.fullmatch('[UCR][0-9a-fA-F]{32}', recipient) is None:
                raise BaaSError(400, 'invalid_line_recipient_id')
            url = 'https://api.line.me/v2/bot/message/push?to=' + quote(recipient, safe='')
            encrypted = encrypted_secret(access_token)
            with connection.cursor() as cursor:
                cursor.execute('INSERT INTO tenant_webhooks(tenant_id,url,secret_hash,secret_enc,events_json) VALUES(%s,%s,%s,%s,%s)', (tenant_id, url, hashlib.sha256(access_token.encode()).hexdigest(), encrypted, json.dumps(events, separators=(',', ':'))))
                webhook_id = int(cursor.lastrowid)
            connection.commit()
            _usage(connection, client, 'webhooks.create', 201, rid, ip_hash)
            return _reply(201, {'ok': True, 'request_id': rid, 'webhook_id': webhook_id, 'type': 'line', 'message': 'LINE Messaging API destination created. The channel access token is stored encrypted and is never returned.'}, headers)
        url = str(data.get('url', '')).strip()
        if not _webhook_url_allowed(url):
            raise BaaSError(400, 'invalid_webhook_url')
        secret = 'whsec_' + secrets.token_urlsafe(32).rstrip('=')
        encrypted = encrypted_secret(secret)
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO tenant_webhooks(tenant_id,url,secret_hash,secret_enc,events_json) VALUES(%s,%s,%s,%s,%s)', (tenant_id, url, hashlib.sha256(secret.encode()).hexdigest(), encrypted, json.dumps(events, separators=(',', ':'))))
            webhook_id = int(cursor.lastrowid)
        connection.commit()
        _usage(connection, client, 'webhooks.create', 201, rid, ip_hash)
        return _reply(201, {'ok': True, 'request_id': rid, 'webhook_id': webhook_id, 'secret': secret, 'message': 'The signing secret is returned only once.'}, headers)
    except BaaSError as exc:
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        error = str(exc)
        return _reply(413 if error == 'request_too_large' else 400, {'ok': False, 'error': error})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'webhook_service_unavailable'})
    finally:
        if connection:
            connection.close()

def _queue_webhook(connection, tenant_id, event, data):
    event_id = uuid.uuid4().hex
    payload = json.dumps({'id': event_id, 'type': event, 'created_at': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'data': data}, ensure_ascii=False, separators=(',', ':'))
    with connection.cursor() as cursor:
        cursor.execute("SELECT id,events_json FROM tenant_webhooks WHERE tenant_id=%s AND status='active'", (tenant_id,))
        hooks = cursor.fetchall()
        for hook in hooks:
            try:
                events = json.loads(str(hook.get('events_json') or '[]'))
            except (TypeError, json.JSONDecodeError):
                events = []
            if isinstance(events, list) and event in events:
                cursor.execute('INSERT IGNORE INTO tenant_webhook_deliveries (tenant_id,webhook_id,event_type,event_id,payload_json) VALUES(%s,%s,%s,%s,%s)', (tenant_id, int(hook['id']), event, event_id, payload))

def _revoke_license_devices(connection, license_id):
    with connection.cursor() as cursor:
        cursor.execute('UPDATE license_devices SET revoked_at=UTC_TIMESTAMP(),token_version=token_version+1 WHERE license_id=%s AND revoked_at IS NULL', (license_id,))
        return int(getattr(cursor, 'rowcount', 0))

def _generate_baas_product_key():
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return '-'.join((''.join((secrets.choice(alphabet) for _ in range(5))) for _ in range(5)))

@legacy_compatible(callback_index=None, request_index=1)
def _issuance_session_meta(data, request_context):
    session_id = str(data.get('issuance_session_id', '')).strip().lower()
    try:
        item = int(data.get('issuance_session_item') or 0)
        count = int(data.get('issuance_session_count') or 0)
    except (TypeError, ValueError):
        raise BaaSError(400, 'invalid_issuance_session_item')
    if not session_id and item == 0 and (count == 0):
        return None
    if re.fullmatch('[0-9a-f]{32}', session_id) is None:
        raise BaaSError(400, 'invalid_issuance_session_id')
    if count < 1 or count > 200:
        raise BaaSError(400, 'invalid_issuance_session_count', {'max': 200})
    if item < 1 or item > count:
        raise BaaSError(400, 'invalid_issuance_session_item')
    header_id = str(request_context.get('header:x-baas-issuance-session', '')).strip().lower()
    header_item = str(request_context.get('header:x-baas-issuance-item', '')).strip()
    header_count = str(request_context.get('header:x-baas-issuance-count', '')).strip()
    try:
        item_mismatch = bool(header_item) and int(header_item) != item
        count_mismatch = bool(header_count) and int(header_count) != count
    except ValueError:
        raise BaaSError(400, 'issuance_session_header_mismatch')
    if header_id and header_id != session_id or item_mismatch or count_mismatch:
        raise BaaSError(400, 'issuance_session_header_mismatch')
    return {'id': session_id, 'item': item, 'count': count}

def _ensure_issuance_session_schema(connection):
    with connection.cursor() as cursor:
        cursor.execute("CREATE TABLE IF NOT EXISTS tenant_key_issue_sessions (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,session_id CHAR(32) NOT NULL,tenant_id BIGINT UNSIGNED NOT NULL,product_id BIGINT UNSIGNED NOT NULL,environment VARCHAR(16) NOT NULL,api_version VARCHAR(16) NOT NULL,requested_count INT UNSIGNED NOT NULL,completed_count INT UNSIGNED NOT NULL DEFAULT 0,status VARCHAR(20) NOT NULL DEFAULT 'running',created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,completed_at DATETIME NULL,PRIMARY KEY(id),UNIQUE KEY uq_tenant_issue_session(tenant_id,session_id),KEY idx_tenant_issue_session_status(tenant_id,status,created_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci")
        cursor.execute('CREATE TABLE IF NOT EXISTS tenant_key_issue_session_items (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,session_row_id BIGINT UNSIGNED NOT NULL,item_no INT UNSIGNED NOT NULL,license_id BIGINT UNSIGNED NOT NULL,request_key VARCHAR(100) NOT NULL,request_id CHAR(16) NOT NULL,key_fingerprint CHAR(64) NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(id),UNIQUE KEY uq_tenant_issue_session_item(session_row_id,item_no),UNIQUE KEY uq_tenant_issue_session_request(session_row_id,request_key),UNIQUE KEY uq_tenant_issue_session_license(license_id),KEY idx_tenant_issue_fingerprint(key_fingerprint)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci')

def _record_issuance_session(connection, client, product_id, session, license_id, product_key, request_key, rid):
    tenant_id = int(client['tenant_id'])
    environment = str(client.get('tenant_environment') or 'unknown')
    with connection.cursor() as cursor:
        cursor.execute('INSERT IGNORE INTO tenant_key_issue_sessions (session_id,tenant_id,product_id,environment,api_version,requested_count) VALUES(%s,%s,%s,%s,%s,%s)', (session['id'], tenant_id, product_id, environment, 'v1', session['count']))
        cursor.execute('SELECT * FROM tenant_key_issue_sessions WHERE tenant_id=%s AND session_id=%s FOR UPDATE', (tenant_id, session['id']))
        row = cursor.fetchone()
        if not row:
            raise BaaSError(409, 'issuance_session_not_found')
        if int(row['product_id']) != product_id or row['environment'] != environment or row['api_version'] != 'v1' or (int(row['requested_count']) != session['count']):
            raise BaaSError(409, 'issuance_session_context_mismatch')
        cursor.execute('SELECT request_key FROM tenant_key_issue_session_items WHERE session_row_id=%s AND item_no=%s LIMIT 1', (int(row['id']), session['item']))
        if cursor.fetchone():
            raise BaaSError(409, 'issuance_session_item_already_exists')
        cursor.execute('INSERT INTO tenant_key_issue_session_items (session_row_id,item_no,license_id,request_key,request_id,key_fingerprint) VALUES(%s,%s,%s,%s,%s,%s)', (int(row['id']), session['item'], license_id, request_key, rid, hashlib.sha256(product_key.encode()).hexdigest()))
        cursor.execute("UPDATE tenant_key_issue_sessions SET completed_count=completed_count+1,status=CASE WHEN completed_count+1>=requested_count THEN 'completed' ELSE 'running' END,completed_at=CASE WHEN completed_count+1>=requested_count THEN UTC_TIMESTAMP() ELSE completed_at END WHERE id=%s", (int(row['id']),))
        cursor.execute('SELECT completed_count,requested_count,status FROM tenant_key_issue_sessions WHERE id=%s', (int(row['id']),))
        current = cursor.fetchone() or {}
    return {'session_id': session['id'], 'item': session['item'], 'count': session['count'], 'completed': int(current.get('completed_count') or 0), 'status': str(current.get('status') or 'running')}

@legacy_compatible(callback_index=1, request_index=0)
def licenses(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    method = str(request_context.get('method', 'GET'))
    operation = 'licenses.' + method.lower()
    try:
        connection = database.connect()
        scope = 'licenses:read' if method == 'GET' else 'licenses:write'
        client, headers, ip_hash = _authorize_key(connection, request_context, scope, operation, rid)
        tenant_id = int(client['tenant_id'])
        if method == 'GET':
            from http_utils import php_parse_query as parse_qs
            query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
            limit = _query_limit(request_context)
            cursor_id = _query_int(request_context, 'cursor')
            product_id = _query_int(request_context, 'product_id')
            license_id = _query_int(request_context, 'license_id')
            search = query.get('search', [''])[-1].strip()[:80]
            sql = "SELECT l.id,l.tenant_id,l.product_id,p.code AS product_code, CASE WHEN t.parent_tenant_id IS NOT NULL OR t.environment='sandbox' THEN 'sandbox' WHEN t.environment='production' THEN 'production' ELSE 'unknown' END AS environment, l.label,l.active,l.max_devices,l.evaluation_days,l.expires_at,l.revoked_at,l.created_at FROM licenses l LEFT JOIN tenants t ON t.id=l.tenant_id LEFT JOIN products p ON p.id=l.product_id AND p.tenant_id=l.tenant_id WHERE l.tenant_id=%s AND l.deleted_at IS NULL"
            args = [tenant_id]
            if license_id:
                sql += ' AND l.id=%s'
                args.append(license_id)
            if product_id:
                sql += ' AND l.product_id=%s'
                args.append(product_id)
            if cursor_id:
                sql += ' AND l.id<%s'
                args.append(cursor_id)
            if search:
                sql += ' AND (l.label LIKE %s OR CAST(l.id AS CHAR)=%s)'
                args.extend(('%' + search + '%', search))
            sql += ' ORDER BY l.id DESC LIMIT ' + str(limit)
            with connection.cursor() as cursor:
                cursor.execute(sql, tuple(args))
                rows = cursor.fetchall()
                devices = []
                if license_id and rows:
                    cursor.execute('SELECT id,device_label,first_activated_at,last_seen_at,access_expires_at,revoked_at,app_version FROM license_devices WHERE license_id=%s ORDER BY id DESC LIMIT 200', (license_id,))
                    devices = cursor.fetchall()
            _usage(connection, client, 'licenses.list', 200, rid, ip_hash)
            return _reply(200, {'ok': True, 'request_id': rid, 'licenses': rows, 'devices': devices, 'next_cursor': int(rows[-1]['id']) if len(rows) == limit else None}, headers)
        if method not in ('POST', 'DELETE'):
            raise BaaSError(405, 'method_not_allowed')
        _assert_write_fence(connection)
        data = _baas_json_input(request_context)
        if method == 'DELETE':
            try:
                license_id = int(data.get('license_id') or 0)
            except (TypeError, ValueError):
                license_id = 0
            if license_id < 1:
                raise BaaSError(400, 'invalid_license_id')
            idem = str(data.get('idempotency_key', request_context.get('header:idempotency-key', ''))).strip()
            if re.fullmatch('[A-Za-z0-9_-]{20,100}', idem) is None:
                raise BaaSError(400, 'invalid_idempotency_key')
            with connection.cursor() as cursor:
                cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s', (tenant_id, 'baas_delete_license', idem))
                saved = cursor.fetchone()
            if saved and saved.get('response_json'):
                try:
                    replay = json.loads(str(saved['response_json']))
                except json.JSONDecodeError:
                    raise BaaSError(503, 'idempotency_response_invalid')
                _usage(connection, client, 'licenses.delete.replay', 200, rid, ip_hash)
                return _reply(200, replay, headers)
            reason = str(data.get('reason', 'tenant_api_delete')).strip() or 'tenant_api_delete'
            reason = reason[:200]
            deleted_by = hashlib.sha256(('tenant_api_client:' + str(client.get('id', 0))).encode()).hexdigest()
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('SELECT id FROM licenses WHERE id=%s AND tenant_id=%s AND deleted_at IS NULL FOR UPDATE', (license_id, tenant_id))
                exists = cursor.fetchone()
            if not exists:
                connection.rollback()
                raise BaaSError(404, 'license_not_found')
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET active=0,revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),deleted_at=UTC_TIMESTAMP(),deleted_reason=%s,deleted_by=%s WHERE id=%s AND tenant_id=%s AND deleted_at IS NULL', (reason, deleted_by, license_id, tenant_id))
                if int(getattr(cursor, 'rowcount', 0)) < 1:
                    raise RuntimeError('license_delete_failed')
            revoked_devices = _revoke_license_devices(connection, license_id)
            with connection.cursor() as cursor:
                cursor.execute("UPDATE phone_activation_requests SET status='cancelled',cancelled_at=COALESCE(cancelled_at,UTC_TIMESTAMP()),cancelled_reason=COALESCE(cancelled_reason,%s) WHERE license_id=%s AND status NOT IN ('confirmed','cancelled','expired')", ('license_deleted', license_id))
                cancelled_phone = int(getattr(cursor, 'rowcount', 0))
                cursor.execute('UPDATE offline_activation_requests SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),revocation_reason=COALESCE(revocation_reason,%s) WHERE license_id=%s AND revoked_at IS NULL', ('license_deleted', license_id))
                revoked_offline = int(getattr(cursor, 'rowcount', 0))
            _queue_webhook(connection, tenant_id, 'license.revoked', {'license_id': license_id, 'reason': 'deleted'})
            result = {'ok': True, 'api_version': 'baas-v1', 'request_id': rid, 'license_id': license_id, 'tenant_id': tenant_id, 'environment': str(client.get('tenant_environment') or 'unknown'), 'action': 'delete', 'deleted': True, 'revoked_devices': revoked_devices, 'cancelled_phone_requests': cancelled_phone, 'revoked_offline_requests': revoked_offline}
            with connection.cursor() as cursor:
                cursor.execute('INSERT INTO idempotency_keys(tenant_id,operation,request_key,response_json) VALUES(%s,%s,%s,%s)', (tenant_id, 'baas_delete_license', idem, json.dumps(result, ensure_ascii=False, separators=(',', ':'))))
            connection.commit()
            _usage(connection, client, 'licenses.delete', 200, rid, ip_hash)
            return _reply(200, result, headers)
        action = str(data.get('action', 'issue')).strip().lower()
        if action == 'issue':
            count = data.get('count', 1)
            if isinstance(count, bool) or re.fullmatch(r'[0-9]{1,6}', str(count)) is None or int(count) < 1:
                raise BaaSError(400, 'invalid_issue_count')
            if int(count) != 1:
                raise BaaSError(410, 'bulk_issuance_moved_to_v8', {'replacement': '/api/baas/v8/issuance.php'})
            try:
                product_id = int(data.get('product_id') or 0)
            except (TypeError, ValueError):
                product_id = 0
            with connection.cursor() as cursor:
                cursor.execute("SELECT id FROM products WHERE id=%s AND tenant_id=%s AND status='active'", (product_id, tenant_id))
                if not cursor.fetchone():
                    raise BaaSError(404, 'product_not_found')
            session = _issuance_session_meta(data, request_context)
            if session is not None:
                _ensure_issuance_session_schema(connection)
            idem = str(data.get('idempotency_key', request_context.get('header:idempotency-key', ''))).strip()
            if re.fullmatch('[A-Za-z0-9_-]{20,100}', idem) is None:
                raise BaaSError(400, 'invalid_idempotency_key')
            with connection.cursor() as cursor:
                cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s', (tenant_id, 'baas_issue_license', idem))
                saved = cursor.fetchone()
            if saved and saved.get('response_json'):
                try:
                    replay = json.loads(str(saved['response_json']))
                except json.JSONDecodeError:
                    raise BaaSError(503, 'idempotency_response_invalid')
                _usage(connection, client, 'licenses.issue.replay', 200, rid, ip_hash)
                return _reply(200, replay, headers)
            with connection.cursor() as cursor:
                cursor.execute('SELECT t.max_licenses,(SELECT COUNT(*) FROM licenses l WHERE l.tenant_id=t.id AND l.deleted_at IS NULL) AS used FROM tenants t WHERE t.id=%s', (tenant_id,))
                quota = cursor.fetchone()
            if not quota or int(quota.get('used') or 0) >= int(quota.get('max_licenses') or 0):
                raise BaaSError(409, 'license_quota_exceeded')
            mode = str(data.get('license_mode', 'single')).lower()
            if mode not in ('single', 'volume', 'evaluation'):
                raise BaaSError(400, 'invalid_license_mode')
            try:
                max_devices = max(2, min(10000, int(data.get('max_devices', 10)))) if mode == 'volume' else 1
                evaluation_days = max(1, min(3650, int(data.get('evaluation_days', 30)))) if mode == 'evaluation' else None
            except (TypeError, ValueError):
                raise BaaSError(400, 'invalid_license_mode')
            label = str(data.get('label', '')).strip()
            expires = str(data.get('expires_at', '')).strip()
            expires_value = None
            if expires:
                if re.fullmatch('\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}', expires) is None:
                    raise BaaSError(400, 'invalid_expires_at', {'message': '有効期限はYYYY-MM-DD HH:MM:SS形式のUTCで指定してください'})
                try:
                    expires_value = datetime.strptime(expires, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                except ValueError:
                    raise BaaSError(400, 'invalid_expires_at')
                if expires_value <= datetime.now(timezone.utc):
                    raise BaaSError(400, 'invalid_expires_at')
            config = {'key_pepper': secret_value('key_pepper'), 'token_secret': secret_value('token_secret')}
            from core import license_key_hash, offline_secret, offline_lookup, offline_secret_encrypt
            for _ in range(5):
                product_key = _generate_baas_product_key()
                secret = offline_secret(product_key)
                try:
                    connection.begin()
                    with connection.cursor() as cursor:
                        cursor.execute('INSERT INTO licenses(tenant_id,product_id,key_hash,label,active,max_devices,evaluation_days,expires_at,offline_lookup,offline_secret_enc) VALUES(%s,%s,%s,%s,1,%s,%s,%s,%s,%s)', (tenant_id, product_id, license_key_hash(config, product_key), label[:100] or None, max_devices, evaluation_days, expires_value.strftime('%Y-%m-%d %H:%M:%S') if expires_value else None, offline_lookup(secret), offline_secret_encrypt(config, secret)))
                        license_id = int(cursor.lastrowid)
                        cursor.execute('SELECT environment,parent_tenant_id FROM tenants WHERE id=%s', (tenant_id,))
                        tenant_meta = cursor.fetchone() or {}
                    stored_environment = str(tenant_meta.get('environment') or '').strip().lower()
                    environment = 'sandbox' if tenant_meta.get('parent_tenant_id') or stored_environment == 'sandbox' else 'production' if stored_environment == 'production' else 'unknown'
                    result = {'ok': True, 'api_version': 'baas-v1', 'request_id': rid, 'product_key': product_key, 'license_id': license_id, 'tenant_id': tenant_id, 'environment': environment, 'product_id': product_id, 'license_mode': mode, 'max_devices': max_devices, 'evaluation_days': evaluation_days, 'expires_at': expires_value.strftime('%Y-%m-%d %H:%M:%S') if expires_value else None}
                    if session is not None:
                        result['issuance_session'] = _record_issuance_session(connection, client, product_id, session, license_id, product_key, idem, rid)
                    body = json.dumps(result, ensure_ascii=False, separators=(',', ':'))
                    with connection.cursor() as cursor:
                        cursor.execute('INSERT INTO idempotency_keys(tenant_id,operation,request_key,response_json) VALUES(%s,%s,%s,%s)', (tenant_id, 'baas_issue_license', idem, body))
                    _queue_webhook(connection, tenant_id, 'license.issued', {'license_id': license_id, 'product_id': product_id, 'license_mode': mode, 'max_devices': max_devices, 'evaluation_days': evaluation_days, 'expires_at': result['expires_at']})
                    connection.commit()
                    _usage(connection, client, 'licenses.issue', 201, rid, ip_hash)
                    return _reply(201, result, headers)
                except Exception as exc:
                    connection.rollback()
                    if getattr(exc, 'args', [None])[0] in (1062, '23000'):
                        continue
                    raise
            raise BaaSError(503, 'key_generation_exhausted')
        try:
            license_id = int(data.get('license_id') or 0)
        except (TypeError, ValueError):
            license_id = 0
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute('SELECT id,active,max_devices,label,expires_at FROM licenses WHERE id=%s AND tenant_id=%s AND deleted_at IS NULL FOR UPDATE', (license_id, tenant_id))
            row = cursor.fetchone()
        if not row:
            connection.rollback()
            raise BaaSError(404, 'license_not_found')
        if action == 'update':
            label = str(data.get('label', '')).strip()
            new_label = label[:100] if label else None
            try:
                max_devices = max(1, min(10000, int(data.get('max_devices', row['max_devices']))))
            except (TypeError, ValueError):
                max_devices = 1
            expires = str(data.get('expires_at', '')).strip()
            if expires and re.fullmatch('\\d{4}-\\d{2}-\\d{2}(?: \\d{2}:\\d{2}:\\d{2})?', expires) is None:
                connection.rollback()
                raise BaaSError(400, 'invalid_expires_at')
            new_expires = expires or None
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET label=%s,max_devices=%s,expires_at=%s WHERE id=%s AND tenant_id=%s', (new_label, max_devices, new_expires, license_id, tenant_id))
            if new_label != row.get('label') or max_devices != int(row['max_devices']) or new_expires != row.get('expires_at'):
                _queue_webhook(connection, tenant_id, 'license.updated', {'license_id': license_id, 'label': new_label, 'max_devices': max_devices, 'expires_at': new_expires})
        elif action in ('activate', 'deactivate'):
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET active=%s WHERE id=%s AND tenant_id=%s', (1 if action == 'activate' else 0, license_id, tenant_id))
            if action == 'activate' and int(row['active']) != 1:
                _queue_webhook(connection, tenant_id, 'license.activated', {'license_id': license_id})
            if action == 'deactivate' and int(row['active']) == 1:
                revoked = _revoke_license_devices(connection, license_id)
                _queue_webhook(connection, tenant_id, 'license.updated', {'license_id': license_id, 'active': False, 'revoked_devices': revoked})
        elif action == 'revoke_all_devices':
            revoked = _revoke_license_devices(connection, license_id)
            if revoked > 0:
                _queue_webhook(connection, tenant_id, 'device.revoked', {'license_id': license_id, 'count': revoked, 'reason': 'revoke_all_devices'})
        elif action in ('revoke_device', 'restore_device'):
            try:
                device_id = int(data.get('device_id') or 0)
            except (TypeError, ValueError):
                device_id = 0
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,revoked_at FROM license_devices WHERE id=%s AND license_id=%s FOR UPDATE', (device_id, license_id))
                device = cursor.fetchone()
            if not device:
                connection.rollback()
                raise BaaSError(404, 'device_not_found')
            if action == 'revoke_device' and device.get('revoked_at') is None:
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE license_devices SET revoked_at=UTC_TIMESTAMP(),token_version=token_version+1 WHERE id=%s', (device_id,))
                _queue_webhook(connection, tenant_id, 'device.revoked', {'license_id': license_id, 'device_id': device_id})
            elif action == 'restore_device' and device.get('revoked_at') is not None:
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE license_devices SET revoked_at=NULL,token_version=token_version+1 WHERE id=%s', (device_id,))
                _queue_webhook(connection, tenant_id, 'device.restored', {'license_id': license_id, 'device_id': device_id})
        else:
            connection.rollback()
            raise BaaSError(400, 'invalid_action')
        connection.commit()
        _usage(connection, client, 'licenses.' + action, 200, rid, ip_hash)
        return _reply(200, {'ok': True, 'request_id': rid, 'license_id': license_id, 'action': action}, headers)
    except BaaSError as exc:
        if connection and getattr(connection, 'in_transaction', False):
            connection.rollback()
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        error = str(exc)
        status_code = 413 if error == 'request_too_large' else 400
        return _reply(status_code, {'ok': False, 'error': error})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'license_service_unavailable'})
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def batch(request_context):
    """Retain old job reads while moving every new multi-key request to V8."""
    rid = uuid.uuid4().hex[:16]
    connection = None
    method = str(request_context.get('method', 'GET'))
    try:
        connection = database.connect()
        scope = 'licenses:read' if method == 'GET' else 'licenses:write'
        operation = 'batch.status' if method == 'GET' else 'batch.issue'
        client, headers, ip_hash = _authorize_key(connection, request_context, scope, operation, rid)
        tenant_id = int(client['tenant_id'])
        if method == 'GET':
            job_id = max(1, _query_int(request_context, 'job_id'))
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,status,requested_count,succeeded_count,failed_count,result_json,created_at,completed_at FROM baas_batch_jobs WHERE id=%s AND tenant_id=%s', (job_id, tenant_id))
                row = cursor.fetchone()
            if not row:
                raise BaaSError(404, 'batch_not_found')
            try:
                results = json.loads(str(row.get('result_json') or '[]'))
            except (TypeError, json.JSONDecodeError):
                results = []
            if not isinstance(results, list):
                results = []
            changed = False
            for item in results:
                if isinstance(item, dict) and 'product_key' in item:
                    item.pop('product_key', None)
                    changed = True
            if changed:
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE baas_batch_jobs SET result_json=%s WHERE id=%s AND tenant_id=%s', (json.dumps(results, ensure_ascii=False, separators=(',', ':')), job_id, tenant_id))
                connection.commit()
            job = dict(row)
            job.pop('result_json', None)
            job['results'] = results
            return _reply(200, {'ok': True, 'job': job}, headers)
        if method != 'POST':
            raise BaaSError(405, 'method_not_allowed')
        data = _baas_json_input(request_context)
        items = data.get('items')
        if not isinstance(items, list) or not 1 <= len(items) <= 100:
            raise BaaSError(400, 'invalid_batch_size')
        idem = str(request_context.get('header:idempotency-key', data.get('idempotency_key', ''))).strip()
        if re.fullmatch('[A-Za-z0-9_-]{20,100}', idem) is None:
            raise BaaSError(400, 'invalid_idempotency_key')
        with connection.cursor() as cursor:
            cursor.execute('SELECT id FROM baas_batch_jobs WHERE tenant_id=%s AND request_key=%s', (tenant_id, idem))
            existing = cursor.fetchone()
        if existing and existing.get('id'):
            return _reply(200, {'ok': True, 'job_id': int(existing['id']), 'replayed': True}, headers)
        _assert_write_fence(connection)
        with connection.cursor() as cursor:
            cursor.execute("SELECT max_licenses FROM tenants WHERE id=%s AND status='active' FOR UPDATE", (tenant_id,))
            tenant = cursor.fetchone()
            if not tenant:
                raise BaaSError(409, 'tenant_not_found_or_inactive')
            cursor.execute('SELECT COUNT(*) AS n FROM licenses WHERE tenant_id=%s AND deleted_at IS NULL', (tenant_id,))
            current_licenses = int((cursor.fetchone() or {}).get('n', 0))
            cursor.execute("SELECT COALESCE(SUM(GREATEST(requested_count-processed_count,0)),0) AS n FROM product_key_v8_jobs WHERE tenant_id=%s AND status IN ('queued','processing','cancel_requested')", (tenant_id,))
            reserved = int((cursor.fetchone() or {}).get('n', 0))
            cursor.execute("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name IN ('product_key_issue_jobs_v4','product_key_issue_jobs_v5')")
            legacy_tables = int((cursor.fetchone() or {}).get('n', 0))
            for table in ('product_key_issue_jobs_v4', 'product_key_issue_jobs_v5'):
                cursor.execute('SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s', (table,))
                if int((cursor.fetchone() or {}).get('n', 0)):
                    cursor.execute("SELECT COALESCE(SUM(GREATEST(requested_count-processed_count,0)),0) AS n FROM " + table + " WHERE tenant_id=%s AND status IN ('queued','processing','cancel_requested')", (tenant_id,))
                    reserved += int((cursor.fetchone() or {}).get('n', 0))
            if legacy_tables or current_licenses + reserved + len(items) > int(tenant['max_licenses']):
                raise BaaSError(410 if legacy_tables else 409,
                                'bulk_issuance_moved_to_v8' if legacy_tables else 'license_quota_exceeded',
                                {'replacement': '/api/baas/v8/issuance.php'} if legacy_tables else {})
            cursor.execute("INSERT INTO baas_batch_jobs(tenant_id,client_id,request_key,status,requested_count) VALUES(%s,%s,%s,'processing',%s)", (tenant_id, int(client['id']), idem, len(items)))
            job_id = int(cursor.lastrowid)
        from core import license_key_hash, offline_secret, offline_lookup, offline_secret_encrypt
        config = {'key_pepper': secret_value('key_pepper'), 'token_secret': secret_value('token_secret')}
        results = []
        succeeded = failed = 0
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                results.append({'index': index, 'ok': False, 'error': 'product_not_found'})
                failed += 1
                continue
            try:
                product_id = int(item.get('product_id') or 0)
            except (TypeError, ValueError):
                product_id = 0
            with connection.cursor() as cursor:
                cursor.execute("SELECT id FROM products WHERE id=%s AND tenant_id=%s AND status='active'", (product_id, tenant_id))
                product = cursor.fetchone()
            if not product:
                results.append({'index': index, 'ok': False, 'error': 'product_not_found'})
                failed += 1
                continue
            item_succeeded = False
            for _ in range(5):
                product_key = _generate_baas_product_key()
                secret = offline_secret(product_key)
                try:
                    with connection.cursor() as cursor:
                        cursor.execute('INSERT INTO licenses(tenant_id,product_id,key_hash,label,active,max_devices,offline_lookup,offline_secret_enc) VALUES(%s,%s,%s,%s,1,1,%s,%s)', (tenant_id, product_id, license_key_hash(config, product_key), str(item.get('label', ''))[:100] or None, offline_lookup(secret), offline_secret_encrypt(config, secret)))
                        license_id = int(cursor.lastrowid)
                    results.append({'index': index, 'ok': True, 'license_id': license_id, 'product_key': product_key})
                    succeeded += 1
                    item_succeeded = True
                    break
                except Exception as exc:
                    connection.rollback()
                    if getattr(exc, 'args', [None])[0] not in (1062, '23000'):
                        break
            if not item_succeeded:
                results.append({'index': index, 'ok': False, 'error': 'issue_failed'})
                failed += 1
        for result in results:
            if result.get('ok'):
                _queue_webhook(connection, tenant_id, 'license.issued', {'license_id': int(result['license_id']), 'batch_job_id': job_id})
        stored = [{key: value for key, value in item.items() if key != 'product_key'} for item in results]
        with connection.cursor() as cursor:
            cursor.execute("UPDATE baas_batch_jobs SET status='completed',succeeded_count=%s,failed_count=%s,result_json=%s,completed_at=UTC_TIMESTAMP() WHERE id=%s", (succeeded, failed, json.dumps(stored, ensure_ascii=False, separators=(',', ':')), job_id))
        connection.commit()
        _usage(connection, client, 'batch.issue', 207, rid, ip_hash)
        return _reply(207, {'ok': failed == 0, 'job_id': job_id, 'succeeded': succeeded, 'failed': failed, 'results': results}, headers)
    except BaaSError as exc:
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        error = str(exc)
        status = 413 if error == 'request_too_large' else 400
        return _reply(status, {'ok': False, 'error': error})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'server_not_writable'})
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def licenses_bulk_delete(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    if str(request_context.get('method', '')) != 'POST':
        return _reply(405, {'ok': False, 'error': 'method_not_allowed'})
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'licenses:write', 'licenses.bulk_delete', rid)
        if str(client.get('tenant_environment') or '') != 'sandbox':
            raise BaaSError(403, 'sandbox_only')
        from ha_handlers import _effective_role
        role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
        writable = role == 'primary' and _effective_role() != 'maintenance' or (role == 'standby' and _effective_role() == 'promoted')
        if not writable:
            raise BaaSError(503, 'server_not_writable')
        _assert_write_fence(connection)
        data = _baas_json_input(request_context)
        try:
            product_id = int(data.get('product_id') or 0)
        except (TypeError, ValueError):
            product_id = 0
        raw_ids = data.get('license_ids')
        if product_id < 1:
            raise BaaSError(400, 'invalid_product_id')
        if not isinstance(raw_ids, list) or not 1 <= len(raw_ids) <= 1000:
            raise BaaSError(400, 'invalid_license_ids', {'max_count': 1000})
        license_ids = []
        for value in raw_ids:
            if type(value) is int:
                license_id = value
            elif isinstance(value, str) and re.fullmatch('[0-9]{1,20}', value):
                license_id = int(value)
            else:
                raise BaaSError(400, 'invalid_license_ids')
            if license_id < 1:
                raise BaaSError(400, 'invalid_license_ids')
            license_ids.append(license_id)
        if len(set(license_ids)) != len(license_ids):
            raise BaaSError(400, 'duplicate_license_ids')
        idem = str(data.get('idempotency_key', request_context.get('header:idempotency-key', ''))).strip()
        if re.fullmatch('[A-Za-z0-9_-]{20,100}', idem) is None:
            raise BaaSError(400, 'invalid_idempotency_key')
        reason = str(data.get('reason', 'sandbox_bulk_delete')).strip() or 'sandbox_bulk_delete'
        reason = reason[:200]
        canonical_ids = sorted(license_ids)
        canonical = json.dumps({'product_id': product_id, 'license_ids': canonical_ids, 'reason': reason}, ensure_ascii=True, separators=(',', ':'))
        request_hash = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s LIMIT 1', (int(client['tenant_id']), 'baas_bulk_delete_licenses', idem))
            saved = cursor.fetchone()
        if saved and saved.get('response_json'):
            try:
                response = json.loads(str(saved['response_json']))
            except json.JSONDecodeError:
                response = None
            if not isinstance(response, dict) or not hmac.compare_digest(str(response.get('_request_hash', '')), request_hash):
                raise BaaSError(409, 'idempotency_key_reused_with_different_request')
            response.pop('_request_hash', None)
            _usage(connection, client, 'licenses.bulk_delete.replay', 200, rid, ip_hash)
            return _reply(200, response, headers)
        tenant_id = int(client['tenant_id'])
        deleted_by = hashlib.sha256(('tenant_api_client:' + str(client.get('id', 0))).encode()).hexdigest()
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute('SELECT id FROM products WHERE id=%s AND tenant_id=%s LIMIT 1', (product_id, tenant_id))
            if not cursor.fetchone():
                connection.rollback()
                raise BaaSError(404, 'product_not_found')
            placeholders = ','.join(['%s'] * len(license_ids))
            cursor.execute('SELECT id FROM licenses WHERE tenant_id=%s AND product_id=%s AND active=1 AND deleted_at IS NULL AND id IN (' + placeholders + ') FOR UPDATE', tuple([tenant_id, product_id] + license_ids))
            selected = cursor.fetchall()
        eligible = [int(row['id'] if isinstance(row, dict) else row[0]) for row in selected]
        deleted = len(eligible)
        revoked_devices = cancelled_phone = revoked_offline = 0
        if eligible:
            eligible_placeholders = ','.join(['%s'] * len(eligible))
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET active=0,revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),deleted_at=UTC_TIMESTAMP(),deleted_reason=%s,deleted_by=%s WHERE tenant_id=%s AND product_id=%s AND active=1 AND deleted_at IS NULL AND id IN (' + eligible_placeholders + ')', tuple([reason, deleted_by, tenant_id, product_id] + eligible))
                deleted = int(getattr(cursor, 'rowcount', deleted))
                cursor.execute('UPDATE license_devices SET revoked_at=UTC_TIMESTAMP(),token_version=token_version+1 WHERE revoked_at IS NULL AND license_id IN (' + eligible_placeholders + ')', tuple(eligible))
                revoked_devices = int(getattr(cursor, 'rowcount', 0))
                cursor.execute("UPDATE phone_activation_requests SET status='cancelled',cancelled_at=COALESCE(cancelled_at,UTC_TIMESTAMP()),cancelled_reason=COALESCE(cancelled_reason,'license_deleted') WHERE status NOT IN ('confirmed','cancelled','expired') AND license_id IN (" + eligible_placeholders + ')', tuple(eligible))
                cancelled_phone = int(getattr(cursor, 'rowcount', 0))
                cursor.execute("UPDATE offline_activation_requests SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),revocation_reason=COALESCE(revocation_reason,'license_deleted') WHERE revoked_at IS NULL AND license_id IN (" + eligible_placeholders + ')', tuple(eligible))
                revoked_offline = int(getattr(cursor, 'rowcount', 0))
                cursor.execute("SELECT id,events_json FROM tenant_webhooks WHERE tenant_id=%s AND status='active'", (tenant_id,))
                hooks = cursor.fetchall()
                active_hooks = []
                for hook in hooks:
                    try:
                        events = json.loads(str(hook.get('events_json') or '[]'))
                    except (TypeError, json.JSONDecodeError):
                        events = []
                    if isinstance(events, list) and 'license.revoked' in events:
                        active_hooks.append(int(hook['id']))
                for deleted_license_id in eligible:
                    event_id = uuid.uuid4().hex
                    payload = json.dumps({'id': event_id, 'type': 'license.revoked', 'created_at': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'data': {'license_id': deleted_license_id, 'reason': 'deleted'}}, ensure_ascii=False, separators=(',', ':'))
                    for webhook_id in active_hooks:
                        cursor.execute('INSERT IGNORE INTO tenant_webhook_deliveries (tenant_id,webhook_id,event_type,event_id,payload_json) VALUES(%s,%s,%s,%s,%s)', (tenant_id, webhook_id, 'license.revoked', event_id, payload))
        response = {'ok': True, 'api_version': 'baas-v1.1', 'request_id': rid, 'environment': 'sandbox', 'product_id': product_id, 'requested_count': len(license_ids), 'deleted_count': deleted, 'skipped_count': len(license_ids) - deleted, 'revoked_devices': revoked_devices, 'cancelled_phone_requests': cancelled_phone, 'revoked_offline_requests': revoked_offline, '_request_hash': request_hash}
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO idempotency_keys(tenant_id,operation,request_key,response_json) VALUES(%s,%s,%s,%s)', (tenant_id, 'baas_bulk_delete_licenses', idem, json.dumps(response, ensure_ascii=False, separators=(',', ':'))))
        connection.commit()
        response.pop('_request_hash', None)
        _usage(connection, client, 'licenses.bulk_delete', 200, rid, ip_hash)
        return _reply(200, response, headers)
    except BaaSError as exc:
        if connection and getattr(connection, 'in_transaction', False):
            connection.rollback()
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        error = str(exc)
        status_code = 413 if error == 'request_too_large' else 400
        return _reply(status_code, {'ok': False, 'error': error})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception as exc:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        if connection and getattr(exc, 'args', ()) and (exc.args[0] in (1062, '23000')):
            try:
                with connection.cursor() as cursor:
                    cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s LIMIT 1', (int(client['tenant_id']), 'baas_bulk_delete_licenses', idem))
                    saved = cursor.fetchone()
                response = json.loads(str(saved['response_json'])) if saved and saved.get('response_json') else None
                if isinstance(response, dict) and hmac.compare_digest(str(response.get('_request_hash', '')), request_hash):
                    response.pop('_request_hash', None)
                    _usage(connection, client, 'licenses.bulk_delete.replay', 200, rid, ip_hash)
                    return _reply(200, response, headers)
            except Exception:
                pass
        return _reply(503, {'ok': False, 'error': 'bulk_license_delete_failed'})
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def benchmark_cleanup(request_context):
    """Remove only explicitly tagged benchmark licenses from sandbox tenants."""
    rid = uuid.uuid4().hex[:16]
    connection = None
    if str(request_context.get('method', 'GET')) != 'POST':
        return _reply(405, {'ok': False, 'error': 'method_not_allowed'})
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'licenses:write', 'benchmark.cleanup', rid)
        if str(client.get('tenant_environment') or '') != 'sandbox':
            raise BaaSError(403, 'benchmark_sandbox_required')
        requested_environment = str(request_context.get('header:x-baas-environment', 'production')).strip().lower()
        benchmark_flag = str(request_context.get('header:x-tuti-baas-benchmark', request_context.get('header:x-baas-benchmark', ''))).strip().lower()
        supplied_token = str(request_context.get('header:x-baas-benchmark-token', '')).strip()
        expected_token = str(secret_value('baas_benchmark_token') or '').strip()
        enabled = requested_environment == 'sandbox' and benchmark_flag in {'1', 'true', 'yes', 'benchmark'} and (len(expected_token) >= 32) and bool(supplied_token) and hmac.compare_digest(supplied_token, expected_token)
        if not enabled:
            raise BaaSError(403, 'benchmark_sandbox_required')
        if str(client.get('tenant_environment') or '') != requested_environment:
            raise BaaSError(403, 'benchmark_sandbox_required')
        _assert_write_fence(connection)
        data = _baas_json_input(request_context)
        try:
            product_id_value = int(data.get('product_id') or 0)
        except (TypeError, ValueError):
            product_id_value = 0
        run_id = str(data.get('benchmark_run_id') or '').strip().lower()
        if product_id_value < 1:
            raise BaaSError(400, 'invalid_product_id')
        if re.fullmatch('[a-f0-9]{32}', run_id) is None:
            raise BaaSError(400, 'invalid_benchmark_run_id')
        tenant_id = int(client['tenant_id'])
        prefix = '[bench:' + run_id + ']%'
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute('SELECT id FROM licenses WHERE tenant_id=%s AND product_id=%s AND deleted_at IS NULL AND label LIKE %s FOR UPDATE', (tenant_id, product_id_value, prefix))
            rows = cursor.fetchall()
            license_ids = [int(row['id']) for row in rows]
            deleted = revoked_devices = cancelled_phone = revoked_offline = 0
            for license_id in license_ids:
                cursor.execute("UPDATE licenses SET active=0,revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),deleted_at=UTC_TIMESTAMP(),deleted_reason='benchmark_completed',deleted_by=%s WHERE id=%s AND tenant_id=%s AND deleted_at IS NULL", (hashlib.sha256(('benchmark_cleanup:' + run_id).encode()).hexdigest(), license_id, tenant_id))
                deleted += int(getattr(cursor, 'rowcount', 0))
                revoked_devices += _revoke_license_devices(connection, license_id)
                cursor.execute("UPDATE phone_activation_requests SET status='cancelled',cancelled_at=COALESCE(cancelled_at,UTC_TIMESTAMP()),cancelled_reason=COALESCE(cancelled_reason,'benchmark_completed') WHERE license_id=%s AND status NOT IN ('confirmed','cancelled','expired')", (license_id,))
                cancelled_phone += int(getattr(cursor, 'rowcount', 0))
                cursor.execute("UPDATE offline_activation_requests SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),revocation_reason=COALESCE(revocation_reason,'benchmark_completed') WHERE license_id=%s AND revoked_at IS NULL", (license_id,))
                revoked_offline += int(getattr(cursor, 'rowcount', 0))
        connection.commit()
        return _reply(200, {'ok': True, 'request_id': rid, 'benchmark_run_id': run_id, 'deleted_count': deleted, 'revoked_devices': revoked_devices, 'cancelled_phone_requests': cancelled_phone, 'revoked_offline_requests': revoked_offline}, headers)
    except BaaSError as exc:
        if connection:
            connection.rollback()
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        if connection:
            connection.rollback()
        error = str(exc)
        status = 413 if error == 'request_too_large' else 400
        return _reply(status, {'ok': False, 'error': error})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'benchmark_cleanup_failed'})
    finally:
        if connection:
            connection.close()
_SANDBOX_SCOPES = ('tenant:read', 'products:write', 'licenses:read', 'licenses:write')

def _sandbox_scopes(raw):
    if raw is None:
        return list(_SANDBOX_SCOPES)
    if isinstance(raw, str):
        value = _sandbox_php_trim(raw)
        if not value:
            return []
        if value.startswith('['):
            try:
                raw = json.loads(value)
            except json.JSONDecodeError:
                raw = re.split('\\s*,\\s*', value, flags=re.ASCII)
        else:
            raw = re.split('\\s*,\\s*', value, flags=re.ASCII)
    if isinstance(raw, dict):
        raw = list(raw.values())
    elif not isinstance(raw, list):
        raw = [raw]
    scopes = []
    for value in raw:
        if isinstance(value, (str, int, float, bool)):
            for scope in re.split('\\s*,\\s*', _sandbox_php_trim(value), flags=re.ASCII):
                if scope in _SANDBOX_SCOPES and scope not in scopes:
                    scopes.append(scope)
    return scopes

def _sandbox_php_string(value):
    """Match PHP's JSON scalar/array casts used by sandbox-key inputs."""
    if value is None or value is False:
        return ''
    if value is True:
        return '1'
    if isinstance(value, (list, dict)):
        return 'Array'
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)

def _sandbox_php_trim(value):
    from core import PHP_TRIM_CHARS
    return _sandbox_php_string(value).strip(PHP_TRIM_CHARS)

def _sandbox_ascii_lower(value):
    return value.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))

def _sandbox_key_issue(connection, tenant_id, name, scopes, rate, expires):
    if tenant_id < 1 or not name or (not scopes):
        raise BaaSError(400, 'invalid_api_client')
    token = 'baas_sandbox_' + base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii')
    prefix = token[:12]
    pepper = key_pepper({'key_pepper': secret_value('key_pepper')})
    key_hash = hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()
    expires_at = None
    if str(expires or '').strip():
        value = str(expires).strip()
        try:
            parsed = parse_iso_datetime(value[:-1] + '+00:00' if value.endswith('Z') else value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            expires_at = parsed.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            raise BaaSError(400, 'invalid_expires_at')
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO tenant_api_clients(tenant_id,name,key_prefix,key_hash,scopes_json,rate_limit_per_minute,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s)', (tenant_id, name[:120], prefix, key_hash, json.dumps(scopes, separators=(',', ':')), max(10, min(600, int(rate))), expires_at))
        client_id = int(cursor.lastrowid)
    return {'client_id': client_id, 'tenant_id': tenant_id, 'api_key': token, 'key_prefix': prefix, 'scopes': scopes}

def _sandbox_idempotency_replay(connection, tenant, operation, key):
    if re.fullmatch('[A-Za-z0-9_-]{20,100}', key) is None:
        raise BaaSError(400, 'invalid_idempotency_key')
    with connection.cursor() as cursor:
        cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s', (tenant, operation, key))
        saved = cursor.fetchone()
    if saved and saved.get('response_json'):
        from idempotency_crypto import encrypt_response, decrypt_response
        stored = str(saved['response_json'])
        context = f'{tenant}|{operation}|{key}'
        pepper = secret_value('key_pepper')
        plain = decrypt_response(stored, context, pepper)
        if plain is None:
            if not stored.startswith('{'):
                raise BaaSError(503, 'idempotency_result_unavailable')
            plain = stored
            encrypted = encrypt_response(plain, context, pepper)
            with connection.cursor() as cursor:
                cursor.execute('UPDATE idempotency_keys SET response_json=%s WHERE tenant_id=%s AND operation=%s AND request_key=%s AND response_json=%s', (encrypted, tenant, operation, key, stored))
            connection.commit()
        return plain
    return None

@legacy_compatible(callback_index=0, request_index=None)
def _sandbox_replay_response(response_json, headers=()):
    body = response_json.encode('utf-8')
    response_headers = [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Idempotent-Replay', 'true')]
    response_headers.extend(headers)
    _http_status, _http_headers = ('200 OK', response_headers)
    return make_response([body], _http_status, _http_headers)

def _sandbox_idempotency_save(connection, tenant, operation, key, response):
    from idempotency_crypto import encrypt_response
    plain = json.dumps(response, ensure_ascii=False, separators=(',', ':'))
    encrypted = encrypt_response(plain, f'{tenant}|{operation}|{key}', secret_value('key_pepper'))
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO idempotency_keys(tenant_id,operation,request_key,response_json) VALUES(%s,%s,%s,%s)', (tenant, operation, key, encrypted))

@legacy_compatible(callback_index=1, request_index=0)
def sandbox_keys(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    method = str(request_context.get('method', 'GET'))
    operation = 'sandbox_keys.' + method.lower()
    try:
        connection = database.connect()
        scope = 'tenant:read' if method == 'GET' else 'licenses:write'
        client, headers, ip_hash = _authorize_key(connection, request_context, scope, operation, rid)
        if str(client.get('tenant_environment') or '') != 'production' or client.get('parent_tenant_id'):
            raise BaaSError(409, 'production_key_required')
        production_tenant = int(client['tenant_id'])
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,slug,name,plan_code,max_products,max_licenses FROM tenants WHERE id=%s AND environment='production' AND status='active'", (production_tenant,))
            parent = cursor.fetchone()
            if not parent:
                raise BaaSError(404, 'production_tenant_not_found')
            cursor.execute("SELECT id,slug FROM tenants WHERE parent_tenant_id=%s AND environment='sandbox' LIMIT 1", (production_tenant,))
            sandbox = cursor.fetchone()
        if method == 'GET':
            if not sandbox:
                return _reply(200, {'ok': True, 'production_tenant_id': production_tenant, 'sandbox_tenant_id': None, 'api_clients': []}, headers)
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,tenant_id,name,key_prefix,scopes_json,status,rate_limit_per_minute,last_used_at,expires_at,created_at,revoked_at,replacement_client_id,grace_expires_at FROM tenant_api_clients WHERE tenant_id=%s ORDER BY id DESC LIMIT 500', (int(sandbox['id']),))
                clients = cursor.fetchall()
            _usage(connection, client, 'sandbox_keys.list', 200, rid, ip_hash)
            return _reply(200, {'ok': True, 'production_tenant_id': production_tenant, 'sandbox_tenant_id': int(sandbox['id']), 'sandbox_slug': str(sandbox['slug']), 'api_clients': clients}, headers)
        if method != 'POST':
            raise BaaSError(405, 'method_not_allowed')
        _baas_require_writable()
        _assert_write_fence(connection)
        data = _baas_json_input(request_context)
        action_raw = data.get('action')
        action = _sandbox_php_string('issue' if action_raw is None else action_raw)
        if not sandbox:
            base = str(parent['slug'])[:55] + '-sandbox'
            slug, suffix = (base, 2)
            while True:
                with connection.cursor() as cursor:
                    cursor.execute('SELECT 1 FROM tenants WHERE slug=%s', (slug,))
                    if not cursor.fetchone():
                        break
                tail = '-' + str(suffix)
                suffix += 1
                slug = base[:63 - len(tail)] + tail
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("INSERT INTO tenants(slug,name,status,plan_code,environment,parent_tenant_id,max_products,max_licenses) VALUES(%s,%s,'active',%s,'sandbox',%s,%s,%s)", (slug, (str(parent['name']) + ' Sandbox')[:160], parent['plan_code'], production_tenant, int(parent['max_products']), int(parent['max_licenses'])))
                    sandbox_id = int(cursor.lastrowid)
                    cursor.execute("INSERT INTO products(tenant_id,code,name,status) VALUES(%s,'default',%s,'active')", (sandbox_id, (str(parent['name']) + ' Sandbox Default Product')[:160]))
                connection.commit()
                sandbox = {'id': sandbox_id, 'slug': slug}
            except Exception:
                connection.rollback()
                raise
        sandbox_tenant = int(sandbox['id'])
        if action == 'issue':
            idem_raw = data.get('idempotency_key')
            idem = _sandbox_php_trim(request_context.get('header:idempotency-key', '') if idem_raw is None else idem_raw)
            replay = _sandbox_idempotency_replay(connection, production_tenant, 'baas_sandbox_key_issue', idem)
            if replay is not None:
                return _sandbox_replay_response(replay, headers)
            name_raw = data.get('name')
            name = _sandbox_php_trim('Sandbox Client' if name_raw is None else name_raw)
            scopes = _sandbox_scopes(data.get('scopes'))
            from core import php_int_cast
            raw_rate = data.get('rate_limit_per_minute')
            rate = php_int_cast(120 if raw_rate is None else raw_rate)
            raw_expires = data.get('expires_at')
            expires = _sandbox_php_trim('' if raw_expires is None else raw_expires)
            result = _sandbox_key_issue(connection, sandbox_tenant, name, scopes, rate, expires)
            response = {'ok': True, 'production_tenant_id': production_tenant, 'sandbox_tenant_id': sandbox_tenant, 'environment': 'sandbox', **result}
            _sandbox_idempotency_save(connection, production_tenant, 'baas_sandbox_key_issue', idem, response)
            _queue_webhook(connection, sandbox_tenant, 'sandbox.key.issued', {k: v for k, v in result.items() if k != 'api_key'})
            connection.commit()
            _usage(connection, client, 'sandbox_keys.issue', 201, rid, ip_hash)
            return _reply(201, response, headers)
        if action == 'rotate':
            idem_raw = data.get('idempotency_key')
            idem = _sandbox_php_trim(request_context.get('header:idempotency-key', '') if idem_raw is None else idem_raw)
            replay = _sandbox_idempotency_replay(connection, production_tenant, 'baas_sandbox_key_rotate', idem)
            if replay is not None:
                return _sandbox_replay_response(replay, headers)
            from core import php_int_cast
            old_id = php_int_cast(data.get('client_id') or 0)
            raw_grace = data.get('grace_minutes')
            grace = max(0, min(10080, php_int_cast(60 if raw_grace is None else raw_grace)))
            with connection.cursor() as cursor:
                cursor.execute('SELECT tenant_id,name,scopes_json,rate_limit_per_minute,expires_at FROM tenant_api_clients WHERE id=%s AND tenant_id=%s AND revoked_at IS NULL', (old_id, sandbox_tenant))
                old = cursor.fetchone()
            if not old:
                raise BaaSError(404, 'api_client_not_found')
            scopes_raw = old.get('scopes_json')
            try:
                old_scopes = json.loads(str(scopes_raw or '[]'))
            except json.JSONDecodeError:
                old_scopes = []
            raw_expires = data.get('expires_at')
            default_expires = old.get('expires_at') or ''
            expires = _sandbox_php_trim(default_expires if raw_expires is None else raw_expires)
            result = _sandbox_key_issue(connection, sandbox_tenant, str(old['name']) + ' rotated', _sandbox_scopes(old_scopes), int(old['rate_limit_per_minute']), expires)
            grace_expires = None
            with connection.cursor() as cursor:
                if grace == 0:
                    cursor.execute("UPDATE tenant_api_clients SET status='revoked',revoked_at=UTC_TIMESTAMP(),replacement_client_id=%s WHERE id=%s AND tenant_id=%s", (result['client_id'], old_id, sandbox_tenant))
                else:
                    grace_expires = datetime.now(timezone.utc) + timedelta(minutes=grace)
                    grace_text = grace_expires.strftime('%Y-%m-%d %H:%M:%S')
                    cursor.execute("UPDATE tenant_api_clients SET status='retiring',grace_expires_at=%s,replacement_client_id=%s WHERE id=%s AND tenant_id=%s", (grace_text, result['client_id'], old_id, sandbox_tenant))
                    grace_expires = grace_text
            response = {'ok': True, 'production_tenant_id': production_tenant, 'sandbox_tenant_id': sandbox_tenant, 'environment': 'sandbox', 'replaced_client_id': old_id, 'grace_expires_at': grace_expires, **result}
            _sandbox_idempotency_save(connection, production_tenant, 'baas_sandbox_key_rotate', idem, response)
            _queue_webhook(connection, sandbox_tenant, 'sandbox.key.rotated', {k: v for k, v in response.items() if k != 'api_key'})
            connection.commit()
            _usage(connection, client, 'sandbox_keys.rotate', 201, rid, ip_hash)
            return _reply(201, response, headers)
        if action == 'revoke':
            try:
                from core import php_int_cast
                client_id = php_int_cast(data.get('client_id') or 0)
            except (TypeError, ValueError):
                client_id = 0
            with connection.cursor() as cursor:
                cursor.execute("UPDATE tenant_api_clients SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE id=%s AND tenant_id=%s AND revoked_at IS NULL", (client_id, sandbox_tenant))
                affected = int(getattr(cursor, 'rowcount', 0))
            connection.commit()
            _usage(connection, client, 'sandbox_keys.revoke', 200, rid, ip_hash)
            return _reply(200, {'ok': True, 'production_tenant_id': production_tenant, 'sandbox_tenant_id': sandbox_tenant, 'client_id': client_id, 'affected': affected}, headers)
        raise BaaSError(400, 'invalid_action')
    except BaaSError as exc:
        if connection and getattr(connection, 'in_transaction', False):
            connection.rollback()
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        error = str(exc)
        status_code = 413 if error == 'request_too_large' else 400
        return _reply(status_code, {'ok': False, 'error': error})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'sandbox_key_service_unavailable'})
    finally:
        if connection:
            connection.close()
_SAMPLE_SDK_SCOPES = ['tenant:read', 'products:write', 'licenses:write']
_SAMPLE_SDK_POLICY = {'policy_version': 1, 'class': 'sample_sdk', 'audience': 'baas_subscriber_sample', 'sandbox_only': True, 'allowed_operations': ['status', 'products.get', 'products.post', 'licenses.v3.post', 'audit.list', 'billing.summary'], 'allowed_routes': ['GET /api/baas/v1/status.php', 'GET /api/baas/v1/products.php', 'POST /api/baas/v1/products.php', 'POST /api/baas/v3/licenses.php', 'GET /api/baas/v1/audit.php', 'GET /api/baas/v1/billing.php'], 'allowed_product_actions': ['create'], 'v3_max_batch': 1000, 'blocked_by_default': True}

def _sample_sdk_php_int(value):
    from core import php_int_cast
    return php_int_cast(value)

def _sample_sdk_issue(connection, tenant_id, name, rate, ttl_hours):
    from core import key_pepper
    ttl = max(1, min(720, int(ttl_hours)))
    limit = max(10, min(600, int(rate)))
    token = 'baas_sdk_' + base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii')
    prefix = token[:12]
    pepper = key_pepper({'key_pepper': secret_value('key_pepper')})
    token_hash = hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()
    expiry = datetime.now(timezone.utc) + timedelta(hours=ttl)
    expires_at = expiry.strftime('%Y-%m-%d %H:%M:%S')
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO tenant_api_clients(tenant_id,name,key_prefix,key_hash,scopes_json,key_kind,policy_json,rate_limit_per_minute,expires_at) VALUES(%s,%s,%s,%s,%s,'sample_sdk',%s,%s,%s)", (tenant_id, name[:120], prefix, token_hash, json.dumps(_SAMPLE_SDK_SCOPES), json.dumps(_SAMPLE_SDK_POLICY, separators=(',', ':')), limit, expires_at))
        client_id = int(cursor.lastrowid)
    return {'client_id': client_id, 'tenant_id': tenant_id, 'api_key': token, 'key_prefix': prefix, 'key_class': 'sample_sdk', 'environment': 'sandbox', 'scopes': list(_SAMPLE_SDK_SCOPES), 'policy': dict(_SAMPLE_SDK_POLICY), 'rate_limit_per_minute': limit, 'expires_at': expires_at, 'expires_at_utc': expiry.isoformat(timespec='seconds')}

def _baas_require_writable():
    """Match PHP's explicit baas_writable() gate before BaaS endpoint writes."""
    from ha_handlers import _effective_role
    role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    effective = _effective_role()
    writable = role == 'primary' and effective != 'maintenance' or (role == 'standby' and effective == 'promoted')
    if not writable:
        raise BaaSError(503, 'server_not_writable')

def _sample_sdk_replay(connection, tenant_id, operation, key):
    if re.fullmatch('[A-Za-z0-9_-]{20,100}', key) is None:
        raise BaaSError(400, 'invalid_idempotency_key')
    with connection.cursor() as cursor:
        cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s', (tenant_id, operation, key))
        saved = cursor.fetchone()
    if saved and saved.get('response_json'):
        return str(saved['response_json'])
    return None

@legacy_compatible(callback_index=0, request_index=None)
def _sample_sdk_replay_response(response_json, headers=()):
    body = response_json.encode('utf-8')
    response_headers = [('Content-Type', 'application/json; charset=utf-8')]
    response_headers.extend(headers)
    response_headers.append(('X-Idempotent-Replay', 'true'))
    _http_status, _http_headers = ('200 OK', response_headers)
    return make_response([body], _http_status, _http_headers)

def _sample_sdk_save(connection, tenant_id, operation, key, response):
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO idempotency_keys(tenant_id,operation,request_key,response_json) VALUES(%s,%s,%s,%s)', (tenant_id, operation, key, json.dumps(response, ensure_ascii=False, separators=(',', ':'))))

def _sample_sdk_ensure_sandbox(connection, parent, production_tenant, manage_transaction=True):
    with connection.cursor() as cursor:
        cursor.execute("SELECT id,slug FROM tenants WHERE parent_tenant_id=%s AND environment='sandbox' AND status='active' LIMIT 1", (production_tenant,))
        sandbox = cursor.fetchone()
    if sandbox:
        return sandbox
    if manage_transaction:
        connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,slug FROM tenants WHERE parent_tenant_id=%s AND environment='sandbox' AND status='active' LIMIT 1 FOR UPDATE", (production_tenant,))
            sandbox = cursor.fetchone()
        if sandbox:
            if manage_transaction:
                connection.commit()
            return sandbox
        base = str(parent['slug'])[:55] + '-sandbox'
        slug = base
        suffix = 2
        while True:
            with connection.cursor() as cursor:
                cursor.execute('SELECT 1 FROM tenants WHERE slug=%s', (slug,))
                if not cursor.fetchone():
                    break
            tail = '-' + str(suffix)
            suffix += 1
            slug = base[:63 - len(tail)] + tail
        with connection.cursor() as cursor:
            cursor.execute("INSERT INTO tenants(slug,name,status,plan_code,environment,parent_tenant_id,max_products,max_licenses) VALUES(%s,%s,'active',%s,'sandbox',%s,%s,%s)", (slug, (str(parent['name']) + ' Sandbox')[:160], parent['plan_code'], production_tenant, int(parent['max_products']), int(parent['max_licenses'])))
            sandbox_id = int(cursor.lastrowid)
            cursor.execute("INSERT INTO products(tenant_id,code,name,status) VALUES(%s,'default',%s,'active')", (sandbox_id, (str(parent['name']) + ' Sandbox Default Product')[:160]))
        if manage_transaction:
            connection.commit()
        return {'id': sandbox_id, 'slug': slug}
    except Exception:
        if manage_transaction:
            connection.rollback()
        raise

@legacy_compatible(callback_index=None, request_index=3)
def _sample_sdk_record(connection, auth_mode, client, request_context, operation, status, context):
    if auth_mode == 'tenant' and client is not None:
        _usage(connection=connection, client=client, operation=operation, status=status, request_id=uuid.uuid4().hex[:16], ip_hash=_client_ip_hash(request_context))
        return
    if auth_mode == 'ha':
        import audit
        audit.append_event('sample_sdk_key_' + operation, {'status': status, **context}, request_context.get('client_address', ''), role=os.environ.get('PYTHON_MIGRATION_HA_ROLE', 'unknown'))

@legacy_compatible(callback_index=None, request_index=2)
def _sample_sdk_sync_peer(auth_mode, reason, request_context):
    if auth_mode == 'ha':
        from ha_handlers import ha_sync_peer
        ha_sync_peer(reason, request_context)

@legacy_compatible(callback_index=1, request_index=0)
def sample_sdk_keys(request_context):
    """Manage subscriber sample SDK keys for an active production tenant."""
    rid = uuid.uuid4().hex[:16]
    connection = None
    method = str(request_context.get('method', 'GET'))
    try:
        ha_credential = bool(_sandbox_php_trim(request_context.get('header:x-ha-token', '')) or _sandbox_php_trim(request_context.get('header:x-ha-session', '')))
        auth_mode = 'ha' if ha_credential else 'tenant'
        client = None
        ip_hash = _client_ip_hash(request_context)
        if ha_credential:
            sync_token = str(os.environ.get('PYTHON_MIGRATION_HA_SYNC_TOKEN', '') or secret_value('ha_sync_token'))
            provided_token = _sandbox_php_trim(request_context.get('header:x-ha-token', ''))
            sync_authorized = bool(sync_token and provided_token and hmac.compare_digest(sync_token.encode('utf-8'), provided_token.encode('utf-8')))
            session_claims = None if sync_authorized else _decode_admin_session(_sandbox_php_trim(request_context.get('header:x-ha-session', '')))
            session_authorized = False
            if session_claims is not None:
                scopes = session_claims.get('scope', [])
                if not isinstance(scopes, list):
                    scopes = [scopes]
                if 'license:manage' in scopes:
                    credential_hash = str(session_claims.get('credential_id_hash') or '').lower()
                    try:
                        if re.fullmatch('[a-f0-9]{64}', credential_hash):
                            connection = database.connect()
                            role = _admin_role(connection, session_claims)
                        else:
                            role = _admin_role(None, session_claims)
                    except Exception:
                        role = None
                    session_authorized = _role_allows_scope(role, 'license:manage')
            if not sync_authorized and (not session_authorized):
                return json_response('404 Not Found', {'ok': False, 'error': 'not_found'})
            headers = []
            if connection is None:
                connection = database.connect()
        else:
            connection = database.connect()
            scope = 'tenant:read' if method == 'GET' else 'licenses:write'
            client, headers, ip_hash = _authorize_key(connection, request_context, scope, 'sample_sdk_keys.' + method.lower(), rid)
            if str(client.get('key_kind') or 'standard') != 'standard':
                raise BaaSError(403, 'standard_production_key_required')
            if str(client.get('tenant_environment') or '') != 'production' or client.get('parent_tenant_id'):
                raise BaaSError(409, 'production_key_required')
        with connection.cursor() as cursor:
            cursor.execute('SHOW COLUMNS FROM tenant_api_clients')
            columns = {str(row.get('Field') or '') for row in cursor.fetchall()}
        if not {'key_kind', 'policy_json'}.issubset(columns):
            raise BaaSError(503, 'sample_sdk_key_migration_required', {'required_migration': '019_sample_sdk_api_keys'})
        if method == 'POST':
            data = _baas_json_input(request_context)
        else:
            data = {}
        if auth_mode == 'ha' and method == 'GET':
            from http_utils import php_parse_query as parse_qs
            query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
            view = _sandbox_php_trim(query.get('view', [''])[-1])
            view = _sandbox_ascii_lower(view)
            if view == 'tenants':
                with connection.cursor() as cursor:
                    cursor.execute("SELECT id,slug,name,plan_code,max_products,max_licenses FROM tenants WHERE environment='production' AND parent_tenant_id IS NULL AND status='active' ORDER BY name,id")
                    tenants = cursor.fetchall()
                return _reply(200, {'ok': True, 'auth_mode': 'ha', 'production_tenants': tenants}, headers)
        if auth_mode == 'ha':
            if method == 'GET':
                from http_utils import php_parse_query as parse_qs
                query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
                production_tenant = _sample_sdk_php_int(query.get('tenant_id', [0])[-1])
            else:
                production_tenant = _sample_sdk_php_int(data.get('tenant_id') or 0)
        else:
            production_tenant = int(client['tenant_id'])
        if production_tenant < 1:
            raise BaaSError(400, 'production_tenant_required')
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,slug,name,plan_code,max_products,max_licenses FROM tenants WHERE id=%s AND environment='production' AND status='active'", (production_tenant,))
            parent = cursor.fetchone()
        if not parent:
            raise BaaSError(404, 'production_tenant_not_found')
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,slug FROM tenants WHERE parent_tenant_id=%s AND environment='sandbox' LIMIT 1", (production_tenant,))
            sandbox = cursor.fetchone()
        if method not in ('GET', 'POST'):
            raise BaaSError(405, 'method_not_allowed')
        if method == 'GET':
            if not sandbox:
                return _reply(200, {'ok': True, 'auth_mode': auth_mode, 'production_tenant_id': production_tenant, 'sandbox_tenant_id': None, 'api_clients': []}, headers)
            with connection.cursor() as cursor:
                cursor.execute("SELECT id,tenant_id,name,key_prefix,key_kind,policy_json,status,rate_limit_per_minute,last_used_at,expires_at,created_at,revoked_at,replacement_client_id,grace_expires_at FROM tenant_api_clients WHERE tenant_id=%s AND key_kind='sample_sdk' ORDER BY id DESC LIMIT 500", (int(sandbox['id']),))
                rows = cursor.fetchall()
            for row in rows:
                try:
                    row['policy'] = json.loads(str(row.pop('policy_json', '')))
                except (TypeError, json.JSONDecodeError):
                    row['policy'] = None
            _sample_sdk_record(connection, auth_mode, client, request_context, 'sample_sdk_keys.list', 200, {'production_tenant_id': production_tenant})
            return _reply(200, {'ok': True, 'auth_mode': auth_mode, 'production_tenant_id': production_tenant, 'sandbox_tenant_id': int(sandbox['id']), 'sandbox_slug': str(sandbox['slug']), 'api_clients': rows}, headers)
        _baas_require_writable()
        _assert_write_fence(connection)
        action_value = data.get('action')
        action = _sandbox_ascii_lower(_sandbox_php_trim('issue' if action_value is None else action_value))
        if not sandbox:
            sandbox = _sample_sdk_ensure_sandbox(connection, parent, production_tenant)
        sandbox_tenant = int(sandbox['id'])
        if action == 'issue':
            idem_value = data.get('idempotency_key')
            idem = _sandbox_php_trim(request_context.get('header:idempotency-key', '') if idem_value is None else idem_value)
            replay = _sample_sdk_replay(connection, production_tenant, 'baas_sample_sdk_key_issue', idem)
            if replay is not None:
                return _sample_sdk_replay_response(replay, headers)
            name_value = data.get('name')
            name = _sandbox_php_trim('Sample SDK Client' if name_value is None else name_value)
            name = name or 'Sample SDK Client'
            rate_value = data.get('rate_limit_per_minute')
            ttl_value = data.get('ttl_hours')
            rate = _sample_sdk_php_int(60 if rate_value is None else rate_value)
            ttl = _sample_sdk_php_int(168 if ttl_value is None else ttl_value)
            result = _sample_sdk_issue(connection, sandbox_tenant, name, rate, ttl)
            response = {'ok': True, 'auth_mode': auth_mode, 'production_tenant_id': production_tenant, 'sandbox_tenant_id': sandbox_tenant, 'sandbox_slug': str(sandbox['slug']), **result}
            _sample_sdk_save(connection, production_tenant, 'baas_sample_sdk_key_issue', idem, response)
            connection.commit()
            _sample_sdk_record(connection, auth_mode, client, request_context, 'sample_sdk_keys.issue', 201, {'production_tenant_id': production_tenant, 'client_id': result['client_id']})
            _sample_sdk_sync_peer(auth_mode, 'sample_sdk_key_issued', request_context)
            return _reply(201, response, headers)
        if action == 'rotate':
            idem_value = data.get('idempotency_key')
            idem = _sandbox_php_trim(request_context.get('header:idempotency-key', '') if idem_value is None else idem_value)
            replay = _sample_sdk_replay(connection, production_tenant, 'baas_sample_sdk_key_rotate', idem)
            if replay is not None:
                return _sample_sdk_replay_response(replay, headers)
            old_id = _sample_sdk_php_int(data.get('client_id') or 0)
            grace_value = data.get('grace_minutes')
            ttl_value = data.get('ttl_hours')
            grace = max(0, min(1440, _sample_sdk_php_int(15 if grace_value is None else grace_value)))
            ttl = _sample_sdk_php_int(168 if ttl_value is None else ttl_value)
            with connection.cursor() as cursor:
                cursor.execute("SELECT id,name,rate_limit_per_minute FROM tenant_api_clients WHERE id=%s AND tenant_id=%s AND key_kind='sample_sdk' AND revoked_at IS NULL", (old_id, sandbox_tenant))
                old = cursor.fetchone()
            if not old:
                raise BaaSError(404, 'sample_sdk_key_not_found')
            result = _sample_sdk_issue(connection, sandbox_tenant, str(old['name']) + ' rotated', int(old['rate_limit_per_minute']), ttl)
            grace_expires = None
            if grace == 0:
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE tenant_api_clients SET status='revoked',revoked_at=UTC_TIMESTAMP(),replacement_client_id=%s WHERE id=%s AND tenant_id=%s", (result['client_id'], old_id, sandbox_tenant))
            else:
                grace_expires = (datetime.now(timezone.utc) + timedelta(minutes=grace)).strftime('%Y-%m-%d %H:%M:%S')
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE tenant_api_clients SET status='retiring',grace_expires_at=%s,replacement_client_id=%s WHERE id=%s AND tenant_id=%s", (grace_expires, result['client_id'], old_id, sandbox_tenant))
            response = {'ok': True, 'auth_mode': auth_mode, 'replaced_client_id': old_id, 'grace_expires_at': grace_expires, **result}
            _sample_sdk_save(connection, production_tenant, 'baas_sample_sdk_key_rotate', idem, response)
            connection.commit()
            _sample_sdk_record(connection, auth_mode, client, request_context, 'sample_sdk_keys.rotate', 201, {'production_tenant_id': production_tenant, 'old_client_id': old_id, 'new_client_id': result['client_id']})
            _sample_sdk_sync_peer(auth_mode, 'sample_sdk_key_rotated', request_context)
            return _reply(201, response, headers)
        if action == 'revoke':
            client_id = _sample_sdk_php_int(data.get('client_id') or 0)
            with connection.cursor() as cursor:
                cursor.execute("UPDATE tenant_api_clients SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE id=%s AND tenant_id=%s AND key_kind='sample_sdk' AND revoked_at IS NULL", (client_id, sandbox_tenant))
                affected = int(getattr(cursor, 'rowcount', 0))
            connection.commit()
            _sample_sdk_record(connection, auth_mode, client, request_context, 'sample_sdk_keys.revoke', 200, {'production_tenant_id': production_tenant, 'client_id': client_id})
            _sample_sdk_sync_peer(auth_mode, 'sample_sdk_key_revoked', request_context)
            return _reply(200, {'ok': True, 'auth_mode': auth_mode, 'client_id': client_id, 'affected': affected}, headers)
        raise BaaSError(400, 'invalid_action')
    except BaaSError as exc:
        if connection and exc.status >= 400 and getattr(connection, 'in_transaction', False):
            connection.rollback()
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        status = 413 if str(exc) == 'request_too_large' else 400
        return _reply(status, {'ok': False, 'error': str(exc)})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'sample_sdk_key_service_unavailable'})
    finally:
        if connection:
            connection.close()

def _sample_sdk_setup_response_key():
    secret = secret_value('token_secret')
    if len(secret) < 32:
        raise database.DatabaseConfigurationError('test token secret is not configured')
    return hashlib.sha256(b'subscriber-sdk-setup|' + secret.encode()).digest()

def _sample_sdk_seal_response(value):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(_sample_sdk_setup_response_key()).encrypt(nonce, value.encode('utf-8'), b'TUTI-BAAS-SUBSCRIBER-SDK-SETUP-V1')
    return base64.urlsafe_b64encode(nonce + encrypted[-16:] + encrypted[:-16]).rstrip(b'=').decode('ascii')

def _sample_sdk_open_response(value):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        raw = base64.urlsafe_b64decode(value + '=' * ((4 - len(value) % 4) % 4))
        if len(raw) < 29:
            raise ValueError
        plain = AESGCM(_sample_sdk_setup_response_key()).decrypt(raw[:12], raw[28:] + raw[12:28], b'TUTI-BAAS-SUBSCRIBER-SDK-SETUP-V1')
        return plain.decode('utf-8')
    except Exception as exc:
        raise ValueError('subscriber_sdk_setup_response_invalid') from exc

@legacy_compatible(callback_index=None, request_index=1)
def _sample_sdk_activation_fields(data, request_context):
    """Apply PHP null-coalescing and string casts for setup-code inputs."""
    code_value = data.get('setup_code')
    idem_value = data.get('idempotency_key')
    if code_value is None:
        code_value = ''
    if idem_value is None:
        idem_value = request_context.get('header:idempotency-key', '')
    return (_sandbox_php_trim(code_value), _sandbox_php_trim(idem_value))

def _sample_sdk_setup_expired(value, now=None):
    """Mirror PHP's integer timestamp comparison for setup-code expiry."""
    expiry = parse_utc_datetime(str(value or ''))
    current = time.time() if now is None else now
    return expiry is None or int(expiry.timestamp()) < int(current)

def _sample_sdk_issued_client_valid(row, api_key, pepper, now=None):
    """Mirror sample_sdk_validate_issued_client() from the PHP library."""
    if not row:
        return False
    expected_hash = hmac.new(pepper.encode(), api_key.encode(), hashlib.sha256).hexdigest()
    expiry_raw = row.get('expires_at')
    expiry = parse_utc_datetime(str(expiry_raw)) if expiry_raw else None
    expiry_valid = not expiry_raw or (expiry is not None and int(expiry.timestamp()) >= int(time.time() if now is None else now))
    return hmac.compare_digest(str(row.get('key_hash', '')), expected_hash) and row.get('key_kind') == 'sample_sdk' and (row.get('status') == 'active') and (not row.get('revoked_at')) and (row.get('tenant_status') == 'active') and (row.get('tenant_environment') == 'sandbox' or bool(row.get('parent_tenant_id'))) and expiry_valid

@legacy_compatible(callback_index=1, request_index=0)
def sample_sdk_activate(request_context):
    """Redeem a subscriber setup code and issue a scoped sandbox SDK credential."""
    connection = None
    method = str(request_context.get('method', ''))
    if method != 'POST':
        return _reply(405, {'ok': False, 'error': 'method_not_allowed'})
    try:
        from ha_handlers import _effective_role
        role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', 'unknown'))
        effective = _effective_role()
        writable = role == 'primary' and effective != 'maintenance' or (role == 'standby' and effective == 'promoted')
        if not writable:
            return _reply(503, {'ok': False, 'error': 'server_not_writable'})
        connection = database.connect()
        _assert_write_fence(connection)
        with connection.cursor() as cursor:
            cursor.execute('SHOW COLUMNS FROM tenant_api_clients')
            columns = {str(row.get('Field') or '') for row in cursor.fetchall()}
            cursor.execute("SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='subscriber_sdk_setup_codes'")
            setup_schema = int(_column_value(cursor.fetchone()) or 0) == 1
        if not {'key_kind', 'policy_json'}.issubset(columns):
            return _reply(503, {'ok': False, 'error': 'sample_sdk_key_migration_required', 'required_migration': '019_sample_sdk_api_keys'})
        if not setup_schema:
            return _reply(503, {'ok': False, 'error': 'subscriber_sdk_setup_migration_required', 'required_migration': '020_subscriber_sdk_setup_codes'})
        ip_hash = _client_ip_hash(request_context)
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS n FROM tenant_api_attempts WHERE ip_hash=%s AND operation='sample_sdk.setup.activate' AND attempted_at>=UTC_TIMESTAMP()-INTERVAL 15 MINUTE", (ip_hash,))
            attempts = int(_column_value(cursor.fetchone()) or 0)
        if attempts >= 20:
            return _reply(429, {'ok': False, 'error': 'setup_rate_limited'}, [('Retry-After', '900')])
        data = _baas_json_input(request_context)
        code, idem = _sample_sdk_activation_fields(data, request_context)
        if re.fullmatch('baas_setup_[A-Za-z0-9_-]{32,120}', code) is None:
            _attempt(connection, None, code[:12], 'sample_sdk.setup.activate', 'invalid_setup_code', 401, ip_hash)
            return _reply(401, {'ok': False, 'error': 'invalid_setup_code'})
        if re.fullmatch('[A-Za-z0-9_-]{20,100}', idem) is None:
            return _reply(400, {'ok': False, 'error': 'invalid_idempotency_key'})
        pepper = key_pepper({'key_pepper': secret_value('key_pepper')})
        code_hash = hmac.new(pepper.encode(), code.encode(), hashlib.sha256).hexdigest()
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute('SELECT s.*,t.slug,t.name,t.status AS tenant_status,t.environment FROM subscriber_sdk_setup_codes s JOIN tenants t ON t.id=s.production_tenant_id WHERE s.code_hash=%s LIMIT 1 FOR UPDATE', (code_hash,))
            row = cursor.fetchone()
        if not row or not hmac.compare_digest(str(row.get('code_hash', '')), code_hash):
            connection.rollback()
            _attempt(connection, None, code[:12], 'sample_sdk.setup.activate', 'invalid_setup_code', 401, ip_hash)
            return _reply(401, {'ok': False, 'error': 'invalid_setup_code'})
        if row.get('tenant_status') != 'active' or row.get('environment') != 'production':
            connection.rollback()
            return _reply(409, {'ok': False, 'error': 'contract_tenant_inactive'})
        if row.get('revoked_at') or row.get('status') == 'revoked':
            connection.rollback()
            return _reply(410, {'ok': False, 'error': 'setup_code_revoked'})
        if _sample_sdk_setup_expired(row.get('expires_at')):
            with connection.cursor() as cursor:
                cursor.execute("UPDATE subscriber_sdk_setup_codes SET status='expired' WHERE id=%s", (int(row['id']),))
            connection.commit()
            return _reply(410, {'ok': False, 'error': 'setup_code_expired'})
        if row.get('status') == 'expired' and (not row.get('redeemed_at')) and (not row.get('revoked_at')):
            with connection.cursor() as cursor:
                cursor.execute("UPDATE subscriber_sdk_setup_codes SET status='active' WHERE id=%s AND status='expired'", (int(row['id']),))
            row['status'] = 'active'
        if row.get('redeemed_at'):
            if hmac.compare_digest(str(row.get('request_key') or ''), idem) and row.get('response_enc'):
                response = json.loads(_sample_sdk_open_response(str(row['response_enc'])))
                connection.commit()
                response['idempotent_replay'] = True
                _attempt(connection, None, code[:12], 'sample_sdk.setup.activate', 'replay', 200, ip_hash)
                return _reply(200, response)
            connection.rollback()
            return _reply(409, {'ok': False, 'error': 'setup_code_already_used'})
        production_tenant = int(row['production_tenant_id'])
        parent = {'id': production_tenant, 'slug': row['slug'], 'name': row['name'], 'plan_code': row.get('plan_code', ''), 'max_products': row.get('max_products', 100), 'max_licenses': row.get('max_licenses', 10000)}
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,slug,name,plan_code,max_products,max_licenses FROM tenants WHERE id=%s AND environment='production' AND status='active'", (production_tenant,))
            parent = cursor.fetchone()
        if not parent:
            connection.rollback()
            return _reply(404, {'ok': False, 'error': 'production_tenant_not_found'})
        sandbox = _sample_sdk_ensure_sandbox(connection, parent, production_tenant, manage_transaction=False)
        sandbox_tenant = int(sandbox['id'])
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,code,name FROM products WHERE tenant_id=%s AND status='active' ORDER BY CASE WHEN code='default' THEN 0 ELSE 1 END,id LIMIT 1", (sandbox_tenant,))
            product = cursor.fetchone()
        if not product:
            raise RuntimeError('sample_sdk_default_product_missing')
        product = {'id': int(product['id']), 'code': str(product['code']), 'name': str(product['name'])}
        issued = _sample_sdk_issue(connection, sandbox_tenant, 'Subscriber SDK Sample', int(row['sdk_rate_limit_per_minute']), int(row['sdk_key_ttl_hours']))
        with connection.cursor() as cursor:
            cursor.execute('SELECT c.id,c.key_hash,c.key_kind,c.status,c.revoked_at,c.expires_at,t.status AS tenant_status,t.environment AS tenant_environment,t.parent_tenant_id FROM tenant_api_clients c JOIN tenants t ON t.id=c.tenant_id WHERE c.id=%s LIMIT 1', (int(issued['client_id']),))
            issued_row = cursor.fetchone()
        if not _sample_sdk_issued_client_valid(issued_row, issued['api_key'], pepper):
            raise RuntimeError('sample_sdk_key_issue_verification_failed')
        response = {'ok': True, 'onboarding': 'baas_subscriber_sample', 'contract_tenant_id': production_tenant, 'contract_name': str(row['name']), 'sandbox_tenant_id': sandbox_tenant, 'sandbox_slug': str(sandbox['slug']), 'default_product': product, 'setup_code_consumed': True, 'issued_key_verified': True, 'issued_on_role': role, **issued}
        sealed = _sample_sdk_seal_response(json.dumps(response, ensure_ascii=False, separators=(',', ':')))
        with connection.cursor() as cursor:
            cursor.execute("UPDATE subscriber_sdk_setup_codes SET status='redeemed',request_key=%s,response_enc=%s,redeemed_at=UTC_TIMESTAMP(),redeemed_ip_hash=%s WHERE id=%s AND redeemed_at IS NULL", (idem, sealed, ip_hash, int(row['id'])))
            if int(getattr(cursor, 'rowcount', 0)) != 1:
                raise RuntimeError('setup_code_redeem_race')
        connection.commit()
        try:
            from ha_handlers import ha_sync_peer
            peer = ha_sync_peer('subscriber_sdk_setup_redeemed', request_context)
        except Exception:
            peer = {'ok': False}
        response['ha_peer_synced'] = bool((peer or {}).get('ok'))
        _attempt(connection, None, code[:12], 'sample_sdk.setup.activate', 'redeemed', 201, ip_hash)
        return _reply(201, response)
    except BaaSError as exc:
        if connection:
            connection.rollback()
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        if connection:
            connection.rollback()
        return _reply(413 if str(exc) == 'request_too_large' else 400, {'ok': False, 'error': str(exc)})
    except database.DatabaseConfigurationError:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception as exc:
        if connection:
            connection.rollback()
        error = 'sample_sdk_key_issue_verification_failed' if str(exc) == 'sample_sdk_key_issue_verification_failed' else 'sample_sdk_setup_activation_failed'
        return _reply(503, {'ok': False, 'error': error})
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def products(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        method = str(request_context.get('method', 'GET'))
        operation = 'products.' + method.lower()
        scope = 'tenant:read' if method == 'GET' else 'products:write'
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, scope, operation, rid)
        tenant_id = int(client['tenant_id'])
        if method == 'GET':
            from http_utils import php_parse_query as parse_qs
            query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
            cursor_id = _query_int(request_context, 'cursor')
            search = query.get('search', [''])[-1].strip()[:80]
            state = query.get('status', [''])[-1].strip()
            sql = "SELECT id,code,name,status,created_at,updated_at FROM products WHERE tenant_id=%s AND status<>'deleted'"
            args = [tenant_id]
            if cursor_id > 0:
                sql += ' AND id<%s'
                args.append(cursor_id)
            if search:
                sql += ' AND (code LIKE %s OR name LIKE %s)'
                args.extend(('%' + search + '%', '%' + search + '%'))
            if state in ('active', 'archived'):
                sql += ' AND status=%s'
                args.append(state)
            limit = _query_limit(request_context)
            sql += ' ORDER BY id DESC LIMIT ' + str(limit)
            with connection.cursor() as cursor:
                cursor.execute(sql, tuple(args))
                rows = cursor.fetchall()
            _usage(connection, client, 'products.list', 200, rid, ip_hash)
            return _reply(200, {'ok': True, 'request_id': rid, 'products': rows, 'next_cursor': int(rows[-1]['id']) if len(rows) == limit else None}, headers)
        if method != 'POST':
            raise BaaSError(405, 'method_not_allowed')
        _assert_write_fence(connection)
        data = _baas_json_input(request_context)
        action = str(data.get('action', 'create')).strip().lower()
        if str(client.get('key_kind') or '').lower() == 'sample_sdk' and action != 'create':
            raise BaaSError(403, 'sample_sdk_action_not_allowed', {'key_class': 'sample_sdk', 'resource': 'products', 'attempted_action': action, 'allowed_actions': ['create']})
        if action in ('update', 'archive', 'restore'):
            try:
                product_id_value = int(data.get('product_id') or 0)
            except (TypeError, ValueError):
                product_id_value = 0
            with connection.cursor() as cursor:
                cursor.execute("SELECT id,code,name,status FROM products WHERE id=%s AND tenant_id=%s AND status<>'deleted'", (product_id_value, tenant_id))
                row = cursor.fetchone()
            if not row:
                raise BaaSError(404, 'product_not_found')
            name = str(data.get('name', row['name'])).strip()
            if not name or len(name) > 160:
                raise BaaSError(400, 'invalid_product')
            new_status = 'archived' if action == 'archive' else 'active' if action == 'restore' else str(row['status'])
            with connection.cursor() as cursor:
                cursor.execute('UPDATE products SET name=%s,status=%s WHERE id=%s AND tenant_id=%s', (name[:160], new_status, product_id_value, tenant_id))
            connection.commit()
            _usage(connection, client, 'products.' + action, 200, rid, ip_hash)
            return _reply(200, {'ok': True, 'request_id': rid, 'product': {'id': product_id_value, 'code': row['code'], 'name': name, 'status': new_status}}, headers)
        code = str(data.get('code', '')).strip().lower()
        name = str(data.get('name', '')).strip()
        if re.fullmatch('[a-z0-9][a-z0-9_-]{1,63}', code) is None or not name or len(name) > 160:
            raise BaaSError(400, 'invalid_product')
        with connection.cursor() as cursor:
            cursor.execute("SELECT t.max_products,(SELECT COUNT(*) FROM products p WHERE p.tenant_id=t.id AND p.status<>'deleted') AS used FROM tenants t WHERE t.id=%s", (tenant_id,))
            quota = cursor.fetchone()
        if not quota or int(quota.get('used') or 0) >= int(quota.get('max_products') or 0):
            raise BaaSError(409, 'product_quota_exceeded')
        try:
            with connection.cursor() as cursor:
                cursor.execute('INSERT INTO products(tenant_id,code,name) VALUES(%s,%s,%s)', (tenant_id, code, name[:160]))
                product_id_value = int(cursor.lastrowid)
        except Exception as exc:
            connection.rollback()
            if getattr(exc, 'args', [None])[0] in (1062, '23000'):
                raise BaaSError(409, 'product_code_exists')
            raise
        connection.commit()
        _usage(connection, client, 'products.create', 201, rid, ip_hash)
        return _reply(201, {'ok': True, 'request_id': rid, 'product': {'id': product_id_value, 'code': code, 'name': name, 'status': 'active'}}, headers)
    except BaaSError as exc:
        if connection and exc.status >= 400:
            connection.rollback()
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        error = str(exc)
        return _reply(413 if error == 'request_too_large' else 400, {'ok': False, 'error': error})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'products_failed'})
    finally:
        if connection:
            connection.close()
