"""Mobile manager administrator login, SSO resume, status and logout."""
from native_http import make_response, add_headers, legacy_compatible
from deployment_settings import site_url
import hmac
import json
import re
import secrets
import time
from http.cookies import SimpleCookie
from urllib.parse import urlencode
from http_utils import php_parse_query as parse_qs
from core import PHP_TRIM_CHARS
from admin_api_handlers import SESSION_COOKIE, CSRF_COOKIE
SSO_COOKIE = 'tuti_python_migration_admin_sso'
BASE_PATH = site_url('/license/python-migration/')
ALLOWED_HOSTS = {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}
ADMIN_IDLE_TIMEOUT = 1800

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status, payload, headers=()):
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    _http_status, _http_headers = (status, [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('Referrer-Policy', 'no-referrer'), ('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"), ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))] + list(headers))
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=None, request_index=0)
def _cookies(request_context):
    jar = SimpleCookie()
    try:
        jar.load(request_context.get('header:cookie', ''))
    except Exception:
        pass
    return {key: morsel.value for key, morsel in jar.items()}

@legacy_compatible(callback_index=None, request_index=0)
def _host(request_context):
    host = str(request_context.get('header:host', '2415.jp')).lower()
    return host if host in ALLOWED_HOSTS else '2415.jp'

def _clear_cookies():
    return [('Set-Cookie', name + '=; Path=' + BASE_PATH + '; Max-Age=0; Secure; SameSite=Strict' + ('; HttpOnly' if name != CSRF_COOKIE else '')) for name in (SESSION_COOKIE, CSRF_COOKIE, SSO_COOKIE)]

@legacy_compatible(callback_index=None, request_index=0)
def _logout_url(request_context):
    return 'https://sso.2415.jp/logout?' + urlencode({'post_logout_redirect_uri': 'https://' + _host(request_context) + BASE_PATH + 'mobile-manager/', 'state': 'mobile-logout'})

def _tenant_summary(connection):
    with connection.cursor() as cursor:
        cursor.execute("SELECT t.id,t.slug,t.environment,t.parent_tenant_id,t.status,t.plan_code,t.max_products,t.max_licenses,(SELECT COUNT(*) FROM products p WHERE p.tenant_id=t.id AND p.status<>'deleted') products,(SELECT COUNT(*) FROM licenses l WHERE l.tenant_id=t.id AND l.deleted_at IS NULL) licenses FROM tenants t ORDER BY t.slug ASC LIMIT 1000")
        rows = cursor.fetchall()
    return [{'id': int(row['id']), 'slug': str(row['slug']), 'environment': 'sandbox' if row.get('environment') == 'sandbox' or row.get('parent_tenant_id') else 'production', 'status': str(row['status']), 'plan_code': str(row.get('plan_code') or ''), 'max_products': int(row.get('max_products') or 0), 'max_licenses': int(row.get('max_licenses') or 0), 'products': int(row.get('products') or 0), 'licenses': int(row.get('licenses') or 0)} for row in rows]

def _principal(credential_hash, enroll=False):
    if not re.fullmatch('[a-f0-9]{64}', str(credential_hash or '')):
        return None
    import database
    connection = database.connect()
    try:
        if enroll:
            connection.begin()
        with connection.cursor() as cursor:
            suffix = ' FOR UPDATE' if enroll else ''
            cursor.execute('SELECT role_name,status,revoked_at FROM admin_principals WHERE credential_id_hash=%s LIMIT 1' + suffix, (credential_hash,))
            row = cursor.fetchone()
            if row is None and enroll:
                cursor.execute('SELECT COUNT(*) AS n FROM admin_principals')
                count = int((cursor.fetchone() or {}).get('n', 0))
                role = 'security-admin' if count == 0 else 'viewer'
                cursor.execute('INSERT INTO admin_principals(credential_id_hash,display_name,role_name,last_login_at) VALUES(%s,%s,%s,UTC_TIMESTAMP())', (credential_hash, 'Passkey administrator', role))
                row = {'role_name': role, 'status': 'active', 'revoked_at': None}
            elif row and enroll and (row.get('status') == 'active') and (not row.get('revoked_at')):
                cursor.execute('UPDATE admin_principals SET last_login_at=UTC_TIMESTAMP() WHERE credential_id_hash=%s', (credential_hash,))
            elif row is not None and enroll:
                connection.rollback()
                return None
        if enroll:
            connection.commit()
        return str(row['role_name']) if row and row.get('role_name') and (row.get('status', 'active') == 'active') and (not row.get('revoked_at')) else None
    except Exception:
        if enroll:
            try:
                connection.rollback()
            except Exception:
                pass
        raise
    finally:
        connection.close()

def _resume_sso(token):
    from passkey_handlers import _read_store, _store_path, _write_store
    from web_passkey_auth import issue_principal_token
    path = _store_path()
    store = _read_store(path)
    row = store.get('sso_sessions', {}).get(token)
    if not isinstance(row, dict):
        return (None, None)
    now = int(time.time())
    absolute = int(row.get('absolute_expires', int(row.get('created', 0)) + 43200))
    if int(row.get('expires', 0)) < now or absolute <= now:
        del store['sso_sessions'][token]
        _write_store(path, store)
        return (None, None)
    credential_hash = str(row.get('credential_id_hash', ''))
    role = _principal(credential_hash)
    if role not in {'viewer', 'operator', 'security-admin', 'ha-admin'}:
        del store['sso_sessions'][token]
        _write_store(path, store)
        return (None, None)
    expires = min(now + 1800, absolute)
    row.update({'role_name': role, 'expires': expires, 'absolute_expires': absolute})
    _write_store(path, store)
    return ({'credential_id_hash': credential_hash, 'role': role, 'expires': expires}, issue_principal_token(credential_hash, 'admin_mobile', 300))

@legacy_compatible(callback_index=None, request_index=0)
def _csrf_valid(request_context, csrf):
    cookies = _cookies(request_context)
    return request_context.get('header:origin', '') == 'https://' + _host(request_context) and bool(cookies.get(CSRF_COOKIE)) and hmac.compare_digest(str(cookies[CSRF_COOKIE]), str(csrf or ''))

def _session_token(claims):
    """Sign the browser session for PHP's 30-minute idle window.

    Mobile API credentials remain short lived (300 seconds); the PHP site
    stores browser login state separately in its 1800-second PHP session.
    """
    refreshed = dict(claims)
    now = int(time.time())
    refreshed['issued_at'] = now
    refreshed['expires'] = now + ADMIN_IDLE_TIMEOUT
    refreshed['nonce'] = secrets.token_urlsafe(18)
    from web_passkey_auth import _encode_token
    return _encode_token(refreshed)

@legacy_compatible(callback_index=1, request_index=0)
def admin_auth(request_context):
    method = request_context.get('method', 'GET')
    query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
    action = query.get('action', [''])[-1]
    if action in {'mnsl_start', 'mnsl_poll', 'mnsl_authorize', 'mnsl_contracts', 'mnsl_products', 'mnsl_issue'}:
        from mnsl_app_sso import handle
        return handle(request_context)
    if action in {'app_start', 'app_poll', 'app_authorize'}:
        from app_sso import handle
        return handle(request_context)
    cookies = _cookies(request_context)
    if method == 'GET' and action in {'status', 'heartbeat'}:
        token = cookies.get(SESSION_COOKIE, '')
        from baas_handlers import _decode_admin_session
        claims = _decode_admin_session(token) if token else None
        context = None
        authenticated = bool(claims and claims.get('client') == 'admin_mobile')
        if authenticated and claims.get('auth_method') != 'oidc_sso':
            return _reply('401 Unauthorized', {'ok': False, 'authenticated': False, 'error': 'SSO_SESSION_EXPIRED'}, _clear_cookies())
        role = 'viewer'
        principal_inactive = False
        if authenticated:
            try:
                principal_role = _principal(str(claims.get('credential_id_hash', ''))) if context is None else context.get('role')
                context = context or {'role': principal_role}
                if principal_role is None:
                    principal_inactive = True
                if context.get('role') not in {'viewer', 'operator', 'security-admin', 'ha-admin'}:
                    authenticated = False
                else:
                    role = context['role']
            except Exception:
                context = None
        if principal_inactive:
            return _reply('401 Unauthorized', {'ok': False, 'authenticated': False, 'error': 'ADMIN_PRINCIPAL_INACTIVE'}, _clear_cookies())
        auth_method = str((claims or {}).get('auth_method') or 'passkey') if authenticated else ''
        sso_expires_at = int((claims or {}).get('sso_expires_at') or 0) if authenticated else 0
        sso_display_name = str((claims or {}).get('sso_display_name') or '') if authenticated else ''
        session_metadata = None
        if authenticated and auth_method == 'oidc_sso':
            sid = str(claims.get('oidc_sid') or '')
            try:
                checked_at = int(claims.get('oidc_checked_at') or 0)
            except (TypeError, ValueError):
                checked_at = 0
            if not sid or int(time.time()) - checked_at >= 30:
                from admin_oidc import session_status
                session = session_status(sid) if sid else None
                if not session:
                    return _reply('401 Unauthorized', {'ok': False, 'authenticated': False, 'error': 'SSO_SESSION_EXPIRED'}, _clear_cookies())
                sso_expires_at = int(session['expires_at'])
                sso_display_name = str(session.get('display_name') or 'SSO ID')[:200]
                claims['oidc_checked_at'] = int(time.time())
                claims['sso_expires_at'] = sso_expires_at
                claims['sso_display_name'] = sso_display_name
            from web_passkey_auth import issue_principal_token
            session_metadata = None
            if auth_method == 'oidc_sso':
                session_metadata = {'auth_method': 'oidc_sso', 'oidc_sid': sid, 'sso_expires_at': sso_expires_at, 'sso_display_name': sso_display_name, 'oidc_checked_at': int(claims.get('oidc_checked_at') or time.time()), 'reauthenticated_at': int(claims.get('reauthenticated_at') or 0)}
            refreshed_token = issue_principal_token(str(claims.get('credential_id_hash') or ''), 'admin_mobile', 300, session_metadata)
            if not refreshed_token:
                return _reply('401 Unauthorized', {'ok': False, 'authenticated': False, 'error': 'SSO_SESSION_EXPIRED'}, _clear_cookies())
            token = refreshed_token
        elif authenticated:
            from web_passkey_auth import issue_principal_token
            refreshed_token = issue_principal_token(str(claims.get('credential_id_hash') or ''), 'admin_mobile', 300)
            if refreshed_token:
                token = refreshed_token
        browser_token = _session_token(claims) if authenticated else ''
        csrf = cookies.get(CSRF_COOKIE) if authenticated else None
        api_token = token if authenticated else ''
        session_cookie = ('Set-Cookie', SESSION_COOKIE + '=' + browser_token + '; Path=' + BASE_PATH + '; Max-Age=' + str(ADMIN_IDLE_TIMEOUT) + '; Secure; HttpOnly; SameSite=Strict')
        if action == 'heartbeat':
            return _reply('200 OK', {'ok': True, 'authenticated': authenticated, 'csrf': csrf, 'tenant_api_session': api_token, 'auth_method': auth_method, 'sso_expires_at': sso_expires_at, 'sso_display_name': sso_display_name}, [session_cookie])
        tenants = []
        if authenticated:
            try:
                import database
                connection = database.connect()
                try:
                    tenants = _tenant_summary(connection)
                finally:
                    connection.close()
            except Exception:
                tenants = []
        return _reply('200 OK', {'ok': True, 'authenticated': authenticated, 'role': role, 'csrf': csrf, 'tenant_api_session': api_token, 'auth_method': auth_method, 'sso_expires_at': sso_expires_at, 'sso_display_name': sso_display_name, 'tenants': tenants}, [session_cookie] if authenticated else [])
    if method == 'POST' and action == 'logout':
        from baas_handlers import _decode_admin_session
        token = cookies.get(SESSION_COOKIE, '')
        claims = _decode_admin_session(token) if token else None
        if not claims:
            return _reply('401 Unauthorized', {'ok': False}, _clear_cookies())
        if not _csrf_valid(request_context, request_context.get('header:x-csrf-token', '')):
            return _reply('403 Forbidden', {'ok': False, 'error': 'csrf_validation_failed'})
        sso_token = cookies.get(SSO_COOKIE, '')
        if sso_token:
            from passkey_handlers import _read_store, _store_path, _write_store, _audit
            path = _store_path()
            store = _read_store(path)
            removed = store.get('sso_sessions', {}).pop(sso_token, None)
            _write_store(path, store)
            if removed:
                _audit(request_context, 'admin_sso_revoked', {'credential_id_hash': removed.get('credential_id_hash', '')})
        return _reply('200 OK', {'ok': True, 'logout_url': _logout_url(request_context)}, _clear_cookies())
    return _reply('400 Bad Request', {'ok': False, 'error': 'invalid_request'})
