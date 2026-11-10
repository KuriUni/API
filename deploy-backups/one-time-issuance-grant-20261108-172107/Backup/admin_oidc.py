"""Isolated admin OpenID Connect login and session checks."""
from native_http import make_response, add_headers, legacy_compatible
from deployment_settings import site_url
import base64
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from http_utils import php_parse_query
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
ISSUER = 'https://sso.2415.jp'
CLIENT_ID = 'tuti-admin-portal'
TENANT_CLIENT_ID = 'tuti-tenant-portal'
FLOW_COOKIE = 'tuti_python_migration_admin_oidc_flow'
TENANT_FLOW_COOKIE = 'tuti_python_migration_tenant_oidc_flow'
ALLOWED_HOSTS = {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}
JWKS_CACHE_TTL_SECONDS = 300
_JWKS_CACHE = None
_JWKS_CACHE_EXPIRES = 0.0
_JWKS_LOCK = threading.Lock()

class _NoRedirect(urllib.request.HTTPRedirectHandler):

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def _b64e(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

def _b64d(value):
    if not isinstance(value, str) or re.fullmatch('[A-Za-z0-9_-]*', value) is None:
        raise ValueError('invalid_base64url')
    return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))

def _secret():
    from migration_config import secret_value
    value = secret_value('admin_oidc_sso_client_secret')
    return value if isinstance(value, str) and len(value) >= 32 else ''

def _flow_key():
    from passkey_handlers import _key
    return _key('admin-oidc-flow/v1')

@legacy_compatible(callback_index=None, request_index=0)
def _host(request_context):
    host = str(request_context.get('header:host', '')).lower()
    return host if host in ALLOWED_HOSTS else ''

def _callback_url(host):
    return 'https://' + host + site_url('/license/python-migration/admin_api.php?admin_sso_callback=1')

def _clear_admin_cookie_paths(cookie_names):
    """Expire stale same-name cookies from older Path variants on this host."""
    headers = []
    for name in cookie_names:
        for path in ('/', '/license', '/license/'):
            headers.append(('Set-Cookie', name + '=; Path=' + path + '; Max-Age=0; Secure; HttpOnly; SameSite=Lax'))
    return headers

def _encode_flow(flow):
    payload = _b64e(json.dumps(flow, separators=(',', ':')).encode())
    signature = _b64e(hmac.new(_flow_key(), payload.encode('ascii'), hashlib.sha256).digest())
    return payload + '.' + signature

def _flow_cookie_name(prefix, state):
    """Give every concurrent OIDC request its own cookie slot."""
    state = str(state or '')
    if not re.fullmatch('[A-Za-z0-9_-]{32,128}', state):
        raise ValueError('oidc_state_invalid')
    return prefix + '_' + state

@legacy_compatible(callback_index=None, request_index=0)
def _read_flow(request_context, cookie_name=FLOW_COOKIE):
    jar = SimpleCookie()
    try:
        jar.load(str(request_context.get('header:cookie', '')))
        value = jar.get(cookie_name)
        if not value:
            return None
        payload, signature = value.value.split('.', 1)
        expected = _b64e(hmac.new(_flow_key(), payload.encode('ascii'), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        flow = json.loads(_b64d(payload).decode('utf-8'))
        return flow if isinstance(flow, dict) else None
    except Exception:
        return None

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status, body=b'', content_type='text/plain; charset=utf-8', headers=()):
    all_headers = [('Content-Type', content_type), ('Cache-Control', 'no-store'), ('Pragma', 'no-cache'), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'), *headers, ('Content-Length', str(len(body)))]
    _http_status, _http_headers = (status, all_headers)
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=0, request_index=None)
def _redirect(location, status='303 See Other', headers=()):
    return _reply(status, headers=[('Location', location), *headers])

def _http_json(url, form=None, basic=None):
    if not url.startswith(ISSUER + '/'):
        raise RuntimeError('oidc_url_rejected')
    headers = {'Accept': 'application/json', 'User-Agent': 'TutiLicensePythonAdmin/1.0', 'Connection': 'close'}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    if basic is not None:
        headers['Authorization'] = 'Basic ' + basic
    req = urllib.request.Request(url, data=data, headers=headers, method='POST' if data is not None else 'GET')
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        with opener.open(req, timeout=15) as response:
            if response.status < 200 or response.status >= 300:
                raise RuntimeError('oidc_provider_rejected')
            raw = response.read(1048577)
        if len(raw) > 1048576:
            raise RuntimeError('oidc_response_too_large')
        value = json.loads(raw.decode('utf-8'))
    except (OSError, urllib.error.URLError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError('oidc_provider_unavailable') from exc
    if not isinstance(value, dict):
        raise RuntimeError('oidc_invalid_response')
    return value

def _jwks(force_refresh=False):
    global _JWKS_CACHE, _JWKS_CACHE_EXPIRES
    with _JWKS_LOCK:
        now = time.monotonic()
        if not force_refresh and _JWKS_CACHE is not None and now < _JWKS_CACHE_EXPIRES:
            return _JWKS_CACHE
        value = _http_json(ISSUER + '/jwks')
        keys = value.get('keys')
        if not isinstance(keys, list) or len(keys) > 100:
            raise RuntimeError('oidc_invalid_jwks')
        _JWKS_CACHE = tuple(key for key in keys if isinstance(key, dict))
        _JWKS_CACHE_EXPIRES = now + JWKS_CACHE_TTL_SECONDS
        return _JWKS_CACHE

def _verify_id_token(token, nonce, expected_client_id=CLIENT_ID):
    if not isinstance(token, str) or len(token) > 65536:
        raise RuntimeError('oidc_bad_token')
    pieces = str(token).split('.')
    if len(pieces) != 3:
        raise RuntimeError('oidc_bad_token')
    try:
        header = json.loads(_b64d(pieces[0]).decode('utf-8'))
        claims = json.loads(_b64d(pieces[1]).decode('utf-8'))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError('oidc_bad_token') from exc
    if not isinstance(header, dict) or not isinstance(claims, dict) or header.get('alg') != 'RS256' or (not isinstance(header.get('kid'), str)) or len(header.get('kid', '')) > 256:
        raise RuntimeError('oidc_bad_token_header')
    keys = _jwks()
    jwk = next((key for key in keys if key.get('kid') == header['kid']), None)
    if jwk is None:
        keys = _jwks(force_refresh=True)
        jwk = next((key for key in keys if key.get('kid') == header['kid']), None)
    if (not jwk or jwk.get('kty') != 'RSA'
            or jwk.get('alg', 'RS256') != 'RS256' or jwk.get('use', 'sig') != 'sig'):
        raise RuntimeError('oidc_key_missing')
    try:
        if (not isinstance(jwk.get('n'), str) or len(jwk['n']) > 1400
                or not isinstance(jwk.get('e'), str) or len(jwk['e']) > 16):
            raise ValueError('oidc_rsa_key_size_invalid')
        n, e = (int.from_bytes(_b64d(jwk['n']), 'big'), int.from_bytes(_b64d(jwk['e']), 'big'))
        public = rsa.RSAPublicNumbers(e, n).public_key()
        if public.key_size < 2048 or public.key_size > 8192 or e < 3 or e % 2 == 0:
            raise ValueError('oidc_rsa_key_size_invalid')
        public.verify(_b64d(pieces[2]), (pieces[0] + '.' + pieces[1]).encode('ascii'), padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        raise RuntimeError('oidc_signature_invalid') from exc
    now = int(time.time())
    try:
        issued, expires = (int(claims.get('iat', 0)), int(claims.get('exp', 0)))
    except (TypeError, ValueError) as exc:
        raise RuntimeError('oidc_claims_invalid') from exc
    aud = claims.get('aud')
    audience_ok = expected_client_id in aud if isinstance(aud, list) else aud == expected_client_id
    if isinstance(aud, list) and len(aud) > 1 and claims.get('azp') != expected_client_id:
        audience_ok = False
    if 'azp' in claims and claims.get('azp') != expected_client_id:
        audience_ok = False
    if claims.get('iss') != ISSUER or not audience_ok or issued < 1 or (issued > now + 60) or (expires <= now) or (expires - issued > 600) or (not hmac.compare_digest(str(claims.get('nonce', '')), nonce)) or (not isinstance(claims.get('sub'), str)) or (len(claims['sub']) < 16) or (not re.fullmatch('[a-f0-9]{64}', str(claims.get('sid', '')))):
        raise RuntimeError('oidc_claims_invalid')
    if 'tenant_id' in claims and (type(claims['tenant_id']) is not int or not 0 < claims['tenant_id'] < 2**63):
        raise RuntimeError('oidc_claims_invalid')
    return claims

def session_status(sid, client_id=CLIENT_ID):
    if not re.fullmatch('[a-f0-9]{64}', str(sid or '')):
        return None
    secret = _secret()
    if not secret:
        return None
    try:
        result = _http_json(ISSUER + '/session/introspect', {'sid': sid}, base64.b64encode((client_id + ':' + secret).encode()).decode())
        if result.get('active') is True and int(result.get('expires_at', 0)) > int(time.time()):
            return result
    except Exception:
        pass
    return None

def session_active(sid, client_id=CLIENT_ID):
    return session_status(sid, client_id) is not None

def invite_contractor(sid, email, tenant_id):
    if not re.fullmatch('[a-f0-9]{64}', str(sid or '')):
        raise RuntimeError('oidc_session_invalid')
    secret = _secret()
    if not secret:
        raise RuntimeError('oidc_client_unconfigured')
    return _http_json(ISSUER + '/contractor/invite', {'sid': sid, 'email': email, 'tenant_id': str(tenant_id)}, base64.b64encode((CLIENT_ID + ':' + secret).encode()).decode())

def lookup_sso_identity(sid, email):
    if not re.fullmatch('[a-f0-9]{64}', str(sid or '')):
        raise RuntimeError('oidc_session_invalid')
    secret = _secret()
    if not secret:
        raise RuntimeError('oidc_client_unconfigured')
    return _http_json(ISSUER + '/admin/identity/search', {'sid': sid, 'email': email}, base64.b64encode((CLIENT_ID + ':' + secret).encode()).decode())

def resolve_sso_identity(sid, public_id):
    if not re.fullmatch('[a-f0-9]{64}', str(sid or '')) or not re.fullmatch('SID-[A-Z2-7]{26}', str(public_id or '').strip().upper()):
        raise RuntimeError('oidc_identity_invalid')
    secret = _secret()
    if not secret:
        raise RuntimeError('oidc_client_unconfigured')
    result = _http_json(ISSUER + '/admin/identity/resolve', {'sid': sid, 'public_id': str(public_id).strip().upper()}, base64.b64encode((CLIENT_ID + ':' + secret).encode()).decode())
    if result.get('found') is not True or not isinstance(result.get('identity'), dict):
        raise RuntimeError('oidc_identity_not_found')
    identity = result['identity']
    sub = str(identity.get('sub') or '')
    if not sub or len(sub) > 200:
        raise RuntimeError('oidc_subject_unavailable')
    return {'sub': sub, 'public_id': str(identity.get('public_id') or ''), 'display_name': str(identity.get('display_name') or '')}

def delete_sso_identity(sid, email, public_id):
    if not re.fullmatch('[a-f0-9]{64}', str(sid or '')):
        raise RuntimeError('oidc_session_invalid')
    secret = _secret()
    if not secret:
        raise RuntimeError('oidc_client_unconfigured')
    return _http_json(ISSUER + '/admin/identity/delete', {'sid': sid, 'email': email, 'public_id': public_id}, base64.b64encode((CLIENT_ID + ':' + secret).encode()).decode())

@legacy_compatible(callback_index=1, request_index=0)
def start(request_context):
    host = _host(request_context)
    secret = _secret()
    if not host:
        return _reply('400 Bad Request', b'SSO host rejected.')
    if not secret:
        return _redirect('admin_api.php?oidc_error=unconfigured')
    verifier = _b64e(secrets.token_bytes(48))
    state = _b64e(secrets.token_bytes(32))
    nonce = _b64e(secrets.token_bytes(32))
    now = int(time.time())
    query = php_parse_query(str(request_context.get('query', '')), keep_blank_values=True)
    target = query.get('target', ['admin'])[-1]
    if target not in {'admin', 'mobile'}:
        target = 'admin'
    return_app = query.get('return_app', [''])[-1]
    if return_app not in {'', 'ops', 'desktop'} or (return_app in {'ops', 'desktop'} and target != 'admin'):
        return_app = ''
    desktop_redirect = ''
    desktop_state = ''
    if return_app == 'desktop':
        desktop_redirect = str(query.get('desktop_redirect', [''])[-1])
        desktop_state = str(query.get('desktop_state', [''])[-1])
        try:
            parsed_redirect = urllib.parse.urlsplit(desktop_redirect)
            valid_redirect = (parsed_redirect.scheme == 'http' and parsed_redirect.hostname == '127.0.0.1'
                             and parsed_redirect.port is not None and 49152 <= parsed_redirect.port <= 65535
                             and parsed_redirect.path == '/callback' and not parsed_redirect.username
                             and not parsed_redirect.password and not parsed_redirect.query and not parsed_redirect.fragment)
        except ValueError:
            valid_redirect = False
        if not valid_redirect or not re.fullmatch('[a-f0-9]{64}', desktop_state):
            return _reply('400 Bad Request', b'Invalid desktop callback.')
    app_ticket = query.get('app_ticket', [''])[-1]
    if app_ticket:
        from app_sso import valid_ticket
        if target != 'mobile' or not valid_ticket(app_ticket, host):
            return _reply('400 Bad Request', b'Invalid application login.')
    step_up = query.get('step_up', [''])[-1] not in ('', '0')
    actor_hash = ''
    if step_up:
        from admin_api_handlers import SESSION_COOKIE, _cookie_value
        from baas_handlers import _decode_admin_session
        existing = _decode_admin_session(_cookie_value(request_context, SESSION_COOKIE))
        if not existing or existing.get('auth_source') != 'oidc_sso':
            return _redirect('admin_api.php?oidc_error=expired')
        actor_hash = str(existing.get('credential_id_hash') or '')
        if not re.fullmatch('[a-f0-9]{64}', actor_hash):
            return _redirect('admin_api.php?oidc_error=expired')
    flow = {'state': state, 'nonce': nonce, 'verifier': verifier, 'created': now, 'host': host, 'target': target, 'step_up': step_up, 'actor_hash': actor_hash, 'app_ticket': app_ticket, 'return_app': return_app, 'desktop_redirect': desktop_redirect, 'desktop_state': desktop_state}
    challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
    params = {'response_type': 'code', 'client_id': CLIENT_ID, 'redirect_uri': _callback_url(host), 'scope': 'openid', 'state': state, 'nonce': nonce, 'code_challenge': challenge, 'code_challenge_method': 'S256'}
    if step_up or app_ticket:
        params['prompt'] = 'login'
    if app_ticket:
        params['max_age'] = '0'
    location = ISSUER + '/authorize?' + urllib.parse.urlencode(params)
    cookie = _encode_flow(flow)
    cookie_name = _flow_cookie_name(FLOW_COOKIE, state)
    return _redirect(location, '303 See Other', [('Set-Cookie', cookie_name + '=' + cookie + site_url('; Path=/license/python-migration/; Max-Age=600; Secure; HttpOnly; SameSite=Lax'))])

@legacy_compatible(callback_index=1, request_index=0)
def start_tenant(request_context):
    host = _host(request_context)
    secret = _secret()
    if not host:
        return _reply('400 Bad Request', b'SSO host rejected.')
    if not secret:
        return _redirect('admin_api.php?oidc_error=unconfigured')
    verifier = _b64e(secrets.token_bytes(48))
    state = _b64e(secrets.token_bytes(32))
    nonce = _b64e(secrets.token_bytes(32))
    query = php_parse_query(str(request_context.get('query', '')), keep_blank_values=True)
    app_ticket = query.get('app_ticket', [''])[-1]
    if app_ticket:
        from mnsl_app_sso import valid_ticket
        if not valid_ticket(app_ticket, host):
            return _reply('400 Bad Request', b'Invalid MNSL application login.')
    flow = {'state': state, 'nonce': nonce, 'verifier': verifier, 'created': int(time.time()), 'host': host, 'target': 'tenant_app' if app_ticket else 'tenant', 'app_ticket': app_ticket}
    challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
    params = {'response_type': 'code', 'client_id': TENANT_CLIENT_ID, 'redirect_uri': _callback_url(host), 'scope': 'openid', 'state': state, 'nonce': nonce, 'code_challenge': challenge, 'code_challenge_method': 'S256'}
    query = php_parse_query(str(request_context.get('query', '')), keep_blank_values=True)
    if app_ticket or query.get('step_up', [''])[-1] not in ('', '0'):
        params['prompt'] = 'login'
    if app_ticket:
        params['max_age'] = '0'
    location = ISSUER + '/authorize?' + urllib.parse.urlencode(params)
    if app_ticket:
        from mnsl_app_sso import store_oidc_flow
        store_oidc_flow(app_ticket, host, flow)
    cookie = _encode_flow(flow)
    cookie_name = _flow_cookie_name(TENANT_FLOW_COOKIE, state)
    return _redirect(location, '303 See Other', [('Set-Cookie', cookie_name + '=' + cookie + site_url('; Path=/license/python-migration/; Max-Age=600; Secure; HttpOnly; SameSite=Lax'))])

@legacy_compatible(callback_index=1, request_index=0)
def callback(request_context):
    host = _host(request_context)
    query = php_parse_query(str(request_context.get('query', '')), keep_blank_values=True)
    requested_state = query.get('state', [''])[-1]
    matching = []
    if re.fullmatch('[A-Za-z0-9_-]{32,128}', str(requested_state or '')):
        for prefix in (TENANT_FLOW_COOKIE, FLOW_COOKIE):
            name = _flow_cookie_name(prefix, requested_state)
            item = _read_flow(request_context, name)
            if isinstance(item, dict) and hmac.compare_digest(str(item.get('state', '')), requested_state):
                matching.append((name, item))
        # Accept old clients during rollout, but only when their cookie state
        # exactly matches this callback. Never fall back to another live flow.
        for name in (TENANT_FLOW_COOKIE, FLOW_COOKIE):
            item = _read_flow(request_context, name)
            if isinstance(item, dict) and hmac.compare_digest(str(item.get('state', '')), requested_state):
                matching.append((name, item))
    if matching:
        flow_cookie, flow = matching[0]
    else:
        flow_cookie, flow = '', None
    if not flow and re.fullmatch('[A-Za-z0-9_-]{32,128}', str(requested_state or '')):
        # Some embedded browsers discard or overwrite cookies across the SSO
        # provider round-trip. The random state plus server-held PKCE verifier
        # safely recovers this native-app flow without accepting another login.
        try:
            from mnsl_app_sso import consume_oidc_flow
            recovered = consume_oidc_flow(requested_state, host)
        except Exception:
            recovered = None
        if isinstance(recovered, dict) and recovered.get('target') == 'tenant_app' and recovered.get('app_ticket'):
            flow = recovered
            flow_cookie = _flow_cookie_name(TENANT_FLOW_COOKIE, requested_state)
    elif flow and flow.get('target') == 'tenant_app':
        try:
            from mnsl_app_sso import consume_oidc_flow
            consume_oidc_flow(requested_state, host)
        except Exception:
            pass
    clear = (('Set-Cookie', flow_cookie + site_url('=; Path=/license/python-migration/; Max-Age=0; Secure; HttpOnly; SameSite=Lax')) if flow_cookie else None)
    clear_headers = [clear] if clear else []
    def fail_app_login(code):
        if isinstance(flow, dict) and flow.get('target') == 'tenant_app' and flow.get('app_ticket'):
            try:
                from mnsl_app_sso import fail_login
                fail_login(str(flow['app_ticket']), host, code)
            except Exception:
                pass
    if not host or not isinstance(flow, dict) or flow.get('host') != host or (int(flow.get('created', 0)) < int(time.time()) - 600):
        fail_app_login('mnsl_sso_login_expired')
        return _redirect('admin_api.php?oidc_error=expired', headers=clear_headers)
    if 'error' in query:
        fail_app_login('mnsl_sso_provider_login_failed')
        return _redirect('admin_api.php?oidc_error=provider', headers=clear_headers)
    code, state = (query.get('code', [''])[-1], query.get('state', [''])[-1])
    if not code or not hmac.compare_digest(str(flow.get('state', '')), state):
        fail_app_login('mnsl_sso_callback_state_invalid')
        return _redirect('admin_api.php?oidc_error=state', headers=clear_headers)
    secret = _secret()
    if not secret:
        fail_app_login('mnsl_sso_service_unavailable')
        return _redirect('admin_api.php?oidc_error=unconfigured', headers=clear_headers)
    target = str(flow.get('target', 'admin'))
    if target not in {'admin', 'mobile', 'tenant', 'tenant_app'}:
        fail_app_login('mnsl_sso_callback_invalid')
        return _redirect('admin_api.php?oidc_error=failed', headers=clear_headers)
    connection = None
    failure_stage = 'token_exchange'
    try:
        client_id = TENANT_CLIENT_ID if target in {'tenant', 'tenant_app'} else CLIENT_ID
        token = _http_json(ISSUER + '/token', {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': _callback_url(host), 'code_verifier': str(flow['verifier'])}, base64.b64encode((client_id + ':' + secret).encode()).decode())
        failure_stage = 'id_token_verification'
        claims = _verify_id_token(str(token.get('id_token', '')), str(flow['nonce']), client_id)
        failure_stage = 'sso_session_introspection'
        session = _http_json(ISSUER + '/session/introspect', {'sid': claims['sid']}, base64.b64encode((client_id + ':' + secret).encode()).decode())
        if session.get('active') is not True or int(session.get('expires_at', 0)) <= int(time.time()):
            raise RuntimeError('oidc_session_revoked')
        failure_stage = 'post_authentication_setup'
        if target == 'tenant_app':
            from mnsl_app_sso import complete_login
            return complete_login(request_context, flow, claims, session, clear_headers)
        if target == 'tenant':
            ticket = _b64e(secrets.token_bytes(32))
            subject_hash = hashlib.sha256((ISSUER + '\x00' + str(claims['sub'])).encode()).hexdigest()
            from database import connect
            connection = connect()
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('DELETE FROM tenant_sso_bootstrap_tickets WHERE expires_at<UTC_TIMESTAMP() OR used_at IS NOT NULL')
                cursor.execute('INSERT INTO tenant_sso_bootstrap_tickets (ticket_hash,subject_hash,oidc_sid,created_at,expires_at) VALUES(%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP()+INTERVAL 2 MINUTE)', (hashlib.sha256(ticket.encode()).hexdigest(), subject_hash, str(claims['sid'])))
            connection.commit()
            location = 'https://' + host + site_url('/license/python-migration/tenant-portal/#sso_ticket=') + urllib.parse.quote(ticket, safe='')
            return _redirect(location, headers=[*clear_headers, ('Referrer-Policy', 'no-referrer')])
        principal_hash = hashlib.sha256((ISSUER + '\x00' + claims['sub']).encode()).hexdigest()
        auth_time = int(claims.get('auth_time') or 0)
        if flow.get('step_up') and (not hmac.compare_digest(str(flow.get('actor_hash') or ''), principal_hash) or auth_time < int(flow['created']) or auth_time > int(time.time()) + 60):
            raise RuntimeError('oidc_step_up_identity_invalid')
        app_ticket = str(flow.get('app_ticket') or '')
        if app_ticket:
            from app_sso import valid_ticket
            if target != 'mobile' or not valid_ticket(app_ticket, host) or auth_time < int(flow['created']) or auth_time > int(time.time()) + 60:
                raise RuntimeError('oidc_app_login_invalid')
        reauthenticated_at = auth_time if flow.get('step_up') or app_ticket else 0
        from database import connect
        connection = connect()
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute('SELECT role_name,status,revoked_at FROM admin_principals WHERE credential_id_hash=%s LIMIT 1 FOR UPDATE', (principal_hash,))
            principal = cursor.fetchone()
            if not principal:
                cursor.execute("INSERT INTO admin_principals(credential_id_hash,display_name,role_name,last_login_at) VALUES(%s,%s,'viewer',UTC_TIMESTAMP())", (principal_hash, 'SSO administrator'))
                role = 'viewer'
            elif principal.get('status') == 'active' and (not principal.get('revoked_at')):
                role = str(principal.get('role_name', 'viewer'))
                cursor.execute('UPDATE admin_principals SET last_login_at=UTC_TIMESTAMP() WHERE credential_id_hash=%s', (principal_hash,))
            else:
                raise RuntimeError('oidc_principal_disabled')
        connection.commit()
        if target == 'mobile':
            from web_passkey_auth import issue_principal_token
            mobile_token = issue_principal_token(principal_hash, 'admin_mobile', 300, {'auth_method': 'oidc_sso', 'oidc_sid': str(claims['sid']), 'sso_expires_at': int(session['expires_at']), 'sso_display_name': str(session.get('display_name') or 'SSO ID')[:200], 'oidc_checked_at': int(time.time()), 'reauthenticated_at': reauthenticated_at})
            if not mobile_token:
                raise RuntimeError('oidc_mobile_session_issue_failed')
            from admin_api_handlers import SESSION_COOKIE, CSRF_COOKIE
            from mobile_admin_auth import SSO_COOKIE, BASE_PATH
            csrf = secrets.token_urlsafe(32)
            max_age = 300
            destination = 'https://' + host + site_url('/license/python-migration/mobile-manager/admin-auth.php?action=app_authorize&ticket=') + app_ticket if app_ticket else 'https://' + host + site_url('/license/python-migration/mobile-manager/?mode=admin&sso_resume=1')
            return _redirect(destination, headers=[*clear_headers, ('Set-Cookie', SESSION_COOKIE + '=' + mobile_token + '; Path=' + BASE_PATH + '; Max-Age=' + str(max_age) + '; Secure; HttpOnly; SameSite=Strict'), ('Set-Cookie', CSRF_COOKIE + '=' + csrf + '; Path=' + BASE_PATH + '; Max-Age=300; Secure; SameSite=Strict'), ('Set-Cookie', SSO_COOKIE + '=; Path=' + BASE_PATH + '; Max-Age=0; Secure; HttpOnly; SameSite=Strict')])
        expires = min(int(time.time()) + 1800, int(session['expires_at']))
        from web_passkey_auth import ADMIN_SCOPES, _encode_token
        local_token = _encode_token({'purpose': 'ha_admin', 'auth_source': 'oidc_sso', 'scope': list(ADMIN_SCOPES), 'client': 'admin_web', 'credential_id_hash': principal_hash, 'issued_at': 0, 'expires': expires, 'oidc_sid': str(claims['sid']), 'reauthenticated_at': reauthenticated_at, 'auth_method': 'oidc_sso', 'nonce': _b64e(secrets.token_bytes(16))})
        csrf = secrets.token_urlsafe(32)
        from admin_api_handlers import SESSION_COOKIE, CSRF_COOKIE
        if target == 'admin' and flow.get('return_app') == 'desktop':
            destination = str(flow.get('desktop_redirect') or '') + '#session=' + urllib.parse.quote(local_token, safe='') + '&state=' + urllib.parse.quote(str(flow.get('desktop_state') or ''), safe='')
            session_cookie = SESSION_COOKIE + '=' + local_token + site_url('; Path=/license/python-migration/; Max-Age=') + str(max(1, expires - int(time.time()))) + '; Secure; HttpOnly; SameSite=Lax'
            csrf_cookie = CSRF_COOKIE + '=' + csrf + site_url('; Path=/license/python-migration/; Max-Age=') + str(max(1, expires - int(time.time()))) + '; Secure; SameSite=Lax'
            return _redirect(destination, headers=[*clear_headers, ('Set-Cookie', session_cookie), ('Set-Cookie', csrf_cookie), ('Referrer-Policy', 'no-referrer')])
        destination = 'ops-app/' if target == 'admin' and flow.get('return_app') == 'ops' else 'admin_api.php'
        cookie_path = site_url('/license/python-migration/')
        cookie_max_age = str(max(1, expires - int(time.time())))
        reset = _clear_admin_cookie_paths((SESSION_COOKIE, CSRF_COOKIE))
        return _redirect(destination, headers=[*clear_headers, *reset,
            ('Set-Cookie', SESSION_COOKIE + '=' + local_token + '; Path=' + cookie_path + '; Max-Age=' + cookie_max_age + '; Secure; HttpOnly; SameSite=Lax'),
            ('Set-Cookie', CSRF_COOKIE + '=' + csrf + '; Path=' + cookie_path + '; Max-Age=' + cookie_max_age + '; Secure; SameSite=Lax')])
    except Exception:
        if target == 'tenant_app':
            # Keep internal exception details in the audit log; the native app
            # receives only a stable, non-sensitive code instead of polling
            # forever while the browser shows a different page.
            fail_app_login('mnsl_sso_' + failure_stage + '_failed')
        try:
            from audit import append_event
            append_event('admin_oidc_callback_failed', {
                'stage': failure_stage,
                'target': target,
                'error_type': type(__import__('sys').exc_info()[1]).__name__,
                'host': host,
            })
        except Exception:
            pass
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        return _redirect('admin_api.php?oidc_error=failed', headers=clear_headers)
    finally:
        if connection:
            connection.close()
