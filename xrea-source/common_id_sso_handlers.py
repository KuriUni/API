"""Python implementation of the Common ID OpenID Connect provider."""
from native_http import make_response, add_headers, legacy_compatible
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from http.cookies import SimpleCookie
from urllib.parse import quote, urlsplit
import database
from core import key_pepper, parse_utc_datetime
from migration_config import secret_value
from http_utils import php_parse_query as parse_qs
ISSUER = 'https://sso.2415.jp'
COOKIE_NAME = '__Host-baas_common_id'
ACTION_PATH = '/api/baas/v1/common-id-sso.php?action='

class SsoError(Exception):

    def __init__(self, status, error, headers=()):
        super().__init__(error)
        self.status, self.error, self.headers = (status, error, headers)

@legacy_compatible(callback_index=0, request_index=None)
def _response(status, payload=None, headers=()):
    names = {200: '200 OK', 302: '302 Found', 400: '400 Bad Request', 401: '401 Unauthorized', 405: '405 Method Not Allowed', 429: '429 Too Many Requests', 503: '503 Service Unavailable'}
    response_headers = [('Cache-Control', 'no-store'), ('Pragma', 'no-cache'), ('Referrer-Policy', 'no-referrer'), ('X-Content-Type-Options', 'nosniff'), *headers]
    if payload is None:
        body = b''
        response_headers.append(('Content-Length', '0'))
    else:
        body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
        response_headers.extend([('Content-Type', 'application/json; charset=utf-8'), ('Content-Length', str(len(body)))])
    _http_status, _http_headers = (names.get(status, f'{status} Error'), response_headers)
    return make_response([body], _http_status, _http_headers)

def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b'=').decode('ascii')

def _hash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def _clients():
    try:
        value = json.loads(secret_value('common_id_sso_clients') or '{}')
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}

def _client(client_id):
    value = _clients().get(client_id)
    if not isinstance(value, dict) or not value.get('active') or (not isinstance(value.get('client_secret'), str)) or (len(value['client_secret']) < 32) or (not isinstance(value.get('redirect_uris'), list)):
        return None
    return value

def _redirect_allowed(client, uri):
    if not uri or len(uri) > 2048 or '#' in uri or re.search('[\\x00-\\x20\\x7f]', uri):
        return False
    try:
        parts = urlsplit(uri)
        valid = parts.scheme.lower() == 'https' and bool(parts.hostname) and (parts.username is None) and (parts.password is None) and (not parts.fragment)
    except ValueError:
        return False
    return valid and uri in client.get('redirect_uris', [])

def _opaque(value, minimum, maximum):
    return minimum <= len(value) <= maximum and re.fullmatch('[A-Za-z0-9._~-]+', value) is not None

def _private_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    pem = secret_value('common_id_sso_signing_private_key')
    if not pem:
        raise ValueError('sso_signing_key_missing')
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ValueError('sso_signing_key_invalid')
    return key

def _kid(key):
    from cryptography.hazmat.primitives import serialization
    encoded = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(encoded).hexdigest()[:24]

def _jwk(key):
    numbers = key.public_key().public_numbers()

    def integer(value):
        return _b64(value.to_bytes((value.bit_length() + 7) // 8, 'big'))
    return {'kty': 'RSA', 'use': 'sig', 'alg': 'RS256', 'kid': _kid(key), 'n': integer(numbers.n), 'e': integer(numbers.e)}

def _subject(passkey_id):
    pepper = key_pepper({'key_pepper': secret_value('key_pepper')})
    return hmac.new(pepper.encode(), f'common-id-passkey:{passkey_id}'.encode(), hashlib.sha256).hexdigest()

def _id_token(key, client_id, passkey_id, auth_time, nonce):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    now = int(time.time())
    header = _b64(json.dumps({'alg': 'RS256', 'typ': 'JWT', 'kid': _kid(key)}, separators=(',', ':')).encode())
    claims = {'iss': ISSUER, 'sub': _subject(passkey_id), 'aud': client_id, 'iat': now, 'exp': now + 600, 'auth_time': auth_time, 'nonce': nonce}
    payload = _b64(json.dumps(claims, separators=(',', ':')).encode())
    signing_input = f'{header}.{payload}'.encode('ascii')
    return signing_input.decode() + '.' + _b64(key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256()))

@legacy_compatible(callback_index=None, request_index=0)
def _query(request_context):
    values = parse_qs(str(request_context.get('query', '')), keep_blank_values=True)
    return {key: items[-1] if items else '' for key, items in values.items()}

@legacy_compatible(callback_index=None, request_index=0)
def _form_body(request_context):
    stream = request_context.get('body_stream')
    raw = stream.read(131073) if stream is not None else b''
    if len(raw) > 131072:
        raise SsoError(400, 'invalid_request')
    values = parse_qs(raw.decode('utf-8', 'replace'), keep_blank_values=True)
    return {key: items[-1] if items else '' for key, items in values.items()}

@legacy_compatible(callback_index=None, request_index=1)
def _browser_identity(connection, request_context):
    cookie = SimpleCookie()
    try:
        cookie.load(str(request_context.get('header:cookie', '')))
        token = cookie[COOKIE_NAME].value
    except Exception:
        return None
    if re.fullmatch('[A-Za-z0-9_-]{43}', token) is None:
        return None
    with connection.cursor() as cursor:
        cursor.execute("SELECT s.passkey_id,s.created_at FROM common_id_sso_browser_sessions s JOIN tenant_portal_passkeys p ON p.id=s.passkey_id AND p.revoked_at IS NULL WHERE s.session_hash=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP() AND EXISTS(SELECT 1 FROM tenant_portal_memberships m JOIN tenants t ON t.id=m.tenant_id AND t.status='active' WHERE m.passkey_id=p.id) LIMIT 1", (_hash(token),))
        row = cursor.fetchone()
    if not row:
        return None
    created = parse_utc_datetime(str(row.get('created_at') or ''))
    row['auth_time'] = int(created.timestamp()) if created else int(time.time())
    return row

@legacy_compatible(callback_index=3, request_index=None)
def _issue_code(connection, request_id, identity):
    request_hash = _hash(request_id)
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT client_id,redirect_uri,state_value,code_challenge,nonce_value,expires_at FROM common_id_sso_requests WHERE request_id_hash=%s LIMIT 1 FOR UPDATE', (request_hash,))
            row = cursor.fetchone()
            expires = parse_utc_datetime(str((row or {}).get('expires_at') or ''))
            if not row or expires is None or int(expires.timestamp()) < int(time.time()):
                raise SsoError(400, 'sso_request_expired')
            code = _b64(secrets.token_bytes(32))
            cursor.execute('INSERT INTO common_id_sso_codes(code_hash,client_id,redirect_uri,state_value,code_challenge,nonce_value,passkey_id,auth_time,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP()+INTERVAL 90 SECOND)', (_hash(code), row['client_id'], row['redirect_uri'], row['state_value'], row['code_challenge'], row['nonce_value'], int(identity['passkey_id']), int(identity.get('auth_time') or time.time())))
            cursor.execute('DELETE FROM common_id_sso_requests WHERE request_id_hash=%s', (request_hash,))
        connection.commit()
        uri = str(row['redirect_uri'])
        separator = '&' if '?' in uri else '?'
        target = uri + separator + 'code=' + quote(code, safe='') + '&state=' + quote(str(row['state_value']), safe='')
        return _response(302, headers=[('Location', target)])
    except SsoError:
        connection.rollback()
        raise
    except Exception as exc:
        connection.rollback()
        raise SsoError(400, 'sso_request_invalid') from exc

def _discovery():
    endpoint = ISSUER + ACTION_PATH
    return {'issuer': ISSUER, 'authorization_endpoint': endpoint + 'authorize', 'token_endpoint': endpoint + 'token', 'userinfo_endpoint': endpoint + 'userinfo', 'jwks_uri': endpoint + 'jwks', 'response_types_supported': ['code'], 'grant_types_supported': ['authorization_code'], 'subject_types_supported': ['public'], 'id_token_signing_alg_values_supported': ['RS256'], 'scopes_supported': ['openid'], 'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'], 'code_challenge_methods_supported': ['S256'], 'claims_supported': ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce']}

@legacy_compatible(callback_index=1, request_index=0)
def common_id_sso(request_context):
    query = _query(request_context)
    action = str(query.get('action', ''))
    method = str(request_context.get('method', 'GET'))
    if action == 'discovery':
        if method != 'GET':
            return _response(405, {'ok': False, 'error': 'method_not_allowed'})
        return _response(200, _discovery())
    if action not in {'authorize', 'resume', 'token', 'userinfo', 'jwks'}:
        return _response(400, {'ok': False, 'error': 'invalid_action'})
    if action in {'jwks', 'userinfo'} and method != 'GET':
        return _response(405, {'ok': False, 'error': 'method_not_allowed'})
    if action == 'token' and method != 'POST':
        return _response(405, {'ok': False, 'error': 'method_not_allowed'})
    if action == 'jwks':
        try:
            return _response(200, {'keys': [_jwk(_private_key())]})
        except Exception:
            return _response(503, {'ok': False, 'error': 'sso_signing_key_unavailable'})
    connection = None
    try:
        if action == 'authorize':
            connection = database.connect()
            if method != 'GET':
                return _response(405, {'ok': False, 'error': 'method_not_allowed'})
            ip_hash = hashlib.sha256(str(request_context.get('client_address', '')).encode()).hexdigest()
            with connection.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) AS n FROM tenant_portal_passkey_attempts WHERE ip_hash=%s AND attempted_at>=UTC_TIMESTAMP()-INTERVAL 1 MINUTE', (ip_hash,))
                if int((cursor.fetchone() or {}).get('n') or 0) >= 20:
                    connection.commit()
                    return _response(429, {'ok': False, 'error': 'rate_limited'}, [('Retry-After', '60')])
                cursor.execute('INSERT INTO tenant_portal_passkey_attempts(ip_hash) VALUES(%s)', (ip_hash,))
            connection.commit()
            client_id = str(query.get('client_id', '')).strip()
            redirect_uri = str(query.get('redirect_uri', '')).strip()
            state = str(query.get('state', '')).strip()
            challenge = str(query.get('code_challenge', '')).strip()
            nonce = str(query.get('nonce', '')).strip()
            client = _client(client_id)
            if client is None:
                return _response(400, {'ok': False, 'error': 'invalid_client'})
            if query.get('response_type') != 'code' or not _redirect_allowed(client, redirect_uri) or (not _opaque(state, 16, 512)) or (not _opaque(nonce, 16, 256)) or (re.fullmatch('[A-Za-z0-9_-]{43}', challenge) is None) or (query.get('code_challenge_method') != 'S256') or (query.get('scope', 'openid') != 'openid'):
                return _response(400, {'ok': False, 'error': 'invalid_request'})
            request_id = _b64(secrets.token_bytes(32))
            with connection.cursor() as cursor:
                cursor.execute('DELETE FROM common_id_sso_requests WHERE expires_at<UTC_TIMESTAMP()')
                cursor.execute('DELETE FROM common_id_sso_codes WHERE expires_at<UTC_TIMESTAMP()-INTERVAL 1 HOUR')
                cursor.execute('DELETE FROM common_id_sso_tokens WHERE expires_at<UTC_TIMESTAMP()-INTERVAL 1 DAY OR revoked_at<UTC_TIMESTAMP()-INTERVAL 1 DAY')
                cursor.execute('DELETE FROM common_id_sso_browser_sessions WHERE expires_at<UTC_TIMESTAMP()-INTERVAL 1 DAY OR revoked_at<UTC_TIMESTAMP()-INTERVAL 1 DAY')
                cursor.execute('INSERT INTO common_id_sso_requests(request_id_hash,client_id,redirect_uri,state_value,code_challenge,nonce_value,expires_at) VALUES(%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP()+INTERVAL 5 MINUTE)', (_hash(request_id), client_id, redirect_uri, state, challenge, nonce))
            connection.commit()
            identity = _browser_identity(connection, request_context)
            if identity is not None:
                return _issue_code(connection, request_id, identity)
            return _response(302, headers=[('Location', ISSUER + '/tenant-portal/?sso_request=' + quote(request_id, safe=''))])
        if action == 'resume':
            connection = database.connect()
            if method != 'GET':
                return _response(405, {'ok': False, 'error': 'method_not_allowed'})
            request_id = str(query.get('request_id', '')).strip()
            identity = _browser_identity(connection, request_context)
            if re.fullmatch('[A-Za-z0-9_-]{43}', request_id) is None or identity is None:
                return _response(401, {'ok': False, 'error': 'sso_login_required'})
            return _issue_code(connection, request_id, identity)
        if action == 'token':
            connection = database.connect()
            try:
                data = _form_body(request_context)
            except SsoError:
                return _response(400, {'ok': False, 'error': 'invalid_grant'})
            client_id = str(data.get('client_id', '')).strip()
            client_secret = str(data.get('client_secret', ''))
            authorization = str(request_context.get('header:authorization', ''))
            match = re.fullmatch('(?i:Basic)\\s+([A-Za-z0-9+/]+={0,2})', authorization)
            if match:
                try:
                    credentials = base64.b64decode(match.group(1), validate=True).decode('utf-8')
                except (ValueError, UnicodeDecodeError):
                    credentials = ''
                if ':' in credentials:
                    client_id, client_secret = credentials.split(':', 1)
            client = _client(client_id)
            if client is None or not hmac.compare_digest(str(client['client_secret']), client_secret):
                return _response(401, {'ok': False, 'error': 'invalid_client'})
            code = str(data.get('code', '')).strip()
            redirect_uri = str(data.get('redirect_uri', '')).strip()
            verifier = str(data.get('code_verifier', ''))
            if data.get('grant_type') != 'authorization_code' or re.fullmatch('[A-Za-z0-9_-]{43}', code) is None or (not _redirect_allowed(client, redirect_uri)) or (re.fullmatch('[A-Za-z0-9._~-]{43,128}', verifier) is None):
                return _response(400, {'ok': False, 'error': 'invalid_grant'})
            try:
                signing_key = _private_key()
            except Exception:
                return _response(503, {'ok': False, 'error': 'sso_signing_key_unavailable'})
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute("SELECT c.id,c.passkey_id,c.code_challenge,c.nonce_value,c.auth_time FROM common_id_sso_codes c JOIN tenant_portal_passkeys p ON p.id=c.passkey_id AND p.revoked_at IS NULL WHERE c.code_hash=%s AND c.client_id=%s AND c.redirect_uri=%s AND EXISTS(SELECT 1 FROM tenant_portal_memberships m JOIN tenants t ON t.id=m.tenant_id AND t.status='active' WHERE m.passkey_id=p.id) AND c.consumed_at IS NULL AND c.expires_at>UTC_TIMESTAMP() LIMIT 1 FOR UPDATE", (_hash(code), client_id, redirect_uri))
                row = cursor.fetchone()
                expected_challenge = _b64(hashlib.sha256(verifier.encode()).digest())
                if not row or not hmac.compare_digest(str(row['code_challenge']), expected_challenge):
                    connection.rollback()
                    return _response(400, {'ok': False, 'error': 'invalid_grant'})
                id_token = _id_token(signing_key, client_id, int(row['passkey_id']), int(row['auth_time']), str(row['nonce_value']))
                cursor.execute('UPDATE common_id_sso_codes SET consumed_at=UTC_TIMESTAMP() WHERE id=%s AND consumed_at IS NULL', (int(row['id']),))
                access_token = _b64(secrets.token_bytes(32))
                cursor.execute('INSERT INTO common_id_sso_tokens(token_hash,client_id,passkey_id,expires_at) VALUES(%s,%s,%s,UTC_TIMESTAMP()+INTERVAL 10 MINUTE)', (_hash(access_token), client_id, int(row['passkey_id'])))
            connection.commit()
            return _response(200, {'access_token': access_token, 'token_type': 'Bearer', 'expires_in': 600, 'scope': 'openid', 'id_token': id_token})
        if action == 'userinfo':
            connection = database.connect()
            match = re.fullmatch('Bearer ([A-Za-z0-9_-]{43})', str(request_context.get('header:authorization', '')))
            if not match:
                return _response(401, {'ok': False, 'error': 'invalid_token'})
            with connection.cursor() as cursor:
                cursor.execute("SELECT a.passkey_id FROM common_id_sso_tokens a JOIN tenant_portal_passkeys p ON p.id=a.passkey_id AND p.revoked_at IS NULL WHERE a.token_hash=%s AND a.revoked_at IS NULL AND a.expires_at>UTC_TIMESTAMP() AND EXISTS(SELECT 1 FROM tenant_portal_memberships m JOIN tenants t ON t.id=m.tenant_id AND t.status='active' WHERE m.passkey_id=p.id) LIMIT 1", (_hash(match.group(1)),))
                identity = cursor.fetchone()
            if not identity:
                return _response(401, {'ok': False, 'error': 'invalid_token'})
            return _response(200, {'sub': _subject(int(identity['passkey_id']))})
    except database.DatabaseConfigurationError:
        return _response(503, {'ok': False, 'error': 'service_unavailable'})
    except SsoError as exc:
        return _response(exc.status, {'ok': False, 'error': exc.error}, exc.headers)
    except Exception:
        if connection:
            connection.rollback()
        return _response(503, {'ok': False, 'error': 'common_id_sso_unavailable'})
    finally:
        if connection:
            connection.close()
