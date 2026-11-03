"""Python OIDC relying-party routes for the isolated Common ID demo site."""
from native_http import make_response, add_headers, legacy_compatible
from deployment_settings import site_url
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from http_utils import php_parse_query
ISSUER = 'https://sso.2415.jp'
CLIENT_ID = 'tuti-python-demo'
COOKIE = '__Host-tuti_sso_demo_python_migration'
CLUSTER = {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}

def _secret():
    value = os.environ.get('PYTHON_MIGRATION_SSO_DEMO_CLIENT_SECRET', '') or os.environ.get('COMMON_ID_SSO_DEMO_CLIENT_SECRET', '')
    if len(value) < 32:
        try:
            from migration_config import secret_value
            value = secret_value('common_id_sso_demo_client_secret')
        except Exception:
            value = ''
    if not isinstance(value, str) or len(value) < 32:
        raise RuntimeError('demo_client_secret_unconfigured')
    return value

def _cookie_key():
    from migration_config import secret_value
    secret = secret_value('token_secret')
    if not isinstance(secret, str) or len(secret) < 32:
        raise RuntimeError('demo_cookie_secret_unconfigured')
    return hmac.new(secret.encode(), b'tuti-common-id-demo/python-migration/v1', hashlib.sha256).digest()

def _encryption_key():
    return hmac.new(_cookie_key(), b'tuti-common-id-demo/session-encryption/v2', hashlib.sha256).digest()

def _b64e(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip('=')

def _b64d(raw):
    if not isinstance(raw, str) or len(raw) > 8192:
        raise ValueError('invalid_cookie')
    return base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4))

def _encode_cookie(state):
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(state, separators=(',', ':')).encode()
    ciphertext = AESGCM(_encryption_key()).encrypt(nonce, plaintext, b'common-id-sso-demo:v2')
    return 'v2.' + _b64e(nonce) + '.' + _b64e(ciphertext)

@legacy_compatible(callback_index=None, request_index=0)
def _read_cookie(request_context):
    parsed = SimpleCookie()
    try:
        parsed.load(request_context.get('header:cookie', ''))
        token = parsed.get(COOKIE)
        if not token:
            return {}
        if token.value.startswith('v2.'):
            version, encoded_nonce, encoded_ciphertext = token.value.split('.', 2)
            if version != 'v2':
                return {}
            plaintext = AESGCM(_encryption_key()).decrypt(_b64d(encoded_nonce), _b64d(encoded_ciphertext), b'common-id-sso-demo:v2')
            state = json.loads(plaintext.decode('utf-8'))
            if not isinstance(state, dict) or int(state.get('expires', 0)) <= int(time.time()):
                return {}
            return state
        payload, signature = token.value.split('.', 1)
        expected = _b64e(hmac.new(_cookie_key(), payload.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return {}
        state = json.loads(_b64d(payload))
        if not isinstance(state, dict) or int(state.get('expires', 0)) <= int(time.time()):
            return {}
        return state
    except Exception:
        return {}

@legacy_compatible(callback_index=0, request_index=None)
def _response(status, body=b'', content_type='application/json; charset=utf-8', headers=()):
    base = [('Content-Type', content_type), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer')]
    base.extend(headers)
    base.append(('Content-Length', str(len(body))))
    _http_status, _http_headers = (status, base)
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=0, request_index=None)
def _json(status, payload):
    return _response(status, json.dumps(payload, separators=(',', ':')).encode())

@legacy_compatible(callback_index=0, request_index=None)
def _redirect(location, status='303 See Other', clear_cookie=False, cookie_value=None):
    headers = [('Location', location)]
    if clear_cookie:
        headers.append(('Set-Cookie', COOKIE + '=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax'))
    elif cookie_value is not None:
        headers.append(('Set-Cookie', COOKIE + '=' + cookie_value + '; Path=/; Secure; HttpOnly; SameSite=Lax'))
    return _response(status, b'', 'text/plain; charset=utf-8', headers)

def _new_session_cookie():
    return _encode_cookie({'expires': int(time.time()) + 43200})

@legacy_compatible(callback_index=None, request_index=0)
def _host(request_context):
    raw = request_context.get('header:host', '2415.jp').lower().split(':', 1)[0]
    return raw if raw in CLUSTER else '2415.jp'

@legacy_compatible(callback_index=None, request_index=0)
def _base(request_context):
    override = os.environ.get('PYTHON_MIGRATION_SSO_DEMO_BASE_URL', '').rstrip('/')
    if override:
        return override
    return 'https://' + _host(request_context) + site_url('/license/python-migration/common-id-sso-demo')

def _page(identity=None, error=''):
    if identity:
        content = '<p>サインイン済みです。共通IDの匿名識別子:</p><div class="sub">' + html.escape(str(identity.get('sub', ''))) + '</div><p><a class="button" href="logout.php">このアプリからログアウト</a></p>'
    else:
        content = '<p>この別ドメインのWebアプリへ、共通IDでサインインします。</p><p><a class="button" href="login.php">共通IDでログイン</a></p>'
    if error:
        content += '<p class="error">' + html.escape(error) + '</p><p><a href="index.php">戻る</a></p>'
    return ('<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>共通ID SSO サンプル</title><style>:root{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:#172033;background:#f3f6fb}body{margin:0;min-height:100vh;display:grid;place-items:center}.card{width:min(34rem,calc(100% - 2rem));box-sizing:border-box;background:#fff;border:1px solid #dce3ef;border-radius:1rem;padding:2rem;box-shadow:0 1rem 3rem #17203312}h1{font-size:1.4rem;margin:0 0 .5rem}p{line-height:1.7;color:#536079}.button{display:inline-block;background:#234bbb;color:white;text-decoration:none;border-radius:.65rem;padding:.8rem 1.1rem;font-weight:650}.sub{font:.85rem ui-monospace,monospace;overflow-wrap:anywhere;background:#f3f6fb;padding:.7rem;border-radius:.5rem}.error{color:#b42318}</style></head><body><main class="card"><h1>共通ID SSO サンプル</h1>' + content + '</main></body></html>').encode()

@legacy_compatible(callback_index=0, request_index=None)
def _error_page(message, status='400 Bad Request', clear_cookie=True):
    body = ('<!doctype html><meta charset="utf-8"><title>SSOエラー</title><p>' + html.escape(message) + '</p><p><a href="index.php">戻る</a></p>').encode()
    headers = [('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")]
    if clear_cookie:
        headers.append(('Set-Cookie', COOKIE + '=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax'))
    return _response(status, body, 'text/html; charset=utf-8', headers)

def _http_json(url, form=None, basic=None):
    headers = {'Accept': 'application/json', 'User-Agent': 'TutiLicenseSSODemo/1.0'}
    data = None
    if form is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        data = urllib.parse.urlencode(form).encode()
    if basic:
        headers['Authorization'] = 'Basic ' + base64.b64encode(basic.encode()).decode()
    request = urllib.request.Request(url, data=data, headers=headers, method='POST' if data is not None else 'GET')
    try:

        class NoRedirect(urllib.request.HTTPRedirectHandler):

            def redirect_request(self, req, fp, code, msg, response_headers, new_url):
                return None
        opener = urllib.request.build_opener(NoRedirect())
        with opener.open(request, timeout=15) as response:
            if not 200 <= int(response.getcode()) < 300:
                raise RuntimeError('sso_server_request_failed')
            raw = response.read(1048577)
            if len(raw) > 1048576:
                raise RuntimeError('sso_server_invalid_response')
            value = json.loads(raw.decode('utf-8'))
    except RuntimeError:
        raise
    except (OSError, ValueError, UnicodeDecodeError, urllib.error.URLError) as exc:
        raise RuntimeError('sso_server_request_failed') from exc
    if not isinstance(value, dict):
        raise RuntimeError('sso_server_invalid_response')
    return value

def _jwt_part(value):
    raw = _b64d(value)
    result = json.loads(raw.decode('utf-8'))
    if not isinstance(result, dict):
        raise ValueError('invalid_jwt')
    return result

def _verify_id_token(token, nonce):
    pieces = token.split('.')
    if len(pieces) != 3:
        raise RuntimeError('invalid_id_token')
    header, claims = (_jwt_part(pieces[0]), _jwt_part(pieces[1]))
    if header.get('alg') != 'RS256' or not isinstance(header.get('kid'), str):
        raise RuntimeError('invalid_id_token_algorithm')
    jwks = _http_json(ISSUER + '/jwks')
    candidates = jwks.get('keys', [])
    jwk = next((item for item in candidates if isinstance(item, dict) and item.get('kid') == header['kid']), None) if isinstance(candidates, list) else None
    if not jwk or jwk.get('kty') != 'RSA':
        raise RuntimeError('id_token_key_not_found')
    try:
        n, e = (int.from_bytes(_b64d(jwk['n']), 'big'), int.from_bytes(_b64d(jwk['e']), 'big'))
        key = rsa.RSAPublicNumbers(e, n).public_key()
        signature = _b64d(pieces[2])
        key.verify(signature, (pieces[0] + '.' + pieces[1]).encode(), padding.PKCS1v15(), hashes.SHA256())
    except Exception as exc:
        raise RuntimeError('id_token_signature_invalid') from exc
    aud = claims.get('aud')
    now, issued, expires = (int(time.time()), int(claims.get('iat', 0)), int(claims.get('exp', 0)))
    if claims.get('iss') != ISSUER or not (CLIENT_ID in aud if isinstance(aud, list) else aud == CLIENT_ID) or issued < 1 or (issued > now + 60) or (expires <= now) or (expires - issued > 600) or (not hmac.compare_digest(str(claims.get('nonce', '')), nonce)) or (not isinstance(claims.get('sub'), str)):
        raise RuntimeError('id_token_claims_invalid')
    return {'sub': claims['sub']}

@legacy_compatible(callback_index=1, request_index=0)
def common_id_demo(request_context):
    path = request_context.get('path', '')
    base = _base(request_context)
    state = _read_cookie(request_context)
    if path == '/common-id-sso-demo/common.php':
        if COOKIE not in request_context.get('header:cookie', ''):
            try:
                cookie = _new_session_cookie()
            except Exception:
                cookie = None
            headers = [('Cache-Control', 'no-store'), ('Content-Length', '0')]
            if cookie is not None:
                headers.append(('Set-Cookie', COOKIE + '=' + cookie + '; Path=/; Secure; HttpOnly; SameSite=Lax'))
            _http_status, _http_headers = ('200 OK', headers)
            return make_response([b''], _http_status, _http_headers)
        _http_status, _http_headers = ('200 OK', [('Cache-Control', 'no-store'), ('Content-Length', '0')])
        return make_response([b''], _http_status, _http_headers)
    if path == '/common-id-sso-demo/index.php':
        body = _page(state.get('identity') if isinstance(state.get('identity'), dict) else None)
        headers = [('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")]
        if not state and COOKIE not in request_context.get('header:cookie', ''):
            try:
                cookie = _new_session_cookie()
                headers.append(('Set-Cookie', COOKIE + '=' + cookie + '; Path=/; Secure; HttpOnly; SameSite=Lax'))
            except Exception:
                return _error_page('検証サイトのセッション署名キーが設定されていません。', '503 Service Unavailable', clear_cookie=False)
        return _response('200 OK', body, 'text/html; charset=utf-8', headers)
    if path == '/common-id-sso-demo/login.php':
        if state.get('identity'):
            return _redirect('index.php')
        verifier = _b64e(secrets.token_bytes(48))
        nonce, oauth_state = (_b64e(secrets.token_bytes(32)), _b64e(secrets.token_bytes(32)))
        created = int(time.time())
        callback = base + '/callback.php'
        challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
        params = {'response_type': 'code', 'client_id': CLIENT_ID, 'redirect_uri': callback, 'scope': 'openid', 'state': oauth_state, 'nonce': nonce, 'code_challenge': challenge, 'code_challenge_method': 'S256'}
        location = ISSUER + '/authorize?' + urllib.parse.urlencode(params)
        try:
            cookie = _encode_cookie({'expires': created + 600, 'oidc': {'state': oauth_state, 'nonce': nonce, 'verifier': verifier, 'created': created}})
        except Exception:
            return _error_page('検証サイトのセッション署名キーが設定されていません。', '503 Service Unavailable', clear_cookie=False)
        return _redirect(location, status='302 Found', cookie_value=cookie)
    if path == '/common-id-sso-demo/logout.php':
        return _redirect('index.php', clear_cookie=True)
    if path != '/common-id-sso-demo/callback.php':
        return _json('404 Not Found', {'ok': False, 'error': 'not_found'})
    query = php_parse_query(request_context.get('query', ''), keep_blank_values=True)
    flow = state.get('oidc')
    if not isinstance(flow, dict) or int(flow.get('created', 0)) < int(time.time()) - 600:
        return _error_page('ログイン要求が期限切れです。もう一度お試しください。')
    if 'error' in query:
        return _error_page('共通IDログインが完了しませんでした。')
    code = query.get('code', [''])[-1]
    response_state = query.get('state', [''])[-1]
    if not code or not hmac.compare_digest(str(flow.get('state', '')), response_state):
        return _error_page('ログイン応答を確認できませんでした。')
    try:
        token = _http_json(ISSUER + '/token', {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': base + '/callback.php', 'code_verifier': str(flow['verifier'])}, CLIENT_ID + ':' + _secret())
        identity = _verify_id_token(str(token.get('id_token', '')), str(flow['nonce']))
        cookie = _encode_cookie({'expires': int(time.time()) + 43200, 'identity': identity})
        return _redirect('index.php', cookie_value=cookie)
    except RuntimeError as exc:
        if str(exc).endswith('unconfigured'):
            return _error_page('検証サイトの共通ID設定が完了していません。', '503 Service Unavailable')
        return _error_page('共通IDとの接続に失敗しました。設定とサーバーログを確認してください。', '502 Bad Gateway')
    except Exception:
        return _error_page('共通IDとの接続に失敗しました。設定とサーバーログを確認してください。', '502 Bad Gateway')
