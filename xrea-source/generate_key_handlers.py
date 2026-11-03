"""Isolated Python implementation of the legacy product-key generator page."""
from native_http import make_response, add_headers, legacy_compatible
from deployment_settings import site_url
from py36_compat import parse_iso_datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import html
import time
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import quote
import database
from core import license_key_hash, offline_lookup, offline_secret, offline_secret_encrypt, php_int_cast, _php_trim
from migration_config import secret_value
COOKIE = 'tuti_python_migration_generate_key_session'
CSRF = 'tuti_python_migration_generate_key_csrf'
BASE_PATH = site_url('/license/python-migration/')
ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
_IDEMPOTENCY_DDL = 'CREATE TABLE IF NOT EXISTS idempotency_keys (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,operation VARCHAR(40) NOT NULL,request_key VARCHAR(100) NOT NULL,response_json TEXT NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(id),UNIQUE KEY uq_idempotency_operation_key(operation,request_key)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'

def _ensure_idempotency_schema(connection):
    with connection.cursor() as cursor:
        cursor.execute(_IDEMPOTENCY_DDL)

@legacy_compatible(callback_index=0, request_index=None)
def _api_failure():
    return _reply('500 Internal Server Error', {'success': False, 'error_id': secrets.token_hex(4)})

def _php_string(value):
    if value is None or value is False:
        return ''
    if value is True:
        return '1'
    if isinstance(value, (dict, list)):
        return 'Array'
    return str(value)

def _parse_php_datetime(value):
    """Parse common absolute forms accepted by PHP DateTimeImmutable."""
    if value.startswith('@'):
        try:
            return datetime.fromtimestamp(float(value[1:]), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            raise ValueError('invalid_expires_at')
    try:
        return parse_iso_datetime(value)
    except (TypeError, ValueError):
        pass
    if re.fullmatch('\\d{4}-\\d{2}', value):
        try:
            return datetime.strptime(value, '%Y-%m')
        except ValueError:
            pass
    if re.fullmatch('\\d{4}', value):
        return datetime(int(value), 1, 1)
    try:
        return parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        pass
    for pattern in ('%Y/%m/%d %H:%M:%S', '%Y/%m/%d %H:%M', '%Y/%m/%d', '%m/%d/%Y %H:%M:%S', '%m/%d/%Y %H:%M', '%m/%d/%Y', '%d.%m.%Y %H:%M:%S', '%d.%m.%Y %H:%M', '%d.%m.%Y', '%B %d, %Y %H:%M:%S', '%B %d, %Y %H:%M', '%B %d, %Y', '%b %d, %Y %H:%M:%S', '%b %d, %Y %H:%M', '%b %d, %Y'):
        try:
            return datetime.strptime(value, pattern)
        except ValueError:
            continue
    raise ValueError('invalid_expires_at')

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status, payload, headers=()):
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    _http_status, _http_headers = (status, [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))] + list(headers))
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=0, request_index=None)
def _page(logged_in=False, csrf='', message='', key='', legacy_allowed=None, headers=()):
    if legacy_allowed is None:
        legacy_allowed = _legacy_password_allowed()
    msg = '<p class="msg" role="status">' + html.escape(message) + '</p>' if message else ''
    issued = '<pre class="key">' + html.escape(key) + '</pre>' if key else ''
    form = f'<form method="post"><input type="hidden" name="csrf" value="{html.escape(csrf)}"><label>顧客名・メモ<input name="label" maxlength="100"></label><label>同時利用台数<input name="max_devices" type="number" min="1" max="500" value="1"></label><label>有効期限（UTC、空欄なら無期限）<input name="expires_at" type="datetime-local"></label><button name="issue" value="1">新しいキーを発行</button></form><p><a href="admin_api.php">統合ライセンス管理センター</a></p>' if logged_in else '<a class="button" href="ha/passkey.php?mode=authenticate&amp;client=generate_web">パスキーでログイン</a><p class="small">検証サイトではパスキー認証を使用します。</p>'
    if not logged_in and legacy_allowed:
        form = form + '<details class="legacy"><summary>緊急用パスワード</summary><p class="small">許可されたメンテナンス中のみ利用できます。</p><form method="post"><label>管理者パスワード<input name="password" type="password" autocomplete="current-password" required></label><button>ログイン</button></form></details>'
    page = f"<!doctype html><html lang=ja><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><meta name=referrer content=no-referrer><title>プロダクトキー発行</title><style>body{{margin:0;background:#f3f7f8;color:#142b35;font:16px system-ui;min-height:100vh;display:grid;place-items:center}}.card{{box-sizing:border-box;width:min(700px,calc(100% - 28px));background:white;border:1px solid #dce7e8;border-radius:18px;padding:26px;box-shadow:0 8px 30px #1232}}h1{{margin-top:0}}label{{display:block;margin:14px 0 6px;font-weight:700}}input{{box-sizing:border-box;width:100%;padding:12px;border:1px solid #ccd;border-radius:9px;font:inherit}}button,.button{{display:block;width:100%;box-sizing:border-box;margin-top:18px;padding:14px;border:0;border-radius:10px;background:#087e74;color:#fff;text-align:center;text-decoration:none;font-weight:700}}.msg{{padding:12px;background:#e8f5f3}}.key{{overflow-wrap:anywhere;padding:16px;background:#f0faf8;color:#10584f;font-size:20px}}.small{{color:#617780;font-size:13px}}</style><main class=card><h1>{('プロダクトキー発行' if logged_in else 'ライセンス管理')}</h1>{msg}{issued}{form}</main></html>".encode()
    _http_status, _http_headers = ('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'), ('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"), ('Content-Length', str(len(page)))] + list(headers))
    return make_response([page], _http_status, _http_headers)

def _legacy_password_allowed():
    if os.environ.get('PYTHON_MIGRATION_ALLOW_LEGACY_PASSWORD_ADMIN') != '1':
        return False
    state = {}
    try:
        from ha_handlers import _runtime_json
        state = _runtime_json('state.json') or {}
    except Exception:
        pass
    maintenance = state.get('maintenance') is True if 'maintenance' in state else os.environ.get('PYTHON_MIGRATION_HA_MAINTENANCE') == '1'
    return maintenance

@legacy_compatible(callback_index=None, request_index=0)
def _network_allowed(request_context):
    configured = _php_trim(os.environ.get('LICENSE_ADMIN_ALLOWED_IPS', ''))
    if not configured:
        configured = secret_value('admin_allowed_ips') or os.environ.get('PYTHON_MIGRATION_ADMIN_ALLOWED_IPS', '')
    allowed = [_php_trim(item) for item in configured.split(',') if _php_trim(item)]
    return not allowed or _php_string(request_context.get('client_address')) in allowed

@legacy_compatible(callback_index=None, request_index=0)
def _form_post(request_context):
    from ha_mode import _php_post
    return _php_post(request_context)

@legacy_compatible(callback_index=None, request_index=0)
def _attempt_subject(request_context):
    remote_addr = request_context.get('client_address')
    address = _php_string('0.0.0.0' if remote_addr is None else remote_addr)
    return hashlib.sha256(address.encode()).hexdigest()

def _attempt_locked(connection, subject_hash):
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) AS n FROM auth_attempts WHERE action=%s AND subject_type='ip' AND subject_hash=%s AND success=0 AND attempted_at>=DATE_SUB(UTC_TIMESTAMP(),INTERVAL 15 MINUTE)", ('generate_key_login', subject_hash))
        row = cursor.fetchone() or {}
    return int(row.get('n', 0)) >= 5

def _record_attempt(connection, subject_hash, reason):
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO auth_attempts(ip_hash,action,subject_type,subject_hash,success,error_code,attempted_at) VALUES(%s,'generate_key_login','ip',%s,0,%s,UTC_TIMESTAMP())", (subject_hash, subject_hash, str(reason)[:80]))

def _clear_attempts(connection, subject_hash):
    with connection.cursor() as cursor:
        cursor.execute("DELETE FROM auth_attempts WHERE action='generate_key_login' AND subject_type='ip' AND subject_hash=%s", (subject_hash,))

def _password_matches(password):
    encoded = secret_value('admin_password_hash').strip()
    if not encoded:
        return False
    try:
        import bcrypt
        normalized = encoded.encode('ascii')
        if normalized.startswith(b'$2y$'):
            normalized = b'$2b$' + normalized[4:]
        if normalized.startswith((b'$2a$', b'$2b$', b'$2x$')):
            return bcrypt.checkpw(str(password).encode('utf-8')[:72], normalized)
    except (ImportError, ValueError, UnicodeEncodeError):
        return False
    return False

@legacy_compatible(callback_index=1, request_index=0)
def _legacy_login(request_context, password):
    subject = _attempt_subject(request_context)
    connection = None
    try:
        connection = database.connect()
        if _attempt_locked(connection, subject):
            return _page(message='管理者認証の試行が一時停止されています。15分後に再試行してください。', legacy_allowed=True)
        if not _password_matches(password):
            _record_attempt(connection, subject, 'ui_login')
            connection.commit()
            return _page(message='管理者パスワードが違います。', legacy_allowed=True)
        _clear_attempts(connection, subject)
        connection.commit()
        from web_passkey_auth import ADMIN_SCOPES, _encode_token
        now = int(time.time())
        token = _encode_token({'purpose': 'ha_admin', 'scope': list(ADMIN_SCOPES), 'client': 'generate_web', 'issued_at': now, 'expires': now + 1800, 'auth_method': 'legacy_password', 'nonce': secrets.token_urlsafe(18)})
        csrf = secrets.token_urlsafe(32)
        _http_status, _http_headers = ('303 See Other', [('Location', BASE_PATH + 'generate_key.php'), ('Set-Cookie', COOKIE + '=' + token + '; Path=' + BASE_PATH + '; Max-Age=1800; Secure; HttpOnly; SameSite=Strict'), ('Set-Cookie', CSRF + '=' + csrf + '; Path=' + BASE_PATH + '; Max-Age=1800; Secure; SameSite=Strict'), ('Cache-Control', 'no-store'), ('Content-Length', '0')])
        return make_response([b''], _http_status, _http_headers)
    except Exception:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        return _page(message='管理者ログインを確認できませんでした。設定とDB接続を確認してください。', legacy_allowed=True)
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=None, request_index=0)
def _legacy_api_auth(request_context, password):
    subject = _attempt_subject(request_context)
    connection = None
    try:
        connection = database.connect()
        if _attempt_locked(connection, subject):
            connection.rollback()
            return ('429 Too Many Requests', secrets.token_hex(4))
        if not _password_matches(password):
            _record_attempt(connection, subject, 'api_generate_key')
            connection.commit()
            return ('403 Forbidden', secrets.token_hex(4))
        _clear_attempts(connection, subject)
        connection.commit()
        return None
    except Exception:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        return ('503 Service Unavailable', secrets.token_hex(4))
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=None, request_index=0)
def _cookie(request_context, name):
    jar = SimpleCookie()
    try:
        jar.load(str(request_context.get('header:cookie', '')))
        return jar[name].value if name in jar else ''
    except Exception:
        return ''

@legacy_compatible(callback_index=None, request_index=0)
def _claims(request_context, data, allow_cookie=True):
    token_value = request_context.get('header:x-ha-session')
    if token_value is None:
        token_value = data.get('passkey_session')
    if token_value is None and allow_cookie:
        token_value = _cookie(request_context, COOKIE)
    token = _php_trim(token_value)
    if not token:
        return (None, '', False)
    from baas_handlers import _decode_admin_session
    claims = _decode_admin_session(token)
    scopes = claims.get('scope', []) if claims else []
    if not isinstance(scopes, list):
        scopes = [scopes]
    if not claims or 'admin:manage' not in scopes:
        return (None, token, False)
    if claims.get('auth_method') == 'legacy_password':
        return (claims, token, True) if _legacy_password_allowed() else (None, token, False)
    request_context['header:x-ha-session'] = token
    from ha_handlers import _ha_authorized_scope
    if not _ha_authorized_scope(request_context, 'admin:manage'):
        return (None, token, False)
    return (claims, token, True)

def _refresh_session(claims, csrf):
    refreshed_claims = dict(claims)
    now = int(time.time())
    refreshed_claims['expires'] = now + 1800
    refreshed_claims['last_activity'] = now
    from web_passkey_auth import _encode_token
    token = _encode_token(refreshed_claims)
    return (token, [('Set-Cookie', COOKIE + '=' + token + '; Path=' + BASE_PATH + '; Max-Age=1800; Secure; HttpOnly; SameSite=Strict'), ('Set-Cookie', CSRF + '=' + csrf + '; Path=' + BASE_PATH + '; Max-Age=1800; Secure; SameSite=Strict')])

@legacy_compatible(callback_index=2, request_index=0)
def _exchange_code(request_context, code):
    from passkey_handlers import passkey_api
    body = json.dumps({'action': 'verify_code', 'code': code, 'client': 'generate_web'}).encode()
    internal = dict(request_context, **{'body_stream': __import__('io').BytesIO(body)}, **{'method': 'POST', 'content_type': 'application/json', 'content_length': str(len(body))})
    try:
        response = passkey_api(internal)
        result = json.loads(response.body)
    except Exception:
        return _page(message='パスキー認証を確認できませんでした。もう一度ログインしてください。')
    if response.status_code != 200 or not result.get('ok'):
        return _page(message='パスキー認証の有効期限が切れました。もう一度ログインしてください。')
    token = str(result.get('session_token', ''))
    claims, _, authorized = _claims(dict(request_context), {'passkey_session': token})
    if not authorized:
        return _page(message='キー発行権限のある管理者パスキーが必要です。')
    csrf = secrets.token_urlsafe(32)
    token, session_headers = _refresh_session(claims, csrf)
    _http_status, _http_headers = ('303 See Other', [('Location', BASE_PATH + 'generate_key.php'), *session_headers, ('Cache-Control', 'no-store'), ('Content-Length', '0')])
    return make_response([b''], _http_status, _http_headers)

def _issue(data, request_id, emergency_password=False, api_action=False):
    key = ''.join((secrets.choice(ALPHABET) for _ in range(25)))
    key = '-'.join((key[i:i + 5] for i in range(0, 25, 5)))
    pepper = secret_value('key_pepper')
    token_secret = secret_value('token_secret')
    if len(pepper) < 32 or len(token_secret) < 32:
        raise database.DatabaseConfigurationError('test key secrets are not configured')
    label_value = data.get('label')
    if api_action and label_value is None:
        label_value = 'Pythonアプリ発行'
    label = _php_trim(_php_string('' if label_value is None else label_value))[:100] or None
    max_value = data.get('max_devices')
    max_devices = min(500, max(1, php_int_cast(1 if max_value is None else max_value)))
    expires_value = data.get('expires_at')
    expires = _php_trim(_php_string('' if expires_value is None else expires_value))
    if expires:
        try:
            expires = _parse_php_datetime(expires.replace('Z', '+00:00')).strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            raise ValueError('invalid_expires_at')
    config = {'key_pepper': pepper, 'token_secret': token_secret}
    secret = offline_secret(key)
    idem = _php_trim(_php_string(data.get('idempotency_key')))
    with database.connect() as connection:
        if not (emergency_password and _legacy_password_allowed()):
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
        if idem:
            _ensure_idempotency_schema(connection)
        connection.begin()
        try:
            with connection.cursor() as cursor:
                cursor.execute('INSERT INTO licenses(key_hash,label,active,max_devices,expires_at,offline_lookup,offline_secret_enc) VALUES(%s,%s,1,%s,%s,%s,%s)', (license_key_hash(config, key), label, max_devices, expires or None, offline_lookup(secret), offline_secret_encrypt(config, secret)))
                license_id = int(cursor.lastrowid)
                if idem:
                    cursor.execute('INSERT INTO idempotency_keys(operation,request_key,response_json) VALUES(%s,%s,%s)', ('generate_key', idem, json.dumps({'success': True, 'generated_key': key}, separators=(',', ':'))))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
    return (key, license_id)

@legacy_compatible(callback_index=1, request_index=0)
def generate_key(request_context):
    if not _network_allowed(request_context):
        _http_status, _http_headers = ('404 Not Found', [('Cache-Control', 'no-store'), ('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'), ('Content-Length', '0')])
        return make_response([b''], _http_status, _http_headers)
    method = str(request_context.get('method', 'GET'))
    query = str(request_context.get('query', ''))
    if method == 'GET':
        claims, token, authorized = _claims(request_context, {})
        if not authorized or token != _cookie(request_context, COOKIE):
            return _page()
        csrf = _cookie(request_context, CSRF)
        if not csrf:
            csrf = secrets.token_urlsafe(32)
        _, headers = _refresh_session(claims, csrf)
        return _page(True, csrf, headers=headers)
    if method != 'POST':
        claims, token, authorized = _claims(request_context, {})
        if not authorized or token != _cookie(request_context, COOKIE):
            return _page()
        csrf = _cookie(request_context, CSRF)
        _, headers = _refresh_session(claims, csrf)
        return _page(True, csrf, headers=headers)
    data = _form_post(request_context)
    if not _cookie(request_context, COOKIE) and 'password' in data and (str(data.get('api_action', '')) != 'generate_key') and _legacy_password_allowed():
        return _legacy_login(request_context, str(data.get('password', '')))
    emergency_api = False
    if not _cookie(request_context, COOKIE) and str(data.get('api_action', '')) == 'generate_key' and ('password' in data) and _legacy_password_allowed():
        auth_error = _legacy_api_auth(request_context, str(data.get('password', '')))
        if auth_error:
            status, error_id = auth_error
            return _reply(status, {'success': False, 'error_id': error_id})
        emergency_api = True
    api_request = _php_string(data.get('api_action')) == 'generate_key'
    claims, token, authorized = ({'auth_method': 'legacy_password'}, '', True) if emergency_api else _claims(request_context, data, allow_cookie=not api_request)
    if not authorized:
        return _reply('403 Forbidden', {'success': False, 'error': 'PASSKEY_REQUIRED'})
    if token and token == _cookie(request_context, COOKIE):
        origin = str(request_context.get('header:origin', ''))
        host = str(request_context.get('header:host', '2415.jp')).lower().split(':', 1)[0]
        csrf = str(data.get('csrf', ''))
        if origin != 'https://' + host or not hmac.compare_digest(csrf, _cookie(request_context, CSRF)):
            return _reply('403 Forbidden', {'success': False, 'error': 'CSRF_VALIDATION_FAILED'})
    if 'logout' in data and data['logout'] is not None:
        headers = [('Set-Cookie', COOKIE + '=; Path=' + BASE_PATH + '; Max-Age=0; Secure; HttpOnly; SameSite=Strict'), ('Set-Cookie', CSRF + '=; Path=' + BASE_PATH + '; Max-Age=0; Secure; SameSite=Strict'), ('Location', BASE_PATH + 'generate_key.php')]
        _http_status, _http_headers = ('303 See Other', headers + [('Content-Length', '0'), ('Cache-Control', 'no-store')])
        return make_response([b''], _http_status, _http_headers)
    session_headers = _refresh_session(claims, _cookie(request_context, CSRF))[1] if token and token == _cookie(request_context, COOKIE) else []
    api = str(data.get('api_action', '')) == 'generate_key'
    if not api and ('issue' not in data or data['issue'] is None):
        return _reply('400 Bad Request', {'success': False, 'error': 'invalid_action'})
    idem = _php_trim(_php_string(data.get('idempotency_key', '')))
    if api and re.fullmatch('[A-Za-z0-9_-]{20,100}', idem) is None:
        return _api_failure()
    try:
        if api:
            connection = database.connect()
            try:
                _ensure_idempotency_schema(connection)
                with connection.cursor() as cursor:
                    cursor.execute('SELECT response_json FROM idempotency_keys WHERE operation=%s AND request_key=%s', ('generate_key', idem))
                    row = cursor.fetchone()
                if row and row.get('response_json'):
                    return _reply('200 OK', json.loads(row['response_json']))
            finally:
                connection.close()
        emergency_password = claims.get('auth_method') == 'legacy_password'
        key, license_id = _issue(data, secrets.token_hex(8), emergency_password=emergency_password, api_action=api)
        if api:
            return _reply('200 OK', {'success': True, 'generated_key': key})
        return _page(True, _cookie(request_context, CSRF), 'プロダクトキーを発行しました。この画面を閉じる前に保存してください。', key, headers=session_headers)
    except ValueError:
        if api:
            return _api_failure()
        error_id = secrets.token_hex(4)
        return _page(True, _cookie(request_context, CSRF), '発行できませんでした。エラーID: ' + error_id, headers=session_headers)
    except Exception:
        if api:
            return _api_failure()
        error_id = secrets.token_hex(4)
        return _page(True, _cookie(request_context, CSRF), '発行できませんでした。エラーID: ' + error_id, headers=session_headers)
