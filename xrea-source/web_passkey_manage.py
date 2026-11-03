"""Python implementation of the isolated administrator passkey manager."""
from native_http import make_response, add_headers, legacy_compatible
import hashlib
import hmac
import json
import os
import time
from http.cookies import SimpleCookie
from urllib.parse import quote
from file_locking import fcntl
from admin_api_handlers import CSRF_COOKIE, SESSION_COOKIE
from passkey_handlers import _read_store, _store_path, _write_store

@legacy_compatible(callback_index=0, request_index=None)
def _json(status, payload):
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    _http_status, _http_headers = (status, [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=None, request_index=0)
def _cookies(request_context):
    jar = SimpleCookie()
    try:
        jar.load(request_context.get('header:cookie', ''))
    except Exception:
        pass
    return jar

@legacy_compatible(callback_index=1, request_index=0)
def web_passkey_manage(request_context):
    jar = _cookies(request_context)
    token = str(request_context.get('header:x-ha-session', '') or (jar.get(SESSION_COOKIE).value if jar.get(SESSION_COOKIE) else '')).strip()
    if not token:
        return _json('401 Unauthorized', {'ok': False, 'error': 'passkey_login_required'})
    from baas_handlers import _decode_admin_session
    claims = _decode_admin_session(token)
    if not claims:
        return _json('401 Unauthorized', {'ok': False, 'error': 'passkey_login_required'})
    if 'passkey:manage' not in claims.get('scope', []):
        return _json('403 Forbidden', {'ok': False, 'error': 'insufficient_role'})
    request_context['header:x-ha-session'] = token
    from ha_handlers import _ha_authorized_scope
    if not _ha_authorized_scope(request_context, 'passkey:manage'):
        return _json('403 Forbidden', {'ok': False, 'error': 'insufficient_role'})
    if jar.get(SESSION_COOKIE):
        host = str(request_context.get('header:host', '')).lower().split(':', 1)[0]
        csrf_cookie = jar.get(CSRF_COOKIE).value if jar.get(CSRF_COOKIE) else ''
        csrf_header = str(request_context.get('header:x-csrf-token', ''))
        if str(request_context.get('header:origin', '')) != 'https://' + host or not csrf_cookie or (not hmac.compare_digest(csrf_cookie, csrf_header)):
            return _json('403 Forbidden', {'ok': False, 'error': 'csrf_validation_failed'})
    try:
        stream = request_context.get('body_stream')
        raw = stream.read() if stream is not None else b''
        decoded = json.loads(raw.decode('utf-8')) if raw else None
        if isinstance(decoded, dict):
            data = decoded
        elif isinstance(decoded, list):
            data = {}
        else:
            raise ValueError()
    except Exception:
        return _json('400 Bad Request', {'ok': False, 'error': 'invalid_json'})
    action_value = data.get('action')
    action = str('' if action_value is None else action_value)
    if action not in {'list', 'enroll', 'rename', 'revoke'}:
        return _json('400 Bad Request', {'ok': False, 'error': 'unknown_action'})
    if action != 'list' and int(claims.get('issued_at', 0) or 0) < int(time.time()) - 120:
        return _json('428 Precondition Required', {'ok': False, 'error': 'passkey_reauthentication_required'})
    try:
        path = _store_path()
        lock_path = path.with_name('passkey-store.lock')
        with open(lock_path, 'a+b') as lock:
            os.chmod(lock_path, 384)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            store = _read_store(path)
            credentials = store['credentials']
            if action == 'list':
                items = [{'id': key, 'label': str(row.get('label') or 'パスキー'), 'created_at': row.get('created'), 'last_used_at': row.get('last_used'), 'sign_count': int(row.get('count', 0))} for key, row in credentials.items()]
                result = {'ok': True, 'credentials': items}
            elif action == 'enroll':
                host = str(request_context.get('header:host', '2415.jp')).lower().split(':', 1)[0]
                if host not in {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}:
                    host = '2415.jp'
                from passkey_handlers import _b64e
                ticket = _b64e(os.urandom(24))
                label = str(data.get('label', '管理用パスキー')).strip()[:60] or '管理用パスキー'
                store['tickets'][ticket] = {'expires': int(time.time()) + 300, 'label': label, 'return_host': host}
                _write_store(path, store)
                url = f'https://{host}/license/python-migration/ha/passkey.php?mode=register&client=admin_web&ticket={quote(ticket)}&return_host={quote(host)}'
                result = {'ok': True, 'url': url, 'federation_synced': None, 'federation_failed': []}
            else:
                credential_id = str(data.get('id', ''))
                if credential_id not in credentials:
                    return _json('404 Not Found', {'ok': False, 'error': 'passkey_not_found'})
                if action == 'rename':
                    credentials[credential_id]['label'] = str(data.get('label', '')).strip()[:60]
                    credentials[credential_id]['updated_at'] = int(time.time())
                else:
                    if len(credentials) <= 1:
                        return _json('409 Conflict', {'ok': False, 'error': 'cannot_revoke_last_passkey'})
                    del credentials[credential_id]
                    store['revoked_credentials'][credential_id] = int(time.time())
                    credential_hash = hashlib.sha256(credential_id.encode()).hexdigest()
                    store['sso_sessions'] = {key: row for key, row in store.get('sso_sessions', {}).items() if not hmac.compare_digest(credential_hash, str(row.get('credential_id_hash', '')))}
                _write_store(path, store)
                result = {'ok': True, 'url': None, 'federation_synced': None, 'federation_failed': []}
        if action in {'rename', 'revoke'}:
            try:
                from federation_handlers import push_passkey_store
                federation_cookie = jar.get('tuti_admin_sso')
                federation = push_passkey_store(federation_cookie.value if federation_cookie else '', store, request_context.get('header:host', ''))
                result['federation_synced'] = federation.get('ok')
                result['federation_failed'] = federation.get('failed', [])
            except Exception:
                result['federation_synced'] = False
                result['federation_failed'] = [host for host in ('2415.jp', 'backup.2415.jp', 'main.2415.jp') if host != str(request_context.get('header:host', '')).lower()]
        return _json('200 OK', result)
    except Exception:
        return _json('503 Service Unavailable', {'ok': False, 'error': 'passkey_management_failed'})
