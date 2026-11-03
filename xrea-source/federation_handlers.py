"""Isolated Python endpoint for HA passkey federation."""
from native_http import make_response, add_headers, legacy_compatible
from file_locking import fcntl
import copy
import base64
import hashlib
import hmac
import json
import os
import re
import time
from pathlib import Path
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlsplit
from path_utils import is_relative_to
from core import PHP_TRIM_CHARS, php_int_cast
from cryptography.hazmat.primitives.serialization import load_pem_public_key
HOSTS = {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}
FEDERATION_HOSTS = ('2415.jp', 'backup.2415.jp', 'main.2415.jp')
TOKEN_RE = re.compile('^[A-Za-z0-9_-]{43}$')
DEFAULTS = {'credentials': {}, 'revoked_credentials': {}, 'sso_sessions': {}}

@legacy_compatible(callback_index=0, request_index=None)
def _json(status, value):
    body = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
    _http_status, _http_headers = (status, [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

def _valid_id(value):
    if not isinstance(value, str) or not value or len(value) > 2048:
        return False
    if not re.fullmatch('(?:[A-Za-z0-9_-]+|[A-Za-z0-9+/]+={0,2})', value):
        return False
    try:
        import base64
        return bool(base64.urlsafe_b64decode(value.rstrip('=') + '=' * (-len(value.rstrip('=')) % 4)))
    except Exception:
        return False

def _clean_credentials(rows):
    valid, skipped = ({}, 0)
    if isinstance(rows, dict):
        entries = rows.items()
    elif isinstance(rows, list):
        entries = enumerate(rows)
    else:
        return (valid, 1)
    for key, row in entries:
        pem = row.get('pem', row.get('public_key_pem')) if isinstance(row, dict) else None
        if not _valid_id(key) or not isinstance(pem, str) or (not pem.strip()):
            skipped += 1
            continue
        try:
            load_pem_public_key(pem.encode())
        except Exception:
            skipped += 1
            continue
        item = dict(row, id=key, pem=pem)
        if not isinstance(item.get('label'), str) or not item['label'].strip(PHP_TRIM_CHARS):
            item['label'] = 'パスキー'
        valid[key] = item
    return (valid, skipped)

def _store_path():
    private = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not private:
        raise RuntimeError('private_runtime_directory_required')
    root = Path(private).expanduser().resolve()
    webroot = Path(os.environ.get('DOCUMENT_ROOT', Path(__file__).resolve().parent)).resolve()
    if root == webroot or is_relative_to(root, webroot):
        raise RuntimeError('private_runtime_directory_inside_webroot')
    runtime = root / 'runtime'
    runtime.mkdir(mode=448, parents=True, exist_ok=True)
    runtime.chmod(448)
    return runtime / 'passkey-store.json'

def _read_store(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value, dict):
            raise ValueError()
    except FileNotFoundError:
        value = {}
    for key in DEFAULTS:
        if not isinstance(value.get(key), dict):
            value[key] = {}
    creds, _ = _clean_credentials(value['credentials'])
    value['credentials'] = creds
    return value

class _NoRedirect(HTTPRedirectHandler):

    def redirect_request(self, request, response, code, message, headers, new_url):
        return None

def _migration_base_path():
    configured = os.environ.get('PYTHON_MIGRATION_PUBLIC_BASE_URL', 'https://2415.jp/license/python-migration')
    path = urlsplit(configured).path.rstrip('/')
    return path or '/license/python-migration'

def _federation_request(host, payload):
    url = 'https://' + host + _migration_base_path() + '/ha/passkey-federation.php'
    request = Request(url, data=json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8'), headers={'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'TutiLicenseHA/1.0 (+https://2415.jp)', 'Connection': 'close'}, method='POST')
    try:
        response = build_opener(_NoRedirect()).open(request, timeout=12)
        with response:
            status = int(response.getcode())
            raw = response.read(1048577)
    except Exception as error:
        return (None, {'transport': type(error).__name__})
    if len(raw) > 1048576:
        return (None, {'response_error': 'response_too_large', 'http_status': status})
    try:
        result = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        result = None
    if status != 200 or not isinstance(result, dict) or result.get('ok') is not True:
        error = result.get('error') if isinstance(result, dict) else None
        diagnostic = {'http_status': status}
        if isinstance(error, str) and re.fullmatch('[a-z0-9_]{1,64}', error):
            diagnostic['response_error'] = error
        else:
            diagnostic['response_error'] = 'invalid_response'
        return (None, diagnostic)
    return (result, {})

def _merge_replica_state(local, remote):
    """Mirror PHP pkf_merge_state() for local credentials and remote replicas."""
    local = copy.deepcopy(local if isinstance(local, dict) else {})
    remote = remote if isinstance(remote, dict) else {}
    for key in ('credentials', 'revoked_credentials', 'sso_sessions'):
        if not isinstance(local.get(key), dict):
            local[key] = {}
        if not isinstance(remote.get(key), dict):
            remote[key] = {}
    local['credentials'], _ = _clean_credentials(local['credentials'])
    local['sso_sessions'] = {key: row for key, row in local['sso_sessions'].items() if isinstance(row, dict)}
    for key in list(local['revoked_credentials']):
        key = str(key)
        local['credentials'].pop(key, None)
        digest = hashlib.sha256(key.encode()).hexdigest()
        local['sso_sessions'] = {sid: row for sid, row in local['sso_sessions'].items() if not hmac.compare_digest(digest, str(row.get('credential_id_hash', '')))}
    for key, stamp in remote['revoked_credentials'].items():
        key = str(key)
        if not _valid_id(key):
            continue
        previous = local['revoked_credentials'].get(key, 0)
        local['revoked_credentials'][key] = max(php_int_cast(previous), php_int_cast(stamp))
        local['credentials'].pop(key, None)
        digest = hashlib.sha256(key.encode()).hexdigest()
        local['sso_sessions'] = {sid: row for sid, row in local['sso_sessions'].items() if not hmac.compare_digest(digest, str(row.get('credential_id_hash', '')))}
    credentials, _ = _clean_credentials(remote['credentials'])
    for key, item in credentials.items():
        if key in local['revoked_credentials']:
            continue
        item = copy.deepcopy(item)
        old = local['credentials'].get(key)
        if isinstance(old, dict):
            item['count'] = max(php_int_cast(old.get('count') or 0), php_int_cast(item.get('count') or 0))
            item['last_used'] = max(str(old.get('last_used') or ''), str(item.get('last_used') or '')) or None
            if php_int_cast(old.get('updated_at') or 0) > php_int_cast(item.get('updated_at') or 0):
                item['label'] = old.get('label', item.get('label', 'パスキー'))
            item['created'] = old.get('created', item.get('created') or '')
        local['credentials'][key] = item
    return local

def _write_replica_state(incoming):
    path = _store_path()
    lock_path = path.with_name('passkey-store.lock')
    with open(lock_path, 'a+b') as lock:
        os.chmod(lock_path, 384)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        current = _read_store(path)
        merged = _merge_replica_state(current, incoming)
        tmp = path.with_name(path.name + '.federation.tmp')
        with open(tmp, 'w', encoding='utf-8') as output:
            os.fchmod(output.fileno(), 384)
            json.dump(merged, output, ensure_ascii=False, separators=(',', ':'))
            output.write('\n')
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    return merged

def push_passkey_store(cookie_token, store, request_host=''):
    """Federate a changed passkey store using the endpoint-specific PHP contract."""
    failed_all = list(FEDERATION_HOSTS)
    try:
        cookie_token = str(cookie_token)
        if not re.fullmatch('[A-Za-z0-9_-]+', cookie_token):
            raise ValueError('invalid_cookie')
        raw = base64.urlsafe_b64decode(cookie_token + '=' * (-len(cookie_token) % 4))
        cookie = json.loads(raw.decode('utf-8'))
    except Exception:
        return {'ok': False, 'synced': [], 'failed': failed_all}
    if not isinstance(cookie, dict):
        return {'ok': False, 'synced': [], 'failed': failed_all}
    issuer_value = cookie.get('issuer', '')
    parsed_issuer = urlsplit(str(issuer_value) if '://' in str(issuer_value) else '//' + str(issuer_value))
    issuer = (parsed_issuer.hostname or '').lower()
    token = str(cookie.get('token', ''))
    if issuer not in HOSTS or not TOKEN_RE.fullmatch(token) or php_int_cast(cookie.get('expires', 0)) <= int(time.time()):
        return {'ok': False, 'synced': [], 'failed': failed_all}
    if not _identity(issuer, token, request_host):
        return {'ok': False, 'synced': [], 'failed': failed_all}
    self_host = str(request_host or '').lower()
    hosts = [host for host in FEDERATION_HOSTS if host != self_host]
    merged = _merge_replica_state(store, {})
    failed, synced, errors = ({}, {}, {})
    skipped_credentials = 0

    def exchange(state):
        nonlocal skipped_credentials
        credentials, skipped = _clean_credentials(state.get('credentials', {}))
        skipped_credentials = max(skipped_credentials, skipped)
        responses = []
        for host in hosts:
            payload = {'action': 'sync', 'issuer': issuer, 'sso_token': token, 'credentials': credentials, 'revoked_credentials': state.get('revoked_credentials', {})}
            result, diagnostic = _federation_request(host, payload)
            if result is None:
                synced.pop(host, None)
                failed[host] = host
                errors[host] = diagnostic
            else:
                failed.pop(host, None)
                errors.pop(host, None)
                synced[host] = host
                responses.append(result)
        return responses
    before = json.dumps({'credentials': merged['credentials'], 'revoked_credentials': merged['revoked_credentials']}, ensure_ascii=False, separators=(',', ':'))
    responses = exchange(merged)
    for response in responses:
        merged = _merge_replica_state(merged, response)
    merged = _write_replica_state(merged)
    after = json.dumps({'credentials': merged['credentials'], 'revoked_credentials': merged['revoked_credentials']}, ensure_ascii=False, separators=(',', ':'))
    if after != before:
        for response in exchange(merged):
            merged = _merge_replica_state(merged, response)
        merged = _write_replica_state(merged)
    if skipped_credentials:
        try:
            from ha_handlers import _append_ha_audit
            _append_ha_audit('passkey_federation_invalid_rows_skipped', {'count': skipped_credentials})
        except Exception:
            pass
    failed_hosts = list(failed.values())
    return {'ok': not failed_hosts, 'synced': list(synced.values()), 'failed': failed_hosts, 'errors': errors, 'skipped_credentials': skipped_credentials}

def _remote_identity(issuer, token):
    """Ask the issuing host to introspect a cross-host Passkey session."""
    url = 'https://' + issuer + _migration_base_path() + '/ha/passkey_api.php?action=sso_introspect'
    body = json.dumps({'action': 'sso_introspect', 'token': token}, separators=(',', ':')).encode('utf-8')
    request = Request(url, data=body, headers={'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': 'TutiLicenseHA/1.0 (+https://2415.jp)', 'Connection': 'close'}, method='POST')
    try:
        response = build_opener(_NoRedirect()).open(request, timeout=12)
        with response:
            if response.getcode() != 200:
                return None
            raw = response.read(1048577)
        if len(raw) > 1048576:
            return None
        result = json.loads(raw.decode('utf-8'))
    except Exception:
        return None
    if not isinstance(result, dict) or result.get('ok') is not True:
        return None
    role = str(result.get('role_name', ''))
    try:
        created = int(result.get('created_at', 0))
    except (TypeError, ValueError, OverflowError):
        return None
    now = int(time.time())
    if role not in {'security-admin', 'ha-admin'} or created < now - 300 or created > now + 30:
        return None
    return result

def _identity(issuer, token, request_host=''):
    if issuer not in HOSTS or not TOKEN_RE.fullmatch(token):
        return None
    host = str(request_host).lower()
    if host and host != issuer:
        return _remote_identity(issuer, token)
    try:
        path = _store_path()
        store = _read_store(path)
        row = store['sso_sessions'].get(token)
        if not isinstance(row, dict):
            return None
        now = int(time.time())
        created = int(row.get('created', 0))
        absolute = int(row.get('absolute_expires', created + 43200))
        credential_hash = str(row.get('credential_id_hash', ''))
        if created < now - 300 or created > now + 30 or int(row.get('expires', 0)) <= now or (absolute <= now) or (not re.fullmatch('[a-f0-9]{64}', credential_hash)):
            return None
        if not any((hmac.compare_digest(credential_hash, hashlib.sha256(key.encode()).hexdigest()) and key not in store['revoked_credentials'] for key in store['credentials'])):
            return None
        from database import connect
        db = connect()
        try:
            with db.cursor() as cursor:
                cursor.execute("SELECT role_name FROM admin_principals WHERE credential_id_hash=%s AND status='active' AND revoked_at IS NULL LIMIT 1", (credential_hash,))
                principal = cursor.fetchone()
        finally:
            db.close()
    except Exception:
        return None
    if not principal or principal.get('role_name') not in {'security-admin', 'ha-admin'}:
        return None
    return {'ok': True, 'credential_id_hash': credential_hash, 'role_name': principal['role_name'], 'created_at': created, 'expires_at': min(int(row.get('expires', 0)), absolute)}

def _merge_credential(store, key, row):
    clean, skipped = _clean_credentials({key: row})
    if key not in clean:
        return False
    if int(store['revoked_credentials'].get(key, 0)) > 0:
        return True
    item = clean[key]
    old = store['credentials'].get(key)
    if isinstance(old, dict):
        item['count'] = max(php_int_cast(old.get('count') or 0), php_int_cast(item.get('count') or 0))
        item['last_used'] = max(str(old.get('last_used') or ''), str(item.get('last_used') or '')) or None
        if php_int_cast(old.get('updated_at') or 0) > php_int_cast(item.get('updated_at') or 0):
            item['label'] = old.get('label', item['label'])
        item['created'] = old.get('created', item.get('created'))
    updated_at = item.get('updated_at')
    item['updated_at'] = max(1, php_int_cast(time.time() if updated_at is None else updated_at))
    store['credentials'][key] = item
    return True

def _revoke(store, key, timestamp=None):
    previous = php_int_cast(store['revoked_credentials'].get(key) or 0)
    value = php_int_cast(time.time() if timestamp is None else timestamp)
    store['revoked_credentials'][key] = max(1, previous, value)
    store['credentials'].pop(key, None)
    digest = hashlib.sha256(key.encode()).hexdigest()
    store['sso_sessions'] = {token: row for token, row in store['sso_sessions'].items() if not isinstance(row, dict) or not hmac.compare_digest(digest, str(row.get('credential_id_hash', '')))}

@legacy_compatible(callback_index=1, request_index=0)
def passkey_federation(request_context):
    if request_context.get('method', '') != 'POST':
        return _json('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
    try:
        raw = request_context['body_stream'].read(1048577)
        if len(raw) > 1048576:
            return _json('413 Payload Too Large', {'ok': False, 'error': 'payload_too_large'})
        data = json.loads(raw.decode('utf-8'), parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('invalid_json')))
    except (ValueError, UnicodeDecodeError, KeyError):
        return _json('400 Bad Request', {'ok': False, 'error': 'invalid_json'})
    if isinstance(data, list):
        return _json('400 Bad Request', {'ok': False, 'error': 'invalid_action'})
    if not isinstance(data, dict):
        return _json('400 Bad Request', {'ok': False, 'error': 'invalid_json'})
    action, issuer, token = (str(data.get('action', '')), str(data.get('issuer', '')), str(data.get('sso_token', '')))
    if action not in {'upsert', 'revoke', 'sync'}:
        return _json('400 Bad Request', {'ok': False, 'error': 'invalid_action'})
    try:
        if not _identity(issuer, token, request_context.get('header:host', '')):
            return _json('401 Unauthorized', {'ok': False, 'error': 'recent_security_admin_passkey_required'})
        credentials = data.get('credentials')
        revoked_credentials = data.get('revoked_credentials')
        if credentials is None:
            credentials = []
        if revoked_credentials is None:
            revoked_credentials = []
        if action == 'sync' and (not isinstance(credentials, (dict, list)) or len(credentials) > 100 or (not isinstance(revoked_credentials, (dict, list))) or (len(revoked_credentials) > 500)):
            return _json('400 Bad Request', {'ok': False, 'error': 'invalid_sync_state'})
        path = _store_path()
        lock_path = path.with_name('passkey-store.lock')
        with open(lock_path, 'a+') as lock:
            os.chmod(lock_path, 384)
            fcntl.flock(lock, fcntl.LOCK_EX)
            store = _read_store(path)
            skipped = 0
            if action == 'sync':
                revoked = revoked_credentials.items() if isinstance(revoked_credentials, dict) else enumerate(revoked_credentials)
                for key, stamp in revoked:
                    key = str(key)
                    if not _valid_id(key):
                        skipped += 1
                    else:
                        _revoke(store, key, stamp)
                incoming = credentials.items() if isinstance(credentials, dict) else enumerate(credentials)
                for key, row in incoming:
                    key = str(key)
                    skipped += int(not _merge_credential(store, key, row))
            elif action == 'revoke':
                key = str(data.get('id', ''))
                if not _valid_id(key):
                    return _json('400 Bad Request', {'ok': False, 'error': 'invalid_credential_id'})
                _revoke(store, key)
            else:
                key = str(data.get('id', ''))
                if not _merge_credential(store, key, data.get('credential')):
                    return _json('400 Bad Request', {'ok': False, 'error': 'invalid_credential'})
            tmp = path.with_name(path.name + '.tmp')
            with open(tmp, 'w', encoding='utf-8') as output:
                os.fchmod(output.fileno(), 384)
                json.dump(store, output, ensure_ascii=False, separators=(',', ':'))
                output.write('\n')
                output.flush()
                os.fsync(output.fileno())
            os.replace(tmp, path)
            fcntl.flock(lock, fcntl.LOCK_UN)
        try:
            from ha_handlers import _append_ha_audit
            if skipped:
                _append_ha_audit('passkey_federation_invalid_rows_skipped', {'count': skipped})
            _append_ha_audit('passkey_federation_' + action, {'source': issuer, 'credential_count': len(store['credentials']), 'skipped_rows': skipped})
        except Exception:
            pass
        return _json('200 OK', {'ok': True, 'action': action, 'credential_count': len(store['credentials']), 'skipped_rows': skipped, 'credentials': store['credentials'], 'revoked_credentials': store['revoked_credentials']})
    except Exception:
        return _json('503 Service Unavailable', {'ok': False, 'error': 'federation_apply_failed'})
