"""Python implementation of the isolated HA WebAuthn API.

The passkey store and its lock live under PYTHON_MIGRATION_PRIVATE_DIR. The
format is JSON so the Python HA snapshot/import code can carry it safely.
"""
from native_http import make_response, add_headers, legacy_compatible
import base64
from file_locking import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import struct
import time
from email.parser import BytesParser
from email.policy import default as default_email_policy
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote
from path_utils import is_relative_to
from http_utils import php_parse_query as parse_qs, read_bounded_body, RequestError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
RP_ID = '2415.jp'
ORIGINS = {'https://2415.jp', 'https://backup.2415.jp', 'https://main.2415.jp'}
DEFAULTS = {'credentials': {}, 'challenges': {}, 'tickets': {}, 'codes': {}, 'sessions': {}, 'sso_sessions': {}, 'recovery_codes': [], 'recovery_attempts': {}, 'revoked_credentials': {}}
MAX_PASSKEY_BODY_BYTES = 1024 * 1024
MAX_STORE_BYTES = 8 * 1024 * 1024
STORE_CAPS = {'credentials': 100, 'challenges': 2048, 'tickets': 2048, 'codes': 2048, 'sessions': 4096, 'sso_sessions': 4096, 'recovery_attempts': 4096, 'revoked_credentials': 10000, 'recovery_codes': 8}
PUBLIC_ERRORS = {'attested_data_missing', 'cannot_revoke_last_passkey', 'cbor_bounds', 'cbor_length', 'challenge_expired', 'client_data_mismatch', 'client_data_too_large', 'code_client_mismatch', 'credential_limit_reached', 'credential_not_found', 'desktop_ticket_expired', 'invalid_app_challenge', 'invalid_app_verifier', 'invalid_assertion', 'invalid_attestation', 'invalid_client_data', 'invalid_code', 'invalid_desktop_ticket', 'invalid_enrollment_ticket', 'invalid_key', 'invalid_recovery_code', 'passkey_not_registered', 'recovery_locked', 'rp_id_mismatch', 'sign_count_invalid', 'signature_invalid', 'store_capacity_reached', 'unsupported_cbor', 'unsupported_key', 'user_verification_required'}

def _b64e(value):
    return base64.urlsafe_b64encode(value).decode('ascii').rstrip('=')

def _b64d(value):
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_+/-]*={0,2}', value):
        return None
    try:
        standard = value.translate(str.maketrans('-_', '+/'))
        return base64.b64decode(standard + '=' * (-len(standard) % 4), validate=True)
    except Exception:
        return None

def _private_dir():
    raw = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not raw:
        raise RuntimeError('private_runtime_directory_required')
    root = Path(raw).expanduser().resolve()
    docroot = Path(os.environ.get('DOCUMENT_ROOT', Path(__file__).resolve().parent)).resolve()
    if root == docroot or is_relative_to(root, docroot):
        raise RuntimeError('private_runtime_directory_inside_webroot')
    path = root / 'runtime'
    # A pre-existing symlink could redirect credentials and recovery material
    # outside the configured private directory.
    if path.is_symlink():
        raise RuntimeError('unsafe_private_runtime_directory')
    path.mkdir(mode=448, parents=True, exist_ok=True)
    resolved = path.resolve(strict=True)
    if resolved != path or not is_relative_to(resolved, root):
        raise RuntimeError('unsafe_private_runtime_directory')
    try:
        path.chmod(448)
    except OSError:
        pass
    return path

def _entry_not_expired(row, now):
    if not isinstance(row, dict):
        return False
    try:
        return int(row.get('expires', 0)) >= now
    except (TypeError, ValueError, OverflowError):
        return False

def _store_path():
    return _private_dir() / 'passkey-store.json'

def _read_store(path):
    try:
        if path.is_symlink() or path.stat().st_size > MAX_STORE_BYTES:
            raise RuntimeError('passkey_store_invalid')
        store = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(store, dict):
            raise RuntimeError('passkey_store_invalid')
    except FileNotFoundError:
        return {key: value.copy() if isinstance(value, (dict, list)) else value for key, value in DEFAULTS.items()}
    except (OSError, ValueError):
        raise RuntimeError('passkey_store_invalid')
    for key, value in DEFAULTS.items():
        store.setdefault(key, value.copy() if isinstance(value, (dict, list)) else value)
    now = int(time.time())
    for group in ('challenges', 'tickets', 'codes', 'sessions', 'sso_sessions'):
        rows = store.get(group)
        if not isinstance(rows, dict):
            raise RuntimeError('passkey_store_invalid')
        store[group] = {key: row for key, row in rows.items() if _entry_not_expired(row, now)}
    attempts = store.get('recovery_attempts')
    if not isinstance(attempts, dict):
        raise RuntimeError('passkey_store_invalid')
    recent_attempts = {}
    for key, row in attempts.items():
        if not isinstance(row, dict):
            continue
        try:
            until = int(row.get('until', 0))
            updated_at = int(row.get('updated_at', 0))
        except (TypeError, ValueError, OverflowError):
            continue
        if until > now or (not until and (not updated_at or updated_at > now - 900)):
            recent_attempts[key] = row
    store['recovery_attempts'] = recent_attempts
    expected_shapes = {
        'credentials': dict, 'challenges': dict, 'tickets': dict, 'codes': dict,
        'sessions': dict, 'sso_sessions': dict, 'recovery_attempts': dict,
        'revoked_credentials': dict, 'recovery_codes': list,
    }
    for group, maximum in STORE_CAPS.items():
        rows = store.get(group)
        if not isinstance(rows, expected_shapes[group]) or len(rows) > maximum:
            raise RuntimeError('passkey_store_invalid')
    return store

def _write_store(path, store):
    now = int(time.time())
    for group in ('challenges', 'tickets', 'codes', 'sessions', 'sso_sessions'):
        rows = store.get(group, {})
        if isinstance(rows, dict):
            store[group] = {key: row for key, row in rows.items() if _entry_not_expired(row, now)}
    for group, maximum in STORE_CAPS.items():
        rows = store.get(group)
        expected_type = list if group == 'recovery_codes' else dict
        if not isinstance(rows, expected_type) or len(rows) > maximum:
            raise RuntimeError('store_capacity_reached')
    temp = path.with_name(path.name + '.tmp.' + secrets.token_hex(8))
    payload = (json.dumps(store, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
    if len(payload) > MAX_STORE_BYTES:
        raise RuntimeError('store_capacity_reached')
    try:
        fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
        try:
            directory_fd = os.open(str(path.parent), os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass

def _key(purpose):
    token = os.environ.get('PYTHON_MIGRATION_HA_SYNC_TOKEN', '')
    if not token:
        from migration_config import secret_value
        token = secret_value('ha_sync_token')
    if not token:
        raise RuntimeError('passkey_configuration_unavailable')
    return hmac.new(token.encode(), ('tuti-license-ha/' + purpose).encode(), hashlib.sha256).digest()

def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

@legacy_compatible(callback_index=0, request_index=None)
def _json(status, payload):
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode()
    _http_status, _http_headers = (status, [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=None, request_index=0)
def _body(request_context):
    raw = read_bounded_body(request_context, MAX_PASSKEY_BODY_BYTES)
    try:
        value = json.loads(raw.decode('utf-8')) if raw else {}
        if isinstance(value, (dict, list)):
            return value if isinstance(value, dict) else {}
    except (ValueError, UnicodeDecodeError):
        pass
    content_type_header = str(request_context.get('content_type') or request_context.get('header:content-type') or '')
    content_type = content_type_header.lower()
    if content_type.startswith('application/x-www-form-urlencoded'):
        try:
            decoded = raw.decode('utf-8')
        except UnicodeDecodeError:
            return {}
        fields = {}
        for key, values in parse_qs(decoded, keep_blank_values=True).items():
            key = key.replace(' ', '_').replace('.', '_')
            match = re.match('^([^\\[\\]]+)\\[', key)
            fields[match.group(1) if match else key] = 'Array' if match else values[-1] if values else ''
        return fields
    if content_type.startswith('multipart/form-data'):
        try:
            headers = ('Content-Type: ' + content_type_header + '\r\nMIME-Version: 1.0\r\n\r\n').encode('ascii')
            message = BytesParser(policy=default_email_policy).parsebytes(headers + raw)
            fields = {}
            for part in message.iter_parts():
                if part.get_content_disposition() != 'form-data':
                    continue
                name = part.get_param('name', header='content-disposition')
                if not isinstance(name, str) or part.get_filename() is not None:
                    continue
                payload = part.get_payload(decode=True) or b''
                charset = part.get_content_charset() or 'utf-8'
                name = name.replace(' ', '_').replace('.', '_')
                match = re.match('^([^\\[\\]]+)\\[', name)
                fields[match.group(1) if match else name] = 'Array' if match else payload.decode(charset)
            return fields
        except Exception:
            return {}
    return {}

@legacy_compatible(callback_index=None, request_index=0)
def _query(request_context):
    return {key: values[-1] for key, values in parse_qs(request_context.get('query', ''), keep_blank_values=True).items()}

@legacy_compatible(callback_index=None, request_index=0)
def _audit(request_context, event, context=None):
    try:
        from audit import append_event
        append_event(event, context or {}, ip_address=request_context.get('client_address', ''), path=_private_dir() / 'audit.log', role='ha-admin')
    except Exception:
        pass

@legacy_compatible(callback_index=None, request_index=0)
def _sync(request_context):
    try:
        from ha_handlers import ha_sync_peer
        return bool(ha_sync_peer('passkey_change', request_context).get('ok'))
    except Exception:
        return False

@legacy_compatible(callback_index=None, request_index=0)
def _authorize(request_context, scope='passkey:manage'):
    from ha_handlers import _ha_authorized_scope
    return _ha_authorized_scope(request_context, scope)

def _input_client(data, expected_type, challenge):
    raw = _b64d(data.get('clientDataJSON', ''))
    if raw is None:
        raise RuntimeError('invalid_client_data')
    if len(raw) > 16384:
        raise RuntimeError('client_data_too_large')
    try:
        value = json.loads(raw.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError('invalid_client_data')
    if not isinstance(value, dict) or value.get('crossOrigin', False) is not False or value.get('type') != expected_type or (value.get('challenge') != challenge) or (value.get('origin') not in ORIGINS):
        raise RuntimeError('client_data_mismatch')
    return raw

def _cbor(data, pos=0, depth=0):
    if depth > 12 or pos >= len(data) or len(data) > 65536:
        raise RuntimeError('cbor_bounds')
    initial = data[pos]
    pos += 1
    major, add = (initial >> 5, initial & 31)
    if add < 24:
        size = add
    else:
        count = {24: 1, 25: 2, 26: 4, 27: 8}.get(add)
        if count is None or pos + count > len(data):
            raise RuntimeError('cbor_length')
        size = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    if size > 65536:
        raise RuntimeError('cbor_bounds')
    if major == 0:
        return (size, pos)
    if major == 1:
        return (-1 - size, pos)
    if major in (2, 3):
        if pos + size > len(data):
            raise RuntimeError('cbor_bounds')
        raw = data[pos:pos + size]
        return (raw if major == 2 else raw.decode('utf-8'), pos + size)
    if major == 4:
        result = []
        for _ in range(size):
            value, pos = _cbor(data, pos, depth + 1)
            result.append(value)
        return (result, pos)
    if major == 5:
        result = {}
        for _ in range(size):
            key, pos = _cbor(data, pos, depth + 1)
            value, pos = _cbor(data, pos, depth + 1)
            result[key] = value
        return (result, pos)
    raise RuntimeError('unsupported_cbor')

def _authenticator_data(raw, registration):
    if len(raw) < 37 or not hmac.compare_digest(hashlib.sha256(RP_ID.encode()).digest(), raw[:32]):
        raise RuntimeError('rp_id_mismatch')
    flags = raw[32]
    if not flags & 1 or not flags & 4:
        raise RuntimeError('user_verification_required')
    count = struct.unpack('>I', raw[33:37])[0]
    result = {'flags': flags, 'count': count}
    if registration:
        if not flags & 64:
            raise RuntimeError('attested_data_missing')
        if len(raw) < 55:
            raise RuntimeError('invalid_attestation')
        length = struct.unpack('>H', raw[53:55])[0]
        pos = 55
        if pos + length > len(raw):
            raise RuntimeError('invalid_attestation')
        credential_id = raw[pos:pos + length]
        cose, _ = _cbor(raw, pos + length)
        if not isinstance(cose, dict) or (cose.get(1), cose.get(3), cose.get(-1)) != (2, -7, 1):
            raise RuntimeError('unsupported_key')
        x, y = (cose.get(-2), cose.get(-3))
        if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or (len(y) != 32):
            raise RuntimeError('invalid_key')
        try:
            public_key = ec.EllipticCurvePublicNumbers(int.from_bytes(x, 'big'), int.from_bytes(y, 'big'), ec.SECP256R1()).public_key()
        except ValueError:
            raise RuntimeError('invalid_key')
        result.update({'id': credential_id, 'pem': public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()})
    return result

def _session(credential_hash=None, client='ha'):
    scopes = ['ha:operate', 'ha:promote', 'license:read', 'license:write', 'license:manage', 'phone:manage', 'admin:manage', 'offline:issue', 'passkey:manage'] if client == 'ha' else ['license:read', 'license:write', 'license:manage', 'phone:manage', 'admin:manage', 'offline:issue', 'passkey:manage']
    if client == 'desktop':
        scopes.append('tenant:api')
    expires = int(time.time()) + 300
    claims = {'purpose': 'ha_admin', 'scope': scopes, 'client': client, 'expires': expires, 'nonce': _b64e(secrets.token_bytes(16))}
    if isinstance(credential_hash, str) and re.fullmatch('[a-f0-9]{64}', credential_hash):
        claims['credential_id_hash'] = credential_hash
    else:
        claims['recovery_code_auth'] = True
    encoded = _b64e(json.dumps(claims, separators=(',', ':')).encode())
    signature = _b64e(hmac.new(_key('admin-session/v1'), encoded.encode(), hashlib.sha256).digest())
    return {'session_token': encoded + '.' + signature, 'authenticated_until': expires, 'scope': scopes}

@legacy_compatible(callback_index=None, request_index=0)
def _host(request_context):
    host = str(request_context.get('header:host', '')).lower()
    return host if host in {'2415.jp', 'backup.2415.jp', 'main.2415.jp'} else '2415.jp'

@legacy_compatible(callback_index=1, request_index=0)
def passkey_api(request_context):
    method = request_context.get('method', '')
    query = _query(request_context)
    action = str(query.get('action', ''))
    try:
        data = _body(request_context) if method == 'POST' else {}
    except RequestError as error:
        status = '413 Payload Too Large' if str(error) == 'request_too_large' else '400 Bad Request'
        return _json(status, {'ok': False, 'error': str(error)})
    if 'action' not in query:
        body_action = data.get('action', '')
        action = str('' if body_action is None else body_action)
    try:
        path = _store_path()
        lock_path = path.with_name('passkey-store.lock')
        with open(lock_path, 'a+b') as lock:
            os.chmod(lock_path, 384)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            store = _read_store(path)
            try:
                result = _dispatch(request_context, method, query, data, action, store, path)
                return _json(result[0], result[1])
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except Exception as error:
        request_id = secrets.token_hex(8)
        _audit(request_context, 'passkey_operation_failed', {'request_id': request_id, 'action': action})
        message = str(error)
        if message in {'passkey_store_invalid', 'store_capacity_reached'}:
            return _json('503 Service Unavailable', {'ok': False, 'error': message, 'request_id': request_id})
        if message == 'credential_limit_reached':
            return _json('409 Conflict', {'ok': False, 'error': message, 'request_id': request_id})
        return _json('400 Bad Request', {'ok': False, 'error': message if message in PUBLIC_ERRORS else 'passkey_operation_failed', 'request_id': request_id})

@legacy_compatible(callback_index=None, request_index=0)
def _dispatch(request_context, method, query, data, action, store, path):
    if action == 'bootstrap_status':
        return ('200 OK', {'ok': True, 'registered': bool(store['credentials']), 'credential_count': len(store['credentials']), 'rp_id': RP_ID, 'origin': 'https://' + _host(request_context)})
    if action in {'enroll', 'credentials', 'credential_rename', 'credential_revoke', 'recovery_generate'}:
        if not _authorize(request_context):
            return ('404 Not Found', {'ok': False, 'error': 'not_found'})
    if action == 'credentials':
        items = [{'id': key, 'label': value.get('label', 'パスキー'), 'created_at': value.get('created'), 'last_used_at': value.get('last_used'), 'sign_count': int(value.get('count', 0))} for key, value in store['credentials'].items()]
        return ('200 OK', {'ok': True, 'credentials': items, 'count': len(items), 'recovery_code_count': len(store['recovery_codes'])})
    if action == 'credential_rename':
        key = str(data.get('id', ''))
        if key not in store['credentials']:
            raise RuntimeError('credential_not_found')
        label = str(data.get('label', '')).strip()[:60] or 'パスキー'
        store['credentials'][key]['label'] = label
        _write_store(path, store)
        _audit(request_context, 'passkey_renamed', {'credential_id_hash': hashlib.sha256(key.encode()).hexdigest()})
        return ('200 OK', {'ok': True, 'peer_synced': _sync(request_context)})
    if action == 'credential_revoke':
        key = str(data.get('id', ''))
        if key not in store['credentials']:
            raise RuntimeError('credential_not_found')
        if len(store['credentials']) <= 1:
            raise RuntimeError('cannot_revoke_last_passkey')
        del store['credentials'][key]
        store['revoked_credentials'][key] = int(time.time())
        _write_store(path, store)
        _audit(request_context, 'passkey_revoked', {'credential_id_hash': hashlib.sha256(key.encode()).hexdigest()})
        return ('200 OK', {'ok': True, 'remaining': len(store['credentials']), 'peer_synced': _sync(request_context)})
    if action == 'recovery_generate':
        secret = _key('recovery-code/v1')
        codes = ['REC-' + _b64e(secrets.token_bytes(12))[:16].upper() for _ in range(8)]
        store['recovery_codes'] = [{'hash': hmac.new(secret, code.encode(), hashlib.sha256).hexdigest(), 'created': _now_iso(), 'version': 1} for code in codes]
        _write_store(path, store)
        _audit(request_context, 'recovery_codes_generated', {'count': len(codes)})
        return ('200 OK', {'ok': True, 'codes': codes, 'count': len(codes), 'peer_synced': _sync(request_context)})
    if action == 'recovery_verify':
        code = str(data.get('code', '')).strip().upper()
        ip = hashlib.sha256(str(request_context.get('client_address', '')).encode()).hexdigest()
        attempt = store['recovery_attempts'].get(ip, {'count': 0, 'until': 0})
        if int(attempt.get('until', 0)) > int(time.time()):
            raise RuntimeError('recovery_locked')
        secret = _key('recovery-code/v1')
        from migration_config import secret_value
        legacy_secret = secret_value('ha_sync_token').encode()
        found = None
        for index, row in enumerate(store['recovery_codes']):
            row_secret = secret if int(row.get('version', 0)) == 1 else legacy_secret
            candidate = hmac.new(row_secret, code.encode(), hashlib.sha256).hexdigest()
            if hmac.compare_digest(str(row.get('hash', '')), candidate):
                found = index
                break
        if found is None:
            attempt['count'] = int(attempt.get('count', 0)) + 1
            attempt['updated_at'] = int(time.time())
            if attempt['count'] >= 5:
                attempt = {'count': 0, 'until': int(time.time()) + 900}
            store['recovery_attempts'][ip] = attempt
            _write_store(path, store)
            _audit(request_context, 'recovery_code_failed')
            raise RuntimeError('invalid_recovery_code')
        store['recovery_codes'].pop(found)
        store['recovery_attempts'].pop(ip, None)
        session = _session()
        _write_store(path, store)
        _audit(request_context, 'recovery_code_used', {'remaining': len(store['recovery_codes'])})
        return ('200 OK', {'ok': True, 'remaining': len(store['recovery_codes']), 'peer_synced': _sync(request_context), **session})
    if action == 'enroll':
        payload = str(data.get('app_challenge', '')).strip().lower()
        if payload and (len(payload) != 64 or any((c not in '0123456789abcdef' for c in payload))):
            raise RuntimeError('invalid_app_challenge')
        ticket = _b64e(secrets.token_bytes(24))
        store['tickets'][ticket] = {'expires': int(time.time()) + 300, 'label': str(data.get('label', '')).strip()[:60] or 'パスキー', 'app_challenge': payload}
        _write_store(path, store)
        client = 'desktop_register' if query.get('client') == 'desktop' else 'ha'
        return ('200 OK', {'ok': True, 'url': f'https://{_host(request_context)}/license/ha/passkey.php?mode=register&ticket={quote(ticket)}&client={client}'})
    if action == 'revoke':
        return ('410 Gone', {'ok': False, 'error': 'bulk_passkey_revoke_removed'})
    if action == 'desktop_start':
        if not store['credentials']:
            raise RuntimeError('passkey_not_registered')
        ticket, poll = (_b64e(secrets.token_bytes(24)), _b64e(secrets.token_bytes(32)))
        store['tickets'][ticket] = {'kind': 'desktop_auth', 'poll_hash': hashlib.sha256(poll.encode()).hexdigest(), 'expires': int(time.time()) + 300}
        _write_store(path, store)
        url = f'https://{_host(request_context)}/license/ha/passkey.php?mode=authenticate&client=desktop&ticket={quote(ticket)}'
        return ('200 OK', {'ok': True, 'ticket': ticket, 'poll_token': poll, 'expires_in': 300, 'url': url})
    if action == 'desktop_poll':
        ticket, poll = (str(data.get('ticket', '')), str(data.get('poll_token', '')))
        row = store['tickets'].get(ticket)
        if not row or row.get('kind') != 'desktop_auth' or int(row.get('expires', 0)) < int(time.time()) or (not hmac.compare_digest(str(row.get('poll_hash', '')), hashlib.sha256(poll.encode()).hexdigest())):
            raise RuntimeError('invalid_desktop_ticket')
        if not row.get('code'):
            return ('202 Accepted', {'ok': True, 'pending': True})
        code = row['code']
        del store['tickets'][ticket]
        _write_store(path, store)
        return ('200 OK', {'ok': True, 'pending': False, 'code': code})
    if action == 'begin':
        mode, ticket = (str(query.get('mode', 'authenticate')), str(query.get('ticket', '')))
        label = app_challenge = return_host = ''
        if mode == 'register':
            enrollment = store['tickets'].get(ticket)
            if not enrollment or int(enrollment.get('expires', 0)) < int(time.time()):
                raise RuntimeError('invalid_enrollment_ticket')
            label = enrollment.get('label', '')
            app_challenge = enrollment.get('app_challenge', '')
            return_host = enrollment.get('return_host', '')
            del store['tickets'][ticket]
        elif not store['credentials']:
            raise RuntimeError('passkey_not_registered')
        client = str(query.get('client', 'ha'))
        if client not in {'ha', 'keyadmin', 'desktop', 'desktop_register', 'admin_web', 'admin_mobile', 'generate_web'}:
            client = 'ha'
        if mode != 'register' and client in {'ha', 'keyadmin'}:
            app_challenge = str(query.get('app_challenge', '')).strip().lower()
            if app_challenge and (len(app_challenge) != 64 or any((c not in '0123456789abcdef' for c in app_challenge))):
                raise RuntimeError('invalid_app_challenge')
        if client == 'desktop':
            desktop = store['tickets'].get(ticket)
            if not desktop or desktop.get('kind') != 'desktop_auth' or int(desktop.get('expires', 0)) < int(time.time()):
                raise RuntimeError('invalid_desktop_ticket')
        local_host = _host(request_context)
        return_host = str(query.get('return_host', '')).lower() if mode != 'register' else return_host
        if client in {'admin_web', 'admin_mobile'} and return_host not in {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}:
            return_host = local_host
        request_id, challenge = (_b64e(secrets.token_bytes(18)), _b64e(secrets.token_bytes(32)))
        store['challenges'][request_id] = {'mode': mode, 'client': client, 'ticket': ticket if client == 'desktop' else None, 'label': label, 'challenge': challenge, 'app_challenge': app_challenge, 'return_host': return_host if client in {'admin_web', 'admin_mobile'} else None, 'expires': int(time.time()) + 900}
        _write_store(path, store)
        if mode == 'register':
            public_key = {'challenge': challenge, 'rp': {'id': RP_ID, 'name': '2415.jp License HA'}, 'user': {'id': _b64e(hashlib.sha256(b'license-ha-admin').digest()), 'name': 'license-admin@2415.jp', 'displayName': 'TUTI License Administrator'}, 'pubKeyCredParams': [{'type': 'public-key', 'alg': -7}], 'timeout': 300000, 'attestation': 'none', 'authenticatorSelection': {'residentKey': 'required', 'userVerification': 'required'}}
        else:
            public_key = {'challenge': challenge, 'rpId': RP_ID, 'timeout': 300000, 'userVerification': 'required'}
        return ('200 OK', {'ok': True, 'request_id': request_id, 'publicKey': public_key})
    if action == 'finish':
        request_id = str(data.get('request_id', ''))
        row = store['challenges'].get(request_id)
        if not row or int(row.get('expires', 0)) < int(time.time()):
            raise RuntimeError('challenge_expired')
        del store['challenges'][request_id]
        response = data.get('response') if isinstance(data.get('response'), dict) else {}
        if row.get('mode') == 'register':
            if len(store['credentials']) >= STORE_CAPS['credentials']:
                raise RuntimeError('credential_limit_reached')
            client_data = _input_client(response, 'webauthn.create', row['challenge'])
            attestation = _b64d(response.get('attestationObject', ''))
            if attestation is None:
                raise RuntimeError('invalid_attestation')
            obj, _ = _cbor(attestation)
            if not isinstance(obj, dict) or not isinstance(obj.get('authData'), bytes):
                raise RuntimeError('invalid_attestation')
            auth = _authenticator_data(obj['authData'], True)
            credential_id = _b64e(auth['id'])
            store['credentials'][credential_id] = {'id': credential_id, 'pem': auth['pem'], 'count': auth['count'], 'label': row.get('label') or 'パスキー', 'created': _now_iso(), 'last_used': None}
        else:
            client_data = _input_client(response, 'webauthn.get', row['challenge'])
            credential_id = str(data.get('id', ''))
            credential = store['credentials'].get(credential_id)
            if not credential:
                raise RuntimeError('credential_not_found')
            auth_raw, signature = (_b64d(response.get('authenticatorData', '')), _b64d(response.get('signature', '')))
            if auth_raw is None or signature is None:
                raise RuntimeError('invalid_assertion')
            auth = _authenticator_data(auth_raw, False)
            previous = int(credential.get('count', 0))
            if previous > 0 and auth['count'] > 0 and (auth['count'] <= previous):
                raise RuntimeError('sign_count_invalid')
            try:
                from cryptography.hazmat.primitives.serialization import load_pem_public_key
                load_pem_public_key(credential['pem'].encode()).verify(signature, auth_raw + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
            except Exception:
                raise RuntimeError('signature_invalid')
            store['credentials'][credential_id]['count'] = auth['count']
            store['credentials'][credential_id]['last_used'] = _now_iso()
        if row.get('client') == 'desktop_register':
            _write_store(path, store)
            return ('200 OK', {'ok': True, 'peer_synced': _sync(request_context), 'redirect': f'https://{_host(request_context)}/license/ha/passkey.php?complete=register'})
        code = _b64e(secrets.token_bytes(24))
        store['codes'][code] = {'expires': int(time.time()) + 120, 'client': row.get('client', 'ha'), 'credential_id_hash': hashlib.sha256(credential_id.encode()).hexdigest(), 'app_challenge': row.get('app_challenge', ''), 'return_host': row.get('return_host', '')}
        host = _host(request_context)
        client = row.get('client', 'ha')
        if client == 'desktop':
            desktop_ticket = store['tickets'].get(row.get('ticket'))
            if not desktop_ticket:
                raise RuntimeError('desktop_ticket_expired')
            desktop_ticket['code'] = code
            redirect = f'https://{host}/license/ha/passkey.php?complete=1'
        elif client in {'admin_web', 'admin_mobile'}:
            return_host = row.get('return_host') if row.get('return_host') in {'2415.jp', 'backup.2415.jp', 'main.2415.jp'} else '2415.jp'
            target = '/license/python-migration/admin_api.php' if client == 'admin_web' else '/license/python-migration/mobile-manager/admin-auth.php'
            redirect = f'https://{return_host}{target}?passkey_code={quote(code)}&return_host={quote(return_host)}'
        elif client == 'generate_web':
            redirect = f'https://{host}/license/python-migration/generate_key.php?passkey_code={quote(code)}'
        else:
            callback = 'passkey-keyadmin-callback.php' if client == 'keyadmin' else 'passkey-ha-callback.php'
            server = 'main' if str(request_context.get('header:host', '')).split(':', 1)[0] == 'main.2415.jp' else 'backup' if str(request_context.get('header:host', '')).startswith('backup.') else 'primary'
            redirect = f'https://{host}/license/ha/{callback}?code={quote(code)}&server={server}&client={quote(client)}'
        app_redirect = None
        if row.get('app_challenge') and client in {'keyadmin', 'ha'}:
            app_redirect = f"tuti-licensekeys://{('keyadmin' if client == 'keyadmin' else 'ha')}/passkey-callback?code={quote(code)}&server={('main' if str(request_context.get('header:host', '')).split(':', 1)[0] == 'main.2415.jp' else 'backup' if str(request_context.get('header:host', '')).startswith('backup.') else 'primary')}&client={client}"
        _write_store(path, store)
        return ('200 OK', {'ok': True, 'code': code, 'redirect': redirect, 'app_redirect': app_redirect})
    if action == 'verify_code':
        code, client = (str(data.get('code', '')), str(data.get('client', '')))
        row = store['codes'].get(code)
        if not row or int(row.get('expires', 0)) < int(time.time()):
            raise RuntimeError('invalid_code')
        if not hmac.compare_digest(str(row.get('client', '')), client):
            raise RuntimeError('code_client_mismatch')
        bound = str(row.get('app_challenge', ''))
        if bound:
            verifier = str(data.get('app_verifier', ''))
            if not verifier or not hmac.compare_digest(bound, hashlib.sha256(verifier.encode()).hexdigest()):
                raise RuntimeError('invalid_app_verifier')
        credential_hash = str(row.get('credential_id_hash', ''))
        del store['codes'][code]
        session = _session(credential_hash if len(credential_hash) == 64 else None, client)
        _write_store(path, store)
        return ('200 OK', {'ok': True, **session})
    if action == 'recover_app':
        client = str(data.get('client', ''))
        if client not in {'ha', 'keyadmin'}:
            raise RuntimeError('code_client_mismatch')
        verifier = str(data.get('app_verifier', ''))
        if not verifier:
            raise RuntimeError('invalid_app_verifier')
        challenge = hashlib.sha256(verifier.encode()).hexdigest()
        match = next(((key, row) for key, row in store['codes'].items() if int(row.get('expires', 0)) >= int(time.time()) and row.get('client') == client and row.get('app_challenge') and hmac.compare_digest(row['app_challenge'], challenge)), None)
        if not match:
            return ('202 Accepted', {'ok': True, 'pending': True})
        code, row = match
        del store['codes'][code]
        cred_hash = str(row.get('credential_id_hash', ''))
        result = {'ok': True, 'pending': False}
        if client == 'ha':
            expires = int(time.time()) + 30 * 86400
            jti = _b64e(secrets.token_bytes(18))
            claims = {'purpose': 'ha_auto_promote', 'aud': 'backup.2415.jp', 'scope': ['ha:promote'], 'jti': jti, 'expires': expires, 'nonce': _b64e(secrets.token_bytes(16))}
            encoded = _b64e(json.dumps(claims, separators=(',', ':')).encode())
            signature = _b64e(hmac.new(_key('automation/v1'), encoded.encode(), hashlib.sha256).digest())
            result.update({'automation_token': encoded + '.' + signature, 'automation_expires_at': expires})
            _audit(request_context, 'automation_credential_issued', {'jti': jti, 'client': client, 'expires': expires})
        result.update(_session(cred_hash if len(cred_hash) == 64 else None, client))
        _write_store(path, store)
        _audit(request_context, 'passkey_app_callback_recovered', {'client': client, 'credential_id_hash': cred_hash})
        return ('200 OK', result)
    if action in {'sso_introspect', 'sso_revoke'}:
        if method != 'POST':
            return ('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
        token = str(data.get('token', ''))
        row = store['sso_sessions'].get(token)
        if not re.fullmatch('[A-Za-z0-9_-]{43}', token) or not row:
            return ('401 Unauthorized', {'ok': False, 'error': 'sso_session_invalid'})
        absolute = int(row.get('absolute_expires', int(row.get('created', 0)) + 43200))
        if int(row.get('expires', 0)) < int(time.time()) or absolute <= int(time.time()):
            del store['sso_sessions'][token]
            _write_store(path, store)
            return ('401 Unauthorized', {'ok': False, 'error': 'sso_session_expired'})
        credential_hash = str(row.get('credential_id_hash', ''))
        if action == 'sso_revoke':
            del store['sso_sessions'][token]
            _write_store(path, store)
            _audit(request_context, 'admin_sso_revoked', {'credential_id_hash': credential_hash})
            return ('200 OK', {'ok': True})
        try:
            credential_present = any((hmac.compare_digest(credential_hash, hashlib.sha256(str(credential_id).encode()).hexdigest()) and str(credential_id) not in store['revoked_credentials'] for credential_id in store['credentials']))
            if not credential_present:
                del store['sso_sessions'][token]
                _write_store(path, store)
                return ('401 Unauthorized', {'ok': False, 'error': 'sso_credential_revoked'})
            from database import connect
            connection = connect()
            try:
                cursor = connection.cursor()
                cursor.execute("SELECT role_name FROM admin_principals WHERE credential_id_hash=%s AND status='active' AND revoked_at IS NULL LIMIT 1", (credential_hash,))
                principal = cursor.fetchone()
            finally:
                connection.close()
        except Exception as error:
            raise RuntimeError('passkey_operation_failed') from error
        role = principal.get('role_name') if principal else None
        if role not in {'viewer', 'operator', 'security-admin', 'ha-admin'}:
            del store['sso_sessions'][token]
            _write_store(path, store)
            return ('401 Unauthorized', {'ok': False, 'error': 'sso_principal_inactive'})
        expires = min(int(time.time()) + 1800, absolute)
        row.update({'role_name': role, 'expires': expires, 'absolute_expires': absolute})
        _write_store(path, store)
        return ('200 OK', {'ok': True, 'credential_id_hash': credential_hash, 'role_name': role, 'created_at': int(row.get('created', 0)), 'expires_at': expires})
    return ('400 Bad Request', {'ok': False, 'error': 'invalid_action'})
