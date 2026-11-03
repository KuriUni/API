"""Native Python implementation of the encrypted, rotating QR result protocol."""
from native_http import make_response, add_headers, legacy_compatible
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import time
from http import HTTPStatus
from file_locking import fcntl
from path_utils import is_relative_to
ROOT = Path(__file__).resolve().parent
HEADERS = [('Cache-Control', 'no-store, max-age=0'), ('Referrer-Policy', 'no-referrer'), ('X-Content-Type-Options', 'nosniff'), ('X-TUTI-QR-Revision', 'rotating-20261025'), ('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")]

@legacy_compatible(callback_index=0, request_index=None)
def _reply(code, data, extra=()):
    body = json.dumps(data, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    _http_status, _http_headers = (str(code) + ' ' + HTTPStatus(code).phrase, HEADERS + [('Content-Type', 'application/json; charset=utf-8'), ('Content-Length', str(len(body)))] + list(extra))
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=None, request_index=0)
def _store(request_context):
    private = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not private:
        raise OSError('private_storage_required')
    private = Path(private).expanduser().resolve()
    root = private / 'card-results'
    public = Path(request_context.get('document_root') or os.environ.get('DOCUMENT_ROOT') or ROOT / 'site').resolve()
    if root.is_symlink() or is_relative_to(root, public) or root == public:
        raise OSError('public_storage_forbidden')
    root.mkdir(mode=448, parents=True, exist_ok=True)
    return root

def _read(path):
    if path.is_symlink():
        raise OSError('unsafe_result_path')
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else None
    except (FileNotFoundError, ValueError):
        return None

def _write(path, row):
    if path.is_symlink():
        raise OSError('unsafe_result_path')
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(str(path), flags, 384)
    with os.fdopen(fd, 'w', encoding='utf-8') as output:
        os.fchmod(output.fileno(), 384)
        json.dump(row, output, separators=(',', ':'))

@legacy_compatible(callback_index=1, request_index=0)
def card_result(request_context):
    method = request_context.get('method', 'GET')
    if method == 'GET':
        body = (ROOT / 'card_result_page.html').read_bytes()
        _http_status, _http_headers = ('200 OK', HEADERS + [('Content-Type', 'text/html; charset=utf-8'), ('Content-Length', str(len(body)))])
        return make_response([body], _http_status, _http_headers)
    if method != 'POST':
        return _reply(405, {'ok': False}, [('Allow', 'GET, POST')])
    try:
        length = int(request_context.get('content_length') or 0)
    except (TypeError, ValueError):
        return _reply(400, {'ok': False})
    if length > 180000:
        return _reply(413, {'ok': False})
    if length < 0:
        return _reply(400, {'ok': False})
    stream = request_context.get('body_stream')
    raw = stream.read(length) if stream is not None and length else b''
    try:
        data = json.loads(raw.decode('utf-8'), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return _reply(400, {'ok': False})
    if not isinstance(data, dict) or data.get('action') not in ('create', 'read', 'revoke', 'rotate'):
        return _reply(400, {'ok': False})
    action = data['action']
    try:
        root = _store(request_context)
        lock_path = root / '.lock'
        if lock_path.is_symlink():
            raise OSError('unsafe_result_lock')
        with lock_path.open('a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                now = int(time.time())
                live = []
                for path in root.glob('*.json'):
                    row = _read(path)
                    if not row or int(row.get('expires', 0)) <= now:
                        path.unlink()
                    else:
                        live.append((path, row))
                if action == 'create':
                    if data.get('rotating') is not None and (not isinstance(data['rotating'], bool)):
                        return _reply(400, {'ok': False})
                    rotating = data.get('rotating') is True
                    iv, cipher = (data.get('iv', ''), data.get('cipher', ''))
                    if not isinstance(iv, str) or not isinstance(cipher, str) or len(iv) != 16 or (not 24 <= len(cipher) <= 175000) or (re.fullmatch('[A-Za-z0-9+/]+={0,2}', cipher) is None):
                        return _reply(400, {'ok': False})
                    try:
                        if len(base64.b64decode(iv, validate=True)) != 12:
                            raise ValueError()
                        base64.b64decode(cipher, validate=True)
                    except ValueError:
                        return _reply(400, {'ok': False})
                    ip = hashlib.sha256(str(request_context.get('client_address', 'unknown')).encode('utf-8')).hexdigest()
                    if len(live) >= 64 or sum((row.get('ip') == ip for _, row in live)) >= 3:
                        return _reply(429, {'ok': False, 'error': 'temporarily_busy'})
                    identifier = secrets.token_hex(16)
                    token = secrets.token_hex(24)
                    owner = secrets.token_hex(24)
                    row = {'expires': now + 180, 'token': hashlib.sha256(token.encode()).hexdigest(), 'owner': hashlib.sha256(owner.encode()).hexdigest(), 'ip': ip, 'iv': iv, 'cipher': cipher, 'rotating': rotating, 'token_expires': now + (8 if rotating else 180), 'last_rotate': now, 'version': 1}
                    _write(root / (identifier + '.json'), row)
                    return _reply(201, {'ok': True, 'id': identifier, 'token': token, 'owner': owner, 'expires_in': 180, 'rotating': rotating, 'token_valid_for': 8 if rotating else 180})
                identifier, token = (data.get('id', ''), data.get('token', ''))
                if not isinstance(identifier, str) or not isinstance(token, str) or re.fullmatch('[a-f0-9]{32}', identifier) is None or (re.fullmatch('[a-f0-9]{48}', token) is None):
                    return _reply(400, {'ok': False})
                path = root / (identifier + '.json')
                row = _read(path)
                missing = {'ok': False, 'error': 'expired_or_used'}
                if not row or row['expires'] <= now:
                    return _reply(404, missing)
                digest = hashlib.sha256(token.encode()).hexdigest()
                if action == 'read':
                    current = secrets.compare_digest(row['token'], digest) and int(row.get('token_expires', row['expires'])) > now
                    previous = secrets.compare_digest(row.get('previous_token', ''), digest) and int(row.get('previous_expires', 0)) > now
                    if not current and (not previous):
                        return _reply(404, missing)
                elif not secrets.compare_digest(row['owner'], digest):
                    return _reply(404, missing)
                if action == 'rotate':
                    if row.get('rotating') is not True:
                        return _reply(409, {'ok': False, 'error': 'not_rotating'})
                    if now - int(row['last_rotate']) < 2:
                        return _reply(429, {'ok': False, 'error': 'refresh_too_fast'})
                    token = secrets.token_hex(24)
                    row['previous_token'] = row['token']
                    row['previous_expires'] = min(row['token_expires'], now + 3)
                    row['token'] = hashlib.sha256(token.encode()).hexdigest()
                    row['token_expires'] = min(row['expires'], now + 8)
                    row['last_rotate'] = now
                    row['version'] += 1
                    _write(path, row)
                    return _reply(200, {'ok': True, 'id': identifier, 'token': token, 'version': row['version'], 'token_valid_for': row['token_expires'] - now, 'expires_in': row['expires'] - now})
                path.unlink()
                if action == 'revoke':
                    return _reply(200, {'ok': True})
                return _reply(200, {'ok': True, 'iv': row['iv'], 'cipher': row['cipher']})
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
    except (OSError, ValueError, KeyError, TypeError):
        return _reply(503, {'ok': False})
