"""Python port of the temporary encrypted mobile-face capture endpoint."""
from native_http import make_response, add_headers, legacy_compatible
import json
import os
import re
import secrets
import tempfile
import time
from pathlib import Path
from urllib.parse import parse_qs
SESSION_TTL = 300
MAX_CIPHER_BYTES = 4194304
MAX_FORM_BYTES = 16384
_SID = re.compile('[A-Za-z0-9_-]{20,48}\\Z')
_IV = re.compile('[A-Za-z0-9_-]{16,32}\\Z')
ROOT = Path(__file__).resolve().parent

def _storage_dir():
    private = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    path = Path(private).expanduser() / 'mobile-face' if private else Path(tempfile.gettempdir()) / 'python-migration-mobile-face'
    resolved = path.resolve()
    site = (ROOT / 'site').resolve()
    if resolved == site or site in resolved.parents:
        raise OSError('private_storage_must_be_outside_public_site')
    resolved.mkdir(mode=448, parents=True, exist_ok=True)
    os.chmod(resolved, 448)
    return resolved

def _sid(value):
    if not isinstance(value, str) or _SID.fullmatch(value) is None:
        raise ValueError('invalid_session')
    return value

def _base(directory, sid):
    return directory / __import__('hashlib').sha256(sid.encode()).hexdigest()

@legacy_compatible(callback_index=None, request_index=0)
def _read_body(request_context, limit):
    stream = request_context.get('body_stream')
    raw = stream.read(limit + 1) if stream is not None else b''
    if len(raw) > limit:
        raise OverflowError('payload_too_large')
    return raw

@legacy_compatible(callback_index=None, request_index=0)
def _form(request_context):
    raw = _read_body(request_context, MAX_FORM_BYTES)
    content_type = request_context.get('content_type', '').lower()
    if 'application/json' in content_type:
        try:
            data = json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}
    if 'application/x-www-form-urlencoded' in content_type or 'multipart/form-data' in content_type:
        return {key: values[-1] for key, values in parse_qs(raw.decode('utf-8', errors='replace'), keep_blank_values=True).items()}
    return {}

@legacy_compatible(callback_index=0, request_index=None)
def _json(status, payload):
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    _http_status, _http_headers = (status, _security_headers() + [('Content-Type', 'application/json; charset=utf-8'), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

def _status(code):
    return {200: '200 OK', 400: '400 Bad Request', 404: '404 Not Found', 405: '405 Method Not Allowed', 409: '409 Conflict', 410: '410 Gone', 413: '413 Payload Too Large', 500: '500 Internal Server Error'}.get(code, '%d Error' % code)

def _security_headers():
    return [('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0'), ('Pragma', 'no-cache'), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'), ('Permissions-Policy', 'camera=(self)'), ('Content-Security-Policy', "default-src 'self'; img-src 'self' blob: data:; media-src 'self' blob:; connect-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")]

def _delete(directory, sid):
    base = _base(directory, sid)
    for suffix in ('.json', '.bin'):
        try:
            (base.parent / (base.name + suffix)).unlink()
        except FileNotFoundError:
            pass

def _cleanup(directory):
    cutoff = time.time() - SESSION_TTL - 120
    for path in directory.iterdir():
        if path.suffix not in ('.json', '.bin'):
            continue
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except FileNotFoundError:
            continue

def _read_meta(directory, sid):
    path = _base(directory, sid).with_suffix('.json')
    if not path.is_file():
        raise LookupError((404, 'session_not_found'))
    try:
        meta = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        raise LookupError((410, 'session_invalid'))
    if not isinstance(meta, dict):
        raise LookupError((410, 'session_invalid'))
    if int(meta.get('expires_at', 0)) < int(time.time()):
        _delete(directory, sid)
        raise LookupError((410, 'session_expired'))
    return meta

def _write_meta(directory, sid, meta):
    target = _base(directory, sid).with_suffix('.json')
    temporary = target.with_name(target.name + '.tmp.' + secrets.token_hex(4))
    try:
        with open(temporary, 'x', encoding='utf-8') as handle:
            os.chmod(temporary, 384)
            json.dump(meta, handle, ensure_ascii=False, separators=(',', ':'))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
        os.chmod(target, 384)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

@legacy_compatible(callback_index=1, request_index=0)
def mobile_face(request_context):
    query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
    action = query.get('action', [''])[-1]
    try:
        directory = _storage_dir()
        _cleanup(directory)
    except OSError:
        return _json('500 Internal Server Error', {'ok': False, 'error': 'storage_unavailable'})
    headers = _security_headers()
    if action == 'health':
        payload = json.dumps({'ok': True, 'service': 'mobile-face-v2', 'ttl_seconds': SESSION_TTL}, separators=(',', ':')).encode()
        _http_status, _http_headers = ('200 OK', headers + [('Content-Type', 'application/json; charset=utf-8'), ('Content-Length', str(len(payload)))])
        return make_response([payload], _http_status, _http_headers)
    method = request_context.get('method', 'GET')
    fields = {}
    try:
        if method in ('POST', 'PUT', 'PATCH') and action != 'upload':
            fields = _form(request_context)
        if action == 'create':
            if method != 'POST':
                return _json('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
            sid = _sid(str(fields.get('sid', '')))
            now = int(time.time())
            _write_meta(directory, sid, {'created_at': now, 'expires_at': now + SESSION_TTL, 'ready': False, 'iv': None, 'size': 0})
            return _json('200 OK', {'ok': True, 'expires_in': SESSION_TTL})
        if action:
            sid = _sid(str(query.get('sid', [fields.get('sid', '')])[-1]))
            if action == 'status':
                meta = _read_meta(directory, sid)
                return _json('200 OK', {'ok': True, 'ready': bool(meta.get('ready', False)), 'expires_at': meta.get('expires_at', 0), 'size': meta.get('size', 0)})
            if action == 'upload':
                if method != 'POST':
                    return _json('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
                meta = _read_meta(directory, sid)
                iv = str(request_context.get('header:x-tuti-iv', ''))
                if _IV.fullmatch(iv) is None:
                    return _json('400 Bad Request', {'ok': False, 'error': 'invalid_iv'})
                raw = _read_body(request_context, MAX_CIPHER_BYTES)
                if not raw:
                    return _json('400 Bad Request', {'ok': False, 'error': 'empty_payload'})
                target = _base(directory, sid).with_suffix('.bin')
                temporary = target.with_name(target.name + '.tmp.' + secrets.token_hex(4))
                try:
                    with open(temporary, 'xb') as handle:
                        os.chmod(temporary, 384)
                        handle.write(raw)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary, target)
                    os.chmod(target, 384)
                finally:
                    try:
                        temporary.unlink()
                    except FileNotFoundError:
                        pass
                meta.update({'ready': True, 'iv': iv, 'size': len(raw), 'uploaded_at': int(time.time())})
                _write_meta(directory, sid, meta)
                return _json('200 OK', {'ok': True})
            if action == 'fetch':
                meta = _read_meta(directory, sid)
                target = _base(directory, sid).with_suffix('.bin')
                if not meta.get('ready') or not target.is_file():
                    return _json('409 Conflict', {'ok': False, 'error': 'not_ready'})
                payload = target.read_bytes()
                _http_status, _http_headers = ('200 OK', headers + [('Content-Type', 'application/octet-stream'), ('Content-Length', str(len(payload))), ('X-Tuti-IV', str(meta.get('iv') or ''))])
                return make_response([payload], _http_status, _http_headers)
            if action == 'delete':
                if method != 'POST':
                    return _json('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
                _delete(directory, sid)
                return _json('200 OK', {'ok': True})
            return _json('404 Not Found', {'ok': False, 'error': 'unknown_action'})
        if method != 'GET':
            return _json('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
        sid = query.get('sid', [''])[-1]
        try:
            sid = _sid(sid)
        except ValueError:
            body = b'Invalid session'
            _http_status, _http_headers = ('400 Bad Request', headers + [('Content-Type', 'text/plain; charset=utf-8'), ('Content-Length', str(len(body)))])
            return make_response([body], _http_status, _http_headers)
        template = (ROOT / 'mobile_face_page.html').read_text(encoding='utf-8')
        safe_sid = json.dumps(sid).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
        body = template.replace('__SID_JSON__', safe_sid).encode('utf-8')
        _http_status, _http_headers = ('200 OK', headers + [('Content-Type', 'text/html; charset=utf-8'), ('Content-Length', str(len(body)))])
        return make_response([body], _http_status, _http_headers)
    except LookupError as exc:
        status, error = exc.args[0]
        return _json(_status(status), {'ok': False, 'error': error})
    except ValueError as exc:
        status = 413 if str(exc) == 'payload_too_large' else 400
        error = 'payload_too_large' if status == 413 else str(exc)
        return _json(_status(status), {'ok': False, 'error': error})
    except OverflowError:
        return _json('413 Payload Too Large', {'ok': False, 'error': 'payload_too_large'})
    except OSError:
        return _json('500 Internal Server Error', {'ok': False, 'error': 'storage_write_failed'})
