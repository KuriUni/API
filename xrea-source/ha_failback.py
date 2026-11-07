"""Python port of the HA standby failback operation state machine."""
from native_http import make_response, add_headers, legacy_compatible
import json
import os
import re
import secrets
import tempfile
import time
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default as default_email_policy
from pathlib import Path
from urllib.parse import parse_qsl
from core import php_int_cast
from file_locking import fcntl
from http_utils import json_response, read_bounded_body, RequestError
STAGES = ['STARTED', 'EXPORTED', 'VALIDATED', 'IMPORTED', 'VERIFIED', 'DEMOTED', 'PRIMARY_RESUMED', 'SYNCED']
MAX_FAILBACK_BODY_BYTES = 65536

def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def _state_path():
    private = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not private:
        return None
    return Path(private).expanduser() / 'runtime' / 'failback-operation.json'

def _read_state(path):
    try:
        if path.is_symlink() or path.stat().st_size > 16384:
            raise ValueError('invalid_failback_state')
        value = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(value, dict):
            raise ValueError('invalid_failback_state')
        if value:
            try:
                valid = (value.get('status') in {'active', 'complete'}
                         and value.get('stage') in set(STAGES + ['COMPLETE'])
                         and re.fullmatch('[a-f0-9]{32}', str(value.get('operation_id', ''))) is not None
                         and int(value.get('expires_at', 0)) > 0)
            except (TypeError, ValueError, OverflowError):
                valid = False
            if not valid:
                raise ValueError('invalid_failback_state')
        return value
    except FileNotFoundError:
        return {}

def _write_state(path, state):
    path.parent.mkdir(mode=448, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp.' + secrets.token_hex(4))
    try:
        with open(temporary, 'x', encoding='utf-8') as handle:
            os.chmod(temporary, 384)
            json.dump(state, handle, ensure_ascii=False, separators=(',', ':'))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 384)
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
            temporary.unlink()
        except FileNotFoundError:
            pass

@legacy_compatible(callback_index=None, request_index=0)
def _request_data(request_context):
    raw = read_bounded_body(request_context, MAX_FAILBACK_BODY_BYTES)
    content_type = str(request_context.get('content_type', ''))
    form = {}
    if 'application/x-www-form-urlencoded' in content_type.lower():
        try:
            for key, value in parse_qsl(raw.decode('utf-8', errors='replace'), keep_blank_values=True):
                _store_form_field(form, key, value)
        except UnicodeDecodeError:
            form = {}
    elif 'multipart/form-data' in content_type.lower():
        header_value = str(request_context.get('content_type', ''))
        mime_header = ('Content-Type: ' + header_value + '\r\nMIME-Version: 1.0\r\n\r\n').encode('ascii')
        try:
            message = BytesParser(policy=default_email_policy).parsebytes(mime_header + raw)
            for part in message.iter_parts():
                if part.get_content_disposition() != 'form-data' or part.get_filename() is not None:
                    continue
                name = part.get_param('name', header='content-disposition')
                if not isinstance(name, str):
                    continue
                payload = part.get_payload(decode=True) or b''
                charset = part.get_content_charset() or 'utf-8'
                _store_form_field(form, name, payload.decode(charset, errors='replace'))
        except (LookupError, ValueError, UnicodeError):
            form = {}
    if 'application/json' in content_type:
        try:
            decoded = json.loads(raw.decode('utf-8'))
            if isinstance(decoded, dict):
                return (decoded, form)
            if isinstance(decoded, list):
                return ({}, form)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            pass
    return (form, form)

def _store_form_field(fields, name, value):
    import re
    name = str(name).replace(' ', '_').replace('.', '_')
    match = re.match('^([^\\[\\]]+)\\[', name)
    fields[match.group(1) if match else name] = 'Array' if match else value

def _php_string(value, default=''):
    if value is None:
        return default
    if value is True:
        return '1'
    if value is False:
        return ''
    if isinstance(value, (dict, list)):
        return 'Array'
    return str(value)

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status, payload):
    return json_response(status, payload)

def _failback_operation_impl(request_context):
    from ha_handlers import _append_ha_audit, _effective_role, _ha_authorized_scope
    if request_context.get('method', '') == 'POST':
        try:
            data, post_fields = _request_data(request_context)
        except RequestError as error:
            status = '413 Payload Too Large' if str(error) == 'request_too_large' else '400 Bad Request'
            return _reply(status, {'ok': False, 'error': str(error)})
    else:
        data, post_fields = ({}, {})
    if post_fields.get('token') and (not request_context.get('header:x-ha-token')):
        request_context['header:x-ha-token'] = str(post_fields['token'])
    if not _ha_authorized_scope(request_context, 'ha:operate'):
        return _reply('404 Not Found', {'ok': False, 'error': 'not_found'})
    if request_context.get('method', '') != 'POST':
        return _reply('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
    if os.environ.get('PYTHON_MIGRATION_HA_ROLE', '') != 'standby':
        return _reply('409 Conflict', {'ok': False, 'error': 'standby_required'})
    path = _state_path()
    if path is None:
        return _reply('503 Service Unavailable', {'ok': False, 'error': 'storage_unavailable'})
    action = _php_string(data.get('action'), 'status')
    now = int(time.time())
    try:
        state = _read_state(path)
    except FileNotFoundError:
        state = {}
    except (OSError, ValueError):
        return _reply('503 Service Unavailable', {'ok': False, 'error': 'failback_state_invalid'})
    active = state.get('status') == 'active' and php_int_cast(state.get('expires_at', 0)) > now
    if action == 'status':
        return _reply('200 OK', {'ok': True, 'active': active, 'operation': state})
    if action == 'begin':
        if not active:
            if _effective_role() != 'promoted':
                return _reply('409 Conflict', {'ok': False, 'error': 'standby_not_promoted'})
            state = {'operation_id': secrets.token_hex(16), 'status': 'active', 'stage': 'STARTED', 'started_at_utc': _now_iso(), 'updated_at_utc': _now_iso(), 'expires_at': now + 1800}
            try:
                _write_state(path, state)
            except OSError:
                return _reply('503 Service Unavailable', {'ok': False, 'error': 'storage_write_failed'})
            _append_ha_audit('failback_operation_started', {'operation_id_hash': __import__('hashlib').sha256(state['operation_id'].encode()).hexdigest()}, request_context)
        return _reply('200 OK', {'ok': True, 'resumed': active, 'operation': state})
    operation_id = _php_string(data.get('operation_id'), '')
    stored_id = str(state.get('operation_id', '')).encode('utf-8')
    provided_id = operation_id.encode('utf-8')
    if not active or not secrets.compare_digest(stored_id, provided_id):
        return _reply('409 Conflict', {'ok': False, 'error': 'failback_operation_not_active'})
    if action == 'stage':
        stage = _php_string(data.get('stage'), '')
        old_index = STAGES.index(state['stage']) if state.get('stage') in STAGES else -1
        new_index = STAGES.index(stage) if stage in STAGES else -1
        if new_index < 0 or old_index < 0 or new_index != old_index + 1:
            expected = STAGES[old_index + 1] if 0 <= old_index + 1 < len(STAGES) else None
            return _reply('409 Conflict', {'ok': False, 'error': 'invalid_failback_stage', 'expected': expected})
        state.update({'stage': stage, 'updated_at_utc': _now_iso(), 'expires_at': now + 1800})
        try:
            _write_state(path, state)
        except OSError:
            return _reply('503 Service Unavailable', {'ok': False, 'error': 'storage_write_failed'})
        _append_ha_audit('failback_stage', {'operation_id_hash': __import__('hashlib').sha256(operation_id.encode()).hexdigest(), 'stage': stage}, request_context)
        return _reply('200 OK', {'ok': True, 'operation': state})
    if action == 'complete':
        if state.get('stage') != 'SYNCED':
            return _reply('409 Conflict', {'ok': False, 'error': 'failback_not_synced'})
        state.update({'status': 'complete', 'stage': 'COMPLETE', 'updated_at_utc': _now_iso()})
        try:
            _write_state(path, state)
        except OSError:
            return _reply('503 Service Unavailable', {'ok': False, 'error': 'storage_write_failed'})
        _append_ha_audit('failback_operation_completed', {'operation_id_hash': __import__('hashlib').sha256(operation_id.encode()).hexdigest()}, request_context)
        return _reply('200 OK', {'ok': True, 'operation': state})
    return _reply('400 Bad Request', {'ok': False, 'error': 'invalid_action'})

@legacy_compatible(callback_index=1, request_index=0)
def failback_operation(request_context):
    path = _state_path()
    if path is None:
        return _failback_operation_impl(request_context)
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = path.with_name(path.name + '.lock')
        if lock_path.is_symlink():
            return _reply('503 Service Unavailable', {'ok': False, 'error': 'failback_lock_unavailable'})
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        lock_fd = os.open(str(lock_path), flags, 0o600)
        with os.fdopen(lock_fd, 'a+b') as lock:
            os.chmod(lock_path, 0o600)
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return _reply('409 Conflict', {'ok': False, 'error': 'failback_operation_busy'})
            try:
                return _failback_operation_impl(request_context)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
    except OSError:
        return _reply('503 Service Unavailable', {'ok': False, 'error': 'failback_lock_unavailable'})
