"""Python port of the HA maintenance and failover mode endpoint."""
from native_http import make_response, add_headers, legacy_compatible
from py36_compat import parse_iso_datetime
import base64
import hashlib
import hmac
import json
import os
import re
import time
from email.parser import BytesParser
from email.policy import default as default_email_policy
from pathlib import Path
from path_utils import unlink_missing_ok
from urllib.parse import parse_qsl
from urllib.request import Request, urlopen
import database
from core import PHP_TRIM_CHARS, php_int_cast
from http_utils import json_response

@legacy_compatible(callback_index=0, request_index=None)
def _response(status, payload):
    return json_response(status, payload)

@legacy_compatible(callback_index=None, request_index=0)
def _php_post(request_context):
    """Approximate PHP $_POST for this form endpoint; ignore query and JSON."""

    def assign(fields, name, value):
        name = str(name).replace(' ', '_').replace('.', '_')
        match = re.match('^([^\\[\\]]+)\\[', name)
        fields[match.group(1) if match else name] = 'Array' if match else value
    content_type_header = str(request_context.get('content_type', ''))
    content_type = content_type_header.lower()
    stream = request_context.get('body_stream')
    raw = stream.read() if stream is not None else b''
    if content_type.startswith('application/x-www-form-urlencoded'):
        try:
            raw_fields = parse_qsl(raw.decode('utf-8'), keep_blank_values=True)
        except UnicodeDecodeError:
            return {}
        values = {}
        for key, value in raw_fields:
            assign(values, key, value)
        return values
    if content_type.startswith('multipart/form-data'):
        try:
            headers = ('Content-Type: ' + content_type_header + '\r\nMIME-Version: 1.0\r\n\r\n').encode('ascii')
            message = BytesParser(policy=default_email_policy).parsebytes(headers + raw)
            values = {}
            for part in message.iter_parts():
                if part.get_content_disposition() != 'form-data':
                    continue
                name = part.get_param('name', header='content-disposition')
                if not isinstance(name, str) or part.get_filename() is not None:
                    continue
                payload = part.get_payload(decode=True) or b''
                charset = part.get_content_charset() or 'utf-8'
                assign(values, name, payload.decode(charset))
            return values
        except Exception:
            return {}
    return {}

@legacy_compatible(callback_index=None, request_index=0)
def _authorized(request_context, action):
    from ha_handlers import _ha_authorized_scope
    if action == 'status':
        if _ha_authorized_scope(request_context, 'ha:operate'):
            return True
        token = str(request_context.get('header:x-ha-session', '')).strip()
        try:
            from baas_handlers import _decode_admin_session
            return _decode_admin_session(token) is not None
        except Exception:
            return False
    required = 'ha:promote' if action == 'promote' else 'ha:operate'
    if _ha_authorized_scope(request_context, required):
        return True
    if action != 'promote':
        return False
    token = str(request_context.get('header:x-ha-automation', ''))
    try:
        encoded, signature = token.split('.', 1)
        payload = base64.urlsafe_b64decode(encoded + '=' * ((4 - len(encoded) % 4) % 4))
        supplied = base64.urlsafe_b64decode(signature + '=' * ((4 - len(signature) % 4) % 4))
        claims = json.loads(payload.decode('utf-8'))
        from passkey_handlers import _key
        expected = hmac.new(_key('automation/v1'), encoded.encode('ascii'), hashlib.sha256).digest()
        from ha_handlers import _runtime_json
        revoked = _runtime_json('revoked-automation.json') or {}
        jtis = list(revoked.values()) if isinstance(revoked, dict) else revoked
        scope = claims.get('scope', []) if isinstance(claims, dict) else []
        scope_values = list(scope.values()) if isinstance(scope, dict) else scope if isinstance(scope, list) else [scope]
        return isinstance(claims, dict) and claims.get('purpose') == 'ha_auto_promote' and (claims.get('aud') == 'backup.2415.jp') and ('ha:promote' in scope_values) and isinstance(claims.get('jti'), str) and (claims['jti'] not in (jtis if isinstance(jtis, list) else [])) and (php_int_cast(claims.get('expires', 0)) >= int(time.time())) and hmac.compare_digest(expected, supplied)
    except Exception:
        return False

def _advance_write_fence(writer_role):
    if writer_role not in {'primary', 'promoted', 'standby', 'maintenance'}:
        raise ValueError('invalid_writer_role')
    connection = database.connect()
    try:
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute('SELECT epoch FROM ha_fence_state WHERE singleton_id=1 FOR UPDATE')
            row = cursor.fetchone()
            epoch = max(1, int((row or {}).get('epoch', 0)) + 1)
            cursor.execute('INSERT INTO ha_fence_state(singleton_id,epoch,writer_role,lease_id,lease_expires_at) VALUES(1,%s,%s,NULL,NULL) ON DUPLICATE KEY UPDATE epoch=VALUES(epoch),writer_role=VALUES(writer_role),lease_id=NULL,lease_expires_at=NULL', (epoch, writer_role))
        connection.commit()
        return epoch
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()

def _peer_primary_available():
    peer = str(os.environ.get('PYTHON_MIGRATION_HA_PEER', '')).strip().rstrip('/')
    token = str(os.environ.get('PYTHON_MIGRATION_HA_SYNC_TOKEN', ''))
    if not peer or not token:
        return False
    if not peer.startswith('https://'):
        return False
    request = Request(peer + '/ha/status.php', headers={'Accept': 'application/json', 'X-HA-Token': token})
    try:
        with urlopen(request, timeout=5) as response:
            data = json.loads(response.read(65536).decode('utf-8'))
        return isinstance(data, dict) and data.get('ok') is True and (data.get('effective_role') == 'primary')
    except Exception:
        return False

def _sync_is_fresh(last_sync):
    if not isinstance(last_sync, dict):
        return False
    raw = str(last_sync.get('synced_at_utc', ''))
    try:
        from datetime import datetime, timezone
        parsed = parse_iso_datetime(raw.replace('Z', '+00:00'))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age = int(time.time()) - int(parsed.timestamp())
        return age <= 1200
    except (ValueError, OverflowError):
        return False

@legacy_compatible(callback_index=1, request_index=0)
def ha_mode(request_context):
    if str(request_context.get('method', '')) != 'POST':
        _http_status, _http_headers = ('405 Method Not Allowed', [('Content-Length', '0')])
        return make_response([b''], _http_status, _http_headers)
    data = _php_post(request_context)
    if data.get('token') and (not request_context.get('header:x-ha-token')):
        request_context['header:x-ha-token'] = str(data['token'])
    action_value = data.get('action')
    action = str('status' if action_value is None else action_value)
    if not _authorized(request_context, action):
        return _response('404 Not Found', {'ok': False, 'error': 'not_found'})
    if action == 'rotate-token':
        # Require the current operator credential; merge only ha_sync_token.
        new_token = str(data.get('new_token', '') or '')
        if not re.fullmatch(r'[A-Za-z0-9_-]{43,128}', new_token):
            return _response('400 Bad Request', {'ok': False, 'error': 'invalid_new_token'})
        if os.environ.get('PYTHON_MIGRATION_HA_SYNC_TOKEN', ''):
            return _response('409 Conflict', {'ok': False, 'error': 'token_configured_in_environment'})
        try:
            from migration_config import update_runtime_secrets
            update_runtime_secrets({'ha_sync_token': new_token})
        except Exception:
            return _response('503 Service Unavailable', {'ok': False, 'error': 'token_rotation_failed'})
        from ha_handlers import _append_ha_audit
        _append_ha_audit('ha_sync_token_rotated', {'configured_role': os.environ.get('PYTHON_MIGRATION_HA_ROLE', 'unknown')}, request_context)
        return _response('200 OK', {'ok': True, 'rotated': True})
    role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', 'unknown'))
    from ha_handlers import _append_ha_audit, _effective_role, _runtime_json, _runtime_path, _write_runtime_json
    state = _runtime_json('state.json') or {}
    if role == 'primary':
        if action not in {'maintenance', 'resume', 'status'}:
            return _response('400 Bad Request', {'ok': False, 'error': 'invalid_primary_action'})
        if action == 'status':
            return _response('200 OK', {'ok': True, 'role': 'maintenance' if state.get('maintenance') is True else 'primary'})
        state = {'maintenance': action == 'maintenance', 'changed_at_utc': __import__('datetime').datetime.now(__import__('datetime').timezone.utc).isoformat(timespec='seconds')}
        writer = 'maintenance' if action == 'maintenance' else 'primary'
        try:
            epoch = _advance_write_fence(writer)
            _write_runtime_json('state.json', state)
        except Exception:
            return _response('503 Service Unavailable', {'ok': False, 'error': 'state_write_failed'})
        _append_ha_audit('role_change', {'action': action, 'new_role': writer, 'epoch': epoch}, request_context)
        return _response('200 OK', {'ok': True, 'role': writer})
    if role != 'standby' or action not in {'promote', 'force_promote', 'demote', 'status'}:
        return _response('400 Bad Request', {'ok': False, 'error': 'invalid_standby_action'})
    if action == 'status':
        return _response('200 OK', {'ok': True, 'role': 'promoted' if _effective_role() == 'promoted' else 'standby'})
    observed_seconds = None
    if action in {'promote', 'force_promote'}:
        last_sync = _runtime_json('last-sync.json')
        if not _sync_is_fresh(last_sync):
            return _response('409 Conflict', {'ok': False, 'error': 'standby_snapshot_too_old'})
        if _peer_primary_available():
            path = _runtime_path('failure-observation.json')
            if path is not None:
                try:
                    unlink_missing_ok(path)
                except OSError:
                    pass
            return _response('409 Conflict', {'ok': False, 'error': 'primary_still_available'})
        reason = str(data.get('reason', '')).strip(PHP_TRIM_CHARS)
        if action == 'force_promote':
            if str(data.get('confirm_force', '')) != 'FORCE':
                return _response('400 Bad Request', {'ok': False, 'error': 'force_confirmation_required'})
            if not reason:
                return _response('400 Bad Request', {'ok': False, 'error': 'force_reason_required'})
        path = _runtime_path('failure-observation.json')
        if path is None:
            return _response('503 Service Unavailable', {'ok': False, 'error': 'state_write_failed'})
        observation = _runtime_json('failure-observation.json') or {}
        started = int(observation.get('started_at', 0) or 0)
        if started <= 0 or started > int(time.time()):
            started = int(time.time())
            from datetime import datetime, timezone
            _write_runtime_json('failure-observation.json', {'started_at': started, 'started_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds')})
        observed_seconds = int(time.time()) - started
        if action == 'promote' and observed_seconds < 600:
            return _response('409 Conflict', {'ok': False, 'error': 'primary_outage_not_confirmed', 'observed_seconds': observed_seconds, 'required_seconds': 600})
    if action == 'demote' and _effective_role() == 'promoted' and (str(data.get('confirm_failback', '')) != '1'):
        return _response('409 Conflict', {'ok': False, 'error': 'failback_required'})
    promoting = action in {'promote', 'force_promote'}
    new_role = 'promoted' if promoting else 'standby'
    state = {'promoted': promoting}
    from datetime import datetime, timezone
    state['changed_at_utc'] = datetime.now(timezone.utc).isoformat(timespec='seconds')
    try:
        epoch = _advance_write_fence(new_role)
        _write_runtime_json('state.json', state)
    except Exception:
        return _response('503 Service Unavailable', {'ok': False, 'error': 'state_write_failed'})
    audit_event = 'forced_role_change' if action == 'force_promote' else 'role_change'
    _append_ha_audit(audit_event, {'action': action, 'new_role': new_role, 'epoch': epoch, 'observed_seconds': observed_seconds, 'reason': reason[:100] if action == 'force_promote' else None}, request_context)
    if action == 'demote':
        path = _runtime_path('failure-observation.json')
        if path is not None:
            try:
                unlink_missing_ok(path)
            except OSError:
                pass
    return _response('200 OK', {'ok': True, 'role': new_role})
