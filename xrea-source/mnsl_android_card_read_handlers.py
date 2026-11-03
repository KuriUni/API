"""Python implementation of the short-lived Android NFC read handoff API."""
from native_http import make_response, add_headers, legacy_compatible
from deployment_settings import site_url
from py36_compat import parse_iso_datetime
import base64
import hashlib
import hmac
import re
import secrets
import uuid
from datetime import datetime, timezone
import database
from core import PHP_TRIM_CHARS
from http_utils import RequestError
from baas_handlers import BaaSError, _assert_write_fence, _authorize_key, _baas_json_input, _reply
TTL_SECONDS = 180
ACR_PENDING = 'mnsl_android_pending'
ACR_DONE = 'mnsl_android_read_done'
FLOW_RE = re.compile('[A-Za-z0-9_-]{20}\\Z', re.ASCII)

def _b64url(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

def _time_text(value):
    if isinstance(value, str):
        value = parse_iso_datetime(value.replace(' ', 'T')).replace(tzinfo=timezone.utc)
    elif getattr(value, 'tzinfo', None) is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec='seconds')

def _load_flow(connection, flow_id):
    with connection.cursor() as cursor:
        cursor.execute('SELECT id,tenant_id,client_id,environment,nonce_hash,status,acr,failure_code,expires_at FROM jpki_verifications WHERE verification_hash=%s LIMIT 1', (hashlib.sha256(flow_id.encode()).hexdigest(),))
        row = cursor.fetchone()
    if not row or row.get('acr') not in {ACR_PENDING, ACR_DONE}:
        return None
    expired = row.get('expires_at')
    if isinstance(expired, str):
        expired = parse_iso_datetime(expired.replace(' ', 'T')).replace(tzinfo=timezone.utc)
    elif getattr(expired, 'tzinfo', None) is None:
        expired = expired.replace(tzinfo=timezone.utc)
    if row.get('status') == 'pending' and int(expired.timestamp()) < int(datetime.now(timezone.utc).timestamp()):
        with connection.cursor() as cursor:
            cursor.execute("UPDATE jpki_verifications SET status='expired',failure_code='expired' WHERE id=%s AND status='pending'", (int(row['id']),))
        connection.commit()
        row['status'], row['failure_code'] = ('expired', 'expired')
    return row

@legacy_compatible(callback_index=None, request_index=0)
def _audit(request_context, action, row, flow_id, outcome):
    try:
        from ha_handlers import _append_ha_audit
        _append_ha_audit(action, {'tenant_id': int(row['tenant_id']), 'flow_id_hash': hashlib.sha256(flow_id.encode()).hexdigest(), 'reported_outcome': outcome, 'reported_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds')}, request_context)
    except Exception:
        pass

@legacy_compatible(callback_index=1, request_index=0)
def mnsl_android_card_read(request_context):
    rid = uuid.uuid4().hex[:16]
    if request_context.get('method', 'GET').upper() != 'POST':
        return _reply(405, {'ok': False, 'error': 'method_not_allowed'}, [('Allow', 'POST')])
    connection = None
    try:
        data = _baas_json_input(request_context)
        action = str(data.get('action', '')).strip(PHP_TRIM_CHARS).translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))
        if action not in {'create', 'status', 'app_status', 'complete', 'fail'}:
            return _reply(400, {'ok': False, 'error': 'invalid_action'})
        connection = database.connect()
        try:
            _assert_write_fence(connection)
        except Exception:
            return _reply(503, {'ok': False, 'error': 'server_not_writable'})
        if action in {'app_status', 'complete', 'fail'}:
            flow_id = str(data.get('flow_id', '')).strip(PHP_TRIM_CHARS)
            nonce = str(data.get('nonce', '')).strip(PHP_TRIM_CHARS)
            if not FLOW_RE.fullmatch(flow_id):
                return _reply(400, {'ok': False, 'error': 'invalid_flow_id'})
            if not FLOW_RE.fullmatch(nonce):
                return _reply(400, {'ok': False, 'error': 'invalid_flow_nonce'})
            row = _load_flow(connection, flow_id)
            if not row or not hmac.compare_digest(hashlib.sha256(nonce.encode()).hexdigest(), str(row['nonce_hash'])):
                return _reply(404, {'ok': False, 'error': 'android_card_flow_not_found'})
            if action == 'app_status':
                state = {'pending': 'pending' if row['acr'] == ACR_PENDING else 'unavailable', 'verified': 'read_complete' if row['acr'] == ACR_DONE else 'unavailable', 'failed': 'read_failed' if row['acr'] == ACR_DONE else 'unavailable', 'expired': 'expired'}.get(str(row['status']), 'unavailable')
                if state == 'unavailable':
                    return _reply(409, {'ok': False, 'error': 'android_card_flow_not_pending', 'state': str(row['status'])})
                return _reply(200, {'ok': True, 'state': state, 'expires_at_utc': _time_text(row['expires_at'])})
            status, acr = (str(row['status']), str(row['acr']))
            if status == 'verified' and acr == ACR_DONE and (action == 'complete'):
                return _reply(200, {'ok': True, 'state': 'read_complete', 'replayed': True})
            if status == 'failed' and acr == ACR_DONE and (action == 'fail'):
                return _reply(200, {'ok': True, 'state': 'read_failed', 'replayed': True, 'failure_code': str(row.get('failure_code') or '')})
            if status != 'pending' or acr != ACR_PENDING:
                return _reply(409, {'ok': False, 'error': 'android_card_flow_not_pending', 'state': status})
            next_status = 'verified' if action == 'complete' else 'failed'
            failure_code = None
            if action == 'fail':
                reason_value = data.get('reason')
                if reason_value is None:
                    reason_value = 'card_read_failed'
                failure_code = str(reason_value).strip(PHP_TRIM_CHARS).translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))
                if failure_code not in {'card_read_failed', 'user_cancelled'}:
                    return _reply(400, {'ok': False, 'error': 'invalid_failure_reason'})
            with connection.cursor() as cursor:
                cursor.execute("UPDATE jpki_verifications SET status=%s,acr=%s,failure_code=%s,verified_at=UTC_TIMESTAMP(),code_verifier_enc='' WHERE id=%s AND status='pending' AND acr=%s AND expires_at>=UTC_TIMESTAMP()", (next_status, ACR_DONE, failure_code, int(row['id']), ACR_PENDING))
                updated = cursor.rowcount
            if updated != 1:
                return _reply(409, {'ok': False, 'error': 'android_card_flow_expired_or_used'})
            connection.commit()
            _audit(request_context, 'mnsl_android_card_read_reported' if action == 'complete' else 'mnsl_android_card_read_failed', row, flow_id, 'complete' if action == 'complete' else failure_code)
            return _reply(200, {'ok': True, 'state': 'read_complete' if action == 'complete' else 'read_failed', 'peer_sync_scheduled': True})
        operation = 'mnsl.android.card_read.create' if action == 'create' else 'mnsl.android.card_read.status'
        client, headers, _ip_hash = _authorize_key(connection, request_context, 'tenant:read', operation, rid)
        if str(client.get('key_kind') or 'standard') != 'operator_admin':
            return _reply(403, {'ok': False, 'error': 'operator_admin_required'}, headers)
        if action == 'create':
            flow_id = _b64url(secrets.token_bytes(15))
            state = _b64url(secrets.token_bytes(32))
            nonce = _b64url(secrets.token_bytes(15))
            with connection.cursor() as cursor:
                cursor.execute('DELETE FROM jpki_verifications WHERE acr IN (%s,%s) AND expires_at<UTC_TIMESTAMP()-INTERVAL 30 DAY LIMIT 100', (ACR_PENDING, ACR_DONE))
                cursor.execute("INSERT INTO jpki_verifications(verification_hash,state_hash,tenant_id,client_id,environment,nonce_hash,code_verifier_enc,status,acr,expires_at) VALUES(%s,%s,%s,%s,%s,%s,'','pending',%s,UTC_TIMESTAMP()+INTERVAL 180 SECOND)", (hashlib.sha256(flow_id.encode()).hexdigest(), hashlib.sha256(state.encode()).hexdigest(), int(client['tenant_id']), int(client['id']), str(client['tenant_environment']), hashlib.sha256(nonce.encode()).hexdigest(), ACR_PENDING))
            connection.commit()
            return _reply(201, {'ok': True, 'flow_id': flow_id, 'nonce': nonce, 'app_path': site_url('/license/python-migration/ha/android-card-read.php'), 'expires_in': TTL_SECONDS, 'method': 'android_local_nfc_read_completion_report', 'personal_data_transferred': False, 'identity_verified': False, 'peer_sync_scheduled': True}, headers)
        flow_id = str(data.get('flow_id', '')).strip(PHP_TRIM_CHARS)
        if not FLOW_RE.fullmatch(flow_id):
            return _reply(400, {'ok': False, 'error': 'invalid_flow_id'}, headers)
        row = _load_flow(connection, flow_id)
        if not row or int(row['tenant_id']) != int(client['tenant_id']) or int(row['client_id']) != int(client['id']) or (str(row['environment']) != str(client['tenant_environment'])):
            return _reply(404, {'ok': False, 'error': 'android_card_flow_not_found'}, headers)
        state = {'pending': 'waiting_for_android', 'verified': 'read_complete', 'failed': 'read_failed', 'expired': 'expired'}.get(str(row['status']), 'unavailable')
        return _reply(200, {'ok': True, 'state': state, 'failure_code': str(row.get('failure_code') or ''), 'expires_at_utc': _time_text(row['expires_at']), 'identity_verified': False, 'personal_data_transferred': False}, headers)
    except RequestError as error:
        status = 413 if str(error) == 'request_too_large' else 400
        return _reply(status, {'ok': False, 'error': str(error)})
    except BaaSError as error:
        return _reply(error.status, {'ok': False, 'error': error.error, **error.extra})
    except Exception:
        if connection:
            try:
                connection.rollback()
            except Exception:
                pass
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    finally:
        if connection:
            try:
                connection.close()
            except Exception:
                pass
