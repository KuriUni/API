"""Local MNSL card-key proof challenge and verification API."""
from native_http import make_response, add_headers, legacy_compatible
from py36_compat import parse_iso_datetime
import base64
import hashlib
import hmac
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import database
from core import PHP_TRIM_CHARS, key_pepper
from http_utils import RequestError
from migration_config import secret_value
from baas_handlers import BaaSError, _assert_write_fence, _authorize_key, _baas_json_input
TTL_SECONDS = 180
SIGNING_CONTEXT = b'TUTI-MNSL-WEB-CARD-AUTH-V1\n'
FLOW = re.compile('[A-Za-z0-9_-]{43}\\Z', re.ASCII)

def _b64d(value):
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]+', value):
        return None
    try:
        return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    except Exception:
        return None

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status, payload, headers=()):
    from baas_handlers import _reply as baas_reply
    return baas_reply(status, payload, headers)

@legacy_compatible(callback_index=None, request_index=0)
def _audit(request_context, tenant_id, flow_id, subject_hash, verified_at):
    try:
        from ha_handlers import _append_ha_audit
        _append_ha_audit('mnsl_local_card_key_proof_verified', {'tenant_id': tenant_id, 'flow_id_hash': hashlib.sha256(flow_id.encode()).hexdigest(), 'subject_hash': subject_hash, 'verified_at_utc': verified_at}, request_context)
    except Exception:
        pass

@legacy_compatible(callback_index=None, request_index=0)
def _sync(request_context):
    try:
        from ha_handlers import ha_sync_peer
        return bool(ha_sync_peer('mnsl_local_card_key_proof_verified', request_context).get('ok'))
    except Exception:
        return False

@legacy_compatible(callback_index=1, request_index=None)
def _failure(connection, row_id, code):
    public = code if code in {'expired', 'nonce_mismatch', 'invalid_key', 'signature_invalid'} else 'signature_invalid'
    try:
        with connection.cursor() as cursor:
            cursor.execute("UPDATE jpki_verifications SET status='failed',failure_code=%s WHERE id=%s AND status='processing'", (public, row_id))
        connection.commit()
    except Exception:
        connection.rollback()
    return _reply(410 if public == 'expired' else 422, {'ok': False, 'error': 'card_proof_' + public})

@legacy_compatible(callback_index=1, request_index=0)
def mnsl_card_auth(request_context):
    rid = uuid.uuid4().hex[:16]
    if request_context.get('method', 'GET').upper() != 'POST':
        return _reply(405, {'ok': False, 'error': 'method_not_allowed'}, [('Allow', 'POST')])
    connection = None
    try:
        data = _baas_json_input(request_context)
        action = str(data.get('action', '')).strip(PHP_TRIM_CHARS)
        if action not in {'challenge', 'verify'}:
            return _reply(400, {'ok': False, 'error': 'invalid_action'})
        connection = database.connect()
        operation = 'mnsl.card_auth.' + action
        client, headers, ip_hash = _authorize_key(connection, request_context, 'tenant:read', operation, rid)
        if str(client.get('key_kind') or 'standard') != 'operator_admin':
            return _reply(403, {'ok': False, 'error': 'operator_admin_required'}, headers)
        try:
            _assert_write_fence(connection)
        except Exception:
            return _reply(503, {'ok': False, 'error': 'server_not_writable'}, headers)
        if action == 'challenge':
            flow_id, nonce, state = (base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=') for _ in range(3))
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM jpki_verifications WHERE acr IN ('mnsl_local_pending','mnsl_local_key') AND expires_at<UTC_TIMESTAMP()-INTERVAL 30 DAY LIMIT 100")
                cursor.execute("INSERT INTO jpki_verifications(verification_hash,state_hash,tenant_id,client_id,environment,nonce_hash,code_verifier_enc,status,acr,expires_at) VALUES(%s,%s,%s,%s,%s,%s,'','pending','mnsl_local_pending',UTC_TIMESTAMP()+INTERVAL 180 SECOND)", (hashlib.sha256(flow_id.encode()).hexdigest(), hashlib.sha256(state.encode()).hexdigest(), int(client['tenant_id']), int(client['id']), str(client['tenant_environment']), hashlib.sha256(nonce.encode()).hexdigest()))
            connection.commit()
            return _reply(201, {'ok': True, 'flow_id': flow_id, 'nonce': nonce, 'message': SIGNING_CONTEXT.decode() + flow_id + '\n' + nonce, 'expires_in': TTL_SECONDS, 'method': 'mnsl_local_card_key_possession', 'certificate_chain_verified': False, 'legal_identity_verified': False}, headers)
        flow_id = str(data.get('flow_id', '')).strip(PHP_TRIM_CHARS)
        nonce = str(data.get('nonce', '')).strip(PHP_TRIM_CHARS)
        signature = _b64d(data.get('signature', ''))
        spki = _b64d(data.get('public_key_spki', ''))
        if not FLOW.fullmatch(flow_id) or not FLOW.fullmatch(nonce) or signature is None or (not 256 <= len(signature) <= 1024) or (spki is None) or (not 256 <= len(spki) <= 8192):
            return _reply(400, {'ok': False, 'error': 'invalid_card_proof'}, headers)
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute('SELECT id,tenant_id,client_id,environment,nonce_hash,expires_at,status FROM jpki_verifications WHERE verification_hash=%s LIMIT 1 FOR UPDATE', (hashlib.sha256(flow_id.encode()).hexdigest(),))
            row = cursor.fetchone()
            if not row or int(row['tenant_id']) != int(client['tenant_id']) or int(row['client_id']) != int(client['id']) or (not hmac.compare_digest(str(row['environment']), str(client['tenant_environment']))):
                connection.rollback()
                return _reply(404, {'ok': False, 'error': 'card_challenge_not_found'}, headers)
            expiry = row['expires_at']
            if isinstance(expiry, str):
                expiry = parse_iso_datetime(expiry.replace(' ', 'T')).replace(tzinfo=timezone.utc)
            elif getattr(expiry, 'tzinfo', None) is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            expired = int(expiry.timestamp()) < int(time.time()) if hasattr(expiry, 'timestamp') else False
            if row['status'] != 'pending' or expired:
                if row['status'] == 'pending':
                    cursor.execute("UPDATE jpki_verifications SET status='expired',failure_code='expired' WHERE id=%s AND status='pending'", (int(row['id']),))
                connection.commit()
                return _reply(410, {'ok': False, 'error': 'card_challenge_expired_or_used'}, headers)
            if not hmac.compare_digest(str(row['nonce_hash']), hashlib.sha256(nonce.encode()).hexdigest()):
                cursor.execute("UPDATE jpki_verifications SET status='failed',failure_code='nonce_mismatch' WHERE id=%s AND status='pending'", (int(row['id']),))
                connection.commit()
                return _reply(422, {'ok': False, 'error': 'card_proof_nonce_mismatch'}, headers)
            cursor.execute("UPDATE jpki_verifications SET status='processing' WHERE id=%s AND status='pending'", (int(row['id']),))
            if cursor.rowcount != 1:
                connection.rollback()
                return _reply(409, {'ok': False, 'error': 'card_challenge_expired_or_used'}, headers)
        connection.commit()
        try:
            public_key = serialization.load_der_public_key(spki)
        except (ValueError, TypeError):
            return _failure(connection, int(row['id']), 'invalid_key')
        if not isinstance(public_key, rsa.RSAPublicKey) or not 2048 <= public_key.key_size <= 4096 or len(signature) != (public_key.key_size + 7) // 8:
            return _failure(connection, int(row['id']), 'invalid_key')
        message = SIGNING_CONTEXT + flow_id.encode() + b'\n' + nonce.encode()
        try:
            public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            return _failure(connection, int(row['id']), 'signature_invalid')
        pepper = key_pepper({'key_pepper': secret_value('key_pepper')})
        subject_hash = hmac.new(pepper.encode(), ('mnsl-local-card-v1|' + str(int(client['tenant_id'])) + '|' + hashlib.sha256(spki).hexdigest()).encode(), hashlib.sha256).hexdigest()
        verified_at = datetime.now(timezone.utc).isoformat(timespec='seconds')
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute("UPDATE jpki_verifications SET status='verified',subject_hash=%s,acr='mnsl_local_key',failure_code=NULL,verified_at=UTC_TIMESTAMP(),code_verifier_enc='' WHERE id=%s AND status='processing'", (subject_hash, int(row['id'])))
            if cursor.rowcount != 1:
                raise RuntimeError('card_challenge_state_changed')
        connection.commit()
        _audit(request_context, int(client['tenant_id']), flow_id, subject_hash, verified_at)
        return _reply(200, {'ok': True, 'verified': True, 'verified_at_utc': verified_at, 'reference': hashlib.sha256(flow_id.encode()).hexdigest()[:12], 'method': 'mnsl_local_card_key_possession', 'peer_synced': _sync(request_context), 'certificate_chain_verified': False, 'legal_identity_verified': False, 'message': 'カード内の鍵による今回限りの署名を確認しました。証明書の発行元・失効状態は検証していません。'}, headers)
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
