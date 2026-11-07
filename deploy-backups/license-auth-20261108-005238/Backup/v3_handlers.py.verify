"""Python implementations of selected License API v3 routes."""
from native_http import make_response, add_headers, legacy_compatible
import hashlib
import hmac
import json
import pymysql
import os
import re
import time
import uuid
import sys
from datetime import datetime, timedelta, timezone
import database
from core import ConfigurationError, device_reference, random_token, token_hash, product_id, parse_utc_datetime, normalize_license_key, normalize_device_fingerprint, is_valid_device_fingerprint, is_valid_license_key_format, license_key_hash, device_hash
from http_utils import RequestError, json_response, request_data
import v3_crypto
from migration_config import secret_value
API_VERSION = '3.0-beta1'

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status_code, payload, rid, headers=()):
    status = {200: '200 OK', 400: '400 Bad Request', 401: '401 Unauthorized', 405: '405 Method Not Allowed', 409: '409 Conflict', 429: '429 Too Many Requests', 503: '503 Service Unavailable'}.get(status_code, '%d Error' % status_code)
    body = dict(payload)
    body.setdefault('success', 200 <= status_code < 300)
    body.setdefault('api_version', API_VERSION)
    body.setdefault('request_id', rid)
    response_headers = list(headers) + [('X-Request-ID', rid)]
    if status_code == 503:
        response_headers.append(('Retry-After', '2'))
    return json_response(status, body, response_headers)

@legacy_compatible(callback_index=0, request_index=None)
def _error(status_code, code, message, rid, extra=None):
    payload = {'success': False, 'error_code': code, 'error': message}
    if extra:
        payload.update(extra)
    return _reply(status_code, payload, rid)

@legacy_compatible(callback_index=0, request_index=None)
def _method_error(rid, allow):
    return _reply(405, {'success': False, 'error_code': 'METHOD_NOT_ALLOWED', 'error': '%s を使用してください。' % allow}, rid, [('Allow', allow)])

def _config():
    return {'key_pepper': secret_value('key_pepper'), 'token_secret': secret_value('token_secret'), 'license_v3_signing_secret': secret_value('license_v3_signing_secret')}

class V3Error(RuntimeError):

    def __init__(self, status, code, message, extra=None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.extra = extra or {}

@legacy_compatible(callback_index=None, request_index=0)
def _require_post(request_context, rid):
    if request_context.get('method', '') != 'POST':
        raise V3Error(405, 'METHOD_NOT_ALLOWED', 'POST を使用してください。')

def _public_error(exc):
    if isinstance(exc, RequestError):
        return V3Error(400, 'INVALID_REQUEST', 'リクエスト形式が正しくありません。')
    if isinstance(exc, (database.DatabaseConfigurationError, ConfigurationError, pymysql.err.Error)):
        return V3Error(503, 'SERVICE_UNAVAILABLE', '一時的に認証サービスを利用できません。')
    if isinstance(exc, V3Error):
        return exc
    code = str(exc)
    mapping = {'challenge_invalid': (400, 'CHALLENGE_INVALID'), 'challenge_already_used': (409, 'CHALLENGE_ALREADY_USED'), 'challenge_expired': (401, 'CHALLENGE_EXPIRED'), 'challenge_nonce_invalid': (401, 'CHALLENGE_INVALID'), 'challenge_key_mismatch': (401, 'CHALLENGE_KEY_MISMATCH'), 'device_signature_invalid': (401, 'DEVICE_SIGNATURE_INVALID'), 'license_device_limit_reached': (409, 'DEVICE_LIMIT_REACHED'), 'session_revoked': (401, 'SESSION_REVOKED'), 'license_inactive': (403, 'LICENSE_INACTIVE'), 'license_expired': (403, 'LICENSE_EXPIRED'), 'access_token_expired': (401, 'ACCESS_TOKEN_EXPIRED'), 'refresh_token_expired': (401, 'REFRESH_TOKEN_EXPIRED'), 'proof_required': (400, 'PROOF_REQUIRED'), 'proof_timestamp_invalid': (401, 'PROOF_TIMESTAMP_INVALID'), 'proof_signature_invalid': (401, 'PROOF_SIGNATURE_INVALID'), 'proof_replayed': (409, 'PROOF_REPLAYED'), 'offline_signing_unavailable': (503, 'OFFLINE_SIGNING_UNAVAILABLE'), 'license_not_found': (400, 'LICENSE_NOT_FOUND'), 'schema_missing': (503, 'V3_MIGRATION_REQUIRED'), 'node_not_writable': (503, 'SERVICE_UNAVAILABLE'), 'ha_write_fence_rejected': (503, 'SERVICE_UNAVAILABLE'), 'device_public_key_invalid': (400, 'DEVICE_PUBLIC_KEY_INVALID'), 'device_public_key_too_weak': (400, 'DEVICE_PUBLIC_KEY_TOO_WEAK'), 'device_public_key_curve_unsupported': (400, 'DEVICE_KEY_CURVE_UNSUPPORTED'), 'device_public_key_type_unsupported': (400, 'DEVICE_KEY_TYPE_UNSUPPORTED')}
    mapping['challenge_purpose_invalid'] = (400, 'CHALLENGE_PURPOSE_INVALID')
    if code not in mapping:
        if isinstance(exc, ValueError):
            return V3Error(400, 'V3_REQUEST_FAILED', 'リクエスト形式が正しくありません。')
        return V3Error(503, 'SERVICE_UNAVAILABLE', '一時的に認証サービスを利用できません。')
    status, public_code = mapping[code]
    extra = {'required_migration': '027_license_api_v3_beta'} if code == 'schema_missing' else None
    message = 'ライセンスキーが正しくありません。' if code == 'license_not_found' else code
    return V3Error(status, public_code, message, extra)


@legacy_compatible(callback_index=0, request_index=None)
def _error_response(exc, rid):
    public = _public_error(exc)
    if public.status == 503:
        print('license_request_failed request_id=%s error_type=%s' % (rid, type(exc).__name__), file=sys.stderr)
    headers = [('Allow', 'POST')] if public.status == 405 else ()
    return _reply(public.status, {'success': False, 'error_code': public.code, 'error': str(public), **public.extra}, rid, headers)

def _require_v3_schema(connection):
    required = ('license_v3_challenges', 'license_v3_devices', 'license_v3_sessions', 'license_v3_refresh_history', 'license_v3_proofs', 'license_v3_offline_tickets')
    with connection.cursor() as cursor:
        for table in required:
            cursor.execute('SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s', (table,))
            if int(cursor.fetchone()['n']) == 0:
                raise RuntimeError('schema_missing')

def _assert_write_fence(connection):
    role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    try:
        from ha_handlers import _runtime_json
        state = _runtime_json('state.json') or {}
    except Exception:
        state = {}
    maintenance = state.get('maintenance') is True if 'maintenance' in state else os.environ.get('PYTHON_MIGRATION_HA_MAINTENANCE') == '1'
    promoted = state.get('promoted') is True if 'promoted' in state else os.environ.get('PYTHON_MIGRATION_HA_PROMOTED') == '1'
    if role == 'primary' and (not maintenance):
        expected = 'primary'
    elif role == 'standby' and promoted:
        expected = 'promoted'
    else:
        raise RuntimeError('node_not_writable')
    with connection.cursor() as cursor:
        cursor.execute('SELECT epoch,writer_role FROM ha_fence_state WHERE singleton_id=1')
        row = cursor.fetchone()
    if not row or not hmac.compare_digest(expected, str(row.get('writer_role') or '')):
        raise RuntimeError('ha_write_fence_rejected')

def _load_session(connection, token, kind='access', for_update=False):
    config = _config()
    if len(str(config['token_secret']).strip()) < 32:
        raise RuntimeError('offline_signing_unavailable')
    col = 'refresh_token_hash' if kind == 'refresh' else 'access_token_hash'
    hashed = token_hash(config, token)
    sql = 'SELECT s.*,d.device_hash,d.device_label,d.public_key_pem,d.key_thumbprint,d.key_algorithm,d.revoked_at AS device_revoked_at,l.active,l.expires_at,l.revoked_at AS license_revoked_at,l.max_devices,l.tenant_id,l.product_id,l.label AS license_label,l.offline_epoch FROM license_v3_sessions s JOIN license_v3_devices d ON d.id=s.device_id JOIN licenses l ON l.id=s.license_id WHERE s.%s=%%s AND l.deleted_at IS NULL LIMIT 1' % col
    if for_update:
        sql += ' FOR UPDATE'
    with connection.cursor() as cursor:
        cursor.execute(sql, (hashed,))
        return cursor.fetchone()

def _session_active(row, kind='access'):
    if row.get('revoked_at') or row.get('device_revoked_at'):
        raise RuntimeError('session_revoked')
    if int(row.get('active') or 0) != 1 or row.get('license_revoked_at'):
        raise RuntimeError('license_inactive')
    expiry = row.get('expires_at')
    if expiry and _as_utc(expiry) <= datetime.now(timezone.utc):
        raise RuntimeError('license_expired')
    token_expiry = row.get('refresh_expires_at' if kind == 'refresh' else 'access_expires_at')
    if not token_expiry or _as_utc(token_expiry) <= datetime.now(timezone.utc):
        raise RuntimeError(kind + '_token_expired')

def _as_utc(value):
    if isinstance(value, datetime):
        return value.replace(tzinfo=value.tzinfo or timezone.utc).astimezone(timezone.utc)
    parsed = parse_utc_datetime(str(value))
    if parsed is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    return parsed


def _rollback_connection(connection):
    try:
        connection.rollback()
    except pymysql.err.Error:
        pass


def _close_connection(connection):
    try:
        connection.close()
    except pymysql.err.Error:
        pass


def _session_timing(access_expiry, refresh_expiry, now):
    access_remaining = max(0, int((_as_utc(access_expiry).replace(microsecond=0) - now).total_seconds()))
    refresh_remaining = max(0, int((_as_utc(refresh_expiry).replace(microsecond=0) - now).total_seconds()))
    return {'server_time_utc': now.isoformat(timespec='seconds'),
            'access_expires_in': access_remaining, 'refresh_expires_in': refresh_remaining,
            'refresh_after_seconds': access_remaining * 4 // 5}


def _revoke_session_family(connection, family_id, reason):
    with connection.cursor() as cursor:
        cursor.execute('UPDATE license_v3_sessions SET revoked_at=UTC_TIMESTAMP(),revoke_reason=%s WHERE family_id=%s AND revoked_at IS NULL', (reason, family_id))
        affected = cursor.rowcount
        cursor.execute('UPDATE license_v3_offline_tickets SET revoked_at=UTC_TIMESTAMP() WHERE session_id IN (SELECT session_id FROM license_v3_sessions WHERE family_id=%s) AND revoked_at IS NULL', (family_id,))
    return affected

def _verify_pop(connection, session, action, data):
    nonce = str(data.get('request_nonce', '')).strip()
    try:
        timestamp = int(data.get('timestamp', 0))
    except (TypeError, ValueError):
        timestamp = 0
    signature = str(data.get('signature', '')).strip()
    if not 16 <= len(nonce) <= 180 or timestamp <= 0 or (not signature):
        raise RuntimeError('proof_required')
    if abs(int(time.time()) - timestamp) > 120:
        raise RuntimeError('proof_timestamp_invalid')
    message = v3_crypto.proof_message(action, str(session['session_id']), nonce, timestamp)
    if not v3_crypto.verify_signature(str(session['public_key_pem']), message, signature):
        raise RuntimeError('proof_signature_invalid')
    proof_hash = hashlib.sha256((str(session['session_id']) + '|' + action + '|' + nonce + '|' + str(timestamp)).encode()).hexdigest()
    try:
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO license_v3_proofs(proof_hash,session_id,action,expires_at) VALUES(%s,%s,%s,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 240 SECOND))', (proof_hash, str(session['session_id']), action))
            cursor.execute('DELETE FROM license_v3_proofs WHERE expires_at < UTC_TIMESTAMP()')
    except Exception as exc:
        if getattr(exc, 'args', [None])[0] == 1062:
            raise RuntimeError('proof_replayed')
        raise

def _consume_challenge(connection, purpose, challenge_id, nonce, public_key, signature):
    challenge_id = str(challenge_id).strip().lower()
    if re.fullmatch('[a-f0-9]{32}', challenge_id) is None:
        raise RuntimeError('challenge_invalid')
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM license_v3_challenges WHERE challenge_id=%s LIMIT 1 FOR UPDATE', (challenge_id,))
        row = cursor.fetchone()
    if not row or str(row.get('purpose')) != purpose:
        raise RuntimeError('challenge_invalid')
    if row.get('consumed_at'):
        raise RuntimeError('challenge_already_used')
    if _as_utc(row['expires_at']) <= datetime.now(timezone.utc):
        raise RuntimeError('challenge_expired')
    if not hmac.compare_digest(str(row['nonce_hash']), hashlib.sha256(str(nonce).encode('utf-8')).hexdigest()):
        raise RuntimeError('challenge_nonce_invalid')
    if not hmac.compare_digest(str(row['device_key_thumbprint']), str(public_key['thumbprint'])):
        raise RuntimeError('challenge_key_mismatch')
    message = v3_crypto.challenge_message(purpose, challenge_id, str(nonce), public_key['thumbprint'])
    if not v3_crypto.verify_signature(public_key['pem'], message, str(signature)):
        raise RuntimeError('device_signature_invalid')
    with connection.cursor() as cursor:
        cursor.execute('UPDATE license_v3_challenges SET consumed_at=UTC_TIMESTAMP() WHERE id=%s', (int(row['id']),))

def _license_by_key(connection, key_hash):
    with connection.cursor() as cursor:
        # Take the per-license lock before any consistent read in the activation
        # transaction. Under MySQL REPEATABLE READ, a plain lookup here could
        # establish a stale snapshot while waiting for the later capacity lock.
        cursor.execute('SELECT * FROM licenses WHERE key_hash=%s AND deleted_at IS NULL LIMIT 1 FOR UPDATE', (key_hash,))
        return cursor.fetchone()

def _lock_license(connection, license_id):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM licenses WHERE id=%s AND deleted_at IS NULL LIMIT 1 FOR UPDATE', (license_id,))
        return cursor.fetchone()

def _resolve_product(connection, license_row, product_code):
    tenant_id = int(license_row.get('tenant_id') or 1)
    product_code = str(product_code or '').strip().lower()
    if tenant_id == 1:
        return product_code
    with connection.cursor() as cursor:
        cursor.execute("SELECT code FROM products WHERE id=%s AND tenant_id=%s AND status='active' LIMIT 1", (int(license_row.get('product_id') or 0), tenant_id))
        row = cursor.fetchone()
    expected = str((row or {}).get('code') or '').strip().lower()
    if re.fullmatch('[a-z0-9][a-z0-9_-]{1,63}', expected) is None:
        raise V3Error(400, 'PRODUCT_UNAVAILABLE', 'ライセンスに有効な製品が設定されていません。')
    if re.fullmatch('[a-z0-9][a-z0-9_-]{1,63}', product_code) is None:
        raise V3Error(400, 'PRODUCT_CODE_REQUIRED', 'product_code が必要です。', {'expected_product_code': expected, 'product_binding_retryable': True})
    if not hmac.compare_digest(expected, product_code):
        raise V3Error(400, 'PRODUCT_MISMATCH', '製品コードとライセンスが一致しません。', {'expected_product_code': expected, 'product_binding_retryable': True})
    return expected

def _start_evaluation(connection, license_row):
    if license_row.get('evaluation_days') is None or license_row.get('evaluation_started_at'):
        return license_row
    days = max(1, min(3650, int(license_row['evaluation_days'])))
    started = datetime.now(timezone.utc)
    expires = started + timedelta(days=days)
    with connection.cursor() as cursor:
        cursor.execute('UPDATE licenses SET evaluation_started_at=%s,expires_at=%s WHERE id=%s AND evaluation_started_at IS NULL', (started.strftime('%Y-%m-%d %H:%M:%S'), expires.strftime('%Y-%m-%d %H:%M:%S'), int(license_row['id'])))
    license_row = dict(license_row)
    license_row['evaluation_started_at'] = started
    license_row['expires_at'] = expires
    return license_row

def _active_license(license_row):
    if int(license_row.get('active') or 0) != 1:
        raise RuntimeError('このライセンスは無効です。')
    if license_row.get('revoked_at'):
        raise RuntimeError('このライセンスは失効しています。')
    if license_row.get('expires_at') and _as_utc(license_row['expires_at']) <= datetime.now(timezone.utc):
        raise RuntimeError('このライセンスは期限切れです。')

def _guard_capacity(connection, license_row, device_hash_value, include_v3=True):
    license_id = int(license_row['id'])
    with connection.cursor() as cursor:
        sources = 'SELECT device_hash FROM license_devices WHERE license_id=%s AND revoked_at IS NULL AND refresh_expires_at>UTC_TIMESTAMP()'
        args = (license_id,)
        if include_v3:
            sources += ' UNION ALL SELECT device_hash FROM license_v3_devices WHERE license_id=%s AND revoked_at IS NULL'
            args += (license_id,)
        cursor.execute('SELECT 1 AS found FROM (' + sources + ') d WHERE device_hash=%s LIMIT 1', args + (device_hash_value,))
        existing = cursor.fetchone()
        if existing:
            return
        cursor.execute('SELECT COUNT(DISTINCT device_hash) AS n FROM (' + sources + ') d', args)
        count = int(cursor.fetchone()['n'])
    if count >= max(1, int(license_row.get('max_devices') or 1)):
        raise RuntimeError('license_device_limit_reached')

def _upsert_device(connection, license_row, device_hash_value, public_key, label, app_version):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM license_v3_devices WHERE license_id=%s AND device_hash=%s LIMIT 1 FOR UPDATE', (int(license_row['id']), device_hash_value))
        row = cursor.fetchone()
        label = str(label or '').strip()[:120]
        version = str(app_version or '').strip()[:40]
        if row is None:
            cursor.execute('INSERT INTO license_v3_devices(license_id,device_hash,device_label,public_key_pem,key_thumbprint,key_algorithm,app_version,bound_at,last_seen_at,revoked_at) VALUES(%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP(),NULL)', (int(license_row['id']), device_hash_value, label, public_key['pem'], public_key['thumbprint'], public_key['algorithm'], version))
            device_id = cursor.lastrowid
        else:
            device_id = int(row['id'])
            cursor.execute('UPDATE license_v3_devices SET device_label=%s,public_key_pem=%s,key_thumbprint=%s,key_algorithm=%s,app_version=%s,last_seen_at=UTC_TIMESTAMP(),revoked_at=NULL WHERE id=%s', (label, public_key['pem'], public_key['thumbprint'], public_key['algorithm'], version, device_id))
        cursor.execute('SELECT * FROM license_v3_devices WHERE id=%s', (device_id,))
        return cursor.fetchone() or {}

def _issue_session(connection, license_row, device_row):
    config = _config()
    now = datetime.now(timezone.utc)
    access_exp = now + timedelta(seconds=900)
    refresh_exp = now + timedelta(days=30)
    if license_row.get('expires_at'):
        license_exp = _as_utc(license_row['expires_at'])
        access_exp = min(access_exp, license_exp)
        refresh_exp = min(refresh_exp, license_exp)
    session_id = os.urandom(16).hex()
    family_id = os.urandom(16).hex()
    access, refresh = (random_token(32), random_token(48))
    scopes_value = v3_crypto.scopes()
    with connection.cursor() as cursor:
        cursor.execute("UPDATE license_v3_sessions SET revoked_at=UTC_TIMESTAMP(),revoke_reason='reactivated' WHERE device_id=%s AND revoked_at IS NULL", (int(device_row['id']),))
        cursor.execute('INSERT INTO license_v3_sessions(session_id,family_id,license_id,device_id,access_token_hash,refresh_token_hash,scopes_json,access_expires_at,refresh_expires_at,token_version,created_at,last_seen_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,1,UTC_TIMESTAMP(),UTC_TIMESTAMP())', (session_id, family_id, int(license_row['id']), int(device_row['id']), token_hash(config, access), token_hash(config, refresh), json.dumps(scopes_value, separators=(',', ':')), access_exp.strftime('%Y-%m-%d %H:%M:%S'), refresh_exp.strftime('%Y-%m-%d %H:%M:%S')))
    return {'session_id': session_id, 'family_id': family_id, 'access_token': access, 'refresh_token': refresh, 'access_expires_at': access_exp.strftime('%Y-%m-%d %H:%M:%S'), 'refresh_expires_at': refresh_exp.strftime('%Y-%m-%d %H:%M:%S'), 'token_version': 1, 'scopes': scopes_value, **_session_timing(access_exp, refresh_exp, now)}

@legacy_compatible(callback_index=1, request_index=0)
def activate(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        _require_post(request_context, rid)
        data = request_data(request_context)
        config = _config()
        license_key = normalize_license_key(data.get('license_key', ''))
        fingerprint = normalize_device_fingerprint(data.get('device_fingerprint', ''))
        if not is_valid_license_key_format(license_key):
            raise V3Error(400, 'LICENSE_KEY_INVALID', 'license_key の形式が正しくありません。')
        if not is_valid_device_fingerprint(fingerprint):
            raise V3Error(400, 'DEVICE_FINGERPRINT_INVALID', 'device_fingerprint はSHA-256 hex形式で指定してください。')
        try:
            public_key = v3_crypto.normalize_public_key(data.get('device_public_key', ''))
        except ValueError:
            raise
        if len(str(config['key_pepper']).strip()) < 32:
            raise RuntimeError('key_pepper must be a random secret of at least 32 characters.')
        if len(str(config['token_secret']).strip()) < 32:
            raise RuntimeError('token_secret must be a random secret of at least 32 characters.')
        challenge_id = str(data.get('challenge_id', '')).strip().lower()
        nonce = str(data.get('nonce', '')).strip()
        signature = str(data.get('signature', '')).strip()
        connection = database.connect()
        _require_v3_schema(connection)
        _assert_write_fence(connection)
        connection.begin()
        _consume_challenge(connection, 'activate', challenge_id, nonce, public_key, signature)
        license_row = _license_by_key(connection, license_key_hash(config, license_key))
        if license_row is None:
            raise RuntimeError('license_not_found')
        license_row = _lock_license(connection, int(license_row['id']))
        if license_row is None:
            raise RuntimeError('license_not_found')
        resolved_product = _resolve_product(connection, license_row, data.get('product_code', ''))
        license_row = _start_evaluation(connection, license_row)
        _active_license(license_row)
        fingerprint_hash = device_hash(config, fingerprint)
        _guard_capacity(connection, license_row, fingerprint_hash)
        device = _upsert_device(connection, license_row, fingerprint_hash, public_key, data.get('device_label', ''), data.get('app_version', ''))
        session = _issue_session(connection, license_row, device)
        with connection.cursor() as cursor:
            cursor.execute('UPDATE licenses SET last_activated_at=UTC_TIMESTAMP(),last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(license_row['id']),))
        connection.commit()
        _record_product_usage(connection, license_row, 'license_v3.activate', 200, rid, request_context)
        return _reply(200, {'message': 'License API v3 Beta device-bound session issued.', 'license': _license_payload(license_row), 'product_code': resolved_product, 'device': {'device_id': int(device['id']), 'device_ref': device_reference(fingerprint_hash), 'key_thumbprint': public_key['thumbprint'], 'key_algorithm': public_key['algorithm']}, 'session': session}, rid)
    except RequestError:
        if connection:
            _rollback_connection(connection)
        return _error(400, 'INVALID_REQUEST', 'リクエスト形式が正しくありません。', rid)
    except database.DatabaseConfigurationError:
        if connection:
            _rollback_connection(connection)
        return _error(503, 'SERVICE_UNAVAILABLE', 'テストDBを利用できません。', rid)
    except Exception as exc:
        if connection:
            _rollback_connection(connection)
        return _error_response(exc, rid)
    finally:
        if connection:
            _close_connection(connection)

@legacy_compatible(callback_index=None, request_index=5)
def _record_product_usage(connection, license_row, operation, status_code, rid, request_context):
    tenant_id = int(license_row.get('tenant_id') or 0)
    if tenant_id < 1:
        return
    ip_hash = hashlib.sha256(str(request_context.get('client_address', '0.0.0.0')).encode('utf-8')).hexdigest()
    try:
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO tenant_api_usage(tenant_id,client_id,operation,status_code,request_id,ip_hash) VALUES(%s,0,%s,%s,%s,%s)', (tenant_id, operation[:64], status_code, rid, ip_hash))
        connection.commit()
    except Exception:
        _rollback_connection(connection)

@legacy_compatible(callback_index=1, request_index=0)
def reauth(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        _require_post(request_context, rid)
        data = request_data(request_context)
        token = _bearer(request_context, data)
        if not token:
            raise V3Error(401, 'ACCESS_TOKEN_REQUIRED', 'access_token が必要です。')
        connection = database.connect()
        _require_v3_schema(connection)
        _assert_write_fence(connection)
        connection.begin()
        session = _load_session(connection, token, 'access', True)
        if not session:
            raise V3Error(401, 'SESSION_NOT_FOUND', 'セッションが見つかりません。')
        _session_active(session, 'access')
        public_key = v3_crypto.normalize_public_key(session['public_key_pem'])
        _consume_challenge(connection, 'reauth', data.get('challenge_id', ''), data.get('nonce', ''), public_key, data.get('signature', ''))
        new_session = _rotate_session(connection, session)
        connection.commit()
        return _reply(200, {'message': 'Fresh device-key reauthentication succeeded.', 'session': new_session}, rid)
    except RequestError:
        if connection:
            _rollback_connection(connection)
        return _error(400, 'INVALID_REQUEST', 'リクエスト形式が正しくありません。', rid)
    except database.DatabaseConfigurationError:
        return _error(503, 'SERVICE_UNAVAILABLE', 'テストDBを利用できません。', rid)
    except Exception as exc:
        if connection:
            _rollback_connection(connection)
        return _error_response(exc, rid)
    finally:
        if connection:
            _close_connection(connection)

def _rotate_session(connection, session):
    config = _config()
    old_hash = str(session['refresh_token_hash'])
    with connection.cursor() as cursor:
        cursor.execute('INSERT IGNORE INTO license_v3_refresh_history(token_hash,session_id,family_id,expires_at,used_at) VALUES(%s,%s,%s,%s,UTC_TIMESTAMP())', (old_hash, str(session['session_id']), str(session['family_id']), session['refresh_expires_at']))
    now = datetime.now(timezone.utc)
    access_exp = now + timedelta(seconds=900)
    refresh_exp = now + timedelta(days=30)
    license_exp = session.get('expires_at')
    if license_exp:
        license_exp = _as_utc(license_exp)
        access_exp = min(access_exp, license_exp)
        refresh_exp = min(refresh_exp, license_exp)
    access, refresh = (random_token(32), random_token(48))
    with connection.cursor() as cursor:
        cursor.execute('UPDATE license_v3_sessions SET access_token_hash=%s,refresh_token_hash=%s,access_expires_at=%s,refresh_expires_at=%s,token_version=token_version+1,last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (token_hash(config, access), token_hash(config, refresh), access_exp.strftime('%Y-%m-%d %H:%M:%S'), refresh_exp.strftime('%Y-%m-%d %H:%M:%S'), int(session['id'])))
    try:
        scopes_value = json.loads(session.get('scopes_json') or '[]')
    except (TypeError, ValueError):
        scopes_value = []
    return {'session_id': str(session['session_id']), 'family_id': str(session['family_id']), 'access_token': access, 'refresh_token': refresh, 'access_expires_at': access_exp.strftime('%Y-%m-%d %H:%M:%S'), 'refresh_expires_at': refresh_exp.strftime('%Y-%m-%d %H:%M:%S'), 'token_version': int(session['token_version']) + 1, 'scopes': scopes_value, **_session_timing(access_exp, refresh_exp, now)}

@legacy_compatible(callback_index=None, request_index=0)
def _bearer(request_context, data):
    auth = str(request_context.get('header:authorization', '')).strip()
    match = re.match('^Bearer\\s+(.+)$', auth, re.I)
    return match.group(1).strip() if match else str(data.get('access_token', '')).strip()

@legacy_compatible(callback_index=1, request_index=0)
def session_endpoint(request_context, action):
    rid = uuid.uuid4().hex[:16]
    try:
        _require_post(request_context, rid)
        data = request_data(request_context)
        token = _bearer(request_context, data)
        token_kind = 'refresh' if action == 'refresh' else 'access'
        if action == 'refresh':
            token = str(data.get('refresh_token', '')).strip()
        if not token:
            if action == 'refresh':
                raise V3Error(401, 'REFRESH_TOKEN_REQUIRED', 'refresh_token が必要です。')
            raise V3Error(401, 'ACCESS_TOKEN_REQUIRED', 'access_token が必要です。')
        connection = database.connect()
        try:
            _require_v3_schema(connection)
            _assert_write_fence(connection)
            if action == 'refresh':
                connection.begin()
            session = _load_session(connection, token, token_kind, action == 'refresh')
            if not session:
                if action == 'refresh':
                    token_hash_value = token_hash(_config(), token)
                    with connection.cursor() as cursor:
                        cursor.execute('SELECT family_id FROM license_v3_refresh_history WHERE token_hash=%s AND expires_at>UTC_TIMESTAMP() LIMIT 1', (token_hash_value,))
                        history = cursor.fetchone()
                    if history:
                        family_id = str(history['family_id'])
                        _revoke_session_family(connection, family_id, 'refresh_reuse_detected')
                        connection.commit()
                        raise V3Error(401, 'REFRESH_REUSE_DETECTED', '使用済みrefresh tokenが再利用されたためsession familyを失効しました。', {'family_id': family_id})
                raise V3Error(401, 'SESSION_NOT_FOUND', 'セッションが見つかりません。')
            _session_active(session, token_kind)
            if action in ('verify', 'introspect', 'revoke', 'refresh', 'offline-ticket'):
                _verify_pop(connection, session, 'offline-ticket' if action == 'offline-ticket' else action, data)
            if action == 'refresh':
                new_session = _rotate_session(connection, session)
                connection.commit()
                return _reply(200, {'message': 'Tokens rotated.', 'session': new_session}, rid)
            if action == 'verify':
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE license_v3_sessions SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(session['id']),))
                    cursor.execute('UPDATE license_v3_devices SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(session['device_id']),))
                license_row = _license_row(connection, int(session['license_id']))
                connection.commit()
                return _reply(200, {'valid': True, 'session': {'session_id': session['session_id'], 'family_id': session['family_id'], 'token_version': int(session['token_version']), 'scopes': _json_list(session.get('scopes_json')), 'access_expires_at': session['access_expires_at']}, 'device': {'device_ref': device_reference(session['device_hash']), 'key_thumbprint': session['key_thumbprint']}, 'license': _license_payload(license_row) if license_row else None}, rid)
            if action == 'introspect':
                connection.commit()
                session_payload = {key: session[key] for key in ('session_id', 'family_id', 'created_at', 'last_seen_at', 'access_expires_at', 'refresh_expires_at')}
                session_payload.update({'token_version': int(session['token_version']), 'scopes': _json_list(session.get('scopes_json'))})
                return _reply(200, {'active': True, 'session': session_payload, 'device': {'device_ref': device_reference(session['device_hash']), 'key_thumbprint': session['key_thumbprint'], 'key_algorithm': session['key_algorithm']}}, rid)
            if action == 'revoke':
                scope = 'family' if str(data.get('scope', 'session')).strip().lower() == 'family' else 'session'
                if scope == 'family':
                    affected = _revoke_session_family(connection, str(session['family_id']), 'client_family_revoke')
                else:
                    with connection.cursor() as cursor:
                        cursor.execute("UPDATE license_v3_sessions SET revoked_at=UTC_TIMESTAMP(),revoke_reason='client_revoke' WHERE id=%s AND revoked_at IS NULL", (int(session['id']),))
                        affected = cursor.rowcount
                        cursor.execute('UPDATE license_v3_offline_tickets SET revoked_at=UTC_TIMESTAMP() WHERE session_id=%s AND revoked_at IS NULL', (str(session['session_id']),))
                connection.commit()
                return _reply(200, {'revoked': True, 'scope': scope, 'affected_sessions': affected}, rid)
            if action == 'offline-ticket':
                ticket = _offline_ticket(connection, session, data.get('hours', 24))
                connection.commit()
                return _reply(200, {'offline_ticket': ticket}, rid)
        finally:
            _close_connection(connection)
    except RequestError:
        return _error(400, 'INVALID_REQUEST', 'リクエスト形式が正しくありません。', rid)
    except database.DatabaseConfigurationError:
        return _error(503, 'SERVICE_UNAVAILABLE', 'テストDBを利用できません。', rid)
    except Exception as exc:
        return _error_response(exc, rid)

def _json_list(raw):
    try:
        value = json.loads(raw or '[]')
        return value if isinstance(value, list) else []
    except (TypeError, ValueError):
        return []

def _license_row(connection, license_id):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM licenses WHERE id=%s AND deleted_at IS NULL LIMIT 1', (license_id,))
        return cursor.fetchone()

def _license_payload(license_row):
    config = _config()
    return {'license_id': int(license_row.get('id') or 0), 'tenant_id': int(license_row.get('tenant_id') or 1), 'product_id': product_id(config, int(license_row.get('id') or 0)), 'label': license_row.get('label'), 'active': int(license_row.get('active') or 0), 'expires_at': _iso_value(license_row.get('expires_at')), 'revoked_at': _iso_value(license_row.get('revoked_at')), 'max_devices': int(license_row.get('max_devices') or 1), 'license_mode': 'evaluation' if license_row.get('evaluation_days') is not None else 'volume' if int(license_row.get('max_devices') or 1) > 1 else 'single', 'evaluation_days': int(license_row['evaluation_days']) if license_row.get('evaluation_days') is not None else None, 'evaluation_started_at': _iso_value(license_row.get('evaluation_started_at')), 'last_activated_at': _iso_value(license_row.get('last_activated_at')), 'last_seen_at': _iso_value(license_row.get('last_seen_at'))}

def _iso_value(value):
    return value.isoformat(sep=' ') if isinstance(value, datetime) else value

def _offline_ticket(connection, session, hours):
    config = _config()
    material = v3_crypto.offline_signing_material(config)
    try:
        hours = max(1, min(72, int(hours)))
    except (TypeError, ValueError):
        hours = 24
    now = int(time.time())
    license_exp = _as_utc(session['expires_at']).timestamp() if session.get('expires_at') else now + hours * 3600
    expires = min(now + hours * 3600, int(license_exp))
    if expires <= now:
        raise RuntimeError('license_expired')
    ticket_id = os.urandom(16).hex()
    payload = {'v': 3, 'ticket_id': ticket_id, 'license_id': int(session['license_id']), 'product_id': int(session.get('product_id') or 0), 'device_key_thumbprint': str(session['key_thumbprint']), 'session_id': str(session['session_id']), 'offline_epoch': int(session.get('offline_epoch') or 1), 'iat': now, 'exp': expires, 'kid': material['kid']}
    payload_json = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
    body = v3_crypto.b64url_encode(payload_json.encode('utf-8'))
    signature = v3_crypto.b64url_encode(material['private_key'].sign(body.encode('ascii')))
    ticket = 'v3o.' + body + '.' + signature
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO license_v3_offline_tickets(ticket_id,license_id,device_id,session_id,kid,payload_hash,expires_at,created_at) VALUES(%s,%s,%s,%s,%s,%s,FROM_UNIXTIME(%s),UTC_TIMESTAMP())', (ticket_id, int(session['license_id']), int(session['device_id']), str(session['session_id']), material['kid'], hashlib.sha256(body.encode('ascii')).hexdigest(), expires))
    return {'ticket': ticket, 'ticket_id': ticket_id, 'algorithm': material['algorithm'], 'kid': material['kid'], 'expires_at': datetime.fromtimestamp(expires, timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), 'max_offline_hours': hours}

def _issue_challenge(connection, purpose, public_key, ip_hash):
    challenge_id = os.urandom(16).hex()
    nonce = v3_crypto.b64url_encode(os.urandom(32))
    expires = datetime.now(timezone.utc) + timedelta(seconds=300)
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM license_v3_challenges WHERE expires_at < UTC_TIMESTAMP() OR consumed_at < (UTC_TIMESTAMP() - INTERVAL 1 DAY)')
        cursor.execute('INSERT INTO license_v3_challenges (challenge_id,purpose,nonce_hash,device_key_thumbprint,ip_hash,expires_at) VALUES(%s,%s,%s,%s,%s,%s)', (challenge_id, purpose, hashlib.sha256(nonce.encode('ascii')).hexdigest(), public_key['thumbprint'], ip_hash, expires.strftime('%Y-%m-%d %H:%M:%S')))
    return {'challenge_id': challenge_id, 'nonce': nonce, 'purpose': purpose, 'expires_at': expires.strftime('%Y-%m-%d %H:%M:%S'), 'device_key_thumbprint': public_key['thumbprint'], 'signature_algorithm': public_key['algorithm']}

@legacy_compatible(callback_index=1, request_index=0)
def challenge(request_context):
    rid = uuid.uuid4().hex[:16]
    if request_context.get('method', '') != 'POST':
        return _method_error(rid, 'POST')
    try:
        data = request_data(request_context)
        purpose = str(data.get('purpose', 'activate')).strip().lower()
        if purpose not in ('activate', 'reauth'):
            raise ValueError('challenge_purpose_invalid')
        public_key = v3_crypto.normalize_public_key(data.get('device_public_key', ''))
    except RequestError:
        return _error(400, 'INVALID_REQUEST', 'リクエスト形式が正しくありません。', rid)
    except ValueError as exc:
        code = str(exc)
        mapping = {'device_public_key_invalid': ('DEVICE_PUBLIC_KEY_INVALID', 400), 'device_public_key_too_weak': ('DEVICE_PUBLIC_KEY_TOO_WEAK', 400), 'device_public_key_curve_unsupported': ('DEVICE_KEY_CURVE_UNSUPPORTED', 400), 'device_public_key_type_unsupported': ('DEVICE_KEY_TYPE_UNSUPPORTED', 400), 'challenge_purpose_invalid': ('CHALLENGE_PURPOSE_INVALID', 400)}
        public_code, status_code = mapping.get(code, ('V3_REQUEST_FAILED', 400))
        return _error(status_code, public_code, code, rid)
    try:
        connection = database.connect()
    except database.DatabaseConfigurationError:
        return _error(503, 'SERVICE_UNAVAILABLE', 'テストDBを利用できません。', rid)
    try:
        _require_v3_schema(connection)
        _assert_write_fence(connection)
        ip = str(request_context.get('client_address', '0.0.0.0'))
        ip_hash = hashlib.sha256(ip.encode('utf-8')).hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS n FROM auth_attempts WHERE action=%s AND subject_type=%s AND subject_hash=%s AND attempted_at >= (UTC_TIMESTAMP() - INTERVAL 900 SECOND)', ('v3_challenge', 'ip', ip_hash))
            if int(cursor.fetchone()['n']) >= 60:
                _rollback_connection(connection)
                return _error(429, 'RATE_LIMITED', '試行回数が多すぎます。', rid)
            result = _issue_challenge(connection, purpose, public_key, ip_hash)
            cursor.execute('INSERT INTO auth_attempts(ip_hash,action,subject_type,subject_hash,success,error_code,attempted_at) VALUES(%s,%s,%s,%s,1,%s,UTC_TIMESTAMP())', (ip_hash, 'v3_challenge', 'ip', ip_hash, 'ok'))
        connection.commit()
        return _reply(200, {'challenge': result}, rid)
    except RuntimeError as exc:
        _rollback_connection(connection)
        if str(exc) == 'schema_missing':
            return _error(503, 'V3_MIGRATION_REQUIRED', 'License API v3 Beta のDB migrationが未適用です。', rid, {'required_migration': '027_license_api_v3_beta'})
        return _error(503, 'SERVICE_UNAVAILABLE', 'サービスを利用できません。', rid)
    except Exception:
        _rollback_connection(connection)
        return _error(503, 'SERVICE_UNAVAILABLE', 'サービスを利用できません。', rid)
    finally:
        _close_connection(connection)
