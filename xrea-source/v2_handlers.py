"""Python implementations of License API v2 routes with isolated DB access."""
from native_http import make_response, add_headers, legacy_compatible
import hashlib
import hmac
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
import audit
import database
from core import ConfigurationError, device_hash, device_reference, hash_secret, key_pepper, license_id_from_product_id, license_key_hash, offline_lookup, offline_secret, offline_secret_encrypt, product_id, token_secret, _php_trim, _ASCII_UPPER, normalize_device_fingerprint, normalize_license_key, normalize_text, normalize_app_version, is_valid_license_key_format, is_valid_device_fingerprint, first_non_empty, token_hash, device_display_label, parse_utc_datetime, random_token
from http_utils import RequestError, v2_response, request_data
from v3_handlers import _assert_write_fence
from migration_config import secret_value
KEY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
ACCESS_TTL = 43200
REFRESH_TTL = 2592000

class V2Error(Exception):

    def __init__(self, status, payload):
        super().__init__(str(payload.get('error', 'request_failed')))
        self.status = status
        self.payload = payload

def _record_auth_attempt(connection, ip_hash, action, subject_type, subject_hash, success, error_code=None):
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO auth_attempts(ip_hash,action,subject_type,subject_hash,success,error_code,attempted_at) VALUES(%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP())', (ip_hash, action, subject_type, subject_hash, 1 if success else 0, error_code))

def _clear_auth_attempts(connection, action, subject_type, subject_hash):
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM auth_attempts WHERE action=%s AND subject_type=%s AND subject_hash=%s', (action, subject_type, subject_hash))

def _license_payload(config, license_row, device_row=None):
    evaluation_days = license_row.get('evaluation_days')
    payload = {'license_id': int(license_row.get('id') or 0), 'tenant_id': int(license_row.get('tenant_id') or 1), 'product_id': product_id(config, int(license_row.get('id') or 0)), 'label': license_row.get('label'), 'active': int(license_row.get('active') or 0), 'expires_at': license_row.get('expires_at'), 'revoked_at': license_row.get('revoked_at'), 'max_devices': int(license_row.get('max_devices') or 1), 'license_mode': 'evaluation' if evaluation_days is not None else 'volume' if int(license_row.get('max_devices') or 1) > 1 else 'single', 'evaluation_days': int(evaluation_days) if evaluation_days is not None else None, 'evaluation_started_at': license_row.get('evaluation_started_at'), 'last_activated_at': license_row.get('last_activated_at'), 'last_seen_at': license_row.get('last_seen_at')}
    if device_row is not None:
        device_hash_value = str(device_row.get('device_hash') or '')
        payload['device'] = {'device_id': int(device_row.get('id') or 0), 'device_ref': device_reference(device_hash_value), 'display_label': device_display_label(str(device_row.get('device_label') or ''), device_hash_value), 'device_label': device_row.get('device_label'), 'last_seen_at': device_row.get('last_seen_at'), 'first_activated_at': device_row.get('first_activated_at'), 'revoked_at': device_row.get('revoked_at'), 'access_expires_at': device_row.get('access_expires_at'), 'refresh_expires_at': device_row.get('refresh_expires_at'), 'token_version': int(device_row.get('token_version') or 1)}
    return payload

@legacy_compatible(callback_index=1, request_index=0)
def _v2_activate(request_context, rid):
    if _non_writable_role():
        return v2_response(503, {'success': False, 'error': 'server_not_writable'}, rid)
    connection = None
    ip_hash = ''
    license_subject = ''
    device_subject = ''
    transaction_open = False
    try:
        data = request_data(request_context)
        action = _php_trim(data.get('api_action', data.get('action', 'activate'))).lower()
        action = {'license_activate': 'activate', 'activation': 'activate', 'validate': 'verify', 'check': 'verify', 'renew_session': 'refresh', 'logout': 'deactivate', 'revoke': 'deactivate'}.get(action, action)
        if action == 'verify':
            return _v2_verify(request_context, rid, data)
        if action == 'refresh':
            return _v2_refresh(request_context, rid, data)
        if action == 'deactivate':
            return _v2_deactivate(request_context, rid, data)
        if action == 'status':
            return _v2_status(request_context, rid, data)
        if action == 'record_usage':
            return _v2_record_usage(request_context, rid, data)
        if action != 'activate':
            return v2_response(400, {'success': False, 'error': '不明な api_action です。'}, rid)
        license_key = normalize_license_key(first_non_empty(data, ('license_key', 'product_key', 'key')))
        fingerprint = normalize_device_fingerprint(first_non_empty(data, ('device_fingerprint', 'device_id', 'device', 'installation_id')))
        label = normalize_text(_php_trim(data.get('device_label', data.get('device_name', ''))))
        app_version = normalize_app_version(_php_trim(data.get('app_version', data.get('client_version', ''))))
        product_code = _php_trim(data.get('product_code', data.get('product', ''))).lower()
        if fingerprint and (not is_valid_device_fingerprint(fingerprint)):
            raise V2Error(400, {'success': False, 'error': 'device_fingerprint の形式が正しくありません。'})
        if not license_key:
            raise V2Error(400, {'success': False, 'error': 'license_key が必要です。'})
        if not is_valid_license_key_format(license_key):
            raise V2Error(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'})
        if not fingerprint:
            raise V2Error(400, {'success': False, 'error': 'device_fingerprint が必要です。'})
        config = _runtime_config()
        key_pepper(config)
        token_secret(config)
        ip_hash = hash_secret(_php_trim(request_context.get('client_address', '0.0.0.0')))
        license_subject = hash_secret(license_key)
        device_subject = hash_secret(fingerprint)
        connection = database.connect()
        _assert_write_fence(connection)
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS n FROM auth_attempts WHERE ip_hash=%s AND attempted_at >= (UTC_TIMESTAMP() - INTERVAL 15 MINUTE)', (ip_hash,))
            if int(cursor.fetchone()['n']) >= 30:
                _record_auth_attempt(connection, ip_hash, 'generic', 'ip', ip_hash, False, 'rate_limited')
                connection.commit()
                raise V2Error(429, {'success': False, 'error': '試行回数が多すぎます。しばらくしてから再試行してください。'})
        key_hash = license_key_hash(config, license_key)
        recovery_secret = offline_secret(license_key)
        recovery_lookup = offline_lookup(recovery_secret)
        with connection.cursor() as cursor:
            cursor.execute('SELECT id FROM licenses WHERE offline_lookup=%s AND deleted_at IS NULL LIMIT 1', (recovery_lookup,))
            recovery_row = cursor.fetchone()
        for subject_type, subject_hash in (('license_key', license_subject), ('device_fingerprint', device_subject)):
            if not recovery_row and _attempt_count(connection, 'activate', subject_type, subject_hash) >= 5:
                _record_auth_attempt(connection, ip_hash, 'activate', subject_type, subject_hash, False, 'locked')
                connection.commit()
                raise V2Error(429, {'success': False, 'error': '試行回数が多すぎます。しばらくしてから再試行してください。'})
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM licenses WHERE key_hash=%s AND deleted_at IS NULL LIMIT 1', (key_hash,))
            license_row = cursor.fetchone()
        if license_row is None and recovery_row:
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM licenses WHERE id=%s AND offline_lookup=%s AND deleted_at IS NULL LIMIT 1 FOR UPDATE', (int(recovery_row['id']), recovery_lookup))
                recovered = cursor.fetchone()
                if recovered:
                    encrypted = offline_secret_encrypt(config, recovery_secret)
                    cursor.execute('UPDATE licenses SET key_hash=%s,offline_secret_enc=%s WHERE id=%s', (key_hash, encrypted, int(recovered['id'])))
                    recovered['key_hash'] = key_hash
                    recovered['offline_secret_enc'] = encrypted
                    license_row = recovered
        if license_row is None:
            for subject_type, subject_hash in (('license_key', license_subject), ('device_fingerprint', device_subject)):
                _record_auth_attempt(connection, ip_hash, 'activate', subject_type, subject_hash, False, 'not_found')
            connection.commit()
            raise V2Error(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'})
        connection.begin()
        transaction_open = True
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM licenses WHERE id=%s AND deleted_at IS NULL LIMIT 1 FOR UPDATE', (int(license_row['id']),))
            license_row = cursor.fetchone()
        if not license_row:
            raise V2Error(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'})
        tenant_id = int(license_row.get('tenant_id') or 1)
        resolved_product = product_code
        if tenant_id != 1:
            with connection.cursor() as cursor:
                cursor.execute('SELECT code FROM products WHERE id=%s AND tenant_id=%s AND status="active" LIMIT 1', (int(license_row.get('product_id') or 0), tenant_id))
                resolved_product = str((cursor.fetchone() or {}).get('code') or '').strip().lower()
            if re.fullmatch('[a-z0-9][a-z0-9_-]{1,63}', resolved_product) is None:
                raise V2Error(400, {'success': False, 'error': 'ライセンスに有効な製品が設定されていません。', 'code': 'product_unavailable'})
            if product_code and product_code.lower() != resolved_product:
                raise V2Error(400, {'success': False, 'error': '製品コードとライセンスが一致しません。', 'code': 'product_mismatch', 'expected_product_code': resolved_product, 'product_binding_retryable': True})
            if not product_code and '/api/v2/activate.php' not in request_context.get('path', ''):
                raise V2Error(400, {'success': False, 'error': 'product_code が必要です。', 'code': 'product_code_required', 'expected_product_code': resolved_product, 'product_binding_retryable': True})
        expires = license_row.get('expires_at')
        is_expired = bool(expires and parse_utc_datetime(str(expires)) and (parse_utc_datetime(str(expires)) <= datetime.now(timezone.utc)))
        if int(license_row.get('active') or 0) != 1 or license_row.get('revoked_at') or is_expired:
            if license_row.get('revoked_at'):
                state, message = ('LICENSE_REVOKED', 'このライセンスは失効しています。')
            elif int(license_row.get('active') or 0) != 1:
                state, message = ('LICENSE_INACTIVE', 'このライセンスは無効です。')
            else:
                state, message = ('LICENSE_EXPIRED', 'このライセンスは期限切れです。')
            raise V2Error(400, {'success': False, 'error': message, 'error_code': state})
        if license_row.get('evaluation_days') is not None and (not license_row.get('evaluation_started_at')):
            now = datetime.now(timezone.utc).replace(microsecond=0)
            expiry = now + timedelta(days=max(1, min(3650, int(license_row['evaluation_days']))))
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET evaluation_started_at=%s,expires_at=%s WHERE id=%s AND evaluation_started_at IS NULL', (now.strftime('%Y-%m-%d %H:%M:%S'), expiry.strftime('%Y-%m-%d %H:%M:%S'), int(license_row['id'])))
                cursor.execute('SELECT * FROM licenses WHERE id=%s LIMIT 1 FOR UPDATE', (int(license_row['id']),))
                license_row = cursor.fetchone() or license_row
        if not license_row.get('offline_lookup') or not license_row.get('offline_secret_enc'):
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET offline_lookup=%s,offline_secret_enc=%s WHERE id=%s AND (offline_lookup IS NULL OR offline_secret_enc IS NULL)', (recovery_lookup, offline_secret_encrypt(config, recovery_secret), int(license_row['id'])))
            license_row['offline_lookup'] = recovery_lookup
        fingerprint_hash = device_hash(config, fingerprint)
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM license_devices WHERE license_id=%s AND device_hash=%s LIMIT 1', (int(license_row['id']), fingerprint_hash))
            device_row = cursor.fetchone()
            cursor.execute('SELECT COUNT(*) AS cnt FROM license_devices WHERE license_id=%s AND revoked_at IS NULL AND refresh_expires_at>UTC_TIMESTAMP()', (int(license_row['id']),))
            active_count = int(cursor.fetchone()['cnt'])
        if not (device_row and (not device_row.get('revoked_at'))) and active_count >= max(1, int(license_row.get('max_devices') or 1)):
            raise V2Error(409, {'success': False, 'error': 'このライセンスの利用台数上限に達しています。', 'error_code': 'DEVICE_LIMIT_REACHED'})
        now = datetime.now(timezone.utc).replace(microsecond=0)
        access_expiry, refresh_expiry = (now + timedelta(seconds=ACCESS_TTL), now + timedelta(seconds=REFRESH_TTL))
        license_expiry = parse_utc_datetime(str(license_row.get('expires_at') or ''))
        if license_expiry:
            access_expiry = min(access_expiry, license_expiry)
            refresh_expiry = min(refresh_expiry, license_expiry)
        access_token, refresh_token = (random_token(), random_token(48))
        final_label = device_display_label(label, fingerprint_hash)
        session = (int(license_row['id']), fingerprint_hash, final_label, token_hash(config, access_token), token_hash(config, refresh_token), access_expiry.strftime('%Y-%m-%d %H:%M:%S'), refresh_expiry.strftime('%Y-%m-%d %H:%M:%S'), ip_hash, app_version or None)
        with connection.cursor() as cursor:
            if device_row:
                cursor.execute('UPDATE license_devices SET device_label=%s,access_token_hash=%s,refresh_token_hash=%s,access_expires_at=%s,refresh_expires_at=%s,revoked_at=NULL,last_seen_at=UTC_TIMESTAMP(),last_ip_hash=%s,app_version=%s,token_version=token_version+1 WHERE id=%s', (final_label, session[3], session[4], session[5], session[6], ip_hash, app_version or None, int(device_row['id'])))
            else:
                cursor.execute('INSERT INTO license_devices(license_id,device_hash,device_label,access_token_hash,refresh_token_hash,access_expires_at,refresh_expires_at,first_activated_at,last_seen_at,revoked_at,last_ip_hash,app_version,token_version) VALUES(%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP(),NULL,%s,%s,1)', (int(license_row['id']), fingerprint_hash, final_label, session[3], session[4], session[5], session[6], ip_hash, app_version or None))
            cursor.execute('UPDATE licenses SET last_activated_at=UTC_TIMESTAMP(),last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(license_row['id']),))
            cursor.execute('SELECT * FROM license_devices WHERE license_id=%s AND device_hash=%s LIMIT 1', (int(license_row['id']), fingerprint_hash))
            device_row = cursor.fetchone() or {'device_hash': fingerprint_hash, 'device_label': final_label, 'access_expires_at': session[5], 'refresh_expires_at': session[6]}
        connection.commit()
        transaction_open = False
        _clear_auth_attempts(connection, 'activate', 'license_key', license_subject)
        _clear_auth_attempts(connection, 'activate', 'device_fingerprint', device_subject)
        _record_auth_attempt(connection, ip_hash, 'activate', 'license_key', license_subject, True, 'ok')
        _record_auth_attempt(connection, ip_hash, 'activate', 'device_fingerprint', device_subject, True, 'ok')
        connection.commit()
        try:
            tenant = int(license_row.get('tenant_id') or 0)
            if tenant > 0:
                with connection.cursor() as cursor:
                    cursor.execute('INSERT INTO tenant_api_usage(tenant_id,client_id,operation,status_code,request_id,ip_hash) VALUES(%s,0,%s,200,%s,%s)', (tenant, 'product_key.activate', rid, hashlib.sha256(str(request_context.get('client_address', '0.0.0.0')).encode()).hexdigest()))
        except Exception:
            connection.rollback()
        else:
            connection.commit()
        payload = {'success': True, 'api_version': '2.0', 'message': 'セッションを発行しました。', 'license': _license_payload(config, license_row, device_row), 'session': {'access_token': access_token, 'refresh_token': refresh_token, 'access_expires_at': session[5], 'refresh_expires_at': session[6], 'device_ref': device_reference(fingerprint_hash), 'device_label': final_label, 'app_version': app_version or None}}
        if tenant != 1 and (not product_code):
            return v2_response(200, payload, rid)
        payload['license']['product_code'] = resolved_product
        return v2_response(200, payload, rid)
    except V2Error as exc:
        if connection and transaction_open:
            connection.rollback()
            if license_subject and device_subject and (exc.status not in (429,)):
                try:
                    _record_auth_attempt(connection, ip_hash, 'activate', 'license_key', license_subject, False, 'activation_failed')
                    _record_auth_attempt(connection, ip_hash, 'activate', 'device_fingerprint', device_subject, False, 'activation_failed')
                    connection.commit()
                except Exception:
                    connection.rollback()
        return v2_response(exc.status, exc.payload, rid)
    except RequestError:
        if connection and transaction_open:
            connection.rollback()
        return v2_response(400, {'success': False, 'error': '不正なリクエスト形式です。'}, rid)
    except database.DatabaseConfigurationError:
        if connection and transaction_open:
            connection.rollback()
        return v2_response(503, {'success': False, 'error': 'service_unavailable'}, rid)
    except Exception:
        if connection and transaction_open:
            connection.rollback()
        if connection and ip_hash:
            try:
                for subject_type, subject_hash in (('license_key', license_subject), ('device_fingerprint', device_subject)):
                    if subject_hash:
                        _record_auth_attempt(connection, ip_hash, 'activate', subject_type, subject_hash, False, 'activation_failed')
                connection.commit()
            except Exception:
                connection.rollback()
        return v2_response(503, {'success': False, 'error': 'activation_failed'}, rid)
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def _v2_verify(request_context, rid, data):
    config = _runtime_config()
    try:
        access_token = _php_trim(data.get('access_token', ''))
        fingerprint = normalize_device_fingerprint(first_non_empty(data, ('device_fingerprint', 'device_id', 'device', 'installation_id')))
        if not access_token:
            raise V2Error(400, {'success': False, 'error': 'access_token が必要です。'})
        if not fingerprint:
            raise V2Error(400, {'success': False, 'error': 'device_fingerprint が必要です。'})
        if not is_valid_device_fingerprint(fingerprint):
            raise V2Error(400, {'success': False, 'error': 'device_fingerprint の形式が正しくありません。'})
        key_pepper(config)
        token_secret(config)
        ip_hash = hash_secret(_php_trim(request_context.get('client_address', '0.0.0.0')))
        connection = database.connect()
        _assert_write_fence(connection)
        token_digest = token_hash(config, access_token)
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM license_devices WHERE access_token_hash=%s LIMIT 1', (token_digest,))
            device_row = cursor.fetchone()
        if not device_row:
            raise V2Error(400, {'success': False, 'error': 'セッションが見つかりません。'})
        expected_hash = device_hash(config, fingerprint)
        if not hmac.compare_digest(str(device_row.get('device_hash') or ''), expected_hash):
            raise V2Error(400, {'success': False, 'error': '端末情報が一致しません。'})
        if device_row.get('revoked_at'):
            raise V2Error(400, {'success': False, 'error': 'セッションの有効期限が切れています。'})
        for field in ('access_expires_at', 'refresh_expires_at'):
            expiry = parse_utc_datetime(str(device_row.get(field) or ''))
            if expiry and expiry < datetime.now(timezone.utc):
                raise V2Error(400, {'success': False, 'error': 'セッションの有効期限が切れています。'})
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM licenses WHERE id=%s AND deleted_at IS NULL LIMIT 1', (int(device_row.get('license_id') or 0),))
            license_row = cursor.fetchone()
        if not license_row:
            raise V2Error(400, {'success': False, 'error': 'ライセンスが見つかりません。'})
        expires = parse_utc_datetime(str(license_row.get('expires_at') or ''))
        if int(license_row.get('active') or 0) != 1 or license_row.get('revoked_at') or (expires and expires <= datetime.now(timezone.utc)):
            if license_row.get('revoked_at'):
                message = 'このライセンスは失効しています。'
            elif int(license_row.get('active') or 0) != 1:
                message = 'このライセンスは無効です。'
            else:
                message = 'このライセンスは期限切れです。'
            raise V2Error(400, {'success': False, 'error': message})
        with connection.cursor() as cursor:
            cursor.execute('UPDATE license_devices SET last_seen_at=UTC_TIMESTAMP(),last_ip_hash=%s WHERE id=%s', (ip_hash, int(device_row['id'])))
            cursor.execute('UPDATE licenses SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(license_row['id']),))
        connection.commit()
        _record_usage(connection, license_row, 'product_key.verify', 200, rid, request_context)
        return v2_response(200, {'success': True, 'api_version': '2.0', 'message': 'セッションは有効です。', 'license': _license_payload(config, license_row, device_row)}, rid)
    except V2Error as exc:
        return v2_response(exc.status, exc.payload, rid)
    except database.DatabaseConfigurationError:
        return v2_response(503, {'success': False, 'error': 'service_unavailable'}, rid)
    except Exception:
        return v2_response(503, {'success': False, 'error': 'verification_failed'}, rid)
    finally:
        if 'connection' in locals() and connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def _v2_refresh(request_context, rid, data):
    config = _runtime_config()
    connection = None
    try:
        refresh_token = _php_trim(data.get('refresh_token', ''))
        fingerprint = normalize_device_fingerprint(first_non_empty(data, ('device_fingerprint', 'device_id', 'device', 'installation_id')))
        if not refresh_token:
            raise V2Error(400, {'success': False, 'error': 'refresh_token が必要です。'})
        if not fingerprint:
            raise V2Error(400, {'success': False, 'error': 'device_fingerprint が必要です。'})
        if not is_valid_device_fingerprint(fingerprint):
            raise V2Error(400, {'success': False, 'error': 'device_fingerprint の形式が正しくありません。'})
        key_pepper(config)
        token_secret(config)
        ip_hash = hash_secret(_php_trim(request_context.get('client_address', '0.0.0.0')))
        connection = database.connect()
        _assert_write_fence(connection)
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM license_devices WHERE refresh_token_hash=%s LIMIT 1', (token_hash(config, refresh_token),))
            device_row = cursor.fetchone()
        if not device_row:
            raise V2Error(400, {'success': False, 'error': '更新トークンが見つかりません。'})
        expected_hash = device_hash(config, fingerprint)
        if not hmac.compare_digest(str(device_row.get('device_hash') or ''), expected_hash):
            raise V2Error(400, {'success': False, 'error': '端末情報が一致しません。'})
        if device_row.get('revoked_at'):
            raise V2Error(400, {'success': False, 'error': 'セッションの有効期限が切れています。'})
        now = datetime.now(timezone.utc)
        for field in ('access_expires_at', 'refresh_expires_at'):
            expiry = parse_utc_datetime(str(device_row.get(field) or ''))
            if expiry and expiry < now:
                raise V2Error(400, {'success': False, 'error': 'セッションの有効期限が切れています。'})
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM licenses WHERE id=%s AND deleted_at IS NULL LIMIT 1', (int(device_row.get('license_id') or 0),))
            license_row = cursor.fetchone()
        if not license_row:
            raise V2Error(400, {'success': False, 'error': 'ライセンスが見つかりません。'})
        license_expiry = parse_utc_datetime(str(license_row.get('expires_at') or ''))
        if int(license_row.get('active') or 0) != 1 or license_row.get('revoked_at') or (license_expiry and license_expiry <= now):
            if license_row.get('revoked_at'):
                message = 'このライセンスは失効しています。'
            elif int(license_row.get('active') or 0) != 1:
                message = 'このライセンスは無効です。'
            else:
                message = 'このライセンスは期限切れです。'
            raise V2Error(400, {'success': False, 'error': message})
        access_expiry = now.replace(microsecond=0) + timedelta(seconds=ACCESS_TTL)
        refresh_expiry = now.replace(microsecond=0) + timedelta(seconds=REFRESH_TTL)
        if license_expiry:
            access_expiry = min(access_expiry, license_expiry)
            refresh_expiry = min(refresh_expiry, license_expiry)
        access_token, next_refresh_token = (random_token(), random_token(48))
        access_expiry_text = access_expiry.strftime('%Y-%m-%d %H:%M:%S')
        refresh_expiry_text = refresh_expiry.strftime('%Y-%m-%d %H:%M:%S')
        with connection.cursor() as cursor:
            cursor.execute('UPDATE license_devices SET access_token_hash=%s,refresh_token_hash=%s,access_expires_at=%s,refresh_expires_at=%s,last_seen_at=UTC_TIMESTAMP(),last_ip_hash=%s,token_version=token_version+1 WHERE id=%s', (token_hash(config, access_token), token_hash(config, next_refresh_token), access_expiry_text, refresh_expiry_text, ip_hash, int(device_row['id'])))
            cursor.execute('UPDATE licenses SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(license_row['id']),))
        connection.commit()
        device_payload = dict(device_row)
        device_payload.update({'access_expires_at': access_expiry_text, 'refresh_expires_at': refresh_expiry_text, 'last_seen_at': now.strftime('%Y-%m-%d %H:%M:%S'), 'revoked_at': None})
        _record_usage(connection, license_row, 'product_key.refresh', 200, rid, request_context)
        return v2_response(200, {'success': True, 'api_version': '2.0', 'message': 'セッションを更新しました。', 'license': _license_payload(config, license_row, device_payload), 'session': {'access_token': access_token, 'refresh_token': next_refresh_token, 'access_expires_at': access_expiry_text, 'refresh_expires_at': refresh_expiry_text, 'device_label': device_row.get('device_label'), 'app_version': device_row.get('app_version')}}, rid)
    except V2Error as exc:
        return v2_response(exc.status, exc.payload, rid)
    except database.DatabaseConfigurationError:
        return v2_response(503, {'success': False, 'error': 'service_unavailable'}, rid)
    except Exception:
        return v2_response(503, {'success': False, 'error': 'refresh_failed'}, rid)
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def _v2_deactivate(request_context, rid, data):
    config = _runtime_config()
    connection = None
    transaction_open = False
    try:
        license_key = normalize_license_key(first_non_empty(data, ('license_key', 'product_key', 'key')))
        try:
            device_id = int(data.get('device_id') or 0)
        except (TypeError, ValueError):
            device_id = 0
        refresh_token = _php_trim(data.get('refresh_token', ''))
        fingerprint = normalize_device_fingerprint(first_non_empty(data, ('device_fingerprint', 'device_id', 'device', 'installation_id')))
        key_pepper(config)
        token_secret(config)
        connection = database.connect()
        _assert_write_fence(connection)
        if license_key and device_id > 0:
            if not is_valid_license_key_format(license_key):
                raise V2Error(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'})
            key_hash = license_key_hash(config, license_key)
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM licenses WHERE key_hash=%s AND deleted_at IS NULL LIMIT 1', (key_hash,))
                license_row = cursor.fetchone()
            if not license_row:
                raise V2Error(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'})
            connection.begin()
            transaction_open = True
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM license_devices WHERE id=%s AND license_id=%s LIMIT 1 FOR UPDATE', (device_id, int(license_row['id'])))
                device_row = cursor.fetchone()
                if not device_row:
                    raise V2Error(404, {'success': False, 'error': 'セッションが見つかりません。'})
                cursor.execute('UPDATE license_devices SET revoked_at=UTC_TIMESTAMP(),token_version=token_version+1 WHERE id=%s', (device_id,))
            connection.commit()
            transaction_open = False
        else:
            if not refresh_token:
                raise V2Error(400, {'success': False, 'error': 'refresh_token か device_id / license_key が必要です。'})
            if not fingerprint:
                raise V2Error(400, {'success': False, 'error': 'device_fingerprint が必要です。'})
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM license_devices WHERE refresh_token_hash=%s LIMIT 1', (token_hash(config, refresh_token),))
                device_row = cursor.fetchone()
            if not device_row:
                raise V2Error(404, {'success': False, 'error': 'セッションが見つかりません。'})
            expected_hash = device_hash(config, fingerprint)
            if not hmac.compare_digest(str(device_row.get('device_hash') or ''), expected_hash):
                raise V2Error(400, {'success': False, 'error': '端末情報が一致しません。'})
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM licenses WHERE id=%s AND deleted_at IS NULL LIMIT 1', (int(device_row.get('license_id') or 0),))
                license_row = cursor.fetchone()
                cursor.execute('UPDATE license_devices SET revoked_at=UTC_TIMESTAMP(),token_version=token_version+1 WHERE id=%s', (int(device_row['id']),))
            connection.commit()
        if license_row:
            _record_usage(connection, license_row, 'product_key.deactivate', 200, rid, request_context)
        return v2_response(200, {'success': True, 'api_version': '2.0', 'message': 'セッションを失効しました。'}, rid)
    except V2Error as exc:
        if connection and transaction_open:
            connection.rollback()
        return v2_response(exc.status, exc.payload, rid)
    except database.DatabaseConfigurationError:
        if connection and transaction_open:
            connection.rollback()
        return v2_response(503, {'success': False, 'error': 'service_unavailable'}, rid)
    except Exception:
        if connection and transaction_open:
            connection.rollback()
        return v2_response(503, {'success': False, 'error': 'deactivation_failed'}, rid)
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def _v2_status(request_context, rid, data):
    config = _runtime_config()
    connection = None
    ip_hash = ''
    subject = ''
    try:
        license_key = normalize_license_key(first_non_empty(data, ('license_key', 'product_key', 'key')))
        product_code = _php_trim(data.get('product_code', data.get('product', ''))).lower()
        if not license_key:
            raise V2Error(400, {'success': False, 'error': 'license_key が必要です。'})
        if not is_valid_license_key_format(license_key):
            raise V2Error(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'})
        key_pepper(config)
        token_secret(config)
        ip_hash = hash_secret(_php_trim(request_context.get('client_address', '0.0.0.0')))
        subject = hash_secret(license_key)
        connection = database.connect()
        _assert_write_fence(connection)
        if _attempt_count(connection, 'status', 'license_key', subject) >= 5:
            _record_auth_attempt(connection, ip_hash, 'status', 'license_key', subject, False, 'locked')
            connection.commit()
            raise V2Error(429, {'success': False, 'error': '試行回数が多すぎます。しばらくしてから再試行してください。'})
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM licenses WHERE key_hash=%s AND deleted_at IS NULL LIMIT 1', (license_key_hash(config, license_key),))
            license_row = cursor.fetchone()
        if not license_row:
            _record_auth_attempt(connection, ip_hash, 'status', 'license_key', subject, False, 'not_found')
            connection.commit()
            raise V2Error(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'})
        resolved_product = product_code
        tenant_id = int(license_row.get('tenant_id') or 1)
        if tenant_id != 1:
            with connection.cursor() as cursor:
                cursor.execute('SELECT code FROM products WHERE id=%s AND tenant_id=%s AND status="active" LIMIT 1', (int(license_row.get('product_id') or 0), tenant_id))
                expected = str((cursor.fetchone() or {}).get('code') or '').strip().lower()
            if re.fullmatch('[a-z0-9][a-z0-9_-]{1,63}', expected) is None:
                raise V2Error(400, {'success': False, 'error': 'ライセンスに有効な製品が設定されていません。', 'code': 'product_unavailable'})
            if product_code and product_code != expected:
                raise V2Error(400, {'success': False, 'error': '製品コードとライセンスが一致しません。', 'code': 'product_mismatch', 'expected_product_code': expected, 'product_binding_retryable': True})
            if not product_code and '/api/v2/activate.php' not in request_context.get('path', ''):
                raise V2Error(400, {'success': False, 'error': 'product_code が必要です。', 'code': 'product_code_required', 'expected_product_code': expected, 'product_binding_retryable': True})
            resolved_product = expected
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS n FROM license_devices WHERE license_id=%s AND revoked_at IS NULL AND refresh_expires_at>UTC_TIMESTAMP()', (int(license_row['id']),))
            active_sessions = int(cursor.fetchone()['n'])
        _clear_auth_attempts(connection, 'status', 'license_key', subject)
        _record_auth_attempt(connection, ip_hash, 'status', 'license_key', subject, True, 'ok')
        connection.commit()
        _record_usage(connection, license_row, 'product_key.status', 200, rid, request_context)
        payload = {'success': True, 'api_version': '2.0', 'license': _license_payload(config, license_row), 'active_sessions': active_sessions}
        payload['license']['product_code'] = resolved_product
        return v2_response(200, payload, rid)
    except V2Error as exc:
        return v2_response(exc.status, exc.payload, rid)
    except database.DatabaseConfigurationError:
        return v2_response(503, {'success': False, 'error': 'service_unavailable'}, rid)
    except Exception:
        if connection and ip_hash and subject:
            try:
                _record_auth_attempt(connection, ip_hash, 'status', 'license_key', subject, False, 'status_failed')
                connection.commit()
            except Exception:
                connection.rollback()
        return v2_response(503, {'success': False, 'error': 'status_failed'}, rid)
    finally:
        if connection:
            connection.close()

def _php_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    return _php_trim(value).lower() in ('1', 'true', 'yes', 'on')

@legacy_compatible(callback_index=1, request_index=0)
def _v2_record_usage(request_context, rid, data):
    config = _runtime_config()
    connection = None
    try:
        access_token = _php_trim(data.get('access_token', ''))
        if not access_token:
            raise V2Error(400, {'success': False, 'error': 'access_token が必要です。'})
        operation = _php_trim(data.get('operation', 'mnsl.face_liveness.verify')).lower()
        allowed = {'mnsl.face.verify', 'mnsl.liveness.verify', 'mnsl.face_liveness.verify', 'face.verify', 'liveness.verify', 'face_liveness.verify', 'mnsl.jpki.challenge.issue', 'mnsl.jpki.certificate.parse', 'mnsl.jpki.certificate.validity.verify', 'mnsl.jpki.certificate.chain.verify', 'mnsl.jpki.certificate.revocation.verify', 'mnsl.jpki.user_auth.verify', 'mnsl.jpki.signing_cert.verify', 'mnsl.jpki.signature.verify', 'mnsl.jpki.challenge.verify', 'mnsl.jpki.full.verify', 'mnsl.jpki.binding.create', 'mnsl.jpki.binding.verify', 'mnsl.jpki.binding.refresh', 'mnsl.jpki.binding.revoke', 'mnsl.jpki.binding', 'mnsl.terms.jpki.verify'}
        biometric = {'mnsl.face.verify', 'mnsl.liveness.verify', 'mnsl.face_liveness.verify', 'face.verify', 'liveness.verify', 'face_liveness.verify'}
        payload_hash = _php_trim(data.get('payload_sha256', '')).lower()
        idem_key = _php_trim(data.get('idempotency_key', '')).lower()
        explicit_idempotency = bool(idem_key)
        if not idem_key:
            idem_key = secrets.token_hex(32)
        try:
            frame_count = int(data.get('frame_count') or 0)
        except (TypeError, ValueError):
            frame_count = 0
        try:
            random_actions = int(data.get('random_actions_completed') or 0)
        except (TypeError, ValueError):
            random_actions = 0
        liveness_pass, face_pass = (_php_bool(data.get('liveness_pass', False)), _php_bool(data.get('face_pass', False)))
        if operation not in allowed or re.fullmatch('[0-9a-f]{64}', payload_hash) is None or re.fullmatch('[0-9a-f]{64}', idem_key) is None or (operation in biometric and (frame_count < 1 or random_actions < 0 or (not liveness_pass) or (not face_pass))):
            raise V2Error(400, {'success': False, 'error': 'usage payload が不正です。', 'idempotency_key': '64 lowercase hex characters when supplied', 'allowed_operations': sorted(allowed)})
        key_pepper(config)
        token_secret(config)
        ip_hash = hash_secret(_php_trim(request_context.get('client_address', '0.0.0.0')))
        connection = database.connect()
        _assert_write_fence(connection)
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM license_devices WHERE access_token_hash=%s LIMIT 1', (token_hash(config, access_token),))
            device_row = cursor.fetchone()
        if not device_row:
            raise V2Error(400, {'success': False, 'error': 'セッションが見つかりません。'})
        if device_row.get('revoked_at'):
            raise V2Error(400, {'success': False, 'error': 'セッションの有効期限が切れています。'})
        now = datetime.now(timezone.utc)
        for field in ('access_expires_at', 'refresh_expires_at'):
            expiry = parse_utc_datetime(str(device_row.get(field) or ''))
            if expiry and expiry < now:
                raise V2Error(400, {'success': False, 'error': 'セッションの有効期限が切れています。'})
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM licenses WHERE id=%s AND deleted_at IS NULL LIMIT 1', (int(device_row.get('license_id') or 0),))
            license_row = cursor.fetchone()
        if not license_row:
            raise V2Error(400, {'success': False, 'error': 'ライセンスが見つかりません。'})
        expiry = parse_utc_datetime(str(license_row.get('expires_at') or ''))
        if int(license_row.get('active') or 0) != 1 or license_row.get('revoked_at') or (expiry and expiry <= now):
            raise V2Error(400, {'success': False, 'error': 'ライセンスが有効ではありません。'})
        tenant_id = int(license_row.get('tenant_id') or 1)
        verification_source = _php_trim(data.get('verification_source', ''))[:80]
        fingerprint = hashlib.sha256('|'.join((operation, str(license_row['id']), str(device_row['id']), payload_hash, str(frame_count), str(random_actions), '1' if liveness_pass else '0', '1' if face_pass else '0', verification_source)).encode('utf-8')).hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s', (tenant_id, 'license_usage_v1', idem_key))
            stored_row = cursor.fetchone()
        if stored_row and stored_row.get('response_json'):
            saved = json.loads(stored_row['response_json'])
            if not hmac.compare_digest(str(saved.get('request_fingerprint') or ''), fingerprint):
                raise V2Error(409, {'success': False, 'error': 'idempotency_key_reused_with_different_request'})
            return v2_response(200, saved['response'], rid)
        usage_request_id = secrets.token_hex(16)
        response = {'success': True, 'api_version': '2.0', 'request_id': usage_request_id, 'operation': operation, 'license': _license_payload(config, license_row, device_row)}
        if explicit_idempotency:
            response['idempotent'] = True
        saved_response = json.dumps({'request_fingerprint': fingerprint, 'response': response}, ensure_ascii=False, separators=(',', ':'))
        try:
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('INSERT INTO tenant_api_usage(tenant_id,client_id,operation,status_code,request_id,ip_hash) VALUES(%s,0,%s,200,%s,%s)', (tenant_id, operation[:64], usage_request_id, ip_hash))
                cursor.execute('UPDATE license_devices SET last_seen_at=UTC_TIMESTAMP(),last_ip_hash=%s WHERE id=%s', (ip_hash, int(device_row['id'])))
                cursor.execute('UPDATE licenses SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(license_row['id']),))
                cursor.execute('INSERT INTO idempotency_keys(tenant_id,operation,request_key,response_json) VALUES(%s,%s,%s,%s)', (tenant_id, 'license_usage_v1', idem_key, saved_response))
            connection.commit()
        except Exception as exc:
            connection.rollback()
            if getattr(exc, 'args', [None])[0] != 1062:
                raise
            with connection.cursor() as cursor:
                cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s', (tenant_id, 'license_usage_v1', idem_key))
                winner = cursor.fetchone()
            saved = json.loads(winner['response_json']) if winner and winner.get('response_json') else None
            if not isinstance(saved, dict):
                raise
            if not hmac.compare_digest(str(saved.get('request_fingerprint') or ''), fingerprint):
                raise V2Error(409, {'success': False, 'error': 'idempotency_key_reused_with_different_request'})
            response = saved['response']
        return v2_response(200, response, rid)
    except V2Error as exc:
        return v2_response(exc.status, exc.payload, rid)
    except database.DatabaseConfigurationError:
        return v2_response(503, {'success': False, 'error': 'service_unavailable'}, rid)
    except Exception:
        return v2_response(503, {'success': False, 'error': 'usage_recording_failed'}, rid)
    finally:
        if connection:
            connection.close()

def _runtime_config():
    return {'key_pepper': secret_value('key_pepper'), 'token_secret': secret_value('token_secret')}

def _non_writable_role():
    role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    maintenance = os.environ.get('PYTHON_MIGRATION_HA_MAINTENANCE') == '1'
    promoted = os.environ.get('PYTHON_MIGRATION_HA_PROMOTED') == '1'
    return not (role == 'primary' and (not maintenance) or (role == 'standby' and promoted))

def _attempt_count(connection, action, subject_type, subject_hash):
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) AS n FROM auth_attempts WHERE action=%s AND subject_type=%s AND subject_hash=%s AND success=0 AND attempted_at >= (UTC_TIMESTAMP() - INTERVAL 900 SECOND)', (action, subject_type, subject_hash))
        return int(cursor.fetchone()['n'])

def _record_attempt(connection, ip_hash, subject_type, subject_hash, success, error_code):
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO auth_attempts(ip_hash,action,subject_type,subject_hash,success,error_code,attempted_at) VALUES(%s,'reissue',%s,%s,%s,%s,UTC_TIMESTAMP())", (ip_hash, subject_type, subject_hash, 1 if success else 0, error_code))

@legacy_compatible(callback_index=None, request_index=2)
def _audit(event, context, request_context):
    audit.append_event(event, context, request_context.get('client_address', ''))

@legacy_compatible(callback_index=None, request_index=5)
def _record_usage(connection, license_row, operation, status_code, request_id, request_context):
    tenant_id = int(license_row.get('tenant_id') or 0)
    if tenant_id < 1:
        return
    ip_hash = hashlib.sha256(str(request_context.get('client_address', '0.0.0.0')).encode('utf-8')).hexdigest()
    try:
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO tenant_api_usage(tenant_id,client_id,operation,status_code,request_id,ip_hash) VALUES(%s,0,%s,%s,%s,%s)', (tenant_id, operation[:64], status_code, request_id, ip_hash))
        connection.commit()
    except Exception:
        connection.rollback()

@legacy_compatible(callback_index=1, request_index=0)
def activate(request_context):
    rid = uuid.uuid4().hex[:16]
    if request_context.get('method', '') != 'POST':
        return v2_response(405, {'success': False, 'error': 'POST で送信してください。'}, rid)
    return _v2_activate(request_context, rid)

@legacy_compatible(callback_index=1, request_index=0)
def reissue(request_context):
    rid = uuid.uuid4().hex[:16]
    if request_context.get('method', '') != 'POST':
        return v2_response(405, {'success': False, 'error': 'method_not_allowed'}, rid)
    if _non_writable_role():
        return v2_response(503, {'success': False, 'error': 'server_not_writable'}, rid)
    connection = None
    ip_hash = ''
    product_subject = ''
    product_id_value = ''
    try:
        data = request_data(request_context)
        product_id_value = _php_trim(data.get('product_id', '')).translate(_ASCII_UPPER)
        fingerprint = normalize_device_fingerprint(data.get('device_fingerprint', ''))
        config = _runtime_config()
        key_pepper(config)
        secret = token_secret(config)
        del secret
        ip_hash = hash_secret(_php_trim(request_context.get('client_address', '0.0.0.0')))
        product_subject = hash_secret(product_id_value)
        license_id = license_id_from_product_id(config, product_id_value)
        connection = database.connect()
        _assert_write_fence(connection)
        if _attempt_count(connection, 'reissue', 'product_id', product_subject) >= 5 or _attempt_count(connection, 'reissue', 'ip', ip_hash) >= 5:
            _record_attempt(connection, ip_hash, 'product_id', product_subject, False, 'locked')
            connection.commit()
            _audit('license_key_reissue_blocked', {'product_id_hash': hashlib.sha256(product_id_value.encode('utf-8')).hexdigest(), 'ip_hash': ip_hash}, request_context)
            return v2_response(429, {'success': False, 'error': 'reissue_temporarily_locked'}, rid)
        if license_id is None:
            raise ValueError('invalid_product_id')
        if re.fullmatch('[a-f0-9]{64}', fingerprint) is None:
            raise ValueError('invalid_device_fingerprint')
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM licenses WHERE id=%s LIMIT 1 FOR UPDATE', (license_id,))
            license_row = cursor.fetchone()
        if not license_row or not hmac.compare_digest(product_id(config, license_id), product_id_value):
            raise RuntimeError('reissue_not_available')
        if int(license_row.get('active') or 0) != 1 or license_row.get('revoked_at'):
            raise RuntimeError('reissue_not_available')
        expiry = license_row.get('expires_at')
        if expiry:
            from v3_handlers import _as_utc
            from datetime import datetime, timezone
            if _as_utc(expiry) < datetime.now(timezone.utc):
                raise RuntimeError('reissue_not_available')
        if license_row.get('reissue_used_at'):
            raise RuntimeError('reissue_already_used')
        fingerprint_hash = device_hash(config, fingerprint)
        with connection.cursor() as cursor:
            cursor.execute('SELECT id FROM license_devices WHERE license_id=%s AND device_hash=%s AND revoked_at IS NULL LIMIT 1', (license_id, fingerprint_hash))
            registered_device = cursor.fetchone()
        if not registered_device:
            raise RuntimeError('registered_device_required')
        new_key = ''
        for _ in range(5):
            candidate = '-'.join((''.join((secrets.choice(KEY_ALPHABET) for _ in range(5))) for _ in range(5)))
            candidate_hash = license_key_hash(config, candidate)
            with connection.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) AS n FROM licenses WHERE key_hash=%s', (candidate_hash,))
                exists = int(cursor.fetchone()['n'])
            if exists == 0:
                new_key = candidate
                break
        if not new_key:
            raise RuntimeError('key_generation_failed')
        new_offline_secret = offline_secret(new_key)
        with connection.cursor() as cursor:
            cursor.execute('UPDATE licenses SET key_hash=%s,offline_lookup=%s,offline_secret_enc=%s,offline_epoch=offline_epoch+1,reissue_used_at=UTC_TIMESTAMP() WHERE id=%s AND reissue_used_at IS NULL', (license_key_hash(config, new_key), offline_lookup(new_offline_secret), offline_secret_encrypt(config, new_offline_secret), license_id))
            if cursor.rowcount != 1:
                raise RuntimeError('reissue_already_used')
            cursor.execute('UPDATE license_devices SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),token_version=token_version+1 WHERE license_id=%s', (license_id,))
            cursor.execute('DELETE FROM offline_activation_requests WHERE license_id=%s', (license_id,))
        connection.commit()
        for subject_type, subject_hash in (('product_id', product_subject), ('ip', ip_hash)):
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM auth_attempts WHERE action='reissue' AND subject_type=%s AND subject_hash=%s", (subject_type, subject_hash))
        _record_attempt(connection, ip_hash, 'product_id', product_subject, True, 'ok')
        connection.commit()
        _record_usage(connection, license_row, 'product_key.reissue', 200, rid, request_context)
        _audit('license_key_reissued', {'license_id': int(license_id), 'product_id_hash': hashlib.sha256(product_id_value.encode('utf-8')).hexdigest(), 'device_ref': device_reference(fingerprint_hash)}, request_context)
        return v2_response(200, {'success': True, 'message': 'プロダクトキーを1回に限り再発行しました。旧キーと旧セッションは無効です。', 'product_id': product_id_value, 'product_key': new_key, 'reissue_remaining': 0}, rid)
    except RequestError:
        if connection:
            connection.rollback()
        return v2_response(409, {'success': False, 'error': 'reissue_not_available'}, rid)
    except database.DatabaseConfigurationError:
        if connection:
            connection.rollback()
        return v2_response(503, {'success': False, 'error': 'reissue_failed'}, rid)
    except Exception as exc:
        if connection:
            connection.rollback()
        message = str(exc)
        reason = message if message in {'invalid_product_id', 'invalid_device_fingerprint', 'reissue_not_available', 'reissue_already_used', 'registered_device_required'} else 'reissue_failed'
        if connection and ip_hash and product_subject:
            try:
                _record_attempt(connection, ip_hash, 'product_id', product_subject, False, reason)
                _record_attempt(connection, ip_hash, 'ip', ip_hash, False, reason)
                connection.commit()
            except Exception:
                connection.rollback()
        _audit('license_key_reissue_failed', {'product_id_hash': hashlib.sha256(product_id_value.encode('utf-8')).hexdigest(), 'ip_hash': ip_hash, 'reason': reason}, request_context)
        status_code = 400 if reason in ('invalid_product_id', 'invalid_device_fingerprint') else 409
        if isinstance(exc, ConfigurationError) or not isinstance(exc, (RuntimeError, ValueError)):
            status_code = 503
        return v2_response(status_code, {'success': False, 'error': 'reissue_not_available'}, rid)
    finally:
        if connection:
            connection.close()
