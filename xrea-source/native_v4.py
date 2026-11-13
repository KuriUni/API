"""License API v4: body-bound device proofs and isolated session families."""
import hashlib
import hmac
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import database
import v3_crypto
import v3_handlers as domain
import v4_crypto
from core import (device_hash, device_reference, is_valid_device_fingerprint,
                  is_valid_license_key_format, license_key_hash, normalize_device_fingerprint,
                  normalize_license_key, random_token, token_hash)
from fastapi import Request, Response
from http_utils import RequestError
from starlette.concurrency import run_in_threadpool

API_VERSION = v4_crypto.API_VERSION
ROUTES = ('index', 'challenge', 'activate', 'migrate', 'verify', 'introspect', 'refresh', 'reauth', 'revoke', 'offline-ticket', 'offline-public-key')
PROOF_HEADERS = ('x-license-session', 'x-license-timestamp', 'x-license-nonce', 'x-license-proof')
REQUIRED_TABLES = ('license_v4_challenges', 'license_v4_devices', 'license_v4_sessions',
                   'license_v4_proofs', 'license_v4_refresh_history', 'license_v4_offline_tickets')


def reply(payload, rid, status=200, headers=None):
    result = dict(payload)
    result.setdefault('success', 200 <= status < 300)
    result.setdefault('api_version', API_VERSION)
    result.setdefault('request_id', rid)
    return Response(json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode('utf-8'),
                    status_code=status, headers={
                        'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
                        'X-Content-Type-Options': 'nosniff', 'X-Request-ID': rid,
                        **({'Retry-After': '2'} if status == 503 else {}), **(headers or {})})


def error_response(exc, rid, allow='POST'):
    public = domain._public_error(exc)
    if public.status == 503:
        print('license_v4_request_failed request_id=%s error_type=%s' % (rid, type(exc).__name__), file=sys.stderr)
    headers = {'Allow': allow} if public.status == 405 else None
    return reply({'success': False, 'error_code': public.code, 'error': str(public), **public.extra}, rid, public.status, headers)


def _require_schema(connection):
    with connection.cursor() as cursor:
        placeholders = ','.join(['%s'] * len(REQUIRED_TABLES))
        cursor.execute('SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name IN (' + placeholders + ')', REQUIRED_TABLES)
        present = {str(row['table_name']) for row in cursor.fetchall()}
        if not set(REQUIRED_TABLES).issubset(present):
            raise domain.V3Error(503, 'V4_MIGRATION_REQUIRED', 'License API v4のDB移行が必要です。', {'required_migration': 'license_v4'})


def _connect(begin=False):
    connection = database.connect()
    try:
        _require_schema(connection)
        domain._assert_write_fence(connection)
        if begin:
            connection.begin()
        return connection
    except Exception:
        domain._rollback_connection(connection)
        domain._close_connection(connection)
        raise


def _request_hash(data):
    return v4_crypto.body_hash(data, omit_signature=True)


def _create_challenge(connection, purpose, public_key, ip_hash):
    challenge_id = os.urandom(16).hex()
    nonce = v3_crypto.b64url_encode(os.urandom(32))
    expires = datetime.now(timezone.utc) + timedelta(seconds=120)
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM license_v4_challenges WHERE expires_at<UTC_TIMESTAMP() OR consumed_at<(UTC_TIMESTAMP()-INTERVAL 1 DAY)')
        cursor.execute('INSERT INTO license_v4_challenges(challenge_id,purpose,nonce_hash,device_key_thumbprint,ip_hash,expires_at) VALUES(%s,%s,%s,%s,%s,%s)',
                       (challenge_id, purpose, hashlib.sha256(nonce.encode('ascii')).hexdigest(), public_key['thumbprint'], ip_hash, expires.strftime('%Y-%m-%d %H:%M:%S')))
    return {'challenge_id': challenge_id, 'nonce': nonce, 'purpose': purpose,
            'expires_at': expires.strftime('%Y-%m-%d %H:%M:%S'),
            'device_key_thumbprint': public_key['thumbprint'],
            'signature_algorithm': public_key['algorithm']}


def _consume_challenge(connection, purpose, data, public_key):
    challenge_id = str(data.get('challenge_id', '')).strip().lower()
    nonce = str(data.get('nonce', '')).strip()
    signature = str(data.get('signature', '')).strip()
    if re.fullmatch('[a-f0-9]{32}', challenge_id) is None:
        raise RuntimeError('challenge_invalid')
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM license_v4_challenges WHERE challenge_id=%s LIMIT 1 FOR UPDATE', (challenge_id,))
        row = cursor.fetchone()
    if not row or str(row['purpose']) != purpose:
        raise RuntimeError('challenge_invalid')
    if row.get('consumed_at'):
        raise RuntimeError('challenge_already_used')
    if domain._as_utc(row['expires_at']) <= datetime.now(timezone.utc):
        raise RuntimeError('challenge_expired')
    if not hmac.compare_digest(str(row['nonce_hash']), hashlib.sha256(nonce.encode('utf-8')).hexdigest()):
        raise RuntimeError('challenge_nonce_invalid')
    if not hmac.compare_digest(str(row['device_key_thumbprint']), str(public_key['thumbprint'])):
        raise RuntimeError('challenge_key_mismatch')
    if purpose == 'activate':
        message = v4_crypto.activation_message(data, challenge_id, nonce, public_key['thumbprint'])
    elif purpose == 'migrate':
        message = v4_crypto.migration_message(data, challenge_id, nonce, public_key['thumbprint'])
    else:
        raise domain.V3Error(400, 'CHALLENGE_PURPOSE_INVALID', 'この用途のチャレンジは発行できません。')
    if not v3_crypto.verify_signature(public_key['pem'], message, signature):
        raise RuntimeError('device_signature_invalid')
    with connection.cursor() as cursor:
        cursor.execute('UPDATE license_v4_challenges SET consumed_at=UTC_TIMESTAMP() WHERE id=%s AND consumed_at IS NULL', (int(row['id']),))
        if cursor.rowcount != 1:
            raise RuntimeError('challenge_already_used')


def _license_active(row):
    domain._active_license(row)


def _upsert_device(connection, license_row, fingerprint_hash, public_key, label, version):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM license_v4_devices WHERE license_id=%s AND device_hash=%s LIMIT 1 FOR UPDATE',
                       (int(license_row['id']), fingerprint_hash))
        current = cursor.fetchone()
        cursor.execute('SELECT id FROM license_v4_devices WHERE license_id=%s AND key_thumbprint=%s AND device_hash<>%s LIMIT 1',
                       (int(license_row['id']), public_key['thumbprint'], fingerprint_hash))
        if cursor.fetchone():
            raise domain.V3Error(409, 'DEVICE_KEY_ALREADY_BOUND', 'この端末鍵は別の端末に登録されています。')
        label = str(label or '').strip()[:120]
        version = str(version or '').strip()[:40]
        if current is None:
            cursor.execute('INSERT INTO license_v4_devices(license_id,device_hash,device_label,public_key_pem,key_thumbprint,key_algorithm,app_version,bound_at,last_seen_at,revoked_at) VALUES(%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP(),NULL)',
                           (int(license_row['id']), fingerprint_hash, label, public_key['pem'], public_key['thumbprint'], public_key['algorithm'], version))
            device_id = cursor.lastrowid
        else:
            device_id = int(current['id'])
            if not hmac.compare_digest(str(current['key_thumbprint']), public_key['thumbprint']):
                cursor.execute("UPDATE license_v4_sessions SET revoked_at=UTC_TIMESTAMP(),revoke_reason='device_key_rotated' WHERE device_id=%s AND revoked_at IS NULL", (device_id,))
            cursor.execute('UPDATE license_v4_devices SET device_label=%s,public_key_pem=%s,key_thumbprint=%s,key_algorithm=%s,app_version=%s,last_seen_at=UTC_TIMESTAMP(),revoked_at=NULL WHERE id=%s',
                           (label, public_key['pem'], public_key['thumbprint'], public_key['algorithm'], version, device_id))
        cursor.execute('SELECT * FROM license_v4_devices WHERE id=%s', (device_id,))
        return cursor.fetchone() or {}


def _new_tokens(connection, license_row, device, existing_session=None):
    config = domain._config()
    now = datetime.now(timezone.utc)
    access_exp = now + timedelta(minutes=5)
    refresh_exp = now + timedelta(days=14)
    if license_row.get('expires_at'):
        license_exp = domain._as_utc(license_row['expires_at'])
        access_exp, refresh_exp = min(access_exp, license_exp), min(refresh_exp, license_exp)
    if access_exp <= now or refresh_exp <= now:
        raise RuntimeError('license_expired')
    access_token = 'v4.a.' + random_token(32)
    refresh_token = 'v4.r.' + random_token(48)
    session_id = str(existing_session['session_id']) if existing_session else os.urandom(16).hex()
    family_id = str(existing_session['family_id']) if existing_session else os.urandom(16).hex()
    scopes = ['license.verify','license.refresh','license.revoke','license.introspect','license.offline']
    if existing_session:
        with connection.cursor() as cursor:
            cursor.execute('INSERT IGNORE INTO license_v4_refresh_history(token_hash,session_id,family_id,expires_at,used_at) VALUES(%s,%s,%s,%s,UTC_TIMESTAMP())',
                           (str(existing_session['refresh_token_hash']), session_id, family_id, existing_session['refresh_expires_at']))
            cursor.execute('UPDATE license_v4_sessions SET access_token_hash=%s,refresh_token_hash=%s,access_expires_at=%s,refresh_expires_at=%s,token_version=token_version+1,last_seen_at=UTC_TIMESTAMP() WHERE id=%s AND revoked_at IS NULL',
                           (token_hash(config, access_token), token_hash(config, refresh_token), access_exp.strftime('%Y-%m-%d %H:%M:%S'), refresh_exp.strftime('%Y-%m-%d %H:%M:%S'), int(existing_session['id'])))
            if cursor.rowcount != 1:
                raise domain.V3Error(409, 'SESSION_CHANGED', 'セッションが更新されています。')
        version = int(existing_session['token_version']) + 1
    else:
        session_id, family_id = os.urandom(16).hex(), os.urandom(16).hex()
        with connection.cursor() as cursor:
            cursor.execute("UPDATE license_v4_sessions SET revoked_at=UTC_TIMESTAMP(),revoke_reason='reactivated' WHERE device_id=%s AND revoked_at IS NULL", (int(device['id']),))
            cursor.execute('INSERT INTO license_v4_sessions(session_id,family_id,license_id,device_id,access_token_hash,refresh_token_hash,scopes_json,access_expires_at,refresh_expires_at,token_version,created_at,last_seen_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,1,UTC_TIMESTAMP(),UTC_TIMESTAMP())',
                           (session_id, family_id, int(license_row['id']), int(device['id']), token_hash(config, access_token), token_hash(config, refresh_token), json.dumps(scopes, separators=(',', ':')), access_exp.strftime('%Y-%m-%d %H:%M:%S'), refresh_exp.strftime('%Y-%m-%d %H:%M:%S')))
        version = 1
    return {'session_id': session_id, 'family_id': family_id, 'access_token': access_token,
            'refresh_token': refresh_token, 'access_expires_at': access_exp.strftime('%Y-%m-%d %H:%M:%S'),
            'refresh_expires_at': refresh_exp.strftime('%Y-%m-%d %H:%M:%S'),
            'token_version': version, 'scopes': scopes,
            **domain._session_timing(access_exp, refresh_exp, now)}


def _load_session(connection, token, kind, lock=False):
    if not str(token).startswith('v4.' + ('r.' if kind == 'refresh' else 'a.')):
        return None
    config = domain._config()
    column = 'refresh_token_hash' if kind == 'refresh' else 'access_token_hash'
    sql = ('SELECT s.*,d.device_hash,d.device_label,d.public_key_pem,d.key_thumbprint,d.key_algorithm,'
           'd.revoked_at AS device_revoked_at,l.active,l.expires_at,l.revoked_at AS license_revoked_at,'
           'l.max_devices,l.tenant_id,l.product_id,l.label AS license_label,l.offline_epoch '
           'FROM license_v4_sessions s JOIN license_v4_devices d ON d.id=s.device_id '
           'JOIN licenses l ON l.id=s.license_id WHERE s.%s=%%s AND l.deleted_at IS NULL LIMIT 1' % column)
    if lock:
        sql += ' FOR UPDATE'
    with connection.cursor() as cursor:
        cursor.execute(sql, (token_hash(config, token),))
        return cursor.fetchone()


def _session_active(session, kind):
    if session.get('revoked_at') or session.get('device_revoked_at'):
        raise RuntimeError('session_revoked')
    if int(session.get('active') or 0) != 1 or session.get('license_revoked_at'):
        raise RuntimeError('license_inactive')
    if session.get('expires_at') and domain._as_utc(session['expires_at']) <= datetime.now(timezone.utc):
        raise RuntimeError('license_expired')
    expiry = session.get('refresh_expires_at' if kind == 'refresh' else 'access_expires_at')
    if not expiry or domain._as_utc(expiry) <= datetime.now(timezone.utc):
        raise RuntimeError(kind + '_token_expired')


def _verify_pop(connection, session, action, data, headers, token):
    session_id = str(headers.get('x-license-session', '')).strip()
    nonce = str(headers.get('x-license-nonce', '')).strip()
    proof = str(headers.get('x-license-proof', '')).strip()
    try:
        timestamp = int(headers.get('x-license-timestamp', '0'))
    except (TypeError, ValueError):
        timestamp = 0
    if session_id != str(session['session_id']) or re.fullmatch('[A-Za-z0-9_-]{16,180}', nonce) is None or timestamp <= 0 or not proof:
        raise RuntimeError('proof_required')
    if abs(int(time.time()) - timestamp) > 60:
        raise RuntimeError('proof_timestamp_invalid')
    path = v4_crypto.PUBLIC_PREFIX + action + '.php'
    credential_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    message = v4_crypto.request_message('POST', path, session_id, timestamp, nonce, data, credential_hash)
    if not v3_crypto.verify_signature(str(session['public_key_pem']), message, proof):
        raise RuntimeError('proof_signature_invalid')
    proof_hash = hashlib.sha256((session_id + '|' + nonce).encode()).hexdigest()
    try:
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO license_v4_proofs(proof_hash,session_id,action,expires_at) VALUES(%s,%s,%s,DATE_ADD(UTC_TIMESTAMP(),INTERVAL 120 SECOND))',
                           (proof_hash, session_id, action))
            cursor.execute('DELETE FROM license_v4_proofs WHERE expires_at<UTC_TIMESTAMP()')
    except Exception as exc:
        if getattr(exc, 'args', [None])[0] == 1062:
            raise RuntimeError('proof_replayed')
        raise


def _issue_challenge(data, remote_addr, rid):
    purpose = str(data.get('purpose', 'activate')).strip().lower()
    if purpose not in ('activate', 'migrate'):
        raise domain.V3Error(400, 'CHALLENGE_PURPOSE_INVALID', 'purposeはactivateまたはmigrateを指定してください。')
    public_key = v3_crypto.normalize_public_key(data.get('device_public_key', ''))
    connection = _connect(begin=True)
    try:
        ip_hash = hashlib.sha256(str(remote_addr).encode('utf-8')).hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS n FROM auth_attempts WHERE action=%s AND subject_type=%s AND subject_hash=%s AND attempted_at>=(UTC_TIMESTAMP()-INTERVAL 900 SECOND)',
                           ('v4_challenge', 'ip', ip_hash))
            if int(cursor.fetchone()['n']) >= 60:
                raise domain.V3Error(429, 'RATE_LIMITED', '試行回数が多すぎます。')
            result = _create_challenge(connection, purpose, public_key, ip_hash)
            cursor.execute('INSERT INTO auth_attempts(ip_hash,action,subject_type,subject_hash,success,error_code,attempted_at) VALUES(%s,%s,%s,%s,1,%s,UTC_TIMESTAMP())',
                           (ip_hash, 'v4_challenge', 'ip', ip_hash, 'ok'))
        connection.commit()
        return {'challenge': result}
    except Exception:
        domain._rollback_connection(connection)
        raise
    finally:
        domain._close_connection(connection)


def _activate(data, remote_addr, rid):
    config = domain._config()
    key = normalize_license_key(data.get('license_key', ''))
    fingerprint = normalize_device_fingerprint(data.get('device_fingerprint', ''))
    if not is_valid_license_key_format(key):
        raise domain.V3Error(400, 'LICENSE_KEY_INVALID', 'license_keyの形式が正しくありません。')
    if not is_valid_device_fingerprint(fingerprint):
        raise domain.V3Error(400, 'DEVICE_FINGERPRINT_INVALID', 'device_fingerprintはSHA-256 hex形式で指定してください。')
    public_key = v3_crypto.normalize_public_key(data.get('device_public_key', ''))
    if min(len(str(config.get(name, '')).strip()) for name in ('key_pepper', 'token_secret')) < 32:
        raise domain.V3Error(503, 'SERVICE_UNAVAILABLE', '認証サービスを利用できません。')
    connection = _connect(begin=True)
    try:
        _consume_challenge(connection, 'activate', data, public_key)
        license_row = domain._license_by_key(connection, license_key_hash(config, key))
        if not license_row:
            raise RuntimeError('license_not_found')
        license_row = domain._lock_license(connection, int(license_row['id']))
        if not license_row:
            raise RuntimeError('license_not_found')
        product = domain._resolve_product(connection, license_row, data.get('product_code', ''))
        license_row = domain._start_evaluation(connection, license_row)
        _license_active(license_row)
        fingerprint_hash = device_hash(config, fingerprint)
        domain._guard_capacity(connection, license_row, fingerprint_hash)
        device = _upsert_device(connection, license_row, fingerprint_hash, public_key,
                                data.get('device_label', ''), data.get('app_version', ''))
        session = _new_tokens(connection, license_row, device)
        with connection.cursor() as cursor:
            cursor.execute('UPDATE licenses SET last_activated_at=UTC_TIMESTAMP(),last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(license_row['id']),))
        connection.commit()
        return {'message': 'License API v4 device-bound session issued.',
                'license': domain._license_payload(license_row), 'product_code': product,
                'device': {'device_id': int(device['id']), 'device_ref': device_reference(fingerprint_hash),
                           'key_thumbprint': public_key['thumbprint'], 'key_algorithm': public_key['algorithm']},
                'session': session}
    except Exception:
        domain._rollback_connection(connection)
        raise
    finally:
        domain._close_connection(connection)


def _migrate_v2(data, remote_addr, rid):
    config = domain._config()
    access_token = str(data.get('access_token', '')).strip()
    fingerprint = normalize_device_fingerprint(data.get('device_fingerprint', ''))
    if not access_token or len(access_token) > 8192:
        raise domain.V3Error(400, 'V2_SESSION_REQUIRED', '有効なV2アクセストークンが必要です。')
    if not is_valid_device_fingerprint(fingerprint):
        raise domain.V3Error(400, 'DEVICE_FINGERPRINT_INVALID', 'device_fingerprintはSHA-256 hex形式で指定してください。')
    public_key = v3_crypto.normalize_public_key(data.get('device_public_key', ''))
    connection = _connect(begin=True)
    try:
        _consume_challenge(connection, 'migrate', data, public_key)
        with connection.cursor() as cursor:
            cursor.execute('SELECT d.*,l.active,l.expires_at,l.revoked_at AS license_revoked_at,l.deleted_at,l.max_devices,l.tenant_id,l.product_id,l.label AS license_label FROM license_devices d JOIN licenses l ON l.id=d.license_id WHERE d.access_token_hash=%s AND l.deleted_at IS NULL LIMIT 1 FOR UPDATE',
                           (token_hash(config, access_token),))
            legacy = cursor.fetchone()
        if not legacy or legacy.get('revoked_at'):
            raise domain.V3Error(401, 'V2_SESSION_INVALID', '保存済みV2セッションが無効または失効しています。')
        fingerprint_hash = device_hash(config, fingerprint)
        if not hmac.compare_digest(str(legacy.get('device_hash') or ''), fingerprint_hash):
            raise domain.V3Error(401, 'V2_DEVICE_MISMATCH', 'V2セッションとこの端末の情報が一致しません。')
        now = datetime.now(timezone.utc)
        for field in ('access_expires_at', 'refresh_expires_at'):
            expiry = legacy.get(field)
            if not expiry or domain._as_utc(expiry) <= now:
                raise domain.V3Error(401, 'V2_SESSION_EXPIRED', 'V2セッションの期限が切れています。先にオンライン再確認を実行してください。')
        license_row = domain._lock_license(connection, int(legacy['license_id']))
        if not license_row:
            raise domain.V3Error(401, 'V2_LICENSE_UNAVAILABLE', 'V2ライセンスが見つかりません。')
        domain._active_license(license_row)
        domain._guard_capacity(connection, license_row, fingerprint_hash)
        device = _upsert_device(connection, license_row, fingerprint_hash, public_key,
                                data.get('device_label', legacy.get('device_label', '')),
                                data.get('app_version', ''))
        session = _new_tokens(connection, license_row, device)
        with connection.cursor() as cursor:
            cursor.execute('UPDATE licenses SET last_activated_at=UTC_TIMESTAMP(),last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(license_row['id']),))
        connection.commit()
        return {'message': 'License API v2 session migrated to a device-bound v4 session.',
                'migration': {'from_api_version': 2, 'to_api_version': 4},
                'license': domain._license_payload(license_row),
                'device': {'device_id': int(device['id']), 'device_ref': device_reference(fingerprint_hash),
                           'key_thumbprint': public_key['thumbprint'], 'key_algorithm': public_key['algorithm']},
                'session': session}
    except Exception:
        domain._rollback_connection(connection)
        raise
    finally:
        domain._close_connection(connection)


def _session_action(action, data, headers, remote_addr, rid):
    kind = 'refresh' if action == 'refresh' else 'access'
    token = str(data.get('refresh_token', '')).strip() if kind == 'refresh' else str(headers.get('authorization', '')).strip()
    if kind == 'access' and token.lower().startswith('bearer '):
        token = token[7:].strip()
    if not token:
        raise domain.V3Error(401, kind.upper() + '_TOKEN_REQUIRED', kind + ' tokenが必要です。')
    connection = _connect(begin=True)
    try:
        session = _load_session(connection, token, kind, lock=(action == 'refresh'))
        if not session:
            if action == 'refresh':
                token_hash_value = token_hash(domain._config(), token)
                with connection.cursor() as cursor:
                    cursor.execute('SELECT family_id FROM license_v4_refresh_history WHERE token_hash=%s AND expires_at>UTC_TIMESTAMP() LIMIT 1', (token_hash_value,))
                    history = cursor.fetchone()
                if history:
                    with connection.cursor() as cursor:
                        cursor.execute("UPDATE license_v4_sessions SET revoked_at=UTC_TIMESTAMP(),revoke_reason='refresh_reuse_detected' WHERE family_id=%s AND revoked_at IS NULL", (str(history['family_id']),))
                    connection.commit()
                    raise domain.V3Error(401, 'REFRESH_REUSE_DETECTED', '使用済み更新トークンが再利用されたため、セッション系列を失効しました。')
            raise domain.V3Error(401, 'SESSION_NOT_FOUND', '有効なセッションが見つかりません。')
        _session_active(session, kind)
        _verify_pop(connection, session, action, data, headers, token)
        if action in ('refresh', 'reauth'):
            updated = _new_tokens(connection, session, {
                'id': int(session['device_id']), 'license_id': int(session['license_id'])
            }, existing_session=session)
            connection.commit()
            return {'message': 'セッション鍵証明を確認し、トークンをローテーションしました。', 'session': updated}
        if action == 'revoke':
            scope = 'family' if str(data.get('scope', 'session')).lower() == 'family' else 'session'
            with connection.cursor() as cursor:
                if scope == 'family':
                    cursor.execute("UPDATE license_v4_sessions SET revoked_at=UTC_TIMESTAMP(),revoke_reason='client_family_revoke' WHERE family_id=%s AND revoked_at IS NULL", (str(session['family_id']),))
                    affected = cursor.rowcount
                    cursor.execute('UPDATE license_v4_offline_tickets SET revoked_at=UTC_TIMESTAMP() WHERE session_id IN (SELECT session_id FROM license_v4_sessions WHERE family_id=%s) AND revoked_at IS NULL', (str(session['family_id']),))
                else:
                    cursor.execute("UPDATE license_v4_sessions SET revoked_at=UTC_TIMESTAMP(),revoke_reason='client_revoke' WHERE id=%s AND revoked_at IS NULL", (int(session['id']),))
                    affected = cursor.rowcount
                    cursor.execute('UPDATE license_v4_offline_tickets SET revoked_at=UTC_TIMESTAMP() WHERE session_id=%s AND revoked_at IS NULL', (str(session['session_id']),))
            connection.commit()
            return {'revoked': True, 'scope': scope, 'affected_sessions': affected}
        if action == 'offline-ticket':
            ticket = _offline_ticket(connection, session, data.get('hours', 24))
            connection.commit()
            return {'offline_ticket': ticket}
        if action == 'introspect':
            with connection.cursor() as cursor:
                cursor.execute('UPDATE license_v4_sessions SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(session['id']),))
                cursor.execute('UPDATE license_v4_devices SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(session['device_id']),))
            connection.commit()
            session_payload = {key: session[key] for key in ('session_id', 'family_id', 'created_at', 'last_seen_at', 'access_expires_at', 'refresh_expires_at')}
            session_payload.update({'token_version': int(session['token_version']), 'scopes': json.loads(session['scopes_json'])})
            return {'active': True, 'session': session_payload,
                    'device': {'device_ref': device_reference(str(session['device_hash'])),
                               'key_thumbprint': str(session['key_thumbprint']), 'key_algorithm': str(session['key_algorithm'])}}
        with connection.cursor() as cursor:
            cursor.execute('UPDATE license_v4_sessions SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(session['id']),))
            cursor.execute('UPDATE license_v4_devices SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(session['device_id']),))
        license_row = domain._license_row(connection, int(session['license_id']))
        connection.commit()
        return {'valid': True,
                'session': {'session_id': str(session['session_id']), 'family_id': str(session['family_id']),
                            'token_version': int(session['token_version']), 'scopes': json.loads(session['scopes_json']),
                            'access_expires_at': session['access_expires_at']},
                'device': {'device_ref': device_reference(str(session['device_hash'])),
                           'key_thumbprint': str(session['key_thumbprint']), 'key_algorithm': str(session['key_algorithm'])},
                'license': domain._license_payload(license_row) if license_row else None}
    except Exception:
        domain._rollback_connection(connection)
        raise
    finally:
        domain._close_connection(connection)


def execute(action, data, headers, remote_addr, rid):
    try:
        if action == 'challenge':
            payload = _issue_challenge(data, remote_addr, rid)
        elif action == 'activate':
            payload = _activate(data, remote_addr, rid)
        elif action == 'migrate':
            payload = _migrate_v2(data, remote_addr, rid)
        else:
            payload = _session_action(action, data, headers, remote_addr, rid)
        return reply(payload, rid)
    except Exception as exc:
        return error_response(exc, rid)


def _offline_ticket(connection, session, hours):
    material = v3_crypto.offline_signing_material(domain._config(), version=4)
    try:
        hours = max(1, min(72, int(hours)))
    except (TypeError, ValueError):
        hours = 24
    now = int(time.time())
    license_exp = domain._as_utc(session['expires_at']).timestamp() if session.get('expires_at') else now + hours * 3600
    expires = min(now + hours * 3600, int(license_exp))
    if expires <= now:
        raise RuntimeError('license_expired')
    ticket_id = os.urandom(16).hex()
    payload = {'v': 4, 'ticket_id': ticket_id, 'license_id': int(session['license_id']),
               'product_id': int(session.get('product_id') or 0),
               'device_key_thumbprint': str(session['key_thumbprint']),
               'session_id': str(session['session_id']), 'offline_epoch': int(session.get('offline_epoch') or 1),
               'iat': now, 'exp': expires, 'kid': material['kid']}
    body = v3_crypto.b64url_encode(json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
    signature = v3_crypto.b64url_encode(material['private_key'].sign(body.encode('ascii')))
    ticket = 'v4o.' + body + '.' + signature
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM license_v4_offline_tickets WHERE expires_at<UTC_TIMESTAMP()')
        cursor.execute('INSERT INTO license_v4_offline_tickets(ticket_id,license_id,device_id,session_id,kid,payload_hash,expires_at,created_at) VALUES(%s,%s,%s,%s,%s,%s,FROM_UNIXTIME(%s),UTC_TIMESTAMP())',
                       (ticket_id, int(session['license_id']), int(session['device_id']), str(session['session_id']), material['kid'], hashlib.sha256(body.encode('ascii')).hexdigest(), expires))
    return {'ticket': ticket, 'ticket_id': ticket_id, 'algorithm': material['algorithm'], 'kid': material['kid'],
            'expires_at': datetime.fromtimestamp(expires, timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
            'max_offline_hours': hours}


def install_routes(api, maintenance_if_needed):
    def endpoint_for(action):
        async def endpoint(request: Request) -> Response:
            maintenance = await run_in_threadpool(maintenance_if_needed, request)
            if maintenance is not None:
                return maintenance
            rid = uuid.uuid4().hex[:16]
            if action in ('index', 'activate') and request.method == 'GET':
                root = Path(os.environ.get('TUTI_STATIC_ROOT') or Path(__file__).resolve().parent)
                try:
                    body = (root / 'api' / 'v4' / 'activate.html').read_bytes()
                except OSError:
                    return error_response(domain.V3Error(503, 'SERVICE_UNAVAILABLE', '認証ガイドを表示できません。'), rid)
                return Response(body, media_type='text/html; charset=utf-8', headers={
                    'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                    'X-Frame-Options': 'DENY', 'X-Request-ID': rid,
                })
            if action == 'offline-public-key' and request.method == 'GET':
                try:
                    return reply({'offline_signing_key': v3_crypto.public_signing_key(domain._config(), version=4)}, rid)
                except Exception as exc:
                    return error_response(exc, rid)
            if action == 'offline-public-key':
                return error_response(domain.V3Error(405, 'METHOD_NOT_ALLOWED', 'GETを使用してください。'), rid, allow='GET')
            if request.method != 'POST':
                return error_response(domain.V3Error(405, 'METHOD_NOT_ALLOWED', 'POSTを使用してください。'), rid)
            try:
                from native_v3 import read_data
                data = await read_data(request)
            except RequestError as exc:
                return error_response(exc, rid)
            headers = {key.lower(): value for key, value in request.headers.items()}
            environ = request.scope.get('wsgi_environ') or {}
            remote = str(environ.get('REMOTE_ADDR') or (request.client.host if request.client else '0.0.0.0'))
            return await run_in_threadpool(execute, action, data, headers, remote, rid)
        return endpoint

    for action in ROUTES:
        endpoint = endpoint_for(action)
        for prefix in ('/api/v4/', '/license/api/v4/'):
            api.add_api_route(prefix + action + '.php', endpoint, name='v4_' + action,
                              methods=['GET','POST','PUT','PATCH','DELETE','OPTIONS','HEAD','TRACE'],
                              include_in_schema=False)
