"""License v3 transactions and FastAPI endpoints, without WSGI dispatch.

Cryptography and database primitives are shared with the Python port. HTTP
input, transaction orchestration and HTTP output are owned by these routes.
"""
import hashlib
import json
import re
import uuid
from contextlib import contextmanager
from urllib.parse import parse_qsl

import database
import v3_crypto
import v3_handlers as domain
from core import (device_hash, device_reference, is_valid_device_fingerprint,
                  is_valid_license_key_format, license_key_hash,
                  normalize_device_fingerprint, normalize_license_key)
from fastapi import Request, Response
from http_utils import MAX_FIELDS, MAX_JSON_BYTES, MAX_VALUE_BYTES, RequestError, _json_default
from starlette.concurrency import run_in_threadpool


def reply(payload, rid, status=200, headers=None):
    result = dict(payload)
    result.setdefault('success', 200 <= status < 300)
    result.setdefault('api_version', domain.API_VERSION)
    result.setdefault('request_id', rid)
    return Response(json.dumps(result, ensure_ascii=False, separators=(',', ':'),
                               default=_json_default).encode('utf-8'), status_code=status,
                    headers={'Content-Type': 'application/json; charset=utf-8',
                             'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                             **(headers or {})})


def error_response(exc, rid):
    if isinstance(exc, RequestError):
        exc = domain.V3Error(400, 'INVALID_REQUEST', 'リクエスト形式が正しくありません。')
    elif isinstance(exc, database.DatabaseConfigurationError):
        exc = domain.V3Error(503, 'SERVICE_UNAVAILABLE', 'テストDBを利用できません。')
    if isinstance(exc, domain.V3Error):
        headers = {'Allow': 'POST'} if exc.status == 405 else None
        return reply({'success': False, 'error_code': exc.code, 'error': str(exc), **exc.extra},
                     rid, exc.status, headers)
    codes = {
        'challenge_invalid': (400, 'CHALLENGE_INVALID'),
        'challenge_already_used': (409, 'CHALLENGE_ALREADY_USED'),
        'challenge_expired': (401, 'CHALLENGE_EXPIRED'),
        'challenge_nonce_invalid': (401, 'CHALLENGE_INVALID'),
        'challenge_key_mismatch': (401, 'CHALLENGE_KEY_MISMATCH'),
        'device_signature_invalid': (401, 'DEVICE_SIGNATURE_INVALID'),
        'license_device_limit_reached': (409, 'DEVICE_LIMIT_REACHED'),
        'session_revoked': (401, 'SESSION_REVOKED'),
        'license_inactive': (403, 'LICENSE_INACTIVE'),
        'license_expired': (403, 'LICENSE_EXPIRED'),
        'access_token_expired': (401, 'ACCESS_TOKEN_EXPIRED'),
        'refresh_token_expired': (401, 'REFRESH_TOKEN_EXPIRED'),
        'proof_required': (400, 'PROOF_REQUIRED'),
        'proof_timestamp_invalid': (401, 'PROOF_TIMESTAMP_INVALID'),
        'proof_signature_invalid': (401, 'PROOF_SIGNATURE_INVALID'),
        'proof_replayed': (409, 'PROOF_REPLAYED'),
        'offline_signing_unavailable': (503, 'OFFLINE_SIGNING_UNAVAILABLE'),
        'license_not_found': (400, 'LICENSE_NOT_FOUND'),
        'schema_missing': (503, 'V3_MIGRATION_REQUIRED'),
        'node_not_writable': (503, 'SERVICE_UNAVAILABLE'),
        'ha_write_fence_rejected': (503, 'SERVICE_UNAVAILABLE'),
        'device_public_key_invalid': (400, 'DEVICE_PUBLIC_KEY_INVALID'),
        'device_public_key_too_weak': (400, 'DEVICE_PUBLIC_KEY_TOO_WEAK'),
        'device_public_key_curve_unsupported': (400, 'DEVICE_KEY_CURVE_UNSUPPORTED'),
        'device_public_key_type_unsupported': (400, 'DEVICE_KEY_TYPE_UNSUPPORTED'),
        'challenge_purpose_invalid': (400, 'CHALLENGE_PURPOSE_INVALID'),
    }
    code = str(exc)
    status, public_code = codes.get(code, (400, 'V3_REQUEST_FAILED'))
    # Do not expose unknown driver errors or configuration values to clients.
    message = code if code in codes else 'リクエストを処理できません。'
    if code == 'license_not_found':
        message = 'ライセンスキーが正しくありません。'
    payload = {'success': False, 'error_code': public_code, 'error': message}
    if code == 'schema_missing':
        payload['required_migration'] = '027_license_api_v3_beta'
    return reply(payload, rid, status)


def _parse_pairs(value):
    output = {}
    for key, item in parse_qsl(value, keep_blank_values=True):
        output[key.replace(' ', '_').replace('.', '_')] = item
    return output


async def read_data(request):
    """Read the legacy JSON/form/query contract directly from ASGI."""
    length = request.headers.get('content-length')
    if length is not None:
        try:
            if int(length) < 0:
                raise ValueError()
        except ValueError:
            raise RequestError('invalid_content_length')
    content_type = request.headers.get('content-type', '').lower()
    is_json = 'application/json' in content_type
    is_form = 'application/x-www-form-urlencoded' in content_type
    raw = bytearray()
    if is_json or is_form:
        if length is not None and int(length) > MAX_JSON_BYTES:
            raise RequestError('request_too_large')
        async for chunk in request.stream():
            if len(raw) + len(chunk) > MAX_JSON_BYTES:
                raise RequestError('request_too_large')
            raw.extend(chunk)
    try:
        if is_json:
            data = json.loads(raw.decode('utf-8'),
                              parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
            if isinstance(data, list):
                if len(data) > MAX_FIELDS or any(isinstance(v, (dict, list)) for v in data):
                    raise RequestError('invalid_request_shape')
                data = {}
            elif not isinstance(data, dict):
                raise RequestError('invalid_request_shape')
        else:
            data = _parse_pairs(request.scope.get('query_string', b'').decode('latin-1'))
            form = _parse_pairs(raw.decode('utf-8')) if is_form else {}
            if len(data) + len(form) > MAX_FIELDS:
                raise RequestError('too_many_fields')
            data.update(form)
            if any('[' in key or ']' in key for key in data):
                raise RequestError('invalid_request_shape')
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise RequestError('invalid_request') from exc
    if len(data) > MAX_FIELDS:
        raise RequestError('too_many_fields')
    for value in data.values():
        if isinstance(value, (dict, list)):
            raise RequestError('invalid_request_shape')
        if isinstance(value, str) and len(value.encode('utf-8')) > MAX_VALUE_BYTES:
            raise RequestError('value_too_long')
    return data


@contextmanager
def connection_for_write(begin=False):
    connection = database.connect()
    try:
        domain._require_v3_schema(connection)
        domain._assert_write_fence(connection)
        if begin:
            connection.begin()
        yield connection
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def bearer(authorization, data):
    match = re.match(r'^Bearer\s+(.+)$', str(authorization).strip(), re.I)
    return match.group(1).strip() if match else str(data.get('access_token', '')).strip()


def record_usage(connection, license_row, action, rid, remote_addr):
    if not license_row or int(license_row.get('tenant_id') or 0) < 1:
        return
    try:
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO tenant_api_usage(tenant_id,client_id,operation,status_code,request_id,ip_hash) '
                           'VALUES(%s,0,%s,%s,%s,%s)',
                           (int(license_row['tenant_id']), 'license_v3.' + action, 200, rid,
                            hashlib.sha256(remote_addr.encode('utf-8')).hexdigest()))
        connection.commit()
    except Exception:
        connection.rollback()


def activate(data, authorization, remote_addr, rid):
    config = domain._config()
    key = normalize_license_key(data.get('license_key', ''))
    fingerprint = normalize_device_fingerprint(data.get('device_fingerprint', ''))
    if not is_valid_license_key_format(key):
        raise domain.V3Error(400, 'LICENSE_KEY_INVALID', 'license_key の形式が正しくありません。')
    if not is_valid_device_fingerprint(fingerprint):
        raise domain.V3Error(400, 'DEVICE_FINGERPRINT_INVALID', 'device_fingerprint はSHA-256 hex形式で指定してください。')
    public_key = v3_crypto.normalize_public_key(data.get('device_public_key', ''))
    if any(len(str(config[name]).strip()) < 32 for name in ('key_pepper', 'token_secret')):
        raise domain.V3Error(503, 'SERVICE_UNAVAILABLE', 'サービスを利用できません。')
    fingerprint_hash = device_hash(config, fingerprint)
    with connection_for_write(begin=True) as connection:
        domain._consume_challenge(connection, 'activate', str(data.get('challenge_id', '')).strip().lower(),
                                  str(data.get('nonce', '')).strip(), public_key,
                                  str(data.get('signature', '')).strip())
        license_row = domain._license_by_key(connection, license_key_hash(config, key))
        if license_row is None:
            raise RuntimeError('license_not_found')
        license_row = domain._lock_license(connection, int(license_row['id'])) or license_row
        product = domain._resolve_product(connection, license_row, data.get('product_code', ''))
        license_row = domain._start_evaluation(connection, license_row)
        domain._active_license(license_row)
        domain._guard_capacity(connection, license_row, fingerprint_hash)
        device = domain._upsert_device(connection, license_row, fingerprint_hash, public_key,
                                       data.get('device_label', ''), data.get('app_version', ''))
        session = domain._issue_session(connection, license_row, device)
        with connection.cursor() as cursor:
            cursor.execute('UPDATE licenses SET last_activated_at=UTC_TIMESTAMP(),last_seen_at=UTC_TIMESTAMP() WHERE id=%s',
                           (int(license_row['id']),))
        connection.commit()
        record_usage(connection, license_row, 'activate', rid, remote_addr)
        return {'message': 'License API v3 Beta device-bound session issued.',
                'license': domain._license_payload(license_row), 'product_code': product,
                'device': {'device_id': int(device['id']), 'device_ref': device_reference(fingerprint_hash),
                           'key_thumbprint': public_key['thumbprint'], 'key_algorithm': public_key['algorithm']},
                'session': session}


def reauth(data, authorization, remote_addr, rid):
    token = bearer(authorization, data)
    if not token:
        raise domain.V3Error(401, 'ACCESS_TOKEN_REQUIRED', 'access_token が必要です。')
    with connection_for_write(begin=True) as connection:
        session = domain._load_session(connection, token, 'access', True)
        if not session:
            raise domain.V3Error(401, 'SESSION_NOT_FOUND', 'セッションが見つかりません。')
        domain._session_active(session, 'access')
        public_key = v3_crypto.normalize_public_key(session['public_key_pem'])
        domain._consume_challenge(connection, 'reauth', str(data.get('challenge_id', '')).strip().lower(),
                                  str(data.get('nonce', '')).strip(), public_key,
                                  str(data.get('signature', '')).strip())
        new_session = domain._rotate_session(connection, session)
        connection.commit()
        return {'message': 'Fresh device-key reauthentication succeeded.', 'session': new_session}


def session_action(action, data, authorization, remote_addr, rid):
    token_kind = 'refresh' if action == 'refresh' else 'access'
    token = str(data.get('refresh_token', '')).strip() if action == 'refresh' else bearer(authorization, data)
    if not token:
        raise domain.V3Error(401, token_kind.upper() + '_TOKEN_REQUIRED', token_kind + '_token が必要です。')
    with connection_for_write(begin=action == 'refresh') as connection:
        session = domain._load_session(connection, token, token_kind, action == 'refresh')
        if not session:
            if action == 'refresh':
                with connection.cursor() as cursor:
                    cursor.execute('SELECT family_id FROM license_v3_refresh_history WHERE token_hash=%s '
                                   'AND expires_at>UTC_TIMESTAMP() LIMIT 1',
                                   (domain.token_hash(domain._config(), token),))
                    history = cursor.fetchone()
                    if history:
                        family_id = str(history['family_id'])
                        cursor.execute("UPDATE license_v3_sessions SET revoked_at=UTC_TIMESTAMP(),"
                                       "revoke_reason='refresh_reuse_detected' WHERE family_id=%s AND revoked_at IS NULL",
                                       (family_id,))
                # Reuse revocation must remain committed even though the HTTP result is 401.
                connection.commit()
                if history:
                    raise domain.V3Error(401, 'REFRESH_REUSE_DETECTED',
                                         '使用済みrefresh tokenが再利用されたためsession familyを失効しました。',
                                         {'family_id': family_id})
            raise domain.V3Error(401, 'SESSION_NOT_FOUND',
                                 'refresh session が見つかりません。' if action == 'refresh' else 'セッションが見つかりません。')
        domain._session_active(session, token_kind)
        domain._verify_pop(connection, session, action, data)
        if action == 'refresh':
            new_session = domain._rotate_session(connection, session)
            connection.commit()
            record_usage(connection, domain._license_row(connection, int(session['license_id'])), action, rid, remote_addr)
            return {'message': 'Tokens rotated.', 'session': new_session}
        if action == 'verify':
            with connection.cursor() as cursor:
                cursor.execute('UPDATE license_v3_sessions SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(session['id']),))
                cursor.execute('UPDATE license_v3_devices SET last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(session['device_id']),))
            license_row = domain._license_row(connection, int(session['license_id']))
            connection.commit()
            record_usage(connection, license_row, action, rid, remote_addr)
            return {'valid': True,
                    'session': {'session_id': session['session_id'], 'family_id': session['family_id'],
                                'token_version': int(session['token_version']),
                                'scopes': domain._json_list(session.get('scopes_json')),
                                'access_expires_at': session['access_expires_at']},
                    'device': {'device_ref': device_reference(session['device_hash']),
                               'key_thumbprint': session['key_thumbprint']},
                    'license': domain._license_payload(license_row) if license_row else None}
        if action == 'introspect':
            connection.commit()
            payload = {key: session[key] for key in ('session_id', 'family_id', 'created_at', 'last_seen_at',
                                                     'access_expires_at', 'refresh_expires_at')}
            payload.update(token_version=int(session['token_version']), scopes=domain._json_list(session.get('scopes_json')))
            return {'active': True, 'session': payload,
                    'device': {'device_ref': device_reference(session['device_hash']),
                               'key_thumbprint': session['key_thumbprint'], 'key_algorithm': session['key_algorithm']}}
        if action == 'revoke':
            scope = 'family' if str(data.get('scope', 'session')).strip().lower() == 'family' else 'session'
            with connection.cursor() as cursor:
                if scope == 'family':
                    cursor.execute("UPDATE license_v3_sessions SET revoked_at=UTC_TIMESTAMP(),revoke_reason='client_family_revoke' "
                                   'WHERE family_id=%s AND revoked_at IS NULL', (str(session['family_id']),))
                else:
                    cursor.execute("UPDATE license_v3_sessions SET revoked_at=UTC_TIMESTAMP(),revoke_reason='client_revoke' "
                                   'WHERE id=%s AND revoked_at IS NULL', (int(session['id']),))
                affected = cursor.rowcount
                cursor.execute('UPDATE license_v3_offline_tickets SET revoked_at=UTC_TIMESTAMP() '
                               'WHERE session_id=%s AND revoked_at IS NULL', (str(session['session_id']),))
            connection.commit()
            return {'revoked': True, 'scope': scope, 'affected_sessions': affected}
        ticket = domain._offline_ticket(connection, session, data.get('hours', 24))
        connection.commit()
        return {'offline_ticket': ticket}


def challenge(data, authorization, remote_addr, rid):
    purpose = str(data.get('purpose', 'activate')).strip().lower()
    if purpose not in ('activate', 'reauth'):
        raise ValueError('challenge_purpose_invalid')
    public_key = v3_crypto.normalize_public_key(data.get('device_public_key', ''))
    with connection_for_write() as connection:
        ip_hash = hashlib.sha256(remote_addr.encode('utf-8')).hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS n FROM auth_attempts WHERE success=0 AND action=%s AND subject_type=%s '
                           'AND subject_hash=%s AND attempted_at >= (UTC_TIMESTAMP() - INTERVAL 900 SECOND)',
                           ('v3_challenge', 'ip', ip_hash))
            if int(cursor.fetchone()['n']) >= 60:
                raise domain.V3Error(429, 'RATE_LIMITED', '試行回数が多すぎます。')
            result = domain._issue_challenge(connection, purpose, public_key, ip_hash)
            cursor.execute('INSERT INTO auth_attempts(ip_hash,action,subject_type,subject_hash,success,error_code,attempted_at) '
                           'VALUES(%s,%s,%s,%s,1,%s,UTC_TIMESTAMP())', (ip_hash, 'v3_challenge', 'ip', ip_hash, 'ok'))
        connection.commit()
        return {'challenge': result}


def execute(action, data, authorization, remote_addr, rid):
    try:
        if action == 'activate':
            payload = activate(data, authorization, remote_addr, rid)
        elif action == 'reauth':
            payload = reauth(data, authorization, remote_addr, rid)
        elif action == 'challenge':
            payload = challenge(data, authorization, remote_addr, rid)
        else:
            payload = session_action(action, data, authorization, remote_addr, rid)
        return reply(payload, rid)
    except Exception as exc:
        return error_response(exc, rid)


def install_routes(api, maintenance_if_needed):
    def endpoint_for(action):
        async def endpoint(request: Request) -> Response:
            maintenance = await run_in_threadpool(maintenance_if_needed, request)
            if maintenance is not None:
                return maintenance
            rid = uuid.uuid4().hex[:16]
            if request.method != 'POST':
                return error_response(domain.V3Error(405, 'METHOD_NOT_ALLOWED', 'POST を使用してください。'), rid)
            try:
                data = await read_data(request)
            except RequestError as exc:
                return error_response(exc, rid)
            original = request.scope.get('wsgi_environ') or {}
            # Apache metadata is only transport context; no WSGI handler is called.
            remote_addr = str(original.get('REMOTE_ADDR') or (request.client.host if request.client else '0.0.0.0'))
            return await run_in_threadpool(execute, action, data, request.headers.get('authorization', ''), remote_addr, rid)
        return endpoint

    for action in ('challenge', 'activate', 'reauth', 'verify', 'introspect', 'refresh', 'revoke', 'offline-ticket'):
        endpoint = endpoint_for(action)
        for prefix in ('/api/v3/', '/license/api/v3/'):
            api.add_api_route(prefix + action + '.php', endpoint, name='v3_' + action,
                              methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE'],
                              include_in_schema=False)
