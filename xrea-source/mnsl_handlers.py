"""Python implementation of MNSL secure-identity session lifecycle."""
from native_http import make_response, add_headers, legacy_compatible
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
import database
from core import PHP_TRIM_CHARS, php_int_cast
from baas_handlers import BaaSError, _assert_write_fence, _authorize_key, _baas_json_input, _client_ip_hash, _reply
from billing_policy import RULES, credit
from http_utils import RequestError
from migration_config import secret_value
SESSION_TTL = 600
EXPECTED_FRAMES = 5
RANDOM_ACTIONS = 3
IDEMPOTENCY_OPERATION = 'mnsl_ios_randomizer'
RANDOM_ACTION_NAMES = ('blink', 'smile', 'turn_left', 'turn_right')
RECORDABLE_OPERATIONS = ('mnsl.face.verify', 'mnsl.liveness.verify', 'mnsl.face_liveness.verify', 'face.verify', 'liveness.verify', 'face_liveness.verify', 'mnsl.jpki.challenge.issue', 'mnsl.jpki.certificate.parse', 'mnsl.jpki.certificate.validity.verify', 'mnsl.jpki.certificate.chain.verify', 'mnsl.jpki.certificate.revocation.verify', 'mnsl.jpki.user_auth.verify', 'mnsl.jpki.signing_cert.verify', 'mnsl.jpki.signature.verify', 'mnsl.jpki.challenge.verify', 'mnsl.jpki.full.verify', 'mnsl.jpki.binding.create', 'mnsl.jpki.binding.verify', 'mnsl.jpki.binding.refresh', 'mnsl.jpki.binding.revoke', 'mnsl.jpki.binding', 'mnsl.terms.jpki.verify')

def _php_gmdate_c(epoch=None):
    """Format gmdate('c') with PHP's explicit UTC offset and integer seconds."""
    value = int(time.time()) if epoch is None else int(epoch)
    return time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(value))
BIOMETRIC_OPERATIONS = frozenset({'mnsl.face.verify', 'mnsl.liveness.verify', 'mnsl.face_liveness.verify', 'face.verify', 'liveness.verify', 'face_liveness.verify'})

class MnslError(Exception):

    def __init__(self, status, error, extra=None):
        super().__init__(error)
        self.status, self.error, self.extra = (status, error, extra or {})

def _b64url(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

def _php_string(value):
    if value is None or value is False:
        return ''
    if value is True:
        return '1'
    if isinstance(value, (dict, list)):
        return 'Array'
    return str(value)

def _php_trim(value):
    return _php_string(value).strip(PHP_TRIM_CHARS)

def _php_lower(value):
    return value.translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))

def _decode(text):
    if not isinstance(text, str) or not re.fullmatch('[A-Za-z0-9_-]+', text):
        return None
    try:
        return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    except Exception:
        return None

def _signing_key():
    secret = secret_value('token_secret')
    if not secret:
        secret = secret_value('key_pepper')
    if len(secret) < 24:
        raise RuntimeError('MNSL API signing secret is unavailable.')
    return hmac.new(secret.encode(), b'mnsl-ios-secure-identity-v1', hashlib.sha256).digest()

def _sign_token(claims):
    payload = _b64url(json.dumps(claims, ensure_ascii=False, separators=(',', ':')).encode())
    signature = _b64url(hmac.new(_signing_key(), payload.encode(), hashlib.sha256).digest())
    return payload + '.' + signature

def _verify_token(token, client):
    match = re.fullmatch('([A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]+)', token)
    if len(token) > 4096 or not match:
        raise MnslError(401, 'invalid_session_token')
    payload, signed = match.groups()
    expected = hmac.new(_signing_key(), payload.encode(), hashlib.sha256).digest()
    actual = _decode(signed)
    raw = _decode(payload)
    if actual is None or not hmac.compare_digest(expected, actual) or raw is None:
        raise MnslError(401, 'invalid_session_token')
    try:
        claims = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MnslError(401, 'invalid_session_token')
    if not isinstance(claims, dict) or int(claims.get('v', 0)) != 1:
        raise MnslError(401, 'invalid_session_token')
    if int(claims.get('exp', 0)) < int(time.time()):
        raise MnslError(409, 'session_expired')
    if int(claims.get('tenant_id', 0)) != int(client['tenant_id']) or int(claims.get('client_id', 0)) != int(client['id']):
        raise MnslError(403, 'session_owner_mismatch')
    if not re.fullmatch('[0-9a-f]{32}', str(claims.get('session_id', ''))) or int(claims.get('frames', 0)) != EXPECTED_FRAMES or (not isinstance(claims.get('actions'), list)) or (len(claims['actions']) != RANDOM_ACTIONS):
        raise MnslError(401, 'invalid_session_token')
    return claims

def _price(environment):
    pricing = RULES.get('api_pricing', {}).get('mnsl.ios.randomizer.capture', {})
    units = int(pricing.get('sandbox_units' if environment == 'sandbox' else 'production_units', 0))
    return {'operation': 'mnsl.ios.randomizer.capture', 'billing_unit': 'completed_secure_identity_session', 'units': units, 'jpy_equivalent': credit(units), 'charge_on': 'successful_complete_only', 'per_frame_billing': False}

def _actions():
    values = list(RANDOM_ACTION_NAMES)
    for index in range(len(values) - 1, 0, -1):
        other = secrets.randbelow(index + 1)
        values[index], values[other] = (values[other], values[index])
    return values[:RANDOM_ACTIONS]

def _bool(data, key):
    value = data.get(key, False)
    return value is True or (type(value) is int and value == 1) or _php_lower(_php_string(value)) in {'1', 'true'}

def _existing(connection, tenant_id, session_id):
    with connection.cursor() as cursor:
        cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s LIMIT 1', (tenant_id, IDEMPOTENCY_OPERATION, session_id))
        row = cursor.fetchone()
    if not row:
        return None
    raw = row.get('response_json') if isinstance(row, dict) else next(iter(row.values()), None)
    if not isinstance(raw, str) or not raw:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None

def _save_terminal(connection, tenant_id, session_id, response):
    raw = json.dumps(response, ensure_ascii=False, separators=(',', ':'))
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO idempotency_keys(tenant_id,operation,request_key,response_json) VALUES(%s,%s,%s,%s)', (tenant_id, IDEMPOTENCY_OPERATION, session_id, raw))

def _recordable(data):
    operation_value = data.get('operation')
    operation = _php_lower(_php_trim('mnsl.face_liveness.verify' if operation_value is None else operation_value))
    payload_value = data.get('payload_sha256')
    payload_sha = _php_lower(_php_trim('' if payload_value is None else payload_value))
    frames_value = data.get('frame_count')
    action_value = data.get('random_actions_completed')
    frames = php_int_cast(0 if frames_value is None else frames_value)
    action_count = php_int_cast(0 if action_value is None else action_value)
    source_value = data.get('verification_source')
    source = _php_trim('client' if source_value is None else source_value)[:80]
    is_biometric = operation in BIOMETRIC_OPERATIONS
    if operation not in RECORDABLE_OPERATIONS or not re.fullmatch('[0-9a-f]{64}', payload_sha) or (is_biometric and (frames < 1 or action_count < 0 or (not _bool(data, 'liveness_pass')))):
        raise MnslError(409, 'verification_incomplete', {'allowed_operations': list(RECORDABLE_OPERATIONS)})
    return (operation, payload_sha, frames, action_count, source)

@legacy_compatible(callback_index=1, request_index=0)
def mnsl(request_context):
    method = str(request_context.get('method', 'GET'))
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        connection = database.connect()
        scope = 'tenant:read' if method == 'GET' else 'licenses:write'
        client, headers, ip_hash = _authorize_key(connection, request_context, scope, 'mnsl.' + method.lower(), rid)
        tenant_id = int(client['tenant_id'])
        environment = str(client.get('tenant_environment') or 'production')
        if method == 'GET':
            price = _price(environment)
            return _reply(200, {'ok': True, 'service': 'mnsl-secure-identity', 'schema': 1, 'endpoint': '/api/baas/v1/mnsl.php', 'supported_actions': ['begin', 'status', 'complete', 'fail', 'record_verification'], 'expected_frames': EXPECTED_FRAMES, 'random_actions': RANDOM_ACTIONS, 'session_ttl_seconds': SESSION_TTL, 'raw_biometrics_stored': False, 'pricing': price}, headers)
        if method != 'POST':
            return _reply(405, {'ok': False, 'error': 'method_not_allowed'}, headers)
        try:
            _assert_write_fence(connection)
        except Exception:
            return _reply(503, {'ok': False, 'error': 'server_not_writable'}, headers)
        data = _baas_json_input(request_context)
        action_value = data.get('action')
        action = _php_lower(_php_trim('' if action_value is None else action_value))
        if action == 'begin':
            session_id = secrets.token_hex(16)
            actions = _actions()
            issued = int(time.time())
            claims = {'v': 1, 'session_id': session_id, 'tenant_id': tenant_id, 'client_id': int(client['id']), 'environment': environment, 'iat': issued, 'exp': issued + SESSION_TTL, 'frames': EXPECTED_FRAMES, 'actions': actions, 'nonce': secrets.token_hex(16)}
            token = _sign_token(claims)
            return _reply(201, {'ok': True, 'state': 'started', 'session_id': session_id, 'session_token': token, 'expires_at_utc': _php_gmdate_c(claims['exp']), 'capture_plan': {'initial': 'front', 'random_actions': actions, 'final': 'front', 'frame_count': EXPECTED_FRAMES}, 'pricing': _price(environment)}, headers)
        if action == 'record_verification':
            operation, payload_sha, frames, action_count, source = _recordable(data)
            rules = RULES
            api = rules.get('operation_map', {}).get(operation, operation if operation in rules.get('api_pricing', {}) else '')
            pricing = rules.get('api_pricing', {}).get(api, {}) if api else {}
            units = int(pricing.get('sandbox_units' if environment == 'sandbox' else 'production_units', 0))
            request_id = uuid.uuid4().hex[:16]
            try:
                with connection.cursor() as cursor:
                    cursor.execute('INSERT INTO tenant_api_usage(tenant_id,client_id,operation,status_code,request_id,ip_hash) VALUES(%s,%s,%s,200,%s,%s)', (tenant_id, int(client['id']), operation, request_id, ip_hash))
                connection.commit()
            except Exception:
                connection.rollback()
                return _reply(503, {'ok': False, 'error': 'verification_usage_commit_failed'}, headers)
            return _reply(200, {'ok': True, 'state': 'recorded', 'request_id': request_id, 'charged': True, 'billing_operation': operation, 'billing_api': api, 'charge_jpy_equivalent': credit(units), 'frame_count': frames, 'random_actions_completed': action_count, 'verification_source': source, 'payload_sha256': payload_sha, 'recorded_at_utc': _php_gmdate_c()}, headers)
        token_value = data.get('session_token')
        if token_value is None:
            token_value = request_context.get('header:x-mnsl-session-token')
        token = _php_trim(token_value)
        claims = _verify_token(token, client)
        session_id = str(claims['session_id'])
        existing = _existing(connection, tenant_id, session_id)
        if action == 'status':
            return _reply(200, {'ok': True, 'session_id': session_id, 'state': (existing or {}).get('state', 'started'), 'terminal': existing is not None, 'pricing': _price(environment)}, headers)
        if action == 'fail':
            if existing is not None:
                existing['replayed'] = True
                return _reply(200, existing, headers)
            reason_value = data.get('reason')
            reason = _php_trim('client_failed' if reason_value is None else reason_value)[:120] or 'client_failed'
            response = {'ok': True, 'state': 'failed', 'session_id': session_id, 'reason': reason, 'charged': False, 'charge_jpy_equivalent': '0.000', 'completed_at_utc': _php_gmdate_c()}
            try:
                _save_terminal(connection, tenant_id, session_id, response)
                connection.commit()
            except Exception as error:
                connection.rollback()
                if getattr(error, 'args', ()) and str(error.args[0]) in {'1062', '23000'}:
                    saved = _existing(connection, tenant_id, session_id)
                    if saved is not None:
                        saved['replayed'] = True
                        return _reply(200, saved, headers)
                return _reply(503, {'ok': False, 'error': 'secure_identity_commit_failed'}, headers)
            return _reply(200, response, headers)
        if action != 'complete':
            return _reply(400, {'ok': False, 'error': 'invalid_action'}, headers)
        if existing is not None:
            if existing.get('state') == 'completed':
                existing['replayed'] = True
                return _reply(200, existing, headers)
            return _reply(409, {'ok': False, 'error': 'session_already_terminal', 'state': existing.get('state', 'unknown'), 'session_id': session_id}, headers)
        frames_value = data.get('frame_count')
        action_value = data.get('random_actions_completed')
        frames = php_int_cast(0 if frames_value is None else frames_value)
        action_count = php_int_cast(0 if action_value is None else action_value)
        payload_value = data.get('payload_sha256')
        payload_sha = _php_lower(_php_trim('' if payload_value is None else payload_value))
        required = ('encrypted_transfer', 'session_protection', 'anti_replay_pass', 'audit_ready', 'random_action_pass')
        if frames != EXPECTED_FRAMES or action_count != RANDOM_ACTIONS or (not all((_bool(data, flag) for flag in required))) or (not re.fullmatch('[0-9a-f]{64}', payload_sha)):
            return _reply(409, {'ok': False, 'error': 'verification_incomplete', 'expected_frames': EXPECTED_FRAMES, 'expected_random_actions': RANDOM_ACTIONS, 'required_flags': list(required)}, headers)
        price = _price(environment)
        request_id = uuid.uuid4().hex[:16]
        response = {'ok': True, 'state': 'completed', 'session_id': session_id, 'request_id': request_id, 'charged': True, 'billing_operation': 'mnsl.ios.randomizer.capture', 'charge_jpy_equivalent': price['jpy_equivalent'], 'frame_count': frames, 'payload_sha256': payload_sha, 'completed_at_utc': _php_gmdate_c()}
        try:
            connection.begin()
            _save_terminal(connection, tenant_id, session_id, response)
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO tenant_api_usage(tenant_id,client_id,operation,status_code,request_id,ip_hash) VALUES(%s,%s,'mnsl.ios.randomizer.capture',200,%s,%s)", (tenant_id, int(client['id']), request_id, ip_hash))
            connection.commit()
        except Exception as error:
            connection.rollback()
            if getattr(error, 'args', ()) and str(error.args[0]) in {'1062', '23000'}:
                saved = _existing(connection, tenant_id, session_id)
                if saved is not None:
                    saved['replayed'] = True
                    return _reply(200, saved, headers)
            return _reply(503, {'ok': False, 'error': 'secure_identity_commit_failed'}, headers)
        return _reply(200, response, headers)
    except RequestError as error:
        status = 413 if str(error) == 'request_too_large' else 400
        return _reply(status, {'ok': False, 'error': str(error)})
    except BaaSError as error:
        return _reply(error.status, {'ok': False, 'error': error.error, **error.extra})
    except MnslError as error:
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
