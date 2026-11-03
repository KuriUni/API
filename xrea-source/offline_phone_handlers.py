"""Python port of the HA offline-phone confirmation issue/list/revoke API."""
from native_http import make_response, add_headers, legacy_compatible
from py36_compat import parse_iso_datetime
import base64
import hashlib
import hmac
import io
import json
import os
import re
import time
from datetime import datetime, timezone
from email.parser import BytesParser
from email.policy import default as default_email_policy
from pathlib import Path
from path_utils import is_relative_to
from urllib.parse import parse_qsl
import database
from core import PHP_TRIM_CHARS, php_int_cast
from http_utils import json_response
from migration_config import secret_value
IID_PATTERN = re.compile('IID-([0-9A-F]{20})-([0-9A-F]{20})-([0-9A-F]{12})-([0-9A-F]{8})\\Z')

class OfflinePhoneInputError(ValueError):
    pass

def _php_string(value):
    if value is None or value is False:
        return ''
    if value is True:
        return '1'
    if isinstance(value, (list, dict)):
        return 'Array'
    return str(value)

def _store_form_field(fields, name, value):
    name = str(name).replace(' ', '_').replace('.', '_')
    match = re.match('^([^\\[\\]]+)\\[', name)
    fields[match.group(1) if match else name] = 'Array' if match else value

@legacy_compatible(callback_index=None, request_index=1)
def _parse_form(raw, request_context):
    content_type_header = str(request_context.get('content_type') or request_context.get('header:content-type') or '')
    content_type = content_type_header.lower()
    fields = {}
    if content_type.startswith('application/x-www-form-urlencoded'):
        for key, value in parse_qsl(raw.decode('utf-8', errors='replace'), keep_blank_values=True):
            _store_form_field(fields, key, value)
        return fields
    if content_type.startswith('multipart/form-data'):
        header = ('Content-Type: ' + content_type_header + '\r\nMIME-Version: 1.0\r\n\r\n').encode('ascii')
        message = BytesParser(policy=default_email_policy).parsebytes(header + raw)
        for part in message.iter_parts():
            if part.get_content_disposition() != 'form-data' or part.get_filename() is not None:
                continue
            name = part.get_param('name', header='content-disposition')
            if not isinstance(name, str):
                continue
            payload = part.get_payload(decode=True) or b''
            charset = part.get_content_charset() or 'utf-8'
            _store_form_field(fields, name, payload.decode(charset))
    return fields

def _reject_json_constant(_value):
    raise ValueError('invalid_json_constant')

@legacy_compatible(callback_index=None, request_index=0)
def _request_data(request_context):
    stream = request_context.get('body_stream')
    raw = stream.read() if stream is not None else b''
    try:
        value = json.loads(raw.decode('utf-8'), parse_constant=_reject_json_constant) if raw else None
        if isinstance(value, dict):
            return (value, {})
        if isinstance(value, list):
            return ({}, {})
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        pass
    form = _parse_form(raw, request_context)
    return (form, form)

@legacy_compatible(callback_index=None, request_index=0)
def _auth_post_fields(request_context):
    """Read PHP-style $_POST auth fields without decoding JSON before auth."""
    if request_context.get('method', '') != 'POST':
        return {}
    stream = request_context.get('body_stream')
    raw = stream.read() if stream is not None else b''
    request_context['body_stream'] = io.BytesIO(raw)
    content_type = str(request_context.get('content_type') or request_context.get('header:content-type') or '').lower()
    if content_type.startswith(('application/x-www-form-urlencoded', 'multipart/form-data')):
        return _parse_form(raw, request_context)
    return {}

def validate_installation_id(value):
    iid = _php_string(value).strip(PHP_TRIM_CHARS).translate(str.maketrans('abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'))
    match = IID_PATTERN.fullmatch(iid)
    if not match:
        raise OfflinePhoneInputError('invalid_installation_id')
    first, device_ref, third, checksum = match.groups()
    expected = hashlib.sha256(('iid|' + first + device_ref + third).encode()).hexdigest()[:8].upper()
    if not hmac.compare_digest(expected, checksum):
        raise OfflinePhoneInputError('invalid_installation_id')
    return (iid, device_ref)

def _derived_key(purpose):
    token = secret_value('ha_sync_token')
    if not token:
        token = os.environ.get('PYTHON_MIGRATION_HA_SYNC_TOKEN', '')
    if not token:
        raise RuntimeError('offline_signing_key_unconfigured')
    return hmac.new(token.encode(), ('tuti-license-ha/' + purpose).encode(), hashlib.sha256).digest()

def _ip_hash(remote_addr):
    address = '' if remote_addr is None else str(remote_addr)
    return hmac.new(_derived_key('offline-rate/v1'), address.encode(), hashlib.sha256).hexdigest()

def _signing_key():
    private_dir = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not private_dir:
        raise RuntimeError('offline_signing_key_unconfigured')
    private_root = Path(private_dir).expanduser().resolve()
    document_root = Path(os.environ.get('DOCUMENT_ROOT', Path(__file__).resolve().parent)).resolve()
    if private_root == document_root or document_root in private_root.parents:
        raise RuntimeError('offline_signing_key_unconfigured')
    key_path = private_root / 'offline-signing-rsa8192-private.pem'
    try:
        resolved_key = key_path.resolve(strict=True)
        if not is_relative_to(resolved_key, private_root) or resolved_key == document_root or document_root in resolved_key.parents:
            raise RuntimeError('offline_signing_key_unconfigured')
        if resolved_key.stat().st_mode & 63:
            raise RuntimeError('offline_signing_key_invalid')
        key_bytes = resolved_key.read_bytes()
    except RuntimeError:
        raise
    except OSError:
        raise RuntimeError('offline_signing_key_unconfigured')
    try:
        from cryptography.hazmat.primitives import serialization
        key = serialization.load_pem_private_key(key_bytes, password=None)
    except Exception:
        raise RuntimeError('offline_signing_key_unconfigured')
    from cryptography.hazmat.primitives.asymmetric import rsa
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 8192:
        raise RuntimeError('offline_signing_key_invalid')
    return key

def _sign_confirmation(claims, private_key):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    payload = base64.urlsafe_b64encode(json.dumps(claims, ensure_ascii=False, separators=(',', ':')).encode()).rstrip(b'=').decode('ascii')
    signature = private_key.sign(('TUTI-OFFLINE-CID3|' + payload).encode(), padding.PKCS1v15(), hashes.SHA256())
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b'=').decode('ascii')
    return 'CID3.' + payload + '.' + encoded_signature

@legacy_compatible(callback_index=0, request_index=None)
def _status(code, payload):
    names = {200: '200 OK', 400: '400 Bad Request', 401: '401 Unauthorized', 404: '404 Not Found', 405: '405 Method Not Allowed', 409: '409 Conflict', 429: '429 Too Many Requests', 503: '503 Service Unavailable'}
    return json_response(names.get(code, '%d Error' % code), payload)

@legacy_compatible(callback_index=1, request_index=0)
def offline_phone(request_context):
    from ha_handlers import _append_ha_audit, _ha_authorized_scope
    from v3_handlers import _assert_write_fence
    post_fields = _auth_post_fields(request_context)
    auth_environ = request_context
    if post_fields.get('token') and (not request_context.get('header:x-ha-token')):
        auth_environ = dict(request_context)
        auth_environ['header:x-ha-token'] = post_fields['token']
    if not _ha_authorized_scope(auth_environ, 'offline:issue'):
        return _status(404, {'ok': False, 'error': 'not_found'})
    if request_context.get('method', '') != 'POST':
        return _status(405, {'ok': False, 'error': 'method_not_allowed'})
    from ha_handlers import _runtime_json
    role = os.environ.get('PYTHON_MIGRATION_HA_ROLE', '')
    state = _runtime_json('state.json') or {}
    maintenance = state.get('maintenance') is True if 'maintenance' in state else os.environ.get('PYTHON_MIGRATION_HA_MAINTENANCE') == '1'
    promoted = state.get('promoted') is True if 'promoted' in state else os.environ.get('PYTHON_MIGRATION_HA_PROMOTED') == '1'
    if not (role == 'primary' and (not maintenance) or (role == 'standby' and promoted)):
        return _status(503, {'ok': False, 'error': 'server_not_writable'})
    data, _post_fields = _request_data(request_context)
    connection = None
    try:
        action_value = data.get('action')
        action = _php_string('issue' if action_value is None else action_value)
        connection = database.connect()
        _assert_write_fence(connection)
        if action == 'list':
            raw_limit = data.get('limit')
            limit = php_int_cast(100 if raw_limit is None else raw_limit)
            limit = max(1, min(200, limit))
            raw_query = data.get('q')
            query = _php_string('' if raw_query is None else raw_query).strip(PHP_TRIM_CHARS)
            raw_status = data.get('status', 'all')
            status_filter = 'all' if raw_status is None else _php_string(raw_status)
            raw_license_id = data.get('license_id')
            license_id = php_int_cast(0 if raw_license_id is None else raw_license_id)
            sql = 'SELECT r.id,r.license_id,l.label AS license_label,r.device_ref,r.expires_day,r.issued_at,r.revoked_at,r.revocation_reason,r.last_reconciled_at FROM offline_activation_requests r LEFT JOIN licenses l ON l.id=r.license_id'
            where, args = ([], [])
            if license_id > 0:
                where.append('r.license_id=%s')
                args.append(license_id)
            if query:
                if query and re.fullmatch('[0-9]+', query):
                    where.append('(r.license_id=%s OR r.id=%s)')
                    numeric_query = php_int_cast(query)
                    args.extend((numeric_query, numeric_query))
                else:
                    where.append("(r.device_ref LIKE %s OR COALESCE(l.label,'') LIKE %s)")
                    args.extend(('%' + query + '%', '%' + query + '%'))
            if status_filter == 'active':
                where.append('r.revoked_at IS NULL')
            elif status_filter == 'revoked':
                where.append('r.revoked_at IS NOT NULL')
            if where:
                sql += ' WHERE ' + ' AND '.join(where)
            sql += ' ORDER BY r.id DESC LIMIT ' + str(limit)
            with connection.cursor() as cursor:
                cursor.execute(sql, tuple(args))
                rows = cursor.fetchall()
            return _status(200, {'ok': True, 'requests': rows})
        if action == 'revoke':
            raw_request_id = data.get('request_id')
            request_id = php_int_cast(0 if raw_request_id is None else raw_request_id)
            raw_reason = data.get('reason', 'operator_revoked')
            reason = _php_string('operator_revoked' if raw_reason is None else raw_reason).strip(PHP_TRIM_CHARS)[:200]
            if request_id < 1:
                raise OfflinePhoneInputError('invalid_request_id')
            with connection.cursor() as cursor:
                cursor.execute('UPDATE offline_activation_requests SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),revocation_reason=COALESCE(revocation_reason,%s) WHERE id=%s', (reason, request_id))
                changed = cursor.rowcount
            if changed < 1:
                raise RuntimeError('request_not_found')
            connection.commit()
            _append_ha_audit('offline_phone_confirmation_revoked', {'request_id': request_id, 'reason': reason}, request_context)
            return _status(200, {'ok': True, 'request_id': request_id})
        if action != 'issue':
            raise OfflinePhoneInputError('invalid_action')
        iid, device_ref = validate_installation_id(data.get('installation_id', ''))
        raw_days = data.get('days')
        days = php_int_cast(30 if raw_days is None else raw_days)
        days = max(1, min(30, days))
        ip_hash = _ip_hash(request_context.get('client_address', ''))
        session_or_token = request_context.get('header:x-ha-session')
        if session_or_token is None:
            session_or_token = request_context.get('header:x-ha-token', '')
        issued_by_hash = hashlib.sha256(str(session_or_token).encode()).hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS count FROM offline_activation_requests WHERE request_ip_hash=%s AND issued_at>=UTC_TIMESTAMP()-INTERVAL 1 HOUR', (ip_hash,))
            row = cursor.fetchone() or {}
            if int(row.get('count', 0)) >= 20:
                raise RuntimeError('offline_rate_limited')
            cursor.execute('SELECT * FROM licenses WHERE offline_lookup=%s LIMIT 1', (iid[4:24],))
            license_row = cursor.fetchone()
        if not license_row or int(license_row.get('active') or 0) != 1 or license_row.get('revoked_at') or (not license_row.get('offline_secret_enc')):
            raise RuntimeError('offline_activation_unavailable')
        if int(license_row.get('evaluation_days') or 0) != 0:
            raise RuntimeError('evaluation_offline_not_allowed')
        expires_at = license_row.get('expires_at')
        if expires_at:
            if isinstance(expires_at, datetime):
                parsed = expires_at
            else:
                try:
                    parsed = parse_iso_datetime(str(expires_at).replace('Z', '+00:00'))
                except ValueError:
                    raise RuntimeError('offline_activation_unavailable')
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            if int(parsed.timestamp()) < int(time.time()):
                raise RuntimeError('offline_activation_unavailable')
        license_id = int(license_row['id'])
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS count FROM offline_activation_requests WHERE license_id=%s AND issued_at>=UTC_TIMESTAMP()-INTERVAL 1 DAY', (license_id,))
            row = cursor.fetchone() or {}
            if int(row.get('count', 0)) >= 5:
                raise RuntimeError('license_offline_limit_reached')
        iid_hash = hashlib.sha256(iid.encode()).hexdigest()
        requested_expiry = int(time.time() // 86400) + days
        with connection.cursor() as cursor:
            cursor.execute('INSERT IGNORE INTO offline_activation_requests(license_id,installation_id_hash,device_ref,expires_day,issued_by_hash,request_ip_hash) VALUES(%s,%s,%s,%s,%s,%s)', (license_id, iid_hash, device_ref, requested_expiry, issued_by_hash, ip_hash))
        connection.commit()
        with connection.cursor() as cursor:
            cursor.execute('SELECT id,expires_day,revoked_at FROM offline_activation_requests WHERE installation_id_hash=%s', (iid_hash,))
            request_row = cursor.fetchone()
        if not request_row or request_row.get('revoked_at'):
            raise RuntimeError('offline_confirmation_revoked')
        expires_day = int(request_row['expires_day'])
        private_key = _signing_key()
        issued_day = int(time.time() // 86400)
        claims = {'v': 3, 'alg': 'RS256', 'kid': 'rsa8192-v1', 'iid_hash': iid_hash, 'device_ref': device_ref, 'license_id': license_id, 'epoch': int(license_row.get('offline_epoch') if license_row.get('offline_epoch') is not None else 1), 'issued_day': issued_day, 'expires_day': expires_day}
        confirmation = _sign_confirmation(claims, private_key)
        _append_ha_audit('offline_phone_confirmation_issued', {'request_id': int(request_row['id']), 'license_id': license_id, 'installation_id_hash': iid_hash, 'device_ref': device_ref, 'expires_day': expires_day, 'signature_algorithm': 'RSA-8192/SHA-256', 'kid': 'rsa8192-v1'}, request_context)
        return _status(200, {'ok': True, 'request_id': int(request_row['id']), 'confirmation_id': confirmation, 'expires_day': expires_day, 'valid_days': max(0, expires_day - int(time.time() // 86400)), 'license_id': license_id, 'signature_algorithm': 'RSA-8192/SHA-256', 'kid': 'rsa8192-v1'})
    except OfflinePhoneInputError as exc:
        return _status(400, {'ok': False, 'error': str(exc)})
    except database.DatabaseConfigurationError:
        return _status(503, {'ok': False, 'error': 'offline_confirmation_failed'})
    except RuntimeError as exc:
        return _status(429 if str(exc) == 'offline_rate_limited' else 409, {'ok': False, 'error': str(exc)})
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        return _status(503, {'ok': False, 'error': 'offline_confirmation_failed'})
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
