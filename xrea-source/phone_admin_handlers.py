"""HA-authorized management API for phone activation requests."""
from native_http import make_response, add_headers, legacy_compatible
import json
import os
import secrets
import time
from urllib.parse import parse_qs
import database
from core import phone_confirmation_code, phone_email_decrypt, parse_utc_datetime, token_hash, format_grouped_digits, normalize_digits, hash_secret, php_int_cast, php_bool_cast, PHP_TRIM_CHARS
from http_utils import json_response, read_bounded_body
from v2_handlers import _runtime_config
from v3_handlers import _assert_write_fence

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status, body):
    return json_response(status, body)

def _php_string(value):
    if value is None or value is False:
        return ''
    if value is True:
        return '1'
    if isinstance(value, (dict, list)):
        return 'Array'
    return str(value)

def _php_query_value(query, name, default):
    if name in query:
        values = query[name]
        nested = [value for key, rows in query.items() if key.startswith(name + '[') for value in rows]
        if nested:
            return list(values) + nested
        return values[-1] if values else default
    nested = [value for key, rows in query.items() if key.startswith(name + '[') for value in rows]
    return nested if nested else default

@legacy_compatible(callback_index=None, request_index=0)
def _post_json(request_context):
    raw = read_bounded_body(request_context, 131072)
    try:
        value = json.loads(raw.decode('utf-8'), parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Syntax error')))
    except UnicodeDecodeError:
        raise ValueError('Malformed UTF-8 characters, possibly incorrectly encoded')
    except (json.JSONDecodeError, ValueError):
        raise ValueError('Syntax error')
    depth = 0
    pending = [(value, 0)]
    while pending:
        item, parent_depth = pending.pop()
        if isinstance(item, (dict, list)):
            depth = parent_depth + 1
            if depth > 16:
                raise ValueError('Maximum stack depth exceeded')
            pending.extend(((child, parent_depth + 1) for child in (item.values() if isinstance(item, dict) else item)))
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {}
    raise ValueError('invalid_request')

def _expire(connection):
    with connection.cursor() as cursor:
        cursor.execute("UPDATE phone_activation_requests SET status='expired' WHERE confirmed_at IS NULL AND status<>'expired' AND expires_at<UTC_TIMESTAMP()")
        count = int(getattr(cursor, 'rowcount', 0) or 0)
    connection.commit()
    return count

def _valid_request(row):
    if not row or row.get('cancelled_at') or row.get('confirmed_at'):
        return False
    expires = parse_utc_datetime(str(row.get('expires_at') or ''))
    return expires is None or expires.timestamp() >= int(time.time())

def _issue_code(connection, config, request, email):
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM phone_activation_requests WHERE id=%s LIMIT 1 FOR UPDATE', (int(request['id']),))
            current = cursor.fetchone()
        if not _valid_request(current):
            raise RuntimeError('このリクエストは有効ではありません。')
        if int(current.get('confirmation_code_issue_count') or 0) >= 5:
            raise RuntimeError('confirmation_code_issue_limit_reached')
        code = phone_confirmation_code()
        with connection.cursor() as cursor:
            cursor.execute("UPDATE phone_activation_requests SET confirmation_code_hash=%s,confirmation_code_expires_at=DATE_ADD(UTC_TIMESTAMP(), INTERVAL 600 SECOND),confirmation_code_issued_at=UTC_TIMESTAMP(),confirmation_code_issue_count=confirmation_code_issue_count+1,confirmation_fail_count=0,cancelled_at=NULL,cancelled_reason=NULL,status='code_issued' WHERE id=%s AND confirmed_at IS NULL", (token_hash(config, normalize_digits(code)), int(current['id'])))
        from v2_handlers import _clear_auth_attempts
        _clear_auth_attempts(connection, 'phone_confirm', 'installation_id', hash_secret(normalize_digits(str(current['installation_id']))))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    if email:
        from phone_handlers import _mail_confirmation_code
        if not _mail_confirmation_code(email, str(current['installation_id']), code):
            with connection.cursor() as cursor:
                cursor.execute("UPDATE phone_activation_requests SET confirmation_code_hash=NULL,confirmation_code_expires_at=NULL,status='requested' WHERE id=%s AND confirmed_at IS NULL", (int(current['id']),))
            connection.commit()
            raise RuntimeError('confirmation_email_delivery_failed')
        with connection.cursor() as cursor:
            cursor.execute('UPDATE phone_activation_requests SET email_sent_at=UTC_TIMESTAMP() WHERE id=%s', (int(current['id']),))
        connection.commit()
    return code

@legacy_compatible(callback_index=1, request_index=0)
def phone_admin(request_context):
    from ha_handlers import _append_ha_audit, _effective_role, _ha_authorized_scope
    if not _ha_authorized_scope(request_context, 'phone:manage'):
        return _reply('404 Not Found', {'ok': False, 'error': 'not_found'})
    method = str(request_context.get('method', 'GET'))
    role_config = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', 'unknown'))
    effective = _effective_role()
    writable = role_config == 'primary' and effective != 'maintenance' or (role_config == 'standby' and effective == 'promoted')
    connection = None
    try:
        connection = database.connect()
        _expire(connection)
        if method == 'GET':
            query = parse_qs(str(request_context.get('query', '')), keep_blank_values=True)
            q = _php_string(_php_query_value(query, 'q', '')).strip(PHP_TRIM_CHARS)
            limit_value = _php_query_value(query, 'limit', '100')
            offset_value = _php_query_value(query, 'offset', '0')
            limit = max(1, min(100, php_int_cast(limit_value)))
            offset = max(0, php_int_cast(offset_value))
            where, params = ('', [])
            if q:
                where = ' WHERE (CAST(id AS CHAR) LIKE %s OR installation_id LIKE %s '
                where += 'OR device_label LIKE %s OR status LIKE %s)'
                pattern = '%' + q.replace('%', '\\%').replace('_', '\\_') + '%'
                params = [pattern] * 4
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM phone_activation_requests' + where + ' ORDER BY id DESC LIMIT %s OFFSET %s', tuple(params + [limit, offset]))
                rows = cursor.fetchall()
            from phone_handlers import _request_payload
            return _reply('200 OK', {'ok': True, 'role': ('promoted' if effective == 'promoted' else 'standby') if role_config == 'standby' else 'primary', 'writable': writable, 'requests': [_request_payload(row) for row in rows]})
        if method != 'POST':
            return _reply('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
        if not writable:
            return _reply('503 Service Unavailable', {'ok': False, 'error': 'server_not_writable', 'role': role_config})
        _assert_write_fence(connection)
        try:
            data = _post_json(request_context)
        except Exception as exc:
            status = '413 Payload Too Large' if str(exc) == 'request_too_large' else '400 Bad Request'
            return _reply(status, {'ok': False, 'error': str(exc)})
        action = _php_string(data.get('action')).strip(PHP_TRIM_CHARS)
        installation = ''.join((ch for ch in _php_string(data.get('installation_id')).strip() if ch in '0123456789'))
        if not installation:
            return _reply('400 Bad Request', {'ok': False, 'error': 'installation_id_required'})
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM phone_activation_requests WHERE installation_id=%s LIMIT 1', (installation,))
            request = cursor.fetchone()
        if not request:
            return _reply('404 Not Found', {'ok': False, 'error': 'installation_id_not_found'})
        if action == 'cancel_phone_request':
            with connection.cursor() as cursor:
                cursor.execute("UPDATE phone_activation_requests SET status='cancelled',cancelled_at=UTC_TIMESTAMP(),cancelled_reason=%s WHERE id=%s AND confirmed_at IS NULL", ('admin_cancelled', int(request['id'])))
            connection.commit()
            _append_ha_audit('phone_request_cancelled', {'request_id': int(request['id']), 'license_id': int(request['license_id'])}, request_context)
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM phone_activation_requests WHERE installation_id=%s LIMIT 1', (installation,))
                updated = cursor.fetchone() or request
            from phone_handlers import _request_payload
            return _reply('200 OK', {'ok': True, 'message': '電話認証リクエストを取消しました。', 'request': _request_payload(updated)})
        if action == 'issue_phone_confirmation_code':
            if not _valid_request(request):
                return _reply('400 Bad Request', {'ok': False, 'error': 'phone_request_not_valid'})
            config = _runtime_config()
            email_sent = php_bool_cast(request.get('email_enc'))
            email = phone_email_decrypt(config, str(request['email_enc'])) if email_sent else ''
            code = _issue_code(connection, config, request, email)
            _append_ha_audit('phone_confirmation_code_issued', {'request_id': int(request['id']), 'license_id': int(request['license_id'])}, request_context)
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM phone_activation_requests WHERE installation_id=%s LIMIT 1', (installation,))
                updated = cursor.fetchone() or request
            from phone_handlers import _request_payload
            return _reply('200 OK', {'ok': True, 'message': '確認コードをメールで再送しました。' if email_sent else 'confirmation code を発行しました。', 'request': _request_payload(updated), 'confirmation_code': None if email_sent else format_grouped_digits(code)})
        return _reply('400 Bad Request', {'ok': False, 'error': 'invalid_action'})
    except database.DatabaseConfigurationError:
        return _reply('503 Service Unavailable', {'ok': False, 'error': 'service_unavailable'})
    except RuntimeError as exc:
        if connection:
            connection.rollback()
        error = str(exc)
        public_error = {'confirmation_code_issue_limit_reached': 'confirmation code の再発行回数の上限に達しています。', 'confirmation_email_delivery_failed': 'confirmation_email_delivery_failed'}.get(error, error)
        request_id = secrets.token_hex(8)
        _append_ha_audit('phone_admin_failed', {'request_id': request_id, 'error': error}, request_context)
        return _reply('400 Bad Request', {'ok': False, 'error': public_error, 'request_id': request_id})
    except Exception:
        if connection:
            connection.rollback()
        request_id = secrets.token_hex(8)
        _append_ha_audit('phone_admin_failed', {'request_id': request_id}, request_context)
        return _reply('503 Service Unavailable', {'ok': False, 'error': 'phone_admin_failed', 'request_id': request_id})
    finally:
        if connection:
            connection.close()
