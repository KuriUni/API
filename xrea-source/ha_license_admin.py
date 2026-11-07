"""HA license search and administrative operations."""
from native_http import make_response, add_headers, legacy_compatible
from py36_compat import parse_iso_datetime
import os
import json
import re
import uuid
from datetime import datetime, timezone
from urllib.parse import parse_qsl
import database
from core import PHP_TRIM_CHARS, is_valid_license_key_format, license_key_hash, php_int_cast, normalize_license_key
from http_utils import json_response, read_bounded_body, RequestError
from v2_handlers import _runtime_config
from v3_handlers import _assert_write_fence
_ENV_SQL = "CASE WHEN t.parent_tenant_id IS NOT NULL OR t.environment='sandbox' THEN 'sandbox' WHEN t.environment='production' THEN 'production' ELSE 'unknown' END"
_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')

class LicenseAdminInputError(ValueError):
    """An exception PHP handles as an InvalidArgumentException."""

def _php_string(value, default=''):
    if value is None:
        return default
    if value is True:
        return '1'
    if value is False:
        return ''
    if isinstance(value, (list, dict)):
        return 'Array'
    return str(value)

def _coalesce(data, key, default):
    value = data.get(key)
    return default if value is None else value

def _php_trim(value):
    return _php_string(value).strip(PHP_TRIM_CHARS)

def _php_trim_lower(value):
    return _php_trim(value).translate(_ASCII_LOWER)

@legacy_compatible(callback_index=None, request_index=0)
def _php_get_query(request_context):
    """Parse GET field names with PHP parse_str's space/dot normalization."""
    query = {}
    for key, value in parse_qsl(str(request_context.get('query', '')), keep_blank_values=True):
        key = key.replace(' ', '_').replace('.', '_')
        match = re.match('^([^\\[\\]]+)\\[', key)
        query[match.group(1) if match else key] = [[value]] if match else [value]
    return query

@legacy_compatible(callback_index=None, request_index=0)
def _license_admin_json_data(request_context):
    """Decode the endpoint's direct json_decode(..., true, 16, THROW) body."""
    try:
        raw = read_bounded_body(request_context, 65536)
    except RequestError as exc:
        raise LicenseAdminInputError(str(exc)) from exc
    try:
        decoded = json.loads(raw.decode('utf-8'), parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('Syntax error')))
    except UnicodeDecodeError as exc:
        raise LicenseAdminInputError('Malformed UTF-8 characters, possibly incorrectly encoded') from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise LicenseAdminInputError('Syntax error') from exc
    except RecursionError as exc:
        raise LicenseAdminInputError('Maximum stack depth exceeded') from exc
    pending = [(decoded, 0)]
    while pending:
        value, parent_depth = pending.pop()
        if isinstance(value, (dict, list)):
            depth = parent_depth + 1
            if depth > 16:
                raise LicenseAdminInputError('Maximum stack depth exceeded')
            children = value.values() if isinstance(value, dict) else value
            pending.extend(((child, depth) for child in children))
    return decoded if isinstance(decoded, dict) else {}

def _role_and_write():
    from ha_handlers import _effective_role
    configured = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    effective = _effective_role()
    writable = configured == 'primary' and effective != 'maintenance' or (configured == 'standby' and effective == 'promoted')
    return (configured, writable, 'promoted' if configured == 'standby' else 'primary')

def _revoke_devices(connection, license_id):
    with connection.cursor() as cursor:
        cursor.execute('UPDATE license_devices SET revoked_at=UTC_TIMESTAMP(),token_version=token_version+1 WHERE license_id=%s AND revoked_at IS NULL', (license_id,))
        return int(cursor.rowcount or 0)

def _date_value(value):
    raw = _php_trim(value)
    if not raw:
        return None
    try:
        parsed = parse_iso_datetime(raw.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('invalid_expires_at') from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

@legacy_compatible(callback_index=1, request_index=0)
def license_admin(request_context):
    from ha_handlers import _append_ha_audit, _ha_authorized_scope
    if not _ha_authorized_scope(request_context, 'license:manage'):
        return json_response('404 Not Found', {'ok': False, 'error': 'not_found'})
    method = str(request_context.get('method', ''))
    configured_role, writable, public_role = _role_and_write()
    connection = None
    try:
        connection = database.connect()
        if method == 'POST':
            _assert_write_fence(connection)
        if str(request_context.get('method', 'GET')) == 'GET':
            query = _php_get_query(request_context)

            def get(name, default=''):
                return query.get(name, [default])[-1]
            if php_int_cast(get('context', '0')) == 1:
                with connection.cursor() as cursor:
                    cursor.execute(f"SELECT t.id,t.slug,t.name,t.status,t.plan_code,{_ENV_SQL} environment,t.parent_tenant_id,t.max_products,t.max_licenses FROM tenants t ORDER BY CASE {_ENV_SQL} WHEN 'production' THEN 0 WHEN 'sandbox' THEN 1 ELSE 2 END,COALESCE(t.parent_tenant_id,t.id),t.id")
                    tenants = cursor.fetchall()
                    cursor.execute("SELECT id,tenant_id,code,name,status FROM products WHERE status<>'deleted' ORDER BY tenant_id,id")
                    products = cursor.fetchall()
                from ha_handlers import _json_value
                return json_response('200 OK', {'ok': True, 'role': public_role, 'writable': writable, 'tenants': _json_value(tenants), 'products': _json_value(products)})
            try:
                detail_id = php_int_cast(get('license_id', '0'))
            except ValueError:
                detail_id = 0
            if detail_id > 0:
                with connection.cursor() as cursor:
                    cursor.execute(f"SELECT l.*,{_ENV_SQL} environment,t.slug tenant_slug,t.name tenant_name,t.status tenant_status,p.code product_code,p.name product_name,CASE WHEN l.evaluation_days IS NOT NULL THEN 'evaluation' WHEN l.max_devices>1 THEN 'volume' ELSE 'single' END license_mode FROM licenses l LEFT JOIN tenants t ON t.id=l.tenant_id LEFT JOIN products p ON p.id=l.product_id AND p.tenant_id=l.tenant_id WHERE l.id=%s AND l.deleted_at IS NULL", (detail_id,))
                    license_row = cursor.fetchone()
                    if not license_row:
                        raise LicenseAdminInputError('license_not_found')
                    cursor.execute('SELECT id,device_label,first_activated_at,last_seen_at,access_expires_at,refresh_expires_at,revoked_at,app_version,token_version FROM license_devices WHERE license_id=%s ORDER BY id DESC', (detail_id,))
                    devices = cursor.fetchall()
                    cursor.execute('SELECT action,success,error_code,attempted_at FROM auth_attempts WHERE subject_hash=%s ORDER BY id DESC LIMIT 30', (license_row.get('key_hash'),))
                    attempts = cursor.fetchall()
                    cursor.execute('SELECT id,device_ref,expires_day,issued_at,revoked_at,revocation_reason,last_reconciled_at FROM offline_activation_requests WHERE license_id=%s ORDER BY id DESC LIMIT 100', (detail_id,))
                    offline = cursor.fetchall()
                license_row.pop('key_hash', None)
                from ha_handlers import _json_value
                return json_response('200 OK', {'ok': True, 'role': public_role, 'writable': writable, 'license': _json_value(license_row), 'devices': _json_value(devices), 'offline_requests': _json_value(offline), 'recent_attempts': _json_value(attempts)})
            search = _php_trim(get('q'))
            try:
                limit = max(1, min(200, php_int_cast(get('limit', '100'))))
                offset = max(0, php_int_cast(get('offset', '0')))
                tenant_id = max(0, php_int_cast(get('tenant_id', '0')))
            except ValueError as exc:
                raise LicenseAdminInputError('invalid_request') from exc
            environment = _php_trim_lower(get('environment', 'all'))
            if environment not in {'all', 'production', 'sandbox'}:
                raise LicenseAdminInputError('invalid_environment')
            where, params = (['l.deleted_at IS NULL'], [])
            if environment != 'all':
                where.append(_ENV_SQL + '=%s')
                params.append(environment)
            if tenant_id:
                where.append('l.tenant_id=%s')
                params.append(tenant_id)
            scope_where, scope_params = (list(where), list(params))
            if search:
                where.append('(CAST(l.id AS CHAR)=%s OR l.label LIKE %s OR t.slug LIKE %s OR t.name LIKE %s OR p.code LIKE %s OR p.name LIKE %s)')
                params.extend([search] + ['%' + search + '%'] * 5)
            state = _php_string(get('state', 'all'))
            if state == 'active':
                where.append('l.active=1 AND (l.expires_at IS NULL OR l.expires_at>=UTC_TIMESTAMP())')
            elif state == 'inactive':
                where.append('l.active=0')
            elif state == 'expired':
                where.append('l.expires_at IS NOT NULL AND l.expires_at<UTC_TIMESTAMP()')
            mode = _php_string(get('mode', 'all'))
            if mode == 'evaluation':
                where.append('l.evaluation_days IS NOT NULL')
            elif mode == 'volume':
                where.append('l.evaluation_days IS NULL AND l.max_devices>1')
            elif mode == 'single':
                where.append('l.evaluation_days IS NULL AND l.max_devices=1')
            select = f"SELECT l.id,l.tenant_id,l.product_id,t.slug tenant_slug,t.name tenant_name,{_ENV_SQL} environment,p.code product_code,p.name product_name,l.label,l.active,l.max_devices,CASE WHEN l.evaluation_days IS NOT NULL THEN 'evaluation' WHEN l.max_devices>1 THEN 'volume' ELSE 'single' END license_mode,l.evaluation_days,l.evaluation_started_at,l.expires_at,l.revoked_at,l.created_at,l.last_activated_at,l.last_seen_at,(SELECT COUNT(*) FROM license_devices d WHERE d.license_id=l.id AND d.revoked_at IS NULL) active_devices FROM licenses l LEFT JOIN tenants t ON t.id=l.tenant_id LEFT JOIN products p ON p.id=l.product_id AND p.tenant_id=l.tenant_id WHERE " + ' AND '.join(where) + ' ORDER BY l.id DESC LIMIT %s OFFSET %s'
            with connection.cursor() as cursor:
                cursor.execute(select, tuple(params + [limit, offset]))
                licenses = cursor.fetchall()
                stats_sql = 'SELECT COUNT(*) total,SUM(l.active=1) active,SUM(l.active=0) inactive,SUM(l.expires_at IS NOT NULL AND l.expires_at<UTC_TIMESTAMP()) expired FROM licenses l LEFT JOIN tenants t ON t.id=l.tenant_id WHERE ' + ' AND '.join(scope_where)
                cursor.execute(stats_sql, tuple(scope_params))
                stats = cursor.fetchone() or {}
            stats = {key: int(value or 0) for key, value in stats.items()}
            from ha_handlers import _json_value
            return json_response('200 OK', {'ok': True, 'role': public_role, 'writable': writable, 'scope': {'environment': environment, 'tenant_id': tenant_id or None}, 'stats': stats, 'licenses': _json_value(licenses)})
        if not writable:
            return json_response('503 Service Unavailable', {'ok': False, 'error': 'server_not_writable', 'role': configured_role})
        data = _license_admin_json_data(request_context)
        action = _php_string(_coalesce(data, 'action', ''))
        if action == 'lookup_product_key':
            key = normalize_license_key(_php_string(_coalesce(data, 'product_key', '')))
            if not is_valid_license_key_format(key):
                raise LicenseAdminInputError('invalid_product_key')
            key_hash = license_key_hash(_runtime_config(), key)
            with connection.cursor() as cursor:
                cursor.execute(f'SELECT l.id,{_ENV_SQL} environment,l.tenant_id,l.product_id,t.slug tenant_slug,t.name tenant_name,p.code product_code,p.name product_name FROM licenses l LEFT JOIN tenants t ON t.id=l.tenant_id LEFT JOIN products p ON p.id=l.product_id AND p.tenant_id=l.tenant_id WHERE l.key_hash=%s AND l.deleted_at IS NULL LIMIT 1', (key_hash,))
                found = cursor.fetchone()
            license_id = int(found.get('id') or 0) if found else 0
            _append_ha_audit('product_key_lookup', {'license_id': license_id, 'found': bool(license_id)}, request_context)
            return json_response('200 OK', {'ok': True, 'found': bool(license_id), 'license_id': license_id or None, 'environment': found.get('environment') if found else None, 'tenant_id': int(found['tenant_id']) if found and found.get('tenant_id') is not None else None, 'product_id': int(found['product_id']) if found and found.get('product_id') is not None else None, 'tenant_name': found.get('tenant_name') if found else None, 'product_name': found.get('product_name') if found else None})
        try:
            license_id = php_int_cast(data.get('license_id'))
        except (TypeError, ValueError):
            license_id = 0
        if license_id < 1:
            raise LicenseAdminInputError('invalid_request')
        if data.get('expected_environment') is not None or data.get('expected_tenant_id') is not None:
            with connection.cursor() as cursor:
                cursor.execute(f'SELECT l.tenant_id,{_ENV_SQL} environment FROM licenses l LEFT JOIN tenants t ON t.id=l.tenant_id WHERE l.id=%s AND l.deleted_at IS NULL', (license_id,))
                scope = cursor.fetchone()
            if not scope:
                raise LicenseAdminInputError('license_not_found')
            if data.get('expected_environment') is not None:
                expected = _php_trim_lower(data['expected_environment'])
                expected = expected if expected in {'production', 'sandbox'} else 'unknown'
                if expected != str(scope['environment']):
                    raise LicenseAdminInputError('environment_mismatch')
            if data.get('expected_tenant_id') is not None and php_int_cast(data['expected_tenant_id']) != int(scope['tenant_id']):
                raise LicenseAdminInputError('tenant_mismatch')
        affected = 0
        if action in {'activate', 'deactivate'}:
            active = 1 if action == 'activate' else 0
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET active=%s,revoked_at=%s WHERE id=%s', (active, None if active else datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), license_id))
                affected = int(cursor.rowcount or 0)
            if not active:
                _revoke_devices(connection, license_id)
        elif action == 'update':
            label = _php_trim(_coalesce(data, 'label', ''))[:100] or None
            max_devices = max(1, min(10000, php_int_cast(_coalesce(data, 'max_devices', 1))))
            expiry = _date_value(_coalesce(data, 'expires_at', ''))
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET label=%s,max_devices=%s,expires_at=%s WHERE id=%s', (label, max_devices, expiry, license_id))
                affected = int(cursor.rowcount or 0)
        elif action in {'revoke_device', 'restore_device'}:
            try:
                device_id = php_int_cast(data.get('device_id'))
            except (TypeError, ValueError):
                device_id = 0
            if device_id < 1:
                raise LicenseAdminInputError('invalid_device')
            revoked_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if action == 'revoke_device' else None
            with connection.cursor() as cursor:
                cursor.execute('UPDATE license_devices SET revoked_at=%s,token_version=token_version+1 WHERE id=%s AND license_id=%s', (revoked_at, device_id, license_id))
                affected = int(cursor.rowcount or 0)
        elif action == 'revoke_all_devices':
            with connection.cursor() as cursor:
                cursor.execute('UPDATE license_devices SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),token_version=token_version+1 WHERE license_id=%s', (license_id,))
                affected = int(cursor.rowcount or 0)
        elif action == 'extend_expiry':
            days = max(1, min(3650, php_int_cast(_coalesce(data, 'days', 30))))
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET expires_at=DATE_ADD(GREATEST(COALESCE(expires_at,UTC_TIMESTAMP()),UTC_TIMESTAMP()),INTERVAL %s DAY) WHERE id=%s', (days, license_id))
                affected = int(cursor.rowcount or 0)
        elif action == 'delete_license':
            reason = _php_trim(_coalesce(data, 'reason', 'administrator_request'))[:200]
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET active=0,revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),deleted_at=UTC_TIMESTAMP(),deleted_reason=%s WHERE id=%s AND deleted_at IS NULL AND (active=0 OR (expires_at IS NOT NULL AND expires_at<UTC_TIMESTAMP()))', (reason, license_id))
                affected = int(cursor.rowcount or 0)
            if affected < 1:
                raise LicenseAdminInputError('license_not_deletable')
            _revoke_devices(connection, license_id)
        elif action == 'delete_issued_license':
            reason = _php_trim(_coalesce(data, 'reason', 'administrator_delete_issued_key'))[:200]
            reason = reason or 'administrator_delete_issued_key'
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE licenses SET active=0,revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),deleted_at=UTC_TIMESTAMP(),deleted_reason=%s WHERE id=%s AND deleted_at IS NULL', (reason, license_id))
                    affected = int(cursor.rowcount or 0)
                if affected < 1:
                    raise LicenseAdminInputError('license_not_found_or_already_deleted')
                _revoke_devices(connection, license_id)
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE phone_activation_requests SET status='cancelled',cancelled_at=COALESCE(cancelled_at,UTC_TIMESTAMP()),cancelled_reason=COALESCE(cancelled_reason,%s) WHERE license_id=%s AND status NOT IN ('confirmed','cancelled','expired')", ('license_deleted', license_id))
                    cursor.execute('UPDATE offline_activation_requests SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()),revocation_reason=COALESCE(revocation_reason,%s) WHERE license_id=%s AND revoked_at IS NULL', ('license_deleted', license_id))
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        else:
            raise LicenseAdminInputError('invalid_action')
        connection.commit()
        event = 'license_' + action
        _append_ha_audit(event, {'license_id': license_id, 'device_id': php_int_cast(data.get('device_id'))}, request_context)
        return json_response('200 OK', {'ok': True, 'license_id': license_id, 'action': action, 'affected': affected, 'role': public_role})
    except LicenseAdminInputError as exc:
        if connection:
            connection.rollback()
        status = '413 Payload Too Large' if str(exc) == 'request_too_large' else '400 Bad Request'
        return json_response(status, {'ok': False, 'error': str(exc)})
    except database.DatabaseConfigurationError:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        request_id = uuid.uuid4().hex[:16]
        _append_ha_audit('license_admin_failed', {'request_id': request_id}, request_context)
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'license_admin_failed', 'request_id': request_id})
    finally:
        if connection:
            connection.close()
