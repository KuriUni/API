"""Python implementation of the HA single-license issuance endpoint."""
from native_http import make_response, add_headers, legacy_compatible
from py36_compat import parse_iso_datetime
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timezone
import database
from core import PHP_TRIM_CHARS, license_key_hash, offline_lookup, offline_secret, php_int_cast, offline_secret_encrypt, product_id
from http_utils import json_response
from v2_handlers import _runtime_config
from v3_handlers import _assert_write_fence
_KEY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
_IDEMPOTENCY_RE = re.compile('^[A-Za-z0-9_-]{20,100}$')
_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')

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

def _php_trim_lower(value):
    return _php_trim(value).translate(_ASCII_LOWER)

@legacy_compatible(callback_index=None, request_index=0)
def _post_data(request_context):
    content_type = str(request_context.get('content_type', ''))
    if 'application/json' not in content_type:
        from ha_mode import _php_post
        return _php_post(request_context)
    stream = request_context.get('body_stream')
    raw = stream.read() if stream is not None else b''
    if raw == b'':
        raise ValueError('Syntax error')
    try:
        value = json.loads(raw.decode('utf-8'), parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_json')))
    except UnicodeDecodeError as exc:
        raise ValueError('Malformed UTF-8 characters, possibly incorrectly encoded') from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError('Syntax error') from exc
    pending = [(value, 0)]
    while pending:
        item, parent_depth = pending.pop()
        if isinstance(item, (dict, list)):
            depth = parent_depth + 1
            if depth > 32:
                raise ValueError('Maximum stack depth exceeded')
            pending.extend(((child, depth) for child in (item.values() if isinstance(item, dict) else item)))
    if isinstance(value, list):
        return {}
    if not isinstance(value, dict):
        raise ValueError('invalid_request')
    return value

def _new_product_key():
    return '-'.join((''.join((secrets.choice(_KEY_ALPHABET) for _ in range(5))) for _ in range(5)))

@legacy_compatible(callback_index=1, request_index=0)
def issue_license(request_context):
    from ha_handlers import _append_ha_audit, _effective_role, _ha_authorized_scope
    if not _ha_authorized_scope(request_context, 'license:write'):
        return json_response('404 Not Found', {'ok': False, 'error': 'not_found'})
    if str(request_context.get('method', '')) != 'POST':
        return json_response('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'}, [('Allow', 'POST')])
    configured_role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    effective_role = _effective_role()
    writable = configured_role == 'primary' and effective_role != 'maintenance' or (configured_role == 'standby' and effective_role == 'promoted')
    if not writable:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'server_not_writable', 'role': configured_role})
    connection = None
    try:
        try:
            data = _post_data(request_context)
        except ValueError as exc:
            return json_response('400 Bad Request', {'ok': False, 'error': str(exc)})
        idem_value = data.get('idempotency_key')
        if idem_value is None:
            idem_value = request_context.get('header:idempotency-key', '')
        idem = _php_trim(idem_value)
        if not _IDEMPOTENCY_RE.fullmatch(idem):
            raise ValueError('invalid_idempotency_key')
        mode_value = data.get('license_mode')
        mode = _php_trim_lower('single' if mode_value is None else mode_value)
        if mode not in {'single', 'volume', 'evaluation'}:
            raise ValueError('invalid_license_mode')
        label_value = data.get('label')
        label = _php_trim('' if label_value is None else label_value)[:100] or None
        max_devices_value = data.get('max_devices')
        evaluation_days_value = data.get('evaluation_days')
        max_devices = max(2, min(10000, php_int_cast(10 if max_devices_value is None else max_devices_value))) if mode == 'volume' else 1
        evaluation_days = max(1, min(3650, php_int_cast(30 if evaluation_days_value is None else evaluation_days_value))) if mode == 'evaluation' else None
        expires_at = None
        expires_value = data.get('expires_at')
        expires_input = _php_trim('' if expires_value is None else expires_value)
        if mode != 'evaluation' and expires_input:
            try:
                from generate_key_handlers import _parse_php_datetime
                expires = _parse_php_datetime(expires_input.replace('Z', '+00:00'))
            except ValueError as exc:
                raise RuntimeError('invalid_expiry_datetime') from exc
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if int(expires.timestamp()) <= int(datetime.now(timezone.utc).timestamp()):
                raise ValueError('expires_at_must_be_future')
            expires_at = expires.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        tenant_value = data.get('tenant_id')
        product_value = data.get('product_id')
        tenant_id = max(1, php_int_cast(1 if tenant_value is None else tenant_value))
        requested_product_id = max(0, php_int_cast(0 if product_value is None else product_value))
        config = _runtime_config()
        connection = database.connect()
        _assert_write_fence(connection)
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,slug,name,status,environment,parent_tenant_id,max_licenses FROM tenants WHERE id=%s AND status='active' LIMIT 1", (tenant_id,))
            tenant = cursor.fetchone()
        if not tenant:
            raise ValueError('tenant_not_found_or_inactive')
        stored_environment = _php_trim_lower(tenant.get('environment') or '')
        tenant_environment = 'sandbox' if tenant.get('parent_tenant_id') or stored_environment == 'sandbox' else 'production' if stored_environment == 'production' else 'unknown'
        if tenant_environment == 'unknown':
            raise ValueError('tenant_environment_invalid')
        environment_value = data.get('environment')
        environment = _php_trim_lower(tenant_environment if environment_value is None else environment_value)
        if environment not in {'production', 'sandbox'}:
            raise ValueError('invalid_environment')
        if environment != tenant_environment:
            raise ValueError('environment_mismatch')
        with connection.cursor() as cursor:
            if requested_product_id:
                cursor.execute("SELECT id,code,name FROM products WHERE id=%s AND tenant_id=%s AND status='active' LIMIT 1", (requested_product_id, tenant_id))
            else:
                cursor.execute("SELECT id,code,name FROM products WHERE tenant_id=%s AND status='active' ORDER BY (code='default') DESC,id ASC LIMIT 1", (tenant_id,))
            product = cursor.fetchone()
        if not product:
            raise ValueError('product_not_found_or_inactive')
        product_numeric_id = int(product['id'])
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS count FROM licenses WHERE tenant_id=%s AND deleted_at IS NULL', (tenant_id,))
            current = int((cursor.fetchone() or {}).get('count') or 0)
        if current >= int(tenant.get('max_licenses') or 0):
            raise ValueError('license_quota_exceeded')
        with connection.cursor() as cursor:
            cursor.execute('CREATE TABLE IF NOT EXISTS idempotency_keys (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,tenant_id BIGINT UNSIGNED NOT NULL DEFAULT 1,operation VARCHAR(40) NOT NULL,request_key VARCHAR(100) NOT NULL,response_json TEXT NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(id),UNIQUE KEY uq_idempotency_tenant_operation_key(tenant_id,operation,request_key)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci')
            cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s LIMIT 1', (tenant_id, 'issue_license', idem))
            saved = cursor.fetchone()
        if saved and saved.get('response_json'):
            return json_response('200 OK', json.loads(saved['response_json']))
        key = _new_product_key()
        offline = offline_secret(key)
        connection.begin()
        try:
            with connection.cursor() as cursor:
                cursor.execute('INSERT INTO licenses(tenant_id,product_id,key_hash,label,active,max_devices,evaluation_days,expires_at,offline_lookup,offline_secret_enc) VALUES(%s,%s,%s,%s,1,%s,%s,%s,%s,%s)', (tenant_id, product_numeric_id, license_key_hash(config, key), label, max_devices, evaluation_days, expires_at, offline_lookup(offline), offline_secret_encrypt(config, offline)))
                license_id = int(cursor.lastrowid)
            issuing_role = 'promoted' if configured_role == 'standby' else 'primary'
            result = {'ok': True, 'product_key': key, 'license_id': license_id, 'product_id': product_id(config, license_id), 'tenant_id': tenant_id, 'tenant_slug': str(tenant.get('slug') or ''), 'environment': environment, 'tenant_product_id': product_numeric_id, 'product_code': str(product.get('code') or ''), 'product_name': str(product.get('name') or ''), 'license_mode': mode, 'max_devices': max_devices, 'evaluation_days': evaluation_days, 'expires_at': expires_at, 'issued_by_role': issuing_role}
            encoded = json.dumps(result, ensure_ascii=False, separators=(',', ':'))
            with connection.cursor() as cursor:
                cursor.execute('INSERT INTO idempotency_keys(tenant_id,operation,request_key,response_json) VALUES(%s,%s,%s,%s)', (tenant_id, 'issue_license', idem, encoded))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        _append_ha_audit('license_issued', {'idempotency_key_hash': __import__('hashlib').sha256(idem.encode()).hexdigest(), 'license_id': license_id, 'tenant_id': tenant_id, 'environment': environment, 'tenant_product_id': product_numeric_id, 'issued_by_role': issuing_role}, request_context)
        return json_response('200 OK', result)
    except ValueError as exc:
        if connection:
            connection.rollback()
        return json_response('400 Bad Request', {'ok': False, 'error': str(exc)})
    except Exception:
        if connection:
            connection.rollback()
        request_id = uuid.uuid4().hex[:16]
        _append_ha_audit('issue_license_failed', {'request_id': request_id}, request_context)
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'issue_failed', 'request_id': request_id})
    finally:
        if connection:
            connection.close()
