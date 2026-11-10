"""HA tenant, API client, and subscriber setup administration."""
from native_http import make_response, add_headers, legacy_compatible
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
import database
from core import PHP_TRIM_CHARS, hash_secret, php_int_cast
from http_utils import json_response, read_bounded_body
from migration_config import secret_value
from v2_handlers import _runtime_config
from v3_handlers import _assert_write_fence
_PLANS = {'trial': (1, 100), 'standard': (5, 1000), 'business': (20, 10000), 'enterprise': (100, 100000)}
_CLIENT_SCOPES = ['tenant:read', 'products:write', 'licenses:read', 'licenses:write']
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

def _normalize_tenant_fields(data):
    slug = _php_trim_lower(data.get('slug'))
    name = _php_trim(data.get('name'))
    if not re.fullmatch('[a-z0-9][a-z0-9-]{1,62}', slug) or not name or len(name) > 160:
        raise ValueError('invalid_tenant')
    return (slug, name)

def _normalize_expiry(value):
    expiry = _php_trim(value)
    if not expiry:
        return None
    from generate_key_handlers import _parse_php_datetime
    try:
        parsed = _parse_php_datetime(expiry)
    except ValueError as exc:
        raise ValueError('invalid_expires_at') from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

@legacy_compatible(callback_index=None, request_index=0)
def _post_json(request_context):
    raw = read_bounded_body(request_context, 262144)
    try:
        value = json.loads(raw.decode('utf-8'), parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Syntax error')))
    except UnicodeDecodeError:
        raise ValueError('Malformed UTF-8 characters, possibly incorrectly encoded')
    except (json.JSONDecodeError, ValueError):
        raise ValueError('Syntax error')
    pending = [(value, 0)]
    while pending:
        item, parent_depth = pending.pop()
        if isinstance(item, (dict, list)):
            depth = parent_depth + 1
            if depth > 32:
                raise ValueError('Maximum stack depth exceeded')
            pending.extend(((child, depth) for child in (item.values() if isinstance(item, dict) else item)))
    return value if isinstance(value, dict) else {}

def _writable():
    role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    try:
        from ha_handlers import _effective_role
        effective = _effective_role()
    except Exception:
        effective = role
    return role == 'primary' and effective != 'maintenance' or (role == 'standby' and effective == 'promoted')

def _plan(code):
    code = _php_string(code)
    if code not in _PLANS:
        raise ValueError('invalid_plan')
    products, licenses = _PLANS[code]
    return {'code': code, 'products': products, 'licenses': licenses}

def _php_gmdate_c(value):
    """Format a timestamp like PHP gmdate('c'), using whole epoch seconds."""
    epoch = int(value.timestamp()) if isinstance(value, datetime) else int(value)
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec='seconds')

def _setup_expiry_times(ttl_minutes):
    expires = datetime.fromtimestamp(int(time.time()) + ttl_minutes * 60, timezone.utc)
    expires_at_utc = _php_gmdate_c(int(time.time()) + ttl_minutes * 60)
    return (expires.strftime('%Y-%m-%d %H:%M:%S'), expires_at_utc)

def _is_integrity_conflict(error):
    if str(getattr(error, 'sqlstate', '')) == '23000':
        return True
    args = getattr(error, 'args', ())
    return bool(args and args[0] in (1062, '23000'))

def _table_exists(connection, table):
    if not re.fullmatch('[A-Za-z0-9_]+', table):
        return False
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s', (table,))
        return int((cursor.fetchone() or {}).get('n') or 0) > 0

def _delete_for_tenants(connection, table, column, tenant_ids):
    if not tenant_ids or not _table_exists(connection, table):
        return 0
    if table not in {'api_billing_invoices', 'tenant_portal_key_reissues', 'tenant_portal_passkey_challenges', 'tenant_portal_sessions', 'tenant_portal_passkeys', 'tenant_webhook_deliveries', 'baas_batch_jobs', 'tenant_webhooks', 'idempotency_keys', 'tenant_api_attempts', 'tenant_api_usage', 'tenant_api_usage_daily', 'tenant_api_clients', 'product_key_v8_jobs', 'products', 'licenses'}:
        raise ValueError('invalid_delete_table')
    marks = ','.join(['%s'] * len(tenant_ids))
    with connection.cursor() as cursor:
        cursor.execute(f'DELETE FROM `{table}` WHERE `{column}` IN ({marks})', tuple(tenant_ids))
        return int(cursor.rowcount or 0)

def _normalize_scopes(raw):
    if raw is None:
        return list(_CLIENT_SCOPES)
    if isinstance(raw, str):
        raw = _php_trim(raw)
        if not raw:
            return []
        if raw.startswith('['):
            try:
                raw = json.loads(raw)
            except json.JSONDecodeError:
                raw = re.split('\\s*,\\s*', raw, flags=re.ASCII)
        else:
            raw = re.split('\\s*,\\s*', raw, flags=re.ASCII)
    if isinstance(raw, dict):
        raw = list(raw.values())
    elif not isinstance(raw, list):
        raw = [raw]
    scopes = []
    for item in raw:
        if isinstance(item, (str, int, float, bool)):
            scopes.extend((part for part in re.split('\\s*,\\s*', _php_trim(item), flags=re.ASCII) if part))
    return list(dict.fromkeys((scope for scope in _CLIENT_SCOPES if scope in scopes)))

def _issue_api_key(connection, data):
    tenant_value = data.get('tenant_id')
    rate_value = data.get('rate_limit_per_minute')
    tenant_id = php_int_cast(0 if tenant_value is None else tenant_value)
    rate = php_int_cast(120 if rate_value is None else rate_value)
    name = _php_trim(data.get('name'))
    scopes = _normalize_scopes(data.get('scopes'))
    if tenant_id < 1 or not name or (not scopes):
        raise ValueError('invalid_api_client')
    with connection.cursor() as cursor:
        cursor.execute("SELECT environment,parent_tenant_id FROM tenants WHERE id=%s AND status='active'", (tenant_id,))
        tenant = cursor.fetchone()
    if not tenant:
        raise ValueError('tenant_not_found_or_inactive')
    stored = _php_trim(tenant.get('environment') or '').translate(_ASCII_LOWER)
    environment = 'sandbox' if tenant.get('parent_tenant_id') or stored == 'sandbox' else 'production' if stored == 'production' else 'unknown'
    if environment == 'unknown':
        raise ValueError('tenant_environment_invalid')
    secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii')
    token = ('baas_sandbox_' if environment == 'sandbox' else 'baas_prod_') + secret
    prefix = token[:12]
    config = _runtime_config()
    token_hash = hmac.new(config['key_pepper'].encode(), token.encode(), hashlib.sha256).hexdigest()
    expiry = _normalize_expiry(data.get('expires_at'))
    with connection.cursor() as cursor:
        cursor.execute('INSERT INTO tenant_api_clients(tenant_id,name,key_prefix,key_hash,scopes_json,rate_limit_per_minute,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s)', (tenant_id, name[:120], prefix, token_hash, json.dumps(scopes, separators=(',', ':')), max(10, min(600, rate)), expiry))
        client_id = int(cursor.lastrowid)
    return {'client_id': client_id, 'tenant_id': tenant_id, 'environment': environment, 'api_key': token, 'key_prefix': prefix, 'scopes': scopes, 'message': 'API key is shown once.'}

def _issue_setup_code(connection, data):
    tenant_value = data.get('tenant_id')
    ttl_value = data.get('ttl_minutes')
    sdk_ttl_value = data.get('sdk_key_ttl_hours')
    rate_value = data.get('sdk_rate_limit_per_minute')
    tenant_id = php_int_cast(0 if tenant_value is None else tenant_value)
    ttl = max(5, min(1440, php_int_cast(30 if ttl_value is None else ttl_value)))
    sdk_ttl = max(1, min(720, php_int_cast(168 if sdk_ttl_value is None else sdk_ttl_value)))
    rate = max(10, min(600, php_int_cast(60 if rate_value is None else rate_value)))
    with connection.cursor() as cursor:
        cursor.execute("SELECT id,slug,name FROM tenants WHERE id=%s AND environment='production' AND parent_tenant_id IS NULL AND status='active'", (tenant_id,))
        tenant = cursor.fetchone()
    if not tenant:
        raise ValueError('production_tenant_not_found_or_inactive')
    if not _table_exists(connection, 'subscriber_sdk_setup_codes'):
        raise RuntimeError('migration_020_required')
    token = 'baas_setup_' + base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii')
    prefix = token[:16]
    key_hash = hmac.new(_runtime_config()['key_pepper'].encode(), token.encode(), hashlib.sha256).hexdigest()
    expires, expires_at_utc = _setup_expiry_times(ttl)
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO subscriber_sdk_setup_codes(production_tenant_id,code_prefix,code_hash,status,expires_at,sdk_key_ttl_hours,sdk_rate_limit_per_minute) VALUES(%s,%s,%s,'active',%s,%s,%s)", (tenant_id, prefix, key_hash, expires, sdk_ttl, rate))
        setup_id = int(cursor.lastrowid)
    return {'setup_id': setup_id, 'tenant_id': tenant_id, 'tenant_slug': str(tenant.get('slug') or ''), 'tenant_name': str(tenant.get('name') or ''), 'setup_code': token, 'expires_at': expires, 'expires_at_utc': expires_at_utc, 'sdk_key_ttl_hours': sdk_ttl, 'sdk_rate_limit_per_minute': rate, 'message': 'Setup code is shown once. Give it only to the BaaS subscriber.'}

def _list_setup_codes(connection, tenant_id):
    with connection.cursor() as cursor:
        cursor.execute('SELECT id setup_id,production_tenant_id tenant_id,code_prefix,status,expires_at,sdk_key_ttl_hours,sdk_rate_limit_per_minute,issued_at,redeemed_at,revoked_at FROM subscriber_sdk_setup_codes WHERE production_tenant_id=%s ORDER BY id DESC LIMIT 100', (tenant_id,))
        rows = cursor.fetchall()
    now = datetime.now(timezone.utc)
    for row in rows:
        for source, target in (('expires_at', 'expires_at_utc'), ('issued_at', 'issued_at_utc'), ('redeemed_at', 'redeemed_at_utc'), ('revoked_at', 'revoked_at_utc')):
            value = row.get(source)
            if isinstance(value, datetime):
                value = value.replace(tzinfo=value.tzinfo or timezone.utc)
                row[target] = value.astimezone(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
                row[source] = value.strftime('%Y-%m-%d %H:%M:%S')
            elif isinstance(value, str) and _php_trim(value):
                try:
                    parsed = parse_iso_datetime(value.replace('Z', '+00:00'))
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    row[target] = parsed.astimezone(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
                except ValueError:
                    row[target] = None
            else:
                row[target] = None
        expiry = row.get('expires_at')
        if row.get('revoked_at'):
            row['status'] = 'revoked'
        elif row.get('redeemed_at'):
            row['status'] = 'redeemed'
        else:
            try:
                expiry_dt = expiry if isinstance(expiry, datetime) else parse_iso_datetime(str(expiry).replace('Z', '+00:00'))
                expiry_dt = expiry_dt.replace(tzinfo=expiry_dt.tzinfo or timezone.utc)
                row['status'] = 'expired' if expiry_dt <= now else 'active'
            except (TypeError, ValueError):
                row['status'] = 'active'
    return rows

@legacy_compatible(callback_index=1, request_index=0)
def tenant_admin(request_context):
    from ha_handlers import _append_ha_audit, ha_sync_peer, _ha_authorized_scope
    if not _ha_authorized_scope(request_context, 'admin:manage'):
        return json_response('404 Not Found', {'ok': False, 'error': 'not_found'})
    method = str(request_context.get('method', 'GET'))
    connection = None
    try:
        connection = database.connect()
        _assert_write_fence(connection)
        from api_usage_limits import ensure_schema as ensure_api_usage_limits_schema
        ensure_api_usage_limits_schema(connection)
        if method == 'GET':
            from urllib.parse import parse_qs
            parsed_query = parse_qs(str(request_context.get('query', '')), keep_blank_values=True)
            query = {key.replace(' ', '_').replace('.', '_'): values for key, values in parsed_query.items()}
            tenant_id = max(0, php_int_cast(query.get('tenant_id', ['0'])[-1]))
            if tenant_id:
                if _php_trim_lower(query.get('view', [''])[-1]) == 'subscriber_sdk_setups':
                    return json_response('200 OK', {'ok': True, 'tenant_id': tenant_id, 'setup_codes': _list_setup_codes(connection, tenant_id)})
                with connection.cursor() as cursor:
                    cursor.execute('SELECT id,tenant_id,name,key_prefix,scopes_json,status,rate_limit_per_minute,last_used_at,expires_at,created_at,revoked_at,replacement_client_id,grace_expires_at FROM tenant_api_clients WHERE tenant_id=%s ORDER BY id DESC LIMIT 500', (tenant_id,))
                    clients = cursor.fetchall()
                from ha_handlers import _json_value
                return json_response('200 OK', {'ok': True, 'tenant_id': tenant_id, 'api_clients': _json_value(clients)})
            with connection.cursor() as cursor:
                cursor.execute("SELECT t.id,t.slug,t.name,t.status,t.plan_code,CASE WHEN t.parent_tenant_id IS NOT NULL OR t.environment='sandbox' THEN 'sandbox' WHEN t.environment='production' THEN 'production' ELSE 'unknown' END environment,t.parent_tenant_id,t.max_products,t.max_licenses,t.created_at,t.updated_at,lim.monthly_limit_units,(SELECT COUNT(*) FROM products p WHERE p.tenant_id=t.id AND p.status<>'deleted') products,(SELECT COUNT(*) FROM licenses l WHERE l.tenant_id=t.id AND l.active=1 AND l.deleted_at IS NULL) licenses,(SELECT COUNT(*) FROM tenant_api_clients c WHERE c.tenant_id=t.id AND c.status='active' AND c.revoked_at IS NULL) active_api_clients FROM tenants t LEFT JOIN tenant_api_usage_limits lim ON lim.tenant_id=t.id ORDER BY COALESCE(t.parent_tenant_id,t.id),CASE WHEN t.parent_tenant_id IS NOT NULL OR t.environment='sandbox' THEN 1 WHEN t.environment='production' THEN 0 ELSE 2 END,t.id")
                rows = cursor.fetchall()
            from api_usage_limits import units_to_credits
            for row in rows:
                row['monthly_api_limit_credits'] = units_to_credits(row['monthly_limit_units']) if row.get('monthly_limit_units') is not None else ''
            from ha_handlers import _json_value
            return json_response('200 OK', {'ok': True, 'tenants': _json_value(rows)})
        if method != 'POST':
            return json_response('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'}, [('Allow', 'GET, POST')])
        if not _writable():
            return json_response('503 Service Unavailable', {'ok': False, 'error': 'server_not_writable'})
        try:
            data = _post_json(request_context)
        except ValueError as exc:
            status = '413 Payload Too Large' if str(exc) == 'request_too_large' else '400 Bad Request'
            return json_response(status, {'ok': False, 'error': str(exc)})
        action = _php_string(data.get('action') if data.get('action') is not None else '')
        if action == 'preview_tenant_license_delete':
            tenant_id = php_int_cast(data.get('tenant_id'))
            if tenant_id <= 1:
                raise ValueError('protected_or_invalid_tenant')
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,slug,name,status,environment,parent_tenant_id FROM tenants WHERE id=%s LIMIT 1', (tenant_id,))
                tenant = cursor.fetchone()
                if not tenant:
                    raise ValueError('tenant_not_found')
                cursor.execute('SELECT COUNT(*) AS n FROM licenses WHERE tenant_id=%s AND active=1 AND deleted_at IS NULL', (tenant_id,))
                active_count = int((cursor.fetchone() or {}).get('n') or 0)
                cursor.execute('SELECT COUNT(*) AS n FROM licenses WHERE tenant_id=%s AND deleted_at IS NULL', (tenant_id,))
                total_count = int((cursor.fetchone() or {}).get('n') or 0)
            environment = 'sandbox' if tenant.get('parent_tenant_id') or tenant.get('environment') == 'sandbox' else 'production'
            return json_response('200 OK', {'ok': True, 'tenant': {'id': int(tenant['id']), 'slug': str(tenant['slug']), 'name': str(tenant['name']), 'status': str(tenant['status']), 'environment': environment}, 'active_license_count': active_count, 'non_deleted_license_count': total_count})
        if action == 'delete_tenant_licenses':
            try:
                tenant_id = php_int_cast(data.get('tenant_id'))
                confirm_id = php_int_cast(data.get('confirm_tenant_id'))
                expected = php_int_cast(-1 if data.get('expected_count') is None else data.get('expected_count'))
            except (TypeError, ValueError) as exc:
                raise ValueError('tenant_confirmation_mismatch') from exc
            operation_id = _php_trim_lower(data.get('operation_id'))
            if tenant_id <= 1 or confirm_id != tenant_id:
                raise ValueError('tenant_confirmation_mismatch')
            if expected < 1 or expected > 1000000:
                raise ValueError('invalid_expected_count')
            if not re.fullmatch('[a-f0-9]{32}', operation_id):
                raise ValueError('invalid_operation_id')
            request_hash = hashlib.sha256(json.dumps({'tenant_id': tenant_id, 'expected_count': expected}, separators=(',', ':')).encode()).hexdigest()
            with connection.cursor() as cursor:
                cursor.execute('SELECT response_json FROM idempotency_keys WHERE tenant_id=%s AND operation=%s AND request_key=%s LIMIT 1', (tenant_id, 'operator_bulk_delete_licenses', operation_id))
                saved = cursor.fetchone()
            if saved and saved.get('response_json'):
                replay = json.loads(saved['response_json'])
                if not hmac.compare_digest(str(replay.get('_request_hash', '')), request_hash):
                    raise ValueError('operation_id_reused')
                replay.pop('_request_hash', None)
                return json_response('200 OK', replay)
            with connection.cursor() as cursor:
                cursor.execute('DROP TEMPORARY TABLE IF EXISTS tmp_operator_tenant_license_delete')
                cursor.execute('CREATE TEMPORARY TABLE tmp_operator_tenant_license_delete (license_id BIGINT UNSIGNED NOT NULL PRIMARY KEY) ENGINE=InnoDB')
            try:
                connection.begin()
                with connection.cursor() as cursor:
                    cursor.execute('SELECT id FROM tenants WHERE id=%s FOR UPDATE', (tenant_id,))
                    if not cursor.fetchone():
                        raise ValueError('tenant_not_found')
                    cursor.execute('SELECT COUNT(*) AS n FROM licenses WHERE tenant_id=%s AND active=1 AND deleted_at IS NULL', (tenant_id,))
                    current = int((cursor.fetchone() or {}).get('n') or 0)
                    if current != expected:
                        raise RuntimeError('tenant_license_count_changed')
                    cursor.execute('INSERT INTO tmp_operator_tenant_license_delete(license_id) SELECT id FROM licenses WHERE tenant_id=%s AND active=1 AND deleted_at IS NULL', (tenant_id,))
                    cursor.execute('SELECT COUNT(*) AS n FROM tmp_operator_tenant_license_delete')
                    if int((cursor.fetchone() or {}).get('n') or 0) != expected:
                        raise RuntimeError('tenant_license_count_changed')
                    cursor.execute('UPDATE license_devices d JOIN tmp_operator_tenant_license_delete x ON x.license_id=d.license_id SET d.revoked_at=UTC_TIMESTAMP(),d.token_version=d.token_version+1 WHERE d.revoked_at IS NULL')
                    revoked_devices = int(cursor.rowcount or 0)
                    cursor.execute("UPDATE phone_activation_requests p JOIN tmp_operator_tenant_license_delete x ON x.license_id=p.license_id SET p.status='cancelled',p.cancelled_at=COALESCE(p.cancelled_at,UTC_TIMESTAMP()),p.cancelled_reason=COALESCE(p.cancelled_reason,'license_deleted') WHERE p.status NOT IN ('confirmed','cancelled','expired')")
                    cancelled_phone = int(cursor.rowcount or 0)
                    cursor.execute("UPDATE offline_activation_requests o JOIN tmp_operator_tenant_license_delete x ON x.license_id=o.license_id SET o.revoked_at=COALESCE(o.revoked_at,UTC_TIMESTAMP()),o.revocation_reason=COALESCE(o.revocation_reason,'license_deleted') WHERE o.revoked_at IS NULL")
                    revoked_offline = int(cursor.rowcount or 0)
                    deleted_by = hashlib.sha256(b'operator_tenant_bulk_delete').hexdigest()
                    cursor.execute("UPDATE licenses l JOIN tmp_operator_tenant_license_delete x ON x.license_id=l.id SET l.active=0,l.revoked_at=COALESCE(l.revoked_at,UTC_TIMESTAMP()),l.deleted_at=UTC_TIMESTAMP(),l.deleted_reason='tenant_bulk_delete',l.deleted_by=%s WHERE l.tenant_id=%s AND l.active=1 AND l.deleted_at IS NULL", (deleted_by, tenant_id))
                    deleted = int(cursor.rowcount or 0)
                    response = {'ok': True, 'tenant_id': tenant_id, 'requested_count': expected, 'deleted_count': deleted, 'revoked_devices': revoked_devices, 'cancelled_phone_requests': cancelled_phone, 'revoked_offline_requests': revoked_offline, '_request_hash': request_hash}
                    cursor.execute('INSERT INTO idempotency_keys(tenant_id,operation,request_key,response_json) VALUES(%s,%s,%s,%s)', (tenant_id, 'operator_bulk_delete_licenses', operation_id, json.dumps(response, separators=(',', ':'))))
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                with connection.cursor() as cursor:
                    cursor.execute('DROP TEMPORARY TABLE IF EXISTS tmp_operator_tenant_license_delete')
            _append_ha_audit('tenant_licenses_bulk_deleted', {'tenant_id': tenant_id, 'deleted_count': deleted, 'operation_id': operation_id}, request_context)
            sync = ha_sync_peer('tenant_licenses_bulk_deleted', request_context)
            response.pop('_request_hash', None)
            response.update({'ha_peer_synced': bool(sync.get('ok')), 'ha_sync_queued': bool(sync.get('queued'))})
            return json_response('200 OK', response)
        if action == 'issue_subscriber_sdk_setup':
            result = _issue_setup_code(connection, data)
            connection.commit()
            _append_ha_audit('subscriber_sdk_setup_issued', {'tenant_id': result['tenant_id'], 'setup_id': result['setup_id'], 'expires_at': result['expires_at']}, request_context)
            sync = ha_sync_peer('subscriber_sdk_setup_issued', request_context)
            result.update({'ok': True, 'ha_peer_synced': bool(sync.get('ok')), 'ha_sync_queued': bool(sync.get('queued'))})
            return json_response('201 Created', result)
        if action == 'revoke_subscriber_sdk_setup':
            tenant_id, setup_id = (php_int_cast(data.get('tenant_id')), php_int_cast(data.get('setup_id')))
            if tenant_id < 1 or setup_id < 1:
                raise ValueError('invalid_setup_code_target')
            with connection.cursor() as cursor:
                cursor.execute("UPDATE subscriber_sdk_setup_codes SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE id=%s AND production_tenant_id=%s AND redeemed_at IS NULL AND revoked_at IS NULL", (setup_id, tenant_id))
                affected = int(cursor.rowcount or 0)
            connection.commit()
            _append_ha_audit('subscriber_sdk_setup_revoked', {'tenant_id': tenant_id, 'setup_id': setup_id, 'affected': affected}, request_context)
            ha_sync_peer('subscriber_sdk_setup_revoked', request_context)
            return json_response('200 OK', {'ok': True, 'tenant_id': tenant_id, 'setup_id': setup_id, 'affected': affected})
        if action == 'create_tenant':
            slug, name = _normalize_tenant_fields(data)
            plan = _plan(data.get('plan_code') if data.get('plan_code') is not None else 'standard')
            try:
                connection.begin()
                with connection.cursor() as cursor:
                    cursor.execute('INSERT INTO tenants(slug,name,plan_code,max_products,max_licenses) VALUES(%s,%s,%s,%s,%s)', (slug, name, plan['code'], plan['products'], plan['licenses']))
                    tenant_id = int(cursor.lastrowid)
                    cursor.execute("INSERT INTO products(tenant_id,code,name,status) VALUES(%s,'default',%s,'active')", (tenant_id, (name + ' Default Product')[:160]))
                    product_id = int(cursor.lastrowid)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            _append_ha_audit('tenant_created', {'tenant_id': tenant_id, 'slug': slug, 'default_product_id': product_id}, request_context)
            ha_sync_peer('tenant_created', request_context)
            return json_response('201 Created', {'ok': True, 'tenant_id': tenant_id, 'slug': slug, 'default_product_id': product_id})
        if action == 'ensure_sandbox':
            parent_id = php_int_cast(data.get('tenant_id'))
            with connection.cursor() as cursor:
                cursor.execute("SELECT id,slug,name,plan_code,max_products,max_licenses FROM tenants WHERE id=%s AND environment='production' AND status='active'", (parent_id,))
                parent = cursor.fetchone()
                if not parent:
                    raise ValueError('production_tenant_not_found_or_inactive')
                cursor.execute("SELECT id,slug FROM tenants WHERE parent_tenant_id=%s AND environment='sandbox' LIMIT 1", (parent_id,))
                old = cursor.fetchone()
            if old:
                return json_response('200 OK', {'ok': True, 'created': False, 'production_tenant_id': parent_id, 'sandbox_tenant_id': int(old['id']), 'sandbox_slug': str(old['slug'])})
            base = str(parent['slug'])[:55] + '-sandbox'
            slug, suffix = (base, 2)
            while True:
                with connection.cursor() as cursor:
                    cursor.execute('SELECT 1 FROM tenants WHERE slug=%s', (slug,))
                    if not cursor.fetchone():
                        break
                tail = '-' + str(suffix)
                suffix += 1
                slug = base[:63 - len(tail)] + tail
            try:
                connection.begin()
                with connection.cursor() as cursor:
                    cursor.execute("INSERT INTO tenants(slug,name,status,plan_code,environment,parent_tenant_id,max_products,max_licenses) VALUES(%s,%s,'active',%s,'sandbox',%s,%s,%s)", (slug, (str(parent['name']) + ' Sandbox')[:160], str(parent['plan_code']), parent_id, int(parent['max_products']), int(parent['max_licenses'])))
                    sandbox_id = int(cursor.lastrowid)
                    cursor.execute("INSERT INTO products(tenant_id,code,name,status) VALUES(%s,'default',%s,'active')", (sandbox_id, (str(parent['name']) + ' Sandbox Default Product')[:160]))
                    product_id = int(cursor.lastrowid)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            _append_ha_audit('tenant_sandbox_created', {'tenant_id': sandbox_id, 'parent_tenant_id': parent_id}, request_context)
            ha_sync_peer('tenant_sandbox_created', request_context)
            return json_response('201 Created', {'ok': True, 'created': True, 'production_tenant_id': parent_id, 'sandbox_tenant_id': sandbox_id, 'sandbox_slug': slug, 'default_product_id': product_id})
        if action == 'update_tenant':
            tenant_id = php_int_cast(data.get('tenant_id'))
            name = _php_trim(data.get('name'))
            plan = _plan(data.get('plan_code') if data.get('plan_code') is not None else 'standard')
            if tenant_id < 1 or not name:
                raise ValueError('invalid_tenant')
            from api_usage_limits import credits_to_units, get_limit_units, set_limit_units
            monthly_limit_units = None
            update_monthly_limit = 'monthly_api_limit_credits' in data
            if update_monthly_limit:
                monthly_limit_units = credits_to_units(data.get('monthly_api_limit_credits'))
            else:
                monthly_limit_units = get_limit_units(connection, tenant_id)
            with connection.cursor() as cursor:
                cursor.execute('SELECT id FROM tenants WHERE id=%s LIMIT 1', (tenant_id,))
                if not cursor.fetchone():
                    raise ValueError('tenant_not_found')
                cursor.execute('UPDATE tenants SET name=%s,plan_code=%s,max_products=%s,max_licenses=%s WHERE id=%s', (name[:160], plan['code'], plan['products'], plan['licenses'], tenant_id))
                affected = int(cursor.rowcount or 0)
                if update_monthly_limit:
                    set_limit_units(connection, tenant_id, monthly_limit_units)
            connection.commit()
            _append_ha_audit('tenant_updated', {'tenant_id': tenant_id, 'plan_code': plan['code'], 'monthly_api_limit_units': monthly_limit_units}, request_context)
            ha_sync_peer('tenant_updated', request_context)
            return json_response('200 OK', {'ok': True, 'tenant_id': tenant_id, 'affected': affected, 'plan_code': plan['code'], 'max_products': plan['products'], 'max_licenses': plan['licenses'], 'monthly_api_limit_credits': units_to_credits(monthly_limit_units) if monthly_limit_units is not None else ''})
        if action == 'delete_tenant':
            try:
                tenant_id = php_int_cast(data.get('tenant_id'))
            except (TypeError, ValueError) as exc:
                raise ValueError('protected_or_invalid_tenant') from exc
            if tenant_id <= 1:
                raise ValueError('protected_or_invalid_tenant')
            with connection.cursor() as cursor:
                cursor.execute('SELECT id FROM tenants WHERE id=%s', (tenant_id,))
                if not cursor.fetchone():
                    raise ValueError('tenant_not_found')
                cursor.execute('SELECT id FROM tenants WHERE parent_tenant_id=%s', (tenant_id,))
                tenant_ids = list(dict.fromkeys([tenant_id] + [int(row['id']) for row in cursor.fetchall()]))
            marks = ','.join(['%s'] * len(tenant_ids))
            affected = {'tenants': 0}
            try:
                connection.begin()
                with connection.cursor() as cursor:
                    if _table_exists(connection, 'auth_attempts'):
                        cursor.execute(f'DELETE FROM auth_attempts WHERE subject_hash IN (SELECT key_hash FROM licenses WHERE tenant_id IN ({marks}))', tuple(tenant_ids))
                        affected['auth_attempts'] = int(cursor.rowcount or 0)
                    for table in ('license_devices', 'phone_activation_requests', 'offline_activation_requests'):
                        if _table_exists(connection, table):
                            cursor.execute(f'DELETE FROM `{table}` WHERE license_id IN (SELECT id FROM licenses WHERE tenant_id IN ({marks}))', tuple(tenant_ids))
                            affected[table] = int(cursor.rowcount or 0)
                affected['api_billing_invoices'] = _delete_for_tenants(connection, 'api_billing_invoices', 'account_tenant_id', tenant_ids)
                for table in ('tenant_portal_key_reissues', 'tenant_portal_passkey_challenges', 'tenant_portal_sessions', 'tenant_portal_passkeys', 'tenant_webhook_deliveries', 'baas_batch_jobs', 'tenant_webhooks', 'idempotency_keys', 'tenant_api_attempts', 'tenant_api_usage', 'tenant_api_usage_daily', 'tenant_api_clients', 'product_key_v8_jobs', 'products', 'licenses'):
                    affected[table] = _delete_for_tenants(connection, table, 'tenant_id', tenant_ids)
                with connection.cursor() as cursor:
                    cursor.execute(f'DELETE FROM tenants WHERE id IN ({marks})', tuple(tenant_ids))
                    affected['tenants'] = int(cursor.rowcount or 0)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            _append_ha_audit('tenant_deleted', {'tenant_id': tenant_id, 'tenant_ids': tenant_ids, 'affected': affected}, request_context)
            ha_sync_peer('tenant_deleted', request_context)
            return json_response('200 OK', {'ok': True, 'tenant_id': tenant_id, 'tenant_ids': tenant_ids, 'affected': affected})
        if action in {'suspend_tenant', 'resume_tenant'}:
            tenant_id = php_int_cast(data.get('tenant_id'))
            if tenant_id <= 1:
                raise ValueError('protected_or_invalid_tenant')
            status = 'active' if action == 'resume_tenant' else 'suspended'
            with connection.cursor() as cursor:
                cursor.execute('UPDATE tenants SET status=%s WHERE id=%s', (status, tenant_id))
                if status == 'suspended':
                    cursor.execute("UPDATE tenant_api_clients SET status='suspended' WHERE tenant_id=%s AND status='active'", (tenant_id,))
                else:
                    cursor.execute("UPDATE tenant_api_clients SET status='active' WHERE tenant_id=%s AND status='suspended' AND revoked_at IS NULL", (tenant_id,))
            connection.commit()
            _append_ha_audit('tenant_' + status, {'tenant_id': tenant_id}, request_context)
            ha_sync_peer('tenant_' + status, request_context)
            return json_response('200 OK', {'ok': True, 'tenant_id': tenant_id, 'status': status})
        if action == 'issue_api_key':
            result = _issue_api_key(connection, data)
            connection.commit()
            _append_ha_audit('tenant_api_key_issued', {'tenant_id': result['tenant_id'], 'client_id': result['client_id'], 'key_prefix': result['key_prefix'], 'scopes': result['scopes']}, request_context)
            ha_sync_peer('tenant_api_key_issued', request_context)
            return json_response('201 Created', {'ok': True, **result})
        if action == 'rotate_api_key':
            old_id = php_int_cast(data.get('client_id'))
            grace = max(0, min(10080, php_int_cast(60 if data.get('grace_minutes') is None else data.get('grace_minutes'))))
            with connection.cursor() as cursor:
                cursor.execute('SELECT tenant_id,name,scopes_json,rate_limit_per_minute,expires_at FROM tenant_api_clients WHERE id=%s AND revoked_at IS NULL', (old_id,))
                old = cursor.fetchone()
            if not old:
                raise ValueError('api_client_not_found')
            scopes = json.loads(old.get('scopes_json') or '[]')
            result = _issue_api_key(connection, {'tenant_id': int(old['tenant_id']), 'name': str(old['name']) + ' rotated', 'scopes': scopes, 'rate_limit_per_minute': int(old['rate_limit_per_minute']), 'expires_at': data.get('expires_at') or old.get('expires_at') or ''})
            if grace == 0:
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE tenant_api_clients SET status='revoked',revoked_at=UTC_TIMESTAMP(),replacement_client_id=%s WHERE id=%s", (result['client_id'], old_id))
                grace_expires = None
            else:
                grace_expires = datetime.fromtimestamp(time.time() + grace * 60, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE tenant_api_clients SET status='retiring',grace_expires_at=%s,replacement_client_id=%s WHERE id=%s", (grace_expires, result['client_id'], old_id))
            connection.commit()
            _append_ha_audit('tenant_api_key_rotated', {'old_client_id': old_id, 'new_client_id': result['client_id'], 'tenant_id': result['tenant_id'], 'grace_minutes': grace}, request_context)
            ha_sync_peer('tenant_api_key_rotated', request_context)
            return json_response('201 Created', {'ok': True, 'replaced_client_id': old_id, 'grace_expires_at': grace_expires, **result})
        if action == 'revoke_api_key':
            client_id = php_int_cast(data.get('client_id'))
            with connection.cursor() as cursor:
                cursor.execute("UPDATE tenant_api_clients SET status='revoked',revoked_at=UTC_TIMESTAMP() WHERE id=%s AND revoked_at IS NULL", (client_id,))
                affected = int(cursor.rowcount or 0)
            connection.commit()
            _append_ha_audit('tenant_api_key_revoked', {'client_id': client_id}, request_context)
            ha_sync_peer('tenant_api_key_revoked', request_context)
            return json_response('200 OK', {'ok': True, 'client_id': client_id, 'affected': affected})
        if action == 'find_issuance_by_request_id':
            request_id = _php_trim_lower(data.get('request_id'))
            if not re.fullmatch('[a-f0-9]{16}', request_id):
                raise ValueError('invalid_request_id')
            results = []
            if _table_exists(connection, 'product_key_issue_batches'):
                with connection.cursor() as cursor:
                    cursor.execute('SELECT request_id,api_version,source AS issuance_source,batch_id,tenant_id,product_id,environment,license_mode,requested_count,status,created_at,completed_at FROM product_key_issue_batches WHERE request_id=%s LIMIT 20', (request_id,))
                    results.extend(({'source': 'batch-v2-v3', **row} for row in cursor.fetchall()))
            if _table_exists(connection, 'tenant_api_usage'):
                with connection.cursor() as cursor:
                    cursor.execute("SELECT request_id,operation,status_code,tenant_id,client_id,used_at AS created_at FROM tenant_api_usage WHERE request_id=%s AND (operation LIKE 'licenses.issue%' OR operation LIKE 'benchmark.issue%') ORDER BY used_at DESC LIMIT 20", (request_id,))
                    results.extend(({'source': 'api-request', **row} for row in cursor.fetchall()))
            for version in ('v4', 'v5', 'v6'):
                table = 'product_key_issue_jobs_' + version
                if not _table_exists(connection, table):
                    continue
                with connection.cursor() as cursor:
                    cursor.execute(f'SELECT request_id,job_id,tenant_id,product_id,environment,license_mode,requested_count,processed_count,succeeded_count,failed_count,status,error_code,created_at,completed_at FROM `{table}` WHERE request_id=%s LIMIT 20', (request_id,))
                    results.extend(({'source': version, **row} for row in cursor.fetchall()))
            from ha_handlers import _json_value
            return json_response('200 OK', {'ok': True, 'request_id': request_id, 'results': _json_value(results)})
        raise ValueError('unknown_action')
    except RuntimeError as exc:
        if connection:
            connection.rollback()
        if str(exc) == 'tenant_license_count_changed':
            return json_response('409 Conflict', {'ok': False, 'error': str(exc)})
        request_id = uuid.uuid4().hex[:16]
        from ha_handlers import _append_ha_audit
        _append_ha_audit('tenant_admin_failed', {'request_id': request_id}, request_context)
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'tenant_admin_failed'})
    except ValueError as exc:
        if connection:
            connection.rollback()
        status = '409 Conflict' if str(exc) == 'operation_id_reused' else '400 Bad Request'
        return json_response(status, {'ok': False, 'error': str(exc)})
    except database.DatabaseConfigurationError:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'service_unavailable'})
    except Exception as exc:
        if connection:
            connection.rollback()
        if _is_integrity_conflict(exc):
            return json_response('409 Conflict', {'ok': False, 'error': 'conflict'})
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'tenant_admin_failed'})
    finally:
        if connection:
            connection.close()
