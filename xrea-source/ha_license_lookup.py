"""Read-only Python port of the HA product-key lookup endpoint."""
from native_http import make_response, add_headers, legacy_compatible
import json
import uuid
from datetime import date, datetime
import database
from core import is_valid_license_key_format, license_key_hash, normalize_license_key
from http_utils import json_response
from migration_config import secret_value

class LookupInputError(ValueError):
    pass

def _reject_json_constant(_value):
    raise LookupInputError('Syntax error')

def _runtime_config():
    return {'key_pepper': secret_value('key_pepper')}

def _json_value(value):
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value

@legacy_compatible(callback_index=1, request_index=0)
def license_lookup(request_context):
    from ha_handlers import _append_ha_audit, _ha_authorized_scope
    if not _ha_authorized_scope(request_context, 'license:read'):
        return json_response('404 Not Found', {'ok': False, 'error': 'not_found'})
    if request_context.get('method', '') != 'POST':
        return json_response('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'}, [('Allow', 'POST')])
    connection = None
    try:
        stream = request_context.get('body_stream')
        raw = stream.read() if stream is not None else b''
        try:
            data = json.loads(raw.decode('utf-8'), parse_constant=_reject_json_constant)
        except UnicodeDecodeError:
            raise LookupInputError('Malformed UTF-8 characters, possibly incorrectly encoded')
        except (json.JSONDecodeError, ValueError):
            raise LookupInputError('Syntax error')
        depth = 0
        pending = [(data, 0)]
        while pending:
            value, parent_depth = pending.pop()
            if isinstance(value, (dict, list)):
                depth = max(depth, parent_depth + 1)
                if depth > 16:
                    raise LookupInputError('Maximum stack depth exceeded')
                pending.extend(((item, parent_depth + 1) for item in (value.values() if isinstance(value, dict) else value)))
        if isinstance(data, dict):
            action = data.get('action', 'lookup_product_key')
            if action is None:
                action = 'lookup_product_key'
        else:
            action = 'lookup_product_key'
        if str(action) != 'lookup_product_key':
            raise LookupInputError('invalid_action')
        raw_key = data.get('product_key', '') if isinstance(data, dict) else ''
        if raw_key is None or raw_key is False:
            raw_key = ''
        elif raw_key is True:
            raw_key = '1'
        elif isinstance(raw_key, (dict, list)):
            raw_key = 'Array'
        else:
            raw_key = str(raw_key)
        product_key = normalize_license_key(raw_key)
        if not is_valid_license_key_format(product_key):
            raise LookupInputError('invalid_product_key')
        config = _runtime_config()
        key_hash = license_key_hash(config, product_key)
        connection = database.connect()
        query = "SELECT l.id,l.tenant_id,l.product_id,t.slug tenant_slug,t.name tenant_name,CASE WHEN t.parent_tenant_id IS NOT NULL OR t.environment='sandbox' THEN 'sandbox' WHEN t.environment='production' THEN 'production' ELSE 'unknown' END environment,p.code product_code,p.name product_name,l.label,l.active,l.max_devices,CASE WHEN l.evaluation_days IS NOT NULL THEN 'evaluation' WHEN l.max_devices>1 THEN 'volume' ELSE 'single' END license_mode,l.evaluation_days,l.evaluation_started_at,l.expires_at,l.revoked_at,l.created_at,l.last_activated_at,l.last_seen_at,(SELECT COUNT(*) FROM license_devices d WHERE d.license_id=l.id AND d.revoked_at IS NULL) active_devices FROM licenses l LEFT JOIN tenants t ON t.id=l.tenant_id LEFT JOIN products p ON p.id=l.product_id AND p.tenant_id=l.tenant_id WHERE l.key_hash=%s AND l.deleted_at IS NULL LIMIT 1"
        with connection.cursor() as cursor:
            cursor.execute(query, (key_hash,))
            license_row = cursor.fetchone()
        found = isinstance(license_row, dict)
        license_id = int(license_row.get('id') or 0) if found else 0
        _append_ha_audit('product_key_lookup', {'license_id': license_id, 'found': found, 'fast_path': True}, request_context)
        return json_response('200 OK', {'ok': True, 'found': found, 'license_id': license_id or None, 'environment': license_row.get('environment') if found else None, 'tenant_id': int(license_row.get('tenant_id') or 0) if found else None, 'product_id': int(license_row.get('product_id') or 0) if found else None, 'license': _json_value(license_row) if found else None})
    except LookupInputError as exc:
        return json_response('400 Bad Request', {'ok': False, 'error': str(exc)})
    except Exception:
        request_id = uuid.uuid4().hex[:16]
        _append_ha_audit('product_key_lookup_failed', {'request_id': request_id}, request_context)
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'product_key_lookup_failed', 'request_id': request_id})
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
