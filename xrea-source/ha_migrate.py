"""Authenticated schema 039 installation/validation endpoint."""
from native_http import make_response, add_headers, legacy_compatible
import json
import database
from ha_handlers import _ha_authorized_scope, _response
from schema39_storage import run_migrations
from http_utils import request_data, RequestError

@legacy_compatible(callback_index=1, request_index=0)
def migrate(request_context):
    if not _ha_authorized_scope(request_context, 'ha:operate'):
        return _response('404 Not Found', b'{"ok":false,"error":"not_found"}')
    if request_context.get('method', '') != 'POST':
        return _response('405 Method Not Allowed', b'{"ok":false,"error":"method_not_allowed"}')
    connection = None
    try:
        data = request_data(request_context)
        scope = data.get('scope', 'all') if isinstance(data, dict) else 'all'
        if scope not in ('all', 'v8', 'license_v4', 'api_usage', 'stripe'):
            return _response('400 Bad Request', b'{"ok":false,"error":"invalid_migration_scope"}')
        connection = database.connect()
        if scope == 'v8':
            payload = {'ok': True, 'scope': 'v8'}
        elif scope == 'license_v4':
            from license_v4_storage import ensure_schema
            payload = {'ok': True, 'scope': 'license_v4', 'license_v4': ensure_schema(connection)}
        elif scope == 'api_usage':
            from api_usage_limits import ensure_schema
            ensure_schema(connection)
            payload = {'ok': True, 'scope': 'api_usage', 'monthly_api_limits': True}
        elif scope == 'stripe':
            from stripe_billing import ensure_schema
            ensure_schema(connection)
            payload = {'ok': True, 'scope': 'stripe', 'stripe_billing': True}
        else:
            from schema39_storage import run_migrations as current_migrations
            payload = current_migrations(connection)
        if scope not in ('license_v4', 'api_usage', 'stripe'):
            from product_key_v8_storage import ensure_schema as ensure_v8_issuance_schema
            payload['product_key_issuance_v8'] = ensure_v8_issuance_schema(connection)
        return _response('200 OK', json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8'))
    except RequestError:
        return _response('400 Bad Request', b'{"ok":false,"error":"invalid_request"}')
    except Exception as error:
        if connection is not None:
            connection.rollback()
        code = str(error)
        if code != 'controlled_data_migration_required' and (not code.startswith(('storage_table_', 'storage_view_', 'storage_columns_', 'storage_projection_', 'storage_views_', 'storage_plan_'))):
            code = 'migration_failed'
        return _response('503 Service Unavailable', json.dumps({'ok': False, 'error': code}, separators=(',', ':')).encode('utf-8'))
    finally:
        if connection is not None:
            connection.close()
