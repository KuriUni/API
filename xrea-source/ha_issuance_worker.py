"""HA-authorized worker entry points for V4/V5 compatibility and V6 unified jobs."""
from native_http import make_response, add_headers, legacy_compatible
import json
import secrets
import time
import database
from core import php_int_cast
from http_utils import json_response

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status, payload):
    labels = {200: '200 OK', 400: '400 Bad Request', 404: '404 Not Found', 405: '405 Method Not Allowed', 413: '413 Payload Too Large', 503: '503 Service Unavailable'}
    return json_response(labels.get(status, f'{status} Error'), payload, [('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff')])

def _schema_error(version, missing):
    """Match the version-specific schema gate in the PHP worker endpoint."""
    if version == 'v4':
        if any(('.' not in item for item in missing)):
            migration = '021_product_key_issuance_v4'
        elif 'product_key_issue_jobs_v4.speed_tier' in missing:
            migration = '022_product_key_issuance_v4_speed_tier'
        else:
            migration = '023_product_key_issuance_v4_priority'
        error = 'v4_migration_required'
        return {'error': error, 'required_migration': migration, 'request_id': secrets.token_hex(8), 'api_version': 'baas-v1.1', 'ok': False, 'error_code': error.upper()}
    error = 'v5_native_migration_required'
    return {'ok': False, 'api_version': 'baas-v5-x20-beta4', 'error': error, 'required_migration': '026_product_key_issuance_v5_native', 'missing_tables': list(missing)}

@legacy_compatible(callback_index=1, request_index=0)
def issuance_worker(request_context, version):
    from ha_handlers import _ha_authorized_scope
    if not _ha_authorized_scope(request_context, 'ha:operate'):
        return _reply(404, {'ok': False, 'error': 'not_found'})
    if version == 'v4':
        default_budget, min_budget, max_budget, default_jobs = (12000, 500, 30000, 12)
        profile, worker_name = ('adaptive-throughput-v2', 'product-key-v4')
    else:
        default_budget, min_budget, max_budget, default_jobs = (30000, 1000, 60000, 8)
        profile, worker_name = ('native-bulk-x20-v2', 'product-key-v5')
    connection = None
    try:
        connection = database.connect()
        from v3_handlers import _assert_write_fence
        _assert_write_fence(connection)
        from ha_legacy_issuance_worker import _schema_missing
        missing = _schema_missing(connection, version)
        if missing:
            return _reply(503, _schema_error(version, missing))
        try:
            stream = request_context.get('body_stream')
            if php_int_cast(request_context.get('content_length')) > 65536:
                return _reply(413, {'ok': False, 'error': 'request_too_large'})
            raw = stream.read(65537) if stream is not None else b''
            if len(raw) > 65536:
                return _reply(413, {'ok': False, 'error': 'request_too_large'})
            data = json.loads(raw.decode('utf-8') or '{}')
            if not isinstance(data, dict):
                data = {}
        except Exception:
            data = {}
        raw_budget = data.get('budget_ms')
        raw_jobs = data.get('max_jobs')
        budget = max(min_budget, min(max_budget, php_int_cast(default_budget if raw_budget is None else raw_budget)))
        jobs = max(1, min(20, php_int_cast(default_jobs if raw_jobs is None else raw_jobs)))
        started = time.monotonic()
        from ha_legacy_issuance_worker import pump_legacy_jobs
        processed = pump_legacy_jobs(connection, version, budget, jobs)
        elapsed = max(1, round((time.monotonic() - started) * 1000))
        return _reply(200, {'ok': True, 'worker': worker_name, 'worker_profile': profile, 'processed_jobs': processed, 'processed_job_count': len(processed), 'budget_ms': budget, 'elapsed_ms': elapsed})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': version + '_worker_failed', 'request_id': secrets.token_hex(8)})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': version + '_worker_failed', 'request_id': secrets.token_hex(8)})
    finally:
        if connection:
            connection.close()
