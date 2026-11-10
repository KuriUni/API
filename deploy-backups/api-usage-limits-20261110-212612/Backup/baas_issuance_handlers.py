"""BaaS unified issuance status, results, and cancellation endpoints."""
from native_http import make_response, add_headers, legacy_compatible
from py36_compat import parse_iso_datetime
import json
import hashlib
import hmac
import io
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from http_utils import php_parse_query as parse_qs
import database
from baas_handlers import BaaSError, _authorize_key, _usage, _reply
from core import php_int_cast
from v3_handlers import _assert_write_fence
API_VERSION = 'baas-v6-unified-x20-v1'
PLATFORM_VERSION = 'product-key-issuance-v6-unified-x20-v1'
RESULT_PAGE_MAX = 1000
MAX_REQUEST = 100000
PLANNER_VERSION = 'unified-adaptive-x20-v1'
ISSUANCE_INSERT_BATCH = 500

def _decode_issuance_json(raw):
    """Decode a PHP json_decode(..., true, 32) request body."""
    try:
        text = raw.decode('utf-8')
        value = json.loads(text, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError())) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return (None, 'invalid_json')
    depth = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in '[{':
            depth += 1
            if depth > 32:
                return (None, 'invalid_json')
        elif char in ']}':
            depth -= 1
    if isinstance(value, list):
        return ({}, None)
    if not isinstance(value, dict):
        return (None, 'invalid_request')
    return (value, None)

@legacy_compatible(callback_index=None, request_index=0)
def _read_issuance_json(request_context, max_bytes):
    try:
        declared = php_int_cast(request_context.get('content_length') or 0)
    except (TypeError, ValueError):
        declared = 0
    if declared > max_bytes:
        return (None, 'request_too_large')
    stream = request_context.get('body_stream')
    raw = stream.read(max_bytes + 1) if stream is not None else b''
    if len(raw) > max_bytes:
        return (None, 'request_too_large')
    return _decode_issuance_json(raw)

def _coalesce(data, key, default):
    value = data.get(key)
    return default if value is None else value

def _v6_headers():
    return [('X-BaaS-V6-Status', 'unified-x20-v1'), ('X-BaaS-V6-Max-Request', str(MAX_REQUEST)), ('X-BaaS-V6-Planner', PLANNER_VERSION), ('X-BaaS-V6-Engine', 'unified-bulk-x20-v1')]

def _compatibility_headers(source_version):
    return [('X-BaaS-Compatibility-Source', source_version), ('X-BaaS-Executed-By', 'v6')]

@legacy_compatible(callback_index=None, request_index=0)
def _query(request_context):
    return parse_qs(request_context.get('query', ''), keep_blank_values=True)

def _job_public(row):
    requested = max(1, int(row.get('requested_count') or 1))
    status = str(row.get('status') or 'unknown')
    terminal = status in {'completed', 'failed', 'cancelled'}
    return {'job_id': str(row['job_id']), 'status': status, 'terminal': terminal, 'environment': str(row['environment']), 'product_id': int(row['product_id']), 'license_mode': str(row['license_mode']), 'requested_count': requested, 'processed_count': int(row.get('processed_count') or 0), 'succeeded_count': int(row.get('succeeded_count') or 0), 'failed_count': int(row.get('failed_count') or 0), 'chunk_size': int(row.get('chunk_size') or requested), 'engine_profile': str(row.get('engine_profile') or 'unified-bulk-x20-v1'), 'progress_percent': round(min(100, int(row.get('processed_count') or 0) * 100 / requested), 2), 'next_item_no': int(row.get('next_item_no') or 1), 'error_code': row.get('error_code'), 'created_at_utc': str(row.get('created_at') or ''), 'started_at_utc': row.get('started_at'), 'heartbeat_at_utc': row.get('heartbeat_at'), 'completed_at_utc': row.get('completed_at'), 'poll_after_ms': 0 if terminal else 100}

def _job(connection, tenant_id, job_id):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE tenant_id=%s AND job_id=%s LIMIT 1', (tenant_id, job_id))
        return cursor.fetchone()

def _missing_schema(connection):
    required = {'product_key_issue_jobs_v6', 'product_key_issue_plans_v6', 'product_key_issue_v6_items'}
    with connection.cursor() as cursor:
        cursor.execute('SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name IN (%s,%s,%s)', tuple(sorted(required)))
        found = {str(row['table_name']) for row in cursor.fetchall()}
    return sorted(required - found)

def _plan(count, requested_mode='auto'):
    mode = str(requested_mode).strip().lower()
    if mode not in {'auto', 'direct', 'vector', 'async', 'x20'}:
        raise ValueError('invalid_execution_mode')
    if mode == 'auto':
        mode = 'direct' if count <= 8 else 'vector' if count <= 1000 else 'turbo' if count <= 10000 else 'async'
    if mode == 'direct' and count > 8:
        raise ValueError('direct_mode_count_exceeded')
    if mode == 'vector' and count > 1000:
        raise ValueError('vector_mode_count_exceeded')
    if mode == 'async':
        chunk = 10000 if count <= 25000 else 12500 if count <= 50000 else 20000
    elif mode == 'x20':
        chunk = min(10000, count)
    else:
        chunk = count
    return {'execution_mode': mode, 'chunk_size': max(1, min(chunk, count)), 'sync': mode not in {'async', 'x20'}}

class _DuplicateLicenseKey(Exception):
    pass

def _is_duplicate_key_error(error):
    args = getattr(error, 'args', ())
    return bool(args and args[0] in (1062, '1062'))

def _prepare_issuance_records(tenant_id, product_id, job_id, first_item, count, label,
                              max_devices, evaluation_days, expires_at, config, pepper, secret):
    from core import offline_lookup, offline_secret, offline_secret_encrypt
    from baas_v7_handlers import _key, _seal
    records = []
    for offset in range(count):
        item_no = first_item + offset
        product_key = _key()
        key_hash = hmac.new(pepper, product_key.encode('ascii'), hashlib.sha256).hexdigest()
        offline = offline_secret(product_key)
        item_label = label or f'BaaS v6 {job_id[:8]} #{item_no}'
        records.append({
            'item_no': item_no,
            'product_key': product_key,
            'key_hash': key_hash,
            'fingerprint': hashlib.sha256(product_key.encode('ascii')).hexdigest(),
            'license_values': (tenant_id, product_id, key_hash, item_label, max_devices,
                               evaluation_days, expires_at, offline_lookup(offline),
                               offline_secret_encrypt(config, offline)),
            'product_key_enc': _seal(product_key, secret, job_id, item_no),
        })
    return records

def _persist_issuance_records(cursor, records, job_row_id, include_items=False):
    """Write bounded multi-row batches and map generated IDs by the unique key hash."""
    issued = []
    for start in range(0, len(records), ISSUANCE_INSERT_BATCH):
        batch = records[start:start + ISSUANCE_INSERT_BATCH]
        try:
            cursor.executemany(
                'INSERT INTO licenses(tenant_id,product_id,key_hash,label,active,max_devices,evaluation_days,expires_at,offline_lookup,offline_secret_enc) VALUES(%s,%s,%s,%s,1,%s,%s,%s,%s,%s)',
                [record['license_values'] for record in batch])
        except Exception as error:
            if _is_duplicate_key_error(error):
                raise _DuplicateLicenseKey from error
            raise

        placeholders = ','.join(['%s'] * len(batch))
        cursor.execute('SELECT id,key_hash FROM licenses WHERE key_hash IN (' + placeholders + ')',
                       tuple(record['key_hash'] for record in batch))
        license_ids = {str(row['key_hash']): int(row['id']) for row in cursor.fetchall()}
        if len(license_ids) != len(batch) or any(record['key_hash'] not in license_ids for record in batch):
            raise RuntimeError('issued_license_id_mapping_failed')

        item_rows = []
        for record in batch:
            license_id = license_ids[record['key_hash']]
            item_rows.append((6, int(job_row_id), record['item_no'], license_id,
                              record['fingerprint'], record['product_key_enc']))
            if include_items:
                issued.append({'item': record['item_no'], 'license_id': license_id,
                               'product_key': record['product_key'],
                               'key_fingerprint': record['fingerprint']})
        cursor.executemany(
            'INSERT INTO issuance_items(engine_version,job_row_id,item_no,license_id,key_fingerprint,product_key_enc) VALUES(%s,%s,%s,%s,%s,%s)',
            item_rows)
    return issued

def _write_issuance_batch(cursor, tenant_id, product_id, job_row_id, job_id, first_item,
                          count, label, max_devices, evaluation_days, expires_at,
                          config, pepper, secret, include_items=False):
    issued = []
    for offset in range(0, count, ISSUANCE_INSERT_BATCH):
        batch_count = min(ISSUANCE_INSERT_BATCH, count - offset)
        for attempt in range(4):
            records = _prepare_issuance_records(tenant_id, product_id, job_id,
                first_item + offset, batch_count, label, max_devices, evaluation_days,
                expires_at, config, pepper, secret)
            try:
                issued.extend(_persist_issuance_records(cursor, records, job_row_id, include_items))
                break
            except _DuplicateLicenseKey:
                if attempt == 3:
                    raise RuntimeError('product_key_generation_failed')
    return issued

def process_job(connection, job_id, budget_ms=20000, max_chunks=16):
    """Process a V6 queue job under a MySQL advisory lock and per-chunk transactions."""
    job_id = str(job_id).lower()
    if not re.fullmatch('[0-9a-f]{32}', job_id):
        return None
    budget_ms = max(100, min(60000, int(budget_ms)))
    max_chunks = max(1, min(100, int(max_chunks)))
    lock_name = 'tuti:baas-v6:job:' + job_id
    with connection.cursor() as cursor:
        cursor.execute('SELECT GET_LOCK(%s,0)', (lock_name,))
        locked = cursor.fetchone()
    if not locked or int(next(iter(locked.values())) if isinstance(locked, dict) else locked[0]) != 1:
        return None
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE job_id=%s LIMIT 1', (job_id,))
            job = cursor.fetchone()
        if not job:
            return None
        if str(job['status']) in {'completed', 'failed', 'cancelled'}:
            return job
        if str(job['status']) == 'cancel_requested':
            with connection.cursor() as cursor:
                cursor.execute("UPDATE product_key_issue_jobs_v6 SET status='cancelled',completed_at=UTC_TIMESTAMP(),heartbeat_at=UTC_TIMESTAMP() WHERE id=%s", (int(job['id']),))
                cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE id=%s', (int(job['id']),))
                job = cursor.fetchone() or job
            connection.commit()
            return job
        with connection.cursor() as cursor:
            cursor.execute("UPDATE product_key_issue_jobs_v6 SET status='processing',started_at=COALESCE(started_at,UTC_TIMESTAMP()),heartbeat_at=UTC_TIMESTAMP() WHERE id=%s AND status IN ('queued','processing')", (int(job['id']),))
        connection.commit()
        started = time.monotonic()
        chunks = 0
        while chunks < max_chunks and (time.monotonic() - started) * 1000 < budget_ms:
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE id=%s LIMIT 1', (int(job['id']),))
                job = cursor.fetchone()
            if not job:
                return None
            if str(job['status']) == 'cancel_requested':
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE product_key_issue_jobs_v6 SET status='cancelled',completed_at=UTC_TIMESTAMP(),heartbeat_at=UTC_TIMESTAMP() WHERE id=%s", (int(job['id']),))
                    cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE id=%s', (int(job['id']),))
                    job = cursor.fetchone() or job
                connection.commit()
                break
            if str(job['status']) != 'processing':
                break
            remaining = int(job['requested_count']) - int(job['processed_count'])
            if remaining <= 0:
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE product_key_issue_jobs_v6 SET status='completed',completed_at=COALESCE(completed_at,UTC_TIMESTAMP()),heartbeat_at=UTC_TIMESTAMP() WHERE id=%s", (int(job['id']),))
                    cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE id=%s', (int(job['id']),))
                    job = cursor.fetchone() or job
                connection.commit()
                break
            chunk_size = min(int(job['chunk_size']), remaining)
            try:
                _process_chunk(connection, job, chunk_size)
            except Exception as exc:
                connection.rollback()
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE product_key_issue_jobs_v6 SET status='failed',failed_count=GREATEST(failed_count,requested_count-processed_count),error_code=%s,heartbeat_at=UTC_TIMESTAMP(),completed_at=UTC_TIMESTAMP() WHERE id=%s AND status NOT IN ('completed','cancelled')", (str(exc)[:80] or 'v6_chunk_failed', int(job['id'])))
                    cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE id=%s', (int(job['id']),))
                    job = cursor.fetchone() or job
                connection.commit()
                break
            chunks += 1
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE job_id=%s LIMIT 1', (job_id,))
            latest = cursor.fetchone()
        return latest or job
    finally:
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT RELEASE_LOCK(%s)', (lock_name,))
        except Exception:
            pass

def _process_chunk(connection, job, chunk):
    from core import key_pepper, token_secret
    from v2_handlers import _runtime_config
    config = _runtime_config()
    pepper, secret = (key_pepper(config).encode(), token_secret(config))
    first_item = int(job['next_item_no'])
    job_id = str(job['job_id'])
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1 FROM tenants WHERE id=%s AND status='active' LIMIT 1", (int(job['tenant_id']),))
            if not cursor.fetchone():
                raise RuntimeError('tenant_not_found_or_inactive')
            cursor.execute("SELECT 1 FROM products WHERE id=%s AND tenant_id=%s AND status='active' LIMIT 1", (int(job['product_id']), int(job['tenant_id'])))
            if not cursor.fetchone():
                raise RuntimeError('product_not_found')
            label = str(job.get('label') or '').strip() or None
            _write_issuance_batch(cursor, int(job['tenant_id']), int(job['product_id']),
                int(job['id']), job_id, first_item, chunk, label, int(job['max_devices']),
                job.get('evaluation_days'), job.get('expires_at'), config, pepper, secret)
            processed = int(job['processed_count']) + chunk
            complete = processed >= int(job['requested_count'])
            cursor.execute('UPDATE product_key_issue_jobs_v6 SET processed_count=%s,succeeded_count=succeeded_count+%s,next_item_no=%s,heartbeat_at=UTC_TIMESTAMP(),status=%s,completed_at=CASE WHEN %s=1 THEN UTC_TIMESTAMP() ELSE completed_at END WHERE id=%s', (processed, chunk, first_item + chunk, 'completed' if complete else 'processing', 1 if complete else 0, int(job['id'])))
        if complete:
            from baas_handlers import _queue_webhook
            _queue_webhook(connection, int(job['tenant_id']), 'license.bulk_job_completed', {'job_id': job_id, 'count': int(job['requested_count']), 'product_id': int(job['product_id']), 'api_version': 'v6', 'engine_profile': str(job.get('engine_profile') or 'unified-bulk-x20-v1')})
        connection.commit()
    except Exception:
        connection.rollback()
        raise

def pump_due_jobs(connection, budget_ms=20000, max_jobs=8):
    max_jobs = max(1, min(20, int(max_jobs)))
    with connection.cursor() as cursor:
        cursor.execute("SELECT job_id FROM product_key_issue_jobs_v6 WHERE status IN ('queued','processing','cancel_requested') ORDER BY CASE WHEN status='cancel_requested' THEN 0 ELSE 1 END,created_at ASC LIMIT %s", (max_jobs * 5,))
        candidates = cursor.fetchall()
    started, results = (time.monotonic(), [])
    for row in candidates:
        if len(results) >= max_jobs:
            break
        remaining = budget_ms - int((time.monotonic() - started) * 1000)
        if remaining <= 100:
            break
        processed = process_job(connection, str(row['job_id']), remaining, 16)
        if processed:
            results.append(_job_public(processed))
    return results

@legacy_compatible(callback_index=1, request_index=0)
def issuance_status(request_context, source_version='v6'):
    _http_extra = []
    if source_version == 'v6':
        _http_extra = _v6_headers() + _http_extra
    raw_method = str(request_context.get('method', 'GET'))
    method = raw_method.upper() if source_version in {'v2', 'v3', 'v4', 'v5'} else raw_method
    if source_version in {'v2', 'v3'} and method != 'POST':
        return add_headers(_reply(405, {'ok': False, 'error': 'method_not_allowed'}), _http_extra)
    if method not in {'GET', 'POST'}:
        return add_headers(_reply(405, {'ok': False, 'error': 'method_not_allowed'}), _http_extra)
    if source_version in {'v4', 'v5'} and method == 'GET':
        _http_extra = _compatibility_headers(source_version) + _http_extra
        _http_extra = _v6_headers() + _http_extra
    if method == 'POST':
        return add_headers(issuance_submit(request_context, source_version, source_headers_added=source_version == 'v6'), _http_extra)
    if raw_method != 'GET':
        return add_headers(_reply(405, {'ok': False, 'error': 'method_not_allowed'}), _http_extra)
    if source_version not in {'v4', 'v5'}:
        _http_extra = _v6_headers() + _http_extra
    query = _query(request_context)
    if query.get('action', [''])[-1] == 'quote':
        return add_headers(_quote(request_context, query), _http_extra)
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'licenses:write', 'licenses.v6.status', rid)
        missing = _missing_schema(connection)
        if missing:
            return add_headers(_reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'v6_native_migration_required', 'required_migration': '028_product_key_issuance_v6_unified', 'missing_tables': missing, 'request_id': rid}, headers), _http_extra)
        job_id = str(query.get('job_id', [''])[-1]).strip().lower()
        if not re.fullmatch('[0-9a-f]{32}', job_id):
            return add_headers(_reply(400, {'ok': False, 'error': 'job_id_required', 'request_id': rid}, headers), _http_extra)
        job = _job(connection, int(client['tenant_id']), job_id)
        if not job:
            return add_headers(_reply(404, {'ok': False, 'error': 'v6_job_not_found', 'request_id': rid}, headers), _http_extra)
        if str(job['status']) not in {'completed', 'failed', 'cancelled'}:
            try:
                _assert_write_fence(connection)
                job = process_job(connection, job_id, 10000, 16) or job
            except Exception:
                pass
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM product_key_issue_plans_v6 WHERE tenant_id=%s AND job_id=%s LIMIT 1', (int(client['tenant_id']), job_id))
            plan = cursor.fetchone()
        if not plan:
            return add_headers(_reply(404, {'ok': False, 'error': 'v6_plan_not_found', 'request_id': rid}, headers), _http_extra)
        _usage(connection, client, 'licenses.issue.v6.status', 200, rid, ip_hash)
        return add_headers(_reply(200, {'ok': True, 'api_version': API_VERSION, 'issuance_platform': PLATFORM_VERSION, 'request_id': rid, 'plan': _public_plan(plan), 'job': _job_public(job), 'results_endpoint': '/api/baas/v6/issuance-results.php?job_id=' + job_id}, headers), _http_extra)
    except BaaSError as exc:
        return add_headers(_reply(exc.status, {'ok': False, 'api_version': API_VERSION, 'error': exc.error, **exc.extra, 'request_id': rid}), _http_extra)
    except database.DatabaseConfigurationError:
        return add_headers(_reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'service_unavailable', 'request_id': rid}), _http_extra)
    except Exception:
        return add_headers(_reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'v6_status_unavailable', 'request_id': rid}), _http_extra)
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def issuance_submit(request_context, source_version='v6', source_headers_added=False):
    """Submit synchronous V6 jobs; large asynchronous queue processing is separate."""
    _http_extra = []
    raw_method = str(request_context.get('method', 'GET'))
    gateway_method = raw_method.upper() if source_version in {'v2', 'v3', 'v4', 'v5'} else raw_method
    if gateway_method != 'POST':
        return add_headers(_reply(405, {'ok': False, 'error': 'method_not_allowed'}), _http_extra)
    rid = uuid.uuid4().hex[:16]
    if source_version in {'v2', 'v3', 'v4', 'v5'}:
        try:
            declared_length = int(request_context.get('content_length') or 0)
        except (TypeError, ValueError):
            declared_length = 0
        if declared_length > 1048576:
            return add_headers(_reply(413, {'ok': False, 'error': 'request_too_large', 'request_id': rid}), _http_extra)
        if 'application/json' not in str(request_context.get('content_type', '')).lower():
            return add_headers(_reply(415, {'ok': False, 'error': 'application_json_required', 'request_id': rid}), _http_extra)
        legacy_data, parse_error = _read_issuance_json(request_context, 131072)
        if parse_error == 'request_too_large':
            return add_headers(_reply(413, {'ok': False, 'error': 'request_too_large', 'request_id': rid}), _http_extra)
        if parse_error == 'invalid_json':
            return add_headers(_reply(400, {'ok': False, 'error': 'invalid_json', 'request_id': rid}), _http_extra)
        if parse_error == 'invalid_request':
            return add_headers(_reply(400, {'ok': False, 'error': 'invalid_request', 'request_id': rid}), _http_extra)
        action = legacy_data.get('action', 'issue')
        if action is None:
            action = 'issue'
        if str(action).strip().lower() != 'issue':
            return add_headers(_reply(400, {'ok': False, 'error': 'unsupported_action', 'request_id': rid}), _http_extra)
        raw_count = legacy_data.get('count', 1)
        if raw_count is None:
            raw_count = 1
        count = php_int_cast(raw_count)
        if count < 1 or count > 100000:
            return add_headers(_reply(400, {'ok': False, 'error': 'v6_compat_issue_count_invalid', 'min_request': 1, 'max_request': 100000, 'request_id': rid}), _http_extra)
        legacy_data['count'] = count
        raw = json.dumps(legacy_data, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        request_context = dict(request_context)
        request_context['body_stream'] = io.BytesIO(raw)
        request_context['content_length'] = str(len(raw))
        _http_extra = _compatibility_headers(source_version) + _http_extra
        _http_extra = _v6_headers() + _http_extra
    elif not source_headers_added:
        _http_extra = _v6_headers() + _http_extra
    if raw_method != 'POST':
        return add_headers(_reply(405, {'ok': False, 'error': 'method_not_allowed'}), _http_extra)
    connection = None
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'licenses:write', 'licenses.v6.submit', rid)
        _assert_write_fence(connection)
        missing = _missing_schema(connection)
        if missing:
            return add_headers(_reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'v6_native_migration_required', 'required_migration': '028_product_key_issuance_v6_unified', 'missing_tables': missing, 'request_id': rid}, headers), _http_extra)
        max_body = 1048576 if source_version in {'v2', 'v3', 'v4', 'v5'} else 65536
        if php_int_cast(request_context.get('content_length') or 0) > max_body:
            return add_headers(_reply(413, {'ok': False, 'error': 'request_too_large', 'request_id': rid}, headers), _http_extra)
        if 'application/json' not in str(request_context.get('content_type', '')).lower():
            return add_headers(_reply(415, {'ok': False, 'error': 'application_json_required', 'request_id': rid}, headers), _http_extra)
        data, parse_error = _read_issuance_json(request_context, max_body)
        if parse_error:
            status = 413 if parse_error == 'request_too_large' else 400
            return add_headers(_reply(status, {'ok': False, 'error': parse_error, 'request_id': rid}, headers), _http_extra)
        if source_version in {'v2', 'v3', 'v4', 'v5'}:
            if str(data.get('action', 'issue')).strip().lower() != 'issue':
                return add_headers(_reply(400, {'ok': False, 'error': 'unsupported_action', 'request_id': rid}, headers), _http_extra)
        count = php_int_cast(_coalesce(data, 'count', 1))
        if count < 1 or count > 100000:
            raise ValueError('invalid_issue_count')
        product = php_int_cast(data.get('product_id') or 0)
        if product < 1:
            raise ValueError('product_id_required')
        idem = str(_coalesce(data, 'idempotency_key', request_context.get('header:idempotency-key', ''))).strip()
        if not re.fullmatch('[A-Za-z0-9_-]{20,100}', idem):
            raise ValueError('invalid_idempotency_key')
        mode = str(_coalesce(data, 'license_mode', 'single')).strip().lower()
        if mode not in {'single', 'volume', 'evaluation'}:
            raise ValueError('invalid_license_mode')
        execution = str(_coalesce(data, 'execution_mode', 'auto')).strip().lower()
        atomicity = str(_coalesce(data, 'atomicity', 'auto')).strip().lower()
        if execution not in {'auto', 'direct', 'vector', 'async', 'x20'}:
            raise ValueError('invalid_execution_mode')
        if atomicity not in {'auto', 'atomic', 'chunk'}:
            raise ValueError('invalid_atomicity')
        plan = _plan(count, execution)
        if atomicity == 'auto':
            atomicity = 'atomic' if plan['sync'] else 'chunk'
        if atomicity == 'atomic' and (not plan['sync']):
            raise ValueError('atomic_async_not_supported_in_beta')
        label = str(_coalesce(data, 'label', '')).strip()[:100] or None
        max_devices = max(2, min(10000, php_int_cast(_coalesce(data, 'max_devices', 10)))) if mode == 'volume' else 1
        evaluation_days = max(1, min(3650, php_int_cast(_coalesce(data, 'evaluation_days', 30)))) if mode == 'evaluation' else None
        expires_at = None
        expiry_input = str(_coalesce(data, 'expires_at', '')).strip()
        if mode != 'evaluation' and expiry_input:
            try:
                parsed = parse_iso_datetime(expiry_input.replace('Z', '+00:00'))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                raise ValueError('invalid_expires_at')
            if int(parsed.timestamp()) <= int(datetime.now(timezone.utc).timestamp()):
                raise ValueError('expires_at_must_be_future')
            expires_at = parsed.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        environment = str(client.get('tenant_environment', 'unknown'))
        if environment not in {'production', 'sandbox'}:
            raise ValueError('tenant_environment_invalid')
        tenant_id = int(client['tenant_id'])
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM products WHERE id=%s AND tenant_id=%s AND status='active' LIMIT 1", (product, tenant_id))
            if not cursor.fetchone():
                raise ValueError('product_not_found')
        canonical = {'api_version': 'product-key-issuance-v6-unified-x20-v1', 'tenant_id': tenant_id, 'product_id': product, 'count': count, 'license_mode': mode, 'atomicity': atomicity, 'execution_mode': plan['execution_mode'], 'label': label, 'max_devices': max_devices, 'evaluation_days': evaluation_days, 'expires_at': expires_at}
        request_hash = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE tenant_id=%s AND request_key=%s LIMIT 1', (tenant_id, idem))
            old = cursor.fetchone()
        if old:
            if int(old['client_id']) != int(client['id']):
                raise PermissionError('idempotency_key_reserved_by_other_issuer')
            if not hmac.compare_digest(str(old['request_hash']), request_hash):
                raise PermissionError('idempotency_key_reused_with_different_request')
            plan_row = None
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM product_key_issue_plans_v6 WHERE tenant_id=%s AND job_id=%s LIMIT 1', (tenant_id, str(old['job_id'])))
                plan_row = cursor.fetchone()
            from v2_handlers import _runtime_config
            from core import token_secret
            from baas_v7_handlers import _open
            with connection.cursor() as cursor:
                cursor.execute('SELECT item_no,license_id,key_fingerprint,product_key_enc FROM product_key_issue_v6_items WHERE job_row_id=%s ORDER BY item_no ASC LIMIT %s', (int(old['id']), min(count, 1000)))
                rows = cursor.fetchall()
            secret = token_secret(_runtime_config())
            items = [{'item': int(row['item_no']), 'license_id': int(row['license_id']), 'product_key': _open(str(row['product_key_enc']), secret, str(old['job_id']), int(row['item_no'])), 'key_fingerprint': str(row['key_fingerprint'])} for row in rows]
            _usage(connection, client, 'licenses.issue.v6.replay', 200, rid, ip_hash)
            return add_headers(_reply(200, {'ok': True, 'api_version': API_VERSION, 'idempotent_replay': True, 'request_id': rid, 'plan': _public_plan(plan_row) if plan_row else None, 'job': _job_public(old), 'items': items}, headers), _http_extra)
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute("SELECT max_licenses FROM tenants WHERE id=%s AND status='active' FOR UPDATE", (tenant_id,))
            tenant_row = cursor.fetchone()
            if not tenant_row:
                raise ValueError('tenant_not_found_or_inactive')
            cursor.execute('SELECT COUNT(*) AS n FROM licenses WHERE tenant_id=%s AND deleted_at IS NULL', (tenant_id,))
            current = int((cursor.fetchone() or {}).get('n', 0))
            reserved = 0
            for table in ('product_key_issue_jobs_v4', 'product_key_issue_jobs_v5', 'product_key_issue_jobs_v6', 'product_key_v8_jobs'):
                cursor.execute('SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s', (table,))
                if cursor.fetchone():
                    cursor.execute(f"SELECT COALESCE(SUM(GREATEST(requested_count-processed_count,0)),0) AS n FROM {table} WHERE tenant_id=%s AND status IN ('queued','processing','cancel_requested')", (tenant_id,))
                    reserved += int((cursor.fetchone() or {}).get('n', 0))
            if current + reserved + count > int(tenant_row['max_licenses']):
                raise ValueError('license_quota_exceeded')
            job_id = secrets.token_hex(16)
            plan_id = secrets.token_hex(12)
            cursor.execute("INSERT INTO issuance_jobs(engine_version,job_id,request_id,tenant_id,client_id,product_id,environment,license_mode,requested_count,processed_count,succeeded_count,failed_count,chunk_size,engine_profile,next_item_no,request_key,request_hash,label,max_devices,evaluation_days,expires_at,status) VALUES(6,%s,%s,%s,%s,%s,%s,%s,%s,0,0,0,%s,'unified-bulk-x20-v1',1,%s,%s,%s,%s,%s,%s,'queued')", (job_id, rid, tenant_id, int(client['id']), product, environment, mode, count, int(plan['chunk_size']), idem, request_hash, label, max_devices, evaluation_days, expires_at))
            job_row_id = int(getattr(cursor, 'lastrowid', 0) or 0)
            cursor.execute('INSERT INTO issuance_plans(engine_version,plan_id,job_id,tenant_id,client_id,execution_mode,atomicity,requested_count,initial_chunk_size,planner_version) VALUES(6,%s,%s,%s,%s,%s,%s,%s,%s,%s)', (plan_id, job_id, tenant_id, int(client['id']), plan['execution_mode'], atomicity, count, int(plan['chunk_size']), 'unified-adaptive-x20-v1'))
        connection.commit()
        if not plan['sync']:
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE id=%s', (job_row_id,))
                job = cursor.fetchone()
                cursor.execute('SELECT * FROM product_key_issue_plans_v6 WHERE plan_id=%s', (plan_id,))
                plan_row = cursor.fetchone()
            from billing_policy import issue_submit_operation
            _usage(connection, client, issue_submit_operation(6, count), 202, rid, ip_hash)
            return add_headers(_reply(202, {'pricing': _pricing_payload(count, environment), 'ok': True, 'api_version': API_VERSION, 'issuance_platform': PLATFORM_VERSION, 'beta': True, 'execution': 'async', 'request_id': rid, 'plan': _public_plan(plan_row), 'job': _job_public(job), 'status_endpoint': '/api/baas/v6/issuance.php?job_id=' + job_id, 'results_endpoint': '/api/baas/v6/issuance-results.php?job_id=' + job_id, 'cancel_endpoint': '/api/baas/v6/issuance-cancel.php'}, headers), _http_extra)
        config = __import__('v2_handlers')._runtime_config()
        from core import key_pepper, token_secret
        pepper = key_pepper(config).encode()
        secret = token_secret(config)
        connection.begin()
        with connection.cursor() as cursor:
            issued = _write_issuance_batch(cursor, tenant_id, product, job_row_id, job_id,
                1, count, label, max_devices, evaluation_days, expires_at, config, pepper,
                secret, include_items=count <= 1000)
            cursor.execute("UPDATE product_key_issue_jobs_v6 SET processed_count=%s,succeeded_count=%s,next_item_no=%s,status='completed',started_at=UTC_TIMESTAMP(),heartbeat_at=UTC_TIMESTAMP(),completed_at=UTC_TIMESTAMP() WHERE id=%s", (count, count, count + 1, job_row_id))
            cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE id=%s', (job_row_id,))
            job = cursor.fetchone()
            cursor.execute('SELECT * FROM product_key_issue_plans_v6 WHERE plan_id=%s', (plan_id,))
            plan_row = cursor.fetchone()
        from baas_handlers import _queue_webhook
        _queue_webhook(connection, tenant_id, 'license.bulk_job_completed', {'job_id': job_id, 'count': count, 'product_id': product, 'api_version': 'v6', 'engine_profile': 'unified-bulk-x20-v1'})
        connection.commit()
        from billing_policy import issue_submit_operation
        _usage(connection, client, issue_submit_operation(6, count), 201, rid, ip_hash)
        response = {'pricing': _pricing_payload(count, environment), 'ok': True, 'api_version': API_VERSION, 'issuance_platform': PLATFORM_VERSION, 'beta': True, 'execution': 'sync', 'request_id': rid, 'plan': _public_plan(plan_row), 'job': _job_public(job), 'count': count, 'results_endpoint': '/api/baas/v6/issuance-results.php?job_id=' + job_id}
        if count <= 1000:
            response['items'] = issued
        return add_headers(_reply(201, response, headers), _http_extra)
    except BaaSError as exc:
        if connection:
            connection.rollback()
        return add_headers(_reply(exc.status, {'ok': False, 'api_version': API_VERSION, 'error': exc.error, **exc.extra, 'request_id': rid}), _http_extra)
    except PermissionError as exc:
        if connection:
            connection.rollback()
        return add_headers(_reply(409, {'ok': False, 'api_version': API_VERSION, 'error': str(exc), 'request_id': rid}), _http_extra)
    except (ValueError, TypeError, OverflowError) as exc:
        if connection:
            connection.rollback()
        error = str(exc) or 'invalid_request'
        status = 409 if error in {'license_quota_exceeded', 'tenant_not_found_or_inactive'} else 400
        return add_headers(_reply(status, {'ok': False, 'api_version': API_VERSION, 'error': error, 'request_id': rid}), _http_extra)
    except database.DatabaseConfigurationError:
        if connection:
            connection.rollback()
        return add_headers(_reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'service_unavailable', 'request_id': rid}), _http_extra)
    except Exception:
        if connection:
            connection.rollback()
        return add_headers(_reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'v6_sync_issuance_failed', 'request_id': rid}), _http_extra)
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def issuance_results(request_context, source_version='v6'):
    _http_extra = []
    raw_method = str(request_context.get('method', 'GET'))
    gateway_method = raw_method.upper() if source_version in {'v4', 'v5'} else raw_method
    if gateway_method != 'GET':
        return add_headers(_reply(405, {'ok': False, 'error': 'method_not_allowed'}), _http_extra)
    if source_version in {'v4', 'v5'}:
        _http_extra = _compatibility_headers(source_version) + _http_extra
    if raw_method != 'GET':
        return add_headers(_reply(405, {'ok': False, 'error': 'method_not_allowed'}), _http_extra)
    rid = uuid.uuid4().hex[:16]
    query = _query(request_context)
    connection = None
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'licenses:write', 'licenses.v6.results', rid)
        missing = _missing_schema(connection)
        if missing:
            return add_headers(_reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'v6_native_migration_required', 'missing_tables': missing, 'request_id': rid}, headers), _http_extra)
        job_id = str(query.get('job_id', [''])[-1]).strip().lower()
        if not re.fullmatch('[0-9a-f]{32}', job_id):
            return add_headers(_reply(400, {'ok': False, 'error': 'job_id_required', 'request_id': rid}, headers), _http_extra)
        tenant_id = int(client['tenant_id'])
        job = _job(connection, tenant_id, job_id)
        if not job:
            return add_headers(_reply(404, {'ok': False, 'error': 'v6_job_not_found', 'request_id': rid}, headers), _http_extra)
        cursor = max(0, php_int_cast(query.get('cursor', ['0'])[-1]))
        limit = max(1, min(RESULT_PAGE_MAX, php_int_cast(query.get('limit', ['500'])[-1])))
        reveal = str(query.get('reveal', ['false'])[-1]).lower() in {'1', 'true', 'yes'}
        with connection.cursor() as db_cursor:
            db_cursor.execute('SELECT item_no,license_id,key_fingerprint,product_key_enc,created_at FROM product_key_issue_v6_items WHERE job_row_id=%s AND item_no>%s ORDER BY item_no ASC LIMIT %s', (int(job['id']), cursor, limit))
            rows = db_cursor.fetchall()
        config = None
        if reveal:
            from v2_handlers import _runtime_config
            config = _runtime_config()
        items, last = ([], cursor)
        for row in rows:
            item_no = int(row['item_no'])
            item = {'item': item_no, 'license_id': int(row['license_id']), 'key_fingerprint': str(row['key_fingerprint']), 'created_at_utc': str(row['created_at'])}
            if reveal:
                from baas_v7_handlers import _open
                from core import token_secret
                item['product_key'] = _open(str(row['product_key_enc']), token_secret(config), job_id, item_no)
            items.append(item)
            last = item_no
        has_more = last < int(job.get('succeeded_count') or 0)
        _usage(connection, client, 'licenses.issue.v6.results', 200, rid, ip_hash)
        return add_headers(_reply(200, {'ok': True, 'api_version': API_VERSION, 'issuance_platform': PLATFORM_VERSION, 'request_id': rid, 'job': _job_public(job), 'keys_revealed': reveal, 'items': items, 'next_cursor': last if has_more else None, 'has_more': has_more}, headers), _http_extra)
    except BaaSError as exc:
        return add_headers(_reply(exc.status, {'ok': False, 'api_version': API_VERSION, 'error': exc.error, **exc.extra, 'request_id': rid}), _http_extra)
    except database.DatabaseConfigurationError:
        return add_headers(_reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'service_unavailable', 'request_id': rid}), _http_extra)
    except Exception:
        return add_headers(_reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'v6_results_unavailable', 'request_id': rid}), _http_extra)
    finally:
        if connection:
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def issuance_cancel(request_context, source_version='v6'):
    _http_extra = []
    raw_method = str(request_context.get('method', 'GET'))
    gateway_method = raw_method.upper() if source_version in {'v4', 'v5'} else raw_method
    if gateway_method != 'POST':
        return add_headers(_reply(405, {'ok': False, 'error': 'method_not_allowed'}), _http_extra)
    if source_version in {'v4', 'v5'}:
        _http_extra = _compatibility_headers(source_version) + _http_extra
    if raw_method != 'POST':
        return add_headers(_reply(405, {'ok': False, 'error': 'method_not_allowed'}), _http_extra)
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'licenses:write', 'licenses.v6.cancel', rid)
        _assert_write_fence(connection)
        missing = _missing_schema(connection)
        if missing:
            return add_headers(_reply(503, {'ok': False, 'error': 'v6_native_migration_required', 'missing_tables': missing, 'request_id': rid}, headers), _http_extra)
        if php_int_cast(request_context.get('content_length') or 0) > 65536:
            return add_headers(_reply(413, {'ok': False, 'error': 'request_too_large', 'request_id': rid}, headers), _http_extra)
        if 'application/json' not in str(request_context.get('content_type', '')).lower():
            return add_headers(_reply(415, {'ok': False, 'error': 'application_json_required', 'request_id': rid}, headers), _http_extra)
        data, parse_error = _read_issuance_json(request_context, 65536)
        if parse_error:
            status = 413 if parse_error == 'request_too_large' else 400
            return add_headers(_reply(status, {'ok': False, 'error': parse_error, 'request_id': rid}, headers), _http_extra)
        job_id = str(data.get('job_id', '')).strip().lower()
        if not re.fullmatch('[0-9a-f]{32}', job_id):
            return add_headers(_reply(400, {'ok': False, 'error': 'job_id_required', 'request_id': rid}, headers), _http_extra)
        job = _job(connection, int(client['tenant_id']), job_id)
        if not job:
            return add_headers(_reply(404, {'ok': False, 'error': 'v6_job_not_found', 'request_id': rid}, headers), _http_extra)
        if str(job['status']) in {'completed', 'failed', 'cancelled'}:
            return add_headers(_reply(409, {'ok': False, 'error': 'v6_job_already_terminal', 'job': _job_public(job), 'request_id': rid}, headers), _http_extra)
        with connection.cursor() as cursor:
            cursor.execute("UPDATE product_key_issue_jobs_v6 SET status='cancel_requested',heartbeat_at=UTC_TIMESTAMP() WHERE id=%s AND status IN ('queued','processing')", (int(job['id']),))
        connection.commit()
        updated = process_job(connection, job_id, 250, 1) or _job(connection, int(client['tenant_id']), job_id) or job
        _usage(connection, client, 'licenses.issue.v6.cancel', 202, rid, ip_hash)
        return add_headers(_reply(202, {'ok': True, 'api_version': API_VERSION, 'issuance_platform': PLATFORM_VERSION, 'request_id': rid, 'job': _job_public(updated)}, headers), _http_extra)
    except BaaSError as exc:
        if connection:
            connection.rollback()
        return add_headers(_reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra, 'request_id': rid}), _http_extra)
    except database.DatabaseConfigurationError:
        return add_headers(_reply(503, {'ok': False, 'error': 'service_unavailable', 'request_id': rid}), _http_extra)
    except Exception:
        if connection:
            connection.rollback()
        return add_headers(_reply(503, {'ok': False, 'error': 'v6_cancel_unavailable', 'request_id': rid}), _http_extra)
    finally:
        if connection:
            connection.close()

def _public_plan(row):
    return {'plan_id': str(row['plan_id']), 'job_id': str(row['job_id']), 'execution_mode': str(row['execution_mode']), 'atomicity': str(row['atomicity']), 'initial_chunk_size': int(row['initial_chunk_size']), 'planner_version': str(row['planner_version']), 'engine_profile': 'unified-bulk-x20-v1', 'created_at_utc': str(row['created_at'])}

def _pricing_payload(count, environment):
    from billing_policy import issue_submit_units, credit, RULES
    units = issue_submit_units(count)
    if environment == 'sandbox':
        units = (units + 5) // 10
    return {'mode': RULES['mode'], 'currency': 'Cr', 'basis': 'requested_key_count', 'requested_count': count, 'charge_units': units, 'charge_credit': credit(units)}

@legacy_compatible(callback_index=1, request_index=0)
def _quote(request_context, query):
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'licenses:write', 'licenses.v6.quote', rid)
        raw = query.get('count', [''])[-1]
        if not re.fullmatch('[0-9]{1,6}', raw):
            return _reply(400, {'ok': False, 'error': 'invalid_issue_count', 'request_id': rid}, headers)
        count = int(raw)
        if count < 1 or count > 100000:
            return _reply(400, {'ok': False, 'error': 'invalid_issue_count', 'request_id': rid}, headers)
        from billing_policy import issue_submit_units, credit, RULES
        environment = str(client.get('tenant_environment', 'unknown'))
        if environment not in {'production', 'sandbox'}:
            return _reply(409, {'ok': False, 'error': 'tenant_environment_invalid', 'request_id': rid}, headers)
        units = issue_submit_units(count)
        if environment == 'sandbox':
            units = (units + 5) // 10
        return _reply(200, {'ok': True, 'api_version': API_VERSION, 'pricing': {'mode': RULES['mode'], 'currency': 'Cr', 'basis': 'requested_key_count', 'requested_count': count, 'charge_units': units, 'charge_credit': credit(units)}, 'request_id': rid}, headers)
    except BaaSError as exc:
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra, 'request_id': rid})
    except Exception:
        return _reply(503, {'ok': False, 'error': 'quote_unavailable', 'request_id': rid})
    finally:
        if connection:
            connection.close()
