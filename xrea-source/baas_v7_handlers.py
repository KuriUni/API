"""Python implementation of the synchronous BaaS V7 issuance endpoint."""
from native_http import make_response, add_headers, legacy_compatible
import base64
import hashlib
import hmac
import json
import re
import secrets
import uuid
import os
from datetime import datetime, timezone
import database
from billing_policy import credit, issue_submit_operation, issue_submit_units, RULES
from baas_handlers import BaaSError, _authorize_key, _queue_webhook, _reply as _base_reply, _usage
from core import key_pepper, token_secret, license_key_hash, offline_lookup, offline_secret, offline_secret_encrypt, php_int_cast, _php_trim
from migration_config import secret_value
from v3_handlers import _assert_write_fence
API_VERSION = 'baas-v7-beta-minimal-sync-v1'
MAX_REQUEST = 1000
ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status, payload, headers=()):
    base = [('X-BaaS-V7-Status', 'beta-minimal-sync-v1'), ('X-BaaS-V7-Max-Request', str(MAX_REQUEST))]
    return _base_reply(status, payload, base + list(headers))

@legacy_compatible(callback_index=None, request_index=0)
def _json_request(request_context):
    try:
        length = int(request_context.get('content_length') or 0)
    except ValueError:
        length = 0
    if length > 65536:
        raise ValueError('request_too_large')
    if 'application/json' not in str(request_context.get('content_type', '')).lower():
        raise TypeError('application_json_required')
    raw = request_context.get('body_stream').read(65537) if request_context.get('body_stream') else b''
    if len(raw) > 65536:
        raise ValueError('request_too_large')
    value = json.loads(raw.decode('utf-8') or '{}')
    if not isinstance(value, dict):
        raise ValueError('invalid_request')
    return value

def _key():
    return '-'.join((''.join((secrets.choice(ALPHABET) for _ in range(5))) for _ in range(5)))

def _seal(product_key, token, job_id, item_no):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = hashlib.sha256(('TUTI-BAAS-PK-ISSUANCE-V6|' + token).encode()).digest()
    iv = secrets.token_bytes(12)
    aad = f'v6|{job_id}|{item_no}'.encode()
    sealed = AESGCM(key).encrypt(iv, product_key.encode(), aad)
    return base64.urlsafe_b64encode(iv + sealed[-16:] + sealed[:-16]).decode().rstrip('=')

def _open(encoded, token, job_id, item_no):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.urlsafe_b64decode(encoded + '=' * (-len(encoded) % 4))
    key = hashlib.sha256(('TUTI-BAAS-PK-ISSUANCE-V6|' + token).encode()).digest()
    return AESGCM(key).decrypt(raw[:12], raw[28:] + raw[12:28], f'v6|{job_id}|{item_no}'.encode()).decode()

def _public_job(row):
    count = max(1, int(row.get('requested_count') or 1))
    status = str(row.get('status') or 'unknown')
    terminal = status in {'completed', 'failed', 'cancelled'}
    return {'job_id': str(row['job_id']), 'status': status, 'terminal': terminal, 'environment': str(row['environment']), 'product_id': int(row['product_id']), 'license_mode': str(row['license_mode']), 'requested_count': count, 'processed_count': int(row.get('processed_count') or 0), 'succeeded_count': int(row.get('succeeded_count') or 0), 'failed_count': int(row.get('failed_count') or 0), 'chunk_size': int(row.get('chunk_size') or count), 'engine_profile': str(row.get('engine_profile') or 'v7-minimal-sync-v1'), 'progress_percent': round(min(100, int(row.get('processed_count') or 0) * 100 / count), 2), 'next_item_no': int(row.get('next_item_no') or 1), 'error_code': row.get('error_code'), 'created_at_utc': str(row.get('created_at') or ''), 'started_at_utc': row.get('started_at'), 'heartbeat_at_utc': row.get('heartbeat_at'), 'completed_at_utc': row.get('completed_at'), 'poll_after_ms': 0 if terminal else 100}

def _node_writable():
    role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    from ha_handlers import _runtime_json
    state = _runtime_json('state.json') or {}
    maintenance = state.get('maintenance') is True if 'maintenance' in state else os.environ.get('PYTHON_MIGRATION_HA_MAINTENANCE') == '1'
    promoted = state.get('promoted') is True if 'promoted' in state else os.environ.get('PYTHON_MIGRATION_HA_PROMOTED') == '1'
    return role == 'primary' and (not maintenance) or (role == 'standby' and promoted)

@legacy_compatible(callback_index=1, request_index=0)
def issuance(request_context):
    rid = uuid.uuid4().hex[:16]
    if str(request_context.get('method', '')) != 'POST':
        return _reply(405, {'ok': False, 'error': 'method_not_allowed'}, [('Allow', 'POST')])
    connection = None
    try:
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'licenses:write', 'licenses.v7.submit', rid)
        if not _node_writable():
            return _reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'server_not_writable', 'request_id': rid}, headers)
        _assert_write_fence(connection)
        data = _json_request(request_context)
        tenant = int(client['tenant_id'])
        raw_count = data.get('count')
        count = php_int_cast(1 if raw_count is None else raw_count)
        if count < 1 or count > MAX_REQUEST:
            raise ValueError('v7_count_must_be_1_to_1000')
        product = php_int_cast(data.get('product_id') or 0)
        if product < 1:
            raise ValueError('product_id_required')
        idem = str(data.get('idempotency_key', request_context.get('header:idempotency-key', ''))).strip()
        if not re.fullmatch('[A-Za-z0-9_-]{20,100}', idem):
            raise ValueError('invalid_idempotency_key')
        label = _php_trim(data.get('label') if data.get('label') is not None else '')[:100] or None
        environment = str(client.get('tenant_environment', 'unknown'))
        if environment not in {'production', 'sandbox'}:
            raise ValueError('tenant_environment_invalid')
        canonical = {'api_version': API_VERSION, 'tenant_id': tenant, 'product_id': product, 'count': count, 'license_mode': 'single', 'label': label}
        request_hash = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE tenant_id=%s AND request_key=%s LIMIT 1', (tenant, idem))
            old = cursor.fetchone()
        if old:
            if int(old['client_id']) != int(client['id']):
                return _reply(409, {'ok': False, 'api_version': API_VERSION, 'error': 'idempotency_key_reserved_by_other_issuer', 'request_id': rid}, headers)
            if not hmac.compare_digest(str(old['request_hash']), request_hash):
                return _reply(409, {'ok': False, 'api_version': API_VERSION, 'error': 'idempotency_key_reused_with_different_request', 'request_id': rid}, headers)
            if str(old['status']) != 'completed':
                return _reply(409, {'ok': False, 'api_version': API_VERSION, 'error': 'v7_previous_request_not_completed', 'request_id': rid}, headers)
            pepper, token = (key_pepper(_runtime_config()), token_secret(_runtime_config()))
            with connection.cursor() as cursor:
                cursor.execute('SELECT item_no,license_id,key_fingerprint,product_key_enc FROM product_key_issue_v6_items WHERE job_row_id=%s ORDER BY item_no ASC LIMIT %s', (int(old['id']), count))
                rows = cursor.fetchall()
            items = [{'item': int(row['item_no']), 'license_id': int(row['license_id']), 'product_key': _open(str(row['product_key_enc']), token, str(old['job_id']), int(row['item_no'])), 'key_fingerprint': str(row['key_fingerprint'])} for row in rows]
            _usage(connection, client, 'licenses.issue.v7.replay', 200, rid, ip_hash)
            return _reply(200, {'ok': True, 'api_version': API_VERSION, 'idempotent_replay': True, 'request_id': rid, 'job': _public_job(old), 'items': items}, headers)
        from api_usage_limits import check_monthly_limit, submit_charge_units
        check_monthly_limit(connection, tenant, environment, submit_charge_units(7, count, environment), rid)
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM products WHERE id=%s AND tenant_id=%s AND status='active' LIMIT 1", (product, tenant))
            if not cursor.fetchone():
                raise ValueError('product_not_found')
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute("SELECT max_licenses FROM tenants WHERE id=%s AND status='active' FOR UPDATE", (tenant,))
            tenant_row = cursor.fetchone()
            if not tenant_row:
                raise ValueError('tenant_not_found_or_inactive')
            cursor.execute('SELECT COUNT(*) AS n FROM licenses WHERE tenant_id=%s AND deleted_at IS NULL', (tenant,))
            current = int((cursor.fetchone() or {}).get('n', 0))
            reserved = 0
            for table in ('product_key_issue_jobs_v4', 'product_key_issue_jobs_v5', 'product_key_issue_jobs_v6'):
                cursor.execute('SELECT 1 FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s', (table,))
                if cursor.fetchone():
                    cursor.execute(f"SELECT COALESCE(SUM(GREATEST(requested_count-processed_count,0)),0) AS n FROM {table} WHERE tenant_id=%s AND status IN ('queued','processing','cancel_requested')", (tenant,))
                    reserved += int((cursor.fetchone() or {}).get('n', 0))
            if current + reserved + count > int(tenant_row['max_licenses']):
                raise ValueError('license_quota_exceeded')
            job_id = secrets.token_hex(16)
            cursor.execute("INSERT INTO issuance_jobs(engine_version,job_id,request_id,tenant_id,client_id,product_id,environment,license_mode,requested_count,processed_count,succeeded_count,failed_count,chunk_size,engine_profile,next_item_no,request_key,request_hash,label,max_devices,evaluation_days,expires_at,status) VALUES(6,%s,%s,%s,%s,%s,%s,'single',%s,0,0,0,%s,'v7-minimal-sync-v1',1,%s,%s,%s,1,NULL,NULL,'queued')", (job_id, rid, tenant, int(client['id']), product, environment, count, count, idem, request_hash, label))
            job_row_id = int(getattr(cursor, 'lastrowid', 0) or 0)
        connection.commit()
        config = _runtime_config()
        pepper, token = (key_pepper(config), token_secret(config))
        issued = []
        connection.begin()
        with connection.cursor() as cursor:
            # V7 keeps its existing V6-compatible storage format, but writes
            # license and result rows in bounded batches instead of per-key SQL.
            from baas_issuance_handlers import _write_issuance_batch
            issued = _write_issuance_batch(
                cursor, tenant, product, job_row_id, job_id, 1, count, label,
                1, None, None, config, pepper.encode('utf-8'), token,
                include_items=True)
            cursor.execute("UPDATE product_key_issue_jobs_v6 SET processed_count=%s,succeeded_count=%s,failed_count=0,next_item_no=%s,status='completed',started_at=COALESCE(started_at,UTC_TIMESTAMP()),heartbeat_at=UTC_TIMESTAMP(),completed_at=UTC_TIMESTAMP() WHERE id=%s", (count, count, count + 1, job_row_id))
            cursor.execute('SELECT * FROM product_key_issue_jobs_v6 WHERE id=%s', (job_row_id,))
            job = cursor.fetchone()
        _queue_webhook(connection, tenant, 'license.bulk_job_completed', {'job_id': job_id, 'count': count, 'product_id': product, 'api_version': 'v7', 'engine_profile': 'v7-minimal-sync-v1'})
        connection.commit()
        units = issue_submit_units(count, 10)
        if environment == 'sandbox':
            units = (units + 5) // 10
        _usage(connection, client, issue_submit_operation(7, count), 201, rid, ip_hash)
        return _reply(201, {'pricing': {'mode': RULES['mode'], 'currency': 'Cr', 'basis': 'requested_key_count', 'requested_count': count, 'charge_units': units, 'charge_credit': credit(units)}, 'ok': True, 'api_version': API_VERSION, 'beta': True, 'execution': 'sync', 'request_id': rid, 'count': count, 'job': _public_job(job), 'items': issued}, headers)
    except BaaSError as exc:
        if connection:
            connection.rollback()
        return _reply(exc.status, {'ok': False, 'api_version': API_VERSION, 'error': exc.error, **exc.extra, 'request_id': rid})
    except TypeError as exc:
        return _reply(415, {'ok': False, 'api_version': API_VERSION, 'error': str(exc), 'request_id': rid})
    except ValueError as exc:
        if connection:
            connection.rollback()
        error = str(exc)
        status = 409 if error in {'license_quota_exceeded', 'tenant_not_found_or_inactive'} else 400
        return _reply(status, {'ok': False, 'api_version': API_VERSION, 'error': error, 'request_id': rid})
    except database.DatabaseConfigurationError:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'service_unavailable', 'request_id': rid})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'api_version': API_VERSION, 'error': 'v7_sync_issuance_failed', 'request_id': rid})
    finally:
        if connection:
            connection.close()

def _runtime_config():
    from v2_handlers import _runtime_config as config_loader
    return config_loader()
