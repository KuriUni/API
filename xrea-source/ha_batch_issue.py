"""HA batch license issuance endpoints v2 and v3."""
from native_http import make_response, add_headers, legacy_compatible
import hashlib
import io
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timezone
import database
from core import PHP_TRIM_CHARS, license_key_hash, offline_lookup, offline_secret, offline_secret_encrypt, product_id, _aes_gcm_encrypt, _aes_gcm_decrypt, b64url_encode, b64url_decode, php_int_cast
from http_utils import json_response
from v2_handlers import _runtime_config
from v3_handlers import _assert_write_fence
_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
_IDEMPOTENCY = re.compile('^[A-Za-z0-9_-]{20,100}$')
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

def _php_datetime(value):
    from generate_key_handlers import _parse_php_datetime
    return _parse_php_datetime(value.replace('Z', '+00:00'))

def _is_integrity_conflict(error):
    if str(getattr(error, 'sqlstate', '')) == '23000':
        return True
    args = getattr(error, 'args', ())
    return bool(args and args[0] in (1062, '23000'))

@legacy_compatible(callback_index=None, request_index=0)
def _batch_input(request_context, version):
    v3 = version == 'v3'
    content_type = str(request_context.get('content_type', '')).lower()
    if v3:
        if php_int_cast(request_context.get('content_length')) > 65536:
            raise BatchIssueError(413, 'request_too_large')
        if 'application/json' not in content_type:
            raise BatchIssueError(415, 'application_json_required')
    stream = request_context.get('body_stream')
    raw = stream.read() if stream is not None else b''
    if v3 and len(raw) > 65536:
        raise BatchIssueError(413, 'request_too_large')
    if not v3 and 'application/json' not in content_type:
        from ha_mode import _php_post
        return _php_post({**request_context, 'body_stream': io.BytesIO(raw)})
    try:
        data = json.loads(raw.decode('utf-8'), parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_json')))
    except UnicodeDecodeError as exc:
        raise BatchIssueError(400, 'Malformed UTF-8 characters, possibly incorrectly encoded') from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise BatchIssueError(400, 'Syntax error') from exc
    pending = [(data, 0)]
    while pending:
        item, parent_depth = pending.pop()
        if isinstance(item, (dict, list)):
            depth = parent_depth + 1
            if depth > 32:
                raise BatchIssueError(400, 'Maximum stack depth exceeded')
            pending.extend(((child, depth) for child in (item.values() if isinstance(item, dict) else item)))
    if isinstance(data, list):
        return {}
    if not isinstance(data, dict):
        raise BatchIssueError(400, 'invalid_request')
    return data

class BatchIssueError(Exception):

    def __init__(self, status, error):
        super().__init__(error)
        self.status = status
        self.error = error

def _key():
    return '-'.join((''.join((secrets.choice(_ALPHABET) for _ in range(5))) for _ in range(5)))

def _seal(config, version, value):
    prefix = ('TUTI-PK-ISSUANCE-' + version.upper() + '|').encode()
    aad = ('TUTI-PK-ISSUANCE-' + version.upper()).encode()
    return _aes_gcm_encrypt(config['token_secret'], prefix, aad, value.encode('utf-8'))

def _open(config, version, encoded):
    prefix = ('TUTI-PK-ISSUANCE-' + version.upper() + '|').encode()
    aad = ('TUTI-PK-ISSUANCE-' + version.upper()).encode()
    return _aes_gcm_decrypt(config['token_secret'], prefix, aad, encoded).decode('utf-8')

def _ensure_schema(connection):
    with connection.cursor() as cursor:
        cursor.execute("CREATE TABLE IF NOT EXISTS product_key_issue_batches (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,batch_id CHAR(32) NOT NULL,request_id CHAR(16) NOT NULL,tenant_id BIGINT UNSIGNED NOT NULL,client_id BIGINT UNSIGNED NULL,product_id BIGINT UNSIGNED NOT NULL,environment VARCHAR(16) NOT NULL,api_version VARCHAR(32) NOT NULL DEFAULT 'product-key-issuance-v2',source VARCHAR(16) NOT NULL DEFAULT 'ha-v2',license_mode VARCHAR(20) NOT NULL,requested_count INT UNSIGNED NOT NULL,request_key VARCHAR(100) NOT NULL,request_hash CHAR(64) NOT NULL,response_enc LONGTEXT NULL,status VARCHAR(20) NOT NULL DEFAULT 'pending',issued_by_role VARCHAR(20) NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,completed_at DATETIME NULL,PRIMARY KEY(id),UNIQUE KEY uq_pk_issue_batch_id(batch_id),UNIQUE KEY uq_pk_issue_tenant_request(tenant_id,request_key),KEY idx_pk_issue_tenant_created(tenant_id,created_at),KEY idx_pk_issue_status(status,created_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
        for column, definition in (('client_id', 'BIGINT UNSIGNED NULL'), ('api_version', "VARCHAR(32) NOT NULL DEFAULT 'product-key-issuance-v2'"), ('source', "VARCHAR(16) NOT NULL DEFAULT 'ha-v2'")):
            cursor.execute("SELECT COUNT(*) AS n FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='product_key_issue_batches' AND column_name=%s", (column,))
            if not int((cursor.fetchone() or {}).get('n') or 0):
                cursor.execute('ALTER TABLE product_key_issue_batches ADD COLUMN ' + column + ' ' + definition)
        cursor.execute('CREATE TABLE IF NOT EXISTS product_key_issue_items (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,batch_row_id BIGINT UNSIGNED NOT NULL,item_no INT UNSIGNED NOT NULL,license_id BIGINT UNSIGNED NOT NULL,key_fingerprint CHAR(64) NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(id),UNIQUE KEY uq_pk_issue_batch_item(batch_row_id,item_no),UNIQUE KEY uq_pk_issue_license(license_id),KEY idx_pk_issue_item_fingerprint(key_fingerprint)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4')
    connection.commit()

def _existing(connection, tenant_id, idem, for_update=False):
    with connection.cursor() as cursor:
        cursor.execute('SELECT request_hash,response_enc,status,api_version,source FROM product_key_issue_batches WHERE tenant_id=%s AND request_key=%s LIMIT 1' + (' FOR UPDATE' if for_update else ''), (tenant_id, idem))
        return cursor.fetchone()

def _replay(connection, config, version, source, request_hash, row, request_id=None):
    if version == 'v3' and (row.get('api_version') != 'product-key-issuance-v3' or row.get('source') != 'ha-v3'):
        raise BatchIssueError(409, 'idempotency_key_reserved_by_other_issuer')
    if not secrets.compare_digest(str(row.get('request_hash') or ''), request_hash):
        raise BatchIssueError(409, 'idempotency_key_reused_with_different_request')
    if row.get('status') != 'completed' or not str(row.get('response_enc') or '').strip():
        raise BatchIssueError(425, 'idempotency_request_in_progress')
    try:
        payload = json.loads(_open(config, version, str(row['response_enc'])))
    except Exception as exc:
        raise BatchIssueError(503, 'issuance_response_invalid') from exc
    payload['idempotent_replay'] = True
    return payload

@legacy_compatible(callback_index=1, request_index=0)
def batch_issue(request_context, version):
    from ha_handlers import _append_ha_audit, _effective_role, _ha_authorized_scope
    v3 = version == 'v3'
    auth_environ = request_context
    if str(request_context.get('method', '')) == 'POST' and 'application/json' not in str(request_context.get('content_type', '')).lower():
        stream = request_context.get('body_stream')
        raw = stream.read() if stream is not None else b''
        from ha_mode import _php_post
        form = _php_post({**request_context, 'body_stream': io.BytesIO(raw)})
        auth_environ = dict(request_context)
        if 'header:x-ha-token' not in request_context and form.get('token') is not None:
            auth_environ['header:x-ha-token'] = _php_string(form.get('token'))
        auth_environ['body_stream'] = io.BytesIO(raw)
    api_version = 'product-key-issuance-v3' if v3 else 'product-key-issuance-v2'
    source = 'ha-v3' if v3 else 'ha-v2'
    maximum = 1000 if v3 else 100
    headers = []
    if v3:
        headers = [('X-Product-Key-Issuance-Version', 'v3'), ('X-Product-Key-Max-Batch', '1000')]
    if not _ha_authorized_scope(auth_environ, 'license:write'):
        return json_response('404 Not Found', {'ok': False, 'error': 'not_found'}, headers)
    if str(request_context.get('method', '')) != 'POST':
        return json_response('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'}, headers + [('Allow', 'POST')])
    role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    effective = _effective_role()
    writable = role == 'primary' and effective != 'maintenance' or (role == 'standby' and effective == 'promoted')
    if not writable:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'server_not_writable', 'role': role}, headers)
    connection = None
    lock_name = None
    try:
        data = _batch_input(auth_environ, version)
        idem_value = data.get('idempotency_key')
        if idem_value is None:
            idem_value = request_context.get('header:idempotency-key', '')
        idem = _php_trim(idem_value)
        if not _IDEMPOTENCY.fullmatch(idem):
            raise BatchIssueError(400, 'invalid_idempotency_key')
        mode_value = data.get('license_mode')
        mode = _php_trim_lower('single' if mode_value is None else mode_value)
        if mode not in {'single', 'volume', 'evaluation'}:
            raise BatchIssueError(400, 'invalid_license_mode')
        count_value = data.get('count')
        tenant_value = data.get('tenant_id')
        product_value = data.get('product_id')
        device_value = data.get('max_devices')
        evaluation_value = data.get('evaluation_days')
        count = php_int_cast(1 if count_value is None else count_value)
        tenant_id = php_int_cast(0 if tenant_value is None else tenant_value)
        requested_product_id = max(0, php_int_cast(0 if product_value is None else product_value))
        max_devices = max(2, min(10000, php_int_cast(10 if device_value is None else device_value))) if mode == 'volume' else 1
        evaluation_days = max(1, min(3650, php_int_cast(30 if evaluation_value is None else evaluation_value))) if mode == 'evaluation' else None
        if count < 1 or count > maximum:
            raise BatchIssueError(400, 'invalid_issue_count')
        if tenant_id < 1:
            raise BatchIssueError(400, 'tenant_required')
        environment_value = data.get('environment')
        environment = _php_trim_lower('' if environment_value is None else environment_value)
        if environment not in {'production', 'sandbox'}:
            raise BatchIssueError(400, 'invalid_environment')
        label_value = data.get('label')
        label = _php_trim('' if label_value is None else label_value)[:100] or None
        expires_at = None
        expires_value = data.get('expires_at')
        expires_raw = _php_trim('' if expires_value is None else expires_value)
        if mode != 'evaluation' and expires_raw:
            try:
                expiry = _php_datetime(expires_raw)
            except ValueError as exc:
                raise RuntimeError('invalid_expiry_datetime') from exc
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if int(expiry.timestamp()) <= int(datetime.now(timezone.utc).timestamp()):
                raise BatchIssueError(400, 'expires_at_must_be_future')
            expires_at = expiry.astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        config = _runtime_config()
        connection = database.connect()
        _assert_write_fence(connection)
        _ensure_schema(connection)
        with connection.cursor() as cursor:
            cursor.execute("SELECT id,slug,status,environment,parent_tenant_id,max_licenses FROM tenants WHERE id=%s AND status='active' LIMIT 1", (tenant_id,))
            tenant = cursor.fetchone()
        if not tenant:
            raise BatchIssueError(400, 'tenant_not_found_or_inactive')
        stored_environment = _php_trim_lower(tenant.get('environment') or '')
        tenant_environment = 'sandbox' if tenant.get('parent_tenant_id') or stored_environment == 'sandbox' else 'production' if stored_environment == 'production' else 'unknown'
        if tenant_environment == 'unknown':
            raise BatchIssueError(400, 'tenant_environment_invalid')
        if environment != tenant_environment:
            raise BatchIssueError(400, 'environment_mismatch')
        canonical = {**({'api_version': api_version, 'source': source} if v3 else {}), 'environment': environment, 'tenant_id': tenant_id, 'requested_product_id': requested_product_id, 'license_mode': mode, 'count': count, 'label': label, 'max_devices': max_devices, 'evaluation_days': evaluation_days, 'expires_at': expires_at}
        request_hash = hashlib.sha256(json.dumps(canonical, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
        existing = _existing(connection, tenant_id, idem)
        if existing:
            payload = _replay(connection, config, version, source, request_hash, existing)
            return json_response('200 OK', payload, headers)
        with connection.cursor() as cursor:
            if requested_product_id:
                cursor.execute("SELECT id,code,name FROM products WHERE id=%s AND tenant_id=%s AND status='active' LIMIT 1", (requested_product_id, tenant_id))
            else:
                cursor.execute("SELECT id,code,name FROM products WHERE tenant_id=%s AND status='active' ORDER BY (code='default') DESC,id ASC LIMIT 1", (tenant_id,))
            product = cursor.fetchone()
        if not product:
            raise BatchIssueError(400, 'product_not_found_or_inactive')
        product_numeric_id = int(product['id'])
        if v3:
            lock_name = 'tuti:pkv3:tenant:' + str(tenant_id)
            with connection.cursor() as cursor:
                cursor.execute('SELECT GET_LOCK(%s,0) AS acquired', (lock_name,))
                acquired = int((cursor.fetchone() or {}).get('acquired') or 0)
            if acquired != 1:
                raise BatchIssueError(429, 'issuance_busy')
        rid, batch_id = (secrets.token_hex(8), secrets.token_hex(16))
        issued_role = 'promoted' if role == 'standby' else 'primary'
        connection.begin()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT max_licenses FROM tenants WHERE id=%s AND status='active' FOR UPDATE", (tenant_id,))
                quota_row = cursor.fetchone()
            if not quota_row:
                raise BatchIssueError(400, 'tenant_not_found_or_inactive')
            replay = _existing(connection, tenant_id, idem, for_update=True)
            if replay:
                connection.commit()
                payload = _replay(connection, config, version, source, request_hash, replay)
                return json_response('200 OK', payload, headers)
            with connection.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) AS n FROM licenses WHERE tenant_id=%s AND deleted_at IS NULL', (tenant_id,))
                current = int((cursor.fetchone() or {}).get('n') or 0)
            if current + count > int(quota_row.get('max_licenses') or 0):
                raise BatchIssueError(409, 'license_quota_exceeded')
            with connection.cursor() as cursor:
                cursor.execute("INSERT INTO product_key_issue_batches(batch_id,request_id,tenant_id,client_id,product_id,environment,api_version,source,license_mode,requested_count,request_key,request_hash,status,issued_by_role) VALUES(%s,%s,%s,NULL,%s,%s,%s,%s,%s,%s,%s,%s,'pending',%s)", (batch_id, rid, tenant_id, product_numeric_id, environment, api_version, source, mode, count, idem, request_hash, issued_role))
                batch_row_id = int(cursor.lastrowid)
            items = []
            for item_no in range(1, count + 1):
                inserted = False
                for _attempt in range(12):
                    candidate = _key()
                    secret = offline_secret(candidate)
                    try:
                        item_label = label or f'PKM {version} batch {batch_id[:8]} #{item_no}'
                        with connection.cursor() as cursor:
                            cursor.execute('INSERT INTO licenses(tenant_id,product_id,key_hash,label,active,max_devices,evaluation_days,expires_at,offline_lookup,offline_secret_enc) VALUES(%s,%s,%s,%s,1,%s,%s,%s,%s,%s)', (tenant_id, product_numeric_id, license_key_hash(config, candidate), item_label, max_devices, evaluation_days, expires_at, offline_lookup(secret), offline_secret_encrypt(config, secret)))
                            license_id = int(cursor.lastrowid)
                        inserted = True
                        break
                    except Exception as exc:
                        if not _is_integrity_conflict(exc):
                            raise
                if not inserted:
                    raise RuntimeError('product_key_generation_failed')
                fingerprint = hashlib.sha256(candidate.encode('ascii')).hexdigest()
                with connection.cursor() as cursor:
                    cursor.execute('INSERT INTO product_key_issue_items(batch_row_id,item_no,license_id,key_fingerprint) VALUES(%s,%s,%s,%s)', (batch_row_id, item_no, license_id, fingerprint))
                items.append({'item': item_no, 'license_id': license_id, 'product_key': candidate, 'product_id': product_id(config, license_id), 'tenant_product_id': product_numeric_id, 'key_fingerprint': fingerprint})
            result = {'ok': True, 'api_version': api_version, 'request_id': rid, 'batch_id': batch_id, **({'max_batch': maximum} if v3 else {}), 'idempotent_replay': False, 'issued_at_utc': datetime.now(timezone.utc).isoformat(timespec='seconds'), 'issued_by_role': issued_role, 'environment': environment, 'tenant_id': tenant_id, 'tenant_slug': str(tenant.get('slug') or ''), 'tenant_product_id': product_numeric_id, 'product_code': str(product.get('code') or ''), 'product_name': str(product.get('name') or ''), 'license_mode': mode, 'count': len(items), 'max_devices': max_devices, 'evaluation_days': evaluation_days, 'expires_at': expires_at, 'items': items}
            encoded = json.dumps(result, ensure_ascii=False, separators=(',', ':'))
            sealed = _seal(config, version, encoded)
            with connection.cursor() as cursor:
                cursor.execute("UPDATE product_key_issue_batches SET response_enc=%s,status='completed',completed_at=UTC_TIMESTAMP() WHERE id=%s", (sealed, batch_row_id))
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        event = 'product_key_batch_v3_issued' if v3 else 'product_key_batch_issued'
        _append_ha_audit(event, {'request_id': rid, 'batch_id': batch_id, 'idempotency_key_hash': hashlib.sha256(idem.encode()).hexdigest(), 'request_hash': request_hash, 'tenant_id': tenant_id, 'environment': environment, 'tenant_product_id': product_numeric_id, 'license_mode': mode, 'count': len(items), 'issued_by_role': issued_role}, request_context)
        return json_response('200 OK', result, headers)
    except BatchIssueError as exc:
        if connection:
            connection.rollback()
        body = {'ok': False, 'error': exc.error}
        if exc.error == 'issuance_busy':
            body['retry_after_seconds'] = 2
            headers.append(('Retry-After', '2'))
        status_text = {400: 'Bad Request', 409: 'Conflict', 413: 'Payload Too Large', 415: 'Unsupported Media Type', 425: 'Too Early', 429: 'Too Many Requests', 503: 'Service Unavailable'}.get(exc.status, 'Error')
        return json_response(f'{exc.status} {status_text}', body, headers)
    except database.DatabaseConfigurationError:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'service_unavailable'}, headers)
    except Exception:
        if connection:
            connection.rollback()
        rid = uuid.uuid4().hex[:16]
        event = 'product_key_batch_v3_issue_failed' if v3 else 'product_key_batch_issue_failed'
        _append_ha_audit(event, {'request_id': rid}, request_context)
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'product_key_issue_failed', 'request_id': rid}, headers)
    finally:
        if connection:
            if lock_name:
                try:
                    with connection.cursor() as cursor:
                        cursor.execute('SELECT RELEASE_LOCK(%s)', (lock_name,))
                except Exception:
                    pass
            connection.close()

@legacy_compatible(callback_index=1, request_index=0)
def issue_license_v2(request_context):
    return batch_issue(request_context, 'v2')

@legacy_compatible(callback_index=1, request_index=0)
def issue_license_v3(request_context):
    return batch_issue(request_context, 'v3')
