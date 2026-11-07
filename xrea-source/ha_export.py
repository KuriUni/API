"""HA snapshot export endpoint for the isolated Python migration site."""
from native_http import make_response, add_headers, legacy_compatible
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import database
REQUIRED_TABLES = ['tenants', 'products', 'tenant_api_clients', 'tenant_api_usage', 'tenant_api_usage_daily', 'tenant_api_attempts', 'licenses', 'license_devices', 'auth_attempts', 'phone_activation_requests', 'offline_activation_requests', 'idempotency_keys', 'admin_principals', 'admin_audit_events', 'data_change_journal', 'ha_fence_state', 'tenant_webhooks', 'baas_batch_jobs', 'tenant_webhook_deliveries']
OPTIONAL_TABLES = ['archived_identity_records', 'issuance_jobs', 'issuance_plans', 'issuance_items', 'product_key_v8_jobs', 'product_key_v8_items', 'tenant_key_issue_sessions', 'tenant_key_issue_session_items', 'product_key_issue_batches', 'product_key_issue_items', 'license_v3_challenges', 'license_v3_devices', 'license_v3_sessions', 'license_v3_refresh_history', 'license_v3_proofs', 'license_v3_offline_tickets', 'api_billing_invoices', 'subscriber_sdk_setup_codes', 'tenant_portal_key_reissues', 'admin_service_intakes', 'jpki_verifications', 'tenant_sso_bootstrap_tickets', 'tenant_sso_memberships', 'tenant_sso_sessions']

@legacy_compatible(callback_index=0, request_index=None)
def _response(status, payload):
    body = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(',', ':')).encode('utf-8')
    _http_status, _http_headers = (status, [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=None, request_index=0)
def _ha_authorized(request_context, connection):
    from migration_config import secret_value
    expected = str(os.environ.get('PYTHON_MIGRATION_HA_SYNC_TOKEN', '') or secret_value('ha_sync_token'))
    provided = str(request_context.get('header:x-ha-token', ''))
    if len(expected) >= 32 and hmac.compare_digest(expected, provided):
        return True
    from baas_handlers import _admin_role, _decode_admin_session, _role_allows_scope
    claims = _decode_admin_session(str(request_context.get('header:x-ha-session', '')).strip())
    return bool(claims and _role_allows_scope(_admin_role(connection, claims), 'ha:operate'))

def _json_safe(value):
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat(sep=' ') if isinstance(value, datetime.datetime) else value.isoformat()
    if isinstance(value, bytes):
        return base64.b64encode(value).decode('ascii')
    if isinstance(value, (bytearray, memoryview)):
        return base64.b64encode(bytes(value)).decode('ascii')
    try:
        from decimal import Decimal
        if isinstance(value, Decimal):
            return str(value)
    except ImportError:
        pass
    return value

def _passkey_snapshot():
    private_dir = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if private_dir:
        store_path = os.path.join(os.path.expanduser(private_dir), 'passkey-store.json')
        try:
            with open(store_path, 'r', encoding='utf-8') as stream:
                store = json.load(stream)
            if isinstance(store, dict) and isinstance(store.get('credentials'), (dict, list)):
                recovery = store.get('recovery_codes', [])
                if not isinstance(recovery, (dict, list)):
                    recovery = []
                return (store['credentials'], recovery)
        except (OSError, ValueError):
            pass
    return ([], [])

def _ensure_idempotency_table(cursor):
    """Match export.php's bootstrap table creation while allowing read-only DBs
    to proceed when the table already exists.
    """
    cursor.execute('SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s', ('idempotency_keys',))
    if int((cursor.fetchone() or {}).get('n') or 0) == 0:
        cursor.execute('CREATE TABLE IF NOT EXISTS idempotency_keys (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,operation VARCHAR(40) NOT NULL,request_key VARCHAR(100) NOT NULL,response_json TEXT NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(id),UNIQUE KEY uq_idempotency_operation_key(operation,request_key)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci')

@legacy_compatible(callback_index=1, request_index=0)
def export_snapshot(request_context):
    connection = None
    try:
        role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
        from migration_config import secret_value
        expected = str(os.environ.get('PYTHON_MIGRATION_HA_SYNC_TOKEN', '') or secret_value('ha_sync_token'))
        supplied = str(request_context.get('header:x-ha-token', ''))
        sync_authorized = bool(len(expected) >= 32 and supplied and hmac.compare_digest(expected, supplied))
        if not sync_authorized:
            from baas_handlers import _admin_role, _decode_admin_session, _role_allows_scope
            claims = _decode_admin_session(str(request_context.get('header:x-ha-session', '')).strip())
            if claims is None:
                return _response('404 Not Found', {'ok': False, 'error': 'not_found'})
            credential_hash = str(claims.get('credential_id_hash') or '').lower()
            if re.fullmatch('[a-f0-9]{64}', credential_hash):
                try:
                    connection = database.connect()
                    authorized = _ha_authorized(request_context, connection)
                except Exception:
                    return _response('404 Not Found', {'ok': False, 'error': 'not_found'})
                if not authorized:
                    return _response('404 Not Found', {'ok': False, 'error': 'not_found'})
            elif not _role_allows_scope(_admin_role(None, claims), 'ha:operate'):
                return _response('404 Not Found', {'ok': False, 'error': 'not_found'})
        from ha_handlers import _runtime_json
        promoted = os.environ.get('PYTHON_MIGRATION_HA_PROMOTED') == '1' or (_runtime_json('state.json') or {}).get('promoted') is True
        from http_utils import php_parse_query
        standby_backup = (role == 'standby' and sync_authorized and
                          php_parse_query(request_context.get('query', '')).get('standby_backup', [''])[-1] == '1')
        if request_context.get('method', '') != 'GET' or not (role == 'primary' or (role == 'standby' and promoted) or standby_backup):
            _http_status, _http_headers = ('405 Method Not Allowed', [])
            return make_response([b''], _http_status, _http_headers)
        if connection is None:
            connection = database.connect()
        schemas, rows_by_table, hashes = ({}, {}, {})
        with connection.cursor() as cursor:
            _ensure_idempotency_table(cursor)
            connection.commit()
            cursor.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            connection.begin()
            tables = set()
            cursor.execute('SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()')
            tables = {str(row['table_name']) for row in cursor.fetchall()}
            missing = [table for table in REQUIRED_TABLES if table not in tables]
            if missing:
                raise RuntimeError('required_snapshot_table_missing')
            selected = REQUIRED_TABLES + [table for table in OPTIONAL_TABLES if table in tables]
            for table in selected:
                cursor.execute('SHOW COLUMNS FROM `' + table + '`')
                schema = [{key: _json_safe(value) for key, value in row.items()} for row in cursor.fetchall()]
                schemas[table] = schema
                fields = [str(col['Field']) for col in schema]
                if not fields:
                    raise RuntimeError('snapshot_schema_empty')
                quoted = ','.join(('`' + field.replace('`', '``') + '`' for field in fields))
                where = ''
                if table in {'licenses', 'issuance_jobs'}:
                    where = " WHERE label IS NULL OR label NOT LIKE '[bench:%'"
                elif table == 'product_key_issue_v4_items':
                    where = " WHERE job_row_id IN (SELECT id FROM product_key_issue_jobs_v4 WHERE label IS NULL OR label NOT LIKE '[bench:%')"
                elif table == 'product_key_issue_v5_items':
                    where = " WHERE job_row_id IN (SELECT id FROM product_key_issue_jobs_v5 WHERE label IS NULL OR label NOT LIKE '[bench:%')"
                elif table == 'product_key_issue_v6_items':
                    where = " WHERE job_row_id IN (SELECT id FROM product_key_issue_jobs_v6 WHERE label IS NULL OR label NOT LIKE '[bench:%')"
                elif table == 'product_key_issue_plans_v5':
                    where = " WHERE job_id IN (SELECT job_id FROM product_key_issue_jobs_v5 WHERE label IS NULL OR label NOT LIKE '[bench:%') OR job_id IN (SELECT job_id FROM product_key_issue_jobs_v4 WHERE label IS NULL OR label NOT LIKE '[bench:%')"
                elif table == 'product_key_issue_plans_v6':
                    where = " WHERE job_id IN (SELECT job_id FROM product_key_issue_jobs_v6 WHERE label IS NULL OR label NOT LIKE '[bench:%')"
                elif table == 'issuance_items':
                    where = " WHERE job_row_id IN (SELECT id FROM issuance_jobs WHERE label IS NULL OR label NOT LIKE '[bench:%')"
                elif table == 'issuance_plans':
                    where = " WHERE EXISTS (SELECT 1 FROM issuance_jobs j WHERE j.tenant_id=issuance_plans.tenant_id AND j.job_id=issuance_plans.job_id AND (j.engine_version=issuance_plans.engine_version OR (issuance_plans.engine_version=5 AND j.engine_version=4)) AND (j.label IS NULL OR j.label NOT LIKE '[bench:%'))"
                cursor.execute('SELECT ' + quoted + ' FROM `' + table + '`' + where + ' ORDER BY ' + quoted)
                rows = [{key: _json_safe(value) for key, value in row.items()} for row in cursor.fetchall()]
                rows_by_table[table] = rows
                canonical = json.dumps(rows, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
                hashes[table] = hashlib.sha256(canonical.encode()).hexdigest()
        connection.commit()
        from audit import append_event
        snapshot_id = secrets.token_hex(16)
        append_event('snapshot_exported', {'snapshot_id': snapshot_id, 'table_hashes': hashes}, ip_address=str(request_context.get('client_address', '')), role=role)
        passkey_credentials, passkey_recovery_codes = ([], [])
        from migration_config import secret_value
        payload = {'ok': True, 'schema': 2, 'storage_model': 'domain-039', 'binary_encoding': 'base64-v1', 'snapshot_id': snapshot_id, 'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'), 'schema_hash': hashlib.sha256(json.dumps(schemas, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest(), 'table_hashes': hashes, 'schemas': schemas, 'secrets': {'key_pepper': secret_value('key_pepper'), 'token_secret': secret_value('token_secret'), 'admin_password_hash': secret_value('admin_password_hash'), 'license_v3_signing_secret': secret_value('license_v3_signing_secret'), 'jpki_private_key': secret_value('jpki_private_key')}, 'passkey_credentials': passkey_credentials, 'passkey_recovery_codes': passkey_recovery_codes, 'tables': rows_by_table}
        return _response('200 OK', payload)
    except database.DatabaseConfigurationError:
        return _response('503 Service Unavailable', {'ok': False, 'error': 'snapshot_failed'})
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        return _response('503 Service Unavailable', {'ok': False, 'error': 'snapshot_failed'})
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
