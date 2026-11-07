"""Python implementation of the public HA health endpoint."""
from native_http import make_response, add_headers, legacy_compatible
from py36_compat import parse_iso_datetime
import os
import hashlib
import hmac
import json
import datetime
from decimal import Decimal
from file_locking import fcntl
import base64
import re
import io
import sys
import urllib.error
import urllib.request
from email.parser import BytesParser
from email.policy import default as email_policy
from urllib.parse import urlsplit
import secrets
import time
from pathlib import Path
from http_utils import php_parse_query as parse_qs
from database import connect
from path_utils import is_relative_to
ALLOWED_ORIGINS = {'https://2415.jp', 'https://backup.2415.jp', 'https://main.2415.jp'}
HA_HTTP_HEADERS = {'Accept': 'application/json', 'User-Agent': 'TutiLicenseHA/1.0 (+https://2415.jp)', 'Cache-Control': 'no-cache', 'Connection': 'close'}

@legacy_compatible(callback_index=0, request_index=None)
def _response(status, body=b'', headers=()):
    base = [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff')]
    base.extend(headers)
    if body:
        base.append(('Content-Length', str(len(body))))
    _http_status, _http_headers = (status, base)
    return make_response([body], _http_status, _http_headers)

def _private_storage_checks():
    private_dir = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not private_dir:
        return (False, False)
    private_path = Path(private_dir).expanduser().resolve()
    document_root = Path(os.environ.get('DOCUMENT_ROOT', Path(__file__).resolve().parent)).resolve()
    try:
        outside = not is_relative_to(private_path, document_root)
        configured = private_path.is_dir() and os.access(private_path, os.W_OK)
        return (configured, outside)
    except (OSError, ValueError):
        return (False, False)

def _ready():
    checks = {'database': False, 'schema': False, 'private_storage': False, 'private_storage_outside_public_html': False, 'write_fence': False}
    connection = None
    try:
        connection = connect()
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1 AS value')
            row = cursor.fetchone()
            checks['database'] = bool(row and int(row['value']) == 1)
            cursor.execute('SELECT COUNT(*) AS count FROM schema_migrations WHERE version=%s', ('014_sandbox_tenants',))
            row = cursor.fetchone()
            checks['schema'] = bool(row and int(row['count']) == 1)
            cursor.execute('SELECT writer_role FROM ha_fence_state WHERE singleton_id=1')
            fence = cursor.fetchone()
            expected = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
            state = _runtime_json('state.json') or {}
            maintenance = state.get('maintenance') is True if 'maintenance' in state else os.environ.get('PYTHON_MIGRATION_HA_MAINTENANCE') == '1'
            promoted = state.get('promoted') is True if 'promoted' in state else os.environ.get('PYTHON_MIGRATION_HA_PROMOTED') == '1'
            if expected == 'primary' and not maintenance:
                expected = 'primary'
            elif expected == 'standby' and promoted:
                expected = 'promoted'
            else:
                # Match PHP ha_expected_writer_role(): an unpromoted standby
                # is not a writer and may retain the primary's replicated fence.
                expected = None
            checks['write_fence'] = bool(fence and (expected is None or fence.get('writer_role') == expected))
        configured, outside = _private_storage_checks()
        checks['private_storage'] = configured
        checks['private_storage_outside_public_html'] = outside
    except Exception:
        pass
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
    return all(checks.values())

@legacy_compatible(callback_index=1, request_index=0)
def health(request_context):
    origin = request_context.get('header:origin', '')
    headers = []
    allowed = origin in ALLOWED_ORIGINS
    if allowed:
        headers.extend([('Access-Control-Allow-Origin', origin), ('Vary', 'Origin'), ('Access-Control-Allow-Methods', 'GET, OPTIONS'), ('Access-Control-Max-Age', '600')])
    if request_context.get('method', 'GET') == 'OPTIONS':
        if not allowed:
            return _response('403 Forbidden')
        return _response('204 No Content', headers=headers)
    probe = parse_qs(request_context.get('query', ''), keep_blank_values=True).get('probe', [''])[0]
    if probe == 'live':
        import json
        return _response('200 OK', json.dumps({'ok': True, 'probe': 'live'}, separators=(',', ':')).encode(), headers)
    import json
    ready = _ready()
    # Keep this public liveness/readiness response free of HA topology and
    # disaster-recovery state. Authenticated operators use ha_status() for detail.
    value={'ok': ready, 'probe': 'ready'}
    payload = json.dumps(value, separators=(',', ':')).encode()
    return _response('200 OK' if ready else '503 Service Unavailable', payload, headers)
AUDIT_EVENTS = {'forced_role_change', 'failback_operation_started', 'failback_stage', 'failback_operation_completed', 'snapshot_import_validated', 'snapshot_imported', 'role_change', 'ha_sync_token_rotated', 'offline_phone_confirmation_issued', 'offline_phone_confirmation_revoked', 'passkey_federation_incomplete', 'passkey_federation_sync', 'passkey_federation_apply_failed', 'passkey_federation_invalid_rows_skipped', 'mnsl_local_card_key_proof_verified', 'mnsl_android_card_read_reported', 'mnsl_android_card_read_failed', 'product_key_lookup', 'product_key_lookup_failed', 'license_issued', 'issue_license_failed', 'product_key_batch_issued', 'product_key_batch_issue_failed', 'product_key_batch_v3_issued', 'product_key_batch_v3_issue_failed', 'license_activate', 'license_deactivate', 'license_update', 'license_revoke_device', 'license_restore_device', 'license_revoke_all_devices', 'license_extend_expiry', 'license_delete_license', 'license_delete_issued_license', 'license_admin_failed', 'api_billing_invoice_issued', 'api_billing_invoice_draft_saved', 'api_billing_invoice_paid', 'api_billing_invoice_void', 'api_billing_invoice_draft_deleted', 'offline_signing_key_provisioned', 'tenant_licenses_bulk_deleted', 'subscriber_sdk_setup_issued', 'subscriber_sdk_setup_revoked', 'tenant_created', 'tenant_sandbox_created', 'tenant_updated', 'tenant_deleted', 'tenant_suspended', 'tenant_active', 'tenant_api_key_issued', 'tenant_api_key_rotated', 'tenant_api_key_revoked', 'tenant_admin_failed', 'tenant_portal_passkey_registered', 'tenant_common_id_membership_added', 'tenant_portal_api_key_reissued', 'tenant_portal_passkey_revoked'}

@legacy_compatible(callback_index=None, request_index=0)
def _ha_authorized_scope(request_context, scope):
    expected = os.environ.get('PYTHON_MIGRATION_HA_SYNC_TOKEN', '')
    if not expected:
        try:
            from migration_config import secret_value
            expected = secret_value('ha_sync_token')
        except Exception:
            expected = ''
    if 'header:x-ha-token' in request_context:
        provided = str(request_context.get('header:x-ha-token') or '')
    else:
        provided = _ha_post_token(request_context)
    if expected and hmac.compare_digest(expected, provided):
        return True
    try:
        from baas_handlers import _admin_role, _decode_admin_session, _role_allows_scope
        claims = _decode_admin_session(str(request_context.get('header:x-ha-session', '')).strip())
        if claims:
            scopes = claims.get('scope', [])
            if not isinstance(scopes, list):
                scopes = [scopes]
            if scope not in scopes:
                return False
            from database import connect
            connection = connect()
            try:
                return _role_allows_scope(_admin_role(connection, claims), scope)
            finally:
                connection.close()
    except Exception:
        return False
    return False

@legacy_compatible(callback_index=None, request_index=0)
def _ha_post_token(request_context):
    """Read PHP's $_POST['token'] fallback and replay the body for the handler."""
    if request_context.get('method', '') != 'POST':
        return ''
    content_type = str(request_context.get('content_type', '')).strip()
    media_type = content_type.split(';', 1)[0].strip().lower()
    if media_type not in {'application/x-www-form-urlencoded', 'multipart/form-data'}:
        return ''
    stream = request_context.get('body_stream')
    if stream is None:
        return ''
    maximum = 8 * 1024 * 1024
    prefix = stream.read(maximum + 1)
    request_context['body_stream'] = _ReplayInput(prefix, stream)
    if len(prefix) > maximum:
        return ''
    try:
        if media_type == 'application/x-www-form-urlencoded':
            fields = parse_qs(prefix.decode('utf-8', 'replace'), keep_blank_values=True)
            values = fields.get('token')
            return str(values[-1]) if values else ''
        headers = ('Content-Type: ' + content_type + '\r\nMIME-Version: 1.0\r\n\r\n').encode('ascii', 'replace')
        message = BytesParser(policy=email_policy).parsebytes(headers + prefix)
        if not message.is_multipart():
            return ''
        token = ''
        for part in message.iter_parts():
            if part.get_content_disposition() == 'form-data' and part.get_param('name', header='content-disposition') == 'token' and (part.get_filename() is None):
                value = part.get_payload(decode=True) or b''
                token = value.decode(part.get_content_charset() or 'utf-8', 'replace')
        return token
    except Exception:
        return ''

class _ReplayInput:
    """A readable prefix followed by the unconsumed original request stream."""

    def __init__(self, prefix, tail):
        self.prefix = prefix
        self.offset = 0
        self.tail = tail

    def read(self, size=-1):
        remaining = self.prefix[self.offset:]
        if size is None or size < 0:
            self.offset = len(self.prefix)
            return remaining + self.tail.read()
        if size <= len(remaining):
            self.offset += size
            return remaining[:size]
        self.offset = len(self.prefix)
        return remaining + self.tail.read(size - len(remaining))

@legacy_compatible(callback_index=None, request_index=0)
def _ha_audit_authorized(request_context):
    return _ha_authorized_scope(request_context, 'ha:operate')

def _ha_audit_path():
    private_dir = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not private_dir:
        return None
    return Path(private_dir).expanduser() / 'runtime' / 'audit.log'

def _ha_audit_log():
    path = _ha_audit_path()
    if path is None or not path.is_file():
        return []
    return [line for line in path.read_text(encoding='utf-8').splitlines() if line]

@legacy_compatible(callback_index=1, request_index=0)
def audit_recent(request_context):
    if not _ha_audit_authorized(request_context):
        return _response('404 Not Found', b'{"ok":false,"error":"not_found"}')
    try:
        rows = []
        for line in reversed(_ha_audit_log()[-300:]):
            row = json.loads(line)
            if not isinstance(row, dict) or row.get('event') not in AUDIT_EVENTS:
                continue
            rows.append({'at_utc': row.get('at_utc'), 'event': row.get('event'), 'configured_role': row.get('configured_role'), 'context': row.get('context', {})})
            if len(rows) >= 30:
                break
        body = json.dumps({'ok': True, 'events': rows, 'count': len(rows)}, ensure_ascii=False, separators=(',', ':')).encode()
        return _response('200 OK', body)
    except Exception:
        return _response('503 Service Unavailable', b'{"ok":false,"error":"audit_unavailable"}')

@legacy_compatible(callback_index=1, request_index=0)
def audit_verify(request_context):
    if not _ha_audit_authorized(request_context):
        return _response('404 Not Found', b'{"ok":false,"error":"not_found"}')
    try:
        lines = _ha_audit_log()
        previous = ''
        chained = 0
        for index, line in enumerate(lines, start=1):
            row = json.loads(line)
            if not isinstance(row, dict):
                return _response('409 Conflict', json.dumps({'ok': False, 'error': 'invalid_json', 'line': index}, separators=(',', ':')).encode())
            if 'entry_hash' not in row:
                previous = hashlib.sha256(line.encode()).hexdigest()
                continue
            entry_hash = str(row.pop('entry_hash'))
            if row.get('prev_hash', '') != previous:
                return _response('409 Conflict', json.dumps({'ok': False, 'error': 'previous_hash_mismatch', 'line': index}, separators=(',', ':')).encode())
            canonical = json.dumps(row, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
            actual = hashlib.sha256(canonical.encode()).hexdigest()
            if not hmac.compare_digest(entry_hash, actual):
                return _response('409 Conflict', json.dumps({'ok': False, 'error': 'entry_hash_mismatch', 'line': index}, separators=(',', ':')).encode())
            previous = entry_hash
            chained += 1
        return _response('200 OK', json.dumps({'ok': True, 'entries': len(lines), 'chained_entries': chained, 'last_hash': previous}, separators=(',', ':')).encode())
    except Exception:
        return _response('503 Service Unavailable', b'{"ok":false,"error":"audit_unavailable"}')
STATUS_TABLES = ['tenants', 'products', 'tenant_api_clients', 'tenant_api_usage', 'tenant_api_usage_daily', 'tenant_api_attempts', 'licenses', 'license_devices', 'auth_attempts', 'phone_activation_requests', 'offline_activation_requests', 'admin_principals', 'admin_audit_events', 'data_change_journal', 'ha_fence_state', 'tenant_webhooks', 'baas_batch_jobs', 'tenant_webhook_deliveries', 'product_key_issue_batches', 'product_key_issue_items', 'api_billing_invoices', 'tenant_key_issue_sessions', 'tenant_key_issue_session_items', 'subscriber_sdk_setup_codes', 'product_key_issue_jobs_v4', 'product_key_issue_v4_items', 'product_key_issue_plans_v5', 'product_key_issue_jobs_v5', 'product_key_issue_v5_items', 'product_key_issue_plans_v6', 'product_key_issue_jobs_v6', 'product_key_issue_v6_items', 'product_key_v8_jobs', 'product_key_v8_items', 'license_v3_challenges', 'license_v3_devices', 'license_v3_sessions', 'license_v3_refresh_history', 'license_v3_proofs', 'license_v3_offline_tickets', 'issuance_jobs', 'issuance_plans', 'issuance_items', 'archived_identity_records', 'tenant_portal_key_reissues', 'jpki_verifications']

def _runtime_path(filename):
    private_dir = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not private_dir:
        return None
    return Path(private_dir).expanduser() / 'runtime' / filename

def _runtime_json(filename):
    path = _runtime_path(filename)
    if path is None or not path.is_file():
        return None
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else None
    except (OSError, ValueError):
        return None

def _ha_sync_token():
    token = os.environ.get('PYTHON_MIGRATION_HA_SYNC_TOKEN', '')
    if token:
        return token
    try:
        from migration_config import secret_value
        return str(secret_value('ha_sync_token') or '')
    except Exception:
        return ''

def _runtime_lock_active():
    path = _runtime_path('sync.lock')
    if path is None:
        return False
    path.parent.mkdir(mode=448, parents=True, exist_ok=True)
    try:
        with open(path, 'a+b') as lock_file:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                return False
            except BlockingIOError:
                return True
    except OSError:
        return False

def _runtime_sync_state():
    last_sync = _runtime_json('last-sync.json')
    progress = dict(_runtime_json('sync-progress.json') or {})
    active = _runtime_lock_active()
    progress['running'] = active
    progress['stale'] = not active
    return (last_sync, progress)

def _effective_role():
    state = _runtime_json('state.json') or {}
    role = os.environ.get('PYTHON_MIGRATION_HA_ROLE', 'unknown') or 'unknown'
    promoted = state.get('promoted') is True if 'promoted' in state else os.environ.get('PYTHON_MIGRATION_HA_PROMOTED') == '1'
    maintenance = state.get('maintenance') is True if 'maintenance' in state else os.environ.get('PYTHON_MIGRATION_HA_MAINTENANCE') == '1'
    if promoted:
        return 'promoted'
    if maintenance:
        return 'maintenance'
    return role

def _ha_private_storage_state():
    private_dir = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not private_dir:
        return (False, False)
    try:
        private_path = Path(private_dir).expanduser().resolve()
        document_root = Path(os.environ.get('DOCUMENT_ROOT', Path(__file__).resolve().parent)).resolve()
        public_html = document_root
        if 'public_html' in document_root.parts:
            index = document_root.parts.index('public_html')
            public_html = Path(*document_root.parts[:index + 1])
        return (not is_relative_to(private_path, document_root), not is_relative_to(private_path, public_html))
    except (OSError, ValueError):
        return (False, False)

@legacy_compatible(callback_index=1, request_index=0)
def ha_status(request_context):
    if not _ha_audit_authorized(request_context):
        return _response('404 Not Found', b'{"ok":false,"error":"not_found"}')
    query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
    if query.get('sync_progress', [''])[0] == '1':
        last_sync, progress = _runtime_sync_state()
        return _response('200 OK', json.dumps({'ok': True, 'effective_role': _effective_role(), 'last_sync': last_sync, 'sync_progress': progress}, ensure_ascii=False, separators=(',', ':')).encode())
    connection = None
    try:
        connection = connect()
        counts, schema_hashes, schema_columns, missing = ({}, {}, {}, [])
        with connection.cursor() as cursor:
            cursor.execute('SELECT table_name FROM information_schema.tables WHERE table_schema=DATABASE()')
            existing = {str(row['table_name']) for row in cursor.fetchall()}
            for table in STATUS_TABLES:
                if table not in existing:
                    missing.append(table)
                    counts[table] = None
                    schema_hashes[table] = None
                    schema_columns[table] = []
                    continue
                cursor.execute('SELECT COUNT(*) AS count FROM `' + table + '`')
                counts[table] = int(cursor.fetchone()['count'])
                cursor.execute('SHOW COLUMNS FROM `' + table + '`')
                definition = [dict(row) for row in cursor.fetchall()]
                schema_hashes[table] = hashlib.sha256(json.dumps(definition, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
                schema_columns[table] = [str(row['Field']) for row in definition]
            cursor.execute('CREATE TABLE IF NOT EXISTS idempotency_keys (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, operation VARCHAR(40) NOT NULL, request_key VARCHAR(100) NOT NULL, response_json TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(id), UNIQUE KEY uq_idempotency_operation_key(operation,request_key)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci')
            cursor.execute('SELECT COUNT(*) AS count FROM idempotency_keys')
            counts['idempotency_keys'] = int(cursor.fetchone()['count'])
            cursor.execute('SHOW COLUMNS FROM idempotency_keys')
            idem_definition = [dict(row) for row in cursor.fetchall()]
            schema_hashes['idempotency_keys'] = hashlib.sha256(json.dumps(idem_definition, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
            schema_columns['idempotency_keys'] = [str(row['Field']) for row in idem_definition]
        last_sync, progress = _runtime_sync_state()
        synced_at = (last_sync or {}).get('synced_at_utc')
        sync_age = None
        if synced_at:
            try:
                parsed = parse_iso_datetime(str(synced_at).replace('Z', '+00:00'))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=datetime.timezone.utc)
                sync_age = max(0, int((datetime.datetime.now(datetime.timezone.utc) - parsed).total_seconds()))
            except ValueError:
                pass
        pending = _runtime_json('pending-sync.json')
        private_configured, private_outside = _ha_private_storage_state()
        runtime_dir = _runtime_path('state.json')
        result = {'ok': True, 'configured_role': os.environ.get('PYTHON_MIGRATION_HA_ROLE', 'unknown'), 'effective_role': _effective_role(), 'counts': counts, 'schema_hashes': schema_hashes, 'schema_columns': schema_columns, 'schema_ready': not missing, 'missing_tables': missing, 'last_sync': last_sync, 'sync_age_seconds': sync_age, 'sync_fresh': sync_age is not None and sync_age <= 600, 'pending_sync': pending if isinstance(pending, dict) else {'pending': False, 'attempts': 0}, 'sync_progress': progress, 'private_storage_configured': private_configured, 'private_storage_outside_public_html': private_outside, 'runtime_storage_configured': runtime_dir is not None and runtime_dir.parent.is_dir(), 'legacy_public_passkey_store_present': False}
        return _response('200 OK', json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode())
    except Exception:
        return _response('503 Service Unavailable', b'{"ok":false,"error":"status_failed"}')
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

@legacy_compatible(callback_index=None, request_index=2)
def _append_ha_audit(event, context, request_context):
    path = _runtime_path('audit.log')
    if path is None:
        return False
    configured, _ = _private_storage_checks()
    _, outside_public = _ha_private_storage_state()
    if not configured or not outside_public:
        return False
    from audit import append_event
    return append_event(event, context, str(request_context.get('client_address', '')), path=path, role=os.environ.get('PYTHON_MIGRATION_HA_ROLE', 'unknown'))

def _json_value(value):
    if isinstance(value, datetime.datetime):
        return value.isoformat(sep=' ')
    if isinstance(value, (datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, bytes):
        return base64.b64encode(value).decode('ascii')
    if isinstance(value, (bytearray, memoryview)):
        return base64.b64encode(bytes(value)).decode('ascii')
    return value

def _retry_sync_json_value(value):
    """Serialize aggregate MySQL DECIMAL values like PDO's fetched strings."""
    if isinstance(value, Decimal):
        return str(value)
    return _json_value(value)

def _restore_rows_hash(rows):
    normalized = [{key: _json_value(value) for key, value in row.items()} for row in rows]
    encoded = json.dumps(normalized, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
    return hashlib.sha256(encoded.encode()).hexdigest()

def _write_runtime_json(filename, value):
    path = _runtime_path(filename)
    if path is None:
        raise RuntimeError('private_runtime_storage_unavailable')
    configured, _ = _private_storage_checks()
    _, outside_public = _ha_private_storage_state()
    if not configured or not outside_public:
        raise RuntimeError('private_runtime_storage_unavailable')
    path.parent.mkdir(mode=448, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp.' + secrets.token_hex(6))
    encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':')) + '\n'
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise

def _write_private_json(filename, value):
    private_dir = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not private_dir or not re.fullmatch('[a-z0-9._-]+\\.json', filename):
        raise RuntimeError('private_storage_unavailable')
    configured, _ = _private_storage_checks()
    _, outside = _ha_private_storage_state()
    if not configured or not outside:
        raise RuntimeError('private_storage_unavailable')
    directory = Path(private_dir).expanduser().resolve()
    directory.mkdir(mode=448, parents=True, exist_ok=True)
    target = directory / filename
    temporary = target.with_name(target.name + '.tmp.' + secrets.token_hex(6))
    descriptor = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            json.dump(value, stream, ensure_ascii=False, separators=(',', ':'))
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
RESTORE_TEST_TABLES = ['tenants', 'products', 'tenant_api_clients', 'tenant_api_usage', 'tenant_api_usage_daily', 'tenant_api_attempts', 'licenses', 'license_devices', 'auth_attempts', 'phone_activation_requests', 'offline_activation_requests', 'idempotency_keys', 'admin_service_intakes', 'jpki_verifications']

def _restore_test_order(table):
    return 'id'

@legacy_compatible(callback_index=1, request_index=0)
def ha_restore_test(request_context):
    if not _ha_audit_authorized(request_context):
        return _response('404 Not Found', b'{"ok":false,"error":"not_found"}')
    if request_context.get('method', '') != 'POST':
        return _response('405 Method Not Allowed', b'{"ok":false,"error":"method_not_allowed"}')
    role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    promoted = os.environ.get('PYTHON_MIGRATION_HA_PROMOTED') == '1' or (_runtime_json('state.json') or {}).get('promoted') is True
    if role != 'primary' and (not (role == 'standby' and promoted)):
        return _response('409 Conflict', b'{"ok":false,"error":"writable_role_required"}')
    connection = connect()
    try:
        from phone_handlers import _ensure_phone_schema
        _ensure_phone_schema(connection)
        with connection.cursor() as cursor:
            cursor.execute('CREATE TABLE IF NOT EXISTS idempotency_keys (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, operation VARCHAR(40) NOT NULL, request_key VARCHAR(100) NOT NULL, response_json TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(id), UNIQUE KEY uq_idempotency_operation_key(operation,request_key)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci')
    except Exception:
        try:
            connection.close()
        except Exception:
            pass
        raise
    request_id = secrets.token_hex(8)
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS count FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name='licenses' AND column_name='reissue_used_at'")
            if int(cursor.fetchone()['count']) != 1:
                raise RuntimeError('reissue_state_column_missing')
            results = {}
            for table in RESTORE_TEST_TABLES:
                quoted = '`' + table + '`'
                order = _restore_test_order(table)
                cursor.execute('SELECT * FROM ' + quoted + ' ORDER BY `' + order + '`')
                source_rows = [dict(row) for row in cursor.fetchall()]
                expected = _restore_rows_hash(source_rows)
                temp = 'restore_test_' + table
                cursor.execute('DROP TEMPORARY TABLE IF EXISTS `' + temp + '`')
                cursor.execute('CREATE TEMPORARY TABLE `' + temp + '` LIKE ' + quoted)
                for row in source_rows:
                    names = list(row)
                    if not names:
                        continue
                    columns = ','.join(('`' + name.replace('`', '``') + '`' for name in names))
                    marks = ','.join(['%s'] * len(names))
                    cursor.execute('INSERT INTO `' + temp + '` (' + columns + ') VALUES (' + marks + ')', tuple((row[name] for name in names)))
                cursor.execute('SELECT * FROM `' + temp + '` ORDER BY `' + order + '`')
                restored_rows = [dict(row) for row in cursor.fetchall()]
                cursor.execute('DROP TEMPORARY TABLE `' + temp + '`')
                actual = _restore_rows_hash(restored_rows)
                if not hmac.compare_digest(expected, actual):
                    raise RuntimeError('restore_hash_mismatch:' + table)
                results[table] = {'rows': len(restored_rows), 'sha256': actual}
        record = {'tested_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'), 'ok': True, 'tables': results, 'reissue_state_verified': True}
        _write_runtime_json('last-restore-test.json', record)
        _append_ha_audit('database_restore_test_succeeded', {'counts': {name: value['rows'] for name, value in results.items()}}, request_context)
        return _response('200 OK', json.dumps(record, ensure_ascii=False, separators=(',', ':')).encode())
    except Exception:
        try:
            _append_ha_audit('database_restore_test_failed', {'request_id': request_id}, request_context)
        except Exception:
            pass
        return _response('503 Service Unavailable', json.dumps({'ok': False, 'error': 'restore_test_failed', 'request_id': request_id}, separators=(',', ':')).encode())
    finally:
        try:
            connection.close()
        except Exception:
            pass

@legacy_compatible(callback_index=1, request_index=0)
def ha_import(request_context):
    if not _ha_audit_authorized(request_context):
        return _response('404 Not Found', b'{"ok":false,"error":"not_found"}')
    maintenance = os.environ.get('PYTHON_MIGRATION_HA_MAINTENANCE') == '1' or (_runtime_json('state.json') or {}).get('maintenance') is True
    if str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', '')) != 'primary' or not maintenance or request_context.get('method', '') != 'POST':
        return _response('409 Conflict', b'{"ok":false,"error":"primary_maintenance_required"}')
    max_bytes = 50 * 1024 * 1024
    try:
        stream = request_context.get('body_stream')
        raw = stream.read(max_bytes + 1) if stream is not None else b''
        if len(raw) > max_bytes:
            return _response('413 Content Too Large', b'{"ok":false,"error":"snapshot_too_large"}')
        snapshot = json.loads(raw.decode('utf-8'), parse_constant=lambda _value: (_ for _ in ()).throw(ValueError('invalid_snapshot')))
        pending = [(snapshot, 1)] if isinstance(snapshot, (dict, list)) else []
        while pending:
            value, depth = pending.pop()
            if depth > 512:
                return _response('400 Bad Request', b'{"ok":false,"error":"invalid_snapshot"}')
            children = value.values() if isinstance(value, dict) else value
            pending.extend(((child, depth + 1) for child in children if isinstance(child, (dict, list))))
    except (AttributeError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        return _response('400 Bad Request', b'{"ok":false,"error":"invalid_snapshot"}')
    query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
    archive_restore = str(request_context.get('header:x-ha-restore', '')) == 'archive'
    from ha_snapshot import SnapshotError, INSERT_ORDER, restore_rows, snapshot_counts, validate_local_schema, validate_snapshot
    try:
        snapshot_id = validate_snapshot(snapshot, archive_restore=archive_restore)
    except SnapshotError as error:
        body = {'ok': False, 'error': error.error, **error.details}
        return _response(f"{error.status} {('Conflict' if error.status == 409 else 'Service Unavailable' if error.status == 503 else 'Bad Request')}", json.dumps(body, separators=(',', ':')).encode())
    connection = None
    try:
        connection = connect()
        from phone_handlers import _ensure_phone_schema
        _ensure_phone_schema(connection)
        with connection.cursor() as cursor:
            cursor.execute('CREATE TABLE IF NOT EXISTS idempotency_keys (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, operation VARCHAR(40) NOT NULL, request_key VARCHAR(100) NOT NULL, response_json TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(id), UNIQUE KEY uq_idempotency_operation_key(operation,request_key)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci')
        local_schemas, ignored = validate_local_schema(connection, snapshot)
        if query.get('validate_only', [''])[0] == '1':
            incoming = {table: len(snapshot['tables'].get(table, [])) for table in INSERT_ORDER}
            _append_ha_audit('snapshot_import_validated', {'snapshot_id': snapshot_id, 'counts': incoming}, request_context)
            return _response('200 OK', json.dumps({'ok': True, 'validate_only': True, 'snapshot_id': snapshot_id, 'counts': incoming, 'ignored_source_columns': ignored}, ensure_ascii=False, separators=(',', ':')).encode())
        connection.begin()
        restore_rows(connection, snapshot, local_schemas, delete_unique=False)
        connection.commit()
        counts = snapshot_counts(connection, snapshot)
        imported_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
        _write_runtime_json('last-import.json', {'imported_at_utc': imported_at, 'counts': counts})
        _write_private_json('passkey-store.json', {'credentials': [], 'recovery_codes': [], 'challenges': {}, 'codes': {}})
        _append_ha_audit('snapshot_imported', {'snapshot_id': snapshot_id, 'counts': counts, 'table_hashes': snapshot['table_hashes'], 'passkey_credential_count': len(snapshot['passkey_credentials']), 'ignored_source_columns': ignored}, request_context)
        return _response('200 OK', json.dumps({'ok': True, 'snapshot_id': snapshot_id, 'counts': counts, 'table_hashes': snapshot['table_hashes']}, ensure_ascii=False, separators=(',', ':')).encode())
    except SnapshotError as error:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        body = {'ok': False, 'error': error.error, **error.details}
        return _response(f'{error.status} Conflict', json.dumps(body, separators=(',', ':')).encode())
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        request_id = secrets.token_hex(8)
        try:
            _append_ha_audit('import_failed', {'request_id': request_id}, request_context)
        except Exception:
            pass
        return _response('503 Service Unavailable', json.dumps({'ok': False, 'error': 'import_failed', 'request_id': request_id}, separators=(',', ':')).encode())
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

class _NoRedirect(urllib.request.HTTPRedirectHandler):

    def redirect_request(self, request, response, code, message, headers, new_url):
        return None

def _ha_peer_export(peer, token):
    base = str(peer or '').strip().rstrip('/')
    parsed = urlsplit(base)
    if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError('peer_not_configured')
    if parsed.scheme != 'https' and (not (parsed.scheme == 'http' and parsed.hostname in {'localhost', '127.0.0.1', '::1'})):
        raise ValueError('peer_not_configured')
    request = urllib.request.Request(base + '/ha/export.php', headers={**HA_HTTP_HEADERS, 'X-HA-Token': token}, method='GET')
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        response = opener.open(request, timeout=180)
        with response:
            status = int(response.status)
            raw = response.read(50 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        status = int(error.code)
        raw = error.read(1024 * 1024)
    if len(raw) > 50 * 1024 * 1024:
        raise OverflowError('snapshot_too_large')
    try:
        payload = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    return (status, payload)

@legacy_compatible(callback_index=1, request_index=0)
def ha_sync(request_context):
    if not _ha_audit_authorized(request_context):
        return _response('404 Not Found', b'{"ok":false,"error":"not_found"}')
    role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    promoted = os.environ.get('PYTHON_MIGRATION_HA_PROMOTED') == '1' or (_runtime_json('state.json') or {}).get('promoted') is True
    if role != 'standby' or promoted or request_context.get('method', '') != 'POST':
        return _response('409 Conflict', b'{"ok":false,"error":"sync_not_allowed"}')
    private_configured, _ = _private_storage_checks()
    _, private_outside_public = _ha_private_storage_state()
    if not private_configured or not private_outside_public:
        return _response('503 Service Unavailable', b'{"ok":false,"error":"sync_storage_unavailable"}')
    lock_path = _runtime_path('sync.lock')
    lock_path.parent.mkdir(mode=448, parents=True, exist_ok=True)
    try:
        lock_file = open(lock_path, 'a+b')
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, BlockingIOError):
        try:
            lock_file.close()
        except (UnboundLocalError, OSError):
            pass
        return _response('409 Conflict', b'{"ok":false,"error":"sync_already_running"}')
    from ha_snapshot import INSERT_ORDER, SnapshotError, restore_rows, validate_local_schema, validate_snapshot
    connection = None
    progress_path = _runtime_path('sync-progress.json')
    background_parent = False
    try:
        _write_runtime_json('sync-progress.json', {'running': True, 'phase': 'export', 'started_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'), 'table': None})
        query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
        async_requested = bool(query.get('async')) and query['async'][-1] == '1'
        if async_requested and request_context.get('GATEWAY_INTERFACE', '').startswith('CGI/') and hasattr(os, 'fork'):
            try:
                child_pid = os.fork()
            except OSError:
                child_pid = -1
            if child_pid > 0:
                background_parent = True
                return _response('202 Accepted', json.dumps({'ok': True, 'accepted': True, 'sync_in_progress': True, 'status_endpoint': '/ha/status.php?sync_progress=1'}, separators=(',', ':')).encode())
            if child_pid == 0:
                try:
                    os.setsid()
                    sys.stdout.flush()
                    sys.stderr.flush()
                    null_fd = os.open(os.devnull, os.O_WRONLY)
                    os.dup2(null_fd, 1)
                    os.dup2(null_fd, 2)
                    if null_fd > 2:
                        os.close(null_fd)
                except OSError:
                    pass
        token = _ha_sync_token()
        peer = os.environ.get('PYTHON_MIGRATION_HA_PEER', '')
        try:
            peer_status, snapshot = _ha_peer_export(peer, token)
        except OverflowError:
            return _response('503 Service Unavailable', b'{"ok":false,"error":"snapshot_too_large"}')
        except Exception:
            return _response('503 Service Unavailable', b'{"ok":false,"error":"invalid_snapshot"}')
        if peer_status >= 400:
            peer_error = snapshot.get('error') if isinstance(snapshot, dict) else None
            return _response('503 Service Unavailable', json.dumps({'ok': False, 'error': 'peer_export_failed', 'peer_http_status': peer_status, 'peer_error': peer_error}, separators=(',', ':')).encode())
        try:
            snapshot_id = validate_snapshot(snapshot, max_age_seconds=300)
        except SnapshotError as error:
            return _response('503 Service Unavailable', json.dumps({'ok': False, 'error': error.error, **error.details}, separators=(',', ':')).encode())
        secrets_data = snapshot.get('secrets', {})
        if not isinstance(secrets_data.get('key_pepper'), str) or not secrets_data['key_pepper'] or (not isinstance(secrets_data.get('token_secret'), str)) or (not secrets_data['token_secret']):
            return _response('503 Service Unavailable', b'{"ok":false,"error":"invalid_secrets"}')
        if not isinstance(snapshot.get('passkey_credentials'), (dict, list)):
            return _response('503 Service Unavailable', b'{"ok":false,"error":"invalid_passkey_credentials"}')
        if not isinstance(snapshot.get('passkey_recovery_codes', []), (dict, list)):
            return _response('503 Service Unavailable', b'{"ok":false,"error":"invalid_passkey_recovery_codes"}')
        connection = connect()
        with connection.cursor() as cursor:
            cursor.execute('CREATE TABLE IF NOT EXISTS idempotency_keys (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT, operation VARCHAR(40) NOT NULL, request_key VARCHAR(100) NOT NULL, response_json TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(id), UNIQUE KEY uq_idempotency_operation_key(operation,request_key)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci')
        local_schemas, _ignored = validate_local_schema(connection, snapshot)
        _write_runtime_json('sync-progress.json', {'running': True, 'phase': 'restore', 'snapshot_id': snapshot_id, 'started_at_utc': snapshot.get('generated_at_utc'), 'table': None, 'completed_tables': 0, 'total_tables': sum((1 for table in snapshot['tables'] if table in INSERT_ORDER))})
        connection.begin()
        restore_rows(connection, snapshot, local_schemas, delete_unique=True, progress=lambda state: _write_runtime_json('sync-progress.json', state))
        connection.commit()
        from migration_config import update_runtime_secrets
        update_runtime_secrets({'key_pepper': secrets_data['key_pepper'], 'token_secret': secrets_data['token_secret'], 'admin_password_hash': str(secrets_data.get('admin_password_hash', '')), 'license_v3_signing_secret': str(secrets_data.get('license_v3_signing_secret', '')), 'jpki_private_key': str(secrets_data.get('jpki_private_key', ''))})
        private_dir = Path(os.environ['PYTHON_MIGRATION_PRIVATE_DIR']).expanduser().resolve()
        passkey_store_path = private_dir / 'passkey-store.json'
        current_store = {}
        if passkey_store_path.is_file():
            try:
                loaded = json.loads(passkey_store_path.read_text(encoding='utf-8'))
                if isinstance(loaded, dict):
                    current_store = loaded
            except (OSError, ValueError):
                pass
        current_store['credentials'] = []
        current_store['recovery_codes'] = []
        current_store.setdefault('challenges', {})
        current_store.setdefault('codes', {})
        _write_private_json('passkey-store.json', current_store)
        counts = {table: len(snapshot['tables'][table]) for table in snapshot['tables'] if table in INSERT_ORDER}
        synced_at = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
        last_sync = {'synced_at_utc': synced_at, 'source_generated_at_utc': snapshot.get('generated_at_utc'), 'snapshot_id': snapshot_id, 'schema_hash': snapshot.get('schema_hash'), 'table_hashes': snapshot['table_hashes'], 'row_counts': counts, 'passkey_credential_count': len(snapshot['passkey_credentials'])}
        _write_runtime_json('last-sync.json', last_sync)
        _append_ha_audit('standby_synchronized', {'snapshot_id': snapshot_id, 'row_counts': counts, 'table_hashes': snapshot['table_hashes']}, request_context)
        try:
            progress_path.unlink()
        except OSError:
            pass
        return _response('200 OK', json.dumps({'ok': True, 'snapshot_id': snapshot_id, 'synced_at_utc': synced_at, 'restore_mode': 'bulk'}, separators=(',', ':')).encode())
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        try:
            if connection is not None:
                with connection.cursor() as cursor:
                    cursor.execute('SET UNIQUE_CHECKS=1')
                    cursor.execute('SET FOREIGN_KEY_CHECKS=1')
        except Exception:
            pass
        request_id = secrets.token_hex(8)
        try:
            _append_ha_audit('sync_restore_failed', {'request_id': request_id}, request_context)
        except Exception:
            pass
        try:
            progress_path.unlink()
        except OSError:
            pass
        return _response('503 Service Unavailable', json.dumps({'ok': False, 'error': 'restore_failed', 'request_id': request_id}, separators=(',', ':')).encode())
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if background_parent:
            lock_file.close()
        else:
            try:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
            finally:
                lock_file.close()

@legacy_compatible(callback_index=None, request_index=1)
def ha_sync_peer(reason, request_context):
    role = str(os.environ.get('PYTHON_MIGRATION_HA_ROLE', ''))
    if role != 'primary':
        return {'ok': True, 'required': False}
    token = _ha_sync_token()
    peer = os.environ.get('PYTHON_MIGRATION_HA_PEER', '').strip().rstrip('/')
    error = None
    peer_result = None
    if peer and token:
        parsed = urlsplit(peer)
        allowed_scheme = parsed.scheme == 'https' or (parsed.scheme == 'http' and parsed.hostname in {'localhost', '127.0.0.1', '::1'})
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or (not allowed_scheme):
            error = 'peer_not_configured'
        else:
            request = urllib.request.Request(peer + '/ha/sync.php', data=b'{}', headers={**HA_HTTP_HEADERS, 'Content-Type': 'application/json', 'X-HA-Token': token}, method='POST')
            try:
                response = urllib.request.build_opener(_NoRedirect()).open(request, timeout=25)
                with response:
                    raw = response.read(1024 * 1024 + 1)
                    if len(raw) > 1024 * 1024:
                        raise OverflowError('peer_response_too_large')
                    peer_result = json.loads(raw.decode('utf-8'))
                    accepted = response.status == 202
                if not isinstance(peer_result, dict) or peer_result.get('ok') is not True:
                    error = str(peer_result.get('error', 'peer_sync_failed')) if isinstance(peer_result, dict) else 'peer_unreachable'
                elif accepted or peer_result.get('accepted') is True or peer_result.get('sync_in_progress') is True:
                    error = 'peer_sync_in_progress'
            except OverflowError:
                error = 'peer_response_too_large'
            except urllib.error.HTTPError as exc:
                try:
                    peer_result = json.loads(exc.read(1024 * 1024).decode('utf-8'))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    peer_result = None
                error = str(peer_result.get('error', 'peer_sync_failed')) if isinstance(peer_result, dict) else 'peer_unreachable'
            except Exception:
                error = 'peer_unreachable'
    else:
        error = 'peer_not_configured'
    if error is None:
        path = _runtime_path('pending-sync.json')
        if path is not None:
            try:
                path.unlink()
            except OSError:
                pass
        _append_ha_audit('peer_sync_succeeded', {'reason': reason}, request_context)
        return {'ok': True, 'required': True, 'peer_result': peer_result}
    previous = _runtime_json('pending-sync.json') or {}
    attempts = int(previous.get('attempts', 0)) + 1
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    _write_runtime_json('pending-sync.json', {'pending': True, 'reason': reason, 'first_failed_at_utc': previous.get('first_failed_at_utc', now), 'last_failed_at_utc': now, 'attempts': attempts, 'last_error': error})
    _append_ha_audit('peer_sync_queued', {'reason': reason, 'attempts': attempts, 'error': error}, request_context)
    result = {'ok': False, 'required': True, 'queued': True, 'attempts': attempts, 'error': error}
    if error == 'peer_sync_in_progress':
        result['in_progress'] = True
    return result

@legacy_compatible(callback_index=1, request_index=0)
def ha_retry_sync(request_context):
    if not _ha_audit_authorized(request_context):
        return _response('404 Not Found', b'{"ok":false,"error":"not_found"}')
    if request_context.get('method', 'GET') != 'POST':
        return _response('405 Method Not Allowed', b'{"ok":false,"error":"method_not_allowed"}')
    connection = None
    try:
        connection = connect()
        with connection.cursor() as cursor:
            cursor.execute('CREATE TABLE IF NOT EXISTS schema_migrations (version VARCHAR(64) NOT NULL, applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(version)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci')
            cursor.execute('CREATE TABLE IF NOT EXISTS schema_migration_history (version VARCHAR(64) NOT NULL, applied_at DATETIME NOT NULL, archived_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(version), KEY idx_schema_migration_history_archived(archived_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci')
            cursor.execute('INSERT IGNORE INTO schema_migration_history(version,applied_at) SELECT version,applied_at FROM schema_migrations')
            cursor.execute("SELECT COUNT(*) AS count FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='idempotency_keys' AND index_name='idx_idempotency_created_at'")
            index_exists = int(cursor.fetchone()['count']) > 0
            if not index_exists:
                cursor.execute('ALTER TABLE idempotency_keys ADD INDEX idx_idempotency_created_at (created_at)')
            cursor.execute('DELETE FROM idempotency_keys WHERE created_at < NOW() - INTERVAL 30 DAY')
            cursor.execute('DELETE FROM auth_attempts WHERE attempted_at < NOW() - INTERVAL 180 DAY')
            cursor.execute('DELETE FROM tenant_api_attempts WHERE attempted_at < NOW() - INTERVAL 180 DAY')
            fingerprint = {}
            for table, column in (('tenants', 'updated_at'), ('products', 'updated_at'), ('tenant_api_clients', 'created_at'), ('tenant_api_usage', 'used_at'), ('tenant_api_attempts', 'attempted_at'), ('licenses', 'updated_at'), ('license_devices', 'last_seen_at'), ('auth_attempts', 'attempted_at'), ('phone_activation_requests', 'last_seen_at'), ('offline_activation_requests', 'issued_at'), ('idempotency_keys', 'created_at')):
                cursor.execute('SELECT COUNT(*) AS c,COALESCE(MAX(id),0) AS m,COALESCE(MAX(`' + column + "`),'') AS t FROM `" + table + '`')
                fingerprint[table] = {key: _retry_sync_json_value(value) for key, value in cursor.fetchone().items()}
            cursor.execute("SELECT COALESCE(SUM(request_count),0) AS c,COALESCE(MAX(usage_day),'') AS t FROM tenant_api_usage_daily")
            fingerprint['tenant_api_usage_daily'] = {key: _retry_sync_json_value(value) for key, value in cursor.fetchone().items()}
            cursor.execute("SELECT COUNT(*) AS c,COALESCE(MAX(id),0) AS m,COALESCE(SUM(amount_units),0) AS fees,COALESCE(MAX(created_at),'') AS created FROM tenant_portal_key_reissues")
            fingerprint['tenant_portal_key_reissues'] = {key: _retry_sync_json_value(value) for key, value in cursor.fetchone().items()}
            cursor.execute("SELECT COUNT(*) AS c,COALESCE(MAX(id),0) AS m,COALESCE(MAX(archived_at),'') AS archived FROM archived_identity_records")
            fingerprint['archived_identity_records'] = {key: _retry_sync_json_value(value) for key, value in cursor.fetchone().items()}
        connection.commit()
        generation = hashlib.sha256(json.dumps(fingerprint, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
        previous = _runtime_json('last-periodic-generation.json') or {}
        if hmac.compare_digest(str(previous.get('generation', '')), generation):
            return _response('200 OK', json.dumps({'ok': True, 'required': False, 'unchanged': True, 'generation': generation}, separators=(',', ':')).encode())
        result = ha_sync_peer('scheduled_periodic_sync', request_context)
        if result['ok']:
            _write_runtime_json('last-periodic-generation.json', {'generation': generation, 'synced_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')})
        result['generation'] = generation
        return _response('200 OK' if result['ok'] else '503 Service Unavailable', json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode())
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        return _response('503 Service Unavailable', b'{"ok":false,"error":"retry_sync_failed"}')
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

@legacy_compatible(callback_index=1, request_index=0)
def ha_retention(request_context):
    if not _ha_authorized_scope(request_context, 'admin:manage'):
        return _response('404 Not Found', b'{"ok":false,"error":"not_found"}')
    if request_context.get('method', '') != 'POST':
        return _response('405 Method Not Allowed', b'{"ok":false,"error":"method_not_allowed"}')
    from http_utils import request_data, request_id
    from v3_handlers import _assert_write_fence
    rid = request_id()
    connection = None
    try:
        connection = connect()
        _assert_write_fence(connection)
        payload = request_data(request_context)
        usage_days = max(30, min(730, int(payload.get('usage_retention_days', 180))))
        attempt_days = max(7, min(365, int(payload.get('attempt_retention_days', 90))))
        with connection.cursor() as cursor:
            connection.begin()
            cursor.execute('INSERT INTO tenant_api_usage_daily(usage_day,tenant_id,client_id,operation,status_code,request_count) SELECT DATE(used_at),tenant_id,client_id,operation,status_code,COUNT(*) FROM tenant_api_usage WHERE used_at<UTC_TIMESTAMP()-INTERVAL %s DAY GROUP BY DATE(used_at),tenant_id,client_id,operation,status_code ON DUPLICATE KEY UPDATE request_count=VALUES(request_count)', (usage_days,))
            cursor.execute('DELETE FROM tenant_api_usage WHERE used_at<UTC_TIMESTAMP()-INTERVAL %s DAY', (usage_days,))
            usage_deleted = int(cursor.rowcount)
            cursor.execute('DELETE FROM tenant_api_attempts WHERE attempted_at<UTC_TIMESTAMP()-INTERVAL %s DAY', (attempt_days,))
            attempts_deleted = int(cursor.rowcount)
            cursor.execute("UPDATE tenant_api_clients SET status='revoked',revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()) WHERE status='retiring' AND grace_expires_at<UTC_TIMESTAMP()")
            keys_revoked = int(cursor.rowcount)
        connection.commit()
        result = {'ok': True, 'usage_deleted': usage_deleted, 'attempts_deleted': attempts_deleted, 'retiring_keys_revoked': keys_revoked, 'usage_retention_days': usage_days, 'attempt_retention_days': attempt_days, 'request_id': rid}
        _append_ha_audit('retention_completed', result, request_context)
        return _response('200 OK', json.dumps(result, separators=(',', ':')).encode())
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        return _response('503 Service Unavailable', json.dumps({'ok': False, 'error': 'retention_failed', 'request_id': rid}, separators=(',', ':')).encode())
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
