"""HA snapshot validation and restore primitives for the isolated migration site."""

from py36_compat import parse_iso_datetime
import base64
import datetime
import hashlib
import hmac
import json
import re


DELETE_ORDER = ['stripe_webhook_events', 'stripe_key_reissue_payments', 'stripe_billing_key_suspensions', 'stripe_invoice_payments', 'product_key_v8_items', 'product_key_v8_jobs', 'issuance_items', 'issuance_plans', 'issuance_jobs', 'archived_identity_records', 'license_v4_offline_tickets', 'license_v4_proofs', 'license_v4_refresh_history', 'license_v4_sessions', 'license_v4_devices', 'license_v4_challenges', 'license_v3_offline_tickets', 'license_v3_proofs', 'license_v3_refresh_history', 'license_v3_sessions', 'license_v3_devices', 'license_v3_challenges', 'product_key_issue_v6_items', 'product_key_issue_jobs_v6', 'product_key_issue_plans_v6', 'product_key_issue_v5_items', 'product_key_issue_jobs_v5', 'product_key_issue_plans_v5', 'product_key_issue_v4_items', 'product_key_issue_jobs_v4', 'tenant_key_issue_session_items', 'tenant_key_issue_sessions', 'product_key_issue_items', 'product_key_issue_batches', 'subscriber_sdk_setup_codes', 'tenant_api_usage_reservations', 'tenant_api_usage_limits', 'api_billing_invoices', 'tenant_sso_temporary_grants', 'tenant_sso_sessions', 'tenant_sso_bootstrap_tickets', 'tenant_sso_memberships', 'tenant_portal_key_reissues', 'jpki_verifications', 'tenant_webhook_deliveries', 'baas_batch_jobs', 'tenant_webhooks', 'admin_audit_events', 'data_change_journal', 'admin_service_intakes', 'admin_principals', 'license_devices', 'phone_activation_requests', 'offline_activation_requests', 'auth_attempts', 'idempotency_keys', 'tenant_api_attempts', 'tenant_api_usage', 'tenant_api_usage_daily', 'licenses', 'tenant_api_clients', 'products', 'tenants', 'ha_fence_state']
INSERT_ORDER = ['issuance_jobs', 'issuance_plans', 'issuance_items', 'archived_identity_records', 'tenants', 'tenant_api_usage_limits', 'tenant_api_usage_reservations', 'admin_service_intakes', 'products', 'tenant_api_clients', 'tenant_sso_memberships', 'tenant_sso_temporary_grants', 'tenant_sso_bootstrap_tickets', 'tenant_sso_sessions', 'tenant_portal_key_reissues', 'jpki_verifications', 'licenses', 'license_devices', 'license_v3_challenges', 'license_v3_devices', 'license_v3_sessions', 'license_v3_refresh_history', 'license_v3_proofs', 'license_v3_offline_tickets', 'license_v4_challenges', 'license_v4_devices', 'license_v4_sessions', 'license_v4_refresh_history', 'license_v4_proofs', 'license_v4_offline_tickets', 'subscriber_sdk_setup_codes', 'product_key_issue_batches', 'product_key_issue_items', 'product_key_issue_jobs_v4', 'product_key_issue_v4_items', 'product_key_issue_plans_v5', 'product_key_issue_jobs_v5', 'product_key_issue_v5_items', 'product_key_issue_plans_v6', 'product_key_issue_jobs_v6', 'product_key_issue_v6_items', 'product_key_v8_jobs', 'product_key_v8_items', 'api_billing_invoices', 'stripe_invoice_payments', 'stripe_webhook_events', 'stripe_key_reissue_payments', 'stripe_billing_key_suspensions', 'auth_attempts', 'phone_activation_requests', 'offline_activation_requests', 'idempotency_keys', 'tenant_api_usage_daily', 'tenant_api_usage', 'tenant_api_attempts', 'admin_principals', 'admin_audit_events', 'data_change_journal', 'ha_fence_state', 'tenant_webhooks', 'baas_batch_jobs', 'tenant_webhook_deliveries', 'tenant_key_issue_sessions', 'tenant_key_issue_session_items']


class SnapshotError(ValueError):
    def __init__(self, error, status=400, details=None):
        super().__init__(error)
        self.error = error
        self.status = status
        self.details = details or {}


def _php_json(value, preserve_fraction=False):
    # PHP's JSON_UNESCAPED_SLASHES still escapes non-ASCII by default.
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)


def _php_hash(value):
    return hashlib.sha256(_php_json(value, preserve_fraction=True).encode()).hexdigest()


def validate_snapshot(snapshot, archive_restore=False, max_age_seconds=600):
    if not isinstance(snapshot, dict) or type(snapshot.get("schema")) is not int \
            or snapshot.get("schema") != 2 \
            or not isinstance(snapshot.get("tables"), dict) \
            or not isinstance(snapshot.get("table_hashes"), dict):
        raise SnapshotError("invalid_snapshot")
    if snapshot.get("binary_encoding") not in (None, "base64-v1"):
        raise SnapshotError("invalid_snapshot_binary_encoding")
    if 'issuance_jobs' in snapshot['tables'] and any(t in snapshot['tables'] for t in ('product_key_issue_jobs_v4','product_key_issue_jobs_v5','product_key_issue_jobs_v6')):
        raise SnapshotError('mixed_storage_snapshot',409)
    snapshot_id = str(snapshot.get("snapshot_id", ""))
    if re.fullmatch(r"[a-f0-9]{32}", snapshot_id) is None:
        raise SnapshotError("invalid_snapshot_id")
    credentials = snapshot.get("passkey_credentials")
    if not isinstance(credentials, (dict, list)):
        raise SnapshotError("invalid_passkey_credentials")
    recovery_codes = snapshot.get("passkey_recovery_codes", [])
    if not isinstance(recovery_codes, (dict, list)):
        raise SnapshotError("invalid_passkey_recovery_codes")
    hashes = snapshot["table_hashes"]
    for table, rows in snapshot["tables"].items():
        if not isinstance(table, str) or not isinstance(rows, list):
            raise SnapshotError("invalid_snapshot")
        try:
            actual = _php_hash(rows)
        except (TypeError, ValueError):
            raise SnapshotError("invalid_snapshot")
        if not hmac.compare_digest(str(hashes.get(table, "")), actual):
            raise SnapshotError("snapshot_hash_mismatch", 409, {"table": table})
    schemas = snapshot.get("schemas", [])
    if not isinstance(schemas, (dict, list)) or not hmac.compare_digest(
        str(snapshot.get("schema_hash", "")), _php_hash(schemas)
    ):
        raise SnapshotError("schema_hash_mismatch", 409)
    generated = snapshot.get("generated_at_utc")
    try:
        parsed = parse_iso_datetime(str(generated).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        age = abs((datetime.datetime.now(datetime.timezone.utc) - parsed).total_seconds())
    except (TypeError, ValueError):
        raise SnapshotError("stale_snapshot", 409)
    if not archive_restore and age > max_age_seconds:
        raise SnapshotError("stale_snapshot", 409)
    schema_entries = schemas.items() if isinstance(schemas, dict) else enumerate(schemas)
    for table, schema in schema_entries:
        if not isinstance(table, str) or not isinstance(schema, list):
            raise SnapshotError("invalid_snapshot")
        if table in snapshot["tables"] and any(
            not isinstance(column, dict) or not isinstance(column.get("Field"), str)
            or not isinstance(column.get("Type"), str) for column in schema
        ):
            raise SnapshotError("invalid_snapshot")
    return snapshot_id


def _schema_for(connection, table):
    with connection.cursor() as cursor:
        cursor.execute("SHOW COLUMNS FROM `" + table + "`")
        return [dict(row) for row in cursor.fetchall()]


def validate_local_schema(connection, snapshot):
    local_schemas = {}
    ignored = {}
    source_schemas = snapshot.get("schemas", [])
    if not isinstance(source_schemas, dict):
        source_schemas = {}
    for table in INSERT_ORDER:
        if table not in snapshot["tables"]:
            continue
        try:
            local = _schema_for(connection, table)
        except Exception:
            raise SnapshotError("local_schema_incompatible", 409, {"table": table, "column": "<table_missing>"})
        source_by_name = {column["Field"]: column for column in source_schemas.get(table, [])}
        local_by_name = {column["Field"]: column for column in local}
        for name, actual in local_by_name.items():
            source = source_by_name.get(name)
            required = (str(actual.get("Null", "")).upper() == "NO"
                        and actual.get("Default") is None
                        and "auto_increment" not in str(actual.get("Extra", "")).lower())
            if source is None:
                if required:
                    raise SnapshotError("snapshot_missing_required_column", 409, {"table": table, "column": name})
                continue
            compatible_chunk=(table=='product_key_issue_jobs_v4' and name=='chunk_size'
                              and str(source.get('Type','')).lower().startswith('smallint')
                              and str(actual.get('Type','')).lower().startswith('int'))
            if str(actual.get("Type", "")).lower() != str(source.get("Type", "")).lower() and not compatible_chunk:
                raise SnapshotError("local_schema_incompatible", 409, {"table": table, "column": name})
        ignored[table] = [name for name in source_by_name if name not in local_by_name]
        local_schemas[table] = local
    return local_schemas, ignored


def _decode_binary_rows(rows, schema):
    fields = [str(column["Field"]) for column in schema
              if re.match(r"^(?:varbinary|binary|(?:tiny|medium|long)?blob)\b",
                          str(column.get("Type", "")), re.I)]
    decoded_rows = []
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("invalid_row")
        decoded = dict(row)
        for field in fields:
            value = decoded.get(field)
            if value is None:
                continue
            if not isinstance(value, str):
                raise RuntimeError("invalid_snapshot_binary")
            try:
                binary = base64.b64decode(value, validate=True)
            except (ValueError, TypeError):
                raise RuntimeError("invalid_snapshot_binary")
            if base64.b64encode(binary).decode("ascii") != value:
                raise RuntimeError("invalid_snapshot_binary")
            decoded[field] = binary
        decoded_rows.append(decoded)
    return decoded_rows


def ha_snapshot_binary_rows(rows, schema, encode):
    """Encode/decode binary columns using the PHP snapshot-codec contract."""
    fields = [str(column.get("Field", "")) for column in schema
              if re.match(r"^(?:varbinary|binary|(?:tiny|medium|long)?blob)\b",
                          str(column.get("Type", "")), re.I)]
    if not fields:
        return rows
    result = []
    for row in rows:
        if not isinstance(row, dict):
            raise RuntimeError("invalid_snapshot_row")
        converted = dict(row)
        for field in fields:
            value = converted.get(field)
            if value is None:
                continue
            if encode:
                if not isinstance(value, (bytes, bytearray, memoryview)):
                    raise RuntimeError("invalid_snapshot_binary")
                converted[field] = base64.b64encode(bytes(value)).decode("ascii")
            else:
                if not isinstance(value, str):
                    raise RuntimeError("invalid_snapshot_binary")
                try:
                    binary = base64.b64decode(value, validate=True)
                except (ValueError, TypeError):
                    raise RuntimeError("invalid_snapshot_binary")
                if base64.b64encode(binary).decode("ascii") != value:
                    raise RuntimeError("invalid_snapshot_binary")
                converted[field] = binary
        result.append(converted)
    return result


def restore_rows(connection, snapshot, local_schemas, delete_unique=True, progress=None):
    tables = snapshot["tables"]
    with connection.cursor() as cursor:
        if progress:
            progress({"running": True, "phase": "restore", "table": None, "completed_tables": 0})
        cursor.execute("SET FOREIGN_KEY_CHECKS=0")
        if delete_unique:
            cursor.execute("SET UNIQUE_CHECKS=0")
        try:
            for table in DELETE_ORDER:
                if table in tables:
                    cursor.execute("DELETE FROM `" + table + "`")
            completed = 0
            total = sum(1 for table in INSERT_ORDER if table in tables)
            for table in INSERT_ORDER:
                if table not in tables:
                    continue
                rows = tables[table]
                if snapshot.get("binary_encoding") == "base64-v1":
                    rows = _decode_binary_rows(rows, local_schemas.get(table, []))
                if progress:
                    progress({"running": True, "phase": "restore", "table": table,
                              "table_rows": len(rows), "completed_tables": completed,
                              "total_tables": total, "snapshot_id": snapshot["snapshot_id"]})
                if not isinstance(rows, list):
                    raise RuntimeError("invalid_row")
                allowed = {str(column["Field"]) for column in local_schemas[table]}
                batch_names = None
                batch = []
                from schema39_storage import import_row
                insert_table,_ = import_row(table,{})
                def flush():
                    nonlocal batch
                    if not batch or not batch_names:
                        return
                    cols = ",".join("`" + name.replace("`", "``") + "`" for name in batch_names)
                    marks = "(" + ",".join(["%s"] * len(batch_names)) + ")"
                    sql = "INSERT INTO `" + insert_table + "` (" + cols + ") VALUES " + ",".join([marks] * len(batch))
                    params = tuple(value for values in batch for value in values)
                    cursor.execute(sql, params)
                    batch = []
                for source_row in rows:
                    if not isinstance(source_row, dict):
                        raise RuntimeError("invalid_row")
                    row = {name: value for name, value in source_row.items() if name in allowed}
                    if row:
                        _,row=import_row(table,row,snapshot.get('storage_model')!='domain-039')
                    names = list(row)
                    if not names:
                        continue
                    if batch_names is not None and names != batch_names:
                        flush()
                        batch_names = None
                    if batch_names is None:
                        batch_names = names
                    batch.append([row[name] for name in names])
                    max_rows = max(1, min(500, 4000 // max(1, len(batch_names))))
                    if len(batch) >= max_rows:
                        flush()
                flush()
                completed += 1
            if any(t.startswith('product_key_issue_jobs_v') or t in {'issuance_jobs','issuance_plans'} for t in tables):
                from schema39_storage import link_plans
                link_plans(cursor)
            cursor.execute("SET UNIQUE_CHECKS=1")
            cursor.execute("SET FOREIGN_KEY_CHECKS=1")
        except Exception:
            try:
                cursor.execute("SET UNIQUE_CHECKS=1")
                cursor.execute("SET FOREIGN_KEY_CHECKS=1")
            except Exception:
                pass
            raise


def snapshot_counts(connection, snapshot):
    counts = {}
    with connection.cursor() as cursor:
        for table in INSERT_ORDER:
            if table not in snapshot["tables"]:
                continue
            cursor.execute("SELECT COUNT(*) AS count FROM `" + table + "`")
            row = cursor.fetchone()
            counts[table] = int(row["count"])
    return counts
