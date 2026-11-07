"""HA-only worker for the independent V8 issuance queue."""
from native_http import legacy_compatible
import json
import hashlib
import secrets
import time
import database
from core import php_int_cast
from http_utils import json_response


def _reply(status, payload):
    labels = {200: "200 OK", 400: "400 Bad Request", 404: "404 Not Found",
              405: "405 Method Not Allowed", 503: "503 Service Unavailable"}
    return json_response(labels.get(status, f"{status} Error"), payload,
                         [("Cache-Control", "no-store"), ("X-Content-Type-Options", "nosniff")])


def _rollback_benchmark(connection, count):
    """Exercise V8 key generation and SQL inserts, then remove all rows by rollback."""
    from baas_v8_handlers import _derive_ciphers, _generate_records, _insert_records
    from v2_handlers import _runtime_config

    run_id = secrets.token_hex(16)
    job_id = secrets.token_hex(16)
    request_id = secrets.token_hex(8)
    label = "[bench:%s]V8 rollback test" % run_id
    phase = "lookup"
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM tenants WHERE id=1 AND status='active' LIMIT 1")
            tenant = cursor.fetchone()
            if not tenant:
                raise RuntimeError("internal_benchmark_tenant_unavailable")
            cursor.execute("SELECT id FROM products WHERE tenant_id=1 AND status='active' ORDER BY id LIMIT 1")
            product = cursor.fetchone()
            if not product:
                raise RuntimeError("internal_benchmark_product_unavailable")
            tenant_id, product_id = int(tenant["id"]), int(product["id"])

        connection.begin()
        phase = "job_insert"
        with connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO product_key_v8_jobs(job_id,request_id,tenant_id,client_id,product_id,environment,"
                "license_mode,requested_count,chunk_size,label,max_devices,idempotency_key,request_hash,status) "
                "VALUES(%s,%s,%s,0,%s,'production','single',%s,10000,%s,1,%s,%s,'processing')",
                (job_id, request_id, tenant_id, product_id, count, label,
                 "benchmark_" + run_id, hashlib.sha256(run_id.encode("ascii")).hexdigest()),
            )
            job_row_id = int(cursor.lastrowid)
        phase = "runtime_config"
        config = _runtime_config()
        ciphers = _derive_ciphers(config)
        phase = "key_generation"
        generation_started = time.monotonic()
        records = _generate_records(tenant_id, product_id, job_id, 1, count,
                                    label, 1, None, None, ciphers)
        generation_ms = max(1, round((time.monotonic() - generation_started) * 1000))
        phase = "db_insert"
        insertion_started = time.monotonic()
        with connection.cursor() as cursor:
            _insert_records(cursor, job_row_id, records)
            cursor.execute("UPDATE product_key_v8_jobs SET processed_count=%s,succeeded_count=%s,status='completed' WHERE id=%s",
                           (count, count, job_row_id))
        insertion_ms = max(1, round((time.monotonic() - insertion_started) * 1000))
    except Exception as exc:
        connection.rollback()
        raise RuntimeError("benchmark_%s_%s" % (phase, type(exc).__name__)) from None
    finally:
        connection.rollback()

    phase = "rollback_verify"
    with connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) AS n FROM licenses WHERE tenant_id=%s AND product_id=%s AND label=%s",
                       (tenant_id, product_id, label))
        remaining_licenses = int((cursor.fetchone() or {}).get("n", 0))
        cursor.execute("SELECT COUNT(*) AS n FROM product_key_v8_jobs WHERE job_id=%s", (job_id,))
        remaining_jobs = int((cursor.fetchone() or {}).get("n", 0))
    if remaining_licenses or remaining_jobs:
        raise RuntimeError("benchmark_rollback_incomplete")
    total_ms = generation_ms + insertion_ms
    return {"count": count, "generation_ms": generation_ms, "insert_ms": insertion_ms,
            "measured_ms": total_ms, "keys_per_second": round(count * 1000 / total_ms),
            "persisted_licenses": remaining_licenses, "persisted_jobs": remaining_jobs,
            "cleanup": "transaction_rollback_verified"}


@legacy_compatible(callback_index=1, request_index=0)
def product_key_v8_worker(request_context):
    from ha_handlers import _ha_authorized_scope
    if not _ha_authorized_scope(request_context, "ha:operate"):
        return _reply(404, {"ok": False, "error": "not_found"})
    if str(request_context.get("method", "")).upper() != "POST":
        return _reply(405, {"ok": False, "error": "method_not_allowed"},)
    connection = None
    try:
        stream = request_context.get("body_stream")
        raw = stream.read(16385) if stream is not None else b""
        if len(raw) > 16384:
            return _reply(400, {"ok": False, "error": "invalid_worker_request"})
        data = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(data, dict):
            return _reply(400, {"ok": False, "error": "invalid_worker_request"})
        if "benchmark_count" in data:
            count = php_int_cast(data.get("benchmark_count"))
            if not 1 <= count <= 10000:
                return _reply(400, {"ok": False, "error": "benchmark_count_must_be_1_to_10000"})
            connection = database.connect()
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            from baas_v8_handlers import _schema_ready
            if not _schema_ready(connection):
                return _reply(503, {"ok": False, "error": "v8_migration_required"})
            started = time.monotonic()
            try:
                result = _rollback_benchmark(connection, count)
            except RuntimeError as exc:
                stage = str(exc)
                if not stage.startswith("benchmark_"):
                    stage = "benchmark_internal_error"
                return _reply(503, {"ok": False, "error": "v8_benchmark_failed", "stage": stage})
            result["wall_ms"] = max(1, round((time.monotonic() - started) * 1000))
            return _reply(200, {"ok": True, "benchmark": "v8-rollback", **result})
        budget = max(1000, min(60000, php_int_cast(data.get("budget_ms", 20000))))
        max_jobs = max(1, min(20, php_int_cast(data.get("max_jobs", 8))))
        only_job_id = str(data.get("job_id", "") or "").strip().lower()
        if only_job_id and (len(only_job_id) != 32 or any(ch not in "0123456789abcdef" for ch in only_job_id)):
            return _reply(400, {"ok": False, "error": "invalid_job_id"})
        connection = database.connect()
        from v3_handlers import _assert_write_fence
        _assert_write_fence(connection)
        from baas_v8_handlers import _schema_ready, pump_due_jobs
        if not _schema_ready(connection):
            return _reply(503, {"ok": False, "error": "v8_migration_required",
                                "required_migration": "029_product_key_issuance_v8_standalone"})
        started = time.monotonic()
        processed = pump_due_jobs(connection, budget, max_jobs, only_job_id or None)
        elapsed = max(1, round((time.monotonic() - started) * 1000))
        return _reply(200, {"ok": True, "worker": "product-key-v8-native-bulk",
                            "api_version": "baas-v8-native-bulk-v1",
                            "engine_profile": "v8-native-bulk-v1",
                            "processed_jobs": processed, "processed_job_count": len(processed),
                            "budget_ms": budget, "elapsed_ms": elapsed})
    except database.DatabaseConfigurationError:
        return _reply(503, {"ok": False, "error": "v8_worker_failed",
                            "request_id": secrets.token_hex(8)})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {"ok": False, "error": "v8_worker_failed",
                            "request_id": secrets.token_hex(8)})
    finally:
        if connection:
            connection.close()
