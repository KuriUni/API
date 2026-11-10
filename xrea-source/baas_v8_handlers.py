"""Independent V8 product-key issuance pipeline.

This module does not call V1–V7 issuance handlers or use their job/result
tables. It writes the canonical licenses table, with its own V8 job store,
high-throughput key-material preparation, bounded worker, and result cipher.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
import pymysql

import database
from core import key_pepper, php_int_cast, token_secret
from http_utils import php_parse_query
from native_http import legacy_compatible
from baas_handlers import BaaSError, _authorize_key, _queue_webhook, _reply, _usage


API_VERSION = "baas-v8-native-bulk-v1"
PLATFORM_VERSION = "product-key-issuance-v8-independent-v1"
ENGINE_PROFILE = "v8-native-bulk-v1"
MAX_REQUEST = 100000
MAX_BODY = 65536
RESULT_PAGE_MAX = 1000
JOB_CHUNK_SIZE = 10000
INSERT_BATCH_SIZE = 2000
# Small batches finish faster when the submit request also runs the first
# (and usually only) bounded worker chunk. This avoids two extra HTTP round
# trips for jobs that take only a few hundred milliseconds to generate.
INLINE_COMPLETION_MAX_COUNT = 1000
INLINE_COMPLETION_BUDGET_MS = 2000
MAX_TRANSIENT_RETRIES = 5
TRANSIENT_DB_ERRORS = frozenset((1040, 1205, 1213, 2006, 2013))
_KEY_ALPHABET = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_B32_SOURCE = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
_B32_TRANSLATION = bytes.maketrans(_B32_SOURCE, _KEY_ALPHABET)
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9_-]{20,100}$")
_JOB_ID = re.compile(r"^[0-9a-f]{32}$")


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64url(value):
    raw = str(value).encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def _read_json(request_context, max_bytes=MAX_BODY):
    try:
        declared = int(request_context.get("content_length") or 0)
    except (TypeError, ValueError):
        raise ValueError('invalid_content_length') from None
    if declared < 0:
        raise ValueError('invalid_content_length')
    if declared > max_bytes:
        raise ValueError("request_too_large")
    if str(request_context.get('content_type', '')).split(';', 1)[0].strip().lower() != 'application/json':
        raise TypeError("application_json_required")
    stream = request_context.get("body_stream")
    raw = stream.read(max_bytes + 1) if stream is not None else b""
    if len(raw) > max_bytes:
        raise ValueError("request_too_large")
    try:
        data = json.loads(raw.decode("utf-8") or "{}",
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid_json") from exc
    if not isinstance(data, dict):
        raise ValueError("invalid_request")
    return data


def _query(request_context):
    return php_parse_query(request_context.get("query", ""), keep_blank_values=True)


def _job_public(row):
    requested = max(1, int(row.get("requested_count") or 1))
    status = str(row.get("status") or "unknown")
    terminal = status in {"completed", "failed", "cancelled"}
    return {
        "job_id": str(row["job_id"]), "status": status, "terminal": terminal,
        "environment": str(row["environment"]), "product_id": int(row["product_id"]),
        "license_mode": str(row["license_mode"]), "requested_count": requested,
        "processed_count": int(row.get("processed_count") or 0),
        "succeeded_count": int(row.get("succeeded_count") or 0),
        "failed_count": int(row.get("failed_count") or 0),
        "chunk_size": int(row.get("chunk_size") or JOB_CHUNK_SIZE),
        "engine_profile": ENGINE_PROFILE,
        "progress_percent": round(min(100, int(row.get("processed_count") or 0) * 100 / requested), 2),
        "error_code": row.get("error_code"),
        "retry_count": int(row.get("retry_count") or 0),
        "next_attempt_at_utc": str(row.get("next_attempt_at") or '') or None,
        "retry_after_ms": _retry_after_ms(row),
        "created_at_utc": str(row.get("created_at") or ""),
        "started_at_utc": row.get("started_at"),
        "heartbeat_at_utc": row.get("heartbeat_at"),
        "completed_at_utc": row.get("completed_at"),
        "poll_after_ms": 0 if terminal else 1500,
    }


def _retry_after_ms(row, now=None):
    value = row.get('next_attempt_at')
    if not value:
        return 0
    if isinstance(value, str):
        from py36_compat import parse_iso_datetime
        value = parse_iso_datetime(value)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return max(0, int((value - (now or datetime.now(timezone.utc))).total_seconds() * 1000))


def _transient_error(error):
    return isinstance(error, pymysql.err.OperationalError) and bool(error.args) and error.args[0] in TRANSIENT_DB_ERRORS


def _rollback(connection):
    try:
        connection.rollback()
        return True
    except pymysql.err.Error:
        # A lost connection cannot record retry state. Preserve the committed
        # job counters so the next connection can resume instead.
        return False


def _submission_identity(data, request_context):
    body = str(data.get('idempotency_key') or '').strip()
    header = str(request_context.get('header:idempotency-key') or '').strip()
    if body and header and body != header:
        raise ValueError('idempotency_key_mismatch')
    value = body or header
    if not _IDEMPOTENCY.fullmatch(value):
        raise ValueError('invalid_idempotency_key')
    mode = str(data.get('execution_mode') or 'auto').strip().lower()
    if mode not in {'auto', 'async'}:
        raise ValueError('invalid_execution_mode')
    return value, mode


def _get_job(connection, tenant_id, job_id):
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM product_key_v8_jobs WHERE tenant_id=%s AND job_id=%s LIMIT 1",
            (tenant_id, job_id),
        )
        return cursor.fetchone()


def _legacy_issuance_reserved_count(cursor, tenant_id):
    """Count queued work in every pre-V8 store while draining old jobs."""
    reserved = 0
    for table in ("product_key_issue_jobs_v4", "product_key_issue_jobs_v5"):
        cursor.execute(
            "SELECT COUNT(*) AS n FROM information_schema.tables "
            "WHERE table_schema=DATABASE() AND table_name=%s", (table,))
        exists = cursor.fetchone()
        if not exists or int(exists.get("n", 0)) == 0:
            continue
        cursor.execute(
            "SELECT COALESCE(SUM(GREATEST(requested_count-processed_count,0)),0) AS n "
            "FROM " + table + " WHERE tenant_id=%s AND status IN "
            "('queued','processing','cancel_requested')", (tenant_id,))
        reserved += int((cursor.fetchone() or {}).get("n", 0))
    # V6 (and jobs submitted by the retired V7 handler) used the unified store.
    for engine in (4, 5, 6):
        cursor.execute(
            "SELECT COALESCE(SUM(GREATEST(requested_count-processed_count,0)),0) AS n "
            "FROM issuance_jobs WHERE tenant_id=%s AND engine_version=%s AND status IN "
            "('queued','processing','cancel_requested')", (tenant_id, engine))
        reserved += int((cursor.fetchone() or {}).get("n", 0))
    return reserved


def _get_pricing(count, environment):
    from billing_policy import RULES, credit, issue_submit_units
    units = issue_submit_units(count)
    if environment == "sandbox":
        units = (units + 5) // 10
    return {"mode": RULES["mode"], "currency": "Cr", "basis": "requested_key_count",
            "requested_count": count, "charge_units": units, "charge_credit": credit(units)}


def _schema_ready(connection):
    expected = {
        "product_key_v8_jobs": {"job_id", "tenant_id", "client_id", "idempotency_key", "status", "retry_count", "next_attempt_at", "last_error_at"},
        "product_key_v8_items": {"job_row_id", "item_no", "license_id", "product_key_enc"},
    }
    with connection.cursor() as cursor:
        for table, columns in expected.items():
            cursor.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema=DATABASE() AND table_name=%s", (table,),
            )
            present = {str(row["column_name"]) for row in cursor.fetchall()}
            if not columns.issubset(present):
                return False
    return True


def _derive_ciphers(config):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    secret = token_secret(config).encode("utf-8")
    offline_key = hashlib.sha256(b"offline-storage|" + secret).digest()
    result_key = hashlib.sha256(b"TUTI-PK-ISSUANCE-V8|" + secret).digest()
    return AESGCM(offline_key), AESGCM(result_key), key_pepper(config).encode("utf-8")


def _generate_records(tenant_id, product_id, job_id, first_item, count, label,
                      max_devices, evaluation_days, expires_at, ciphers):
    """Prepare one bounded batch using block RNG and reused AES-GCM contexts."""
    offline_cipher, result_cipher, pepper = ciphers
    encoded = base64.b32encode(os.urandom(count * 20))
    offline_ivs = os.urandom(count * 12)
    result_ivs = os.urandom(count * 12)
    records = []
    for offset, block_start in enumerate(range(0, len(encoded), 32)):
        item_no = first_item + offset
        product_key = encoded[block_start:block_start + 25].translate(_B32_TRANSLATION)
        key_bytes = (product_key[:5] + b"-" + product_key[5:10] + b"-" +
                     product_key[10:15] + b"-" + product_key[15:20] + b"-" + product_key[20:25])
        key_hash = hmac.digest(pepper, key_bytes, "sha256").hex()
        fingerprint = hashlib.sha256(key_bytes).hexdigest()
        offline_secret = hashlib.sha256(b"TUTI-OFFLINE-V1|" + key_bytes).digest()
        lookup = hashlib.sha256(b"lookup|" + offline_secret).hexdigest()[:20].upper()
        offline_iv = offline_ivs[offset * 12:(offset + 1) * 12]
        offline_encrypted = offline_cipher.encrypt(offline_iv, offline_secret, b"TUTI-OFFLINE-V1")
        offline_stored = _b64url(offline_iv + offline_encrypted[-16:] + offline_encrypted[:-16])
        result_iv = result_ivs[offset * 12:(offset + 1) * 12]
        aad = ("v8|%s|%d" % (job_id, item_no)).encode("ascii")
        result_encrypted = result_cipher.encrypt(result_iv, key_bytes, aad)
        result_stored = _b64url(result_iv + result_encrypted[-16:] + result_encrypted[:-16])
        item_label = label or ("BaaS V8 %s #%d" % (job_id[:8], item_no))
        records.append({
            "item_no": item_no,
            "key_hash": key_hash,
            "fingerprint": fingerprint,
            "license_values": (tenant_id, product_id, key_hash, item_label, max_devices,
                               evaluation_days, expires_at, lookup, offline_stored),
            "product_key_enc": result_stored,
        })
    return records


def _insert_records(cursor, job_row_id, records):
    hashes = [record["key_hash"] for record in records]
    if not hashes:
        return
    cursor.executemany(
        "INSERT INTO licenses(tenant_id,product_id,key_hash,label,active,max_devices,"
        "evaluation_days,expires_at,offline_lookup,offline_secret_enc) "
        "VALUES(%s,%s,%s,%s,1,%s,%s,%s,%s,%s)",
        [record["license_values"] for record in records],
    )
    marks = ",".join(["%s"] * len(hashes))
    cursor.execute("SELECT id,key_hash FROM licenses WHERE key_hash IN (" + marks + ")", tuple(hashes))
    ids = {str(row["key_hash"]): int(row["id"]) for row in cursor.fetchall()}
    if len(ids) != len(records):
        raise RuntimeError("v8_license_id_mapping_failed")
    cursor.executemany(
        "INSERT INTO product_key_v8_items(job_row_id,item_no,license_id,key_fingerprint,product_key_enc) "
        "VALUES(%s,%s,%s,%s,%s)",
        [(job_row_id, record["item_no"], ids[record["key_hash"]],
          record["fingerprint"], record["product_key_enc"]) for record in records],
    )


def _process_chunk(connection, job, count):
    from v2_handlers import _runtime_config
    from v3_handlers import _assert_write_fence
    _assert_write_fence(connection)
    config = _runtime_config()
    ciphers = _derive_ciphers(config)
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT status,processed_count,requested_count FROM product_key_v8_jobs "
                           "WHERE id=%s FOR UPDATE", (int(job["id"]),))
            current = cursor.fetchone()
            if not current or str(current["status"]) != "processing":
                _rollback(connection)
                return
            count = min(int(count), int(current["requested_count"]) - int(current["processed_count"]))
            if count <= 0:
                _rollback(connection)
                return
            first_item = int(current["processed_count"]) + 1
            cursor.execute("SELECT 1 FROM tenants WHERE id=%s AND status='active' LIMIT 1",
                           (int(job["tenant_id"]),))
            if not cursor.fetchone():
                raise RuntimeError("tenant_not_found_or_inactive")
            cursor.execute("SELECT 1 FROM products WHERE id=%s AND tenant_id=%s AND status='active' LIMIT 1",
                           (int(job["product_id"]), int(job["tenant_id"])))
            if not cursor.fetchone():
                raise RuntimeError("product_not_found")
            remaining = count
            item_no = first_item
            while remaining:
                size = min(INSERT_BATCH_SIZE, remaining)
                records = _generate_records(
                    int(job["tenant_id"]), int(job["product_id"]), str(job["job_id"]),
                    item_no, size, str(job.get("label") or "").strip() or None,
                    int(job["max_devices"]), job.get("evaluation_days"),
                    job.get("expires_at"), ciphers,
                )
                _insert_records(cursor, int(job["id"]), records)
                item_no += size
                remaining -= size
            processed = int(current["processed_count"]) + count
            complete = processed >= int(current["requested_count"])
            cursor.execute(
                "UPDATE product_key_v8_jobs SET processed_count=%s,succeeded_count=succeeded_count+%s,"
                "heartbeat_at=UTC_TIMESTAMP(),next_attempt_at=NULL,error_code=NULL,status=%s,completed_at=CASE WHEN %s THEN UTC_TIMESTAMP() "
                "ELSE completed_at END WHERE id=%s AND status='processing'",
                (processed, count, "completed" if complete else "processing", 1 if complete else 0,
                 int(job["id"])),
            )
        if complete:
            _queue_webhook(connection, int(job["tenant_id"]), "license.bulk_job_completed", {
                "job_id": str(job["job_id"]), "count": int(job["requested_count"]),
                "product_id": int(job["product_id"]), "api_version": "v8",
                "engine_profile": ENGINE_PROFILE,
            })
        connection.commit()
    except Exception:
        _rollback(connection)
        raise


def process_job(connection, job_id, budget_ms=20000, max_chunks=8):
    job_id = str(job_id).lower()
    if not _JOB_ID.fullmatch(job_id):
        return None
    budget_ms = max(1000, min(60000, int(budget_ms)))
    max_chunks = max(1, min(20, int(max_chunks)))
    lock_name = "tuti:baas-v8:job:" + job_id
    with connection.cursor() as cursor:
        cursor.execute("SELECT GET_LOCK(%s,0)", (lock_name,))
        lock_row = cursor.fetchone()
    lock_value = (next(iter(lock_row.values())) if isinstance(lock_row, dict) else lock_row[0]) if lock_row else 0
    if int(lock_value or 0) != 1:
        busy_job = _get_job_by_id(connection, job_id)
        if busy_job:
            busy_job['_worker_busy'] = True
        return busy_job
    try:
        job = _get_job_by_id(connection, job_id)
        if not job or job["status"] in {"completed", "failed", "cancelled"}:
            return job
        if job["status"] == "cancel_requested":
            with connection.cursor() as cursor:
                cursor.execute("UPDATE product_key_v8_jobs SET status='cancelled',completed_at=UTC_TIMESTAMP(),"
                               "heartbeat_at=UTC_TIMESTAMP() WHERE id=%s AND status='cancel_requested'",
                               (int(job["id"]),))
            connection.commit()
            return _get_job_by_id(connection, job_id)
        if _retry_after_ms(job) > 0:
            return job
        with connection.cursor() as cursor:
            cursor.execute("UPDATE product_key_v8_jobs SET status='processing',"
                           "started_at=COALESCE(started_at,UTC_TIMESTAMP()),heartbeat_at=UTC_TIMESTAMP() "
                           "WHERE id=%s AND status IN ('queued','processing')", (int(job["id"]),))
        connection.commit()
        started = time.monotonic()
        chunks = 0
        while chunks < max_chunks and (time.monotonic() - started) * 1000 < budget_ms:
            job = _get_job_by_id(connection, job_id)
            if not job or job["status"] in {"completed", "failed", "cancelled"}:
                break
            if job["status"] == "cancel_requested":
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE product_key_v8_jobs SET status='cancelled',completed_at=UTC_TIMESTAMP(),"
                                   "heartbeat_at=UTC_TIMESTAMP() WHERE id=%s", (int(job["id"]),))
                connection.commit()
                break
            if _retry_after_ms(job) > 0:
                break
            remaining = int(job["requested_count"]) - int(job["processed_count"])
            if remaining <= 0:
                break
            try:
                _process_chunk(connection, job, min(int(job["chunk_size"]), remaining))
            except Exception as exc:
                if not _rollback(connection):
                    raise
                retries = int(job.get('retry_count') or 0)
                if _transient_error(exc) and retries < MAX_TRANSIENT_RETRIES:
                    delay = min(300, 5 * 2 ** retries)
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "UPDATE product_key_v8_jobs SET status='queued',retry_count=retry_count+1,"
                            "next_attempt_at=DATE_ADD(UTC_TIMESTAMP(),INTERVAL %s SECOND),"
                            "last_error_at=UTC_TIMESTAMP(),error_code='transient_database_error',heartbeat_at=UTC_TIMESTAMP() "
                            "WHERE id=%s AND status='processing'", (delay, int(job['id'])))
                    connection.commit()
                    break
                code = str(exc) if re.fullmatch(r"[a-z0-9_]{1,64}", str(exc)) else "v8_chunk_failed"
                with connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE product_key_v8_jobs SET status='failed',failed_count=GREATEST("
                        "requested_count-processed_count,0),error_code=%s,heartbeat_at=UTC_TIMESTAMP(),"
                        "completed_at=UTC_TIMESTAMP(),last_error_at=UTC_TIMESTAMP(),next_attempt_at=NULL "
                        "WHERE id=%s AND status NOT IN ('completed','cancelled','cancel_requested')",
                        (code, int(job["id"])),
                    )
                connection.commit()
                break
            chunks += 1
        return _get_job_by_id(connection, job_id)
    finally:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (lock_name,))
        except Exception:
            pass


def _get_job_by_id(connection, job_id):
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM product_key_v8_jobs WHERE job_id=%s LIMIT 1", (job_id,))
        return cursor.fetchone()


def pump_due_jobs(connection, budget_ms=50000, max_jobs=8, only_job_id=None):
    budget_ms = max(1000, min(60000, int(budget_ms)))
    max_jobs = max(1, min(20, int(max_jobs)))
    with connection.cursor() as cursor:
        if only_job_id:
            cursor.execute(
                "SELECT job_id FROM product_key_v8_jobs WHERE job_id=%s AND status IN "
                "('queued','processing','cancel_requested') AND (status='cancel_requested' OR next_attempt_at IS NULL OR next_attempt_at<=UTC_TIMESTAMP()) LIMIT 1",
                (str(only_job_id),),
            )
        else:
            cursor.execute(
                "SELECT job_id FROM product_key_v8_jobs WHERE status IN "
                "('queued','processing','cancel_requested') AND (status='cancel_requested' OR next_attempt_at IS NULL OR next_attempt_at<=UTC_TIMESTAMP()) "
                "ORDER BY CASE WHEN status='cancel_requested' THEN 0 ELSE 1 END,created_at,id LIMIT %s",
                (max_jobs * 4,),
            )
        candidates = [str(row["job_id"]) for row in cursor.fetchall()]
    started = time.monotonic()
    processed = []
    for job_id in candidates:
        remaining = budget_ms - int((time.monotonic() - started) * 1000)
        if remaining < 1000 or len(processed) >= max_jobs:
            break
        job = process_job(connection, job_id, remaining, 8)
        if job and not job.get('_worker_busy'):
            processed.append(_job_public(job))
    return processed


def queue_status(connection):
    """Read-only operational totals; never returns keys or client identifiers."""
    with connection.cursor() as cursor:
        cursor.execute("SELECT status,COUNT(*) AS jobs,"
                       "SUM(CASE WHEN next_attempt_at>UTC_TIMESTAMP() THEN 1 ELSE 0 END) AS delayed_jobs,"
                       "MAX(GREATEST(TIMESTAMPDIFF(SECOND,created_at,UTC_TIMESTAMP()),0)) AS oldest_age_seconds,"
                       "SUM(CASE WHEN status='processing' AND heartbeat_at<DATE_SUB(UTC_TIMESTAMP(),INTERVAL 5 MINUTE) THEN 1 ELSE 0 END) AS stale_jobs "
                       "FROM product_key_v8_jobs WHERE status IN ('queued','processing','cancel_requested') GROUP BY status")
        rows = cursor.fetchall()
    counts = {name: 0 for name in ('queued', 'processing', 'cancel_requested')}
    delayed = stale = oldest = 0
    for row in rows:
        counts[str(row['status'])] = int(row['jobs'])
        delayed += int(row.get('delayed_jobs') or 0)
        stale += int(row.get('stale_jobs') or 0)
        oldest = max(oldest, int(row.get('oldest_age_seconds') or 0))
    return {'counts': counts, 'active_jobs': sum(counts.values()), 'delayed_jobs': delayed,
            'stale_processing_jobs': stale, 'oldest_age_seconds': oldest,
            'max_transient_retries': MAX_TRANSIENT_RETRIES}


def _status_error(connection, status, error, request_id, headers=()):
    return _reply(status, {"ok": False, "api_version": API_VERSION,
                           "issuance_platform": PLATFORM_VERSION,
                           "error": error, "request_id": request_id}, headers)


def _preflight(connection, request_id):
    if not _schema_ready(connection):
        return _reply(503, {"ok": False, "api_version": API_VERSION,
                            "issuance_platform": PLATFORM_VERSION,
                            "error": "v8_migration_required",
                            "required_migration": "040_product_key_v8_reliability",
                            "request_id": request_id})
    return None


def _request_hash(tenant_id, product_id, count, mode, label, max_devices,
                  evaluation_days, expires_at):
    canonical = {"api_version": API_VERSION, "tenant_id": tenant_id,
                 "product_id": product_id, "count": count, "license_mode": mode,
                 "label": label, "max_devices": max_devices,
                 "evaluation_days": evaluation_days, "expires_at": expires_at}
    return hashlib.sha256(json.dumps(canonical, ensure_ascii=False,
                                    separators=(",", ":")).encode("utf-8")).hexdigest()


@legacy_compatible(callback_index=1, request_index=0)
def issuance(request_context):
    method = str(request_context.get("method", "GET"))
    if method not in {"GET", "POST"}:
        return _reply(405, {"ok": False, "error": "method_not_allowed"}, [("Allow", "GET, POST")])
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        connection = database.connect()
        preflight = _preflight(connection, rid)
        if preflight:
            return preflight
        if method == "GET":
            query = _query(request_context)
            if query.get("action", [""])[-1] == "quote":
                try:
                    count = int(query.get("count", [""])[-1])
                except (TypeError, ValueError):
                    count = 0
                if not 1 <= count <= MAX_REQUEST:
                    return _status_error(connection, 400, "invalid_issue_count", rid)
                client, headers, ip_hash = _authorize_key(connection, request_context,
                                                           "licenses:write", "licenses.v8.quote", rid)
                environment = str(client.get("tenant_environment", "unknown"))
                if environment not in {"sandbox", "production"}:
                    return _status_error(connection, 409, "tenant_environment_invalid", rid, headers)
                _usage(connection, client, "licenses.issue.v8.quote", 200, rid, ip_hash)
                return _reply(200, {"ok": True, "api_version": API_VERSION,
                                    "issuance_platform": PLATFORM_VERSION,
                                    "pricing": _get_pricing(count, environment), "request_id": rid}, headers)
            client, headers, ip_hash = _authorize_key(connection, request_context,
                                                       "licenses:write", "licenses.v8.status", rid)
            job_id = str(query.get("job_id", [""])[-1]).strip().lower()
            if not _JOB_ID.fullmatch(job_id):
                return _status_error(connection, 400, "job_id_required", rid, headers)
            job = _get_job(connection, int(client["tenant_id"]), job_id)
            if not job:
                return _status_error(connection, 404, "v8_job_not_found", rid, headers)
            _usage(connection, client, "licenses.issue.v8.status", 200, rid, ip_hash)
            return _reply(200, {"ok": True, "api_version": API_VERSION,
                                "issuance_platform": PLATFORM_VERSION, "request_id": rid,
                                "job": _job_public(job),
                                "results_endpoint": "/api/baas/v8/issuance-results.php?job_id=" + job_id}, headers)

        data = _read_json(request_context)
        client, headers, ip_hash = _authorize_key(connection, request_context,
                                                   "licenses:write", "licenses.v8.submit", rid)
        from v3_handlers import _assert_write_fence
        _assert_write_fence(connection)
        tenant_id = int(client["tenant_id"])
        count = php_int_cast(data.get("count", 1))
        product_id = php_int_cast(data.get("product_id", 0))
        if not 1 <= count <= MAX_REQUEST:
            raise ValueError("count_must_be_1_to_100000")
        if product_id < 1:
            raise ValueError("product_id_required")
        idem, execution_mode = _submission_identity(data, request_context)
        mode = str(data.get("license_mode") or "single").strip().lower()
        if mode not in {"single", "volume", "evaluation"}:
            raise ValueError("invalid_license_mode")
        label = str(data.get("label") or "").strip()[:100] or None
        max_devices = max(2, min(10000, php_int_cast(data.get("max_devices", 10)))) if mode == "volume" else 1
        evaluation_days = max(1, min(3650, php_int_cast(data.get("evaluation_days", 30)))) if mode == "evaluation" else None
        expires_at = None
        expiry_text = str(data.get("expires_at") or "").strip()
        if expiry_text and mode != "evaluation":
            from py36_compat import parse_iso_datetime
            parsed = parse_iso_datetime(expiry_text.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            if parsed.timestamp() <= time.time():
                raise ValueError("expires_at_must_be_future")
            expires_at = parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        environment = str(client.get("tenant_environment", "unknown"))
        if environment not in {"production", "sandbox"}:
            raise ValueError("tenant_environment_invalid")
        request_hash = _request_hash(tenant_id, product_id, count, mode, label,
                                     max_devices, evaluation_days, expires_at)
        with connection.cursor() as cursor:
            cursor.execute("SELECT id FROM products WHERE id=%s AND tenant_id=%s AND status='active' LIMIT 1",
                           (product_id, tenant_id))
            if not cursor.fetchone():
                raise ValueError("product_not_found")
        connection.commit()
        connection.begin()
        with connection.cursor() as cursor:
            cursor.execute("SELECT max_licenses FROM tenants WHERE id=%s AND status='active' FOR UPDATE",
                           (tenant_id,))
            tenant = cursor.fetchone()
            if not tenant:
                raise ValueError("tenant_not_found_or_inactive")
            cursor.execute("SELECT * FROM product_key_v8_jobs WHERE tenant_id=%s AND idempotency_key=%s LIMIT 1",
                           (tenant_id, idem))
            prior = cursor.fetchone()
            if prior:
                connection.commit()
                if int(prior["client_id"]) != int(client["id"]):
                    return _status_error(connection, 409, "idempotency_key_reserved_by_other_issuer", rid, headers)
                if not hmac.compare_digest(str(prior["request_hash"]), request_hash):
                    return _status_error(connection, 409, "idempotency_key_reused_with_different_request", rid, headers)
                _usage(connection, client, "licenses.issue.v8.replay", 200, rid, ip_hash)
                return _reply(200, {"ok": True, "api_version": API_VERSION,
                                    "issuance_platform": PLATFORM_VERSION, "idempotent_replay": True,
                                    "request_id": rid, "job": _job_public(prior),
                                    "status_endpoint": "/api/baas/v8/issuance.php?job_id=" + str(prior["job_id"]),
                                    "results_endpoint": "/api/baas/v8/issuance-results.php?job_id=" + str(prior["job_id"])}, headers)
            from api_usage_limits import check_monthly_limit, submit_charge_units
            check_monthly_limit(connection, tenant_id, environment, submit_charge_units(8, count, environment), rid)
            cursor.execute("SELECT COUNT(*) AS n FROM licenses WHERE tenant_id=%s AND deleted_at IS NULL",
                           (tenant_id,))
            current = int((cursor.fetchone() or {}).get("n", 0))
            cursor.execute("SELECT COALESCE(SUM(GREATEST(requested_count-processed_count,0)),0) AS n "
                           "FROM product_key_v8_jobs WHERE tenant_id=%s AND status IN "
                           "('queued','processing','cancel_requested')", (tenant_id,))
            reserved = int((cursor.fetchone() or {}).get("n", 0))
            reserved += _legacy_issuance_reserved_count(cursor, tenant_id)
            if current + reserved + count > int(tenant["max_licenses"]):
                raise ValueError("license_quota_exceeded")
            job_id = secrets.token_hex(16)
            cursor.execute(
                "INSERT INTO product_key_v8_jobs(job_id,request_id,tenant_id,client_id,product_id,environment,"
                "license_mode,requested_count,chunk_size,label,max_devices,evaluation_days,expires_at,"
                "idempotency_key,request_hash,status) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'queued')",
                (job_id, rid, tenant_id, int(client["id"]), product_id, environment, mode,
                 count, JOB_CHUNK_SIZE, label, max_devices, evaluation_days, expires_at, idem, request_hash),
            )
            job_row_id = int(cursor.lastrowid)
        connection.commit()
        from billing_policy import issue_submit_operation
        _usage(connection, client, issue_submit_operation(8, count), 202, rid, ip_hash)
        job = _get_job(connection, tenant_id, job_id)
        if count <= INLINE_COMPLETION_MAX_COUNT and execution_mode == 'auto':
            # Run only this newly-created job, with a strict budget. A worker
            # that already owns the per-job lock can continue asynchronously.
            process_job(connection, job_id, INLINE_COMPLETION_BUDGET_MS, 1)
            job = _get_job(connection, tenant_id, job_id)
        completed_inline = bool(job and str(job.get("status")) == "completed")
        return _reply(200 if completed_inline else 202, {"ok": True, "api_version": API_VERSION,
                            "issuance_platform": PLATFORM_VERSION,
                            "execution": "completed_inline" if completed_inline else "async",
                            "pricing": _get_pricing(count, environment), "request_id": rid,
                            "job": _job_public(job),
                            "status_endpoint": "/api/baas/v8/issuance.php?job_id=" + job_id,
                            "results_endpoint": "/api/baas/v8/issuance-results.php?job_id=" + job_id,
                            "cancel_endpoint": "/api/baas/v8/issuance-cancel.php"}, headers)
    except BaaSError as exc:
        if connection:
            _rollback(connection)
        return _reply(exc.status, {"ok": False, "api_version": API_VERSION,
                                  "issuance_platform": PLATFORM_VERSION, "error": exc.error,
                                  **exc.extra, "request_id": rid})
    except TypeError as exc:
        if connection:
            _rollback(connection)
        return _status_error(connection, 415, str(exc), rid)
    except (ValueError, OverflowError) as exc:
        if connection:
            _rollback(connection)
        error = str(exc) or "invalid_request"
        status = 409 if error in {"license_quota_exceeded", "tenant_not_found_or_inactive"} else 400
        return _status_error(connection, status, error, rid)
    except database.DatabaseConfigurationError:
        if connection:
            _rollback(connection)
        return _status_error(connection, 503, "service_unavailable", rid)
    except Exception:
        if connection:
            _rollback(connection)
        return _status_error(connection, 503, "v8_submission_failed", rid)
    finally:
        if connection:
            connection.close()


@legacy_compatible(callback_index=1, request_index=0)
def issuance_results(request_context):
    rid = uuid.uuid4().hex[:16]
    if str(request_context.get("method", "GET")) != "GET":
        return _reply(405, {"ok": False, "error": "method_not_allowed"}, [("Allow", "GET")])
    connection = None
    try:
        connection = database.connect()
        preflight = _preflight(connection, rid)
        if preflight:
            return preflight
        client, headers, ip_hash = _authorize_key(connection, request_context,
                                                   "licenses:write", "licenses.v8.results", rid)
        query = _query(request_context)
        job_id = str(query.get("job_id", [""])[-1]).strip().lower()
        if not _JOB_ID.fullmatch(job_id):
            return _status_error(connection, 400, "job_id_required", rid, headers)
        job = _get_job(connection, int(client["tenant_id"]), job_id)
        if not job:
            return _status_error(connection, 404, "v8_job_not_found", rid, headers)
        cursor_value = query.get("cursor", ["0"])[-1]
        limit_value = query.get("limit", ["500"])[-1]
        if not str(cursor_value).isdigit() or not str(limit_value).isdigit():
            return _status_error(connection, 400, "invalid_page", rid, headers)
        cursor_no = max(0, int(cursor_value))
        limit = max(1, min(RESULT_PAGE_MAX, int(limit_value)))
        reveal = str(query.get("reveal", ["false"])[-1]).lower() in {"1", "true", "yes"}
        with connection.cursor() as db_cursor:
            db_cursor.execute("SELECT item_no,license_id,key_fingerprint,product_key_enc,created_at "
                              "FROM product_key_v8_items WHERE job_row_id=%s AND item_no>%s "
                              "ORDER BY item_no ASC LIMIT %s", (int(job["id"]), cursor_no, limit + 1))
            rows = db_cursor.fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = []
        config = None
        if reveal:
            from v2_handlers import _runtime_config
            config = _runtime_config()
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            result_cipher = AESGCM(hashlib.sha256(
                b"TUTI-PK-ISSUANCE-V8|" + token_secret(config).encode("utf-8")).digest())
        last = cursor_no
        for row in rows:
            item_no = int(row["item_no"])
            item = {"item": item_no, "license_id": int(row["license_id"]),
                    "key_fingerprint": str(row["key_fingerprint"]),
                    "created_at_utc": str(row["created_at"])}
            if reveal:
                raw = _unb64url(row["product_key_enc"])
                plaintext = result_cipher.decrypt(raw[:12], raw[28:] + raw[12:28],
                                                   ("v8|%s|%d" % (job_id, item_no)).encode("ascii"))
                item["product_key"] = plaintext.decode("ascii")
            items.append(item)
            last = item_no
        _usage(connection, client, "licenses.issue.v8.results", 200, rid, ip_hash)
        return _reply(200, {"ok": True, "api_version": API_VERSION,
                            "issuance_platform": PLATFORM_VERSION, "request_id": rid,
                            "job": _job_public(job), "keys_revealed": reveal,
                            "items": items, "next_cursor": last if has_more else None,
                            "has_more": has_more}, headers)
    except BaaSError as exc:
        return _reply(exc.status, {"ok": False, "api_version": API_VERSION,
                                  "error": exc.error, **exc.extra, "request_id": rid})
    except database.DatabaseConfigurationError:
        return _status_error(connection, 503, "service_unavailable", rid)
    except Exception:
        return _status_error(connection, 503, "v8_results_unavailable", rid)
    finally:
        if connection:
            connection.close()


@legacy_compatible(callback_index=1, request_index=0)
def issuance_cancel(request_context):
    rid = uuid.uuid4().hex[:16]
    if str(request_context.get("method", "")) != "POST":
        return _reply(405, {"ok": False, "error": "method_not_allowed"}, [("Allow", "POST")])
    connection = None
    try:
        connection = database.connect()
        preflight = _preflight(connection, rid)
        if preflight:
            return preflight
        client, headers, ip_hash = _authorize_key(connection, request_context,
                                                   "licenses:write", "licenses.v8.cancel", rid)
        data = _read_json(request_context)
        job_id = str(data.get("job_id", "")).strip().lower()
        if not _JOB_ID.fullmatch(job_id):
            return _status_error(connection, 400, "job_id_required", rid, headers)
        job = _get_job(connection, int(client["tenant_id"]), job_id)
        if not job:
            return _status_error(connection, 404, "v8_job_not_found", rid, headers)
        if str(job["status"]) in {"completed", "failed", "cancelled"}:
            return _status_error(connection, 409, "v8_job_already_terminal", rid, headers)
        with connection.cursor() as cursor:
            cursor.execute("UPDATE product_key_v8_jobs SET status='cancel_requested',heartbeat_at=UTC_TIMESTAMP() "
                           "WHERE id=%s AND status IN ('queued','processing')", (int(job["id"]),))
        connection.commit()
        updated = _get_job(connection, int(client["tenant_id"]), job_id)
        _usage(connection, client, "licenses.issue.v8.cancel", 202, rid, ip_hash)
        return _reply(202, {"ok": True, "api_version": API_VERSION,
                            "issuance_platform": PLATFORM_VERSION, "request_id": rid,
                            "job": _job_public(updated)}, headers)
    except BaaSError as exc:
        if connection:
            _rollback(connection)
        return _reply(exc.status, {"ok": False, "api_version": API_VERSION,
                                  "error": exc.error, **exc.extra, "request_id": rid})
    except (TypeError, ValueError) as exc:
        if connection:
            _rollback(connection)
        return _status_error(connection, 400, str(exc) or "invalid_request", rid)
    except database.DatabaseConfigurationError:
        if connection:
            _rollback(connection)
        return _status_error(connection, 503, "service_unavailable", rid)
    except Exception:
        if connection:
            _rollback(connection)
        return _status_error(connection, 503, "v8_cancel_unavailable", rid)
    finally:
        if connection:
            connection.close()
