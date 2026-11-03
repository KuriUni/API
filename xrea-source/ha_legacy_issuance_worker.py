"""Python workers for already queued V4 and V5 issuance jobs."""
import base64
import hashlib
import json
import secrets
import time

from core import (
    license_key_hash, normalize_license_key, offline_lookup,
    offline_secret, offline_secret_encrypt, token_secret,
)

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
V4_PROFILE = "adaptive-throughput-v2"
V5_PROFILE = "native-bulk-x20-v2"


def _value(row):
    return next(iter(row.values())) if isinstance(row, dict) else row[0]


def _schema_missing(connection, version):
    if version == "v4":
        tables = ("product_key_issue_jobs_v4", "product_key_issue_v4_items")
        columns = (("product_key_issue_jobs_v4", "speed_tier"),
                   ("product_key_issue_jobs_v4", "queue_priority"))
    else:
        tables = ("product_key_issue_jobs_v5", "product_key_issue_v5_items",
                  "product_key_issue_plans_v5")
        columns = ()
    missing = []
    with connection.cursor() as cursor:
        for table in tables:
            cursor.execute("SELECT COUNT(*) AS n FROM information_schema.tables "
                           "WHERE table_schema=DATABASE() AND table_name=%s", (table,))
            if int(_value(cursor.fetchone())) == 0:
                missing.append(table)
        for table, column in columns:
            cursor.execute("SELECT COUNT(*) AS n FROM information_schema.columns "
                           "WHERE table_schema=DATABASE() AND table_name=%s AND column_name=%s",
                           (table, column))
            if int(_value(cursor.fetchone())) == 0:
                missing.append(table + "." + column)
    return missing


def _product_key():
    return "-".join("".join(secrets.choice(ALPHABET) for _ in range(5)) for _ in range(5))


def _seal(config, version, job_id, item_no, product_key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    secret = token_secret(config)
    storage_key = hashlib.sha256((f"TUTI-BAAS-PK-ISSUANCE-{version.upper()}|" + secret).encode()).digest()
    iv = secrets.token_bytes(12)
    aad = f"{version}|{job_id}|{item_no}".encode()
    encrypted = AESGCM(storage_key).encrypt(iv, product_key.encode(), aad)
    raw = iv + encrypted[-16:] + encrypted[:-16]
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def open_sealed_key(config, version, job_id, item_no, encoded):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    if len(raw) < 29:
        raise ValueError(version + "_secret_invalid")
    secret = token_secret(config)
    storage_key = hashlib.sha256((f"TUTI-BAAS-PK-ISSUANCE-{version.upper()}|" + secret).encode()).digest()
    plaintext = AESGCM(storage_key).decrypt(
        raw[:12], raw[28:] + raw[12:28], f"{version}|{job_id}|{item_no}".encode())
    if not plaintext:
        raise ValueError(version + "_secret_invalid")
    return plaintext.decode("utf-8")


def _insert_result_rows(cursor, version, rows):
    table = f"product_key_issue_{version}_items"
    for offset in range(0, len(rows), 1000):
        batch = rows[offset:offset + 1000]
        cursor.executemany(
            f"INSERT INTO `{table}`(job_row_id,item_no,license_id,key_fingerprint,product_key_enc) "
            "VALUES(%s,%s,%s,%s,%s)", batch)


def _insert_v4_chunk(cursor, connection, config, job, count):
    rows = []
    insert_sql = ("INSERT INTO licenses(tenant_id,product_id,key_hash,label,active,max_devices,"
                  "evaluation_days,expires_at,offline_lookup,offline_secret_enc) "
                  "VALUES(%s,%s,%s,%s,1,%s,%s,%s,%s,%s)")
    first_item = int(job["next_item_no"])
    base_label = str(job.get("label") or "").strip()
    for batch_start in range(0, count, 500):
        batch_count = min(500, count - batch_start)
        for attempt in range(4):
            metadata, license_values = [], []
            seen = set()
            for offset in range(batch_count):
                item_no = first_item + batch_start + offset
                candidate = _product_key()
                key_hash = license_key_hash(config, candidate)
                while key_hash in seen:
                    candidate = _product_key()
                    key_hash = license_key_hash(config, candidate)
                seen.add(key_hash)
                offline = offline_secret(candidate)
                label = base_label or f"BaaS v4 job {str(job['job_id'])[:8]} #{item_no}"
                license_values.append((int(job["tenant_id"]), int(job["product_id"]),
                    key_hash, label, int(job["max_devices"]), job.get("evaluation_days"),
                    job.get("expires_at"), offline_lookup(offline),
                    offline_secret_encrypt(config, offline)))
                metadata.append((item_no, candidate, key_hash))
            try:
                cursor.executemany(insert_sql, license_values)
            except Exception as exc:
                code = getattr(exc, "args", (None,))[0]
                if code not in (1062, "1062") or attempt == 3:
                    if code in (1062, "1062"):
                        raise RuntimeError("product_key_generation_failed") from exc
                    raise
                continue

            placeholders = ",".join(["%s"] * len(metadata))
            cursor.execute("SELECT id,key_hash FROM licenses WHERE key_hash IN (" + placeholders + ")",
                           tuple(entry[2] for entry in metadata))
            id_map = {str(row["key_hash"]): int(row["id"]) for row in cursor.fetchall()}
            if len(id_map) != len(metadata):
                raise RuntimeError("v4_license_id_resolution_failed")
            for item_no, candidate, key_hash in metadata:
                fingerprint = hashlib.sha256(normalize_license_key(candidate).encode()).hexdigest()
                rows.append((int(job["id"]), item_no, id_map[key_hash], fingerprint,
                             _seal(config, "v4", str(job["job_id"]), item_no, candidate)))
            break
    _insert_result_rows(cursor, "v4", rows)
    return len(rows)


def _insert_v5_chunk(cursor, config, job, count):
    results = []
    seen = set()
    base_label = str(job.get("label") or "").strip()
    first_item = int(job["next_item_no"])
    storage_key = hashlib.sha256(
        ("TUTI-BAAS-PK-ISSUANCE-V5|" + token_secret(config)).encode()).digest()
    offline_key = hashlib.sha256(("offline-storage|" + token_secret(config)).encode()).digest()

    # V5 writes license rows and result rows in bounded multi-row batches.
    for chunk_offset in range(0, count, 1000):
        take = min(1000, count - chunk_offset)
        license_rows = []
        metadata = []
        for offset in range(take):
            item_no = first_item + chunk_offset + offset
            candidate = _product_key()
            key_hash = license_key_hash(config, candidate)
            attempts = 1
            while key_hash in seen and attempts < 4:
                candidate = _product_key()
                key_hash = license_key_hash(config, candidate)
                attempts += 1
            if key_hash in seen:
                raise RuntimeError("product_key_generation_failed")
            seen.add(key_hash)
            offline = offline_secret(candidate)
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            iv = secrets.token_bytes(12)
            offline_enc = base64.urlsafe_b64encode(
                iv + (lambda value: value[-16:] + value[:-16])(
                    AESGCM(offline_key).encrypt(iv, offline, b"TUTI-OFFLINE-V1"))
            ).decode("ascii").rstrip("=")
            label = base_label or f"BaaS v5 {str(job['job_id'])[:8]} #{item_no}"
            license_rows.append((int(job["tenant_id"]), int(job["product_id"]), key_hash, label,
                                 int(job["max_devices"]), job.get("evaluation_days"),
                                 job.get("expires_at"), offline_lookup(offline), offline_enc))
            key_iv = secrets.token_bytes(12)
            sealed = AESGCM(storage_key).encrypt(
                key_iv, candidate.encode(), f"v5|{job['job_id']}|{item_no}".encode())
            key_enc = base64.urlsafe_b64encode(key_iv + sealed[-16:] + sealed[:-16]).decode().rstrip("=")
            metadata.append((item_no, candidate, key_hash,
                             hashlib.sha256(normalize_license_key(candidate).encode()).hexdigest(), key_enc))

        placeholders = ",".join(["(%s,%s,%s,%s,1,%s,%s,%s,%s,%s)"] * len(license_rows))
        params = tuple(value for row in license_rows for value in row)
        cursor.execute("INSERT INTO licenses(tenant_id,product_id,key_hash,label,active,max_devices,"
                       "evaluation_days,expires_at,offline_lookup,offline_secret_enc) VALUES " + placeholders, params)
        first_id = int(getattr(cursor, "lastrowid", 0) or 0)
        id_map = {}
        if first_id > 0:
            cursor.execute("SELECT id,key_hash FROM licenses WHERE tenant_id=%s AND id BETWEEN %s AND %s ORDER BY id ASC",
                           (int(job["tenant_id"]), first_id, first_id + len(metadata) - 1))
            for row in cursor.fetchall():
                if str(row["key_hash"]) in seen:
                    id_map[str(row["key_hash"])] = int(row["id"])
        missing_hashes = [str(row[2]) for row in metadata if str(row[2]) not in id_map]
        for offset in range(0, len(missing_hashes), 500):
            group = missing_hashes[offset:offset + 500]
            if not group:
                continue
            cursor.execute("SELECT id,key_hash FROM licenses WHERE key_hash IN (" +
                           ",".join(["%s"] * len(group)) + ")", tuple(group))
            for row in cursor.fetchall():
                id_map[str(row["key_hash"])] = int(row["id"])
        for item_no, candidate, key_hash, fingerprint, key_enc in metadata:
            license_id = id_map.get(key_hash)
            if not license_id:
                raise RuntimeError("v5_license_id_resolution_failed")
            results.append((int(job["id"]), item_no, license_id, fingerprint, key_enc))
    _insert_result_rows(cursor, "v5", results)
    return len(results)


def _process_chunk(connection, version, job, count, config):
    connection.begin()
    try:
        with connection.cursor() as cursor:
            if version == "v4":
                cursor.execute("SELECT max_licenses FROM tenants WHERE id=%s AND status='active' FOR UPDATE",
                               (int(job["tenant_id"]),))
                tenant = cursor.fetchone()
                if not tenant:
                    raise RuntimeError("tenant_not_found_or_inactive")
                cursor.execute("SELECT COUNT(*) AS n FROM licenses WHERE tenant_id=%s AND deleted_at IS NULL",
                               (int(job["tenant_id"]),))
                current = int(cursor.fetchone()["n"])
                maximum = int(tenant["max_licenses"])
                if current + count > maximum:
                    raise RuntimeError("license_quota_exceeded")
                cursor.execute("SELECT id FROM products WHERE id=%s AND tenant_id=%s AND status='active' LIMIT 1 FOR UPDATE",
                               (int(job["product_id"]), int(job["tenant_id"])))
                if not cursor.fetchone():
                    raise RuntimeError("product_not_found")
                made = _insert_v4_chunk(cursor, connection, config, job, count)
            else:
                cursor.execute("SELECT 1 FROM tenants WHERE id=%s AND status='active' LIMIT 1",
                               (int(job["tenant_id"]),))
                if not cursor.fetchone():
                    raise RuntimeError("tenant_not_found_or_inactive")
                cursor.execute("SELECT 1 FROM products WHERE id=%s AND tenant_id=%s AND status='active' LIMIT 1",
                               (int(job["product_id"]), int(job["tenant_id"])))
                if not cursor.fetchone():
                    raise RuntimeError("product_not_found")
                made = _insert_v5_chunk(cursor, config, job, count)

            processed = int(job["processed_count"]) + made
            done = processed >= int(job["requested_count"])
            table = f"product_key_issue_jobs_{version}"
            cursor.execute(f"UPDATE `{table}` SET processed_count=%s,succeeded_count=succeeded_count+%s,"
                           "next_item_no=%s,heartbeat_at=UTC_TIMESTAMP(),status=%s,"
                           "completed_at=CASE WHEN %s=1 THEN UTC_TIMESTAMP() ELSE completed_at END WHERE id=%s",
                           (processed, made, int(job["next_item_no"]) + made,
                            "completed" if done else "processing", 1 if done else 0, int(job["id"])))
        if done:
            from baas_handlers import _queue_webhook
            payload = {"job_id": str(job["job_id"]), "count": int(job["requested_count"]),
                       "product_id": int(job["product_id"]), "api_version": version}
            if version == "v5":
                payload["engine_profile"] = str(job.get("engine_profile") or V5_PROFILE)
            _queue_webhook(connection, int(job["tenant_id"]), "license.bulk_job_completed", payload)
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def _v4_priority(job):
    if job.get("queue_priority") is not None:
        return max(1, int(job["queue_priority"]))
    tier = str(job.get("speed_tier") or "").lower().strip()
    priorities = {"light": 10, "middle": 20, "high": 30, "max": 40,
                  "maxx5": 50, "max10": 60, "max20": 70}
    if tier in priorities:
        return priorities[tier]
    chunk = int(job.get("chunk_size") or 1)
    return 10 if chunk <= 100 else 20 if chunk <= 250 else 30 if chunk <= 400 else 40 if chunk <= 500 else 50 if chunk <= 2500 else 60 if chunk <= 5000 else 70


def _v4_speed_surcharge(job):
    tier = str(job.get("speed_tier") or "").lower().strip()
    count = max(1, min(10000, int(job.get("requested_count") or 1)))
    tiers = {
        "light": (min(100, count), "1x", "Light", 1.0, 10000, 10),
        "middle": (min(250, count), "1_5x", "Middle", 1.5, 15000, 20),
        "high": (min(400, count), "2x", "High", 2.0, 20000, 30),
        "max": (min(500, count), "3x", "Max", 3.0, 30000, 40),
        "maxx5": (min(2500, count), "5x", "Maxx5", 5.0, 50000, 50),
        "max10": (min(5000, count), "10x", "Max10", 10.0, 100000, 60),
        "max20": (count, "20x", "Max20", 20.0, 200000, 70),
    }
    if tier in tiers:
        chunk, code, label, multiplier, basis, priority = tiers[tier]
        result = {"code": code, "label": label, "multiplier": multiplier,
                  "multiplier_basis_points": basis, "priority": priority, "chunk": chunk}
        return result
    else:
        chunk = max(1, int(job.get("chunk_size") or 1))
        if chunk <= 100:
            code, label, multiplier, basis, priority = "1x", "Light", 1.0, 10000, 10
        elif chunk <= 250:
            code, label, multiplier, basis, priority = "1_5x", "Middle", 1.5, 15000, 20
        elif chunk <= 400:
            code, label, multiplier, basis, priority = "2x", "High", 2.0, 20000, 30
        elif chunk <= 500:
            code, label, multiplier, basis, priority = "3x", "Max", 3.0, 30000, 40
        elif chunk <= 2500:
            code, label, multiplier, basis, priority = "5x", "Maxx5", 5.0, 50000, 50
        elif chunk <= 5000:
            code, label, multiplier, basis, priority = "10x", "Max10", 10.0, 100000, 60
        else:
            code, label, multiplier, basis, priority = "20x", "Max20", 20.0, 200000, 70
    return {"code": code, "label": label, "multiplier": multiplier,
            "multiplier_basis_points": basis, "priority": priority}


def _v4_max_chunks(job):
    tier = str(job.get("speed_tier") or "").lower().strip()
    if tier in {"light": 4, "middle": 6, "high": 8, "max": 12,
                "maxx5": 4, "max10": 2, "max20": 1}:
        return {"light": 4, "middle": 6, "high": 8, "max": 12,
                "maxx5": 4, "max10": 2, "max20": 1}[tier]
    chunk = int(job.get("chunk_size") or 1)
    if chunk <= 100:
        return 4
    if chunk <= 250:
        return 6
    if chunk <= 400:
        return 8
    if chunk <= 500:
        return 12
    if chunk <= 2500:
        return 4
    if chunk <= 5000:
        return 2
    return 1


def _v4_higher_priority(connection, job):
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 FROM product_key_issue_jobs_v4 WHERE id<>%s AND status='queued' "
                       "AND queue_priority>%s ORDER BY queue_priority DESC,created_at ASC LIMIT 1",
                       (int(job["id"]), _v4_priority(job)))
        return bool(cursor.fetchone())


def _public_job(version, job):
    requested = max(1, int(job.get("requested_count") or 1))
    status = str(job.get("status") or "unknown")
    terminal = status in {"completed", "failed", "cancelled"}
    def utc_text(value):
        return value.isoformat(sep=" ") if hasattr(value, "isoformat") else value

    result = {
        "job_id": str(job["job_id"]), "status": status, "terminal": terminal,
        "environment": str(job["environment"]), "product_id": int(job["product_id"]),
        "license_mode": str(job["license_mode"]), "requested_count": requested,
        "processed_count": int(job.get("processed_count") or 0),
        "succeeded_count": int(job.get("succeeded_count") or 0),
        "failed_count": int(job.get("failed_count") or 0),
        "chunk_size": int(job.get("chunk_size") or requested),
        "progress_percent": round(min(100, int(job.get("processed_count") or 0) * 100 / requested), 2),
        "next_item_no": int(job.get("next_item_no") or 1), "error_code": job.get("error_code"),
        "created_at_utc": str(job.get("created_at") or ""),
        "started_at_utc": utc_text(job.get("started_at")),
        "heartbeat_at_utc": utc_text(job.get("heartbeat_at")),
        "completed_at_utc": utc_text(job.get("completed_at")),
    }
    if version == "v4":
        result.update({"speed_tier": job.get("speed_tier"), "speed_surcharge": _v4_speed_surcharge(job),
                       "queue_priority": _v4_priority(job),
                       "preemption_policy": "chunk-boundary", "worker_profile": V4_PROFILE,
                       "preemptions": int(job.get("preemptions") or 0),
                       "last_preempted_at_utc": utc_text(job.get("last_preempted_at")),
                       "poll_after_ms": 0 if terminal else 800})
    else:
        result.update({"engine_profile": str(job.get("engine_profile") or V5_PROFILE),
                       "poll_after_ms": 0 if terminal else 100})
    return result


def _mark_failed(connection, version, job_id, error):
    table = f"product_key_issue_jobs_{version}"
    with connection.cursor() as cursor:
        cursor.execute(f"UPDATE `{table}` SET status='failed',"
                       "failed_count=GREATEST(failed_count,requested_count-processed_count),"
                       "error_code=%s,heartbeat_at=UTC_TIMESTAMP(),completed_at=UTC_TIMESTAMP() "
                       "WHERE id=%s AND status NOT IN ('completed','cancelled')",
                       (str(error)[:80], int(job_id)))
    connection.commit()


def _process_job(connection, version, job_id, budget_ms, max_chunks):
    table = f"product_key_issue_jobs_{version}"
    lock_name = f"tuti:baas-{version}:job:{job_id}"
    with connection.cursor() as cursor:
        cursor.execute("SELECT GET_LOCK(%s,0)", (lock_name,))
        locked = cursor.fetchone()
    if not locked or int(_value(locked)) != 1:
        return None
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM `{table}` WHERE job_id=%s LIMIT 1", (job_id,))
            job = cursor.fetchone()
        if not job:
            return None
        if str(job["status"]) in {"completed", "failed", "cancelled"}:
            return job
        if str(job["status"]) == "cancel_requested":
            with connection.cursor() as cursor:
                cursor.execute(f"UPDATE `{table}` SET status='cancelled',completed_at=UTC_TIMESTAMP(),"
                               "heartbeat_at=UTC_TIMESTAMP() WHERE id=%s", (int(job["id"]),))
                cursor.execute(f"SELECT * FROM `{table}` WHERE id=%s", (int(job["id"]),))
                job = cursor.fetchone() or job
            connection.commit()
            return job
        if version == "v4" and _v4_higher_priority(connection, job):
            with connection.cursor() as cursor:
                cursor.execute("UPDATE product_key_issue_jobs_v4 SET status='queued',preemptions=preemptions+1,"
                               "last_preempted_at=UTC_TIMESTAMP(),heartbeat_at=UTC_TIMESTAMP() "
                               "WHERE id=%s AND status='processing'", (int(job["id"]),))
                cursor.execute("SELECT * FROM product_key_issue_jobs_v4 WHERE id=%s", (int(job["id"]),))
                job = cursor.fetchone() or job
            connection.commit()
            return job
        with connection.cursor() as cursor:
            cursor.execute(f"UPDATE `{table}` SET status='processing',started_at=COALESCE(started_at,UTC_TIMESTAMP()),"
                           "heartbeat_at=UTC_TIMESTAMP() WHERE id=%s AND status IN ('queued','processing')",
                           (int(job["id"]),))
        connection.commit()
        from v2_handlers import _runtime_config
        config = _runtime_config()
        started, chunks = time.monotonic(), 0
        while chunks < max_chunks and (time.monotonic() - started) * 1000 < budget_ms:
            with connection.cursor() as cursor:
                cursor.execute(f"SELECT * FROM `{table}` WHERE id=%s LIMIT 1", (int(job["id"]),))
                job = cursor.fetchone()
            if not job:
                return None
            if str(job["status"]) == "cancel_requested":
                with connection.cursor() as cursor:
                    cursor.execute(f"UPDATE `{table}` SET status='cancelled',completed_at=UTC_TIMESTAMP(),"
                                   "heartbeat_at=UTC_TIMESTAMP() WHERE id=%s", (int(job["id"]),))
                connection.commit()
                break
            if str(job["status"]) != "processing":
                break
            remaining = int(job["requested_count"]) - int(job["processed_count"])
            if remaining <= 0:
                with connection.cursor() as cursor:
                    cursor.execute(f"UPDATE `{table}` SET status='completed',"
                                   "completed_at=COALESCE(completed_at,UTC_TIMESTAMP()),"
                                   "heartbeat_at=UTC_TIMESTAMP() WHERE id=%s", (int(job["id"]),))
                connection.commit()
                break
            count = min(int(job["chunk_size"]), remaining)
            try:
                _process_chunk(connection, version, job, count, config)
                chunks += 1
            except Exception as exc:
                connection.rollback()
                _mark_failed(connection, version, int(job["id"]), str(exc) or version + "_chunk_failed")
                break
            if version == "v4":
                with connection.cursor() as cursor:
                    cursor.execute("SELECT * FROM product_key_issue_jobs_v4 WHERE id=%s", (int(job["id"]),))
                    after = cursor.fetchone()
                if after and _v4_higher_priority(connection, after):
                    with connection.cursor() as cursor:
                        cursor.execute("UPDATE product_key_issue_jobs_v4 SET status='queued',"
                                       "preemptions=preemptions+1,last_preempted_at=UTC_TIMESTAMP(),"
                                       "heartbeat_at=UTC_TIMESTAMP() WHERE id=%s AND status='processing'",
                                       (int(job["id"]),))
                    connection.commit()
                    break
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM `{table}` WHERE job_id=%s LIMIT 1", (job_id,))
            return cursor.fetchone() or job
    finally:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT RELEASE_LOCK(%s)", (lock_name,))
        except Exception:
            pass


def _pump_v4(connection, budget_ms, max_jobs):
    with connection.cursor() as cursor:
        cursor.execute("SELECT job_id,speed_tier,chunk_size,requested_count,processed_count,queue_priority,status "
                       "FROM product_key_issue_jobs_v4 WHERE status IN ('queued','processing','cancel_requested') "
                       "ORDER BY CASE WHEN status='cancel_requested' THEN 0 ELSE 1 END,queue_priority DESC,"
                       "CASE status WHEN 'processing' THEN 0 ELSE 1 END,created_at ASC LIMIT %s", (max_jobs,))
        rows = cursor.fetchall()
    started, output = time.monotonic(), []
    fair_slice = max(1200, int(budget_ms / max(1, len(rows))))
    for row in rows:
        remaining = budget_ms - int((time.monotonic() - started) * 1000)
        if remaining <= 150:
            break
        job = _process_job(connection, "v4", str(row["job_id"]), max(250, min(remaining, fair_slice)), _v4_max_chunks(row))
        if job:
            output.append(_public_job("v4", job))
    return output


def _pump_v5(connection, budget_ms, max_jobs):
    candidate_limit = min(200, max_jobs * 5)
    with connection.cursor() as cursor:
        cursor.execute("SELECT job_id FROM product_key_issue_jobs_v5 WHERE status IN "
                       "('queued','processing','cancel_requested') ORDER BY CASE WHEN status='cancel_requested' "
                       "THEN 0 ELSE 1 END,created_at ASC LIMIT %s", (candidate_limit,))
        rows = cursor.fetchall()
    started, output = time.monotonic(), []
    for row in rows:
        if len(output) >= max_jobs:
            break
        remaining = budget_ms - int((time.monotonic() - started) * 1000)
        if remaining <= 100:
            break
        job = _process_job(connection, "v5", str(row["job_id"]), remaining, 16)
        if job:
            output.append(_public_job("v5", job))
    return output


def pump_legacy_jobs(connection, version, budget_ms, max_jobs):
    if version not in {"v4", "v5"}:
        raise ValueError("unsupported_legacy_worker")
    missing = _schema_missing(connection, version)
    if missing:
        raise RuntimeError(version + "_migration_required")
    max_jobs = max(1, min(20, int(max_jobs)))
    budget_ms = max(250, min(60000, int(budget_ms)))
    return _pump_v4(connection, budget_ms, max_jobs) if version == "v4" else _pump_v5(connection, budget_ms, max_jobs)
