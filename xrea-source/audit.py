"""Hash-chained HA audit log compatible with ha_audit() in PHP."""
from file_locking import fcntl
import hashlib
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

APP_ROOT = Path(__file__).resolve().parent


REDACT_KEY_PARTS = (
    "token", "session", "password", "secret", "credential", "authorization",
    "cookie", "apikey", "privatekey", "signature", "auth", "dapi", "sid",
)
MAX_AUDIT_CONTEXT_BYTES = 8 * 1024
MAX_AUDIT_DEPTH = 6
MAX_AUDIT_ITEMS = 64
MAX_AUDIT_STRING = 1024


def _redact_key(key):
    normalized = "".join(char for char in str(key).casefold() if char.isalnum())
    return any(part in normalized for part in REDACT_KEY_PARTS)


def _sanitize_audit_value(value, depth=0):
    """Bound audit data and remove secrets, including nested credential fields."""
    if depth >= MAX_AUDIT_DEPTH:
        return "[maximum depth]"
    if isinstance(value, dict):
        safe = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_AUDIT_ITEMS:
                safe["_truncated"] = True
                break
            key_text = str(key)[:128]
            if _redact_key(key_text):
                safe[key_text] = "[redacted]"
            else:
                safe[key_text] = _sanitize_audit_value(item, depth + 1)
        return safe
    if isinstance(value, (list, tuple)):
        safe = [_sanitize_audit_value(item, depth + 1) for item in value[:MAX_AUDIT_ITEMS]]
        if len(value) > MAX_AUDIT_ITEMS:
            safe.append("[truncated]")
        return safe
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = str(value)
    if len(text) > MAX_AUDIT_STRING:
        return text[:MAX_AUDIT_STRING] + "[truncated]"
    return text


def _private_dir():
    raw = os.environ.get("PYTHON_MIGRATION_PRIVATE_DIR", "").strip()
    if not raw:
        raise RuntimeError("private_runtime_directory_required")
    path = Path(raw).expanduser().resolve()
    if path == APP_ROOT or APP_ROOT in path.parents:
        raise RuntimeError("private_runtime_directory_inside_webroot")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def _verify_lines(lines):
    previous = ""
    chained = 0
    for index, line in enumerate(lines, 1):
        try:
            row = json.loads(line)
        except (TypeError, ValueError):
            return {"ok": False, "error": "invalid_json", "line": index}
        if not isinstance(row, dict):
            return {"ok": False, "error": "invalid_json", "line": index}
        if "entry_hash" not in row:
            previous = hashlib.sha256(line.encode("utf-8")).hexdigest()
            continue
        entry_hash = str(row.pop("entry_hash"))
        if row.get("prev_hash", "") != previous:
            return {"ok": False, "error": "previous_hash_mismatch", "line": index}
        canonical = json.dumps(row, ensure_ascii=False, separators=(",", ":"))
        actual = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if entry_hash != actual:
            return {"ok": False, "error": "entry_hash_mismatch", "line": index}
        previous = entry_hash
        chained += 1
    return {"ok": True, "entries": len(lines), "chained_entries": chained, "last_hash": previous}


def verify_audit(path=None):
    path = Path(path) if path is not None else _private_dir() / "runtime" / "audit.log"
    if not path.is_file():
        return {"ok": True, "entries": 0, "chained_entries": 0, "last_hash": ""}
    lines = path.read_text(encoding="utf-8").splitlines()
    return _verify_lines([line for line in lines if line])


def append_event(event, context=None, ip_address="", path=None, role=None):
    """Append a redacted, chained record. Return False on unavailable storage."""
    try:
        log_path = Path(path) if path is not None else _private_dir() / "runtime" / "audit.log"
        log_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lock_path = str(log_path) + ".lock"
        with open(lock_path, "a+b") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            shared_log = open(log_path, "a+b")
            fcntl.flock(shared_log.fileno(), fcntl.LOCK_EX)
            try:
                if log_path.exists() and log_path.stat().st_size > 5 * 1024 * 1024:
                    shared_log.seek(0)
                    verify = _verify_lines([line for line in shared_log.read().decode('utf-8').splitlines() if line])
                    if verify.get("ok"):
                        stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
                        archive_name = "audit-%s.log" % stamp
                        archive = log_path.with_name(archive_name)
                        fcntl.flock(shared_log.fileno(), fcntl.LOCK_UN)
                        shared_log.close()
                        os.replace(str(log_path), str(archive))
                        shared_log = open(log_path, "a+b")
                        fcntl.flock(shared_log.fileno(), fcntl.LOCK_EX)
                        anchor = {
                            "rotated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            "archive": archive_name,
                            "entries": verify["entries"],
                            "last_hash": verify["last_hash"],
                        }
                        _atomic_json(log_path.with_name("audit-anchor.json"), anchor)
                previous = ""
                if log_path.exists():
                    shared_log.seek(0)
                    lines = [line for line in shared_log.read().decode('utf-8').splitlines() if line]
                    if lines:
                        try:
                            previous = str(json.loads(lines[-1]).get("entry_hash") or "")
                        except (ValueError, AttributeError):
                            previous = ""
                        if not previous:
                            previous = hashlib.sha256(lines[-1].encode("utf-8")).hexdigest()
                safe_context = _sanitize_audit_value(context if isinstance(context, dict) else {})
                context_json = json.dumps(safe_context, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
                if len(context_json.encode("utf-8")) > MAX_AUDIT_CONTEXT_BYTES:
                    safe_context = {"_truncated": True, "reason": "context_size_limit"}
                record = {
                    "event_id": secrets.token_hex(12),
                    "at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "event": str(event)[:128],
                    "configured_role": str(role or os.environ.get("PYTHON_MIGRATION_HA_ROLE", "unknown"))[:128],
                    "ip_hash": hashlib.sha256(str(ip_address).encode("utf-8")).hexdigest(),
                    "context": safe_context,
                    "prev_hash": previous,
                }
                canonical = json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
                record["entry_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                encoded = json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
                os.fchmod(shared_log.fileno(), 0o600)
                shared_log.seek(0, os.SEEK_END)
                shared_log.write(encoded.encode("utf-8"))
                shared_log.flush()
                os.fsync(shared_log.fileno())
                return True
            finally:
                if not shared_log.closed:
                    fcntl.flock(shared_log.fileno(), fcntl.LOCK_UN)
                    shared_log.close()
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
    except (OSError, RuntimeError, ValueError, TypeError):
        return False


def _atomic_json(path, value):
    temporary = path.with_name(path.name + ".tmp." + secrets.token_hex(6))
    data = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temporary), str(path))
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
