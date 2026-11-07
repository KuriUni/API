"""Pure-Python Sunabar API emulator core for a shared-host CGI deployment."""
import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import time
import uuid
from pathlib import Path


API_KEY_TTL = 86400
LICENSE_TTL = 30 * 86400
MAX_BODY = 16384
STATE_DIR = Path(__file__).resolve().parent / ".sunabar"
sys.path.insert(0, str(Path(__file__).resolve().parent / "pymysql_vendor.zip"))
import pymysql
from pymysql.cursors import DictCursor

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS sunabar_api_keys (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        key_hash CHAR(64) NOT NULL UNIQUE,
        workspace_id CHAR(32) NOT NULL,
        scope VARCHAR(64) NOT NULL,
        created_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        revoked_at BIGINT NULL,
        INDEX idx_sunabar_key_workspace (workspace_id),
        INDEX idx_sunabar_key_expiry (expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS sunabar_licenses (
        license_id CHAR(20) NOT NULL PRIMARY KEY,
        key_hash CHAR(64) NOT NULL UNIQUE,
        workspace_id CHAR(32) NOT NULL,
        product_id INT NOT NULL,
        product_name VARCHAR(120) NOT NULL,
        license_mode VARCHAR(24) NOT NULL,
        max_devices INT NOT NULL,
        label VARCHAR(100) NOT NULL,
        issued_at BIGINT NOT NULL,
        expires_at BIGINT NOT NULL,
        status VARCHAR(16) NOT NULL DEFAULT 'active',
        INDEX idx_sunabar_license_workspace (workspace_id),
        INDEX idx_sunabar_license_status_expiry (status, expires_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
    """CREATE TABLE IF NOT EXISTS sunabar_sessions (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
        workspace_id CHAR(32) NOT NULL, license_id CHAR(20) NOT NULL,
        device_hash CHAR(64) NOT NULL, access_hash CHAR(64) NOT NULL,
        refresh_hash CHAR(64) NOT NULL, access_expires_at BIGINT NOT NULL,
        refresh_expires_at BIGINT NOT NULL, revoked_at BIGINT NULL,
        UNIQUE KEY uq_sunabar_device (workspace_id, license_id, device_hash),
        UNIQUE KEY uq_sunabar_access (access_hash),
        UNIQUE KEY uq_sunabar_refresh (refresh_hash)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""",
)
PRODUCTS = [
    {"id": 101, "code": "TUTI-DESKTOP", "name": "TUTI Desktop", "status": "active",
     "license_modes": ["single", "volume", "evaluation"]},
    {"id": 102, "code": "MNSL-CLIENT", "name": "My Number Smart Login", "status": "active",
     "license_modes": ["single", "volume"]},
    {"id": 103, "code": "SAMPLE-APP", "name": "Sample App", "status": "active",
     "license_modes": ["single", "evaluation"]},
]


class ApiError(Exception):
    def __init__(self, status, code, message=None):
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message or code.replace("_", " ")


def _b64(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64(value):
    if not isinstance(value, str) or len(value) > 4096 or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError("invalid_token")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _secret():
    if STATE_DIR.is_symlink():
        raise RuntimeError("unsafe_state_directory")
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    path = STATE_DIR / "signing.key"
    if path.is_symlink():
        raise RuntimeError("unsafe_signing_key")
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        fd = None
    if fd is not None:
        try:
            os.write(fd, secrets.token_bytes(32))
            os.fsync(fd)
        finally:
            os.close(fd)
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("unsafe_signing_key_permissions")
    raw = path.read_bytes()
    if len(raw) != 32:
        raise RuntimeError("invalid_signing_key")
    return hmac.new(raw, b"TUTI-SUNABAR-EMULATOR-v1", hashlib.sha256).digest()


def _db_connect():
    config_path = STATE_DIR / "database.json"
    if STATE_DIR.is_symlink() or config_path.is_symlink():
        raise RuntimeError("unsafe_database_config")
    info = config_path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise RuntimeError("unsafe_database_config_permissions")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or config.get("database") != "qowcpjnw_suna":
        raise RuntimeError("invalid_database_config")
    connection = pymysql.connect(
        host=str(config.get("host", "localhost")),
        port=int(config.get("port", 3306)),
        user=str(config.get("user", "")),
        password=str(config.get("password", "")),
        database="qowcpjnw_suna",
        charset="utf8mb4",
        cursorclass=DictCursor,
        connect_timeout=5,
        read_timeout=8,
        write_timeout=8,
        autocommit=False,
    )
    try:
        with connection.cursor() as cursor:
            for statement in _SCHEMA:
                cursor.execute(statement)
            cursor.execute("SHOW INDEX FROM sunabar_api_keys WHERE Key_name=%s", ("idx_sunabar_key_expiry",))
            if not cursor.fetchone():
                try:
                    cursor.execute("CREATE INDEX idx_sunabar_key_expiry ON sunabar_api_keys (expires_at)")
                except pymysql.err.Error as error:
                    # Another CGI worker may add the index at the same time.
                    if not error.args or error.args[0] != 1061:
                        raise
        connection.commit()
    except Exception:
        connection.rollback()
        connection.close()
        raise
    try:
        _maybe_cleanup_expired_api_keys(connection)
    except Exception:
        # Expiry cleanup is maintenance. A transient filesystem or DB error must
        # never turn an otherwise usable API request into an outage.
        connection.rollback()
        print("sunabar_maintenance_failed task=expired_api_keys", file=sys.stderr)
    return connection


def _maybe_cleanup_expired_api_keys(connection):
    """Delete expired key hashes at most hourly, without scheduling/cron support."""
    now = int(time.time())
    if STATE_DIR.is_symlink():
        raise RuntimeError("unsafe_state_directory")
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    lock_path = STATE_DIR / "api-key-cleanup.lock"
    state_path = STATE_DIR / "api-key-cleanup.json"
    if lock_path.is_symlink() or state_path.is_symlink():
        raise RuntimeError("unsafe_api_key_cleanup_state")
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(os.dup(fd), "r+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                last_cleanup = int(state_path.read_text(encoding="ascii").strip())
            except FileNotFoundError:
                last_cleanup = 0
            except (OSError, ValueError):
                # A damaged marker means run cleanup now and replace it atomically.
                last_cleanup = 0
            if now - last_cleanup < 3600:
                return
            with connection.cursor() as cursor:
                cursor.execute("DELETE FROM sunabar_api_keys WHERE expires_at<=%s", (now,))
            connection.commit()
            temp_path = STATE_DIR / (".api-key-cleanup-" + secrets.token_hex(8))
            temp_fd = os.open(str(temp_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.write(temp_fd, str(now).encode("ascii"))
                os.fsync(temp_fd)
            finally:
                os.close(temp_fd)
            os.replace(str(temp_path), str(state_path))
            os.chmod(state_path, 0o600)
    finally:
        os.close(fd)


def _encode(prefix, claims):
    payload = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signature = _b64(hmac.new(_secret(), (prefix + "." + payload).encode("ascii"), hashlib.sha256).digest())
    return prefix + "." + payload + "." + signature


def _decode(token, prefix, allow_expired=False):
    parts = str(token or "").split(".")
    if (len(parts) != 3 or parts[0] != prefix or
            len(parts[1]) > 4096 or re.fullmatch(r"[A-Za-z0-9_-]+", parts[1]) is None or
            re.fullmatch(r"[A-Za-z0-9_-]{43}", parts[2]) is None):
        raise ValueError("invalid_token")
    expected = _b64(hmac.new(_secret(), (parts[0] + "." + parts[1]).encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, parts[2]):
        raise ValueError("invalid_token")
    claims = json.loads(_unb64(parts[1]).decode("utf-8"))
    if not isinstance(claims, dict):
        raise ValueError("invalid_token")
    try:
        expiry = int(claims.get("exp", 0))
    except (ValueError, TypeError, OverflowError):
        raise ValueError("invalid_token") from None
    if expiry <= int(time.time()) and not allow_expired:
        raise ValueError("expired_token")
    return claims


def _limited(name, limit, window):
    now = int(time.time())
    key = hashlib.sha256(name.encode("utf-8")).hexdigest()
    if STATE_DIR.is_symlink():
        raise RuntimeError("unsafe_state_directory")
    STATE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    state = STATE_DIR / "rate.json"
    lock_path = STATE_DIR / "rate.lock"
    if state.is_symlink() or lock_path.is_symlink():
        raise RuntimeError("unsafe_rate_state")
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(os.dup(fd), "r+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                records = json.loads(state.read_text(encoding="utf-8"))
                if not isinstance(records, dict):
                    raise RuntimeError("invalid_rate_state")
            except FileNotFoundError:
                records = {}
            except (OSError, ValueError):
                raise RuntimeError("invalid_rate_state") from None
            values = [int(item) for item in records.get(key, []) if now - int(item) < window]
            if len(values) >= limit:
                return False
            values.append(now)
            records = {k: [int(item) for item in vals if now - int(item) < 86400]
                       for k, vals in records.items() if isinstance(vals, list)}
            records[key] = values
            temp = STATE_DIR / (".rate-" + secrets.token_hex(8))
            temp_fd = os.open(str(temp), os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                payload = json.dumps(records, separators=(",", ":")).encode("utf-8")
                os.write(temp_fd, payload)
                os.fsync(temp_fd)
            finally:
                os.close(temp_fd)
            os.replace(str(temp), str(state))
            os.chmod(state, 0o600)
            return True
    finally:
        os.close(fd)


def _api_key(headers, remote_addr):
    value = str(headers.get("x-sunabar-api-key", "")).strip()
    if not value:
        authorization = str(headers.get("authorization", "")).strip()
        if authorization.lower().startswith("bearer "):
            value = authorization[7:].strip()
    if not value:
        raise ApiError(401, "api_key_required", "Set X-Sunabar-API-Key or Authorization: Bearer.")
    try:
        claims = _decode(value, "sunabar_demo")
    except RuntimeError:
        raise
    except ValueError as exc:
        code = str(exc) if str(exc) == "expired_token" else "invalid_api_key"
        raise ApiError(401, code, "Sunabar API key is invalid or expired.") from None
    if claims.get("scope") != "sunabar:emulate" or re.fullmatch(r"[a-f0-9]{32}", str(claims.get("workspace", ""))) is None:
        raise ApiError(401, "invalid_api_key")
    connection = _db_connect()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT workspace_id, scope, expires_at, revoked_at FROM sunabar_api_keys WHERE key_hash=%s LIMIT 1",
                (hashlib.sha256(value.encode("ascii")).hexdigest(),),
            )
            stored = cursor.fetchone()
        if (not stored or stored["revoked_at"] is not None or
                int(stored["expires_at"]) <= int(time.time()) or
                not hmac.compare_digest(str(stored["workspace_id"]), str(claims["workspace"])) or
                stored["scope"] != "sunabar:emulate"):
            raise ApiError(401, "invalid_api_key", "Sunabar API key is invalid, expired, or revoked.")
    finally:
        connection.close()
    if not _limited("api:" + claims["workspace"] + ":" + remote_addr, 120, 60):
        raise ApiError(429, "rate_limited", "This API key reached its 120 requests/minute limit for this client.")
    return claims


def _response(status, payload, headers=()):
    phrases = {200: "OK", 201: "Created", 204: "No Content", 400: "Bad Request", 401: "Unauthorized",
               404: "Not Found", 405: "Method Not Allowed", 409: "Conflict", 413: "Content Too Large",
               415: "Unsupported Media Type", 422: "Unprocessable Content", 429: "Too Many Requests",
               500: "Internal Server Error", 503: "Service Unavailable"}
    body = b"" if status == 204 else json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    lines = ["Status: %d %s\r\n" % (status, phrases.get(status, "Error")),
             "Content-Type: application/json; charset=utf-8\r\n", "Cache-Control: no-store\r\n",
             "X-Content-Type-Options: nosniff\r\n", "Access-Control-Allow-Origin: *\r\n",
             "Access-Control-Allow-Headers: X-Sunabar-API-Key, Authorization, Content-Type\r\n",
             "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"]
    for key, value in headers:
        lines.append("%s: %s\r\n" % (key, value))
    lines.append("Content-Length: %d\r\n" % len(body))
    return "".join(lines).encode("ascii") + b"\r\n" + body


def _json_body(method, content_type, content_length, stream):
    if method != "POST":
        return {}
    if "application/json" not in (content_type or "").lower():
        raise ApiError(415, "unsupported_media_type", "Use Content-Type: application/json.")
    try:
        length = int(content_length or 0)
    except (TypeError, ValueError):
        raise ApiError(400, "invalid_content_length") from None
    if length < 0 or length > MAX_BODY:
        raise ApiError(413, "request_too_large")
    raw = stream.read(length)
    if len(raw) != length:
        raise ApiError(400, "incomplete_request_body")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ApiError(400, "invalid_json") from None
    if not isinstance(data, dict):
        raise ApiError(400, "invalid_request_shape")
    return data


def handle(method, path, headers, remote_addr, content_type, content_length, stream):
    if method == "OPTIONS":
        return _response(204, {})
    if path == "/api/v1/healthz" and method == "GET":
        connection = _db_connect()
        connection.close()
        return _response(200, {"ok": True, "api_version": "sunabar-v1",
                               "dependencies": {"database": "ok"}})
    if path in ("/api/v1/activate", "/api/v1/session/check", "/api/v1/session/refresh", "/api/v1/session/deactivate"):
        if method != "POST":
            raise ApiError(405, "method_not_allowed")
        from sunabar_sessions import handle_session
        identity = _api_key(headers, remote_addr)
        data = _json_body(method, content_type, content_length, stream)
        return handle_session(path, identity, data, _db_connect, _response, ApiError)
    if path == "/api/v1/key" and method == "POST":
        _json_body(method, content_type, content_length, stream)
        if not _limited("key:" + remote_addr, 10, 3600):
            raise ApiError(429, "rate_limited", "At most 10 API keys can be issued per hour from this address.")
        now = int(time.time())
        workspace = secrets.token_hex(16)
        key = _encode("sunabar_demo", {"v": 1, "workspace": workspace,
                                       "scope": "sunabar:emulate", "iat": now, "exp": now + API_KEY_TTL})
        connection = _db_connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO sunabar_api_keys (key_hash, workspace_id, scope, created_at, expires_at) VALUES (%s,%s,%s,%s,%s)",
                    (hashlib.sha256(key.encode("ascii")).hexdigest(), workspace,
                     "sunabar:emulate", now, now + API_KEY_TTL),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return _response(201, {"ok": True, "api_version": "sunabar-v1", "data": {
            "api_key": key, "scope": "sunabar:emulate", "key_type": "Sunabar emulator only",
            "expires_at": now + API_KEY_TTL, "expires_in": API_KEY_TTL,
            "warning": "This key cannot access production or Sandbox BaaS APIs."}})

    if path == "/api/v1/products" and method == "GET":
        _api_key(headers, remote_addr)
        return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"products": PRODUCTS}})

    if path == "/api/v1/licenses/list" and method == "GET":
        api_key = _api_key(headers, remote_addr)
        connection = _db_connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""SELECT license_id, product_id, product_name, license_mode,
                    max_devices, label, issued_at, expires_at, status FROM sunabar_licenses
                    WHERE workspace_id=%s ORDER BY issued_at DESC, license_id DESC LIMIT 100""",
                    (api_key["workspace"],))
                rows = cursor.fetchall()
            now = int(time.time())
            for row in rows:
                if row["status"] == "active" and int(row["expires_at"]) <= now:
                    row["status"] = "expired"
            return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"licenses": rows, "limit": 100}})
        finally:
            connection.close()

    if path == "/api/v1/licenses/revoke" and method == "POST":
        api_key = _api_key(headers, remote_addr)
        data = _json_body(method, content_type, content_length, stream)
        license_id = str(data.get("license_id") or "")
        if re.fullmatch(r"[a-f0-9]{20}", license_id) is None:
            raise ApiError(422, "invalid_license_id")
        connection = _db_connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT status FROM sunabar_licenses WHERE license_id=%s AND workspace_id=%s FOR UPDATE", (license_id, api_key["workspace"]))
                row = cursor.fetchone()
                if not row:
                    raise ApiError(404, "license_not_found")
                cursor.execute("UPDATE sunabar_licenses SET status='revoked' WHERE license_id=%s AND workspace_id=%s", (license_id, api_key["workspace"]))
            connection.commit()
            return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"license_id": license_id, "status": "revoked"}})
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    if path in ("/api/v1/licenses", "/api/v1/verify") and method == "POST":
        api_key = _api_key(headers, remote_addr)
        data = _json_body(method, content_type, content_length, stream)
        if path == "/api/v1/licenses":
            try:
                product_id = int(data.get("product_id"))
            except (TypeError, ValueError):
                raise ApiError(422, "invalid_product_id") from None
            product = next((item for item in PRODUCTS if item["id"] == product_id), None)
            if product is None:
                raise ApiError(404, "product_not_found")
            mode = str(data.get("license_mode", "single"))
            if mode not in product["license_modes"]:
                raise ApiError(422, "invalid_license_mode")
            try:
                max_devices = int(data.get("max_devices", 1))
            except (TypeError, ValueError):
                max_devices = 0
            if mode == "volume" and not 2 <= max_devices <= 500:
                raise ApiError(422, "invalid_max_devices")
            if mode != "volume":
                max_devices = 1
            now = int(time.time())
            claims = {"v": 1, "workspace": api_key["workspace"], "id": uuid.uuid4().hex[:20],
                      "product_id": product_id, "product_name": product["name"], "license_mode": mode,
                      "max_devices": max_devices, "label": str(data.get("label", "Sunabar sample"))[:100],
                      "iat": now, "exp": now + LICENSE_TTL}
            alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
            demo_key = "SUNABAR-" + "-".join("".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(5))
            connection = _db_connect()
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """INSERT INTO sunabar_licenses
                           (license_id, key_hash, workspace_id, product_id, product_name, license_mode,
                            max_devices, label, issued_at, expires_at, status)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'active')""",
                        (claims["id"], hashlib.sha256(demo_key.encode("ascii")).hexdigest(),
                         claims["workspace"], product_id, product["name"], mode, max_devices,
                         claims["label"], now, claims["exp"]),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
            return _response(201, {"ok": True, "api_version": "sunabar-v1", "data": {"license": {
                "license_id": claims["id"], "license_key": demo_key, "product_key": demo_key, "product_id": product_id,
                "product_name": product["name"], "license_mode": mode, "max_devices": max_devices,
                "label": claims["label"], "status": "active", "expires_at": claims["exp"]}},
                "note": "Simulated only. This key cannot activate real software."})

        supplied_key = str(data.get("license_key") or data.get("product_key") or "")
        if re.fullmatch(r"SUNABAR-(?:[A-HJ-NP-Z2-9]{5}-){4}[A-HJ-NP-Z2-9]{5}", supplied_key):
            connection = _db_connect()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("""SELECT license_id, product_id, product_name, license_mode,
                        max_devices, label, expires_at, status FROM sunabar_licenses
                        WHERE key_hash=%s AND workspace_id=%s LIMIT 1""",
                        (hashlib.sha256(supplied_key.encode("ascii")).hexdigest(), api_key["workspace"]))
                    record = cursor.fetchone()
            finally:
                connection.close()
            if not record:
                return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"valid": False, "status": "not_found"}})
            if record["status"] != "active":
                return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"valid": False, "status": record["status"]}})
            try:
                requested_product = int(data.get("product_id", record["product_id"]))
            except (TypeError, ValueError):
                requested_product = 0
            if requested_product != int(record["product_id"]):
                raise ApiError(409, "product_mismatch")
            expired = int(record["expires_at"]) <= int(time.time())
            record.pop("status", None)
            return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {
                "valid": not expired, "status": "expired" if expired else "active", "license": record}})

        try:
            license_claims = _decode(supplied_key, "sunabar_license", allow_expired=True)
        except (ValueError, json.JSONDecodeError):
            return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"valid": False, "status": "not_found"}})
        if not hmac.compare_digest(str(license_claims.get("workspace", "")), str(api_key["workspace"])):
            return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"valid": False, "status": "not_found"}})
        connection = _db_connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT status FROM sunabar_licenses WHERE key_hash=%s AND license_id=%s AND workspace_id=%s LIMIT 1",
                    (hashlib.sha256(supplied_key.encode("ascii")).hexdigest(),
                     str(license_claims.get("id", "")), str(api_key["workspace"])),
                )
                stored_license = cursor.fetchone()
        finally:
            connection.close()
        if not stored_license:
            return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"valid": False, "status": "not_found"}})
        if stored_license["status"] != "active":
            return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"valid": False, "status": stored_license["status"]}})
        try:
            product_id = int(data.get("product_id", license_claims["product_id"]))
        except (TypeError, ValueError):
            product_id = 0
        if product_id != int(license_claims["product_id"]):
            raise ApiError(409, "product_mismatch")
        expired = int(license_claims.get("exp", 0)) <= int(time.time())
        return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {
            "valid": not expired, "status": "expired" if expired else "active", "license": {
                "license_id": license_claims["id"], "product_id": license_claims["product_id"],
                "product_name": license_claims["product_name"], "license_mode": license_claims["license_mode"],
                "max_devices": license_claims["max_devices"], "label": license_claims["label"],
                "expires_at": license_claims["exp"]}}})

    if path in ("/api/v1/key", "/api/v1/products", "/api/v1/licenses", "/api/v1/verify", "/api/v1/healthz", "/api/v1/licenses/list", "/api/v1/licenses/revoke"):
        raise ApiError(405, "method_not_allowed")
    raise ApiError(404, "not_found")


if __name__ == "__main__":
    import sys
    method = os.environ.get("REQUEST_METHOD", "GET").upper()
    raw_path = os.environ.get("PATH_INFO", "") or os.environ.get("REQUEST_URI", "/")
    path = raw_path.split("?", 1)[0]
    headers = {}
    for name, value in os.environ.items():
        if name.startswith("HTTP_"):
            headers[name[5:].lower().replace("_", "-")] = value
    remote_addr = os.environ.get("REMOTE_ADDR", "unknown")[:128]
    try:
        response = handle(method, path, headers, remote_addr,
                          os.environ.get("CONTENT_TYPE", ""),
                          os.environ.get("CONTENT_LENGTH", "0"), sys.stdin.buffer)
    except ApiError as exc:
        response = _response(exc.status, {"ok": False, "api_version": "sunabar-v1",
                                          "error": exc.code, "message": exc.message,
                                          "request_id": uuid.uuid4().hex[:16]})
    except Exception:
        response = _response(503, {"ok": False, "api_version": "sunabar-v1",
                                   "error": "service_unavailable",
                                   "message": "The Sunabar emulator is temporarily unavailable.",
                                   "request_id": uuid.uuid4().hex[:16]})
    sys.stdout.buffer.write(response)
