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
import time
import uuid
from pathlib import Path


API_KEY_TTL = 86400
LICENSE_TTL = 30 * 86400
MAX_BODY = 16384
STATE_DIR = Path(__file__).resolve().parent / ".sunabar"
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


def _encode(prefix, claims):
    payload = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    signature = _b64(hmac.new(_secret(), (prefix + "." + payload).encode("ascii"), hashlib.sha256).digest())
    return prefix + "." + payload + "." + signature


def _decode(token, prefix, allow_expired=False):
    parts = str(token or "").split(".")
    if len(parts) != 3 or parts[0] != prefix:
        raise ValueError("invalid_token")
    expected = _b64(hmac.new(_secret(), (parts[0] + "." + parts[1]).encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, parts[2]):
        raise ValueError("invalid_token")
    claims = json.loads(_unb64(parts[1]).decode("utf-8"))
    if not isinstance(claims, dict):
        raise ValueError("invalid_token")
    if int(claims.get("exp", 0)) <= int(time.time()) and not allow_expired:
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
                    records = {}
            except FileNotFoundError:
                records = {}
            except (OSError, ValueError, json.JSONDecodeError):
                records = {}
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
    raw = stream.read(MAX_BODY + 1)
    if len(raw) > MAX_BODY:
        raise ApiError(413, "request_too_large")
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
    if path == "/api/v1/key" and method == "POST":
        if not _limited("key:" + remote_addr, 10, 3600):
            raise ApiError(429, "rate_limited", "At most 10 API keys can be issued per hour from this address.")
        now = int(time.time())
        key = _encode("sunabar_demo", {"v": 1, "workspace": secrets.token_hex(16),
                                       "scope": "sunabar:emulate", "iat": now, "exp": now + API_KEY_TTL})
        return _response(201, {"ok": True, "api_version": "sunabar-v1", "data": {
            "api_key": key, "scope": "sunabar:emulate", "key_type": "Sunabar emulator only",
            "expires_at": now + API_KEY_TTL, "expires_in": API_KEY_TTL,
            "warning": "This key cannot access production or Sandbox BaaS APIs."}})

    if path == "/api/v1/products" and method == "GET":
        _api_key(headers, remote_addr)
        return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"products": PRODUCTS}})

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
            demo_key = _encode("sunabar_license", claims)
            return _response(201, {"ok": True, "api_version": "sunabar-v1", "data": {"license": {
                "license_id": claims["id"], "license_key": demo_key, "product_id": product_id,
                "product_name": product["name"], "license_mode": mode, "max_devices": max_devices,
                "label": claims["label"], "status": "active", "expires_at": claims["exp"]}},
                "note": "Simulated only. This key cannot activate real software."})

        try:
            license_claims = _decode(str(data.get("license_key") or ""), "sunabar_license", allow_expired=True)
        except (ValueError, RuntimeError, json.JSONDecodeError):
            return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"valid": False, "status": "not_found"}})
        if not hmac.compare_digest(str(license_claims.get("workspace", "")), str(api_key["workspace"])):
            return _response(200, {"ok": True, "api_version": "sunabar-v1", "data": {"valid": False, "status": "not_found"}})
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

    if path in ("/api/v1/key", "/api/v1/products", "/api/v1/licenses", "/api/v1/verify"):
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
