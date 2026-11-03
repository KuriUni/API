"""Python equivalents of the shared PHP administrator passkey auth helpers."""
import base64
from file_locking import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time

from passkey_handlers import _key, _read_store, _store_path, _write_store

VALID_CLIENTS = {"admin_web", "admin_mobile", "generate_web"}
ADMIN_SCOPES = ["license:read", "license:write", "license:manage", "phone:manage",
                "admin:manage", "offline:issue", "passkey:manage",
                "tenant:read", "products:write", "licenses:read", "licenses:write"]


def _encode_token(claims):
    encoded = base64.urlsafe_b64encode(json.dumps(claims, separators=(",", ":"),
                                                 ensure_ascii=False).encode()).decode().rstrip("=")
    signature = hmac.new(_key("admin-session/v1"), encoded.encode("ascii"), hashlib.sha256).digest()
    return encoded + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")


def consume_code(code, expected_client):
    if (not re.fullmatch(r"[A-Za-z0-9_-]{20,80}", str(code or ""))
            or expected_client not in VALID_CLIENTS):
        return None
    try:
        path = _store_path()
        with open(path.with_name("passkey-store.lock"), "a+b") as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            store = _read_store(path)
            row = store.get("codes", {}).get(code)
            if (not isinstance(row, dict) or int(row.get("expires", 0)) < int(time.time())
                    or not hmac.compare_digest(expected_client, str(row.get("client", "")))):
                return None
            del store["codes"][code]
            _write_store(path, store)
            now = int(time.time())
            scopes = list(ADMIN_SCOPES)
            if expected_client == "admin_mobile":
                scopes.append("tenant:api")
            claims = {"purpose": "ha_admin", "scope": scopes, "client": expected_client,
                      "credential_id_hash": str(row.get("credential_id_hash", "")),
                      "issued_at": now, "expires": now + 300,
                      "nonce": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")}
            if expected_client in {"admin_web", "admin_mobile"}:
                host = str(row.get("return_host", ""))
                claims["return_host"] = host if host in {"2415.jp", "backup.2415.jp", "main.2415.jp"} else "2415.jp"
            return _encode_token(claims)
    except Exception:
        return None


def issue_sso_session(credential_hash, role):
    if (not re.fullmatch(r"[a-f0-9]{64}", str(credential_hash or ""))
            or role not in {"viewer", "operator", "security-admin", "ha-admin"}):
        return None
    try:
        path = _store_path()
        with open(path.with_name("passkey-store.lock"), "a+b") as lock:
            os.chmod(lock.name, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            store = _read_store(path)
            token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
            created = int(time.time())
            expires = created + 1800
            store.setdefault("sso_sessions", {})[token] = {
                "credential_id_hash": credential_hash, "role_name": role,
                "created": created, "expires": expires, "absolute_expires": created + 43200,
            }
            _write_store(path, store)
        from passkey_handlers import _audit
        _audit({}, "admin_sso_issued", {"credential_id_hash": credential_hash,
                                       "role_name": role, "expires_at": created + 43200})
        return {"token": token, "expires": expires}
    except Exception:
        return None


def issue_principal_token(credential_hash, client, ttl=300, session_metadata=None):
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        return None
    if (not isinstance(session_metadata, dict) or session_metadata.get('auth_method') != 'oidc_sso'
            or not re.fullmatch(r'[a-f0-9]{64}', str(session_metadata.get('oidc_sid') or ''))):
        return None
    if (not re.fullmatch(r"[a-f0-9]{64}", str(credential_hash or ""))
            or client != "admin_mobile" or not 15 <= ttl <= 300):
        return None
    claims = {"purpose": "ha_admin", "auth_source": "oidc_sso", "scope": list(ADMIN_SCOPES) + ["tenant:api"],
              "client": client, "credential_id_hash": credential_hash,
              "issued_at": int(time.time()), "expires": int(time.time()) + ttl,
              "nonce": base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")}
    if client == "admin_mobile":
        claims.update({"auth_method": "passkey", "sso_expires_at": 0, "sso_display_name": ""})
    if session_metadata is not None:
        if (client != "admin_mobile" or not isinstance(session_metadata, dict)
                or session_metadata.get("auth_method") != "oidc_sso"
                or not re.fullmatch(r"[a-f0-9]{64}", str(session_metadata.get("oidc_sid", "")))):
            return None
        try:
            expires_at = int(session_metadata["sso_expires_at"])
            checked_at = int(session_metadata["oidc_checked_at"])
        except (KeyError, TypeError, ValueError):
            return None
        if expires_at <= int(time.time()) or checked_at <= 0:
            return None
        claims.update({
            "auth_method": "oidc_sso", "oidc_sid": session_metadata["oidc_sid"],
            "sso_expires_at": expires_at,
            "sso_display_name": str(session_metadata.get("sso_display_name") or "SSO ID")[:200],
            "oidc_checked_at": checked_at,
            "reauthenticated_at": int(session_metadata.get('reauthenticated_at') or 0),
        })
    try:
        return _encode_token(claims)
    except Exception:
        return None
