#!/usr/bin/env python3
"""Minimal standalone OIDC provider for https://sso.2415.jp (Python 3.6+)."""
import base64
from email.message import EmailMessage
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode
from wsgiref.simple_server import make_server


ROOT = Path(__file__).resolve().parent

# Activate the optional workspace-managed CLI only on a local checkout.
# Deployed standalone providers retain their operating-system OpenSSL.
_workspace_openssl = ROOT.parent / "tools/workspace/openssl_runtime.py"
if _workspace_openssl.is_file():
    import importlib.util as _runtime_import
    _runtime_spec = _runtime_import.spec_from_file_location("tuti_local_openssl", str(_workspace_openssl))
    _runtime_module = _runtime_import.module_from_spec(_runtime_spec)
    _runtime_spec.loader.exec_module(_runtime_module)
    _runtime_module.activate()

DATA = Path(os.environ.get("SSO_DATA_DIR", ROOT.parent.parent / ".sso-2415-data")).resolve()
DB = DATA / "sso.sqlite3"
KEY = DATA / "signing-key.pem"
EMAIL_KEY = DATA / "email-key.bin"
ISSUER = "https://sso.2415.jp"
COOKIE = "__Host-sso_session"
SESSION_TTL = 8 * 60 * 60
SESSION_IDLE_TTL = 30 * 60
CODE_TTL = 90
ACCESS_TTL = 10 * 60
PBKDF2_ROUNDS = 310_000
ADMIN_CLIENT_ID = "tuti-admin-portal"
TENANT_CLIENT_ID = "tuti-tenant-portal"
PASSKEY_RP_ID = "sso.2415.jp"
SSO_DATABASE_SCHEMA_VERSION = 5
GLOBAL_AUTH_RATE_LIMIT = 240
GLOBAL_AUTH_RATE_WINDOW = 300


def b64u(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def new_public_id():
    return "SID-" + base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=")


def new_user_handle():
    return b64u(secrets.token_bytes(32))


def b64u_decode(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise ValueError("invalid_base64url")
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def cbor_decode(data, pos=0):
    if pos >= len(data):
        raise ValueError("invalid_cbor")
    initial = data[pos]; pos += 1
    major, extra = initial >> 5, initial & 31
    if extra < 24: length = extra
    elif extra == 24: length = data[pos]; pos += 1
    elif extra == 25: length = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
    elif extra == 26: length = int.from_bytes(data[pos:pos + 4], "big"); pos += 4
    elif extra == 27: length = int.from_bytes(data[pos:pos + 8], "big"); pos += 8
    else: raise ValueError("unsupported_cbor_length")
    if major == 0: return length, pos
    if major == 1: return -1 - length, pos
    if major in (2, 3):
        end = pos + length
        if end > len(data): raise ValueError("invalid_cbor_length")
        raw = data[pos:end]
        return (raw if major == 2 else raw.decode("utf-8")), end
    if major == 4:
        result = []
        for _ in range(length):
            value, pos = cbor_decode(data, pos); result.append(value)
        return result, pos
    if major == 5:
        result = {}
        for _ in range(length):
            key, pos = cbor_decode(data, pos); value, pos = cbor_decode(data, pos); result[key] = value
        return result, pos
    if major == 7 and extra in (20, 21, 22):
        return ({20: False, 21: True, 22: None}[extra]), pos
    raise ValueError("unsupported_cbor_type")


def der_tlv(tag, value):
    length = len(value)
    if length < 128: prefix = bytes([length])
    else:
        encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
        prefix = bytes([0x80 | len(encoded)]) + encoded
    return bytes([tag]) + prefix + value


def der_integer(value):
    value = value.lstrip(b"\0")
    if not value or value[0] & 0x80: value = b"\0" + value
    return der_tlv(2, value)


def cose_public_key(cose):
    if not isinstance(cose, dict): raise ValueError("invalid_cose_key")
    if cose.get(1) == 2 and cose.get(3) == -7 and cose.get(-1) == 1:
        x, y = cose.get(-2), cose.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
            raise ValueError("invalid_es256_key")
        algorithm = der_tlv(0x30, bytes.fromhex("06072a8648ce3d0201") + bytes.fromhex("06082a8648ce3d030107"))
        point = b"\x04" + x + y
        spki = der_tlv(0x30, algorithm + der_tlv(3, b"\0" + point))
    elif cose.get(1) == 3 and cose.get(3) == -257:
        modulus, exponent = cose.get(-1), cose.get(-2)
        if not isinstance(modulus, bytes) or not isinstance(exponent, bytes): raise ValueError("invalid_rs256_key")
        rsa = der_tlv(0x30, der_integer(modulus) + der_integer(exponent))
        algorithm = bytes.fromhex("300d06092a864886f70d0101010500")
        spki = der_tlv(0x30, algorithm + der_tlv(3, b"\0" + rsa))
    else:
        raise ValueError("unsupported_passkey_algorithm")
    encoded = base64.b64encode(spki).decode("ascii")
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(encoded[i:i + 64] for i in range(0, len(encoded), 64)) + "\n-----END PUBLIC KEY-----\n"


def webauthn_client_data(encoded, expected_type, challenge):
    raw = b64u_decode(encoded)
    if len(raw) > 8192: raise ValueError("client_data_too_large")
    data = json.loads(raw.decode("utf-8"))
    if (data.get("type") != expected_type or data.get("origin") != ISSUER
            or data.get("crossOrigin") is True or not hmac.compare_digest(str(data.get("challenge", "")), challenge)):
        raise ValueError("invalid_client_data")
    return raw


def webauthn_auth_data(raw, registration=False):
    if len(raw) < 37 or not hmac.compare_digest(raw[:32], hashlib.sha256(PASSKEY_RP_ID.encode("ascii")).digest()):
        raise ValueError("invalid_rp_id")
    flags = raw[32]
    if (flags & 0x01) == 0 or (flags & 0x04) == 0:
        raise ValueError("user_verification_required")
    counter = int.from_bytes(raw[33:37], "big")
    result = {"counter": counter}
    if registration:
        if (flags & 0x40) == 0 or len(raw) < 55: raise ValueError("invalid_attested_credential")
        credential_length = int.from_bytes(raw[53:55], "big")
        credential_start = 55
        credential_end = credential_start + credential_length
        if credential_length < 16 or credential_end >= len(raw): raise ValueError("invalid_credential_id")
        cose, consumed = cbor_decode(raw, credential_end)
        if consumed != len(raw): raise ValueError("invalid_cose_trailing_data")
        result.update({"credential_id": raw[credential_start:credential_end], "public_key": cose_public_key(cose)})
    return result


def webauthn_registration(encoded_client_data, encoded_attestation, challenge, encoded_credential_id):
    client_data = webauthn_client_data(encoded_client_data, "webauthn.create", challenge)
    attestation = cbor_decode(b64u_decode(encoded_attestation))[0]
    if not isinstance(attestation, dict) or attestation.get("fmt") != "none" or attestation.get("attStmt") != {}:
        raise ValueError("attestation_must_be_none")
    auth = webauthn_auth_data(attestation.get("authData", b""), True)
    if not hmac.compare_digest(auth["credential_id"], b64u_decode(encoded_credential_id)):
        raise ValueError("credential_id_mismatch")
    return {"credential_id": b64u(auth["credential_id"]), "public_key": auth["public_key"], "counter": auth["counter"],
            "client_data": client_data}


def webauthn_assertion(encoded_client_data, encoded_auth_data, encoded_signature, challenge, public_key, old_counter, user_handle=None, expected_handle=None):
    client_data = webauthn_client_data(encoded_client_data, "webauthn.get", challenge)
    auth_raw = b64u_decode(encoded_auth_data)
    auth = webauthn_auth_data(auth_raw)
    signature = b64u_decode(encoded_signature)
    if not signature or len(signature) > 2048: raise ValueError("invalid_signature")
    if user_handle and expected_handle and not hmac.compare_digest(b64u_decode(user_handle), b64u_decode(expected_handle)):
        raise ValueError("user_handle_mismatch")
    if old_counter and auth["counter"] and auth["counter"] <= old_counter:
        raise ValueError("signature_counter_replay")
    with tempfile.NamedTemporaryFile() as key_file, tempfile.NamedTemporaryFile() as sig_file:
        key_file.write(public_key.encode("ascii")); key_file.flush()
        sig_file.write(signature); sig_file.flush()
        signed = auth_raw + hashlib.sha256(client_data).digest()
        verified = subprocess.run(["openssl", "dgst", "-sha256", "-verify", key_file.name, "-signature", sig_file.name],
                                  input=signed, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    if verified.returncode != 0: raise ValueError("signature_invalid")
    return auth["counter"]


def email_lookup(value):
    key = EMAIL_KEY.read_bytes()
    normalized = value.strip().casefold().encode("utf-8")
    return hmac.new(key[:32], b"sso-email-lookup-v1|" + normalized, hashlib.sha256).hexdigest()


def recovery_key_hash(value):
    key = EMAIL_KEY.read_bytes()
    normalized = re.sub(r"[-\s]", "", value).upper()
    return hmac.new(key[:32], b"sso-recovery-key-v1|" + normalized.encode("ascii", "ignore"), hashlib.sha256).hexdigest()


def new_recovery_certificate(public_id, now=None):
    token = "RC1-" + base64.b32encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    return {"format": "2415.jp/sso-recovery-certificate", "version": 1, "issuer": ISSUER,
            "subject": str(public_id), "issued_at": int(time.time() if now is None else now), "credential": token}


def recovery_certificate_hash(certificate, public_id):
    if not isinstance(certificate, dict) or certificate.get("format") != "2415.jp/sso-recovery-certificate" or certificate.get("version") != 1 or certificate.get("issuer") != ISSUER or certificate.get("subject") != str(public_id):
        return ""
    token = certificate.get("credential", "")
    if not isinstance(token, str) or re.fullmatch(r"RC1-[A-Z2-7]{52}", token) is None:
        return ""
    return recovery_key_hash(token)


def totp_code(secret, step):
    key = base64.b32decode(secret + "=" * ((8 - len(secret) % 8) % 8), casefold=True)
    digest = hmac.new(key, int(step).to_bytes(8, "big"), hashlib.sha1).digest()
    offset = digest[-1] & 15
    number = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000
    return "%06d" % number


def verify_totp(secret, supplied, now=None, last_step=-1):
    if not isinstance(supplied, str) or not re.fullmatch(r"[0-9]{6}", supplied):
        return None
    current = int(time.time() if now is None else now) // 30
    for step in (current - 1, current, current + 1):
        if step > int(last_step) and hmac.compare_digest(totp_code(secret, step), supplied):
            return step
    return None


def decrypt_private_value(value, purpose):
    if not isinstance(value, str) or not value.startswith("v1:"):
        raise ValueError("invalid_encrypted_value")
    key = EMAIL_KEY.read_bytes()
    packed = b64u_decode(value[3:])
    if len(packed) < 64 or (len(packed) - 48) % 16:
        raise ValueError("invalid_encrypted_value")
    iv, encrypted, supplied_mac = packed[:16], packed[16:-32], packed[-32:]
    expected_mac = hmac.new(key[:32], ("sso-private-v1|" + purpose + "|").encode("ascii") + iv + encrypted, hashlib.sha256).digest()
    if not hmac.compare_digest(supplied_mac, expected_mac):
        raise ValueError("encrypted_value_authentication_failed")
    result = subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-K", key[32:64].hex(), "-iv", iv.hex(), "-nosalt"],
                            input=encrypted, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=10)
    return result.stdout.decode("utf-8")


def encrypt_private_value(value, purpose):
    key = EMAIL_KEY.read_bytes()
    iv = secrets.token_bytes(16)
    encrypted = subprocess.run(["openssl", "enc", "-aes-256-cbc", "-K", key[32:64].hex(), "-iv", iv.hex(), "-nosalt"],
                               input=value.encode("utf-8"), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, check=True, timeout=15).stdout
    mac = hmac.new(key[:32], ("sso-private-v1|" + purpose + "|").encode("ascii") + iv + encrypted, hashlib.sha256).digest()
    return "v1:" + base64.urlsafe_b64encode(iv + encrypted + mac).decode("ascii").rstrip("=")


def recovery_code_hash(flow_hash, salt, code):
    key = EMAIL_KEY.read_bytes()
    return hmac.new(key[:32], b"sso-recovery-code-v1|" + salt + flow_hash.encode("ascii") + code.encode("ascii"), hashlib.sha256).hexdigest()


def send_recovery_code(address, code):
    if len(address) > 254 or not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", address):
        return False
    body = "SSO ID パスキー再設定\n\n確認コード: %s\n有効期限: 10分\n\n心当たりがない場合は、このメールを破棄してください。\n" % code
    message = EmailMessage()
    message["To"] = address
    message["From"] = "SSO.2415.JP <no-reply@2415.jp>"
    message["Subject"] = "SSO ID passkey reset verification code"
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(body, subtype="plain", charset="utf-8", cte="base64")
    try:
        result = subprocess.run(["/usr/sbin/sendmail", "-t", "-oi", "-f", "no-reply@2415.jp"], input=message.as_bytes(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        return result.returncode == 0
    except Exception:
        return False


def send_contractor_invite(address, code, setup_url):
    if len(address) > 254 or not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", address):
        return False
    body = ("SSO ID 登録のご案内\n\n"
            "契約者向けSSO IDの登録手続きが開始されました。\n"
            "次のページを開き、メール確認コードを入力してパスキーを登録してください。\n\n"
            + setup_url + "\n\n確認コード: " + code + "\n"
            "この案内の有効期限は24時間、確認コードは10分です。\n"
            "心当たりがない場合は、このメールを破棄してください。\n")
    message = EmailMessage()
    message["To"] = address
    message["From"] = "SSO.2415.JP <no-reply@2415.jp>"
    message["Subject"] = "SSO ID registration invitation"
    message["Auto-Submitted"] = "auto-generated"
    message.set_content(body, subtype="plain", charset="utf-8", cte="base64")
    try:
        result = subprocess.run(["/usr/sbin/sendmail", "-t", "-oi", "-f", "no-reply@2415.jp"], input=message.as_bytes(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        return result.returncode == 0
    except Exception:
        return False



@contextmanager
def db():
    con = sqlite3.connect(DB, timeout=10, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=10000")
    try:
        yield con
    finally:
        con.close()


def ensure_session_schema():
    """Add session-management data without exposing the private SSO database."""
    with db() as con:
        version = int(con.execute("PRAGMA user_version").fetchone()[0])
        if version > SSO_DATABASE_SCHEMA_VERSION:
            raise RuntimeError("database_schema_newer_than_provider")
        if version == SSO_DATABASE_SCHEMA_VERSION:
            return
        # CGI may start several workers at once. Serialize the one-time migration,
        # then recheck so waiters skip all schema inspection after the first commit.
        con.execute("BEGIN IMMEDIATE")
        version = int(con.execute("PRAGMA user_version").fetchone()[0])
        if version == SSO_DATABASE_SCHEMA_VERSION:
            con.commit()
            return
        if version > SSO_DATABASE_SCHEMA_VERSION:
            raise RuntimeError("database_schema_newer_than_provider")
        user_columns = {row[1] for row in con.execute("PRAGMA table_info(users)")}
        for name, definition in {"public_id": "TEXT", "user_handle": "TEXT", "recovery_email_hash": "TEXT NOT NULL DEFAULT ''", "tenant_id": "TEXT NOT NULL DEFAULT ''"}.items():
            if name not in user_columns:
                try: con.execute("ALTER TABLE users ADD COLUMN %s %s" % (name, definition))
                except sqlite3.OperationalError as error:
                    if "duplicate column name" not in str(error).lower(): raise
        for row in con.execute("SELECT id FROM users WHERE public_id IS NULL OR public_id='' OR user_handle IS NULL OR user_handle='' ").fetchall():
            con.execute("UPDATE users SET public_id=COALESCE(NULLIF(public_id,''),?),user_handle=COALESCE(NULLIF(user_handle,''),?) WHERE id=?",
                        (new_public_id(), new_user_handle(), row["id"]))
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_public_id ON users(public_id)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_users_recovery_email_active ON users(recovery_email_hash,active,id)")
        con.execute("CREATE TABLE IF NOT EXISTS passkeys(credential_id TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,public_key TEXT NOT NULL,sign_count INTEGER NOT NULL DEFAULT 0,transports TEXT NOT NULL DEFAULT '[]',created_at INTEGER NOT NULL,last_used INTEGER)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(user_id)")
        con.execute("CREATE TABLE IF NOT EXISTS passkey_flows(flow_hash TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,challenge TEXT NOT NULL,mode TEXT NOT NULL,expires_at INTEGER NOT NULL)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_passkey_flows_expiry ON passkey_flows(expires_at)")
        con.execute("CREATE TABLE IF NOT EXISTS totp_credentials(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,secret_encrypted TEXT NOT NULL,enabled_at INTEGER NOT NULL,last_step INTEGER NOT NULL DEFAULT -1)")
        con.execute("CREATE TABLE IF NOT EXISTS totp_setup_flows(flow_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf_hash TEXT NOT NULL,secret_encrypted TEXT NOT NULL,expires_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0)")
        con.execute("CREATE TABLE IF NOT EXISTS mfa_flows(login_flow_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0)")
        con.execute("CREATE TABLE IF NOT EXISTS registration_onboarding(session_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,request_json TEXT NOT NULL,expires_at INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS sso_schema_migrations(migration_id TEXT PRIMARY KEY,applied_at INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS global_subject_hashes(subject_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_global_subject_hashes_user ON global_subject_hashes(user_id)")
        subject_rows = con.execute("SELECT g.user_id,g.sub FROM global_subjects g JOIN users u ON u.id=g.user_id").fetchall()
        con.executemany("INSERT INTO global_subject_hashes(subject_hash,user_id) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET subject_hash=excluded.subject_hash",
                        [(hashlib.sha256((ISSUER + "\0" + str(row["sub"])).encode("utf-8")).hexdigest(), int(row["user_id"])) for row in subject_rows])
        if not con.execute("SELECT 1 FROM sso_schema_migrations WHERE migration_id='retire-totp-recovery-codes-v1'").fetchone():
            con.execute("DROP TABLE IF EXISTS totp_recovery_codes")
            con.execute("INSERT INTO sso_schema_migrations(migration_id,applied_at) VALUES('retire-totp-recovery-codes-v1',?)",(int(time.time()),))
        con.execute("CREATE INDEX IF NOT EXISTS idx_totp_setup_expiry ON totp_setup_flows(expires_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_mfa_expiry ON mfa_flows(expires_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_registration_onboarding_expiry ON registration_onboarding(expires_at)")
        flow_columns = {row[1]: row for row in con.execute("PRAGMA table_info(passkey_flows)")}
        if flow_columns.get("user_id") and flow_columns["user_id"][3]:
            # Flows are short-lived. Rebuild once so unknown IDs can receive the
            # same WebAuthn-shaped response as real IDs without a dummy account.
            flow_columns = {row[1]: row for row in con.execute("PRAGMA table_info(passkey_flows)")}
            if flow_columns.get("user_id") and flow_columns["user_id"][3]:
                con.execute("DROP TABLE passkey_flows")
                con.execute("CREATE TABLE passkey_flows(flow_hash TEXT PRIMARY KEY,user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,challenge TEXT NOT NULL,mode TEXT NOT NULL,expires_at INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS recovery_keys(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,key_hash TEXT NOT NULL,created_at INTEGER NOT NULL,used_at INTEGER,certificate_version INTEGER NOT NULL DEFAULT 0)")
        recovery_key_columns = {row[1] for row in con.execute("PRAGMA table_info(recovery_keys)")}
        if "certificate_version" not in recovery_key_columns:
            con.execute("ALTER TABLE recovery_keys ADD COLUMN certificate_version INTEGER NOT NULL DEFAULT 0")
        con.execute("CREATE TABLE IF NOT EXISTS recovery_flows(flow_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf_hash TEXT NOT NULL,code_salt TEXT NOT NULL,code_hash TEXT NOT NULL,expires_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,challenge TEXT,verified_at INTEGER,email_hash TEXT NOT NULL DEFAULT '',existing_challenge TEXT,passkey_check_status TEXT NOT NULL DEFAULT 'pending',totp_verified_at INTEGER,totp_attempts INTEGER NOT NULL DEFAULT 0,certificate_hash TEXT NOT NULL DEFAULT '')")
        recovery_columns = {row[1] for row in con.execute("PRAGMA table_info(recovery_flows)")}
        for name, definition in {"email_hash": "TEXT NOT NULL DEFAULT ''", "existing_challenge": "TEXT", "passkey_check_status": "TEXT NOT NULL DEFAULT 'pending'", "totp_verified_at": "INTEGER", "totp_attempts": "INTEGER NOT NULL DEFAULT 0", "certificate_hash": "TEXT NOT NULL DEFAULT ''"}.items():
            if name not in recovery_columns:
                con.execute("ALTER TABLE recovery_flows ADD COLUMN %s %s" % (name, definition))
        con.execute("CREATE INDEX IF NOT EXISTS idx_recovery_flows_expiry ON recovery_flows(expires_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_recovery_flows_user ON recovery_flows(user_id)")
        con.execute("CREATE TABLE IF NOT EXISTS recovery_limits(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,last_sent_at INTEGER NOT NULL DEFAULT 0,window_started INTEGER NOT NULL DEFAULT 0,sends INTEGER NOT NULL DEFAULT 0,attempt_window INTEGER NOT NULL DEFAULT 0,attempts INTEGER NOT NULL DEFAULT 0,locked_until INTEGER NOT NULL DEFAULT 0)")
        con.execute("CREATE TABLE IF NOT EXISTS recovery_email_setup(flow_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,csrf_hash TEXT NOT NULL,email_hash TEXT NOT NULL,code_salt TEXT NOT NULL,code_hash TEXT NOT NULL,expires_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_recovery_email_setup_expiry ON recovery_email_setup(expires_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_recovery_email_setup_user ON recovery_email_setup(user_id)")
        con.execute("CREATE TABLE IF NOT EXISTS contractor_invites(flow_hash TEXT PRIMARY KEY,email_lookup TEXT NOT NULL,email_encrypted TEXT NOT NULL,public_id TEXT NOT NULL,user_handle TEXT NOT NULL,code_salt TEXT NOT NULL,code_hash TEXT NOT NULL,expires_at INTEGER NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,verified_at INTEGER,passkey_challenge TEXT,created_at INTEGER NOT NULL)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_contractor_invites_expiry ON contractor_invites(expires_at)")
        invite_columns = {row[1] for row in con.execute("PRAGMA table_info(contractor_invites)")}
        if "tenant_id" not in invite_columns:
            con.execute("ALTER TABLE contractor_invites ADD COLUMN tenant_id TEXT NOT NULL DEFAULT ''")
        con.execute("CREATE INDEX IF NOT EXISTS idx_contractor_invites_email ON contractor_invites(email_lookup,created_at)")
        con.execute("CREATE TABLE IF NOT EXISTS contractor_registration_ip_events(ip_hash TEXT NOT NULL,created_at INTEGER NOT NULL)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_contractor_registration_ip_events ON contractor_registration_ip_events(ip_hash,created_at)")
        columns = {row[1] for row in con.execute("PRAGMA table_info(sessions)")}
        for name, definition in {
            "created_at": "INTEGER NOT NULL DEFAULT 0",
            "last_seen": "INTEGER NOT NULL DEFAULT 0",
            "user_agent": "TEXT NOT NULL DEFAULT ''",
            "csrf_hash": "TEXT NOT NULL DEFAULT ''",
        }.items():
            if name not in columns:
                try:
                    con.execute("ALTER TABLE sessions ADD COLUMN %s %s" % (name, definition))
                except sqlite3.OperationalError as error:
                    if "duplicate column name" not in str(error).lower():
                        raise
        con.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id,revoked_at,expires_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_created_active ON sessions(user_id,revoked_at,created_at DESC,expires_at)")
        con.execute("CREATE TABLE IF NOT EXISTS security_rate_limits(rate_key TEXT PRIMARY KEY,window_started INTEGER NOT NULL,attempts INTEGER NOT NULL)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_security_rate_limits_window ON security_rate_limits(window_started)")
        con.execute("CREATE TABLE IF NOT EXISTS security_rate_limit_maintenance(singleton INTEGER PRIMARY KEY CHECK(singleton=1),last_cleanup INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS database_maintenance(task TEXT PRIMARY KEY,last_run INTEGER NOT NULL)")
        con.execute("CREATE TABLE IF NOT EXISTS sso_admin_identity_audit(event_id TEXT PRIMARY KEY,actor_user_id INTEGER NOT NULL,action TEXT NOT NULL,target_hash TEXT NOT NULL,success INTEGER NOT NULL,created_at INTEGER NOT NULL)")
        for table, index_name, columns in (
            ("login_flows", "idx_login_flows_expiry", "expires_at"),
            ("auth_codes", "idx_auth_codes_expiry", "expires_at"),
            ("auth_codes", "idx_auth_codes_consumed", "consumed_at"),
            ("access_tokens", "idx_access_tokens_expiry", "expires_at"),
            ("sessions", "idx_sessions_expiry", "expires_at"),
            ("sessions", "idx_sessions_revoked", "revoked_at"),
            ("login_limits", "idx_login_limits_cleanup", "window_started,locked_until"),
        ):
            con.execute("CREATE INDEX IF NOT EXISTS %s ON %s(%s)" % (index_name, table, columns))
        for table in ("auth_codes", "access_tokens"):
            table_columns = {row[1] for row in con.execute("PRAGMA table_info(" + table + ")")}
            if "sid_hash" not in table_columns:
                try:
                    con.execute("ALTER TABLE " + table + " ADD COLUMN sid_hash TEXT NOT NULL DEFAULT ''")
                except sqlite3.OperationalError as error:
                    if "duplicate column name" not in str(error).lower():
                        raise
        # Tenant portal SSO uses its own OIDC client so contractor IDs never
        # pass through the administrator-only client policy. The same private
        # server credential is copied as a hash; callback URIs stay in lockstep
        # with the admin portal's already-registered exact callback list.
        admin_client = con.execute(
            "SELECT secret_hash,redirect_uri,active,created_at FROM clients WHERE client_id=?",
            (ADMIN_CLIENT_ID,),
        ).fetchone()
        if admin_client:
            tenant_client = con.execute(
                "SELECT secret_hash,redirect_uri,active,created_at FROM clients WHERE client_id=?",
                (TENANT_CLIENT_ID,),
            ).fetchone()
            admin_redirects = {row[0] for row in con.execute(
                "SELECT redirect_uri FROM client_redirect_uris WHERE client_id=?", (ADMIN_CLIENT_ID,)
            )}
            tenant_redirects = {row[0] for row in con.execute(
                "SELECT redirect_uri FROM client_redirect_uris WHERE client_id=?", (TENANT_CLIENT_ID,)
            )}
            client_values = (admin_client["secret_hash"], admin_client["redirect_uri"], admin_client["active"], admin_client["created_at"])
            tenant_values = tuple(tenant_client) if tenant_client else None
            if tenant_values != client_values or tenant_redirects != admin_redirects:
                con.execute(
                    "INSERT INTO clients(client_id,secret_hash,redirect_uri,active,created_at) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(client_id) DO UPDATE SET secret_hash=excluded.secret_hash,redirect_uri=excluded.redirect_uri,active=excluded.active,created_at=excluded.created_at",
                    (TENANT_CLIENT_ID,) + client_values,
                )
                if tenant_redirects != admin_redirects:
                    con.execute("DELETE FROM client_redirect_uris WHERE client_id=?", (TENANT_CLIENT_ID,))
                    con.executemany(
                        "INSERT INTO client_redirect_uris(client_id,redirect_uri) VALUES(?,?)",
                        [(TENANT_CLIENT_ID, uri) for uri in sorted(admin_redirects)],
                    )
        con.execute("PRAGMA user_version=%d" % SSO_DATABASE_SCHEMA_VERSION)
        con.commit()


def key_ready():
    return KEY.is_file() and KEY.stat().st_mode & 0o077 == 0


def rsa_public_jwk():
    if not key_ready():
        raise RuntimeError("signing_key_unavailable")
    der = subprocess.run(
        ["openssl", "pkey", "-in", str(KEY), "-pubout", "-outform", "DER"],
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
    ).stdout
    # DER SubjectPublicKeyInfo -> BIT STRING -> RSAPublicKey -> two INTEGERs.
    def tlv(buf, pos=0):
        tag = buf[pos]
        pos += 1
        length = buf[pos]
        pos += 1
        if length & 0x80:
            count = length & 0x7f
            length = int.from_bytes(buf[pos:pos + count], "big")
            pos += count
        return tag, buf[pos:pos + length], pos + length

    _, outer, _ = tlv(der)
    _, _, pos = tlv(outer)
    _, bit_string, _ = tlv(outer, pos)
    _, rsa, _ = tlv(bit_string[1:])
    _, modulus, pos = tlv(rsa)
    _, exponent, _ = tlv(rsa, pos)
    kid = b64u(hashlib.sha256(der).digest()[:18])
    return {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
            "n": b64u(modulus.lstrip(b"\0")), "e": b64u(exponent.lstrip(b"\0"))}


def sign_jwt(claims, jwk):
    header = b64u(json.dumps({"alg": "RS256", "typ": "JWT", "kid": jwk["kid"]}, separators=(",", ":")).encode())
    payload = b64u(json.dumps(claims, separators=(",", ":"), ensure_ascii=False).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(KEY)], input=signing_input,
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5,
    ).stdout
    return f"{header}.{payload}.{b64u(signature)}"


def readiness_checks():
    checks = {"database": "unavailable", "signing": "unavailable"}
    try:
        if not DB.is_file():
            raise RuntimeError("database_missing")
        connection = sqlite3.connect(DB.as_uri() + "?mode=rw", timeout=2, uri=True)
        try:
            for table in ("users", "clients", "auth_codes", "sessions"):
                row = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
                ).fetchone()
                if row is None:
                    raise RuntimeError("database_schema_unavailable")
            connection.execute("SELECT 1 FROM users LIMIT 0")
        finally:
            connection.close()
        checks["database"] = "ok"
    except Exception:
        pass
    try:
        now = int(time.time())
        jwk = rsa_public_jwk()
        probe = sign_jwt(
            {"iss": ISSUER, "iat": now, "exp": now + 30, "purpose": "healthz"}, jwk
        )
        if len(probe.split(".")) != 3 or not probe.rsplit(".", 1)[-1]:
            raise RuntimeError("signing_probe_failed")
        checks["signing"] = "ok"
    except Exception:
        pass
    return checks


def response(start_response, status: str, body: bytes, content_type: str = "application/json; charset=utf-8", headers=()):
    script_nonce = ""
    if content_type.startswith("text/html") and b"<script>" in body:
        script_nonce = b64u(secrets.token_bytes(18))
        body = body.replace(b"<script>", (f'<script nonce="{script_nonce}">'.encode("ascii")))
    script_policy = f"'nonce-{script_nonce}'" if script_nonce else "'none'"
    base = [("Content-Type", content_type), ("Cache-Control", "no-store"),
            ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
            ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"),
            ("X-Frame-Options", "DENY"),
            ("Cross-Origin-Opener-Policy", "same-origin-allow-popups"),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()"),
            ("X-Permitted-Cross-Domain-Policies", "none"),
            ("Content-Security-Policy", f"default-src 'none'; script-src {script_policy}; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")]
    start_response(status, base + list(headers))
    return [body]


def append_query(url: str, parameters: dict) -> str:
    separator = "" if url.endswith(("?", "&")) else ("&" if "?" in url else "?")
    return url + separator + urlencode(parameters)


def json_response(start_response, status: str, value: dict, headers=()):
    return response(start_response, status, json.dumps(value, separators=(",", ":")).encode(), headers=headers)


def fields(environ):
    if environ.get("REQUEST_METHOD") != "POST":
        return {}
    try:
        size = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        return {}
    if size < 0 or size > 16_384:
        return {}
    raw = environ["wsgi.input"].read(size).decode("utf-8", "strict")
    if "application/json" in environ.get("CONTENT_TYPE", ""):
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}


def valid_admin_api_request(environ, con, sid):
    auth = environ.get("HTTP_AUTHORIZATION", "")
    if not auth.startswith("Basic ") or not re.fullmatch(r"[a-f0-9]{64}", sid or ""):
        return False
    try:
        client_id, secret = base64.b64decode(auth[6:], validate=True).decode("utf-8").split(":", 1)
    except Exception:
        return False
    if client_id != ADMIN_CLIENT_ID:
        return False
    client = con.execute("SELECT secret_hash,active FROM clients WHERE client_id=?", (client_id,)).fetchone()
    session = con.execute("SELECT u.id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1", (sid, int(time.time()))).fetchone()
    return bool(client and client["active"] and hmac.compare_digest(hashlib.sha256(secret.encode("utf-8")).hexdigest(), client["secret_hash"]) and session and is_admin_user(con, session["id"]))


def canonical_mnsl_update_manifest(value):
    """Return the exact legacy MNSL updater payload after strict field validation."""
    if not isinstance(value, dict):
        raise ValueError("invalid_manifest")
    product = value.get("product")
    if value.get("schema") != 1 or product not in ("MyNumberSmartLogin", "MyNumberSmartLogin-SSO"):
        raise ValueError("invalid_manifest")
    channel = value.get("channel")
    version = value.get("version")
    package_name = value.get("package_name")
    digest = value.get("sha256")
    if channel not in ("stable", "beta") or not isinstance(version, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
        raise ValueError("invalid_manifest")
    package_pattern = r"MNSL-[A-Za-z0-9._-]+\.zip" if product == "MyNumberSmartLogin" else r"MNSL-SSO-[A-Za-z0-9._-]+\.zip"
    if not isinstance(package_name, str) or not re.fullmatch(package_pattern, package_name):
        raise ValueError("invalid_manifest")
    if not isinstance(digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
        raise ValueError("invalid_manifest")
    try:
        revision = int(value.get("revision"))
        size = int(value.get("size"))
    except (TypeError, ValueError):
        raise ValueError("invalid_manifest")
    if revision <= 0 or size <= 0 or size > 1_073_741_824:
        raise ValueError("invalid_manifest")
    published = value.get("published_utc")
    terms = value.get("terms_version", "")
    notes = value.get("release_notes", "")
    if not isinstance(published, str) or len(published) > 40 or not isinstance(terms, str) or len(terms) > 32 or not isinstance(notes, str) or len(notes) > 2000:
        raise ValueError("invalid_manifest")
    reconsent = "true" if value.get("requires_reconsent") is True else "false"
    mandatory = "true" if value.get("mandatory") is True else "false"
    notes = notes.replace("\r", " ").replace("\n", " ")
    return "\n".join((
        "MNSL-UPDATE-V1", "schema=1", "product=" + product,
        "channel=" + channel, "version=" + version, "revision=" + str(revision),
        "package_name=" + package_name, "sha256=" + digest.lower(),
        "size=" + str(size), "published_utc=" + published,
        "terms_version=" + terms, "requires_reconsent=" + reconsent,
        "mandatory=" + mandatory, "release_notes=" + notes,
    ))


def sign_mnsl_update_manifest(environ, start_response):
    """Admin SSO step-up authorizes signing; the SSO private key never leaves this host."""
    if environ.get("REQUEST_METHOD") != "POST":
        return json_response(start_response, "405 Method Not Allowed", {"error": "method_not_allowed"})
    try:
        value = fields(environ)
        sid = str(value.get("sid", ""))
        manifest = value.get("manifest")
        if isinstance(manifest, str):
            manifest = json.loads(manifest)
        payload = canonical_mnsl_update_manifest(manifest)
        now = int(time.time())
        with db() as con:
            if not valid_admin_api_request(environ, con, sid):
                return json_response(start_response, "403 Forbidden", {"error": "admin_session_required"})
            session = con.execute("SELECT s.user_id,s.created_at,u.public_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1", (hashlib.sha256(sid.encode()).hexdigest(), now)).fetchone()
            if not session or now - int(session["created_at"] or 0) > 120 or now < int(session["created_at"] or 0):
                return json_response(start_response, "428 Precondition Required", {"error": "recent_admin_passkey_required"})
            jwk = rsa_public_jwk()
            signature = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(KEY)],
                input=payload.encode("utf-8"), check=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=5,
            ).stdout
            con.execute("CREATE TABLE IF NOT EXISTS sso_update_signing_audit(event_id TEXT PRIMARY KEY,actor_user_id INTEGER NOT NULL,channel TEXT NOT NULL,version TEXT NOT NULL,revision INTEGER NOT NULL,package_sha256 TEXT NOT NULL,created_at INTEGER NOT NULL)")
            con.execute("INSERT INTO sso_update_signing_audit(event_id,actor_user_id,channel,version,revision,package_sha256,created_at) VALUES(?,?,?,?,?,?,?)", (b64u(secrets.token_bytes(16)), int(session["user_id"]), str(manifest["channel"]), str(manifest["version"]), int(manifest["revision"]), str(manifest["sha256"]).lower(), now))
        return json_response(start_response, "200 OK", {"signature": base64.b64encode(signature).decode("ascii"), "kid": jwk["kid"], "algorithm": "RS256", "authorized_admin_sid": str(session["public_id"]), "signed_at": now}, headers=[("Cache-Control", "no-store")])
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return json_response(start_response, "400 Bad Request", {"error": "invalid_manifest"})


def valid_admin_browser_request(environ, con, f):
    if environ.get("HTTP_ORIGIN", "") != ISSUER:
        return False
    token = cookie(environ, COOKIE)
    if not token:
        return False
    now = int(time.time())
    session = con.execute("SELECT s.user_id,s.csrf_hash,s.created_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1", (hashlib.sha256(token.encode()).hexdigest(), now)).fetchone()
    csrf = str(f.get("csrf", ""))
    return bool(session and now - int(session["created_at"] or 0) <= 120 and now >= int(session["created_at"] or 0) and hmac.compare_digest(session["csrf_hash"], hashlib.sha256(csrf.encode()).hexdigest()) and is_admin_user(con, session["user_id"]))


def record_identity_admin_audit(con, environ, sid, action, target, success, now):
    token = cookie(environ, COOKIE) or sid
    actor = con.execute("SELECT user_id FROM sessions WHERE token_hash=? AND expires_at>? AND revoked_at IS NULL", (hashlib.sha256(token.encode()).hexdigest(), now)).fetchone()
    if actor:
        con.execute("INSERT INTO sso_admin_identity_audit(event_id,actor_user_id,action,target_hash,success,created_at) VALUES(?,?,?,?,?,?)", (b64u(secrets.token_bytes(16)), actor["user_id"], action, security_rate_key("sso-admin-target", target), int(bool(success)), now))


def admin_identity_page(csrf):
    page = '''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="referrer" content="no-referrer"><meta name="theme-color" content="#f3f6fb"><title>SSO IDの管理 | 2415.jp</title><style>
:root{color-scheme:light dark;--ink:#14243a;--muted:#627188;--paper:#fff;--canvas:#f3f6fb;--line:#dce5ef;--blue:#2857d9;--danger:#b33445}*{box-sizing:border-box}body{margin:0;min-height:100vh;padding:20px;display:grid;place-items:center;color:var(--ink);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 8% 12%,#dce9ff 0,transparent 36%),var(--canvas)}main{width:min(100%,620px)}.brand{margin:0 0 15px 4px;font-weight:800;color:#243c60}.card{padding:clamp(22px,5vw,34px);border:1px solid var(--line);border-radius:22px;background:var(--paper);box-shadow:0 20px 60px #19375b18}h1{margin:0;font-size:clamp(1.5rem,5vw,1.9rem)}p{color:var(--muted)}label{display:block;margin:18px 0 7px;font-weight:750}input{width:100%;min-height:50px;padding:11px 13px;border:1px solid #bdcad9;border-radius:11px;background:var(--paper);color:var(--ink);font:inherit;font-size:16px}.row{display:flex;gap:9px}button{min-height:48px;padding:10px 15px;border:0;border-radius:11px;background:var(--blue);color:#fff;font:inherit;font-weight:800;cursor:pointer}button.danger{background:var(--danger)}button:disabled{opacity:.6}#identity{margin-top:15px;padding:14px;border-radius:12px;background:#edf3ff;font-weight:800;overflow-wrap:anywhere}#status{min-height:1.5em;margin-top:13px;color:#36516c}a{color:var(--blue)}.warning{padding:12px;border-left:4px solid var(--danger);background:#fff4f4;color:#71313a;font-size:.9rem}@media(max-width:520px){body{padding:14px}.row{flex-direction:column}.row button{width:100%}}@media(prefers-color-scheme:dark){:root{--ink:#edf3fc;--muted:#aab7c8;--paper:#192432;--canvas:#111923;--line:#344255}.brand{color:#dbe7f7}.card{box-shadow:0 20px 60px #0005}input{border-color:#45566c}#identity{background:#202f4a}.warning{background:#33252a;color:#f1c3ca}}
</style></head><body><main><div class="brand">2415.jp · SSO ID 管理</div><section class="card"><h1>SSO IDを忘れた利用者</h1><p>管理者が直近2分以内にパスキー認証した状態でのみ利用できます。最初に登録済みメールアドレスを照合し、IDを本人へ伝えてください。</p><label for="email">登録済みメールアドレス</label><div class="row"><input id="email" type="email" maxlength="254" autocomplete="email" placeholder="name@example.jp"><button id="lookup">SSO IDを照合</button></div><div id="identity" hidden></div><section id="delete-area" hidden><p class="warning">削除するとSSO IDを無効化し、パスキー、認証アプリ、復旧情報、全セッションを消去します。同じメールアドレスで新しいIDを作成できます。</p><label for="confirm-id">削除を承認するため、表示されたSSO IDを入力</label><div class="row"><input id="confirm-id" maxlength="30" autocomplete="off" placeholder="SID-…"><button id="delete" class="danger">アカウントを削除</button></div></section><p id="status" role="status" aria-live="polite"></p><p><a href="/account">アカウント管理へ戻る</a></p></section></main><script>(()=>{const csrf=CSRF,byId=id=>document.getElementById(id),status=byId('status'),identity=byId('identity'),area=byId('delete-area');let currentId='';async function send(path,data){const r=await fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify({...data,csrf})});const j=await r.json();if(!r.ok||!j.ok)throw new Error(j.message||'処理できませんでした。');return j}byId('lookup').addEventListener('click',async()=>{status.textContent='照合中です…';identity.hidden=true;area.hidden=true;currentId='';try{const j=await send('/admin/identity/search',{email:byId('email').value});if(!j.found){status.textContent='一致する有効なSSO IDはありません。';return}currentId=j.identity.public_id;identity.textContent='SSO ID: '+currentId;identity.hidden=false;area.hidden=false;byId('confirm-id').value='';status.textContent='IDを本人へ案内してください。'}catch(e){status.textContent=e.message}});byId('delete').addEventListener('click',async()=>{const confirmId=byId('confirm-id').value.trim().toUpperCase();if(confirmId!==currentId){status.textContent='表示されたSSO IDを正確に入力してください。';return}if(!confirm('SSO ID '+currentId+' のアカウントと認証情報を削除しますか？'))return;status.textContent='削除しています…';try{await send('/admin/identity/delete',{email:byId('email').value,public_id:currentId});identity.hidden=true;area.hidden=true;currentId='';status.textContent='アカウントを削除しました。同じメールアドレスで新しいSSO IDを登録できます。'}catch(e){status.textContent=e.message}})})();</script></body></html>'''
    return page.replace("CSRF", html.escape(csrf, quote=True)).encode("utf-8")


def contractor_setup_page(flow):
    flow_json = json.dumps(flow)
    page = '''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="referrer" content="no-referrer"><title>契約者SSO ID登録</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:18px;background:#f1f5fb;color:#17243a;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.card{width:min(100%,520px);padding:clamp(22px,6vw,38px);border:1px solid #dce5ef;border-radius:22px;background:#fff;box-shadow:0 20px 60px #19375b18}.brand{font-weight:850;color:#2857d9;letter-spacing:.04em}.eyebrow{margin:24px 0 5px;color:#527092;font-size:.76rem;font-weight:800;letter-spacing:.1em}h1{margin:0;font-size:clamp(1.55rem,5vw,2rem);line-height:1.25}p{color:#5d6c82}label{display:block;margin:18px 0 7px;font-weight:750}input{width:100%;min-height:52px;padding:11px 13px;border:1px solid #b9c7d8;border-radius:11px;font:inherit;font-size:1.1rem;letter-spacing:.1em}button{width:100%;min-height:50px;margin-top:15px;padding:11px;border:0;border-radius:11px;background:#2857d9;color:#fff;font:inherit;font-weight:800;cursor:pointer}button:disabled{opacity:.6}#status{min-height:28px;margin-top:14px;font-weight:650;overflow-wrap:anywhere}small{display:block;color:#65748a;margin-top:7px}@media(prefers-color-scheme:dark){body{background:#111923;color:#edf3fc}.card{background:#192432;border-color:#344255}p,small{color:#aab7c8}input{background:#111923;color:#edf3fc;border-color:#45566c}}
</style></head><body><main class="card"><div class="brand">2415.JP · SSO ID</div><p class="eyebrow">CONTRACT HOLDER ID</p><h1>契約者向けSSO IDを登録</h1><p>メールアドレスを確認した後、この端末のパスキーを登録します。登録完了後、メールアドレスはアカウントから削除され、復旧用の照合値だけが保護して保存されます。</p><form id="verify"><label for="code">メール確認コード</label><input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required><small>メールに届いた6桁のコードを入力してください。</small><button id="continue" type="submit">確認してパスキー登録へ</button></form><button id="register" type="button" hidden>この端末のパスキーを登録</button><p id="status" role="status" aria-live="polite"></p></main><script>
(function(){const flow=FLOW;const form=document.getElementById('verify'),code=document.getElementById('code'),status=document.getElementById('status'),register=document.getElementById('register');let publicKey=null;const dec=s=>{const b=atob(s.replace(/-/g,'+').replace(/_/g,'/'));return Uint8Array.from(b,c=>c.charCodeAt(0))};const enc=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');function downloadCertificate(cert){const a=document.createElement('a'),url=URL.createObjectURL(new Blob([JSON.stringify(cert,null,2)],{type:'application/json'}));a.href=url;a.download=(String(cert.subject||'SSO').replace(/[^A-Za-z0-9_-]/g,'')||'SSO')+'-recovery-certificate.json';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500)}async function post(path,data){const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'same-origin',cache:'no-store',body:JSON.stringify(Object.assign({flow:flow},data))});const j=await r.json().catch(()=>({}));if(!r.ok)throw new Error(j.message||'確認できませんでした。時間をおいてやり直してください。');return j}form.addEventListener('submit',async e=>{e.preventDefault();document.getElementById('continue').disabled=true;status.textContent='メールを確認しています…';try{const j=await post('/contractor/verify',{code:code.value.trim()});publicKey=j.publicKey;publicKey.challenge=dec(publicKey.challenge);publicKey.user.id=dec(publicKey.user.id);form.hidden=true;register.hidden=false;status.textContent='メールを確認しました。続けてパスキーを登録してください。'}catch(err){status.textContent=err.message;document.getElementById('continue').disabled=false}});register.addEventListener('click',async()=>{register.disabled=true;status.textContent='パスキー登録を待っています…';try{if(!window.isSecureContext||!navigator.credentials)throw new Error('HTTPS対応のブラウザーで開いてください。');const c=await navigator.credentials.create({publicKey:publicKey});if(!c)throw new Error('パスキー登録がキャンセルされました。');const j=await post('/contractor/finish',{credential:{id:enc(c.rawId),clientDataJSON:enc(c.response.clientDataJSON),attestationObject:enc(c.response.attestationObject),transports:c.response.getTransports?c.response.getTransports():[]}});register.hidden=true;downloadCertificate(j.recovery_certificate);status.textContent='登録完了。SSO ID: '+j.public_id+'。復旧証明書を安全な場所に保存してください。';location.assign(j.next||'/account')}catch(err){status.textContent=err.name==='NotAllowedError'?'パスキー登録がキャンセルされました。もう一度お試しください。':err.message;register.disabled=false}})})();
</script></body></html>'''.replace("FLOW", flow_json)
    return page.encode("utf-8")


def contractor_register_page():
    page = '''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="referrer" content="no-referrer"><title>契約者SSO ID作成</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:18px;background:#f1f5fb;color:#17243a;font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.card{width:min(100%,520px);padding:clamp(22px,6vw,38px);border:1px solid #dce5ef;border-radius:22px;background:#fff;box-shadow:0 20px 60px #19375b18}.brand{font-weight:850;color:#2857d9;letter-spacing:.04em}.eyebrow{margin:24px 0 5px;color:#527092;font-size:.76rem;font-weight:800;letter-spacing:.1em}h1{margin:0;font-size:clamp(1.55rem,5vw,2rem);line-height:1.25}p{color:#5d6c82}label{display:block;margin:18px 0 7px;font-weight:750}input{width:100%;min-height:52px;padding:11px 13px;border:1px solid #b9c7d8;border-radius:11px;font:inherit}button{width:100%;min-height:50px;margin-top:15px;padding:11px;border:0;border-radius:11px;background:#2857d9;color:#fff;font:inherit;font-weight:800;cursor:pointer}button:disabled{opacity:.6}#status{min-height:28px;margin-top:14px;font-weight:650;overflow-wrap:anywhere}small{display:block;color:#65748a;margin-top:7px}a{color:#2857d9}@media(prefers-color-scheme:dark){body{background:#111923;color:#edf3fc}.card{background:#192432;border-color:#344255}p,small{color:#aab7c8}input{background:#111923;color:#edf3fc;border-color:#45566c}a{color:#8eacff}}
</style></head><body><main class="card"><div class="brand">2415.JP · SSO ID</div><p class="eyebrow">TENANT SELF-SERVICE</p><h1>契約者向けSSO IDを作成</h1><p>受信できるメールアドレスに確認コードを送り、確認後にパスキーを登録します。登録完了後、メールアドレスはアカウントから削除され、照合値だけが保護して保存されます。</p><form id="register"><label for="email">メールアドレス</label><input id="email" name="email" type="email" autocomplete="email" maxlength="254" required><label hidden aria-hidden="true">この欄は入力しないでください<input name="website" tabindex="-1" autocomplete="off"></label><small>SSO IDの作成だけでは、各契約APIへの利用権限は追加されません。契約と利用権限はテナント側の設定に従います。</small><button id="submit" type="submit">確認コードをメールで受け取る</button></form><p id="status" role="status" aria-live="polite"></p><small><a href="/account">SSO IDをお持ちの方</a></small></main><script>
(function(){const form=document.getElementById('register'),status=document.getElementById('status'),button=document.getElementById('submit');form.addEventListener('submit',async e=>{e.preventDefault();button.disabled=true;status.textContent='登録案内を確認しています…';try{const r=await fetch('/contractor/register/start',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'omit',cache:'no-store',body:JSON.stringify({email:form.email.value.trim(),website:form.website.value})});if(!r.ok)throw new Error('時間をおいてから、もう一度お試しください。');status.textContent='該当する場合は、確認コードと登録用リンクをメールでお送りします。迷惑メールフォルダーもご確認ください。';form.hidden=true}catch(_){status.textContent='登録案内を開始できませんでした。入力内容と接続を確認して、時間をおいてお試しください。';button.disabled=false}})})();
</script></body></html>'''
    return page.encode("utf-8")


def query(environ):
    return {k: v[0] for k, v in parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True).items()}


def cookie(environ, name):
    for part in environ.get("HTTP_COOKIE", "").split(";"):
        key, sep, value = part.strip().partition("=")
        if sep and key == name:
            return value
    return ""


def security_rate_key(category, value):
    """Create a non-reversible, keyed rate-limit key (never store raw IP/ID)."""
    try:
        secret = EMAIL_KEY.read_bytes()[:32]
    except OSError:
        secret = hashlib.sha256(ISSUER.encode("ascii")).digest()
    raw = (str(category) + "|" + str(value)).encode("utf-8", "replace")[:512]
    return hmac.new(secret, b"sso-rate-limit-v1|" + raw, hashlib.sha256).hexdigest()


def consume_security_rate_limit(key, maximum, window_seconds, now=None):
    """Atomically consume one request from a fixed window; safe under CGI concurrency."""
    now = int(time.time()) if now is None else int(now)
    with db() as con:
        con.execute("BEGIN IMMEDIATE")
        allowed = consume_security_rate_limit_in_transaction(con, key, maximum, window_seconds, now)
        con.commit()
        return allowed


def consume_security_rate_limit_in_transaction(con, key, maximum, window_seconds, now=None):
    """Consume a limit inside a caller's existing BEGIN IMMEDIATE transaction."""
    now = int(time.time()) if now is None else int(now)
    maintenance = con.execute(
        "SELECT last_cleanup FROM security_rate_limit_maintenance WHERE singleton=1"
    ).fetchone()
    if not maintenance or int(maintenance["last_cleanup"]) <= now - 3600:
        con.execute("DELETE FROM security_rate_limits WHERE window_started<?", (now - 86400,))
        con.execute(
            "INSERT INTO security_rate_limit_maintenance(singleton,last_cleanup) VALUES(1,?) "
            "ON CONFLICT(singleton) DO UPDATE SET last_cleanup=excluded.last_cleanup",
            (now,),
        )
    row = con.execute("SELECT window_started,attempts FROM security_rate_limits WHERE rate_key=?", (key,)).fetchone()
    if row and int(row["window_started"]) + window_seconds > now and int(row["attempts"]) >= maximum:
        return False
    if not row or int(row["window_started"]) + window_seconds <= now:
        con.execute("INSERT OR REPLACE INTO security_rate_limits(rate_key,window_started,attempts) VALUES(?,?,1)", (key, now))
    else:
        con.execute("UPDATE security_rate_limits SET attempts=attempts+1 WHERE rate_key=?", (key,))
    return True


def cleanup_expired_auth_state(con, now):
    """Sweep short-lived auth rows periodically instead of locking on every authorize request."""
    maintenance = con.execute(
        "SELECT last_run FROM database_maintenance WHERE task='expired_auth_state'"
    ).fetchone()
    if maintenance and int(maintenance["last_run"]) > now - 300:
        return 0
    con.execute("BEGIN IMMEDIATE")
    maintenance = con.execute(
        "SELECT last_run FROM database_maintenance WHERE task='expired_auth_state'"
    ).fetchone()
    if maintenance and int(maintenance["last_run"]) > now - 300:
        con.commit()
        return 0
    removed = 0
    for statement, parameters in (
        ("DELETE FROM login_flows WHERE expires_at<=?", (now,)),
        ("DELETE FROM passkey_flows WHERE expires_at<=?", (now,)),
        ("DELETE FROM registration_onboarding WHERE expires_at<=?", (now,)),
        ("DELETE FROM auth_codes WHERE expires_at<=? OR consumed_at IS NOT NULL AND consumed_at<?", (now, now - 3600)),
        ("DELETE FROM access_tokens WHERE expires_at<=?", (now,)),
        ("DELETE FROM sessions WHERE expires_at<=? OR revoked_at IS NOT NULL", (now,)),
        ("DELETE FROM login_limits WHERE window_started<? AND locked_until<?", (now - 86400, now)),
        ("DELETE FROM recovery_flows WHERE expires_at<=?", (now,)),
        ("DELETE FROM recovery_email_setup WHERE expires_at<=?", (now,)),
        ("DELETE FROM contractor_invites WHERE expires_at<=?", (now,)),
    ):
        removed += con.execute(statement, parameters).rowcount
    con.execute(
        "INSERT INTO database_maintenance(task,last_run) VALUES('expired_auth_state',?) "
        "ON CONFLICT(task) DO UPDATE SET last_run=excluded.last_run",
        (now,),
    )
    con.commit()
    return removed


def touch_browser_session(environ, now=None):
    """Enforce a rolling idle timeout for browser sessions on every request."""
    token = cookie(environ, COOKIE)
    if not token:
        return False
    now = int(time.time() if now is None else now)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as con:
        session = con.execute(
            "SELECT last_seen,created_at FROM sessions WHERE token_hash=? AND expires_at>? AND revoked_at IS NULL",
            (token_hash, now),
        ).fetchone()
        if not session:
            return False
        last_seen = int(session["last_seen"] or session["created_at"] or 0)
        if last_seen <= 0 or now - last_seen >= SESSION_IDLE_TTL:
            con.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL", (now, token_hash))
            return False
        if now - last_seen >= 60:
            con.execute("UPDATE sessions SET last_seen=? WHERE token_hash=? AND revoked_at IS NULL", (now, token_hash))
        return True


def user_for_session(environ):
    token = cookie(environ, COOKIE)
    if not token:
        return None
    with db() as con:
        return con.execute("SELECT u.id,u.public_id,u.display_name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1", (hashlib.sha256(token.encode()).hexdigest(), int(time.time()))).fetchone()


def authorize_login_page(flow, csrf, error=False):
    error_html = '<p class="error" role="alert">IDまたはパスキーを確認してください。初回登録済みの方は「旧アカウント移行」からパスキー登録を完了してください。</p>' if error else ""
    page = '''<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="referrer" content="no-referrer"><meta name="theme-color" content="#f4f7fb"><title>ログイン | SSO ID</title>
<style>
:root{color-scheme:light dark;--ink:#14243a;--muted:#627188;--paper:#fff;--canvas:#f3f6fb;--blue:#2857d9;--blue-dark:#1940b5;--line:#dce5ef;--focus:#3a72ff}
*{box-sizing:border-box}body{margin:0;min-height:100vh;min-height:100svh;padding:max(20px,env(safe-area-inset-top)) 16px max(20px,env(safe-area-inset-bottom));display:grid;place-items:center;color:var(--ink);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 8% 12%,#dce9ff 0,transparent 36%),radial-gradient(ellipse at 95% 90%,#d9f5ed 0,transparent 32%),var(--canvas)}
.shell{width:min(100%,480px)}.brand{display:flex;align-items:center;gap:11px;margin:0 0 16px 4px;color:#243c60;font-weight:800}.brand-mark{display:grid;place-items:center;width:38px;height:38px;border-radius:12px;background:linear-gradient(145deg,#3568ed,#173fae);color:#fff;font-weight:900;box-shadow:0 7px 16px #204cb333}.card{overflow:hidden;border:1px solid #e0e7f0;border-radius:24px;background:var(--paper);box-shadow:0 24px 70px #1b365219}.card-head{padding:30px 34px 16px}.kicker{margin:0 0 8px;color:var(--blue);font-size:.76rem;font-weight:850;letter-spacing:.12em}h1{margin:0;font-size:clamp(1.6rem,5vw,1.9rem);line-height:1.2;letter-spacing:-.035em}.lead{margin:11px 0 0;color:var(--muted);font-size:.95rem}.panel{padding:21px 34px 28px}.error{margin:0 0 15px;padding:12px 14px;border:1px solid #f2c4ca;border-radius:12px;background:#fff3f4;color:#8e2430;font-size:.9rem;font-weight:650}.form-section{margin:0 0 18px}.field{margin:15px 0 0}.field label{display:block;margin:0 0 7px;font-size:.88rem;font-weight:750}.field input{display:block;width:100%;min-height:52px;padding:12px 14px;border:1px solid #cdd7e4;border-radius:12px;background:#fff;color:var(--ink);font:inherit;font-size:16px}.field input:focus{outline:0;border-color:var(--focus);box-shadow:0 0 0 4px #3a72ff24}button{min-height:50px;padding:11px 15px;border:0;border-radius:12px;background:linear-gradient(135deg,var(--blue),var(--blue-dark));color:#fff;font:inherit;font-weight:800;cursor:pointer;box-shadow:0 8px 18px #2857d92e}form>button{width:100%;margin-top:17px}button:hover{filter:brightness(1.06)}button:focus-visible,a:focus-visible,summary:focus-visible{outline:3px solid #79a0ff;outline-offset:3px}button:disabled{opacity:.65;cursor:wait}#run-passkey,#run-enroll{margin-top:10px}.hint{margin:7px 0 0;color:var(--muted);font-size:.82rem}.recover-link{display:block;margin:16px 0 2px;text-align:center;color:#3158b7;font-size:.88rem;font-weight:700;text-decoration:none}.recover-link:hover{text-decoration:underline}.legacy{margin-top:20px;border-top:1px solid var(--line);padding-top:15px}.legacy summary{color:#3158b7;font-weight:750;cursor:pointer}.legacy>p{color:var(--muted);font-size:.85rem}.password-row{display:flex;gap:8px}.password-row input{flex:1;min-width:0}.password-row button{min-width:78px;margin:0;background:#eef3ff;color:#244bb8;box-shadow:none}.password-row+button{width:100%;margin-top:15px}.status{min-height:25px;margin:16px 0 0;color:#41536c;font-size:.9rem;font-weight:650;overflow-wrap:anywhere}.trust{display:flex;align-items:center;justify-content:center;gap:7px;margin:14px 0 0;color:#7b899b;font-size:.77rem}.trust svg{width:15px;height:15px;color:#168a78}.footer{margin:14px 4px 0;color:#7b899b;font-size:.74rem;text-align:center}
@media(max-width:520px){body{padding:14px 12px max(14px,env(safe-area-inset-bottom));background:linear-gradient(180deg,#eaf1ff,#f4f8fc 42%,#eff8f5)}.shell{margin:auto 0}.brand{margin:0 0 12px 3px;font-size:.94rem}.card{border-radius:20px}.card-head{padding:25px 22px 13px}.panel{padding:19px 22px 24px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{transition:none!important;scroll-behavior:auto!important}}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--ink:#edf3fc;--muted:#aab7c8;--paper:#192432;--canvas:#111923;--line:#354356;--blue:#7295ff;--blue-dark:#4167dc}body{background:radial-gradient(ellipse at 8% 12%,#203355 0,transparent 38%),radial-gradient(ellipse at 95% 90%,#12382f 0,transparent 35%),var(--canvas)}.brand{color:#dbe7f7}.brand-mark{box-shadow:none}.card{border-color:#344255;box-shadow:0 24px 70px #0005}.error{border-color:#63404a;background:#39252b;color:#ffb2bb}.field input{border-color:#45566c;background:#111a26;color:var(--ink)}.field input:focus{border-color:#7195ff;box-shadow:0 0 0 4px #7195ff24}.password-row button{background:#202f4c;color:#b9caff}.recover-link,.legacy summary{color:#a8c1ff}.status,.trust,.footer{color:#95a3b7}.trust svg{color:#68cbb8}}
</style></head>
<body><main class="shell">
<div class="brand"><span class="brand-mark" aria-hidden="true">S</span><span>2415.jp <span style="font-weight:600;opacity:.72">/ SSO ID</span></span></div>
<section class="card" aria-labelledby="page-title"><header class="card-head"><p class="kicker">SECURE SIGN IN</p><h1 id="page-title">SSO IDでログイン</h1><p class="lead">発行済みのSSO IDを入力し、パスキーで本人確認します。</p></header>
<div class="panel">ERROR_SLOT
<form id="passkey-login"><input type="hidden" name="flow" value="__FLOW__"><input type="hidden" name="csrf" value="__CSRF__"><div class="field"><label for="sso-id">SSO ID（省略可）</label><input id="sso-id" inputmode="text" autocomplete="username webauthn" autocapitalize="characters" spellcheck="false" placeholder="SID-…（空欄ならパスキーから選択）"></div><button type="submit">パスキー認証を準備</button><p class="hint">SSO IDを入力するか、空欄のまま進んで登録済みパスキーを選べます。</p></form>
<p><a class="recover-link" href="/recover">パスキーを紛失した場合</a></p><button id="run-passkey" type="button" hidden>この端末のパスキーで認証</button><p id="status" class="status" role="status" aria-live="polite"></p><form id="totp-login" hidden><div class="field"><label for="totp-login-code">認証アプリの6桁コード</label><input id="totp-login-code" inputmode="numeric" autocomplete="one-time-code" maxlength="24" required></div><button type="submit">コードを確認してログイン</button><p class="hint">6桁コードは30秒ごとに更新されます。</p></form>
<details class="legacy"><summary>旧アカウントから移行する（初回のみ）</summary><p>初回登録済みの旧アカウントは、メールとパスワードで確認してからパスキーを登録します。</p><form id="legacy-login"><input type="hidden" name="flow" value="__FLOW__"><input type="hidden" name="csrf" value="__CSRF__"><div class="field"><label for="email">登録済みメールアドレス</label><input id="email" type="email" autocomplete="username" required maxlength="254"></div><div class="field"><label for="password">現在のパスワード</label><div class="password-row"><input id="password" type="password" autocomplete="current-password" required maxlength="1024"><button type="button" id="show-password">表示</button></div></div><button type="submit">本人確認してパスキー登録へ</button></form><button id="run-enroll" type="button" hidden>この端末のパスキー登録を開始</button></details>
<p class="trust"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3 20 6v5c0 5-3.4 8-8 10-4.6-2-8-5-8-10V6l8-3Z" stroke="currentColor" stroke-width="1.8"/><path d="m8.5 12 2.2 2.2 4.8-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>通信は暗号化され、パスキーで保護されます</p></div></section>
<footer class="footer">安全なシングルサインオン · sso.2415.jp</footer>
</main><script>const FLOW="__FLOW__",CSRF="__CSRF__",statusNode=document.getElementById('status');const flowReloadMarker='sso-passkey-pending';try{const attemptAt=Number(localStorage.getItem(flowReloadMarker)||0);if(attemptAt&&Date.now()-attemptAt<120000){statusNode.textContent='パスキー確認後にSSOログイン画面へ戻りました。認証応答の処理が完了していません。最初からやり直してください。';localStorage.removeItem(flowReloadMarker)}else if(attemptAt){localStorage.removeItem(flowReloadMarker)}}catch(e){}const enc=b=>{let s='';new Uint8Array(b).forEach(v=>s+=String.fromCharCode(v));return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')};const dec=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));function downloadCertificate(cert){const a=document.createElement('a'),url=URL.createObjectURL(new Blob([JSON.stringify(cert,null,2)],{type:'application/json'}));a.href=url;a.download=(String(cert.subject||'SSO').replace(/[^A-Za-z0-9_-]/g,'')||'SSO')+'-recovery-certificate.json';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500)}async function post(path,data){const r=await fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});let j={};try{j=await r.json()}catch(e){}if(!r.ok||!j.ok)throw new Error(j.message||j.error||('HTTP '+r.status+'：認証に失敗しました。'));return j}async function enroll(o){let p=o.publicKey;p.challenge=dec(p.challenge);p.user.id=dec(p.user.id);const c=await navigator.credentials.create({publicKey:p});return{id:enc(c.rawId),clientDataJSON:enc(c.response.clientDataJSON),attestationObject:enc(c.response.attestationObject),transports:c.response.getTransports?c.response.getTransports():[]}}let loginOptions=null,enrollOptions=null;document.getElementById('passkey-login').addEventListener('submit',async e=>{e.preventDefault();statusNode.textContent='パスキーを準備しています…';try{let id=document.getElementById('sso-id').value.trim().toUpperCase(),b=await post('/login/begin',{flow:FLOW,csrf:CSRF,public_id:id});loginOptions=b.publicKey;loginOptions.challenge=dec(loginOptions.challenge);loginOptions.allowCredentials=loginOptions.allowCredentials.map(x=>({type:'public-key',id:dec(x.id),transports:x.transports||[]}));document.getElementById('run-passkey').hidden=false;statusNode.textContent=id?'準備できました。端末のパスキーで認証してください。':'登録済みパスキーを選択してください。'}catch(err){statusNode.textContent=err.message==='Load failed'?'サーバーへ接続できません。通信を確認して再読み込みしてください。':err.message}});document.getElementById('run-passkey').addEventListener('click',async e=>{if(!loginOptions)return;const button=e.currentTarget;button.disabled=true;try{localStorage.setItem(flowReloadMarker,String(Date.now()))}catch(e){}statusNode.textContent='端末のパスキーを確認しています…';try{let c=await navigator.credentials.get({publicKey:loginOptions}),f=await post('/login',{action:'passkey_assertion',flow:FLOW,csrf:CSRF,credential:{id:enc(c.rawId),clientDataJSON:enc(c.response.clientDataJSON),authenticatorData:enc(c.response.authenticatorData),signature:enc(c.response.signature),userHandle:c.response.userHandle?enc(c.response.userHandle):''}});if(f.mfa_required){try{localStorage.removeItem(flowReloadMarker)}catch(e){}document.getElementById('totp-login').hidden=false;button.hidden=true;statusNode.textContent='パスキーを確認しました。認証アプリの6桁コードを入力してください。';document.getElementById('totp-login-code').focus();return}try{localStorage.removeItem(flowReloadMarker)}catch(e){}location.assign(f.next)}catch(err){try{localStorage.removeItem(flowReloadMarker)}catch(e){}button.disabled=false;statusNode.textContent=err.name==='NotAllowedError'?'認証がキャンセルされたか時間切れです。もう一度押してください。':err.message}});document.getElementById('totp-login').addEventListener('submit',async e=>{e.preventDefault();const field=document.getElementById('totp-login-code'),button=e.currentTarget.querySelector('button');button.disabled=true;statusNode.textContent='追加認証を確認しています…';try{const j=await post('/login/totp',{flow:FLOW,csrf:CSRF,code:field.value.trim()});location.assign(j.next)}catch(err){button.disabled=false;statusNode.textContent=err.message;field.focus()}});document.getElementById('legacy-login').addEventListener('submit',async e=>{e.preventDefault();statusNode.textContent='本人確認しています…';try{let b=await post('/login',{action:'legacy_login',flow:FLOW,csrf:CSRF,email:document.getElementById('email').value,password:document.getElementById('password').value});enrollOptions=b.publicKey;enrollOptions.challenge=dec(enrollOptions.challenge);enrollOptions.user.id=dec(enrollOptions.user.id);document.getElementById('run-enroll').hidden=false;statusNode.textContent='本人確認できました。「この端末のパスキー登録を開始」を押してください。'}catch(err){statusNode.textContent=err.message==='Load failed'?'サーバーへ接続できません。通信を確認して再読み込みしてください。':err.message}});document.getElementById('run-enroll').addEventListener('click',async e=>{if(!enrollOptions)return;const button=e.currentTarget;button.disabled=true;statusNode.textContent='端末のパスキー登録を待っています…';try{let c=await navigator.credentials.create({publicKey:enrollOptions}),credential={id:enc(c.rawId),clientDataJSON:enc(c.response.clientDataJSON),attestationObject:enc(c.response.attestationObject),transports:c.response.getTransports?c.response.getTransports():[]},f=await post('/login',{action:'finish_enrollment',flow:FLOW,csrf:CSRF,credential});if(f.recovery_certificate)downloadCertificate(f.recovery_certificate);statusNode.textContent='登録完了。SSO ID: '+f.public_id+'。復旧証明書を安全な場所に保存してください。（6秒後に設定画面へ移動します）';try{await navigator.clipboard.writeText(f.public_id)}catch(copyError){}setTimeout(()=>location.assign(f.next),6000)}catch(err){button.disabled=false;statusNode.textContent=err.name==='NotAllowedError'?'登録がキャンセルされたか時間切れです。もう一度押してください。':err.message}});document.getElementById('show-password').addEventListener('click',function(){let p=document.getElementById('password'),show=p.type==='password';p.type=show?'text':'password';this.textContent=show?'隠す':'表示'});</script></html>'''
    return (page.replace("__FLOW__", html.escape(flow, quote=True)).replace("__CSRF__", html.escape(csrf, quote=True)).replace("ERROR_SLOT", error_html)).encode("utf-8")


def first_user_id(con):
    """Keep the first registered identity as the administrator permanently."""
    row = con.execute("SELECT MIN(id) AS id FROM users").fetchone()
    return row["id"] if row else None


def is_admin_user(con, user_id):
    first_id = first_user_id(con)
    return first_id is not None and int(user_id) == int(first_id)


def admin_denied_page():
    body = '''<!doctype html>
<html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#f4f7fb"><title>管理者IDが必要です | SSO ID</title><style>
:root{color-scheme:light dark;--ink:#14243a;--muted:#627188;--paper:#fff;--canvas:#f3f6fb;--blue:#2857d9;--line:#dce5ef}*{box-sizing:border-box}body{margin:0;min-height:100vh;min-height:100svh;padding:20px;display:grid;place-items:center;background:radial-gradient(ellipse at 8% 12%,#dce9ff 0,transparent 36%),radial-gradient(ellipse at 95% 90%,#d9f5ed 0,transparent 32%),var(--canvas);color:var(--ink);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.shell{width:min(100%,520px)}.brand{display:flex;align-items:center;gap:11px;margin:0 0 16px 4px;color:#243c60;font-weight:800}.mark{display:grid;place-items:center;width:38px;height:38px;border-radius:12px;background:linear-gradient(145deg,#3568ed,#173fae);color:#fff;font-weight:900}.card{padding:clamp(24px,6vw,36px);border:1px solid #e0e7f0;border-radius:24px;background:var(--paper);box-shadow:0 24px 70px #1b365219}.icon{display:grid;place-items:center;width:50px;height:50px;margin-bottom:19px;border-radius:16px;background:#fff2e9;color:#ba5b21;font-size:1.35rem;font-weight:900}.eyebrow{margin:0 0 7px;color:#ad571f;font-size:.75rem;font-weight:850;letter-spacing:.1em}h1{margin:0;font-size:clamp(1.5rem,5vw,1.85rem);line-height:1.25;letter-spacing:-.03em}p{margin:12px 0 0;color:var(--muted)}.note{margin-top:22px;padding:14px 15px;border:1px solid #f0dfd0;border-radius:13px;background:#fffaf5;color:#70482e;font-size:.88rem}a{display:flex;align-items:center;justify-content:center;min-height:50px;margin-top:22px;padding:11px 16px;border-radius:12px;background:linear-gradient(135deg,#2857d9,#1940b5);color:#fff;text-align:center;text-decoration:none;font-weight:800}a:focus-visible{outline:3px solid #79a0ff;outline-offset:3px}@media(max-width:520px){body{padding:14px}.card{border-radius:20px}}@media(prefers-color-scheme:dark){:root{--ink:#edf3fc;--muted:#aab7c8;--paper:#192432;--canvas:#111923}.card{border-color:#344255;box-shadow:0 24px 70px #0005}body{background:radial-gradient(ellipse at 8% 12%,#203355 0,transparent 38%),var(--canvas)}.brand{color:#dbe7f7}.icon{background:#3b3029;color:#ffc295}.note{border-color:#594638;background:#2c2723;color:#efc7a4}}
</style></head><body><main class="shell"><div class="brand"><span class="mark" aria-hidden="true">S</span><span>2415.jp / SSO ID</span></div><section class="card"><div class="icon" aria-hidden="true">!</div><p class="eyebrow">ADMIN ACCESS REQUIRED</p><h1>管理者IDでログインしてください</h1><p>このSSO IDは契約者モードです。管理者機能には、管理者として登録されたSSO IDでのログインが必要です。</p><div class="note">現在のセッションは管理者権限を持っていません。別のSSO IDでログインし直してください。</div><a href="/logout">別のSSO IDでログイン</a></section></main></body></html>'''
    return body.encode("utf-8")


def expire_session_cookie():
    return ("Set-Cookie", f"{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")


def account_page(user, current_hash, sessions, notice="", registration_onboarding=False):
    csrf = b64u(secrets.token_bytes(32))
    display_name = str(user["display_name"] or "SSO ID ユーザー")
    rows = []
    for row in sessions:
        is_current = hmac.compare_digest(row["token_hash"], current_hash)
        agent = (row["user_agent"] or "ブラウザー情報なし")[:180]
        created = int(row["created_at"] or 0)
        when = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(created)) if created else "記録なし（既存セッション）"
        expires = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(row["expires_at"])))
        revoke = ""
        if not is_current:
            revoke = ("<form method=post action=/account class=card-action><input type=hidden name=csrf value=\"%s\">"
                      "<input type=hidden name=action value=revoke_one><input type=hidden name=session value=\"%s\">"
                      "<button class=secondary>この端末をログアウト</button></form>" %
                      (html.escape(csrf), html.escape(row["token_hash"])))
        device_name = html.escape(agent)
        status_label = "この端末" if is_current else "別の端末"
        rows.append("""<li class="session-card %s" data-search="%s"><div class="session-head"><div><span class="eyebrow">%s</span><h3>%s</h3></div><span class="badge %s">%s</span></div><dl><div><dt>ログイン日時</dt><dd><time class=local-time data-epoch="%d">%s</time></dd></div><div><dt>セッション期限</dt><dd><time class=local-time data-epoch="%d">%s</time></dd></div></dl>%s</li>""" % (
            "is-current" if is_current else "", html.escape(agent.casefold()), status_label, device_name, "current" if is_current else "other", status_label,
            created, html.escape(when), int(row["expires_at"]), html.escape(expires), revoke))
    with db() as con:
        con.execute("UPDATE sessions SET csrf_hash=? WHERE token_hash=? AND revoked_at IS NULL", (hashlib.sha256(csrf.encode()).hexdigest(), current_hash))
    message = "<div class=notice role=status aria-live=polite>%s</div>" % html.escape(notice) if notice else ""
    if registration_onboarding:
        message += '''<section id=registration-onboarding class=controls aria-labelledby=registration-title><h2 id=registration-title>アカウント作成：追加認証の設定</h2><p>SSO ID: <code>%s</code></p><p>認証アプリを設定すると、次回からパスキーに加えて6桁コードも必要になります。設定は任意です。ここで設定する場合は、認証アプリに表示されるキーを登録してから有効化してください。</p><div class=control-buttons><a class=top-link href="#totp-title">認証アプリを設定</a><button id=onboarding-skip class=secondary type=button>TOTPを設定せずに続ける</button><button id=onboarding-continue class=secondary type=button hidden>復旧証明書を保存して続ける</button></div><p id=onboarding-status role=status aria-live=polite></p></section>''' % html.escape(str(user["public_id"] or ""))
    with db() as con:
        is_admin = is_admin_user(con, user["id"])
        passkeys = con.execute("SELECT credential_id,created_at,last_used,transports FROM passkeys WHERE user_id=? ORDER BY created_at", (user["id"],)).fetchall()
        totp_enabled = con.execute("SELECT 1 FROM totp_credentials WHERE user_id=?", (user["id"],)).fetchone() is not None
    if is_admin:
        role_label = "管理者ID"
        mode_card = '''<article class=mode-card><div class=mode-icon admin-icon aria-hidden=true>A</div><div class=mode-copy><span class=eyebrow>ADMINISTRATOR</span><h3>管理者モード</h3><p>2415.jpの管理センターやモバイル管理を開きます。このSSO IDは管理者として登録されています。</p></div><div class=mode-links><a href="https://2415.jp/license/admin_api.php" rel="noreferrer">管理センターを開く <span aria-hidden=true>↗</span></a><a class=quiet-link href="https://2415.jp/license/mobile-manager/?mode=admin" rel="noreferrer">モバイル管理を開く <span aria-hidden=true>↗</span></a><a class=quiet-link href="/admin/identity">利用者のSSO ID回復</a></div></article>'''
    else:
        role_label = "契約者ID"
        mode_card = '''<article class="mode-card tenant-mode"><div class="mode-icon tenant-icon" aria-hidden="true">T</div><div class=mode-copy><span class=eyebrow>CONTRACT HOLDER</span><h3>契約者モード</h3><p>契約者向けテナントAPIキーで製品・ライセンス・利用状況を管理します。複数契約はキーまたは所属契約を切り替えて扱えます。</p></div><div class=mode-links><a href="https://2415.jp/license/tenant-portal/" rel="noreferrer">契約者ポータルを開く <span aria-hidden=true>↗</span></a></div><small class=mode-security>APIキーはSSOへ送信・保存されず、契約者ポータル内で扱います。</small></article>'''
    modes = ('<section class=mode-section aria-labelledby=mode-title><div class=section-title><h2 id=mode-title>利用するモード</h2><span>%s</span></div><div class=mode-grid>%s</div></section>' % (role_label, mode_card))
    mode_css = '''.mode-section{margin:26px 0 4px}.mode-section>.section-title{margin:0 0 12px}.mode-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.mode-card{display:flex;flex-direction:column;align-items:flex-start;gap:12px;min-width:0;padding:18px;border:1px solid var(--line);border-radius:17px;background:var(--surface)}.mode-card.tenant-mode{border-top:3px solid #087e74}.mode-icon{display:grid;place-items:center;width:38px;height:38px;border-radius:12px;background:var(--brand-soft);color:var(--brand);font-weight:850}.mode-icon.tenant-icon{background:#e8f5f3;color:#087e74}.mode-copy h3{margin:4px 0;font-size:1.05rem}.mode-copy p{margin:0;color:var(--muted);font-size:.88rem;line-height:1.6}.mode-links{display:grid;gap:9px;width:100%;margin-top:auto}.mode-links a{display:flex;justify-content:space-between;align-items:center;gap:8px;min-height:42px;padding:9px 12px;border-radius:10px;background:var(--brand);color:#fff;text-decoration:none;font-weight:700;font-size:.86rem}.mode-links a:hover{filter:brightness(.94)}.mode-links a.quiet-link{min-height:34px;padding:5px 2px;background:transparent;color:var(--brand);font-size:.8rem}.mode-security{color:var(--muted);font-size:.76rem;line-height:1.45}@media(max-width:620px){.mode-grid{grid-template-columns:1fr}.mode-card{padding:16px}.mode-section{margin-top:22px}}@media(prefers-color-scheme:dark){.mode-icon.tenant-icon{background:#1c3c38;color:#7bd0c3}}'''
    page = '''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>セッション管理 | SSO ID</title><style>
:root{color-scheme:light dark;--bg:#f3f6fb;--surface:#fff;--text:#17243a;--muted:#5f6e82;--line:#dfe6ef;--brand:#194b93;--brand-soft:#edf4ff;--danger:#a62d3b;--danger-soft:#fff0f1;--good:#16804a;--good-soft:#eaf8f0;--shadow:0 20px 60px #14213d12}*{box-sizing:border-box}body{font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at top left,#e4efff 0,transparent 42%%),var(--bg);color:var(--text);margin:0;min-height:100vh;padding:24px 16px}main{width:min(100%%,760px);margin:0 auto}.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:0 0 22px}.brand{display:flex;align-items:center;gap:11px;color:var(--text);text-decoration:none;font-weight:800;letter-spacing:.01em}.brand-mark{display:grid;place-items:center;width:38px;height:38px;border-radius:12px;background:var(--brand);color:#fff}.top-link{color:var(--brand);font-weight:650;text-decoration:none}.top-link:hover{text-decoration:underline}.panel{background:var(--surface);border:1px solid var(--line);border-radius:24px;padding:clamp(22px,5vw,40px);box-shadow:var(--shadow)}.intro{display:flex;align-items:flex-start;gap:18px}.avatar{flex:0 0 54px;height:54px;border-radius:17px;background:var(--brand-soft);color:var(--brand);display:grid;place-items:center;font-size:1.35rem;font-weight:800}.eyebrow{color:var(--muted);font-size:.78rem;font-weight:750;letter-spacing:.09em;text-transform:uppercase}h1{font-size:clamp(1.55rem,4vw,2rem);line-height:1.2;letter-spacing:-.035em;margin:3px 0 6px}.subhead{color:var(--muted);margin:0}.summary{display:flex;align-items:center;gap:12px;margin:26px 0 8px;padding:15px 17px;border-radius:15px;background:var(--brand-soft)}.summary-number{font-size:1.8rem;line-height:1;font-weight:800;color:var(--brand)}.summary-copy{font-weight:650}.summary-copy small{display:block;color:var(--muted);font-weight:400;margin-top:3px}.notice{margin:16px 0;padding:13px 15px;border:1px solid #b9e7ca;border-radius:13px;background:var(--good-soft);color:var(--good);font-weight:650}.section-title{display:flex;align-items:baseline;justify-content:space-between;gap:12px;margin:30px 0 12px}.section-title h2{font-size:1.05rem;margin:0}.section-title span{font-size:.8rem;color:var(--muted)}ul{list-style:none;padding:0;margin:0;display:grid;gap:12px}.session-card{padding:18px;border:1px solid var(--line);border-radius:17px;background:var(--surface)}.session-card.is-current{border-color:#b8d0f5;box-shadow:inset 3px 0 var(--brand)}.session-head{display:flex;justify-content:space-between;align-items:flex-start;gap:12px}.session-head h3{margin:4px 0 0;font-size:1rem;overflow-wrap:anywhere}.badge{flex:none;display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:999px;font-size:.76rem;font-weight:750}.badge.current{background:var(--good-soft);color:var(--good)}.badge.other{background:#f0f2f5;color:var(--muted)}dl{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:17px 0 0;padding-top:14px;border-top:1px solid var(--line)}dt{color:var(--muted);font-size:.78rem}dd{margin:3px 0 0;font-size:.88rem;font-weight:650}.card-action{margin-top:14px;padding-top:13px;border-top:1px solid var(--line)}button{min-height:44px;padding:10px 15px;border:0;border-radius:11px;font:inherit;font-weight:700;cursor:pointer;transition:transform .12s ease,filter .12s ease}button:hover{filter:brightness(.96)}button:active{transform:translateY(1px)}button:focus-visible,a:focus-visible{outline:3px solid #78aaff;outline-offset:3px}.secondary{background:#eef2f8;color:var(--brand)}.danger{background:var(--danger-soft);color:var(--danger);border:1px solid #f0c4c9}.controls{margin-top:26px;padding-top:22px;border-top:1px solid var(--line)}.controls h2{font-size:1rem;margin:0 0 6px}.controls p{font-size:.88rem;color:var(--muted);margin:0 0 14px}.control-buttons{display:flex;flex-wrap:wrap;gap:10px}.control-buttons form{margin:0}.footer{display:flex;justify-content:space-between;flex-wrap:wrap;gap:12px;margin:18px 4px 0;color:var(--muted);font-size:.82rem}.footer a{color:var(--brand)}@media(max-width:520px){body{padding:12px}.topbar{margin-bottom:13px}.panel{border-radius:19px;padding:21px 17px}.intro{gap:13px}.avatar{flex-basis:46px;height:46px;border-radius:14px}.summary{margin-top:21px}.section-title{margin-top:25px}dl{grid-template-columns:1fr;gap:9px}.control-buttons,.control-buttons form,.control-buttons button{width:100%%}.control-buttons{display:grid}.footer{padding:0 4px}}@media(prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;scroll-behavior:auto!important}}@media(prefers-color-scheme:dark){:root{--bg:#111823;--surface:#192332;--text:#edf3fc;--muted:#a8b5c8;--line:#344153;--brand:#8db7ff;--brand-soft:#223551;--danger:#ff9ca6;--danger-soft:#3a242a;--good:#73d49e;--good-soft:#1d352b;--shadow:0 20px 60px #0005}body{background:radial-gradient(ellipse at top left,#1d3150 0,transparent 42%%),var(--bg)}.badge.other{background:#293546}.secondary{background:#26364b;color:#a9c9ff}}
</style></head><body><main><nav class=topbar aria-label="SSO ID"><a class=brand href="/"><span class=brand-mark aria-hidden=true>S</span><span>SSO ID</span></a><a class=top-link href="/">トップへ戻る</a></nav><section class=panel aria-labelledby=page-title><div class=intro><div class=avatar aria-hidden=true>%s</div><div><span class=eyebrow>アカウントセキュリティ</span><h1 id=page-title>ログイン中の端末</h1><p class=subhead>%s さんのSSOセッションを管理します。</p></div></div><div class=summary><span class=summary-number>%d</span><span class=summary-copy>有効なセッション<small>不要な端末をログアウトすると、連携サイトも次回の確認時にログアウトします。</small></span></div>%s<div class=section-title><h2>端末とログイン情報</h2><span>日時はUTC表記</span></div><ul>%s</ul><section class=controls aria-labelledby=control-title><h2 id=control-title>一括操作</h2><p>ログイン状態に心当たりがない場合は、他の端末またはすべての端末をログアウトしてください。</p><div class=control-buttons><form method=post action=/account><input type=hidden name=csrf value="%s"><input type=hidden name=action value=revoke_others><button class=secondary>他の端末をすべてログアウト</button></form><form method=post action=/account><input type=hidden name=csrf value="%s"><input type=hidden name=action value=revoke_all><button class=danger>すべての端末からログアウト</button></form></div></section></section><footer class=footer><span>セッションは期限が切れると自動的に終了します。</span><a href="/logout?post_logout_redirect_uri=https%%3A%%2F%%2Fsso.2415.jp%%2F">この端末からログアウト</a></footer></main></body></html>''' % (
        html.escape(display_name[:1]), html.escape(display_name), len(sessions), message, "".join(rows), html.escape(csrf), html.escape(csrf))
    page = page.replace("</style>", mode_css + '''.mode-grid{grid-template-columns:minmax(0,1fr)}.role-chip{display:table;align-items:center;gap:7px;margin:0 0 8px;padding:5px 10px;border-radius:999px;background:var(--brand-soft);color:var(--brand);font-size:.76rem;font-weight:800}.role-chip:before{content:"";display:inline-block;vertical-align:middle;margin-right:7px;width:7px;height:7px;border-radius:50%;background:var(--good)}.session-tools{display:flex;align-items:center;gap:12px;margin:-2px 0 13px}.session-tools label{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.session-search{flex:1;min-width:0;min-height:44px;padding:10px 13px;border:1px solid var(--line);border-radius:11px;background:var(--surface);color:var(--text);font:inherit}.result-count{flex:none;color:var(--muted);font-size:.82rem}.session-card[hidden]{display:none}.empty-filter{display:none;padding:20px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:14px}.empty-filter.visible{display:block}.notice{display:flex;align-items:center;gap:9px}.notice:before{content:"✓";display:grid;place-items:center;width:22px;height:22px;flex:none;border-radius:50%;background:var(--good);color:#fff;font-weight:900}.controls{padding:20px;border:1px solid var(--line);border-radius:17px;background:var(--surface)}.danger{font-weight:800}.session-card{transition:border-color .15s ease,box-shadow .15s ease}.session-card:hover{border-color:#a9c3e8;box-shadow:0 8px 24px #14213d0a}@media(max-width:520px){.session-tools{align-items:stretch;flex-direction:column;gap:7px}.result-count{text-align:right}.controls{padding:17px}.intro{align-items:center}}@media(prefers-reduced-motion:reduce){.session-card{transition:none}}''' + "</style>", 1).replace("<div class=summary>", modes + "<div class=summary>", 1)
    account_theme = ":root{--brand:#2857d9;--brand-soft:#edf3ff;--bg:#f3f6fb}body{min-height:100vh;padding:clamp(14px,3vw,30px);background:radial-gradient(ellipse at 8% 8%,#dce9ff 0,transparent 36%),radial-gradient(ellipse at 95% 90%,#d9f5ed 0,transparent 32%),var(--bg)}main{width:min(100%,1020px);margin:auto}.panel{border-radius:24px;box-shadow:0 24px 70px #1b365219}.topbar{padding:2px 4px 15px}.section-title h2{letter-spacing:-.02em}.session-card{border-radius:16px}@media(prefers-color-scheme:dark){body{background:radial-gradient(ellipse at 8% 8%,#203355 0,transparent 38%),var(--bg)}.panel{box-shadow:0 24px 70px #0005}}"
    page = page.replace("</style>", account_theme + "</style>", 1)
    page = page.replace("<span class=eyebrow>アカウントセキュリティ</span>", "<span class=role-chip>" + role_label + "</span><span class=eyebrow>アカウントセキュリティ</span>", 1)
    page = page.replace("<div class=section-title><h2>端末とログイン情報</h2><span>日時はUTC表記</span></div><ul>", "<div class=section-title><h2>端末とログイン情報</h2><span>時刻はお使いの地域に合わせて表示</span></div><div class=session-tools><label for=session-search>端末名で検索</label><input class=session-search id=session-search type=search placeholder=端末名で検索 autocomplete=off><span class=result-count id=session-count aria-live=polite></span></div><ul id=session-list>", 1)
    page = page.replace("</ul><section class=controls", "</ul><p class=empty-filter id=session-empty>一致する端末がありません。検索語を変えてください。</p><section class=controls", 1)
    page = page.replace('<form method=post action=/account><input type=hidden name=csrf value="%s"><input type=hidden name=action value=revoke_all>', '<form method=post action=/account onsubmit="return confirm(\'すべての端末からログアウトします。続けますか？\')"><input type=hidden name=csrf value="%s"><input type=hidden name=action value=revoke_all>', 1)
    with db() as con:
        has_email = bool(con.execute("SELECT recovery_email_hash FROM users WHERE id=?", (user["id"],)).fetchone()["recovery_email_hash"])
        has_certificate = con.execute("SELECT 1 FROM recovery_keys WHERE user_id=? AND certificate_version=1", (user["id"],)).fetchone() is not None
    recovery_markup = '''<section class=controls aria-labelledby=recovery-title><h2 id=recovery-title>アカウント復旧証明書</h2><p id=recovery-email-status role=status aria-live=polite>%s</p><form id=recovery-email-form><label for=recovery-email>復旧用メールアドレス</label><input id=recovery-email type=email inputmode=email autocomplete=email autocapitalize=none spellcheck=false maxlength=254 required><button class=secondary>確認コードを送信</button></form><form id=recovery-code-form hidden><label for=recovery-code>メールの確認コード</label><input id=recovery-code inputmode=numeric autocomplete=one-time-code pattern=[0-9]{8} maxlength=8 required><button class=secondary>メールを確認</button></form><p>パスキーと認証アプリを両方使えない場合、登録済みメールとこの証明書でリセット申請を行えます。証明書は一度だけ発行でき、リセット申請にも一回だけ使用できます。発行後は再ダウンロード・再発行できません。使用後はTOTPも解除されます。</p><button id=recovery-key-button class=secondary type=button data-csrf="%s" %s>%s</button><output id=recovery-key-output hidden></output></section>''' % ("復旧メール確認済み" if has_email else "復旧メール未設定です。ここで確認してください。", html.escape(csrf), "disabled" if has_certificate else "", "復旧証明書は発行済みです。再発行できません" if has_certificate else "パスキーで本人確認して復旧証明書を一度だけ発行")
    page = page.replace("</section></section><footer class=footer>", recovery_markup + "</section></section><footer class=footer>", 1)
    passkey_rows = "".join("<li>登録済みパスキー %d · 登録日時 <time class=local-time data-epoch=\"%d\">%s</time></li>" % (i + 1, int(row["created_at"] or 0), html.escape(time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(row["created_at"] or 0))) if row["created_at"] else "記録なし")) for i, row in enumerate(passkeys))
    passkey_markup = '''<section class=controls aria-labelledby=passkey-title><h2 id=passkey-title>パスキー</h2><p>予備の端末にも登録すると、1台を紛失しても別の端末でログインできます。追加登録には、現在のパスキーで本人確認が必要です。</p><ul>%s</ul><button id=add-passkey class=secondary type=button data-csrf="%s" %s>予備のパスキーを追加</button><p id=passkey-status role=status aria-live=polite></p></section>''' % (passkey_rows or "<li>登録済みパスキーがありません。</li>", html.escape(csrf), "disabled" if len(passkeys) >= 5 else "")
    totp_markup = '''<section class=controls aria-labelledby=totp-title><h2 id=totp-title>認証アプリ（Google Authenticator等）</h2><p id=totp-status role=status aria-live=polite>%s</p>%s<pre id=totp-output hidden></pre><div id=totp-setup hidden><p>アプリでキーを手入力し、表示中の6桁コードを入力してください。キーはこの画面を閉じると再表示できません。</p><p><strong>設定キー:</strong> <code id=totp-secret></code></p><p><a id=totp-uri-link rel="noreferrer">認証アプリで開く</a></p><form id=totp-enable-form><label for=totp-enable-code>アプリの6桁コード</label><input id=totp-enable-code inputmode=numeric autocomplete=one-time-code pattern="[0-9]{6}" maxlength=6 required><button class=secondary>コードを確認して有効化</button></form></div><form id=totp-manage-form%s><label for=totp-manage-code>認証アプリの6桁コード</label><input id=totp-manage-code inputmode=numeric autocomplete=one-time-code pattern="[0-9]{6}" maxlength=6 required><button id=totp-disable class=danger type=button>認証アプリを解除</button></form><button id=totp-begin class=secondary type=button data-csrf="%s" %s>認証アプリを設定</button></section>''' % (
        "認証アプリは有効です。ログイン時はパスキーの後にアプリのコードが必要です。" if totp_enabled else "認証アプリは未設定です。",
        "" if totp_enabled else "", " hidden" if not totp_enabled else "", html.escape(csrf), "hidden" if totp_enabled else "")
    page = page.replace(recovery_markup + "</section></section><footer class=footer>", recovery_markup + passkey_markup + totp_markup + "</section></section><footer class=footer>", 1)
    page = page.replace("</body>", '''<script>(()=>{const input=document.getElementById('session-search'),cards=[...document.querySelectorAll('.session-card')],count=document.getElementById('session-count'),empty=document.getElementById('session-empty');document.querySelectorAll('.local-time').forEach(t=>{const n=Number(t.dataset.epoch);if(n>0){try{t.textContent=new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'short'}).format(new Date(n*1000));t.title=new Date(n*1000).toISOString()}catch(e){}}});const filter=()=>{const q=input.value.trim().toLocaleLowerCase();let shown=0;cards.forEach(c=>{const match=!q||c.dataset.search.includes(q);c.hidden=!match;if(match)shown++});count.textContent=shown+' / '+cards.length+' 台を表示';empty.classList.toggle('visible',shown===0)};input.addEventListener('input',filter);filter();const emailForm=document.getElementById('recovery-email-form'),codeForm=document.getElementById('recovery-code-form'),emailStatus=document.getElementById('recovery-email-status'),keyButton=document.getElementById('recovery-key-button'),keyOutput=document.getElementById('recovery-key-output');let emailFlow='';const csrf=keyButton.dataset.csrf,enc=x=>{let s='';new Uint8Array(x).forEach(v=>s+=String.fromCharCode(v));return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')},dec=x=>Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-x.length%4)%4)),c=>c.charCodeAt(0));async function post(url,data){const r=await fetch(url,{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}),j=await r.json();if(!r.ok||!j.ok)throw new Error(j.message||'処理できませんでした');return j}emailForm.addEventListener('submit',async e=>{e.preventDefault();emailStatus.textContent='確認コードを送信しています…';try{const j=await post('/account/recovery-email/start',{csrf,email:document.getElementById('recovery-email').value});emailFlow=j.flow;codeForm.hidden=false;emailStatus.textContent=j.message;document.getElementById('recovery-code').focus()}catch(err){emailStatus.textContent=err.message}});codeForm.addEventListener('submit',async e=>{e.preventDefault();emailStatus.textContent='コードを確認しています…';try{const j=await post('/account/recovery-email/verify',{csrf,flow:emailFlow,code:document.getElementById('recovery-code').value,email:document.getElementById('recovery-email').value});emailStatus.textContent=j.message;codeForm.hidden=true;emailForm.hidden=true}catch(err){emailStatus.textContent=err.message}});function downloadCertificate(cert){const a=document.createElement('a'),url=URL.createObjectURL(new Blob([JSON.stringify(cert,null,2)],{type:'application/json'}));a.href=url;a.download=(String(cert.subject||'SSO').replace(/[^A-Za-z0-9_-]/g,'')||'SSO')+'-recovery-certificate.json';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500)};keyButton.addEventListener('click',async()=>{keyButton.disabled=true;emailStatus.textContent='パスキーで本人確認しています…';try{const b=await post('/account/recovery-key/begin',{csrf});b.publicKey.challenge=dec(b.publicKey.challenge);b.publicKey.allowCredentials=b.publicKey.allowCredentials.map(x=>({type:'public-key',id:dec(x.id),transports:x.transports||[]}));const c=await navigator.credentials.get({publicKey:b.publicKey}),j=await post('/account/recovery-key/finish',{csrf,flow:b.flow,credential:{id:enc(c.rawId),clientDataJSON:enc(c.response.clientDataJSON),authenticatorData:enc(c.response.authenticatorData),signature:enc(c.response.signature),userHandle:c.response.userHandle?enc(c.response.userHandle):''}});keyOutput.hidden=false;downloadCertificate(j.recovery_certificate);keyOutput.hidden=false;keyOutput.textContent='復旧証明書をダウンロードしました。安全な場所に保管してください。再発行・再ダウンロードはできません。';emailStatus.textContent='復旧証明書を保存してください。';keyButton.textContent='復旧証明書は一度だけ発行可能'}catch(err){emailStatus.textContent=err.name==='NotAllowedError'?'本人確認を完了できませんでした。もう一度お試しください。':err.message}finally{keyButton.disabled=false}});const add=document.getElementById('add-passkey'),ps=document.getElementById('passkey-status');add?.addEventListener('click',async()=>{add.disabled=true;ps.textContent='現在のパスキーで本人確認してください…';try{let s=await post('/account/passkey/add/begin',{csrf});s.publicKey.challenge=dec(s.publicKey.challenge);s.publicKey.allowCredentials=s.publicKey.allowCredentials.map(x=>({type:'public-key',id:dec(x.id),transports:x.transports||[]}));const a=await navigator.credentials.get({publicKey:s.publicKey});s=await post('/account/passkey/add/verify',{csrf,flow:s.flow,credential:{id:enc(a.rawId),clientDataJSON:enc(a.response.clientDataJSON),authenticatorData:enc(a.response.authenticatorData),signature:enc(a.response.signature),userHandle:a.response.userHandle?enc(a.response.userHandle):''}});s.publicKey.challenge=dec(s.publicKey.challenge);s.publicKey.user.id=dec(s.publicKey.user.id);s.publicKey.excludeCredentials=s.publicKey.excludeCredentials.map(x=>({type:'public-key',id:dec(x.id),transports:x.transports||[]}));ps.textContent='新しい端末でパスキーを登録してください…';const c=await navigator.credentials.create({publicKey:s.publicKey});await post('/account/passkey/add/finish',{csrf,flow:s.flow,credential:{id:enc(c.rawId),clientDataJSON:enc(c.response.clientDataJSON),attestationObject:enc(c.response.attestationObject),transports:c.response.getTransports?c.response.getTransports():[]}});ps.textContent='予備のパスキーを追加しました。';location.reload()}catch(err){ps.textContent=err.name==='NotAllowedError'?'操作がキャンセルされました。もう一度お試しください。':err.message;add.disabled=false}})})()</script></body>''', 1)
    totp_script = '''<script>(()=>{const start=document.getElementById('totp-begin'),status=document.getElementById('totp-status'),setup=document.getElementById('totp-setup'),secret=document.getElementById('totp-secret'),uriLink=document.getElementById('totp-uri-link'),output=document.getElementById('totp-output'),csrf=start.dataset.csrf,onboarding=document.getElementById('registration-onboarding'),onboardingStatus=document.getElementById('onboarding-status'),skip=document.getElementById('onboarding-skip'),continueButton=document.getElementById('onboarding-continue');let flow='';const enc=x=>{let s='';new Uint8Array(x).forEach(v=>s+=String.fromCharCode(v));return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')},dec=x=>Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-x.length%4)%4)),c=>c.charCodeAt(0));function downloadCertificate(cert){const a=document.createElement('a'),url=URL.createObjectURL(new Blob([JSON.stringify(cert,null,2)],{type:'application/json'}));a.href=url;a.download=(String(cert.subject||'SSO').replace(/[^A-Za-z0-9_-]/g,'')||'SSO')+'-recovery-certificate.json';document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1500)}async function post(url,data){const r=await fetch(url,{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)}),j=await r.json();if(!r.ok||!j.ok)throw new Error(j.message||'処理できませんでした。');return j}async function finishOnboarding(action,button){button.disabled=true;onboardingStatus.textContent='ログインを完了しています…';try{const j=await post('/account/onboarding/complete',{csrf,action});location.assign(j.next)}catch(err){onboardingStatus.textContent=err.message;button.disabled=false}}if(onboarding){skip.addEventListener('click',()=>finishOnboarding('skip',skip));continueButton.addEventListener('click',()=>finishOnboarding('continue',continueButton))}start.addEventListener('click',async()=>{start.disabled=true;status.textContent='登録済みパスキーで本人確認しています…';try{let b=await post('/account/totp/begin',{csrf});b.publicKey.challenge=dec(b.publicKey.challenge);b.publicKey.allowCredentials=b.publicKey.allowCredentials.map(x=>({type:'public-key',id:dec(x.id),transports:x.transports||[]}));const a=await navigator.credentials.get({publicKey:b.publicKey});const s=await post('/account/totp/verify-passkey',{csrf,flow:b.flow,credential:{id:enc(a.rawId),clientDataJSON:enc(a.response.clientDataJSON),authenticatorData:enc(a.response.authenticatorData),signature:enc(a.response.signature),userHandle:a.response.userHandle?enc(a.response.userHandle):''}});flow=s.flow;secret.textContent=s.secret;uriLink.href=s.otpauth_uri;setup.hidden=false;start.hidden=true;status.textContent='認証アプリへ設定キーを登録し、次のコードで有効化してください。'}catch(err){status.textContent=err.name==='NotAllowedError'?'パスキー確認を完了できませんでした。':err.message;start.disabled=false}});document.getElementById('totp-enable-form').addEventListener('submit',async e=>{e.preventDefault();const button=e.currentTarget.querySelector('button');button.disabled=true;try{const j=await post('/account/totp/enable',{csrf,flow,code:document.getElementById('totp-enable-code').value.trim()});if(j.recovery_certificate){downloadCertificate(j.recovery_certificate);output.hidden=false;output.textContent='復旧証明書をダウンロードしました。安全な場所に保管してください。'}else{output.hidden=false;output.textContent='復旧証明書は登録時に発行済みです。'}status.textContent='認証アプリを有効にしました。';setup.hidden=true;document.getElementById('totp-manage-form').hidden=false;document.getElementById('totp-begin').hidden=true;if(onboarding){skip.hidden=true;continueButton.hidden=false;onboardingStatus.textContent='復旧証明書をダウンロードしました。保存先を確認してから続けてください。'}}catch(err){status.textContent=err.message;button.disabled=false}});const code=document.getElementById('totp-manage-code');document.getElementById('totp-disable').addEventListener('click',async()=>{if(!window.confirm('認証アプリを解除しますか？ログイン時の追加認証が無効になります。'))return;const button=document.getElementById('totp-disable');button.disabled=true;try{await post('/account/totp/disable',{csrf,code:code.value.trim()});status.textContent='認証アプリを解除しました。';location.reload()}catch(err){status.textContent=err.message;button.disabled=false}})})();</script>'''
    page = page.replace("</body>", totp_script + "</body>", 1)
    return page.encode("utf-8")


def client_for(con, client_id: str):
    return con.execute("SELECT client_id,secret_hash,redirect_uri,active FROM clients WHERE client_id=?", (client_id,)).fetchone()


def valid_authorize(p, con):
    client = client_for(con, p.get("client_id", ""))
    if not client or not client["active"]:
        return None, "invalid_client"
    if p.get("response_type") != "code" or p.get("scope") != "openid":
        return None, "unsupported_response_type"
    allowed = con.execute("SELECT redirect_uri FROM client_redirect_uris WHERE client_id=?", (client["client_id"],)).fetchall()
    allowed_uris = {client["redirect_uri"], *(row["redirect_uri"] for row in allowed)}
    if p.get("redirect_uri", "") not in allowed_uris:
        return None, "invalid_redirect_uri"
    challenge = p.get("code_challenge", "")
    if p.get("code_challenge_method") != "S256" or not re.fullmatch(r"[A-Za-z0-9_-]{43}", challenge) or not p.get("state") or len(p["state"]) > 512 or not p.get("nonce") or len(p["nonce"]) > 256:
        return None, "invalid_request"
    return client, ""


def issue_code(con, p, user_id, sid_hash):
    code = b64u(secrets.token_bytes(32))
    con.execute("INSERT INTO auth_codes(code_hash,client_id,user_id,redirect_uri,challenge,nonce,auth_time,expires_at,sid_hash) VALUES(?,?,?,?,?,?,?,?,?)",
                (hashlib.sha256(code.encode()).hexdigest(), p["client_id"], user_id, p["redirect_uri"], p["code_challenge"], p["nonce"], int(time.time()), int(time.time()) + CODE_TTL, sid_hash))
    return code


def recovery_page():
    csrf = b64u(secrets.token_bytes(32))
    page = '''<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="referrer" content="no-referrer">
<meta name="theme-color" content="#f4f7fb">
<title>パスキー再設定 | SSO ID</title>
<style>
:root{color-scheme:light dark;--ink:#14243a;--muted:#627188;--line:#dce5ef;--paper:#fff;--canvas:#f3f6fb;--blue:#2857d9;--blue-dark:#1940b5;--teal:#17a995;--focus:#3a72ff}
*{box-sizing:border-box}
html{min-height:100%;background:var(--canvas)}
body{margin:0;min-height:100vh;min-height:100svh;padding:max(20px,env(safe-area-inset-top)) 18px max(20px,env(safe-area-inset-bottom));display:grid;place-items:center;color:var(--ink);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 8% 12%,#dce9ff 0,transparent 35%),radial-gradient(ellipse at 95% 90%,#d9f5ed 0,transparent 32%),var(--canvas)}
.shell{width:min(100%,520px)}
.brand{display:flex;align-items:center;gap:11px;margin:0 0 18px 4px;color:#243c60;font-weight:800;letter-spacing:.02em}
.brand-mark{width:38px;height:38px;display:grid;place-items:center;border-radius:12px;background:linear-gradient(145deg,#3568ed,#173fae);color:white;box-shadow:0 7px 16px #204cb333}
.brand-mark svg{width:22px;height:22px}
.card{overflow:hidden;border:1px solid #e0e7f0;border-radius:24px;background:var(--paper);box-shadow:0 24px 70px #1b365219}
.card-head{padding:30px 34px 22px}
.kicker{margin:0 0 9px;color:var(--blue);font-size:.76rem;font-weight:850;letter-spacing:.12em;text-transform:uppercase}
h1{margin:0;font-size:clamp(1.55rem,5vw,1.9rem);line-height:1.22;letter-spacing:-.035em}
.lead{max-width:42ch;margin:12px 0 0;color:var(--muted);font-size:.96rem}
.steps{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:24px 0 0;padding:0;list-style:none}
.steps li{position:relative;display:flex;align-items:center;gap:8px;min-width:0;color:#8a97a9;font-size:.76rem;font-weight:700}
.steps li:before{content:"";width:24px;height:24px;flex:0 0 24px;border:1px solid #cbd5e2;border-radius:50%;background:#f7f9fc}
.steps li:after{content:"";position:absolute;left:28px;right:3px;top:11px;height:2px;background:#e5ebf2;transform:translateX(100%);z-index:0}
.steps li:last-child:after{display:none}
.steps .is-current{border-color:#b9cdf6;background:#f3f7ff;color:var(--blue)}.steps .is-current:before{border:6px solid #dce7ff;background:var(--blue)}
.steps .is-done{color:#148270}.steps .is-done:before{content:"✓";display:grid;place-items:center;border-color:#a8e2d7;background:#e6f8f3;color:#148270;font-size:.8rem}.steps .is-done:after{background:#b8e8de}
.security-note{display:grid;gap:5px;margin:20px 0 0;padding:14px 16px;border:1px solid #d6e3fb;border-left:4px solid var(--blue);border-radius:13px;background:#f5f8ff;color:#293b58;font-size:.88rem}.security-note strong{font-size:.91rem}.security-note span{color:var(--muted)}
.panel{padding:24px 34px 30px;border-top:1px solid #edf1f6;background:linear-gradient(180deg,#fbfcfe,#fff 46%)}
.form-title{margin:0 0 5px;font-size:1.06rem;font-weight:800}.form-copy{margin:0 0 18px;color:var(--muted);font-size:.9rem}
.field{margin:17px 0 0}.field label{display:block;margin:0 0 7px;font-size:.88rem;font-weight:750}
.field input{display:block;width:100%;min-height:52px;padding:12px 14px;border:1px solid #cdd7e4;border-radius:12px;background:#fff;color:var(--ink);font:inherit;font-size:16px;transition:border-color .15s,box-shadow .15s}
.field input::placeholder{color:#9aa6b6}.field input:focus{outline:0;border-color:var(--focus);box-shadow:0 0 0 4px #3a72ff24}
button{width:100%;min-height:52px;margin-top:20px;padding:12px 16px;border:0;border-radius:13px;background:linear-gradient(135deg,var(--blue),var(--blue-dark));color:#fff;font:inherit;font-weight:800;letter-spacing:.01em;cursor:pointer;box-shadow:0 8px 18px #2857d92e;transition:transform .12s,filter .12s,box-shadow .12s}
button:hover{filter:brightness(1.06);box-shadow:0 11px 22px #2857d936}button:active{transform:translateY(1px)}button:focus-visible,a:focus-visible{outline:3px solid #79a0ff;outline-offset:3px}button:disabled{opacity:.65;cursor:wait;box-shadow:none}
button.secondary{border:1px solid #c8d6f4;background:#eef3ff;color:#244bb8;box-shadow:none}
#verify,#totp-verify,#register,#check-passkey{display:none}
#status{min-height:25px;margin:17px 0 0;padding:12px 14px;border:1px solid #dbe5f2;border-radius:12px;background:#f6f8fc;color:#41536c;font-size:.9rem;font-weight:650;overflow-wrap:anywhere}
#status:empty{min-height:0;margin-top:0}
#done{padding:18px;border:1px solid #bce5dc;border-radius:14px;background:#effbf7}#done p{margin:0 0 9px;color:#176958}#done a{display:inline-block;margin-top:5px;color:#1d4ec3;font-weight:750}
.privacy{display:flex;gap:9px;align-items:flex-start;margin:16px 0 0;color:#718096;font-size:.79rem}.privacy svg{width:17px;height:17px;flex:none;margin-top:2px;color:#168a78}
.footer{display:flex;justify-content:space-between;gap:10px;margin:15px 4px 0;color:#7b899b;font-size:.75rem}.footer a{color:#4664a0;font-weight:700;text-decoration:none}.footer a:hover{text-decoration:underline}
@media(max-width:520px){body{place-items:start center;padding:16px 12px max(16px,env(safe-area-inset-bottom));background:linear-gradient(180deg,#eaf1ff,#f4f8fc 42%,#eff8f5)}.shell{margin:auto 0}.brand{margin:2px 0 13px 3px;font-size:.94rem}.card{border-radius:20px}.card-head{padding:25px 22px 19px}.panel{padding:21px 22px 24px}.steps{grid-template-columns:repeat(2,minmax(0,1fr));gap:7px;margin-top:20px}.steps li{gap:7px;min-height:42px;padding:8px;border:1px solid var(--line);border-radius:11px;background:#fafcff;font-size:.75rem}.steps li:before{width:21px;height:21px;flex-basis:21px}.steps li:after{display:none}.security-note{margin-top:16px;padding:12px}.footer{font-size:.7rem}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important}}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--ink:#edf3fc;--muted:#aab7c8;--line:#354356;--paper:#192432;--canvas:#111923}.brand{color:#dbe7f7}.brand-mark{box-shadow:none}body{background:radial-gradient(ellipse at 8% 12%,#203355 0,transparent 38%),radial-gradient(ellipse at 95% 90%,#12382f 0,transparent 35%),var(--canvas)}.card{border-color:#344255;box-shadow:0 24px 70px #0005}.panel{border-color:#2b394b;background:linear-gradient(180deg,#1d2a3a,#192432 55%)}.steps li{background:#1d2a3a}.steps li:before{border-color:#4a5a70;background:#243246}.steps li:after{background:#36465b}.steps .is-current{border-color:#4b6598;background:#202f4a;color:#b9ccff}.steps .is-current:before{border-color:#324f88;background:var(--blue)}.steps .is-done:before{border-color:#286c60;background:#183c38;color:#75d4c1}.steps .is-done:after{background:#286c60}.security-note{border-color:#344968;background:#202d42;color:#e0eaff}.field input{border-color:#45566c;background:#111a26;color:var(--ink)}.field input:focus{border-color:#7195ff;box-shadow:0 0 0 4px #7195ff24}button.secondary{border-color:#425b92;background:#202f4c;color:#b9caff}#status{border-color:#36465a;background:#1a2737;color:#c3cede}#done{border-color:#286c60;background:#183c38}#done p{color:#9ce2d2}#done a,.footer a{color:#a8c1ff}.privacy,.footer{color:#95a3b7}}
</style>
</head>
<body>
<main class="shell">
  <div class="brand"><span class="brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M12 2.5 20 6v5.2c0 5.1-3.4 8.6-8 10.3-4.6-1.7-8-5.2-8-10.3V6l8-3.5Z" stroke="currentColor" stroke-width="1.8"/><path d="M9.4 11.8a2.6 2.6 0 1 1 4.7 1.5l3 3h-2.4v1.5h-2v-1.9l-1.4-1.4a2.6 2.6 0 0 1-1.9-2.7Z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/></svg></span><span>2415.jp <span style="font-weight:600;opacity:.72">/ SSO ID</span></span></div>
  <section class="card" aria-labelledby="page-title">
    <header class="card-head">
      <p class="kicker">SECURE ACCOUNT RECOVERY</p>
      <h1 id="page-title">パスキーを再設定</h1>
      <p class="lead">パスキーが使えない場合は、登録メールと認証アプリ、または一回限りの復旧証明書で本人確認して再設定します。</p>
      <ol class="steps" aria-label="再設定の手順">
        <li class="is-current" data-step="1" aria-current="step">パスキー確認</li>
        <li data-step="2" aria-current="false">メール確認</li>
        <li data-step="3" aria-current="false">追加の本人確認</li>
        <li data-step="4" aria-current="false">パスキー登録</li>
      </ol>
      <aside class="security-note" role="note"><strong>再設定にはメール確認と追加の本人確認が必要です</strong><span>認証アプリを使えない場合は、事前に保存した復旧証明書をアップロードしてください。証明書を使うとパスキーとTOTPをリセットします。</span></aside>
    </header>
    <div class="panel">
      <form id="start" autocomplete="on">
        <input type="hidden" id="csrf" value="__CSRF__">
        <h2 class="form-title">本人確認を開始</h2>
        <p class="form-copy">まずSIDに登録されたパスキーを確認します。メールアドレスは、パスキーを使えない場合のOTP送信に使います。</p>
        <div class="field"><label for="id">SSO ID</label><input id="id" autocomplete="username" autocapitalize="characters" spellcheck="false" placeholder="SID-…" required></div>
        <div class="field"><label for="email">登録済みメールアドレス</label><input id="email" type="email" inputmode="email" autocomplete="email" autocapitalize="none" spellcheck="false" placeholder="name@example.jp" required maxlength="254"></div>
        <div class="field"><label for="recovery-certificate">復旧証明書ファイル（JSON・任意）</label><input id="recovery-certificate" type="file" accept=".json,application/json"></div>
        <button type="submit">本人確認を開始</button>
        <p class="privacy"><svg viewBox="0 0 24 24" fill="none" aria-hidden="true"><path d="M12 3 20 6v5c0 5-3.4 8-8 10-4.6-2-8-5-8-10V6l8-3Z" stroke="currentColor" stroke-width="1.8"/><path d="m8.5 12 2.2 2.2 4.8-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg><span>確認コードは、パスキーで本人確認できなかった場合にだけ送信されます。</span></p>
      </form>
      <form id="verify" autocomplete="on">
        <h2 class="form-title">メールの確認コード</h2>
        <p class="form-copy">届いた8桁のコードを入力してください。有効期限は10分です。</p>
        <div class="field"><label for="code">確認コード</label><input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{8}" maxlength="8" placeholder="12345678" required></div>
        <button type="submit">コードを確認して次へ</button>
      </form>
      <form id="totp-verify" autocomplete="on">
        <h2 class="form-title">Google Authenticatorの確認コード</h2>
        <p class="form-copy">メール確認コードに続けて、事前登録済み認証アプリの6桁コードを入力してください。両方の確認後、登録済みパスキーを失効させます。</p>
        <div class="field"><label for="totp-code">Google OTP</label><input id="totp-code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" placeholder="123456" required></div>
        <button type="submit">Google OTPを確認</button>
      </form>
      <button id="check-passkey" class="secondary" type="button">登録済みパスキーで本人確認</button>
      <button id="register" type="button">新しいパスキーを登録</button>
      <section id="done" hidden aria-live="polite"><p id="result"></p><p>この端末のパスキー登録が完了しました。</p><a href="/">ログインへ戻る</a></section>
      <p id="status" role="status" aria-live="polite"></p>
    </div>
  </section>
  <footer class="footer"><a href="/">ログインに戻る</a><span>保護されたSSO ID設定</span></footer>
</main>
<script>(()=>{const csrf=document.getElementById('csrf').value,status=document.getElementById('status'),start=document.getElementById('start'),verify=document.getElementById('verify'),totpVerify=document.getElementById('totp-verify'),checkPasskey=document.getElementById('check-passkey'),register=document.getElementById('register'),done=document.getElementById('done');let flow='',options=null,existingOptions=null,recoveryCertificate=null;const stepItems=[...document.querySelectorAll('[data-step]')];function setStep(n){stepItems.forEach((el,i)=>{el.classList.toggle('is-done',i+1<n);el.classList.toggle('is-current',i+1===n);el.setAttribute('aria-current',i+1===n?'step':'false')})}const enc=x=>{let s='';new Uint8Array(x).forEach(v=>s+=String.fromCharCode(v));return btoa(s).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'')},dec=x=>Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-x.length%4)%4)),c=>c.charCodeAt(0));async function post(path,data){const r=await fetch(path,{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const j=await r.json();if(!r.ok||!j.ok)throw new Error(j.message||'入力内容を確認してください');return j}start.addEventListener('submit',async e=>{e.preventDefault();status.textContent='登録情報を確認しています…';try{const public_id=document.getElementById('id').value.trim().toUpperCase();recoveryCertificate=null;const certFile=document.getElementById('recovery-certificate').files[0];if(certFile){if(certFile.size>8192)throw new Error('復旧証明書ファイルが大きすぎます。');recoveryCertificate=JSON.parse(await certFile.text());if(recoveryCertificate.format!=='2415.jp/sso-recovery-certificate'||recoveryCertificate.version!==1||recoveryCertificate.issuer!=='https://sso.2415.jp'||recoveryCertificate.subject!==public_id)throw new Error('復旧証明書の対象SSO IDが一致しません。')}const begin=await post('/recover/passkey-begin',{csrf,public_id,certificate:recoveryCertificate});if(begin.hasPasskey){flow=begin.flow;existingOptions=begin.existingPasskey;existingOptions.challenge=dec(existingOptions.challenge);existingOptions.allowCredentials=existingOptions.allowCredentials.map(x=>({type:'public-key',id:dec(x.id),transports:x.transports||[]}));start.hidden=true;setStep(1);checkPasskey.style.display='block';status.textContent='このSIDに登録されたパスキーで本人確認してください。ボタンを押すと認証が始まります。';return}const j=await post('/recover/start',{csrf,public_id,email:document.getElementById('email').value,certificate:recoveryCertificate});if(!j.flow){status.textContent=j.message||'入力内容が一致しないか、確認コードを送信できませんでした。SSO IDと登録済みメールアドレスを確認してください。';return}flow=j.flow;start.hidden=true;setStep(2);verify.style.display='block';status.textContent='確認コードを送信しました。メールを確認してください。';document.getElementById('code').focus()}catch(err){status.textContent=err.message}});
checkPasskey.addEventListener('click',async()=>{checkPasskey.disabled=true;status.textContent='パスキー認証を待っています…';try{const c=await navigator.credentials.get({publicKey:existingOptions});const r=await fetch('/recover/passkey-check',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json'},body:JSON.stringify({csrf,flow,credential:{id:enc(c.rawId),clientDataJSON:enc(c.response.clientDataJSON),authenticatorData:enc(c.response.authenticatorData),signature:enc(c.response.signature),userHandle:c.response.userHandle?enc(c.response.userHandle):''}})});const j=await r.json();if(r.status===409&&j.error==='existing_passkey_verified'){checkPasskey.style.display='none';setStep(1);status.textContent='本人確認できました。このSSO IDのリセットは不要です。登録済みパスキーでログインしてください。';return}if(!r.ok)throw new Error(j.message||'パスキーを確認できませんでした。もう一度お試しください。');throw new Error('登録済みパスキーを確認できませんでした。')}catch(err){if(err.name==='NotAllowedError'){try{await post('/recover/allow-reset',{csrf,flow});await post('/recover/send-otp',{csrf,flow,email:document.getElementById('email').value,certificate:recoveryCertificate});checkPasskey.style.display='none';setStep(2);verify.style.display='block';status.textContent='パスキーで本人確認できなかったため、メールに確認コードを送信しました。';document.getElementById('code').focus()}catch(nextError){checkPasskey.disabled=false;status.textContent=nextError.message}}else{checkPasskey.disabled=false;status.textContent=err.message}}});
verify.addEventListener('submit',async e=>{e.preventDefault();status.textContent='メールコードを確認しています…';try{const j=await post('/recover/verify',{csrf,flow,code:document.getElementById('code').value,email:document.getElementById('email').value});verify.hidden=true;if(j.certificate_accepted){options=j.publicKey;options.challenge=dec(options.challenge);options.user.id=dec(options.user.id);setStep(4);register.style.display='block';status.textContent='復旧証明書とメールを確認しました。パスキーとTOTPはリセット済みです。新しいパスキーを登録してください。'}else{setStep(3);totpVerify.style.display='block';status.textContent='メールを確認しました。続けて認証アプリの6桁コードを入力してください。';document.getElementById('totp-code').focus()}}catch(err){status.textContent=err.message}});totpVerify.addEventListener('submit',async e=>{e.preventDefault();const button=e.currentTarget.querySelector('button');button.disabled=true;status.textContent='Google OTPを確認しています…';try{const j=await post('/recover/totp-verify',{csrf,flow,code:document.getElementById('totp-code').value.trim()});options=j.publicKey;options.challenge=dec(options.challenge);options.user.id=dec(options.user.id);totpVerify.hidden=true;setStep(4);register.style.display='block';status.textContent='メールとGoogle OTPを確認しました。既存パスキーを失効しました。新しいパスキーを登録してください。'}catch(err){button.disabled=false;status.textContent=err.message}});register.addEventListener('click',async()=>{register.disabled=true;status.textContent='パスキー登録を待っています…';try{const c=await navigator.credentials.create({publicKey:options});const j=await post('/recover/finish',{csrf,flow,credential:{id:enc(c.rawId),clientDataJSON:enc(c.response.clientDataJSON),attestationObject:enc(c.response.attestationObject),transports:c.response.getTransports?c.response.getTransports():[]}});register.style.display='none';done.hidden=false;setStep(4);document.getElementById('result').textContent='パスキーの再設定が完了しました。';status.textContent='パスキーを再設定しました。ログインしてください。'}catch(err){register.disabled=false;status.textContent=err.name==='NotAllowedError'?'登録がキャンセルされました。もう一度お試しください。':err.message}})})()</script></body></html>'''
    return page.replace("__CSRF__", html.escape(csrf, quote=True)).encode("utf-8")


def identity_home_page(user=None):
    if user:
        content = ('''<p class="eyebrow">SIGNED IN</p><h1>ようこそ、%s さん</h1><p class="lead">SSO IDで保護されたセッションが有効です。アカウント設定から端末やログイン状態を管理できます。</p><div class="actions"><a class="primary" href="/account">アカウントを管理 <span aria-hidden="true">→</span></a><a class="secondary" href="/logout?post_logout_redirect_uri=https%%3A%%2F%%2Fsso.2415.jp%%2F">この端末からログアウト</a></div>''' % html.escape(user["display_name"] or "ユーザー"))
    else:
        content = '''<p class="eyebrow">IDENTITY FOR YOUR APPS</p><h1>ひとつのSSO IDで<br>安全にログイン</h1><p class="lead">SSO IDは、2415.jpの連携アプリで使う共通認証サービスです。ログインは各連携アプリから開始してください。</p><div class="features"><div><b>パスキー認証</b><span>生体認証や端末ロックで確認</span></div><div><b>アカウント保護</b><span>端末ごとのセッションを管理</span></div></div><div class="actions"><a class="primary" href="/.well-known/openid-configuration">連携情報を見る <span aria-hidden="true">→</span></a><a class="secondary" href="/recover">パスキーを再設定</a></div>'''
    return ('''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="referrer" content="no-referrer"><meta name="theme-color" content="#f4f7fb"><title>SSO ID | 2415.jp</title><style>
:root{color-scheme:light dark;--ink:#14243a;--muted:#627188;--paper:#fff;--canvas:#f3f6fb;--blue:#2857d9;--blue-dark:#1940b5;--line:#dce5ef}*{box-sizing:border-box}body{margin:0;min-height:100vh;min-height:100svh;padding:20px;display:grid;place-items:center;color:var(--ink);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:radial-gradient(ellipse at 8% 12%,#dce9ff 0,transparent 36%),radial-gradient(ellipse at 95% 90%,#d9f5ed 0,transparent 32%),var(--canvas)}main{width:min(100%,800px)}.brand{display:flex;align-items:center;gap:11px;margin:0 0 16px 4px;color:#243c60;font-weight:800}.mark{display:grid;place-items:center;width:38px;height:38px;border-radius:12px;background:linear-gradient(145deg,#3568ed,#173fae);color:white;font-weight:900;box-shadow:0 7px 16px #204cb333}.card{overflow:hidden;border:1px solid #e0e7f0;border-radius:26px;background:var(--paper);box-shadow:0 24px 70px #1b365219}.hero{padding:clamp(30px,7vw,58px)}.eyebrow{margin:0 0 10px;color:var(--blue);font-size:.76rem;font-weight:850;letter-spacing:.12em}.hero h1{margin:0;font-size:clamp(2rem,6vw,3.35rem);line-height:1.12;letter-spacing:-.045em}.lead{max-width:55ch;margin:17px 0 0;color:var(--muted);font-size:1.02rem}.features{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:28px}.features div{display:grid;gap:4px;padding:16px;border:1px solid var(--line);border-radius:15px;background:#f8faff}.features b{font-size:.91rem}.features span{color:var(--muted);font-size:.82rem}.actions{display:flex;flex-wrap:wrap;gap:10px;margin-top:30px}.actions a{display:flex;align-items:center;justify-content:center;gap:12px;min-height:50px;padding:11px 17px;border:1px solid var(--line);border-radius:12px;color:var(--ink);font-weight:800;text-decoration:none}.actions a.primary{border:0;background:linear-gradient(135deg,var(--blue),var(--blue-dark));color:white;box-shadow:0 8px 18px #2857d92e}.actions a:hover{filter:brightness(1.04)}a:focus-visible{outline:3px solid #79a0ff;outline-offset:3px}.foot{display:flex;justify-content:space-between;gap:12px;margin:14px 4px 0;color:#7b899b;font-size:.75rem}@media(max-width:520px){body{padding:14px 12px}.card{border-radius:20px}.hero{padding:27px 22px 25px}.features{grid-template-columns:1fr;gap:8px;margin-top:22px}.features div{padding:13px}.actions{display:grid;margin-top:23px}.actions a{width:100%}.foot{font-size:.69rem}}@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important}}@media(prefers-color-scheme:dark){:root{--ink:#edf3fc;--muted:#aab7c8;--paper:#192432;--canvas:#111923;--line:#354356}body{background:radial-gradient(ellipse at 8% 12%,#203355 0,transparent 38%),radial-gradient(ellipse at 95% 90%,#12382f 0,transparent 35%),var(--canvas)}.brand{color:#dbe7f7}.mark{box-shadow:none}.card{border-color:#344255;box-shadow:0 24px 70px #0005}.features div{background:#202d3d}.foot{color:#95a3b7}}
</style></head><body><main><div class="brand"><span class="mark" aria-hidden="true">S</span><span>2415.jp / SSO ID</span></div><section class="card hero">%s</section><footer class="foot"><span>安全なシングルサインオン</span><span>sso.2415.jp</span></footer></main></body></html>'''.replace("%s", content)).encode("utf-8")


def _app_impl(environ, start_response):
    path = environ.get("PATH_INFO", "")
    method = environ.get("REQUEST_METHOD", "GET")
    if path.startswith("/mnsl-signing/"):
        from mnsl_signing import handle
        return handle(environ, start_response, DATA)
    if path in ("/acount.php", "/account.php") and method in ("GET", "HEAD"):
        return response(start_response, "302 Found", b"", headers=[("Location", "/account")])
    if path in ("/", "/authorize", "/login", "/login/begin", "/login/totp", "/logout", "/account", "/recover", "/token", "/userinfo", "/session/introspect") or path.startswith("/recover/") or path.startswith("/admin/identity/") or path.startswith("/account/recovery-key/") or path.startswith("/account/recovery-email/") or path.startswith("/account/passkey/") or path.startswith("/account/totp/") or path.startswith("/contractor/"):
        if DB.is_file():
            ensure_session_schema()
    # Rolling browser idle timeout. API clients that authenticate with bearer
    # credentials remain governed by their explicit token/session expiry.
    if cookie(environ, COOKIE) and path != "/logout":
        touch_browser_session(environ)
    if path == "/healthz" and method == "GET":
        checks = readiness_checks()
        ready = all(status == "ok" for status in checks.values())
        return json_response(
            start_response,
            "200 OK" if ready else "503 Service Unavailable",
            {"ok": ready, "issuer": ISSUER, "checks": checks},
            headers=[("X-TUTI-SSO-Revision", "sso-login-security-20261103")],
        )
    # Public authentication endpoints are cheap to flood and are also credential
    # guessing surfaces. Apply an atomic per-source fixed-window limit before
    # parsing credentials; REMOTE_ADDR is used directly (never trust X-Forwarded-For).
    rate_policy = {
        "/login/begin": (60, 300), "/login": (45, 300),
        "/token": (60, 60), "/session/introspect": (300, 60),
        "/contractor/register/start": (20, 3600), "/contractor/verify": (30, 300),
        "/contractor/finish": (20, 300), "/recover/start": (10, 3600),
        "/admin/identity/search": (20, 300), "/admin/identity/resolve": (30, 300), "/admin/identity/list-members": (30, 300), "/admin/identity/delete": (8, 3600),
        "/recover/verify": (15, 300), "/recover/totp-verify": (8, 300), "/recover/passkey-begin": (20, 300),
        "/recover/passkey-check": (20, 300), "/recover/allow-reset": (10, 300),
        "/recover/send-otp": (5, 3600), "/recover/finish": (10, 300),
        "/account/recovery-email/start": (10, 3600), "/account/recovery-email/verify": (20, 300),
        "/account/recovery-key/begin": (20, 300), "/account/recovery-key/finish": (20, 300),
        "/account/passkey/add/begin": (20, 300), "/account/passkey/add/verify": (20, 300),
        "/account/passkey/add/finish": (10, 300),
        "/login/totp": (12, 300), "/account/onboarding/complete": (8, 300), "/account/totp/begin": (12, 300),
        "/account/totp/verify-passkey": (12, 300), "/account/totp/enable": (12, 300),
        "/account/totp/disable": (12, 300),
    }
    remote = str(environ.get("REMOTE_ADDR", "unknown"))[:128] or "unknown"
    auth_surface = (method == "POST" and path in rate_policy) or (method == "GET" and path == "/authorize")
    if auth_surface and not consume_security_rate_limit(
            security_rate_key("ip:auth-surface", remote), GLOBAL_AUTH_RATE_LIMIT, GLOBAL_AUTH_RATE_WINDOW):
        return json_response(start_response, "429 Too Many Requests", {"error": "rate_limited", "message": "試行回数が上限に達しました。時間をおいて再度お試しください。"}, headers=[("Retry-After", "60")])
    if method == "POST" and path in rate_policy:
        maximum, window_seconds = rate_policy[path]
        rate_key = security_rate_key("ip:" + path, remote)
        if not consume_security_rate_limit(rate_key, maximum, window_seconds):
            return json_response(start_response, "429 Too Many Requests", {"error": "rate_limited", "message": "試行回数が上限に達しました。時間をおいて再度お試しください。"}, headers=[("Retry-After", "60")])
    if path == "/contractor/register" and method == "GET":
        return response(start_response, "200 OK", contractor_register_page(), "text/html; charset=utf-8", headers=[("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer")])
    if path == "/contractor/register/start" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f = fields(environ)
            if str(f.get("website", "")).strip():
                return json_response(start_response, "202 Accepted", {"ok": True})
            now = int(time.time())
            remote = str(environ.get("REMOTE_ADDR", ""))[:128]
            ip_hash = hmac.new(EMAIL_KEY.read_bytes()[:32], b"sso-contractor-register-ip-v1|" + remote.encode("utf-8", "replace"), hashlib.sha256).hexdigest()
            with db() as con:
                con.execute("DELETE FROM contractor_registration_ip_events WHERE created_at<?", (now - 3600,))
                recent = con.execute("SELECT COUNT(*) AS n FROM contractor_registration_ip_events WHERE ip_hash=? AND created_at>?", (ip_hash, now - 3600)).fetchone()["n"]
                if recent >= 5:
                    return json_response(start_response, "202 Accepted", {"ok": True})
                con.execute("INSERT INTO contractor_registration_ip_events(ip_hash,created_at) VALUES(?,?)", (ip_hash, now))
            address = str(f.get("email", "")).strip().casefold()
            if not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", address) or len(address) > 254:
                return json_response(start_response, "400 Bad Request", {"error": "invalid_email"})
            lookup = email_lookup(address)
            with db() as con:
                exists = con.execute("SELECT 1 FROM users WHERE recovery_email_hash=? OR email=? LIMIT 1", (lookup, lookup)).fetchone()
                previous = con.execute("SELECT created_at FROM contractor_invites WHERE email_lookup=? ORDER BY created_at DESC LIMIT 1", (lookup,)).fetchone()
            # Keep the response identical for existing identities and throttled addresses.
            if exists or (previous and now - int(previous["created_at"]) < 60):
                return json_response(start_response, "202 Accepted", {"ok": True})
            flow = b64u(secrets.token_bytes(32))
            flow_hash = hashlib.sha256(flow.encode("ascii")).hexdigest()
            code = "%06d" % secrets.randbelow(1000000)
            salt = secrets.token_bytes(16)
            code_hash = hmac.new(EMAIL_KEY.read_bytes()[:32], b"sso-contractor-invite-v1|" + salt + flow_hash.encode("ascii") + code.encode("ascii"), hashlib.sha256).hexdigest()
            with db() as con:
                con.execute("DELETE FROM contractor_invites WHERE email_lookup=?", (lookup,))
                con.execute("INSERT INTO contractor_invites(flow_hash,email_lookup,email_encrypted,public_id,user_handle,code_salt,code_hash,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                            (flow_hash, lookup, encrypt_private_value(address, "email"), new_public_id(), new_user_handle(), salt.hex(), code_hash, now + 86400, now))
            setup_url = ISSUER + "/contractor/setup?flow=" + flow
            if not send_contractor_invite(address, code, setup_url):
                with db() as con:
                    con.execute("DELETE FROM contractor_invites WHERE flow_hash=?", (flow_hash,))
                return json_response(start_response, "503 Service Unavailable", {"error": "registration_mail_failed"})
            return json_response(start_response, "202 Accepted", {"ok": True})
        except Exception:
            return json_response(start_response, "400 Bad Request", {"error": "invalid_request"})
    if path == "/contractor/invite" and method == "POST":
        try:
            f = fields(environ)
            address = str(f.get("email", "")).strip().casefold()
            tenant_id = str(f.get("tenant_id", "")).strip()
            sid = str(f.get("sid", ""))
            if not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", address) or len(address) > 254 or not re.fullmatch(r"[1-9][0-9]{0,18}", tenant_id):
                return json_response(start_response, "400 Bad Request", {"error":"invalid_email"})
            now = int(time.time())
            lookup = email_lookup(address)
            flow = b64u(secrets.token_bytes(32))
            flow_hash = hashlib.sha256(flow.encode("ascii")).hexdigest()
            code = "%06d" % secrets.randbelow(1000000)
            salt = secrets.token_bytes(16)
            code_hash = hmac.new(EMAIL_KEY.read_bytes()[:32], b"sso-contractor-invite-v1|" + salt + flow_hash.encode("ascii") + code.encode("ascii"), hashlib.sha256).hexdigest()
            with db() as con:
                if not valid_admin_api_request(environ, con, sid):
                    return json_response(start_response, "403 Forbidden", {"error":"admin_session_required"})
                exists = con.execute("SELECT 1 FROM users WHERE recovery_email_hash=? OR email=? LIMIT 1", (lookup, lookup)).fetchone()
                if exists:
                    return json_response(start_response, "409 Conflict", {"error":"identity_already_exists"})
                previous = con.execute("SELECT created_at FROM contractor_invites WHERE email_lookup=? ORDER BY created_at DESC LIMIT 1", (lookup,)).fetchone()
                if previous and now - int(previous["created_at"]) < 60:
                    return json_response(start_response, "429 Too Many Requests", {"error":"invite_rate_limited"})
                public_id = new_public_id()
                con.execute("DELETE FROM contractor_invites WHERE email_lookup=?", (lookup,))
                con.execute("INSERT INTO contractor_invites(flow_hash,email_lookup,email_encrypted,public_id,user_handle,code_salt,code_hash,expires_at,created_at,tenant_id) VALUES(?,?,?,?,?,?,?,?,?,?)",
                            (flow_hash, lookup, encrypt_private_value(address, "email"), public_id, new_user_handle(), salt.hex(), code_hash, now + 86400, now, tenant_id))
            setup_url = ISSUER + "/contractor/setup?flow=" + flow
            if not send_contractor_invite(address, code, setup_url):
                with db() as con: con.execute("DELETE FROM contractor_invites WHERE flow_hash=?", (flow_hash,))
                return json_response(start_response, "503 Service Unavailable", {"error":"invite_mail_failed"})
            return json_response(start_response, "202 Accepted", {"ok":True, "tenant_id":tenant_id})
        except Exception:
            return json_response(start_response, "400 Bad Request", {"error":"invalid_request"})
    if path == "/admin/identity" and method == "GET":
        token = cookie(environ, COOKIE)
        token_hash = hashlib.sha256(token.encode()).hexdigest() if token else ""
        with db() as con:
            session = con.execute("SELECT s.user_id,s.token_hash,s.created_at,u.active FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL", (token_hash, int(time.time()))).fetchone()
            if not session or not session["active"] or not is_admin_user(con, session["user_id"]):
                return response(start_response, "403 Forbidden", b"Administrator SSO login required.", "text/plain; charset=utf-8")
            now = int(time.time())
            if now - int(session["created_at"] or 0) > 120:
                return response(start_response, "428 Precondition Required", "<html lang=ja><meta charset=utf-8><title>再認証が必要です</title><main style='font:16px system-ui;max-width:600px;margin:12vh auto;padding:24px'><h1>パスキーで再認証してください</h1><p>利用者アカウントの削除には、直近2分以内の管理者パスキー認証が必要です。管理センターから再認証した後、この画面を開き直してください。</p><p><a href='https://2415.jp/license/admin_api.php'>管理センターに戻る</a></p></main></html>".encode(), "text/html; charset=utf-8", headers=[("Cache-Control", "no-store")])
            csrf = b64u(secrets.token_bytes(32))
            con.execute("UPDATE sessions SET csrf_hash=? WHERE token_hash=?", (hashlib.sha256(csrf.encode()).hexdigest(), token_hash))
        return response(start_response, "200 OK", admin_identity_page(csrf), "text/html; charset=utf-8", headers=[("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer")])
    if path in ("/admin/identity/search", "/admin/identity/resolve", "/admin/identity/list-members", "/admin/identity/delete") and method == "POST":
        try:
            f = fields(environ)
            sid = str(f.get("sid", ""))
            with db() as con:
                if not valid_admin_api_request(environ, con, sid) and not valid_admin_browser_request(environ, con, f):
                    return json_response(start_response, "403 Forbidden", {"error": "admin_session_required"})
                if path.endswith("/resolve"):
                    public_id = str(f.get("public_id", "")).strip().upper()
                    if not re.fullmatch(r"SID-[A-Z2-7]{26}", public_id):
                        return json_response(start_response, "400 Bad Request", {"error": "invalid_public_id"})
                    user = con.execute("SELECT u.public_id,u.display_name,g.sub FROM users u JOIN global_subjects g ON g.user_id=u.id WHERE u.public_id=? AND u.active=1 LIMIT 1", (public_id,)).fetchone()
                    record_identity_admin_audit(con, environ, sid, "resolve_for_temporary_grant", security_rate_key("sso-admin-grant-target", public_id), bool(user), int(time.time()))
                    con.commit()
                    if not user:
                        return json_response(start_response, "404 Not Found", {"ok": True, "found": False}, [("Cache-Control", "no-store")])
                    return json_response(start_response, "200 OK", {"ok": True, "found": True, "identity": {"public_id": str(user["public_id"]), "display_name": str(user["display_name"] or ""), "sub": str(user["sub"] or "")}}, [("Cache-Control", "no-store")])
                if path.endswith("/list-members"):
                    raw_hashes = str(f.get("subject_hashes", ""))
                    hashes = list(dict.fromkeys(part for part in raw_hashes.split(",") if re.fullmatch(r"[a-f0-9]{64}", part)))
                    if not hashes or len(hashes) > 200 or len(hashes) != len([p for p in raw_hashes.split(",") if p]):
                        return json_response(start_response, "400 Bad Request", {"error": "invalid_subject_list"})
                    wanted = set(hashes)
                    matches = []
                    placeholders = ",".join("?" for _ in hashes)
                    users = con.execute("SELECT h.subject_hash,u.public_id,u.display_name FROM global_subject_hashes h JOIN users u ON u.id=h.user_id WHERE u.active=1 AND h.subject_hash IN (" + placeholders + ") ORDER BY u.public_id", hashes).fetchall()
                    matches = [{"subject_hash": str(user["subject_hash"]), "public_id": str(user["public_id"]), "display_name": str(user["display_name"] or "")} for user in users]
                    record_identity_admin_audit(con, environ, sid, "list_tenant_members", security_rate_key("sso-tenant-members", ",".join(sorted(wanted))), True, int(time.time()))
                    con.commit()
                    return json_response(start_response, "200 OK", {"ok": True, "identities": matches}, [("Cache-Control", "no-store")])
                if path.endswith("/search"):
                    address = str(f.get("email", "")).strip().casefold()
                    if len(address) > 254 or not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", address):
                        return json_response(start_response, "400 Bad Request", {"error": "invalid_email"})
                    lookup = email_lookup(address)
                    matches = con.execute("SELECT id,public_id,display_name,created_at FROM users WHERE active=1 AND recovery_email_hash=? ORDER BY id LIMIT 2", (lookup,)).fetchall()
                    if not matches:
                        for candidate in con.execute("SELECT id,public_id,display_name,created_at,email_encrypted FROM users WHERE active=1 AND recovery_email_hash='' AND email_encrypted<>'' ORDER BY id LIMIT 500").fetchall():
                            try:
                                if hmac.compare_digest(email_lookup(decrypt_private_value(candidate["email_encrypted"], "email")), lookup):
                                    matches.append(candidate)
                                    if len(matches) > 1:
                                        break
                            except Exception:
                                continue
                    if len(matches) > 1:
                        record_identity_admin_audit(con, environ, sid, "lookup", lookup, False, int(time.time()))
                        con.commit()
                        return json_response(start_response, "409 Conflict", {"error": "ambiguous_identity"})
                    if not matches:
                        record_identity_admin_audit(con, environ, sid, "lookup", lookup, False, int(time.time()))
                        con.commit()
                        return json_response(start_response, "200 OK", {"ok": True, "found": False}, [("Cache-Control", "no-store")])
                    user = matches[0]
                    record_identity_admin_audit(con, environ, sid, "lookup", lookup, True, int(time.time()))
                    con.commit()
                    return json_response(start_response, "200 OK", {"ok": True, "found": True, "identity": {"public_id": user["public_id"], "display_name": user["display_name"], "created_at": user["created_at"]}}, [("Cache-Control", "no-store")])
                public_id = str(f.get("public_id", "")).strip().upper()
                address = str(f.get("email", "")).strip().casefold()
                if not re.fullmatch(r"SID-[A-Z2-7]{26}", public_id) or len(address) > 254 or not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", address):
                    return json_response(start_response, "400 Bad Request", {"error": "invalid_confirmation"})
                lookup = email_lookup(address)
                con.execute("BEGIN IMMEDIATE")
                target = con.execute("SELECT id,recovery_email_hash,email_encrypted FROM users WHERE public_id=? AND active=1", (public_id,)).fetchone()
                email_matches = bool(target and target["recovery_email_hash"] and hmac.compare_digest(target["recovery_email_hash"], lookup))
                if target and not email_matches and not target["recovery_email_hash"] and target["email_encrypted"]:
                    try:
                        email_matches = hmac.compare_digest(email_lookup(decrypt_private_value(target["email_encrypted"], "email")), lookup)
                    except Exception:
                        email_matches = False
                if not target or not email_matches:
                    con.rollback()
                    return json_response(start_response, "404 Not Found", {"error": "identity_not_found"})
                user_id = int(target["id"])
                if is_admin_user(con, user_id):
                    con.rollback()
                    return json_response(start_response, "403 Forbidden", {"error": "protected_administrator"})
                now = int(time.time())
                con.execute("DELETE FROM login_flows WHERE flow_hash IN (SELECT flow_hash FROM passkey_flows WHERE user_id=?)", (user_id,))
                con.execute("DELETE FROM login_flows WHERE flow_hash IN (SELECT login_flow_hash FROM mfa_flows WHERE user_id=?)", (user_id,))
                for table in ("passkeys", "totp_credentials", "recovery_keys", "recovery_flows", "recovery_limits", "recovery_email_setup", "totp_setup_flows", "mfa_flows", "passkey_flows", "registration_onboarding"):
                    con.execute("DELETE FROM " + table + " WHERE user_id=?", (user_id,))
                con.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (now, user_id))
                con.execute("DELETE FROM auth_codes WHERE user_id=?", (user_id,))
                con.execute("DELETE FROM access_tokens WHERE user_id=?", (user_id,))
                con.execute("UPDATE users SET active=0,email='deleted:'||public_id,email_encrypted='',email_verified=0,recovery_email_hash='',display_name=public_id,password_salt='',password_hash='' WHERE id=?", (user_id,))
                record_identity_admin_audit(con, environ, sid, "delete", public_id, True, now)
                con.commit()
            return json_response(start_response, "200 OK", {"ok": True, "deleted": True}, [("Cache-Control", "no-store")])
        except Exception:
            try:
                con.rollback()
            except Exception:
                pass
            return json_response(start_response, "400 Bad Request", {"error": "invalid_request"})
    if path == "/contractor/setup" and method == "GET":
        flow = query(environ).get("flow", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{40,50}", flow):
            return response(start_response, "400 Bad Request", b"Invalid invitation.", "text/plain; charset=utf-8")
        with db() as con:
            invite = con.execute("SELECT verified_at FROM contractor_invites WHERE flow_hash=? AND expires_at>?", (hashlib.sha256(flow.encode("ascii")).hexdigest(), int(time.time()))).fetchone()
        if not invite:
            return response(start_response, "410 Gone", b"This invitation has expired.", "text/plain; charset=utf-8")
        return response(start_response, "200 OK", contractor_setup_page(flow), "text/html; charset=utf-8", headers=[("Cache-Control","no-store"),("Referrer-Policy","no-referrer")])
    if path == "/contractor/verify" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER: return json_response(start_response, "403 Forbidden", {"error":"origin_rejected"})
        try:
            f=fields(environ); flow=str(f.get("flow","")); code=str(f.get("code","")); now=int(time.time())
            if not re.fullmatch(r"[A-Za-z0-9_-]{40,50}",flow): return json_response(start_response,"400 Bad Request",{"error":"invalid_invitation"})
            flow_hash=hashlib.sha256(flow.encode("ascii")).hexdigest()
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                invite=con.execute("SELECT * FROM contractor_invites WHERE flow_hash=? AND expires_at>?",(flow_hash,now)).fetchone()
                if not invite or invite["verified_at"] or invite["attempts"]>=5:
                    con.rollback(); return json_response(start_response,"410 Gone",{"error":"invitation_expired"})
                valid=bool(re.fullmatch(r"[0-9]{6}",code))
                supplied=code.encode("ascii") if valid else b"invalid"
                expected=hmac.new(EMAIL_KEY.read_bytes()[:32],b"sso-contractor-invite-v1|"+bytes.fromhex(invite["code_salt"])+flow_hash.encode("ascii")+supplied,hashlib.sha256).hexdigest()
                if now>int(invite["created_at"])+600 or not valid or not hmac.compare_digest(expected,invite["code_hash"]):
                    attempts=int(invite["attempts"])+1
                    if attempts>=5: con.execute("DELETE FROM contractor_invites WHERE flow_hash=?",(flow_hash,))
                    else: con.execute("UPDATE contractor_invites SET attempts=? WHERE flow_hash=?",(attempts,flow_hash))
                    con.commit(); return json_response(start_response,"400 Bad Request",{"error":"verification_failed","message":"確認コードが違うか、有効期限が切れています。"})
                challenge=b64u(secrets.token_bytes(32))
                con.execute("UPDATE contractor_invites SET verified_at=?,passkey_challenge=? WHERE flow_hash=?",(now,challenge,flow_hash)); con.commit()
                public_id=invite["public_id"]; user_handle=invite["user_handle"]
            return json_response(start_response,"200 OK",{"ok":True,"publicKey":{"challenge":challenge,"rp":{"id":PASSKEY_RP_ID,"name":"SSO ID 2415.jp"},"user":{"id":user_handle,"name":public_id,"displayName":public_id},"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"timeout":120000,"attestation":"none","authenticatorSelection":{"residentKey":"required","requireResidentKey":True,"userVerification":"required"}}})
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"invalid_request"})
    if path == "/contractor/finish" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER: return json_response(start_response, "403 Forbidden", {"error":"origin_rejected"})
        try:
            f=fields(environ); flow=str(f.get("flow","")); credential=f.get("credential") or {}; now=int(time.time())
            if not re.fullmatch(r"[A-Za-z0-9_-]{40,50}",flow) or not isinstance(credential,dict): return json_response(start_response,"400 Bad Request",{"error":"invalid_invitation"})
            flow_hash=hashlib.sha256(flow.encode("ascii")).hexdigest()
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                invite=con.execute("SELECT * FROM contractor_invites WHERE flow_hash=? AND expires_at>? AND verified_at>? AND passkey_challenge IS NOT NULL",(flow_hash,now,now-600)).fetchone()
                if not invite: con.rollback(); return json_response(start_response,"410 Gone",{"error":"invitation_expired"})
                registered=webauthn_registration(credential.get("clientDataJSON",""),credential.get("attestationObject",""),invite["passkey_challenge"],credential.get("id",""))
                transports=json.dumps([x for x in credential.get("transports",[]) if x in ("usb","nfc","ble","internal","hybrid")])
                cursor=con.execute("INSERT INTO users(email,email_encrypted,email_verified,display_name,password_salt,password_hash,active,created_at,public_id,user_handle,recovery_email_hash,tenant_id) VALUES(?, '',0,?,'','',1,?,?,?,?,?)",("deleted:"+invite["public_id"],invite["public_id"],now,invite["public_id"],invite["user_handle"],invite["email_lookup"],invite["tenant_id"]))
                user_id=cursor.lastrowid
                con.execute("INSERT INTO passkeys(credential_id,user_id,public_key,sign_count,transports,created_at) VALUES(?,?,?,?,?,?)",(registered["credential_id"],user_id,registered["public_key"],registered["counter"],transports,now))
                public_id=invite["public_id"]
                certificate=new_recovery_certificate(public_id,now)
                con.execute("INSERT INTO recovery_keys(user_id,key_hash,created_at,used_at,certificate_version) VALUES(?,?,?,NULL,1)",(user_id,recovery_key_hash(certificate["credential"]),now))
                session=b64u(secrets.token_bytes(32));csrf=b64u(secrets.token_bytes(32));session_hash=hashlib.sha256(session.encode()).hexdigest()
                con.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at,user_agent,csrf_hash) VALUES(?,?,?,?,?,?)",(session_hash,user_id,now+SESSION_TTL,now,environ.get("HTTP_USER_AGENT","")[:180],hashlib.sha256(csrf.encode()).hexdigest()))
                con.execute("INSERT INTO registration_onboarding(session_hash,user_id,request_json,expires_at) VALUES(?,?,?,?)",(session_hash,user_id,"",now+1800))
                con.execute("DELETE FROM contractor_invites WHERE flow_hash=?",(flow_hash,)); con.commit()
            return json_response(start_response,"200 OK",{"ok":True,"onboarding":True,"next":"/account","public_id":public_id,"recovery_certificate":certificate},[("Set-Cookie",f"{COOKIE}={session}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"),("Cache-Control","no-store")])
        except sqlite3.IntegrityError:
            return json_response(start_response,"409 Conflict",{"error":"identity_already_exists"})
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"passkey_registration_failed","message":"パスキーを登録できませんでした。招待メールからやり直してください。"})
    if path == "/.well-known/openid-configuration" and method == "GET":
        return json_response(start_response, "200 OK", {
            "issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize",
            "token_endpoint": ISSUER + "/token", "userinfo_endpoint": ISSUER + "/userinfo",
            "jwks_uri": ISSUER + "/jwks", "end_session_endpoint": ISSUER + "/logout",
            "response_types_supported": ["code"], "grant_types_supported": ["authorization_code"],
            "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
            "scopes_supported": ["openid"], "token_endpoint_auth_methods_supported": ["client_secret_basic"],
            "code_challenge_methods_supported": ["S256"],
        })
    if path == "/jwks" and method == "GET":
        try:
            return json_response(start_response, "200 OK", {"keys": [rsa_public_jwk()]})
        except Exception:
            return json_response(start_response, "503 Service Unavailable", {"error": "signing_key_unavailable"})
    if path == "/admin/update/sign":
        return sign_mnsl_update_manifest(environ, start_response)
    if path == "/recover" and method == "GET":
        return response(start_response, "200 OK", recovery_page(), "text/html; charset=utf-8", headers=[("Cache-Control", "no-store")])
    if path == "/account/recovery-email/start" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER: return json_response(start_response, "403 Forbidden", {"error":"origin_rejected"})
        try:
            f=fields(environ); token=cookie(environ,COOKIE); token_hash=hashlib.sha256(token.encode()).hexdigest() if token else ""; address=f.get("email","").strip(); now=int(time.time())
            if len(address)>254 or not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+",address): return json_response(start_response,"400 Bad Request",{"error":"invalid_email","message":"メールアドレスを確認してください。"})
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                current=con.execute("SELECT s.user_id,s.csrf_hash FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1",(token_hash,now)).fetchone()
                if not current or not hmac.compare_digest(current["csrf_hash"],hashlib.sha256(f.get("csrf","").encode()).hexdigest()): return json_response(start_response,"403 Forbidden",{"error":"csrf_validation_failed"})
                limit=con.execute("SELECT * FROM recovery_limits WHERE user_id=?",(current["user_id"],)).fetchone(); window=limit["window_started"] if limit and now-limit["window_started"]<3600 else now; sends=limit["sends"] if limit and now-limit["window_started"]<3600 else 0
                if limit and (limit["locked_until"]>now or now-limit["last_sent_at"]<60 or sends>=3): con.rollback(); return json_response(start_response,"429 Too Many Requests",{"error":"recovery_rate_limited","message":"時間をおいてから再度お試しください。"})
                con.execute("INSERT OR REPLACE INTO recovery_limits(user_id,last_sent_at,window_started,sends,attempt_window,attempts,locked_until) VALUES(?,?,?,?,?,?,?)",(current["user_id"],now,window,sends+1,now,0,0)); con.commit()
                flow=b64u(secrets.token_bytes(32)); flow_hash=hashlib.sha256(flow.encode()).hexdigest(); code="%08d"%secrets.randbelow(100000000); salt=secrets.token_bytes(16)
                con.execute("DELETE FROM recovery_email_setup WHERE user_id=?",(current["user_id"],)); con.execute("INSERT INTO recovery_email_setup(flow_hash,user_id,csrf_hash,email_hash,code_salt,code_hash,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?)",(flow_hash,current["user_id"],hashlib.sha256(f.get("csrf","").encode()).hexdigest(),email_lookup(address),salt.hex(),recovery_code_hash(flow_hash,salt,code),now+600,now))
            if not send_recovery_code(address,code):
                with db() as con: con.execute("DELETE FROM recovery_email_setup WHERE flow_hash=?",(flow_hash,))
                return json_response(start_response,"503 Service Unavailable",{"error":"mail_unavailable","message":"メールを送信できませんでした。"})
            return json_response(start_response,"200 OK",{"ok":True,"flow":flow,"message":"確認コードを送りました。メールをご確認ください。"},[("Cache-Control","no-store")])
        except Exception: return json_response(start_response,"400 Bad Request",{"error":"invalid_request"})
    if path == "/account/recovery-email/verify" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER: return json_response(start_response,"403 Forbidden",{"error":"origin_rejected"})
        try:
            f=fields(environ); token=cookie(environ,COOKIE); token_hash=hashlib.sha256(token.encode()).hexdigest() if token else ""; flow_hash=hashlib.sha256(f.get("flow","").encode()).hexdigest(); now=int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE"); current=con.execute("SELECT s.user_id,s.csrf_hash FROM sessions s WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL",(token_hash,now)).fetchone(); pending=con.execute("SELECT * FROM recovery_email_setup WHERE flow_hash=? AND expires_at>?",(flow_hash,now)).fetchone()
                if not current or not pending or current["user_id"]!=pending["user_id"] or not hmac.compare_digest(current["csrf_hash"],hashlib.sha256(f.get("csrf","").encode()).hexdigest()) or not hmac.compare_digest(pending["csrf_hash"],hashlib.sha256(f.get("csrf","").encode()).hexdigest()):
                    con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"invalid_recovery_flow"})
                code=f.get("code",""); valid=re.fullmatch(r"[0-9]{8}",code) and hmac.compare_digest(pending["code_hash"],recovery_code_hash(flow_hash,bytes.fromhex(pending["code_salt"]),code))
                if not valid:
                    attempts=pending["attempts"]+1; con.execute("UPDATE recovery_email_setup SET attempts=? WHERE flow_hash=?",(attempts,flow_hash))
                    if attempts>=5: con.execute("DELETE FROM recovery_email_setup WHERE flow_hash=?",(flow_hash,))
                    con.commit(); return json_response(start_response,"400 Bad Request",{"error":"invalid_code","message":"確認コードが違うか期限切れです。"})
                # Address is never written; only this keyed verifier remains.
                address=f.get("email","").strip()
                if len(address)>254 or not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+",address): con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"invalid_email"})
                if not hmac.compare_digest(pending["email_hash"], email_lookup(address)):
                    con.execute("DELETE FROM recovery_email_setup WHERE flow_hash=?",(flow_hash,)); con.commit()
                    return json_response(start_response,"400 Bad Request",{"error":"email_mismatch","message":"確認コードを送信したメールアドレスと一致しません。もう一度最初から入力してください。"})
                con.execute("UPDATE users SET recovery_email_hash=? WHERE id=?",(pending["email_hash"],current["user_id"])); con.execute("DELETE FROM recovery_email_setup WHERE flow_hash=?",(flow_hash,)); con.commit()
            return json_response(start_response,"200 OK",{"ok":True,"message":"復旧用メールを確認しました。アドレスは保存せず照合値のみ保持します。"},[("Cache-Control","no-store")])
        except Exception: return json_response(start_response,"400 Bad Request",{"error":"invalid_request"})
    if path == "/account/recovery-key/begin" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER: return json_response(start_response,"403 Forbidden",{"error":"origin_rejected"})
        try:
            f=fields(environ); token=cookie(environ,COOKIE); token_hash=hashlib.sha256(token.encode()).hexdigest() if token else ""; now=int(time.time())
            with db() as con:
                current=con.execute("SELECT s.user_id,s.csrf_hash,u.public_id,u.user_handle FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1",(token_hash,now)).fetchone()
                if not current or not hmac.compare_digest(current["csrf_hash"],hashlib.sha256(f.get("csrf","").encode()).hexdigest()): return json_response(start_response,"403 Forbidden",{"error":"csrf_validation_failed"})
                keys=con.execute("SELECT credential_id,transports FROM passkeys WHERE user_id=?",(current["user_id"],)).fetchall()
                if not keys: return json_response(start_response,"409 Conflict",{"error":"passkey_missing"})
                issued=con.execute("SELECT 1 FROM recovery_keys WHERE user_id=? AND certificate_version=1",(current["user_id"],)).fetchone()
                if issued: return json_response(start_response,"409 Conflict",{"error":"recovery_certificate_already_issued","message":"復旧証明書はすでに発行済みです。再発行できません。"},[("Cache-Control","no-store")])
                flow=b64u(secrets.token_bytes(32)); flow_hash=hashlib.sha256(flow.encode()).hexdigest(); challenge=b64u(secrets.token_bytes(32)); con.execute("INSERT OR REPLACE INTO passkey_flows(flow_hash,user_id,challenge,mode,expires_at) VALUES(?,?,?,?,?)",(flow_hash,current["user_id"],challenge,"recovery_key",now+300))
            return json_response(start_response,"200 OK",{"ok":True,"flow":flow,"publicKey":{"challenge":challenge,"rpId":PASSKEY_RP_ID,"timeout":120000,"userVerification":"required","allowCredentials":[{"type":"public-key","id":k["credential_id"],"transports":json.loads(k["transports"] or "[]")} for k in keys]}},[("Cache-Control","no-store")])
        except Exception: return json_response(start_response,"400 Bad Request",{"error":"invalid_request"})
    if path == "/account/recovery-key/finish" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER: return json_response(start_response,"403 Forbidden",{"error":"origin_rejected"})
        try:
            f=fields(environ); token=cookie(environ,COOKIE); token_hash=hashlib.sha256(token.encode()).hexdigest() if token else ""; flow_hash=hashlib.sha256(f.get("flow","").encode()).hexdigest(); cred=f.get("credential") or {}; now=int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE"); current=con.execute("SELECT s.user_id,s.csrf_hash,u.public_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1",(token_hash,now)).fetchone(); pending=con.execute("SELECT * FROM passkey_flows WHERE flow_hash=? AND mode='recovery_key' AND expires_at>?",(flow_hash,now)).fetchone()
                if not current or not pending or current["user_id"]!=pending["user_id"] or not hmac.compare_digest(current["csrf_hash"],hashlib.sha256(f.get("csrf","").encode()).hexdigest()): con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"invalid_recovery_flow"})
                keyrow=con.execute("SELECT * FROM passkeys WHERE credential_id=? AND user_id=?",(cred.get("id",""),current["user_id"])).fetchone()
                if not keyrow: con.rollback(); return json_response(start_response,"401 Unauthorized",{"error":"invalid_passkey"})
                count=webauthn_assertion(cred.get("clientDataJSON",""),cred.get("authenticatorData",""),cred.get("signature",""),pending["challenge"],keyrow["public_key"],keyrow["sign_count"],cred.get("userHandle",""))
                if con.execute("SELECT 1 FROM recovery_keys WHERE user_id=? AND certificate_version=1",(current["user_id"],)).fetchone():
                    con.rollback(); return json_response(start_response,"409 Conflict",{"error":"recovery_certificate_already_issued","message":"復旧証明書はすでに発行済みです。再発行できません。"},[("Cache-Control","no-store")])
                con.execute("UPDATE passkeys SET sign_count=?,last_used=? WHERE credential_id=?",(count,now,keyrow["credential_id"])); certificate=new_recovery_certificate(current["public_id"],now); con.execute("INSERT INTO recovery_keys(user_id,key_hash,created_at,used_at,certificate_version) VALUES(?,?,?,NULL,1) ON CONFLICT(user_id) DO UPDATE SET key_hash=excluded.key_hash,created_at=excluded.created_at,used_at=NULL,certificate_version=1 WHERE recovery_keys.certificate_version=0",(current["user_id"],recovery_key_hash(certificate["credential"]),now)); con.execute("DELETE FROM passkey_flows WHERE flow_hash=?",(flow_hash,)); con.commit()
            return json_response(start_response,"200 OK",{"ok":True,"recovery_certificate":certificate},[("Cache-Control","no-store")])
        except Exception: return json_response(start_response,"400 Bad Request",{"error":"invalid_passkey","message":"パスキーを確認できませんでした。"})
    if path == "/recover/passkey-begin" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f=fields(environ); public_id=f.get("public_id","").strip().upper(); csrf=f.get("csrf",""); certificate=f.get("certificate")
            if certificate is not None and len(json.dumps(certificate, ensure_ascii=False)) > 8192:
                return json_response(start_response,"400 Bad Request",{"ok":False,"error":"invalid_recovery_certificate","message":"復旧証明書ファイルを読み取れません。"})
            if not re.fullmatch(r"SID-[A-Z2-7]{26}",public_id):
                return json_response(start_response,"200 OK",{"ok":True,"hasPasskey":False})
            now=int(time.time()); flow=b64u(secrets.token_bytes(32)); flow_hash=hashlib.sha256(flow.encode()).hexdigest(); salt=secrets.token_bytes(16)
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                user=con.execute("SELECT id,user_handle FROM users WHERE public_id=? AND active=1",(public_id,)).fetchone()
                keys=con.execute("SELECT credential_id,transports FROM passkeys WHERE user_id=?",(user["id"],)).fetchall() if user else []
                if not user or not keys:
                    con.rollback(); return json_response(start_response,"200 OK",{"ok":True,"hasPasskey":False})
                certificate_hash=recovery_certificate_hash(certificate,public_id) if certificate is not None else ""
                stored_certificate=con.execute("SELECT key_hash FROM recovery_keys WHERE user_id=? AND certificate_version=1 AND used_at IS NULL",(user["id"],)).fetchone()
                if certificate_hash and stored_certificate and hmac.compare_digest(certificate_hash,stored_certificate["key_hash"]):
                    con.rollback(); return json_response(start_response,"200 OK",{"ok":True,"hasPasskey":False,"certificateAccepted":True},[("Cache-Control","no-store")])
                challenge=b64u(secrets.token_bytes(32))
                con.execute("DELETE FROM recovery_flows WHERE user_id=?",(user["id"],))
                con.execute("INSERT INTO recovery_flows(flow_hash,user_id,csrf_hash,code_salt,code_hash,expires_at,created_at,email_hash,existing_challenge,passkey_check_status) VALUES(?,?,?,?,?,?,?,?,?,'pending')",(flow_hash,user["id"],hashlib.sha256(csrf.encode()).hexdigest(),salt.hex(),"",now+600,now,"",challenge))
                con.commit()
            options={"challenge":challenge,"rpId":PASSKEY_RP_ID,"timeout":120000,"userVerification":"required","allowCredentials":[{"type":"public-key","id":k["credential_id"],"transports":json.loads(k["transports"] or "[]")} for k in keys]}
            return json_response(start_response,"200 OK",{"ok":True,"hasPasskey":True,"flow":flow,"existingPasskey":options},[("Cache-Control","no-store")])
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"invalid_request"})
    if path == "/recover/start" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f = fields(environ); public_id = f.get("public_id", "").strip().upper(); address = f.get("email", "").strip(); csrf = f.get("csrf", "")
            if not re.fullmatch(r"SID-[A-Z2-7]{26}", public_id) or len(address) > 254 or not re.fullmatch(r"[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+", address):
                return json_response(start_response, "200 OK", {"ok": True, "message": "該当する場合、確認コードを送信しました。"})
            certificate = f.get("certificate")
            if certificate is not None and len(json.dumps(certificate, ensure_ascii=False)) > 8192:
                return json_response(start_response, "400 Bad Request", {"ok": False, "error": "invalid_recovery_certificate", "message": "復旧証明書ファイルを読み取れません。"})
            certificate_hash = recovery_certificate_hash(certificate, public_id) if certificate is not None else ""
            if certificate is not None and not certificate_hash:
                return json_response(start_response, "400 Bad Request", {"ok": False, "error": "invalid_recovery_certificate", "message": "復旧証明書の内容または対象SSO IDが一致しません。"})
            now = int(time.time()); flow = b64u(secrets.token_bytes(32)); flow_hash = hashlib.sha256(flow.encode()).hexdigest(); code = "%08d" % secrets.randbelow(100000000); salt = secrets.token_bytes(16)
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                user = con.execute("SELECT u.id,u.recovery_email_hash,u.email_encrypted FROM users u WHERE u.public_id=? AND u.active=1", (public_id,)).fetchone()
                address_hash = email_lookup(address)
                email_matches = bool(user and user["recovery_email_hash"] and hmac.compare_digest(user["recovery_email_hash"], address_hash))
                if user and not email_matches and not user["recovery_email_hash"] and user["email_encrypted"]:
                    try:
                        legacy_address = decrypt_private_value(user["email_encrypted"], "email")
                        email_matches = hmac.compare_digest(email_lookup(legacy_address), address_hash)
                    except Exception:
                        email_matches = False
                # Recovery is email-OTP based for all accounts, including accounts that
                # already have a recovery key. The verified email address is the recovery proof.
                authorized = bool(user and email_matches)
                if not authorized:
                    con.rollback(); return json_response(start_response, "200 OK", {"ok": True, "message": "該当する場合、確認コードを送信しました。"})
                stored_certificate = con.execute("SELECT key_hash FROM recovery_keys WHERE user_id=? AND certificate_version=1 AND used_at IS NULL", (user["id"],)).fetchone()
                certificate_valid = bool(certificate_hash and stored_certificate and hmac.compare_digest(certificate_hash, stored_certificate["key_hash"]))
                if certificate is not None and not certificate_valid:
                    con.rollback(); return json_response(start_response, "400 Bad Request", {"ok": False, "error": "invalid_recovery_certificate", "message": "復旧証明書は無効または使用済みです。"})
                totp_enabled = con.execute("SELECT 1 FROM totp_credentials WHERE user_id=?",(user["id"],)).fetchone() is not None
                existing_keys = con.execute("SELECT credential_id,transports FROM passkeys WHERE user_id=?", (user["id"],)).fetchall()
                if existing_keys and not certificate_valid:
                    existing_challenge = b64u(secrets.token_bytes(32))
                    con.execute("DELETE FROM recovery_flows WHERE user_id=?", (user["id"],))
                    con.execute("INSERT INTO recovery_flows(flow_hash,user_id,csrf_hash,code_salt,code_hash,expires_at,created_at,email_hash,existing_challenge,passkey_check_status) VALUES(?,?,?,?,?,?,?,?,?,'pending')", (flow_hash,user["id"],hashlib.sha256(csrf.encode()).hexdigest(),salt.hex(),"",now+600,now,address_hash,existing_challenge))
                    con.execute("UPDATE recovery_flows SET certificate_hash=? WHERE flow_hash=?", (certificate_hash if certificate_valid else "", flow_hash))
                    con.commit()
                    existing_options={"challenge":existing_challenge,"rpId":PASSKEY_RP_ID,"timeout":120000,"userVerification":"required","allowCredentials":[{"type":"public-key","id":k["credential_id"],"transports":json.loads(k["transports"] or "[]")} for k in existing_keys]}
                    return json_response(start_response,"200 OK",{"ok":True,"flow":flow,"existingPasskey":existing_options,"message":"先に登録済みパスキーを確認します。"},[("Cache-Control","no-store")])
                if not totp_enabled and not certificate_valid:
                    con.rollback(); return json_response(start_response,"409 Conflict",{"ok":False,"error":"totp_not_configured","message":"再設定には事前登録済みGoogle Authenticatorが必要です。ログインできる場合はアカウント設定から先に登録してください。"})
                limit = con.execute("SELECT * FROM recovery_limits WHERE user_id=?", (user["id"],)).fetchone(); window = limit["window_started"] if limit and now-limit["window_started"]<3600 else now; sends = limit["sends"] if limit and now-limit["window_started"]<3600 else 0
                if limit and (limit["locked_until"]>now or now-limit["last_sent_at"]<60 or sends>=3):
                    con.rollback(); return json_response(start_response, "429 Too Many Requests", {"error":"recovery_rate_limited","message":"時間をおいてから再度お試しください。"})
                con.execute("INSERT OR REPLACE INTO recovery_limits(user_id,last_sent_at,window_started,sends,attempt_window,attempts,locked_until) VALUES(?,?,?,?,?,?,?)", (user["id"],now,window,sends+1,now,0,0))
                con.execute("DELETE FROM recovery_flows WHERE user_id=?", (user["id"],))
                con.execute("INSERT INTO recovery_flows(flow_hash,user_id,csrf_hash,code_salt,code_hash,expires_at,created_at,email_hash,passkey_check_status,certificate_hash) VALUES(?,?,?,?,?,?,?,?,'not_required',?)", (flow_hash,user["id"],hashlib.sha256(csrf.encode()).hexdigest(),salt.hex(),recovery_code_hash(flow_hash,salt,code),now+600,now,address_hash,certificate_hash if certificate_valid else "")); con.commit()
            if not send_recovery_code(address, code):
                with db() as con: con.execute("DELETE FROM recovery_flows WHERE flow_hash=?",(flow_hash,))
                return json_response(start_response,"503 Service Unavailable",{"error":"mail_unavailable","message":"メールを送信できませんでした。時間をおいてください。"})
            return json_response(start_response,"200 OK",{"ok":True,"flow":flow,"message":"確認コードを送信しました。メールを確認してください。"},[("Cache-Control","no-store")])
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"invalid_request"})
    if path == "/recover/verify" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f=fields(environ); flow_hash=hashlib.sha256(f.get("flow","").encode()).hexdigest(); now=int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                flow=con.execute("SELECT r.*,u.public_id,u.user_handle FROM recovery_flows r JOIN users u ON u.id=r.user_id WHERE r.flow_hash=? AND r.expires_at>? AND r.verified_at IS NULL AND u.active=1",(flow_hash,now)).fetchone()
                if not flow or not hmac.compare_digest(flow["csrf_hash"],hashlib.sha256(f.get("csrf","").encode()).hexdigest()):
                    con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"invalid_recovery_flow","message":"再設定を最初からやり直してください。"})
                code=f.get("code",""); valid=re.fullmatch(r"[0-9]{8}",code) and hmac.compare_digest(flow["code_hash"],recovery_code_hash(flow_hash,bytes.fromhex(flow["code_salt"]),code))
                if not valid:
                    attempts=flow["attempts"]+1; con.execute("UPDATE recovery_flows SET attempts=? WHERE flow_hash=?",(attempts,flow_hash))
                    if attempts>=5: con.execute("DELETE FROM recovery_flows WHERE flow_hash=?",(flow_hash,))
                    con.commit(); return json_response(start_response,"400 Bad Request",{"error":"invalid_code","message":"確認コードが違うか期限切れです。"})
                if flow["passkey_check_status"] not in ("unavailable","not_required"):
                    con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"passkey_check_required","message":"パスキー確認から再設定を開始してください。"})
                if flow["certificate_hash"]:
                    consumed=con.execute("UPDATE recovery_keys SET used_at=? WHERE user_id=? AND certificate_version=1 AND key_hash=? AND used_at IS NULL",(now,flow["user_id"],flow["certificate_hash"])).rowcount
                    if consumed != 1:
                        con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"invalid_recovery_certificate","message":"復旧証明書は無効または使用済みです。"})
                    challenge=b64u(secrets.token_bytes(32))
                    con.execute("DELETE FROM passkeys WHERE user_id=?",(flow["user_id"],))
                    con.execute("DELETE FROM totp_credentials WHERE user_id=?",(flow["user_id"],))
                    con.execute("DELETE FROM totp_setup_flows WHERE user_id=?",(flow["user_id"],))
                    con.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",(now,flow["user_id"]))
                    con.execute("DELETE FROM auth_codes WHERE user_id=?",(flow["user_id"],))
                    con.execute("DELETE FROM access_tokens WHERE user_id=?",(flow["user_id"],))
                    con.execute("DELETE FROM login_flows WHERE flow_hash IN (SELECT flow_hash FROM passkey_flows WHERE user_id=?)",(flow["user_id"],))
                    con.execute("DELETE FROM login_flows WHERE flow_hash IN (SELECT login_flow_hash FROM mfa_flows WHERE user_id=?)",(flow["user_id"],))
                    con.execute("DELETE FROM passkey_flows WHERE user_id=?",(flow["user_id"],))
                    con.execute("DELETE FROM mfa_flows WHERE user_id=?",(flow["user_id"],))
                    con.execute("DELETE FROM recovery_flows WHERE user_id=? AND flow_hash<>?",(flow["user_id"],flow_hash))
                    con.execute("UPDATE recovery_flows SET verified_at=?,challenge=?,passkey_check_status='unavailable',totp_verified_at=?,totp_attempts=0,expires_at=? WHERE flow_hash=?",(now,challenge,now,now+600,flow_hash))
                    options={"challenge":challenge,"rp":{"id":PASSKEY_RP_ID,"name":"SSO ID 2415.jp"},"user":{"id":flow["user_handle"],"name":flow["public_id"],"displayName":flow["public_id"]},"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"timeout":120000,"attestation":"none","authenticatorSelection":{"residentKey":"required","requireResidentKey":True,"userVerification":"required"}}
                else:
                    if not con.execute("SELECT 1 FROM totp_credentials WHERE user_id=?",(flow["user_id"],)).fetchone():
                        con.rollback(); return json_response(start_response,"409 Conflict",{"error":"recovery_proof_required","message":"認証アプリまたは復旧証明書による本人確認が必要です。"})
                    existing_challenge=b64u(secrets.token_bytes(32))
                    con.execute("UPDATE recovery_flows SET verified_at=?,challenge=NULL,existing_challenge=?,passkey_check_status=?,totp_verified_at=NULL,totp_attempts=0 WHERE flow_hash=?",(now,existing_challenge,flow["passkey_check_status"],flow_hash))
                if flow["email_hash"]:
                    con.execute("UPDATE users SET recovery_email_hash=CASE WHEN recovery_email_hash='' THEN ? ELSE recovery_email_hash END,email_encrypted='' WHERE id=?",(flow["email_hash"],flow["user_id"]))
                con.commit()
            if flow["certificate_hash"]:
                return json_response(start_response,"200 OK",{"ok":True,"certificate_accepted":True,"publicKey":options},[("Cache-Control","no-store")])
            return json_response(start_response,"200 OK",{"ok":True,"totp_required":True},[("Cache-Control","no-store")])
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"invalid_request"})
    if path == "/recover/totp-verify" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f=fields(environ); flow_hash=hashlib.sha256(f.get("flow","").encode()).hexdigest(); now=int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                flow=con.execute("SELECT r.*,u.public_id,u.user_handle FROM recovery_flows r JOIN users u ON u.id=r.user_id WHERE r.flow_hash=? AND r.expires_at>? AND r.verified_at IS NOT NULL AND r.totp_verified_at IS NULL AND r.passkey_check_status IN ('unavailable','not_required') AND u.active=1",(flow_hash,now)).fetchone()
                supplied=hashlib.sha256(f.get("csrf","").encode()).hexdigest()
                if not flow or not hmac.compare_digest(flow["csrf_hash"],supplied):
                    con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"invalid_recovery_flow","message":"再設定を最初からやり直してください。"})
                credential=con.execute("SELECT * FROM totp_credentials WHERE user_id=?",(flow["user_id"],)).fetchone()
                if not credential:
                    con.rollback(); return json_response(start_response,"409 Conflict",{"error":"totp_not_configured","message":"事前登録済みGoogle Authenticatorが見つかりません。メール確認だけではパスキーを削除できません。"})
                secret=decrypt_private_value(credential["secret_encrypted"],"totp-secret")
                matched_step=verify_totp(secret,str(f.get("code","" )).strip(),now,credential["last_step"])
                if matched_step is None:
                    attempts=int(flow["totp_attempts"])+1
                    if attempts>=5: con.execute("DELETE FROM recovery_flows WHERE flow_hash=?",(flow_hash,))
                    else: con.execute("UPDATE recovery_flows SET totp_attempts=? WHERE flow_hash=?",(attempts,flow_hash))
                    con.commit(); return json_response(start_response,"401 Unauthorized",{"error":"invalid_totp","message":"Google Authenticatorのコードが違うか、使用済みです。"})
                changed=con.execute("UPDATE totp_credentials SET last_step=? WHERE user_id=? AND last_step<?",(matched_step,flow["user_id"],matched_step)).rowcount
                if changed!=1:
                    con.rollback(); return json_response(start_response,"401 Unauthorized",{"error":"otp_replayed","message":"そのGoogle OTPは使用済みです。次のコードを入力してください。"})
                challenge=b64u(secrets.token_bytes(32))
                con.execute("DELETE FROM passkeys WHERE user_id=?",(flow["user_id"],))
                con.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",(now,flow["user_id"]))
                con.execute("DELETE FROM auth_codes WHERE user_id=?",(flow["user_id"]))
                con.execute("DELETE FROM access_tokens WHERE user_id=?",(flow["user_id"]))
                con.execute("DELETE FROM login_flows WHERE flow_hash IN (SELECT flow_hash FROM passkey_flows WHERE user_id=?)",(flow["user_id"],))
                con.execute("DELETE FROM login_flows WHERE flow_hash IN (SELECT login_flow_hash FROM mfa_flows WHERE user_id=?)",(flow["user_id"],))
                con.execute("DELETE FROM passkey_flows WHERE user_id=?",(flow["user_id"],)); con.execute("DELETE FROM mfa_flows WHERE user_id=?",(flow["user_id"],))
                con.execute("DELETE FROM recovery_flows WHERE user_id=? AND flow_hash<>?",(flow["user_id"],flow_hash))
                con.execute("UPDATE recovery_flows SET totp_verified_at=?,totp_attempts=0,challenge=?,expires_at=? WHERE flow_hash=?",(now,challenge,now+600,flow_hash))
                con.commit()
            options={"challenge":challenge,"rp":{"id":PASSKEY_RP_ID,"name":"SSO ID 2415.jp"},"user":{"id":flow["user_handle"],"name":flow["public_id"],"displayName":flow["public_id"]},"pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"timeout":120000,"attestation":"none","authenticatorSelection":{"residentKey":"required","requireResidentKey":True,"userVerification":"required"}}
            return json_response(start_response,"200 OK",{"ok":True,"totp_verified":True,"publicKey":options},[("Cache-Control","no-store")])
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"totp_recovery_failed","message":"Google OTPを確認できませんでした。"})
    if path == "/recover/passkey-check" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f=fields(environ); flow_hash=hashlib.sha256(f.get("flow","").encode()).hexdigest(); cred=f.get("credential") or {}; now=int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                pending=con.execute("SELECT r.*,u.user_handle FROM recovery_flows r JOIN users u ON u.id=r.user_id WHERE r.flow_hash=? AND r.expires_at>? AND r.passkey_check_status='pending' AND u.active=1",(flow_hash,now)).fetchone()
                if not pending or not hmac.compare_digest(pending["csrf_hash"],hashlib.sha256(f.get("csrf","").encode()).hexdigest()):
                    con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"invalid_recovery_flow"})
                keyrow=con.execute("SELECT * FROM passkeys WHERE credential_id=? AND user_id=?",(cred.get("id",""),pending["user_id"])).fetchone()
                if not keyrow:
                    con.rollback(); return json_response(start_response,"401 Unauthorized",{"error":"invalid_passkey"})
                count=webauthn_assertion(cred.get("clientDataJSON",""),cred.get("authenticatorData",""),cred.get("signature",""),pending["existing_challenge"],keyrow["public_key"],keyrow["sign_count"],cred.get("userHandle",""),pending["user_handle"])
                con.execute("UPDATE passkeys SET sign_count=?,last_used=? WHERE credential_id=?",(count,now,keyrow["credential_id"]))
                con.execute("DELETE FROM recovery_flows WHERE flow_hash=?",(flow_hash,)); con.commit()
            return json_response(start_response,"409 Conflict",{"ok":False,"error":"existing_passkey_verified","message":"このSSO IDで使える登録済みパスキーが確認できました。再設定はできません。確認したパスキーでログインしてください。"})
        except Exception:
            return json_response(start_response,"401 Unauthorized",{"error":"passkey_not_confirmed","message":"既存パスキーを確認できませんでした。再度お試しください。"})
    if path == "/recover/send-otp" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f=fields(environ); flow=f.get("flow",""); flow_hash=hashlib.sha256(flow.encode()).hexdigest(); address=f.get("email","").strip(); now=int(time.time()); certificate=f.get("certificate")
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                pending=con.execute("SELECT r.*,u.active,u.public_id,u.recovery_email_hash,u.email_encrypted FROM recovery_flows r JOIN users u ON u.id=r.user_id WHERE r.flow_hash=? AND r.expires_at>? AND r.passkey_check_status='unavailable'",(flow_hash,now)).fetchone()
                if not pending or not pending["active"] or not hmac.compare_digest(pending["csrf_hash"],hashlib.sha256(f.get("csrf","").encode()).hexdigest()):
                    con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"invalid_recovery_flow","message":"再設定を最初からやり直してください。"})
                certificate_hash=recovery_certificate_hash(certificate,pending["public_id"]) if certificate is not None else ""
                stored_certificate=con.execute("SELECT key_hash FROM recovery_keys WHERE user_id=? AND certificate_version=1 AND used_at IS NULL",(pending["user_id"],)).fetchone()
                certificate_valid=bool(certificate_hash and stored_certificate and hmac.compare_digest(certificate_hash,stored_certificate["key_hash"]))
                if certificate is not None and not certificate_valid:
                    con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"invalid_recovery_certificate","message":"復旧証明書は無効または使用済みです。"})
                if not con.execute("SELECT 1 FROM totp_credentials WHERE user_id=?",(pending["user_id"],)).fetchone() and not certificate_valid:
                    con.rollback(); return json_response(start_response,"409 Conflict",{"error":"recovery_proof_required","message":"復旧には認証アプリまたは未使用の復旧証明書が必要です。"})
                address_hash=email_lookup(address)
                email_matches=bool(pending["recovery_email_hash"] and hmac.compare_digest(pending["recovery_email_hash"],address_hash))
                if not email_matches and not pending["recovery_email_hash"] and pending["email_encrypted"]:
                    try: email_matches=hmac.compare_digest(email_lookup(decrypt_private_value(pending["email_encrypted"],"email")),address_hash)
                    except Exception: email_matches=False
                if not email_matches:
                    con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"recovery_email_mismatch","message":"登録済みメールアドレスを確認してください。"})
                limit=con.execute("SELECT * FROM recovery_limits WHERE user_id=?",(pending["user_id"],)).fetchone(); window=limit["window_started"] if limit and now-limit["window_started"]<3600 else now; sends=limit["sends"] if limit and now-limit["window_started"]<3600 else 0
                if limit and (limit["locked_until"]>now or now-limit["last_sent_at"]<60 or sends>=3):
                    con.rollback(); return json_response(start_response,"429 Too Many Requests",{"error":"recovery_rate_limited","message":"時間をおいてから再度お試しください。"})
                code="%08d" % secrets.randbelow(100000000); salt=secrets.token_bytes(16)
                con.execute("INSERT OR REPLACE INTO recovery_limits(user_id,last_sent_at,window_started,sends,attempt_window,attempts,locked_until) VALUES(?,?,?,?,?,?,?)",(pending["user_id"],now,window,sends+1,now,0,0))
                con.execute("UPDATE recovery_flows SET code_salt=?,code_hash=?,verified_at=NULL,attempts=0,email_hash=?,totp_verified_at=NULL,totp_attempts=0,certificate_hash=?,challenge=NULL WHERE flow_hash=?",(salt.hex(),recovery_code_hash(flow_hash,salt,code),address_hash,certificate_hash if certificate_valid else "",flow_hash)); con.commit()
            if not send_recovery_code(address,code):
                with db() as con: con.execute("DELETE FROM recovery_flows WHERE flow_hash=?",(flow_hash,))
                return json_response(start_response,"503 Service Unavailable",{"error":"mail_unavailable","message":"メールを送信できませんでした。時間をおいてください。"})
            return json_response(start_response,"200 OK",{"ok":True,"message":"確認コードを送信しました。メールを確認してください。"},[("Cache-Control","no-store")])
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"invalid_request"})
    if path == "/recover/allow-reset" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f=fields(environ); flow_hash=hashlib.sha256(f.get("flow","").encode()).hexdigest(); now=int(time.time())
            with db() as con:
                pending=con.execute("SELECT * FROM recovery_flows WHERE flow_hash=? AND expires_at>? AND passkey_check_status='pending'",(flow_hash,now)).fetchone()
                if not pending or not hmac.compare_digest(pending["csrf_hash"],hashlib.sha256(f.get("csrf","").encode()).hexdigest()):
                    return json_response(start_response,"400 Bad Request",{"error":"invalid_recovery_flow"})
                con.execute("UPDATE recovery_flows SET passkey_check_status='unavailable' WHERE flow_hash=?",(flow_hash,))
            return json_response(start_response,"200 OK",{"ok":True})
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"invalid_request"})
    if path == "/recover/finish" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f=fields(environ); flow_hash=hashlib.sha256(f.get("flow","").encode()).hexdigest(); now=int(time.time()); cred=f.get("credential") or {}
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                flow=con.execute("SELECT r.*,u.public_id FROM recovery_flows r JOIN users u ON u.id=r.user_id WHERE r.flow_hash=? AND r.expires_at>? AND r.verified_at IS NOT NULL AND r.totp_verified_at IS NOT NULL AND r.passkey_check_status IN ('unavailable','not_required') AND u.active=1",(flow_hash,now)).fetchone()
                if not flow or not hmac.compare_digest(flow["csrf_hash"],hashlib.sha256(f.get("csrf","").encode()).hexdigest()):
                    con.rollback(); return json_response(start_response,"400 Bad Request",{"error":"invalid_recovery_flow"})
                registered=webauthn_registration(cred.get("clientDataJSON",""),cred.get("attestationObject",""),flow["challenge"],cred.get("id","")); transports=json.dumps([x for x in cred.get("transports",[]) if x in ("usb","nfc","ble","internal","hybrid")])
                con.execute("DELETE FROM passkeys WHERE user_id=?",(flow["user_id"],)); con.execute("INSERT INTO passkeys(credential_id,user_id,public_key,sign_count,transports,created_at) VALUES(?,?,?,?,?,?)",(registered["credential_id"],flow["user_id"],registered["public_key"],registered["counter"],transports,now))
                con.execute("UPDATE users SET email_encrypted='' WHERE id=?",(flow["user_id"],))
                con.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL",(now,flow["user_id"])); con.execute("DELETE FROM auth_codes WHERE user_id=?",(flow["user_id"],)); con.execute("DELETE FROM access_tokens WHERE user_id=?",(flow["user_id"],)); con.execute("DELETE FROM recovery_flows WHERE user_id=?",(flow["user_id"],)); con.execute("DELETE FROM recovery_limits WHERE user_id=?",(flow["user_id"],)); con.commit()
            return json_response(start_response,"200 OK",{"ok":True},[("Cache-Control","no-store")])
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"passkey_registration_failed","message":"パスキーを登録できませんでした。再度やり直してください。"})
    if path == "/authorize" and method == "GET":
        p = query(environ)
        with db() as con:
            now = int(time.time())
            cleanup_expired_auth_state(con, now)
            client, error = valid_authorize(p, con)
            if error:
                return json_response(start_response, "400 Bad Request", {"error": error})
            user = user_for_session(environ)
            # Critical operations request fresh central authentication even when
            # the browser already has an SSO session.
            if p.get("prompt") == "login":
                user = None
            if user and not con.execute("SELECT 1 FROM passkeys WHERE user_id=? LIMIT 1", (user["id"],)).fetchone():
                # A pre-upgrade password session must not silently bypass required passkey enrollment.
                user = None
            if user and p.get("client_id") == ADMIN_CLIENT_ID and not is_admin_user(con, user["id"]):
                return response(start_response, "403 Forbidden", admin_denied_page(), "text/html; charset=utf-8")
            if user:
                sid_hash = hashlib.sha256(cookie(environ, COOKIE).encode()).hexdigest()
                code = issue_code(con, p, user["id"], sid_hash)
                location = append_query(p["redirect_uri"], {"code": code, "state": p["state"]})
                return response(start_response, "302 Found", b"", headers=[("Location", location)])
            flow = b64u(secrets.token_bytes(32))
            csrf = b64u(secrets.token_bytes(32))
            packed = json.dumps(p, separators=(",", ":"))
            con.execute("INSERT INTO login_flows(flow_hash,csrf_hash,request_json,expires_at) VALUES(?,?,?,?)",
                        (hashlib.sha256(flow.encode()).hexdigest(), hashlib.sha256(csrf.encode()).hexdigest(), packed, int(time.time()) + 300))
        return response(start_response, "200 OK", authorize_login_page(flow, csrf, query(environ).get("error") == "invalid"), "text/html; charset=utf-8")
    if path == "/login/begin" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f = fields(environ)
            flow_hash = hashlib.sha256(f.get("flow", "").encode()).hexdigest()
            with db() as con:
                flow = con.execute("SELECT csrf_hash FROM login_flows WHERE flow_hash=? AND expires_at>?", (flow_hash, int(time.time()))).fetchone()
                if not flow or not hmac.compare_digest(flow["csrf_hash"], hashlib.sha256(f.get("csrf", "").encode()).hexdigest()):
                    return json_response(start_response, "400 Bad Request", {"error": "invalid_login_flow"})
                public_id = f.get("public_id", "").strip().upper()
                if public_id and not re.fullmatch(r"SID-[A-Z2-7]{26}", public_id):
                    return json_response(start_response, "401 Unauthorized", {"error": "invalid_credentials", "message": "認証できませんでした。入力内容を確認してください。"})
                if public_id:
                    identity_key = security_rate_key("passkey-id", public_id)
                    if not consume_security_rate_limit_in_transaction(con, identity_key, 12, 900):
                        con.commit()
                        return json_response(start_response, "429 Too Many Requests", {"error": "rate_limited", "message": "試行回数が上限に達しました。時間をおいて再度お試しください。"}, headers=[("Retry-After", "900")])
                user = con.execute("SELECT id,user_handle FROM users WHERE public_id=? AND active=1", (public_id,)).fetchone() if public_id else None
                keys = con.execute("SELECT credential_id,transports FROM passkeys WHERE user_id=?", (user["id"] if user else -1,)).fetchall()
                challenge = b64u(secrets.token_bytes(32))
                flow_user_id = user["id"] if user and keys else None
                login_mode = "discoverable" if not public_id else "login"
                con.execute("INSERT OR REPLACE INTO passkey_flows(flow_hash,user_id,challenge,mode,expires_at) VALUES(?,?,?,?,?)",
                            (flow_hash, flow_user_id, challenge, login_mode, int(time.time()) + 300))
                allowed_credentials = [{"type": "public-key", "id": row["credential_id"], "transports": json.loads(row["transports"] or "[]")} for row in keys]
                if not allowed_credentials and public_id:
                    # Random credential IDs keep the response shape and status
                    # independent of whether the submitted SSO ID exists.
                    allowed_credentials = [{"type": "public-key", "id": b64u(secrets.token_bytes(24)), "transports": []}]
            return json_response(start_response, "200 OK", {"ok": True, "publicKey": {"challenge": challenge, "rpId": PASSKEY_RP_ID, "timeout": 120000, "userVerification": "required", "allowCredentials": allowed_credentials}})
        except Exception:
            return json_response(start_response, "400 Bad Request", {"error": "invalid_request"})
    if path == "/login" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f = fields(environ)
        except Exception:
            return json_response(start_response, "400 Bad Request", {"error": "invalid_request"})
        flow_hash = hashlib.sha256(f.get("flow", "").encode()).hexdigest()
        with db() as con:
            con.execute("BEGIN IMMEDIATE")
            flow = con.execute("SELECT * FROM login_flows WHERE flow_hash=? AND expires_at>?", (flow_hash, int(time.time()))).fetchone()
            if not flow or not hmac.compare_digest(flow["csrf_hash"], hashlib.sha256(f.get("csrf", "").encode()).hexdigest()):
                con.rollback()
                return json_response(start_response, "400 Bad Request", {"error": "invalid_login_flow"})
            action = f.get("action", "")
            now = int(time.time())
            if action == "legacy_login":
                normalized_email = f.get("email", "").strip().casefold()
                email_hash = email_lookup(normalized_email)
                limit = con.execute("SELECT attempts,window_started,locked_until FROM login_limits WHERE email_hash=?", (email_hash,)).fetchone()
                user = con.execute("SELECT id,password_salt,password_hash FROM users WHERE email=? AND email_verified=1 AND active=1", (email_hash,)).fetchone()
                salt = bytes.fromhex(user["password_salt"]) if user and user["password_salt"] else b"\0" * 16
                expected = user["password_hash"] if user and user["password_hash"] else "0" * 64
                actual = hashlib.pbkdf2_hmac("sha256", f.get("password", "").encode(), salt, PBKDF2_ROUNDS).hex()
                has_key = con.execute("SELECT 1 FROM passkeys WHERE user_id=? LIMIT 1", (user["id"],)).fetchone() if user else None
                if not user or has_key or (limit and limit["locked_until"] > now) or not hmac.compare_digest(actual, expected):
                    attempts = limit["attempts"] + 1 if limit and now - limit["window_started"] < 900 else 1
                    window = limit["window_started"] if limit and now - limit["window_started"] < 900 else now
                    locked_until = max(limit["locked_until"] if limit else 0, now + 900 if attempts >= 5 else 0)
                    con.execute("INSERT OR REPLACE INTO login_limits(email_hash,attempts,window_started,locked_until) VALUES(?,?,?,?)", (email_hash, attempts, window, locked_until))
                    con.commit()
                    return json_response(start_response, "401 Unauthorized", {"error": "invalid_credentials", "message": "ログイン情報を確認してください。"})
                con.execute("DELETE FROM login_limits WHERE email_hash=?", (email_hash,))
                challenge = b64u(secrets.token_bytes(32))
                con.execute("INSERT OR REPLACE INTO passkey_flows(flow_hash,user_id,challenge,mode,expires_at) VALUES(?,?,?,?,?)", (flow_hash, user["id"], challenge, "enroll", now + 300))
                public_id, user_handle = con.execute("SELECT public_id,user_handle FROM users WHERE id=?", (user["id"],)).fetchone()
                con.commit()
                return json_response(start_response, "200 OK", {"ok": True, "publicKey": {"challenge": challenge, "rp": {"id": PASSKEY_RP_ID, "name": "SSO ID 2415.jp"}, "user": {"id": user_handle, "name": public_id, "displayName": public_id}, "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}], "timeout": 120000, "attestation": "none", "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"}}})
            if action == "passkey_assertion":
                pending = con.execute("SELECT * FROM passkey_flows WHERE flow_hash=? AND mode IN ('login','discoverable') AND expires_at>?", (flow_hash, now)).fetchone()
                if not pending:
                    con.rollback(); return json_response(start_response, "401 Unauthorized", {"error": "invalid_passkey"})
                flow_attempt_key = security_rate_key("passkey-flow", flow_hash)
                if not consume_security_rate_limit_in_transaction(con, flow_attempt_key, 5, 300, now):
                    con.commit(); return json_response(start_response, "429 Too Many Requests", {"error": "rate_limited", "message": "この認証フローの試行上限に達しました。最初からログインし直してください。"}, headers=[("Retry-After", "300")])
                cred = f.get("credential") or {}
                if pending and pending["mode"] == "discoverable":
                    key = con.execute("SELECT p.*,u.public_id,u.user_handle FROM passkeys p JOIN users u ON u.id=p.user_id WHERE p.credential_id=? AND u.active=1", (cred.get("id", ""),)).fetchone()
                else:
                    key = con.execute("SELECT p.*,u.public_id,u.user_handle FROM passkeys p JOIN users u ON u.id=p.user_id WHERE p.credential_id=? AND p.user_id=? AND u.active=1", (cred.get("id", ""), pending["user_id"] if pending else -1)).fetchone()
                if not key:
                    con.commit(); return json_response(start_response, "401 Unauthorized", {"error": "invalid_passkey"})
                try:
                    count = webauthn_assertion(cred.get("clientDataJSON", ""), cred.get("authenticatorData", ""), cred.get("signature", ""), pending["challenge"], key["public_key"], key["sign_count"], cred.get("userHandle", ""), key["user_handle"])
                except Exception:
                    con.commit(); return json_response(start_response, "401 Unauthorized", {"error": "invalid_passkey", "message": "パスキー認証を確認できませんでした。もう一度お試しください。"})
                p = json.loads(flow["request_json"])
                client, error = valid_authorize(p, con)
                if error:
                    con.commit(); return json_response(start_response, "400 Bad Request", {"error": error})
                if p.get("client_id") == ADMIN_CLIENT_ID and not is_admin_user(con, key["user_id"]):
                    con.execute("DELETE FROM passkey_flows WHERE flow_hash=?", (flow_hash,)); con.execute("DELETE FROM login_flows WHERE flow_hash=?", (flow_hash,)); con.commit()
                    return response(start_response, "403 Forbidden", admin_denied_page(), "text/html; charset=utf-8")
                con.execute("UPDATE passkeys SET sign_count=?,last_used=? WHERE credential_id=?", (count, now, key["credential_id"]))
                if con.execute("SELECT 1 FROM totp_credentials WHERE user_id=?", (key["user_id"],)).fetchone():
                    con.execute("DELETE FROM passkey_flows WHERE flow_hash=?", (flow_hash,))
                    con.execute("INSERT OR REPLACE INTO mfa_flows(login_flow_hash,user_id,expires_at,attempts) VALUES(?,?,?,0)", (flow_hash,key["user_id"],now+300))
                    con.commit()
                    return json_response(start_response, "200 OK", {"ok": True, "mfa_required": True}, [("Cache-Control", "no-store")])
                con.execute("DELETE FROM passkey_flows WHERE flow_hash=?", (flow_hash,)); con.execute("DELETE FROM login_flows WHERE flow_hash=?", (flow_hash,))
                session = b64u(secrets.token_bytes(32)); csrf = b64u(secrets.token_bytes(32)); session_hash = hashlib.sha256(session.encode()).hexdigest()
                con.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at,user_agent,csrf_hash) VALUES(?,?,?,?,?,?)", (session_hash,key["user_id"],now+SESSION_TTL,now,environ.get("HTTP_USER_AGENT","")[:180],hashlib.sha256(csrf.encode()).hexdigest()))
                code = issue_code(con, p, key["user_id"], session_hash); con.commit()
                return json_response(start_response, "200 OK", {"ok": True, "next": append_query(p["redirect_uri"], {"code": code, "state": p["state"]})}, [("Set-Cookie", f"{COOKIE}={session}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}")])
            if action == "finish_enrollment":
                pending = con.execute("SELECT * FROM passkey_flows WHERE flow_hash=? AND mode='enroll' AND expires_at>?", (flow_hash, now)).fetchone()
                cred = f.get("credential") or {}
                user = con.execute("SELECT * FROM users WHERE id=? AND active=1", (pending["user_id"] if pending else -1,)).fetchone()
                if not pending or not user or con.execute("SELECT 1 FROM passkeys WHERE user_id=?", (user["id"],)).fetchone():
                    con.rollback(); return json_response(start_response, "401 Unauthorized", {"error": "invalid_enrollment"})
                try:
                    registered = webauthn_registration(cred.get("clientDataJSON", ""), cred.get("attestationObject", ""), pending["challenge"], cred.get("id", ""))
                    transports = json.dumps([x for x in cred.get("transports", []) if x in ("usb", "nfc", "ble", "internal", "hybrid")])
                except Exception:
                    con.rollback(); return json_response(start_response, "400 Bad Request", {"error": "passkey_registration_failed", "message": "パスキーを登録できませんでした。端末の確認をやり直してください。"})
                con.execute("INSERT INTO passkeys(credential_id,user_id,public_key,sign_count,transports,created_at) VALUES(?,?,?,?,?,?)", (registered["credential_id"],user["id"],registered["public_key"],registered["counter"],transports,now))
                con.execute("UPDATE users SET email='deleted:'||public_id,email_encrypted='',email_verified=0,display_name=public_id,password_salt='',password_hash='' WHERE id=?", (user["id"],))
                con.execute("DELETE FROM login_limits")
                p = json.loads(flow["request_json"])
                if p.get("client_id") == ADMIN_CLIENT_ID and not is_admin_user(con,user["id"]):
                    con.execute("DELETE FROM passkey_flows WHERE flow_hash=?",(flow_hash,));con.execute("DELETE FROM login_flows WHERE flow_hash=?",(flow_hash,));con.commit()
                    return response(start_response,"403 Forbidden",admin_denied_page(),"text/html; charset=utf-8")
                con.execute("DELETE FROM passkey_flows WHERE flow_hash=?", (flow_hash,)); con.execute("DELETE FROM login_flows WHERE flow_hash=?", (flow_hash,))
                con.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (now, user["id"]))
                session=b64u(secrets.token_bytes(32));csrf=b64u(secrets.token_bytes(32));session_hash=hashlib.sha256(session.encode()).hexdigest()
                con.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at,user_agent,csrf_hash) VALUES(?,?,?,?,?,?)",(session_hash,user["id"],now+SESSION_TTL,now,environ.get("HTTP_USER_AGENT","")[:180],hashlib.sha256(csrf.encode()).hexdigest()))
                existing_certificate=con.execute("SELECT 1 FROM recovery_keys WHERE user_id=? AND certificate_version=1",(user["id"],)).fetchone()
                certificate=None
                if not existing_certificate:
                    certificate=new_recovery_certificate(user["public_id"],now)
                    con.execute("INSERT INTO recovery_keys(user_id,key_hash,created_at,used_at,certificate_version) VALUES(?,?,?,NULL,1) ON CONFLICT(user_id) DO UPDATE SET key_hash=excluded.key_hash,created_at=excluded.created_at,used_at=NULL,certificate_version=1 WHERE recovery_keys.certificate_version=0",(user["id"],recovery_key_hash(certificate["credential"]),now))
                con.execute("DELETE FROM registration_onboarding WHERE user_id=?",(user["id"],))
                con.execute("INSERT INTO registration_onboarding(session_hash,user_id,request_json,expires_at) VALUES(?,?,?,?)",(session_hash,user["id"],json.dumps(p,separators=(",",":")),now+1800))
                con.commit()
                return json_response(start_response,"200 OK",{"ok":True,"onboarding":True,"next":"/account","public_id":user["public_id"],"recovery_certificate":certificate},[("Set-Cookie",f"{COOKIE}={session}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"),("Cache-Control","no-store")])
            con.rollback()
            return json_response(start_response, "400 Bad Request", {"error": "passkey_required"})
    if path == "/login/totp" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f = fields(environ)
            flow_hash = hashlib.sha256(f.get("flow", "").encode()).hexdigest()
            supplied_csrf = hashlib.sha256(f.get("csrf", "").encode()).hexdigest()
            token_code = str(f.get("code", "")).strip()
            now = int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                login = con.execute("SELECT * FROM login_flows WHERE flow_hash=? AND expires_at>?", (flow_hash, now)).fetchone()
                pending = con.execute("SELECT m.* FROM mfa_flows m JOIN users u ON u.id=m.user_id AND u.active=1 WHERE m.login_flow_hash=? AND m.expires_at>?", (flow_hash, now)).fetchone()
                if not login or not pending or not hmac.compare_digest(login["csrf_hash"], supplied_csrf):
                    con.rollback()
                    return json_response(start_response, "400 Bad Request", {"error": "invalid_mfa_flow"})
                account_key = security_rate_key("totp-user", pending["user_id"])
                if not consume_security_rate_limit_in_transaction(con, account_key, 10, 900, now):
                    con.commit()
                    return json_response(start_response, "429 Too Many Requests", {"error": "rate_limited", "message": "追加認証の試行上限に達しました。時間をおいて再度お試しください。"}, headers=[("Retry-After", "900")])
                if int(pending["attempts"]) >= 5:
                    con.execute("DELETE FROM mfa_flows WHERE login_flow_hash=?", (flow_hash,))
                    con.execute("DELETE FROM login_flows WHERE flow_hash=?", (flow_hash,))
                    con.commit()
                    return json_response(start_response, "429 Too Many Requests", {"error": "mfa_attempts_exceeded", "message": "認証回数の上限に達しました。最初からログインし直してください。"})
                credential = con.execute("SELECT * FROM totp_credentials WHERE user_id=?", (pending["user_id"],)).fetchone()
                if not credential:
                    con.execute("DELETE FROM mfa_flows WHERE login_flow_hash=?", (flow_hash,))
                    con.commit()
                    return json_response(start_response, "401 Unauthorized", {"error": "mfa_not_configured"})
                secret = decrypt_private_value(credential["secret_encrypted"], "totp-secret")
                matched_step = verify_totp(secret, token_code, now, credential["last_step"])
                if matched_step is None:
                    attempts = int(pending["attempts"]) + 1
                    if attempts >= 5:
                        con.execute("DELETE FROM mfa_flows WHERE login_flow_hash=?", (flow_hash,))
                        con.execute("DELETE FROM login_flows WHERE flow_hash=?", (flow_hash,))
                    else:
                        con.execute("UPDATE mfa_flows SET attempts=? WHERE login_flow_hash=?", (attempts, flow_hash))
                    con.commit()
                    return json_response(start_response, "401 Unauthorized", {"error": "invalid_otp", "message": "認証コードを確認してください。"})
                changed = con.execute("UPDATE totp_credentials SET last_step=? WHERE user_id=? AND last_step<?", (matched_step,pending["user_id"],matched_step)).rowcount
                if changed != 1:
                    con.commit()
                    return json_response(start_response, "401 Unauthorized", {"error": "otp_replayed", "message": "その認証コードは使用済みです。次のコードを入力してください。"})
                p = json.loads(login["request_json"])
                client, error = valid_authorize(p, con)
                if error:
                    con.commit()
                    return json_response(start_response, "400 Bad Request", {"error": error})
                session = b64u(secrets.token_bytes(32)); csrf = b64u(secrets.token_bytes(32)); session_hash = hashlib.sha256(session.encode()).hexdigest()
                con.execute("INSERT INTO sessions(token_hash,user_id,expires_at,created_at,user_agent,csrf_hash) VALUES(?,?,?,?,?,?)", (session_hash,pending["user_id"],now+SESSION_TTL,now,environ.get("HTTP_USER_AGENT","")[:180],hashlib.sha256(csrf.encode()).hexdigest()))
                code = issue_code(con, p, pending["user_id"], session_hash)
                con.execute("DELETE FROM mfa_flows WHERE login_flow_hash=?", (flow_hash,))
                con.execute("DELETE FROM login_flows WHERE flow_hash=?", (flow_hash,))
                con.commit()
            return json_response(start_response, "200 OK", {"ok": True, "next": append_query(p["redirect_uri"], {"code": code, "state": p["state"]})}, [("Set-Cookie", f"{COOKIE}={session}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"), ("Cache-Control", "no-store")])
        except Exception:
            return json_response(start_response, "401 Unauthorized", {"error": "invalid_otp", "message": "認証コードを確認できませんでした。"})
    if path == "/token" and method == "POST":
        auth = environ.get("HTTP_AUTHORIZATION", "")
        if not auth.startswith("Basic "):
            return json_response(start_response, "401 Unauthorized", {"error": "invalid_client"}, [("WWW-Authenticate", "Basic realm=token")])
        try:
            client_id, secret = base64.b64decode(auth[6:], validate=True).decode().split(":", 1)
            f = fields(environ)
        except Exception:
            return json_response(start_response, "400 Bad Request", {"error": "invalid_request"})
        with db() as con:
            con.execute("BEGIN IMMEDIATE")
            client = client_for(con, client_id)
            if not client or not client["active"] or not hmac.compare_digest(hashlib.sha256(secret.encode()).hexdigest(), client["secret_hash"]):
                con.rollback()
                return json_response(start_response, "401 Unauthorized", {"error": "invalid_client"})
            if f.get("grant_type") != "authorization_code":
                con.rollback()
                return json_response(start_response, "400 Bad Request", {"error": "unsupported_grant_type"})
            code_hash = hashlib.sha256(f.get("code", "").encode()).hexdigest()
            now = int(time.time())
            code = con.execute("SELECT a.*,u.tenant_id AS tenant_id FROM auth_codes a JOIN users u ON u.id=a.user_id AND u.active=1 JOIN sessions s ON s.token_hash=a.sid_hash AND s.user_id=a.user_id WHERE a.code_hash=? AND a.client_id=? AND a.consumed_at IS NULL AND a.expires_at>? AND s.expires_at>? AND s.revoked_at IS NULL", (code_hash, client_id, now, now)).fetchone()
            if not code or not hmac.compare_digest(code["redirect_uri"], f.get("redirect_uri", "")):
                con.rollback()
                return json_response(start_response, "400 Bad Request", {"error": "invalid_grant"})
            expected_challenge = b64u(hashlib.sha256(f.get("code_verifier", "").encode()).digest())
            verifier = f.get("code_verifier", "")
            if not re.fullmatch(r"[A-Za-z0-9._~-]{43,128}", verifier) or not hmac.compare_digest(expected_challenge, code["challenge"]):
                con.rollback()
                return json_response(start_response, "400 Bad Request", {"error": "invalid_grant"})
            consumed = con.execute("UPDATE auth_codes SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL", (now, code_hash))
            if consumed.rowcount != 1:
                con.rollback()
                return json_response(start_response, "400 Bad Request", {"error": "invalid_grant"})
            access = b64u(secrets.token_bytes(32))
            con.execute("INSERT INTO access_tokens(token_hash,client_id,user_id,expires_at,sid_hash) VALUES(?,?,?,?,?)", (hashlib.sha256(access.encode()).hexdigest(), client_id, code["user_id"], int(time.time()) + ACCESS_TTL, code["sid_hash"]))
            subject = con.execute("SELECT sub FROM global_subjects WHERE user_id=?", (code["user_id"],)).fetchone()
            if subject:
                sub = subject["sub"]
            else:
                sub = b64u(secrets.token_bytes(32))
                con.execute("INSERT INTO global_subjects(user_id,sub) VALUES(?,?)", (code["user_id"], sub))
            subject_hash = hashlib.sha256((ISSUER + "\0" + str(sub)).encode("utf-8")).hexdigest()
            con.execute("INSERT INTO global_subject_hashes(subject_hash,user_id) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET subject_hash=excluded.subject_hash",
                        (subject_hash, int(code["user_id"])))
            now = int(time.time())
            sid_hash = str(code["sid_hash"] or "")
            if not re.fullmatch(r"[a-f0-9]{64}", sid_hash):
                con.rollback()
                return json_response(start_response, "400 Bad Request", {"error": "session_binding_missing"})
            claims = {"iss": ISSUER, "sub": sub, "aud": client_id, "iat": now, "exp": now + ACCESS_TTL, "auth_time": code["auth_time"], "nonce": code["nonce"], "sid": sid_hash}
            invited_tenant = str(code["tenant_id"] or "").strip()
            if re.fullmatch(r"[1-9][0-9]{0,18}", invited_tenant):
                tenant_number = int(invited_tenant)
                if tenant_number < 2**63:
                    claims["tenant_id"] = tenant_number
            id_token = sign_jwt(claims, rsa_public_jwk())
            con.commit()
        return json_response(start_response, "200 OK", {"access_token": access, "token_type": "Bearer", "expires_in": ACCESS_TTL, "id_token": id_token})
    if path == "/userinfo" and method == "GET":
        auth = environ.get("HTTP_AUTHORIZATION", "")
        if not auth.startswith("Bearer "):
            return json_response(start_response, "401 Unauthorized", {"error": "invalid_token"})
        token_hash = hashlib.sha256(auth[7:].encode()).hexdigest()
        with db() as con:
            row = con.execute("SELECT a.client_id,a.user_id,u.active FROM access_tokens a JOIN users u ON u.id=a.user_id JOIN clients c ON c.client_id=a.client_id AND c.active=1 JOIN sessions s ON s.token_hash=a.sid_hash AND s.user_id=a.user_id WHERE a.token_hash=? AND a.expires_at>? AND s.expires_at>? AND s.revoked_at IS NULL", (token_hash, int(time.time()), int(time.time()))).fetchone()
            if not row or not row["active"]:
                return json_response(start_response, "401 Unauthorized", {"error": "invalid_token"})
            client = client_for(con, row["client_id"])
            subject = con.execute("SELECT sub FROM global_subjects WHERE user_id=?", (row["user_id"],)).fetchone()
            if not subject:
                return json_response(start_response, "401 Unauthorized", {"error": "invalid_token"})
            sub = subject["sub"]
        return json_response(start_response, "200 OK", {"sub": sub})
    if path == "/session/introspect" and method == "POST":
        auth = environ.get("HTTP_AUTHORIZATION", "")
        if not auth.startswith("Basic "):
            return json_response(start_response, "401 Unauthorized", {"error": "invalid_client"})
        try:
            client_id, secret = base64.b64decode(auth[6:], validate=True).decode().split(":", 1)
            form = fields(environ)
        except Exception:
            return json_response(start_response, "400 Bad Request", {"error": "invalid_request"})
        sid_hash = form.get("sid", "")
        if not re.fullmatch(r"[a-f0-9]{64}", sid_hash):
            return json_response(start_response, "400 Bad Request", {"error": "invalid_sid"})
        with db() as con:
            client = client_for(con, client_id)
            if not client or not client["active"] or not hmac.compare_digest(hashlib.sha256(secret.encode()).hexdigest(), client["secret_hash"]):
                return json_response(start_response, "401 Unauthorized", {"error": "invalid_client"})
            row = con.execute("SELECT s.expires_at,s.created_at,u.display_name FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1 AND (u.email_verified=1 OR EXISTS(SELECT 1 FROM passkeys p WHERE p.user_id=u.id))",
                              (sid_hash, int(time.time()))).fetchone()
        return json_response(start_response, "200 OK", {"active": row is not None, "expires_at": int(row["expires_at"]) if row else 0,
                                                          "display_name": str(row["display_name"]) if row else "", "auth_time": int(row["created_at"] or 0) if row else 0})
    if path == "/logout" and method == "GET":
        token = cookie(environ, COOKIE)
        if token:
            with db() as con:
                con.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL", (int(time.time()), hashlib.sha256(token.encode()).hexdigest()))
        params = query(environ)
        return_to = params.get("post_logout_redirect_uri", "")
        allowed_returns = {
            "https://2415.jp/license/admin_api.php",
            "https://backup.2415.jp/license/admin_api.php",
            "https://main.2415.jp/license/admin_api.php",
            "https://2415.jp/license/mobile-manager/",
            "https://backup.2415.jp/license/mobile-manager/",
            "https://main.2415.jp/license/mobile-manager/",
            "https://2415.jp/license/tenant-portal/",
            "https://backup.2415.jp/license/tenant-portal/",
            "https://main.2415.jp/license/tenant-portal/",
        }
        location = return_to if return_to in allowed_returns else ISSUER + "/"
        state = params.get("state", "")
        if return_to in allowed_returns and re.fullmatch(r"[A-Za-z0-9._~-]{1,512}", state):
            location = append_query(location, {"state": state})
        return response(start_response, "303 See Other", b"", headers=[expire_session_cookie(),
            ("Clear-Site-Data", '"cache", "cookies", "storage"'), ("Location", location)])
    if path == "/account/passkey/add/begin" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f = fields(environ)
            token = cookie(environ, COOKIE)
            token_hash = hashlib.sha256(token.encode()).hexdigest() if token else ""
            now = int(time.time())
            flow = b64u(secrets.token_bytes(32))
            challenge = b64u(secrets.token_bytes(32))
            with db() as con:
                current = con.execute("SELECT s.user_id,s.csrf_hash,u.public_id,u.user_handle FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1", (token_hash, now)).fetchone()
                if not current or not current["csrf_hash"] or not hmac.compare_digest(current["csrf_hash"], hashlib.sha256(f.get("csrf", "").encode()).hexdigest()):
                    return json_response(start_response, "403 Forbidden", {"error": "csrf_validation_failed"})
                keys = con.execute("SELECT credential_id,transports FROM passkeys WHERE user_id=? ORDER BY created_at", (current["user_id"],)).fetchall()
                if not keys:
                    return json_response(start_response, "409 Conflict", {"error": "passkey_required", "message": "追加登録には、先に現在のパスキーを登録してください。"})
                if len(keys) >= 5:
                    return json_response(start_response, "409 Conflict", {"error": "passkey_limit_reached", "message": "登録できるパスキーは5件までです。"})
                con.execute("INSERT OR REPLACE INTO passkey_flows(flow_hash,user_id,challenge,mode,expires_at) VALUES(?,?,?,?,?)", (hashlib.sha256(flow.encode()).hexdigest(), current["user_id"], challenge, "manage_add_assert", now + 300))
                options = {"challenge": challenge, "rpId": PASSKEY_RP_ID, "timeout": 120000, "userVerification": "required", "allowCredentials": [{"type": "public-key", "id": row["credential_id"], "transports": json.loads(row["transports"] or "[]")} for row in keys]}
            return json_response(start_response, "200 OK", {"ok": True, "flow": flow, "publicKey": options}, [("Cache-Control", "no-store")])
        except Exception:
            return json_response(start_response, "400 Bad Request", {"error": "invalid_request"})
    if path == "/account/passkey/add/verify" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f = fields(environ)
            token = cookie(environ, COOKIE)
            token_hash = hashlib.sha256(token.encode()).hexdigest() if token else ""
            flow_hash = hashlib.sha256(f.get("flow", "").encode()).hexdigest()
            credential = f.get("credential") or {}
            now = int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                current = con.execute("SELECT s.user_id,s.csrf_hash,u.user_handle FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1", (token_hash, now)).fetchone()
                pending = con.execute("SELECT * FROM passkey_flows WHERE flow_hash=? AND mode='manage_add_assert' AND expires_at>?", (flow_hash, now)).fetchone()
                supplied_csrf = hashlib.sha256(f.get("csrf", "").encode()).hexdigest()
                if not current or not pending or current["user_id"] != pending["user_id"] or not hmac.compare_digest(current["csrf_hash"], supplied_csrf):
                    con.rollback()
                    return json_response(start_response, "403 Forbidden", {"error": "invalid_passkey_flow"})
                key = con.execute("SELECT * FROM passkeys WHERE credential_id=? AND user_id=?", (credential.get("id", ""), current["user_id"])).fetchone()
                if not key:
                    con.rollback()
                    return json_response(start_response, "401 Unauthorized", {"error": "invalid_passkey"})
                count = webauthn_assertion(credential.get("clientDataJSON", ""), credential.get("authenticatorData", ""), credential.get("signature", ""), pending["challenge"], key["public_key"], key["sign_count"], credential.get("userHandle", ""), current["user_handle"])
                keys = con.execute("SELECT credential_id FROM passkeys WHERE user_id=?", (current["user_id"],)).fetchall()
                if len(keys) >= 5:
                    con.rollback()
                    return json_response(start_response, "409 Conflict", {"error": "passkey_limit_reached", "message": "登録できるパスキーは5件までです。"})
                challenge = b64u(secrets.token_bytes(32))
                con.execute("UPDATE passkeys SET sign_count=?,last_used=? WHERE credential_id=?", (count, now, key["credential_id"]))
                con.execute("UPDATE passkey_flows SET challenge=?,mode='manage_add_register',expires_at=? WHERE flow_hash=?", (challenge, now + 300, flow_hash))
                con.commit()
                options = {"challenge": challenge, "rp": {"id": PASSKEY_RP_ID, "name": "SSO ID 2415.jp"}, "user": {"id": current["user_handle"], "name": "SSO ID", "displayName": "SSO ID"}, "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}], "timeout": 120000, "attestation": "none", "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"}, "excludeCredentials": [{"type": "public-key", "id": row["credential_id"]} for row in keys]}
            return json_response(start_response, "200 OK", {"ok": True, "flow": f.get("flow", ""), "publicKey": options}, [("Cache-Control", "no-store")])
        except Exception:
            return json_response(start_response, "401 Unauthorized", {"error": "invalid_passkey", "message": "現在のパスキーを確認できませんでした。"})
    if path == "/account/passkey/add/finish" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f = fields(environ)
            token = cookie(environ, COOKIE)
            token_hash = hashlib.sha256(token.encode()).hexdigest() if token else ""
            flow_hash = hashlib.sha256(f.get("flow", "").encode()).hexdigest()
            credential = f.get("credential") or {}
            now = int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                current = con.execute("SELECT s.user_id,s.csrf_hash,u.user_handle FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1", (token_hash, now)).fetchone()
                pending = con.execute("SELECT * FROM passkey_flows WHERE flow_hash=? AND mode='manage_add_register' AND expires_at>?", (flow_hash, now)).fetchone()
                supplied_csrf = hashlib.sha256(f.get("csrf", "").encode()).hexdigest()
                if not current or not pending or current["user_id"] != pending["user_id"] or not hmac.compare_digest(current["csrf_hash"], supplied_csrf):
                    con.rollback()
                    return json_response(start_response, "403 Forbidden", {"error": "invalid_passkey_flow"})
                keys = con.execute("SELECT credential_id FROM passkeys WHERE user_id=?", (current["user_id"],)).fetchall()
                if len(keys) >= 5:
                    con.rollback()
                    return json_response(start_response, "409 Conflict", {"error": "passkey_limit_reached"})
                registered = webauthn_registration(credential.get("clientDataJSON", ""), credential.get("attestationObject", ""), pending["challenge"], credential.get("id", ""))
                transports = json.dumps([value for value in credential.get("transports", []) if value in ("usb", "nfc", "ble", "internal", "hybrid")])
                con.execute("INSERT INTO passkeys(credential_id,user_id,public_key,sign_count,transports,created_at) VALUES(?,?,?,?,?,?)", (registered["credential_id"], current["user_id"], registered["public_key"], registered["counter"], transports, now))
                con.execute("DELETE FROM passkey_flows WHERE flow_hash=?", (flow_hash,))
                con.commit()
            return json_response(start_response, "200 OK", {"ok": True}, [("Cache-Control", "no-store")])
        except sqlite3.IntegrityError:
            return json_response(start_response, "409 Conflict", {"error": "passkey_already_registered", "message": "このパスキーはすでに登録されています。"})
        except Exception:
            return json_response(start_response, "400 Bad Request", {"error": "passkey_registration_failed", "message": "パスキーを登録できませんでした。もう一度お試しください。"})
    if path == "/account/totp/begin" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f = fields(environ); token = cookie(environ, COOKIE); token_hash = hashlib.sha256(token.encode()).hexdigest() if token else ""; now = int(time.time())
            flow = b64u(secrets.token_bytes(32)); challenge = b64u(secrets.token_bytes(32))
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                current = con.execute("SELECT s.user_id,s.csrf_hash FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1", (token_hash,now)).fetchone()
                if not current or not hmac.compare_digest(current["csrf_hash"], hashlib.sha256(f.get("csrf","").encode()).hexdigest()):
                    con.rollback(); return json_response(start_response,"403 Forbidden",{"error":"csrf_validation_failed"})
                if con.execute("SELECT 1 FROM totp_credentials WHERE user_id=?",(current["user_id"],)).fetchone():
                    con.rollback(); return json_response(start_response,"409 Conflict",{"error":"totp_already_enabled","message":"認証アプリはすでに有効です。"})
                keys=con.execute("SELECT credential_id,transports FROM passkeys WHERE user_id=? ORDER BY created_at",(current["user_id"],)).fetchall()
                if not keys:
                    con.rollback(); return json_response(start_response,"409 Conflict",{"error":"passkey_required","message":"設定には登録済みパスキーが必要です。"})
                con.execute("INSERT INTO passkey_flows(flow_hash,user_id,challenge,mode,expires_at) VALUES(?,?,?,?,?)",(hashlib.sha256(flow.encode()).hexdigest(),current["user_id"],challenge,"totp_setup_assert",now+300))
                options={"challenge":challenge,"rpId":PASSKEY_RP_ID,"timeout":120000,"userVerification":"required","allowCredentials":[{"type":"public-key","id":row["credential_id"],"transports":json.loads(row["transports"] or "[]")} for row in keys]}
                con.commit()
            return json_response(start_response,"200 OK",{"ok":True,"flow":flow,"publicKey":options},[("Cache-Control","no-store")])
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"invalid_totp_setup"})
    if path == "/account/totp/verify-passkey" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f=fields(environ); token=cookie(environ,COOKIE); token_hash=hashlib.sha256(token.encode()).hexdigest() if token else ""; flow_hash=hashlib.sha256(f.get("flow","").encode()).hexdigest(); credential=f.get("credential") or {}; now=int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                current=con.execute("SELECT s.user_id,s.csrf_hash,u.public_id,u.user_handle FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1",(token_hash,now)).fetchone()
                pending=con.execute("SELECT * FROM passkey_flows WHERE flow_hash=? AND mode='totp_setup_assert' AND expires_at>?",(flow_hash,now)).fetchone()
                supplied=hashlib.sha256(f.get("csrf","").encode()).hexdigest()
                if not current or not pending or current["user_id"]!=pending["user_id"] or not hmac.compare_digest(current["csrf_hash"],supplied) or con.execute("SELECT 1 FROM totp_credentials WHERE user_id=?",(current["user_id"],)).fetchone():
                    con.rollback(); return json_response(start_response,"403 Forbidden",{"error":"invalid_totp_setup_flow"})
                key=con.execute("SELECT * FROM passkeys WHERE credential_id=? AND user_id=?",(credential.get("id",""),current["user_id"])).fetchone()
                if not key:
                    con.rollback(); return json_response(start_response,"401 Unauthorized",{"error":"invalid_passkey"})
                count=webauthn_assertion(credential.get("clientDataJSON",""),credential.get("authenticatorData",""),credential.get("signature",""),pending["challenge"],key["public_key"],key["sign_count"],credential.get("userHandle",""),current["user_handle"])
                con.execute("UPDATE passkeys SET sign_count=?,last_used=? WHERE credential_id=?",(count,now,key["credential_id"]))
                secret=base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
                setup_flow=b64u(secrets.token_bytes(32)); encrypted=encrypt_private_value(secret,"totp-secret")
                con.execute("INSERT INTO totp_setup_flows(flow_hash,user_id,csrf_hash,secret_encrypted,expires_at,attempts) VALUES(?,?,?,?,?,0)",(hashlib.sha256(setup_flow.encode()).hexdigest(),current["user_id"],current["csrf_hash"],encrypted,now+600))
                con.execute("DELETE FROM passkey_flows WHERE flow_hash=?",(flow_hash,)); con.commit()
            label=quote("SSO ID 2415.jp:"+current["public_id"],safe="")
            uri="otpauth://totp/"+label+"?"+urlencode({"secret":secret,"issuer":"SSO ID 2415.jp","algorithm":"SHA1","digits":"6","period":"30"})
            return json_response(start_response,"200 OK",{"ok":True,"flow":setup_flow,"secret":secret,"otpauth_uri":uri},[("Cache-Control","no-store"),("Referrer-Policy","no-referrer")])
        except Exception:
            return json_response(start_response,"401 Unauthorized",{"error":"invalid_passkey","message":"パスキーを確認できませんでした。"})
    if path == "/account/totp/enable" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f=fields(environ); token=cookie(environ,COOKIE); token_hash=hashlib.sha256(token.encode()).hexdigest() if token else ""; flow_hash=hashlib.sha256(f.get("flow","").encode()).hexdigest(); now=int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                current=con.execute("SELECT s.user_id,s.csrf_hash,u.public_id FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1",(token_hash,now)).fetchone()
                pending=con.execute("SELECT * FROM totp_setup_flows WHERE flow_hash=? AND expires_at>?",(flow_hash,now)).fetchone()
                supplied=hashlib.sha256(f.get("csrf","").encode()).hexdigest()
                if not current or not pending or current["user_id"]!=pending["user_id"] or not hmac.compare_digest(current["csrf_hash"],supplied) or not hmac.compare_digest(pending["csrf_hash"],supplied):
                    con.rollback(); return json_response(start_response,"403 Forbidden",{"error":"invalid_totp_setup_flow"})
                secret=decrypt_private_value(pending["secret_encrypted"],"totp-secret")
                matched=verify_totp(secret,str(f.get("code","")),now,-1)
                if matched is None:
                    attempts=int(pending["attempts"])+1
                    if attempts>=5: con.execute("DELETE FROM totp_setup_flows WHERE flow_hash=?",(flow_hash,))
                    else: con.execute("UPDATE totp_setup_flows SET attempts=? WHERE flow_hash=?",(attempts,flow_hash))
                    con.commit(); return json_response(start_response,"401 Unauthorized",{"error":"invalid_otp","message":"6桁のコードを確認してください。"})
                if con.execute("SELECT 1 FROM totp_credentials WHERE user_id=?",(current["user_id"],)).fetchone():
                    con.rollback(); return json_response(start_response,"409 Conflict",{"error":"totp_already_enabled"})
                con.execute("INSERT INTO totp_credentials(user_id,secret_encrypted,enabled_at,last_step) VALUES(?,?,?,?)",(current["user_id"],pending["secret_encrypted"],now,matched))
                existing_certificate=con.execute("SELECT 1 FROM recovery_keys WHERE user_id=? AND certificate_version=1",(current["user_id"],)).fetchone()
                if existing_certificate:
                    certificate=None
                else:
                    certificate=new_recovery_certificate(current["public_id"],now)
                    con.execute("INSERT INTO recovery_keys(user_id,key_hash,created_at,used_at,certificate_version) VALUES(?,?,?,NULL,1) ON CONFLICT(user_id) DO UPDATE SET key_hash=excluded.key_hash,created_at=excluded.created_at,used_at=NULL,certificate_version=1 WHERE recovery_keys.certificate_version=0",(current["user_id"],recovery_key_hash(certificate["credential"]),now))
                con.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND token_hash<>? AND revoked_at IS NULL",(now,current["user_id"],token_hash))
                con.execute("DELETE FROM login_flows WHERE flow_hash IN (SELECT flow_hash FROM passkey_flows WHERE user_id=?)",(current["user_id"],))
                con.execute("DELETE FROM login_flows WHERE flow_hash IN (SELECT login_flow_hash FROM mfa_flows WHERE user_id=?)",(current["user_id"],))
                con.execute("DELETE FROM passkey_flows WHERE user_id=?",(current["user_id"],)); con.execute("DELETE FROM mfa_flows WHERE user_id=?",(current["user_id"],))
                con.execute("DELETE FROM totp_setup_flows WHERE flow_hash=?",(flow_hash,)); con.commit()
            return json_response(start_response,"200 OK",{"ok":True,"recovery_certificate":certificate},[("Cache-Control","no-store")])
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"totp_enable_failed","message":"認証アプリを有効にできませんでした。"})
    if path == "/account/totp/disable" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f=fields(environ); token=cookie(environ,COOKIE); token_hash=hashlib.sha256(token.encode()).hexdigest() if token else ""; now=int(time.time()); supplied_code=str(f.get("code","")).strip()
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                current=con.execute("SELECT s.user_id,s.csrf_hash FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1",(token_hash,now)).fetchone()
                supplied=hashlib.sha256(f.get("csrf","").encode()).hexdigest()
                if not current or not hmac.compare_digest(current["csrf_hash"],supplied):
                    con.rollback(); return json_response(start_response,"403 Forbidden",{"error":"csrf_validation_failed"})
                credential=con.execute("SELECT * FROM totp_credentials WHERE user_id=?",(current["user_id"],)).fetchone()
                if not credential:
                    con.rollback(); return json_response(start_response,"409 Conflict",{"error":"totp_not_enabled"})
                secret=decrypt_private_value(credential["secret_encrypted"],"totp-secret")
                matched=verify_totp(secret,supplied_code,now,credential["last_step"])
                if matched is None:
                    con.rollback(); return json_response(start_response,"401 Unauthorized",{"error":"invalid_otp","message":"認証アプリの現在の6桁コードを入力してください。"})
                changed=con.execute("UPDATE totp_credentials SET last_step=? WHERE user_id=? AND last_step<?",(matched,current["user_id"],matched)).rowcount
                if changed != 1:
                    con.rollback(); return json_response(start_response,"401 Unauthorized",{"error":"otp_replayed","message":"その認証コードは使用済みです。次のコードを入力してください。"})
                con.execute("DELETE FROM totp_credentials WHERE user_id=?",(current["user_id"],)); con.execute("DELETE FROM totp_setup_flows WHERE user_id=?",(current["user_id"],))
                con.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND token_hash<>? AND revoked_at IS NULL",(now,current["user_id"],token_hash))
                con.execute("DELETE FROM login_flows WHERE flow_hash IN (SELECT flow_hash FROM passkey_flows WHERE user_id=?)",(current["user_id"],)); con.execute("DELETE FROM login_flows WHERE flow_hash IN (SELECT login_flow_hash FROM mfa_flows WHERE user_id=?)",(current["user_id"],))
                con.execute("DELETE FROM passkey_flows WHERE user_id=?",(current["user_id"],)); con.execute("DELETE FROM mfa_flows WHERE user_id=?",(current["user_id"],)); con.commit()
            return json_response(start_response,"200 OK",{"ok":True,"disabled":True},[("Cache-Control","no-store")])
        except Exception:
            return json_response(start_response,"400 Bad Request",{"error":"totp_management_failed","message":"認証設定を変更できませんでした。"})
    if path == "/account/onboarding/complete" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        try:
            f = fields(environ)
            action = str(f.get("action", ""))
            if action not in ("skip", "continue"):
                return json_response(start_response, "400 Bad Request", {"error": "invalid_onboarding_action"})
            token = cookie(environ, COOKIE)
            token_hash = hashlib.sha256(token.encode()).hexdigest() if token else ""
            now = int(time.time())
            with db() as con:
                con.execute("BEGIN IMMEDIATE")
                current = con.execute("SELECT s.user_id,s.csrf_hash FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1", (token_hash, now)).fetchone()
                pending = con.execute("SELECT * FROM registration_onboarding WHERE session_hash=? AND expires_at>?", (token_hash, now)).fetchone()
                supplied = hashlib.sha256(str(f.get("csrf", "")).encode()).hexdigest()
                if not current or not pending or current["user_id"] != pending["user_id"] or not hmac.compare_digest(current["csrf_hash"], supplied):
                    con.rollback()
                    return json_response(start_response, "403 Forbidden", {"error": "invalid_onboarding_flow"})
                if action == "continue" and not con.execute("SELECT 1 FROM totp_credentials WHERE user_id=?", (current["user_id"],)).fetchone():
                    con.rollback()
                    return json_response(start_response, "409 Conflict", {"error": "totp_not_enabled", "message": "認証アプリを有効にするか、設定をスキップしてください。"})
                request_data = json.loads(pending["request_json"]) if pending["request_json"] else None
                if request_data:
                    _, error = valid_authorize(request_data, con)
                    if error:
                        con.execute("DELETE FROM registration_onboarding WHERE session_hash=?", (token_hash,))
                        con.commit()
                        return json_response(start_response, "400 Bad Request", {"error": error})
                    code = issue_code(con, request_data, current["user_id"], token_hash)
                con.execute("DELETE FROM registration_onboarding WHERE session_hash=?", (token_hash,))
                con.commit()
            next_url = append_query(request_data["redirect_uri"], {"code": code, "state": request_data["state"]}) if request_data else "/account?registration=complete"
            return json_response(start_response, "200 OK", {"ok": True, "next": next_url}, [("Cache-Control", "no-store")])
        except Exception:
            return json_response(start_response, "400 Bad Request", {"error": "onboarding_completion_failed"})
    if path == "/account" and method == "GET":
        current = cookie(environ, COOKIE)
        current_hash = hashlib.sha256(current.encode()).hexdigest() if current else ""
        user = user_for_session(environ)
        if not user:
            return response(start_response, "303 See Other", b"", headers=[expire_session_cookie(), ("Location", "/")])
        with db() as con:
            sessions = con.execute("SELECT token_hash,created_at,user_agent,expires_at FROM sessions WHERE user_id=? AND revoked_at IS NULL AND expires_at>? ORDER BY created_at DESC LIMIT 100",
                                   (user["id"], int(time.time()))).fetchall()
            registration_onboarding = con.execute("SELECT 1 FROM registration_onboarding WHERE session_hash=? AND user_id=? AND expires_at>?", (current_hash, user["id"], int(time.time()))).fetchone() is not None
        revoked = query(environ).get("revoked")
        notice = {"one": "選択した端末のセッションを失効しました。", "others": "他の端末のセッションを失効しました。"}.get(revoked, "")
        headers = [("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer")]
        return response(start_response, "200 OK", account_page(user, current_hash, sessions, notice, registration_onboarding), "text/html; charset=utf-8", headers=headers)
    if path == "/account" and method == "POST":
        if environ.get("HTTP_ORIGIN", "") != ISSUER:
            return json_response(start_response, "403 Forbidden", {"error": "origin_rejected"})
        form = fields(environ)
        token = cookie(environ, COOKIE)
        token_hash = hashlib.sha256(token.encode()).hexdigest() if token else ""
        action = form.get("action", "")
        if action not in ("revoke_one", "revoke_others", "revoke_all"):
            return json_response(start_response, "400 Bad Request", {"error": "invalid_action"})
        now = int(time.time())
        with db() as con:
            con.execute("BEGIN IMMEDIATE")
            current = con.execute("SELECT s.user_id,s.csrf_hash FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND s.revoked_at IS NULL AND u.active=1 AND (u.email_verified=1 OR EXISTS(SELECT 1 FROM passkeys p WHERE p.user_id=u.id))",
                                  (token_hash, now)).fetchone()
            supplied = form.get("csrf", "")
            if not current or not current["csrf_hash"] or not hmac.compare_digest(current["csrf_hash"], hashlib.sha256(supplied.encode()).hexdigest()):
                con.rollback()
                return json_response(start_response, "403 Forbidden", {"error": "csrf_validation_failed"})
            if action == "revoke_others":
                con.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND token_hash<>? AND revoked_at IS NULL AND expires_at>?",
                            (now, current["user_id"], token_hash, now))
                con.commit()
                return response(start_response, "303 See Other", b"", headers=[("Location", "/account?revoked=others")])
            if action == "revoke_one":
                target_hash = form.get("session", "")
                if not re.fullmatch(r"[a-f0-9]{64}", target_hash) or hmac.compare_digest(target_hash, token_hash):
                    con.rollback()
                    return json_response(start_response, "400 Bad Request", {"error": "invalid_session"})
                changed = con.execute("UPDATE sessions SET revoked_at=? WHERE token_hash=? AND user_id=? AND revoked_at IS NULL AND expires_at>?",
                                      (now, target_hash, current["user_id"], now)).rowcount
                if changed != 1:
                    con.rollback()
                    return json_response(start_response, "404 Not Found", {"error": "session_not_found"})
                con.commit()
                return response(start_response, "303 See Other", b"", headers=[("Location", "/account?revoked=one")])
            con.execute("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL", (now, current["user_id"]))
            con.commit()
        return response(start_response, "303 See Other", b"", headers=[expire_session_cookie(), ("Location", "/")])
    if path == "/" and method == "GET":
        return response(start_response, "200 OK", identity_home_page(user_for_session(environ)), "text/html; charset=utf-8", headers=[("Cache-Control", "no-store")])
    return json_response(start_response, "404 Not Found", {"error": "not_found"})


def app(environ, start_response):
    """Keep unexpected request and database failures from escaping the CGI/WSGI boundary."""
    try:
        return _app_impl(environ, start_response)
    except sqlite3.OperationalError:
        # Busy/locked storage and transient filesystem errors are service outages,
        # not client errors. Keep the message generic and ask clients to retry.
        print("sso_request_failed category=database", file=sys.stderr)
        return json_response(
            start_response, "503 Service Unavailable",
            {"error": "temporarily_unavailable", "message": "一時的に処理できません。少し待ってから再度お試しください。"},
            headers=[("Retry-After", "2")],
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        return json_response(start_response, "400 Bad Request", {"error": "invalid_request"})
    except Exception as error:
        print("sso_request_failed category=internal type=" + type(error).__name__, file=sys.stderr)
        return json_response(
            start_response, "500 Internal Server Error",
            {"error": "server_error", "message": "要求を処理できませんでした。時間をおいて再度お試しください。"},
        )


if __name__ == "__main__":
    host = os.environ.get("SSO_HOST", "127.0.0.1")
    port = int(os.environ.get("SSO_PORT", "8080"))
    if not DB.is_file() or not KEY.is_file():
        raise SystemExit("Run `python3 manage.py init` first.")
    with make_server(host, port, app) as server:
        print(f"SSO dev server listening on http://{host}:{port} (issuer {ISSUER})")
        server.serve_forever()
