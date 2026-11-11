"""Sunabar V4のMySQL統合試験。

実行には SUNABAR_V4_MYSQL_* 環境変数と、専用DB sunabar_test が必要。
本番DBへの接続を誤って行わないよう、DB名は sunabar_test に固定する。
"""
import base64
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

try:
    import pymysql
except ImportError:  # pragma: no cover - CI installs the pinned API requirements
    pymysql = None

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "suna-core-source"))
import sunabar_v4


class SunabarV4MySQLRefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = ("SUNABAR_V4_MYSQL_HOST", "SUNABAR_V4_MYSQL_USER",
                    "SUNABAR_V4_MYSQL_PASSWORD", "SUNABAR_V4_MYSQL_DATABASE")
        if pymysql is None or not all(os.getenv(name) for name in required):
            raise unittest.SkipTest("専用MySQL試験DBが設定されていません")
        if os.environ["SUNABAR_V4_MYSQL_DATABASE"] != "sunabar_test":
            raise RuntimeError("安全のため、統合試験DB名は sunabar_test に限定しています")
        cls.connection_args = {
            "host": os.environ["SUNABAR_V4_MYSQL_HOST"],
            "port": int(os.getenv("SUNABAR_V4_MYSQL_PORT", "3306")),
            "user": os.environ["SUNABAR_V4_MYSQL_USER"],
            "password": os.environ["SUNABAR_V4_MYSQL_PASSWORD"],
            "database": "sunabar_test",
            "charset": "utf8mb4",
            "autocommit": False,
            "cursorclass": pymysql.cursors.DictCursor,
        }
        if not shutil.which("openssl"):
            raise unittest.SkipTest("OpenSSLが利用できません")
        cls.key_dir = tempfile.TemporaryDirectory(prefix="sunabar-v4-activation-test-")
        cls.private_key_path = os.path.join(cls.key_dir.name, "private.pem")
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", cls.private_key_path],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        with open(cls.private_key_path, "rb") as key_file:
            private_key = key_file.read()
        public = subprocess.run(
            ["openssl", "pkey", "-pubout"], input=private_key, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        cls.public_key_pem = public.stdout.decode("ascii")
        connection = cls.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_licenses (
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
                    INDEX idx_sunabar_license_recent (workspace_id, issued_at, license_id),
                    INDEX idx_sunabar_license_status_expiry (status, expires_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_v4_devices (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    workspace_id CHAR(32) NOT NULL,
                    license_id CHAR(20) NOT NULL,
                    device_hash CHAR(64) NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    key_thumbprint CHAR(64) NOT NULL,
                    key_algorithm VARCHAR(32) NOT NULL,
                    device_label VARCHAR(120) NOT NULL DEFAULT '',
                    app_version VARCHAR(40) NOT NULL DEFAULT '',
                    bound_at BIGINT NOT NULL,
                    last_seen_at BIGINT NOT NULL,
                    revoked_at BIGINT NULL,
                    UNIQUE KEY uq_sunabar_v4_device (workspace_id, license_id, device_hash),
                    UNIQUE KEY uq_sunabar_v4_license_key (license_id, key_thumbprint),
                    INDEX idx_sunabar_v4_device_license (license_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_v4_sessions (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    session_id CHAR(32) NOT NULL UNIQUE,
                    family_id CHAR(32) NOT NULL,
                    workspace_id CHAR(32) NOT NULL,
                    license_id CHAR(20) NOT NULL,
                    device_id BIGINT UNSIGNED NOT NULL,
                    access_hash CHAR(64) NOT NULL UNIQUE,
                    refresh_hash CHAR(64) NOT NULL UNIQUE,
                    access_expires_at BIGINT NOT NULL,
                    refresh_expires_at BIGINT NOT NULL,
                    token_version INT NOT NULL DEFAULT 1,
                    created_at BIGINT NOT NULL,
                    last_seen_at BIGINT NOT NULL,
                    revoked_at BIGINT NULL,
                    revoke_reason VARCHAR(40) NOT NULL DEFAULT '',
                    INDEX idx_sunabar_v4_session_family (family_id),
                    INDEX idx_sunabar_v4_session_device (device_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_v4_refresh_history (
                    token_hash CHAR(64) NOT NULL PRIMARY KEY,
                    session_id CHAR(32) NOT NULL,
                    family_id CHAR(32) NOT NULL,
                    expires_at BIGINT NOT NULL,
                    used_at BIGINT NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_v4_challenges (
                    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                    challenge_id CHAR(32) NOT NULL UNIQUE,
                    workspace_id CHAR(32) NOT NULL,
                    purpose VARCHAR(8) NOT NULL,
                    nonce_hash CHAR(64) NOT NULL,
                    key_thumbprint CHAR(64) NOT NULL,
                    expires_at BIGINT NOT NULL,
                    consumed_at BIGINT NULL,
                    INDEX idx_sunabar_v4_challenge_expiry (workspace_id, expires_at)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_v4_proofs (
                    proof_hash CHAR(64) NOT NULL PRIMARY KEY,
                    session_id CHAR(32) NOT NULL,
                    action VARCHAR(16) NOT NULL,
                    expires_at BIGINT NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4""")
            connection.commit()
        finally:
            connection.close()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "key_dir"):
            cls.key_dir.cleanup()

    @classmethod
    def connect(cls):
        return pymysql.connect(**cls.connection_args)

    def setUp(self):
        self.now = int(sunabar_v4.time.time())
        self.old_refresh = "v4.r." + ("R" * 64)
        self.workspace = "integration-workspace"
        self.session_id = "integration-session"
        self.family_id = "integration-family"
        self.device_id = 1
        self.license_key = "SUNABAR-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                for table in ("sunabar_v4_proofs", "sunabar_v4_challenges",
                              "sunabar_v4_refresh_history", "sunabar_v4_sessions",
                              "sunabar_v4_devices", "sunabar_licenses"):
                    cursor.execute("DELETE FROM " + table)
                cursor.execute(
                    "INSERT INTO sunabar_licenses(license_id,key_hash,workspace_id,product_id,product_name,"
                    "license_mode,max_devices,label,issued_at,expires_at,status) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    ("integration-license", sunabar_v4._hash(self.license_key), self.workspace, 1,
                     "統合試験ライセンス", "online", 3, "統合試験", self.now, self.now + 86400, "active"))
                cursor.execute(
                    "INSERT INTO sunabar_v4_devices(id,workspace_id,license_id,device_hash,public_key_pem,"
                    "key_thumbprint,key_algorithm,bound_at,revoked_at,last_seen_at) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,NULL,%s)",
                    (self.device_id, self.workspace, "integration-license", "d" * 64,
                     "test-public-key", "t" * 64, "RSA-SHA256", self.now, self.now))
                cursor.execute(
                    "INSERT INTO sunabar_v4_sessions(session_id,family_id,workspace_id,license_id,"
                    "device_id,access_hash,refresh_hash,access_expires_at,refresh_expires_at,"
                    "token_version,created_at,last_seen_at,revoked_at,revoke_reason) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s,NULL,'')",
                    (self.session_id, self.family_id, self.workspace, "integration-license",
                     self.device_id, sunabar_v4._token_hash("v4.a." + ("A" * 64)),
                     sunabar_v4._token_hash(self.old_refresh), self.now + 300,
                     self.now + 3600, self.now, self.now))
            connection.commit()
        finally:
            connection.close()

    def invoke_refresh(self, token):
        def reply(status, payload):
            return status, payload

        return sunabar_v4.handle_v4(
            "refresh", {"workspace": self.workspace}, {"refresh_token": token},
            {"x-license-session": self.session_id}, self.connect, reply, "mysql-test")

    def test_real_signed_activation_consumes_challenge_and_is_tenant_scoped(self):
        def reply(status, payload):
            return status, payload

        thumbprint = sunabar_v4.normalize_public_key(self.public_key_pem)["thumbprint"]
        status, challenge_reply = sunabar_v4.handle_v4(
            "challenge", {"workspace": self.workspace},
            {"purpose": "activate", "device_public_key": self.public_key_pem},
            {}, self.connect, reply, "activation-challenge")
        self.assertEqual(status, 200)
        challenge = challenge_reply["challenge"]
        data = {
            "license_key": self.license_key,
            "device_fingerprint": "a" * 64,
            "device_public_key": self.public_key_pem,
            "challenge_id": challenge["challenge_id"],
            "nonce": challenge["nonce"],
            "device_label": "統合試験端末",
            "app_version": "test",
            "signature": "placeholder",
        }
        message = sunabar_v4.activation_message(
            data, challenge["challenge_id"], challenge["nonce"], thumbprint)
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.private_key_path],
            input=message.encode("utf-8"), check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10).stdout
        data["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

        status, activated = sunabar_v4.handle_v4(
            "activate", {"workspace": self.workspace}, data, {},
            self.connect, reply, "activation-real-signature")
        self.assertEqual(status, 200, activated)
        self.assertTrue(activated["success"])
        self.assertEqual(activated["session"]["token_version"], 1)
        self.assertEqual(activated["device"]["key_thumbprint"], thumbprint)

        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT consumed_at FROM sunabar_v4_challenges WHERE challenge_id=%s",
                               (challenge["challenge_id"],))
                consumed = cursor.fetchone()
                cursor.execute("SELECT COUNT(*) AS count FROM sunabar_v4_devices "
                               "WHERE workspace_id=%s AND license_id=%s",
                               (self.workspace, "integration-license"))
                device_count = cursor.fetchone()["count"]
                cursor.execute("SELECT COUNT(*) AS count FROM sunabar_v4_sessions "
                               "WHERE workspace_id=%s AND license_id=%s",
                               (self.workspace, "integration-license"))
                session_count = cursor.fetchone()["count"]
            self.assertIsNotNone(consumed["consumed_at"])
            self.assertEqual(device_count, 2)
            self.assertEqual(session_count, 2)
        finally:
            connection.close()

        replay_status, replay = sunabar_v4.handle_v4(
            "activate", {"workspace": self.workspace}, data, {},
            self.connect, reply, "activation-replay")
        self.assertEqual(replay_status, 409)
        self.assertEqual(replay["error_code"], "CHALLENGE_ALREADY_USED")

    def test_activation_signature_cannot_be_reused_after_body_tampering(self):
        def reply(status, payload):
            return status, payload

        thumbprint = sunabar_v4.normalize_public_key(self.public_key_pem)["thumbprint"]
        status, challenge_reply = sunabar_v4.handle_v4(
            "challenge", {"workspace": self.workspace},
            {"purpose": "activate", "device_public_key": self.public_key_pem},
            {}, self.connect, reply, "activation-tamper-challenge")
        self.assertEqual(status, 200)
        challenge = challenge_reply["challenge"]
        data = {
            "license_key": self.license_key,
            "device_fingerprint": "b" * 64,
            "device_public_key": self.public_key_pem,
            "challenge_id": challenge["challenge_id"],
            "nonce": challenge["nonce"],
            "device_label": "署名時のラベル",
            "signature": "placeholder",
        }
        message = sunabar_v4.activation_message(
            data, challenge["challenge_id"], challenge["nonce"], thumbprint)
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.private_key_path],
            input=message.encode("utf-8"), check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10).stdout
        data["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        data["device_label"] = "改ざん後のラベル"

        status, response = sunabar_v4.handle_v4(
            "activate", {"workspace": self.workspace}, data, {},
            self.connect, reply, "activation-tampered-body")
        self.assertEqual(status, 401)
        self.assertEqual(response["error_code"], "DEVICE_SIGNATURE_INVALID")

    def test_challenge_cannot_be_used_from_another_workspace(self):
        def reply(status, payload):
            return status, payload

        other_workspace = "another-workspace"
        thumbprint = sunabar_v4.normalize_public_key(self.public_key_pem)["thumbprint"]
        status, challenge_reply = sunabar_v4.handle_v4(
            "challenge", {"workspace": other_workspace},
            {"purpose": "activate", "device_public_key": self.public_key_pem},
            {}, self.connect, reply, "foreign-workspace-challenge")
        self.assertEqual(status, 200)
        challenge = challenge_reply["challenge"]
        data = {
            "license_key": self.license_key,
            "device_fingerprint": "c" * 64,
            "device_public_key": self.public_key_pem,
            "challenge_id": challenge["challenge_id"],
            "nonce": challenge["nonce"],
            "signature": "placeholder",
        }
        message = sunabar_v4.activation_message(
            data, challenge["challenge_id"], challenge["nonce"], thumbprint)
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.private_key_path],
            input=message.encode("utf-8"), check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10).stdout
        data["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

        status, response = sunabar_v4.handle_v4(
            "activate", {"workspace": self.workspace}, data, {},
            self.connect, reply, "foreign-challenge-activation")
        self.assertEqual(status, 400)
        self.assertEqual(response["error_code"], "CHALLENGE_INVALID")

    def test_license_key_from_another_workspace_cannot_be_activated(self):
        def reply(status, payload):
            return status, payload

        other_license_key = "SUNABAR-OTHER-AAAA-BBBB-CCCC-DDDDD"
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO sunabar_licenses(license_id,key_hash,workspace_id,product_id,"
                    "product_name,license_mode,max_devices,label,issued_at,expires_at,status) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    ("other-license-001", sunabar_v4._hash(other_license_key), "another-workspace",
                     1, "別テナント試験", "online", 3, "別テナント", self.now,
                     self.now + 86400, "active"))
            connection.commit()
        finally:
            connection.close()

        thumbprint = sunabar_v4.normalize_public_key(self.public_key_pem)["thumbprint"]
        status, challenge_reply = sunabar_v4.handle_v4(
            "challenge", {"workspace": self.workspace},
            {"purpose": "activate", "device_public_key": self.public_key_pem},
            {}, self.connect, reply, "tenant-license-challenge")
        self.assertEqual(status, 200)
        challenge = challenge_reply["challenge"]
        data = {
            "license_key": other_license_key,
            "device_fingerprint": "e" * 64,
            "device_public_key": self.public_key_pem,
            "challenge_id": challenge["challenge_id"],
            "nonce": challenge["nonce"],
            "signature": "placeholder",
        }
        message = sunabar_v4.activation_message(
            data, challenge["challenge_id"], challenge["nonce"], thumbprint)
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.private_key_path],
            input=message.encode("utf-8"), check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10).stdout
        data["signature"] = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")

        status, response = sunabar_v4.handle_v4(
            "activate", {"workspace": self.workspace}, data, {},
            self.connect, reply, "foreign-license-activation")
        self.assertEqual(status, 401)
        self.assertEqual(response["error_code"], "LICENSE_UNAVAILABLE")

    def signed_session_headers(self, action, data, token):
        timestamp = int(sunabar_v4.time.time())
        nonce = "sessionproof_" + os.urandom(18).hex()
        credential_hash = sunabar_v4._token_hash(token)
        message = sunabar_v4.request_message(
            action, self.session_id, timestamp, nonce, data, credential_hash)
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.private_key_path],
            input=message.encode("utf-8"), check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10).stdout
        return {
            "authorization": "Bearer " + token,
            "x-license-session": self.session_id,
            "x-license-timestamp": str(timestamp),
            "x-license-nonce": nonce,
            "x-license-proof": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
        }

    def test_real_access_proof_verify_then_family_revoke(self):
        def reply(status, payload):
            return status, payload

        token = "v4.a." + ("V" * 64)
        thumbprint = sunabar_v4.normalize_public_key(self.public_key_pem)["thumbprint"]
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE sunabar_v4_devices SET public_key_pem=%s,key_thumbprint=%s,"
                    "key_algorithm='RSA-SHA256' WHERE id=%s",
                    (self.public_key_pem, thumbprint, self.device_id))
                cursor.execute("UPDATE sunabar_v4_sessions SET access_hash=%s WHERE session_id=%s",
                               (sunabar_v4._token_hash(token), self.session_id))
            connection.commit()
        finally:
            connection.close()

        verify_data = {"check": "session"}
        verify_headers = self.signed_session_headers("verify", verify_data, token)
        status, verified = sunabar_v4.handle_v4(
            "verify", {"workspace": self.workspace}, verify_data, verify_headers,
            self.connect, reply, "real-proof-verify")
        self.assertEqual(status, 200, verified)
        self.assertTrue(verified["valid"])
        self.assertEqual(verified["session"]["session_id"], self.session_id)

        revoke_data = {"scope": "family"}
        revoke_headers = self.signed_session_headers("revoke", revoke_data, token)
        status, revoked = sunabar_v4.handle_v4(
            "revoke", {"workspace": self.workspace}, revoke_data, revoke_headers,
            self.connect, reply, "real-proof-revoke")
        self.assertEqual(status, 200, revoked)
        self.assertTrue(revoked["revoked"])
        self.assertEqual(revoked["scope"], "family")
        self.assertEqual(revoked["affected_sessions"], 1)

        after_revoke_headers = self.signed_session_headers("verify", verify_data, token)
        status, rejected = sunabar_v4.handle_v4(
            "verify", {"workspace": self.workspace}, verify_data, after_revoke_headers,
            self.connect, reply, "verify-after-revoke")
        self.assertEqual(status, 401)
        self.assertEqual(rejected["error_code"], "SESSION_REVOKED")

    def test_inactive_or_expired_license_blocks_existing_access_tokens(self):
        def reply(status, payload):
            return status, payload

        token = "v4.a." + ("L" * 64)
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE sunabar_v4_sessions SET access_hash=%s WHERE session_id=%s",
                               (sunabar_v4._token_hash(token), self.session_id))
                cursor.execute("UPDATE sunabar_licenses SET status='suspended' "
                               "WHERE workspace_id=%s AND license_id=%s",
                               (self.workspace, "integration-license"))
            connection.commit()
        finally:
            connection.close()

        headers = {"authorization": "Bearer " + token, "x-license-session": self.session_id}
        status, response = sunabar_v4.handle_v4(
            "verify", {"workspace": self.workspace}, {}, headers,
            self.connect, reply, "suspended-license")
        self.assertEqual(status, 401)
        self.assertEqual(response["error_code"], "LICENSE_UNAVAILABLE")

        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE sunabar_licenses SET status='active',expires_at=%s "
                               "WHERE workspace_id=%s AND license_id=%s",
                               (int(sunabar_v4.time.time()) - 1, self.workspace, "integration-license"))
            connection.commit()
        finally:
            connection.close()

        status, response = sunabar_v4.handle_v4(
            "verify", {"workspace": self.workspace}, {}, headers,
            self.connect, reply, "expired-license")
        self.assertEqual(status, 401)
        self.assertEqual(response["error_code"], "LICENSE_UNAVAILABLE")

    def test_expired_access_token_is_rejected_before_proof_validation(self):
        def reply(status, payload):
            return status, payload

        token = "v4.a." + ("E" * 64)
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE sunabar_v4_sessions SET access_hash=%s,access_expires_at=%s "
                               "WHERE session_id=%s",
                               (sunabar_v4._token_hash(token), int(sunabar_v4.time.time()) - 1,
                                self.session_id))
            connection.commit()
        finally:
            connection.close()

        headers = {"authorization": "Bearer " + token, "x-license-session": self.session_id}
        status, response = sunabar_v4.handle_v4(
            "verify", {"workspace": self.workspace}, {}, headers,
            self.connect, reply, "expired-access-token")
        self.assertEqual(status, 401)
        self.assertEqual(response["error_code"], "ACCESS_TOKEN_EXPIRED")

    def test_refresh_rotates_token_and_persists_only_hashes(self):
        with patch.object(sunabar_v4, "_require_proof", return_value=None):
            status, payload = self.invoke_refresh(self.old_refresh)
        self.assertEqual(status, 200)
        new_token = payload["session"]["refresh_token"]
        self.assertNotEqual(new_token, self.old_refresh)

        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT refresh_hash,token_version FROM sunabar_v4_sessions "
                               "WHERE session_id=%s", (self.session_id,))
                row = cursor.fetchone()
                cursor.execute("SELECT token_hash FROM sunabar_v4_refresh_history "
                               "WHERE session_id=%s", (self.session_id,))
                history = cursor.fetchone()
            self.assertEqual(row["refresh_hash"], sunabar_v4._token_hash(new_token))
            self.assertNotEqual(row["refresh_hash"], new_token)
            self.assertEqual(row["token_version"], 2)
            self.assertEqual(history["token_hash"], sunabar_v4._token_hash(self.old_refresh))
        finally:
            connection.close()

    def test_concurrent_refresh_reuse_revokes_the_session_family(self):
        barrier = threading.Barrier(2)

        def request():
            barrier.wait(timeout=10)
            return self.invoke_refresh(self.old_refresh)

        with patch.object(sunabar_v4, "_require_proof", return_value=None):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: request(), range(2)))

        self.assertEqual(sorted(status for status, _ in results), [200, 401])
        errors = [body.get("error_code") for status, body in results if status == 401]
        self.assertEqual(errors, ["REFRESH_REUSE_DETECTED"])

        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT revoked_at,revoke_reason FROM sunabar_v4_sessions "
                               "WHERE family_id=%s", (self.family_id,))
                row = cursor.fetchone()
            self.assertIsNotNone(row["revoked_at"])
            self.assertEqual(row["revoke_reason"], "refresh_reuse_detected")
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
