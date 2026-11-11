"""Sunabar V4のMySQL統合試験。

実行には SUNABAR_V4_MYSQL_* 環境変数と、専用DB sunabar_test が必要。
本番DBへの接続を誤って行わないよう、DB名は sunabar_test に固定する。
"""
import os
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
        connection = cls.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_licenses (
                    license_id VARCHAR(128) NOT NULL,
                    workspace_id VARCHAR(128) NOT NULL,
                    status VARCHAR(32) NOT NULL,
                    expires_at BIGINT NOT NULL,
                    PRIMARY KEY (workspace_id, license_id)
                ) ENGINE=InnoDB""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_v4_devices (
                    id BIGINT NOT NULL AUTO_INCREMENT,
                    device_hash CHAR(64) NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    key_thumbprint CHAR(64) NOT NULL,
                    key_algorithm VARCHAR(32) NOT NULL,
                    revoked_at BIGINT NULL,
                    last_seen_at BIGINT NOT NULL,
                    PRIMARY KEY (id)
                ) ENGINE=InnoDB""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_v4_sessions (
                    id BIGINT NOT NULL AUTO_INCREMENT,
                    session_id VARCHAR(64) NOT NULL,
                    family_id VARCHAR(64) NOT NULL,
                    workspace_id VARCHAR(128) NOT NULL,
                    license_id VARCHAR(128) NOT NULL,
                    device_id BIGINT NOT NULL,
                    access_hash CHAR(64) NOT NULL,
                    refresh_hash CHAR(64) NOT NULL,
                    access_expires_at BIGINT NOT NULL,
                    refresh_expires_at BIGINT NOT NULL,
                    token_version INT NOT NULL,
                    created_at BIGINT NOT NULL,
                    last_seen_at BIGINT NOT NULL,
                    revoked_at BIGINT NULL,
                    revoke_reason VARCHAR(64) NULL,
                    PRIMARY KEY (id),
                    UNIQUE KEY uq_test_session_id (session_id),
                    UNIQUE KEY uq_test_refresh_hash (refresh_hash),
                    KEY ix_test_family (family_id)
                ) ENGINE=InnoDB""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_v4_refresh_history (
                    token_hash CHAR(64) NOT NULL,
                    session_id VARCHAR(64) NOT NULL,
                    family_id VARCHAR(64) NOT NULL,
                    expires_at BIGINT NOT NULL,
                    used_at BIGINT NOT NULL,
                    PRIMARY KEY (token_hash),
                    KEY ix_test_refresh_family (family_id)
                ) ENGINE=InnoDB""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_v4_proofs (
                    proof_hash CHAR(64) NOT NULL,
                    session_id VARCHAR(64) NOT NULL,
                    action VARCHAR(32) NOT NULL,
                    expires_at BIGINT NOT NULL,
                    PRIMARY KEY (proof_hash)
                ) ENGINE=InnoDB""")
            connection.commit()
        finally:
            connection.close()

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
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                for table in ("sunabar_v4_proofs", "sunabar_v4_refresh_history",
                              "sunabar_v4_sessions", "sunabar_v4_devices", "sunabar_licenses"):
                    cursor.execute("DELETE FROM " + table)
                cursor.execute(
                    "INSERT INTO sunabar_licenses(license_id,workspace_id,status,expires_at) "
                    "VALUES(%s,%s,%s,%s)",
                    ("integration-license", self.workspace, "active", self.now + 86400))
                cursor.execute(
                    "INSERT INTO sunabar_v4_devices(id,device_hash,public_key_pem,key_thumbprint,"
                    "key_algorithm,revoked_at,last_seen_at) VALUES(%s,%s,%s,%s,%s,NULL,%s)",
                    (self.device_id, "d" * 64, "test-public-key", "t" * 64, "RSA-SHA256", self.now))
                cursor.execute(
                    "INSERT INTO sunabar_v4_sessions(session_id,family_id,workspace_id,license_id,"
                    "device_id,access_hash,refresh_hash,access_expires_at,refresh_expires_at,"
                    "token_version,created_at,last_seen_at,revoked_at,revoke_reason) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s,NULL,NULL)",
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
