"""Sunabar V4の実署名・Proofリプレイ統合試験。

専用MySQL DB sunabar_test と OpenSSL が必要。本番DBには接続しない。
"""
import base64
import hashlib
import os
import pathlib
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

try:
    import pymysql
except ImportError:  # pragma: no cover
    pymysql = None

ROOT = pathlib.Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT / "suna-core-source"))
import sunabar_v4


class SunabarV4ProofMySQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        required = ("SUNABAR_V4_MYSQL_HOST", "SUNABAR_V4_MYSQL_USER",
                    "SUNABAR_V4_MYSQL_PASSWORD", "SUNABAR_V4_MYSQL_DATABASE")
        if pymysql is None or not all(os.getenv(name) for name in required):
            raise unittest.SkipTest("専用MySQL試験DBが設定されていません")
        if os.environ["SUNABAR_V4_MYSQL_DATABASE"] != "sunabar_test":
            raise RuntimeError("安全のため、統合試験DB名は sunabar_test に限定しています")
        if not shutil.which("openssl"):
            raise unittest.SkipTest("OpenSSLが利用できません")
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
        cls.key_dir = tempfile.TemporaryDirectory(prefix="sunabar-v4-proof-test-")
        cls.private_key_path = os.path.join(cls.key_dir.name, "private.pem")
        cls.public_key_path = os.path.join(cls.key_dir.name, "public.pem")
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
             "-out", cls.private_key_path],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        with open(cls.private_key_path, "rb") as key_file:
            private_key = key_file.read()
        public = subprocess.run(
            ["openssl", "pkey", "-pubout", "-out", cls.public_key_path],
            input=private_key, check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10)
        cls.public_key_pem = public.stdout.decode("ascii")
        with cls.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("""CREATE TABLE IF NOT EXISTS sunabar_v4_proofs (
                    proof_hash CHAR(64) NOT NULL,
                    session_id VARCHAR(64) NOT NULL,
                    action VARCHAR(32) NOT NULL,
                    expires_at BIGINT NOT NULL,
                    PRIMARY KEY (proof_hash)
                ) ENGINE=InnoDB""")
            connection.commit()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "key_dir"):
            cls.key_dir.cleanup()

    @classmethod
    def connect(cls):
        return pymysql.connect(**cls.connection_args)

    def make_request(self, nonce=None, timestamp=None, data=None, token=None):
        nonce = nonce or ("proofnonce_" + os.urandom(18).hex())
        timestamp = int(time.time()) if timestamp is None else int(timestamp)
        data = {"operation": "verify", "value": "unchanged"} if data is None else data
        token = token or ("v4.a." + ("T" * 50))
        session_id = "proof-test-" + os.urandom(12).hex()
        credential_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        message = sunabar_v4.request_message(
            "verify", session_id, timestamp, nonce, data, credential_hash)
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.private_key_path],
            input=message.encode("utf-8"), check=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=10).stdout
        proof = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
        session = {"session_id": session_id, "public_key_pem": self.public_key_pem}
        headers = {
            "x-license-session": session_id,
            "x-license-timestamp": str(timestamp),
            "x-license-nonce": nonce,
            "x-license-proof": proof,
        }
        return session, data, headers, token

    def test_real_signature_is_accepted_and_proof_is_persisted(self):
        session, data, headers, token = self.make_request()
        connection = self.connect()
        try:
            sunabar_v4._require_proof(connection, session, "verify", data, headers, token)
            connection.commit()
        finally:
            connection.close()
        proof_hash = sunabar_v4._hash(session["session_id"] + "|" + headers["x-license-nonce"])
        connection = self.connect()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT session_id,action,expires_at FROM sunabar_v4_proofs WHERE proof_hash=%s",
                               (proof_hash,))
                row = cursor.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["session_id"], session["session_id"])
            self.assertEqual(row["action"], "verify")
            self.assertGreater(row["expires_at"], int(time.time()))
        finally:
            connection.close()

    def test_real_signature_replay_is_rejected_by_mysql_unique_key(self):
        session, data, headers, token = self.make_request()
        connection = self.connect()
        try:
            sunabar_v4._require_proof(connection, session, "verify", data, headers, token)
            connection.commit()
        finally:
            connection.close()

        connection = self.connect()
        try:
            with self.assertRaises(sunabar_v4.V4Error) as raised:
                sunabar_v4._require_proof(connection, session, "verify", data, headers, token)
            self.assertEqual(raised.exception.status, 401)
            self.assertEqual(raised.exception.code, "PROOF_REPLAYED")
            connection.rollback()
        finally:
            connection.close()

    def test_body_or_credential_tampering_invalidates_signature(self):
        session, data, headers, token = self.make_request()
        tampered_data = dict(data, value="tampered")
        connection = self.connect()
        try:
            with self.assertRaises(sunabar_v4.V4Error) as raised:
                sunabar_v4._require_proof(connection, session, "verify", tampered_data, headers, token)
            self.assertEqual(raised.exception.code, "PROOF_SIGNATURE_INVALID")
            connection.rollback()
        finally:
            connection.close()

        connection = self.connect()
        try:
            with self.assertRaises(sunabar_v4.V4Error) as raised:
                sunabar_v4._require_proof(connection, session, "verify", data, headers,
                                          token + "-tampered")
            self.assertEqual(raised.exception.code, "PROOF_SIGNATURE_INVALID")
            connection.rollback()
        finally:
            connection.close()

    def test_expired_timestamp_is_rejected_before_database_write(self):
        session, data, headers, token = self.make_request(timestamp=int(time.time()) - 61)
        connection = self.connect()
        try:
            with self.assertRaises(sunabar_v4.V4Error) as raised:
                sunabar_v4._require_proof(connection, session, "verify", data, headers, token)
            self.assertEqual(raised.exception.code, "PROOF_TIMESTAMP_INVALID")
            connection.rollback()
        finally:
            connection.close()

    def test_future_timestamp_is_rejected(self):
        session, data, headers, token = self.make_request(timestamp=int(time.time()) + 61)
        connection = self.connect()
        try:
            with self.assertRaises(sunabar_v4.V4Error) as raised:
                sunabar_v4._require_proof(connection, session, "verify", data, headers, token)
            self.assertEqual(raised.exception.code, "PROOF_TIMESTAMP_INVALID")
            connection.rollback()
        finally:
            connection.close()

    def test_signature_is_bound_to_action_and_session(self):
        session, data, headers, token = self.make_request()
        connection = self.connect()
        try:
            with self.assertRaises(sunabar_v4.V4Error) as raised:
                sunabar_v4._require_proof(connection, session, "revoke", data, headers, token)
            self.assertEqual(raised.exception.code, "PROOF_SIGNATURE_INVALID")
            connection.rollback()
        finally:
            connection.close()

        wrong_session = dict(session, session_id="different-session-id")
        connection = self.connect()
        try:
            with self.assertRaises(sunabar_v4.V4Error) as raised:
                sunabar_v4._require_proof(connection, wrong_session, "verify", data, headers, token)
            self.assertEqual(raised.exception.code, "PROOF_REQUIRED")
            connection.rollback()
        finally:
            connection.close()

    def test_malformed_proof_headers_are_rejected(self):
        session, data, headers, token = self.make_request()
        headers["x-license-nonce"] = "short"
        connection = self.connect()
        try:
            with self.assertRaises(sunabar_v4.V4Error) as raised:
                sunabar_v4._require_proof(connection, session, "verify", data, headers, token)
            self.assertEqual(raised.exception.code, "PROOF_REQUIRED")
            connection.rollback()
        finally:
            connection.close()

    def test_concurrent_identical_proof_has_only_one_winner(self):
        session, data, headers, token = self.make_request()
        barrier = threading.Barrier(2)

        def consume():
            barrier.wait(timeout=10)
            connection = self.connect()
            try:
                sunabar_v4._require_proof(connection, session, "verify", data, headers, token)
                connection.commit()
                return "accepted"
            except sunabar_v4.V4Error as exc:
                connection.rollback()
                return exc.code
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(lambda _: consume(), range(2)))
        self.assertCountEqual(outcomes, ["accepted", "PROOF_REPLAYED"])


if __name__ == "__main__":
    unittest.main()
