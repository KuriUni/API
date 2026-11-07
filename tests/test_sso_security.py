import importlib.util
import pathlib
import tempfile
import unittest
from unittest import mock


SERVER_PATH = pathlib.Path(__file__).resolve().parents[1] / "sso-ftp-source-20261103-002438" / "server.py"
spec = importlib.util.spec_from_file_location("sso_server_under_test", str(SERVER_PATH))
sso = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sso)


class SessionIdleTimeoutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = pathlib.Path(self.temp.name) / "sso.sqlite3"
        with mock.patch.object(sso, "DB", self.db_path):
            with sso.db() as con:
                con.execute("CREATE TABLE sessions(token_hash TEXT PRIMARY KEY,created_at INTEGER NOT NULL,last_seen INTEGER NOT NULL,expires_at INTEGER NOT NULL,revoked_at INTEGER)")
                con.execute("INSERT INTO sessions VALUES(?,?,?,?,NULL)", ("token-hash", 1000, 1000, 10000))
        self.db_patch = mock.patch.object(sso, "DB", self.db_path)
        self.db_patch.start()
        self.cookie_patch = mock.patch.object(sso, "cookie", return_value="test-token")
        self.cookie_patch.start()
        self.token_hash_patch = mock.patch.object(sso.hashlib, "sha256", wraps=sso.hashlib.sha256)
        self.token_hash_patch.start()
        # Use the real deterministic SHA-256 for the token fixture.
        self.expected_hash = sso.hashlib.sha256(b"test-token").hexdigest()
        with sso.db() as con:
            con.execute("UPDATE sessions SET token_hash=?", (self.expected_hash,))

    def tearDown(self):
        self.token_hash_patch.stop()
        self.cookie_patch.stop()
        self.db_patch.stop()
        self.temp.cleanup()

    def test_recent_activity_refreshes_last_seen(self):
        self.assertTrue(sso.touch_browser_session({}, now=1200))
        with sso.db() as con:
            self.assertEqual(con.execute("SELECT last_seen FROM sessions").fetchone()[0], 1200)

    def test_idle_session_is_revoked_at_timeout(self):
        self.assertFalse(sso.touch_browser_session({}, now=1000 + sso.SESSION_IDLE_TTL))
        with sso.db() as con:
            self.assertEqual(con.execute("SELECT revoked_at FROM sessions").fetchone()[0], 1000 + sso.SESSION_IDLE_TTL)

    def test_expired_absolute_session_is_not_refreshed(self):
        with sso.db() as con:
            con.execute("UPDATE sessions SET expires_at=1100")
        self.assertFalse(sso.touch_browser_session({}, now=1100))


class RateLimitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_patch = mock.patch.object(sso, "DB", pathlib.Path(self.temp.name) / "sso.sqlite3")
        self.db_patch.start()
        with sso.db() as con:
            con.execute("CREATE TABLE security_rate_limits(rate_key TEXT PRIMARY KEY,window_started INTEGER NOT NULL,attempts INTEGER NOT NULL)")
            con.execute("CREATE TABLE security_rate_limit_maintenance(singleton INTEGER PRIMARY KEY,last_cleanup INTEGER NOT NULL)")

    def tearDown(self):
        self.db_patch.stop()
        self.temp.cleanup()

    def test_fixed_window_limit_and_reset(self):
        self.assertTrue(sso.consume_security_rate_limit("recovery-test", 2, 60, now=100))
        self.assertTrue(sso.consume_security_rate_limit("recovery-test", 2, 60, now=101))
        self.assertFalse(sso.consume_security_rate_limit("recovery-test", 2, 60, now=102))
        self.assertTrue(sso.consume_security_rate_limit("recovery-test", 2, 60, now=160))


class RecoveryPrimitiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        key_file = pathlib.Path(self.temp.name) / "email-key.bin"
        key_file.write_bytes(bytes(range(64)))
        self.key_patch = mock.patch.object(sso, "EMAIL_KEY", key_file)
        self.key_patch.start()

    def tearDown(self):
        self.key_patch.stop()
        self.temp.cleanup()

    def test_recovery_certificate_is_bound_to_issuer_and_account(self):
        certificate = sso.new_recovery_certificate("SID-TEST", now=100)
        self.assertTrue(sso.recovery_certificate_hash(certificate, "SID-TEST"))
        self.assertEqual(sso.recovery_certificate_hash(certificate, "SID-OTHER"), "")
        certificate["issuer"] = "https://attacker.invalid"
        self.assertEqual(sso.recovery_certificate_hash(certificate, "SID-TEST"), "")

    def test_recovery_code_hash_is_bound_to_flow_and_salt(self):
        first = sso.recovery_code_hash("flow-a", b"salt-a", "12345678")
        self.assertEqual(first, sso.recovery_code_hash("flow-a", b"salt-a", "12345678"))
        self.assertNotEqual(first, sso.recovery_code_hash("flow-b", b"salt-a", "12345678"))
        self.assertNotEqual(first, sso.recovery_code_hash("flow-a", b"salt-b", "12345678"))


if __name__ == "__main__":
    unittest.main()
