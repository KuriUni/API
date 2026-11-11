import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "suna-core-source"))

import sunabar_v4

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxvdtzsaa25UYjWqQXSJc
C4dPbgeGIH1rV1oDV6JYFlER5zwjK85PGcVNZ1D26J72725FjO0ZNXk6EDPfqX67
tkGgz3MuKiHV7EkOCnxC0RAvP0BrhAycWvzCALOnbCEmWtUn5/YDq3spdrGkGs6k
qefmajWBXgtb2E7i7O1E0LRIqRapmhwmQEK7CP+p6bUcEl7NoRaDsQ3EGee0U6Sv
H9OpOMGG31imSw+MVxqxntyTkocI9CGkcTWZ8d2YiXRLM9nDxAUifA0+oAc1fjYz
+CFXFc9ziiLRDzaaS4WrB03TZ+wPvvB/N9AosPg2RkIGqpxSFz1Bs//90jR2tGiH
nQIDAQAB
-----END PUBLIC KEY-----"""
SIGNATURE = "Qy98GHbU702y-NCXnBknKpNcME__ae33Mw224Cqk9DtdKf2PZ0i595C_7zUzCohVyGsHJG4JgfRi2ztJdLncUtTxAkhugKrprvjGo6i_5DPijw-ZIrKEP1AaU2B0DUBEABfxc65Y5bY4CPhEG7J6VqRQctiM451JxVEN9cWMh4s4Atg5RjRPV5p0T8IqMe04ANQIiuaC9MT65K-0HYu9Aj2qLPTv3ONvnEsZoeE3ljrDg-_bRdsVAaq9tSdiUqI2wJ704Me_V_H59UVhjd3weMMMo1EYhYum3miRkpWM7wWucU2SCp9ydZkK9VfLjQFSXxy8B4IPtSm7qacAyjHz9A"
LICENSE_KEY = "SUNABAR-AAAAA-BBBBB-CCCCC-DDDDD-EEEEE"
NONCE = "nonce-value-1234567890"
CHALLENGE_ID = "b" * 32


def activation_data():
    return {"license_key": LICENSE_KEY, "device_fingerprint": "a" * 64,
            "device_public_key": PUBLIC_KEY, "challenge_id": CHALLENGE_ID,
            "nonce": NONCE, "signature": "placeholder"}


class ActivationContractTests(unittest.TestCase):
    def test_activation_message_shape(self):
        thumbprint = sunabar_v4.normalize_public_key(PUBLIC_KEY)["thumbprint"]
        message = sunabar_v4.activation_message(activation_data(), CHALLENGE_ID, NONCE, thumbprint)
        lines = message.splitlines()
        self.assertEqual(lines[:4], ["TUTI-LICENSE-V4", "ACTIVATE", "POST", "/license/api/v4/activate.php"])
        self.assertEqual(lines[4], CHALLENGE_ID)
        self.assertEqual(lines[5], NONCE)
        self.assertEqual(lines[6], thumbprint)
        self.assertEqual(len(lines[7]), 64)

    def test_fixture_signature_verifies(self):
        thumbprint = sunabar_v4.normalize_public_key(PUBLIC_KEY)["thumbprint"]
        message = sunabar_v4.activation_message(activation_data(), CHALLENGE_ID, NONCE, thumbprint)
        self.assertTrue(sunabar_v4.verify_signature(PUBLIC_KEY, message, SIGNATURE))
        self.assertFalse(sunabar_v4.verify_signature(PUBLIC_KEY, message + chr(10), SIGNATURE))
        self.assertFalse(sunabar_v4.verify_signature(PUBLIC_KEY, message, "AAAA"))

    def test_public_key_normalization(self):
        first = sunabar_v4.normalize_public_key(PUBLIC_KEY)
        crlf = PUBLIC_KEY.replace(chr(10), chr(13) + chr(10)) + chr(10)
        second = sunabar_v4.normalize_public_key(crlf)
        self.assertEqual(first["thumbprint"], second["thumbprint"])
        self.assertEqual(first["algorithm"], "RSA-SHA256")
        with self.assertRaises(sunabar_v4.V4Error):
            sunabar_v4.normalize_public_key("not a key")


class CanonicalBodyTests(unittest.TestCase):
    def test_scalar_normalization_matches_v4_contract(self):
        data = {"b": True, "a": None, "c": 7, "signature": "ignored"}
        self.assertEqual(sunabar_v4._canonical(data, True), '{"a":"","b":"true","c":"7"}')

    def test_request_message_contains_credential_hash(self):
        message = sunabar_v4.request_message("refresh", "session", 100, "nonce", {"refresh_token": "v4.r.x"}, "hash")
        self.assertEqual(message.splitlines()[:3],
                         ["TUTI-LICENSE-V4", "POST", "/license/api/v4/refresh.php"])


class UnsupportedActionTests(unittest.TestCase):
    def reply(self, status, payload):
        return status, payload

    def test_offline_actions_are_explicitly_unsupported(self):
        for action, code in (("offline-public-key", "OFFLINE_SIGNING_UNSUPPORTED"),
                             ("offline-ticket", "OFFLINE_UNSUPPORTED"),
                             ("migrate", "MIGRATION_UNSUPPORTED")):
            status, payload = sunabar_v4.handle_v4(action, {"workspace": "w" * 32}, {}, {}, None, self.reply, "rid")
            self.assertEqual(status, 501)
            self.assertFalse(payload["success"])
            self.assertEqual(payload["error_code"], code)
            self.assertEqual(payload["api_version"], "4.0-beta1")

    def test_unknown_action_returns_not_found(self):
        status, payload = sunabar_v4.handle_v4("nope", {"workspace": "w" * 32}, {}, {}, None, self.reply, "rid")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error_code"], "NOT_FOUND")


class FakeCursor:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, *args, **kwargs):
        return None

    def fetchone(self):
        return None


class FakeConnection:
    def cursor(self):
        return FakeCursor()

    def commit(self):
        pass

    def rollback(self):
        pass

    def close(self):
        pass


class ChallengeTests(unittest.TestCase):
    def test_challenge_returns_nonce_and_thumbprint(self):
        captured = {}

        def reply(status, payload):
            captured["status"] = status
            captured["payload"] = payload
            return status, payload

        status, payload = sunabar_v4.handle_v4(
            "challenge", {"workspace": "w" * 32},
            {"purpose": "activate", "device_public_key": PUBLIC_KEY},
            {}, lambda: FakeConnection(), reply, "rid")
        self.assertEqual(status, 200)
        self.assertTrue(payload["success"])
        challenge = payload["challenge"]
        self.assertEqual(len(challenge["challenge_id"]), 32)
        self.assertEqual(challenge["purpose"], "activate")
        self.assertEqual(challenge["device_key_thumbprint"],
                         sunabar_v4.normalize_public_key(PUBLIC_KEY)["thumbprint"])
        self.assertEqual(challenge["signature_algorithm"], "RSA-SHA256")



class RecordingCursor(FakeCursor):
    def __init__(self, connection):
        self.connection = connection

    def execute(self, query, params=None):
        self.connection.statements.append((query, params))


class RecordingConnection(FakeConnection):
    def __init__(self):
        self.statements = []
        self.last_id = 42

    def cursor(self):
        return RecordingCursor(self)

    def insert_id(self):
        return self.last_id


class V4TokenLifetimeTests(unittest.TestCase):
    def test_v4_ttls_are_explicit_and_distinct_from_v1_docs(self):
        self.assertEqual(sunabar_v4.ACCESS_TTL, 300)
        self.assertEqual(sunabar_v4.REFRESH_TTL, 14 * 86400)

    def test_new_session_tokens_are_capped_by_license_expiry(self):
        connection = RecordingConnection()
        now = 1_800_000_000
        original_time = sunabar_v4.time.time
        sunabar_v4.time.time = lambda: now
        try:
            payload = sunabar_v4._new_tokens(
                connection, "workspace", {"license_id": "lic-1", "expires_at": now + 90},
                7)
        finally:
            sunabar_v4.time.time = original_time

        self.assertEqual(payload["access_expires_in"], 90)
        self.assertEqual(payload["refresh_expires_in"], 90)
        self.assertEqual(payload["access_expires_at"], sunabar_v4._utc(now + 90))
        self.assertEqual(payload["refresh_expires_at"], sunabar_v4._utc(now + 90))
        self.assertTrue(payload["access_token"].startswith("v4.a."))
        self.assertTrue(payload["refresh_token"].startswith("v4.r."))
        insert = next(item for item in connection.statements if "INSERT INTO sunabar_v4_sessions" in item[0])
        stored = insert[1]
        self.assertEqual(stored[5], sunabar_v4._token_hash(payload["access_token"]))
        self.assertEqual(stored[6], sunabar_v4._token_hash(payload["refresh_token"]))
        self.assertNotEqual(stored[5], payload["access_token"])
        self.assertNotEqual(stored[6], payload["refresh_token"])

    def test_new_session_uses_v4_default_lifetimes_when_license_allows(self):
        connection = RecordingConnection()
        now = 1_800_000_000
        original_time = sunabar_v4.time.time
        sunabar_v4.time.time = lambda: now
        try:
            payload = sunabar_v4._new_tokens(
                connection, "workspace", {"license_id": "lic-2", "expires_at": now + 30 * 86400},
                8)
        finally:
            sunabar_v4.time.time = original_time

        self.assertEqual(payload["access_expires_in"], 300)
        self.assertEqual(payload["refresh_expires_in"], 14 * 86400)
        self.assertEqual(payload["refresh_after_seconds"], 240)


class V4RefreshRotationTests(unittest.TestCase):
    def test_refresh_rotation_records_old_token_hash_and_increments_version(self):
        connection = RecordingConnection()
        now = 1_800_000_000
        original_time = sunabar_v4.time.time
        sunabar_v4.time.time = lambda: now
        old_token = "v4.r." + ("A" * 50)
        existing = {
            "id": 12, "session_id": "session-1", "family_id": "family-1",
            "token_version": 4, "refresh_token": old_token,
            "refresh_expires_at": now + 1000,
        }
        try:
            payload = sunabar_v4._new_tokens(
                connection, "workspace",
                {"license_id": "lic-3", "expires_at": now + 30 * 86400},
                9, existing=existing)
        finally:
            sunabar_v4.time.time = original_time

        self.assertEqual(payload["token_version"], 5)
        history = next(item for item in connection.statements
                       if "INSERT IGNORE INTO sunabar_v4_refresh_history" in item[0])
        self.assertEqual(history[1][0], sunabar_v4._token_hash(old_token))
        self.assertEqual(history[1][1:3], ("session-1", "family-1"))
        update = next(item for item in connection.statements
                      if "UPDATE sunabar_v4_sessions SET access_hash" in item[0])
        self.assertEqual(update[1][0], sunabar_v4._token_hash(payload["access_token"]))
        self.assertEqual(update[1][1], sunabar_v4._token_hash(payload["refresh_token"]))


if __name__ == "__main__":
    unittest.main()
