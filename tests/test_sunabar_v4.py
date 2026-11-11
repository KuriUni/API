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


if __name__ == "__main__":
    unittest.main()


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
