import base64
import json
import pathlib
import sys
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xrea-source"))

import admin_oidc
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class OidcIdTokenClaimHardeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = cls.private.public_key().public_numbers()
        cls.jwk = {
            "kid": "test-key",
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
            "e": b64url(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
        }

    def _token(self, claims_json=None, overrides=None):
        now = int(time.time())
        claims = {
            "iss": admin_oidc.ISSUER,
            "aud": admin_oidc.CLIENT_ID,
            "iat": now - 30,
            "exp": now + 270,
            "nbf": now - 30,
            "nonce": "expected-nonce",
            "sub": "user-subject-identifier-12345",
            "sid": "a" * 64,
        }
        claims.update(overrides or {})
        header = {"alg": "RS256", "kid": "test-key", "typ": "JWT"}
        header_part = b64url(json.dumps(header, separators=(",", ":")).encode())
        payload_part = b64url((claims_json if claims_json is not None else json.dumps(
            claims, separators=(",", ":")
        )).encode())
        signing_input = (header_part + "." + payload_part).encode("ascii")
        signature = self.private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return header_part + "." + payload_part + "." + b64url(signature)

    def _verify(self, token):
        with mock.patch.object(admin_oidc, "_jwks", return_value=[self.jwk]):
            return admin_oidc._verify_id_token(token, "expected-nonce")

    def test_accepts_valid_token_with_past_not_before(self):
        self.assertEqual(self._verify(self._token())["sid"], "a" * 64)

    def test_rejects_future_not_before(self):
        token = self._token(overrides={"nbf": int(time.time()) + 120})
        with self.assertRaisesRegex(RuntimeError, "oidc_claims_invalid"):
            self._verify(token)

    def test_rejects_non_numeric_not_before(self):
        token = self._token(overrides={"nbf": "tomorrow"})
        with self.assertRaisesRegex(RuntimeError, "oidc_claims_invalid"):
            self._verify(token)

    def test_rejects_expiration_before_issue_time(self):
        now = int(time.time())
        token = self._token(overrides={"iat": now - 30, "exp": now - 1})
        with self.assertRaisesRegex(RuntimeError, "oidc_claims_invalid"):
            self._verify(token)

    def test_rejects_duplicate_json_claim_names(self):
        now = int(time.time())
        duplicate = (
            '{"iss":"' + admin_oidc.ISSUER + '","aud":"' + admin_oidc.CLIENT_ID
            + '","aud":"attacker-client","iat":' + str(now - 30)
            + ',"exp":' + str(now + 270) + ',"nbf":' + str(now - 30)
            + ',"nonce":"expected-nonce","sub":"user-subject-identifier-12345","sid":"'
            + ("a" * 64) + '"}'
        )
        with self.assertRaisesRegex(RuntimeError, "oidc_bad_token"):
            self._verify(self._token(claims_json=duplicate))

    def test_rejects_overlong_subject(self):
        token = self._token(overrides={"sub": "s" * 256})
        with self.assertRaisesRegex(RuntimeError, "oidc_claims_invalid"):
            self._verify(token)


class ApachePrivateFileDenyTests(unittest.TestCase):
    def test_rewrite_and_filesmatch_deny_private_config_and_key_extensions(self):
        rules = (ROOT / "xrea-source" / ".htaccess").read_text(encoding="utf-8")
        for extension in ("ini", "conf", "yaml", "yml", "toml", "properties",
                          "ps1", "bat", "crt", "p12", "pfx"):
            with self.subTest(extension=extension):
                self.assertGreaterEqual(rules.count(extension), 3)


if __name__ == "__main__":
    unittest.main()
