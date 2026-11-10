import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xrea-source"))

import baas_handlers
import admin_api_handlers


class WebhookDestinationValidationTests(unittest.TestCase):
    def test_accepts_public_https_dns_and_ipv4_destinations(self):
        self.assertTrue(baas_handlers._webhook_url_allowed("https://example.com/hooks/tuti"))
        self.assertTrue(baas_handlers._webhook_url_allowed("https://api.line.me/v2/bot/message/push?to=U" + "a" * 32))
        self.assertTrue(baas_handlers._webhook_url_allowed("https://8.8.8.8/hook"))
        self.assertTrue(baas_handlers._webhook_url_allowed("https://example.com:443/hook"))

    def test_rejects_non_https_and_nonstandard_ports(self):
        for url in (
            "http://example.com/hook",
            "ftp://example.com/hook",
            "https://example.com:444/hook",
        ):
            with self.subTest(url=url):
                self.assertFalse(baas_handlers._webhook_url_allowed(url))

    def test_rejects_credentials_fragments_and_control_characters(self):
        for url in (
            "https://user:password@example.com/hook",
            "https://example.com/hook#fragment",
            "https://example.com/a b",
            "https://example.com/\r\nHost: internal",
            "https://example.com\\@internal.example/hook",
        ):
            with self.subTest(url=url):
                self.assertFalse(baas_handlers._webhook_url_allowed(url))

    def test_rejects_private_literal_addresses_and_ipv6(self):
        for url in (
            "https://127.0.0.1/hook",
            "https://10.0.0.1/hook",
            "https://172.16.0.1/hook",
            "https://192.168.1.1/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/hook",
            "https://[2606:4700:4700::1111]/hook",
        ):
            with self.subTest(url=url):
                self.assertFalse(baas_handlers._webhook_url_allowed(url))

    def test_rejects_invalid_or_local_hostnames(self):
        for url in (
            "https://localhost/hook",
            "https://service.local/hook",
            "https://service.internal/hook",
            "https://service.example/hook",
            "https://singlelabel/hook",
            "https://a..example.com/hook",
            "https://-bad.example.com/hook",
            "https://bad-.example.com/hook",
            "https://example.com./hook",
            "https://例え.テスト/hook",
        ):
            with self.subTest(url=url):
                self.assertFalse(baas_handlers._webhook_url_allowed(url))

    def test_rejects_oversized_urls(self):
        self.assertFalse(baas_handlers._webhook_url_allowed("https://example.com/" + "a" * 2048))


class AdminCsrfOriginTests(unittest.TestCase):
    def _context(self, host, origin):
        return {
            "method": "POST",
            "header:host": host,
            "header:origin": origin,
            "header:cookie": (
                admin_api_handlers.SESSION_COOKIE + "=session-token; "
                + admin_api_handlers.CSRF_COOKIE + "=csrf-token"
            ),
            "header:x-csrf-token": "csrf-token",
        }

    def test_cookie_post_rejects_unconfigured_host_and_origin(self):
        with mock.patch.object(baas_handlers, "_decode_admin_session",
                               return_value={"scope": ["ha:operate"]}), \
             mock.patch("ha_handlers._ha_authorized_scope", return_value=True):
            claims, status, _message = admin_api_handlers._authorize(
                self._context("attacker.example", "https://attacker.example"), {}, "ha:operate"
            )
        self.assertIsNone(claims)
        self.assertEqual(status, "403 Forbidden")

    def test_cookie_post_accepts_canonical_origin_and_host_pair(self):
        with mock.patch.object(baas_handlers, "_decode_admin_session",
                               return_value={"scope": ["ha:operate"]}), \
             mock.patch("ha_handlers._ha_authorized_scope", return_value=True):
            claims, error, _message = admin_api_handlers._authorize(
                self._context("2415.jp", "https://2415.jp"), {}, "ha:operate"
            )
        self.assertEqual(claims, {"scope": ["ha:operate"]})
        self.assertIsNone(error)


class ApacheDatabaseFileProtectionTests(unittest.TestCase):
    def test_database_files_and_sqlite_sidecars_are_denied(self):
        rules = (ROOT / "xrea-source" / ".htaccess").read_text(encoding="utf-8")
        self.assertGreaterEqual(rules.count("(?:sqlite3?|db)(?:-(?:wal|shm))?"), 3)


if __name__ == "__main__":
    unittest.main()
