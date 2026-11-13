import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xrea-source"))

import mobile_admin_auth


class MobileAdminOriginCheckTests(unittest.TestCase):
    def test_accepts_matching_origin_and_referer(self):
        self.assertFalse(mobile_admin_auth._origin_header_check(
            {"header:host": "2415.jp", "header:origin": "https://2415.jp"}
        )[0])
        self.assertFalse(mobile_admin_auth._origin_header_check(
            {"header:host": "2415.jp", "header:origin": "https://2415.jp:443"}
        )[0])
        self.assertFalse(mobile_admin_auth._origin_header_check(
            {"header:host": "2415.jp", "header:referer": "https://2415.jp/license/mobile-manager/"}
        )[0])

    def test_accepts_absent_browser_header_when_csrf_token_matches(self):
        self.assertFalse(mobile_admin_auth._origin_header_check({"header:host": "2415.jp"})[0])

    def test_rejects_cross_origin_and_plain_http(self):
        self.assertTrue(mobile_admin_auth._origin_header_check(
            {"header:host": "2415.jp", "header:origin": "https://backup.2415.jp"}
        )[0])
        self.assertTrue(mobile_admin_auth._origin_header_check(
            {"header:host": "2415.jp", "header:origin": "http://2415.jp"}
        )[0])
        self.assertTrue(mobile_admin_auth._origin_header_check(
            {"header:host": "2415.jp", "header:referer": "https://evil.example/"}
        )[0])

    def test_origin_takes_precedence_over_referer(self):
        self.assertTrue(mobile_admin_auth._origin_header_check(
            {"header:host": "2415.jp", "header:origin": "https://evil.example/", "header:referer": "https://2415.jp/"}
        )[0])
