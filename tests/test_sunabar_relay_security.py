import pathlib
import sys
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xrea-source"))

import sunabar_api


class _UpstreamResponse:
    code = 200

    def __init__(self):
        self.headers = {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Allow-Headers": "Authorization, X-Sunabar-API-Key",
        }

    def read(self, size=-1):
        return b'{"ok":true}'

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _Opener:
    def open(self, request, timeout=None):
        return _UpstreamResponse()


class SunabarCorsTests(unittest.TestCase):
    def test_options_does_not_grant_cross_origin_access(self):
        with mock.patch.object(sunabar_api, "make_response", return_value=object()) as response:
            sunabar_api._relay(
                {"method": "OPTIONS", "header:origin": "https://attacker.example"},
                "products",
            )
        status, headers = response.call_args.args[1:]
        self.assertEqual(status, 204)
        self.assertFalse(any(name.lower().startswith("access-control-allow-")
                             for name, _ in headers))

    def test_upstream_cors_headers_are_not_forwarded(self):
        with mock.patch.object(sunabar_api.urllib.request, "build_opener",
                               return_value=_Opener()), \
             mock.patch.object(sunabar_api, "make_response", return_value=object()) as response:
            sunabar_api._relay({"method": "GET"}, "products")
        headers = response.call_args.args[2]
        self.assertFalse(any(name.lower().startswith("access-control-allow-")
                             for name, _ in headers))


if __name__ == "__main__":
    unittest.main()
