"""Tests for the TUTI BaaS API client and the CRM sync endpoints."""
import http.server
import json
import os
import pathlib
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
_DATA_OWNER = "main" not in sys.modules
if _DATA_OWNER:
    _TEMP_DATA = tempfile.mkdtemp(prefix="crm-tuti-test-")
    os.environ["CRM_DATA"] = _TEMP_DATA
os.environ["CRM_PASSWORD"] = "test-password"
os.environ["CRM_SESSION_KEY"] = "test-session-key-" + "x" * 40
os.environ["CRM_SECURE_COOKIES"] = "0"
sys.path.insert(0, str(ROOT / "customer-crm"))

import main  # noqa: E402
import tuti_api  # noqa: E402

DATA = str(main.DATA_DIR)

API_KEY = "baas_sandbox_" + "k" * 40


class _Handler(http.server.BaseHTTPRequestHandler):
    requests: list = []
    response: dict = {}
    status = 200

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)
        type(self).requests.append({
            "path": parsed.path,
            "query": query,
            "key": self.headers.get("X-Tenant-API-Key", ""),
            "environment": self.headers.get("X-BaaS-Environment", ""),
        })
        body = json.dumps(type(self).response).encode("utf-8")
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence test output
        pass


class TutiApiClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if _DATA_OWNER:
            shutil.rmtree(DATA, ignore_errors=True)

    def setUp(self):
        _Handler.requests = []
        _Handler.response = {"ok": True, "licenses": [{"id": 7, "active": True}]}
        _Handler.status = 200
        os.environ["TUTI_API_BASE"] = self.base
        os.environ["TUTI_API_KEY"] = API_KEY
        os.environ.pop("TUTI_API_ENV", None)

    def tearDown(self):
        os.environ.pop("TUTI_API_BASE", None)
        os.environ.pop("TUTI_API_KEY", None)
        os.environ.pop("TUTI_API_ENV", None)

    def test_request_uses_service_endpoint_and_tenant_key(self):
        payload = tuti_api.licenses(limit=25, search="demo")
        self.assertTrue(payload["ok"])
        call = _Handler.requests[-1]
        self.assertEqual(call["path"], "/api/baas/v1/service.php")
        self.assertEqual(call["query"]["service"], ["licenses.list"])
        self.assertEqual(call["query"]["limit"], ["25"])
        self.assertEqual(call["query"]["search"], ["demo"])
        self.assertEqual(call["key"], API_KEY)
        self.assertEqual(call["environment"], "")

    def test_environment_header_is_sent_when_configured(self):
        os.environ["TUTI_API_ENV"] = "sandbox"
        tuti_api.status()
        self.assertEqual(_Handler.requests[-1]["environment"], "sandbox")

    def test_limit_is_clamped(self):
        tuti_api.licenses(limit=10_000)
        self.assertEqual(_Handler.requests[-1]["query"]["limit"], ["200"])

    def test_missing_key_is_not_configured(self):
        os.environ.pop("TUTI_API_KEY")
        self.assertFalse(tuti_api.configured())
        with self.assertRaises(tuti_api.TutiApiError) as ctx:
            tuti_api.status()
        self.assertEqual(ctx.exception.code, "not_configured")

    def test_http_error_is_translated(self):
        _Handler.status = 401
        _Handler.response = {"ok": False, "error": "invalid_api_key"}
        with self.assertRaises(tuti_api.TutiApiError) as ctx:
            tuti_api.licenses()
        self.assertEqual(ctx.exception.status, 401)
        self.assertIn("APIキー", str(ctx.exception))

    def test_api_level_error_is_raised(self):
        _Handler.response = {"ok": False, "error": "invalid_period", "message": "period is invalid"}
        with self.assertRaises(tuti_api.TutiApiError) as ctx:
            tuti_api.usage("bad-period")
        self.assertEqual(ctx.exception.code, "invalid_period")
        self.assertIn("period is invalid", str(ctx.exception))

    def test_describe_hides_the_key(self):
        summary = tuti_api.describe()
        self.assertTrue(summary["configured"])
        self.assertNotIn(API_KEY, json.dumps(summary))
        self.assertTrue(summary["key_hint"].startswith("baas_sandbox_"))
        self.assertTrue(summary["key_hint"].endswith("…"))


class _Request:
    def __init__(self, csrf="csrf-token"):
        self.cookies = {main.SESSION_COOKIE: "unused", "token": "unused"}
        self.headers = {"x-csrf-token": csrf}
        self.client = type("Client", (), {"host": "127.0.0.1"})()


class TutiSyncEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        main.initialize()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if _DATA_OWNER:
            shutil.rmtree(DATA, ignore_errors=True)

    def setUp(self):
        _Handler.requests = []
        os.environ["TUTI_API_BASE"] = f"http://127.0.0.1:{self.server.server_port}"
        os.environ["TUTI_API_KEY"] = API_KEY
        with main.closing(main.connect()) as db:
            db.execute("DELETE FROM tuti_cache")
            db.commit()

    def tearDown(self):
        os.environ.pop("TUTI_API_BASE", None)
        os.environ.pop("TUTI_API_KEY", None)

    def test_sync_caches_every_scope(self):
        _Handler.response = {"ok": True, "usage": {"products": 2, "licenses": 3, "active_licenses": 2}}
        request = _Request()
        session = main._sign({"sub": main.ADMIN_USER, "name": "管理者", "csrf": request.headers["x-csrf-token"],
                              "exp": int(main.time.time()) + 600})
        request.cookies = {main.SESSION_COOKIE: session}
        result = main.tuti_sync(request)
        self.assertTrue(result["ok"], result)
        self.assertEqual(sorted(result["results"]), sorted(main.TUTI_SCREENS))
        self.assertTrue(all(item["ok"] for item in result["results"].values()))
        services = [call["query"]["service"][0] for call in _Handler.requests]
        self.assertEqual(sorted(services), sorted([
            "service.status", "products.list", "licenses.list",
            "usage.summary", "billing.invoices", "audit.list",
        ]))
        overview = main.tuti_overview(request)
        self.assertEqual(overview["scopes"]["status"]["payload"]["usage"]["licenses"], 3)
        self.assertTrue(overview["last_sync"])

    def test_sync_records_partial_failures_without_dropping_cache(self):
        request = _Request()
        session = main._sign({"sub": main.ADMIN_USER, "name": "管理者", "csrf": request.headers["x-csrf-token"],
                              "exp": int(main.time.time()) + 600})
        request.cookies = {main.SESSION_COOKIE: session}
        _Handler.response = {"ok": True, "licenses": [{"id": 1, "active": True}]}
        first = main.tuti_sync(request)
        self.assertTrue(first["ok"])
        _Handler.status = 401
        _Handler.response = {"ok": False, "error": "invalid_api_key"}
        second = main.tuti_sync(request)
        self.assertFalse(second["ok"])
        self.assertEqual(second["results"]["licenses"]["code"], "invalid_api_key")
        cached = main.tuti_overview(request)["scopes"]["licenses"]["payload"]
        self.assertEqual(cached["licenses"][0]["id"], 1)

    def test_sync_requires_csrf(self):
        request = _Request(csrf="wrong")
        session = main._sign({"sub": main.ADMIN_USER, "name": "管理者", "csrf": "csrf-token",
                              "exp": int(main.time.time()) + 600})
        request.cookies = {main.SESSION_COOKIE: session}
        with self.assertRaises(main.HTTPException) as ctx:
            main.tuti_sync(request)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_config_reports_unconfigured(self):
        os.environ.pop("TUTI_API_KEY")
        request = _Request()
        session = main._sign({"sub": main.ADMIN_USER, "name": "管理者", "csrf": request.headers["x-csrf-token"],
                              "exp": int(main.time.time()) + 600})
        request.cookies = {main.SESSION_COOKIE: session}
        config = main.tuti_config(request)
        self.assertFalse(config["configured"])
        os.environ["TUTI_API_KEY"] = API_KEY


if __name__ == "__main__":
    unittest.main()
