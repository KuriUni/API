"""Tests for the TUTI-specialised CRM (customers = TUTI tenants)."""
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
_TEMP_DATA = tempfile.mkdtemp(prefix="tuti-crm-test-")
os.environ["CRM_DATA"] = _TEMP_DATA
os.environ["CRM_SECRET"] = "unit-test-secret"
os.environ["CRM_PASSWORD"] = "test-password"
os.environ["CRM_SESSION_KEY"] = "test-session-key-" + "x" * 40
os.environ["CRM_SECURE_COOKIES"] = "0"
sys.path.insert(0, str(ROOT / "customer-crm"))

import main  # noqa: E402
import secrets_store  # noqa: E402
import tuti_api  # noqa: E402

DATA = str(main.DATA_DIR)
KEY = "baas_sandbox_" + "k" * 40

LICENSES = [
    {"id": 11, "product_id": 3, "product_code": "TUTI-DESK", "environment": "production", "label": "本社 5台",
     "active": 1, "max_devices": 5, "expires_at": "2027-03-31", "created_at": "2026-04-02"},
    {"id": 12, "product_id": 4, "product_code": "TUTI-MOBILE", "environment": "sandbox", "label": "評価用",
     "active": 0, "max_devices": 1, "expires_at": None, "created_at": "2026-05-01"},
]


class _Handler(http.server.BaseHTTPRequestHandler):
    requests: list = []
    failures: dict = {}
    payloads: dict = {}

    def do_GET(self):  # noqa: N802
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        service = (query.get("service") or [""])[0]
        type(self).requests.append({"service": service, "key": self.headers.get("X-Tenant-API-Key", "")})
        if service in type(self).failures:
            status, body = type(self).failures[service]
            raw = json.dumps(body).encode()
            self.send_response(status)
        else:
            raw = json.dumps(type(self).payloads.get(service, {"ok": True})).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


def default_payloads():
    return {
        "service.status": {"ok": True, "tenant": {"slug": "sample"}, "usage": {"products": 2, "licenses": 2, "active_licenses": 1}},
        "products.list": {"ok": True, "products": [{"id": 3, "code": "TUTI-DESK", "name": "Desktop"}]},
        "licenses.list": {"ok": True, "licenses": LICENSES},
        "usage.summary": {"ok": True, "period": "2026-11", "total_requests": 100, "billable_requests": 90,
                          "total_charge_yen_equivalent": "1234.500",
                          "details": [{"api": "licenses.list", "requests": 10, "unit_credit": "0.001", "charge_credit": "0.010"}]},
        "billing.invoices": {"ok": True, "invoices": [
            {"id": 5, "invoice_number": "INV-1", "billing_period": "2026-11", "total_yen": 24800,
             "status": "issued", "issue_date": "2026-11-01", "due_date": "2026-11-30"}]},
        "audit.list": {"ok": True, "events": [
            {"id": 9, "operation": "licenses.list", "status_code": 200, "request_id": "r-9", "used_at": "2026-11-14 08:00:00"}]},
    }


class _Request:
    def __init__(self, csrf="csrf-token"):
        self.headers = {"x-csrf-token": csrf}
        self.cookies = {main.SESSION_COOKIE: main._sign({
            "sub": main.ADMIN_USER, "name": "管理者", "csrf": "csrf-token",
            "exp": int(main.time.time()) + 600})}
        self.client = type("Client", (), {"host": "127.0.0.1"})()


class SecretStoreTests(unittest.TestCase):
    def test_round_trip_and_wrong_key(self):
        key = secrets_store.load_data_key(pathlib.Path(DATA))
        blob = secrets_store.encrypt(key, KEY)
        self.assertNotIn(KEY, blob)
        self.assertEqual(secrets_store.decrypt(key, blob), KEY)
        with self.assertRaises(secrets_store.SecretError):
            secrets_store.decrypt(b"\x00" * 32, blob)

    def test_key_hint_is_partial(self):
        hint = secrets_store.key_hint(KEY)
        self.assertTrue(hint.startswith("baas_sandb"))
        self.assertTrue(hint.endswith(KEY[-4:]))
        self.assertNotIn(KEY, hint)


class BaseUrlTests(unittest.TestCase):
    def test_https_is_default(self):
        self.assertEqual(tuti_api.normalize_base_url(""), tuti_api.DEFAULT_BASE)
        self.assertEqual(tuti_api.normalize_base_url("https://example.jp/"), "https://example.jp")

    def test_loopback_http_is_allowed(self):
        self.assertEqual(tuti_api.normalize_base_url("http://127.0.0.1:8799"), "http://127.0.0.1:8799")

    def test_remote_http_and_credentials_are_rejected(self):
        with self.assertRaises(ValueError):
            tuti_api.normalize_base_url("http://example.jp")
        with self.assertRaises(ValueError):
            tuti_api.normalize_base_url("https://user:pass@example.jp")
        with self.assertRaises(ValueError):
            tuti_api.normalize_base_url("ftp://example.jp")


class CrmApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        main.initialize()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if _DATA_OWNER:
            shutil.rmtree(DATA, ignore_errors=True)

    def setUp(self):
        _Handler.requests = []
        _Handler.failures = {}
        _Handler.payloads = default_payloads()
        os.environ["CRM_SECRET"] = "unit-test-secret"
        with main.closing(main.connect()) as db:
            db.execute("DELETE FROM customers")
            db.execute("DELETE FROM customer_cache")
            db.commit()

    def _create(self, name="サンプル商事", **overrides):
        payload = main.CustomerIn(name=name, base_url=self.base, api_key=KEY, **overrides)
        return main.create_customer(payload, _Request())

    def test_create_encrypts_key_and_hides_it(self):
        created = self._create()
        self.assertNotIn("api_key", created)
        self.assertNotIn(KEY, json.dumps(created))
        self.assertTrue(created["key_hint"].endswith(KEY[-4:]))
        with main.closing(main.connect()) as db:
            stored = db.execute("SELECT api_key_enc FROM customers WHERE id=?", (created["id"],)).fetchone()[0]
        self.assertTrue(stored.startswith("v1:"))
        self.assertNotIn(KEY, stored)
        self.assertEqual(secrets_store.decrypt(main.data_key(), stored), KEY)

    def test_duplicate_name_and_bad_key_are_rejected(self):
        self._create()
        with self.assertRaises(main.HTTPException) as ctx:
            self._create()
        self.assertEqual(ctx.exception.status_code, 400)
        with self.assertRaises(ValueError):
            main.CustomerIn(name="x", api_key="not-a-key")

    def test_sync_fills_cache_and_dashboard(self):
        created = self._create()
        result = main.sync_customer(created["id"], _Request())
        self.assertTrue(result["ok"], result)
        services = sorted(call["service"] for call in _Handler.requests)
        self.assertEqual(services, sorted([
            "service.status", "products.list", "licenses.list",
            "usage.summary", "billing.invoices", "audit.list"]))
        self.assertTrue(all(call["key"] == KEY for call in _Handler.requests))

        dashboard = main.dashboard(_Request())
        self.assertEqual(dashboard["kpis"]["customers"], 1)
        self.assertEqual(dashboard["kpis"]["licenses"], 2)
        self.assertEqual(dashboard["kpis"]["active_licenses"], 1)
        self.assertEqual(dashboard["kpis"]["unpaid_count"], 1)
        self.assertEqual(dashboard["kpis"]["month_charge"], 1234.5)
        self.assertEqual(dashboard["events"][0]["operation"], "licenses.list")
        self.assertEqual(dashboard["events"][0]["customer_name"], "サンプル商事")

        detail = main.get_customer(created["id"], _Request())
        self.assertEqual(detail["usage"]["total_requests"], 100)
        self.assertEqual(len(detail["invoices"]), 1)

    def test_sync_keeps_previous_data_on_failure(self):
        created = self._create()
        main.sync_customer(created["id"], _Request())
        _Handler.failures = {"licenses.list": (401, {"ok": False, "error": "invalid_api_key"})}
        result = main.sync_customer(created["id"], _Request())
        self.assertFalse(result["ok"])
        self.assertEqual(result["results"]["licenses"]["code"], "invalid_api_key")
        detail = main.get_customer(created["id"], _Request())
        self.assertEqual(len(detail["licenses"]), 2)
        self.assertIn("APIキー", detail["scopes"]["licenses"]["error"])
        self.assertLessEqual(len(detail["scopes"]), len(tuti_api.SCOPES))

    def test_license_and_invoice_filters(self):
        created = self._create()
        main.sync_customer(created["id"], _Request())
        all_rows = main.licenses(_Request())["items"]
        self.assertEqual(len(all_rows), 2)
        sandbox = main.licenses(_Request(), environment="sandbox")["items"]
        self.assertEqual([row["id"] for row in sandbox], [12])
        active = main.licenses(_Request(), status="active")["items"]
        self.assertEqual([row["id"] for row in active], [11])
        search = main.licenses(_Request(), q="mobile")["items"]
        self.assertEqual([row["id"] for row in search], [12])
        invoices = main.invoices(_Request(), period="2026-11")["items"]
        self.assertEqual(len(invoices), 1)
        self.assertEqual(invoices[0]["customer_name"], "サンプル商事")
        self.assertEqual(main.invoices(_Request(), period="2026-10")["items"], [])

    def test_update_keeps_key_when_blank(self):
        created = self._create()
        updated = main.update_customer(created["id"], main.CustomerIn(
            name="改名商事", slug="renamed", base_url=self.base, api_key=""), _Request())
        self.assertEqual(updated["name"], "改名商事")
        self.assertEqual(updated["slug"], "renamed")
        with main.closing(main.connect()) as db:
            stored = db.execute("SELECT api_key_enc FROM customers WHERE id=?", (created["id"],)).fetchone()[0]
        self.assertEqual(secrets_store.decrypt(main.data_key(), stored), KEY)

    def test_delete_removes_customer_and_cache(self):
        created = self._create()
        main.sync_customer(created["id"], _Request())
        main.delete_customer(created["id"], _Request())
        with main.closing(main.connect()) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM customers").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM customer_cache").fetchone()[0], 0)

    def test_write_endpoints_require_csrf(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.create_customer(main.CustomerIn(name="x", base_url=self.base, api_key=KEY), _Request(csrf="bad"))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_session_is_required(self):
        class Anonymous:
            headers: dict = {}
            cookies: dict = {}
            client = type("Client", (), {"host": "127.0.0.1"})()
        with self.assertRaises(main.HTTPException) as ctx:
            main.dashboard(Anonymous())
        self.assertEqual(ctx.exception.status_code, 401)

    def test_csv_exports(self):
        created = self._create()
        main.sync_customer(created["id"], _Request())
        license_csv = main.export_licenses(_Request())
        self.assertIn("text/csv", license_csv.media_type)
        invoice_csv = main.export_invoices(_Request())
        self.assertIn("text/csv", invoice_csv.media_type)

    def test_sync_all_reports_each_customer(self):
        self._create("A社")
        payload = main.CustomerIn(name="B社", base_url=self.base, api_key="baas_sandbox_" + "z" * 40)
        main.create_customer(payload, _Request())
        result = main.sync_all(_Request())
        self.assertEqual(result["total"], 2)
        self.assertEqual(result["synced"], 2)
        self.assertTrue(result["ok"])


if __name__ == "__main__":
    unittest.main()
