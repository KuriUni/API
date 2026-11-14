"""Tests for the administrator TUTI CRM (admin SSO + admin APIs)."""
import http.server
import json
import os
import pathlib
import shutil
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
_DATA_OWNER = "main" not in sys.modules
_TEMP_DATA = tempfile.mkdtemp(prefix="tuti-admin-test-")
os.environ["CRM_DATA"] = _TEMP_DATA
os.environ["CRM_SECRET"] = "unit-test-secret"
os.environ["CRM_PASSWORD"] = "test-password"
os.environ["CRM_SESSION_KEY"] = "test-session-key-" + "x" * 40
os.environ["CRM_SECURE_COOKIES"] = "0"
os.environ.pop("TUTI_ADMIN_SESSION", None)
sys.path.insert(0, str(ROOT / "customer-crm"))

import admin_api  # noqa: E402
import admin_sso  # noqa: E402
import main  # noqa: E402
import secrets_store  # noqa: E402

DATA = str(main.DATA_DIR)
TOKEN = "test-admin-session-token-" + "t" * 40

TENANTS = [
    {"id": 12, "name": "みなと商事", "slug": "minato", "status": "active", "environment": "production", "plan_code": "pro"},
    {"id": 13, "name": "北陸システム", "slug": "kita", "status": "active", "environment": "production", "plan_code": "basic"},
]

LICENSES = [
    {"id": 1041, "tenant_id": 12, "label": "本社 5台", "active": True, "max_devices": 5, "active_sessions": 3,
     "expires_at": "2099-03-31 00:00:00", "revoked_at": None, "created_at": "2026-04-02 09:12:00"},
    {"id": 1042, "tenant_id": 12, "label": "大阪支社", "active": False, "max_devices": 3, "active_sessions": 0,
     "expires_at": None, "revoked_at": None, "created_at": "2026-05-18 14:40:00"},
    {"id": 2051, "tenant_id": 13, "label": "全社 20台", "active": True, "max_devices": 20, "active_sessions": 18,
     "expires_at": "2020-01-01 00:00:00", "revoked_at": None, "created_at": "2025-09-10 00:00:00"},
]

INVOICES = [
    {"id": 88, "account_tenant_id": 12, "invoice_number": "INV-2026-0011", "billing_period": "2026-11",
     "customer_name": "みなと商事", "status": "issued", "total_yen": 24800, "issue_date": "2026-11-01",
     "due_date": "2026-11-30"},
    {"id": 91, "account_tenant_id": 13, "invoice_number": "INV-2026-0014", "billing_period": "2026-11",
     "customer_name": "北陸システム", "status": "paid", "total_yen": 9800, "issue_date": "2026-11-01",
     "due_date": "2026-11-30"},
]


class _Handler(http.server.BaseHTTPRequestHandler):
    requests: list = []
    unauthorized = False

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length) or b"{}")
        type(self).requests.append({"path": self.path, "payload": payload,
                                    "token": self.headers.get("X-HA-Session", "")})
        if type(self).unauthorized:
            body = {"success": False, "error": "invalid_admin_session", "message": "セッションが無効です"}
            self._send(401, body)
            return
        action = payload.get("action")
        if self.path.endswith("admin_api.php"):
            if action == "list_tenants":
                self._send(200, {"success": True, "tenants": TENANTS, "page": 1, "limit": 100, "has_next": False})
            elif action == "list_licenses":
                self._send(200, {"success": True, "licenses": LICENSES, "page": 1, "limit": 100, "has_next": False})
            else:
                self._send(400, {"success": False, "error": "unknown_action"})
            return
        if self.path.endswith("api-billing-admin.php"):
            if action in ("list", None):
                self._send(200, {"ok": True, "invoices": INVOICES, "page": 1, "limit": 100, "has_next": False,
                                 "summary": {"total": 2, "draft": 0, "issued": 1, "paid": 1, "void": 0,
                                             "paid_total_yen": "9800.000"}})
            elif action == "tenants":
                self._send(200, {"ok": True, "tenants": TENANTS})
            elif action == "get":
                self._send(200, {"ok": True, "invoice": INVOICES[0]})
            else:
                self._send(400, {"ok": False, "error": "unknown_action"})
            return
        self._send(404, {"ok": False, "error": "not_found"})

    def _send(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args):
        pass


class _Request:
    def __init__(self, csrf="csrf-token"):
        self.headers = {"x-csrf-token": csrf}
        self.cookies = {main.SESSION_COOKIE: main._sign({
            "sub": main.ADMIN_USER, "name": "管理者", "csrf": "csrf-token",
            "exp": int(main.time.time()) + 600})}
        self.client = type("Client", (), {"host": "127.0.0.1"})()


class BaseUrlTests(unittest.TestCase):
    def test_admin_base_requires_https(self):
        self.assertEqual(admin_api.base_url("https://2415.jp/"), "https://2415.jp")
        with self.assertRaises(ValueError):
            admin_api.base_url("http://2415.jp")
        with self.assertRaises(ValueError):
            admin_api.base_url("https://user:pass@2415.jp")

    def test_sso_url_matches_desktop_flow(self):
        url = admin_api.sso_url("https://2415.jp", "http://127.0.0.1:51000/callback", "a" * 64)
        self.assertIn("admin_sso_start=1", url)
        self.assertIn("return_app=desktop", url)
        self.assertIn("desktop_redirect=http%3A%2F%2F127.0.0.1%3A51000%2Fcallback", url)
        self.assertIn("desktop_state=" + "a" * 64, url)
        with self.assertRaises(ValueError):
            admin_api.sso_url("https://2415.jp", "http://evil.example/callback", "a" * 64)


class SecretStoreTests(unittest.TestCase):
    def test_token_round_trip(self):
        key = secrets_store.load_data_key(pathlib.Path(DATA))
        blob = secrets_store.encrypt(key, TOKEN)
        self.assertNotIn(TOKEN, blob)
        self.assertEqual(secrets_store.decrypt(key, blob), TOKEN)
        with self.assertRaises(secrets_store.SecretError):
            secrets_store.decrypt(b"\x00" * 32, blob)


class AdminSyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.base = f"https://2415.jp"
        main.initialize()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if _DATA_OWNER:
            shutil.rmtree(DATA, ignore_errors=True)

    def setUp(self):
        _Handler.requests = []
        _Handler.unauthorized = False
        os.environ["TUTI_ADMIN_SESSION"] = TOKEN
        os.environ["TUTI_ADMIN_BASE"] = "https://2415.jp"
        with main.closing(main.connect()) as db:
            for table in ("tenants", "licenses", "invoices", "sync_state", "admin_auth"):
                db.execute(f"DELETE FROM {table}")
            db.commit()
        original = admin_api._post
        self.addCleanup(setattr, admin_api, "_post", original)

        def fake_post(base, path, token, payload):
            request = urllib.request.Request(
                f"http://127.0.0.1:{self.server.server_port}{path}",
                data=json.dumps(payload).encode(), method="POST",
                headers={"Content-Type": "application/json", "X-HA-Session": token})
            try:
                with urllib.request.urlopen(request) as response:
                    return json.loads(response.read().decode())
            except urllib.error.HTTPError as error:
                raise admin_api._error_for_http(error, str(payload.get("action") or "")) from error
        admin_api._post = fake_post

    def tearDown(self):
        os.environ.pop("TUTI_ADMIN_SESSION", None)
        os.environ.pop("TUTI_ADMIN_BASE", None)

    def test_sync_uses_admin_session_and_billing_api(self):
        result = main.sync(_Request())
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["counts"], {"tenants": 2, "licenses": 3, "invoices": 2})
        paths = [call["path"] for call in _Handler.requests]
        self.assertEqual(paths.count("/license/admin_api.php"), 2)
        self.assertEqual(paths.count("/license/ha/api-billing-admin.php"), 1)
        self.assertTrue(all(call["token"] == TOKEN for call in _Handler.requests))
        actions = [call["payload"].get("action") for call in _Handler.requests]
        self.assertIn("list_tenants", actions)
        self.assertIn("list_licenses", actions)
        self.assertIn("list", actions)

    def test_license_states_are_derived(self):
        main.sync(_Request())
        with main.closing(main.connect()) as db:
            states = {row[0]: row[1] for row in db.execute("SELECT license_id, state FROM licenses").fetchall()}
        self.assertEqual(states[1041], "active")
        self.assertEqual(states[1042], "paused")
        self.assertEqual(states[2051], "expired")

    def test_dashboard_and_tenant_rollups(self):
        main.sync(_Request())
        data = main.dashboard(_Request())
        self.assertEqual(data["kpis"]["tenants"], 2)
        self.assertEqual(data["kpis"]["licenses"], 3)
        self.assertEqual(data["kpis"]["active_licenses"], 1)
        self.assertEqual(data["kpis"]["expired_licenses"], 1)
        self.assertEqual(data["kpis"]["unpaid_count"], 1)
        self.assertEqual(data["kpis"]["unpaid_amount"], 24800)
        detail = main.tenant_detail(12, _Request())
        self.assertEqual(detail["tenant"]["name"], "みなと商事")
        self.assertEqual(detail["summary"]["licenses"], 2)
        self.assertEqual(len(detail["invoices"]), 1)

    def test_filters_and_pagination(self):
        main.sync(_Request())
        self.assertEqual(len(main.licenses(_Request())["items"]), 3)
        self.assertEqual([row["license_id"] for row in main.licenses(_Request(), state="paused")["items"]], [1042])
        self.assertEqual(len(main.licenses(_Request(), tenant_id=13)["items"]), 1)
        self.assertEqual([row["license_id"] for row in main.licenses(_Request(), q="大阪")["items"]], [1042])
        issued = main.invoices(_Request(), status="issued")["items"]
        self.assertEqual([row["invoice_number"] for row in issued], ["INV-2026-0011"])
        first = main.invoices(_Request(), limit=1)["items"]
        self.assertEqual(len(first), 1)
        self.assertEqual(main.invoices(_Request(), limit=1)["total"], 2)

    def test_expired_admin_session_is_reported(self):
        _Handler.unauthorized = True
        result = main.sync(_Request())
        self.assertFalse(result["ok"])
        self.assertTrue(result["expired"])
        self.assertIn("tenants", result["errors"])
        with main.closing(main.connect()) as db:
            state = main._sync_state(db)
        self.assertTrue(state["tenants"]["error"])

    def test_write_endpoints_require_csrf(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.sync(_Request(csrf="wrong"))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_session_is_required(self):
        class Anonymous:
            headers: dict = {}
            cookies: dict = {}
            client = type("Client", (), {"host": "127.0.0.1"})()
        for endpoint in (main.dashboard, main.tenants, main.connection):
            with self.assertRaises(main.HTTPException) as ctx:
                endpoint(Anonymous())
            self.assertEqual(ctx.exception.status_code, 401)

    def test_connection_reports_env_session(self):
        data = main.connection(_Request())
        self.assertTrue(data["connected"])
        self.assertEqual(data["source"], "environment")

    def test_sync_requires_connection(self):
        os.environ.pop("TUTI_ADMIN_SESSION")
        with main.closing(main.connect()) as db:
            db.execute("DELETE FROM admin_auth")
            db.commit()
        with self.assertRaises(main.HTTPException) as ctx:
            main.sync(_Request())
        self.assertEqual(ctx.exception.status_code, 409)

    def test_exports_are_csv(self):
        main.sync(_Request())
        self.assertIn("text/csv", main.export_licenses(_Request()).media_type)
        self.assertIn("text/csv", main.export_invoices(_Request()).media_type)


class SsoLoopbackTests(unittest.TestCase):
    def test_loopback_page_and_state_validation(self):
        flow = admin_sso.start("https://2415.jp")
        self.addCleanup(admin_sso.cancel, flow["state"])
        redirect = urllib.parse.parse_qs(urllib.parse.urlparse(flow["url"]).query)["desktop_redirect"][0]
        port = urllib.parse.urlparse(redirect).port
        self.assertTrue(49152 <= port <= 65535)
        self.assertEqual(redirect, f"http://127.0.0.1:{port}/callback")
        with urllib.request.urlopen(redirect, timeout=5) as response:
            body = response.read().decode()
        self.assertIn("SSO応答をアプリへ返しています", body)
        self.assertIn("Content-Security-Policy", str(response.headers))
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/complete",
            data=json.dumps({"session": "x" * 60, "state": "b" * 64}).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(ctx.exception.code, 403)
        self.assertEqual(admin_sso.poll(flow["state"])["status"], "error")

    def test_complete_flow_returns_token_once(self):
        flow = admin_sso.start("https://2415.jp")
        redirect = urllib.parse.parse_qs(urllib.parse.urlparse(flow["url"]).query)["desktop_redirect"][0]
        port = urllib.parse.urlparse(redirect).port
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/complete",
            data=json.dumps({"session": "s" * 80, "state": flow["state"]}).encode(),
            method="POST",
            headers={"Content-Type": "application/json", "Origin": f"http://127.0.0.1:{port}"})
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
        result = admin_sso.poll(flow["state"])
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["token"], "s" * 80)
        self.assertEqual(admin_sso.poll(flow["state"])["status"], "unknown")


if __name__ == "__main__":
    unittest.main()
