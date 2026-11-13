import inspect
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from io import BytesIO
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xrea-source"))
sys.path.insert(0, str(ROOT / "tools" / "vendor" / "pymysql-1.2.3-py3-none-any.whl"))

import admin_api_handlers
import baas_handlers
import web_passkey_auth


def _render_admin_page(role="security-admin"):
    with mock.patch.object(baas_handlers, "_decode_admin_session", lambda token: {"sub": "ui-test", "reauthenticated_at": 0}), \
            mock.patch.object(admin_api_handlers, "_effective_admin_role", lambda claims: role):
        context = {
            "method": "GET",
            "query": "",
            "header:host": "2415.jp",
            "header:cookie": "tuti_python_migration_admin_session=test; tuti_python_migration_admin_csrf=test-csrf",
            "body_stream": BytesIO(b""),
            "content_type": "",
            "content_length": "0",
        }
        return bytes(admin_api_handlers._admin_page(context).body).decode("utf-8")


def _browser_path():
    configured = os.environ.get("TUTI_UI_BROWSER", "").strip()
    candidates = [configured] if configured else []
    candidates += [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        shutil.which("msedge") or "",
        shutil.which("google-chrome") or "",
        shutil.which("chromium") or "",
        shutil.which("chromium-browser") or "",
    ]
    for candidate in candidates:
        if candidate and pathlib.Path(candidate).is_file():
            return candidate
    return ""


class AdminCenterStaticTests(unittest.TestCase):
    def test_admin_page_contract(self):
        page = _render_admin_page()
        self.assertEqual(page.count('id="license-status"'), 1)
        self.assertEqual(page.count('id="license-state"'), 1)
        self.assertIn('id="license-query"', page)
        self.assertIn('id="license-pagination"', page)
        self.assertIn('id="license-detail"', page)
        self.assertIn('id="export-license-csv"', page)
        self.assertIn('id="cmdk"', page)
        self.assertNotIn(" ? tenant ID ", page)
        self.assertNotIn("No active tenant", page)
        self.assertIn(" · tenant ID ", page)
        identifiers = __import__("re").findall(r'id="([^"]+)"', page)
        self.assertEqual(len(identifiers), len(set(identifiers)))

    def test_permission_gated_sections_are_hidden(self):
        operator = _render_admin_page("operator")
        self.assertIn('id="tenant-management" hidden', operator)
        self.assertNotIn("view=api-invoices", operator.split("quick-nav", 1)[-1].split("</nav>", 1)[0])
        viewer = _render_admin_page("viewer")
        self.assertIn('id="tenant-management" hidden', viewer)
        self.assertIn('id="license-issuance" hidden', viewer)

    def test_invoice_page_contract(self):
        with mock.patch.object(admin_api_handlers, "_effective_admin_role", lambda claims: "security-admin"):
            context = {
                "method": "GET", "query": "view=api-invoices", "header:host": "2415.jp",
                "body_stream": BytesIO(b""), "content_type": "", "content_length": "0",
            }
            page = bytes(admin_api_handlers._invoice_admin_page(context, "test", {"sub": "ui-test"}).body).decode("utf-8")
        self.assertIn("minimumFractionDigits:0", page)
        self.assertNotIn("minimumFractionDigits:3", page)
        self.assertIn('id="billing-summary"', page)
        self.assertIn('id="invoice-pager"', page)
        self.assertIn("発行済み", page)

    def test_workbench_page_contract(self):
        with mock.patch.object(admin_api_handlers, "_effective_admin_role", lambda claims: "security-admin"),                 mock.patch.object(web_passkey_auth, "_encode_token", lambda claims: "test-token"),                 mock.patch.dict(os.environ, {"PYTHON_MIGRATION_URL_PREFIX": "/license"}):
            context = {
                "method": "GET", "query": "view=reception", "header:host": "2415.jp",
                "header:cookie": "tuti_python_migration_admin_session=test; tuti_python_migration_admin_csrf=test-csrf",
                "body_stream": BytesIO(b""), "content_type": "", "content_length": "0",
            }
            page = bytes(admin_api_handlers._api_workbench_page(context, "test", {"sub": "ui-test", "oidc_sid": "sid"}).body).decode("utf-8")
        self.assertIn('id="response-state"', page)
        self.assertIn('id="copy-result"', page)
        self.assertIn('id="request-history"', page)
        self.assertIn("JSONを保存", page)
        self.assertIn('name="api-base" content="/license"', page)
        self.assertNotIn("'/license/python-migration/api/baas/v1/service.php'", page)

    def test_ops_app_is_redirected_to_admin_center(self):
        page = (ROOT / "xrea-source" / "ops-app" / "index.html").read_text(encoding="utf-8")
        self.assertIn("admin_api.php", page)
        self.assertIn("http-equiv=\"refresh\"", page)


@unittest.skipUnless(_browser_path(), "A Chromium/Edge browser is required for the UI E2E test.")
class AdminCenterBrowserTests(unittest.TestCase):
    def setUp(self):
        self.temp_path = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.temp_path, ignore_errors=True))
        self.page_path = self.temp_path / "admin_center.html"
        self.page_path.write_text(_render_admin_page(), encoding="utf-8")
        port_socket = socket.socket()
        port_socket.bind(("127.0.0.1", 0))
        self.port = port_socket.getsockname()[1]
        port_socket.close()
        self.process = subprocess.Popen(
            [
                _browser_path(), "--headless=new", "--disable-gpu", "--no-sandbox",
                f"--remote-debugging-port={self.port}",
                f"--user-data-dir={self.temp_path / 'profile'}",
                "--window-size=1200,900",
                self.page_path.as_uri(),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self._stop_browser)
        self.target = self._wait_for_target()
        from websockets.sync.client import connect
        # websockets 15 uses connect() directly; newer releases offer legacy=True
        # to avoid the context-manager deprecation warning.
        kwargs = {"legacy": True} if "legacy" in inspect.signature(connect).parameters else {}
        self.websocket = connect(self.target["webSocketDebuggerUrl"], **kwargs)
        self.addCleanup(self.websocket.close)
        self.counter = 0
        self.errors = []
        self._send("Runtime.enable")

    def _stop_browser(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()

    def _wait_for_target(self):
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json", timeout=1) as response:
                    targets = json.loads(response.read())
                for target in targets:
                    if target.get("type") == "page" and "admin_center.html" in target.get("url", ""):
                        return target
            except (OSError, ValueError):
                pass
            time.sleep(0.1)
        self.skipTest("The browser did not expose a debugging target.")

    def _send(self, method, params=None):
        self.counter += 1
        request_id = self.counter
        self.websocket.send(json.dumps({"id": request_id, "method": method, "params": params or {}}))
        while True:
            message = json.loads(self.websocket.recv())
            if message.get("method") == "Runtime.exceptionThrown":
                details = message.get("params", {}).get("exceptionDetails", {})
                self.errors.append(details.get("text", "") + ": " + details.get("exception", {}).get("description", ""))
            if message.get("id") == request_id:
                return message

    def evaluate(self, expression):
        response = self._send("Runtime.evaluate", {"expression": expression, "awaitPromise": True, "returnByValue": True})
        if "exceptionDetails" in response.get("result", {}):
            raise AssertionError(response["result"]["exceptionDetails"])
        return response["result"]["result"].get("value")

    def wait_for(self, expression, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.evaluate(expression):
                return True
            time.sleep(0.05)
        self.fail(f"Timed out waiting for: {expression}")

    def test_admin_center_interactions(self):
        self.evaluate("""
            window.__calls = [];
            window.fetch = async (url, options) => {
                const body = options && options.body ? JSON.parse(options.body) : {};
                window.__calls.push({url: String(url), body});
                if (body.action === 'export_license_csv') {
                    return new Response('id,label' + String.fromCharCode(10) + '1,Alpha', {status: 200, headers: {'Content-Type': 'text/csv'}});
                }
                if (body.action === 'get_license') {
                    return new Response(JSON.stringify({success: true, license: {id: 42, label: 'Alpha', tenant_name: 'Tenant', active: true}, usage: {active_sessions: 1}}), {status: 200, headers: {'Content-Type': 'application/json'}});
                }
                const pageNumber = Number(body.page || 1);
                const license = {id: pageNumber * 10 + 1, label: pageNumber === 1 ? 'Alpha' : 'Beta', active: true, license_mode: 'single', max_devices: 1, active_sessions: 1, expires_at: '2027-01-01'};
                const payload = body.action === 'list_licenses'
                    ? {success: true, message: '一覧', licenses: [license], page: pageNumber, limit: 25, has_next: pageNumber < 2}
                    : {success: true, message: 'ok', tenants: []};
                return new Response(JSON.stringify(payload), {status: 200, headers: {'Content-Type': 'application/json'}});
            };
        """)
        self.wait_for("document.readyState === 'complete'")
        self.evaluate("document.getElementById('load-licenses').click()")
        self.wait_for("document.querySelectorAll('#license-results tbody tr').length === 1")
        self.assertFalse(self.evaluate("document.getElementById('license-query').hidden"))
        self.evaluate("(() => { const q = document.getElementById('license-q'); q.value = 'Alpha'; const s = document.getElementById('license-state'); s.value = 'paused'; document.getElementById('license-query-run').click(); })()")
        self.wait_for("document.getElementById('license-page-info').textContent.includes('1 ページ')")
        last_query = self.evaluate("JSON.stringify(window.__calls.filter((call) => call.body.action === 'list_licenses').at(-1).body)")
        self.assertIn('"q":"Alpha"', last_query)
        self.assertIn('"status":"paused"', last_query)
        self.evaluate("document.getElementById('license-next').click()")
        self.wait_for("document.getElementById('license-page-info').textContent.includes('2 ページ')")
        self.assertTrue(self.evaluate("document.getElementById('license-next').disabled"))

        self.evaluate("document.getElementById('cmdk-open').click()")
        self.assertFalse(self.evaluate("document.getElementById('cmdk').hidden"))
        self.evaluate("(() => { const input = document.getElementById('cmdk-input'); input.value = '監査'; input.dispatchEvent(new Event('input', {bubbles: true})); })()")
        self.assertIn("監査", self.evaluate("[...document.querySelectorAll('.cmdk-item b')].map((item) => item.textContent).join('|')"))
        self.evaluate("[...document.querySelectorAll('.cmdk-item')].at(-1).focus()")
        self._send("Input.dispatchKeyEvent", {"type": "keyDown", "key": "Tab", "code": "Tab", "windowsVirtualKeyCode": 9})
        self._send("Input.dispatchKeyEvent", {"type": "keyUp", "key": "Tab", "code": "Tab", "windowsVirtualKeyCode": 9})
        self.assertTrue(self.evaluate("document.getElementById('cmdk-input') === document.activeElement"))
        self.evaluate("document.getElementById('cmdk').dispatchEvent(new KeyboardEvent('keydown', {key: 'Escape', bubbles: true}))")
        self.assertTrue(self.evaluate("document.getElementById('cmdk').hidden"))

        self.evaluate("window.showLicenseDetail(42)")
        self.wait_for("!document.getElementById('license-detail').hidden")
        self.assertIn("ライセンスID", self.evaluate("document.getElementById('license-detail-body').textContent"))
        self.assertTrue(self.evaluate("document.getElementById('license-detail').contains(document.activeElement)"))
        self.evaluate("document.querySelector('#license-detail [data-detail-close]').click()")
        self.assertTrue(self.evaluate("document.getElementById('license-detail').hidden"))

        self.evaluate("document.querySelectorAll('.license-pick').forEach((item) => { item.checked = true; item.dispatchEvent(new Event('change', {bubbles: true})); })")
        self.assertFalse(self.evaluate("document.getElementById('export-license-csv').disabled"))
        self.evaluate("document.getElementById('export-license-csv').click()")
        self.wait_for("window.__calls.some((call) => call.body.action === 'export_license_csv')")
        self.assertFalse(any("SyntaxError" in item for item in self.errors))


if __name__ == "__main__":
    unittest.main()
