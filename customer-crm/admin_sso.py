"""Administrator SSO login through a loopback callback.

The admin SSO flow only returns a session token to a loopback URL
(``return_app=desktop``). This module mirrors what the desktop operations app
does:

1. bind ``127.0.0.1:<port>`` (ports 49152-65535 are the only ones the API accepts)
2. open ``admin_api.php?admin_sso_start=1&return_app=desktop&desktop_redirect=...``
3. the browser lands on the loopback page, whose script posts the token from the
   URL fragment to this server
4. the token is validated against the expected state and handed back once

Nothing is written to disk here; the caller stores the token encrypted.
"""

from __future__ import annotations

import html
import json
import re
import secrets
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import admin_api

FLOW_TTL = 300
PORT_RANGE = (49152, 65535)
MAX_BODY = 16_384

_flows: dict[str, "Flow"] = {}
_lock = threading.Lock()


class Flow:
    def __init__(self, base: str):
        self.base = base
        self.state = secrets.token_hex(32)
        self.created = time.time()
        self.token = ""
        self.error = ""
        self.done = False
        self.server: ThreadingHTTPServer | None = None
        self.port = 0

    @property
    def url(self) -> str:
        return admin_api.sso_url(self.base, f"http://127.0.0.1:{self.port}/callback", self.state)

    @property
    def status(self) -> str:
        if self.done and self.token:
            return "complete"
        if self.done and self.error:
            return "error"
        if time.time() - self.created > FLOW_TTL:
            return "expired"
        return "pending"

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


def _page(nonce: str) -> bytes:
    return (
        "<!doctype html><meta charset=utf-8><meta name=referrer content=no-referrer>"
        "<title>TUTI CRM ログイン</title>"
        "<style>body{font:15px system-ui;margin:60px auto;max-width:520px;padding:0 20px;color:#1b2540}"
        "p{line-height:1.7}</style>"
        "<h1>SSO応答をアプリへ返しています…</h1><p id=s>このタブは自動で閉じてかまいません。</p>"
        f"<script nonce='{nonce}'>"
        "const p=new URLSearchParams(location.hash.slice(1)),session=p.get('session'),state=p.get('state');"
        "history.replaceState(null,'','/callback');"
        "if(!session||!state){document.getElementById('s').textContent='認証応答を取得できません。アプリからやり直してください。';}"
        "else fetch('/complete',{method:'POST',headers:{'Content-Type':'application/json'},"
        "body:JSON.stringify({session,state})}).then(r=>{document.getElementById('s').textContent="
        "r.ok?'ログインしました。アプリに戻ってください。':'認証応答を確認できません。';})"
        ".catch(()=>{document.getElementById('s').textContent='アプリへの接続に失敗しました。';});"
        "</script>"
    ).encode("utf-8")


def _handler(flow: Flow):
    class Handler(BaseHTTPRequestHandler):
        server_version = "TutiCrmSso/1.0"

        def log_message(self, *args):
            pass

        def _send(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8", extra: list | None = None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            for name, value in extra or []:
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802
            if self.headers.get("Host", "") != f"127.0.0.1:{flow.port}":
                return self._send(403, b"Forbidden")
            if self.path.split("?")[0] != "/callback":
                return self._send(404, b"Not Found")
            nonce = secrets.token_urlsafe(18)
            csp = (f"default-src 'none'; script-src 'nonce-{nonce}'; connect-src 'self'; "
                   "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            return self._send(200, _page(nonce), "text/html; charset=utf-8",
                              [("Content-Security-Policy", csp), ("Referrer-Policy", "no-referrer")])

        def do_POST(self):  # noqa: N802
            if self.headers.get("Host", "") != f"127.0.0.1:{flow.port}":
                return self._send(403, b"Forbidden")
            if self.path != "/complete":
                return self._send(404, b"Not Found")
            if self.headers.get("Origin", "") != f"http://127.0.0.1:{flow.port}":
                return self._send(403, b"Forbidden")
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                return self._send(413, b"Too Large")
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                return self._send(400, b"Bad Request")
            token = str(data.get("session") or "")
            state = str(data.get("state") or "")
            if not secrets.compare_digest(state, flow.state):
                flow.done = True
                flow.error = "state_mismatch"
                return self._send(403, b"Forbidden")
            if not 40 <= len(token) <= 8192 or not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", token):
                flow.done = True
                flow.error = "invalid_session"
                return self._send(400, b"Bad Request")
            flow.token = token
            flow.done = True
            flow.stop()
            return self._send(200, b'{"ok":true}', "application/json")

    return Handler


def start(base: str = "") -> dict:
    """Begin a flow and return the URL the operator must open."""
    base = admin_api.base_url(base)
    flow = Flow(base)
    last_error = None
    for _ in range(40):
        port = secrets.randbelow(PORT_RANGE[1] - PORT_RANGE[0]) + PORT_RANGE[0]
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), _handler(flow))
        except OSError as error:
            last_error = error
            continue
        flow.server = server
        flow.port = port
        threading.Thread(target=server.serve_forever, daemon=True).start()
        break
    else:
        raise RuntimeError(f"ローカル認証ポートを確保できません: {last_error}")
    _housekeeping()
    with _lock:
        _flows[flow.state] = flow
    return {"state": flow.state, "url": flow.url, "expires_in": FLOW_TTL}


def poll(state: str) -> dict:
    with _lock:
        flow = _flows.get(state)
    if flow is None:
        return {"status": "unknown"}
    status = flow.status
    result = {"status": status, "base_url": flow.base}
    if status == "complete":
        result["token"] = flow.token
        with _lock:
            _flows.pop(state, None)
        flow.stop()
    elif status == "error":
        result["error"] = flow.error
        with _lock:
            _flows.pop(state, None)
        flow.stop()
    elif status == "expired":
        with _lock:
            _flows.pop(state, None)
        flow.stop()
    return result


def cancel_all() -> None:
    with _lock:
        flows = list(_flows.values())
        _flows.clear()
    for flow in flows:
        flow.stop()


def cancel(state: str) -> None:
    with _lock:
        flow = _flows.pop(state, None)
    if flow is not None:
        flow.stop()


def _housekeeping() -> None:
    now = time.time()
    stale = []
    with _lock:
        for state, flow in _flows.items():
            if now - flow.created > FLOW_TTL:
                stale.append((state, flow))
        for state, _flow in stale:
            _flows.pop(state, None)
    for _state, flow in stale:
        flow.stop()


def loopback_available() -> bool:
    """Whether a loopback listener can be created at all (used by diagnostics)."""
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
        return True
    except OSError:
        return False
