"""TUTI CRM — administrator console for TUTI tenants.

The operator signs in to TUTI once with SSO (Passkey). With that admin session
the app reads the admin APIs used by the admin center:

    admin_api.php            tenants, licenses (all tenants)
    ha/api-billing-admin.php invoices

Nothing is registered per tenant and no tenant API key is stored anywhere.
The app only reads; issuing, pausing or invoicing stays in the admin center.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
from contextlib import closing
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import admin_api
import admin_sso
from secrets_store import SecretError, decrypt, encrypt, load_data_key

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("CRM_DATA", ROOT / "data")).resolve()
DB_PATH = DATA_DIR / "tuti-crm.sqlite3"
STATIC_DIR = ROOT / "static"

ADMIN_USER = os.environ.get("CRM_USER", "admin")
ADMIN_NAME = os.environ.get("CRM_NAME", "管理者")
PASSWORD = os.environ.get("CRM_PASSWORD", "demo")
DEMO_MODE = not os.environ.get("CRM_PASSWORD")
SESSION_KEY = os.environ.get("CRM_SESSION_KEY") or secrets.token_urlsafe(32)
SESSION_COOKIE = "tuti_crm_session"
SESSION_TTL = 60 * 60 * 12
COOKIE_SECURE = os.environ.get("CRM_SECURE_COOKIES", "0") == "1"

DEFAULT_TUTI_BASE = os.environ.get("TUTI_ADMIN_BASE", admin_api.DEFAULT_BASE)


def env_session() -> str:
    return (os.environ.get("TUTI_ADMIN_SESSION") or "").strip()


def env_base() -> str:
    return os.environ.get("TUTI_ADMIN_BASE") or DEFAULT_TUTI_BASE

LICENSE_STATES = ("active", "paused", "expired", "expiring", "revoked")
STATE_LABELS = {"active": "有効", "paused": "停止", "expired": "期限切れ", "expiring": "期限間近", "revoked": "失効"}
INVOICE_LABELS = {"draft": "下書き", "issued": "発行済み", "paid": "入金済み", "void": "無効"}
TENANT_STATUS_LABELS = {"active": "有効", "suspended": "停止", "deleted": "削除"}

_LOGIN_FAILURES: dict[str, list[float]] = {}
_LOGIN_LOCK = threading.Lock()
_SYNC_LOCK = threading.Lock()

app = FastAPI(title="TUTI CRM", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
        "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign(payload: dict) -> str:
    raw = _b64e(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64e(hmac.new(SESSION_KEY.encode("utf-8"), raw.encode("ascii"), hashlib.sha256).digest())
    return raw + "." + sig


def _unsign(token: str) -> Optional[dict]:
    if not isinstance(token, str) or token.count(".") != 1:
        return None
    raw, sig = token.split(".", 1)
    expected = _b64e(hmac.new(SESSION_KEY.encode("utf-8"), raw.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        payload = json.loads(_b64d(raw).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or int(payload.get("exp", 0)) <= int(time.time()):
        return None
    return payload


def _session(request: Request) -> Optional[dict]:
    return _unsign(request.cookies.get(SESSION_COOKIE, ""))


def _require(request: Request, write: bool = False) -> dict:
    session = _session(request)
    if not session:
        raise HTTPException(401, "login_required")
    if write and not hmac.compare_digest(str(request.headers.get("x-csrf-token", "")), str(session.get("csrf", ""))):
        raise HTTPException(403, "csrf_check_failed")
    return session


def _new_session() -> tuple[str, str]:
    csrf = secrets.token_urlsafe(24)
    token = _sign({"sub": ADMIN_USER, "name": ADMIN_NAME, "csrf": csrf, "exp": int(time.time()) + SESSION_TTL})
    return token, csrf


def _login_allowed(remote: str) -> bool:
    now = time.time()
    with _LOGIN_LOCK:
        attempts = [stamp for stamp in _LOGIN_FAILURES.get(remote, []) if now - stamp < 300]
        _LOGIN_FAILURES[remote] = attempts
        return len(attempts) < 8


def _record_login_failure(remote: str) -> None:
    with _LOGIN_LOCK:
        _LOGIN_FAILURES.setdefault(remote, []).append(time.time())


def _clear_login_failures(remote: str) -> None:
    with _LOGIN_LOCK:
        _LOGIN_FAILURES.pop(remote, None)


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db


def data_key() -> bytes:
    return load_data_key(DATA_DIR)


def initialize() -> None:
    with closing(connect()) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS admin_auth (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          base_url TEXT NOT NULL,
          token_enc TEXT NOT NULL,
          connected_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tenants (
          tenant_id INTEGER PRIMARY KEY,
          name TEXT NOT NULL DEFAULT '',
          slug TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT '',
          environment TEXT NOT NULL DEFAULT '',
          plan_code TEXT NOT NULL DEFAULT '',
          fetched_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS licenses (
          license_id INTEGER PRIMARY KEY,
          tenant_id INTEGER NOT NULL DEFAULT 0,
          label TEXT NOT NULL DEFAULT '',
          state TEXT NOT NULL DEFAULT '',
          active INTEGER NOT NULL DEFAULT 0,
          max_devices INTEGER NOT NULL DEFAULT 1,
          active_sessions INTEGER NOT NULL DEFAULT 0,
          expires_at TEXT NOT NULL DEFAULT '',
          revoked_at TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL DEFAULT '',
          fetched_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS invoices (
          invoice_id INTEGER PRIMARY KEY,
          tenant_id INTEGER NOT NULL DEFAULT 0,
          invoice_number TEXT NOT NULL DEFAULT '',
          billing_period TEXT NOT NULL DEFAULT '',
          customer_name TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT '',
          total_yen INTEGER NOT NULL DEFAULT 0,
          issue_date TEXT NOT NULL DEFAULT '',
          due_date TEXT NOT NULL DEFAULT '',
          fetched_at TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS sync_state (
          scope TEXT PRIMARY KEY,
          fetched_at TEXT NOT NULL DEFAULT '',
          error TEXT NOT NULL DEFAULT '',
          total INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS licenses_tenant_idx ON licenses(tenant_id);
        CREATE INDEX IF NOT EXISTS licenses_state_idx ON licenses(state);
        CREATE INDEX IF NOT EXISTS invoices_status_idx ON invoices(status);
        CREATE INDEX IF NOT EXISTS invoices_tenant_idx ON invoices(tenant_id);
        """)
        for legacy in ("customers", "customer_cache", "companies", "contacts", "deals", "activities", "tasks", "tuti_cache"):
            db.execute(f"DROP TABLE IF EXISTS {legacy}")
        db.commit()


# ---------------------------------------------------------------------------
# Models and local admin login
# ---------------------------------------------------------------------------
class LoginIn(BaseModel):
    username: str = Field(max_length=120)
    password: str = Field(max_length=200)


class BaseIn(BaseModel):
    base_url: str = Field(default="", max_length=300)


@app.on_event("startup")
def startup() -> None:
    initialize()


@app.get("/api/healthz")
def healthz() -> dict:
    with closing(connect()) as db:
        db.execute("SELECT 1").fetchone()
    return {"ok": True, "database": "ok"}


@app.get("/api/auth-info")
def auth_info() -> dict:
    return {"demo_mode": DEMO_MODE, "user": ADMIN_USER}


@app.post("/api/login")
def login(payload: LoginIn, request: Request) -> JSONResponse:
    remote = request.client.host if request.client else "unknown"
    if not _login_allowed(remote):
        raise HTTPException(429, "ログイン試行が多すぎます。しばらく待ってから再試行してください")
    if not hmac.compare_digest(payload.username, ADMIN_USER) or not hmac.compare_digest(payload.password, PASSWORD):
        _record_login_failure(remote)
        raise HTTPException(401, "ユーザー名またはパスワードが違います")
    _clear_login_failures(remote)
    token, csrf = _new_session()
    response = JSONResponse({"ok": True, "csrf": csrf})
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, path="/", secure=COOKIE_SECURE,
                        httponly=True, samesite="lax")
    return response


@app.post("/api/logout")
def logout(request: Request) -> JSONResponse:
    _require(request, write=True)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/", secure=COOKIE_SECURE, httponly=True, samesite="lax")
    return response


@app.get("/api/me")
def me(request: Request) -> dict:
    session = _require(request)
    return {"sub": session["sub"], "name": session.get("name", ""), "csrf": session["csrf"], "demo_mode": DEMO_MODE}


@app.get("/")
def index(request: Request):
    if not _session(request):
        return RedirectResponse("/login", status_code=303)
    return FileResponse(STATIC_DIR / "index.html", media_type="text/html")


@app.get("/login")
def login_page(request: Request):
    if _session(request):
        return RedirectResponse("/", status_code=303)
    return FileResponse(STATIC_DIR / "login.html", media_type="text/html")


# ---------------------------------------------------------------------------
# TUTI admin session
# ---------------------------------------------------------------------------
def _stored_session(db: sqlite3.Connection) -> Optional[dict]:
    row = db.execute("SELECT base_url, token_enc, connected_at FROM admin_auth WHERE id=1").fetchone()
    if not row:
        return None
    try:
        token = decrypt(data_key(), row["token_enc"])
    except SecretError:
        return None
    return {"base_url": row["base_url"], "token": token, "connected_at": row["connected_at"], "source": "sso"}


def current_auth(db: sqlite3.Connection) -> Optional[dict]:
    """Return the active admin credential (env override wins)."""
    if env_session():
        return {"base_url": admin_api.base_url(env_base()), "token": env_session(),
                "connected_at": "", "source": "environment"}
    return _stored_session(db)


def _client(db: sqlite3.Connection) -> admin_api.AdminClient:
    auth = current_auth(db)
    if not auth:
        raise HTTPException(409, "TUTIに接続していません。SSOでログインしてください")
    return admin_api.AdminClient(auth["base_url"], auth["token"])


def _sync_state(db: sqlite3.Connection) -> dict:
    rows = db.execute("SELECT scope, fetched_at, error, total FROM sync_state").fetchall()
    return {row["scope"]: {"fetched_at": row["fetched_at"], "error": row["error"], "total": row["total"]}
            for row in rows}


def _mark_sync(db: sqlite3.Connection, scope: str, error: str = "", total: int = 0) -> None:
    db.execute("INSERT INTO sync_state (scope, fetched_at, error, total) VALUES (?,?,?,?) "
               "ON CONFLICT(scope) DO UPDATE SET fetched_at=excluded.fetched_at, error=excluded.error, total=excluded.total",
               (scope, _now(), error, total))


def _license_state(row: dict) -> str:
    if row.get("revoked_at"):
        return "revoked"
    if not row.get("active"):
        return "paused"
    expires = str(row.get("expires_at") or "")
    if expires:
        try:
            when = datetime.strptime(expires[:19], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            when = None
        if when is not None:
            now = datetime.now(timezone.utc)
            if when <= now:
                return "expired"
            if (when - now).days <= 30:
                return "expiring"
    return "active"


@app.get("/api/connection")
def connection(request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        auth = current_auth(db)
        state = _sync_state(db)
        tenants = db.execute("SELECT COUNT(*) FROM tenants").fetchone()[0]
    return {
        "connected": bool(auth),
        "base_url": auth["base_url"] if auth else admin_api.base_url(env_base()),
        "connected_at": auth["connected_at"] if auth else "",
        "source": auth["source"] if auth else "",
        "loopback": admin_sso.loopback_available(),
        "tenants": tenants,
        "sync": state,
        "last_sync": max((item["fetched_at"] for item in state.values()), default=""),
        "env_configured": bool(env_session()),
    }


@app.post("/api/connection/start")
def connection_start(payload: BaseIn, request: Request) -> dict:
    _require(request, write=True)
    if env_session():
        raise HTTPException(400, "TUTI_ADMIN_SESSION が設定されています。環境変数を外すとSSOログインを使えます")
    try:
        base = admin_api.base_url(payload.base_url or env_base())
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    flow = admin_sso.start(base)
    return {"state": flow["state"], "url": flow["url"], "expires_in": flow["expires_in"]}


@app.get("/api/connection/poll")
def connection_poll(request: Request, state: str = "") -> dict:
    _require(request)
    if not state:
        raise HTTPException(400, "state が必要です")
    result = admin_sso.poll(state)
    if result.get("status") == "complete":
        token = result["token"]
        base = result.get("base_url") or ""
        with closing(connect()) as db:
            client = admin_api.AdminClient(base or current_base(db), token)
            try:
                client.check()
            except admin_api.AdminApiError as error:
                raise HTTPException(400, f"管理者セッションを確認できません: {error}") from error
            db.execute("INSERT INTO admin_auth (id, base_url, token_enc, connected_at) VALUES (1,?,?,?) "
                       "ON CONFLICT(id) DO UPDATE SET base_url=excluded.base_url, token_enc=excluded.token_enc, "
                       "connected_at=excluded.connected_at",
                       (client.base, encrypt(data_key(), token), _now()))
            db.commit()
        return {"status": "connected"}
    return result


def current_base(db: sqlite3.Connection) -> str:
    auth = current_auth(db)
    return auth["base_url"] if auth else admin_api.base_url(env_base())


@app.post("/api/connection/disconnect")
def connection_disconnect(request: Request) -> dict:
    _require(request, write=True)
    admin_sso.cancel_all()
    with closing(connect()) as db:
        db.execute("DELETE FROM admin_auth")
        for table in ("tenants", "licenses", "invoices", "sync_state"):
            db.execute(f"DELETE FROM {table}")
        db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------
def _sync_all(db: sqlite3.Connection) -> dict:
    client = _client(db)
    errors: dict[str, str] = {}
    counts = {"tenants": 0, "licenses": 0, "invoices": 0}

    tenant_rows: list = []
    try:
        page = 1
        while page <= 20:
            data = client.tenants(page=page, limit=100)
            tenant_rows.extend(data["items"])
            if not data["has_next"]:
                break
            page += 1
    except admin_api.AdminApiError as error:
        errors["tenants"] = str(error)
        _mark_sync(db, "tenants", str(error))
        if error.unauthenticated:
            db.commit()
            return {"ok": False, "expired": True, "counts": counts, "errors": errors}
    else:
        with db:
            db.execute("DELETE FROM tenants")
            for row in tenant_rows:
                db.execute("INSERT OR REPLACE INTO tenants (tenant_id,name,slug,status,environment,plan_code,fetched_at) "
                           "VALUES (?,?,?,?,?,?,?)",
                           (int(row.get("id") or 0), str(row.get("name") or ""), str(row.get("slug") or ""),
                            str(row.get("status") or ""), str(row.get("environment") or ""),
                            str(row.get("plan_code") or ""), _now()))
        counts["tenants"] = len(tenant_rows)
        _mark_sync(db, "tenants", "", len(tenant_rows))

    license_rows: list = []
    try:
        page = 1
        while page <= 50:
            data = client.licenses(page=page, limit=100)
            license_rows.extend(data["items"])
            if not data["has_next"]:
                break
            page += 1
    except admin_api.AdminApiError as error:
        errors["licenses"] = str(error)
        _mark_sync(db, "licenses", str(error))
    else:
        with db:
            db.execute("DELETE FROM licenses")
            for row in license_rows:
                db.execute(
                    "INSERT OR REPLACE INTO licenses (license_id,tenant_id,label,state,active,max_devices,"
                    "active_sessions,expires_at,revoked_at,created_at,fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (int(row.get("id") or 0), int(row.get("tenant_id") or 0), str(row.get("label") or ""),
                     _license_state(row), 1 if row.get("active") else 0, int(row.get("max_devices") or 1),
                     int(row.get("active_sessions") or 0), str(row.get("expires_at") or ""),
                     str(row.get("revoked_at") or ""), str(row.get("created_at") or ""), _now()))
        counts["licenses"] = len(license_rows)
        _mark_sync(db, "licenses", "", len(license_rows))

    invoice_rows: list = []
    try:
        page = 1
        while page <= 20:
            data = client.invoices(page=page, limit=100)
            invoice_rows.extend(data["items"])
            if not data["has_next"]:
                break
            page += 1
    except admin_api.AdminApiError as error:
        errors["invoices"] = str(error)
        _mark_sync(db, "invoices", str(error))
    else:
        with db:
            db.execute("DELETE FROM invoices")
            for row in invoice_rows:
                db.execute(
                    "INSERT OR REPLACE INTO invoices (invoice_id,tenant_id,invoice_number,billing_period,customer_name,"
                    "status,total_yen,issue_date,due_date,fetched_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (int(row.get("id") or 0), int(row.get("account_tenant_id") or 0),
                     str(row.get("invoice_number") or ""), str(row.get("billing_period") or ""),
                     str(row.get("customer_name") or ""), str(row.get("status") or ""),
                     int(float(row.get("total_yen") or 0)), str(row.get("issue_date") or ""),
                     str(row.get("due_date") or ""), _now()))
        counts["invoices"] = len(invoice_rows)
        _mark_sync(db, "invoices", "", len(invoice_rows))

    db.commit()
    state = _sync_state(db)
    return {
        "ok": not errors,
        "expired": any("無効" in message or "期限切れ" in message for message in errors.values()),
        "counts": counts,
        "errors": errors,
        "last_sync": max((item["fetched_at"] for item in state.values()), default=""),
    }


@app.post("/api/sync")
def sync(request: Request) -> dict:
    _require(request, write=True)
    if not _SYNC_LOCK.acquire(blocking=False):
        raise HTTPException(429, "同期が実行中です。少し待って再試行してください")
    try:
        with closing(connect()) as db:
            return _sync_all(db)
    finally:
        _SYNC_LOCK.release()


# ---------------------------------------------------------------------------
# Views over the cached admin data
# ---------------------------------------------------------------------------
def _tenant_rows(db: sqlite3.Connection) -> list:
    rows = db.execute("""
      SELECT t.*,
        (SELECT COUNT(*) FROM licenses l WHERE l.tenant_id=t.tenant_id) AS licenses,
        (SELECT COUNT(*) FROM licenses l WHERE l.tenant_id=t.tenant_id AND l.state IN ('active','expiring')) AS active_licenses,
        (SELECT COUNT(*) FROM licenses l WHERE l.tenant_id=t.tenant_id AND l.state='expiring') AS expiring_licenses,
        (SELECT COUNT(*) FROM invoices i WHERE i.tenant_id=t.tenant_id AND i.status='issued') AS unpaid_count,
        (SELECT COALESCE(SUM(i.total_yen),0) FROM invoices i WHERE i.tenant_id=t.tenant_id AND i.status='issued') AS unpaid_amount,
        (SELECT COALESCE(SUM(i.total_yen),0) FROM invoices i WHERE i.tenant_id=t.tenant_id AND i.status='paid') AS paid_amount
      FROM tenants t ORDER BY t.name COLLATE NOCASE, t.tenant_id
    """).fetchall()
    return [dict(row) for row in rows]


@app.get("/api/dashboard")
def dashboard(request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        tenants = _tenant_rows(db)
        state = _sync_state(db)
        counts = db.execute("""
          SELECT
            (SELECT COUNT(*) FROM licenses) AS licenses,
            (SELECT COUNT(*) FROM licenses WHERE state IN ('active','expiring')) AS active_licenses,
            (SELECT COUNT(*) FROM licenses WHERE state='expiring') AS expiring_licenses,
            (SELECT COUNT(*) FROM licenses WHERE state='expired') AS expired_licenses,
            (SELECT COUNT(*) FROM invoices WHERE status='issued') AS unpaid_count,
            (SELECT COALESCE(SUM(total_yen),0) FROM invoices WHERE status='issued') AS unpaid_amount,
            (SELECT COALESCE(SUM(total_yen),0) FROM invoices WHERE status='paid') AS paid_amount,
            (SELECT COUNT(*) FROM invoices) AS invoices
        """).fetchone()
        recent = [dict(row) for row in db.execute(
            "SELECT * FROM invoices ORDER BY billing_period DESC, invoice_id DESC LIMIT 6").fetchall()]
        top = [row for row in tenants if row["licenses"]][:8]
    return {
        "kpis": {
            "tenants": len(tenants),
            "active_tenants": sum(1 for row in tenants if row["status"] == "active"),
            "licenses": counts["licenses"],
            "active_licenses": counts["active_licenses"],
            "expiring_licenses": counts["expiring_licenses"],
            "expired_licenses": counts["expired_licenses"],
            "invoices": counts["invoices"],
            "unpaid_count": counts["unpaid_count"],
            "unpaid_amount": counts["unpaid_amount"],
            "paid_amount": counts["paid_amount"],
        },
        "tenants": top,
        "recent_invoices": recent,
        "sync": state,
        "last_sync": max((item["fetched_at"] for item in state.values()), default=""),
    }


@app.get("/api/tenants")
def tenants(request: Request, q: str = "") -> dict:
    _require(request)
    needle = (q or "").strip().lower()
    with closing(connect()) as db:
        rows = _tenant_rows(db)
    if needle:
        rows = [row for row in rows if needle in f"{row['name']} {row['slug']}".lower()]
    return {"items": rows, "total": len(rows)}


@app.get("/api/tenants/{tenant_id}")
def tenant_detail(tenant_id: int, request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        tenant = db.execute("SELECT * FROM tenants WHERE tenant_id=?", (tenant_id,)).fetchone()
        if not tenant:
            raise HTTPException(404, "契約先が見つかりません")
        licenses = [dict(row) for row in db.execute(
            "SELECT * FROM licenses WHERE tenant_id=? ORDER BY license_id DESC", (tenant_id,)).fetchall()]
        invoices = [dict(row) for row in db.execute(
            "SELECT * FROM invoices WHERE tenant_id=? ORDER BY billing_period DESC, invoice_id DESC",
            (tenant_id,)).fetchall()]
        summary = db.execute("""
          SELECT COUNT(*) AS licenses,
            COALESCE(SUM(CASE WHEN state IN ('active','expiring') THEN 1 ELSE 0 END),0) AS active_licenses,
            COALESCE(SUM(CASE WHEN state='expiring' THEN 1 ELSE 0 END),0) AS expiring_licenses
          FROM licenses WHERE tenant_id=?
        """, (tenant_id,)).fetchone()
        billing = db.execute("""
          SELECT COALESCE(SUM(CASE WHEN status='issued' THEN total_yen ELSE 0 END),0) AS unpaid_amount,
                 COUNT(CASE WHEN status='issued' THEN 1 END) AS unpaid_count,
                 COALESCE(SUM(CASE WHEN status='paid' THEN total_yen ELSE 0 END),0) AS paid_amount
          FROM invoices WHERE tenant_id=?
        """, (tenant_id,)).fetchone()
    return {
        "tenant": dict(tenant),
        "summary": {**dict(summary), **dict(billing)},
        "licenses": licenses,
        "invoices": invoices,
    }


@app.get("/api/licenses")
def licenses(request: Request, q: str = "", state: str = "", tenant_id: int = 0, page: int = 1,
             limit: int = 50) -> dict:
    _require(request)
    page = max(1, min(int(page or 1), 100_000))
    limit = max(1, min(int(limit or 50), 200))
    needle = (q or "").strip().lower()
    where, args = [], []
    if state in LICENSE_STATES:
        where.append("l.state=?")
        args.append(state)
    if tenant_id:
        where.append("l.tenant_id=?")
        args.append(tenant_id)
    if needle:
        where.append("(CAST(l.license_id AS TEXT) LIKE ? OR l.label LIKE ? OR t.name LIKE ? OR t.slug LIKE ?)")
        args.extend([f"%{needle}%"] * 4)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    offset = (max(1, page) - 1) * limit
    with closing(connect()) as db:
        total = db.execute(f"SELECT COUNT(*) FROM licenses l LEFT JOIN tenants t ON t.tenant_id=l.tenant_id{clause}",
                           tuple(args)).fetchone()[0]
        rows = db.execute(
            "SELECT l.*, t.name AS tenant_name, t.slug AS tenant_slug FROM licenses l "
            f"LEFT JOIN tenants t ON t.tenant_id=l.tenant_id{clause} "
            "ORDER BY l.license_id DESC LIMIT ? OFFSET ?", tuple(args) + (limit, offset)).fetchall()
    return {"items": [dict(row) for row in rows], "total": total, "page": max(1, page), "limit": limit}


@app.get("/api/invoices")
def invoices(request: Request, q: str = "", status: str = "", tenant_id: int = 0, page: int = 1,
             limit: int = 50) -> dict:
    _require(request)
    page = max(1, min(int(page or 1), 100_000))
    limit = max(1, min(int(limit or 50), 200))
    needle = (q or "").strip().lower()
    where, args = [], []
    if status in ("draft", "issued", "paid", "void"):
        where.append("i.status=?")
        args.append(status)
    if tenant_id:
        where.append("i.tenant_id=?")
        args.append(tenant_id)
    if needle:
        where.append("(i.invoice_number LIKE ? OR i.customer_name LIKE ? OR t.slug LIKE ?)")
        args.extend([f"%{needle}%"] * 3)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    offset = (max(1, page) - 1) * limit
    with closing(connect()) as db:
        total = db.execute(f"SELECT COUNT(*) FROM invoices i LEFT JOIN tenants t ON t.tenant_id=i.tenant_id{clause}",
                           tuple(args)).fetchone()[0]
        rows = db.execute(
            "SELECT i.*, t.slug AS tenant_slug FROM invoices i "
            f"LEFT JOIN tenants t ON t.tenant_id=i.tenant_id{clause} "
            "ORDER BY i.billing_period DESC, i.invoice_id DESC LIMIT ? OFFSET ?",
            tuple(args) + (limit, offset)).fetchall()
        summary = db.execute("""
          SELECT COALESCE(SUM(CASE WHEN status='draft' THEN 1 ELSE 0 END),0) AS draft,
                 COALESCE(SUM(CASE WHEN status='issued' THEN 1 ELSE 0 END),0) AS issued,
                 COALESCE(SUM(CASE WHEN status='paid' THEN 1 ELSE 0 END),0) AS paid,
                 COALESCE(SUM(CASE WHEN status='void' THEN 1 ELSE 0 END),0) AS void,
                 COALESCE(SUM(CASE WHEN status='paid' THEN total_yen ELSE 0 END),0) AS paid_total
          FROM invoices
        """).fetchone()
    return {"items": [dict(row) for row in rows], "total": total, "page": max(1, page),
            "limit": limit, "summary": dict(summary)}


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------
def _csv_response(rows: list, header: list, filename: str) -> StreamingResponse:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    writer.writerows(rows)
    return StreamingResponse(
        iter([("\ufeff" + buffer.getvalue()).encode("utf-8")]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{urllib.parse.quote(filename)}"'},
    )


@app.get("/api/export/licenses.csv")
def export_licenses(request: Request) -> StreamingResponse:
    _require(request)
    with closing(connect()) as db:
        rows = db.execute(
            "SELECT l.*, t.name AS tenant_name FROM licenses l LEFT JOIN tenants t ON t.tenant_id=l.tenant_id "
            "ORDER BY t.name, l.license_id").fetchall()
    data = [[row["tenant_name"] or "", row["license_id"], row["label"], STATE_LABELS.get(row["state"], row["state"]),
             row["max_devices"], row["active_sessions"], row["expires_at"] or "", row["created_at"] or ""]
            for row in rows]
    return _csv_response(data, ["契約先", "ライセンスID", "ラベル", "状態", "端末上限", "接続中端末", "有効期限", "発行日"],
                         "TUTIライセンス.csv")


@app.get("/api/export/invoices.csv")
def export_invoices(request: Request) -> StreamingResponse:
    _require(request)
    with closing(connect()) as db:
        rows = db.execute(
            "SELECT i.*, t.name AS tenant_name FROM invoices i LEFT JOIN tenants t ON t.tenant_id=i.tenant_id "
            "ORDER BY i.billing_period DESC, i.invoice_id DESC").fetchall()
    data = [[row["tenant_name"] or row["customer_name"], row["invoice_number"], row["billing_period"], row["total_yen"],
             INVOICE_LABELS.get(row["status"], row["status"]), row["issue_date"] or "", row["due_date"] or ""]
            for row in rows]
    return _csv_response(data, ["契約先", "請求番号", "対象月", "金額", "状態", "発行日", "支払期限"], "TUTI請求書.csv")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
