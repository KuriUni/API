"""TUTI CRM — a CRM built on the TUTI BaaS API.

The unit of the CRM is a customer: one TUTI tenant, identified by its tenant
API key. For each customer the app reads the tenant-scoped license, billing,
usage and audit APIs and keeps the last snapshot in SQLite so the screen is
instant and survives API outages.

Only read services are used. Nothing here issues, pauses or deletes licenses.
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
from datetime import date, datetime
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

import tuti_api
from secrets_store import SecretError, decrypt, encrypt, key_hint, load_data_key

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

ENVIRONMENTS = ("", "sandbox", "production")
ENVIRONMENT_LABELS = {"": "指定なし", "sandbox": "サンドボックス", "production": "本番"}
API_KEY_RE = re.compile(r"baas_(?:live|prod|sandbox|sdk)_[A-Za-z0-9_-]{32,120}")

_LOGIN_FAILURES: dict[str, list[float]] = {}
_LOGIN_LOCK = threading.Lock()

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


def _today() -> str:
    return date.today().isoformat()


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
        CREATE TABLE IF NOT EXISTS customers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          slug TEXT NOT NULL DEFAULT '',
          base_url TEXT NOT NULL,
          environment TEXT NOT NULL DEFAULT '' CHECK(environment IN ('','sandbox','production')),
          api_key_enc TEXT NOT NULL,
          key_hint TEXT NOT NULL DEFAULT '',
          note TEXT NOT NULL DEFAULT '',
          active INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS customer_cache (
          customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
          scope TEXT NOT NULL,
          payload TEXT NOT NULL DEFAULT 'null',
          fetched_at TEXT NOT NULL DEFAULT '',
          error TEXT NOT NULL DEFAULT '',
          PRIMARY KEY (customer_id, scope)
        );
        CREATE INDEX IF NOT EXISTS customers_name_idx ON customers(name);
        """)
        # This app replaced a generic sales CRM prototype; its tables are not used.
        for legacy in ("activities", "tasks", "deals", "contacts", "companies", "tuti_cache"):
            db.execute(f"DROP TABLE IF EXISTS {legacy}")
        db.commit()


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class CustomerIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=120)
    slug: str = Field(default="", max_length=80)
    base_url: str = Field(default="", max_length=300)
    environment: Literal["", "sandbox", "production"] = ""
    api_key: str = Field(default="", max_length=140)
    note: str = Field(default="", max_length=2000)
    active: bool = True

    @field_validator("slug")
    @classmethod
    def _slug(cls, value: str) -> str:
        if value and not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", value):
            raise ValueError("slug は英小文字・数字・ハイフンのみ使用できます")
        return value

    @field_validator("api_key")
    @classmethod
    def _api_key(cls, value: str) -> str:
        if value and not API_KEY_RE.fullmatch(value):
            raise ValueError("APIキーの形式が不正です（baas_live_… / baas_sandbox_… など）")
        return value


class LoginIn(BaseModel):
    username: str = Field(max_length=120)
    password: str = Field(max_length=200)


# ---------------------------------------------------------------------------
# Auth pages
# ---------------------------------------------------------------------------
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
# Cache helpers
# ---------------------------------------------------------------------------
def _cache_for(db: sqlite3.Connection, customer_id: int) -> dict:
    rows = db.execute("SELECT scope, payload, fetched_at, error FROM customer_cache WHERE customer_id=?",
                      (customer_id,)).fetchall()
    return {row["scope"]: {"payload": json.loads(row["payload"] or "null"),
                           "fetched_at": row["fetched_at"], "error": row["error"]} for row in rows}


def _cache_all(db: sqlite3.Connection) -> dict[int, dict]:
    result: dict[int, dict] = {}
    rows = db.execute("SELECT customer_id, scope, payload, fetched_at, error FROM customer_cache").fetchall()
    for row in rows:
        bucket = result.setdefault(row["customer_id"], {})
        bucket[row["scope"]] = {"payload": json.loads(row["payload"] or "null"),
                                "fetched_at": row["fetched_at"], "error": row["error"]}
    return result


def _write_cache(db: sqlite3.Connection, customer_id: int, scope: str, payload, error: str = "") -> None:
    db.execute(
        "INSERT INTO customer_cache (customer_id, scope, payload, fetched_at, error) VALUES (?,?,?,?,?) "
        "ON CONFLICT(customer_id, scope) DO UPDATE SET payload=excluded.payload, "
        "fetched_at=excluded.fetched_at, error=excluded.error",
        (customer_id, scope, json.dumps(payload, ensure_ascii=False), _now(), error),
    )


def _customer_dict(row: sqlite3.Row) -> dict:
    """Public customer shape. The encrypted key is never returned."""
    return {
        "id": row["id"], "name": row["name"], "slug": row["slug"], "base_url": row["base_url"],
        "environment": row["environment"], "environment_label": ENVIRONMENT_LABELS.get(row["environment"], ""),
        "key_hint": row["key_hint"], "note": row["note"], "active": bool(row["active"]),
        "created_at": row["created_at"], "updated_at": row["updated_at"],
    }


def _licenses_of(cache: dict) -> list:
    payload = (cache.get("licenses") or {}).get("payload") or {}
    rows = payload.get("licenses")
    return rows if isinstance(rows, list) else []


def _usage_of(cache: dict) -> dict:
    payload = (cache.get("usage") or {}).get("payload") or {}
    return payload if isinstance(payload, dict) else {}


def _invoices_of(cache: dict) -> list:
    payload = (cache.get("invoices") or {}).get("payload") or {}
    rows = payload.get("invoices")
    return rows if isinstance(rows, list) else []


def _events_of(cache: dict) -> list:
    payload = (cache.get("audit") or {}).get("payload") or {}
    rows = payload.get("events")
    return rows if isinstance(rows, list) else []


def _products_of(cache: dict) -> list:
    payload = (cache.get("products") or {}).get("payload") or {}
    rows = payload.get("products")
    return rows if isinstance(rows, list) else []


def _charge_of(cache: dict) -> float:
    usage = _usage_of(cache)
    for key in ("total_charge_yen_equivalent", "total_charge_credit"):
        value = usage.get(key)
        if value in (None, ""):
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return 0.0


def _customer_metrics(customer: dict, cache: dict) -> dict:
    licenses = _licenses_of(cache)
    invoices = _invoices_of(cache)
    unpaid = [row for row in invoices if str(row.get("status")) == "issued"]
    return {
        **customer,
        "licenses": len(licenses),
        "active_licenses": sum(1 for row in licenses if row.get("active")),
        "sandbox_licenses": sum(1 for row in licenses if row.get("environment") == "sandbox"),
        "products": len(_products_of(cache)),
        "month_charge": _charge_of(cache),
        "usage_period": _usage_of(cache).get("period", ""),
        "unpaid_count": len(unpaid),
        "unpaid_amount": sum(int(row.get("total_yen") or 0) for row in unpaid),
        "last_sync": max((item.get("fetched_at", "") for item in cache.values()), default=""),
        "errors": [scope for scope, item in cache.items() if item.get("error")],
        "error_message": next((item.get("error") for item in cache.values() if item.get("error")), ""),
    }


def _customers_with_metrics(db: sqlite3.Connection) -> list:
    cache = _cache_all(db)
    rows = db.execute("SELECT * FROM customers ORDER BY name COLLATE NOCASE, id").fetchall()
    return [_customer_metrics(_customer_dict(row), cache.get(row["id"], {})) for row in rows]


def _get_customer(db: sqlite3.Connection, customer_id: int) -> sqlite3.Row:
    row = db.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
    if not row:
        raise HTTPException(404, "顧客が見つかりません")
    return row


def _client_for(row: sqlite3.Row) -> tuti_api.TutiClient:
    try:
        api_key = decrypt(data_key(), row["api_key_enc"])
    except SecretError as error:
        raise HTTPException(409, str(error)) from error
    return tuti_api.TutiClient(row["base_url"], api_key, row["environment"])


def _sync_customer(db: sqlite3.Connection, row: sqlite3.Row, period: str) -> dict:
    client = _client_for(row)
    previous = _cache_for(db, row["id"])
    results = client.fetch_many(period)
    for scope, result in results.items():
        if result["ok"]:
            _write_cache(db, row["id"], scope, result["payload"])
        else:
            kept = (previous.get(scope) or {}).get("payload")
            _write_cache(db, row["id"], scope, kept, result["error"])
    db.commit()
    return {
        "customer_id": row["id"], "customer": row["name"],
        "ok": all(item["ok"] for item in results.values()),
        "results": {scope: {"ok": item["ok"], "error": item["error"], "code": item["code"]}
                    for scope, item in results.items()},
    }


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.get("/api/dashboard")
def dashboard(request: Request) -> dict:
    _require(request)
    month = _today()[:7]
    with closing(connect()) as db:
        customers = _customers_with_metrics(db)
        cache = _cache_all(db)
    active = [item for item in customers if item["active"]]
    events = []
    for customer in customers:
        for event in _events_of(cache.get(customer["id"], {})):
            events.append({**event, "customer_id": customer["id"], "customer_name": customer["name"]})
    events.sort(key=lambda item: str(item.get("used_at") or ""), reverse=True)
    return {
        "month": month,
        "kpis": {
            "customers": len(customers),
            "active_customers": len(active),
            "licenses": sum(item["licenses"] for item in active),
            "active_licenses": sum(item["active_licenses"] for item in active),
            "sandbox_licenses": sum(item["sandbox_licenses"] for item in active),
            "month_charge": round(sum(item["month_charge"] for item in active), 2),
            "unpaid_count": sum(item["unpaid_count"] for item in active),
            "unpaid_amount": sum(item["unpaid_amount"] for item in active),
            "synced_customers": sum(1 for item in active if item["last_sync"]),
            "error_customers": sum(1 for item in active if item["error_message"]),
        },
        "customers": customers,
        "events": events[:10],
    }


# ---------------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------------
@app.get("/api/customers")
def list_customers(request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        customers = _customers_with_metrics(db)
    return {"items": customers, "total": len(customers)}


@app.post("/api/customers", status_code=201)
def create_customer(payload: CustomerIn, request: Request) -> dict:
    _require(request, write=True)
    if not payload.api_key:
        raise HTTPException(400, "テナントAPIキーを入力してください")
    try:
        base_url = tuti_api.normalize_base_url(payload.base_url)
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    with closing(connect()) as db:
        if db.execute("SELECT 1 FROM customers WHERE api_key_enc<>'' AND name=? COLLATE NOCASE",
                      (payload.name,)).fetchone():
            raise HTTPException(400, "同じ名前の顧客が既にあります")
        now = _now()
        cursor = db.execute(
            "INSERT INTO customers (name, slug, base_url, environment, api_key_enc, key_hint, note, active, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (payload.name, payload.slug, base_url, payload.environment,
             encrypt(data_key(), payload.api_key), key_hint(payload.api_key),
             payload.note, 1 if payload.active else 0, now, now),
        )
        db.commit()
        row = _get_customer(db, int(cursor.lastrowid))
    return _customer_metrics(_customer_dict(row), {})


@app.get("/api/customers/{customer_id}")
def get_customer(customer_id: int, request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        row = _get_customer(db, customer_id)
        cache = _cache_for(db, customer_id)
    return {
        "customer": _customer_metrics(_customer_dict(row), cache),
        "scopes": cache,
        "licenses": _licenses_of(cache),
        "products": _products_of(cache),
        "usage": _usage_of(cache),
        "invoices": _invoices_of(cache),
        "events": _events_of(cache),
    }


@app.put("/api/customers/{customer_id}")
def update_customer(customer_id: int, payload: CustomerIn, request: Request) -> dict:
    _require(request, write=True)
    try:
        base_url = tuti_api.normalize_base_url(payload.base_url)
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    with closing(connect()) as db:
        row = _get_customer(db, customer_id)
        clash = db.execute("SELECT id FROM customers WHERE name=? COLLATE NOCASE AND id<>?",
                           (payload.name, customer_id)).fetchone()
        if clash:
            raise HTTPException(400, "同じ名前の顧客が既にあります")
        key_enc = row["api_key_enc"]
        hint = row["key_hint"]
        if payload.api_key:
            key_enc = encrypt(data_key(), payload.api_key)
            hint = key_hint(payload.api_key)
        db.execute(
            "UPDATE customers SET name=?, slug=?, base_url=?, environment=?, api_key_enc=?, key_hint=?, "
            "note=?, active=?, updated_at=? WHERE id=?",
            (payload.name, payload.slug, base_url, payload.environment, key_enc, hint,
             payload.note, 1 if payload.active else 0, _now(), customer_id),
        )
        db.commit()
        row = _get_customer(db, customer_id)
        metrics = _customer_metrics(_customer_dict(row), _cache_for(db, customer_id))
    return metrics


@app.delete("/api/customers/{customer_id}")
def delete_customer(customer_id: int, request: Request) -> dict:
    _require(request, write=True)
    with closing(connect()) as db:
        _get_customer(db, customer_id)
        db.execute("DELETE FROM customers WHERE id=?", (customer_id,))
        db.commit()
    return {"ok": True}


@app.post("/api/customers/{customer_id}/sync")
def sync_customer(customer_id: int, request: Request) -> dict:
    _require(request, write=True)
    period = _today()[:7]
    with closing(connect()) as db:
        row = _get_customer(db, customer_id)
        try:
            return _sync_customer(db, row, period)
        except tuti_api.TutiApiError as error:
            raise HTTPException(502, str(error)) from error


@app.post("/api/sync-all")
def sync_all(request: Request) -> dict:
    _require(request, write=True)
    period = _today()[:7]
    results = []
    with closing(connect()) as db:
        rows = db.execute("SELECT * FROM customers WHERE active=1 ORDER BY id").fetchall()
        for row in rows:
            try:
                results.append(_sync_customer(db, row, period))
            except (tuti_api.TutiApiError, HTTPException) as error:
                message = getattr(error, "detail", None) or str(error)
                results.append({"customer_id": row["id"], "customer": row["name"], "ok": False,
                                "results": {scope: {"ok": False, "error": str(message), "code": "sync_failed"}
                                            for scope in tuti_api.SCOPES}})
    return {
        "ok": all(item["ok"] for item in results),
        "synced": sum(1 for item in results if item["ok"]),
        "total": len(results),
        "items": results,
    }


# ---------------------------------------------------------------------------
# Cross-customer views
# ---------------------------------------------------------------------------
@app.get("/api/licenses")
def licenses(request: Request, q: str = "", environment: str = "", status: str = "", customer_id: int = 0) -> dict:
    _require(request)
    needle = (q or "").strip().lower()
    with closing(connect()) as db:
        customers = {row["id"]: _customer_dict(row) for row in db.execute("SELECT * FROM customers").fetchall()}
        cache = _cache_all(db)
    rows = []
    for cid, customer in customers.items():
        if customer_id and cid != customer_id:
            continue
        for license_row in _licenses_of(cache.get(cid, {})):
            item = {
                **license_row,
                "customer_id": cid, "customer_name": customer["name"],
                "customer_environment": customer["environment"],
            }
            if environment and item.get("environment") != environment:
                continue
            if status == "active" and not item.get("active"):
                continue
            if status == "paused" and item.get("active"):
                continue
            if needle and needle not in " ".join(str(item.get(key, "")) for key in
                                                 ("id", "label", "product_code", "customer_name")).lower():
                continue
            rows.append(item)
    rows.sort(key=lambda item: (item.get("customer_name", ""), int(item.get("id") or 0)), reverse=False)
    return {"items": rows, "total": len(rows)}


@app.get("/api/invoices")
def invoices(request: Request, period: str = "", status: str = "", customer_id: int = 0) -> dict:
    _require(request)
    with closing(connect()) as db:
        customers = {row["id"]: _customer_dict(row) for row in db.execute("SELECT * FROM customers").fetchall()}
        cache = _cache_all(db)
    rows = []
    for cid, customer in customers.items():
        if customer_id and cid != customer_id:
            continue
        for invoice in _invoices_of(cache.get(cid, {})):
            if period and str(invoice.get("billing_period")) != period:
                continue
            if status and str(invoice.get("status")) != status:
                continue
            rows.append({**invoice, "customer_id": cid, "customer_name": customer["name"]})
    rows.sort(key=lambda item: (str(item.get("billing_period") or ""), int(item.get("id") or 0)), reverse=True)
    return {"items": rows, "total": len(rows)}


@app.get("/api/events")
def events(request: Request, customer_id: int = 0, limit: int = 50) -> dict:
    _require(request)
    limit = max(1, min(200, limit))
    with closing(connect()) as db:
        customers = {row["id"]: _customer_dict(row) for row in db.execute("SELECT * FROM customers").fetchall()}
        cache = _cache_all(db)
    rows = []
    for cid, customer in customers.items():
        if customer_id and cid != customer_id:
            continue
        for event in _events_of(cache.get(cid, {})):
            rows.append({**event, "customer_id": cid, "customer_name": customer["name"]})
    rows.sort(key=lambda item: str(item.get("used_at") or ""), reverse=True)
    return {"items": rows[:limit], "total": len(rows)}


# ---------------------------------------------------------------------------
# CSV exports
# ---------------------------------------------------------------------------
def _csv_response(rows: list, header: list, filename: str) -> StreamingResponse:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(header)
    writer.writerows(rows)
    payload = "\ufeff" + buffer.getvalue()
    return StreamingResponse(
        iter([payload.encode("utf-8")]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{urllib.parse.quote(filename)}"'},
    )


@app.get("/api/export/licenses.csv")
def export_licenses(request: Request) -> StreamingResponse:
    data = licenses(request)
    rows = [[item.get("customer_name", ""), item.get("id", ""), item.get("product_code", ""), item.get("label", ""),
             "有効" if item.get("active") else "停止", item.get("environment", ""), item.get("max_devices", ""),
             item.get("expires_at") or "", item.get("created_at") or ""] for item in data["items"]]
    return _csv_response(rows, ["顧客", "ライセンスID", "製品コード", "ラベル", "状態", "環境", "端末上限",
                                "有効期限", "発行日"], "TUTIライセンス.csv")


@app.get("/api/export/invoices.csv")
def export_invoices(request: Request) -> StreamingResponse:
    data = invoices(request)
    rows = [[item.get("customer_name", ""), item.get("invoice_number", ""), item.get("billing_period", ""),
             item.get("total_yen", 0), item.get("status", ""), item.get("issue_date") or "",
             item.get("due_date") or ""] for item in data["items"]]
    return _csv_response(rows, ["顧客", "請求番号", "対象月", "金額", "状態", "発行日", "支払期限"],
                         "TUTI請求書.csv")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
