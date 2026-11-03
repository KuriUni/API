"""Business operations web app: attendance and monthly report data."""
from __future__ import annotations

import csv
import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import time
import urllib.parse
import urllib.request
from contextlib import closing
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import RedirectResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("BUSINESS_OPS_DATA", ROOT / "data")).resolve()
DB_PATH = DATA_DIR / "business-ops.sqlite3"
app = FastAPI(title="業務運用", docs_url=None, redoc_url=None)
ISSUER = os.environ.get("BUSINESS_OPS_OIDC_ISSUER", "https://sso.2415.jp").rstrip("/")
CLIENT_ID = os.environ.get("BUSINESS_OPS_OIDC_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("BUSINESS_OPS_OIDC_CLIENT_SECRET", "")
REDIRECT_URI = os.environ.get("BUSINESS_OPS_OIDC_REDIRECT_URI", "")
SESSION_KEY = os.environ.get("BUSINESS_OPS_SESSION_KEY", "")
SESSION_COOKIE = "business_ops_session"
FLOW_COOKIE = "business_ops_oidc_flow"


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    if request.url.path.startswith(("/api/", "/auth/")):
        response.headers["Cache-Control"] = "no-store"
    return response


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def configured():
    return bool(CLIENT_ID and CLIENT_SECRET and REDIRECT_URI.startswith("https://") and len(SESSION_KEY) >= 32)


def signed(payload: dict) -> str:
    raw = b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = b64e(hmac.new(SESSION_KEY.encode(), raw.encode(), hashlib.sha256).digest())
    return raw + "." + sig


def unsign(token: str):
    if not configured() or not isinstance(token, str) or token.count(".") != 1:
        return None
    raw, sig = token.split(".", 1)
    expected = b64e(hmac.new(SESSION_KEY.encode(), raw.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        value = json.loads(b64d(raw).decode())
        if not isinstance(value, dict) or int(value.get("exp", 0)) <= int(time.time()):
            return None
        return value
    except (ValueError, TypeError, json.JSONDecodeError):
        return None


def get_json(url: str, data=None, basic=None):
    if not url.startswith(ISSUER + "/"):
        raise RuntimeError("OIDC endpoint outside configured issuer")
    headers = {"Accept": "application/json"}
    if data is not None:
        data = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if basic:
        headers["Authorization"] = "Basic " + base64.b64encode((CLIENT_ID + ":" + CLIENT_SECRET).encode()).decode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req, timeout=12) as response:
        if response.status != 200:
            raise RuntimeError("OIDC provider rejected request")
        body = response.read(1024 * 1024 + 1)
    if len(body) > 1024 * 1024:
        raise RuntimeError("OIDC response too large")
    result = json.loads(body.decode("utf-8"))
    if not isinstance(result, dict):
        raise RuntimeError("Invalid OIDC response")
    return result


def verify_id_token(token, nonce):
    parts = str(token).split(".")
    if len(parts) != 3:
        raise ValueError("invalid_token")
    header, claims = json.loads(b64d(parts[0])), json.loads(b64d(parts[1]))
    if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
        raise ValueError("invalid_token_header")
    jwks = get_json(ISSUER + "/jwks")
    jwk = next((item for item in jwks.get("keys", []) if item.get("kid") == header["kid"] and item.get("kty") == "RSA"), None)
    if not jwk:
        raise ValueError("signing_key_missing")
    n, e = int.from_bytes(b64d(jwk["n"]), "big"), int.from_bytes(b64d(jwk["e"]), "big")
    public = rsa.RSAPublicNumbers(e, n).public_key()
    public.verify(b64d(parts[2]), (parts[0] + "." + parts[1]).encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    now = int(time.time())
    aud = claims.get("aud")
    if claims.get("iss") != ISSUER or not (CLIENT_ID in aud if isinstance(aud, list) else aud == CLIENT_ID):
        raise ValueError("token_audience_or_issuer_invalid")
    if int(claims.get("exp", 0)) <= now or int(claims.get("iat", 0)) > now + 60 or claims.get("nonce") != nonce:
        raise ValueError("token_expired_or_nonce_invalid")
    if not isinstance(claims.get("sub"), str) or len(claims["sub"]) < 16:
        raise ValueError("subject_invalid")
    sid = claims.get("sid", "")
    if len(sid) != 64 or any(c not in "0123456789abcdef" for c in sid):
        raise ValueError("session_id_invalid")
    return claims


def require_session(request: Request, write=False):
    session = unsign(request.cookies.get(SESSION_COOKIE, ""))
    if not session or not isinstance(session.get("sub"), str):
        raise HTTPException(401, "login_required")
    # Check revocation/expiry with SSO on each API request; fail closed if unavailable.
    try:
        status = get_json(ISSUER + "/session/introspect", {"sid": session["sid"]}, basic=True)
    except Exception as exc:
        raise HTTPException(503, "sso_session_check_unavailable") from exc
    if status.get("active") is not True or int(status.get("expires_at", 0)) <= int(time.time()):
        raise HTTPException(401, "sso_session_expired")
    if write and not hmac.compare_digest(request.headers.get("x-csrf-token", ""), str(session.get("csrf", ""))):
        raise HTTPException(403, "csrf_check_failed")
    return session


def connect():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    return db


def initialize():
    with closing(connect()) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS attendance (
          employee_id TEXT NOT NULL,
          work_date TEXT NOT NULL,
          start_time TEXT,
          end_time TEXT,
          break_minutes INTEGER NOT NULL DEFAULT 0 CHECK(break_minutes BETWEEN 0 AND 1440),
          task TEXT NOT NULL DEFAULT '',
          updated_at TEXT NOT NULL,
          PRIMARY KEY(employee_id, work_date)
        );
        CREATE INDEX IF NOT EXISTS attendance_date_idx ON attendance(work_date, employee_id);
        """)
        db.commit()


class AttendanceInput(BaseModel):
    work_date: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    break_minutes: int = Field(default=60, ge=0, le=1440)
    task: str = Field(default="", max_length=2000)

    @field_validator("work_date")
    @classmethod
    def valid_date(cls, value):
        try:
            parsed = date.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("日付はYYYY-MM-DDで指定してください") from exc
        if parsed.isoformat() != value:
            raise ValueError("日付はYYYY-MM-DDで指定してください")
        return value

    @field_validator("start_time", "end_time")
    @classmethod
    def valid_time(cls, value):
        if value in (None, ""):
            return None
        try:
            parsed = datetime.strptime(value, "%H:%M").time()
        except ValueError as exc:
            raise ValueError("時刻はHH:MM形式で入力してください") from exc
        return parsed.strftime("%H:%M")


@app.on_event("startup")
def startup():
    initialize()


@app.get("/api/healthz")
def healthz():
    with closing(connect()) as db:
        db.execute("SELECT 1").fetchone()
    return {"ok": True, "database": "ok"}


@app.get("/auth/login")
def login():
    if not configured():
        raise HTTPException(503, "SSO client is not configured")
    discovery = get_json(ISSUER + "/.well-known/openid-configuration")
    if discovery.get("issuer") != ISSUER or discovery.get("authorization_endpoint") != ISSUER + "/authorize":
        raise HTTPException(503, "SSO discovery document is invalid")
    state, nonce = b64e(secrets.token_bytes(32)), b64e(secrets.token_bytes(32))
    verifier = b64e(secrets.token_bytes(48))
    challenge = b64e(hashlib.sha256(verifier.encode()).digest())
    flow = signed({"state": state, "nonce": nonce, "verifier": verifier, "exp": int(time.time()) + 600})
    params = urllib.parse.urlencode({"response_type": "code", "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI, "scope": "openid", "state": state, "nonce": nonce,
        "code_challenge": challenge, "code_challenge_method": "S256"})
    response = RedirectResponse(discovery["authorization_endpoint"] + "?" + params, status_code=303)
    response.set_cookie(FLOW_COOKIE, flow, max_age=600, path="/auth/callback", secure=True, httponly=True, samesite="lax")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/auth/callback")
def callback(request: Request, code: str = "", state: str = "", error: str = ""):
    flow = unsign(request.cookies.get(FLOW_COOKIE, ""))
    if error or not code or not flow or not hmac.compare_digest(state, str(flow.get("state", ""))):
        raise HTTPException(400, "SSO login could not be completed")
    try:
        token = get_json(ISSUER + "/token", {"grant_type": "authorization_code", "code": code,
            "redirect_uri": REDIRECT_URI, "code_verifier": flow["verifier"]}, basic=True)
        claims = verify_id_token(token.get("id_token", ""), flow["nonce"])
        session = get_json(ISSUER + "/session/introspect", {"sid": claims["sid"]}, basic=True)
        if session.get("active") is not True or int(session.get("expires_at", 0)) <= int(time.time()):
            raise ValueError("sso_session_inactive")
    except Exception as exc:
        raise HTTPException(401, "SSO authentication failed") from exc
    local = signed({"sub": claims["sub"], "sid": claims["sid"], "name": str(session.get("display_name") or "")[:120],
                    "csrf": b64e(secrets.token_bytes(24)), "exp": min(int(time.time()) + 1800, int(session["expires_at"]))})
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(SESSION_COOKIE, local, max_age=1800, path="/", secure=True, httponly=True, samesite="strict")
    response.delete_cookie(FLOW_COOKIE, path="/auth/callback", secure=True, httponly=True, samesite="lax")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/auth/logout")
def logout(request: Request):
    require_session(request, write=True)
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/me")
def me(request: Request):
    session = require_session(request)
    return {"sub": session["sub"], "name": session.get("name", ""), "csrf": session["csrf"]}


@app.get("/api/month")
def get_month(request: Request, year: int = Query(ge=2000, le=2100), month: int = Query(ge=1, le=12)):
    employee_id = require_session(request)["sub"]
    first = date(year, month, 1)
    last = date(year + (month == 12), month % 12 + 1, 1)
    with closing(connect()) as db:
        rows = db.execute("SELECT * FROM attendance WHERE employee_id=? AND work_date>=? AND work_date<? ORDER BY work_date", (employee_id, first.isoformat(), last.isoformat())).fetchall()
    return {"employee_id": employee_id, "year": year, "month": month, "entries": [dict(row) for row in rows]}


@app.put("/api/attendance")
def save_attendance(item: AttendanceInput, request: Request):
    employee_id = require_session(request, write=True)["sub"]
    if bool(item.start_time) != bool(item.end_time):
        raise HTTPException(422, "出勤と退勤は両方入力してください")
    if item.start_time and item.end_time:
        start = datetime.strptime(item.start_time, "%H:%M")
        end = datetime.strptime(item.end_time, "%H:%M")
        minutes = int((end-start).total_seconds() // 60)
        if minutes <= item.break_minutes:
            raise HTTPException(422, "休憩時間が勤務時間以上です")
    with closing(connect()) as db:
        db.execute("""INSERT INTO attendance(employee_id,work_date,start_time,end_time,break_minutes,task,updated_at)
          VALUES(?,?,?,?,?,?,?) ON CONFLICT(employee_id,work_date) DO UPDATE SET
          start_time=excluded.start_time,end_time=excluded.end_time,break_minutes=excluded.break_minutes,
          task=excluded.task,updated_at=excluded.updated_at""",
          (employee_id, item.work_date, item.start_time, item.end_time, item.break_minutes,
           item.task.strip(), datetime.now().astimezone().isoformat(timespec="seconds")))
        db.commit()
    return {"ok": True}


@app.delete("/api/attendance")
def clear_attendance(request: Request, work_date: str = Query()):
    employee_id = require_session(request, write=True)["sub"]
    try:
        date.fromisoformat(work_date)
    except ValueError as exc:
        raise HTTPException(422, "日付が不正です") from exc
    with closing(connect()) as db:
        db.execute("DELETE FROM attendance WHERE employee_id=? AND work_date=?", (employee_id, work_date))
        db.commit()
    return {"ok": True}


def month_rows(employee_id: str, year: int, month: int):
    first = date(year, month, 1).isoformat()
    last = date(year + (month == 12), month % 12 + 1, 1).isoformat()
    with closing(connect()) as db:
        return db.execute("SELECT * FROM attendance WHERE employee_id=? AND work_date>=? AND work_date<? ORDER BY work_date", (employee_id, first, last)).fetchall()


@app.get("/api/summary")
def summary(request: Request, year: int = Query(ge=2000, le=2100), month: int = Query(ge=1, le=12)):
    employee_id = require_session(request)["sub"]
    rows = month_rows(employee_id, year, month)
    issues, days, total_minutes = [], 0, 0
    for row in rows:
        if not row["start_time"] and not row["end_time"]:
            continue
        days += 1
        if not row["start_time"] or not row["end_time"]:
            issues.append({"date": row["work_date"], "message": "出勤または退勤が未入力"})
            continue
        start = datetime.strptime(row["start_time"], "%H:%M")
        end = datetime.strptime(row["end_time"], "%H:%M")
        mins = int((end-start).total_seconds() // 60) - row["break_minutes"]
        total_minutes += mins
        if mins <= 0:
            issues.append({"date": row["work_date"], "message": "休憩時間が勤務時間以上"})
        if not row["task"].strip():
            issues.append({"date": row["work_date"], "message": "作業内容が未入力"})
    return {"days": days, "hours": round(total_minutes / 60, 2), "over_8h_days": sum(1 for r in rows if r["start_time"] and r["end_time"] and (datetime.strptime(r["end_time"], "%H:%M")-datetime.strptime(r["start_time"], "%H:%M")).total_seconds()/60-r["break_minutes"]>480), "issues": issues}


@app.get("/api/export.csv")
def export_csv(request: Request, year: int = Query(ge=2000, le=2100), month: int = Query(ge=1, le=12)):
    employee_id = require_session(request)["sub"]
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["従業員ID", "日付", "出勤", "退勤", "休憩分", "実働時間", "作業内容"])
    for row in month_rows(employee_id, year, month):
        hours = ""
        if row["start_time"] and row["end_time"]:
            a = datetime.strptime(row["start_time"], "%H:%M")
            b = datetime.strptime(row["end_time"], "%H:%M")
            hours = round(((b-a).total_seconds()/60-row["break_minutes"])/60, 2)
        writer.writerow([row["employee_id"], row["work_date"], row["start_time"] or "", row["end_time"] or "", row["break_minutes"], hours, row["task"]])
    data = "\ufeff" + output.getvalue()
    filename = f"{year}年{month:02d}月_業務報告.csv"
    return StreamingResponse(iter([data]), media_type="text/csv; charset=utf-8", headers={"Content-Disposition": "attachment; filename*=UTF-8''" + urllib.parse.quote(filename)})


app.mount("/", StaticFiles(directory=ROOT / "static", html=True), name="static")
