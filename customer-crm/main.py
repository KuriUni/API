"""GINIE-style customer relationship management app (FastAPI + SQLite).

This is a self-contained MVP for companies, contacts, deals, activities and
tasks. It intentionally uses only the Python standard library plus FastAPI and
Pydantic so it can run in the same pinned environment as the existing
business-ops app.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
from contextlib import closing
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator

ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("CRM_DATA", ROOT / "data")).resolve()
DB_PATH = DATA_DIR / "customer-crm.sqlite3"
STATIC_DIR = ROOT / "static"

STAGES = ("リード", "初回接触", "提案", "交渉", "受注", "失注")
OPEN_STAGES = ("リード", "初回接触", "提案", "交渉")
INDUSTRIES = ("IT", "製造", "小売", "食品", "医療", "不動産", "物流", "建設", "教育", "サービス", "その他")
RANKS = ("S", "A", "B", "C")
ACTIVITY_KINDS = ("call", "email", "meeting", "visit", "note")
ACTIVITY_LABELS = {"call": "電話", "email": "メール", "meeting": "商談", "visit": "訪問", "note": "メモ"}
PRIORITIES = ("high", "medium", "low")
PRIORITY_LABELS = {"high": "高", "medium": "中", "low": "低"}

SESSION_COOKIE = "crm_session"
SESSION_TTL = 12 * 60 * 60

ADMIN_USER = os.environ.get("CRM_USER", "admin").strip() or "admin"
ADMIN_NAME = os.environ.get("CRM_NAME", "管理者").strip() or "管理者"
PASSWORD = os.environ.get("CRM_PASSWORD", "")
DEMO_MODE = not PASSWORD
if DEMO_MODE:
    PASSWORD = "demo"
SESSION_KEY = os.environ.get("CRM_SESSION_KEY", "")
if len(SESSION_KEY) < 32:
    SESSION_KEY = secrets.token_urlsafe(32)
COOKIE_SECURE = os.environ.get("CRM_SECURE_COOKIES", "0") == "1"
SEED_DEMO = os.environ.get("CRM_SEED", "1") != "0"

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


def initialize() -> None:
    with closing(connect()) as db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS companies (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          name_kana TEXT NOT NULL DEFAULT '',
          industry TEXT NOT NULL DEFAULT '',
          website TEXT NOT NULL DEFAULT '',
          phone TEXT NOT NULL DEFAULT '',
          address TEXT NOT NULL DEFAULT '',
          rank TEXT NOT NULL DEFAULT 'B' CHECK(rank IN ('S','A','B','C')),
          owner TEXT NOT NULL DEFAULT '',
          note TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS contacts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          title TEXT NOT NULL DEFAULT '',
          email TEXT NOT NULL DEFAULT '',
          phone TEXT NOT NULL DEFAULT '',
          mobile TEXT NOT NULL DEFAULT '',
          note TEXT NOT NULL DEFAULT '',
          is_primary INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS deals (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
          title TEXT NOT NULL,
          stage TEXT NOT NULL DEFAULT 'リード' CHECK(stage IN ('リード','初回接触','提案','交渉','受注','失注')),
          amount INTEGER NOT NULL DEFAULT 0 CHECK(amount >= 0),
          probability INTEGER NOT NULL DEFAULT 0 CHECK(probability BETWEEN 0 AND 100),
          expected_close TEXT NOT NULL DEFAULT '',
          owner TEXT NOT NULL DEFAULT '',
          note TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activities (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
          contact_id INTEGER REFERENCES contacts(id) ON DELETE SET NULL,
          deal_id INTEGER REFERENCES deals(id) ON DELETE SET NULL,
          kind TEXT NOT NULL DEFAULT 'note' CHECK(kind IN ('call','email','meeting','visit','note')),
          subject TEXT NOT NULL,
          body TEXT NOT NULL DEFAULT '',
          occurred_at TEXT NOT NULL,
          created_by TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          company_id INTEGER NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
          deal_id INTEGER REFERENCES deals(id) ON DELETE SET NULL,
          title TEXT NOT NULL,
          due_date TEXT NOT NULL DEFAULT '',
          priority TEXT NOT NULL DEFAULT 'medium' CHECK(priority IN ('high','medium','low')),
          status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open','done')),
          note TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL,
          completed_at TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS companies_name_idx ON companies(name);
        CREATE INDEX IF NOT EXISTS contacts_company_idx ON contacts(company_id);
        CREATE INDEX IF NOT EXISTS deals_company_idx ON deals(company_id);
        CREATE INDEX IF NOT EXISTS deals_stage_idx ON deals(stage);
        CREATE INDEX IF NOT EXISTS activities_company_idx ON activities(company_id, occurred_at);
        CREATE INDEX IF NOT EXISTS tasks_status_due_idx ON tasks(status, due_date);
        """)
        if SEED_DEMO and db.execute("SELECT COUNT(*) FROM companies").fetchone()[0] == 0:
            _seed(db)
        db.commit()


def _seed(db: sqlite3.Connection) -> None:
    today = date.today()

    def day(offset: int) -> str:
        return (today + timedelta(days=offset)).isoformat()

    def moment(days_ago: int, hour: int = 10) -> str:
        value = datetime.now().replace(hour=hour, minute=20, second=0, microsecond=0) - timedelta(days=days_ago)
        return value.isoformat(timespec="seconds")

    now = _now()
    companies = [
        ("株式会社ミライ商事", "ミライショウジ", "製造", "https://example.jp/mirai", "03-1234-5678", "東京都千代田区丸の内1-1-1", "S", "佐藤 健", "基幹システム刷新と保守を検討中。決裁者は取締役の山田氏。"),
        ("ネクストリンク株式会社", "ネクストリンク", "IT", "https://example.jp/nextlink", "03-2345-6789", "東京都渋谷区道玄坂2-2-2", "A", "鈴木 葵", "SaaS連携のPoCを実施。技術窓口は開発部の高橋氏。"),
        ("株式会社青葉フーズ", "アオバフーズ", "食品", "https://example.jp/aoba", "045-345-6789", "神奈川県横浜市中区山下町3-3", "B", "佐藤 健", "店舗POSの更新時期。まずは現場ヒアリングから。"),
        ("東都メディカル株式会社", "トウトメディカル", "医療", "", "03-4567-8901", "東京都新宿区西新宿4-4-4", "A", "田中 美咲", "電子カルテ連携のセキュリティ要件を確認中。"),
        ("株式会社グランデ不動産", "グランデフドウサン", "不動産", "https://example.jp/grande", "03-5678-9012", "東京都港区赤坂5-5-5", "B", "田中 美咲", "物件管理DXの提案中。複数拠点の展開を想定。"),
        ("北斗ロジスティクス", "ホクトロジスティクス", "物流", "", "052-678-9012", "愛知県名古屋市中村区名駅6-6-6", "C", "鈴木 葵", "配車システムは今回は見送り。次期予算で再検討。"),
        ("株式会社ソラノワ", "ソラノワ", "教育", "https://example.jp/soranowa", "06-7890-1234", "大阪府大阪市北区梅田7-7-7", "B", "佐藤 健", "学習管理システムを導入済み。追加機能の相談あり。"),
        ("みなと建設株式会社", "ミナトケンセツ", "建設", "", "092-890-1234", "福岡県福岡市博多区博多駅前8-8-8", "C", "田中 美咲", "現場管理アプリの初期検討。情報収集中。"),
    ]
    company_ids = []
    for row in companies:
        cur = db.execute(
            """INSERT INTO companies(name,name_kana,industry,website,phone,address,rank,owner,note,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            row + (now, now),
        )
        company_ids.append(cur.lastrowid)

    contacts = [
        (0, "山田 太郎", "取締役 情報システム部長", "taro.yamada@example.jp", "03-1234-5678", "090-1111-2222", "決裁者。月1回の定例あり。", 1),
        (0, "高橋 直樹", "情報システム部 課長", "naoki.takahashi@example.jp", "03-1234-5679", "", "実務窓口。要件確認を担当。", 0),
        (1, "高橋 直樹", "開発部 マネージャー", "takahashi@example.jp", "03-2345-6789", "090-2222-3333", "技術評価の窓口。", 1),
        (1, "中村 由美", "経営企画室", "yumi.nakamura@example.jp", "", "", "予算策定の担当。", 0),
        (2, "小林 修", "店舗運営部長", "osamu.kobayashi@example.jp", "045-345-6789", "090-3333-4444", "現場の意見をまとめている。", 1),
        (3, "松本 恵", "情報システム部長", "megumi.matsumoto@example.jp", "03-4567-8901", "", "セキュリティ審査の責任者。", 1),
        (3, "伊藤 翔", "医療情報室", "sho.ito@example.jp", "", "", "電子カルテベンダーとの調整役。", 0),
        (4, "渡辺 誠", "取締役 営業本部長", "makoto.watanabe@example.jp", "03-5678-9012", "090-4444-5555", "全社DXの推進担当。", 1),
        (5, "森 大地", "物流管理部", "daichi.mori@example.jp", "052-678-9012", "", "現場オペレーションの責任者。", 1),
        (6, "藤田 真由", "教務部長", "mayu.fujita@example.jp", "06-7890-1234", "", "学習管理の運用担当。", 1),
        (7, "石井 大輔", "現場監督", "daisuke.ishii@example.jp", "092-890-1234", "090-5555-6666", "現場の課題をヒアリング中。", 1),
    ]
    contact_ids = []
    for company_index, name, title, email, phone, mobile, note, primary in contacts:
        cur = db.execute(
            """INSERT INTO contacts(company_id,name,title,email,phone,mobile,note,is_primary,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (company_ids[company_index], name, title, email, phone, mobile, note, primary, now, now),
        )
        contact_ids.append(cur.lastrowid)

    deals = [
        (0, "基幹システム刷新", "提案", 3200000, 60, day(30), "佐藤 健", "現行システムのリプレース。見積提出済み。"),
        (0, "保守契約更新", "受注", 1200000, 100, day(-10), "佐藤 健", "年間保守の更新。"),
        (1, "CRM導入支援", "交渉", 2400000, 75, day(20), "鈴木 葵", "導入範囲とスケジュールを最終調整中。"),
        (1, "データ連携PoC", "初回接触", 800000, 30, day(45), "鈴木 葵", "API連携のPoC提案。"),
        (2, "店舗POS更新", "リード", 1500000, 20, day(60), "佐藤 健", "現場ヒアリング待ち。"),
        (3, "電子カルテ連携", "提案", 4800000, 55, day(40), "田中 美咲", "セキュリティ要件の回答を準備中。"),
        (4, "物件管理DX", "交渉", 3600000, 70, day(15), "田中 美咲", "複数拠点への展開を前提に提案。"),
        (5, "配車システム", "失注", 2000000, 0, day(-20), "鈴木 葵", "次期予算で再検討。"),
        (6, "学習管理システム追加機能", "受注", 1800000, 100, day(-5), "佐藤 健", "追加モジュールの受注。"),
        (7, "現場管理アプリ", "リード", 900000, 15, day(90), "田中 美咲", "情報収集段階。"),
    ]
    deal_ids = []
    for company_index, title, stage, amount, probability, expected, owner, note in deals:
        cur = db.execute(
            """INSERT INTO deals(company_id,title,stage,amount,probability,expected_close,owner,note,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (company_ids[company_index], title, stage, amount, probability, expected, owner, note, now, now),
        )
        deal_ids.append(cur.lastrowid)

    activities = [
        (0, 0, 0, "meeting", "基幹システム刷新 初回提案", "現行システムの課題をヒアリング。見積条件と導入スケジュールを来週提示する。", moment(2, 14), "佐藤 健"),
        (0, 1, 0, "email", "見積書を送付", "概算見積と導入スケジュールをメールで送付。", moment(1, 11), "佐藤 健"),
        (1, 2, 2, "meeting", "CRM導入支援 最終調整", "導入範囲を営業部門から全社へ拡大する方向で調整。", moment(1, 16), "鈴木 葵"),
        (1, 2, 3, "call", "PoC進捗確認", "API連携の検証環境を準備中。来週デモを実施。", moment(4, 10), "鈴木 葵"),
        (2, 4, 4, "visit", "店舗POS 現場ヒアリング", "店舗スタッフの運用課題を確認。年末商戦前の更新は難しそう。", moment(3, 15), "佐藤 健"),
        (3, 5, 5, "email", "セキュリティ要件回答", "電子カルテ連携のセキュリティチェックシートを返送。", moment(2, 9), "田中 美咲"),
        (4, 7, 6, "meeting", "物件管理DX 提案", "複数拠点の権限管理とレポート要件を確認。", moment(5, 13), "田中 美咲"),
        (5, 8, 7, "note", "配車システム 見送り", "今回は予算都合で見送り。次期予算で再提案する。", moment(8, 17), "鈴木 葵"),
        (6, 9, 8, "meeting", "追加機能 キックオフ", "追加モジュールの要件とリリース時期を合意。", moment(3, 11), "佐藤 健"),
        (7, 10, 9, "note", "現場管理アプリ 情報収集", "競合製品の情報を収集中。まずは課題整理から。", moment(6, 10), "田中 美咲"),
    ]
    for company_index, contact_index, deal_index, kind, subject, body, occurred, owner in activities:
        db.execute(
            """INSERT INTO activities(company_id,contact_id,deal_id,kind,subject,body,occurred_at,created_by,created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (company_ids[company_index], contact_ids[contact_index], deal_ids[deal_index], kind, subject, body, occurred, owner, occurred),
        )

    tasks = [
        (0, 0, "見積条件の最終確認", day(-2), "high", "open", "決裁者に確認する。"),
        (0, 0, "導入スケジュール案を送付", day(0), "high", "open", "来週の定例までに送る。"),
        (1, 2, "PoCデモの準備", day(1), "high", "open", "検証環境の接続確認。"),
        (1, 3, "API仕様書のレビュー", day(3), "medium", "open", "開発チームに確認。"),
        (3, 5, "セキュリティ審査の回答", day(-1), "high", "open", "チェックシートの追加項目。"),
        (4, 6, "拠点展開の見積もり", day(7), "medium", "open", ""),
        (6, None, "導入後フォローアップ", day(14), "low", "open", "利用状況を確認。"),
        (2, 4, "POS更新の社内稟議", day(10), "medium", "open", ""),
        (0, None, "初回提案の議事録共有", day(-5), "medium", "done", ""),
        (5, None, "次期予算の再提案", day(60), "low", "open", "次期予算のタイミングで連絡。"),
    ]
    for company_index, deal_index, title, due, priority, status, note in tasks:
        db.execute(
            """INSERT INTO tasks(company_id,deal_id,title,due_date,priority,status,note,created_at,completed_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (company_ids[company_index], deal_ids[deal_index] if deal_index is not None else None,
             title, due, priority, status, note, now, now if status == "done" else ""),
        )


# ---------------------------------------------------------------------------
# Validation models
# ---------------------------------------------------------------------------
class StrictModel(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")


def _iso_date(value: str) -> str:
    if value in (None, ""):
        return ""
    try:
        parsed = date.fromisoformat(str(value))
    except ValueError as exc:
        raise ValueError("日付はYYYY-MM-DDで指定してください") from exc
    if parsed.isoformat() != value:
        raise ValueError("日付はYYYY-MM-DDで指定してください")
    return value


def _iso_datetime(value: str) -> str:
    if value in (None, ""):
        return ""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("日時はYYYY-MM-DDTHH:MMで指定してください") from exc
    return parsed.replace(tzinfo=None, microsecond=0).isoformat(timespec="seconds")


class CompanyIn(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    name_kana: str = Field(default="", max_length=160)
    industry: str = Field(default="", max_length=40)
    website: str = Field(default="", max_length=300)
    phone: str = Field(default="", max_length=60)
    address: str = Field(default="", max_length=300)
    rank: Literal["S", "A", "B", "C"] = "B"
    owner: str = Field(default="", max_length=80)
    note: str = Field(default="", max_length=4000)

    @field_validator("website")
    @classmethod
    def website_https(cls, value: str) -> str:
        if value and not re.match(r"^https?://", value, re.I):
            raise ValueError("Webサイトはhttp://またはhttps://で指定してください")
        return value


class ContactIn(StrictModel):
    company_id: int = Field(gt=0)
    name: str = Field(min_length=1, max_length=120)
    title: str = Field(default="", max_length=120)
    email: str = Field(default="", max_length=200)
    phone: str = Field(default="", max_length=60)
    mobile: str = Field(default="", max_length=60)
    note: str = Field(default="", max_length=2000)
    is_primary: bool = False

    @field_validator("email")
    @classmethod
    def email_format(cls, value: str) -> str:
        if value and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
            raise ValueError("メールアドレスの形式が正しくありません")
        return value


class DealIn(StrictModel):
    company_id: int = Field(gt=0)
    title: str = Field(min_length=1, max_length=160)
    stage: Literal["リード", "初回接触", "提案", "交渉", "受注", "失注"] = "リード"
    amount: int = Field(default=0, ge=0, le=10**12)
    probability: int = Field(default=0, ge=0, le=100)
    expected_close: str = Field(default="", max_length=10)
    owner: str = Field(default="", max_length=80)
    note: str = Field(default="", max_length=4000)

    @field_validator("expected_close")
    @classmethod
    def expected_date(cls, value: str) -> str:
        return _iso_date(value)


class DealStageIn(StrictModel):
    stage: Literal["リード", "初回接触", "提案", "交渉", "受注", "失注"]


class ActivityIn(StrictModel):
    company_id: int = Field(gt=0)
    contact_id: Optional[int] = Field(default=None, gt=0)
    deal_id: Optional[int] = Field(default=None, gt=0)
    kind: Literal["call", "email", "meeting", "visit", "note"] = "note"
    subject: str = Field(min_length=1, max_length=200)
    body: str = Field(default="", max_length=4000)
    occurred_at: str = Field(default="", max_length=32)

    @field_validator("occurred_at")
    @classmethod
    def occurred(cls, value: str) -> str:
        return _iso_datetime(value)


class TaskIn(StrictModel):
    company_id: int = Field(gt=0)
    deal_id: Optional[int] = Field(default=None, gt=0)
    title: str = Field(min_length=1, max_length=200)
    due_date: str = Field(default="", max_length=10)
    priority: Literal["high", "medium", "low"] = "medium"
    status: Literal["open", "done"] = "open"
    note: str = Field(default="", max_length=2000)

    @field_validator("due_date")
    @classmethod
    def due(cls, value: str) -> str:
        return _iso_date(value)


class TaskPatch(StrictModel):
    status: Literal["open", "done"]


class LoginIn(StrictModel):
    username: str = Field(default="admin", max_length=80)
    password: str = Field(min_length=1, max_length=200)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _like(value: str) -> str:
    return "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _row(row: sqlite3.Row | None) -> Optional[dict]:
    return dict(row) if row is not None else None


def _page(total: int, page: int, limit: int) -> dict:
    pages = max(1, math.ceil(total / limit))
    page = min(max(1, page), pages)
    return {"total": total, "page": page, "pages": pages, "limit": limit, "offset": (page - 1) * limit}


def _company_exists(db: sqlite3.Connection, company_id: int) -> None:
    if db.execute("SELECT 1 FROM companies WHERE id=?", (company_id,)).fetchone() is None:
        raise HTTPException(404, "顧客が見つかりません")


def _contact_for_company(db: sqlite3.Connection, contact_id: Optional[int], company_id: int) -> None:
    if contact_id and db.execute("SELECT 1 FROM contacts WHERE id=? AND company_id=?", (contact_id, company_id)).fetchone() is None:
        raise HTTPException(422, "連絡先が選択した顧客に属していません")


def _deal_for_company(db: sqlite3.Connection, deal_id: Optional[int], company_id: int) -> None:
    if deal_id and db.execute("SELECT 1 FROM deals WHERE id=? AND company_id=?", (deal_id, company_id)).fetchone() is None:
        raise HTTPException(422, "案件が選択した顧客に属していません")


def _company_summary_sql() -> str:
    return """
      (SELECT COUNT(*) FROM contacts ct WHERE ct.company_id=c.id) AS contact_count,
      (SELECT COUNT(*) FROM deals d WHERE d.company_id=c.id AND d.stage IN ('リード','初回接触','提案','交渉')) AS open_deal_count,
      (SELECT COALESCE(SUM(d.amount),0) FROM deals d WHERE d.company_id=c.id AND d.stage IN ('リード','初回接触','提案','交渉')) AS pipeline_amount,
      (SELECT MAX(a.occurred_at) FROM activities a WHERE a.company_id=c.id) AS last_activity_at
    """


def _csv_response(rows: list[list[object]], headers: list[str], filename: str) -> StreamingResponse:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    data = "\ufeff" + output.getvalue()
    return StreamingResponse(
        iter([data]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename*=UTF-8''" + urllib.parse.quote(filename)},
    )


# ---------------------------------------------------------------------------
# Auth and pages
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
    if not hmac.compare_digest(payload.username.strip(), ADMIN_USER) or not hmac.compare_digest(payload.password, PASSWORD):
        _record_login_failure(remote)
        raise HTTPException(401, "ユーザー名またはパスワードが違います")
    _clear_login_failures(remote)
    token, csrf = _new_session()
    response = JSONResponse({"ok": True, "csrf": csrf})
    response.set_cookie(
        SESSION_COOKIE, token, max_age=SESSION_TTL, path="/", secure=COOKIE_SECURE,
        httponly=True, samesite="lax",
    )
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
# Dashboard and lookups
# ---------------------------------------------------------------------------
@app.get("/api/dashboard")
def dashboard(request: Request) -> dict:
    _require(request)
    today = _today()
    month = today[:7]
    with closing(connect()) as db:
        counts = db.execute("""
          SELECT
            (SELECT COUNT(*) FROM companies) AS companies,
            (SELECT COUNT(*) FROM contacts) AS contacts,
            (SELECT COUNT(*) FROM deals WHERE stage IN ('リード','初回接触','提案','交渉')) AS open_deals,
            (SELECT COALESCE(SUM(amount),0) FROM deals WHERE stage IN ('リード','初回接触','提案','交渉')) AS pipeline,
            (SELECT COUNT(*) FROM tasks WHERE status='open' AND due_date<>'' AND due_date<?) AS overdue_tasks,
            (SELECT COUNT(*) FROM tasks WHERE status='open' AND due_date=?) AS today_tasks,
            (SELECT COALESCE(SUM(amount),0) FROM deals WHERE stage='受注' AND substr(updated_at,1,7)=?) AS won_month
        """, (today, today, month)).fetchone()
        stage_rows = {row["stage"]: dict(row) for row in db.execute(
            "SELECT stage, COUNT(*) AS count, COALESCE(SUM(amount),0) AS amount FROM deals GROUP BY stage"
        ).fetchall()}
        stages = [
            {"stage": stage, "count": int(stage_rows.get(stage, {}).get("count", 0)),
             "amount": int(stage_rows.get(stage, {}).get("amount", 0))}
            for stage in STAGES
        ]
        tasks = [dict(row) for row in db.execute("""
          SELECT t.*, c.name AS company_name FROM tasks t JOIN companies c ON c.id=t.company_id
          WHERE t.status='open' ORDER BY CASE WHEN t.due_date='' THEN 1 ELSE 0 END, t.due_date, t.id LIMIT 6
        """).fetchall()]
        activities = [dict(row) for row in db.execute("""
          SELECT a.*, c.name AS company_name FROM activities a JOIN companies c ON c.id=a.company_id
          ORDER BY a.occurred_at DESC, a.id DESC LIMIT 7
        """).fetchall()]
        top = [dict(row) for row in db.execute("""
          SELECT c.id, c.name, COALESCE(SUM(d.amount),0) AS amount
          FROM companies c JOIN deals d ON d.company_id=c.id AND d.stage IN ('リード','初回接触','提案','交渉')
          GROUP BY c.id ORDER BY amount DESC, c.id LIMIT 5
        """).fetchall()]
    return {
        "today": today, "month": month, "counts": dict(counts), "stages": stages,
        "tasks": tasks, "activities": activities, "top_companies": top,
    }


@app.get("/api/lookups")
def lookups(request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        companies = [dict(row) for row in db.execute("SELECT id,name FROM companies ORDER BY name").fetchall()]
        contacts = [dict(row) for row in db.execute("SELECT id,company_id,name,title FROM contacts ORDER BY name").fetchall()]
        deals = [dict(row) for row in db.execute("SELECT id,company_id,title,stage FROM deals ORDER BY updated_at DESC").fetchall()]
    return {"companies": companies, "contacts": contacts, "deals": deals, "stages": list(STAGES),
            "industries": list(INDUSTRIES), "ranks": list(RANKS), "owners": []}


@app.get("/api/options")
def options(request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        rows = db.execute("SELECT owner FROM companies WHERE owner<>'' UNION SELECT owner FROM deals WHERE owner<>'' ORDER BY owner").fetchall()
    return {"owners": [row["owner"] for row in rows], "industries": list(INDUSTRIES),
            "ranks": list(RANKS), "stages": list(STAGES)}


# ---------------------------------------------------------------------------
# Companies
# ---------------------------------------------------------------------------
@app.get("/api/companies")
def list_companies(
    request: Request,
    q: str = "", industry: str = "", rank: str = "", owner: str = "",
    page: int = Query(1, ge=1), limit: int = Query(20, ge=1, le=100),
) -> dict:
    _require(request)
    where, params = ["1=1"], []
    if q:
        where.append("(c.name LIKE ? ESCAPE '\\' OR c.name_kana LIKE ? ESCAPE '\\' OR c.industry LIKE ? ESCAPE '\\' OR c.owner LIKE ? ESCAPE '\\' OR c.address LIKE ? ESCAPE '\\')")
        params += [_like(q)] * 5
    if industry:
        where.append("c.industry=?")
        params.append(industry)
    if rank:
        where.append("c.rank=?")
        params.append(rank)
    if owner:
        where.append("c.owner=?")
        params.append(owner)
    clause = " AND ".join(where)
    with closing(connect()) as db:
        total = db.execute(f"SELECT COUNT(*) FROM companies c WHERE {clause}", params).fetchone()[0]
        paging = _page(total, page, limit)
        rows = db.execute(
            f"SELECT c.*, {_company_summary_sql()} FROM companies c WHERE {clause} ORDER BY c.updated_at DESC, c.id DESC LIMIT ? OFFSET ?",
            params + [limit, paging["offset"]],
        ).fetchall()
    return {"items": [dict(row) for row in rows], "total": total, "page": paging["page"],
            "pages": paging["pages"], "limit": limit}


@app.get("/api/companies/{company_id}")
def get_company(company_id: int, request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        company = db.execute(f"SELECT c.*, {_company_summary_sql()} FROM companies c WHERE c.id=?", (company_id,)).fetchone()
        if not company:
            raise HTTPException(404, "顧客が見つかりません")
        contacts = [dict(row) for row in db.execute(
            "SELECT * FROM contacts WHERE company_id=? ORDER BY is_primary DESC, name", (company_id,)
        ).fetchall()]
        deals = [dict(row) for row in db.execute(
            "SELECT * FROM deals WHERE company_id=? ORDER BY updated_at DESC", (company_id,)
        ).fetchall()]
        activities = [dict(row) for row in db.execute("""
          SELECT a.*, ct.name AS contact_name, d.title AS deal_title
          FROM activities a LEFT JOIN contacts ct ON ct.id=a.contact_id LEFT JOIN deals d ON d.id=a.deal_id
          WHERE a.company_id=? ORDER BY a.occurred_at DESC, a.id DESC LIMIT 50
        """, (company_id,)).fetchall()]
        tasks = [dict(row) for row in db.execute(
            "SELECT * FROM tasks WHERE company_id=? ORDER BY status, due_date, id", (company_id,)
        ).fetchall()]
    return {"company": dict(company), "contacts": contacts, "deals": deals,
            "activities": activities, "tasks": tasks}


@app.post("/api/companies", status_code=201)
def create_company(payload: CompanyIn, request: Request) -> dict:
    _require(request, write=True)
    now = _now()
    with closing(connect()) as db:
        cur = db.execute(
            """INSERT INTO companies(name,name_kana,industry,website,phone,address,rank,owner,note,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (payload.name, payload.name_kana, payload.industry, payload.website, payload.phone,
             payload.address, payload.rank, payload.owner, payload.note, now, now),
        )
        db.commit()
        row = db.execute("SELECT * FROM companies WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


@app.put("/api/companies/{company_id}")
def update_company(company_id: int, payload: CompanyIn, request: Request) -> dict:
    _require(request, write=True)
    now = _now()
    with closing(connect()) as db:
        _company_exists(db, company_id)
        db.execute(
            """UPDATE companies SET name=?,name_kana=?,industry=?,website=?,phone=?,address=?,rank=?,owner=?,note=?,updated_at=?
               WHERE id=?""",
            (payload.name, payload.name_kana, payload.industry, payload.website, payload.phone,
             payload.address, payload.rank, payload.owner, payload.note, now, company_id),
        )
        db.commit()
        row = db.execute("SELECT * FROM companies WHERE id=?", (company_id,)).fetchone()
    return dict(row)


@app.delete("/api/companies/{company_id}")
def delete_company(company_id: int, request: Request) -> dict:
    _require(request, write=True)
    with closing(connect()) as db:
        cur = db.execute("DELETE FROM companies WHERE id=?", (company_id,))
        db.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "顧客が見つかりません")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Contacts
# ---------------------------------------------------------------------------
@app.get("/api/contacts")
def list_contacts(request: Request, q: str = "", company_id: Optional[int] = None,
                  page: int = Query(1, ge=1), limit: int = Query(100, ge=1, le=200)) -> dict:
    _require(request)
    where, params = ["1=1"], []
    if company_id:
        where.append("ct.company_id=?")
        params.append(company_id)
    if q:
        where.append("(ct.name LIKE ? ESCAPE '\\' OR ct.email LIKE ? ESCAPE '\\' OR ct.title LIKE ? ESCAPE '\\' OR c.name LIKE ? ESCAPE '\\')")
        params += [_like(q)] * 4
    clause = " AND ".join(where)
    with closing(connect()) as db:
        total = db.execute(f"SELECT COUNT(*) FROM contacts ct JOIN companies c ON c.id=ct.company_id WHERE {clause}", params).fetchone()[0]
        paging = _page(total, page, limit)
        rows = db.execute(f"""
          SELECT ct.*, c.name AS company_name FROM contacts ct JOIN companies c ON c.id=ct.company_id
          WHERE {clause} ORDER BY ct.is_primary DESC, ct.updated_at DESC, ct.id DESC LIMIT ? OFFSET ?
        """, params + [limit, paging["offset"]]).fetchall()
    return {"items": [dict(row) for row in rows], "total": total, "page": paging["page"],
            "pages": paging["pages"], "limit": limit}


@app.get("/api/contacts/{contact_id}")
def get_contact(contact_id: int, request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        row = db.execute("""
          SELECT ct.*, c.name AS company_name FROM contacts ct JOIN companies c ON c.id=ct.company_id
          WHERE ct.id=?
        """, (contact_id,)).fetchone()
    if not row:
        raise HTTPException(404, "連絡先が見つかりません")
    return dict(row)


@app.post("/api/contacts", status_code=201)
def create_contact(payload: ContactIn, request: Request) -> dict:
    _require(request, write=True)
    now = _now()
    with closing(connect()) as db:
        _company_exists(db, payload.company_id)
        cur = db.execute(
            """INSERT INTO contacts(company_id,name,title,email,phone,mobile,note,is_primary,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (payload.company_id, payload.name, payload.title, payload.email, payload.phone,
             payload.mobile, payload.note, int(payload.is_primary), now, now),
        )
        db.commit()
        row = db.execute("SELECT * FROM contacts WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


@app.put("/api/contacts/{contact_id}")
def update_contact(contact_id: int, payload: ContactIn, request: Request) -> dict:
    _require(request, write=True)
    now = _now()
    with closing(connect()) as db:
        _company_exists(db, payload.company_id)
        if db.execute("SELECT 1 FROM contacts WHERE id=?", (contact_id,)).fetchone() is None:
            raise HTTPException(404, "連絡先が見つかりません")
        db.execute(
            """UPDATE contacts SET company_id=?,name=?,title=?,email=?,phone=?,mobile=?,note=?,is_primary=?,updated_at=?
               WHERE id=?""",
            (payload.company_id, payload.name, payload.title, payload.email, payload.phone,
             payload.mobile, payload.note, int(payload.is_primary), now, contact_id),
        )
        db.commit()
        row = db.execute("SELECT * FROM contacts WHERE id=?", (contact_id,)).fetchone()
    return dict(row)


@app.delete("/api/contacts/{contact_id}")
def delete_contact(contact_id: int, request: Request) -> dict:
    _require(request, write=True)
    with closing(connect()) as db:
        cur = db.execute("DELETE FROM contacts WHERE id=?", (contact_id,))
        db.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "連絡先が見つかりません")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Deals
# ---------------------------------------------------------------------------
@app.get("/api/deals")
def list_deals(request: Request, q: str = "", stage: str = "", owner: str = "",
               company_id: Optional[int] = None) -> dict:
    _require(request)
    where, params = ["1=1"], []
    if q:
        where.append("(d.title LIKE ? ESCAPE '\\' OR c.name LIKE ? ESCAPE '\\' OR d.owner LIKE ? ESCAPE '\\')")
        params += [_like(q)] * 3
    if stage:
        where.append("d.stage=?")
        params.append(stage)
    if owner:
        where.append("d.owner=?")
        params.append(owner)
    if company_id:
        where.append("d.company_id=?")
        params.append(company_id)
    clause = " AND ".join(where)
    with closing(connect()) as db:
        rows = db.execute(f"""
          SELECT d.*, c.name AS company_name FROM deals d JOIN companies c ON c.id=d.company_id
          WHERE {clause} ORDER BY d.updated_at DESC, d.id DESC LIMIT 1000
        """, params).fetchall()
    return {"items": [dict(row) for row in rows], "stages": list(STAGES)}


@app.get("/api/deals/{deal_id}")
def get_deal(deal_id: int, request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        row = db.execute("""
          SELECT d.*, c.name AS company_name FROM deals d JOIN companies c ON c.id=d.company_id
          WHERE d.id=?
        """, (deal_id,)).fetchone()
    if not row:
        raise HTTPException(404, "案件が見つかりません")
    return dict(row)


@app.post("/api/deals", status_code=201)
def create_deal(payload: DealIn, request: Request) -> dict:
    _require(request, write=True)
    now = _now()
    with closing(connect()) as db:
        _company_exists(db, payload.company_id)
        cur = db.execute(
            """INSERT INTO deals(company_id,title,stage,amount,probability,expected_close,owner,note,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (payload.company_id, payload.title, payload.stage, payload.amount, payload.probability,
             payload.expected_close, payload.owner, payload.note, now, now),
        )
        db.commit()
        row = db.execute("SELECT * FROM deals WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


@app.put("/api/deals/{deal_id}")
def update_deal(deal_id: int, payload: DealIn, request: Request) -> dict:
    _require(request, write=True)
    now = _now()
    with closing(connect()) as db:
        _company_exists(db, payload.company_id)
        if db.execute("SELECT 1 FROM deals WHERE id=?", (deal_id,)).fetchone() is None:
            raise HTTPException(404, "案件が見つかりません")
        db.execute(
            """UPDATE deals SET company_id=?,title=?,stage=?,amount=?,probability=?,expected_close=?,owner=?,note=?,updated_at=?
               WHERE id=?""",
            (payload.company_id, payload.title, payload.stage, payload.amount, payload.probability,
             payload.expected_close, payload.owner, payload.note, now, deal_id),
        )
        db.commit()
        row = db.execute("SELECT * FROM deals WHERE id=?", (deal_id,)).fetchone()
    return dict(row)


@app.patch("/api/deals/{deal_id}/stage")
def move_deal(deal_id: int, payload: DealStageIn, request: Request) -> dict:
    _require(request, write=True)
    with closing(connect()) as db:
        if db.execute("SELECT 1 FROM deals WHERE id=?", (deal_id,)).fetchone() is None:
            raise HTTPException(404, "案件が見つかりません")
        probability = 100 if payload.stage == "受注" else (0 if payload.stage == "失注" else None)
        if probability is None:
            db.execute("UPDATE deals SET stage=?,updated_at=? WHERE id=?", (payload.stage, _now(), deal_id))
        else:
            db.execute("UPDATE deals SET stage=?,probability=?,updated_at=? WHERE id=?", (payload.stage, probability, _now(), deal_id))
        db.commit()
        row = db.execute("SELECT * FROM deals WHERE id=?", (deal_id,)).fetchone()
    return dict(row)


@app.delete("/api/deals/{deal_id}")
def delete_deal(deal_id: int, request: Request) -> dict:
    _require(request, write=True)
    with closing(connect()) as db:
        cur = db.execute("DELETE FROM deals WHERE id=?", (deal_id,))
        db.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "案件が見つかりません")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------
@app.get("/api/activities")
def list_activities(request: Request, q: str = "", kind: str = "", company_id: Optional[int] = None,
                    deal_id: Optional[int] = None, limit: int = Query(100, ge=1, le=300)) -> dict:
    _require(request)
    where, params = ["1=1"], []
    if q:
        where.append("(a.subject LIKE ? ESCAPE '\\' OR a.body LIKE ? ESCAPE '\\' OR c.name LIKE ? ESCAPE '\\')")
        params += [_like(q)] * 3
    if kind:
        where.append("a.kind=?")
        params.append(kind)
    if company_id:
        where.append("a.company_id=?")
        params.append(company_id)
    if deal_id:
        where.append("a.deal_id=?")
        params.append(deal_id)
    clause = " AND ".join(where)
    with closing(connect()) as db:
        rows = db.execute(f"""
          SELECT a.*, c.name AS company_name, ct.name AS contact_name, d.title AS deal_title
          FROM activities a JOIN companies c ON c.id=a.company_id
          LEFT JOIN contacts ct ON ct.id=a.contact_id LEFT JOIN deals d ON d.id=a.deal_id
          WHERE {clause} ORDER BY a.occurred_at DESC, a.id DESC LIMIT ?
        """, params + [limit]).fetchall()
    return {"items": [dict(row) for row in rows]}


@app.post("/api/activities", status_code=201)
def create_activity(payload: ActivityIn, request: Request) -> dict:
    session = _require(request, write=True)
    occurred = payload.occurred_at or _now()
    with closing(connect()) as db:
        _company_exists(db, payload.company_id)
        _contact_for_company(db, payload.contact_id, payload.company_id)
        _deal_for_company(db, payload.deal_id, payload.company_id)
        cur = db.execute(
            """INSERT INTO activities(company_id,contact_id,deal_id,kind,subject,body,occurred_at,created_by,created_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (payload.company_id, payload.contact_id, payload.deal_id, payload.kind, payload.subject,
             payload.body, occurred, session.get("name", ""), _now()),
        )
        db.commit()
        row = db.execute("SELECT * FROM activities WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


@app.delete("/api/activities/{activity_id}")
def delete_activity(activity_id: int, request: Request) -> dict:
    _require(request, write=True)
    with closing(connect()) as db:
        cur = db.execute("DELETE FROM activities WHERE id=?", (activity_id,))
        db.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "活動履歴が見つかりません")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------
@app.get("/api/tasks")
def list_tasks(request: Request, status: str = "open", q: str = "",
               company_id: Optional[int] = None) -> dict:
    _require(request)
    where, params = ["1=1"], []
    if status in ("open", "done"):
        where.append("t.status=?")
        params.append(status)
    if q:
        where.append("(t.title LIKE ? ESCAPE '\\' OR t.note LIKE ? ESCAPE '\\' OR c.name LIKE ? ESCAPE '\\')")
        params += [_like(q)] * 3
    if company_id:
        where.append("t.company_id=?")
        params.append(company_id)
    clause = " AND ".join(where)
    with closing(connect()) as db:
        rows = db.execute(f"""
          SELECT t.*, c.name AS company_name, d.title AS deal_title
          FROM tasks t JOIN companies c ON c.id=t.company_id LEFT JOIN deals d ON d.id=t.deal_id
          WHERE {clause} ORDER BY t.status, CASE WHEN t.due_date='' THEN 1 ELSE 0 END, t.due_date, t.id
        """, params).fetchall()
    return {"items": [dict(row) for row in rows]}


@app.get("/api/tasks/{task_id}")
def get_task(task_id: int, request: Request) -> dict:
    _require(request)
    with closing(connect()) as db:
        row = db.execute("""
          SELECT t.*, c.name AS company_name, d.title AS deal_title
          FROM tasks t JOIN companies c ON c.id=t.company_id LEFT JOIN deals d ON d.id=t.deal_id
          WHERE t.id=?
        """, (task_id,)).fetchone()
    if not row:
        raise HTTPException(404, "タスクが見つかりません")
    return dict(row)


@app.put("/api/tasks/{task_id}")
def update_task(task_id: int, payload: TaskIn, request: Request) -> dict:
    _require(request, write=True)
    with closing(connect()) as db:
        _company_exists(db, payload.company_id)
        _deal_for_company(db, payload.deal_id, payload.company_id)
        current = db.execute("SELECT status, completed_at FROM tasks WHERE id=?", (task_id,)).fetchone()
        if not current:
            raise HTTPException(404, "タスクが見つかりません")
        completed = current["completed_at"] or _now() if payload.status == "done" else ""
        db.execute("""
          UPDATE tasks SET company_id=?, deal_id=?, title=?, due_date=?, priority=?, status=?, note=?, completed_at=?
          WHERE id=?
        """, (payload.company_id, payload.deal_id, payload.title, payload.due_date, payload.priority,
              payload.status, payload.note, completed, task_id))
        db.commit()
        row = db.execute("""
          SELECT t.*, c.name AS company_name, d.title AS deal_title
          FROM tasks t JOIN companies c ON c.id=t.company_id LEFT JOIN deals d ON d.id=t.deal_id
          WHERE t.id=?
        """, (task_id,)).fetchone()
    return dict(row)


@app.post("/api/tasks", status_code=201)
def create_task(payload: TaskIn, request: Request) -> dict:
    _require(request, write=True)
    now = _now()
    with closing(connect()) as db:
        _company_exists(db, payload.company_id)
        _deal_for_company(db, payload.deal_id, payload.company_id)
        cur = db.execute(
            """INSERT INTO tasks(company_id,deal_id,title,due_date,priority,status,note,created_at,completed_at)
               VALUES(?,?,?,?,?,?,?,?,?)""",
            (payload.company_id, payload.deal_id, payload.title, payload.due_date, payload.priority,
             payload.status, payload.note, now, now if payload.status == "done" else ""),
        )
        db.commit()
        row = db.execute("SELECT * FROM tasks WHERE id=?", (cur.lastrowid,)).fetchone()
    return dict(row)


@app.patch("/api/tasks/{task_id}")
def patch_task(task_id: int, payload: TaskPatch, request: Request) -> dict:
    _require(request, write=True)
    with closing(connect()) as db:
        if db.execute("SELECT 1 FROM tasks WHERE id=?", (task_id,)).fetchone() is None:
            raise HTTPException(404, "タスクが見つかりません")
        db.execute("UPDATE tasks SET status=?, completed_at=? WHERE id=?",
                   (payload.status, _now() if payload.status == "done" else "", task_id))
        db.commit()
        row = db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    return dict(row)


@app.delete("/api/tasks/{task_id}")
def delete_task(task_id: int, request: Request) -> dict:
    _require(request, write=True)
    with closing(connect()) as db:
        cur = db.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        db.commit()
    if cur.rowcount == 0:
        raise HTTPException(404, "タスクが見つかりません")
    return {"ok": True}


# ---------------------------------------------------------------------------
# CSV exports
# ---------------------------------------------------------------------------
@app.get("/api/export/companies.csv")
def export_companies(request: Request):
    _require(request)
    with closing(connect()) as db:
        rows = db.execute(f"SELECT c.*, {_company_summary_sql()} FROM companies c ORDER BY c.name").fetchall()
    data = [[r["id"], r["name"], r["name_kana"], r["industry"], r["rank"], r["owner"], r["phone"],
             r["website"], r["address"], r["contact_count"], r["open_deal_count"],
             r["pipeline_amount"], r["last_activity_at"] or "", r["note"]] for r in rows]
    return _csv_response(data, ["ID", "顧客名", "カナ", "業種", "ランク", "担当", "電話", "Web", "住所",
                               "連絡先数", "進行中案件", "パイプライン", "最終活動", "メモ"],
                         "顧客一覧.csv")


@app.get("/api/export/deals.csv")
def export_deals(request: Request):
    _require(request)
    with closing(connect()) as db:
        rows = db.execute("""
          SELECT d.*, c.name AS company_name FROM deals d JOIN companies c ON c.id=d.company_id
          ORDER BY d.stage, d.expected_close, d.id
        """).fetchall()
    data = [[r["id"], r["company_name"], r["title"], r["stage"], r["amount"], r["probability"],
             r["expected_close"], r["owner"], r["note"]] for r in rows]
    return _csv_response(data, ["ID", "顧客", "案件", "ステージ", "金額", "確度", "完了予定", "担当", "メモ"],
                         "案件一覧.csv")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
