"""TUTI BaaS API client for the CRM.

Talks to the tenant-scoped BaaS API (``/api/baas/v1/service.php``) that the
license platform exposes. Everything here is read-only and uses the same
authentication a tenant integration would use: an ``X-Tenant-API-Key`` header
carrying a ``baas_*`` key.

Configuration is environment only; keys never live in the repository.

    TUTI_API_BASE   default https://2415.jp
    TUTI_API_KEY    baas_live_... / baas_sandbox_...
    TUTI_API_ENV    optional: sandbox | production
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

DEFAULT_BASE = "https://2415.jp"
TIMEOUT_SECONDS = 10.0
MAX_LIMIT = 200


class TutiApiError(Exception):
    """A failed BaaS API call with a machine-readable code for the UI."""

    def __init__(self, code: str, message: str, status: int = 0):
        super().__init__(message)
        self.code = code
        self.status = status

    def as_dict(self) -> dict:
        return {"code": self.code, "message": str(self), "status": self.status}


def api_base() -> str:
    return (os.environ.get("TUTI_API_BASE") or DEFAULT_BASE).rstrip("/")


def api_key() -> str:
    return (os.environ.get("TUTI_API_KEY") or "").strip()


def api_environment() -> str:
    value = (os.environ.get("TUTI_API_ENV") or "").strip().lower()
    return value if value in ("sandbox", "production") else ""


def configured() -> bool:
    return bool(api_key())


def describe() -> dict:
    """Non-secret configuration summary for the UI."""
    key = api_key()
    return {
        "configured": bool(key),
        "base": api_base(),
        "environment": api_environment() or "auto",
        "key_hint": (key[:13] + "…") if len(key) > 13 else "",
    }


def _clamp_limit(limit: Any, default: int = 50) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return default
    return max(1, min(MAX_LIMIT, value))


def _request(service: str, params: Optional[dict] = None) -> dict:
    key = api_key()
    if not key:
        raise TutiApiError("not_configured", "TUTI_API_KEY が未設定です")
    query = dict(params or {})
    query["service"] = service
    clean = {k: v for k, v in query.items() if v not in (None, "")}
    url = f"{api_base()}/api/baas/v1/service.php?{urllib.parse.urlencode(clean)}"
    headers = {
        "Accept": "application/json",
        "X-Tenant-API-Key": key,
        "User-Agent": "TUTI-CRM/1.0",
    }
    environment = api_environment()
    if environment:
        headers["X-BaaS-Environment"] = environment
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(1_000_000)
    except urllib.error.HTTPError as error:
        raise _http_error(error, service) from error
    except urllib.error.URLError as error:
        raise TutiApiError("network_error", f"TUTI API に接続できません（{service}）: {error.reason}") from error
    except TimeoutError as error:
        raise TutiApiError("timeout", f"TUTI API がタイムアウトしました（{service}）") from error
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TutiApiError("invalid_response", f"TUTI API の応答をJSONとして解釈できません（{service}）") from error
    if isinstance(payload, dict) and payload.get("ok") is False:
        raise TutiApiError(
            str(payload.get("error") or "api_error"),
            str(payload.get("message") or payload.get("error") or "TUTI API がエラーを返しました"),
            200,
        )
    if not isinstance(payload, dict):
        raise TutiApiError("invalid_response", f"TUTI API の応答形式が想定外です（{service}）")
    return payload


def _http_error(error: urllib.error.HTTPError, service: str) -> TutiApiError:
    code = "http_error"
    message = f"TUTI API が HTTP {error.code} を返しました（{service}）"
    try:
        body = json.loads(error.read(100_000).decode("utf-8"))
    except (ValueError, OSError, UnicodeDecodeError):
        body = None
    if isinstance(body, dict):
        code = str(body.get("error") or code)
        message = str(body.get("message") or message)
    mapping = {
        401: "APIキーが無効か期限切れです",
        403: "APIキーに必要なスコープがありません",
        410: "テナントポータルのセッション方式は廃止されました",
        429: "レート制限に達しました。少し待って再試行してください",
    }
    if error.code in mapping:
        message = f"{mapping[error.code]}（HTTP {error.code}）"
    return TutiApiError(code, message, error.code)


# --------------------------------------------------------------------------
# Read operations used by the CRM
# --------------------------------------------------------------------------
def status() -> dict:
    return _request("service.status")


def products(limit: int = 50, search: str = "") -> dict:
    return _request("products.list", {"limit": _clamp_limit(limit), "search": search})


def licenses(limit: int = 50, search: str = "", product_id: Any = None) -> dict:
    return _request("licenses.list", {
        "limit": _clamp_limit(limit), "search": search, "product_id": product_id,
    })


def usage(period: str = "") -> dict:
    return _request("usage.summary", {"period": period})


def invoices(period: str = "") -> dict:
    return _request("billing.invoices", {"period": period})


def audit(limit: int = 25) -> dict:
    return _request("audit.list", {"limit": _clamp_limit(limit, 25)})


def identity_info() -> dict:
    return _request("identity.info")
