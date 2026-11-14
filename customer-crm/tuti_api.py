"""TUTI BaaS API client (tenant-scoped, read-only).

Every CRM record ("顧客") is one TUTI tenant with its own tenant API key.
Requests go to ``/api/baas/v1/service.php`` with an ``X-Tenant-API-Key``
header, which is the supported machine-to-machine path of the license API.

Only read services are implemented: the CRM never issues, pauses or deletes
licenses.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

DEFAULT_BASE = "https://2415.jp"
TIMEOUT_SECONDS = 12.0
MAX_LIMIT = 200

SCOPES = ("status", "products", "licenses", "usage", "invoices", "audit")

_SCOPE_REQUESTS = {
    "status": ("service.status", {}),
    "products": ("products.list", {"limit": 50}),
    "licenses": ("licenses.list", {"limit": MAX_LIMIT}),
    "usage": ("usage.summary", {}),
    "invoices": ("billing.invoices", {}),
    "audit": ("audit.list", {"limit": 25}),
}


class TutiApiError(Exception):
    """A failed API call with a machine-readable code for the UI."""

    def __init__(self, code: str, message: str, status: int = 0):
        super().__init__(message)
        self.code = code
        self.status = status

    def as_dict(self) -> dict:
        return {"code": self.code, "message": str(self), "status": self.status}


def _error_for_http(error: urllib.error.HTTPError, service: str) -> TutiApiError:
    code = "http_error"
    message = f"TUTI API が HTTP {error.code} を返しました（{service}）"
    try:
        body = json.loads(error.read(100_000).decode("utf-8"))
    except (ValueError, OSError, UnicodeDecodeError):
        body = None
    if isinstance(body, dict):
        code = str(body.get("error") or code)
        message = str(body.get("message") or message)
    hints = {
        401: "APIキーが無効か期限切れです",
        403: "APIキーに必要なスコープがありません",
        410: "テナントポータルのセッション方式は廃止されました",
        429: "レート制限に達しました。少し待って再試行してください",
    }
    if error.code in hints:
        message = f"{hints[error.code]}（HTTP {error.code}）"
    return TutiApiError(code, message, error.code)


class TutiClient:
    """Read-only client for one tenant API key."""

    def __init__(self, base_url: str, api_key: str, environment: str = ""):
        self.base_url = (base_url or DEFAULT_BASE).rstrip("/")
        self._api_key = api_key
        self.environment = environment if environment in ("sandbox", "production") else ""

    def _get(self, service: str, params: Optional[dict] = None) -> dict:
        query = {key: value for key, value in dict(params or {}).items() if value not in (None, "")}
        query["service"] = service
        url = f"{self.base_url}/api/baas/v1/service.php?{urllib.parse.urlencode(query)}"
        headers = {
            "Accept": "application/json",
            "X-Tenant-API-Key": self._api_key,
            "User-Agent": "TUTI-CRM/2.0",
        }
        if self.environment:
            headers["X-BaaS-Environment"] = self.environment
        request = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
                raw = response.read(1_000_000)
        except urllib.error.HTTPError as error:
            raise _error_for_http(error, service) from error
        except urllib.error.URLError as error:
            raise TutiApiError("network_error", f"TUTI API に接続できません（{service}）: {error.reason}") from error
        except TimeoutError as error:
            raise TutiApiError("timeout", f"TUTI API がタイムアウトしました（{service}）") from error
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TutiApiError("invalid_response", f"TUTI API の応答をJSONとして解釈できません（{service}）") from error
        if not isinstance(payload, dict):
            raise TutiApiError("invalid_response", f"TUTI API の応答形式が想定外です（{service}）")
        if payload.get("ok") is False:
            raise TutiApiError(
                str(payload.get("error") or "api_error"),
                str(payload.get("message") or payload.get("error") or "TUTI API がエラーを返しました"),
            )
        return payload

    def fetch(self, scope: str, period: str = "") -> dict:
        service, params = _SCOPE_REQUESTS[scope]
        params = dict(params)
        if scope in ("usage", "invoices") and period:
            params["period"] = period
        return self._get(service, params)

    def fetch_many(self, period: str = "") -> dict:
        """Fetch every scope, collecting per-scope failures instead of aborting."""
        results: dict = {}
        for scope in SCOPES:
            try:
                results[scope] = {"ok": True, "payload": self.fetch(scope, period), "error": "", "code": ""}
            except TutiApiError as error:
                results[scope] = {"ok": False, "payload": None, "error": str(error), "code": error.code}
        return results


def normalize_base_url(value: str) -> str:
    """Validate a customer base URL. Plain HTTP is only allowed for loopback hosts."""
    raw = (value or "").strip().rstrip("/")
    if not raw:
        return DEFAULT_BASE
    if len(raw) > 300:
        raise ValueError("ベースURLが長すぎます")
    if "@" in raw.split("://", 1)[-1]:
        raise ValueError("ベースURLに認証情報を含めないでください")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("ベースURLは http:// または https:// で指定してください")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("https 以外は localhost でのみ許可されます")
    if parsed.query or parsed.fragment:
        raise ValueError("ベースURLにクエリやフラグメントは指定できません")
    return raw


def summarize_client_keys(payload: Any) -> dict:
    """Defensive helpers shared by the UI payloads."""
    if not isinstance(payload, dict):
        return {}
    return payload
