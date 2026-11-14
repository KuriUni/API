"""Client for the TUTI administrator APIs.

An operator signs in with SSO (Passkey) once; the resulting admin session token
is sent as ``X-HA-Session``. The two endpoints used here are the same ones the
admin center and the desktop operations app use:

    POST {base}/license/admin_api.php           action=list_tenants / list_licenses
    POST {base}/license/ha/api-billing-admin.php action=tenants / list / get

No tenant API keys are involved: the administrator sees every tenant.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_BASE = "https://2415.jp"
TIMEOUT_SECONDS = 20.0

ADMIN_PATH = "/license/admin_api.php"
BILLING_PATH = "/license/ha/api-billing-admin.php"
SSO_PATH = "/license/admin_api.php"
SSO_QUERY = {"admin_sso_start": "1", "return_app": "desktop"}

LICENSE_STATUSES = ("", "active", "paused", "expired", "expiring", "revoked")
INVOICE_STATUSES = ("", "draft", "issued", "paid", "void")


class AdminApiError(Exception):
    """A failed admin API call with a machine-readable code."""

    def __init__(self, code: str, message: str, status: int = 0):
        super().__init__(message)
        self.code = code
        self.status = status

    @property
    def unauthenticated(self) -> bool:
        return self.status in (401, 403) or self.code in ("invalid_admin_session", "admin_scope_required")


def base_url(value: str = "") -> str:
    raw = (value or DEFAULT_BASE).strip().rstrip("/")
    if len(raw) > 300:
        raise ValueError("ベースURLが長すぎます")
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.query or parsed.fragment:
        raise ValueError("管理APIのベースURLは https:// で指定してください")
    if parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("http は localhost の検証用途に限られます")
    if parsed.username or parsed.password:
        raise ValueError("ベースURLに認証情報を含めないでください")
    return raw


def sso_url(base: str, desktop_redirect: str, desktop_state: str) -> str:
    """Build the admin SSO start URL for the desktop loopback flow."""
    if not desktop_redirect.startswith("http://127.0.0.1:"):
        raise ValueError("SSOのコールバックは 127.0.0.1 のみ許可されます")
    query = dict(SSO_QUERY)
    query.update({"desktop_redirect": desktop_redirect, "desktop_state": desktop_state})
    return f"{base}{SSO_PATH}?{urllib.parse.urlencode(query)}"


def _post(base: str, path: str, token: str, payload: dict) -> dict:
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        f"{base}{path}",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-HA-Session": token,
            "User-Agent": "TUTI-CRM-Admin/1.0",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            raw = response.read(2_000_000)
    except urllib.error.HTTPError as error:
        raise _error_for_http(error, payload.get("action", "")) from error
    except urllib.error.URLError as error:
        raise AdminApiError("network_error", f"管理APIに接続できません: {error.reason}") from error
    except TimeoutError as error:
        raise AdminApiError("timeout", "管理APIがタイムアウトしました") from error
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdminApiError("invalid_response", "管理APIの応答をJSONとして解釈できません") from error
    if not isinstance(data, dict):
        raise AdminApiError("invalid_response", "管理APIの応答形式が想定外です")
    if data.get("success") is False or data.get("ok") is False:
        raise AdminApiError(str(data.get("error") or "api_error"),
                            str(data.get("message") or data.get("error") or "管理APIがエラーを返しました"))
    return data


def _error_for_http(error: urllib.error.HTTPError, action: str) -> AdminApiError:
    hint = ""
    try:
        body = json.loads(error.read(200_000).decode("utf-8"))
        hint = str(body.get("message") or body.get("error") or "")
    except (ValueError, OSError, UnicodeDecodeError):
        body = None
    messages = {
        401: "管理者セッションが無効または期限切れです。SSOでログインし直してください",
        403: "この管理者アカウントに必要な権限がありません",
        404: "管理APIのエンドポイントが見つかりません",
    }
    message = messages.get(error.code, f"管理APIが HTTP {error.code} を返しました（{action}）")
    if hint and error.code not in messages:
        message = f"{message}: {hint}"
    return AdminApiError("http_error", message, error.code)


class AdminClient:
    def __init__(self, base: str, token: str):
        self.base = base_url(base)
        self._token = token

    # -- tenants -----------------------------------------------------------
    def tenants(self, page: int = 1, limit: int = 100) -> dict:
        data = _post(self.base, ADMIN_PATH, self._token, {"action": "list_tenants", "page": page, "limit": limit})
        rows = data.get("tenants")
        return {"items": rows if isinstance(rows, list) else [], "has_next": bool(data.get("has_next"))}

    # -- licenses ----------------------------------------------------------
    def licenses(self, page: int = 1, limit: int = 100, q: str = "", status: str = "",
                 tenant_id: int = 0, product_id: int = 0) -> dict:
        payload = {"action": "list_licenses", "page": page, "limit": limit}
        if q:
            payload["q"] = q
        if status in LICENSE_STATUSES and status:
            payload["status"] = status
        if tenant_id:
            payload["tenant_id"] = tenant_id
        if product_id:
            payload["product_id"] = product_id
        data = _post(self.base, ADMIN_PATH, self._token, payload)
        rows = data.get("licenses")
        return {"items": rows if isinstance(rows, list) else [], "has_next": bool(data.get("has_next")),
                "page": int(data.get("page") or page)}

    # -- invoices ----------------------------------------------------------
    def invoices(self, page: int = 1, limit: int = 100, q: str = "", status: str = "",
                 tenant_id: int = 0) -> dict:
        payload = {"action": "list", "page": page, "limit": limit}
        if q:
            payload["q"] = q
        if status in INVOICE_STATUSES and status:
            payload["status"] = status
        if tenant_id:
            payload["tenant_id"] = tenant_id
        data = _post(self.base, BILLING_PATH, self._token, payload)
        rows = data.get("invoices")
        summary = data.get("summary") if isinstance(data.get("summary"), dict) else {}
        return {"items": rows if isinstance(rows, list) else [], "has_next": bool(data.get("has_next")),
                "page": int(data.get("page") or page), "summary": summary}

    def invoice_tenants(self) -> list:
        data = _post(self.base, BILLING_PATH, self._token, {"action": "tenants"})
        rows = data.get("tenants")
        return rows if isinstance(rows, list) else []

    def invoice(self, invoice_id: int) -> dict:
        data = _post(self.base, BILLING_PATH, self._token, {"action": "get", "invoice_id": int(invoice_id)})
        invoice = data.get("invoice")
        return invoice if isinstance(invoice, dict) else {}

    def check(self) -> dict:
        """Cheap call used to verify the session."""
        return self.tenants(page=1, limit=1)
