"""Same-origin relay from 2415.jp to the isolated Core Server Sunabar API."""
import urllib.error
import urllib.request

from native_http import make_response


UPSTREAM = "https://suna.2415.jp/suna/api/v1/"
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
ALLOWED_BROWSER_ORIGINS = {
    "https://2415.jp", "https://www.2415.jp", "https://backup.2415.jp",
    "https://main.2415.jp", "https://suna.2415.jp",
}
ROUTES = {
    "issue_key": ("key", "POST"),
    "revoke_key": ("key/revoke", "POST"),
    "products": ("products", "GET"),
    "create_product": ("products", "POST"),
    "deactivate_product": ("products/deactivate", "POST"),
    "licenses": ("licenses", "POST"),
    "license_list": ("licenses/list", "GET"),
    "audit_list": ("audit/list", "GET"),
    "license_revoke": ("licenses/revoke", "POST"),
    "verify": ("verify", "POST"),
    "health": ("healthz", "GET"),
    "activate": ("activate", "POST"),
    "session_check": ("session/check", "POST"),
    "session_refresh": ("session/refresh", "POST"),
    "session_deactivate": ("session/deactivate", "POST"),
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _json_error(status, code, message):
    import json
    body = json.dumps({"ok": False, "error": code, "message": message},
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return make_response(body, status, [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Content-Length", str(len(body))),
    ])


def _relay(request, route_name):
    route = ROUTES[route_name]
    method = str(request.get("method", "GET")).upper()
    if method == "OPTIONS":
        return make_response(b"", 204, [
            ("Cache-Control", "no-store"),
            ("Content-Length", "0"),
        ])
    if method != route[1]:
        return _json_error(405, "method_not_allowed", "Method not allowed for this Sunabar endpoint.")

    try:
        length = int(request.get("content_length") or 0)
    except (TypeError, ValueError):
        return _json_error(400, "invalid_content_length", "Invalid Content-Length.")
    if length < 0 or length > MAX_REQUEST_BYTES:
        return _json_error(413, "request_too_large", "The request exceeds the Sunabar relay limit.")

    origin = str(request.get("header:origin") or "").strip().rstrip("/")
    if origin and origin not in ALLOWED_BROWSER_ORIGINS:
        return _json_error(403, "origin_not_allowed", "This browser origin is not allowed to call the Sunabar emulator.")

    body = b""
    if method == "POST":
        stream = request.get("body_stream")
        body = stream.read(MAX_REQUEST_BYTES + 1) if stream is not None else b""
        if len(body) > MAX_REQUEST_BYTES:
            return _json_error(413, "request_too_large", "The request exceeds the Sunabar relay limit.")

    headers = {
        "Accept": "application/json",
        "User-Agent": "2415-Sunabar-Relay/1.0",
    }
    content_type = str(request.get("content_type") or request.get("header:content-type") or "")
    api_key = str(request.get("header:x-sunabar-api-key") or "").strip()
    authorization = str(request.get("header:authorization") or "").strip()
    if content_type:
        headers["Content-Type"] = content_type
    if origin:
        headers["Origin"] = origin
    if api_key:
        headers["X-Sunabar-API-Key"] = api_key[:8192]
    if authorization and not api_key:
        headers["Authorization"] = authorization[:8192]
    upstream_request = urllib.request.Request(
        UPSTREAM + route[0], data=body if method == "POST" else None,
        headers=headers, method=method,
    )
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        try:
            upstream = opener.open(upstream_request, timeout=8)
        except urllib.error.HTTPError as exc:
            upstream = exc
        with upstream:
            status = int(upstream.code)
            response_body = upstream.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                return _json_error(502, "upstream_response_too_large", "Sunabar returned an oversized response.")
            response_headers = [
                ("Content-Type", upstream.headers.get("Content-Type", "application/json; charset=utf-8")),
                ("Cache-Control", "no-store"),
                ("X-Content-Type-Options", "nosniff"),
                ("Content-Length", str(len(response_body))),
            ]
            for name in ("Retry-After",):
                value = upstream.headers.get(name)
                if value:
                    response_headers.append((name, value))
            return make_response(response_body, status, response_headers)
    except (urllib.error.URLError, TimeoutError, OSError):
        return _json_error(503, "sunabar_upstream_unavailable",
                           "The Sunabar Core Server is temporarily unavailable.")


def issue_key(request):
    return _relay(request, "issue_key")


def revoke_key(request):
    return _relay(request, "revoke_key")


def products(request):
    route = "create_product" if str(request.get("method", "GET")).upper() == "POST" else "products"
    return _relay(request, route)


def deactivate_product(request):
    return _relay(request, "deactivate_product")


def licenses(request):
    return _relay(request, "licenses")


def license_list(request):
    return _relay(request, "license_list")


def audit_list(request):
    return _relay(request, "audit_list")


def license_revoke(request):
    return _relay(request, "license_revoke")


def verify(request):
    return _relay(request, "verify")


def health(request):
    return _relay(request, "health")


def activate(request):
    return _relay(request, "activate")


def session_check(request):
    return _relay(request, "session_check")


def session_refresh(request):
    return _relay(request, "session_refresh")


def session_deactivate(request):
    return _relay(request, "session_deactivate")
