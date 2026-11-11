"""Same-origin relay from 2415.jp to the isolated Core Server Sunabar API."""
import urllib.error
import urllib.request
import sys
import uuid

from native_http import make_response


UPSTREAM = "https://suna.2415.jp/suna/api/"
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 1024 * 1024
ROUTES = {
    "issue_key": ("v1/key", "POST"),
    "products": ("v1/products", "GET"),
    "licenses": ("v1/licenses", "POST"),
    "license_list": ("v1/licenses/list", "GET"),
    "license_revoke": ("v1/licenses/revoke", "POST"),
    "verify": ("v1/verify", "POST"),
    "health": ("v1/healthz", "GET"),
    "activate": ("v1/activate", "POST"),
    "session_check": ("v1/session/check", "POST"),
    "session_refresh": ("v1/session/refresh", "POST"),
    "session_deactivate": ("v1/session/deactivate", "POST"),
    "v4_challenge": ("v4/challenge", "POST"),
    "v4_activate": ("v4/activate", "POST"),
    "v4_verify": ("v4/verify", "POST"),
    "v4_introspect": ("v4/introspect", "POST"),
    "v4_refresh": ("v4/refresh", "POST"),
    "v4_revoke": ("v4/revoke", "POST"),
    "v4_offline_public_key": ("v4/offline-public-key", "GET"),
    "v4_offline_ticket": ("v4/offline-ticket", "POST"),
    "v4_migrate": ("v4/migrate", "POST"),
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _json_error(status, code, message, request_id=None):
    import json
    request_id = request_id or uuid.uuid4().hex[:16]
    body = json.dumps({"ok": False, "error": code, "message": message, "request_id": request_id},
                      ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return make_response(body, status, [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Request-ID", request_id),
        ("Content-Length", str(len(body))),
    ])


def _relay(request, route_name):
    route = ROUTES[route_name]
    method = str(request.get("method", "GET")).upper()
    if method == "OPTIONS":
        # This relay is same-origin by design. Do not grant arbitrary sites
        # browser access to credential-bearing Sunabar requests.
        return make_response(b"", 204, [
            ("Cache-Control", "no-store"),
            ("Vary", "Origin"),
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
    if api_key:
        headers["X-Sunabar-API-Key"] = api_key[:8192]
    if authorization:
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
            # Never forward upstream CORS permissions through this same-origin
            # relay. Operational headers may be passed through.
            for name in ("Retry-After", "X-Request-ID"):
                value = upstream.headers.get(name)
                if value:
                    response_headers.append((name, value))
            return make_response(response_body, status, response_headers)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        request_id = uuid.uuid4().hex[:16]
        print("sunabar_relay_failed request_id=%s route=%s error_type=%s" %
              (request_id, route_name, type(exc).__name__), file=sys.stderr, flush=True)
        return _json_error(503, "sunabar_upstream_unavailable",
                           "The Sunabar Core Server is temporarily unavailable.", request_id)


def issue_key(request):
    return _relay(request, "issue_key")


def products(request):
    return _relay(request, "products")


def licenses(request):
    return _relay(request, "licenses")


def license_list(request):
    return _relay(request, "license_list")


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


def v4_challenge(request):
    return _relay(request, "v4_challenge")


def v4_activate(request):
    return _relay(request, "v4_activate")


def v4_verify(request):
    return _relay(request, "v4_verify")


def v4_introspect(request):
    return _relay(request, "v4_introspect")


def v4_refresh(request):
    return _relay(request, "v4_refresh")


def v4_revoke(request):
    return _relay(request, "v4_revoke")


def v4_offline_public_key(request):
    return _relay(request, "v4_offline_public_key")


def v4_offline_ticket(request):
    return _relay(request, "v4_offline_ticket")


def v4_migrate(request):
    return _relay(request, "v4_migrate")
