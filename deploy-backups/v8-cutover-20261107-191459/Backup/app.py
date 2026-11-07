"""Isolated Python migration scaffold for the BaaS public API.

This deliberately does not proxy to or import the production PHP application.
Inventoried routes dispatch to Python handlers with the migration status tracked
in PORTED_ROUTES and PARTIALLY_PORTED_ROUTES.
"""
import json
import hashlib
import mimetypes
import os
import sys
import uuid
from pathlib import Path
from typing import Set
from wsgiref.simple_server import make_server
from deployment_settings import site_url

ROOT = Path(__file__).resolve().parent
ROUTE_FILE = ROOT / "routes.json"
SITE_ROOT = ROOT / "site"
RELEASE_MANIFEST_PATH = ROOT / "release-manifest.json"


def load_routes() -> Set[str]:
    data = json.loads(ROUTE_FILE.read_text(encoding="utf-8"))
    return {entry["path"] for entry in data["routes"]}


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


ROUTES = load_routes()
PORTED_ROUTES = {
    "/api/sunabar/v1/key.php", "/api/sunabar/v1/products.php",
    "/api/sunabar/v1/licenses.php", "/api/sunabar/v1/verify.php",
    "/api/sunabar/v1/health.php", "/api/sunabar/v1/license-list.php",
    "/api/sunabar/v1/license-revoke.php", "/api/sunabar/v1/activate.php",
    "/api/sunabar/v1/session-check.php", "/api/sunabar/v1/session-refresh.php",
    "/api/sunabar/v1/session-deactivate.php",
    "/api/baas/issuance-session.php", "/api/baas/v1/billing-policy.php",
    "/api/baas/v1/common-id-sso/constants.php",
    "/api/baas/v1/common-id-sso/http.php",
    "/api/baas/v1/common-id-sso/clients.php",
    "/api/baas/v1/common-id-sso/identity.php",
    "/api/baas/v1/common-id-sso/signing.php",
    "/api/baas/v1/common-id-sso/authorization-code.php",
    "/api/baas/v1/common-id-sso/support.php",
    "/api/v3/challenge.php", "/api/v3/offline-public-key.php",
    "/api/v3/core.php",
    "/api/v3/reauth.php", "/api/v3/activate.php",
    "/api/v3/verify.php", "/api/v3/introspect.php", "/api/v3/revoke.php",
    "/api/v3/refresh.php", "/api/v3/offline-ticket.php",
    "/api/v3/index.php",
    "/api/v2/core.php", "/api/v2/reissue.php", "/api/v2/activate.php", "/api/activate.php",
    "/admin_api/core/input.php", "/admin_api/core/payloads.php",
    "/api/baas/v1/status.php", "/api/baas/v1/products.php", "/api/baas/v1/licenses.php",
    "/api/baas/v1/webhooks.php",
    "/api/baas/v1/audit.php",
    "/api/baas/v1/licenses-bulk-delete.php",
    "/api/baas/v1/billing.php", "/api/baas/v1/invoices.php",
    "/api/baas/v1/batch.php", "/ha/health.php",
    "/api/baas/v7/issuance.php",
    "/api/baas/v1/export.php",
    "/ha/audit-recent.php", "/ha/audit-verify.php",
    "/ha/status.php",
    "/ha/retention.php",
    "/ha/license-lookup.php",
    "/ha/offline-key.php",
    "/api/baas/v1/jpki.php",
    "/api/baas/v1/tenant-sso.php",
    "/api/baas/auto/assess.php",
    "/ha/release.php",
    "/api/activate.php",
    "/api/baas/benchmark/cleanup.php",
    "/license/api/v3/activate.php", "/license/api/v3/challenge.php",
    "/license/api/v3/index.php", "/license/api/v3/introspect.php",
    "/license/api/v3/offline-public-key.php", "/license/api/v3/offline-ticket.php",
    "/license/api/v3/reauth.php", "/license/api/v3/refresh.php",
    "/license/api/v3/revoke.php", "/license/api/v3/verify.php",
    "/license/api/v2/activate.php",
    "/ha/passkey.php", "/ha/passkey-callback.php", "/ha/passkey-ha-callback.php",
    "/ha/passkey-keyadmin-callback.php",
    "/ha/android-card-read.php",
    "/ha/mobile-face.php",
    "/ha/web-passkey-auth.php",
    "/ha/snapshot-codec.php",
    "/ha/passkey-federation-lib.php",
    "/ha/passkey-federation/state.php",
    "/ha/passkey-federation/transport.php",
    "/ha/passkey-federation/identity.php",
    "/ha/passkey-federation/replication.php",
    "/api/baas/v1/common-id-sso/authorize.php",
    "/api/baas/v1/common-id-sso/dispatch.php",
    "/api/baas/v1/common-id-sso/metadata.php",
    "/api/baas/v1/common-id-sso/token.php",
    "/api/baas/v1/common-id-sso/userinfo.php",
    "/common-id-sso-demo/common.php",
    "/common-id-sso-demo/index.php",
    "/common-id-sso-demo/login.php",
    "/common-id-sso-demo/callback.php",
    "/common-id-sso-demo/logout.php",
    "/api/baas/v1/core.php", "/api/baas/v1/portal-key-policy.php",
    "/api/baas/v1/sample-sdk-lib.php", "/api/baas/v4/lib.php",
    "/api/baas/v5/lib.php", "/api/baas/v6/lib.php",
    "/api/baas/v6/legacy-gateway.php",
    "/api/baas/v1/service.php",
    "/api/baas/v2/licenses.php", "/api/baas/v3/licenses.php",
    "/api/baas/v4/issuance-jobs.php", "/api/baas/v4/issuance-results.php",
    "/api/baas/v4/issuance-cancel.php", "/api/baas/v5/issuance.php",
    "/api/baas/v5/issuance-results.php", "/api/baas/v5/issuance-cancel.php",
    "/api/baas/v6/issuance.php", "/api/baas/v6/issuance-results.php",
    "/api/baas/v6/issuance-cancel.php",
    "/api/baas/v8/issuance.php", "/api/baas/v8/issuance-results.php",
    "/api/baas/v8/issuance-cancel.php",
    "/api/baas/v1/common-id-sso.php",
    "/api/phone_activate.php", "/phone_activate.php",
    "/api/baas/v1/mnsl.php",
    "/api/baas/v1/mnsl-card-auth.php",
    "/api/baas/v1/mnsl-android-card-read.php",
    "/api/baas/v1/portal-passkey.php",
    "/api/baas/v1/sandbox-keys.php",
    "/api/baas/v1/sample-sdk-keys.php",
    "/api/baas/v1/sample-sdk-activate.php",
    "/ha/bootstrap.php",
}
PARTIALLY_PORTED_ROUTES = {
    "/ha/passkey_api.php",
    "/ha/passkey-federation.php",
    "/ha/web-passkey-manage.php",
    "/api/v2/phone_activate.php",
    "/ha/export.php",
    "/ha/restore-test.php",
    "/ha/import.php",
    "/ha/sync.php",
    "/ha/retry-sync.php",
    "/ha/failback-operation.php",
    "/ha/api-billing-admin.php",
    "/ha/migrate.php",
    "/ha/offline-phone.php",
    "/mobile-manager/admin-auth.php",
    "/admin_api.php",
    "/generate_key.php",
    "/ha/webhook-dispatch.php",
    "/ha/mode.php",
    "/ha/phone-admin.php",
    "/ha/issue-license.php",
    "/ha/issue-license-v2.php",
    "/ha/issue-license-v3.php",
    "/ha/product-key-v4-worker.php", "/ha/product-key-v5-worker.php",
    "/ha/product-key-v8-worker.php",
    "/ha/license-admin.php",
    "/ha/tenant-admin.php",
}
PORTED_ADMIN_ACTION_INCLUDES = {
    "/admin_api/actions/audit.php",
    "/admin_api/actions/common_id.php",
    "/admin_api/actions/devices.php",
    "/admin_api/actions/phone.php",
    "/admin_api/actions/license.php",
    "/admin_api/actions/reception.php",
    "/admin_api/actions/tenant.php",
    "/admin_api/bootstrap.php",
    "/admin_api/core/auth.php",
    "/admin_api/core/logs.php",
    "/admin_api/core/oidc-sso.php",
    "/admin_api/core/reception-catalog.php",
    "/admin_api/views/bootstrap.php",
    "/admin_api/views/dashboard.php",
    "/admin_api/views/devices.php",
    "/admin_api/views/invoices.php",
    "/admin_api/views/licenses.php",
    "/admin_api/views/phone_requests.php",
    "/admin_api/views/reception.php",
    "/admin_api/views/sessions.php",
    "/admin_api/views/shell.php",
}
PORTED_ROUTES.update(PORTED_ADMIN_ACTION_INCLUDES)
PORTED_ADMIN_EMPTY_INCLUDES = {"/admin_api/core/settings.php"}
PORTED_ROUTES.update(PORTED_ADMIN_EMPTY_INCLUDES)

# Route counts reflect the current canonical public tree. Changed source
# contracts remain partial until their regression/parity gates are complete.
PORTED_ROUTES.intersection_update(ROUTES)
PORTED_ROUTES.add('/api-catalog/index.php')
PARTIALLY_PORTED_ROUTES.intersection_update(ROUTES)
PORTED_ROUTES.update({'/ha/maintenance-response.php', '/api/baas/v1/tenant-sso-session.php', '/error.php', '/maintenance.php', '/ha/maintenance-page.php', '/ha/http-error.php', '/ha/error-page.php', '/api/baas/v1/tenant-sso-contracts.php', '/ha/card-result.php'})
REVIEW_REQUIRED_ROUTES = {'/admin_api/views/sessions.php', '/api/baas/v1/sandbox-keys.php', '/admin_api.php', '/admin_api/views/reception.php', '/admin_api/views/invoices.php', '/admin_api/views/phone_requests.php', '/admin_api/actions/license.php', '/mobile-manager/admin-auth.php', '/admin_api/core/oidc-sso.php', '/admin_api/views/shell.php', '/api/v2/phone_activate.php', '/ha/web-passkey-auth.php', '/admin_api/core/logs.php', '/ha/mobile-face.php', '/admin_api/views/licenses.php', '/admin_api/core/auth.php', '/api/v2/activate.php', '/generate_key.php', '/ha/bootstrap.php', '/admin_api/actions/common_id.php', '/admin_api/views/dashboard.php', '/admin_api/views/devices.php', '/common-id-sso-demo/index.php'}
PORTED_ROUTES.difference_update(REVIEW_REQUIRED_ROUTES)
PARTIALLY_PORTED_ROUTES.update(REVIEW_REQUIRED_ROUTES)

try:
    from http_utils import json_response
except ImportError:  # Keep static portal serving usable if a partial package is copied.
    json_response = None


def _response(start_response, status: str, payload: dict):
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    start_response(status, [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Content-Length", str(len(body))),
    ])
    return [body]


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    if path == '/api-catalog/index.php':
        from native_routes import catalog_page
        from native_http import legacy_to_context, to_wsgi
        return to_wsgi(catalog_page(legacy_to_context(environ)), start_response)
    from wsgi_input import ContentLengthInput
    if environ.get('wsgi.input') is not None and not isinstance(environ['wsgi.input'], ContentLengthInput):
        try:
            length = int(environ.get('CONTENT_LENGTH') or 0)
            if length < 0:
                raise ValueError()
        except (ValueError, TypeError):
            return json_response(start_response, '400 Bad Request', {'ok':False,'error':'invalid_content_length'})
        if length > 50 * 1024 * 1024:
            return json_response(start_response, '413 Content Too Large', {'ok':False,'error':'request_too_large'})
        environ = dict(environ, **{'wsgi.input': ContentLengthInput(environ['wsgi.input'], length)})
    from http_error_handlers import (MAINTENANCE_ALLOWED, is_maintenance,
                                     maintenance_response, error_page, error_status)
    if is_maintenance() and path not in MAINTENANCE_ALLOWED:
        return maintenance_response(environ, start_response)
    if path.startswith('/api/baas/v1/common-id-sso/'):
        return error_page(environ, start_response, 404)
    if path.startswith('/admin_api/'):
        return error_page(environ, start_response, 404)
    if path.startswith('/ha/passkey-federation/') or path == '/ha/passkey-federation-lib.php':
        return error_page(environ, start_response, 404)
    from retired_auth import RETIRED_ROUTES, RETIRED_ALIASES, BOOKMARK_ROUTE, response
    if path in RETIRED_ROUTES + RETIRED_ALIASES + (BOOKMARK_ROUTE,):
        status, headers, body = response(dict(environ, SCRIPT_NAME='/python-endpoints/legacy-auth.cgi',
                                             REQUEST_URI=path))
        headers.append(('Content-Length', str(len(body))))
        start_response(status, headers)
        return [b'' if environ.get('REQUEST_METHOD') == 'HEAD' else body]
    if path == '/error.php':
        return error_page(environ, start_response, error_status(environ))
    if path == '/ha/error-page.php':
        return error_page(environ, start_response, 404)
    if path == '/ha/maintenance-page.php':
        return error_page(environ, start_response, 503, maintenance=True)
    if path == '/maintenance.php':
        return maintenance_response(environ, start_response)
    if path in {'/ha/http-error.php', '/ha/maintenance-response.php',
                '/api/baas/v1/tenant-sso-contracts.php', '/api/baas/v1/tenant-sso-session.php'}:
        start_response('200 OK', [('Content-Length', '0')])
        return [b'']
    if path in ("", "/"):
        start_response("302 Found", [
            ("Location", "tenant-portal/"),
            ("Cache-Control", "no-store"),
            ("Content-Length", "0"),
        ])
        return [b""]
    method = environ.get("REQUEST_METHOD", "GET").upper()
    request_id = uuid.uuid4().hex[:16]

    if path in ("/admin_api/core/input.php", "/admin_api/core/payloads.php"):
        # These public PHP URLs are function-only includes; the internal
        # admin_api tree remains denied as a filesystem path below.
        start_response("200 OK", [("Content-Length", "0"),
                                  ("Cache-Control", "no-store"),
                                  ("X-Content-Type-Options", "nosniff")])
        return [b""]

    if path in PORTED_ADMIN_ACTION_INCLUDES | PORTED_ADMIN_EMPTY_INCLUDES:
        # These PHP files are dispatcher includes. Their actions are handled by
        # admin_api_handlers; direct requests have no standalone body.
        start_response("200 OK", [("Content-Length", "0"),
                                  ("Cache-Control", "no-store"),
                                  ("X-Content-Type-Options", "nosniff")])
        return [b""]

    if path == "/ha/bootstrap.php":
        # Shared HA bootstrap functions have their Python implementations in
        # ha_handlers, audit, and the HA-specific endpoint modules.
        start_response("200 OK", [("Content-Length", "0"),
                                  ("Cache-Control", "no-store"),
                                  ("X-Content-Type-Options", "nosniff")])
        return [b""]

    # These deployed compatibility scripts require the canonical v3 endpoint
    # and preserve the original PHP URL while sharing its handler behavior.
    if path.startswith("/license/api/v3/"):
        path = "/api/v3/" + path[len("/license/api/v3/"):]

    if path == "/api/v2/core.php":
        # The PHP file only declares shared functions and emits no response.
        # Their Python equivalents live in core.py, v2_handlers.py, and the
        # phone and HA modules; never expose helper source at this URL.
        start_response("200 OK", [("Content-Length", "0"),
                                  ("Cache-Control", "no-store"),
                                  ("X-Content-Type-Options", "nosniff")])
        return [b""]

    clean_path = path.lstrip("/")
    first_part = clean_path.split("/", 1)[0].lower()
    if first_part in {"build", "dist", "__pycache__", "logs", "tests", "docs", "client_app", "db", "admin_api"}:
        return _response(start_response, "404 Not Found", {
            "success": False, "error_code": "NOT_FOUND", "request_id": request_id,
        })
    if clean_path.startswith("api/v2/") and clean_path.split("/", 3)[2] not in {
        "activate.php", "phone_activate.php", "boot_activate.php", "reissue.php",
    }:
        return _response(start_response, "404 Not Found", {
            "success": False, "error_code": "NOT_FOUND", "request_id": request_id,
        })
    if clean_path.startswith(".") or Path(clean_path).suffix.lower() in {
        ".py", ".pyc", ".pyo", ".spec", ".docx", ".sql", ".pem", ".xml",
        ".json", ".log", ".bak", ".old", ".orig", ".save", ".md",
    }:
        return _response(start_response, "404 Not Found", {
            "success": False, "error_code": "NOT_FOUND", "request_id": request_id,
        })

    if path == "/ha/card-result.php":
        from card_result_handlers import card_result
        return card_result(environ, start_response)

    if path == "/api/v3/challenge.php":
        from v3_handlers import challenge
        return challenge(environ, start_response)

    if path == "/api/v3/reauth.php":
        from v3_handlers import reauth
        return reauth(environ, start_response)

    if path == "/api/v3/activate.php":
        from v3_handlers import activate
        return activate(environ, start_response)

    v3_session_routes = {
        "/api/v3/verify.php": "verify",
        "/api/v3/introspect.php": "introspect",
        "/api/v3/revoke.php": "revoke",
        "/api/v3/refresh.php": "refresh",
        "/api/v3/offline-ticket.php": "offline-ticket",
    }
    if path in v3_session_routes:
        from v3_handlers import session_endpoint
        return session_endpoint(environ, start_response, v3_session_routes[path])

    if path == "/api/v3/offline-public-key.php":
        if environ.get("REQUEST_METHOD", "GET") != "GET":
            return json_response(start_response, "405 Method Not Allowed", {
                "success": False, "error_code": "METHOD_NOT_ALLOWED",
                "error": "GET を使用してください。", "api_version": "3.0-beta1",
                "request_id": request_id,
            }, [("Allow", "GET")])
        try:
            from v3_crypto import public_signing_key
            from migration_config import secret_value
            config = {
                "token_secret": secret_value("token_secret"),
                "license_v3_signing_secret": secret_value("license_v3_signing_secret"),
            }
            payload = {
                "success": True,
                "api_version": "3.0-beta1",
                "request_id": request_id,
                "offline_signing_key": public_signing_key(config),
            }
            return json_response(start_response, "200 OK", payload)
        except Exception:
            return json_response(start_response, "503 Service Unavailable", {
                "success": False, "error_code": "OFFLINE_SIGNING_UNAVAILABLE",
                "error": "オフライン署名キーを利用できません。",
                "api_version": "3.0-beta1", "request_id": request_id,
            })

    if path == "/api/v3/index.php":
        return json_response(start_response, "200 OK", {
            "name": "TUTI License API v3 Beta",
            "status": "beta",
            "model": "device-bound proof-of-possession session",
            "endpoints": {
                "challenge": "POST /license/api/v3/challenge.php",
                "activate": "POST /license/api/v3/activate.php",
                "verify": "POST /license/api/v3/verify.php",
                "refresh": "POST /license/api/v3/refresh.php",
                "reauth": "POST /license/api/v3/reauth.php",
                "offline_ticket": "POST /license/api/v3/offline-ticket.php",
                "offline_public_key": "GET /license/api/v3/offline-public-key.php",
                "revoke": "POST /license/api/v3/revoke.php",
                "introspect": "POST /license/api/v3/introspect.php",
            },
            "success": True, "api_version": "3.0-beta1", "request_id": request_id,
        })

    if (path in ("/api/v2/activate.php", "/api/activate.php", "/license/api/v2/activate.php")
            and environ.get("REQUEST_METHOD", "GET") == "GET"):
        guide = SITE_ROOT / "api" / "v2" / "activate.html"
        if guide.is_file():
            body = site_url(guide.read_bytes().decode('utf-8')).encode('utf-8')
            start_response("200 OK", [
                ("Content-Type", "text/html; charset=utf-8"),
                ("X-Content-Type-Options", "nosniff"),
                ("Content-Length", str(len(body))),
            ])
            return [body]

    if (path in ("/api/v2/phone_activate.php", "/api/phone_activate.php", "/phone_activate.php")
            and environ.get("REQUEST_METHOD", "GET") == "GET"):
        guide = SITE_ROOT / "api" / "v2" / "phone_activate.html"
        if guide.is_file():
            body = site_url(guide.read_bytes().decode('utf-8')).encode('utf-8')
            start_response("200 OK", [
                ("Content-Type", "text/html; charset=utf-8"),
                ("X-Content-Type-Options", "nosniff"),
                ("Content-Length", str(len(body))),
            ])
            return [body]

    if path in ("/api/v2/phone_activate.php", "/api/phone_activate.php", "/phone_activate.php"):
        from phone_handlers import phone_activate
        return phone_activate(environ, start_response)

    if path in ("/api/v2/activate.php", "/api/activate.php", "/license/api/v2/activate.php"):
        from v2_handlers import activate
        return activate(environ, start_response)

    # These PHP URLs define shared helper functions and emit no response body.
    # Their Python equivalents live in the BaaS and Common ID SSO modules.
    if path in (
        "/api/baas/issuance-session.php", "/api/baas/v1/billing-policy.php",
        "/api/baas/v1/core.php", "/api/baas/v1/portal-key-policy.php",
        "/api/baas/v1/sample-sdk-lib.php", "/api/baas/v4/lib.php",
        "/api/baas/v5/lib.php", "/api/baas/v6/lib.php",
        "/api/baas/v6/legacy-gateway.php",
        "/api/baas/v1/common-id-sso/constants.php",
        "/api/baas/v1/common-id-sso/http.php",
        "/api/baas/v1/common-id-sso/clients.php",
        "/api/baas/v1/common-id-sso/identity.php",
        "/api/baas/v1/common-id-sso/signing.php",
        "/api/baas/v1/common-id-sso/authorization-code.php",
        "/api/baas/v1/common-id-sso/support.php",
    ):
        start_response("200 OK", [
            ("Content-Length", "0"), ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
        ])
        return [b""]

    if path == "/api/v2/reissue.php":
        from v2_handlers import reissue
        return reissue(environ, start_response)

    if path == "/api/baas/v1/status.php":
        from baas_handlers import status
        return status(environ, start_response)

    if path == "/api/baas/v1/products.php":
        from baas_handlers import products
        return products(environ, start_response)

    sunabar_routes = {
        "/api/sunabar/v1/key.php": "issue_key",
        "/api/sunabar/v1/products.php": "products",
        "/api/sunabar/v1/licenses.php": "licenses",
        "/api/sunabar/v1/verify.php": "verify",
        "/api/sunabar/v1/health.php": "health",
        "/api/sunabar/v1/license-list.php": "license_list",
        "/api/sunabar/v1/license-revoke.php": "license_revoke",
        "/api/sunabar/v1/activate.php": "activate",
        "/api/sunabar/v1/session-check.php": "session_check",
        "/api/sunabar/v1/session-refresh.php": "session_refresh",
        "/api/sunabar/v1/session-deactivate.php": "session_deactivate",
    }
    if path in sunabar_routes:
        import sunabar_api
        return getattr(sunabar_api, sunabar_routes[path])(environ, start_response)

    if path == "/api/baas/v1/jpki.php":
        return json_response(start_response, "410 Gone", {
            "ok": False,
            "error": "external_jpki_flow_retired",
            "message": "このAPIはデジタル庁の外部JPKI接続を終了しました。MNSLローカルカード認証APIを使用してください。",
            "replacement": "/api/baas/v1/mnsl-card-auth.php",
        })

    if path == "/api/baas/v1/mnsl-card-auth.php":
        from mnsl_card_auth_handlers import mnsl_card_auth
        return mnsl_card_auth(environ, start_response)

    if path == "/api/baas/v1/mnsl-android-card-read.php":
        from mnsl_android_card_read_handlers import mnsl_android_card_read
        return mnsl_android_card_read(environ, start_response)

    if path == "/api/baas/v1/mnsl.php":
        from mnsl_handlers import mnsl
        return mnsl(environ, start_response)

    if path == "/api/baas/v1/audit.php":
        from baas_handlers import audit
        return audit(environ, start_response)

    if path == "/api/baas/v1/billing.php":
        from baas_handlers import billing
        return billing(environ, start_response)

    if path == "/api/baas/v1/invoices.php":
        from baas_handlers import invoices
        return invoices(environ, start_response)

    if path == "/api/baas/v1/batch.php":
        from baas_handlers import batch
        return batch(environ, start_response)

    if path == "/api/baas/v1/export.php":
        from baas_handlers import export_tenant
        return export_tenant(environ, start_response)

    if path == "/api/baas/v1/service.php":
        from service_handlers import service
        return service(environ, start_response)

    if path == "/api/baas/v1/webhooks.php":
        from baas_handlers import webhooks
        return webhooks(environ, start_response)

    if path == "/api/baas/v1/licenses.php":
        from baas_handlers import licenses
        return licenses(environ, start_response)

    if path == "/api/baas/v1/portal-passkey.php":
        from portal_passkey_handlers import portal_passkey
        return portal_passkey(environ, start_response)

    if path == "/api/baas/v1/licenses-bulk-delete.php":
        from baas_handlers import licenses_bulk_delete
        return licenses_bulk_delete(environ, start_response)

    if path == "/api/baas/v7/issuance.php":
        from baas_v7_handlers import issuance
        return issuance(environ, start_response)

    issuance_routes = {
        "/api/baas/v2/licenses.php": ("status", "v2"),
        "/api/baas/v3/licenses.php": ("status", "v3"),
        "/api/baas/v4/issuance-jobs.php": ("status", "v4"),
        "/api/baas/v4/issuance-results.php": ("results", "v4"),
        "/api/baas/v4/issuance-cancel.php": ("cancel", "v4"),
        "/api/baas/v5/issuance.php": ("status", "v5"),
        "/api/baas/v5/issuance-results.php": ("results", "v5"),
        "/api/baas/v5/issuance-cancel.php": ("cancel", "v5"),
        "/api/baas/v6/issuance.php": ("status", "v6"),
        "/api/baas/v6/issuance-results.php": ("results", "v6"),
        "/api/baas/v6/issuance-cancel.php": ("cancel", "v6"),
        "/api/baas/v8/issuance.php": ("status", "v8"),
        "/api/baas/v8/issuance-results.php": ("results", "v8"),
        "/api/baas/v8/issuance-cancel.php": ("cancel", "v8"),
    }
    if path in issuance_routes:
        if issuance_routes[path][1] == "v8":
            from baas_v8_handlers import issuance_cancel, issuance_results, issuance
            kind, source_version = issuance_routes[path]
            handler = {"status": issuance, "results": issuance_results,
                       "cancel": issuance_cancel}[kind]
            return handler(environ, start_response)
        from baas_issuance_handlers import issuance_cancel, issuance_results, issuance_status
        kind, source_version = issuance_routes[path]
        handler = {"status": issuance_status, "results": issuance_results,
                   "cancel": issuance_cancel}[kind]
        return handler(environ, start_response, source_version)

    if path == "/api/baas/v1/sandbox-keys.php":
        from baas_handlers import sandbox_keys
        return sandbox_keys(environ, start_response)

    if path == "/api/baas/v1/sample-sdk-keys.php":
        from baas_handlers import sample_sdk_keys
        return sample_sdk_keys(environ, start_response)

    if path == "/api/baas/v1/sample-sdk-activate.php":
        from baas_handlers import sample_sdk_activate
        return sample_sdk_activate(environ, start_response)

    if path == "/api/baas/benchmark/cleanup.php":
        from baas_handlers import benchmark_cleanup
        return benchmark_cleanup(environ, start_response)

    if path == "/api/baas/v1/tenant-sso.php":
        from baas_handlers import tenant_sso
        return tenant_sso(environ, start_response)

    if path == "/api/baas/auto/assess.php":
        from auto_handlers import assess
        return assess(environ, start_response)

    if path == "/ha/health.php":
        from ha_handlers import health
        return health(environ, start_response)

    if path.startswith("/common-id-sso-demo/") and path.endswith(".php"):
        from common_id_demo_handlers import common_id_demo
        return common_id_demo(environ, start_response)

    if path == "/ha/snapshot-codec.php":
        # The PHP URL only declares a helper; its Python implementation is
        # ha_snapshot.ha_snapshot_binary_rows and emits no response directly.
        start_response("200 OK", [("Content-Length", "0"),
                                  ("Cache-Control", "no-store"),
                                  ("X-Content-Type-Options", "nosniff")])
        return [b""]

    if path == "/api/v3/core.php":
        # The PHP file defines shared v3 helpers and emits no direct response;
        # the executable equivalents are implemented in v3_handlers.py.
        start_response("200 OK", [("Content-Length", "0"),
                                  ("Cache-Control", "no-store"),
                                  ("X-Content-Type-Options", "nosniff")])
        return [b""]

    if path in {
        "/ha/passkey-federation-lib.php",
        "/ha/passkey-federation/state.php",
        "/ha/passkey-federation/transport.php",
        "/ha/passkey-federation/identity.php",
        "/ha/passkey-federation/replication.php",
        "/ha/web-passkey-auth.php",
    }:
        # PHP helper includes define federation primitives but return no body
        # for direct requests. Their Python equivalents live in this handler.
        start_response("200 OK", [("Content-Length", "0"),
                                  ("Cache-Control", "no-store"),
                                  ("X-Content-Type-Options", "nosniff")])
        return [b""]

    if path == "/ha/passkey-federation.php":
        from federation_handlers import passkey_federation
        return passkey_federation(environ, start_response)

    if path == "/ha/passkey_api.php":
        from passkey_handlers import passkey_api
        return passkey_api(environ, start_response)

    if path == "/ha/web-passkey-manage.php":
        from web_passkey_manage import web_passkey_manage
        return web_passkey_manage(environ, start_response)

    if path == "/mobile-manager/admin-auth.php":
        from mobile_admin_auth import admin_auth
        return admin_auth(environ, start_response)

    if path == "/admin_api.php":
        from admin_api_handlers import admin_api
        return admin_api(environ, start_response)

    if path == "/generate_key.php":
        from generate_key_handlers import generate_key
        return generate_key(environ, start_response)

    if path == "/ha/android-card-read.php":
        from ha_android_card_read import android_card_read
        return android_card_read(environ, start_response)

    if path == "/ha/mobile-face.php":
        from ha_mobile_face import mobile_face
        return mobile_face(environ, start_response)

    static_pages = {
        "/ha/passkey.php": "passkey.html",
        "/ha/passkey-callback.php": "passkey-callback.html",
        "/ha/passkey-ha-callback.php": "passkey-ha-callback.html",
        "/ha/passkey-keyadmin-callback.php": "passkey-keyadmin-callback.html",
    }
    if path in static_pages:
        page = SITE_ROOT / "ha" / static_pages[path]
        if not page.is_file():
            return _response(start_response, "503 Service Unavailable", {
                "success": False, "error_code": "STATIC_PAGE_UNAVAILABLE", "request_id": request_id,
            })
        body = site_url(page.read_bytes().decode('utf-8')).encode('utf-8')
        start_response("200 OK", [
            ("Content-Type", "text/html; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Length", str(len(body))),
        ])
        return [body]

    if path == "/ha/release.php":
        manifest_path = RELEASE_MANIFEST_PATH
        # The operator publishes one shared website manifest to every HA node.
        # A production component must report that manifest, while isolated
        # previews continue reporting their own Python package manifest.
        if os.environ.get('PYTHON_MIGRATION_PROFILE') == 'production' and ROOT.name.startswith('python-production'):
            manifest_path = ROOT.parent / 'release-manifest.json'
        if not manifest_path.is_file():
            manifest_path = ROOT / "ftp-site" / "release-manifest.json"
        try:
            raw_manifest = manifest_path.read_bytes()
        except OSError:
            return json_response(start_response, "503 Service Unavailable", {
                "ok": False, "error": "manifest_missing",
            })
        try:
            manifest = json.loads(raw_manifest.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            manifest = None
        if not isinstance(manifest, dict) or manifest.get("schema") != 1:
            return json_response(start_response, "503 Service Unavailable", {
                "ok": False, "error": "manifest_invalid",
            })
        files = manifest.get("files", [])
        if not isinstance(files, list):
            files = []
        return json_response(start_response, "200 OK", {
            "ok": True,
            "release_id": manifest.get("release_id"),
            "generated_at_utc": manifest.get("generated_at_utc"),
            "manifest_sha256": hashlib.sha256(raw_manifest).hexdigest(),
            "file_count": len(files),
        })

    if path == "/ha/audit-recent.php":
        from ha_handlers import audit_recent
        return audit_recent(environ, start_response)

    if path == "/ha/audit-verify.php":
        from ha_handlers import audit_verify
        return audit_verify(environ, start_response)

    if path == "/ha/status.php":
        from ha_handlers import ha_status
        return ha_status(environ, start_response)

    if path == "/ha/retention.php":
        from ha_handlers import ha_retention
        return ha_retention(environ, start_response)

    if path == "/ha/restore-test.php":
        from ha_handlers import ha_restore_test
        return ha_restore_test(environ, start_response)

    if path == "/ha/import.php":
        from ha_handlers import ha_import
        return ha_import(environ, start_response)

    if path == "/ha/sync.php":
        from ha_handlers import ha_sync
        return ha_sync(environ, start_response)

    if path == "/ha/retry-sync.php":
        from ha_handlers import ha_retry_sync
        return ha_retry_sync(environ, start_response)

    if path == "/ha/license-lookup.php":
        from ha_license_lookup import license_lookup
        return license_lookup(environ, start_response)

    if path == "/ha/issue-license.php":
        from ha_issue_license import issue_license
        return issue_license(environ, start_response)

    if path == "/ha/issue-license-v2.php":
        from ha_batch_issue import issue_license_v2
        return issue_license_v2(environ, start_response)

    if path == "/ha/issue-license-v3.php":
        from ha_batch_issue import issue_license_v3
        return issue_license_v3(environ, start_response)

    if path in {"/ha/product-key-v4-worker.php", "/ha/product-key-v5-worker.php",
                "/ha/product-key-v8-worker.php"}:
        if path.endswith("v8-worker.php"):
            from ha_product_key_v8_worker import product_key_v8_worker
            return product_key_v8_worker(environ, start_response)
        from ha_issuance_worker import issuance_worker
        version = "v4" if path.endswith("v4-worker.php") else "v5"
        return issuance_worker(environ, start_response, version)

    if path == "/ha/license-admin.php":
        from ha_license_admin import license_admin
        return license_admin(environ, start_response)

    if path == "/ha/tenant-admin.php":
        from ha_tenant_admin import tenant_admin
        return tenant_admin(environ, start_response)

    if path == "/ha/failback-operation.php":
        from ha_failback import failback_operation
        return failback_operation(environ, start_response)

    if path == "/ha/migrate.php":
        from ha_migrate import migrate
        return migrate(environ, start_response)

    if path == "/ha/api-billing-admin.php":
        from ha_billing_admin import invoice_admin
        return invoice_admin(environ, start_response)

    if path == "/ha/webhook-dispatch.php":
        from ha_webhook_dispatch import webhook_dispatch
        return webhook_dispatch(environ, start_response)

    if path == "/ha/mode.php":
        from ha_mode import ha_mode
        return ha_mode(environ, start_response)

    if path == "/ha/phone-admin.php":
        from phone_admin_handlers import phone_admin
        return phone_admin(environ, start_response)

    if path == "/ha/offline-phone.php":
        from offline_phone_handlers import offline_phone
        return offline_phone(environ, start_response)

    if path == "/ha/offline-key.php":
        from offline_key_handlers import offline_key
        return offline_key(environ, start_response)

    if path == "/ha/export.php":
        from ha_export import export_snapshot
        return export_snapshot(environ, start_response)

    if path == "/_migration/health":
        private_raw = os.environ.get("PYTHON_MIGRATION_PRIVATE_DIR", "").strip()
        document_root = Path(os.environ.get("DOCUMENT_ROOT", str(ROOT))).expanduser().resolve()
        private_path = Path(private_raw).expanduser().resolve() if private_raw else None
        private_outside = bool(private_path and private_path != document_root
                               and not _is_relative_to(private_path, document_root))
        private_writable = bool(private_path and private_path.is_dir()
                                and os.access(private_path, os.W_OK))
        return _response(start_response, "200 OK", {
            "success": True,
            "service": "baas-python-migration",
            "route_count": len(ROUTES),
            "ported_route_count": len(PORTED_ROUTES),
            "partially_ported_route_count": len(PARTIALLY_PORTED_ROUTES),
            "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
            "minimum_python": "3.11",
            "production_cutover_ready": False,
            "production_routing": os.environ.get('PYTHON_MIGRATION_ROUTING_MODE', 'partial') if os.environ.get('PYTHON_MIGRATION_PROFILE') == 'production' else 'isolated',
            "private_storage_outside_document_root": private_outside,
            "private_storage_writable": private_writable,
            "request_id": request_id,
        })

    relative = path.lstrip("/")
    candidate = (SITE_ROOT / relative).resolve()
    if candidate != SITE_ROOT.resolve() and SITE_ROOT.resolve() not in candidate.parents:
        return _response(start_response, "404 Not Found", {
            "success": False, "error_code": "NOT_FOUND", "request_id": request_id,
        })
    if candidate.is_dir():
        candidate = candidate / "index.html"
    if candidate.is_file() and candidate.suffix.lower() != ".php":
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        body = candidate.read_bytes()
        if candidate.suffix.lower() in {'.html', '.js', '.css', '.svg', '.webmanifest'}:
            body = site_url(body.decode('utf-8')).encode('utf-8')
        start_response("200 OK", [
            ("Content-Type", content_type + ("; charset=utf-8" if content_type.startswith("text/") else "")),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Length", str(len(body))),
        ])
        return [body]

    if path not in ROUTES:
        return _response(start_response, "404 Not Found", {
            "success": False, "error_code": "NOT_FOUND", "request_id": request_id,
        })

    return _response(start_response, "501 Not Implemented", {
        "success": False,
        "error_code": "MIGRATION_NOT_IMPLEMENTED",
        "message": "This route is inventoried but has no Python handler yet.",
        "path": path,
        "method": method,
        "request_id": request_id,
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run('asgi:app', host='127.0.0.1', port=8765)
