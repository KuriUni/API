"""Complete native FastAPI backend; WSGI is supported only at the CGI boundary."""


import json
import uuid

from fastapi import FastAPI, Request, Response
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from app import application


def legacy_application(environ, start_response):
    # Preserve Apache CGI variables (REQUEST_URI, HTTPS, redirect information,
    # and deployment settings) across the ASGI -> WSGI round trip.
    original = environ.get("asgi.scope", {}).get("wsgi_environ")
    return application(original if original is not None else environ, start_response)


class HealthResponse(BaseModel):
    success: bool = True
    service: str = "baas-fastapi"


def maintenance_if_needed(request: Request):
    from http_error_handlers import is_maintenance, maintenance_response
    from native_http import HttpContext, context_key
    if not is_maintenance():
        return None
    original = request.scope.get('wsgi_environ') or {}
    context = HttpContext({
        'method': request.method, 'path': request.url.path,
        'uri': request.url.path, 'mount_path': request.scope.get('root_path', ''),
        'header:accept': request.headers.get('accept', ''),
    })
    for key in ('REQUEST_URI', 'SCRIPT_NAME', 'REDIRECT_STATUS', 'REDIRECT_URL'):
        if key in original:
            context[context_key(key)] = original[key]
    return maintenance_response(context)

def legacy_json(payload, status=200, headers=None):
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return Response(content=body, status_code=status, headers={
        'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff', **(headers or {}),
    })


def create_app() -> FastAPI:
    api = FastAPI(
        title="TUTI BaaS API",
        version="1.0.0",
        description="TUTI BaaSの公開APIカタログ。既存APIは同じURLで利用できます。",
        docs_url="/_fastapi/docs",
        redoc_url="/_fastapi/redoc",
        openapi_url="/_fastapi/openapi.json",
        swagger_ui_parameters={"filter": True, "docExpansion": "none", "displayRequestDuration": True},
    )

    @api.get("/_fastapi/health", response_model=HealthResponse, tags=["health"])
    def health() -> HealthResponse:
        """Process liveness only; does not verify database or production readiness."""
        return HealthResponse()

    @api.head("/_fastapi/health", include_in_schema=False)
    def health_head() -> Response:
        return Response(status_code=200)

    @api.api_route("/api/v3/index.php", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"], include_in_schema=False)
    @api.api_route("/license/api/v3/index.php", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"], include_in_schema=False)
    def v3_index(request: Request) -> Response:
        """Native FastAPI implementation of the public v3 endpoint index."""
        maintenance = maintenance_if_needed(request)
        if maintenance is not None:
            return maintenance
        payload = {
            'name': 'TUTI License API v3 Beta', 'status': 'beta',
            'model': 'device-bound proof-of-possession session',
            'endpoints': {
                'challenge': 'POST /license/api/v3/challenge.php',
                'activate': 'POST /license/api/v3/activate.php',
                'verify': 'POST /license/api/v3/verify.php',
                'refresh': 'POST /license/api/v3/refresh.php',
                'reauth': 'POST /license/api/v3/reauth.php',
                'offline_ticket': 'POST /license/api/v3/offline-ticket.php',
                'offline_public_key': 'GET /license/api/v3/offline-public-key.php',
                'revoke': 'POST /license/api/v3/revoke.php',
                'introspect': 'POST /license/api/v3/introspect.php',
            },
            'success': True, 'api_version': '3.0-beta1', 'request_id': uuid.uuid4().hex[:16],
        }
        return legacy_json(payload)

    @api.api_route('/api/v3/offline-public-key.php', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'], include_in_schema=False)
    @api.api_route('/license/api/v3/offline-public-key.php', methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'], include_in_schema=False)
    def v3_offline_public_key(request: Request) -> Response:
        maintenance = maintenance_if_needed(request)
        if maintenance is not None:
            return maintenance
        rid = uuid.uuid4().hex[:16]
        if request.method != 'GET':
            return legacy_json({'success': False, 'error_code': 'METHOD_NOT_ALLOWED',
                                'error': 'GET を使用してください。', 'api_version': '3.0-beta1',
                                'request_id': rid}, 405, {'Allow': 'GET'})
        try:
            from v3_crypto import public_signing_key
            from migration_config import secret_value
            config = {'token_secret': secret_value('token_secret'),
                      'license_v3_signing_secret': secret_value('license_v3_signing_secret')}
            return legacy_json({'success': True, 'api_version': '3.0-beta1', 'request_id': rid,
                                'offline_signing_key': public_signing_key(config)})
        except Exception:
            return legacy_json({'success': False, 'error_code': 'OFFLINE_SIGNING_UNAVAILABLE',
                                'error': 'オフライン署名キーを利用できません。',
                                'api_version': '3.0-beta1', 'request_id': rid}, 503)

    from native_v3 import install_routes
    install_routes(api, maintenance_if_needed)

    from native_v4 import install_routes as install_license_v4_routes
    install_license_v4_routes(api, maintenance_if_needed)

    from native_routes import install_routes as install_all_routes
    install_all_routes(api)
    from api_catalog import install_catalog
    install_catalog(api)
    return api


app = create_app()
