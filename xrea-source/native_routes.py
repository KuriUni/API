"""Complete route table for the FastAPI backend; no WSGI dispatch fallback."""
import importlib
import json
import mimetypes
import os
import sys
import uuid
from pathlib import Path

from fastapi import Request, Response
from starlette.concurrency import run_in_threadpool

from deployment_settings import site_url
from native_http import HttpContext, context_from_request, make_response

ROOT = Path(__file__).resolve().parent
SITE_ROOT = Path(os.environ.get('TUTI_STATIC_ROOT', str(ROOT / 'site'))).resolve()
INVENTORY = json.loads((ROOT / 'routes.json').read_text(encoding='utf-8'))['routes']
METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD', 'TRACE']

# A descriptor names the actual native business function, never a WSGI app.
HANDLERS = {
    '/api/sunabar/v1/key.php': ('sunabar_api', 'issue_key'),
    '/api/sunabar/v1/products.php': ('sunabar_api', 'products'),
    '/api/sunabar/v1/licenses.php': ('sunabar_api', 'licenses'),
    '/api/sunabar/v1/license-list.php': ('sunabar_api', 'license_list'),
    '/api/sunabar/v1/license-revoke.php': ('sunabar_api', 'license_revoke'),
    '/api/sunabar/v1/verify.php': ('sunabar_api', 'verify'),
    '/api/sunabar/v1/health.php': ('sunabar_api', 'health'),
    '/api/sunabar/v1/activate.php': ('sunabar_api', 'activate'),
    '/api/sunabar/v1/session-check.php': ('sunabar_api', 'session_check'),
    '/api/sunabar/v1/session-refresh.php': ('sunabar_api', 'session_refresh'),
    '/api/sunabar/v1/session-deactivate.php': ('sunabar_api', 'session_deactivate'),
    '/api/sunabar/v4/challenge.php': ('sunabar_api', 'v4_challenge'),
    '/api/sunabar/v4/activate.php': ('sunabar_api', 'v4_activate'),
    '/api/sunabar/v4/verify.php': ('sunabar_api', 'v4_verify'),
    '/api/sunabar/v4/introspect.php': ('sunabar_api', 'v4_introspect'),
    '/api/sunabar/v4/refresh.php': ('sunabar_api', 'v4_refresh'),
    '/api/sunabar/v4/revoke.php': ('sunabar_api', 'v4_revoke'),
    '/api/sunabar/v4/offline-public-key.php': ('sunabar_api', 'v4_offline_public_key'),
    '/api/sunabar/v4/offline-ticket.php': ('sunabar_api', 'v4_offline_ticket'),
    '/api/sunabar/v4/migrate.php': ('sunabar_api', 'v4_migrate'),
    '/admin_api.php': ('admin_api_handlers', 'admin_api'),
    '/generate_key.php': ('generate_key_handlers', 'generate_key'),
    '/mobile-manager/admin-auth.php': ('mobile_admin_auth', 'admin_auth'),
    '/api/baas/auto/assess.php': ('auto_handlers', 'assess'),
    '/api/baas/benchmark/cleanup.php': ('baas_handlers', 'benchmark_cleanup'),
    '/api/baas/v1/mnsl.php': ('mnsl_handlers', 'mnsl'),
    '/api/baas/v1/mnsl-card-auth.php': ('mnsl_card_auth_handlers', 'mnsl_card_auth'),
    '/api/baas/v1/mnsl-android-card-read.php': ('mnsl_android_card_read_handlers', 'mnsl_android_card_read'),
    '/api/baas/v1/service.php': ('service_handlers', 'service'),
    '/api/baas/v8/issuance.php': ('baas_v8_handlers', 'issuance'),
    '/api/baas/v8/issuance-results.php': ('baas_v8_handlers', 'issuance_results'),
    '/api/baas/v8/issuance-cancel.php': ('baas_v8_handlers', 'issuance_cancel'),
    '/api/v2/reissue.php': ('v2_handlers', 'reissue'),
    '/ha/card-result.php': ('card_result_handlers', 'card_result'),
    '/ha/android-card-read.php': ('ha_android_card_read', 'android_card_read'),
    '/ha/mobile-face.php': ('ha_mobile_face', 'mobile_face'),
    '/ha/license-lookup.php': ('ha_license_lookup', 'license_lookup'),
    '/ha/issue-license.php': ('ha_issue_license', 'issue_license'),
    '/ha/product-key-v4-worker.php': ('ha_issuance_worker', 'issuance_worker', 'v4'),
    '/ha/product-key-v5-worker.php': ('ha_issuance_worker', 'issuance_worker', 'v5'),
    '/ha/product-key-v8-worker.php': ('ha_product_key_v8_worker', 'product_key_v8_worker'),
    '/ha/license-admin.php': ('ha_license_admin', 'license_admin'),
    '/ha/tenant-admin.php': ('ha_tenant_admin', 'tenant_admin'),
    '/ha/failback-operation.php': ('ha_failback', 'failback_operation'),
    '/ha/migrate.php': ('ha_migrate', 'migrate'),
    '/ha/api-billing-admin.php': ('ha_billing_admin', 'invoice_admin'),
    '/ha/webhook-dispatch.php': ('ha_webhook_dispatch', 'webhook_dispatch'),
    '/ha/mode.php': ('ha_mode', 'ha_mode'),
    '/ha/phone-admin.php': ('phone_admin_handlers', 'phone_admin'),
    '/ha/offline-phone.php': ('offline_phone_handlers', 'offline_phone'),
    '/ha/offline-key.php': ('offline_key_handlers', 'offline_key'),
    '/ha/export.php': ('ha_export', 'export_snapshot'),
    '/api/stripe/webhook.php': ('stripe_billing', 'webhook'),
}
for leaf, handler in (
    ('status', 'status'), ('products', 'products'), ('audit', 'audit'), ('billing', 'billing'),
    ('invoices', 'invoices'), ('batch', 'batch'), ('export', 'export_tenant'),
    ('webhooks', 'webhooks'), ('licenses', 'licenses'), ('licenses-bulk-delete', 'licenses_bulk_delete'),
    ('sandbox-keys', 'sandbox_keys'), ('sample-sdk-keys', 'sample_sdk_keys'),
    ('sample-sdk-activate', 'sample_sdk_activate'), ('tenant-sso', 'tenant_sso'),
):
    HANDLERS['/api/baas/v1/' + leaf + '.php'] = ('baas_handlers', handler)
for leaf, handler in (
    ('health', 'health'), ('audit-recent', 'audit_recent'), ('audit-verify', 'audit_verify'),
    ('status', 'ha_status'), ('retention', 'ha_retention'), ('restore-test', 'ha_restore_test'),
    ('import', 'ha_import'), ('sync', 'ha_sync'), ('retry-sync', 'ha_retry_sync'),
):
    HANDLERS['/ha/' + leaf + '.php'] = ('ha_handlers', handler)
# Legacy status/results/cancel remain readable for already accepted V4-V6 jobs;
# new submissions are rejected by is_retired_issuance_request before dispatch.
for version, leaves in {
    'v4': [('issuance-jobs', 'issuance_status'), ('issuance-results', 'issuance_results'), ('issuance-cancel', 'issuance_cancel')],
    'v5': [('issuance', 'issuance_status'), ('issuance-results', 'issuance_results'), ('issuance-cancel', 'issuance_cancel')],
    'v6': [('issuance', 'issuance_status'), ('issuance-results', 'issuance_results'), ('issuance-cancel', 'issuance_cancel')],
}.items():
    for leaf, handler in leaves:
        HANDLERS['/api/baas/' + version + '/' + leaf + '.php'] = ('baas_issuance_handlers', handler, version)
for path in ('/api/activate.php', '/api/v2/activate.php', '/license/api/v2/activate.php'):
    HANDLERS[path] = ('v2_handlers', 'activate')
for path in ('/api/v2/phone_activate.php', '/api/phone_activate.php', '/phone_activate.php'):
    HANDLERS[path] = ('phone_handlers', 'phone_activate')
for leaf in ('common', 'index', 'login', 'callback', 'logout'):
    HANDLERS['/common-id-sso-demo/' + leaf + '.php'] = ('common_id_demo_handlers', 'common_id_demo')

EMPTY = {
    '/api/baas/issuance-session.php', '/api/baas/v1/billing-policy.php', '/api/baas/v1/core.php',
    '/api/baas/v1/portal-key-policy.php', '/api/baas/v1/sample-sdk-lib.php',
    '/api/baas/v4/lib.php', '/api/baas/v5/lib.php', '/api/baas/v6/lib.php',
    '/api/baas/v6/legacy-gateway.php', '/api/v2/core.php', '/api/v3/core.php',
    '/ha/bootstrap.php', '/ha/snapshot-codec.php', '/ha/web-passkey-auth.php',
    '/ha/http-error.php', '/ha/maintenance-response.php',
    '/api/baas/v1/tenant-sso-contracts.php', '/api/baas/v1/tenant-sso-session.php',
}
EMPTY_NO_SECURITY = {'/ha/http-error.php', '/ha/maintenance-response.php',
                     '/api/baas/v1/tenant-sso-contracts.php', '/api/baas/v1/tenant-sso-session.php'}
DENIED = {row['path'] for row in INVENTORY if row['access'] == 'denied'}
DENIED.update(row['path'] for row in INVENTORY if row['path'].startswith('/api/baas/v1/common-id-sso/'))
ERRORS = {'/error.php', '/ha/error-page.php', '/ha/maintenance-page.php', '/maintenance.php'}
SPECIAL = ERRORS | {'/ha/release.php', '/api/baas/v1/jpki.php', '/api-catalog/index.php'}


def route_manifest(existing=()):
    from retired_auth import BOOKMARK_ROUTE, RETIRED_ALIASES, RETIRED_ROUTES, RETIRED_ISSUANCE_ROUTES
    retired = set(RETIRED_ROUTES + RETIRED_ALIASES + RETIRED_ISSUANCE_ROUTES + (BOOKMARK_ROUTE,))
    result = {}
    for row in INVENTORY:
        path = row['path']
        if path in DENIED:
            kind, handler = 'denied', 'http_error_handlers.error_page'
        elif path in retired:
            kind, handler = 'retired', 'retired_auth.response'
        elif path in existing:
            kind, handler = 'endpoint', 'native_v4' if path.startswith(('/api/v4/', '/license/api/v4/')) else 'native_v3'
        elif path in HANDLERS:
            kind, handler = 'endpoint', '.'.join(HANDLERS[path][:2])
        elif path in EMPTY:
            kind, handler = 'include', 'native_routes.empty'
        elif path in SPECIAL:
            kind, handler = 'endpoint', 'native_routes.special'
        else:
            raise RuntimeError('Missing native route: ' + path)
        # New native-only routes (for example V8) have no legacy PHP source
        # digest in routes.json. Keep them in the route manifest without
        # making every API route fail to initialize.
        result[path] = {'kind': kind, 'handler': handler, 'wsgi': False,
                        'php_source_sha256': row.get('source_sha256')}
    return result


def special(context):
    from http_error_handlers import error_page, error_status, maintenance_response
    from http_utils import json_response
    path = context['path']
    if path == '/api-catalog/index.php':
        return catalog_page(context)
    if path == '/error.php':
        return error_page(context, error_status(context))
    if path == '/ha/error-page.php':
        return error_page(context, 404)
    if path == '/ha/maintenance-page.php':
        return error_page(context, 503, maintenance=True)
    if path == '/maintenance.php':
        return maintenance_response(context)
    if path == '/api/baas/v1/jpki.php':
        return json_response('410 Gone', {'ok': False, 'error': 'external_jpki_flow_retired',
            'message': 'このAPIはデジタル庁の外部JPKI接続を終了しました。MNSLローカルカード認証APIを使用してください。',
            'replacement': '/api/baas/v1/mnsl-card-auth.php'})
    manifest = ROOT / 'release-manifest.json'
    if os.environ.get('PYTHON_MIGRATION_PROFILE') == 'production' and ROOT.name.startswith('python-production'):
        manifest = ROOT.parent / 'release-manifest.json'
    if not manifest.is_file():
        manifest = ROOT / 'ftp-site/release-manifest.json'
    try:
        raw = manifest.read_bytes()
    except OSError:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'manifest_missing'})
    try:
        data = json.loads(raw.decode('utf-8'))
    except (UnicodeDecodeError, ValueError):
        data = None
    if not isinstance(data, dict) or data.get('schema') != 1:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'manifest_invalid'})
    import hashlib
    return json_response('200 OK', {'ok': True, 'release_id': data.get('release_id'),
        'generated_at_utc': data.get('generated_at_utc'), 'manifest_sha256': hashlib.sha256(raw).hexdigest(),
        'file_count': len(data['files']) if isinstance(data.get('files'), list) else 0})


def catalog_page(context):
    from urllib.parse import parse_qsl
    headers = [('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('X-TUTI-Catalog', 'openapi')]
    json_headers = headers + [('Content-Type', 'application/json; charset=utf-8')]
    if context.get('method') not in {'GET', 'HEAD'}:
        return make_response(b'{"success":false,"error":"method_not_allowed"}', 405,
                             json_headers + [('Allow', 'GET, HEAD')])
    document = None
    for key, value in parse_qsl(context.get('query', ''), keep_blank_values=True):
        if key == 'document':
            document = value
        elif key.startswith('document['):
            document = None
    if document == 'health':
        return make_response(b'{"success":true,"service":"baas-api-catalog"}', 200, json_headers)
    files = {'docs': ('docs.html', 'text/html'), 'redoc': ('redoc.html', 'text/html'),
             'openapi.json': ('openapi.json', 'application/json')}
    if document not in files:
        return make_response(b'{"success":false,"error":"not_found"}', 404, json_headers)
    filename, content_type = files[document]
    try:
        body = (SITE_ROOT / 'api-catalog' / filename).read_bytes()
    except OSError:
        return make_response(b'{"success":false,"error":"catalog_unavailable"}', 503, json_headers)
    return make_response(body, 200, headers + [('Content-Type', content_type + '; charset=utf-8'),
                                             ('Content-Length', str(len(body)))])


def serve_static(context):
    from http_error_handlers import error_page
    path = context['path']
    if path in ('', '/'):
        return make_response(b'', 302, [('Location', 'tenant-portal/'), ('Cache-Control', 'no-store'), ('Content-Length', '0')])
    relative = path.lstrip('/')
    first = relative.split('/', 1)[0].lower()
    if first in {'build', 'dist', '__pycache__', 'logs', 'tests', 'docs', 'client_app', 'db', 'admin_api'} or any(part.startswith('.') for part in Path(relative).parts) or relative.endswith('~'):
        return error_page(context, 404)
    candidate = (SITE_ROOT / relative).resolve()
    if candidate != SITE_ROOT.resolve() and SITE_ROOT.resolve() not in candidate.parents:
        return error_page(context, 404)
    if candidate.is_dir():
        candidate /= 'index.html'
    if not candidate.is_file() or candidate.suffix.lower() in {'.cgi', '.zip', '.so', '.pyd', '.dll', '.php', '.py', '.pyc', '.pyo', '.spec', '.docx', '.sql', '.pem', '.xml', '.json', '.log', '.bak', '.old', '.orig', '.save', '.md'}:
        return error_page(context, 404)
    body = candidate.read_bytes()
    if candidate.suffix.lower() in {'.html', '.js', '.css', '.svg', '.webmanifest'}:
        body = site_url(body.decode('utf-8')).encode('utf-8')
    content_type = mimetypes.guess_type(candidate.name)[0] or 'application/octet-stream'
    return make_response(body, 200, [('Content-Type', content_type + ('; charset=utf-8' if content_type.startswith('text/') else '')),
                                    ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))])


def dispatch_native(context):
    from http_error_handlers import MAINTENANCE_ALLOWED, error_page, is_maintenance, maintenance_response
    from retired_auth import (BOOKMARK_ROUTE, RETIRED_ALIASES, RETIRED_ROUTES,
                              RETIRED_ISSUANCE_ROUTES, is_retired_issuance_request,
                              response as retired_response)
    path = context['path']
    if is_maintenance() and path not in MAINTENANCE_ALLOWED:
        return maintenance_response(context)
    if path in DENIED or path.startswith(('/admin_api/', '/api/baas/v1/common-id-sso/', '/ha/passkey-federation/')) or path == '/ha/passkey-federation-lib.php':
        return error_page(context, 404)
    if path in RETIRED_ROUTES + RETIRED_ALIASES + RETIRED_ISSUANCE_ROUTES + (BOOKMARK_ROUTE,) or is_retired_issuance_request(path, context.get('method')):
        retired = HttpContext(context, mount_path='/python-endpoints/legacy-auth.cgi', uri=path)
        status, headers, body = retired_response(retired)
        return make_response(body, status, headers + [('Content-Length', str(len(body)))])
    if path in EMPTY:
        headers = [('Content-Length', '0')]
        if path not in EMPTY_NO_SECURITY:
            headers += [('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff')]
        return make_response(b'', 200, headers)
    if path in SPECIAL:
        return special(context)
    spec = HANDLERS.get(path)
    if spec:
        # Preserve the GET guides served by the original v2/phone PHP URLs.
        if context.get('method') == 'GET' and spec[0] in {'v2_handlers', 'phone_handlers'} and spec[1] != 'reissue':
            guide = SITE_ROOT / 'api/v2' / ('activate.html' if spec[0] == 'v2_handlers' else 'phone_activate.html')
            if guide.is_file():
                body = site_url(guide.read_text(encoding='utf-8')).encode('utf-8')
                return make_response(body, 200, [('Content-Type', 'text/html; charset=utf-8'),
                    ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))])
        module, function, *extra = spec
        result = getattr(importlib.import_module(module), function)(context, *extra)
        if not isinstance(result, Response):
            raise TypeError(module + '.' + function + ' must return native Response')
        return result
    return serve_static(context)


def install_routes(api):
    from retired_auth import BOOKMARK_ROUTE, RETIRED_ALIASES, RETIRED_ROUTES
    existing = {route.path for route in api.routes}
    api.state.native_route_manifest = route_manifest(existing)

    def endpoint_for(path=None):
        async def endpoint(request: Request) -> Response:
            context, error = await context_from_request(request)
            if error is not None:
                return error
            if path is not None:
                context['path'] = path
            original_stream = context['body_stream']
            try:
                result = await run_in_threadpool(dispatch_native, context)
                if request.method == 'HEAD':
                    result.body = b''
                return result
            finally:
                original_stream.close()
                close = getattr(context['body_stream'], 'close', None)
                if close is not None:
                    close()
        return endpoint

    all_paths = set(api.state.native_route_manifest) | set(RETIRED_ROUTES + RETIRED_ALIASES + (BOOKMARK_ROUTE,))
    for path in sorted(all_paths - existing):
        api.add_api_route(path, endpoint_for(path), methods=METHODS, include_in_schema=False)

    @api.get('/_migration/health', include_in_schema=False)
    def migration_health():
        records = api.state.native_route_manifest
        private_raw = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
        private = Path(private_raw).expanduser().resolve() if private_raw else None
        document_root = Path(os.environ.get('DOCUMENT_ROOT') or ROOT).expanduser().resolve()
        return {'success': True, 'service': 'baas-python-migration', 'framework': 'fastapi',
                'route_count': len(records), 'ported_route_count': len(records),
                'partially_ported_route_count': 0, 'wsgi_route_count': 0,
                'python_version': f'{sys.version_info.major}.{sys.version_info.minor}',
                'minimum_python': '3.11', 'production_cutover_ready': False,
                'private_storage_outside_document_root': bool(private and private != document_root and document_root not in private.parents),
                'private_storage_writable': bool(private and private.is_dir() and os.access(private, os.W_OK)),
                'request_id': uuid.uuid4().hex[:16]}

    api.add_api_route('/{remaining_path:path}', endpoint_for(), methods=METHODS, include_in_schema=False)
