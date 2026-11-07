"""Tenant-scoped Python port of the BaaS v1 service facade."""
from native_http import make_response, add_headers, legacy_compatible
import json
import uuid
from urllib.parse import urlencode
from core import PHP_TRIM_CHARS, php_int_cast
from http_utils import json_response, php_parse_query
_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')

def _php_trim_lower(value):
    return value.strip(PHP_TRIM_CHARS).translate(_ASCII_LOWER)
SERVICE_ROUTES = {'service.status': ('GET', '/api/baas/v1/status.php', None, (), 'status'), 'products.list': ('GET', '/api/baas/v1/products.php', None, ('limit', 'cursor', 'search', 'status'), 'products'), 'products.create': ('POST', '/api/baas/v1/products.php', 'create', (), 'products'), 'products.update': ('POST', '/api/baas/v1/products.php', 'update', (), 'products'), 'products.archive': ('POST', '/api/baas/v1/products.php', 'archive', (), 'products'), 'products.restore': ('POST', '/api/baas/v1/products.php', 'restore', (), 'products'), 'licenses.list': ('GET', '/api/baas/v1/licenses.php', None, ('limit', 'cursor', 'search', 'product_id', 'license_id'), 'licenses'), 'licenses.issue': ('POST', '/api/baas/v1/licenses.php', 'issue', (), 'licenses'), 'licenses.update': ('POST', '/api/baas/v1/licenses.php', 'update', (), 'licenses'), 'licenses.activate': ('POST', '/api/baas/v1/licenses.php', 'activate', (), 'licenses'), 'licenses.pause': ('POST', '/api/baas/v1/licenses.php', 'deactivate', (), 'licenses'), 'licenses.revoke_device': ('POST', '/api/baas/v1/licenses.php', 'revoke_device', (), 'licenses'), 'licenses.restore_device': ('POST', '/api/baas/v1/licenses.php', 'restore_device', (), 'licenses'), 'licenses.revoke_all_devices': ('POST', '/api/baas/v1/licenses.php', 'revoke_all_devices', (), 'licenses'), 'licenses.delete': ('DELETE', '/api/baas/v1/licenses.php', None, (), 'licenses'), 'licenses.sandbox_bulk_delete': ('POST', '/api/baas/v1/licenses-bulk-delete.php', None, (), 'licenses_bulk_delete'), 'licenses.batch_issue': ('POST', '/api/baas/v1/batch.php', None, (), 'batch'), 'licenses.batch_status': ('GET', '/api/baas/v1/batch.php', None, ('job_id',), 'batch'), 'usage.summary': ('GET', '/api/baas/v1/billing.php', None, ('period',), 'billing'), 'audit.list': ('GET', '/api/baas/v1/audit.php', None, ('limit', 'cursor', 'operation', 'client_id', 'status'), 'audit'), 'billing.invoices': ('GET', '/api/baas/v1/invoices.php', None, ('period',), 'invoices'), 'sandbox_keys.list': ('GET', '/api/baas/v1/sandbox-keys.php', None, (), 'sandbox_keys'), 'sandbox_keys.issue': ('POST', '/api/baas/v1/sandbox-keys.php', 'issue', (), 'sandbox_keys'), 'sandbox_keys.rotate': ('POST', '/api/baas/v1/sandbox-keys.php', 'rotate', (), 'sandbox_keys'), 'sandbox_keys.revoke': ('POST', '/api/baas/v1/sandbox-keys.php', 'revoke', (), 'sandbox_keys'), 'webhooks.list': ('GET', '/api/baas/v1/webhooks.php', None, (), 'webhooks'), 'webhooks.create': ('POST', '/api/baas/v1/webhooks.php', 'create', (), 'webhooks'), 'webhooks.create_line': ('POST', '/api/baas/v1/webhooks.php', 'create_line', (), 'webhooks'), 'webhooks.update': ('POST', '/api/baas/v1/webhooks.php', 'update', (), 'webhooks'), 'webhooks.delete': ('POST', '/api/baas/v1/webhooks.php', 'delete', (), 'webhooks'), 'licenses.bulk_issue': ('POST', '/api/baas/v8/issuance.php', None, (), 'issuance_v8', 65536), 'licenses.bulk_status': ('GET', '/api/baas/v8/issuance.php', None, ('job_id',), 'issuance_v8'), 'licenses.bulk_results': ('GET', '/api/baas/v8/issuance-results.php', None, ('job_id', 'limit', 'cursor', 'reveal'), 'issuance_v8_results'), 'licenses.bulk_cancel': ('POST', '/api/baas/v8/issuance-cancel.php', None, (), 'issuance_v8_cancel', 65536), 'licenses.sync_issue': ('POST', '/api/baas/v1/licenses.php', 'issue', (), 'licenses', 65536), 'tenant.export': ('GET', '/api/baas/v1/export.php', None, (), 'export_tenant'), 'identity.info': ('GET', '/api/baas/v1/mnsl.php', None, (), 'mnsl'), 'identity.begin': ('POST', '/api/baas/v1/mnsl.php', 'begin', (), 'mnsl'), 'identity.status': ('POST', '/api/baas/v1/mnsl.php', 'status', (), 'mnsl'), 'identity.fail': ('POST', '/api/baas/v1/mnsl.php', 'fail', (), 'mnsl'), 'identity.complete': ('POST', '/api/baas/v1/mnsl.php', 'complete', (), 'mnsl'), 'identity.record_verification': ('POST', '/api/baas/v1/mnsl.php', 'record_verification', (), 'mnsl'), 'identity.card_challenge': ('POST', '/api/baas/v1/mnsl-card-auth.php', 'challenge', (), 'mnsl_card_auth'), 'identity.card_verify': ('POST', '/api/baas/v1/mnsl-card-auth.php', 'verify', (), 'mnsl_card_auth'), 'identity.android_create': ('POST', '/api/baas/v1/mnsl-android-card-read.php', 'create', (), 'mnsl_android_card_read'), 'identity.android_status': ('POST', '/api/baas/v1/mnsl-android-card-read.php', 'status', (), 'mnsl_android_card_read'), 'identity.android_app_status': ('POST', '/api/baas/v1/mnsl-android-card-read.php', 'app_status', (), 'mnsl_android_card_read'), 'identity.android_complete': ('POST', '/api/baas/v1/mnsl-android-card-read.php', 'complete', (), 'mnsl_android_card_read'), 'identity.android_fail': ('POST', '/api/baas/v1/mnsl-android-card-read.php', 'fail', (), 'mnsl_android_card_read')}

@legacy_compatible(callback_index=0, request_index=None)
def _error(status, error, message, allow=None):
    rid = uuid.uuid4().hex[:16]
    headers = [('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff')]
    if allow:
        headers.append(('Allow', allow))
    return json_response(status, {'ok': False, 'api_version': 'baas-service-v1', 'request_id': rid, 'error': error, 'message_ja': message}, headers)

@legacy_compatible(callback_index=None, request_index=0)
def _read_json(request_context):
    length = php_int_cast(request_context.get('content_length') or 0)
    if length > 131072:
        return (None, 413, 'request_too_large')
    stream = request_context.get('body_stream')
    raw = stream.read(131073) if stream is not None else b''
    request_context['_PYTHON_MIGRATION_RAW_BODY_LENGTH'] = len(raw)
    if len(raw) > 131072:
        return (None, 413, 'request_too_large')
    try:
        value = json.loads(raw.decode('utf-8'), parse_constant=lambda _: (_ for _ in ()).throw(ValueError('invalid_json'))) if raw else {}
        depth = 0
        in_string = escaped = False
        for char in raw.decode('utf-8'):
            if in_string:
                if escaped:
                    escaped = False
                elif char == '\\':
                    escaped = True
                elif char == '"':
                    in_string = False
            elif char == '"':
                in_string = True
            elif char in '[{':
                depth += 1
                if depth > 32:
                    return (None, 400, 'invalid_json')
            elif char in ']}':
                depth -= 1
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return (None, 400, 'invalid_json')
    if isinstance(value, dict):
        php_keys = []
        for key in value:
            if key == '0' or (key.isdigit() and (not key.startswith('0'))) or (key.startswith('-') and key[1:].isdigit() and (not key[1:].startswith('0'))):
                try:
                    number = int(key)
                    php_keys.append(number if -2 ** 63 <= number <= 2 ** 63 - 1 else key)
                except ValueError:
                    php_keys.append(key)
            else:
                php_keys.append(key)
        if php_keys == list(range(len(php_keys))) and php_keys:
            return (None, 400, 'invalid_request')
        return (value, None, None)
    if value == []:
        return ({}, None, None)
    return (None, 400, 'invalid_request')

@legacy_compatible(callback_index=1, request_index=0)
def service(request_context):
    method = str(request_context.get('method', 'GET')).upper()
    if method not in {'GET', 'POST', 'DELETE'}:
        return _error('405 Method Not Allowed', 'method_not_allowed', 'GET、POST、DELETEのいずれかを使用してください。', 'GET, POST, DELETE')
    body = {}
    query = php_parse_query(request_context.get('query', ''))
    if method == 'GET':
        service_values = query.get('service', [])
        if any((key.startswith('service[') for key in query)):
            return _error('400 Bad Request', 'invalid_service', 'serviceには1つのサービス名を指定してください。')
        name = service_values[-1] if service_values else ''
    else:
        if 'application/json' not in _php_trim_lower(str(request_context.get('content_type', ''))):
            return _error('415 Unsupported Media Type', 'application_json_required', 'POST・DELETEではJSON形式で送信してください。')
        body, status, error = _read_json(request_context)
        if error:
            message = 'リクエストは128KB以内にしてください。' if status == 413 else 'JSON形式を確認してください。'
            return _error(f"{status} {('Payload Too Large' if status == 413 else 'Bad Request')}", error, message)
        name = body.get('service', '')
        if name is None:
            name = ''
        if not isinstance(name, str):
            return _error('400 Bad Request', 'invalid_service', 'serviceには1つのサービス名を指定してください。')
        body.pop('service', None)
    name = _php_trim_lower(name) if isinstance(name, str) else ''
    route = SERVICE_ROUTES.get(name)
    if route is None:
        return _error('400 Bad Request', 'unsupported_service', '利用できるサービス名を確認してください。')
    expected_method, target, action, allowed_query, handler = route[:5]
    if method != expected_method:
        return _error('405 Method Not Allowed', 'method_not_allowed', f'{name} は {expected_method} で実行してください。', expected_method)
    max_body = route[5] if len(route) > 5 else 131072
    raw_body_length = int(request_context.get('_PYTHON_MIGRATION_RAW_BODY_LENGTH', 0) or 0)
    if method != 'GET' and raw_body_length > max_body:
        message = 'この業務の入力は65KB以内にしてください。' if max_body == 65536 else 'リクエストは128KB以内にしてください。'
        return _error('413 Payload Too Large', 'request_too_large', message)
    if handler == 'mnsl':
        from mnsl_handlers import mnsl as target_handler
    elif handler == 'mnsl_card_auth':
        from mnsl_card_auth_handlers import mnsl_card_auth as target_handler
    elif handler == 'mnsl_android_card_read':
        from mnsl_android_card_read_handlers import mnsl_android_card_read as target_handler
    elif handler in {'issuance_status', 'issuance_results', 'issuance_cancel'}:
        from baas_issuance_handlers import issuance_cancel, issuance_results, issuance_status
        target_handler = {'issuance_status': issuance_status, 'issuance_results': issuance_results, 'issuance_cancel': issuance_cancel}[handler]
    elif handler == 'issuance_v8':
        from baas_v8_handlers import issuance as target_handler
    elif handler == 'issuance_v8_results':
        from baas_v8_handlers import issuance_results as target_handler
    elif handler == 'issuance_v8_cancel':
        from baas_v8_handlers import issuance_cancel as target_handler
    else:
        handlers = {'status': 'status', 'products': 'products', 'licenses': 'licenses', 'licenses_bulk_delete': 'licenses_bulk_delete', 'batch': 'batch', 'billing': 'billing', 'audit': 'audit', 'invoices': 'invoices', 'sandbox_keys': 'sandbox_keys', 'webhooks': 'webhooks', 'export_tenant': 'export_tenant'}
        from baas_handlers import audit, batch, billing, export_tenant, invoices, licenses, licenses_bulk_delete, products, sandbox_keys, status, webhooks
        target_handler = locals()[handlers[handler]]
    forwarded = []
    for field in allowed_query:
        if any((key.startswith(field + '[') for key in query)):
            continue
        values = query.get(field, [])
        if values:
            forwarded.append((field, values[-1]))
    child = dict(request_context)
    child['path'] = target
    child['mount_path'] = target
    child['uri'] = target + ('?' + urlencode(forwarded) if forwarded else '')
    child['query'] = urlencode(forwarded)
    child['method'] = expected_method
    if method != 'GET':
        if action is not None:
            body['action'] = action
        encoded = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
        import io
        child['body_stream'] = io.BytesIO(encoded)
        child['content_length'] = str(len(encoded))
        child['content_type'] = 'application/json'
    return target_handler(child)
