"""HTTP contract helpers shared by Python ports of the legacy PHP API."""
from native_http import make_response, add_headers, legacy_compatible
import json
import uuid
from datetime import date, datetime, time
from urllib.parse import parse_qsl
MAX_JSON_BYTES = 131072
MAX_FIELDS = 100
MAX_VALUE_BYTES = 4096

def php_parse_query(query_string, keep_blank_values=True):
    """Parse a query string with PHP parse_str field-name normalization."""
    values = {}
    for key, value in parse_qsl(str(query_string or ''), keep_blank_values=keep_blank_values):
        normalized = key.replace(' ', '_').replace('.', '_')
        values.setdefault(normalized, []).append(value)
    return values

class RequestError(ValueError):
    pass


def read_bounded_body(request_context, maximum_bytes):
    """Read an HTTP body with a hard cap, even when Content-Length is absent or false."""
    from core import php_int_cast
    length = php_int_cast(request_context.get('content_length') or 0)
    if length < 0:
        raise RequestError('invalid_content_length')
    if length > maximum_bytes:
        raise RequestError('request_too_large')
    stream = request_context.get('body_stream')
    raw = stream.read(maximum_bytes + 1) if stream is not None else b''
    if len(raw) > maximum_bytes:
        raise RequestError('request_too_large')
    return raw

def request_id():
    from request_metrics import current_request_id
    return current_request_id() or uuid.uuid4().hex[:16]

def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat(sep=' ')
    if isinstance(value, (date, time)):
        return value.isoformat()
    raise TypeError('Object of type %s is not JSON serializable' % type(value).__name__)

@legacy_compatible(callback_index=None, request_index=0)
def request_data(request_context):
    """Decode PHP v2's JSON/form/query input contract, rejecting nested data."""
    method = request_context.get('method', 'GET')
    query = php_parse_query(request_context.get('query', ''), keep_blank_values=True)
    content_type = (request_context.get('content_type') or request_context.get('header:content-type') or '').lower()
    if 'application/json' in content_type:
        from core import php_int_cast
        try:
            length = php_int_cast(request_context.get('content_length') or 0)
        except (TypeError, ValueError):
            raise RequestError('invalid_content_length')
        if length > MAX_JSON_BYTES:
            raise RequestError('request_too_large')
        stream = request_context.get('body_stream')
        raw = stream.read(MAX_JSON_BYTES + 1) if stream is not None else b''
        if len(raw) > MAX_JSON_BYTES:
            raise RequestError('request_too_large')
        try:
            decoded = json.loads(raw.decode('utf-8'), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            raise RequestError('invalid_json')
        if isinstance(decoded, list):
            if len(decoded) > MAX_FIELDS:
                raise RequestError('too_many_fields')
            if any((isinstance(value, (list, dict)) for value in decoded)):
                raise RequestError('invalid_request_shape')
            decoded = {}
        elif not isinstance(decoded, dict):
            raise RequestError('invalid_request_shape')
        if len(decoded) > MAX_FIELDS:
            raise RequestError('too_many_fields')
        for value in decoded.values():
            if isinstance(value, (list, dict)):
                raise RequestError('invalid_request_shape')
            if isinstance(value, str) and len(value.encode('utf-8')) > MAX_VALUE_BYTES:
                raise RequestError('value_too_long')
        return decoded
    form = {}
    if method == 'POST' and 'application/x-www-form-urlencoded' in content_type:
        stream = request_context.get('body_stream')
        raw = stream.read(MAX_JSON_BYTES + 1) if stream is not None else b''
        if len(raw) > MAX_JSON_BYTES:
            raise RequestError('request_too_large')
        try:
            form = {k: v[-1] for k, v in php_parse_query(raw.decode('utf-8'), keep_blank_values=True).items()}
        except UnicodeDecodeError:
            raise RequestError('invalid_form')
    query_values = {key: values[-1] for key, values in query.items()}
    if len(form) + len(query_values) > MAX_FIELDS:
        raise RequestError('too_many_fields')
    combined = dict(query_values)
    combined.update(form)
    output = {}
    for key, value in combined.items():
        if '[' in key or ']' in key or isinstance(value, list):
            raise RequestError('invalid_request_shape')
        if isinstance(value, (dict, list)):
            raise RequestError('invalid_request_shape')
        if isinstance(value, str) and len(value.encode('utf-8')) > MAX_VALUE_BYTES:
            raise RequestError('value_too_long')
        output[key] = value
    return output

@legacy_compatible(callback_index=0, request_index=None)
def json_response(status, payload, headers=()):
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), default=_json_default).encode('utf-8')
    response_headers = [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))]
    response_headers.extend(headers)
    _http_status, _http_headers = (status, response_headers)
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=0, request_index=None)
def v2_response(status_code, payload, rid=None):
    status_name = {200: '200 OK', 201: '201 Created', 400: '400 Bad Request', 401: '401 Unauthorized', 403: '403 Forbidden', 404: '404 Not Found', 405: '405 Method Not Allowed', 409: '409 Conflict', 413: '413 Payload Too Large', 429: '429 Too Many Requests', 500: '500 Internal Server Error', 501: '501 Not Implemented', 503: '503 Service Unavailable'}.get(status_code, '%d Error' % status_code)
    result = dict(payload)
    result.setdefault('request_id', rid or request_id())
    if result.get('success') is False:
        result.setdefault('error_code', {400: 'INVALID_REQUEST', 401: 'UNAUTHORIZED', 403: 'FORBIDDEN', 404: 'NOT_FOUND', 409: 'CONFLICT', 413: 'REQUEST_TOO_LARGE', 429: 'RATE_LIMITED', 503: 'SERVICE_UNAVAILABLE'}.get(status_code, 'ERROR'))
    result.setdefault('api_version', '2.0')
    headers = [('X-Request-ID', str(result['request_id']))]
    if status_code == 503:
        headers.append(('Retry-After', '2'))
    return json_response(status_name, result, headers)
