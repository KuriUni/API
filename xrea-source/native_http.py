"""Native HTTP context and responses; the legacy adapter is CGI-only.

Business handlers accept transport-neutral request data and return Starlette
Responses. No response callback or WSGI application is used by FastAPI.
"""
import functools
from collections.abc import Mapping
from http import HTTPStatus

from starlette.responses import Response


KEYS = {
    'REQUEST_METHOD': 'method', 'PATH_INFO': 'path', 'QUERY_STRING': 'query',
    'CONTENT_TYPE': 'content_type', 'CONTENT_LENGTH': 'content_length',
    'REMOTE_ADDR': 'client_address', 'REQUEST_URI': 'uri', 'SCRIPT_NAME': 'mount_path',
    'SERVER_NAME': 'server_name', 'SERVER_PORT': 'server_port', 'SERVER_PROTOCOL': 'protocol',
    'HTTPS': 'https', 'REDIRECT_STATUS': 'redirect_status', 'REDIRECT_URL': 'redirect_url',
    'DOCUMENT_ROOT': 'document_root', 'wsgi.input': 'body_stream',
}


def context_key(key):
    if isinstance(key, str) and key.startswith('HTTP_'):
        return 'header:' + key[5:].replace('_', '-').lower()
    return KEYS.get(key, key)


class HttpContext(dict):
    """Request data usable by synchronous SQL services without an event loop."""


def legacy_to_context(environ):
    return HttpContext((context_key(key), value) for key, value in environ.items()
                       if not str(key).startswith('wsgi.') or key == 'wsgi.input')


def make_response(body=b'', status=200, headers=()):
    if isinstance(body, (list, tuple)):
        body = b''.join(body)
    if isinstance(body, str):
        body = body.encode('utf-8')
    response = Response(body, status_code=int(str(status).split()[0]))
    response.raw_headers = [(key.lower().encode('latin-1'), str(value).encode('latin-1'))
                            for key, value in headers]
    response.original_headers = list(headers)
    response.legacy_status = str(status) if ' ' in str(status) else None
    return response


def add_headers(response, headers):
    if hasattr(response, 'original_headers'):
        response.original_headers.extend(headers)
    response.raw_headers.extend((key.lower().encode('latin-1'), str(value).encode('latin-1'))
                                for key, value in headers)
    return response


def to_wsgi(response, callback):
    """Only old CGI callers and pre-migration tests use this outward adapter."""
    if not isinstance(response, Response):
        raise TypeError('Native handler must return Response')
    status = getattr(response, 'legacy_status', None)
    if not status:
        try:
            phrase = HTTPStatus(response.status_code).phrase
        except ValueError:
            phrase = 'Error'
        status = str(response.status_code) + ' ' + phrase
    callback(status, getattr(response, 'original_headers', None) or [
        (key.decode('latin-1').title(), value.decode('latin-1')) for key, value in response.raw_headers])
    return [response.body]


def legacy_compatible(callback_index=None, request_index=None):
    """Retain the old Python/CGI interface while native calls use no callback."""
    def decorate(function):
        @functools.wraps(function)
        def call(*args, **kwargs):
            values = list(args)
            legacy_original = None
            native_context = None
            callback = kwargs.pop('start_response', None)
            if callback_index is not None and len(values) > callback_index and callable(values[callback_index]):
                callback = values.pop(callback_index)
            index = request_index
            if index is not None and callback_index is not None and callback_index < index:
                index -= 1
            if index is not None and len(values) > index:
                value = values[index]
                if isinstance(value, Mapping) and not isinstance(value, HttpContext) and any(
                    key in KEYS or str(key).startswith('HTTP_') for key in value
                ):
                    legacy_original = value
                    values[index] = legacy_to_context(value)
                    native_context = values[index]
            for name in ('environ', 'request_context'):
                if name in kwargs:
                    value = kwargs.pop(name)
                    kwargs['request_context'] = legacy_to_context(value) if any(
                        key in KEYS or str(key).startswith('HTTP_') for key in value
                    ) else value
                    break
            result = function(*values, **kwargs)
            if legacy_original is not None:
                inverse_keys = {value: key for key, value in KEYS.items()}
                for key, value in native_context.items():
                    old_key = inverse_keys.get(key, key)
                    if str(key).startswith('header:'):
                        old_key = 'HTTP_' + key[7:].replace('-', '_').upper()
                    legacy_original[old_key] = value
            return to_wsgi(result, callback) if callback is not None else result
        return call
    return decorate


async def context_from_request(request, max_bytes=50 * 1024 * 1024):
    """Read ASGI input once, retaining CGI metadata only as transport data."""
    import os
    from tempfile import SpooledTemporaryFile
    original = request.scope.get('wsgi_environ') or {}
    route_path = request.scope.get('path', request.url.path)
    root_path = request.scope.get('root_path', '').rstrip('/')
    if root_path and (route_path == root_path or route_path.startswith(root_path + '/')):
        route_path = route_path[len(root_path):] or '/'
    context = HttpContext({
        'method': request.method, 'path': route_path,
        'query': request.scope.get('query_string', b'').decode('latin-1'),
        'content_type': request.headers.get('content-type', ''),
        'content_length': request.headers.get('content-length', ''),
        'client_address': request.client.host if request.client else '0.0.0.0',
        'uri': request.url.path + ('?' + request.url.query if request.url.query else ''),
        'mount_path': request.scope.get('root_path', ''),
        'https': 'on' if request.url.scheme == 'https' else 'off',
        'document_root': os.environ.get('DOCUMENT_ROOT', ''),
    })
    # These values are deployment context, never an input/output protocol.
    for source in ('REMOTE_ADDR', 'REQUEST_URI', 'REDIRECT_STATUS', 'REDIRECT_URL', 'SCRIPT_NAME', 'DOCUMENT_ROOT', 'HTTPS'):
        if source in original:
            context[context_key(source)] = original[source]
    for key, value in original.items():
        if key.startswith(('PYTHON_MIGRATION_', 'TUTI_')):
            context[key] = value
    for key, value in request.headers.items():
        context['header:' + key.lower()] = value
    try:
        length = int(context.get('content_length') or 0)
        if length < 0:
            raise ValueError()
    except (ValueError, TypeError):
        return None, make_response(b'{"ok":false,"error":"invalid_content_length"}', 400,
                                   [('Content-Type', 'application/json; charset=utf-8')])
    if length > max_bytes:
        return None, make_response(b'{"ok":false,"error":"request_too_large"}', 413,
                                   [('Content-Type', 'application/json; charset=utf-8')])
    stream = SpooledTemporaryFile(max_size=1024 * 1024, mode='w+b')
    try:
        received = 0
        async for chunk in request.stream():
            received += len(chunk)
            if received > max_bytes:
                stream.close()
                return None, make_response(b'{"ok":false,"error":"request_too_large"}', 413,
                                           [('Content-Type', 'application/json; charset=utf-8')])
            stream.write(chunk)
        stream.seek(0)
        context['body_stream'] = stream
        context['content_length'] = str(received)
        return context, None
    except BaseException:
        stream.close()
        raise
