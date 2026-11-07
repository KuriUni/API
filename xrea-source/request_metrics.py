"""Request-local CGI/DB timing with bounded, private, metadata-only logs."""
import contextvars
from functools import lru_cache
import json
import os
import re
import stat
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

_current = contextvars.ContextVar('request_metrics', default=None)
MAX_LOG_BYTES = 8 * 1024 * 1024
SLOW_MS = 1000
SAMPLE_EVERY = 20


def current_request_id():
    state = _current.get()
    return state.request_id if state is not None else None


@contextmanager
def timed_database(kind):
    state = _current.get()
    if state is None:
        yield
        return
    started = time.perf_counter()
    try:
        yield
    except Exception:
        state.database_errors += 1
        raise
    finally:
        state.database_ms[kind] = state.database_ms.get(kind, 0.0) + (time.perf_counter() - started) * 1000
        state.database_calls[kind] = state.database_calls.get(kind, 0) + 1


@lru_cache(maxsize=16)
def _load_route_paths(path, modified_ns, size):
    """Cache the route inventory per file version; deployment updates invalidate it."""
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        routes = data.get('routes', []) if isinstance(data, dict) else []
        return frozenset(item['path'] for item in routes
                         if isinstance(item, dict) and isinstance(item.get('path'), str))
    except (OSError, ValueError, TypeError):
        return frozenset()


def instrument_connection(connection):
    """Preserve connection identity and driver/transaction semantics."""
    if _current.get() is None:
        return connection
    for name, kind in (('query', 'query'), ('commit', 'transaction'),
                       ('rollback', 'transaction'), ('begin', 'transaction')):
        original = getattr(connection, name, None)
        if callable(original):
            def measured(*args, _original=original, _kind=kind, **kwargs):
                with timed_database(_kind):
                    return _original(*args, **kwargs)
            try:
                setattr(connection, name, measured)
            except (AttributeError, TypeError):
                pass
    return connection


def _route(environ):
    path = environ.get('PATH_INFO') or urlsplit(environ.get('REQUEST_URI', '/')).path
    prefix = environ.get('PYTHON_MIGRATION_URL_PREFIX', '/license')
    if path.startswith(prefix + '/'):
        path = path[len(prefix):]
    if path in ('/', '/_migration/health', '/_fastapi/health', '/_fastapi/docs',
                '/_fastapi/redoc', '/_fastapi/openapi.json'):
        return path
    try:
        routes_path = Path(environ.get('TUTI_METRICS_APP_DIR') or Path(__file__).parent) / 'routes.json'
        info = routes_path.stat()
        if path in _load_route_paths(str(routes_path), info.st_mtime_ns, info.st_size):
            return path
    except (OSError, ValueError, TypeError):
        pass
    for prefix in ('/tenant-portal/', '/mobile-manager/'):
        if path.startswith(prefix):
            return prefix + '*'
    return '/unmatched'


def _append_private(environ, record):
    """Two log files, up to 8MiB each; never block a response for logging."""
    raw = environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '')
    if not raw:
        return
    private = Path(raw).resolve(strict=True)
    app_root = Path(__file__).resolve().parent
    if 'public_html' in private.parts or private == app_root or app_root in private.parents:
        return
    directory = private / 'runtime'
    if directory.is_symlink():
        return
    directory.mkdir(mode=0o700, exist_ok=True)
    path = directory / 'request-metrics.jsonl'
    backup = directory / 'request-metrics.jsonl.1'
    lock_path = directory / 'request-metrics.lock'
    if any(item.is_symlink() for item in (path, backup, lock_path)):
        return
    flags = os.O_CREAT | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0)
    from file_locking import fcntl
    with os.fdopen(os.open(lock_path, flags, 0o600), 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            return
        try:
            data = (json.dumps(record, separators=(',', ':')) + '\n').encode()
            if path.exists():
                info = path.stat()
                if not stat.S_ISREG(info.st_mode):
                    return
                if info.st_size + len(data) > MAX_LOG_BYTES:
                    if backup.exists() and not backup.is_file():
                        return
                    os.replace(path, backup)
            fd = os.open(path, flags | os.O_APPEND, 0o600)
            try:
                if hasattr(os, 'fchmod'):
                    os.fchmod(fd, 0o600)
                view = memoryview(data)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError('short request-metrics write')
                    view = view[written:]
            finally:
                os.close(fd)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


class RequestMetrics:
    def __init__(self, environ, started=None):
        self.environ = dict(environ)
        self.started = time.perf_counter() if started is None else started
        self.request_id = uuid.uuid4().hex[:16]
        self.sampled = int(self.request_id, 16) % SAMPLE_EVERY == 0
        self.bootstrap_ms = 0.0
        self.database_ms = {}
        self.database_calls = {}
        self.database_errors = 0
        self.status = 500
        self.exception_type = None
        self.finished = False

    def bootstrap_complete(self):
        self.bootstrap_ms = (time.perf_counter() - self.started) * 1000

    def activate(self):
        return _current.set(self)

    @staticmethod
    def deactivate(token):
        _current.reset(token)

    def fail(self, error):
        self.status = 500
        self.exception_type = type(error).__name__

    def sync_response_id(self, first_chunk, headers):
        """Match existing JSON request IDs before CGI emits response headers."""
        headers = list(headers)
        content_type = next((value for name, value in headers if name.lower() == 'content-type'), '')
        if 'application/json' not in content_type.lower() or len(first_chunk) > 65536:
            return headers
        try:
            payload = json.loads(first_chunk)
            candidate = payload.get('request_id') if isinstance(payload, dict) else None
            if isinstance(candidate, str) and re.fullmatch(r'[a-fA-F0-9-]{16,64}', candidate):
                self.request_id = candidate
                headers = [(name, value) for name, value in headers if name.lower() != 'x-request-id']
                headers.append(('X-Request-ID', candidate))
        except (UnicodeDecodeError, ValueError, TypeError):
            pass
        return headers

    def wrap(self, application):
        def observed(environ, start_response):
            token = self.activate()
            def response(status, headers, exc_info=None):
                self.status = int(status.split()[0])
                headers = list(headers)
                existing = next((value for name, value in headers if name.lower() == 'x-request-id'), None)
                if existing and re.fullmatch(r'[a-fA-F0-9-]{16,64}', existing):
                    self.request_id = existing
                elif existing is None:
                    headers.append(('X-Request-ID', self.request_id))
                return start_response(status, headers, exc_info) if exc_info is not None else start_response(status, headers)
            iterable = None
            try:
                iterable = application(environ, response)
                for chunk in iterable:
                    yield chunk
            except Exception as error:
                self.fail(error)
                raise
            finally:
                try:
                    if hasattr(iterable, 'close'):
                        iterable.close()
                finally:
                    self.deactivate(token)
        return observed

    def finish(self):
        if self.finished:
            return
        self.finished = True
        elapsed = (time.perf_counter() - self.started) * 1000
        if self.status < 500 and not self.database_errors and elapsed < SLOW_MS and not self.sampled:
            return
        try:
            method = self.environ.get('REQUEST_METHOD', 'GET')
            record = {'time': datetime.now(timezone.utc).isoformat(), 'request_id': self.request_id,
                      'method': method if method in ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS') else 'OTHER',
                      'route': _route(self.environ), 'status': self.status,
                      'elapsed_ms': round(elapsed, 3), 'bootstrap_ms': round(self.bootstrap_ms, 3),
                      'db_ms': {key: round(value, 3) for key, value in self.database_ms.items()},
                      'db_calls': self.database_calls, 'db_errors': self.database_errors}
            if self.exception_type:
                record['exception_type'] = self.exception_type
            _append_private(self.environ, record)
        except Exception:
            # Metrics storage problems must not change an API response.
            pass
