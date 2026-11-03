"""Private MySQL configuration with isolated-test and explicit production gates.

Production writes require independent profile/config switches and validation
of schema 039. Existing read-only connections keep their SQL write barrier.
"""
from native_http import make_response, add_headers, legacy_compatible
import json
import hmac
import os
import re
import threading
from pathlib import Path
from path_utils import is_relative_to

class DatabaseConfigurationError(RuntimeError):
    pass

class ProductionWriteBlocked(RuntimeError):
    pass

class _ReadOnlyCursor:
    _READS = {'SELECT', 'SHOW', 'DESCRIBE', 'DESC', 'EXPLAIN'}
    _MUTATIONS = ('INSERT', 'UPDATE', 'DELETE', 'REPLACE', 'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'RENAME', 'GRANT', 'REVOKE', 'CALL', 'LOAD', 'HANDLER')

    def __init__(self, cursor):
        self._cursor = cursor

    def execute(self, query, args=None):
        statement = str(query).lstrip()
        while statement.startswith(('--', '/*', '#')):
            if statement.startswith('/*'):
                end = statement.find('*/', 2)
                statement = statement[end + 2:].lstrip() if end >= 0 else ''
            else:
                newline = statement.find('\n')
                statement = statement[newline + 1:].lstrip() if newline >= 0 else ''
        operation = statement.split(None, 1)[0].upper() if statement else ''
        if re.fullmatch('SET\\s+TRANSACTION\\s+ISOLATION\\s+LEVEL\\s+REPEATABLE\\s+READ\\s*;?', statement, re.I):
            return self._cursor.execute(query, args)
        if operation not in self._READS or re.search('\\b(?:' + '|'.join(self._MUTATIONS) + ')\\b', statement, re.I) or re.search('\\bINTO\\s+(?:OUTFILE|DUMPFILE)\\b', statement, re.I):
            raise ProductionWriteBlocked('production database connection is read-only')
        return self._cursor.execute(query, args)

    def executemany(self, query, args):
        raise ProductionWriteBlocked('production database connection is read-only')

    def __enter__(self):
        self._cursor.__enter__()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return self._cursor.__exit__(exc_type, exc_value, traceback)

    def __getattr__(self, name):
        return getattr(self._cursor, name)

class _ReadOnlyConnection:

    def __init__(self, connection):
        self._connection = connection

    def cursor(self, *args, **kwargs):
        return _ReadOnlyCursor(self._connection.cursor(*args, **kwargs))

    def __getattr__(self, name):
        return getattr(self._connection, name)

class _RollbackTestConnection:
    """Allow request-local writes whose outer transaction is always rolled back."""

    def __init__(self, connection):
        self._connection = connection

    def begin(self):
        return None

    def commit(self):
        return None

    def rollback(self):
        return None

    def close(self):
        return None

    def __getattr__(self, name):
        return getattr(self._connection, name)
_rollback_test_local = threading.local()
_ROLLBACK_TEST_PATH = '/api/baas/v1/common-id-sso/authorize.php'

@legacy_compatible(callback_index=None, request_index=0)
def begin_rollback_test_request(request_context, path):
    """Enable a private rollback-only DB transaction for one isolated probe URL."""
    if path != _ROLLBACK_TEST_PATH or getattr(_rollback_test_local, 'state', None):
        return False
    configured = _private_config()
    expected = configured.get('rollback_test_token')
    supplied = str(request_context.get('header:x-python-migration-rollback-token', ''))
    if configured.get('allow_production') is not True or configured.get('read_only') is not True or (not isinstance(expected, str)) or (len(expected) < 40) or (not supplied) or (not hmac.compare_digest(expected, supplied)):
        return False
    _rollback_test_local.state = {'connection': None}
    return True

def end_rollback_test_request():
    """Roll back and close the shared physical DB connection, even on errors."""
    state = getattr(_rollback_test_local, 'state', None)
    if not state:
        return
    connection = state.get('connection')
    try:
        if connection is not None:
            connection.rollback()
    finally:
        try:
            if connection is not None:
                connection.close()
        finally:
            try:
                del _rollback_test_local.state
            except AttributeError:
                pass

def _private_config():
    """Read test-only DB credentials from the private runtime directory."""
    raw = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not raw:
        return {}
    try:
        private = Path(raw).expanduser().resolve(strict=True)
        app_root = Path(__file__).resolve().parent
        if private == app_root or is_relative_to(private, app_root):
            return {}
        docroot_raw = os.environ.get('DOCUMENT_ROOT', '').strip()
        if docroot_raw:
            docroot = Path(docroot_raw).resolve()
            public_html = docroot
            if 'public_html' in docroot.parts:
                public_html = Path(*docroot.parts[:docroot.parts.index('public_html') + 1])
            if is_relative_to(private, docroot) or is_relative_to(private, public_html):
                return {}
        path = private / 'database-config.json'
        if path.is_symlink() or not path.is_file():
            return {}
        if path.stat().st_size > 16384:
            return {}
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}

def connect():
    configured = _private_config()
    from_file = configured.get('enabled') is True
    from_environment = os.environ.get('PYTHON_MIGRATION_ALLOW_DATABASE') == '1'
    if not (from_file or from_environment):
        raise DatabaseConfigurationError('test database access is not enabled')

    def setting(environment_name, config_name, default=''):
        value = os.environ.get(environment_name)
        if value is not None and value != '':
            return value
        return configured.get(config_name, default)
    name = str(setting('PYTHON_MIGRATION_DB_NAME', 'name')).strip()
    is_test_database = name.startswith('test_') or name.startswith('python_migration_') or '_test_' in name or name.endswith('_test') or ('_python_migration_' in name) or name.endswith('_python_migration')
    production_read_only = configured.get('allow_production') is True and configured.get('read_only') is True
    production_write = configured.get('allow_production') is True and configured.get('read_only') is False and (configured.get('write_enabled') is True) and (os.environ.get('PYTHON_MIGRATION_PROFILE') == 'production') and (os.environ.get('PYTHON_MIGRATION_ENABLE_PRODUCTION_WRITES') == '1') and (os.environ.get('PYTHON_MIGRATION_HA_ROLE') in {'primary', 'standby'})
    rollback_state = getattr(_rollback_test_local, 'state', None)
    if rollback_state is not None and (not production_read_only):
        raise DatabaseConfigurationError('rollback test requires a read-only production config')
    if not is_test_database and (not (production_read_only or production_write)):
        raise DatabaseConfigurationError('database name must be explicitly test-scoped')
    if rollback_state is not None and rollback_state.get('connection') is not None:
        return _RollbackTestConnection(rollback_state['connection'])
    host = str(setting('PYTHON_MIGRATION_DB_HOST', 'host')).strip()
    user = str(setting('PYTHON_MIGRATION_DB_USER', 'user')).strip()
    password = str(setting('PYTHON_MIGRATION_DB_PASSWORD', 'password'))
    if not host or not user or (not password):
        raise DatabaseConfigurationError('test database connection variables are incomplete')
    try:
        import pymysql
    except ImportError as exc:
        raise DatabaseConfigurationError('install the PyMySQL dependency to enable the test database') from exc
    try:
        port = int(setting('PYTHON_MIGRATION_DB_PORT', 'port', '3306'))
    except (TypeError, ValueError):
        raise DatabaseConfigurationError('test database port is invalid') from None
    timeouts = {}
    for kind, default in (('connect', 5), ('read', 10), ('write', 10)):
        value = setting('PYTHON_MIGRATION_DB_' + kind.upper() + '_TIMEOUT', kind + '_timeout', default)
        if not re.fullmatch('[0-9]{1,2}', str(value)) or not 1 <= int(value) <= 60:
            raise DatabaseConfigurationError('database ' + kind + ' timeout must be an integer from 1 to 60 seconds')
        timeouts[kind + '_timeout'] = int(value)
    from request_metrics import timed_database, instrument_connection
    with timed_database('connect'):
        connection = pymysql.connect(host=host, port=port, user=user, password=password, database=name, charset='utf8mb4', autocommit=False, cursorclass=pymysql.cursors.DictCursor, init_command="SET time_zone = '+00:00'", **timeouts)
    connection = instrument_connection(connection)
    if production_write:
        try:
            from schema39_storage import load_plan, validate, VERSION
            with connection.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) AS n FROM schema_migrations WHERE version=%s', (VERSION,))
                if int((cursor.fetchone() or {}).get('n', 0)) != 1:
                    raise DatabaseConfigurationError('production_schema039_required')
                validate(cursor, load_plan())
        except Exception:
            connection.close()
            raise
    if production_read_only and rollback_state is None:
        try:
            with connection.cursor() as cursor:
                cursor.execute('SET SESSION TRANSACTION READ ONLY')
        except Exception:
            connection.close()
            raise
        return _ReadOnlyConnection(connection)
    if rollback_state is not None:
        rollback_state['connection'] = connection
        return _RollbackTestConnection(connection)
    return connection
