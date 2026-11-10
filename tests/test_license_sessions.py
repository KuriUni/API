import hashlib
import io
import json
import pathlib
import sqlite3
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'xrea-source'))
import pymysql
import v2_handlers as v2
import v3_handlers as v3
import native_v3
from core import token_hash, device_hash
from native_http import HttpContext

CONFIG = {'key_pepper': 'test-pepper-' + 'x' * 40, 'token_secret': 'test-secret-' + 'y' * 40}
FINGERPRINT = 'a' * 64


class SqlCursor:
    def __init__(self, owner): self.owner = owner; self.cursor = owner.raw.cursor(); self.sql = ''
    def __enter__(self): return self
    def __exit__(self, *args): self.cursor.close()
    def execute(self, sql, args=()):
        self.sql = sql; self.owner.statements.append(sql)
        sql = sql.replace('(UTC_TIMESTAMP() - INTERVAL 900 SECOND)', "datetime('now','-900 seconds')")
        if "information_schema.tables" in sql:
            sql = "SELECT 0 AS n"
        sql = sql.replace('UTC_TIMESTAMP()', 'CURRENT_TIMESTAMP').replace('%s', '?').replace(' FOR UPDATE', '')
        self.cursor.execute(sql, args)
    def fetchone(self):
        row = self.cursor.fetchone()
        if self.owner.barrier and self.sql.startswith('SELECT license_id FROM license_devices'):
            self.owner.barrier.wait(timeout=5)
        return dict(row) if row else None
    def fetchall(self): return [dict(row) for row in self.cursor.fetchall()]
    @property
    def rowcount(self): return self.cursor.rowcount


class SqlConnection:
    def __init__(self, path, barrier=None):
        self.raw = sqlite3.connect(path, timeout=5, isolation_level=None, check_same_thread=False)
        self.raw.row_factory = sqlite3.Row
        self.barrier = barrier; self.statements = []
    def cursor(self): return SqlCursor(self)
    def begin(self): self.raw.execute('BEGIN IMMEDIATE')
    def commit(self): self.raw.commit()
    def rollback(self): self.raw.rollback()
    def close(self): self.raw.close()


class LicenseDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = str(pathlib.Path(self.directory.name) / 'sessions.db')
        self.db = sqlite3.connect(self.path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
          CREATE TABLE licenses(id INTEGER PRIMARY KEY, active INTEGER, tenant_id INTEGER, expires_at TEXT, revoked_at TEXT, deleted_at TEXT, last_seen_at TEXT);
          CREATE TABLE license_devices(id INTEGER PRIMARY KEY,license_id INTEGER,device_hash TEXT,device_label TEXT,app_version TEXT,
            access_token_hash TEXT,refresh_token_hash TEXT,access_expires_at TEXT,refresh_expires_at TEXT,revoked_at TEXT,token_version INTEGER,last_seen_at TEXT,last_ip_hash TEXT);
          CREATE TABLE license_v3_devices(license_id INTEGER,device_hash TEXT,revoked_at TEXT);
          CREATE TABLE license_v3_sessions(id INTEGER,session_id TEXT,family_id TEXT,revoked_at TEXT,revoke_reason TEXT);
          CREATE TABLE license_v3_offline_tickets(session_id TEXT,revoked_at TEXT);
          CREATE TABLE license_v3_refresh_history(token_hash TEXT,family_id TEXT,expires_at TEXT);
          CREATE TABLE auth_attempts(ip_hash TEXT,action TEXT,subject_type TEXT,subject_hash TEXT,success INTEGER,error_code TEXT,attempted_at TEXT);
        ''')
        now = datetime.now(timezone.utc)
        self.db.execute('INSERT INTO licenses VALUES(1,1,1,NULL,NULL,NULL,NULL)')
        self.db.execute('INSERT INTO license_devices(id,license_id,device_hash,access_token_hash,refresh_token_hash,access_expires_at,refresh_expires_at,token_version) VALUES(1,1,?,?,?,?,?,1)',
            (device_hash(CONFIG, FINGERPRINT), token_hash(CONFIG, 'test-access'), token_hash(CONFIG, 'test-refresh'),
             (now - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'), (now + timedelta(days=2)).strftime('%Y-%m-%d %H:%M:%S')))
        self.db.commit()
    def tearDown(self): self.db.close(); self.directory.cleanup()
    def refresh(self, barrier=None):
        with patch.object(v2, '_runtime_config', return_value=CONFIG), \
             patch('database.connect', side_effect=lambda: SqlConnection(self.path, barrier)), \
             patch.object(v2, '_assert_write_fence'), patch.object(v2, '_record_usage'), \
             patch.object(v2, '_license_payload', return_value={}):
            return v2._v2_refresh(HttpContext(client_address='127.0.0.1'), 'test-request',
                {'refresh_token': 'test-refresh', 'device_fingerprint': FINGERPRINT})

    def test_refresh_recovers_after_access_expiry_and_rotates_once(self):
        response = self.refresh(); self.assertEqual(response.status_code, 200)
        session = json.loads(response.body)['session']
        self.assertGreater(session['refresh_after_seconds'], 0)
        self.assertEqual(session['token_version'], 2)
        stored = self.db.execute('SELECT refresh_token_hash,token_version FROM license_devices').fetchone()
        self.assertEqual(stored, (token_hash(CONFIG, session['refresh_token']), 2))
        self.assertEqual(self.refresh().status_code, 400)
        self.assertEqual(self.db.execute('SELECT token_version FROM license_devices').fetchone()[0], 2)

    def test_two_simultaneous_refreshes_have_only_one_winner(self):
        barrier = threading.Barrier(2)
        with patch.object(v2, '_runtime_config', return_value=CONFIG), \
             patch('database.connect', side_effect=lambda: SqlConnection(self.path, barrier)), \
             patch.object(v2, '_assert_write_fence'), patch.object(v2, '_record_usage'), \
             patch.object(v2, '_license_payload', return_value={}):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(v2._v2_refresh, HttpContext(client_address='127.0.0.1'), 'test-request',
                    {'refresh_token': 'test-refresh', 'device_fingerprint': FINGERPRINT}) for _ in range(2)]
                statuses = sorted(future.result().status_code for future in futures)
        self.assertEqual(statuses, [200, 400])
        self.assertEqual(self.db.execute('SELECT token_version FROM license_devices').fetchone()[0], 2)

    def test_revoked_expired_or_malformed_sessions_cannot_refresh(self):
        for field, value in (('revoked_at', '2026-01-01'), ('refresh_expires_at', '2000-01-01 00:00:00'), ('refresh_expires_at', 'bad'), ('refresh_expires_at', None)):
            with self.subTest(field=field, value=value):
                self.db.execute('UPDATE license_devices SET revoked_at=NULL,refresh_expires_at=?', ((datetime.now(timezone.utc)+timedelta(days=2)).strftime('%Y-%m-%d %H:%M:%S'),))
                self.db.execute('UPDATE license_devices SET ' + field + '=?', (value,)); self.db.commit()
                self.assertEqual(self.refresh().status_code, 400)
                self.assertEqual(self.db.execute('SELECT token_version FROM license_devices').fetchone()[0], 1)

    def test_refresh_expiry_is_capped_by_license_and_bad_license_state_fails_closed(self):
        expiry = (datetime.now(timezone.utc) + timedelta(minutes=2)).strftime('%Y-%m-%d %H:%M:%S')
        self.db.execute('UPDATE licenses SET expires_at=?', (expiry,)); self.db.commit()
        response = self.refresh(); self.assertEqual(response.status_code, 200)
        session = json.loads(response.body)['session']
        self.assertEqual(session['refresh_expires_at'], expiry)
        self.assertLessEqual(session['access_expires_in'], 120)
        self.db.execute('UPDATE licenses SET expires_at=?', ('invalid',)); self.db.commit()
        with self.assertRaises(v2.V2Error) as caught: v2._parse_license_expiry({'expires_at': 'invalid'})
        self.assertEqual(caught.exception.status, 503)

    def test_v2_and_v3_capacity_counts_distinct_active_devices(self):
        self.db.execute("UPDATE license_devices SET refresh_expires_at='2000-01-01 00:00:00'")
        self.db.execute('INSERT INTO license_v3_devices VALUES(1,?,NULL)', ('other-device',)); self.db.commit()
        connection = SqlConnection(self.path)
        try:
            with self.assertRaisesRegex(RuntimeError, 'license_device_limit_reached'):
                v3._guard_capacity(connection, {'id': 1, 'max_devices': 1}, device_hash(CONFIG, FINGERPRINT))
            v3._guard_capacity(connection, {'id': 1, 'max_devices': 1}, 'other-device')
            v3._guard_capacity(connection, {'id': 1, 'max_devices': 1}, device_hash(CONFIG, FINGERPRINT), include_v3=False)
        finally: connection.close()

    def test_family_revoke_revokes_all_associated_ticket_records_only(self):
        self.db.executemany('INSERT INTO license_v3_sessions VALUES(?,?,?,NULL,NULL)', [(1,'s1','family-a'),(2,'s2','family-a'),(3,'s3','family-b')])
        self.db.executemany('INSERT INTO license_v3_offline_tickets VALUES(?,NULL)', [('s1',),('s2',),('s3',)]); self.db.commit()
        connection = SqlConnection(self.path)
        try:
            connection.begin()
            self.assertEqual(v3._revoke_session_family(connection, 'family-a', 'client_family_revoke'), 2)
            connection.commit()
        finally: connection.close()
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM license_v3_offline_tickets WHERE revoked_at IS NOT NULL').fetchone()[0], 2)
        self.assertIsNone(self.db.execute("SELECT revoked_at FROM license_v3_offline_tickets WHERE session_id='s3'").fetchone()[0])

    def test_successful_challenges_are_counted_in_both_rate_limits(self):
        ip = hashlib.sha256(b'127.0.0.1').hexdigest()
        self.db.executemany("INSERT INTO auth_attempts VALUES(?,'v3_challenge','ip',?,1,'ok',CURRENT_TIMESTAMP)", [(ip,ip)]*60); self.db.commit()
        for native in (True, False):
            with self.subTest(native=native), patch('database.connect', side_effect=lambda: SqlConnection(self.path)), \
                 patch.object(v3, '_require_v3_schema'), patch.object(v3, '_assert_write_fence'), \
                 patch('v3_crypto.normalize_public_key', return_value={'thumbprint': 'test'}), patch.object(v3, '_issue_challenge') as issue:
                data = {'purpose': 'activate', 'device_public_key': 'test'}
                if native: response = native_v3.execute('challenge', data, '', '127.0.0.1', 'test-request')
                else:
                    body = json.dumps(data).encode()
                    response = v3.challenge(HttpContext(method='POST', content_type='application/json', content_length=str(len(body)), body_stream=io.BytesIO(body), client_address='127.0.0.1'))
                self.assertEqual(response.status_code, 429)
                issue.assert_not_called()

    def test_both_transports_revoke_family_ticket_records_after_proof(self):
        for native in (True, False):
            for scope, expected in (('family', 2), ('session', 1)):
                with self.subTest(native=native, scope=scope):
                    self.db.execute('DELETE FROM license_v3_sessions'); self.db.execute('DELETE FROM license_v3_offline_tickets')
                    self.db.executemany('INSERT INTO license_v3_sessions VALUES(?,?,?,NULL,NULL)', [(1,'s1','family-a'),(2,'s2','family-a'),(3,'s3','family-b')])
                    self.db.executemany('INSERT INTO license_v3_offline_tickets VALUES(?,NULL)', [('s1',),('s2',),('s3',)]); self.db.commit()
                    session = {'id': 1, 'session_id': 's1', 'family_id': 'family-a'}
                    with patch('database.connect', side_effect=lambda: SqlConnection(self.path)), \
                         patch.object(v3, '_require_v3_schema'), patch.object(v3, '_assert_write_fence'), \
                         patch.object(v3, '_load_session', return_value=session), patch.object(v3, '_session_active'), \
                         patch.object(v3, '_verify_pop') as proof:
                        data = {'access_token': 'test', 'scope': scope}
                        if native: response = native_v3.execute('revoke', data, '', '127.0.0.1', 'test-request')
                        else:
                            body = json.dumps(data).encode()
                            response = v3.session_endpoint(HttpContext(method='POST', content_type='application/json', content_length=str(len(body)), body_stream=io.BytesIO(body)), 'revoke')
                    self.assertEqual(response.status_code, 200)
                    proof.assert_called_once()
                    self.assertEqual(self.db.execute('SELECT COUNT(*) FROM license_v3_offline_tickets WHERE revoked_at IS NOT NULL').fetchone()[0], expected)

    def test_refresh_reuse_revocation_remains_committed_with_401(self):
        self.db.execute('INSERT INTO license_v3_refresh_history VALUES(?,?,?)', (token_hash(CONFIG, 'used-refresh'), 'family-a', '2099-01-01 00:00:00'))
        for native in (True, False):
            self.db.execute('DELETE FROM license_v3_sessions'); self.db.execute('DELETE FROM license_v3_offline_tickets')
            self.db.execute("INSERT INTO license_v3_sessions VALUES(1,'s1','family-a',NULL,NULL)")
            self.db.execute("INSERT INTO license_v3_offline_tickets VALUES('s1',NULL)"); self.db.commit()
            with self.subTest(native=native), patch('database.connect', side_effect=lambda: SqlConnection(self.path)), \
                 patch.object(v3, '_require_v3_schema'), patch.object(v3, '_assert_write_fence'), \
                 patch.object(v3, '_load_session', return_value=None), patch.object(v3, '_config', return_value=CONFIG):
                data = {'refresh_token': 'used-refresh'}
                if native: response = native_v3.execute('refresh', data, '', '127.0.0.1', 'test-request')
                else:
                    body = json.dumps(data).encode()
                    response = v3.session_endpoint(HttpContext(method='POST', content_type='application/json', content_length=str(len(body)), body_stream=io.BytesIO(body)), 'refresh')
                self.assertEqual(response.status_code, 401)
                self.assertEqual(json.loads(response.body)['error_code'], 'REFRESH_REUSE_DETECTED')
                self.assertIsNotNone(self.db.execute('SELECT revoked_at FROM license_v3_offline_tickets').fetchone()[0])


class LicenseErrorContractTests(unittest.TestCase):
    def test_refresh_does_not_read_license_metadata_after_committing_tokens(self):
        session = {'id': 1, 'license_id': 1, 'tenant_id': 1}
        with patch('database.connect', return_value=MagicMock()), patch.object(v3, '_require_v3_schema'), \
             patch.object(v3, '_assert_write_fence'), patch.object(v3, '_load_session', return_value=session), \
             patch.object(v3, '_session_active'), patch.object(v3, '_verify_pop'), \
             patch.object(v3, '_rotate_session', return_value={'refresh_token': 'test-new'}), \
             patch.object(v3, '_license_row', side_effect=AssertionError('No post-commit lookup')), \
             patch.object(native_v3, 'record_usage') as usage:
            response = native_v3.execute('refresh', {'refresh_token': 'test-old'}, '', '127.0.0.1', 'test-request')
        self.assertEqual(response.status_code, 200)
        self.assertIs(usage.call_args.args[1], session)

    def test_license_deleted_before_lock_cannot_issue_a_v3_session(self):
        data = {'license_key': 'AAAAA-AAAAA-AAAAA-AAAAA-AAAAA', 'device_fingerprint': FINGERPRINT, 'device_public_key': 'test'}
        for native in (True, False):
            with self.subTest(native=native), patch('database.connect', return_value=MagicMock()), \
                 patch.object(v3, '_require_v3_schema'), patch.object(v3, '_assert_write_fence'), \
                 patch.object(v3, '_config', return_value=CONFIG), patch('v3_crypto.normalize_public_key', return_value={'thumbprint': 'test'}), \
                 patch.object(v3, '_consume_challenge'), patch.object(v3, '_license_by_key', return_value={'id': 1}), \
                 patch.object(v3, '_lock_license', return_value=None), patch.object(v3, '_issue_session') as issue:
                if native: response = native_v3.execute('activate', data, '', '127.0.0.1', 'test-request')
                else:
                    body = json.dumps(data).encode()
                    response = v3.activate(HttpContext(method='POST', content_type='application/json', content_length=str(len(body)), body_stream=io.BytesIO(body)))
                self.assertEqual(response.status_code, 400)
                self.assertEqual(json.loads(response.body)['error_code'], 'LICENSE_NOT_FOUND')
                issue.assert_not_called()

    def test_error_contracts_match_and_driver_details_are_never_returned(self):
        for error, status, code in ((pymysql.err.OperationalError(2013, 'private database host'), 503, 'SERVICE_UNAVAILABLE'),
                                    (RuntimeError('private configuration value'), 503, 'SERVICE_UNAVAILABLE'),
                                    (ValueError('private malformed value'), 400, 'V3_REQUEST_FAILED'),
                                    (RuntimeError('license_expired'), 403, 'LICENSE_EXPIRED')):
            for adapter in (native_v3.error_response, v3._error_response):
                with self.subTest(adapter=adapter.__module__, status=status):
                    response = adapter(error, 'test-request')
                    self.assertEqual(response.status_code, status)
                    self.assertEqual(json.loads(response.body)['error_code'], code)
                    self.assertNotIn(b'private', response.body)
                    self.assertEqual(response.headers['X-Request-ID'], 'test-request')
                    if status == 503: self.assertEqual(response.headers['Retry-After'], '2')

    def test_session_expiry_requires_valid_dates_and_timing_is_bounded(self):
        now = datetime.now(timezone.utc).replace(microsecond=0)
        for value in (None, '', 'bad', now.strftime('%Y-%m-%d %H:%M:%S')):
            with self.assertRaises(v2.V2Error): v2._require_session_expiry({'access_expires_at': value}, ('access_expires_at',), now)
        hints = v3._session_timing(now + timedelta(seconds=100), now + timedelta(seconds=200), now)
        self.assertEqual((hints['access_expires_in'], hints['refresh_after_seconds']), (100, 80))


if __name__ == '__main__': unittest.main()
