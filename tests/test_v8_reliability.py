import io
import json
import pathlib
import sys
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'xrea-source'))
import pymysql
import baas_v8_handlers as v8
from native_http import HttpContext

JOB_ID = 'a' * 32


class SubmissionTests(unittest.TestCase):
    def test_lost_connection_during_rollback_still_returns_a_generic_503(self):
        connection = MagicMock()
        connection.rollback.side_effect = pymysql.err.OperationalError(2013, 'test private connection detail')
        with patch('database.connect', return_value=connection), \
             patch.object(v8, '_preflight', side_effect=pymysql.err.OperationalError(2013, 'test private connection detail')):
            response = v8.issuance(HttpContext(method='POST'))
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b'private connection', response.body)

    def test_async_submission_never_runs_an_inline_worker(self):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        # Submission now checks legacy issuance tables and all historical
        # engine queues before reserving tenant quota.
        cursor.fetchone.side_effect = [{'id': 1}, {'max_licenses': 100}, None] + [{'n': 0}] * 20
        job = dict(id=1, job_id=JOB_ID, status='queued', requested_count=1,
                   environment='sandbox', product_id=1, license_mode='single')
        with patch('database.connect', return_value=connection), patch.object(v8, '_preflight', return_value=None), \
             patch.object(v8, '_authorize_key', return_value=({'id': 1, 'tenant_id': 1, 'tenant_environment': 'sandbox'}, [], 'test')), \
             patch.object(v8, '_read_json', return_value={'count': 1, 'product_id': 1, 'idempotency_key': JOB_ID, 'execution_mode': 'async'}), \
             patch('v3_handlers._assert_write_fence'), patch.object(v8, '_usage'), \
             patch.object(v8, '_get_job', return_value=job), patch.object(v8, 'process_job') as process:
            response = v8.issuance(HttpContext(method='POST'))
        self.assertEqual(response.status_code, 202)
        self.assertEqual(json.loads(response.body)['execution'], 'async')
        process.assert_not_called()

    def test_conflicting_idempotency_keys_and_unknown_modes_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'idempotency_key_mismatch'):
            v8._submission_identity({'idempotency_key': 'a' * 32}, {'header:idempotency-key': 'b' * 32})
        with self.assertRaisesRegex(ValueError, 'invalid_execution_mode'):
            v8._submission_identity({'idempotency_key': 'a' * 32, 'execution_mode': 'surprise'}, {})
        self.assertEqual(v8._submission_identity({'execution_mode': 'async'}, {'header:idempotency-key': JOB_ID}), (JOB_ID, 'async'))

    def test_retry_deadlines_use_utc_and_do_not_go_negative(self):
        now = datetime(2026, 11, 8, tzinfo=timezone.utc)
        self.assertEqual(v8._retry_after_ms({'next_attempt_at': (now + timedelta(seconds=5)).replace(tzinfo=None)}, now), 5000)
        self.assertEqual(v8._retry_after_ms({'next_attempt_at': now - timedelta(seconds=1)}, now), 0)


class WorkerRecoveryTests(unittest.TestCase):
    def test_busy_old_job_does_not_block_the_next_queue_candidate(self):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchall.return_value = [{'job_id': JOB_ID}, {'job_id': 'b' * 32}]
        row = dict(job_id=JOB_ID, status='processing', requested_count=10, environment='sandbox', product_id=1, license_mode='single')
        with patch.object(v8, 'process_job', side_effect=[dict(row, _worker_busy=True), dict(row, job_id='b' * 32)]) as process:
            results = v8.pump_due_jobs(connection, max_jobs=1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['job_id'], 'b' * 32)
        self.assertEqual(process.call_count, 2)

    def run_job(self, error=None, retries=0, status='queued', deadline=None, cancel_on_error=False):
        job = {'id': 1, 'job_id': JOB_ID, 'status': status, 'processed_count': 3,
               'requested_count': 10, 'succeeded_count': 3, 'chunk_size': 5,
               'retry_count': retries, 'next_attempt_at': deadline}
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = {'lock': 1}
        def execute(sql, params=()):
            if "SET status='queued'" in sql and job['status'] == 'processing':
                job.update(status='queued', retry_count=job['retry_count'] + 1,
                           next_attempt_at=datetime.now(timezone.utc) + timedelta(seconds=params[0]))
            elif "SET status='failed'" in sql and job['status'] not in ('cancel_requested', 'cancelled', 'completed'):
                job.update(status='failed', failed_count=7)
            elif "SET status='processing'" in sql and job['status'] in ('queued', 'processing'):
                job['status'] = 'processing'
            elif "SET status='cancelled'" in sql and job['status'] == 'cancel_requested':
                job['status'] = 'cancelled'
        cursor.execute.side_effect = execute
        def chunk(*args):
            if cancel_on_error:
                job['status'] = 'cancel_requested'
            if error:
                raise error
            job.update(status='completed', processed_count=10, succeeded_count=10)
        with patch.object(v8, '_get_job_by_id', side_effect=lambda *args: dict(job)), \
             patch.object(v8, '_process_chunk', side_effect=chunk) as process:
            result = v8.process_job(connection, JOB_ID)
        return result, cursor, process

    def test_deadlock_is_scheduled_for_retry_and_keeps_committed_progress(self):
        result, cursor, _ = self.run_job(pymysql.err.OperationalError(1213, 'test deadlock'))
        self.assertEqual((result['status'], result['retry_count'], result['processed_count']), ('queued', 1, 3))
        self.assertGreater(v8._retry_after_ms(result), 0)
        self.assertTrue(any('RELEASE_LOCK' in call.args[0] for call in cursor.execute.call_args_list))

    def test_delayed_job_is_not_processed_early(self):
        result, _, process = self.run_job(deadline=datetime.now(timezone.utc) + timedelta(seconds=30))
        self.assertEqual(result['status'], 'queued')
        process.assert_not_called()

    def test_exhausted_retries_and_permanent_errors_fail(self):
        for error, retries in ((pymysql.err.OperationalError(1213, 'test'), 5), (RuntimeError('product_not_found'), 0)):
            result, _, _ = self.run_job(error, retries)
            self.assertEqual((result['status'], result['processed_count'], result['failed_count']), ('failed', 3, 7))

    def test_cancellation_is_not_overwritten_by_transient_failure(self):
        result, _, _ = self.run_job(pymysql.err.OperationalError(1213, 'test'), cancel_on_error=True)
        self.assertEqual(result['status'], 'cancel_requested')
        result, _, process = self.run_job(status='cancel_requested')
        self.assertEqual(result['status'], 'cancelled')
        process.assert_not_called()

    def test_success_and_resume_do_not_reset_committed_counters(self):
        result, _, _ = self.run_job(retries=2)
        self.assertEqual((result['status'], result['processed_count'], result['retry_count']), ('completed', 10, 2))

    def test_chunk_uses_locked_progress_instead_of_stale_job_copy(self):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.side_effect = [{'status': 'processing', 'processed_count': 7, 'requested_count': 10}, {'ok': 1}, {'ok': 1}]
        job = dict(id=1, job_id=JOB_ID, tenant_id=1, product_id=1, processed_count=3, requested_count=10, max_devices=1)
        with patch('v3_handlers._assert_write_fence'), patch('v2_handlers._runtime_config', return_value={}), \
             patch.object(v8, '_derive_ciphers'), patch.object(v8, '_generate_records', return_value=[]) as generate, \
             patch.object(v8, '_insert_records'), patch.object(v8, '_queue_webhook'):
            v8._process_chunk(connection, job, 5)
        self.assertEqual(generate.call_args.args[3:5], (8, 3))
        updates = [call for call in cursor.execute.call_args_list if 'SET processed_count=' in call.args[0]]
        self.assertEqual(updates[0].args[1][:2], (10, 3))


class ResultPaginationTests(unittest.TestCase):
    def test_deleted_license_gaps_do_not_create_endless_next_cursor(self):
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchall.return_value = [{'item_no': n, 'license_id': n, 'key_fingerprint': 'test', 'created_at': ''} for n in (1, 3)]
        job = dict(id=1, job_id=JOB_ID, status='completed', requested_count=3, succeeded_count=3, environment='sandbox', product_id=1, license_mode='single')
        with patch('database.connect', return_value=connection), patch.object(v8, '_preflight', return_value=None), \
             patch.object(v8, '_authorize_key', return_value=({'tenant_id': 1}, [], 'test')), \
             patch.object(v8, '_get_job', return_value=job), patch.object(v8, '_usage'):
            response = v8.issuance_results(HttpContext(method='GET', query='job_id=' + JOB_ID + '&limit=2'))
        body = json.loads(response.body)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(body['items']), 2)
        self.assertFalse(body['has_more'])
        self.assertIsNone(body['next_cursor'])
        self.assertEqual(cursor.execute.call_args.args[1][-1], 3)


class QueueDiagnosticsTests(unittest.TestCase):
    def test_get_is_read_only_and_requires_authentication(self):
        import ha_product_key_v8_worker as worker
        with patch('ha_handlers._ha_authorized_scope', return_value=False), patch('database.connect') as connect:
            self.assertEqual(worker.product_key_v8_worker(HttpContext(method='GET')).status_code, 404)
            connect.assert_not_called()
        with patch('ha_handlers._ha_authorized_scope', return_value=True), patch('database.connect', return_value=MagicMock()), \
             patch.object(v8, '_schema_ready', return_value=True), patch.object(v8, 'queue_status', return_value={'active_jobs': 0}), \
             patch.object(v8, 'pump_due_jobs', side_effect=AssertionError('must not process on GET')):
            response = worker.product_key_v8_worker(HttpContext(method='GET'))
            self.assertEqual(json.loads(response.body)['mode'], 'status')

    def test_malformed_worker_json_is_a_client_error(self):
        import ha_product_key_v8_worker as worker
        with patch('ha_handlers._ha_authorized_scope', return_value=True), patch('database.connect') as connect:
            response = worker.product_key_v8_worker(HttpContext(method='POST', body_stream=io.BytesIO(b'{bad')))
            self.assertEqual(response.status_code, 400)
            connect.assert_not_called()


class SchemaReliabilityTests(unittest.TestCase):
    def test_existing_schema_is_expanded_once_without_touching_legacy_tables(self):
        import product_key_v8_storage as storage
        columns = {table: set(names) for table, names in storage.REQUIRED_COLUMNS.items()}
        columns['product_key_v8_jobs'] -= {'retry_count', 'next_attempt_at', 'last_error_at'}
        statements = []
        class Cursor:
            index = False
            table = 'product_key_v8_jobs'
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def execute(self, sql, params=()):
                statements.append(sql)
                if 'information_schema.columns' in sql:
                    self.table = params[0] if params else 'product_key_v8_jobs'
                if sql.startswith('ALTER TABLE'):
                    columns['product_key_v8_jobs'].add(sql.split()[5])
                if sql.startswith('CREATE INDEX'):
                    self.index = True
            def fetchall(self): return [{'column_name': name} for name in columns[self.table]]
            def fetchone(self): return {'Key_name': 'idx_pk8_due'} if self.index else None
        connection = MagicMock()
        connection.cursor.return_value = Cursor()
        storage.ensure_schema(connection)
        storage.ensure_schema(connection)
        alters = [sql for sql in statements if sql.startswith('ALTER TABLE')]
        self.assertEqual(len(alters), 3)
        self.assertTrue(all(sql.startswith('ALTER TABLE product_key_v8_jobs ') for sql in alters))
        self.assertEqual(sum(sql.startswith('CREATE INDEX') for sql in statements), 1)


if __name__ == '__main__':
    unittest.main()
