import importlib.util
import pathlib
import sys
import types
import unittest
import io
import json
from unittest.mock import patch, MagicMock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "xrea-source"

sys.path.insert(0, str(SERVER_DIR))
from native_http import HttpContext, legacy_compatible, make_response
spec = importlib.util.spec_from_file_location("issuance_cutover_retired_auth", SERVER_DIR / "retired_auth.py")
retired_auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retired_auth)


class IssuanceCutoverTests(unittest.TestCase):
    def test_only_v1_and_v8_are_new_issuance_entry_points(self):
        self.assertFalse(retired_auth.is_retired_issuance_request("/api/baas/v1/licenses.php", "POST"))
        self.assertFalse(retired_auth.is_retired_issuance_request("/api/baas/v8/issuance.php", "POST"))
        for version, path in ((2, "/api/baas/v2/licenses.php"),
                              (3, "/api/baas/v3/licenses.php"),
                              (7, "/api/baas/v7/issuance.php")):
            with self.subTest(version=version):
                self.assertTrue(retired_auth.is_retired_issuance_request(path, "POST"))

    def test_v4_v6_submit_closed_but_existing_job_operations_remain(self):
        for path in ("/api/baas/v4/issuance-jobs.php", "/api/baas/v5/issuance.php",
                     "/api/baas/v6/issuance.php"):
            with self.subTest(path=path):
                self.assertTrue(retired_auth.is_retired_issuance_request(path, "POST"))
        for path, method in (("/api/baas/v4/issuance-jobs.php", "GET"),
                             ("/api/baas/v4/issuance-results.php", "GET"),
                             ("/api/baas/v5/issuance-cancel.php", "POST"),
                             ("/api/baas/v6/issuance-results.php", "GET")):
            with self.subTest(path=path, method=method):
                self.assertFalse(retired_auth.is_retired_issuance_request(path, method))

    def test_retired_submission_returns_gone_with_v8_replacement(self):
        status, headers, body = retired_auth.response({
            "path": "/api/baas/v7/issuance.php",
            "uri": "/api/baas/v7/issuance.php",
            "method": "POST",
            "mount_path": "",
        })
        self.assertEqual(status, "410 Gone")
        self.assertIn(b"/api/baas/v8/issuance.php", body)
        self.assertTrue(any(name == "Cache-Control" and value == "no-store" for name, value in headers))


class DispatchCompatibilityTests(unittest.TestCase):
    def setUp(self):
        import app
        import native_routes
        self.wsgi = app
        self.native = native_routes

    def invoke(self, path, method, native):
        if native:
            response = self.native.dispatch_native(HttpContext(path=path, method=method, query=''))
            return response.status_code, json.loads(response.body)
        captured = []
        body = b''.join(self.wsgi.application(
            {'PATH_INFO': path, 'REQUEST_METHOD': method, 'QUERY_STRING': '',
             'wsgi.input': io.BytesIO(b''), 'CONTENT_LENGTH': '0'},
            lambda status, headers: captured.append(status)))
        return int(captured[0].split()[0]), json.loads(body)

    def test_retired_routes_are_closed_in_both_transports(self):
        with patch('http_error_handlers.is_maintenance', return_value=False):
            for native in (True, False):
                for path in ('/api/baas/v2/licenses.php', '/api/baas/v7/issuance.php',
                             '/api/baas/v6/issuance.php', '/ha/issue-license-v3.php'):
                    with self.subTest(native=native, path=path):
                        status, body = self.invoke(path, 'POST', native)
                        self.assertEqual(status, 410)
                        self.assertEqual(body['replacement'], '/api/baas/v8/issuance.php')

    def test_existing_jobs_and_workers_remain_reachable(self):
        @legacy_compatible(callback_index=1, request_index=0)
        def handler(context, version=None):
            return make_response(json.dumps({'version': version}), 200)

        modules = {}
        for name in ('baas_issuance_handlers', 'ha_issuance_worker'):
            module = types.ModuleType(name)
            for function in ('issuance_status', 'issuance_results', 'issuance_cancel', 'issuance_worker'):
                setattr(module, function, handler)
            modules[name] = module
        with patch.dict(sys.modules, modules), patch('http_error_handlers.is_maintenance', return_value=False):
            for native in (True, False):
                for version in ('v4', 'v5', 'v6'):
                    path = '/api/baas/' + version + ('/issuance-jobs.php' if version == 'v4' else '/issuance.php')
                    status, body = self.invoke(path, 'GET', native)
                    self.assertEqual((status, body['version']), (200, version))
                    for suffix, method in (('issuance-results.php', 'GET'), ('issuance-cancel.php', 'POST')):
                        status, body = self.invoke('/api/baas/' + version + '/' + suffix, method, native)
                        self.assertEqual((status, body['version']), (200, version))
                for version in ('v4', 'v5'):
                    status, body = self.invoke('/ha/product-key-' + version + '-worker.php', 'POST', native)
                    self.assertEqual((status, body['version']), (200, version))

    def test_v8_routes_dispatch_to_current_handlers(self):
        @legacy_compatible(callback_index=1, request_index=0)
        def handler(context):
            return make_response(b'{"engine":"v8"}', 200)
        module = types.ModuleType('baas_v8_handlers')
        for function in ('issuance', 'issuance_results', 'issuance_cancel'):
            setattr(module, function, handler)
        with patch.dict(sys.modules, {'baas_v8_handlers': module}), patch('http_error_handlers.is_maintenance', return_value=False):
            for native in (True, False):
                for suffix, method in (('issuance.php', 'POST'), ('issuance-results.php', 'GET'), ('issuance-cancel.php', 'POST')):
                    status, body = self.invoke('/api/baas/v8/' + suffix, method, native)
                    self.assertEqual((status, body['engine']), (200, 'v8'))


class V1CompatibilityTests(unittest.TestCase):
    def test_v1_single_issue_remains_and_bulk_or_invalid_counts_are_rejected(self):
        import baas_handlers
        for count, status, error in ((1, 404, 'product_not_found'), (2, 410, 'bulk_issuance_moved_to_v8'),
                                     ('bad', 400, 'invalid_issue_count'), (False, 400, 'invalid_issue_count'),
                                     (0, 400, 'invalid_issue_count'), (1.5, 400, 'invalid_issue_count')):
            with self.subTest(count=count):
                connection = MagicMock()
                connection.cursor.return_value.__enter__.return_value.fetchone.return_value = None
                with patch('database.connect', return_value=connection), \
                     patch.object(baas_handlers, '_authorize_key', return_value=({'tenant_id': 1}, [], 'test-ip')), \
                     patch.object(baas_handlers, '_assert_write_fence'), \
                     patch.object(baas_handlers, '_baas_json_input', return_value={'count': count, 'product_id': 1}):
                    response = baas_handlers.licenses(HttpContext(method='POST'))
                self.assertEqual(response.status_code, status)
                self.assertEqual(json.loads(response.body)['error'], error)


class SnapshotCutoverTests(unittest.TestCase):
    def test_standby_snapshot_requires_explicit_flag_and_sync_authentication(self):
        import ha_export
        token = 'test-only-' + 'x' * 40
        for query, supplied, status, connects in (('', token, 405, False),
                                                  ('standby_backup=1', '', 404, False),
                                                  ('standby_backup=1', token, 503, True)):
            with self.subTest(query=query, authenticated=bool(supplied)), \
                 patch.dict('os.environ', {'PYTHON_MIGRATION_HA_ROLE': 'standby',
                     'PYTHON_MIGRATION_HA_PROMOTED': '0', 'PYTHON_MIGRATION_HA_SYNC_TOKEN': token}), \
                 patch('ha_handlers._runtime_json', return_value={}), \
                 patch('database.connect', side_effect=RuntimeError('test database sentinel')) as connect:
                response = ha_export.export_snapshot(HttpContext(method='GET', query=query,
                    **{'header:x-ha-token': supplied}))
                self.assertEqual(response.status_code, status)
                self.assertEqual(connect.called, connects)

    def test_v8_only_migration_does_not_run_legacy_data_migrations(self):
        import ha_migrate
        body = b'{"scope":"v8"}'
        connection = MagicMock()
        with patch.object(ha_migrate, '_ha_authorized_scope', return_value=True), \
             patch('database.connect', return_value=connection), \
             patch('schema39_storage.run_migrations', side_effect=AssertionError('legacy migration must not run')), \
             patch('product_key_v8_storage.ensure_schema', return_value={'ok': True}) as migration:
            response = ha_migrate.migrate(HttpContext(method='POST', content_type='application/json',
                content_length=str(len(body)), body_stream=io.BytesIO(body)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.body)['scope'], 'v8')
        migration.assert_called_once_with(connection)

    def test_v8_rows_round_trip_through_restore_and_counts(self):
        import ha_snapshot
        import ha_export
        import ha_handlers
        names = ('product_key_v8_jobs', 'product_key_v8_items')
        for name in names:
            self.assertIn(name, ha_export.OPTIONAL_TABLES)
            self.assertIn(name, ha_handlers.STATUS_TABLES)
        snapshot = {'tables': {names[0]: [{'id': 7}], names[1]: [{'job_row_id': 7}]}}
        schemas = {names[0]: [{'Field': 'id'}], names[1]: [{'Field': 'job_row_id'}]}
        connection = MagicMock()
        cursor = connection.cursor.return_value.__enter__.return_value
        inserted = []
        def execute(sql, params=()):
            if sql.startswith('INSERT INTO'):
                table = sql.split('`')[1]
                if table == names[1]:
                    self.assertIn(names[0], inserted)
                inserted.append(table)
        cursor.execute.side_effect = execute
        with patch('schema39_storage.import_row', side_effect=lambda table, row, *args: (table, row)):
            ha_snapshot.restore_rows(connection, snapshot, schemas)
        self.assertEqual(inserted, list(names))
        deletes = [call.args[0] for call in cursor.execute.call_args_list if call.args[0].startswith('DELETE')]
        self.assertEqual(deletes, ['DELETE FROM `product_key_v8_items`', 'DELETE FROM `product_key_v8_jobs`'])
        cursor.fetchone.return_value = {'count': 1}
        self.assertEqual(ha_snapshot.snapshot_counts(connection, snapshot), dict.fromkeys(names, 1))


if __name__ == "__main__":
    unittest.main()
