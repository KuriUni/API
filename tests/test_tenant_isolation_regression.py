"""Cross-tenant object-reference regression tests for BaaS issuance APIs.

These tests model tenant A authenticating with its own API key and supplying
tenant B's otherwise-valid job identifier. They verify that every public
job operation performs an ownership-scoped lookup before exposing or mutating
the job. They do not contact production services or require real credentials.
"""
import io
import json
import pathlib
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "xrea-source"))

from native_http import HttpContext
import baas_issuance_handlers as v6
import baas_v8_handlers as v8

TENANT_A = 101
TENANT_B = 202
TENANT_B_JOB = "b" * 32
TENANT_A_CLIENT = {
    "id": 11,
    "tenant_id": TENANT_A,
    "tenant_environment": "sandbox",
    "tenant_slug": "tenant-a",
}


def _connection():
    connection = MagicMock()
    return connection


def _cancel_context(job_id):
    body = json.dumps({"job_id": job_id}).encode("utf-8")
    return HttpContext(
        method="POST",
        content_type="application/json",
        content_length=str(len(body)),
        body_stream=io.BytesIO(body),
    )


class TenantScopedLookupTests(unittest.TestCase):
    def test_v6_job_lookup_always_binds_authenticated_tenant_and_job_id(self):
        connection = _connection()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = None

        result = v6._job(connection, TENANT_A, TENANT_B_JOB)

        self.assertIsNone(result)
        sql, params = cursor.execute.call_args.args
        self.assertIn("tenant_id=%s", sql)
        self.assertIn("job_id=%s", sql)
        self.assertEqual(params, (TENANT_A, TENANT_B_JOB))

    def test_v8_job_lookup_always_binds_authenticated_tenant_and_job_id(self):
        connection = _connection()
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = None

        result = v8._get_job(connection, TENANT_A, TENANT_B_JOB)

        self.assertIsNone(result)
        sql, params = cursor.execute.call_args.args
        self.assertIn("tenant_id=%s", sql)
        self.assertIn("job_id=%s", sql)
        self.assertEqual(params, (TENANT_A, TENANT_B_JOB))


class V6CrossTenantEndpointTests(unittest.TestCase):
    def setUp(self):
        self.connection = _connection()
        self.auth = patch.object(
            v6, "_authorize_key",
            return_value=(TENANT_A_CLIENT, [], "test-ip-hash"),
        )
        self.auth.start()
        self.addCleanup(self.auth.stop)
        self.db = patch("database.connect", return_value=self.connection)
        self.db.start()
        self.addCleanup(self.db.stop)
        self.schema = patch.object(v6, "_missing_schema", return_value=[])
        self.schema.start()
        self.addCleanup(self.schema.stop)

    def test_status_does_not_disclose_another_tenants_job(self):
        with patch.object(v6, "_job", return_value=None):
            response = v6.issuance_status(
                HttpContext(method="GET", query="job_id=" + TENANT_B_JOB), "v6"
            )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(json.loads(response.body)["error"], "v6_job_not_found")

    def test_results_does_not_disclose_another_tenants_job_or_items(self):
        with patch.object(v6, "_job", return_value=None):
            response = v6.issuance_results(
                HttpContext(method="GET", query="job_id=" + TENANT_B_JOB), "v6"
            )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(json.loads(response.body)["error"], "v6_job_not_found")

    def test_cancel_does_not_mutate_another_tenants_job(self):
        with patch.object(v6, "_job", return_value=None), \
             patch.object(v6, "_assert_write_fence"):
            response = v6.issuance_cancel(_cancel_context(TENANT_B_JOB), "v6")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(json.loads(response.body)["error"], "v6_job_not_found")
        executed = [
            call.args[0] for call in self.connection.cursor.return_value.__enter__.return_value.execute.call_args_list
        ]
        self.assertFalse(any("UPDATE product_key_issue_jobs_v6" in sql for sql in executed))


class V8CrossTenantEndpointTests(unittest.TestCase):
    def setUp(self):
        self.connection = _connection()
        self.auth = patch.object(
            v8, "_authorize_key",
            return_value=(TENANT_A_CLIENT, [], "test-ip-hash"),
        )
        self.auth.start()
        self.addCleanup(self.auth.stop)
        self.db = patch("database.connect", return_value=self.connection)
        self.db.start()
        self.addCleanup(self.db.stop)
        self.preflight = patch.object(v8, "_preflight", return_value=None)
        self.preflight.start()
        self.addCleanup(self.preflight.stop)

    def test_status_does_not_disclose_another_tenants_job(self):
        with patch.object(v8, "_get_job", return_value=None):
            response = v8.issuance(
                HttpContext(method="GET", query="job_id=" + TENANT_B_JOB)
            )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(json.loads(response.body)["error"], "v8_job_not_found")

    def test_results_does_not_disclose_another_tenants_job_or_items(self):
        with patch.object(v8, "_get_job", return_value=None):
            response = v8.issuance_results(
                HttpContext(method="GET", query="job_id=" + TENANT_B_JOB)
            )
        self.assertEqual(response.status_code, 404)
        self.assertEqual(json.loads(response.body)["error"], "v8_job_not_found")

    def test_cancel_does_not_mutate_another_tenants_job(self):
        with patch.object(v8, "_get_job", return_value=None):
            response = v8.issuance_cancel(_cancel_context(TENANT_B_JOB))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(json.loads(response.body)["error"], "v8_job_not_found")
        executed = [
            call.args[0] for call in self.connection.cursor.return_value.__enter__.return_value.execute.call_args_list
        ]
        self.assertFalse(any("UPDATE product_key_v8_jobs" in sql for sql in executed))


if __name__ == "__main__":
    unittest.main()
