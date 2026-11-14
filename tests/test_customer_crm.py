import os
import pathlib
import shutil
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA = tempfile.mkdtemp(prefix="crm-test-")
os.environ["CRM_DATA"] = DATA
os.environ["CRM_PASSWORD"] = "test-password"
os.environ["CRM_SESSION_KEY"] = "test-session-key-" + "x" * 40
os.environ["CRM_SEED"] = "1"
os.environ["CRM_SECURE_COOKIES"] = "0"
sys.path.insert(0, str(ROOT / "customer-crm"))

import main  # noqa: E402
from pydantic import ValidationError  # noqa: E402


class CustomerCrmDataTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        main.initialize()
        main.initialize()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(DATA, ignore_errors=True)

    def test_demo_seed_is_idempotent(self):
        with main.closing(main.connect()) as db:
            counts = {
                table: db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("companies", "contacts", "deals", "activities", "tasks")
            }
        self.assertEqual(counts["companies"], 8)
        self.assertEqual(counts["contacts"], 11)
        self.assertEqual(counts["deals"], 10)
        self.assertEqual(counts["activities"], 10)
        self.assertEqual(counts["tasks"], 10)

    def test_pagination_clamps_to_available_pages(self):
        self.assertEqual(main._page(0, 1, 20)["pages"], 1)
        self.assertEqual(main._page(41, 3, 20)["page"], 3)
        self.assertEqual(main._page(8, 99, 20)["offset"], 0)

    def test_company_validation_rejects_unsafe_website(self):
        company = main.CompanyIn(name="テスト", website="https://example.jp")
        self.assertEqual(company.rank, "B")
        with self.assertRaises(ValidationError):
            main.CompanyIn(name="テスト", website="javascript:alert(1)")
        with self.assertRaises(ValidationError):
            main.CompanyIn(name="")

    def test_deal_and_task_validation(self):
        deal = main.DealIn(company_id=1, title="案件", stage="提案", amount=1000, probability=50)
        self.assertEqual(deal.stage, "提案")
        with self.assertRaises(ValidationError):
            main.DealIn(company_id=1, title="案件", stage="不明")
        with self.assertRaises(ValidationError):
            main.DealIn(company_id=1, title="案件", probability=101)
        with self.assertRaises(ValidationError):
            main.TaskIn(company_id=1, title="タスク", due_date="2026/11/14")

    def test_date_and_datetime_normalization(self):
        self.assertEqual(main._iso_date("2026-11-14"), "2026-11-14")
        self.assertEqual(main._iso_datetime("2026-11-14T10:30"), "2026-11-14T10:30:00")
        with self.assertRaises(ValueError):
            main._iso_date("2026/11/14")
        with self.assertRaises(ValueError):
            main._iso_datetime("not-a-date")

    def test_like_escapes_wildcards(self):
        self.assertEqual(main._like("a%b_c\\d"), "%a\\%b\\_c\\\\d%")

    def test_signed_session_round_trip_and_tamper_rejection(self):
        token = main._sign({"sub": "admin", "exp": 9999999999})
        self.assertEqual(main._unsign(token)["sub"], "admin")
        self.assertIsNone(main._unsign(token + "x"))
        expired = main._sign({"sub": "admin", "exp": 1})
        self.assertIsNone(main._unsign(expired))

    def test_seed_relationships_are_consistent(self):
        with main.closing(main.connect()) as db:
            orphan = db.execute("""
              SELECT COUNT(*) FROM deals d
              LEFT JOIN companies c ON c.id=d.company_id
              WHERE c.id IS NULL
            """).fetchone()[0]
            self.assertEqual(orphan, 0)
            company = db.execute("SELECT name FROM companies ORDER BY id LIMIT 1").fetchone()
            self.assertEqual(company["name"], "株式会社ミライ商事")


if __name__ == "__main__":
    unittest.main()
