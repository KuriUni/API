import importlib.util
import os
import pathlib
import unittest

if os.name == "nt":
    raise unittest.SkipTest("The Sunabar Core uses fcntl, which is unavailable on Windows.")

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORE_PATH = ROOT / "suna-core-source" / "main.py"
SPEC = importlib.util.spec_from_file_location("sunabar_core_under_test", str(CORE_PATH))
sunabar = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sunabar)


class SunabarCoreCorsTests(unittest.TestCase):
    def test_responses_do_not_grant_wildcard_cross_origin_access(self):
        response = sunabar._response(200, {"ok": True}).decode("ascii")
        self.assertNotIn("Access-Control-Allow-Origin", response)
        self.assertNotIn("Access-Control-Allow-Headers", response)
        self.assertNotIn("Access-Control-Allow-Methods", response)

    def test_options_response_does_not_grant_cross_origin_access(self):
        response = sunabar.handle("OPTIONS", "/api/v1/products", {}, "127.0.0.1",
                                  "", "0", __import__("io").BytesIO()).decode("ascii")
        self.assertNotIn("Access-Control-Allow-Origin", response)


if __name__ == "__main__":
    unittest.main()
