import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "xrea-source"))

import app_sso
import migration_config
import passkey_handlers


class PrivateRuntimeSymlinkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.private = self.base / "private"
        self.private.mkdir()
        self.docroot = self.base / "public_html"
        self.docroot.mkdir()
        self.external = self.base / "external"
        self.external.mkdir()
        self.env = mock.patch.dict(os.environ, {
            "PYTHON_MIGRATION_PRIVATE_DIR": str(self.private),
            "DOCUMENT_ROOT": str(self.docroot),
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_passkey_store_rejects_symlinked_runtime_directory(self):
        (self.private / "runtime").symlink_to(self.external, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "unsafe_private_runtime_directory"):
            passkey_handlers._private_dir()

    def test_runtime_secret_reader_fails_closed_on_symlinked_runtime(self):
        (self.private / "runtime").symlink_to(self.external, target_is_directory=True)
        self.assertEqual(migration_config.runtime_secrets(), {})

    def test_runtime_secret_writer_rejects_symlinked_runtime(self):
        (self.private / "runtime").symlink_to(self.external, target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError, "unsafe_runtime_secret_path"):
            migration_config.update_runtime_secrets({"ha_sync_token": "x" * 48})

    def test_passkey_store_lock_rejects_symlinked_lock_file(self):
        runtime = self.private / "runtime"
        runtime.mkdir(mode=0o700)
        target = self.external / "lock-target"
        target.write_text("", encoding="utf-8")
        (runtime / "passkey-store.lock").symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "unsafe_passkey_store_lock"):
            with passkey_handlers._passkey_store_lock():
                pass

    def test_app_sso_store_rejects_symlinked_grant_file(self):
        target = self.external / "grants.json"
        target.write_text("{}", encoding="utf-8")
        link = self.private / "runtime" / "app-sso-grants.json"
        link.parent.mkdir(parents=True)
        link.symlink_to(target)
        with mock.patch.object(app_sso, "_path", return_value=link):
            with self.assertRaisesRegex(RuntimeError, "unsafe_app_sso_store_path"):
                with app_sso._store():
                    pass

    def test_app_sso_store_rejects_symlinked_lock_file(self):
        runtime = self.private / "runtime"
        runtime.mkdir()
        target = self.external / "lock-target"
        target.write_text("", encoding="utf-8")
        link = runtime / "app-sso-grants.lock"
        link.symlink_to(target)
        path = runtime / "app-sso-grants.json"
        with mock.patch.object(app_sso, "_path", return_value=path):
            with self.assertRaisesRegex(RuntimeError, "unsafe_app_sso_store_path"):
                with app_sso._store():
                    pass


if __name__ == "__main__":
    unittest.main()
