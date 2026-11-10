"""Runtime secret resolution for isolated HA snapshots."""
import json
import os
import tempfile
from file_locking import fcntl
from pathlib import Path
from path_utils import is_relative_to


SECRET_ENV = {
    "smtp_password": "PYTHON_MIGRATION_SMTP_PASSWORD",
    "key_pepper": "PYTHON_MIGRATION_KEY_PEPPER",
    "token_secret": "PYTHON_MIGRATION_TOKEN_SECRET",
    "admin_password_hash": "PYTHON_MIGRATION_ADMIN_PASSWORD_HASH",
    "admin_oidc_sso_client_secret": "PYTHON_MIGRATION_ADMIN_OIDC_CLIENT_SECRET",
    "license_v3_signing_secret": "PYTHON_MIGRATION_V3_SIGNING_SECRET",
    "jpki_private_key": "PYTHON_MIGRATION_JPKI_PRIVATE_KEY",
    "baas_benchmark_token": "PYTHON_MIGRATION_BAAS_BENCHMARK_TOKEN",
    "common_id_sso_signing_private_key": "PYTHON_MIGRATION_COMMON_ID_SSO_SIGNING_PRIVATE_KEY",
    "common_id_sso_clients": "PYTHON_MIGRATION_COMMON_ID_SSO_CLIENTS_JSON",
    "common_id_sso_demo_client_secret": "PYTHON_MIGRATION_SSO_DEMO_CLIENT_SECRET",
    "ha_sync_token": "PYTHON_MIGRATION_HA_SYNC_TOKEN",
    "stripe_secret_key": "PYTHON_MIGRATION_STRIPE_SECRET_KEY",
    "stripe_webhook_secret": "PYTHON_MIGRATION_STRIPE_WEBHOOK_SECRET",
    "stripe_enable_live": "PYTHON_MIGRATION_STRIPE_ENABLE_LIVE",
    "stripe_return_base_url": "PYTHON_MIGRATION_STRIPE_RETURN_BASE_URL",
}


def runtime_secrets():
    private_dir = os.environ.get("PYTHON_MIGRATION_PRIVATE_DIR", "").strip()
    if not private_dir:
        return {}
    try:
        directory = Path(private_dir).expanduser().resolve(strict=True)
        document_root = Path(os.environ.get("DOCUMENT_ROOT", Path(__file__).resolve().parent)).resolve()
        public_html = document_root
        if "public_html" in document_root.parts:
            index = document_root.parts.index("public_html")
            public_html = Path(*document_root.parts[:index + 1])
        if is_relative_to(directory, document_root) or is_relative_to(directory, public_html):
            return {}
        path = (directory / "runtime" / "runtime-secrets.json").resolve(strict=True)
        if not is_relative_to(path, directory) or not path.is_file():
            return {}
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def secret_value(name):
    stored = runtime_secrets()
    if name in stored and isinstance(stored[name], str):
        return stored[name]
    env_name = SECRET_ENV.get(name)
    return os.environ.get(env_name, "") if env_name else ""


def set_runtime_secret(name, value):
    """Atomically update one isolated-site secret outside the served document root."""
    update_runtime_secrets({name: value})


def update_runtime_secrets(values):
    """Merge shared secrets under one lock, preserving node-local credentials."""
    if not isinstance(values, dict) or not values or any(
            name not in SECRET_ENV or not isinstance(value, str) for name, value in values.items()):
        raise ValueError("invalid_runtime_secret")
    raw = os.environ.get("PYTHON_MIGRATION_PRIVATE_DIR", "").strip()
    if not raw:
        raise RuntimeError("private_runtime_directory_required")
    root = Path(raw).expanduser().resolve()
    docroot = Path(os.environ.get("DOCUMENT_ROOT", Path(__file__).resolve().parent)).resolve()
    public_html = docroot
    if "public_html" in docroot.parts:
        public_html = Path(*docroot.parts[:docroot.parts.index("public_html") + 1])
    if root == docroot or is_relative_to(root, docroot) or is_relative_to(root, public_html):
        raise RuntimeError("private_runtime_directory_inside_webroot")
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    runtime.chmod(0o700)
    path = runtime / "runtime-secrets.json"
    lock_path = runtime / "runtime-secrets.lock"
    if path.is_symlink() or lock_path.is_symlink():
        raise RuntimeError("unsafe_runtime_secret_path")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a+b", closefd=False) as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            secrets = {}
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(existing, dict):
                    raise RuntimeError("invalid_runtime_secrets")
                secrets = existing
            except FileNotFoundError:
                pass
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                raise RuntimeError("invalid_runtime_secrets") from exc
            secrets.update(values)
            payload = json.dumps(secrets, ensure_ascii=False, separators=(",", ":"))
            temp_name = None
            try:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=runtime,
                                                 prefix=".runtime-secrets-", delete=False) as temp:
                    temp_name = temp.name
                    os.chmod(temp_name, 0o600)
                    temp.write(payload)
                    temp.flush()
                    os.fsync(temp.fileno())
                os.replace(temp_name, path)
                os.chmod(path, 0o600)
            finally:
                if temp_name and os.path.exists(temp_name):
                    os.unlink(temp_name)
    finally:
        os.close(fd)
