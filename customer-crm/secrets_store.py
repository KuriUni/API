"""At-rest encryption for tenant API keys.

Keys are stored as AES-256-GCM ciphertexts. The data key comes from
``CRM_SECRET`` when set; otherwise a random secret file is created next to the
SQLite database so keys survive restarts on a single-machine install.

The plaintext key never leaves this module except to build an API request.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PREFIX = "v1:"
_ASSOCIATED = b"tuti-crm/api-key"


class SecretError(Exception):
    """Raised when a stored key cannot be decrypted."""


def load_data_key(data_dir: Path) -> bytes:
    configured = (os.environ.get("CRM_SECRET") or "").strip()
    if configured:
        return hashlib.sha256(b"tuti-crm-secret-v1:" + configured.encode("utf-8")).digest()
    secret_path = Path(data_dir) / ".secret"
    if not secret_path.exists():
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        secret_path.write_bytes(os.urandom(32))
        try:
            secret_path.chmod(0o600)
        except OSError:
            pass
    return hashlib.sha256(secret_path.read_bytes()).digest()


def encrypt(data_key: bytes, plaintext: str) -> str:
    nonce = os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce, plaintext.encode("utf-8"), _ASSOCIATED)
    return _PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt(data_key: bytes, blob: str) -> str:
    if not isinstance(blob, str) or not blob.startswith(_PREFIX):
        raise SecretError("保存されたAPIキーの形式が不正です")
    try:
        raw = base64.urlsafe_b64decode(blob[len(_PREFIX):].encode("ascii"))
        plaintext = AESGCM(data_key).decrypt(raw[:12], raw[12:], _ASSOCIATED)
        return plaintext.decode("utf-8")
    except Exception as error:  # noqa: BLE001 - surfaced as a user-facing error
        raise SecretError("保存されたAPIキーを復号できません（CRM_SECRET が変わった可能性があります）") from error


def key_hint(api_key: str) -> str:
    """A non-reversible hint such as ``baas_live_…9f2c``."""
    key = (api_key or "").strip()
    if len(key) <= 4:
        return "…"
    prefix = key[:10] if key.startswith("baas_") else ""
    return f"{prefix}…{key[-4:]}"
