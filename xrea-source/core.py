"""Python equivalents of deterministic helpers from api/v2/core.php.

This module intentionally contains no DB connection or production secrets. It
is the first reusable layer for porting legacy API handlers into the test app.
"""

from py36_compat import parse_iso_datetime
import base64
import datetime
import hashlib
import hmac
import re
import secrets
from typing import Any, Dict, Optional


MAX_TEXT_LENGTH = 120
MAX_APP_VERSION_LENGTH = 40
MAX_LICENSE_KEY_LENGTH = 80
MAX_DEVICE_FINGERPRINT_LENGTH = 128
PHONE_INSTALLATION_ID_DIGITS = 54
PHONE_CONFIRMATION_CODE_DIGITS = 6
PHP_TRIM_CHARS = " \t\n\r\x00\x0b"
_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def php_int_cast(value: Any) -> int:
    """Approximate PHP's integer cast for JSON request values."""
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (list, tuple, dict, set)):
        return 1 if value else 0
    match = re.match(r"^[\s]*([+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?)", str(value))
    if not match:
        return 0
    token = match.group(1)
    try:
        if re.fullmatch(r"[+-]?\d+", token):
            number = int(token)
        else:
            number = int(float(token))
        return max(-(2 ** 63), min(2 ** 63 - 1, number))
    except (ValueError, OverflowError):
        return 0


def php_bool_cast(value: Any) -> bool:
    """Match PHP's bool cast, including the special false string `0`."""
    if value is None:
        return False
    if isinstance(value, str):
        return value not in ("", "0")
    if isinstance(value, bytes):
        return value not in (b"", b"0")
    return bool(value)


class ConfigurationError(RuntimeError):
    pass


def _php_string(value: Any) -> str:
    if value is None or value is False:
        return ""
    if value is True:
        return "1"
    return str(value)


def _php_trim(value: Any) -> str:
    return _php_string(value).strip(PHP_TRIM_CHARS)


def normalize_text(value: Any) -> str:
    return _php_trim(value)[:MAX_TEXT_LENGTH]


def normalize_app_version(value: Any) -> str:
    return _php_trim(value)[:MAX_APP_VERSION_LENGTH]


def normalize_license_key(value: Any) -> str:
    value = _php_trim(value).translate(_ASCII_UPPER)
    return re.sub(r"\s+", "", value, flags=re.ASCII)[:MAX_LICENSE_KEY_LENGTH]


def is_valid_license_key_format(value: str) -> bool:
    return bool(value) and re.fullmatch(r"[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}", value) is not None


def normalize_device_fingerprint(value: Any) -> str:
    value = _php_trim(value).translate(_ASCII_LOWER)
    return re.sub(r"\s+", "", value, flags=re.ASCII)[:MAX_DEVICE_FINGERPRINT_LENGTH]


def normalize_digits(value: Any) -> str:
    # The legacy PCRE pattern is not in Unicode mode; retain ASCII digits only.
    return re.sub(r"[^0-9]+", "", _php_trim(value))


def format_grouped_digits(value: Any, group_size: int = 6) -> str:
    digits = normalize_digits(value)
    if not digits:
        return ""
    return "-".join(digits[i:i + group_size] for i in range(0, len(digits), group_size))


def is_valid_phone_installation_id(value: Any) -> bool:
    return len(normalize_digits(value)) == PHONE_INSTALLATION_ID_DIGITS


def is_valid_phone_confirmation_code(value: Any) -> bool:
    return len(normalize_digits(value)) in (PHONE_CONFIRMATION_CODE_DIGITS, 48)


def is_valid_device_fingerprint(value: Any) -> bool:
    return re.fullmatch(r"[a-f0-9]{64}", _php_trim(value).translate(_ASCII_LOWER)) is not None


def first_non_empty(data: Dict[str, Any], keys) -> str:
    for key in keys:
        value = _php_trim(data.get(key, ""))
        if value:
            return value
    return ""


def random_token(byte_count: int = 32) -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(byte_count)).rstrip(b"=").decode("ascii")


def random_digits(length: int) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def grouped_random_digits(groups: int, group_size: int = 6) -> str:
    return "-".join(random_digits(group_size) for _ in range(groups))


def phone_installation_id() -> str:
    return grouped_random_digits(9, 6)


def phone_confirmation_code() -> str:
    return random_digits(PHONE_CONFIRMATION_CODE_DIGITS)


def normalize_email_address(value: Any) -> str:
    email = _php_trim(value).lower()
    if len(email) > 254 or re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", email) is None:
        return ""
    return email


def mask_email_address(value: str) -> str:
    parts = value.split("@", 1)
    if len(parts) != 2:
        return ""
    local, domain = parts
    hidden = max(3, min(8, len(local) - 1))
    return local[:1] + ("*" * hidden) + "@" + domain


def device_display_label(label: str, device_hash_value: str) -> str:
    label = _php_trim(label)
    return label[:MAX_TEXT_LENGTH] if label else device_reference(device_hash_value)


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_utc_datetime(value: str) -> Optional[datetime.datetime]:
    value = _php_trim(value)
    if not value:
        return None
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = parse_iso_datetime(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed.astimezone(datetime.timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _secret(config: Dict[str, Any], name: str) -> str:
    value = _php_trim(config.get(name, ""))
    if len(value) < 32:
        raise ConfigurationError("%s must be a random secret of at least 32 characters." % name)
    return value


def key_pepper(config: Dict[str, Any]) -> str:
    return _secret(config, "key_pepper")


def token_secret(config: Dict[str, Any]) -> str:
    return _secret(config, "token_secret")


def license_key_hash(config: Dict[str, Any], license_key: str) -> str:
    return hmac.new(key_pepper(config).encode(), normalize_license_key(license_key).encode(), hashlib.sha256).hexdigest()


def device_hash(config: Dict[str, Any], fingerprint: str) -> str:
    return hmac.new(key_pepper(config).encode(), normalize_device_fingerprint(fingerprint).encode(), hashlib.sha256).hexdigest()


def device_reference(device_hash_value: str) -> str:
    value = _php_trim(device_hash_value).translate(_ASCII_LOWER)
    return "device-unknown" if not value else "device-" + value[:10].upper()


def product_id(config: Dict[str, Any], license_id: int) -> str:
    numeric_id = int(license_id)
    encoded_id = format(numeric_id, "X").rjust(8, "0")
    signature = hmac.new(key_pepper(config).encode(), ("product-id|%d" % numeric_id).encode(), hashlib.sha256).hexdigest()[:16].upper()
    return "PID-%s-%s" % (encoded_id, signature)


def license_id_from_product_id(config: Dict[str, Any], value: str) -> Optional[int]:
    value = _php_trim(value).translate(_ASCII_UPPER)
    match = re.fullmatch(r"PID-([0-9A-F]{8})-([0-9A-F]{16})", value)
    if not match:
        return None
    license_id = int(match.group(1), 16)
    if license_id <= 0:
        return None
    try:
        return license_id if hmac.compare_digest(product_id(config, license_id), value) else None
    except ConfigurationError:
        return None


def offline_secret(product_key: str) -> bytes:
    value = b"TUTI-OFFLINE-V1|" + normalize_license_key(product_key).encode("utf-8")
    return hashlib.sha256(value).digest()


def offline_lookup(secret: bytes) -> str:
    return hashlib.sha256(b"lookup|" + secret).hexdigest()[:20].upper()


def offline_secret_encrypt(config: Dict[str, Any], secret: bytes) -> str:
    if len(secret) != 32:
        raise ValueError("offline_secret_invalid")
    return _aes_gcm_encrypt(token_secret(config), b"offline-storage|", b"TUTI-OFFLINE-V1", secret)


def offline_secret_decrypt(config: Dict[str, Any], encoded: str) -> bytes:
    value = _aes_gcm_decrypt(token_secret(config), b"offline-storage|", b"TUTI-OFFLINE-V1", encoded)
    if len(value) != 32:
        raise ValueError("offline_secret_invalid")
    return value


def phone_email_encrypt(config: Dict[str, Any], email: str) -> str:
    normalized = normalize_email_address(email)
    if not normalized:
        raise ValueError("phone_email_invalid")
    return _aes_gcm_encrypt(token_secret(config), b"phone-email|", b"TUTI-PHONE-EMAIL-V1", normalized.encode("utf-8"))


def phone_email_decrypt(config: Dict[str, Any], encoded: str) -> str:
    try:
        value = _aes_gcm_decrypt(token_secret(config), b"phone-email|", b"TUTI-PHONE-EMAIL-V1", encoded).decode("utf-8")
    except (UnicodeDecodeError, ValueError):
        raise ValueError("phone_email_invalid")
    normalized = normalize_email_address(value)
    if not normalized:
        raise ValueError("phone_email_invalid")
    return normalized


def _aes_gcm_encrypt(secret: str, key_prefix: bytes, aad: bytes, plaintext: bytes) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise ConfigurationError("The cryptography package is required for AES-GCM helpers.") from exc
    key = hashlib.sha256(key_prefix + secret.encode("utf-8")).digest()
    iv = secrets.token_bytes(12)
    encrypted = AESGCM(key).encrypt(iv, plaintext, aad)
    # PHP packs the GCM tag before the ciphertext: IV || TAG || CIPHERTEXT.
    raw = iv + encrypted[-16:] + encrypted[:-16]
    return b64url_encode(raw)


def _aes_gcm_decrypt(secret: str, key_prefix: bytes, aad: bytes, encoded: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw = b64url_decode(encoded)
        if len(raw) < 28:
            raise ValueError("ciphertext_invalid")
        key = hashlib.sha256(key_prefix + secret.encode("utf-8")).digest()
        # Reassemble cryptography's expected CIPHERTEXT || TAG ordering.
        return AESGCM(key).decrypt(raw[:12], raw[28:] + raw[12:28], aad)
    except ImportError as exc:
        raise ConfigurationError("The cryptography package is required for AES-GCM helpers.") from exc
    except Exception as exc:
        raise ValueError("ciphertext_invalid") from exc


def token_hash(config: Dict[str, Any], token: str) -> str:
    return hmac.new(token_secret(config).encode(), token.encode(), hashlib.sha256).hexdigest()


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError("base64url_invalid")
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
