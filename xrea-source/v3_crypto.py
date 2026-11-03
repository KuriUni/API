"""Cryptographic primitives used by the v3 device-bound license API."""
import base64
import hashlib
import hmac
import os

from core import token_secret

API_VERSION = "3.0-beta1"
DEFAULT_SCOPES = (
    "license.verify", "license.refresh", "license.offline",
    "license.revoke", "license.introspect",
)


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(value):
    import re
    if not value or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
        raise ValueError("base64url_invalid")
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def challenge_message(purpose, challenge_id, nonce, thumbprint):
    return "TUTI-LICENSE-V3\n%s\n%s\n%s\n%s" % (purpose, challenge_id, nonce, thumbprint)


def proof_message(action, session_id, request_nonce, timestamp):
    return "TUTI-LICENSE-V3\n%s\n%s\n%s\n%d" % (action, session_id, request_nonce, timestamp)


def scopes(requested=None):
    if not requested:
        return list(DEFAULT_SCOPES)
    allowed = set(DEFAULT_SCOPES)
    result = []
    for item in requested:
        value = str(item).strip()
        if value in allowed and value not in result:
            result.append(value)
    return result or list(DEFAULT_SCOPES)


def offline_signing_material(config):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:
        raise RuntimeError("offline_signing_unavailable") from exc
    root = str(config.get("license_v3_signing_secret", "") or "").strip()
    if len(root) < 32:
        root = token_secret(config)
    seed = hmac.new(root.encode("utf-8"), b"TUTI-LICENSE-V3-OFFLINE-ED25519", hashlib.sha256).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {
        "private_key": private_key,
        "public": public,
        "kid": hashlib.sha256(public).hexdigest()[:24],
        "algorithm": "Ed25519",
    }


def public_signing_key(config):
    material = offline_signing_material(config)
    return {
        "algorithm": material["algorithm"],
        "kid": material["kid"],
        "public_key": b64url_encode(material["public"]),
        "format": "raw-ed25519",
    }


def normalize_public_key(pem):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        key = serialization.load_pem_public_key(str(pem).strip().encode("ascii"))
    except Exception as exc:
        raise ValueError("device_public_key_invalid") from exc
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise ValueError("device_public_key_too_weak")
        algorithm = "RSA-SHA256"
        bits = key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        curves = {"secp256r1", "secp384r1", "secp521r1"}
        if key.curve.name not in curves:
            raise ValueError("device_public_key_curve_unsupported")
        algorithm = "ECDSA-SHA256"
        bits = key.key_size
    else:
        raise ValueError("device_public_key_type_unsupported")
    canonical = key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii").strip() + "\n"
    return {
        "pem": canonical,
        "thumbprint": hashlib.sha256(canonical.encode("ascii")).hexdigest(),
        "algorithm": algorithm,
        "bits": bits,
    }


def verify_signature(public_key_pem, message, signature_b64):
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        signature = b64url_decode(signature_b64)
        key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except Exception:
        return False


def b64url_encode_signature(raw):
    return b64url_encode(raw)


def sign_message(private_key, message):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(message.encode("utf-8"), padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("device_public_key_type_unsupported")
    return b64url_encode(signature)
