"""Python port of the HA RSA-8192 offline signing-key endpoint."""
from native_http import make_response, add_headers, legacy_compatible
import hashlib
import json
import os
import secrets
from pathlib import Path
from path_utils import is_relative_to
from http_utils import json_response
MAX_KEY_BYTES = 16384
KEY_NAME = 'offline-signing-rsa8192-private.pem'

def _private_key_path(create_directory=False):
    private_dir = os.environ.get('PYTHON_MIGRATION_PRIVATE_DIR', '').strip()
    if not private_dir:
        raise FileNotFoundError('offline_signing_key_unconfigured')
    root = Path(private_dir).expanduser().resolve()
    document_root = Path(os.environ.get('DOCUMENT_ROOT', Path(__file__).resolve().parent)).resolve()
    if 'public_html' in document_root.parts:
        public_html = Path(*document_root.parts[:document_root.parts.index('public_html') + 1])
    else:
        public_html = document_root
    if is_relative_to(root, public_html):
        raise FileNotFoundError('offline_signing_key_unconfigured')
    if create_directory:
        root.mkdir(mode=448, parents=True, exist_ok=True)
        os.chmod(root, 448)
    path = root / KEY_NAME
    if path.exists():
        resolved = path.resolve(strict=True)
        if not is_relative_to(resolved, root) or resolved == document_root or document_root in resolved.parents:
            raise FileNotFoundError('offline_signing_key_unconfigured')
        return resolved
    return path

def _parse_private_key(pem):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except Exception as exc:
        raise ValueError('invalid_rsa_private_key') from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError('invalid_rsa_private_key')
    if key.key_size != 8192:
        raise ValueError('rsa_key_size_invalid')
    return key

def _public_pem(key):
    from cryptography.hazmat.primitives import serialization
    return key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')

def _key_payload(key):
    public_pem = _public_pem(key)
    return {'ok': True, 'algorithm': 'RS256', 'kid': 'rsa8192-v1', 'key_bits': int(key.key_size), 'public_key_pem': public_pem, 'fingerprint': hashlib.sha256(public_pem.encode('ascii')).hexdigest()}

def _self_test(key):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    message = secrets.token_bytes(32)
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    try:
        key.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise RuntimeError('key_self_test_failed') from exc

def _atomic_store(path, pem):
    path.parent.mkdir(mode=448, parents=True, exist_ok=True)
    os.chmod(path.parent, 448)
    temporary = path.with_name(path.name + '.tmp.' + secrets.token_hex(6))
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384)
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(pem)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 384)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

@legacy_compatible(callback_index=1, request_index=0)
def offline_key(request_context):
    method = str(request_context.get('method', ''))
    if method == 'GET':
        try:
            path = _private_key_path()
            pem = path.read_bytes()
            key = _parse_private_key(pem)
            return json_response('200 OK', _key_payload(key))
        except FileNotFoundError:
            return json_response('503 Service Unavailable', {'ok': False, 'error': 'offline_signing_key_unconfigured'})
        except ValueError as exc:
            return json_response('503 Service Unavailable', {'ok': False, 'error': str(exc)})
        except Exception:
            return json_response('503 Service Unavailable', {'ok': False, 'error': 'invalid_rsa_private_key'})
    from ha_handlers import _append_ha_audit, _ha_authorized_scope
    if not _ha_authorized_scope(request_context, 'ha:operate'):
        return json_response('404 Not Found', {'ok': False, 'error': 'not_found'})
    if method != 'POST':
        return json_response('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
    try:
        stream = request_context.get('body_stream')
        pem = stream.read(MAX_KEY_BYTES + 1) if stream is not None else b''
        if len(pem) > MAX_KEY_BYTES:
            raise RuntimeError('key_too_large')
        key = _parse_private_key(pem)
        _self_test(key)
        path = _private_key_path(create_directory=True)
        _atomic_store(path, pem)
        payload = _key_payload(key)
        _append_ha_audit('offline_signing_key_provisioned', {'algorithm': 'RS256', 'kid': 'rsa8192-v1', 'key_bits': int(key.key_size), 'fingerprint': payload['fingerprint']}, request_context)
        return json_response('200 OK', {key: value for key, value in payload.items() if key != 'public_key_pem'})
    except ValueError as exc:
        return json_response('500 Internal Server Error', {'ok': False, 'error': str(exc)})
    except RuntimeError as exc:
        return json_response('500 Internal Server Error', {'ok': False, 'error': str(exc)})
    except Exception:
        return json_response('500 Internal Server Error', {'ok': False, 'error': 'offline_signing_key_provision_failed'})
