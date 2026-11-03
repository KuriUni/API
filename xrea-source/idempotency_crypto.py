"""PHP-compatible encryption for retry receipts containing API keys."""
import base64
import hashlib
import hmac
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_response(plain,context,pepper):
    key=hmac.new(pepper.encode(),('baas-idempotency-response/v1|'+context).encode(),hashlib.sha256).digest()
    iv=secrets.token_bytes(12)
    encrypted=AESGCM(key).encrypt(iv,plain.encode('utf-8'),context.encode('utf-8'))
    cipher,tag=encrypted[:-16],encrypted[-16:]
    return 'enc1:'+base64.urlsafe_b64encode(iv+tag+cipher).rstrip(b'=').decode('ascii')

def decrypt_response(stored,context,pepper):
    if not isinstance(stored,str) or not stored.startswith('enc1:'):return None
    try:
        encoded=stored[5:]
        raw=base64.b64decode(encoded+'='*((4-len(encoded)%4)%4),altchars=b'-_',validate=True)
        if len(raw)<29:return None
        key=hmac.new(pepper.encode(),('baas-idempotency-response/v1|'+context).encode(),hashlib.sha256).digest()
        return AESGCM(key).decrypt(raw[:12],raw[28:]+raw[12:28],context.encode()).decode('utf-8')
    except (ValueError,UnicodeError):return None
    except Exception as error:
        from cryptography.exceptions import InvalidTag
        if isinstance(error,InvalidTag):return None
        raise
