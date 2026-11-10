"""Canonical signed-request contract for License API v4."""
import hashlib
import json

import v3_crypto

API_VERSION = '4.0-beta1'
PUBLIC_PREFIX = '/license/api/v4/'


def canonical_body(data, omit_signature=False):
    """Canonicalize flat scalar request fields identically on client and server."""
    value = {}
    for key, item in data.items():
        if omit_signature and key == 'signature':
            continue
        if item is None:
            item = ''
        if isinstance(item, bool):
            item = 'true' if item else 'false'
        elif not isinstance(item, str):
            item = str(item)
        value[str(key)] = item
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def body_hash(data, omit_signature=False):
    return hashlib.sha256(canonical_body(data, omit_signature).encode('utf-8')).hexdigest()


def activation_message(data, challenge_id, nonce, thumbprint):
    return '\n'.join(('TUTI-LICENSE-V4', 'ACTIVATE', 'POST', PUBLIC_PREFIX + 'activate.php',
                      str(challenge_id), str(nonce), str(thumbprint), body_hash(data, True)))


def request_message(method, path, session_id, timestamp, nonce, data, credential_hash):
    return '\n'.join(('TUTI-LICENSE-V4', str(method).upper(), str(path), str(session_id),
                      str(int(timestamp)), str(nonce), body_hash(data), str(credential_hash)))


def signable_body(data):
    return canonical_body(data)


def signature_encode(raw):
    return v3_crypto.b64url_encode(raw)
