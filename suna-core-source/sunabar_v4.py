"""License API v4 emulation for Sunabar (online device-bound sessions).

Sunabar is an isolated demonstration service. This module implements the v4
challenge/device/session contract with Sunabar's own tables. It does not call
the production License API, does not issue production keys, and does not
implement offline tickets or v2 migration (both return a clear 501).
"""
import base64
import hashlib
import hmac
import json
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

API_VERSION = '4.0-beta1'
PUBLIC_PREFIX = '/license/api/v4/'
SUNUBAR_PREFIX = '/license/api/sunabar/v4/'
ACCESS_TTL = 300
REFRESH_TTL = 14 * 86400
SCOPES = ['license.verify', 'license.refresh', 'license.revoke', 'license.introspect']
TOKEN_RE = re.compile(r'v4\.[ar]\.[A-Za-z0-9_-]{43,86}')


class V4Error(Exception):
    def __init__(self, status, code, message=None):
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message or code.replace('_', ' ').capitalize()


def v4_error(reply, request_id, status, code, message):
    return reply(status, {'success': False, 'api_version': API_VERSION,
                          'error_code': code, 'error': message, 'request_id': request_id})


def _ok(reply, request_id, payload, status=200):
    body = {'success': True, 'api_version': API_VERSION, 'request_id': request_id}
    body.update(payload)
    return reply(status, body)


def _hash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _token_hash(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _utc(epoch):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(epoch)))


def _canonical(data, omit_signature=False):
    value = {}
    for key, item in data.items():
        if omit_signature and key == 'signature':
            continue
        if item is None:
            item = ''
        elif isinstance(item, bool):
            item = 'true' if item else 'false'
        elif not isinstance(item, str):
            item = str(item)
        value[str(key)] = item
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def _body_hash(data, omit_signature=False):
    return hashlib.sha256(_canonical(data, omit_signature).encode('utf-8')).hexdigest()


def _b64url_decode(value):
    if not isinstance(value, str) or len(value) > 8192 or re.fullmatch(r'[A-Za-z0-9_-]+', value) is None:
        raise ValueError('signature_invalid')
    return base64.urlsafe_b64decode(value + '=' * ((4 - len(value) % 4) % 4))


def normalize_public_key(value):
    if not isinstance(value, str):
        raise V4Error(400, 'DEVICE_PUBLIC_KEY_INVALID', 'device_public_key must be a PEM public key.')
    text = value.replace('\r\n', '\n').strip()
    if len(text) < 100 or len(text) > 16384 or '-----BEGIN ' not in text or 'PUBLIC KEY-----' not in text:
        raise V4Error(400, 'DEVICE_PUBLIC_KEY_INVALID', 'device_public_key must be a PEM public key.')
    canonical = text + '\n'
    thumbprint = hashlib.sha256(canonical.encode('ascii', 'replace')).hexdigest()
    return {'pem': canonical, 'thumbprint': thumbprint, 'algorithm': _key_algorithm(canonical)}


def _key_algorithm(pem):
    try:
        result = subprocess.run([_openssl(), 'pkey', '-pubin', '-text', '-noout'],
                                input=pem.encode('ascii'), stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=5, check=False)
        description = result.stdout.decode('ascii', 'ignore').lower()
        if 'modulus' in description or 'publicexponent' in description:
            return 'RSA-SHA256'
        if 'asn1 oid' in description or 'prime' in description:
            return 'ECDSA-SHA256'
    except Exception:
        pass
    return 'RSA-SHA256' if 'RSA' in pem else 'ECDSA-SHA256'


def _openssl():
    binary = shutil.which('openssl')
    if not binary:
        raise V4Error(503, 'SIGNATURE_VERIFICATION_UNAVAILABLE',
                      'The demo server cannot verify device signatures because openssl is unavailable.')
    return binary


def verify_signature(public_key_pem, message, signature):
    binary = _openssl()
    try:
        raw = _b64url_decode(signature)
    except (ValueError, TypeError):
        return False
    if not raw or len(raw) > 4096:
        return False
    with tempfile.TemporaryDirectory(prefix='sunabar-v4-') as folder:
        key_path = folder + '/device.pem'
        signature_path = folder + '/signature.bin'
        with open(key_path, 'w', encoding='ascii') as handle:
            handle.write(public_key_pem)
        with open(signature_path, 'wb') as handle:
            handle.write(raw)
        try:
            result = subprocess.run(
                [binary, 'dgst', '-sha256', '-verify', key_path, '-signature', signature_path],
                input=message.encode('utf-8'), stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, timeout=5, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise V4Error(503, 'SIGNATURE_VERIFICATION_UNAVAILABLE', 'Signature verification failed to run.') from exc
    return result.returncode == 0


def activation_message(data, challenge_id, nonce, thumbprint, prefix=PUBLIC_PREFIX):
    return '\n'.join(('TUTI-LICENSE-V4', 'ACTIVATE', 'POST', prefix + 'activate.php',
                      str(challenge_id), str(nonce), str(thumbprint), _body_hash(data, True)))


def request_message(action, session_id, timestamp, nonce, data, credential_hash, prefix=PUBLIC_PREFIX):
    return '\n'.join(('TUTI-LICENSE-V4', 'POST', prefix + str(action) + '.php', str(session_id),
                      str(int(timestamp)), str(nonce), _body_hash(data), str(credential_hash)))


def _verify_activation(data, challenge_id, nonce, thumbprint, public_key_pem, signature):
    for prefix in (PUBLIC_PREFIX, SUNUBAR_PREFIX):
        if verify_signature(public_key_pem, activation_message(data, challenge_id, nonce, thumbprint, prefix), signature):
            return True
    return False


def _verify_proof(public_key_pem, action, session_id, timestamp, nonce, data, credential_hash, signature):
    for prefix in (PUBLIC_PREFIX, SUNUBAR_PREFIX):
        message = request_message(action, session_id, timestamp, nonce, data, credential_hash, prefix)
        if verify_signature(public_key_pem, message, signature):
            return True
    return False


def _challenge(connection, workspace, data):
    purpose = str(data.get('purpose', 'activate')).strip().lower()
    if purpose != 'activate':
        raise V4Error(501, 'MIGRATION_UNSUPPORTED', 'Sunabar emulates online activation only.')
    public_key = normalize_public_key(data.get('device_public_key'))
    now = int(time.time())
    challenge_id = secrets.token_hex(16)
    nonce = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode('ascii')
    with connection.cursor() as cursor:
        cursor.execute('DELETE FROM sunabar_v4_challenges WHERE expires_at<=%s', (now,))
        cursor.execute('INSERT INTO sunabar_v4_challenges(challenge_id,workspace_id,purpose,nonce_hash,key_thumbprint,expires_at) VALUES(%s,%s,%s,%s,%s,%s)',
                       (challenge_id, workspace, purpose, _hash(nonce), public_key['thumbprint'], now + 120))
    connection.commit()
    return {'challenge': {'challenge_id': challenge_id, 'nonce': nonce, 'purpose': purpose,
                          'expires_at': _utc(now + 120),
                          'device_key_thumbprint': public_key['thumbprint'],
                          'signature_algorithm': public_key['algorithm']}}


def _license_payload(row):
    return {'license_id': str(row['license_id']), 'product_id': int(row['product_id']),
            'product_name': str(row['product_name']), 'license_mode': str(row['license_mode']),
            'max_devices': int(row['max_devices']), 'label': str(row['label']),
            'status': str(row['status']), 'expires_at': _utc(int(row['expires_at']))}


def _device_payload(row, device_id=None):
    device_hash = str(row.get('device_hash') or '')
    return {'device_id': int(device_id if device_id is not None else row['id']),
            'device_ref': device_hash[:16],
            'key_thumbprint': str(row['key_thumbprint']), 'key_algorithm': str(row['key_algorithm'])}


def _new_tokens(connection, workspace, license_row, device_id, existing=None):
    now = int(time.time())
    license_exp = int(license_row['expires_at'])
    access_exp = min(now + ACCESS_TTL, license_exp)
    refresh_exp = min(now + REFRESH_TTL, license_exp)
    if access_exp <= now or refresh_exp <= now:
        raise V4Error(401, 'LICENSE_EXPIRED', 'This demo license has expired.')
    access = 'v4.a.' + secrets.token_urlsafe(32)
    refresh = 'v4.r.' + secrets.token_urlsafe(48)
    if existing:
        session_id = str(existing['session_id'])
        family_id = str(existing['family_id'])
        version = int(existing['token_version']) + 1
        with connection.cursor() as cursor:
            cursor.execute('INSERT IGNORE INTO sunabar_v4_refresh_history(token_hash,session_id,family_id,expires_at,used_at) VALUES(%s,%s,%s,%s,%s)',
                           (_token_hash(existing['refresh_token']), session_id, family_id, int(existing['refresh_expires_at']), now))
            cursor.execute('UPDATE sunabar_v4_sessions SET access_hash=%s,refresh_hash=%s,access_expires_at=%s,refresh_expires_at=%s,token_version=%s,last_seen_at=%s WHERE id=%s AND revoked_at IS NULL',
                           (_token_hash(access), _token_hash(refresh), access_exp, refresh_exp, version, now, int(existing['id'])))
            if cursor.rowcount != 1:
                raise V4Error(409, 'SESSION_CHANGED', 'The session changed while refreshing. Sign in again.')
    else:
        session_id = secrets.token_hex(16)
        family_id = secrets.token_hex(16)
        version = 1
        with connection.cursor() as cursor:
            cursor.execute('UPDATE sunabar_v4_sessions SET revoked_at=%s,revoke_reason=%s WHERE device_id=%s AND revoked_at IS NULL',
                           (now, 'reactivated', device_id))
            cursor.execute('INSERT INTO sunabar_v4_sessions(session_id,family_id,workspace_id,license_id,device_id,access_hash,refresh_hash,access_expires_at,refresh_expires_at,token_version,created_at,last_seen_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                           (session_id, family_id, workspace, str(license_row['license_id']), device_id,
                            _token_hash(access), _token_hash(refresh), access_exp, refresh_exp, version, now, now))
    payload = {'session_id': session_id, 'family_id': family_id, 'access_token': access,
               'refresh_token': refresh, 'access_expires_at': _utc(access_exp),
               'refresh_expires_at': _utc(refresh_exp), 'token_version': version,
               'scopes': list(SCOPES), 'server_time_utc': _utc(now),
               'access_expires_in': max(0, access_exp - now),
               'refresh_expires_in': max(0, refresh_exp - now),
               'refresh_after_seconds': int(max(0, access_exp - now) * 0.8)}
    payload['_refresh_token_value'] = refresh
    return payload


def _consume_challenge(connection, workspace, data, public_key):
    challenge_id = str(data.get('challenge_id', '')).strip().lower()
    nonce = str(data.get('nonce', '')).strip()
    signature = str(data.get('signature', '')).strip()
    if re.fullmatch('[a-f0-9]{32}', challenge_id) is None:
        raise V4Error(400, 'CHALLENGE_INVALID', 'challenge_id is invalid.')
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM sunabar_v4_challenges WHERE challenge_id=%s AND workspace_id=%s LIMIT 1 FOR UPDATE',
                       (challenge_id, workspace))
        row = cursor.fetchone()
    if not row or str(row['purpose']) != 'activate':
        raise V4Error(400, 'CHALLENGE_INVALID', 'The activation challenge is invalid.')
    if row.get('consumed_at') is not None:
        raise V4Error(409, 'CHALLENGE_ALREADY_USED', 'The activation challenge was already used.')
    if int(row['expires_at']) <= int(time.time()):
        raise V4Error(400, 'CHALLENGE_EXPIRED', 'The activation challenge has expired.')
    if not hmac.compare_digest(str(row['nonce_hash']), _hash(nonce)):
        raise V4Error(400, 'CHALLENGE_NONCE_INVALID', 'The challenge nonce does not match.')
    if not hmac.compare_digest(str(row['key_thumbprint']), public_key['thumbprint']):
        raise V4Error(409, 'CHALLENGE_KEY_MISMATCH', 'The device key does not match the challenge.')
    if not _verify_activation(data, challenge_id, nonce, public_key['thumbprint'], public_key['pem'], signature):
        raise V4Error(401, 'DEVICE_SIGNATURE_INVALID', 'The device signature is not valid for this activation.')
    with connection.cursor() as cursor:
        cursor.execute('UPDATE sunabar_v4_challenges SET consumed_at=%s WHERE id=%s AND consumed_at IS NULL',
                       (int(time.time()), int(row['id'])))
        if cursor.rowcount != 1:
            raise V4Error(409, 'CHALLENGE_ALREADY_USED', 'The activation challenge was already used.')


def _activate(connection, workspace, data):
    key = str(data.get('license_key') or data.get('product_key') or '').strip()
    fingerprint = str(data.get('device_fingerprint') or '').strip().lower()
    if not key or len(key) > 4096:
        raise V4Error(400, 'LICENSE_KEY_INVALID', 'license_key is required.')
    if re.fullmatch('[a-f0-9]{64}', fingerprint) is None:
        raise V4Error(400, 'DEVICE_FINGERPRINT_INVALID', 'device_fingerprint must be a SHA-256 hex value.')
    public_key = normalize_public_key(data.get('device_public_key'))
    _consume_challenge(connection, workspace, data, public_key)
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM sunabar_licenses WHERE workspace_id=%s AND key_hash=%s LIMIT 1 FOR UPDATE',
                       (workspace, _hash(key)))
        license_row = cursor.fetchone()
    if not license_row or str(license_row['status']) != 'active' or int(license_row['expires_at']) <= int(time.time()):
        raise V4Error(401, 'LICENSE_UNAVAILABLE', 'This demo license is unavailable or expired.')
    device_hash = _hash(fingerprint)
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM sunabar_v4_devices WHERE workspace_id=%s AND license_id=%s AND device_hash=%s LIMIT 1 FOR UPDATE',
                       (workspace, str(license_row['license_id']), device_hash))
        device = cursor.fetchone()
        cursor.execute('SELECT id FROM sunabar_v4_devices WHERE license_id=%s AND key_thumbprint=%s AND device_hash<>%s LIMIT 1',
                       (str(license_row['license_id']), public_key['thumbprint'], device_hash))
        if cursor.fetchone():
            raise V4Error(409, 'DEVICE_KEY_ALREADY_BOUND', 'This device key is already bound to another device.')
        if device is None:
            cursor.execute('SELECT COUNT(*) AS count FROM sunabar_v4_devices WHERE license_id=%s AND revoked_at IS NULL',
                           (str(license_row['license_id']),))
            if int(cursor.fetchone()['count']) >= int(license_row['max_devices']):
                raise V4Error(409, 'DEVICE_LIMIT_REACHED', 'This license reached its device limit.')
            cursor.execute('INSERT INTO sunabar_v4_devices(workspace_id,license_id,device_hash,public_key_pem,key_thumbprint,key_algorithm,device_label,app_version,bound_at,last_seen_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                           (workspace, str(license_row['license_id']), device_hash, public_key['pem'],
                            public_key['thumbprint'], public_key['algorithm'],
                            str(data.get('device_label', ''))[:120], str(data.get('app_version', ''))[:40],
                            int(time.time()), int(time.time())))
            device_id = int(connection.insert_id())
        else:
            device_id = int(device['id'])
            cursor.execute('UPDATE sunabar_v4_devices SET public_key_pem=%s,key_thumbprint=%s,key_algorithm=%s,device_label=%s,app_version=%s,last_seen_at=%s,revoked_at=NULL WHERE id=%s',
                           (public_key['pem'], public_key['thumbprint'], public_key['algorithm'],
                            str(data.get('device_label', ''))[:120], str(data.get('app_version', ''))[:40],
                            int(time.time()), device_id))
        cursor.execute('SELECT * FROM sunabar_v4_devices WHERE id=%s', (device_id,))
        device = cursor.fetchone()
    session = _new_tokens(connection, workspace, license_row, device_id)
    session.pop('_refresh_token_value', None)
    connection.commit()
    return {'message': 'Sunabar v4 demo session issued. This key is simulated only.',
            'license': _license_payload(license_row),
            'product_code': str(license_row.get('product_name') or ''),
            'device': _device_payload(device), 'session': session}


def _load_session(connection, workspace, token, kind, lock=False):
    prefix = 'v4.r.' if kind == 'refresh' else 'v4.a.'
    if not isinstance(token, str) or len(token) > 200 or not token.startswith(prefix):
        return None
    column = 'refresh_hash' if kind == 'refresh' else 'access_hash'
    sql = ('SELECT s.*,d.device_hash,d.public_key_pem,d.key_thumbprint,d.key_algorithm,d.revoked_at AS device_revoked_at,'
           'l.status AS license_status,l.expires_at AS license_expires_at '
           'FROM sunabar_v4_sessions s JOIN sunabar_v4_devices d ON d.id=s.device_id '
           'JOIN sunabar_licenses l ON l.license_id=s.license_id AND l.workspace_id=s.workspace_id '
           'WHERE s.workspace_id=%s AND s.' + column + '=%s LIMIT 1')
    if lock:
        sql += ' FOR UPDATE'
    with connection.cursor() as cursor:
        cursor.execute(sql, (workspace, _token_hash(token)))
        return cursor.fetchone()


def _require_proof(connection, session, action, data, headers, token):
    session_id = str(headers.get('x-license-session', '')).strip()
    nonce = str(headers.get('x-license-nonce', '')).strip()
    proof = str(headers.get('x-license-proof', '')).strip()
    try:
        timestamp = int(headers.get('x-license-timestamp', '0'))
    except (TypeError, ValueError):
        timestamp = 0
    if session_id != str(session['session_id']) or re.fullmatch('[A-Za-z0-9_-]{16,180}', nonce) is None or timestamp <= 0 or not proof:
        raise V4Error(400, 'PROOF_REQUIRED', 'X-License-Session, X-License-Timestamp, X-License-Nonce and X-License-Proof are required.')
    if abs(int(time.time()) - timestamp) > 60:
        raise V4Error(401, 'PROOF_TIMESTAMP_INVALID', 'The proof timestamp is outside the 60 second window.')
    credential_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    if not _verify_proof(str(session['public_key_pem']), action, session_id, timestamp, nonce, data, credential_hash, proof):
        raise V4Error(401, 'PROOF_SIGNATURE_INVALID', 'The request proof signature is not valid.')
    proof_hash = _hash(session_id + '|' + nonce)
    now = int(time.time())
    try:
        with connection.cursor() as cursor:
            cursor.execute('DELETE FROM sunabar_v4_proofs WHERE expires_at<=%s', (now,))
            cursor.execute('INSERT INTO sunabar_v4_proofs(proof_hash,session_id,action,expires_at) VALUES(%s,%s,%s,%s)',
                           (proof_hash, session_id, action, now + 120))
    except Exception as exc:
        if getattr(exc, 'args', [None])[0] == 1062:
            raise V4Error(401, 'PROOF_REPLAYED', 'This request proof was already used.')
        raise


def _session(connection, workspace, action, data, headers):
    kind = 'refresh' if action in ('refresh', 'reauth') else 'access'
    if kind == 'refresh':
        token = str(data.get('refresh_token', '')).strip()
    else:
        token = str(headers.get('authorization', '')).strip()
        if token.lower().startswith('bearer '):
            token = token[7:].strip()
    if not token:
        raise V4Error(401, 'ACCESS_TOKEN_REQUIRED' if kind == 'access' else 'REFRESH_TOKEN_REQUIRED',
                      'An access token or refresh token is required.')
    session = _load_session(connection, workspace, token, kind, lock=(action == 'refresh'))
    if not session:
        if action == 'refresh':
            with connection.cursor() as cursor:
                cursor.execute('SELECT family_id FROM sunabar_v4_refresh_history WHERE token_hash=%s AND expires_at>%s LIMIT 1',
                               (_token_hash(token), int(time.time())))
                history = cursor.fetchone()
            if history:
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE sunabar_v4_sessions SET revoked_at=%s,revoke_reason='refresh_reuse_detected' WHERE family_id=%s AND revoked_at IS NULL",
                                   (int(time.time()), str(history['family_id'])))
                connection.commit()
                raise V4Error(401, 'REFRESH_REUSE_DETECTED', 'A used refresh token was reused; the session family was revoked.')
        raise V4Error(401, 'SESSION_NOT_FOUND', 'No active demo session was found.')
    if session.get('revoked_at') is not None or session.get('device_revoked_at') is not None:
        raise V4Error(401, 'SESSION_REVOKED', 'The demo session was revoked.')
    if str(session.get('license_status')) != 'active' or int(session['license_expires_at']) <= int(time.time()):
        raise V4Error(401, 'LICENSE_UNAVAILABLE', 'The demo license is no longer active.')
    expiry_field = 'refresh_expires_at' if kind == 'refresh' else 'access_expires_at'
    if int(session[expiry_field]) <= int(time.time()):
        raise V4Error(401, 'REFRESH_TOKEN_EXPIRED' if kind == 'refresh' else 'ACCESS_TOKEN_EXPIRED',
                      'The token has expired.')
    _require_proof(connection, session, action, data, headers, token)
    return session


def _session_license(connection, session):
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM sunabar_licenses WHERE license_id=%s AND workspace_id=%s LIMIT 1',
                       (str(session['license_id']), str(session['workspace_id'])))
        row = cursor.fetchone()
    return _license_payload(row) if row else None


def _session_action(connection, workspace, action, data, headers):
    session = _session(connection, workspace, action, data, headers)
    now = int(time.time())
    with connection.cursor() as cursor:
        cursor.execute('UPDATE sunabar_v4_sessions SET last_seen_at=%s WHERE id=%s', (now, int(session['id'])))
        cursor.execute('UPDATE sunabar_v4_devices SET last_seen_at=%s WHERE id=%s', (now, int(session['device_id'])))
    if action == 'verify':
        connection.commit()
        return {'valid': True,
                'session': {'session_id': str(session['session_id']), 'family_id': str(session['family_id']),
                            'token_version': int(session['token_version']), 'scopes': list(SCOPES),
                            'access_expires_at': _utc(int(session['access_expires_at']))},
                'device': _device_payload(session, session['device_id']),
                'license': _session_license(connection, session)}
    if action == 'introspect':
        connection.commit()
        return {'active': True,
                'session': {'session_id': str(session['session_id']), 'family_id': str(session['family_id']),
                            'created_at': _utc(int(session['created_at'])), 'last_seen_at': _utc(int(session['last_seen_at'])),
                            'access_expires_at': _utc(int(session['access_expires_at'])),
                            'refresh_expires_at': _utc(int(session['refresh_expires_at'])),
                            'token_version': int(session['token_version']), 'scopes': list(SCOPES)},
                'device': _device_payload(session, session['device_id'])}
    if action in ('refresh', 'reauth'):
        existing = dict(session)
        existing['refresh_token'] = data.get('refresh_token')
        updated = _new_tokens(connection, workspace, {'license_id': session['license_id'], 'expires_at': session['license_expires_at']},
                              int(session['device_id']), existing=existing)
        updated.pop('_refresh_token_value', None)
        connection.commit()
        return {'message': 'The demo session tokens were rotated.', 'session': updated}
    if action == 'revoke':
        scope = 'family' if str(data.get('scope', 'session')).lower() == 'family' else 'session'
        with connection.cursor() as cursor:
            if scope == 'family':
                cursor.execute("UPDATE sunabar_v4_sessions SET revoked_at=%s,revoke_reason='client_family_revoke' WHERE family_id=%s AND revoked_at IS NULL",
                               (now, str(session['family_id'])))
            else:
                cursor.execute("UPDATE sunabar_v4_sessions SET revoked_at=%s,revoke_reason='client_revoke' WHERE id=%s AND revoked_at IS NULL",
                               (now, int(session['id'])))
            affected = cursor.rowcount
        connection.commit()
        return {'revoked': True, 'scope': scope, 'affected_sessions': affected}
    raise V4Error(404, 'NOT_FOUND', 'Unknown v4 session action.')


def handle_v4(action, identity, data, headers, connect, reply, request_id):
    workspace = str(identity['workspace'])
    action = str(action or '').lower()
    try:
        if action == 'challenge':
            connection = connect()
            try:
                return _ok(reply, request_id, _challenge(connection, workspace, data))
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        if action == 'activate':
            connection = connect()
            try:
                return _ok(reply, request_id, _activate(connection, workspace, data))
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        if action in ('verify', 'introspect', 'refresh', 'reauth', 'revoke'):
            connection = connect()
            try:
                return _ok(reply, request_id, _session_action(connection, workspace, action, data, headers))
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()
        if action == 'offline-public-key':
            raise V4Error(501, 'OFFLINE_SIGNING_UNSUPPORTED',
                          'Sunabar emulates online v4 sessions only. Offline signing keys are not issued.')
        if action in ('offline-ticket', 'migrate'):
            raise V4Error(501, 'OFFLINE_UNSUPPORTED' if action == 'offline-ticket' else 'MIGRATION_UNSUPPORTED',
                          'Sunabar emulates online v4 sessions only.')
        raise V4Error(404, 'NOT_FOUND', 'Unknown Sunabar v4 action.')
    except V4Error as exc:
        return v4_error(reply, request_id, exc.status, exc.code, exc.message)
    except Exception as exc:
        print('sunabar_v4_failed request_id=%s error_type=%s' % (request_id, type(exc).__name__),
              file=sys.stderr, flush=True)
        return v4_error(reply, request_id, 503, 'SERVICE_UNAVAILABLE',
                        'The Sunabar emulator is temporarily unavailable.')
