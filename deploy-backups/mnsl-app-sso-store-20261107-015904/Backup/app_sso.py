"""Node-bound, proof-key protected handoff from central SSO to native apps.

The browser grants explicitly after fresh OIDC authentication. Bearer credentials
never appear in URLs or HTML; the native app consumes a grant once using both
its polling secret and its locally generated PKCE verifier.
"""
from contextlib import contextmanager
import base64
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import time
from urllib.parse import parse_qs

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from file_locking import fcntl
from native_http import make_response
from deployment_settings import site_url

HOSTS = {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}
LIFETIME = 300


class FlowError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def _b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def _path():
    from passkey_handlers import _store_path
    return _store_path().parent / 'app-sso-grants.json'


def _cipher():
    from admin_oidc import _flow_key
    return AESGCM(hashlib.sha256(_flow_key()).digest())


@contextmanager
def _store():
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix('.lock').open('a+b') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            raw = path.read_bytes() if path.exists() else b'{}'
            if len(raw) > 2_000_000:
                raise RuntimeError('grant_store_too_large')
            rows = json.loads(raw)
            if not isinstance(rows, dict):
                raise RuntimeError('invalid_grant_store')
            rows = {key: row for key, row in rows.items() if int(row['expires']) > int(time.time())}
            yield rows
            temporary = path.with_name(path.name + '.' + secrets.token_hex(8))
            try:
                with temporary.open('x', encoding='utf-8') as output:
                    os.chmod(temporary, 0o600)
                    json.dump(rows, output, separators=(',', ':'))
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _host(context):
    host = str(context.get('header:host', '')).lower()
    if host not in HOSTS:
        raise FlowError(400, 'invalid_sso_host')
    return host


def _endpoint(host):
    return 'https://' + host + site_url('/license/python-migration/mobile-manager/admin-auth.php')


def _body(context):
    try:
        length = int(context.get('content_length', 0))
        if not 0 < length <= 4096:
            raise ValueError()
        raw = context['body_stream'].read(length)
        if len(raw) != length:
            raise ValueError()
        if context.get('content_type', '').split(';')[0] == 'application/x-www-form-urlencoded':
            return {key: values[-1] for key, values in parse_qs(raw.decode()).items()}
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, KeyError, UnicodeError):
        raise FlowError(400, 'invalid_sso_request')


def _reply(status, payload, html_page=False):
    raw = payload.encode('utf-8') if html_page else json.dumps(payload, ensure_ascii=False).encode('utf-8')
    return make_response(raw, status, [('Content-Type', 'text/html; charset=utf-8' if html_page else 'application/json; charset=utf-8'),
        ('Cache-Control', 'no-store'), ('Pragma', 'no-cache'), ('Referrer-Policy', 'no-referrer'),
        ('Content-Security-Policy', "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
        ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(raw)))])


def _row(rows, ticket, host):
    row = rows.get(ticket)
    if not isinstance(row, dict) or row.get('host') != host or row.get('kind') == 'mnsl-issuer':
        raise FlowError(400, 'invalid_or_expired_app_login')
    return row


def valid_ticket(ticket, host):
    if not re.fullmatch(r'[A-Za-z0-9_-]{32}', str(ticket or '')):
        return False
    with _store() as rows:
        return bool(rows.get(ticket, {}).get('host') == host and rows.get(ticket, {}).get('kind') != 'mnsl-issuer')


def _browser_claims(context):
    from admin_api_handlers import SESSION_COOKIE
    from mobile_admin_auth import _cookies
    from baas_handlers import _decode_admin_session
    claims = _decode_admin_session(_cookies(context).get(SESSION_COOKIE, ''))
    return claims if claims and claims.get('auth_source') == 'oidc_sso' else None


def _issue_token(claims, *, tenant_session=False):
    from web_passkey_auth import ADMIN_SCOPES, _encode_token
    from mobile_admin_auth import _principal
    from baas_handlers import _role_allows_scope
    role = _principal(str(claims.get('credential_id_hash', '')))
    if role not in {'viewer', 'operator', 'security-admin', 'ha-admin'}:
        raise FlowError(403, 'sso_role_denied')
    requested = set(ADMIN_SCOPES) | {'tenant:read', 'products:write', 'licenses:read', 'licenses:write'}
    scopes = sorted(scope for scope in requested if _role_allows_scope(role, scope)) + ['tenant:api']
    now = int(time.time())
    return _encode_token({'purpose': 'ha_admin', 'auth_source': 'oidc_sso',
        'scope': scopes, 'client': 'desktop', 'source': 'mnsl_sso' if tenant_session else 'app_sso',
        'credential_id_hash': str(claims['credential_id_hash']), 'oidc_sid': str(claims['oidc_sid']),
        'issued_at': now, 'expires': min(now + 300, int(claims['expires'])),
        'reauthenticated_at': int(claims.get('reauthenticated_at') or 0), 'nonce': _b64(secrets.token_bytes(16))})


def _decode_token(token):
    from baas_handlers import _decode_admin_session
    from mobile_admin_auth import _principal
    from baas_handlers import _role_allows_scope
    claims = _decode_admin_session(token)
    if not claims:
        return None
    role = _principal(str(claims.get('credential_id_hash', '')))
    if role not in {'viewer', 'operator', 'security-admin', 'ha-admin'} or any(scope != 'tenant:api' and not _role_allows_scope(role, scope) for scope in claims.get('scope', [])):
        return None
    return claims


def handle(context):
    try:
        host = _host(context)
        query = parse_qs(context.get('query', ''))
        action = query.get('action', [''])[-1]
        method = context.get('method', 'GET')
        if action == 'app_start' and method == 'POST':
            body = _body(context)
            challenge = body.get('code_challenge', '')
            if not isinstance(challenge, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', challenge):
                raise FlowError(400, 'invalid_code_challenge')
            now = int(time.time())
            ticket, polling = _b64(secrets.token_bytes(24)), _b64(secrets.token_bytes(32))
            address = hashlib.sha256(str(context.get('client_address', '')).encode()).hexdigest()
            with _store() as rows:
                if len(rows) >= 1000 or sum(row.get('address') == address for row in rows.values()) >= 30:
                    raise FlowError(429, 'app_login_rate_limited')
                rows[ticket] = {'host': host, 'challenge': challenge, 'poll_hash': hashlib.sha256(polling.encode()).hexdigest(),
                                'created': now, 'expires': now + LIFETIME, 'address': address}
            return _reply(200, {'ok': True, 'ticket': ticket, 'poll_token': polling, 'expires_in': LIFETIME,
                                'url': _endpoint(host) + '?action=app_authorize&ticket=' + ticket})
        if action == 'app_poll' and method == 'POST':
            body = _body(context)
            ticket, polling, verifier = (body.get(key, '') for key in ('ticket', 'poll_token', 'code_verifier'))
            if not all(isinstance(value, str) for value in (ticket, polling, verifier)) or not re.fullmatch(r'[A-Za-z0-9._~-]{43,128}', verifier):
                raise FlowError(400, 'invalid_app_proof')
            with _store() as rows:
                row = _row(rows, ticket, host)
                if not hmac.compare_digest(row['poll_hash'], hashlib.sha256(polling.encode()).hexdigest()) or not hmac.compare_digest(row['challenge'], _b64(hashlib.sha256(verifier.encode()).digest())):
                    raise FlowError(401, 'invalid_app_proof')
                encrypted = row.get('grant')
                if not encrypted:
                    return _reply(202, {'ok': True, 'pending': True})
                grant = base64.urlsafe_b64decode(encrypted + "=" * (-len(encrypted) % 4))
            token = _cipher().decrypt(grant[:12], grant[12:], (host + ':' + ticket).encode()).decode()
            claims = _decode_token(token)
            if not claims or claims.get('auth_source') != 'oidc_sso':
                raise FlowError(401, 'SSO_SESSION_EXPIRED')
            with _store() as rows:
                _row(rows, ticket, host)
                del rows[ticket]
            return _reply(200, {'ok': True, 'session_token': token, 'authenticated_until': int(claims['expires']), 'auth_method': 'oidc_sso'})
        if action == 'app_authorize' and method in ('GET', 'POST'):
            ticket = query.get('ticket', [''])[-1]
            with _store() as rows:
                row = dict(_row(rows, ticket, host))
            claims = _browser_claims(context)
            fresh = claims and int(claims.get('reauthenticated_at') or 0) >= row['created']
            if not fresh:
                from admin_oidc import start
                login = dict(context, query='target=mobile&app_ticket=' + ticket)
                return start(login)
            from mobile_admin_auth import _cookies, _csrf_valid
            from admin_api_handlers import CSRF_COOKIE
            if method == 'POST':
                body = _body(context)
                if not _csrf_valid(context, body.get('csrf')):
                    raise FlowError(403, 'csrf_rejected')
                token = _issue_token(claims)
                nonce = secrets.token_bytes(12)
                grant = _b64(nonce + _cipher().encrypt(nonce, token.encode(), (host + ':' + ticket).encode()))
                with _store() as rows:
                    current = _row(rows, ticket, host)
                    if current.get('grant'):
                        raise FlowError(409, 'app_login_already_approved')
                    current['grant'] = grant
                return _reply(200, '<!doctype html><html lang="ja"><meta charset="utf-8"><title>SSO認証完了</title><h1>SSO認証が完了しました</h1><p>元のソフトへ戻ってください。この画面は閉じられます。</p></html>', True)
            csrf = html.escape(_cookies(context).get(CSRF_COOKIE, ''), quote=True)
            page = '<!doctype html><html lang="ja"><meta charset="utf-8"><title>ソフトへのSSOログイン</title><h1>ソフトへのSSOログイン</h1><p>接続先：' + html.escape(host) + '</p><p>自分で開始したソフトへのログインだけを許可してください。5分間のAPIセッションを発行します。</p><form method="post"><input type="hidden" name="csrf" value="' + csrf + '"><button type="submit">このソフトへのSSOログインを許可</button></form></html>'
            return _reply(200, page, True)
        raise FlowError(405, 'app_login_method_not_allowed')
    except FlowError as error:
        return _reply(error.status, {'ok': False, 'error': error.code})
    except Exception:
        return _reply(503, {'ok': False, 'error': 'app_sso_unavailable'})
