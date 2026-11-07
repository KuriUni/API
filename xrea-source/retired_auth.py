"""Compatibility responses for retired site-local authentication URLs."""
from native_http import make_response, add_headers, legacy_compatible
import json
import os
import posixpath
import sys
from urllib.parse import parse_qsl, unquote, urlsplit
RETIRED_ROUTES = ('/ha/passkey-callback.php', '/ha/passkey-ha-callback.php', '/ha/passkey-keyadmin-callback.php', '/ha/passkey_api.php', '/ha/web-passkey-manage.php', '/ha/passkey-federation.php', '/api/baas/v1/portal-passkey.php', '/api/baas/v1/common-id-sso.php')
BOOKMARK_ROUTE = '/ha/passkey.php'
RETIRED_ALIASES = ('/.well-known/openid-configuration',)
# All product-key issuance versions except the original V1 and the current V8
# are permanently closed. Keep the URLs inventoried and answer 410 explicitly.
RETIRED_ISSUANCE_ROUTES = (
    '/api/baas/v2/licenses.php', '/api/baas/v3/licenses.php',
    '/api/baas/v7/issuance.php', '/ha/issue-license-v2.php',
    '/ha/issue-license-v3.php',
)
LEGACY_ISSUANCE_SUBMIT_ROUTES = {
    '/api/baas/v4/issuance-jobs.php',
    '/api/baas/v5/issuance.php',
    '/api/baas/v6/issuance.php',
}
LEGACY_ISSUANCE_ROUTES = (
    '/api/baas/v4/issuance-jobs.php', '/api/baas/v4/issuance-results.php',
    '/api/baas/v4/issuance-cancel.php', '/api/baas/v5/issuance.php',
    '/api/baas/v5/issuance-results.php', '/api/baas/v5/issuance-cancel.php',
    '/api/baas/v6/issuance.php', '/api/baas/v6/issuance-results.php',
    '/api/baas/v6/issuance-cancel.php',
)


def is_retired_issuance_request(path, method):
    """Close V2-V7 creation paths but retain legacy status/result/cancel access."""
    method = str(method or 'GET').upper()
    if path in RETIRED_ISSUANCE_ROUTES or (path in LEGACY_ISSUANCE_SUBMIT_ROUTES and method == 'POST'):
        return True
    # V4/V5 HA workers are not new issuance entry points: retain them to drain
    # jobs accepted before the cutover. V4-V7 public submit routes stay closed.
    return False

@legacy_compatible(callback_index=None, request_index=0)
def response(request_context):
    mount = posixpath.dirname(posixpath.dirname(request_context.get('mount_path', ''))).rstrip('/')
    path = unquote(urlsplit(request_context.get('uri', '')).path)
    if mount:
        if not path.startswith(mount + '/'):
            return ('404 Not Found', [], b'')
        path = path[len(mount):]
    headers = [('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff')]
    if path == BOOKMARK_ROUTE:
        client = ''
        for name, value in parse_qsl(request_context.get('query', ''), keep_blank_values=True):
            if name == 'client':
                client = value
            elif name.startswith('client['):
                client = ''
        target = '&target=mobile' if client == 'admin_mobile' else ''
        headers.extend([('Content-Type', 'text/html; charset=UTF-8'), ('Location', '../admin_api.php?admin_sso_start=1' + target)])
        return ('303 See Other', headers, b'')
    retired_issuance = is_retired_issuance_request(path, request_context.get('method', 'GET'))
    if path not in RETIRED_ROUTES and path not in RETIRED_ALIASES and not retired_issuance:
        return ('404 Not Found', headers, b'')
    headers.append(('Content-Type', 'application/json; charset=utf-8'))
    body = json.dumps({'ok': False, 'error': 'product_key_issuance_version_retired' if retired_issuance else 'site_passkeys_retired', 'message': ('プロダクトキー発行はV8へ統合されました。V1互換発行は引き続き利用できます。' if retired_issuance else 'サイト独自のパスキー機能は終了しました。SSO IDをご利用ください。'), 'replacement': '/api/baas/v8/issuance.php' if retired_issuance else 'https://sso.2415.jp', 'sso_url': 'https://sso.2415.jp'}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    return ('410 Gone', headers, body)

def main():
    try:
        remaining = max(0, int(os.environ.get('CONTENT_LENGTH') or '0'))
    except ValueError:
        remaining = 0
    while remaining:
        chunk = sys.stdin.buffer.read(min(remaining, 65536))
        if not chunk:
            break
        remaining -= len(chunk)
    status, headers, body = response(os.environ)
    output = ['Status: ' + status] + [name + ': ' + value for name, value in headers]
    sys.stdout.buffer.write(('\r\n'.join(output) + '\r\n\r\n').encode('ascii'))
    if os.environ.get('REQUEST_METHOD') != 'HEAD':
        sys.stdout.buffer.write(body)
if __name__ == '__main__':
    main()
