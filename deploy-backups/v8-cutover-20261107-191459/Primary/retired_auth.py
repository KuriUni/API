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
    if path not in RETIRED_ROUTES and path not in RETIRED_ALIASES:
        return ('404 Not Found', headers, b'')
    headers.append(('Content-Type', 'application/json; charset=utf-8'))
    body = json.dumps({'ok': False, 'error': 'site_passkeys_retired', 'message': 'サイト独自のパスキー機能は終了しました。SSO IDをご利用ください。', 'sso_url': 'https://sso.2415.jp'}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
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
