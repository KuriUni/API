"""Python renderer for the Android NFC read handoff page."""
from native_http import make_response, add_headers, legacy_compatible
from deployment_settings import site_url
import re
import os
from pathlib import Path
from urllib.parse import parse_qs
HERE = Path(__file__).resolve().parent
TEMPLATE = Path(os.environ.get('TUTI_STATIC_ROOT', str(HERE / 'site'))) / 'ha' / 'android-card-read.html'
FLOW_ID = re.compile('[A-Za-z0-9_-]{20}\\Z', re.ASCII)

@legacy_compatible(callback_index=1, request_index=0)
def android_card_read(request_context):
    query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
    flow = query.get('f', [''])[0]
    valid = bool(FLOW_ID.fullmatch(flow))
    template = TEMPLATE.read_text(encoding='utf-8')
    if valid:
        content = '<h1>My Number Smart Loginを開きます</h1>\n    <p>このQRは My Number Smart Login Android NFC のWeb受付読取モードを起動します。アプリが開かない場合は、受付対応版をインストールしてからボタンを押してください。</p>\n    <p>アプリの画面で照合番号Bを入力し、端末の本人確認を行ってからマイナンバーカードをNFCで読み取ります。</p>\n    <a class="open-app" id="open-app" href="#" hidden>My Number Smart Loginを開く</a>\n    <div class="tip">券面データと顔写真は端末内で処理します。Webへ送るのは一回限りの受付IDと読み取り成否だけです。この結果は公的なJPKI本人確認や法定本人確認を示しません。</div>'
        script = site_url('<script src="/license/python-migration/android-card-read-fallback.js?v=20261007-intent-2" defer></script>')
        status = '200 OK'
    else:
        content = '<h1>QRコードを確認してください</h1>\n    <p>読み取り依頼の期限が切れているか、URLが正しくありません。受付画面で新しいQRコードを表示してください。</p>'
        script = ''
        status = '400 Bad Request'
    body = template.replace('{{CONTENT}}', content).replace('{{SCRIPT}}', script).encode('utf-8')
    _http_status, _http_headers = (status, [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0'), ('Pragma', 'no-cache'), ('Referrer-Policy', 'no-referrer'), ('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"), ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)
