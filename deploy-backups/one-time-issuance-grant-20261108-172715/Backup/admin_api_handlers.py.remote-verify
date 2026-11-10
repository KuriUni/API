"""Python API subset for the legacy /admin_api.php entry point."""
from native_http import make_response, add_headers, legacy_compatible
from deployment_settings import site_url
from py36_compat import parse_iso_datetime, parse_iso_date
import hashlib
import hmac
import html
import csv
import base64
import io
import json
import os
import re
import secrets
import time
import uuid
from http.cookies import SimpleCookie
from io import BytesIO
from datetime import date, datetime, timezone, timedelta
from decimal import Decimal
from urllib.parse import quote
from http_utils import php_parse_query as parse_qs
import database
from admin_core import admin_device_payload, admin_input, admin_license_payload, admin_like_value, admin_page_offset, admin_request_int, admin_request_string, admin_respond, admin_session_payload
from core import key_pepper, license_key_hash, normalize_license_key, parse_utc_datetime, php_bool_cast
from migration_config import secret_value
SESSION_COOKIE = 'tuti_python_migration_admin_session'
CSRF_COOKIE = 'tuti_python_migration_admin_csrf'
ADMIN_IDLE_TIMEOUT = 1800
LOGIN_CSS = 'body{margin:0;background:#eff6f4;color:#17343b;font:16px system-ui,sans-serif;min-height:100vh;display:grid;place-items:center}.card{width:min(520px,calc(100% - 36px));background:#fff;border:1px solid #dce8e5;border-radius:24px;padding:32px;box-shadow:0 20px 60px #17343b18}h1{font-size:28px;margin:.3em 0}.sub{color:#718589;line-height:1.7}.button{display:block;margin:20px 0;padding:16px;border-radius:12px;background:#08796d;color:#fff;text-decoration:none;font-weight:700;text-align:center}.notice{padding:12px;border-radius:10px;background:#f5f8f7;color:#5d7373;font-size:13px}'
ADMIN_UI_CSS = '''
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:150px}body{min-height:100vh;background:radial-gradient(ellipse at 8% 0%,#e4f3ef 0,transparent 38%),#f4f7f7;color:#18353b;font:15px/1.6 system-ui,-apple-system,"Segoe UI","Yu Gothic UI",Meiryo,sans-serif}.wrap{width:min(1280px,100%);margin:0 auto;padding:28px clamp(16px,3vw,42px) 72px}.wrap>header{position:relative;top:auto;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:20px;margin:0 -8px 14px;padding:14px 18px;background:#f8fbfaee;border:1px solid #dce9e6;border-radius:16px;box-shadow:0 8px 26px #17343b0d;backdrop-filter:blur(14px)}header b{font-size:12px;letter-spacing:.08em;color:#08796d}h1{margin:2px 0 4px;font-size:clamp(23px,3vw,32px);line-height:1.25;letter-spacing:-.025em}header p{margin:0}h2{margin:0 0 8px;font-size:20px;line-height:1.35;letter-spacing:-.015em}.muted{color:#637b7e;line-height:1.65}.quick-nav{position:sticky;top:0;z-index:19;display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:8px;margin:0 -8px 20px;padding:10px;background:#edf4f2ef;border:1px solid #dce9e6;border-radius:14px;backdrop-filter:blur(12px)}.quick-nav a{display:flex;min-height:62px;flex-direction:column;justify-content:center;gap:2px;padding:8px 12px;border:1px solid #dce9e6;border-radius:10px;background:#fff;color:#31575b;text-decoration:none;font-size:13px;font-weight:700}.quick-nav a small{color:#637b7e;font-size:11px;font-weight:500;white-space:normal}.quick-nav a:hover,.quick-nav a:focus-visible{border-color:#8dc9bf;background:#f5fbf9;color:#075f56}.card{scroll-margin-top:76px;background:#fff;border:1px solid #dce7e5;border-radius:18px;padding:clamp(20px,2.2vw,30px);margin:18px 0;box-shadow:0 8px 26px #17343b09}.card>p:first-of-type{margin-top:0}.card h2:before{content:"";display:inline-block;width:4px;height:1em;margin:0 10px -2px 0;border-radius:4px;background:#0a8978}.controls{align-items:end;gap:10px}.controls input,.controls select{flex:1 1 170px;min-width:min(100%,150px)}input,select,textarea{max-width:100%;padding:11px 12px;border:1px solid #cbdad7;border-radius:10px;background:#fff;color:#18353b;font:inherit;transition:border-color .15s,box-shadow .15s}input:focus,select:focus,textarea:focus{outline:none;border-color:#078678;box-shadow:0 0 0 3px #07867820}label{display:block;margin:12px 0 6px;color:#35565a;font-size:13px;font-weight:700}button,.button{min-height:42px;padding:10px 15px;border:1px solid #08796d;border-radius:10px;background:#08796d;color:white;font:inherit;font-weight:700;text-decoration:none;cursor:pointer;transition:transform .12s,background .12s,box-shadow .12s}button:hover,.button:hover{background:#06695e;box-shadow:0 4px 12px #08796d24}button:active,.button:active{transform:translateY(1px)}button:disabled{opacity:.48;cursor:not-allowed;box-shadow:none}button.secondary{border-color:#cbdad7;background:#f0f5f4;color:#36575b}button.secondary:hover{background:#e5efed}.error{color:#a62837}#status,#license-status,#csv-status,#tenant-status,#sso-identity-status{min-height:1.5em;margin:10px 0;font-weight:600}#results,#license-results,#tenants,#tenant-keys,#diagnostic-result,#tenant-key-secret{overflow:auto}#results table,#license-results table,#tenants table,#tenant-keys table{min-width:680px}table{width:100%;border-collapse:separate;border-spacing:0;margin-top:14px;overflow:hidden;border:1px solid #e1eae8;border-radius:12px}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid #e7eeec;overflow-wrap:anywhere}th{background:#f1f6f5;color:#35565a;font-size:12px}tr:last-child td{border-bottom:0}tbody tr:hover{background:#f8fbfa}#audit-filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px;margin:14px 0;padding:16px;background:#f7faf9;border:1px solid #e3ecea;border-radius:14px}#audit-filters label{margin:0}#audit-filters input{display:block;width:100%;margin-top:5px}#audit-filters>div{grid-column:1/-1;display:flex;align-items:center;gap:8px}#bulk-controls{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));align-items:end;gap:12px;margin-top:16px;padding:16px;background:#f7faf9;border:1px solid #e3ecea;border-radius:14px}#bulk-controls label{margin:0}#bulk-controls select,#bulk-controls input{display:block;width:100%;margin-top:5px}#bulk-controls [hidden],[hidden]{display:none!important}#license{min-width:0}#license-results,#results{margin-top:14px}#sso-identity-recovery{border-color:#a9d8d0;background:linear-gradient(135deg,#f3fbf9,#fff 65%)}#sso-identity-recovery h2:before{background:#d58a31}#sso-identity-result{margin:12px 0;padding:12px 14px;border-radius:10px;background:#eef7f5;font-weight:700;overflow-wrap:anywhere}#delete-sso-identity{border-color:#bd4651;background:#fff;color:#a42b38}#delete-sso-identity:hover{background:#fff1f2}.section-intro{max-width:75ch}.wrap>footer{margin-top:28px;color:#728887;font-size:12px}a{color:#08796d}pre{max-width:100%;overflow:auto;padding:14px;border-radius:12px;background:#f1f5f4}.skip-link{position:fixed;top:-80px;left:12px;z-index:100;padding:10px 14px;border-radius:9px;background:#123f3d;color:white;font-weight:700}.skip-link:focus{top:10px}::selection{background:#bde4dc}@media(max-width:760px){html{scroll-padding-top:72px}.wrap{padding:12px 12px 48px}.wrap>header{position:relative;align-items:flex-start;margin:0 0 10px;padding:14px;border-radius:13px}.quick-nav{top:0;margin:0 -2px 14px;border-radius:11px}.card{scroll-margin-top:62px;padding:18px 15px;margin:12px 0;border-radius:14px}.controls{align-items:stretch}.controls input,.controls select{flex:1 1 100%;width:100%;min-width:0}.controls button{flex:1 1 auto}#audit-filters{grid-template-columns:1fr;padding:12px}#audit-filters>div{grid-column:auto;flex-wrap:wrap}#bulk-controls{grid-template-columns:1fr;padding:12px}h2{font-size:18px}}@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important}}
'''

def _json_safe(value):
    if isinstance(value, datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {key: _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value

@legacy_compatible(callback_index=0, request_index=None)
def _reply(status, payload, headers=()):
    body = json.dumps(_json_safe(payload), ensure_ascii=False, separators=(',', ':')).encode()
    _http_status, _http_headers = (status, [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Content-Length', str(len(body)))] + list(headers))
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=0, request_index=None)
def _csv_reply(rows):
    import io
    out = io.StringIO(newline='')
    writer = csv.writer(out, lineterminator='\r\n')
    writer.writerow(['license_id', 'label', 'active', 'max_devices', 'evaluation_days', 'expires_at_utc', 'revoked_at_utc', 'created_at_utc', 'last_activated_at_utc', 'last_seen_at_utc'])
    for row in rows:
        label = str(row.get('label') or '')
        if re.match('^[=+@\\-\\t\\r]', label):
            label = "'" + label
        writer.writerow([row.get('id'), label, row.get('active'), row.get('max_devices'), row.get('evaluation_days'), row.get('expires_at'), row.get('revoked_at'), row.get('created_at'), row.get('last_activated_at'), row.get('last_seen_at')])
    body = b'\xef\xbb\xbf' + out.getvalue().encode('utf-8')
    _http_status, _http_headers = ('200 OK', [('Content-Type', 'text/csv; charset=utf-8'), ('Content-Disposition', 'attachment; filename="tuti-licenses.csv"'), ('Cache-Control', 'no-store'), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=1, request_index=0)
def _login_page(request_context, message=''):
    host = str(request_context.get('header:host', '2415.jp')).lower().split(':', 1)[0]
    if host not in {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}:
        host = '2415.jp'
    base = os.environ.get('PYTHON_MIGRATION_PUBLIC_BASE_URL', site_url('https://2415.jp/license/python-migration')).rstrip('/')
    if host == 'backup.2415.jp':
        base = site_url('https://backup.2415.jp/license/python-migration')
    elif host == 'main.2415.jp':
        base = site_url('https://main.2415.jp/license/python-migration')
    oidc_link = '<a class="button" href="admin_api.php?admin_sso_start=1">SSO IDでログイン</a>'
    alert = '<p class="notice" role="status">' + message + '</p>' if message else ''
    body = ('<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>ライセンス管理センター</title><style>' + LOGIN_CSS + '</style></head><body><main class="card"><b>TUTI LICENSE · ADMIN CENTER</b><h1>管理センターへログイン</h1><p class="sub">管理者SSO IDで本人確認してください。</p>' + alert + oidc_link + '<p class="notice">SSO IDとの連携設定と、管理者の登録が必要です。</p></main></body></html>').encode()
    _http_status, _http_headers = ('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'), ('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=0, request_index=None)
def _error(status, message, error_code=None, extra=None, headers=()):
    payload = {'success': False, 'message': message}
    if error_code:
        payload['error_code'] = error_code
    payload.update(extra or {})
    return _reply(status, payload, headers)

def _admin_action(data):
    value = data.get('action')
    if value is None:
        value = data.get('api_action')
    return admin_request_string({'value': value}, 'value')

@legacy_compatible(callback_index=None, request_index=0)
def _authorize(request_context, data, scope):
    token_value = request_context.get('header:x-ha-session')
    if token_value is None:
        token_value = data.get('passkey_session')
    token = admin_request_string({'value': token_value}, 'value')
    from_cookie = False
    if not token:
        cookies = SimpleCookie()
        try:
            cookies.load(request_context.get('header:cookie', ''))
            token = cookies.get(SESSION_COOKIE).value if cookies.get(SESSION_COOKIE) else ''
            from_cookie = bool(token)
        except Exception:
            token = ''
    if not token:
        return (None, '401 Unauthorized', 'パスキー認証が必要です。')
    from baas_handlers import _decode_admin_session
    claims = _decode_admin_session(token)
    if not claims:
        return (None, '401 Unauthorized', '共通ログインの期限が切れました。Passkeyで再認証してください。')
    if claims.get('oidc_sid'):
        from admin_oidc import session_active
        if not session_active(str(claims['oidc_sid'])):
            return (None, '401 Unauthorized', 'SSO IDの認証セッションが失効しました。再ログインしてください。')
    scopes = claims.get('scope', [])
    if not isinstance(scopes, list):
        scopes = [scopes]
    if scope not in scopes:
        return (None, '403 Forbidden', 'この操作を行う権限がありません。')
    request_context['header:x-ha-session'] = token
    from ha_handlers import _ha_authorized_scope
    if not _ha_authorized_scope(request_context, scope):
        return (None, '403 Forbidden', 'この操作を行う権限がありません。')
    if from_cookie and request_context.get('method', 'GET') == 'POST':
        host = str(request_context.get('header:host', '2415.jp')).lower().split(':', 1)[0]
        origin = str(request_context.get('header:origin', ''))
        allowed = 'https://' + host
        cookies = SimpleCookie()
        try:
            cookies.load(request_context.get('header:cookie', ''))
            csrf_cookie = cookies.get(CSRF_COOKIE).value if cookies.get(CSRF_COOKIE) else ''
        except Exception:
            csrf_cookie = ''
        csrf = str(request_context.get('header:x-csrf-token', '') or data.get('csrf', ''))
        if origin != allowed or not csrf_cookie or (not hmac.compare_digest(csrf, csrf_cookie)):
            return (None, '403 Forbidden', 'CSRF validation failed.')
    return (claims, None, None)

@legacy_compatible(callback_index=None, request_index=0)
def _cookie_value(request_context, name):
    cookies = SimpleCookie()
    try:
        cookies.load(request_context.get('header:cookie', ''))
        return cookies.get(name).value if cookies.get(name) else ''
    except Exception:
        return ''

@legacy_compatible(callback_index=1, request_index=0)
def admin_api(request_context):
    """Refresh the signed admin cookie to match PHP's 30-minute idle timeout."""
    query = parse_qs(str(request_context.get('query', '')), keep_blank_values=True)
    host = str(request_context.get('header:host', '')).lower().split(':', 1)[0]
    method = str(request_context.get('method', 'GET'))
    action = query.get('action', [None])[-1]
    if action is None and method == 'POST' and ('application/x-www-form-urlencoded' in str(request_context.get('content_type', '')).lower()):
        stream = request_context.get('body_stream', BytesIO())
        raw = stream.read(131073)
        request_context['body_stream'] = BytesIO(raw)
        if len(raw) <= 131072:
            post = parse_qs(raw.decode('utf-8', errors='replace'), keep_blank_values=True)
            action = post.get('action', [''])[-1]
    action = '' if action is None else str(action)
    auth_callback = 'admin_sso_callback' in query
    if host == 'backup.2415.jp' and action != 'diagnose_error' and (not auth_callback):
        primary = site_url('https://2415.jp/license/python-migration/admin_api.php')
        if method.upper() == 'POST' or 'step_up_resume' in query:
            if 'application/json' in str(request_context.get('content_type', '')).lower():
                return admin_respond('409 Conflict', False, 'この操作は正系の管理センターから行ってください。正系へ移動します。', {'error_code': 'PRIMARY_ONLY', 'canonical_url': primary})
            body = ('<!doctype html><html lang="ja"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>正系サーバーで操作してください</title><body style="font:16px system-ui,sans-serif;max-width:680px;margin:12vh auto;padding:24px;color:#172033"><h1>管理操作を続けられません</h1><p>この画面は待機系サーバーです。登録などの操作は正系の管理センターから行ってください。今回の送信は処理されていません。</p><p><a href="' + primary + '">正系のライセンス管理センターを開く</a></p></body></html>').encode()
            _http_status, _http_headers = ('409 Conflict', [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'no-store'), ('Content-Length', str(len(body)))])
            return make_response([body], _http_status, _http_headers)
        _http_status, _http_headers = ('303 See Other', [('Location', primary), ('Cache-Control', 'no-store'), ('Content-Length', '0')])
        return make_response([b''], _http_status, _http_headers)
    skip_refresh = bool(query.get('admin_sso_callback'))
    if str(request_context.get('method', 'GET')) == 'POST':
        raw = None
        try:
            raw = request_context.get('body_stream', BytesIO()).read(131073)
            if len(raw) <= 65536:
                parsed = admin_input({**request_context, 'body_stream': BytesIO(raw)})
                skip_refresh = skip_refresh or parsed.get('action') == 'logout'
            else:
                skip_refresh = True
        except Exception:
            pass
        finally:
            if raw is not None:
                request_context['body_stream'] = BytesIO(raw)
    refreshed = ''
    csrf = _cookie_value(request_context, CSRF_COOKIE)
    token = _cookie_value(request_context, SESSION_COOKIE)
    if token and (not skip_refresh):
        try:
            from baas_handlers import _decode_admin_session
            claims = _decode_admin_session(token)
            if claims:
                claims['expires'] = int(time.time()) + ADMIN_IDLE_TIMEOUT
                claims['last_activity'] = int(time.time())
                from web_passkey_auth import _encode_token
                refreshed = _encode_token(claims)
        except Exception:
            refreshed = ''
    try:
        response = _admin_api_request(request_context)
    except Exception as error:
        try:
            import traceback
            from audit import append_event
            frames = [{'file': os.path.basename(frame.filename), 'line': frame.lineno}
                      for frame in traceback.extract_tb(error.__traceback__)[-8:]]
            append_event('admin_page_request_failed', {
                'stage': 'admin_api_request',
                'error_type': type(error).__name__,
                'frames': frames,
                'host': host,
            })
        except Exception:
            pass
        return _error('500 Internal Server Error', '管理画面を表示できません。診断ログを確認してください。')
    if refreshed:
        base = site_url('/license/python-migration/')
        response = add_headers(response, [('Set-Cookie', SESSION_COOKIE + '=' + refreshed + '; Path=' + base + '; Max-Age=' + str(ADMIN_IDLE_TIMEOUT) + '; Secure; HttpOnly; SameSite=Strict'), ('Set-Cookie', CSRF_COOKIE + '=' + csrf + '; Path=' + base + '; Max-Age=' + str(ADMIN_IDLE_TIMEOUT) + '; Secure; SameSite=Strict')])
    return response

@legacy_compatible(callback_index=1, request_index=0)
def _operations_dashboard_page(request_context, token, claims):
    from baas_handlers import _role_allows_scope
    role = _effective_admin_role(claims)
    can_ha = _role_allows_scope(role, 'ha:operate')
    links = [
        ('admin_api.php#device-management', '端末・セッション', '登録端末と有効セッション'),
        ('admin_api.php#license-management', 'ライセンス管理', '検索・状態・監査ログ'),
    ]
    if _role_allows_scope(role, 'license:write'):
        links.append(('admin_api.php#license-issuance', 'ライセンス発行', '個別発行・CSV一括発行'))
    if _role_allows_scope(role, 'admin:manage'):
        links.extend([
            ('admin_api.php#tenant-management', 'テナント管理', '契約先とAPIキー'),
            ('admin_api.php?view=api-invoices', '請求書管理', '利用明細と請求書'),
            ('admin_api.php#admin-principal-management', '管理者設定', '管理者権限と所属'),
        ])
    health_url = site_url('/license/python-migration/ha/health.php')
    nav = ''.join('<a class="launch-card" href="%s"><b>%s</b><span>%s</span><i aria-hidden="true">→</i></a>' %
                  (html.escape(href, quote=True), html.escape(label), html.escape(detail))
                  for href, label, detail in links)
    audit_panel = ''
    if can_ha:
        audit_panel = ('<section class="panel"><div class="panel-head"><div><p class="eyebrow">SECURITY & OPERATIONS</p>'
            '<h2>直近の運用監査</h2></div><button id="refresh-audit" class="secondary">更新</button></div>'
            '<p class="muted">HA運用権限で閲覧できる監査イベントを最大30件表示します。詳細情報や認証情報は表示しません。</p>'
            '<div id="audit-state" class="state">読み込み中</div><ol id="audit-list" class="audit-list"></ol></section>')
    ha_script = ''
    if can_ha:
        ha_script = '''
async function loadAudit(){const state=document.getElementById('audit-state'),list=document.getElementById('audit-list');state.textContent='取得中…';list.replaceChildren();try{const r=await fetch(AUDIT_URL,{headers:{'X-HA-Session':HA_SESSION},credentials:'same-origin',cache:'no-store'}),d=await r.json();if(!r.ok||!d.ok)throw Error('監査記録を取得できません');if(!d.events.length){state.textContent='表示できる記録はありません';return}state.textContent=d.count+'件';for(const item of d.events){const row=document.createElement('li'),time=document.createElement('time'),event=document.createElement('b'),role=document.createElement('span');time.textContent=item.at_utc||'日時不明';event.textContent=item.event||'イベント';role.textContent=item.configured_role||'role不明';row.append(time,event,role);list.append(row)}}catch(e){state.textContent=e.message}}
document.getElementById('refresh-audit').addEventListener('click',loadAudit);loadAudit();
'''
    body = '''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>運用ダッシュボード | TUTI LICENSE</title><style>
:root{color-scheme:light;--ink:#18353b;--muted:#637b7e;--line:#dce7e5;--accent:#08796d;--canvas:#f3f7f6}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 10% 0,#e2f2ee 0,transparent 36%),var(--canvas);color:var(--ink);font:15px/1.6 system-ui,-apple-system,"Segoe UI","Yu Gothic UI",Meiryo,sans-serif}.wrap{width:min(1120px,100%);margin:auto;padding:28px 22px 64px}.top{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-bottom:22px}.brand{font-size:12px;font-weight:800;letter-spacing:.12em;color:var(--accent)}h1{margin:6px 0;font-size:clamp(26px,4vw,38px);letter-spacing:-.03em}.muted{color:var(--muted);margin:0}.top a,.launch-card{color:var(--accent);text-decoration:none}.top a{font-weight:700}.panel{background:#fff;border:1px solid var(--line);border-radius:17px;padding:22px;margin:16px 0;box-shadow:0 8px 28px #17343b0b}.panel-head{display:flex;justify-content:space-between;align-items:center;gap:12px}.eyebrow{color:#719086;font-size:10px;font-weight:800;letter-spacing:.15em;margin:0 0 4px}h2{margin:0;font-size:21px}.state{margin:14px 0;padding:12px 14px;border-radius:10px;background:#f2f7f5;font-weight:700}.state.ok{color:#176447;background:#eaf6ef}.state.bad{color:#a32937;background:#fff0f1}.state.warn{color:#94611d;background:#fff8e9}.launch-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:11px;margin-top:16px}.launch-card{position:relative;display:flex;min-height:98px;flex-direction:column;gap:5px;padding:17px 40px 15px 17px;border:1px solid var(--line);border-radius:12px;background:#fff}.launch-card:hover{border-color:#8ec9bd;background:#f7fbfa}.launch-card b{color:var(--ink);font-size:15px}.launch-card span{color:var(--muted);font-size:12px}.launch-card i{position:absolute;right:16px;top:16px;font-size:20px;font-style:normal}.secondary{padding:9px 13px;border:1px solid #cfddda;border-radius:8px;background:#f1f6f5;color:#34575a;font:inherit;font-weight:700;cursor:pointer}.audit-list{list-style:none;padding:0;margin:0}.audit-list li{display:grid;grid-template-columns:minmax(155px,.8fr) minmax(190px,1fr) 100px;gap:12px;padding:12px 3px;border-bottom:1px solid #edf1f0}.audit-list li:last-child{border:0}.audit-list time,.audit-list span{color:var(--muted);font-size:12px;overflow-wrap:anywhere}footer{padding:15px 3px;color:var(--muted);font-size:12px}@media(max-width:600px){.wrap{padding:18px 13px 44px}.top{align-items:flex-start}.panel{padding:17px 14px}.audit-list li{grid-template-columns:1fr;gap:2px}}
</style></head><body><main class="wrap"><header class="top"><div><div class="brand">TUTI LICENSE · OPERATIONS</div><h1>運用ダッシュボード</h1><p class="muted">XREA運用環境の稼働確認と管理機能への入口</p></div><a href="admin_api.php">管理センターへ戻る</a></header>
<section class="panel"><div class="panel-head"><div><p class="eyebrow">SERVICE READINESS</p><h2>サービス稼働状況</h2></div><button id="refresh-health" class="secondary">再確認</button></div><div id="health-state" class="state">確認中…</div><p id="health-detail" class="muted">DB・必須スキーマ・非公開ストレージ・書き込みフェンスを確認しています。</p></section>
<section class="panel"><p class="eyebrow">ADMIN WORKSPACE</p><h2>管理機能</h2><div class="launch-grid">''' + nav + '''</div></section>''' + audit_panel + '''<footer>アクセス権限は既存の管理セッションに従います。画面は読み取り専用で、データ変更は各管理機能から実行してください。</footer></main>
<script>const HEALTH_URL="''' + html.escape(health_url, quote=True) + '''",AUDIT_URL="''' + site_url('/license/python-migration/ha/audit-recent.php') + '''",HA_SESSION="''' + html.escape(token, quote=True) + '''";
async function loadHealth(){const state=document.getElementById('health-state'),detail=document.getElementById('health-detail');state.className='state';state.textContent='確認中…';try{const r=await fetch(HEALTH_URL,{credentials:'same-origin',cache:'no-store'}),d=await r.json();if(!r.ok||d.ok!==true)throw Error('必須サービスの準備状態を確認できません');state.classList.add('ok');state.textContent='稼働中';detail.textContent='データベース、必須スキーマ、非公開ストレージ、書き込みフェンスは正常です。'}catch(e){state.classList.add('bad');state.textContent='要確認';detail.textContent=e.message+'。詳細はヘルスチェックとサーバーログを確認してください。'}}
document.getElementById('refresh-health').addEventListener('click',loadHealth);loadHealth();''' + ha_script + '''</script></body></html>'''
    encoded = body.encode('utf-8')
    headers = [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'no-store'),
                ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'),
                ('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
                ('Content-Length', str(len(encoded)))]
    return make_response([encoded], '200 OK', headers)


@legacy_compatible(callback_index=1, request_index=0)
def _admin_page(request_context):
    from baas_handlers import _decode_admin_session
    token = _cookie_value(request_context, SESSION_COOKIE)
    claims = _decode_admin_session(token) if token else None
    if not claims:
        return _login_page(request_context)
    query = parse_qs(str(request_context.get('query', '')), keep_blank_values=True)
    if query.get('view', [''])[-1] == 'api-invoices':
        return _invoice_admin_page(request_context, token, claims)
    if query.get('view', [''])[-1] == 'reception':
        return _api_workbench_page(request_context, token, claims)
    if claims.get('oidc_sid'):
        from admin_oidc import session_active
        if not session_active(str(claims['oidc_sid'])):
            return _login_page(request_context, 'SSO IDの認証セッションが失効しました。再ログインしてください。')
    if query.get('view', [''])[-1] == 'help':
        return _admin_help_page(request_context, claims)
    if query.get('view', [''])[-1] == 'operations':
        destination = site_url('/license/python-migration/ops-app/')
        return make_response([b''], '303 See Other', [('Location', destination), ('Cache-Control', 'no-store'), ('Content-Length', '0')])
    csrf = _cookie_value(request_context, CSRF_COOKIE)
    try:
        passkey_recent = 0 <= int(time.time()) - int(claims.get('reauthenticated_at', 0)) <= 120
    except (TypeError, ValueError):
        passkey_recent = False
    contractor_panel = ''
    if claims.get('oidc_sid'):
        if passkey_recent:
            contractor_panel = '<section class="card" id="contractor-sso-create"><h2>契約者向けSSO IDを招待</h2><p class="muted">メールで本人確認し、受信者にパスキーを登録してもらいます。</p><label for="contractor-tenant">Tenant ID</label><select id="contractor-tenant" required></select><label for="contractor-email">契約者のメールアドレス</label><div class="controls"><input id="contractor-email" type="email" maxlength="254" required autocomplete="email" placeholder="name@example.jp"><button id="invite-contractor">登録案内をメールで送信</button></div><p class="muted">招待には管理者SSO IDと直近のPasskey再認証が必要です。</p><p id="contractor-status" role="status"></p></section><section class="card" id="sso-identity-recovery"><h2>SSO IDを忘れた利用者</h2><p class="muted">本人が登録したメールアドレスで照合します。見つかったIDは本人に伝えてください。アカウント削除は、IDを再設定できない場合に限ってください。</p><label for="sso-recovery-email">登録済みメールアドレス</label><div class="controls"><input id="sso-recovery-email" type="email" maxlength="254" autocomplete="email" placeholder="name@example.jp"><button id="lookup-sso-identity">SSO IDを照合</button></div><div id="sso-identity-result" aria-live="polite"></div><label for="confirm-sso-id">削除する場合は、表示されたSSO IDを入力</label><div class="controls"><input id="confirm-sso-id" maxlength="30" autocomplete="off" placeholder="SID-…"><button class="secondary" id="delete-sso-identity">アカウントを削除</button></div><p class="muted">削除には管理者SSO IDと直近2分以内のPasskey再認証が必要です。削除するとパスキー、認証アプリ、復旧情報、セッションを失効し、同じメールアドレスで新規登録できます。管理者アカウントは削除できません。</p><p id="sso-identity-status" role="status"></p></section>'
        else:
            host = str(request_context.get('header:host', '2415.jp')).lower().split(':', 1)[0]
            if host not in {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}:
                host = '2415.jp'
            step_up = site_url('/license/python-migration/admin_api.php?admin_sso_start=1&step_up=1&return_host=') + quote(host, safe='')
            contractor_panel = '<section class="card" id="contractor-sso-create"><h2>契約者向けSSO IDを招待</h2><p>招待を行う前にPasskeyを再認証してください。</p><a class="button" href="' + step_up + '">Passkeyを再認証</a></section><section class="card" id="sso-identity-recovery"><h2>SSO IDを忘れた利用者</h2><p class="muted">本人の登録済みメールアドレスを照合し、見つかったIDを案内できます。利用には直近2分以内のPasskey再認証が必要です。</p><a class="button" href="' + step_up + '">再認証してSSO IDを照合</a></section>'
    effective_role = _effective_admin_role(claims)
    from baas_handlers import _role_allows_scope
    claims_scopes = [scope for scope in ('license:read', 'license:write', 'license:manage', 'phone:manage', 'audit:read', 'admin:manage', 'intake:manage', 'passkey:manage', 'ha:operate', 'ha:promote', 'tenant:read', 'products:write', 'licenses:read', 'licenses:write') if _role_allows_scope(effective_role, scope)]
    audit_clear_control = '<button class="secondary" id="clear-attempts">認証試行履歴を解除</button>' if 'audit:read' in claims_scopes else ''
    admin_management_panel = ''
    if 'admin:manage' in claims_scopes:
        reauth_link = ''
        if not passkey_recent:
            host = str(request_context.get('header:host', '2415.jp')).lower().split(':', 1)[0]
            if host not in {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}:
                host = '2415.jp'
            reauth_link = site_url('<p><a href="/license/python-migration/admin_api.php?admin_sso_start=1&amp;step_up=1&amp;return_host=') + quote(host, safe='') + '">Passkeyを再認証して権限変更・所属解除を有効化</a></p>'
        admin_management_panel = '<section class="card" id="api-invoices-link"><h2>API請求書</h2><p>利用明細の確認・下書き・発行を管理します。</p><a class="button" href="admin_api.php?view=api-invoices">請求書管理を開く</a></section><section class="card" id="admin-principal-management"><h2>管理者権限</h2><p class="muted">自分自身と最後のセキュリティ管理者は変更できません。権限変更にはPasskey再認証が必要です。</p><button class="secondary" id="load-admin-principals">管理者一覧を取得</button><div id="admin-principals"></div><p id="principal-status" role="status"></p></section><section class="card" id="common-id-management"><h2>共通ID・テナント所属</h2><p class="muted">Passkey認証情報は表示せず、テナント所属だけを管理します。解除後も他テナントの所属は維持されます。</p><button class="secondary" id="load-common-id-memberships">所属一覧を取得</button><div id="common-id-memberships"></div><p id="common-id-status" role="status"></p>' + reauth_link + '</section>'
        admin_management_panel += '<section class="card" id="one-time-issuance-grant"><h2>今回1件だけの発行権限</h2><p class="muted">契約に所属するSSO IDを選び、そのIDにライセンス1件だけの発行権限を付与します。直近2分以内のPasskey再認証が必要です。未使用でも24時間で失効します。</p><label for="one-time-tenant">対象契約</label><select id="one-time-tenant" required><option value="">契約を選択してください</option></select><label for="one-time-sso-id">この契約に所属するSSO ID</label><select id="one-time-sso-id" required disabled><option value="">先に契約を選択してください</option></select><p id="one-time-identities-status" class="muted" role="status"></p><button id="grant-one-time" disabled>選択したSSO IDに今回1件の権限を付与</button><p id="one-time-grant-status" role="status"></p>' + ('' if passkey_recent else reauth_link) + '</section>'
    if 'admin:manage' in claims_scopes:
        admin_management_panel += '<section class="card" id="admin-password-change"><h2>緊急用パスワードの変更</h2><p class="muted">Passkey再認証後、現在のパスワードを確認して隔離設定を更新します。</p><label for="current-admin-password">現在のパスワード</label><input id="current-admin-password" type="password" autocomplete="current-password"><label for="new-admin-password">新しいパスワード（12文字以上）</label><input id="new-admin-password" type="password" autocomplete="new-password"><label for="confirm-admin-password">新しいパスワード（確認）</label><input id="confirm-admin-password" type="password" autocomplete="new-password"><button id="change-admin-password" ' + ('' if passkey_recent else 'disabled') + '>パスワードを変更</button><p id="password-status" role="status"></p></section>'
    if 'passkey:manage' in claims_scopes:
        admin_management_panel += '<section class="card" id="error-diagnostics"><h2>エラー診断</h2><label for="diagnostic-error-id">エラーID（8文字）</label><div class="controls"><input id="diagnostic-error-id" maxlength="8" autocomplete="off"><button id="diagnose-error">診断を取得</button></div><pre id="diagnostic-result" role="status"></pre></section>'
    api_workbench_panel = '<section class="card" id="api-workbench-link"><h2>業務API実行</h2><p>契約先ごとに、アプリと同じBaaS APIを確認・実行します。</p><a class="button" href="admin_api.php?view=reception">APIワークベンチを開く</a></section>' if 'intake:manage' in claims_scopes else ''
    phone_step_up = ''
    if not passkey_recent and 'phone:manage' in claims_scopes:
        host = str(request_context.get('header:host', '2415.jp')).lower().split(':', 1)[0]
        if host not in {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}:
            host = '2415.jp'
        phone_step_up = site_url('<p class="muted"><a href="/license/python-migration/admin_api.php?admin_sso_start=1&amp;step_up=1&amp;return_host=') + quote(host, safe='') + '">確認コードの再発行・申請取消にはPasskey再認証が必要です。</a></p>'
    bulk_step_up = phone_step_up.replace('確認コードの再発行・申請取消にはPasskey再認証が必要です。', 'ライセンス一括操作にはPasskey再認証が必要です。')
    section_links = ['<a href="ops-app/"><span>独立運用アプリ</span><small>運用コンソールを開く</small></a>', '<a href="#device-management"><span>端末・セッション</span><small>登録状況と利用状況を確認</small></a>', '<a href="#license-management"><span>ライセンス管理</span><small>検索・一覧・監査ログ</small></a>']
    section_links.append('<a href="admin_api.php?view=help"><span>管理者向けヘルプ</span><small>管理者SSO認証が必要</small></a>')
    if 'license:write' in claims_scopes:
        section_links.append('<a href="#license-issuance"><span>ライセンス発行</span><small>個別・CSV一括発行</small></a>')
    if 'admin:manage' in claims_scopes:
        section_links.extend(['<a href="#tenant-management"><span>テナント管理</span><small>契約先とAPIキー</small></a>', '<a href="#admin-principal-management"><span>管理者設定</span><small>権限とアカウント</small></a>'])
    if claims.get('oidc_sid'):
        section_links.append('<a href="#sso-identity-recovery"><span>SSO ID復旧</span><small>登録メールから照合</small></a>')
    section_links.append('<a href="https://2415.jp/TUTI-Help.html#docs%2FSSO-SCENARIOS.md"><span>使い方ガイド</span><small>手順と困ったときの案内</small></a>')
    quick_nav = '<nav class="quick-nav" aria-label="よく使う操作とヘルプ">' + ''.join(section_links) + '</nav>'
    body = ('<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>TUTI LICENSE 管理センター</title><style>body{margin:0;background:#f1f5f4;color:#17343b;font:15px system-ui,sans-serif}.wrap{max-width:1100px;margin:32px auto;padding:0 18px}.card{background:#fff;border:1px solid #dce8e5;border-radius:16px;padding:20px;margin:14px 0;box-shadow:0 6px 24px #17343b0c}header{display:flex;align-items:center;justify-content:space-between;gap:12px}h1{font-size:24px}label{display:block;font-weight:700;margin:12px 0 6px}input{padding:11px;border:1px solid #b9ceca;border-radius:9px;font:inherit}button{padding:10px 14px;border:0;border-radius:9px;background:#08796d;color:white;font:inherit;font-weight:700;cursor:pointer}button.secondary{background:#526b6b}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:9px;border-bottom:1px solid #e4edeb;overflow-wrap:anywhere}.muted{color:#718589}.error{color:#a62b35}.controls{display:flex;flex-wrap:wrap;gap:8px}#status{min-height:1.5em}</style></head><body><main class="wrap"><header><div><b>TUTI LICENSE · ADMIN CENTER</b><h1>端末・セッション管理</h1><p class="muted">パスキーで認証済み。操作がない状態が30分続くとセッションが終了します。</p></div><button class="secondary" id="logout">ログアウト</button></header><section class="card"><h2>ライセンス端末</h2><p class="muted">ライセンスIDまたはライセンスキーを入力して、登録端末を確認します。</p><label for="license">ライセンスID / キー</label><div class="controls"><input id="license" autocomplete="off" style="flex:1;min-width:260px"><input id="search" placeholder="端末を絞り込む"><button id="load">端末を取得</button><button class="secondary" id="load-sessions">有効セッション</button></div><p id="status" role="status"></p><div id="results"></div></section><section class="card"><h2>ライセンス管理</h2><div class="controls"><button id="load-licenses">有効ライセンス一覧</button><button class="secondary" id="load-deleted">削除済み一覧</button><button class="secondary" id="load-phone">電話申請一覧</button><button class="secondary" id="load-audit">監査ログ</button>' + audit_clear_control + '</div><div id="audit-filters"><label>対象ID・リクエストID<input id="audit-q" type="search"></label><label>操作名<input id="audit-event"></label><label>操作者IDの先頭8桁<input id="audit-actor" maxlength="64"></label><label>開始日<input id="audit-from" type="date"></label><label>終了日<input id="audit-to" type="date"></label><div class="controls"><button class="secondary" id="search-audit">監査ログを検索</button><button class="secondary" id="audit-prev">前へ</button><button class="secondary" id="audit-next">次へ</button><span id="audit-page"></span></div></div>' + phone_step_up + '<div id="license-results"></div><div id="bulk-controls" hidden><label>一括操作<select id="bulk-operation"></select></label><label id="bulk-prefix-wrap">ラベル先頭文字<input id="bulk-prefix" maxlength="60"></label><button id="run-bulk-action" disabled>選択分に実行</button>' + bulk_step_up + '</div><p id="license-status" role="status"></p></section><section class="card"><h2>ライセンス発行</h2><div class="controls"><input id="new-tenant" type="number" min="1" value="1" aria-label="テナントID"><input id="new-product" type="number" min="1" value="1" aria-label="製品ID"><input id="new-label" placeholder="ラベル"><select id="new-mode"><option value="single">単一端末</option><option value="volume">複数端末</option><option value="evaluation">評価版</option></select><input id="new-devices" type="number" min="2" max="500" value="10" aria-label="最大端末数"><button id="create-license">発行</button></div><p id="issued-key" role="status"></p><label for="license-csv">CSV一括発行（label,license_mode,max_devices,evaluation_days,expires_at）</label><textarea id="license-csv" rows="5" style="width:100%;box-sizing:border-box" placeholder="label,license_mode,max_devices,evaluation_days,expires_at\nExample,single,1,,"></textarea><button id="import-licenses">CSVから発行</button><p id="csv-status" role="status"></p></section><section class="card"><h2>テナント管理</h2><div class="controls"><input id="tenant-slug" placeholder="slug (example-company)"><input id="tenant-name" placeholder="テナント名"><select id="tenant-plan"><option>standard</option><option>trial</option><option>business</option><option>enterprise</option></select><button id="create-tenant">作成</button><button class="secondary" id="load-tenants">契約先一覧</button><button class="secondary" id="load-tenant-keys">APIクライアント一覧</button></div><div id="tenants"></div><div class="controls"><button class="secondary" id="tenant-prev">契約先 前へ</button><span id="tenant-page"></span><button class="secondary" id="tenant-next">契約先 次へ</button></div><div id="tenant-keys"></div><div class="controls"><button class="secondary" id="key-prev">APIキー 前へ</button><span id="key-page"></span><button class="secondary" id="key-next">APIキー 次へ</button></div><h3>テナントAPIキーを発行</h3><div class="controls"><input id="api-key-tenant" type="number" min="1" placeholder="テナントID"><input id="api-key-name" maxlength="120" placeholder="クライアント名"><input id="api-key-scopes" value="tenant:read,licenses:read" aria-label="権限スコープ"><input id="api-key-rate" type="number" min="10" max="10000" value="120" aria-label="毎分リクエスト上限"><input id="api-key-expiry" type="datetime-local" aria-label="有効期限UTC"><button id="issue-tenant-key">APIキー発行</button></div><p class="muted">発行した秘密鍵はこの画面で一度だけ表示します。スコープはカンマ区切りで指定します。</p><pre id="tenant-key-secret" role="status"></pre><p id="tenant-status" role="status"></p></section>' + api_workbench_panel + admin_management_panel + contractor_panel + '</main><script>const csrf=' + json.dumps(csrf) + ';const passkeyRecent=' + ('true' if passkey_recent else 'false') + ";const byId=id=>document.getElementById(id);const status=byId('status');const results=byId('results');let cached=[],auditPage=1,auditHasNext=false,tenantPage=1,tenantHasNext=false,keyPage=1,keyHasNext=false;function input(){const value=byId('license').value.trim();return /^[0-9]+$/.test(value)?{license_id:Number(value)}:{license_key:value};}async function api(action,extra={}){const response=await fetch('admin_api.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({action,...input(),...extra})});const data=await response.json();if(!response.ok||!data.success)throw new Error(data.message||data.error||'操作に失敗しました');return data;}function table(rows,sessions){const cols=sessions?['device_display_label','device_ref','first_activated_at','last_seen_at','refresh_expires_at']:['device_display_label','device_ref','first_activated_at','last_seen_at','revoked_at'];if(!rows.length){results.textContent='対象の記録はありません。';return;}const t=document.createElement('table'),h=document.createElement('thead'),hr=document.createElement('tr');for(const c of cols){const th=document.createElement('th');th.textContent=c;hr.append(th);}const op=document.createElement('th');op.textContent='操作';hr.append(op);h.append(hr);t.append(h);const b=document.createElement('tbody');for(const row of rows){const tr=document.createElement('tr');for(const c of cols){const td=document.createElement('td');td.textContent=row[c]??'—';tr.append(td);}const td=document.createElement('td');if(!sessions){const btn=document.createElement('button');btn.className='secondary';btn.textContent=row.revoked_at?'失効解除':'失効';btn.addEventListener('click',async()=>{try{await api(row.revoked_at?'unrevoke_device':'revoke_device',{device_id:row.id});await load(false);status.textContent='端末の状態を更新しました。';}catch(e){status.textContent=e.message;status.className='error';}});td.append(btn);}tr.append(td);b.append(tr);}t.append(b);results.replaceChildren(t);}async function load(sessions=false){status.className='';status.textContent='取得しています…';try{const data=await api(sessions?'list_sessions':'list_devices',{q:byId('search').value});cached=sessions?data.sessions:data.devices;table(cached,sessions);status.textContent=data.message;}catch(e){results.replaceChildren();status.className='error';status.textContent=e.message;}}let currentAdminAction='list_licenses';function resultTable(rows,cols,target){const box=byId(target);box.replaceChildren();if(!rows.length){box.textContent='対象の記録はありません。';return;}const t=document.createElement('table'),h=document.createElement('tr');for(const c of cols){const th=document.createElement('th');th.textContent=c;h.append(th);}const hasLicenseActions=target==='license-results'&&rows[0]&&('license_mode'in rows[0]);if(hasLicenseActions){const th=document.createElement('th');th.textContent='操作';h.append(th);}t.append(h);for(const row of rows){const tr=document.createElement('tr');for(const c of cols){const td=document.createElement('td');td.textContent=row[c]??'—';tr.append(td);}if(hasLicenseActions){const td=document.createElement('td'),button=document.createElement('button');button.textContent=currentAdminAction==='list_deleted_licenses'?'復元':(row.active?'一時停止':'再開');button.addEventListener('click',async()=>{try{const operation=currentAdminAction==='list_deleted_licenses'?'restore_license':(row.active?'pause_license':'resume_license');await api(operation,{license_id:row.id});await adminList(currentAdminAction);}catch(e){byId('license-status').textContent=e.message;byId('license-status').className='error';}});td.append(button);if(currentAdminAction!=='list_deleted_licenses'){const del=document.createElement('button');del.className='secondary';del.textContent='削除';del.addEventListener('click',async()=>{if(!confirm('このライセンスを論理削除しますか？'))return;try{await api('delete_license',{license_id:row.id});await adminList(currentAdminAction);}catch(e){byId('license-status').textContent=e.message;byId('license-status').className='error';}});td.append(del);}tr.append(td);}t.append(tr);}box.append(t);}\nfunction auditTable(rows){const box=byId('license-results');box.replaceChildren();if(!rows.length){box.textContent='対象の記録はありません。';return;}const table=document.createElement('table'),head=document.createElement('tr');for(const name of ['日時','操作者・役割','操作・対象','変更前後']){const th=document.createElement('th');th.textContent=name;head.append(th);}table.append(head);const body=document.createElement('tbody');for(const item of rows){const tr=document.createElement('tr');for(const value of [item.created_at,(String(item.actor_hash||'legacy log').slice(0,12)+' · '+(item.role_name||'')+' · '+(item.node_role||'')),(item.event_type||'')+' · '+(item.target_type||'')+' #'+(item.target_id||'')+' · '+(item.request_id||'')]){const td=document.createElement('td');td.textContent=value||'—';tr.append(td);}const td=document.createElement('td'),details=document.createElement('details'),summary=document.createElement('summary'),pre=document.createElement('pre');summary.textContent='差分を見る';pre.textContent=JSON.stringify({before:item.before??null,after:item.after??null},null,2);details.append(summary,pre);td.append(details);tr.append(td);body.append(tr);}table.append(body);box.append(table);}\nfunction updateBulkButton(){const button=byId('run-bulk-action'),count=byId('license-results').querySelectorAll('.license-pick:checked').length;button.disabled=!passkeyRecent||count<1||count>100;}function prepareBulk(action){const control=byId('bulk-controls'),select=byId('bulk-operation'),deleted=action==='list_deleted_licenses',isList=['list_licenses','list_deleted_licenses','list_volume_licenses'].includes(action);control.hidden=!isList;if(!isList)return;select.replaceChildren();const options=deleted?[['restore','停止状態で復元']]:[['pause','一時停止'],['resume','再開'],['delete','論理削除'],['label_prefix','ラベル先頭に追加']];for(const [value,label] of options){const option=document.createElement('option');option.value=value;option.textContent=label;select.append(option);}byId('bulk-prefix-wrap').hidden=deleted||select.value!=='label_prefix';select.onchange=()=>{byId('bulk-prefix-wrap').hidden=deleted||select.value!=='label_prefix';};updateBulkButton();}async function adminList(action){currentAdminAction=action;prepareBulk(action);const s=byId('license-status'),box=byId('license-results');s.className='';s.textContent='取得しています…';try{const params={page:action==='list_audit_logs'?auditPage:1,limit:25};if(action==='list_audit_logs')Object.assign(params,{q:byId('audit-q').value,event_type:byId('audit-event').value,actor:byId('audit-actor').value,from:byId('audit-from').value,to:byId('audit-to').value});const d=await api(action,params);const rows=d.licenses||d.requests||d.logs||[];if(action==='list_audit_logs'){auditPage=d.page||auditPage;auditHasNext=Boolean(d.has_next);byId('audit-page').textContent=auditPage+' ページ';byId('audit-prev').disabled=auditPage<=1;byId('audit-next').disabled=!auditHasNext;auditTable(rows);}else if(action==='list_phone_requests'){box.replaceChildren();if(!rows.length){box.textContent='対象の記録はありません。';}else{const t=document.createElement('table'),h=document.createElement('tr');for(const c of ['id','installation_id','device_label','status','requested_at','操作']){const th=document.createElement('th');th.textContent=c;h.append(th);}t.append(h);const b=document.createElement('tbody');for(const r of rows){const tr=document.createElement('tr');for(const v of [r.id,r.installation_id,r.device_label,r.status,r.requested_at]){const td=document.createElement('td');td.textContent=v??'—';tr.append(td);}const td=document.createElement('td');for(const [label,op] of [['確認コードを発行/再送','issue_phone_confirmation_code'],['申請を取消','cancel_phone_request']]){const button=document.createElement('button');button.className='secondary';button.textContent=label;button.disabled=!passkeyRecent||Boolean(r.confirmed_at)||r.status==='cancelled';button.addEventListener('click',async()=>{if(op==='cancel_phone_request'&&!confirm('この電話認証申請を取り消しますか？'))return;try{const result=await api(op,{installation_id:r.installation_id});s.className='';await adminList('list_phone_requests');s.textContent=result.confirmation_code?'確認コード: '+result.confirmation_code:(result.message||label+'しました。');}catch(e){s.className='error';s.textContent=e.message;}});td.append(button);}tr.append(td);b.append(tr);}t.append(b);box.append(t);}}else if(action.startsWith('list_')){box.replaceChildren();if(!rows.length){box.textContent='対象の記録はありません。';}else{const t=document.createElement('table'),h=document.createElement('tr'),selectHead=document.createElement('th'),selectAll=document.createElement('input');selectAll.type='checkbox';selectAll.id='select-all-licenses';selectHead.append(selectAll);h.append(selectHead);for(const c of ['id','label','active','license_mode','max_devices','active_sessions','expires_at','操作']){const th=document.createElement('th');th.textContent=c;h.append(th);}t.append(h);const b=document.createElement('tbody');for(const r of rows){const tr=document.createElement('tr'),pickCell=document.createElement('td'),pick=document.createElement('input');pick.type='checkbox';pick.className='license-pick';pick.value=r.id;pickCell.append(pick);tr.append(pickCell);for(const v of [r.id,r.label,r.active?'有効':'停止',r.license_mode,r.max_devices,r.active_sessions,r.expires_at]){const td=document.createElement('td');td.textContent=v??'—';tr.append(td);}const td=document.createElement('td');const ops=action==='list_deleted_licenses'?[['復元','restore_license',false],['完全削除','permanently_delete_license',true]]:[[r.active?'停止':'再開',r.active?'pause_license':'resume_license',false],['端末を再認証','force_reauth_license',true],['365日延長','renew_license',true],['削除','delete_license',true]];for(const [label,op,step] of ops){const button=document.createElement('button');button.className='secondary';button.textContent=label;button.disabled=step&&!passkeyRecent;button.addEventListener('click',async()=>{if(!confirm('ライセンス #'+r.id+' に「'+label+'」を実行しますか？'))return;try{const extra={id:Number(r.id)};if(op==='permanently_delete_license')extra.confirm_id=Number(r.id);if(op==='renew_license')extra.renew_days=365;await api(op,extra);await adminList(action);s.textContent='ライセンス #'+r.id+' を更新しました。';}catch(e){s.className='error';s.textContent=e.message;}});td.append(button);}tr.append(td);b.append(tr);}t.append(b);box.append(t);selectAll.addEventListener('change',()=>{box.querySelectorAll('.license-pick').forEach(x=>x.checked=selectAll.checked);updateBulkButton();});box.querySelectorAll('.license-pick').forEach(x=>x.addEventListener('change',updateBulkButton));}}else{resultTable(rows,['event_type','target_type','target_id','created_at'],'license-results');}s.textContent=d.message||'取得しました。';updateBulkButton();}catch(e){s.className='error';s.textContent=e.message;}}\nbyId('load-licenses').addEventListener('click',()=>adminList('list_licenses'));byId('load-deleted').addEventListener('click',()=>adminList('list_deleted_licenses'));byId('load-phone').addEventListener('click',()=>adminList('list_phone_requests'));byId('load-audit').addEventListener('click',()=>adminList('list_audit_logs'));byId('search-audit').addEventListener('click',()=>{auditPage=1;adminList('list_audit_logs');});byId('audit-prev').addEventListener('click',()=>{if(auditPage>1){auditPage--;adminList('list_audit_logs');}});byId('audit-next').addEventListener('click',()=>{if(auditHasNext){auditPage++;adminList('list_audit_logs');}});if(byId('clear-attempts'))byId('clear-attempts').addEventListener('click',async()=>{if(!confirm('認証試行履歴をすべて解除しますか？'))return;const out=byId('license-status');try{const result=await api('clear_attempts');out.className='';out.textContent=result.message||'認証試行履歴を解除しました。';}catch(e){out.className='error';out.textContent=e.message;}});byId('run-bulk-action').addEventListener('click',async()=>{const out=byId('license-status'),ids=[...byId('license-results').querySelectorAll('.license-pick:checked')].map(x=>x.value),operation=byId('bulk-operation').value;if(ids.length<1||ids.length>100)return;if(!confirm('選択した '+ids.length+' 件に一括操作「'+operation+'」を実行しますか？'))return;try{const result=await api('bulk_license_action',{operation,license_ids:ids.join(','),deleted_view:currentAdminAction==='list_deleted_licenses',label_prefix:byId('bulk-prefix').value});out.className='';out.textContent=result.message||'一括処理が完了しました。';await adminList(currentAdminAction);}catch(e){out.className='error';out.textContent=e.message;}});\nbyId('create-license').addEventListener('click',async()=>{const out=byId('issued-key');out.className='';out.textContent='発行しています…';try{const d=await api('create_license',{tenant_id:Number(byId('new-tenant').value),product_id:Number(byId('new-product').value),label:byId('new-label').value,license_mode:byId('new-mode').value,max_devices:Number(byId('new-devices').value)});out.textContent='発行キー（この画面でのみ表示）: '+d.product_key+' / ID '+d.license_id;}catch(e){out.className='error';out.textContent=e.message;}});\nbyId('import-licenses').addEventListener('click',async()=>{const out=byId('csv-status');out.className='';try{const d=await api('import_licenses_csv',{tenant_id:Number(byId('new-tenant').value),product_id:Number(byId('new-product').value),csv_rows:byId('license-csv').value});out.textContent=d.message+' '+(d.licenses||[]).map(x=>'#'+x.id+' '+x.label+' '+x.product_key).join(' / ');}catch(e){out.className='error';out.textContent=e.message;}});\nbyId('create-tenant').addEventListener('click',async()=>{const out=byId('tenant-status');out.className='';try{const d=await api('create_tenant',{tenant_slug:byId('tenant-slug').value,tenant_name:byId('tenant-name').value,plan_code:byId('tenant-plan').value});out.textContent=d.message+' ID '+d.tenant_id+' / 製品ID '+d.product_id;}catch(e){out.className='error';out.textContent=e.message;}});\nfunction tenantTable(rows){const box=byId('tenants');box.replaceChildren();if(!rows.length){box.textContent='テナントがありません。';return;}const t=document.createElement('table'),h=document.createElement('tr');for(const c of ['id','name','slug','status','environment','plan_code','max_products','max_licenses','APIキー対象']){const th=document.createElement('th');th.textContent=c;h.append(th);}t.append(h);const b=document.createElement('tbody');for(const r of rows){const tr=document.createElement('tr');for(const c of ['id','name','slug','status','environment','plan_code','max_products','max_licenses'])addCell(tr,r[c]);const td=addCell(tr,'');const button=document.createElement('button');button.className='secondary';button.textContent='APIキー対象にする';button.disabled=r.status!=='active';button.addEventListener('click',()=>{byId('api-key-tenant').value=r.id;byId('tenant-status').textContent='テナント '+r.name+' (#'+r.id+') をAPIキー対象に設定しました。';});td.append(button);b.append(tr);}t.append(b);box.append(t);}byId('load-tenants').addEventListener('click',async()=>{const out=byId('tenant-status');out.className='';try{const d=await api('list_tenants',{page:tenantPage,limit:100});tenantTable(d.tenants||[]);tenantPage=d.page||tenantPage;tenantHasNext=Boolean(d.has_next);byId('tenant-page').textContent=tenantPage+' ページ';byId('tenant-prev').disabled=tenantPage<=1;byId('tenant-next').disabled=!tenantHasNext;out.textContent='契約先 '+(d.tenants||[]).length+' 件';}catch(e){out.className='error';out.textContent=e.message;}});byId('tenant-prev').addEventListener('click',()=>{if(tenantPage>1){tenantPage--;byId('load-tenants').click();}});byId('tenant-next').addEventListener('click',()=>{if(tenantHasNext){tenantPage++;byId('load-tenants').click();}});\nfunction tenantApiKeyTable(rows){const box=byId('tenant-keys');box.replaceChildren();if(!rows.length){box.textContent='APIクライアントはありません。';return;}const t=document.createElement('table'),h=document.createElement('tr');for(const c of ['id','tenant_name','tenant_slug','name','key_prefix','status','scopes_json','last_used_at','expires_at','rate_limit_per_minute','操作']){const th=document.createElement('th');th.textContent=c;h.append(th);}t.append(h);const b=document.createElement('tbody');for(const r of rows){const tr=document.createElement('tr');for(const c of ['id','tenant_name','tenant_slug','name','key_prefix','status','scopes_json','last_used_at','expires_at','rate_limit_per_minute'])addCell(tr,r[c]);const td=addCell(tr,'');for(const [label,action] of [['ローテーション','rotate_tenant_api_key'],['即時失効','revoke_tenant_api_key']]){const button=document.createElement('button');button.className='secondary';button.textContent=label;const expired=r.expires_at&&new Date(String(r.expires_at).replace(' ','T')+'Z')<=new Date();button.disabled=!passkeyRecent||expired||(action==='rotate_tenant_api_key'?r.status!=='active':!['active','retiring'].includes(r.status));button.addEventListener('click',async()=>{if(!confirm('APIクライアント #'+r.id+' を'+label+'しますか？'))return;try{const result=await api(action,{client_id:Number(r.id),grace_minutes:60});const secret=byId('tenant-key-secret');secret.textContent=result.key?'新しいAPIキー（この画面で一度だけ表示）: '+result.key:(result.message||'APIキーを失効しました。');await byId('load-tenant-keys').click();}catch(e){byId('tenant-status').className='error';byId('tenant-status').textContent=e.message;}});td.append(button);}b.append(tr);}t.append(b);box.append(t);}byId('load-tenant-keys').addEventListener('click',async()=>{const out=byId('tenant-status');out.className='';try{const d=await api('list_tenant_api_keys',{page:keyPage,limit:100});tenantApiKeyTable(d.api_clients||[]);keyPage=d.page||keyPage;keyHasNext=Boolean(d.has_next);byId('key-page').textContent=keyPage+' ページ';byId('key-prev').disabled=keyPage<=1;byId('key-next').disabled=!keyHasNext;out.textContent='テナント '+(d.tenants||[]).length+' 件、APIクライアント '+(d.api_clients||[]).length+' 件';}catch(e){out.className='error';out.textContent=e.message;}});byId('key-prev').addEventListener('click',()=>{if(keyPage>1){keyPage--;byId('load-tenant-keys').click();}});byId('key-next').addEventListener('click',()=>{if(keyHasNext){keyPage++;byId('load-tenant-keys').click();}});byId('issue-tenant-key').addEventListener('click',async()=>{const out=byId('tenant-status'),secret=byId('tenant-key-secret');out.className='';secret.textContent='';try{const d=await api('issue_tenant_api_key',{tenant_id:Number(byId('api-key-tenant').value),client_name:byId('api-key-name').value,scopes:byId('api-key-scopes').value,rate_limit_per_minute:Number(byId('api-key-rate').value),api_key_expires_at:byId('api-key-expiry').value});secret.textContent='新しいAPIキー（この画面で一度だけ表示）: '+d.key;out.textContent=d.message||'APIキーを発行しました。';await byId('load-tenant-keys').click();}catch(e){out.className='error';out.textContent=e.message;}});\nfunction addCell(row,value){const cell=document.createElement('td');cell.textContent=value??'—';row.append(cell);return cell;}if(byId('load-admin-principals'))byId('load-admin-principals').addEventListener('click',async()=>{const out=byId('principal-status'),box=byId('admin-principals');out.className='';try{const d=await api('list_admin_principals');const table=document.createElement('table'),body=document.createElement('tbody');for(const p of d.admin_principals||[]){const tr=document.createElement('tr');addCell(tr,(p.display_name||'管理者')+' · #'+p.id);addCell(tr,p.last_login_at||'記録なし');const controls=addCell(tr,'');const select=document.createElement('select');for(const [value,label] of [['viewer','閲覧のみ'],['operator','運用担当'],['security-admin','セキュリティ管理者'],['ha-admin','HA管理者']]){const option=document.createElement('option');option.value=value;option.textContent=label;option.selected=p.role_name===value;select.append(option);}select.disabled=!passkeyRecent;const button=document.createElement('button');button.className='secondary';button.textContent='権限変更';button.disabled=!passkeyRecent;button.addEventListener('click',async()=>{if(select.value===p.role_name)return;try{await api('set_admin_role',{principal_id:p.id,role_name:select.value});out.textContent='管理者権限を更新しました。';byId('load-admin-principals').click();}catch(e){out.className='error';out.textContent=e.message;}});controls.append(select,button);body.append(tr);}table.append(body);box.replaceChildren(table);out.textContent=(d.admin_principals||[]).length+'人の管理者を表示しています。';}catch(e){out.className='error';out.textContent=e.message;}});if(byId('load-common-id-memberships'))byId('load-common-id-memberships').addEventListener('click',async()=>{const out=byId('common-id-status'),box=byId('common-id-memberships');out.className='';try{const d=await api('list_common_id_memberships');const table=document.createElement('table'),body=document.createElement('tbody');for(const m of d.memberships||[]){const tr=document.createElement('tr');addCell(tr,'SSO ID · '+String(m.subject_hash).slice(0,12));addCell(tr,(m.tenant_name||'テナント')+' · '+(m.tenant_slug||'')+' · #'+m.tenant_id);addCell(tr,m.tenant_status);const controls=addCell(tr,'');const button=document.createElement('button');button.className='secondary';button.textContent='このテナントから解除';button.disabled=!passkeyRecent;button.addEventListener('click',async()=>{if(!confirm('このSSO IDとテナントの所属を解除し、このテナントのセッションを無効にしますか？'))return;try{await api('revoke_common_id_membership',{subject_hash:m.subject_hash,tenant_id:m.tenant_id});out.textContent='共通IDの所属を解除しました。';byId('load-common-id-memberships').click();}catch(e){out.className='error';out.textContent=e.message;}});controls.append(button);body.append(tr);}table.append(body);box.replaceChildren(table);out.textContent=(d.identity_total||0)+'個の有効ID · '+(d.membership_total||0)+'件の所属'+(d.has_more?'（最新200件）':'');}catch(e){out.className='error';out.textContent=e.message;}});if(byId('change-admin-password'))byId('change-admin-password').addEventListener('click',async()=>{const out=byId('password-status');out.className='';try{const d=await api('change_admin_password',{current_password:byId('current-admin-password').value,new_password:byId('new-admin-password').value,new_password_confirm:byId('confirm-admin-password').value});out.textContent=d.message||'パスワードを変更しました。';byId('current-admin-password').value='';byId('new-admin-password').value='';byId('confirm-admin-password').value='';}catch(e){out.className='error';out.textContent=e.message;}});if(byId('diagnose-error'))byId('diagnose-error').addEventListener('click',async()=>{const out=byId('diagnostic-result');out.textContent='';try{const d=await api('diagnose_error',{error_id:byId('diagnostic-error-id').value.trim()});out.textContent=JSON.stringify(d.diagnostic,null,2);}catch(e){out.textContent=e.message;}});if(byId(\'contractor-tenant\')){try{const d=await api(\'list_tenants\',{page:1,limit:100});const select=byId(\'contractor-tenant\');for(const t of d.tenants||[]){if(t.status!==\'active\')continue;const o=document.createElement(\'option\');o.value=t.id;o.textContent=(t.name||t.slug)+\' ? tenant ID \'+t.id;select.append(o)}if(!select.options.length){const o=document.createElement(\'option\');o.value=\'\';o.textContent=\'No active tenant\';select.append(o)}}catch(e){byId(\'contractor-status\').textContent=e.message}};if(byId('invite-contractor'))byId('invite-contractor').addEventListener('click',async()=>{const out=byId('contractor-status');out.className='';try{const response=await fetch('admin_api.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({action:'create_contractor_sso',contractor_email:byId('contractor-email').value,tenant_id:Number(byId(\'contractor-tenant\').value)})});const data=await response.json();if(!response.ok||!data.success)throw new Error(data.message||'招待メールを送信できませんでした。');out.textContent=data.message;}catch(e){out.className='error';out.textContent=e.message;}});\nif(byId('lookup-sso-identity'))byId('lookup-sso-identity').addEventListener('click',async()=>{const out=byId('sso-identity-status'),box=byId('sso-identity-result');out.className='';out.textContent='照合しています…';box.replaceChildren();try{const response=await fetch('admin_api.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({action:'lookup_sso_identity',identity_email:byId('sso-recovery-email').value})});const d=await response.json();if(!response.ok||!d.success)throw new Error(d.message||'照合できませんでした。');if(!d.identity){box.textContent='登録済みメールアドレスと一致する有効なIDはありません。';out.textContent=d.message;return}const row=document.createElement('p');row.textContent='SSO ID: '+d.identity.public_id+(d.identity.display_name?' · '+d.identity.display_name:'');box.replaceChildren(row);byId('confirm-sso-id').value='';out.textContent=d.message;}catch(e){out.className='error';out.textContent=e.message;}});if(byId('delete-sso-identity'))byId('delete-sso-identity').addEventListener('click',async()=>{const out=byId('sso-identity-status'),email=byId('sso-recovery-email').value.trim(),id=byId('confirm-sso-id').value.trim().toUpperCase();if(!id||!confirm('SSO ID '+id+' のアカウントと認証情報を削除し、セッションを失効しますか？'))return;out.className='';out.textContent='削除しています…';try{const response=await fetch('admin_api.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({action:'delete_sso_identity',identity_email:email,public_id:id,confirm_public_id:id})});const d=await response.json();if(!response.ok||!d.success)throw new Error(d.message||'削除できませんでした。');byId('sso-identity-result').textContent='';byId('confirm-sso-id').value='';out.textContent=d.message;}catch(e){out.className='error';out.textContent=e.message;}});byId('load').addEventListener('click',()=>load(false));byId('load-sessions').addEventListener('click',()=>load(true));byId('logout').addEventListener('click',async()=>{try{await api('logout');location.reload();}catch(e){status.textContent=e.message;status.className='error';}});</script></body></html>").encode()
    body = body.replace(b'</style>', ADMIN_UI_CSS.encode('utf-8') + b'</style>', 1)
    body = body.replace('<h1>端末・セッション管理</h1><p class="muted">パスキーで認証済み。操作がない状態が30分続くとセッションが終了します。</p>'.encode('utf-8'), '<h1>管理センター</h1><p class="muted">端末・ライセンス・テナントを管理します。操作がない状態が30分続くとセッションが終了します。</p>'.encode('utf-8'), 1)
    body = body.replace(b'<h2>\xe3\x83\x86\xe3\x83\x8a\xe3\x83\xb3\xe3\x83\x88\xe7\xae\xa1\xe7\x90\x86</h2><div class="controls">', b'<h2>\xe3\x83\x86\xe3\x83\x8a\xe3\x83\xb3\xe3\x83\x88\xe7\xae\xa1\xe7\x90\x86</h2><p class="muted section-intro">\xe5\xa5\x91\xe7\xb4\x84\xe5\x85\x88\xe3\x82\x92\xe4\xbd\x9c\xe6\x88\x90\xe3\x81\x97\xe3\x81\x9f\xe5\xbe\x8c\xe3\x80\x81\xe5\xbf\x85\xe8\xa6\x81\xe3\x81\xab\xe5\xbf\x9c\xe3\x81\x98\xe3\x81\xa6API\xe3\x82\xaf\xe3\x83\xa9\xe3\x82\xa4\xe3\x82\xa2\xe3\x83\xb3\xe3\x83\x88\xe3\x81\xa8\xe6\xa8\xa9\xe9\x99\x90\xe3\x82\x92\xe8\xa8\xad\xe5\xae\x9a\xe3\x81\x97\xe3\x81\xbe\xe3\x81\x99\xe3\x80\x82</p><div class="controls">', 1)
    body = body.replace(b'<h2>\xe3\x83\xa9\xe3\x82\xa4\xe3\x82\xbb\xe3\x83\xb3\xe3\x82\xb9\xe7\x99\xba\xe8\xa1\x8c</h2><div class="controls">', b'<h2>\xe3\x83\xa9\xe3\x82\xa4\xe3\x82\xbb\xe3\x83\xb3\xe3\x82\xb9\xe7\x99\xba\xe8\xa1\x8c</h2><p class="muted section-intro">\xe7\x99\xba\xe8\xa1\x8c\xe5\x85\x88\xe3\x81\xa8\xe3\x83\xa9\xe3\x82\xa4\xe3\x82\xbb\xe3\x83\xb3\xe3\x82\xb9\xe7\xa8\xae\xe5\x88\xa5\xe3\x82\x92\xe9\x81\xb8\xe3\x81\xb3\xe3\x81\xbe\xe3\x81\x99\xe3\x80\x82CSV\xe4\xb8\x80\xe6\x8b\xac\xe7\x99\xba\xe8\xa1\x8c\xe3\x81\xa7\xe3\x81\xaf\xe3\x80\x81\xe5\xae\x9f\xe8\xa1\x8c\xe5\x89\x8d\xe3\x81\xab\xe8\xa1\x8c\xe3\x81\xae\xe5\x86\x85\xe5\xae\xb9\xe3\x82\x92\xe7\xa2\xba\xe8\xaa\x8d\xe3\x81\x97\xe3\x81\xa6\xe3\x81\x8f\xe3\x81\xa0\xe3\x81\x95\xe3\x81\x84\xe3\x80\x82</p><div class="controls">', 1)
    body = body.replace(b'<h2>\xe3\x83\xa9\xe3\x82\xa4\xe3\x82\xbb\xe3\x83\xb3\xe3\x82\xb9\xe7\xae\xa1\xe7\x90\x86</h2><div class="controls">', b'<h2>\xe3\x83\xa9\xe3\x82\xa4\xe3\x82\xbb\xe3\x83\xb3\xe3\x82\xb9\xe7\xae\xa1\xe7\x90\x86</h2><p class="muted section-intro">\xe4\xb8\x80\xe8\xa6\xa7\xe3\x82\x92\xe9\x81\xb8\xe3\x81\xb6\xe3\x81\xa8\xe5\xaf\xbe\xe8\xb1\xa1\xe3\x81\x8c\xe8\xa1\xa8\xe7\xa4\xba\xe3\x81\x95\xe3\x82\x8c\xe3\x81\xbe\xe3\x81\x99\xe3\x80\x82\xe5\xa4\x89\xe6\x9b\xb4\xe5\x89\x8d\xe3\x81\xab\xe5\xaf\xbe\xe8\xb1\xa1\xe3\x81\xa8\xe7\x8a\xb6\xe6\x85\x8b\xe3\x82\x92\xe7\xa2\xba\xe8\xaa\x8d\xe3\x81\x97\xe3\x81\xa6\xe3\x81\x8f\xe3\x81\xa0\xe3\x81\x95\xe3\x81\x84\xe3\x80\x82</p><div class="controls">', 1)
    body = body.replace(b'<body><main class="wrap">', '<body><a class="skip-link" href="#main-content">本文へ移動</a><main id="main-content" class="wrap">'.encode('utf-8'), 1)
    for control_id, label_text in [('search', '端末一覧の絞り込み'), ('new-label', 'ライセンスの表示ラベル'), ('new-mode', 'ライセンス種別'), ('tenant-slug', 'テナント識別子'), ('tenant-name', 'テナント名'), ('tenant-plan', 'テナントの契約プラン')]:
        marker = ('id="' + control_id + '"').encode('ascii')
        body = body.replace(marker, marker + (' aria-label="' + label_text + '"').encode('utf-8'), 1)

    body = body.replace('<section class="card"><h2>ライセンス端末'.encode('utf-8'), '<section class="card" id="device-management"><h2>ライセンス端末'.encode('utf-8'), 1)
    body = body.replace('<section class="card"><h2>ライセンス管理'.encode('utf-8'), '<section class="card" id="license-management"><h2>ライセンス管理'.encode('utf-8'), 1)
    body = body.replace('<section class="card"><h2>ライセンス発行'.encode('utf-8'), '<section class="card" id="license-issuance"><h2>ライセンス発行'.encode('utf-8'), 1)
    body = body.replace('<section class="card"><h2>テナント管理'.encode('utf-8'), '<section class="card" id="tenant-management"><h2>テナント管理'.encode('utf-8'), 1)
    body = body.replace(b'</header>', ('</header>' + quick_nav).encode('utf-8'), 1)
    body = body.replace(b'const passkeyRecent=' + (b'true' if passkey_recent else b'false') + b';const byId=', b'const passkeyRecent=' + (b'true' if passkey_recent else b'false') + b';const canLicenseWrite=' + (b'true' if 'license:write' in claims_scopes else b'false') + b';const canAdminManage=' + (b'true' if 'admin:manage' in claims_scopes else b'false') + b';const canPhoneManage=' + (b'true' if 'phone:manage' in claims_scopes else b'false') + b';const byId=', 1)
    body = body.replace(b'button.disabled=step&&!passkeyRecent;', b'button.disabled=step&&(!passkeyRecent||!canLicenseWrite);', 1)
    body = body.replace("button.textContent=currentAdminAction==='list_deleted_licenses'?'復元':(row.active?'一時停止':'再開');button.addEventListener".encode(), "button.textContent=currentAdminAction==='list_deleted_licenses'?'復元':(row.active?'一時停止':'再開');button.disabled=!canLicenseWrite;button.addEventListener".encode(), 1)
    body = body.replace("del.textContent='削除';del.addEventListener".encode(), "del.textContent='削除';del.disabled=!canLicenseWrite;del.addEventListener".encode(), 1)
    body = body.replace(b'button.disabled=!passkeyRecent||count<1||count>100;', b'button.disabled=!passkeyRecent||!canLicenseWrite||count<1||count>100;', 1)
    body = body.replace(b'button.disabled=!passkeyRecent||Boolean(r.confirmed_at)', b'button.disabled=!passkeyRecent||!canPhoneManage||Boolean(r.confirmed_at)', 1)
    body = body.replace(b"button.disabled=r.status!=='active';", b"button.disabled=!canAdminManage||r.status!=='active';", 1)
    body = body.replace(b'button.disabled=!passkeyRecent||expired||', b'button.disabled=!canAdminManage||!passkeyRecent||expired||', 1)
    notice = 'パスキーの他サイト同期に失敗しました。ネットワークを確認して、別サイトから再ログインしてください。' if query.get('federation_pending', [''])[-1] else '招待メールを送信しました。受信者がメール確認とパスキー登録を終えるとSSO IDが有効になります。' if query.get('contractor_sso_invited', [''])[-1] else 'テナントと既定製品を作成し、HA同期を要求しました。' if query.get('tenant_created', [''])[-1] else '管理ツールへログインしました。'
    if notice:
        notice_html = '<p class="muted" role="status">' + html.escape(notice) + '</p>'
        body = body.replace(b'</header>', ('</header>' + notice_html).encode(), 1)
    if 'admin:manage' not in claims_scopes:
        body = body.replace('<section class="card"><h2>テナント管理</h2>'.encode(), '<section class="card" hidden><h2>テナント管理</h2>'.encode(), 1)
    if 'license:write' not in claims_scopes:
        body = body.replace('<section class="card"><h2>ライセンス発行</h2>'.encode(), '<section class="card" hidden><h2>ライセンス発行</h2>'.encode(), 1)
    if 'phone:manage' not in claims_scopes:
        body = body.replace('<button class="secondary" id="load-phone">電話申請一覧</button>'.encode(), '<button class="secondary" id="load-phone" disabled hidden>電話申請一覧</button>'.encode(), 1)
    if 'audit:read' not in claims_scopes:
        body = body.replace('<button class="secondary" id="load-audit">監査ログ</button>'.encode(), '<button class="secondary" id="load-audit" disabled hidden>監査ログ</button>'.encode(), 1)
        body = body.replace(b'<div id="audit-filters">', b'<div id="audit-filters" hidden>', 1)
    grant_script = ("<script>(async()=>{const target=document.getElementById('one-time-sso-id'),select=document.getElementById('one-time-tenant'),button=document.getElementById('grant-one-time'),out=document.getElementById('one-time-grant-status'),identityStatus=document.getElementById('one-time-identities-status'),passkeyReady=" + ('true' if passkey_recent else 'false') + ";if(!select||!button||!target)return;async function readResponse(r){const raw=await r.text();let d;try{d=JSON.parse(raw)}catch(e){if(r.status===409&&location.hostname==='backup.2415.jp'){out.textContent='正系管理センターに移動します…';location.href='https://2415.jp/license/python-migration/admin_api.php#one-time-issuance-grant';throw new Error('正系管理センターに移動しています。')}throw new Error('管理APIがJSON以外の応答を返しました (HTTP '+r.status+')。ページを再読み込みしてください。')}if(r.status===409&&d.error_code==='PRIMARY_ONLY'){out.textContent='正系管理センターに移動します…';location.href=d.canonical_url+'#one-time-issuance-grant';throw new Error('正系管理センターに移動しています。')}return d};try{const r=await fetch('admin_api.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':" + json.dumps(csrf) + "},body:JSON.stringify({action:'list_tenants',page:1,limit:100})});const d=await readResponse(r);if(!r.ok||!d.success)throw new Error(d.message||'契約一覧を取得できませんでした');for(const t of d.tenants||[]){if(t.status!=='active'||t.environment!=='production'||t.parent_tenant_id)continue;const o=document.createElement('option');o.value=t.id;o.textContent=(t.name||t.slug)+' · '+t.slug+' · #'+t.id;select.append(o)}if(select.options.length<=1){select.options[0].textContent='対象となる本番契約がありません';button.disabled=true}}catch(e){out.className='error';out.textContent=e.message}select.addEventListener('change',async()=>{target.replaceChildren();const placeholder=document.createElement('option');placeholder.value='';placeholder.textContent='SSO IDを取得しています…';target.append(placeholder);target.disabled=true;button.disabled=true;identityStatus.textContent='契約所属を確認しています…';out.textContent='';try{const r=await fetch('admin_api.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':" + json.dumps(csrf) + "},body:JSON.stringify({action:'list_tenant_sso_identities',tenant_id:Number(select.value)})});const d=await readResponse(r);if(!r.ok||!d.success)throw new Error(d.message||'SSO ID一覧を取得できませんでした');target.replaceChildren();for(const identity of d.identities||[]){const o=document.createElement('option');o.value=identity.public_id;o.textContent=identity.public_id+(identity.display_name?' · '+identity.display_name:'');target.append(o)}if(!target.options.length){const o=document.createElement('option');o.value='';o.textContent='この契約に所属するSSO IDはありません';target.append(o);identityStatus.textContent='';target.disabled=true}else{identityStatus.textContent=(d.identities||[]).length+'件のSSO ID';target.disabled=false;button.disabled=!passkeyReady}}catch(e){target.replaceChildren();const o=document.createElement('option');o.value='';o.textContent='一覧を取得できませんでした';target.append(o);identityStatus.className='error';identityStatus.textContent=e.message;target.disabled=true}});target.addEventListener('change',()=>{button.disabled=!passkeyReady||!target.value});button.addEventListener('click',async()=>{const publicId=target.value,t=select.options[select.selectedIndex];if(!publicId){out.className='error';out.textContent='契約に所属するSSO IDを選択してください。';return}if(!t||!select.value||!confirm(publicId+' に「'+t.textContent+'」で1件だけ発行できる権限を付与します。実行しますか？'))return;button.disabled=true;out.className='';out.textContent='付与しています…';try{const r=await fetch('admin_api.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':" + json.dumps(csrf) + "},body:JSON.stringify({action:'grant_one_time_issuance',tenant_id:Number(select.value),target_public_id:publicId})});const d=await readResponse(r);if(!r.ok||!d.success)throw new Error(d.message||'権限を付与できませんでした');out.textContent=d.message+' 対象: '+d.target_public_id+' · 期限: 24時間以内 · Grant ID: '+d.grant_id}catch(e){out.className='error';out.textContent=e.message;button.disabled=!passkeyReady||!target.value}});})();</script>").encode('utf-8')
    body = body.replace(b'</body>', grant_script + b'</body>', 1)
    _http_status, _http_headers = ('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'), ('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

def _effective_admin_role(claims):
    """Resolve the current role from the active principal; session scopes can be stale."""
    connection = None
    try:
        from baas_handlers import _admin_role
        connection = database.connect()
        return _admin_role(connection, claims)
    except Exception:
        return None
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

@legacy_compatible(callback_index=1, request_index=0)
def _admin_help_page(request_context, claims):
    """Serve operator documentation only to an active administrator SSO session."""
    if claims.get('auth_source') != 'oidc_sso' or not claims.get('oidc_sid'):
        return _login_page(request_context, '管理者SSO IDでログインしてください。')
    try:
        from admin_oidc import session_active
        if not session_active(str(claims['oidc_sid'])):
            return _login_page(request_context, 'SSO IDの認証セッションが失効しました。再ログインしてください。')
        from baas_handlers import _role_allows_scope
        if not _role_allows_scope(_effective_admin_role(claims), 'license:read'):
            return _error('403 Forbidden', 'この資料を閲覧する管理者権限がありません。')
        content_path = os.path.join(os.path.dirname(__file__), 'admin-help-content.json')
        with open(content_path, 'r', encoding='utf-8') as stream:
            documents = json.load(stream)
        if not isinstance(documents, list) or len(documents) > 1000:
            raise ValueError('invalid private help catalog')
    except Exception:
        return _error('503 Service Unavailable', '管理者向け資料を読み込めません。')

    payload = json.dumps(documents, ensure_ascii=False, separators=(',', ':')).replace('<', '\\u003c')
    body = '''<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>管理者向け資料 | TUTI</title><style>
*{box-sizing:border-box}body{margin:0;background:#f2f6f5;color:#17343b;font:15px/1.7 system-ui,"Yu Gothic UI",Meiryo,sans-serif}.wrap{width:min(1400px,100%);margin:auto;padding:22px}.head,.tools{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}.head{padding:18px 20px;background:#fff;border:1px solid #dce8e5;border-radius:14px}.head h1{margin:3px 0;font-size:24px}.head p{margin:0;color:#60777a;font-size:13px}.head a{color:#08796d;font-weight:700}.layout{display:grid;grid-template-columns:minmax(250px,340px) minmax(0,1fr);gap:16px;margin-top:16px}.panel{min-width:0;padding:16px;background:#fff;border:1px solid #dce8e5;border-radius:14px}.list{max-height:calc(100vh - 210px);overflow:auto}.item{display:block;width:100%;margin:3px 0;padding:10px;border:1px solid transparent;border-radius:9px;background:#fff;text-align:left;color:#18353b;cursor:pointer}.item:hover,.item[aria-current=true]{border-color:#a8d5cc;background:#f0f8f6}.item small{display:block;color:#637b7e;overflow-wrap:anywhere}input{width:100%;margin:12px 0;padding:10px;border:1px solid #cbdad7;border-radius:9px;font:inherit}#content{white-space:pre-wrap;overflow-wrap:anywhere;max-width:100%;font:14px/1.8 ui-monospace,Consolas,"Yu Gothic UI",monospace}.placeholder{color:#637b7e}#count{color:#637b7e;font-size:12px}@media(max-width:760px){.wrap{padding:12px}.layout{grid-template-columns:1fr}.list{max-height:240px}.head h1{font-size:20px}}
</style></head><body><main class="wrap"><header class="head"><div><b>TUTI · 管理者資料</b><h1>運営・管理者向けヘルプ</h1><p>管理者SSO IDで認証済み。認証の有効期限が切れると再ログインが必要です。</p></div><a href="admin_api.php">管理センターへ戻る</a></header><div class="layout"><nav class="panel" aria-label="資料一覧"><label for="search">資料を検索</label><input id="search" type="search" autocomplete="off" placeholder="タイトル・本文・パス"><div id="count" role="status"></div><div class="list" id="list"></div></nav><section class="panel"><h2 id="title">資料を選択してください</h2><p id="path" class="placeholder"></p><article id="content" class="placeholder">一覧から資料を選ぶと本文を表示します。</article></section></div></main><script id="help-data" type="application/json">''' + payload + '''</script><script>
const docs=JSON.parse(document.getElementById('help-data').textContent),list=document.getElementById('list'),search=document.getElementById('search');let active=null;
function render(){const q=search.value.trim().toLocaleLowerCase(),items=docs.filter(x=>!q||(x.title+' '+x.path+' '+x.content).toLocaleLowerCase().includes(q));document.getElementById('count').textContent=items.length+'件';list.replaceChildren();for(const doc of items){const b=document.createElement('button'),small=document.createElement('small');b.className='item';b.setAttribute('aria-current',String(active===doc));b.textContent=doc.title;small.textContent=doc.project+' · '+doc.category;b.append(small);b.onclick=()=>{active=doc;document.getElementById('title').textContent=doc.title;document.getElementById('path').textContent=doc.path;const c=document.getElementById('content');c.textContent=doc.content;c.classList.remove('placeholder');render()};list.append(b)}}search.addEventListener('input',render);render();
</script></body></html>'''
    encoded = body.encode('utf-8')
    headers = [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'private, no-store, max-age=0'),
               ('Pragma', 'no-cache'), ('X-Content-Type-Options', 'nosniff'),
               ('Referrer-Policy', 'no-referrer'), ('X-Frame-Options', 'DENY'),
               ('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
               ('Content-Length', str(len(encoded)))]
    return make_response([encoded], '200 OK', headers)

@legacy_compatible(callback_index=1, request_index=0)
def _api_workbench_page(request_context, token, claims):
    role = _effective_admin_role(claims)
    from baas_handlers import _role_allows_scope
    if not _role_allows_scope(role, 'intake:manage'):
        return _error('403 Forbidden', '業務API実行には運用権限が必要です。')
    api_scopes = ['tenant:api']
    for scope in ('tenant:read', 'products:write', 'licenses:read', 'licenses:write', 'license:manage'):
        if _role_allows_scope(role, scope):
            api_scopes.append(scope)
    api_claims = {'purpose': 'ha_admin', 'auth_source': 'oidc_sso', 'oidc_sid': claims.get('oidc_sid'), 'reauthenticated_at': int(claims.get('reauthenticated_at') or 0), 'scope': api_scopes, 'client': 'desktop', 'source': 'admin_api', 'admin_role': role, 'credential_id_hash': claims.get('credential_id_hash'), 'issued_at': int(claims.get('reauthenticated_at', 0)), 'expires': int(time.time()) + 300, 'nonce': secrets.token_hex(16)}
    from web_passkey_auth import _encode_token
    api_token = _encode_token(api_claims)
    token_html = api_token.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;')
    csrf = _cookie_value(request_context, CSRF_COOKIE).replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;')
    recent = False
    try:
        recent = 0 <= int(time.time()) - int(claims.get('reauthenticated_at', 0)) <= 120
    except (TypeError, ValueError):
        pass
    stepup = '' if recent else site_url('<p class="warn">ライセンス発行・変更には直前2分以内のPasskey再認証が必要です。<a href="/license/python-migration/admin_api.php?admin_sso_start=1&amp;step_up=1">Passkeyを再認証</a>してから再読み込みしてください。</p>')
    body = ('<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="api-session" content="' + token_html + '"><meta name="admin-csrf" content="' + csrf + '"><title>業務API実行 | TUTI LICENSE</title><style>body{margin:0;background:#f1f5f4;color:#17343b;font:15px system-ui,sans-serif}.wrap{max-width:1200px;margin:26px auto;padding:0 18px}.card{background:#fff;border:1px solid #dce8e5;border-radius:15px;padding:20px;margin:14px 0}header,.controls{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap}label{display:block;font-weight:700;margin:12px 0 6px}input,select,textarea{box-sizing:border-box;max-width:100%;padding:10px;border:1px solid #b9ceca;border-radius:8px;font:inherit}textarea{width:100%;font-family:ui-monospace,monospace}button{padding:10px 14px;border:0;border-radius:8px;background:#08796d;color:white;font:inherit;font-weight:700;cursor:pointer}button.secondary{background:#526b6b}button:disabled{opacity:.5}.warn{padding:10px;background:#fff5dc;border-radius:8px}.muted{color:#718589}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f8f7;padding:14px;border-radius:8px;min-height:30px}</style></head><body><main class="wrap"><header><div><b>TUTI LICENSE · ADMIN CENTER</b><h1>業務API実行</h1><p class="muted">契約先を選んで、アプリと同じBaaS APIを実行します。</p></div><nav><a href="admin_api.php">管理センターへ戻る</a>\u3000<button id="logout" class="secondary">ログアウト</button></nav></header>' + stepup + '\n<section class="card"><h2>契約先と操作</h2><div class="controls"><label>契約先<select id="tenant"><option value="">読み込み中…</option></select></label><label>API操作<select id="operation"><option value="service.status">サービスの利用状況</option><option value="usage.summary">利用料金・請求状況</option><option value="products.list">製品一覧</option><option value="licenses.list">ライセンス検索</option><option value="licenses.issue">ライセンス発行</option><option value="licenses.pause">ライセンス一時停止</option><option value="licenses.activate">ライセンス再開</option><option value="identity.begin">本人確認セッション開始</option><option value="identity.info">本人確認サービス仕様・料金</option></select></label></div><label>検索・期間等のGETパラメーター（JSON）<input id="query" value="{}" style="width:100%"></label><label>POST入力（JSON）<textarea id="payload" rows="8">{}</textarea></label><div class="controls"><button id="run">APIを実行</button><button id="reload-tenants" class="secondary">契約先を再読込</button></div><p id="status" role="status"></p><h3>レスポンス</h3><pre id="result" aria-live="polite"></pre></section>\n<script>const apiToken=document.querySelector(\'meta[name="api-session"]\').content,csrf=document.querySelector(\'meta[name="admin-csrf"]\').content,byId=id=>document.getElementById(id),recent=' + ('true' if recent else 'false') + site_url(";const presets={'service.status':{method:'GET',query:{service:'service.status'}},'usage.summary':{method:'GET',query:{service:'usage.summary',period:new Date().toISOString().slice(0,7)}},'products.list':{method:'GET',query:{service:'products.list',limit:50,cursor:0,search:'',status:''}},'licenses.list':{method:'GET',query:{service:'licenses.list',limit:50,cursor:0,search:'',product_id:'',license_id:''}},'licenses.issue':{method:'POST',payload:{service:'licenses.issue',product_id:1,license_mode:'single',label:'',max_devices:10,evaluation_days:30,expires_at:'',idempotency_key:''}},'licenses.pause':{method:'POST',payload:{service:'licenses.pause',license_id:1}},'licenses.activate':{method:'POST',payload:{service:'licenses.activate',license_id:1}},'identity.begin':{method:'POST',payload:{service:'identity.begin'}},'identity.info':{method:'GET',query:{service:'identity.info'}}};function updatePreset(){const p=presets[byId('operation').value];byId('query').value=JSON.stringify(p.query||{},null,2);byId('payload').value=JSON.stringify(p.payload||{},null,2);byId('payload').disabled=p.method==='GET'||p.method==='DELETE';byId('run').disabled=!recent&&['licenses.issue','licenses.pause','licenses.activate','identity.begin'].includes(byId('operation').value)}function syncCardTenant(){const source=byId('tenant'),target=byId('mnsl-card-tenant');if(!source||!target)return;const value=source.value;target.replaceChildren(new Option('対象のお客様を選択',''));for(const option of [...source.options].slice(1)){const copy=new Option(option.text,option.value);const tenant=(window.workbenchTenants||[]).find(x=>String(x.id)===option.value);copy.dataset.env=tenant?.parent_tenant_id||tenant?.environment==='sandbox'?'sandbox':'production';target.add(copy)}target.value=value;target.dispatchEvent(new Event('change'))}async function loadTenants(){const status=byId('status');status.textContent='契約先を取得しています…';try{const r=await fetch('admin_api.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({action:'list_workbench_tenants'})}),d=await r.json();if(!r.ok||!d.success)throw Error(d.message||d.error||'取得に失敗しました');window.workbenchTenants=d.tenants||[];const s=byId('tenant');s.replaceChildren(new Option('契約先を選択',''));for(const t of window.workbenchTenants){const env=t.parent_tenant_id||t.environment==='sandbox'?'sandbox':t.environment;const o=new Option(t.name+' · '+t.slug+' · '+env+' (#'+t.id+')',t.id);o.dataset.env=env;s.add(o)}s.value=String(d.default_tenant_id||'');syncCardTenant();s.onchange=syncCardTenant;status.textContent=(d.tenants||[]).length+' 件の契約先'}catch(e){status.textContent=e.message;status.className='error'}}async function run(){const id=byId('tenant').value;if(!id){byId('status').textContent='契約先を選択してください。';return}const name=byId('operation').value,p=presets[name];if(!recent&&['licenses.issue','licenses.pause','licenses.activate','identity.begin'].includes(name)){byId('status').textContent='操作前にPasskeyを再認証してください。';return}let params,payload;try{params=JSON.parse(byId('query').value||'{}');payload=JSON.parse(byId('payload').value||'{}');if(!params||Array.isArray(params)||typeof params!=='object'||!payload||Array.isArray(payload)||typeof payload!=='object')throw Error()}catch{byId('status').textContent='入力JSONを確認してください。';return}const method=p.method,url='/license/python-migration/api/baas/v1/service.php'+(method==='GET'?'?'+new URLSearchParams({...params,service:name}):'');byId('status').textContent='処理中…';byId('result').textContent='';try{const r=await fetch(url,{method,credentials:'same-origin',headers:{'X-HA-Session':apiToken,'X-Tenant-ID':id,...(method==='GET'?{}:{'Content-Type':'application/json'})},...(method==='GET'?{}:{body:JSON.stringify({...payload,service:name})})}),raw=await r.text();let d;try{d=JSON.parse(raw)}catch{throw Error('HTTP '+r.status+' 応答をJSONとして読み取れません')}byId('result').textContent=JSON.stringify(d,null,2);byId('status').textContent=r.ok?'APIを実行しました。':'APIエラー: HTTP '+r.status}catch(e){byId('status').textContent=e.message}}byId('operation').onchange=updatePreset;byId('run').onclick=run;byId('reload-tenants').onclick=loadTenants;byId('logout').onclick=async()=>{try{await fetch('admin_api.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({action:'logout'})})}finally{location.href='admin_api.php'}};updatePreset();loadTenants();</script></main></body></html>")).encode()
    body = body.decode('utf-8')
    body = body.replace('<meta name="admin-csrf"', site_url('<meta name="api-base" content="/license/python-migration"><meta name="admin-csrf"'), 1)
    body = body.replace("for(const option of [...source.options].slice(1)){const copy=new Option(option.text,option.value);const tenant=(window.workbenchTenants||[]).find(x=>String(x.id)===option.value);copy.dataset.env=tenant?.parent_tenant_id||tenant?.environment==='sandbox'?'sandbox':'production';target.add(copy)}", "for(const option of [...source.options].slice(1)){const tenant=(window.workbenchTenants||[]).find(x=>String(x.id)===option.value);if(!tenant||tenant.status!=='active')continue;const env=tenant.parent_tenant_id||tenant.environment==='sandbox'?'sandbox':tenant.environment;if(!['production','sandbox'].includes(env))continue;const copy=new Option(option.text,option.value);copy.dataset.env=env;target.add(copy)}", 1)
    body = body.replace("const o=new Option(t.name+' · '+t.slug+' · '+env+' (#'+t.id+')',t.id);o.dataset.env=env;s.add(o)", "const o=new Option(t.name+' · '+t.slug+' · '+env+' (#'+t.id+')',t.id);o.dataset.env=env;o.dataset.status=t.status;s.add(o)", 1)
    card_markup = '<section class="card" id="mnsl-card-auth"><h2>カード読み取り</h2><p class="muted">Windows端末のMNSL連携、またはAndroidアプリでカードを読み取れます。</p><label>対象テナント<select id="mnsl-card-tenant"><option value="">契約先を選択してください</option></select></label><button id="mnsl-card-start" disabled>Windowsでカードを読み取る</button><p id="mnsl-card-state" role="status" aria-live="polite">カード読取ブリッジを確認しています。</p><p class="muted">Windows方式は <a href="downloads/start-mnsl-card-web-bridge.cmd" download>起動ファイル</a> と <a href="downloads/mnsl-card-web-bridge.ps1" download>ブリッジ本体</a> を同じフォルダーへ保存して起動します。PIN・証明書・秘密鍵はサーバーへ送りません。</p><hr><p>Android NFC連携ではQRを発行してアプリで読み取ります。QRは3分で失効します。</p><button id="mnsl-android-start" disabled>Android読み取りQRを発行</button><p id="mnsl-android-state" role="status" aria-live="polite">対象のお客様を選び、QRを発行してください。</p><div id="mnsl-android-qr-panel" hidden><div id="mnsl-android-qr"></div><a id="mnsl-android-link" rel="noreferrer">この端末でアプリを開く</a></div><p class="muted">Webに表示されるのは完了・失敗だけです。カードデータをサーバー側で検証するものではなく、公的なJPKI本人確認や法定の本人確認を意味しません。</p></section>'
    body = body.replace('<section class="card"><h2>契約先と操作</h2>', card_markup + '<section class="card"><h2>契約先と操作</h2>', 1)
    body = body.replace('updatePreset();loadTenants();', 'updatePreset();loadTenants();', 1)
    body = body.replace('</script></main></body></html>', '</script><script src="mnsl-card-auth.js" defer></script><script src="mnsl-android-card-read.js" defer></script></main></body></html>', 1)
    body = body.encode('utf-8')
    _http_status, _http_headers = ('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'), ('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self' http://127.0.0.1:17891; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=1, request_index=0)
def _invoice_admin_page(request_context, token, claims):
    """Python management UI for the already-ported API billing endpoints."""
    from baas_handlers import _role_allows_scope
    role = _effective_admin_role(claims)
    if not _role_allows_scope(role, 'admin:manage'):
        return _error('403 Forbidden', '請求書管理には管理権限が必要です。')
    recent = False
    try:
        recent = 0 <= int(time.time()) - int(claims.get('reauthenticated_at', 0)) <= 120
    except (TypeError, ValueError):
        pass
    host = str(request_context.get('header:host', '2415.jp')).lower().split(':', 1)[0]
    if host not in {'2415.jp', 'backup.2415.jp', 'main.2415.jp'}:
        host = '2415.jp'
    reauth = site_url('/license/python-migration/admin_api.php?admin_sso_start=1&step_up=1&return_host=') + quote(host, safe='')
    session = token.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;')
    stepup = '' if recent else '<p class="warn">発行・入金処理・無効化には直前2分以内のPasskey再認証が必要です。<a href="' + reauth + '">Passkeyを再認証</a>して再読み込みしてください。</p>'
    body = ('<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="ha-session" content="' + session + '"><meta name="referrer" content="no-referrer"><title>API請求書 | TUTI LICENSE</title><link rel="stylesheet" href="admin-center-modern.css"><link rel="stylesheet" href="admin-invoices.css"><style>.billing-wrap{max-width:1250px;margin:24px auto;padding:0 18px}.billing-head,.billing-grid,.billing-actions{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.billing-head{justify-content:space-between}.billing-card{background:#fff;border:1px solid #dce8e5;border-radius:14px;padding:18px;margin:14px 0}.billing-card input,.billing-card select,.billing-card textarea{padding:9px;border:1px solid #b9ceca;border-radius:7px;font:inherit}.billing-card label{display:inline-flex;flex-direction:column;gap:5px;margin:7px}.billing-card button{padding:9px 12px;border:0;border-radius:8px;background:#08796d;color:white;font-weight:700;cursor:pointer}.billing-card button.secondary{background:#526b6b}.billing-card button:disabled{opacity:.5}.billing-table{width:100%;border-collapse:collapse}.billing-table th,.billing-table td{text-align:left;padding:8px;border-bottom:1px solid #e4edeb}.warn,.error{color:#a62b35}.muted{color:#718589}pre{white-space:pre-wrap;overflow-wrap:anywhere}.bill-detail{padding:12px;background:#f4f8f7;border-radius:8px}</style></head><body><main class="billing-wrap"><header class="billing-head"><div><b>TUTI LICENSE · ADMIN CENTER</b><h1>API請求書</h1><p class="muted">利用明細の確認・下書き・発行・入金状況を管理します。</p></div><nav><a href="admin_api.php">管理センターへ戻る</a>\u3000<button id="logout" class="secondary">ログアウト</button></nav></header>' + stepup + '\n<section class="billing-card"><h2>請求書を作成</h2><div class="billing-grid"><label>テナント<select id="tenant"><option value="">読み込み中…</option></select></label><label>対象月<input id="period" type="month" required></label><label>請求先名<input id="customer" maxlength="160" placeholder="テナント名"></label><label>発行日<input id="issue-date" type="date" required></label><label>支払期限<input id="due-date" type="date" required></label><label>税率 (%)<input id="tax" type="number" min="0" max="100" step="0.01" value="10"></label><label>調整額 (円)<input id="adjustment" value="0"></label><label>発行者名<input id="issuer" maxlength="160" value="TUTI License"></label><label>登録番号<input id="registration" maxlength="32"></label></div><label style="display:flex">備考<textarea id="notes" maxlength="2000" rows="2"></textarea></label><div class="billing-actions"><button id="preview" class="secondary">明細を確認</button><button id="draft" class="secondary">下書き保存</button><button id="issue">請求書を発行</button></div><div id="preview-box" class="bill-detail" hidden></div><p id="status" role="status"></p></section>\n<section class="billing-card"><div class="billing-head"><div><h2>請求一覧</h2><p class="muted">請求を選ぶと明細と状態変更の操作を表示します。</p></div><button id="refresh" class="secondary">一覧を更新</button></div><label>状態<select id="filter"><option value="all">すべて</option><option value="issued">発行済み</option><option value="draft">下書き</option><option value="paid">入金済み</option><option value="void">無効</option></select></label><input id="search" type="search" placeholder="請求番号・テナントで検索"><div id="invoice-list" aria-live="polite"></div><div id="invoice-detail"></div></section>\n<script>const token=document.querySelector(\'meta[name="ha-session"]\').content,apiUrl=\'ha/api-billing-admin.php\',recent=' + ('true' if recent else 'false') + ",byId=id=>document.getElementById(id);let invoices=[];async function api(action,extra={}){const r=await fetch(apiUrl,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-HA-Session':token},body:JSON.stringify({action,...extra})});let d;try{d=await r.json()}catch{throw Error('応答を読み取れません (HTTP '+r.status+')')}if(!r.ok||!d.ok)throw Error(d.message||d.error||'処理に失敗しました');return d}function payload(){return {tenant_id:Number(byId('tenant').value),period:byId('period').value,customer_name:byId('customer').value,issue_date:byId('issue-date').value,due_date:byId('due-date').value,tax_rate_basis_points:Math.round(Number(byId('tax').value)*100),adjustment_yen:byId('adjustment').value,issuer_name:byId('issuer').value,issuer_registration_number:byId('registration').value,notes:byId('notes').value}}function yen(n){return new Intl.NumberFormat('ja-JP',{style:'currency',currency:'JPY',minimumFractionDigits:3,maximumFractionDigits:3}).format(Number(n||0))}function safe(v){return String(v??'—')}function drawList(){const q=byId('search').value.toLowerCase(),f=byId('filter').value,rows=invoices.filter(x=>(f==='all'||x.status===f)&&(!q||(String(x.invoice_number)+' '+String(x.account_slug)+' '+String(x.customer_name)).toLowerCase().includes(q)));const box=byId('invoice-list');box.replaceChildren();if(!rows.length){box.textContent='請求書はありません。';return}const t=document.createElement('table');t.className='billing-table';const h=document.createElement('tr');for(const x of ['請求番号','テナント','対象月','請求先','状態','合計','操作']){const th=document.createElement('th');th.textContent=x;h.append(th)}t.append(h);const b=document.createElement('tbody');for(const x of rows){const tr=document.createElement('tr');for(const v of [x.invoice_number,x.account_slug,x.billing_period,x.customer_name,x.status,yen(x.total_yen)]){const td=document.createElement('td');td.textContent=safe(v);tr.append(td)}const td=document.createElement('td');const sel=document.createElement('button');sel.textContent='明細';sel.className='secondary';sel.onclick=()=>showInvoice(x.id);td.append(sel);if(x.status==='draft'||x.status==='issued'){const act=document.createElement('button');act.textContent=x.status==='draft'?'発行':'入金済みにする';act.disabled=!recent;act.onclick=()=>x.status==='draft'?mutate('issue',x.id,{tenant_id:x.account_tenant_id,period:x.billing_period,customer_name:x.customer_name,issue_date:x.issue_date,due_date:x.due_date,tax_rate_basis_points:x.tax_rate_basis_points,adjustment_yen:x.adjustment_yen,issuer_name:x.issuer_name,issuer_registration_number:x.issuer_registration_number,notes:x.notes}):mutate('mark_paid',x.id);td.append(act)}if(['draft','issued'].includes(x.status)){const v=document.createElement('button');v.textContent='無効化';v.className='secondary';v.disabled=!recent;v.onclick=()=>mutate('void',x.id);td.append(v)}if(x.status==='draft'){const del=document.createElement('button');del.textContent='下書き削除';del.className='secondary';del.disabled=!recent;del.onclick=()=>mutate('delete_draft',x.id);td.append(del)}tr.append(td);b.append(tr)}t.append(b);box.append(t)}async function loadList(){try{const d=await api('list',{limit:500});invoices=d.invoices||[];drawList()}catch(e){byId('invoice-list').textContent=e.message}}async function showInvoice(id){try{const d=await api('get',{invoice_id:id}),x=d.invoice;const box=byId('invoice-detail');box.replaceChildren();const pre=document.createElement('pre');pre.textContent=JSON.stringify(x,null,2);pre.className='bill-detail';box.append(pre)}catch(e){byId('status').textContent=e.message}}async function mutate(action,id,extra={}){if(!confirm('この請求書に「'+action+'」を実行しますか？'))return;try{await api(action,{...extra,invoice_id:id});await loadList()}catch(e){byId('status').textContent=e.message}}async function formAction(action){try{const d=await api(action,payload());const x=d.invoice;if(action==='preview'){byId('preview-box').hidden=false;byId('preview-box').textContent=JSON.stringify(x,null,2)}else{byId('status').textContent=(action==='issue'?'発行しました: ':'下書きを保存しました: ')+x.invoice_number;await loadList()}}catch(e){byId('status').textContent=e.message}}async function init(){try{const d=await api('tenants');const s=byId('tenant');s.replaceChildren(new Option('選択してください',''));for(const t of d.tenants||[])s.add(new Option(t.name+' ('+t.slug+')',t.id));const today=new Date(),month=today.toISOString().slice(0,7);byId('period').value=month;byId('issue-date').value=today.toISOString().slice(0,10);const due=new Date(today);due.setDate(due.getDate()+30);byId('due-date').value=due.toISOString().slice(0,10)}catch(e){byId('status').textContent='テナント取得失敗: '+e.message}await loadList()}byId('preview').onclick=()=>formAction('preview');byId('draft').onclick=()=>formAction('save_draft');byId('issue').onclick=()=>{if(recent)formAction('issue');else byId('status').textContent='発行前にPasskeyを再認証してください。'};byId('refresh').onclick=loadList;byId('filter').onchange=drawList;byId('search').oninput=drawList;byId('logout').onclick=async()=>{try{await fetch('admin_api.php',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'logout'})});location.href='admin_api.php'}catch(e){location.href='admin_api.php'}};init();</script></main></body></html>").encode()
    if not recent:
        body = body.replace('id="draft" class="secondary"', 'id="draft" class="secondary" disabled')
        body = body.replace('id="issue">請求書を発行', 'id="issue" disabled>請求書を発行')
    _http_status, _http_headers = ('200 OK', [('Content-Type', 'text/html; charset=utf-8'), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('Referrer-Policy', 'no-referrer'), ('Content-Security-Policy', "default-src 'self'; script-src 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=1, request_index=0)
def _passkey_login_callback(request_context, code):
    body = json.dumps({'action': 'verify_code', 'code': code, 'client': 'admin_web'}, separators=(',', ':')).encode()
    internal = dict(request_context)
    internal.update({'path': '/ha/passkey_api.php', 'method': 'POST', 'content_type': 'application/json', 'content_length': str(len(body)), 'body_stream': BytesIO(body)})
    try:
        from passkey_handlers import passkey_api
        native_result = passkey_api(internal)
        result = json.loads(native_result.body)
        if native_result.status_code != 200 or result.get('ok') is not True:
            return _login_page(request_context, 'パスキー認証の期限が切れたか、検証用セッション設定がありません。')
        token = str(result.get('session_token', ''))
        prior_token = _cookie_value(request_context, SESSION_COOKIE)
        if prior_token:
            from baas_handlers import _decode_admin_session
            prior_claims = _decode_admin_session(prior_token)
            if prior_claims and prior_claims.get('oidc_sid'):
                import base64
                parts = token.split('.', 1)
                raw_claims = base64.urlsafe_b64decode(parts[0] + '=' * (-len(parts[0]) % 4))
                new_claims = json.loads(raw_claims.decode('utf-8'))
                new_claims['oidc_sid'] = str(prior_claims['oidc_sid'])
                from web_passkey_auth import _encode_token
                token = _encode_token(new_claims)
        claims, status, _ = _authorize({**request_context, 'header:x-ha-session': token}, {}, 'license:read')
        if status or not claims:
            return _login_page(request_context, '管理者として有効なパスキーを確認できませんでした。')
        claims['expires'] = int(time.time()) + ADMIN_IDLE_TIMEOUT
        claims['last_activity'] = int(time.time())
        from web_passkey_auth import _encode_token
        token = _encode_token(claims)
        try:
            csrf = __import__('secrets').token_urlsafe(32)
            host = str(request_context.get('header:host', '2415.jp')).lower().split(':', 1)[0]
            base = site_url('/license/python-migration/')
            location = base + 'admin_api.php'
            headers = [('Location', location), ('Set-Cookie', SESSION_COOKIE + '=' + token + '; Path=' + base + '; Max-Age=' + str(ADMIN_IDLE_TIMEOUT) + '; Secure; HttpOnly; SameSite=Strict'), ('Set-Cookie', CSRF_COOKIE + '=' + csrf + '; Path=' + base + '; Max-Age=' + str(ADMIN_IDLE_TIMEOUT) + '; Secure; SameSite=Strict')]
            _http_status, _http_headers = ('303 See Other', headers + [('Content-Length', '0'), ('Cache-Control', 'no-store')])
            return make_response([b''], _http_status, _http_headers)
        except Exception:
            return _login_page(request_context, 'ログインセッションを開始できませんでした。')
    except Exception:
        return _login_page(request_context, 'パスキー認証の検証に失敗しました。検証DBと秘密値を確認してください。')

def _license(connection, data):
    license_id = admin_request_int(data, 'license_id', 0, 0, 2 ** 63 - 1)
    if license_id <= 0:
        license_id = admin_request_int(data, 'id', 0, 0, 2 ** 63 - 1)
    if license_id > 0:
        query, value = ('SELECT * FROM licenses WHERE id=%s AND deleted_at IS NULL LIMIT 1', license_id)
    else:
        key = normalize_license_key(data.get('license_key', data.get('product_key', data.get('key', ''))))
        if not key:
            return None
        pepper = secret_value('key_pepper')
        if len(pepper) < 32:
            raise database.DatabaseConfigurationError('test key pepper is not configured')
        key_hash = license_key_hash({'key_pepper': pepper}, key)
        query, value = ('SELECT * FROM licenses WHERE key_hash=%s AND deleted_at IS NULL LIMIT 1', key_hash)
    with connection.cursor() as cursor:
        cursor.execute(query, (value,))
        return cursor.fetchone()

def _active_count(connection, license_id):
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) AS cnt FROM license_devices WHERE license_id=%s AND revoked_at IS NULL AND refresh_expires_at>UTC_TIMESTAMP()', (license_id,))
        row = cursor.fetchone()
    return int((row or {}).get('cnt', 0))

def _list_devices(connection, data, sessions=False):
    row = _license(connection, data)
    if not row:
        return ('404 Not Found', False, 'キーが見つかりません。', {})
    q = admin_request_string(data, 'q')
    page = admin_request_int(data, 'page', 1, 1, 100000)
    limit = admin_request_int(data, 'limit', 25, 1, 100)
    offset = admin_page_offset(page, limit)
    if sessions:
        where = 'WHERE license_id=%s AND revoked_at IS NULL AND refresh_expires_at>UTC_TIMESTAMP()'
        order = 'ORDER BY last_seen_at DESC,id DESC'
        search = 'CAST(id AS CHAR) LIKE %s OR device_label LIKE %s OR device_hash LIKE %s OR last_ip_hash LIKE %s'
    else:
        where = 'WHERE license_id=%s'
        order = 'ORDER BY id DESC'
        search = 'CAST(id AS CHAR) LIKE %s OR device_label LIKE %s OR device_hash LIKE %s OR access_token_hash LIKE %s OR refresh_token_hash LIKE %s'
    params = [int(row['id'])]
    if q:
        where += ' AND (' + search + ')'
        pattern = admin_like_value(q)
        params.extend([pattern] * (4 if sessions else 5))
    params.extend([limit + 1, offset])
    sql = 'SELECT id,license_id,device_hash,device_label,access_expires_at,refresh_expires_at,first_activated_at,last_seen_at,revoked_at,last_ip_hash,app_version,token_version FROM license_devices ' + where + ' ' + order + ' LIMIT %s OFFSET %s'
    with connection.cursor() as cursor:
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
    has_next = len(rows) > limit
    rows = rows[:limit]
    values = [admin_session_payload(item) for item in rows] if sessions else [admin_device_payload(item) for item in rows]
    license_payload = admin_license_payload(row, len(values) if sessions else _active_count(connection, int(row['id'])))
    if sessions:
        return ('200 OK', True, 'アクティブセッションを取得しました。', {'license': license_payload, 'sessions': values, 'active_sessions': len(values)})
    return ('200 OK', True, '端末一覧を取得しました。', {'devices': values, 'license': license_payload})

@legacy_compatible(callback_index=None, request_index=1)
def _audit_write(connection, request_context, action, device_id, license_id, before, after, claims, target_type='device', target_id=None):
    try:
        request_id = uuid.uuid4().hex[:16]
        actor = str(claims.get('credential_id_hash', ''))
        role = ''
        with connection.cursor() as cursor:
            cursor.execute("SELECT role_name FROM admin_principals WHERE credential_id_hash=%s AND status='active' AND revoked_at IS NULL LIMIT 1", (actor,))
            principal = cursor.fetchone()
            role = str(principal.get('role_name', '')) if principal else ''
            cursor.execute('SELECT event_hash FROM admin_audit_events ORDER BY id DESC LIMIT 1')
            previous_row = cursor.fetchone()
            previous_hash = str((previous_row or {}).get('event_hash') or '0' * 64)
            before_json = json.dumps(_json_safe(before), ensure_ascii=False, separators=(',', ':'))
            after_json = json.dumps(_json_safe(after), ensure_ascii=False, separators=(',', ':'))
            node_role = os.environ.get('PYTHON_MIGRATION_HA_ROLE', 'unknown')
            target_id = str(target_id if target_id is not None else device_id)
            canonical = json.dumps([request_id, actor, role, node_role, action, target_type, target_id, before_json, after_json, previous_hash], ensure_ascii=True, separators=(',', ':'))
            event_hash = hashlib.sha256(canonical.encode()).hexdigest()
            cursor.execute('INSERT IGNORE INTO admin_audit_events(request_id,actor_hash,role_name,node_role,event_type,target_type,target_id,before_json,after_json,ip_hash,prev_hash,event_hash) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', (request_id, actor or None, role or None, node_role, action, target_type, target_id, before_json, after_json, hashlib.sha256(str(request_context.get('client_address', '')).encode()).hexdigest(), previous_hash, event_hash))
    except Exception as error:
        import logging
        logging.getLogger(__name__).error('[ADMIN_AUDIT_PERSIST_FAILED] action=%s exception=%s', re.sub('[^A-Za-z0-9_.:-]', '_', action), type(error).__name__)
    try:
        from ha_handlers import _append_ha_audit
        _append_ha_audit(action, {'target_type': target_type, 'target_id': str(target_id if target_id is not None else device_id), 'device_id': device_id, 'license_id': license_id, 'before': before, 'after': after}, request_context)
    except Exception:
        pass

def _change_journal(connection, entity_type, entity_id, operation, payload):
    try:
        canonical = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        digest = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
        with connection.cursor() as cursor:
            cursor.execute('SELECT COALESCE(MAX(row_version),0)+1 AS version FROM data_change_journal WHERE entity_type=%s AND entity_id=%s', (entity_type, entity_id))
            version = int((cursor.fetchone() or {}).get('version', 1))
            cursor.execute('INSERT INTO data_change_journal(entity_type,entity_id,operation,row_version,payload_hash) VALUES(%s,%s,%s,%s,%s)', (entity_type, entity_id, operation, version, digest))
    except Exception as error:
        import logging
        logging.getLogger(__name__).error('[ADMIN_CHANGE_JOURNAL_WRITE_FAILED] entity_type=%s exception=%s', re.sub('[^A-Za-z0-9_.:-]', '_', entity_type), type(error).__name__)

def _list_audit_logs(connection, data):
    q = admin_request_string(data, 'q')
    event_type = admin_request_string(data, 'event_type')[:80]
    actor = admin_request_string(data, 'actor').lower()
    if not re.fullmatch('[a-f0-9]{8,64}', actor):
        actor = ''
    from_date = admin_request_string(data, 'from')
    to_date = admin_request_string(data, 'to')
    if not re.fullmatch('\\d{4}-\\d{2}-\\d{2}', from_date):
        from_date = ''
    if not re.fullmatch('\\d{4}-\\d{2}-\\d{2}', to_date):
        to_date = ''
    page = admin_request_int(data, 'page', 1, 1, 100000)
    limit = admin_request_int(data, 'limit', 25, 1, 100)
    where, params = ([], [])
    if q:
        where.append('(target_id LIKE %s OR request_id LIKE %s)')
        params.extend([admin_like_value(q)] * 2)
    if event_type:
        where.append('event_type=%s')
        params.append(event_type)
    if actor:
        where.append('actor_hash LIKE %s')
        params.append(actor + '%')
    if from_date:
        where.append('created_at >= %s')
        params.append(from_date + ' 00:00:00')
    if to_date:
        where.append('created_at < DATE_ADD(%s,INTERVAL 1 DAY)')
        params.append(to_date + ' 00:00:00')
    sql = 'SELECT request_id,actor_hash,role_name,node_role,event_type,target_type,target_id,before_json,after_json,outcome,created_at FROM admin_audit_events' + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY id DESC LIMIT %s OFFSET %s'
    params.extend([limit + 1, admin_page_offset(page, limit)])
    with connection.cursor() as cursor:
        cursor.execute(sql, tuple(params))
        rows = cursor.fetchall()
    has_next = len(rows) > limit
    result = []
    for row in rows[:limit]:
        item = dict(row)
        for source, target in (('before_json', 'before'), ('after_json', 'after')):
            raw = item.pop(source, None)
            try:
                item[target] = json.loads(raw) if raw else None
            except (TypeError, ValueError):
                item[target] = None
        result.append(item)
    return (result, has_next, page, limit)

def _diagnose_error(connection, error_id):
    error_id = str(error_id or '').strip().lower()
    if re.fullmatch('[a-f0-9]{8}', error_id) is None:
        return (error_id, None)
    row = None
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT error_type,message,file_path,line_number,context_json FROM admin_error_diagnostics WHERE error_id=%s AND created_at>=UTC_TIMESTAMP()-INTERVAL 7 DAY LIMIT 1', (error_id,))
            row = cursor.fetchone()
    except Exception:
        row = None
    if row:
        try:
            context = json.loads(row.get('context_json') or '{}')
        except (TypeError, ValueError):
            context = {}
        return (error_id, {'type': str(row.get('error_type') or ''), 'message': str(row.get('message') or '')[:1000], 'file': str(row.get('file_path') or ''), 'line': int(row.get('line_number') or 0), 'stage': str(context.get('stage') or '') if isinstance(context, dict) else ''})
    log_dir = os.environ.get('LICENSE_LOG_DIR', '').strip()
    if not log_dir:
        import tempfile
        log_dir = os.path.join(tempfile.gettempdir(), 'license-api')
    path = os.path.join(log_dir, 'errors.log')
    try:
        size = os.path.getsize(path)
        if size <= 0:
            return (error_id, None)
        with open(path, 'rb') as stream:
            stream.seek(max(0, size - 4 * 1024 * 1024))
            if size > 4 * 1024 * 1024:
                stream.readline()
            lines = stream.read(4 * 1024 * 1024).decode('utf-8', 'replace').splitlines()
    except OSError:
        return (error_id, None)
    marker = '[error_id=' + error_id + ']'
    pattern = re.compile('\\[error_id=' + re.escape(error_id) + '\\]\\s+(?P<type>[^\\s]+)\\s+message=(?P<message>.*?)\\s+file=(?P<file>.*):(?P<line>[0-9]+)\\s+trace=', re.I)
    for line in reversed(lines):
        if marker not in line.lower():
            continue
        found = pattern.search(line)
        if not found:
            return (error_id, {'summary': '該当ログは見つかりましたが、詳細を読み取れませんでした。'})
        return (error_id, {'type': found.group('type'), 'message': found.group('message')[:1000], 'file': found.group('file'), 'line': int(found.group('line'))})
    return (error_id, None)

def _list_admin_licenses(connection, data, deleted=False, volume=False):
    q = admin_request_string(data, 'q')
    page = admin_request_int(data, 'page', 1, 1, 100000)
    limit = admin_request_int(data, 'limit', 25, 1, 100)
    where = ['l.deleted_at IS NOT NULL' if deleted else 'l.deleted_at IS NULL']
    args = []
    if volume:
        where.append('l.max_devices>1')
    if q:
        where.append('(CAST(l.id AS CHAR) LIKE %s OR l.label LIKE %s OR t.name LIKE %s OR p.name LIKE %s)')
        args.extend([admin_like_value(q)] * 4)
    for field in ('tenant_id', 'product_id'):
        value = admin_request_int(data, field, 0, 0, 1000000000)
        if value:
            where.append('l.' + field + '=%s')
            args.append(value)
    status = '' if deleted else admin_request_string(data, 'status')
    expiry = 'COALESCE(l.expires_at,IF(l.evaluation_days IS NOT NULL AND l.evaluation_started_at IS NOT NULL,DATE_ADD(l.evaluation_started_at,INTERVAL l.evaluation_days DAY),NULL))'
    conditions = {'active': 'l.active=1 AND l.revoked_at IS NULL AND (' + expiry + ' IS NULL OR ' + expiry + '>UTC_TIMESTAMP())', 'paused': 'l.active=0 AND l.revoked_at IS NULL', 'revoked': 'l.revoked_at IS NOT NULL', 'expired': expiry + ' IS NOT NULL AND ' + expiry + '<=UTC_TIMESTAMP()', 'expiring': expiry + '>UTC_TIMESTAMP() AND ' + expiry + '<=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 30 DAY)'}
    if status in conditions:
        where.append(conditions[status])
    else:
        status = ''
    for field, operator, suffix in (('created_from', '>=', ' 00:00:00'), ('created_to', '<', ' 00:00:00')):
        value = admin_request_string(data, field)
        if re.fullmatch('\\d{4}-\\d{2}-\\d{2}', value):
            try:
                parse_iso_date(value)
            except ValueError:
                value = ''
        else:
            value = ''
        if value:
            where.append('l.created_at' + operator + ('%s' if field == 'created_from' else 'DATE_ADD(%s,INTERVAL 1 DAY)'))
            args.append(value + suffix)
    offset = admin_page_offset(page, limit)
    sql = 'SELECT l.id,l.tenant_id,l.product_id,t.name AS tenant_name,p.name AS product_name,l.label,l.active,l.max_devices,l.evaluation_days,l.evaluation_started_at,l.expires_at,l.revoked_at,l.deleted_at,l.deleted_reason,l.last_activated_at,l.last_seen_at,l.created_at,l.updated_at,(SELECT COUNT(*) FROM license_devices d WHERE d.license_id=l.id AND d.revoked_at IS NULL AND d.refresh_expires_at>UTC_TIMESTAMP()) AS active_sessions FROM licenses l LEFT JOIN tenants t ON t.id=l.tenant_id LEFT JOIN products p ON p.id=l.product_id WHERE ' + ' AND '.join(where) + ' ORDER BY l.id DESC LIMIT %s OFFSET %s'
    args.extend([limit + 1, offset])
    with connection.cursor() as cursor:
        cursor.execute(sql, tuple(args))
        rows = cursor.fetchall()
    has_next = len(rows) > limit
    items = [admin_license_payload(row, int(row.get('active_sessions', 0) or 0)) for row in rows[:limit]]
    return (items, has_next, page, limit)

@legacy_compatible(callback_index=1, request_index=0)
def _admin_api_request(request_context):
    method = request_context.get('method', 'GET')
    query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
    if query.get('tenant_sso_start', [''])[-1] == '1':
        from admin_oidc import start_tenant
        return start_tenant(request_context)
    if query.get('admin_sso_start', [''])[-1] == '1':
        from admin_oidc import start
        return start(request_context)
    if query.get('admin_sso_callback', [''])[-1] == '1':
        from admin_oidc import callback
        return callback(request_context)
    if method == 'GET' and query.get('oidc_error'):
        messages = {'unconfigured': 'SSO IDログインはまだ設定されていません。', 'expired': 'ログイン要求が期限切れです。もう一度お試しください。', 'state': 'ログイン応答を確認できませんでした。', 'provider': '共通IDログインを完了できませんでした。', 'failed': '共通IDとの接続に失敗しました。設定とサーバーログを確認してください。'}
        return _login_page(request_context, messages.get(query.get('oidc_error', [''])[-1], messages['failed']))
    if method == 'GET' and (not request_context.get('query') or query.get('view', [''])[-1] in {'api-invoices', 'reception', 'help'}):
        return _admin_page(request_context) if _cookie_value(request_context, SESSION_COOKIE) else _login_page(request_context)
    try:
        data = admin_input(request_context)
    except RuntimeError as exc:
        return _error('400 Bad Request', str(exc))
    action = _admin_action(data)
    if not action and method == 'GET':
        return _admin_page(request_context) if _cookie_value(request_context, SESSION_COOKIE) else _login_page(request_context)
    supported = {'list_devices', 'list_sessions', 'revoke_device', 'unrevoke_device', 'logout', 'list_audit_logs', 'clear_attempts', 'revoke_common_id_membership', 'set_admin_role', 'list_licenses', 'list_deleted_licenses', 'list_volume_licenses', 'get_license', 'ping'}
    supported.update({'export_license_csv', 'pause_license', 'resume_license', 'force_reauth_license', 'delete_license', 'restore_license', 'renew_license', 'bulk_license_action', 'permanently_delete_license', 'list_phone_requests', 'get_phone_request', 'cancel_phone_request', 'issue_phone_confirmation_code'})
    supported.update({'create_tenant', 'create_contractor_sso', 'lookup_sso_identity', 'delete_sso_identity', 'issue_tenant_api_key', 'revoke_tenant_api_key', 'rotate_tenant_api_key', 'list_tenant_api_keys', 'list_tenants'})
    supported.add('grant_one_time_issuance')
    supported.add('list_tenant_sso_identities')
    supported.update({'diagnose_error', 'change_admin_password'})
    supported.update({'list_admin_principals', 'list_common_id_memberships'})
    supported.add('list_workbench_tenants')
    supported.update({'create_license', 'update_license'})
    supported.add('import_licenses_csv')
    reception_actions = {'list_reception_intakes', 'create_reception_intake', 'update_reception_intake', 'update_reception_workflow', 'add_reception_note', 'bulk_update_reception_intakes'}
    supported.update(reception_actions)
    if action not in supported:
        return _error('400 Bad Request', '対応していない操作です。')
    write = action in {'revoke_device', 'unrevoke_device', 'logout', 'clear_attempts', 'revoke_common_id_membership', 'set_admin_role', 'pause_license', 'resume_license', 'force_reauth_license'}
    write = write or action in {'delete_license', 'restore_license', 'renew_license', 'bulk_license_action', 'create_license', 'update_license', 'permanently_delete_license', 'import_licenses_csv', 'cancel_phone_request', 'issue_phone_confirmation_code', 'create_tenant', 'create_contractor_sso', 'lookup_sso_identity', 'delete_sso_identity', 'issue_tenant_api_key', 'revoke_tenant_api_key'}
    write = write or action == 'rotate_tenant_api_key'
    write = write or action == 'grant_one_time_issuance'
    write = write or action == 'change_admin_password'
    write = write or action in reception_actions - {'list_reception_intakes'}
    if write and method != 'POST':
        return _error('405 Method Not Allowed', 'State-changing actions require POST.', 'METHOD_NOT_ALLOWED', headers=[('Allow', 'POST')])
    scope = 'passkey:manage' if action == 'diagnose_error' else 'admin:manage' if action in {'revoke_common_id_membership', 'set_admin_role', 'create_tenant', 'create_contractor_sso', 'lookup_sso_identity', 'delete_sso_identity', 'issue_tenant_api_key', 'revoke_tenant_api_key', 'rotate_tenant_api_key', 'list_tenant_api_keys', 'list_tenants', 'list_admin_principals', 'list_common_id_memberships', 'grant_one_time_issuance', 'list_tenant_sso_identities'} else 'audit:read' if action in {'list_audit_logs', 'clear_attempts'} else 'intake:manage' if action in reception_actions or action == 'list_workbench_tenants' else 'phone:manage' if action in {'list_phone_requests', 'get_phone_request', 'cancel_phone_request', 'issue_phone_confirmation_code'} else 'license:write' if action in {'revoke_device', 'unrevoke_device', 'pause_license', 'resume_license', 'force_reauth_license', 'delete_license', 'restore_license', 'renew_license', 'bulk_license_action', 'create_license', 'update_license', 'permanently_delete_license', 'import_licenses_csv'} else 'license:read'
    claims, status, message = _authorize(request_context, data, scope)
    if status:
        return _error(status, message, 'INSUFFICIENT_ROLE' if status == '403 Forbidden' else 'SSO_SESSION_EXPIRED')
    if action in {'change_admin_password', 'create_contractor_sso', 'lookup_sso_identity', 'delete_sso_identity', 'set_admin_role', 'revoke_common_id_membership', 'grant_one_time_issuance'}:
        try:
            issued_at = int(claims.get('reauthenticated_at', 0))
        except (TypeError, ValueError):
            issued_at = 0
        if issued_at < int(time.time()) - 120 or issued_at > int(time.time()) + 60:
            return _error('428 Precondition Required', 'Passkey reauthentication is required.', 'PASSKEY_REAUTH_REQUIRED')
    if action in {'create_contractor_sso', 'lookup_sso_identity', 'delete_sso_identity', 'grant_one_time_issuance', 'list_tenant_sso_identities'} and (not claims.get('oidc_sid')):
        return _error('403 Forbidden', 'SSO IDで再ログインしてから招待してください。', 'OIDC_SESSION_REQUIRED')
    if action in reception_actions:
        return admin_respond('410 Gone', False, '相談受付は終了しました。契約先ごとのAPI操作をご利用ください。', {'error_code': 'RECEPTION_RETIRED'})
    if action == 'logout':
        return _reply('200 OK', {'success': True, 'message': 'ログアウトしました。'}, [('Set-Cookie', SESSION_COOKIE + site_url('=; Path=/license/python-migration/; Max-Age=0; Secure; HttpOnly; SameSite=Strict')), ('Set-Cookie', CSRF_COOKIE + site_url('=; Path=/license/python-migration/; Max-Age=0; Secure; SameSite=Strict'))])
    connection = None
    try:
        connection = database.connect()
        if action == 'list_tenant_sso_identities':
            tenant_id = admin_request_int(data, 'tenant_id', 0, 1, 9223372036854775807)
            with connection.cursor() as cursor:
                cursor.execute("CREATE TABLE IF NOT EXISTS tenant_sso_temporary_grants (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,grant_id CHAR(32) NOT NULL,subject_hash CHAR(64) NOT NULL,tenant_id BIGINT UNSIGNED NOT NULL,source_client_id BIGINT UNSIGNED NOT NULL,scopes_json TEXT NOT NULL,granted_by CHAR(64) NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,expires_at DATETIME NOT NULL,issue_request_key VARCHAR(80) DEFAULT NULL,session_token_hash CHAR(64) DEFAULT NULL,consumed_at DATETIME DEFAULT NULL,revoked_at DATETIME DEFAULT NULL,PRIMARY KEY(id),UNIQUE KEY uq_tenant_sso_temporary_grant_id(grant_id),KEY idx_tenant_sso_temporary_subject(subject_hash,tenant_id,expires_at,revoked_at),KEY idx_tenant_sso_temporary_session(session_token_hash),KEY idx_tenant_sso_temporary_expiry(expires_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci")
                cursor.execute("SELECT id FROM tenants WHERE id=%s AND status='active' AND environment='production' AND parent_tenant_id IS NULL LIMIT 1", (tenant_id,))
                if not cursor.fetchone():
                    return admin_respond('400 Bad Request', False, '有効な本番契約を選択してください。')
                cursor.execute("SELECT subject_hash FROM tenant_sso_memberships WHERE tenant_id=%s UNION SELECT subject_hash FROM tenant_sso_temporary_grants WHERE tenant_id=%s AND expires_at>UTC_TIMESTAMP() AND revoked_at IS NULL ORDER BY subject_hash LIMIT 200", (tenant_id, tenant_id))
                subject_hashes = [str(row['subject_hash']) for row in cursor.fetchall() if re.fullmatch('[a-f0-9]{64}', str(row.get('subject_hash') or ''))]
            if not subject_hashes:
                return admin_respond('200 OK', True, 'この契約に所属するSSO IDはありません。', {'identities': []})
            try:
                from admin_oidc import list_sso_identities_for_subjects
                identities = list_sso_identities_for_subjects(str(claims.get('oidc_sid') or ''), subject_hashes)
            except Exception:
                return admin_respond('502 Bad Gateway', False, '契約に所属するSSO IDを取得できませんでした。時間をおいて再度お試しください。')
            allowed = set(subject_hashes)
            rows = [{'public_id': str(row.get('public_id') or ''), 'display_name': str(row.get('display_name') or '')}
                    for row in identities if str(row.get('subject_hash') or '') in allowed and re.fullmatch('SID-[A-Z2-7]{26}', str(row.get('public_id') or ''))]
            rows.sort(key=lambda row: (row['public_id'], row['display_name']))
            return admin_respond('200 OK', True, '契約に所属するSSO IDを取得しました。', {'identities': rows})
        if action == 'grant_one_time_issuance':
            tenant_id = admin_request_int(data, 'tenant_id', 0, 1, 9223372036854775807)
            target_public_id = admin_request_string(data, 'target_public_id').strip().upper()
            if not re.fullmatch('SID-[A-Z2-7]{26}', target_public_id):
                return admin_respond('400 Bad Request', False, '付与先のSSO IDを確認してください。')
            from admin_oidc import ISSUER, resolve_sso_identity
            try:
                identity = resolve_sso_identity(str(claims['oidc_sid']), target_public_id)
            except RuntimeError as exc:
                if 'not_found' in str(exc):
                    return admin_respond('404 Not Found', False, '指定したSSO IDが見つからないか、利用できません。')
                return admin_respond('502 Bad Gateway', False, 'SSO IDを確認できませんでした。再ログイン後にやり直してください。')
            subject = hashlib.sha256((ISSUER + '\0' + identity['sub']).encode('utf-8')).hexdigest()
            actor = str(claims.get('credential_id_hash') or '')
            if not re.fullmatch('[a-f0-9]{64}', actor):
                return admin_respond('403 Forbidden', False, '管理者セッションを確認できません。')
            with connection.cursor() as cursor:
                cursor.execute("CREATE TABLE IF NOT EXISTS tenant_sso_temporary_grants (id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,grant_id CHAR(32) NOT NULL,subject_hash CHAR(64) NOT NULL,tenant_id BIGINT UNSIGNED NOT NULL,source_client_id BIGINT UNSIGNED NOT NULL,scopes_json TEXT NOT NULL,granted_by CHAR(64) NOT NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,expires_at DATETIME NOT NULL,issue_request_key VARCHAR(80) DEFAULT NULL,session_token_hash CHAR(64) DEFAULT NULL,consumed_at DATETIME DEFAULT NULL,revoked_at DATETIME DEFAULT NULL,PRIMARY KEY(id),UNIQUE KEY uq_tenant_sso_temporary_grant_id(grant_id),KEY idx_tenant_sso_temporary_subject(subject_hash,tenant_id,expires_at,revoked_at),KEY idx_tenant_sso_temporary_session(session_token_hash),KEY idx_tenant_sso_temporary_expiry(expires_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci")
                cursor.execute("SELECT id,name,slug FROM tenants WHERE id=%s AND status='active' AND environment='production' AND parent_tenant_id IS NULL LIMIT 1", (tenant_id,))
                tenant = cursor.fetchone()
                if not tenant:
                    return admin_respond('400 Bad Request', False, '有効な本番契約を選択してください。')
                cursor.execute('SELECT 1 FROM tenant_sso_memberships WHERE subject_hash=%s AND tenant_id=%s UNION SELECT 1 FROM tenant_sso_temporary_grants WHERE subject_hash=%s AND tenant_id=%s AND expires_at>UTC_TIMESTAMP() AND revoked_at IS NULL LIMIT 1', (subject, tenant_id, subject, tenant_id))
                if not cursor.fetchone():
                    return admin_respond('403 Forbidden', False, '指定したSSO IDは選択した契約に所属していません。')
                cursor.execute("SELECT id,scopes_json FROM tenant_api_clients WHERE tenant_id=%s AND status='active' AND key_hash IS NOT NULL AND key_hash<>'' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP()) ORDER BY id DESC LIMIT 100", (tenant_id,))
                clients = cursor.fetchall()
            from baas_handlers import _auth_scopes
            client = next((row for row in clients if {'tenant:read', 'licenses:write'}.issubset(set(_auth_scopes(row.get('scopes_json'))))), None)
            if not client:
                return admin_respond('409 Conflict', False, 'この契約に有効なライセンス発行APIクライアントがありません。')
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute("SELECT grant_id FROM tenant_sso_temporary_grants WHERE subject_hash=%s AND tenant_id=%s AND expires_at>UTC_TIMESTAMP() AND revoked_at IS NULL LIMIT 1 FOR UPDATE", (subject, tenant_id))
                if cursor.fetchone():
                    connection.rollback()
                    return admin_respond('409 Conflict', False, 'このSSO IDには対象契約の未失効な1回限り権限があります。先にその権限を使用してください。')
                grant_id = secrets.token_hex(16)
                cursor.execute("INSERT INTO tenant_sso_temporary_grants(grant_id,subject_hash,tenant_id,source_client_id,scopes_json,granted_by,created_at,expires_at) VALUES(%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP()+INTERVAL 24 HOUR)", (grant_id, subject, tenant_id, int(client['id']), '[\"tenant:read\",\"licenses:write\"]', actor))
            _audit_write(connection, request_context, 'tenant_one_time_issuance_granted', tenant_id, None, {}, {'grant_id': grant_id, 'target_public_id': identity.get('public_id', ''), 'source_client_id': int(client['id']), 'expires_in_hours': 24}, claims, target_type='tenant_sso_temporary_grant', target_id=grant_id)
            connection.commit()
            return admin_respond('200 OK', True, '指定したSSO IDに今回1件のライセンス発行権限を付与しました。1件発行すると自動失効します。', {'grant_id': grant_id, 'target_public_id': identity['public_id'], 'tenant_id': tenant_id, 'tenant_name': str(tenant['name']), 'expires_in_hours': 24})
        if action == 'create_contractor_sso':
            email = str(data.get('contractor_email', '')).strip()
            tenant_id = admin_request_int(data, 'tenant_id', 0, 1, 9223372036854775807)
            email_pattern = "^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
            if len(email) > 254 or '\r' in email or '\n' in email or (re.fullmatch(email_pattern, email) is None):
                return admin_respond('400 Bad Request', False, '契約者のメールアドレスを確認してください。')
            with connection.cursor() as cursor:
                cursor.execute("SELECT id FROM tenants WHERE id=%s AND status='active' LIMIT 1", (tenant_id,))
                if not cursor.fetchone():
                    return admin_respond('400 Bad Request', False, 'An active tenant must be selected.')
            from admin_oidc import invite_contractor
            try:
                result = invite_contractor(str(claims['oidc_sid']), email.lower(), tenant_id)
            except RuntimeError as exc:
                status_code = '503 Service Unavailable' if 'unconfigured' in str(exc) else '502 Bad Gateway'
                return admin_respond(status_code, False, '招待メールを送信できませんでした。SSO設定と配信状態を確認してください。')
            if result.get('ok') is not True:
                return admin_respond('502 Bad Gateway', False, '招待メールを送信できませんでした。時間をおいて再度お試しください。')
            email_hash = hmac.new(key_pepper({'key_pepper': secret_value('key_pepper')}).encode(), email.lower().encode(), hashlib.sha256).hexdigest()
            _audit_write(connection, request_context, action, tenant_id, None, {}, {'email_hash': email_hash, 'tenant_id': tenant_id}, claims, target_type='contractor_sso_invite', target_id=str(tenant_id))
            return admin_respond('200 OK', True, '招待メールを送信しました。受信者がメール確認とパスキー登録を終えるとSSO IDが有効になります。')
        if action in {'lookup_sso_identity', 'delete_sso_identity'}:
            email = str(data.get('identity_email', '')).strip().lower()
            email_pattern = "^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
            if len(email) > 254 or re.fullmatch(email_pattern, email) is None:
                return admin_respond('400 Bad Request', False, '登録済みメールアドレスを確認してください。')
            from admin_oidc import delete_sso_identity, lookup_sso_identity
            try:
                if action == 'lookup_sso_identity':
                    result = lookup_sso_identity(str(claims['oidc_sid']), email)
                else:
                    public_id = str(data.get('public_id', '')).strip().upper()
                    if not re.fullmatch(r'SID-[A-Z2-7]{26}', public_id) or str(data.get('confirm_public_id', '')).strip().upper() != public_id:
                        return admin_respond('400 Bad Request', False, '表示されたSSO IDを正確に再入力してください。')
                    result = delete_sso_identity(str(claims['oidc_sid']), email, public_id)
            except RuntimeError:
                return admin_respond('502 Bad Gateway', False, 'SSO IDサービスへ接続できませんでした。設定と接続状態を確認してください。')
            if result.get('error') == 'protected_administrator':
                return admin_respond('403 Forbidden', False, '管理者アカウントは削除できません。')
            if result.get('error') == 'ambiguous_identity':
                return admin_respond('409 Conflict', False, '一致するアカウントが複数あります。サポート窓口で確認してください。')
            if action == 'lookup_sso_identity':
                email_hash = hmac.new(key_pepper({'key_pepper': secret_value('key_pepper')}).encode(), email.encode(), hashlib.sha256).hexdigest()
                _audit_write(connection, request_context, action, 0, None, {}, {'email_hash': email_hash, 'found': bool(result.get('found'))}, claims, target_type='sso_identity_lookup', target_id=email_hash[:24])
                if result.get('ok') is not True:
                    return admin_respond('502 Bad Gateway', False, '照合できませんでした。時間をおいて再度お試しください。')
                return admin_respond('200 OK', True, '一致するSSO IDが見つかりました。' if result.get('found') else '一致するSSO IDは見つかりませんでした。', {'identity': result.get('identity') if result.get('found') else None})
            if result.get('ok') is not True or result.get('deleted') is not True:
                return admin_respond('502 Bad Gateway', False, 'アカウントを削除できませんでした。検索結果とメールアドレスを確認してください。')
            email_hash = hmac.new(key_pepper({'key_pepper': secret_value('key_pepper')}).encode(), email.encode(), hashlib.sha256).hexdigest()
            _audit_write(connection, request_context, action, 0, None, {}, {'email_hash': email_hash}, claims, target_type='sso_identity', target_id=public_id)
            return admin_respond('200 OK', True, 'アカウントと認証情報を削除し、すべてのSSOセッションを失効しました。同じメールアドレスで再登録できます。')
        if action == 'change_admin_password':
            current = str(data.get('current_password', '')).strip()
            new_password = str(data.get('new_password', ''))
            confirmation = str(data.get('new_password_confirm', ''))
            if not current or not new_password or (not confirmation):
                return admin_respond('400 Bad Request', False, '現在のパスワードと新しいパスワードが必要です。')
            if new_password != confirmation:
                return admin_respond('400 Bad Request', False, '新しいパスワードが一致しません。')
            new_password = new_password.strip()
            if len(new_password.encode('utf-8')) < 12:
                return admin_respond('403 Forbidden', False, '新しいパスワードは12文字以上にしてください。')
            configured_hash = secret_value('admin_password_hash').strip()
            try:
                import bcrypt
                if configured_hash:
                    try:
                        valid = bcrypt.checkpw(current.encode('utf-8')[:72], configured_hash.encode('ascii'))
                    except (ValueError, UnicodeEncodeError):
                        valid = False
                else:
                    expected = (os.environ.get('PYTHON_MIGRATION_LICENSE_API_PASSWORD', '') or os.environ.get('LICENSE_API_PASSWORD', '')).strip()
                    valid = bool(expected) and hmac.compare_digest(current, expected)
                if not valid:
                    return admin_respond('403 Forbidden', False, '管理用パスワードが一致しません。')
                new_hash = bcrypt.hashpw(new_password.encode('utf-8')[:72], bcrypt.gensalt()).decode('ascii')
                from migration_config import set_runtime_secret
                set_runtime_secret('admin_password_hash', new_hash)
            except ImportError:
                return admin_respond('503 Service Unavailable', False, 'bcrypt検証機能が利用できません。')
            except Exception:
                return admin_respond('503 Service Unavailable', False, '管理者パスワードを隔離設定へ保存できませんでした。')
            _audit_write(connection, request_context, action, 0, None, {}, {'changed': True}, claims)
            return admin_respond('200 OK', True, '管理者パスワードを変更しました。')
        if action == 'diagnose_error':
            error_id, diagnostic = _diagnose_error(connection, data.get('error_id'))
            return admin_respond('200 OK' if diagnostic else '404 Not Found', diagnostic is not None, 'エラー情報を取得しました。' if diagnostic else '該当するサーバーログが見つかりません。', {'error_id': error_id, 'diagnostic': diagnostic})
        if action == 'list_tenant_api_keys':
            page = admin_request_int(data, 'page', 1, 1, 100000)
            limit = admin_request_int(data, 'limit', 25, 1, 100)
            offset = admin_page_offset(page, limit)
            with connection.cursor() as cursor:
                cursor.execute("SELECT id,name FROM tenants WHERE status='active' ORDER BY name,id")
                tenants = cursor.fetchall()
                cursor.execute('SELECT c.id,c.tenant_id,c.name,c.key_prefix,c.scopes_json,c.status,c.rate_limit_per_minute,c.last_used_at,c.expires_at,c.created_at,c.revoked_at,t.name AS tenant_name,t.slug AS tenant_slug FROM tenant_api_clients c JOIN tenants t ON t.id=c.tenant_id ORDER BY c.id DESC LIMIT %s OFFSET %s', (limit + 1, offset))
                rows = cursor.fetchall()
            has_next = len(rows) > limit
            rows = rows[:limit]
            return admin_respond('200 OK', True, 'テナントAPIクライアント一覧を取得しました。', {'tenants': tenants, 'api_clients': _json_safe(rows), 'page': page, 'limit': limit, 'has_next': has_next})
        if action == 'list_admin_principals':
            with connection.cursor() as cursor:
                cursor.execute("SELECT id,display_name,role_name,last_login_at FROM admin_principals WHERE status='active' AND revoked_at IS NULL ORDER BY id DESC LIMIT 100")
                rows = cursor.fetchall()
            return admin_respond('200 OK', True, '有効な管理者一覧を取得しました。', {'admin_principals': _json_safe(rows)})
        if action == 'list_common_id_memberships':
            with connection.cursor() as cursor:
                cursor.execute('SELECT COUNT(*) AS n FROM tenant_sso_memberships')
                total = int((cursor.fetchone() or {}).get('n', 0))
                cursor.execute("SELECT COUNT(DISTINCT m.subject_hash) AS n FROM tenant_sso_memberships m JOIN tenants t ON t.id=m.tenant_id AND t.status='active'")
                identities = int((cursor.fetchone() or {}).get('n', 0))
                cursor.execute('SELECT m.subject_hash,m.created_at membership_created_at,t.id tenant_id,t.name tenant_name,t.slug tenant_slug,t.status tenant_status,(SELECT MAX(s.last_used_at) FROM tenant_sso_sessions s WHERE s.subject_hash=m.subject_hash AND s.tenant_id=m.tenant_id) last_used_at FROM tenant_sso_memberships m JOIN tenants t ON t.id=m.tenant_id ORDER BY m.created_at DESC,m.subject_hash,m.tenant_id LIMIT 200')
                rows = cursor.fetchall()
            return admin_respond('200 OK', True, '共通IDの所属一覧を取得しました。', {'identity_total': identities, 'membership_total': total, 'memberships': _json_safe(rows), 'has_more': total > len(rows)})
        if action == 'list_tenants':
            page = admin_request_int(data, 'page', 1, 1, 100000)
            limit = admin_request_int(data, 'limit', 100, 1, 100)
            offset = admin_page_offset(page, limit)
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,name,slug,status,environment,plan_code,max_products,max_licenses FROM tenants ORDER BY name,id LIMIT %s OFFSET %s', (limit + 1, offset))
                rows = cursor.fetchall()
            has_next = len(rows) > limit
            rows = rows[:limit]
            return admin_respond('200 OK', True, '契約先一覧を取得しました。', {'tenants': _json_safe(rows), 'page': page, 'limit': limit, 'has_next': has_next})
        if action == 'list_workbench_tenants':
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,slug,name,status,environment,parent_tenant_id FROM tenants ORDER BY name,id LIMIT 1000')
                rows = cursor.fetchall()
            tenants = _json_safe(rows)
            default_id = 0
            for tenant in tenants:
                environment = 'sandbox' if tenant.get('parent_tenant_id') or str(tenant.get('environment', '')).lower() == 'sandbox' else str(tenant.get('environment', '')).lower()
                if tenant.get('status') == 'active' and environment in {'production', 'sandbox'}:
                    default_id = int(tenant['id'])
                    break
            return admin_respond('200 OK', True, '業務APIの契約先一覧を取得しました。', {'tenants': tenants, 'default_tenant_id': default_id})
        if action == 'create_tenant':
            slug = admin_request_string(data, 'tenant_slug').lower()
            name = admin_request_string(data, 'tenant_name')
            plan = admin_request_string(data, 'plan_code') or 'standard'
            plans = {'trial': (1, 100), 'standard': (5, 1000), 'business': (20, 10000), 'enterprise': (100, 100000)}
            if not re.fullmatch('[a-z0-9][a-z0-9-]{1,62}', slug) or not name or len(name) > 160 or (plan not in plans):
                return admin_respond('400 Bad Request', False, '入力内容を確認してください。テナント名、slug、プランが不正です。')
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    cursor.execute('INSERT INTO tenants(slug,name,plan_code,max_products,max_licenses) VALUES(%s,%s,%s,%s,%s)', (slug, name, plan, *plans[plan]))
                    tenant_id = int(getattr(cursor, 'lastrowid', 0) or 0)
                    cursor.execute("INSERT INTO products(tenant_id,code,name,status) VALUES(%s,'default',%s,'active')", (tenant_id, (name + ' Default Product')[:160]))
                    product_id = int(getattr(cursor, 'lastrowid', 0) or 0)
                _audit_write(connection, request_context, action, tenant_id, None, {}, {'slug': slug, 'plan_code': plan, 'product_id': product_id}, claims, target_type='tenant', target_id=tenant_id)
                connection.commit()
            except Exception:
                connection.rollback()
                return admin_respond('409 Conflict', False, 'このテナントIDは既に使用されているか、作成できませんでした。')
            return admin_respond('201 Created', True, 'テナントを作成しました。', {'tenant_id': tenant_id, 'product_id': product_id})
        if action == 'issue_tenant_api_key':
            tenant_id = admin_request_int(data, 'tenant_id', 0, 1, 2 ** 63 - 1)
            name = admin_request_string(data, 'client_name')
            allowed = {'tenant:read', 'products:write', 'licenses:read', 'licenses:write'}
            raw_scopes = data.get('scopes', [])
            if isinstance(raw_scopes, str):
                raw_scopes = re.split('\\s*,\\s*', raw_scopes.strip(' \t\n\r\x00\x0b'), flags=re.ASCII)
            scopes = list(dict.fromkeys((str(value) for value in raw_scopes if str(value) in allowed))) if isinstance(raw_scopes, list) else []
            if not tenant_id or not name or len(name) > 120 or (not scopes):
                return admin_respond('400 Bad Request', False, 'APIキーの対象テナント、名前、権限スコープを確認してください。')
            with connection.cursor() as cursor:
                cursor.execute("SELECT environment,parent_tenant_id FROM tenants WHERE id=%s AND status='active' LIMIT 1", (tenant_id,))
                tenant = cursor.fetchone()
            if not tenant:
                return admin_respond('404 Not Found', False, '対象テナントが見つからないか、停止中です。')
            env_name = str(tenant.get('environment') or '').lower()
            environment = 'sandbox' if tenant.get('parent_tenant_id') or env_name == 'sandbox' else 'production' if env_name == 'production' else 'unknown'
            if environment == 'unknown':
                return admin_respond('409 Conflict', False, '対象テナントの環境を判定できません。')
            pepper = secret_value('key_pepper')
            if len(pepper) < 32:
                raise database.DatabaseConfigurationError('test key pepper is not configured')
            secret = base64.urlsafe_b64encode(__import__('secrets').token_bytes(32)).decode().rstrip('=')
            api_key = ('baas_sandbox_' if environment == 'sandbox' else 'baas_prod_') + secret
            rate = admin_request_int(data, 'rate_limit_per_minute', 120, 10, 10000)
            expiry_text = admin_request_string(data, 'api_key_expires_at')
            expiry = None
            if expiry_text:
                try:
                    expiry_dt = datetime.strptime(expiry_text, '%Y-%m-%dT%H:%M').replace(tzinfo=timezone.utc)
                except ValueError:
                    return admin_respond('400 Bad Request', False, 'APIキーの有効期限は、未来のUTC日時を指定してください。')
                if expiry_dt <= datetime.now(timezone.utc):
                    return admin_respond('400 Bad Request', False, 'APIキーの有効期限は、未来のUTC日時を指定してください。')
                expiry = expiry_dt.strftime('%Y-%m-%d %H:%M:%S')
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            with connection.cursor() as cursor:
                cursor.execute('INSERT INTO tenant_api_clients(tenant_id,name,key_prefix,key_hash,scopes_json,rate_limit_per_minute,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s)', (tenant_id, name, api_key[:12], hmac.new(pepper.encode(), api_key.encode(), hashlib.sha256).hexdigest(), json.dumps(scopes, separators=(',', ':')), rate, expiry))
                client_id = int(getattr(cursor, 'lastrowid', 0) or 0)
            _audit_write(connection, request_context, action, client_id, None, {}, {'tenant_id': tenant_id, 'key_prefix': api_key[:12], 'scopes': scopes}, claims, target_type='tenant_api_client', target_id=client_id)
            connection.commit()
            from ha_handlers import ha_sync_peer
            ha_sync_peer('tenant_api_key_issued', request_context)
            return admin_respond('201 Created', True, 'テナントAPIキーを発行しました。', {'key': api_key, 'client_id': client_id, 'tenant_id': tenant_id, 'name': name, 'scopes': scopes, 'expires_at': expiry})
        if action == 'revoke_tenant_api_key':
            client_id = admin_request_int(data, 'client_id', 0, 1, 2 ** 63 - 1)
            if not client_id:
                return admin_respond('400 Bad Request', False, '失効するAPIクライアントを確認してください。')
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            with connection.cursor() as cursor:
                cursor.execute("UPDATE tenant_api_clients SET status='revoked',revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()) WHERE id=%s AND revoked_at IS NULL", (client_id,))
                changed = int(cursor.rowcount or 0)
                cursor.execute('SELECT tenant_id,key_prefix FROM tenant_api_clients WHERE id=%s', (client_id,))
                client = cursor.fetchone() or {}
            if not changed:
                return admin_respond('404 Not Found', False, 'APIキーは既に失効しているか、見つかりません。')
            _audit_write(connection, request_context, action, client_id, None, {}, {'revoked': True}, claims, target_type='tenant_api_client', target_id=client_id)
            connection.commit()
            from ha_handlers import ha_sync_peer
            ha_sync_peer('tenant_api_key_revoked', request_context)
            return admin_respond('200 OK', True, 'テナントAPIキーを失効しました。', {'client_id': client_id, 'tenant_id': client.get('tenant_id')})
        if action == 'rotate_tenant_api_key':
            client_id = admin_request_int(data, 'client_id', 0, 1, 2 ** 63 - 1)
            if not client_id:
                return admin_respond('400 Bad Request', False, 'ローテーションするAPIクライアントを確認してください。')
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            pepper = secret_value('key_pepper')
            if len(pepper) < 32:
                raise database.DatabaseConfigurationError('test key pepper is not configured')
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT c.tenant_id,c.name,c.scopes_json,c.rate_limit_per_minute,c.expires_at,t.environment,t.parent_tenant_id,t.status AS tenant_status FROM tenant_api_clients c JOIN tenants t ON t.id=c.tenant_id WHERE c.id=%s AND c.status='active' AND c.revoked_at IS NULL FOR UPDATE", (client_id,))
                    old = cursor.fetchone()
                if not old or str(old.get('tenant_status')) != 'active':
                    raise ValueError('有効なテナントのAPIキーだけローテーションできます。')
                env_name = str(old.get('environment') or '').lower()
                environment = 'sandbox' if old.get('parent_tenant_id') or env_name == 'sandbox' else 'production'
                allowed = {'tenant:read', 'products:write', 'licenses:read', 'licenses:write'}
                try:
                    decoded = json.loads(old.get('scopes_json') or '[]')
                except (ValueError, TypeError):
                    decoded = []
                scopes = list(dict.fromkeys((str(value) for value in decoded if str(value) in allowed))) if isinstance(decoded, list) else []
                if not scopes:
                    raise ValueError('APIキーの権限を読み取れないためローテーションできません。')
                expiry = parse_utc_datetime(str(old.get('expires_at') or ''))
                now = datetime.now(timezone.utc).replace(tzinfo=None)
                if expiry is None or expiry.replace(tzinfo=None) <= now:
                    expiry = now + timedelta(days=90)
                secret = base64.urlsafe_b64encode(__import__('secrets').token_bytes(32)).decode().rstrip('=')
                api_key = ('baas_sandbox_' if environment == 'sandbox' else 'baas_prod_') + secret
                prefix = api_key[:12]
                name = (str(old.get('name') or '') + ' rotated')[:120]
                expiry_value = expiry.strftime('%Y-%m-%d %H:%M:%S')
                rate = max(10, min(10000, int(old.get('rate_limit_per_minute') or 120)))
                with connection.cursor() as cursor:
                    cursor.execute('INSERT INTO tenant_api_clients(tenant_id,name,key_prefix,key_hash,scopes_json,rate_limit_per_minute,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s)', (int(old['tenant_id']), name, prefix, hmac.new(pepper.encode(), api_key.encode(), hashlib.sha256).hexdigest(), json.dumps(scopes, separators=(',', ':')), rate, expiry_value))
                    new_client_id = int(getattr(cursor, 'lastrowid', 0) or 0)
                grace = admin_request_int(data, 'grace_minutes', 60, 0, 10080)
                grace_expiry = None if grace == 0 else (datetime.now(timezone.utc) + timedelta(minutes=grace)).strftime('%Y-%m-%d %H:%M:%S')
                with connection.cursor() as cursor:
                    if grace == 0:
                        cursor.execute("UPDATE tenant_api_clients SET status='revoked',revoked_at=UTC_TIMESTAMP(),replacement_client_id=%s WHERE id=%s", (new_client_id, client_id))
                    else:
                        cursor.execute("UPDATE tenant_api_clients SET status='retiring',grace_expires_at=%s,replacement_client_id=%s WHERE id=%s", (grace_expiry, new_client_id, client_id))
                _audit_write(connection, request_context, action, client_id, None, {'status': 'active'}, {'replacement_client_id': new_client_id, 'grace_minutes': grace}, claims, target_type='tenant_api_client', target_id=client_id)
                connection.commit()
            except ValueError as exc:
                connection.rollback()
                return admin_respond('400 Bad Request', False, str(exc))
            except Exception:
                connection.rollback()
                return admin_respond('503 Service Unavailable', False, 'APIキーをローテーションできませんでした。')
            from ha_handlers import ha_sync_peer
            ha_sync_peer('tenant_api_key_rotated', request_context)
            return admin_respond('201 Created', True, 'テナントAPIキーをローテーションしました。', {'key': api_key, 'client_id': new_client_id, 'replaced_client_id': client_id, 'tenant_id': int(old['tenant_id']), 'name': name, 'scopes': scopes, 'expires_at': expiry_value, 'grace_expires_at': grace_expiry})
        if action in {'list_phone_requests', 'get_phone_request', 'cancel_phone_request', 'issue_phone_confirmation_code'}:
            from phone_admin_handlers import _expire, _issue_code
            from admin_core import admin_phone_request_payload
            _expire(connection)
            if action == 'list_phone_requests':
                q = admin_request_string(data, 'q')
                page = admin_request_int(data, 'page', 1, 1, 100000)
                limit = admin_request_int(data, 'limit', 25, 1, 100)
                where, args = ('', [])
                if q:
                    where = 'WHERE (CAST(id AS CHAR) LIKE %s OR installation_id LIKE %s OR device_label LIKE %s OR status LIKE %s)'
                    args = [admin_like_value(q)] * 4
                args.extend([limit + 1, admin_page_offset(page, limit)])
                with connection.cursor() as cursor:
                    cursor.execute('SELECT id,license_id,installation_id,device_label,app_version,status,requested_at,expires_at,confirmation_code_expires_at,confirmed_at,last_seen_at,email_masked,email_sent_at FROM phone_activation_requests ' + where + ' ORDER BY id DESC LIMIT %s OFFSET %s', tuple(args))
                    rows = cursor.fetchall()
                has_next = len(rows) > limit
                values = [admin_phone_request_payload(row) for row in rows[:limit]]
                return admin_respond('200 OK', True, '電話認証リクエスト一覧を取得しました。', {'requests': values, 'page': page, 'limit': limit, 'has_next': has_next})
            installation_id = admin_request_string(data, 'installation_id')
            if not installation_id:
                return admin_respond('400 Bad Request', False, 'installation_id が必要です。')
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM phone_activation_requests WHERE installation_id=%s LIMIT 1', (installation_id,))
                request = cursor.fetchone()
            if not request:
                return admin_respond('404 Not Found', False, 'installation ID が見つかりません。')
            if action == 'get_phone_request':
                return admin_respond('200 OK', True, '電話認証リクエストを取得しました。', {'request': admin_phone_request_payload(request)})
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            if action == 'cancel_phone_request':
                with connection.cursor() as cursor:
                    cursor.execute("UPDATE phone_activation_requests SET status='cancelled',cancelled_at=UTC_TIMESTAMP(),cancelled_reason=%s WHERE id=%s AND confirmed_at IS NULL", ('admin_cancelled', int(request['id'])))
                _audit_write(connection, request_context, action, int(request['id']), int(request['license_id']), {'status': request.get('status')}, {'status': 'cancelled'}, claims, target_type='phone_activation_request', target_id=request['id'])
                connection.commit()
                return admin_respond('200 OK', True, '電話認証リクエストを取消しました。')
            if not __import__('phone_admin_handlers')._valid_request(request):
                return admin_respond('400 Bad Request', False, 'このリクエストは有効ではありません。')
            from core import phone_email_decrypt, format_grouped_digits
            from v2_handlers import _runtime_config
            config = _runtime_config()
            email_sent = php_bool_cast(request.get('email_enc'))
            email = phone_email_decrypt(config, str(request['email_enc'])) if email_sent else ''
            try:
                code = _issue_code(connection, config, request, email)
            except RuntimeError as exc:
                return admin_respond('400 Bad Request', False, str(exc))
            _audit_write(connection, request_context, action, int(request['id']), int(request['license_id']), {}, {'issued': True}, claims, target_type='phone_activation_request', target_id=request['id'])
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM phone_activation_requests WHERE installation_id=%s LIMIT 1', (installation_id,))
                updated = cursor.fetchone() or request
            return admin_respond('200 OK', True, '確認コードをメールで再送しました。' if email_sent else 'confirmation code を発行しました。', {'request': admin_phone_request_payload(updated), 'confirmation_code': None if email_sent else format_grouped_digits(code)})
        if action == 'ping':
            return admin_respond('200 OK', True, '管理APIに接続しました。', {'server_time': datetime.now(timezone.utc).isoformat(timespec='seconds')})
        if action in {'list_licenses', 'list_deleted_licenses', 'list_volume_licenses'}:
            deleted = action == 'list_deleted_licenses'
            items, has_next, page, limit = _list_admin_licenses(connection, data, deleted=deleted, volume=action == 'list_volume_licenses')
            message = '削除済みライセンス一覧を取得しました。' if deleted else 'ボリュームライセンス一覧を取得しました。' if action == 'list_volume_licenses' else '一覧を取得しました。'
            return admin_respond('200 OK', True, message, {'licenses': items, 'page': page, 'limit': limit, 'has_next': has_next})
        if action == 'get_license':
            row = _license(connection, data)
            if not row:
                return admin_respond('404 Not Found', False, 'キーが見つかりません。')
            count = _active_count(connection, int(row['id']))
            return admin_respond('200 OK', True, 'キーを取得しました。', {'license': admin_license_payload(row, count), 'usage': {'active_sessions': count, 'license_mode': admin_license_payload(row).get('license_mode')}})
        if action == 'export_license_csv':
            raw = admin_request_string(data, 'license_ids')
            ids = []
            for item in raw.split(','):
                try:
                    value = int(item.strip())
                except ValueError:
                    continue
                if value > 0 and value not in ids:
                    ids.append(value)
            if not ids or len(ids) > 200:
                return admin_respond('400 Bad Request', False, 'CSV出力対象を1〜200件選択してください。')
            marks = ','.join(['%s'] * len(ids))
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,label,active,max_devices,evaluation_days,expires_at,revoked_at,created_at,last_activated_at,last_seen_at FROM licenses WHERE deleted_at IS NULL AND id IN (' + marks + ') ORDER BY id DESC', tuple(ids))
                rows = cursor.fetchall()
            _audit_write(connection, request_context, 'export_license_csv', 0, None, {'selected': len(ids)}, {'exported': len(rows)}, claims, target_type='license_export', target_id='csv')
            connection.commit()
            return _csv_reply(rows)
        if action in {'pause_license', 'resume_license', 'force_reauth_license'}:
            row = _license(connection, data)
            if not row:
                return admin_respond('404 Not Found', False, 'キーが見つかりません。')
            license_id = int(row['id'])
            from v3_handlers import _assert_write_fence
            from baas_handlers import _revoke_license_devices
            _assert_write_fence(connection)
            if action == 'pause_license' and (not php_bool_cast(row.get('active', 0))):
                count = _active_count(connection, license_id)
                return admin_respond('200 OK', True, 'ライセンスはすでに一時停止されています。', {'license': admin_license_payload(row, count)})
            if action == 'resume_license' and php_bool_cast(row.get('active', 0)) and (not row.get('revoked_at')):
                count = _active_count(connection, license_id)
                return admin_respond('200 OK', True, 'ライセンスはすでに有効です。', {'license': admin_license_payload(row, count)})
            connection.begin()
            revoked = 0
            with connection.cursor() as cursor:
                if action in {'pause_license', 'force_reauth_license'}:
                    revoked = _revoke_license_devices(connection, license_id)
                if action == 'pause_license':
                    cursor.execute('UPDATE licenses SET active=0 WHERE id=%s AND deleted_at IS NULL', (license_id,))
                    message = 'ライセンスを一時停止しました。'
                elif action == 'resume_license':
                    cursor.execute('UPDATE licenses SET active=1,revoked_at=NULL WHERE id=%s AND deleted_at IS NULL', (license_id,))
                    message = 'ライセンスを再有効化しました。'
                else:
                    message = '全端末を強制再認証しました。'
            after = {'active': 0, 'revoked_devices': revoked} if action == 'pause_license' else {'active': 1, 'device_sessions': 'reauthentication_required'} if action == 'resume_license' else {'device_sessions': 'reauthentication_required', 'revoked_devices': revoked}
            _audit_write(connection, request_context, action, license_id, license_id, {'active': int(row.get('active', 0)), 'revoked_at': row.get('revoked_at')}, after, claims, target_type='license', target_id=license_id)
            connection.commit()
            updated = dict(row)
            if action == 'pause_license':
                updated['active'] = 0
            elif action == 'resume_license':
                updated['active'], updated['revoked_at'] = (1, None)
            extra = {'license': admin_license_payload(updated, 0 if action != 'resume_license' else _active_count(connection, license_id))}
            if action != 'resume_license':
                extra['revoked_devices'] = revoked
            return admin_respond('200 OK', True, message, extra)
        if action == 'delete_license':
            row = _license(connection, data)
            if not row:
                return admin_respond('404 Not Found', False, 'キーが見つかりません。')
            license_id = int(row['id'])
            reason = admin_request_string(data, 'reason')[:200] or 'administrator_request'
            from v3_handlers import _assert_write_fence
            from baas_handlers import _revoke_license_devices
            _assert_write_fence(connection)
            connection.begin()
            revoked = _revoke_license_devices(connection, license_id)
            actor_hash = str(claims.get('credential_id_hash', ''))
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET active=0,deleted_at=UTC_TIMESTAMP(),deleted_reason=%s,deleted_by=%s WHERE id=%s AND deleted_at IS NULL', (reason, actor_hash, license_id))
            _change_journal(connection, 'license', license_id, 'delete', {'active': 0})
            _audit_write(connection, request_context, action, license_id, license_id, {'deleted_at': None, 'active': int(row.get('active', 0))}, {'deleted_at': 'now', 'active': 0, 'device_sessions': 'revoked'}, claims, target_type='license', target_id=license_id)
            connection.commit()
            return admin_respond('200 OK', True, 'ライセンスを削除しました。', {'license': admin_license_payload({**row, 'active': 0, 'deleted_at': 'now'}, 0), 'revoked_devices': revoked})
        if action == 'restore_license':
            license_id = admin_request_int(data, 'license_id', 0, 1, 2 ** 63 - 1)
            if not license_id:
                return admin_respond('400 Bad Request', False, 'ライセンスIDが必要です。')
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,deleted_at,deleted_reason FROM licenses WHERE id=%s AND deleted_at IS NOT NULL LIMIT 1 FOR UPDATE', (license_id,))
                deleted = cursor.fetchone()
                if not deleted:
                    connection.rollback()
                    return admin_respond('404 Not Found', False, '削除済みライセンスが見つかりません。')
                cursor.execute('UPDATE licenses SET deleted_at=NULL,deleted_reason=NULL,deleted_by=NULL,active=0 WHERE id=%s', (license_id,))
            _change_journal(connection, 'license', license_id, 'restore', {'active': 0})
            _audit_write(connection, request_context, action, license_id, license_id, {'deleted_at': deleted.get('deleted_at'), 'deleted_reason': deleted.get('deleted_reason')}, {'deleted_at': None, 'active': 0}, claims, target_type='license', target_id=license_id)
            connection.commit()
            return admin_respond('200 OK', True, 'ライセンスを停止状態で復元しました。', {'license_id': license_id})
        if action == 'renew_license':
            row = _license(connection, data)
            if not row:
                return admin_respond('404 Not Found', False, 'ライセンスが見つかりません。')
            days = admin_request_int(data, 'renew_days', 0, 1, 3650)
            if not days:
                return admin_respond('400 Bad Request', False, '延長日数は1〜3650日で指定してください。')
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            expiry = parse_utc_datetime(str(row.get('expires_at') or ''))
            base = max(now, expiry.replace(tzinfo=None) if expiry else now)
            new_expiry = base + timedelta(days=days)
            value = new_expiry.strftime('%Y-%m-%d %H:%M:%S')
            license_id = int(row['id'])
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET expires_at=%s,evaluation_days=NULL,evaluation_started_at=NULL,active=1,revoked_at=NULL WHERE id=%s AND deleted_at IS NULL', (value, license_id))
            _change_journal(connection, 'license', license_id, 'renew', {'expires_at': value, 'days': days})
            _audit_write(connection, request_context, action, license_id, license_id, {'expires_at': row.get('expires_at'), 'evaluation_days': row.get('evaluation_days')}, {'expires_at': value, 'active': 1}, claims, target_type='license', target_id=license_id)
            connection.commit()
            updated = dict(row, expires_at=value, evaluation_days=None, evaluation_started_at=None, active=1, revoked_at=None)
            return admin_respond('200 OK', True, '有効期限を延長しました。', {'license': admin_license_payload(updated, _active_count(connection, license_id))})
        if action == 'bulk_license_action':
            ids = []
            for item in admin_request_string(data, 'license_ids').split(','):
                try:
                    value = int(item.strip())
                except ValueError:
                    continue
                if value > 0 and value not in ids:
                    ids.append(value)
            operation = admin_request_string(data, 'operation')
            deleted_view = php_bool_cast(data.get('deleted_view'))
            if not ids or len(ids) > 100 or operation not in {'delete', 'restore', 'pause', 'resume', 'label_prefix'}:
                return admin_respond('400 Bad Request', False, '対象1〜100件と有効な一括操作を指定してください。')
            if operation in {'delete', 'restore'} and (operation == 'restore') != deleted_view:
                return admin_respond('400 Bad Request', False, '現在の一覧と操作が一致しません。')
            prefix = admin_request_string(data, 'label_prefix').strip()
            if operation == 'label_prefix' and (not prefix or len(prefix) > 60):
                return admin_respond('400 Bad Request', False, 'ラベル先頭文字は1〜60文字で入力してください。')
            from v3_handlers import _assert_write_fence
            from baas_handlers import _revoke_license_devices
            _assert_write_fence(connection)
            connection.begin()
            marks = ','.join(['%s'] * len(ids))
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,label,active,revoked_at,deleted_at,deleted_reason FROM licenses WHERE id IN (' + marks + ') FOR UPDATE', tuple(ids))
                rows = cursor.fetchall()
            changed = []
            try:
                for item in rows:
                    lid = int(item['id'])
                    is_deleted = php_bool_cast(item.get('deleted_at'))
                    active = int(item.get('active') or 0)
                    if operation == 'delete' and (not is_deleted):
                        _revoke_license_devices(connection, lid)
                        with connection.cursor() as cursor:
                            cursor.execute('UPDATE licenses SET active=0,deleted_at=UTC_TIMESTAMP(),deleted_reason=%s,deleted_by=%s WHERE id=%s', ('bulk_administrator_request', claims.get('credential_id_hash', ''), lid))
                        _change_journal(connection, 'license', lid, 'bulk_delete', {'active': 0})
                    elif operation == 'restore' and is_deleted:
                        with connection.cursor() as cursor:
                            cursor.execute('UPDATE licenses SET deleted_at=NULL,deleted_reason=NULL,deleted_by=NULL,active=0 WHERE id=%s', (lid,))
                        _change_journal(connection, 'license', lid, 'bulk_restore', {'active': 0})
                    elif operation == 'pause' and (not is_deleted) and (active == 1):
                        revoked = _revoke_license_devices(connection, lid)
                        with connection.cursor() as cursor:
                            cursor.execute('UPDATE licenses SET active=0 WHERE id=%s', (lid,))
                        _change_journal(connection, 'license', lid, 'bulk_pause', {'active': 0, 'revoked_devices': revoked})
                    elif operation == 'resume' and (not is_deleted) and (active == 0 or item.get('revoked_at')):
                        with connection.cursor() as cursor:
                            cursor.execute('UPDATE licenses SET active=1,revoked_at=NULL WHERE id=%s', (lid,))
                        _change_journal(connection, 'license', lid, 'bulk_resume', {'active': 1, 'device_sessions': 'reauthentication_required'})
                    elif operation == 'label_prefix' and (not is_deleted):
                        label = (prefix + str(item.get('label') or ''))[:100]
                        with connection.cursor() as cursor:
                            cursor.execute('UPDATE licenses SET label=%s WHERE id=%s', (label, lid))
                        _change_journal(connection, 'license', lid, 'bulk_label', {'label_hash': hashlib.sha256(label.encode()).hexdigest()})
                    else:
                        continue
                    changed.append(lid)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            _audit_write(connection, request_context, action, 0, None, {'selected': len(ids)}, {'operation': operation, 'changed': len(changed)}, claims, target_type='license_bulk', target_id=operation)
            return admin_respond('200 OK', True, '一括処理が完了しました。対象 ' + str(len(changed)) + ' 件。', {'operation': operation, 'changed_count': len(changed), 'license_ids': changed})
        if action == 'create_license':
            tenant_id = admin_request_int(data, 'tenant_id', 1, 1, 2 ** 31 - 1)
            product_id = admin_request_int(data, 'product_id', 1, 1, 2 ** 31 - 1)
            debug_mode = php_bool_cast(data.get('debug_mode'))
            mode = 'evaluation' if debug_mode else admin_request_string(data, 'license_mode').lower() or 'single'
            if mode not in {'single', 'volume', 'evaluation'}:
                return admin_respond('400 Bad Request', False, 'ライセンスタイプを確認してください。')
            with connection.cursor() as cursor:
                cursor.execute("SELECT p.id FROM products p JOIN tenants t ON t.id=p.tenant_id WHERE p.id=%s AND p.tenant_id=%s AND p.status='active' AND t.status='active' LIMIT 1", (product_id, tenant_id))
                if not cursor.fetchone():
                    return admin_respond('400 Bad Request', False, '選択した製品はテナントに属していないか、利用停止中です。')
            if mode == 'volume':
                max_devices = admin_request_int(data, 'max_devices', 10, 2, 500)
            else:
                max_devices = 1
            evaluation_days = admin_request_int(data, 'evaluation_days', 100, 1, 3650) if mode == 'evaluation' else None
            expiry = None
            expires_text = admin_request_string(data, 'expires_at')
            if expires_text and mode != 'evaluation':
                try:
                    expiry_dt = parse_iso_datetime(expires_text.replace('Z', '+00:00'))
                    expiry = expiry_dt.strftime('%Y-%m-%d %H:%M:%S')
                except ValueError:
                    return admin_respond('400 Bad Request', False, '有効期限の形式を確認してください。')
            pepper, token_secret = (secret_value('key_pepper'), secret_value('token_secret'))
            if len(pepper) < 32 or len(token_secret) < 32:
                raise database.DatabaseConfigurationError('test license secrets are not configured')
            from core import offline_lookup, offline_secret, offline_secret_encrypt
            from baas_handlers import _generate_baas_product_key
            product_key = _generate_baas_product_key()
            offline = offline_secret(product_key)
            label = admin_request_string(data, 'label')[:100] or None
            active = 0 if data.get('reject_on_issue') else 1
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('INSERT INTO licenses(tenant_id,product_id,key_hash,label,active,max_devices,evaluation_days,expires_at,offline_lookup,offline_secret_enc) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', (tenant_id, product_id, license_key_hash({'key_pepper': pepper}, product_key), label, active, max_devices, evaluation_days, expiry, offline_lookup(offline), offline_secret_encrypt({'token_secret': token_secret}, offline)))
                license_id = int(getattr(cursor, 'lastrowid', 0) or 0)
            _audit_write(connection, request_context, action, license_id, license_id, {}, {'license_mode': mode, 'max_devices': max_devices, 'evaluation_days': evaluation_days, 'tenant_id': tenant_id, 'product_id': product_id}, claims, target_type='license', target_id=license_id)
            connection.commit()
            return admin_respond('200 OK', True, '新しいキーを発行しました。', {'product_key': product_key, 'license_id': license_id, 'license_mode': mode, 'max_devices': max_devices, 'evaluation_days': evaluation_days})
        if action == 'import_licenses_csv':
            raw = admin_request_string(data, 'csv_rows')
            tenant_id = admin_request_int(data, 'tenant_id', 0, 1, 2 ** 31 - 1)
            product_id = admin_request_int(data, 'product_id', 0, 1, 2 ** 31 - 1)
            if not raw or len(raw.encode('utf-8')) > 4096 or (not tenant_id) or (not product_id):
                return admin_respond('400 Bad Request', False, 'CSVとテナント・製品を指定してください。')
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM products p JOIN tenants t ON t.id=p.tenant_id WHERE p.id=%s AND p.tenant_id=%s AND p.status='active' AND t.status='active' LIMIT 1", (product_id, tenant_id))
                if not cursor.fetchone():
                    return admin_respond('400 Bad Request', False, '選択した製品を確認できません。')
            parsed_rows = []
            try:
                for line_no, cells in enumerate(csv.reader(io.StringIO(raw, newline=''), quotechar='"', escapechar='\\'), 1):
                    if len(cells) == 1 and (not cells[0].strip(' \t\n\r\x00\x0b')):
                        continue
                    first = cells[0].lstrip('\ufeff \t\n\r\x00\x0b') if cells else ''
                    if line_no == 1 and first.lower() == 'label':
                        continue
                    if not 2 <= len(cells) <= 5:
                        raise ValueError('CSVは label,license_mode,max_devices,evaluation_days,expires_at の順で指定してください。')
                    cells += [''] * (5 - len(cells))
                    label = cells[0].strip(' \t\n\r\x00\x0b')
                    mode = cells[1].strip(' \t\n\r\x00\x0b').translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))
                    if not label or len(label) > 100 or mode not in {'single', 'volume', 'evaluation'}:
                        raise ValueError(f'CSV {line_no}行目のラベルまたは発行方式が不正です。')
                    try:
                        max_devices = int(cells[2]) if mode == 'volume' else 1
                        evaluation_days = int(cells[3]) if mode == 'evaluation' else None
                    except ValueError:
                        raise ValueError(f'CSV {line_no}行目の端末数または評価日数が範囲外です。')
                    if mode == 'volume' and (not 2 <= max_devices <= 500) or (mode == 'evaluation' and (not 1 <= evaluation_days <= 3650)):
                        raise ValueError(f'CSV {line_no}行目の端末数または評価日数が範囲外です。')
                    expiry = None
                    expiry_text = cells[4].strip()
                    if mode != 'evaluation' and expiry_text:
                        if not re.fullmatch('\\d{4}-\\d{2}-\\d{2}(?:[ T]\\d{2}:\\d{2}(?::\\d{2})?)?', expiry_text):
                            raise ValueError(f'CSV {line_no}行目の有効期限は YYYY-MM-DD HH:MM:SS 形式で指定してください。')
                        try:
                            expiry = parse_iso_datetime(expiry_text.replace('T', ' ')).strftime('%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            raise ValueError(f'CSV {line_no}行目の有効期限を解釈できません。')
                    parsed_rows.append({'label': label, 'max_devices': max_devices, 'evaluation_days': evaluation_days, 'expires_at': expiry})
                    if len(parsed_rows) > 20:
                        raise ValueError('一度に取り込めるのは20件までです。')
            except csv.Error:
                return admin_respond('400 Bad Request', False, 'CSV形式が正しくありません。')
            except ValueError as exc:
                return admin_respond('400 Bad Request', False, str(exc))
            if not parsed_rows:
                return admin_respond('400 Bad Request', False, 'CSVに取り込むデータ行がありません。')
            pepper, token_secret = (secret_value('key_pepper'), secret_value('token_secret'))
            if len(pepper) < 32 or len(token_secret) < 32:
                raise database.DatabaseConfigurationError('test license secrets are not configured')
            from core import offline_lookup, offline_secret, offline_secret_encrypt
            from baas_handlers import _generate_baas_product_key
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            connection.begin()
            issued = []
            try:
                with connection.cursor() as cursor:
                    for item in parsed_rows:
                        key = _generate_baas_product_key()
                        secret = offline_secret(key)
                        cursor.execute('INSERT INTO licenses(tenant_id,product_id,key_hash,label,active,max_devices,evaluation_days,expires_at,offline_lookup,offline_secret_enc) VALUES(%s,%s,%s,%s,1,%s,%s,%s,%s,%s)', (tenant_id, product_id, license_key_hash({'key_pepper': pepper}, key), item['label'], item['max_devices'], item['evaluation_days'], item['expires_at'], offline_lookup(secret), offline_secret_encrypt({'token_secret': token_secret}, secret)))
                        issued.append({'id': int(getattr(cursor, 'lastrowid', 0) or 0), 'label': item['label'], 'product_key': key})
                _audit_write(connection, request_context, action, 0, None, {}, {'count': len(issued), 'tenant_id': tenant_id, 'product_id': product_id, 'license_ids': [item['id'] for item in issued]}, claims, target_type='license_import', target_id='csv')
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            return admin_respond('201 Created', True, 'CSVからライセンスを発行しました。キーは今回の応答にのみ含まれます。', {'licenses': issued})
        if action == 'update_license':
            row = _license(connection, data)
            if not row:
                return admin_respond('404 Not Found', False, 'キーが見つかりません。')
            license_id = int(row['id'])
            updates, values = ([], [])
            updated = dict(row)
            if 'label' in data:
                updates.append('label=%s')
                label_value = admin_request_string(data, 'label')[:100] or None
                values.append(label_value)
                updated['label'] = label_value
            if 'active' in data:
                active = php_bool_cast(data['active'])
                updates.append('active=%s')
                values.append(int(active))
                updated['active'] = int(active)
                if active and 'revoked_at' not in data:
                    updates.append('revoked_at=NULL')
                    updated['revoked_at'] = None
            if 'max_devices' in data:
                max_devices = admin_request_int(data, 'max_devices', 0, 1, 500)
                active_sessions = _active_count(connection, license_id)
                if max_devices < active_sessions:
                    return admin_respond('409 Conflict', False, '現在のアクティブセッション数より小さい台数には変更できません。先に端末を失効してください。', {'license': admin_license_payload(row, active_sessions), 'active_sessions': active_sessions, 'requested_max_devices': max_devices})
                updates.append('max_devices=%s')
                values.append(max_devices)
                updated['max_devices'] = max_devices
            for field in ('expires_at', 'revoked_at'):
                if field in data:
                    text_value = admin_request_string(data, field)
                    if text_value:
                        try:
                            parsed = parse_iso_datetime(text_value.replace('Z', '+00:00'))
                            text_value = parsed.strftime('%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            return admin_respond('400 Bad Request', False, '日時の形式を確認してください。')
                    updates.append(field + '=%s')
                    values.append(text_value or None)
                    updated[field] = text_value or None
            if not updates:
                return admin_respond('400 Bad Request', False, '更新する項目がありません。')
            from v3_handlers import _assert_write_fence
            from baas_handlers import _revoke_license_devices
            _assert_write_fence(connection)
            values.append(license_id)
            with connection.cursor() as cursor:
                cursor.execute('UPDATE licenses SET ' + ','.join(updates) + ' WHERE id=%s AND deleted_at IS NULL', tuple(values))
            revoke = 'active' in data and (not php_bool_cast(data['active'])) or ('revoked_at' in data and bool(data['revoked_at']))
            revoked = _revoke_license_devices(connection, license_id) if revoke else 0
            _audit_write(connection, request_context, action, license_id, license_id, {key: row.get(key) for key in ('label', 'active', 'max_devices', 'expires_at', 'revoked_at')}, {key: updated.get(key) for key in ('label', 'active', 'max_devices', 'expires_at', 'revoked_at')}, claims, target_type='license', target_id=license_id)
            connection.commit()
            return admin_respond('200 OK', True, 'キーを更新しました。', {'license': admin_license_payload(updated, _active_count(connection, license_id))})
        if action == 'permanently_delete_license':
            license_id = admin_request_int(data, 'license_id', 0, 1, 2 ** 63 - 1)
            if not license_id:
                license_id = admin_request_int(data, 'id', 0, 1, 2 ** 63 - 1)
            if not license_id or str(data.get('confirm_id', '')) != str(license_id):
                return admin_respond('400 Bad Request', False, '完全削除には対象ライセンス ID の入力確認が必要です。')
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('SELECT id,label,deleted_at,deleted_reason FROM licenses WHERE id=%s LIMIT 1 FOR UPDATE', (license_id,))
                row = cursor.fetchone()
                if not row or not row.get('deleted_at'):
                    connection.rollback()
                    return admin_respond('409 Conflict', False, '完全削除できる論理削除済みライセンスが見つかりません。')

            def has_column(table, column):
                with connection.cursor() as cursor:
                    cursor.execute('SELECT 1 FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s AND COLUMN_NAME=%s', (table, column))
                    return bool(cursor.fetchone())
            try:
                has_sessions = has_column('license_v3_sessions', 'license_id') and has_column('license_v3_sessions', 'session_id')
                if has_sessions:
                    for table in ('license_v3_proofs', 'license_v3_refresh_history'):
                        if has_column(table, 'session_id'):
                            with connection.cursor() as cursor:
                                cursor.execute('DELETE FROM `' + table + '` WHERE session_id IN (SELECT session_id FROM license_v3_sessions WHERE license_id=%s)', (license_id,))
                related = ('license_v3_offline_tickets', 'license_v3_sessions', 'license_v3_devices', 'offline_activation_requests', 'license_devices', 'phone_activation_requests', 'product_key_issue_items', 'tenant_key_issue_session_items', 'product_key_issue_v4_items', 'product_key_issue_v5_items', 'product_key_issue_v6_items')
                for table in related:
                    if has_column(table, 'license_id'):
                        with connection.cursor() as cursor:
                            cursor.execute('DELETE FROM `' + table + '` WHERE license_id=%s', (license_id,))
                _change_journal(connection, 'license', license_id, 'permanent_delete', {'label': str(row.get('label') or ''), 'deleted_at': str(row.get('deleted_at'))})
                _audit_write(connection, request_context, action, license_id, license_id, {'label': row.get('label'), 'deleted_at': row.get('deleted_at')}, {'permanently_deleted': True}, claims, target_type='license', target_id=license_id)
                with connection.cursor() as cursor:
                    cursor.execute('DELETE FROM licenses WHERE id=%s AND deleted_at IS NOT NULL', (license_id,))
                    if int(cursor.rowcount or 0) != 1:
                        raise RuntimeError('license_delete_failed')
                connection.commit()
            except Exception:
                connection.rollback()
                return admin_respond('500 Internal Server Error', False, '完全削除に失敗しました。ライセンスと関連データはロールバックされました。')
            return admin_respond('200 OK', True, '論理削除済みライセンスと関連データを完全削除しました。', {'license_id': license_id})
        if action == 'list_audit_logs':
            logs, has_next, page, limit = _list_audit_logs(connection, data)
            return admin_respond('200 OK', True, '監査ログを取得しました。', {'logs': _json_safe(logs), 'page': page, 'limit': limit, 'has_next': has_next})
        if action == 'clear_attempts':
            with connection.cursor() as cursor:
                cursor.execute('DELETE FROM auth_attempts')
                deleted = int(getattr(cursor, 'rowcount', 0) or 0)
            _audit_write(connection, request_context, action, 0, None, {}, {'deleted': deleted}, claims)
            connection.commit()
            return admin_respond('200 OK', True, '試行履歴をすべて解除しました。', {'deleted': deleted})
        if action == 'revoke_common_id_membership':
            subject_hash = admin_request_string(data, 'subject_hash')
            tenant_id = admin_request_int(data, 'tenant_id', 0, 1, 2 ** 63 - 1)
            if not re.fullmatch('[a-f0-9]{64}', subject_hash) or not tenant_id:
                return admin_respond('400 Bad Request', False, 'SSO IDとテナントを確認できません。')
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            connection.begin()
            with connection.cursor() as cursor:
                cursor.execute('SELECT subject_hash FROM tenant_sso_memberships WHERE subject_hash=%s AND tenant_id=%s LIMIT 1 FOR UPDATE', (subject_hash, tenant_id))
                if not cursor.fetchone():
                    connection.rollback()
                    return admin_respond('404 Not Found', False, '対象の共通ID所属は既に解除されているか、見つかりません。')
                cursor.execute('UPDATE tenant_sso_sessions SET revoked_at=COALESCE(revoked_at,UTC_TIMESTAMP()) WHERE subject_hash=%s AND tenant_id=%s AND revoked_at IS NULL', (subject_hash, tenant_id))
                cursor.execute('DELETE FROM tenant_sso_memberships WHERE subject_hash=%s AND tenant_id=%s', (subject_hash, tenant_id))
                if int(cursor.rowcount or 0) != 1:
                    connection.rollback()
                    return admin_respond('409 Conflict', False, '共通IDの所属が同時に変更されました。状態を更新して再確認してください。')
            _audit_write(connection, request_context, 'tenant_common_id_membership_revoked', None, None, {'subject_hash': subject_hash, 'tenant_id': tenant_id}, {'revoked': True}, claims, target_type='tenant_sso_membership', target_id=f'{tenant_id}:{subject_hash}')
            connection.commit()
            from ha_handlers import ha_sync_peer
            sync = ha_sync_peer('tenant_common_id_membership_revoked', request_context)
            return admin_respond('200 OK', True, '共通IDの所属を解除しました。', {'peer_synced': bool(sync.get('ok'))})
        if action == 'set_admin_role':
            principal_id = admin_request_int(data, 'principal_id', 0, 1, 2 ** 63 - 1)
            new_role = admin_request_string(data, 'role_name').lower()
            allowed_roles = {'viewer', 'operator', 'security-admin', 'ha-admin'}
            if not principal_id or new_role not in allowed_roles:
                return admin_respond('400 Bad Request', False, '対象管理者と権限を指定してください。')
            actor_hash = str(claims.get('credential_id_hash', ''))
            with connection.cursor() as cursor:
                cursor.execute("SELECT id,credential_id_hash,role_name FROM admin_principals WHERE id=%s AND status='active' AND revoked_at IS NULL LIMIT 1 FOR UPDATE", (principal_id,))
                principal = cursor.fetchone()
                if not principal:
                    return admin_respond('404 Not Found', False, '有効な管理者が見つかりません。')
                old_role = str(principal.get('role_name', ''))
                if actor_hash and hmac.compare_digest(actor_hash, str(principal.get('credential_id_hash', ''))):
                    return admin_respond('409 Conflict', False, 'ログイン中のパスキー自身の権限はこの画面から変更できません。')
                cursor.execute("SELECT role_name FROM admin_principals WHERE credential_id_hash=%s AND status='active' AND revoked_at IS NULL LIMIT 1", (actor_hash,))
                actor = cursor.fetchone() or {}
                if (new_role == 'ha-admin' or old_role == 'ha-admin') and actor.get('role_name') != 'ha-admin':
                    return admin_respond('403 Forbidden', False, 'HA管理者の権限変更にはHA管理者権限が必要です。')
                if old_role in {'security-admin', 'ha-admin'} and new_role not in {'security-admin', 'ha-admin'}:
                    cursor.execute("SELECT COUNT(*) AS n FROM admin_principals WHERE status='active' AND revoked_at IS NULL AND role_name IN ('security-admin','ha-admin')")
                    if int((cursor.fetchone() or {}).get('n', 0)) <= 1:
                        return admin_respond('409 Conflict', False, '最後の管理者権限は解除できません。')
                from v3_handlers import _assert_write_fence
                _assert_write_fence(connection)
                cursor.execute('UPDATE admin_principals SET role_name=%s WHERE id=%s', (new_role, principal_id))
            _audit_write(connection, request_context, action, principal_id, None, {'role_name': old_role}, {'role_name': new_role}, claims, target_type='admin_principal', target_id=principal_id)
            connection.commit()
            return admin_respond('200 OK', True, '管理者権限を更新しました。', {'principal_id': principal_id, 'role_name': new_role})
        if action in {'list_devices', 'list_sessions'}:
            status, success, message, extra = _list_devices(connection, data, sessions=action == 'list_sessions')
            return admin_respond(status, success, message, _json_safe(extra))
        device_id = admin_request_int(data, 'device_id', 0, 0, 2 ** 63 - 1)
        if device_id <= 0:
            return admin_respond('400 Bad Request', False, 'device_id が必要です。')
        with connection.cursor() as cursor:
            cursor.execute('SELECT id,license_id,revoked_at FROM license_devices WHERE id=%s LIMIT 1', (device_id,))
            device = cursor.fetchone()
        if action == 'revoke_device':
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            with connection.cursor() as cursor:
                cursor.execute('UPDATE license_devices SET revoked_at=UTC_TIMESTAMP(),token_version=token_version+1 WHERE id=%s', (device_id,))
            after = {'revoked_at': 'now', 'session': 'revoked'}
            message = '端末を失効しました。'
        else:
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
            with connection.cursor() as cursor:
                cursor.execute('UPDATE license_devices SET revoked_at=NULL WHERE id=%s', (device_id,))
            after = {'revoked_at': None, 'session': 'may_require_reauthentication'}
            message = '端末の失効を解除しました。'
        _audit_write(connection, request_context, action, device_id, (device or {}).get('license_id'), {'revoked_at': (device or {}).get('revoked_at')}, after, claims)
        connection.commit()
        return admin_respond('200 OK', True, message)
    except database.DatabaseConfigurationError:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        return _error('503 Service Unavailable', '管理データベースを利用できません。', 'SERVICE_UNAVAILABLE')
    except Exception:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        return _error('503 Service Unavailable', '管理操作に失敗しました。', 'ADMIN_OPERATION_FAILED')
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
