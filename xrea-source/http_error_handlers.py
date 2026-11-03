"""Native HTTP errors and HA maintenance responses; no PHP runtime required."""
from native_http import make_response, add_headers, legacy_compatible
import html
import json
import os
import re
from http import HTTPStatus
from pathlib import Path
from urllib.parse import parse_qsl
ROOT = Path(__file__).resolve().parent
CATALOG = json.loads((ROOT / 'http-error-catalog.json').read_text(encoding='utf-8'))
TEMPLATES = json.loads((ROOT / 'http-error-templates.json').read_text(encoding='utf-8'))
MAINTENANCE_ALLOWED = {'/admin_api.php'} | {'/ha/' + name + '.php' for name in ('mode', 'status', 'health', 'release', 'export', 'import', 'sync', 'retry-sync', 'failback-operation', 'audit-recent', 'audit-verify', 'migrate', 'restore-test', 'retention', 'bootstrap', 'http-error', 'maintenance-response')}

def is_maintenance():
    if os.environ.get('PYTHON_MIGRATION_HA_MAINTENANCE') == '1':
        return True
    if os.environ.get('PYTHON_MIGRATION_PROFILE') == 'production':
        raw = os.environ.get('DOCUMENT_ROOT', '')
        if raw:
            public = Path(raw).resolve()
            if (public / '.tuti-maintenance').is_file() or (public / 'license/.tuti-maintenance').is_file():
                return True
    from ha_handlers import _runtime_json
    return (_runtime_json('state.json') or {}).get('maintenance') is True

@legacy_compatible(callback_index=1, request_index=0)
def _response(request_context, status, body, headers):
    headers += [('Content-Length', str(len(body)))]
    _http_status, _http_headers = (f'{status} {HTTPStatus(status).phrase}', headers)
    return make_response([b'' if request_context.get('method', 'GET') == 'HEAD' else body], _http_status, _http_headers)

@legacy_compatible(callback_index=None, request_index=0)
def error_status(request_context):
    value = '404'
    for name, item in parse_qsl(request_context.get('query', ''), keep_blank_values=True):
        if name == 'code':
            value = item
        elif name.startswith('code['):
            value = ''
    if 'redirect_status' in request_context:
        value = str(request_context['redirect_status'])
    return int(value) if re.fullmatch('[45][0-9]{2}', value) and value in CATALOG else 404

@legacy_compatible(callback_index=1, request_index=0)
def error_page(request_context, status=404, maintenance=False):
    label, title, description, guidance = CATALOG[str(status)]
    method = request_context.get('method', 'GET')
    uri = request_context.get('redirect_url', request_context.get('uri', request_context.get('path', '')))
    wants_json = 'application/json' in request_context.get('header:accept', '').lower() or re.search('/(?:api|python-endpoints|ha)/', uri) or method not in {'GET', 'HEAD'}
    retry = 60 if status == 429 else 300 if status == 503 else None
    headers = [('Cache-Control', 'no-store, max-age=0'), ('Vary', 'Accept'), ('X-Content-Type-Options', 'nosniff'), ('Content-Type', ('application/json' if wants_json else 'text/html') + '; charset=utf-8')]
    if retry:
        headers.append(('Retry-After', str(retry)))
    if wants_json:
        value = {'success': False, 'ok': False, 'status': status, 'error_code': f'http_{status}', 'message': title}
        if retry:
            value['retry_after'] = retry
        body = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    else:
        script = request_context.get('mount_path', '').rstrip('/')
        if script.endswith('.cgi'):
            script = script.rsplit('/python-endpoints/', 1)[0]
        elif script.endswith('.php'):
            script = script.split('/ha/')[0] if '/ha/' in script else script.rsplit('/', 1)[0]
        values = {'title': title, 'description': description, 'guidance': guidance, 'hintTitle': '次にできること', 'homeLabel': 'サイトへ戻る', 'stateLabel': 'サービスからのお知らせ', 'footerLabel': 'TUTI · サービスインフォメーション', 'note': '問題が続く場合は、表示されたエラーコードを管理者にお伝えください。', 'home': script + '/tenant-portal/', 'status': str(status), 'upperLabel': label.upper()}
        if maintenance:
            values.update(stateLabel='システムメンテナンス', footerLabel='TUTI · サービスメンテナンス', note='ご不便をおかけしますが、再開までお待ちください。')
        template = TEMPLATES[f"{int(maintenance)}-{int(method == 'GET' and (maintenance or status in {408, 429, 503}))}"]
        body = re.sub('\\{\\{(\\w+)\\}\\}', lambda m: html.escape(values[m[1]], quote=True), template).encode('utf-8')
    return _response(request_context, status, body, headers)

@legacy_compatible(callback_index=1, request_index=0)
def maintenance_response(request_context):
    peer = bool(os.environ.get('PYTHON_MIGRATION_HA_PEER', '').strip())
    method = request_context.get('method', 'GET')
    uri = request_context.get('uri', request_context.get('path', ''))
    wants_json = 'application/json' in request_context.get('header:accept', '').lower() or re.search('/(?:api|python-endpoints)/', uri) or method not in {'GET', 'HEAD'}
    headers = [('Retry-After', '300'), ('Cache-Control', 'no-store, max-age=0'), ('Vary', 'Accept'), ('X-BaaS-HA-Writable', '0'), ('X-BaaS-HA-Role', 'primary-maintenance'), ('Content-Type', ('application/json' if wants_json else 'text/html') + '; charset=utf-8')]
    if peer:
        headers.append(('X-BaaS-Failover', 'probe-peer'))
    if wants_json:
        body = json.dumps({'success': False, 'ok': False, 'error': 'primary_maintenance', 'error_code': 'primary_maintenance', 'role': 'primary', 'retry_on_peer': peer, 'status': 503, 'retry_after': 300, 'message': 'ただいまメンテナンス中です。しばらくしてから再度お試しください。'}, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    else:
        extra = [(k, v) for k, v in headers if k.startswith('X-BaaS-')]
        return add_headers(error_page(request_context, 503, maintenance=True), extra)
    return _response(request_context, 503, body, headers)
