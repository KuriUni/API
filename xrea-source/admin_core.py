"""Python equivalents for shared legacy administration input/payload helpers."""
from native_http import make_response, add_headers, legacy_compatible
import datetime
import html
import json
import re
from http_utils import php_parse_query as parse_qs, _json_default
from core import device_display_label, device_reference, format_grouped_digits, parse_utc_datetime, php_bool_cast, PHP_TRIM_CHARS

@legacy_compatible(callback_index=0, request_index=None)
def admin_respond(status, success, message, extra=None):
    payload = {'success': bool(success), 'message': str(message)}
    payload.update(extra or {})
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), default=_json_default).encode('utf-8')
    _http_status, _http_headers = (status, [('Content-Type', 'application/json; charset=utf-8'), ('Cache-Control', 'no-store'), ('Content-Length', str(len(body)))])
    return make_response([body], _http_status, _http_headers)

@legacy_compatible(callback_index=None, request_index=0)
def admin_input(request_context):
    content_type = (request_context.get('content_type') or request_context.get('header:content-type') or '').lower()
    if 'application/json' in content_type:
        stream = request_context.get('body_stream')
        raw = stream.read(131073) if stream is not None else b''
        if len(raw) > 131072:
            raise RuntimeError('JSON が大きすぎます。')
        try:
            data = json.loads(raw.decode('utf-8')) if raw else None
        except (ValueError, UnicodeDecodeError):
            raise RuntimeError('JSON 形式が正しくありません。')
        if not isinstance(data, (dict, list)):
            raise RuntimeError('JSON 形式が正しくありません。')
        if len(data) > 100:
            raise RuntimeError('項目数が多すぎます。')
        for value in data.values() if isinstance(data, dict) else data:
            if isinstance(value, (list, dict)):
                raise RuntimeError('不正なリクエスト形式です。')
            if isinstance(value, str) and len(value.encode('utf-8')) > 4096:
                raise RuntimeError('入力が長すぎます。')
        return data if isinstance(data, dict) else {}
    query = parse_qs(request_context.get('query', ''), keep_blank_values=True)
    method = request_context.get('method', 'GET')
    post = {}
    if method == 'POST':
        stream = request_context.get('body_stream')
        raw = stream.read(131073) if stream is not None else b''
        if len(raw) > 131072:
            raise RuntimeError('フォームが大きすぎます。')
        try:
            post = parse_qs(raw.decode('utf-8'), keep_blank_values=True)
        except UnicodeDecodeError:
            raise RuntimeError('フォーム形式が正しくありません。')
    total = sum((len(values) for values in query.values())) + sum((len(values) for values in post.values()))
    if total > 100:
        raise RuntimeError('項目数が多すぎます。')
    result = {}
    for source, is_post in ((post, True), (query, False)):
        for key, values in source.items():
            if key == 'scopes' and is_post:
                if len(values) > 8 or any((len(value.encode('utf-8')) > 80 for value in values)):
                    raise RuntimeError('API権限の形式が正しくありません。')
                result[key] = values
                continue
            if len(values) != 1:
                raise RuntimeError('不正なリクエスト形式です。')
            value = values[0]
            if len(value.encode('utf-8')) > 4096:
                raise RuntimeError('入力が長すぎます。')
            result.setdefault(key, value)
    return result

def admin_license_mode(row):
    if row.get('evaluation_days') is not None:
        return 'evaluation'
    return 'volume' if max(1, int(row.get('max_devices', 1) or 1)) > 1 else 'single'

def admin_license_payload(row, active_sessions=0):
    max_devices = max(1, int(row.get('max_devices', 1) or 1))
    expires_at = row.get('expires_at')
    if (expires_at is None or expires_at == '') and row.get('evaluation_days') is not None and (row.get('evaluation_started_at') is not None):
        parsed = parse_utc_datetime(str(row['evaluation_started_at']))
        if parsed is not None:
            expires_at = (parsed + datetime.timedelta(days=max(1, int(row['evaluation_days'])))).strftime('%Y-%m-%d %H:%M:%S')
    license_id = int(row.get('id', 0) or 0)
    return {'id': license_id, 'license_id': license_id, 'label': row.get('label'), 'active': php_bool_cast(row.get('active', 0)), 'max_devices': max_devices, 'license_mode': admin_license_mode(row), 'active_sessions': int(active_sessions), 'expires_at': expires_at, 'evaluation_days': row.get('evaluation_days'), 'evaluation_started_at': row.get('evaluation_started_at'), 'revoked_at': row.get('revoked_at'), 'last_activated_at': row.get('last_activated_at'), 'last_seen_at': row.get('last_seen_at'), 'created_at': row.get('created_at'), 'updated_at': row.get('updated_at')}

def admin_device_payload(row):
    device_hash = str(row.get('device_hash') or '')
    label = str(row.get('device_label') or '')
    return {'id': int(row.get('id', 0) or 0), 'device_id': int(row.get('id', 0) or 0), 'license_id': int(row.get('license_id', 0) or 0), 'device_ref': device_reference(device_hash), 'device_display_label': device_display_label(label, device_hash), 'device_label': row.get('device_label'), 'device_hash': row.get('device_hash'), 'access_expires_at': row.get('access_expires_at'), 'refresh_expires_at': row.get('refresh_expires_at'), 'first_activated_at': row.get('first_activated_at'), 'last_seen_at': row.get('last_seen_at'), 'revoked_at': row.get('revoked_at'), 'last_ip_hash': row.get('last_ip_hash'), 'app_version': row.get('app_version'), 'token_version': int(row.get('token_version', 1) or 1)}

def admin_session_payload(row):
    payload = admin_device_payload(row)
    expires = parse_utc_datetime(str(row.get('refresh_expires_at') or ''))
    payload['is_active_session'] = not row.get('revoked_at') and expires is not None and (int(expires.timestamp()) > int(datetime.datetime.now(datetime.timezone.utc).timestamp()))
    return payload

def admin_phone_request_payload(row):
    installation = row.get('installation_id')
    device_hash = str(row.get('device_hash') or '')
    label = str(row.get('device_label') or '')
    return {'id': int(row.get('id', 0) or 0), 'request_id': int(row.get('id', 0) or 0), 'license_id': int(row.get('license_id', 0) or 0), 'installation_id': format_grouped_digits(str(installation)) if installation is not None else None, 'device_ref': device_reference(device_hash), 'device_display_label': device_display_label(label, device_hash), 'device_label': row.get('device_label'), 'app_version': row.get('app_version'), 'status': row.get('status'), 'email_masked': row.get('email_masked'), 'email_sent_at': row.get('email_sent_at'), 'requested_at': row.get('requested_at'), 'expires_at': row.get('expires_at'), 'confirmation_code_expires_at': row.get('confirmation_code_expires_at'), 'confirmed_at': row.get('confirmed_at'), 'last_seen_at': row.get('last_seen_at')}

def admin_escape(value):
    return html.escape(str(value), quote=True).replace('&#x27;', '&#039;')

def admin_request_string(data, key, default=''):
    value = data.get(key, default)
    if isinstance(value, bool):
        return '1' if value else ''
    if isinstance(value, (str, int, float)):
        return str(value).strip(PHP_TRIM_CHARS)
    return default

def admin_request_int(data, key, default, minimum, maximum):
    raw = data.get(key, default)
    if isinstance(raw, bool):
        value = int(raw)
    else:
        match = re.match('^[\\s]*([+-]?\\d+)', str(raw)) if raw is not None else None
        try:
            value = int(match.group(1)) if match else int(raw) if isinstance(raw, (int, float)) else default
        except (TypeError, ValueError, OverflowError):
            value = default
    return max(minimum, min(maximum, value))

def admin_page_offset(page, limit):
    return max(0, (int(page) - 1) * int(limit))

def admin_like_value(value):
    return '%' + str(value).replace('%', '\\%').replace('_', '\\_') + '%'

def admin_hidden_state(data, keys=('q', 'page', 'limit', 'id', 'license_key', 'device_id', 'installation_id')):
    out = []
    for key in keys:
        if key not in data or data[key] is None or data[key] == '':
            continue
        value = data[key]
        if isinstance(value, (dict, list)):
            continue
        out.append('<input type="hidden" name="' + admin_escape(key) + '" value="' + admin_escape(value) + '">')
    return ''.join(out)
