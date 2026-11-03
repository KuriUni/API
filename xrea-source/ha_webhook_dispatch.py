"""HA-authorized delivery worker for queued BaaS webhook events."""
from native_http import make_response, add_headers, legacy_compatible
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import time
from email.parser import BytesParser
from email.policy import default as default_email_policy
from urllib.parse import parse_qsl, urlsplit
import database
from core import _aes_gcm_decrypt, php_int_cast, token_secret
from http_utils import json_response
from migration_config import secret_value
from baas_handlers import _webhook_url_allowed
from v3_handlers import _assert_write_fence

class _PinnedHTTPSConnection(http.client.HTTPSConnection):

    def __init__(self, host, address, timeout=5):
        super().__init__(host, port=443, timeout=timeout, context=ssl.create_default_context())
        self._pinned_address = address

    def connect(self):
        raw = socket.create_connection((self._pinned_address, 443), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)

def _public_ipv4_addresses(host):
    try:
        values = socket.gethostbyname_ex(host)[2]
        addresses = list(dict.fromkeys(values))
        if not addresses:
            return []
        for value in addresses:
            address = ipaddress.ip_address(value)
            if address.version != 4 or not address.is_global:
                return []
        return addresses
    except (OSError, ValueError):
        try:
            address = ipaddress.ip_address(host)
            return [str(address)] if address.version == 4 and address.is_global else []
        except ValueError:
            return []

def _delay_seconds(attempt):
    return min(21600, 30 * 2 ** min(9, max(0, int(attempt) - 1)))

@legacy_compatible(callback_index=None, request_index=0)
def _php_post_limit(request_context):
    """Read only PHP's POST form variable; query and JSON bodies are ignored."""
    fields = {}
    content_type = str(request_context.get('content_type', ''))
    media_type = content_type.split(';', 1)[0].strip().lower()
    stream = request_context.get('body_stream')
    raw = stream.read() if stream is not None else b''
    if media_type == 'application/x-www-form-urlencoded':
        pairs = parse_qsl(raw.decode('utf-8', 'replace'), keep_blank_values=True)
        for name, value in pairs:
            name = name.replace(' ', '_').replace('.', '_')
            match = re.match('^([^\\[\\]]+)\\[', name)
            if match:
                base = match.group(1)
                previous = fields.get(base)
                if not isinstance(previous, list):
                    previous = [] if previous is None else [previous]
                previous.append(value)
                fields[base] = previous
            else:
                fields[name] = value
    elif media_type == 'multipart/form-data':
        try:
            headers = ('Content-Type: ' + content_type + '\r\nMIME-Version: 1.0\r\n\r\n').encode('ascii', 'replace')
            message = BytesParser(policy=default_email_policy).parsebytes(headers + raw)
            for part in message.iter_parts():
                if part.get_content_disposition() != 'form-data' or part.get_filename() is not None:
                    continue
                name = part.get_param('name', header='content-disposition')
                if not isinstance(name, str):
                    continue
                name = name.replace(' ', '_').replace('.', '_')
                match = re.match('^([^\\[\\]]+)\\[', name)
                value = (part.get_payload(decode=True) or b'').decode(part.get_content_charset() or 'utf-8', 'replace')
                fields[match.group(1) if match else name] = value
        except Exception:
            fields = {}
    raw_limit = fields.get('limit', 20)
    return max(1, min(50, php_int_cast(raw_limit)))

def _safe_update(connection, query, params):
    with connection.cursor() as cursor:
        cursor.execute(query, params)

def _dispatch_one(connection, row, config):
    delivery_id = int(row['id'])
    event_type = str(row.get('event_type') or '')
    event_id = str(row.get('event_id') or '')
    url = str(row.get('url') or '')
    try:
        parsed = urlsplit(url)
        host = str(parsed.hostname or '').lower()
        port = int(parsed.port or 443)
    except ValueError:
        host, port = ('', 0)
        parsed = None
    addresses = _public_ipv4_addresses(host) if host else []
    if not parsed or not _webhook_url_allowed(url) or (not addresses) or (port != 443):
        _safe_update(connection, "UPDATE tenant_webhook_deliveries SET status='failed',last_error='unsafe_destination' WHERE id=%s AND status IN ('pending','retry')", (delivery_id,))
        return 'failed'
    if re.fullmatch('[A-Za-z0-9._-]{1,120}', event_type) is None or re.fullmatch('[A-Za-z0-9_-]{1,128}', event_id) is None:
        _safe_update(connection, "UPDATE tenant_webhook_deliveries SET status='failed',last_error='invalid_event_metadata' WHERE id=%s AND status IN ('pending','retry')", (delivery_id,))
        return 'failed'
    payload = str(row.get('payload_json') or '')
    try:
        secret_bytes = _aes_gcm_decrypt(token_secret(config), b'offline-storage|', b'TUTI-OFFLINE-V1', str(row.get('secret_enc') or ''))
        secret = secret_bytes.decode('utf-8')
    except Exception:
        _safe_update(connection, "UPDATE tenant_webhook_deliveries SET status='failed',last_error='secret_decryption_failed' WHERE id=%s AND status IN ('pending','retry')", (delivery_id,))
        return 'failed'
    timestamp = str(int(time.time()))
    line_destination = host == 'api.line.me' and parsed.path == '/v2/bot/message/push'
    if line_destination:
        recipient = dict(parse_qsl(parsed.query, keep_blank_values=True)).get('to', '')
        if re.fullmatch('[UCR][0-9a-fA-F]{32}', recipient) is None:
            _safe_update(connection, "UPDATE tenant_webhook_deliveries SET status='failed',last_error='invalid_line_recipient' WHERE id=%s AND status IN ('pending','retry')", (delivery_id,))
            return 'failed'
        try:
            envelope = json.loads(payload)
        except json.JSONDecodeError:
            envelope = {}
        data = envelope.get('data') if isinstance(envelope, dict) and isinstance(envelope.get('data'), (dict, list)) else {}
        message = ('TUTI BaaS 通知\nイベント: ' + event_type + '\nデータ: ' + json.dumps(data, ensure_ascii=False, separators=(',', ':')))[:5000]
        payload = json.dumps({'to': recipient, 'messages': [{'type': 'text', 'text': message}]}, ensure_ascii=False, separators=(',', ':'))
        target = '/v2/bot/message/push'
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + secret, 'User-Agent': 'tuti-line-messaging/1.0', 'Host': host}
    else:
        target = parsed.path or '/'
        if parsed.query:
            target += '?' + parsed.query
        signature = hmac.new(secret_bytes, (timestamp + '.' + payload).encode(), hashlib.sha256).hexdigest()
        headers = {'Content-Type': 'application/json', 'User-Agent': 'tuti-webhook/1.1', 'X-TUTI-Event': event_type, 'X-TUTI-Event-ID': event_id, 'X-TUTI-Timestamp': timestamp, 'X-TUTI-Signature': 'v1=' + signature, 'Host': host}
    status, error = (0, '')
    connection_http = None
    try:
        connection_http = _PinnedHTTPSConnection(host, addresses[0], timeout=5)
        connection_http.request('POST', target, body=payload.encode('utf-8'), headers=headers)
        response = connection_http.getresponse()
        status = int(response.status)
        response.read(1024)
    except Exception as exc:
        error = str(exc).replace('\r', ' ').replace('\n', ' ')[:180] or 'http_error'
    finally:
        if connection_http is not None:
            connection_http.close()
    attempt = int(row.get('attempt_count') or 0) + 1
    if 200 <= status < 300:
        _safe_update(connection, "UPDATE tenant_webhook_deliveries SET status='delivered',attempt_count=%s,last_status=%s,last_error=NULL,delivered_at=UTC_TIMESTAMP() WHERE id=%s AND status IN ('pending','retry')", (attempt, status, delivery_id))
        return 'delivered'
    if attempt >= 8:
        _safe_update(connection, "UPDATE tenant_webhook_deliveries SET status='failed',attempt_count=%s,last_status=%s,last_error=%s WHERE id=%s AND status IN ('pending','retry')", (attempt, status, error or 'http_error', delivery_id))
        return 'failed'
    _safe_update(connection, "UPDATE tenant_webhook_deliveries SET status='retry',attempt_count=%s,last_status=%s,last_error=%s,next_attempt_at=DATE_ADD(UTC_TIMESTAMP(),INTERVAL %s SECOND) WHERE id=%s AND status IN ('pending','retry')", (attempt, status, error or 'http_error', _delay_seconds(attempt), delivery_id))
    return 'retried'

@legacy_compatible(callback_index=1, request_index=0)
def webhook_dispatch(request_context):
    from ha_handlers import _ha_authorized_scope, _effective_role
    if not _ha_authorized_scope(request_context, 'ha:operate'):
        return json_response('404 Not Found', {'ok': False, 'error': 'not_found'})
    if str(request_context.get('method', '')) != 'POST':
        return json_response('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
    role = os.environ.get('PYTHON_MIGRATION_HA_ROLE', 'unknown')
    effective = _effective_role()
    if not (role == 'primary' and effective != 'maintenance' or (role == 'standby' and effective == 'promoted')):
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'server_not_writable'})
    limit = _php_post_limit(request_context)
    connection = None
    locked = False
    try:
        connection = database.connect()
        _assert_write_fence(connection)
        with connection.cursor() as cursor:
            cursor.execute("SELECT GET_LOCK('tuti_webhook_dispatch_v1',0) AS acquired")
            row = cursor.fetchone()
        locked = bool(row and int(row.get('acquired') or 0) == 1)
        if not locked:
            return json_response('409 Conflict', {'ok': False, 'error': 'dispatcher_already_running'})
        with connection.cursor() as cursor:
            cursor.execute("SELECT d.*,w.url,w.secret_enc FROM tenant_webhook_deliveries d JOIN tenant_webhooks w ON w.id=d.webhook_id AND w.tenant_id=d.tenant_id WHERE d.status IN ('pending','retry') AND d.next_attempt_at<=UTC_TIMESTAMP() AND w.status='active' ORDER BY d.id LIMIT %s", (limit,))
            rows = cursor.fetchall()
        connection.commit()
        config = {'token_secret': secret_value('token_secret')}
        counts = {'delivered': 0, 'retried': 0, 'failed': 0}
        for row in rows:
            counts[_dispatch_one(connection, row, config)] += 1
            connection.commit()
        connection.commit()
        return json_response('200 OK', {'ok': True, 'processed': len(rows), 'delivered': counts['delivered'], 'retried': counts['retried'], 'failed': counts['failed']})
    except database.DatabaseConfigurationError:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection is not None:
            connection.rollback()
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'webhook_dispatch_failed'})
    finally:
        if connection is not None:
            if locked:
                try:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT RELEASE_LOCK('tuti_webhook_dispatch_v1')")
                except Exception:
                    pass
            connection.close()
