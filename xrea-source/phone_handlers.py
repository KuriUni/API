"""Python port of the supported portion of the legacy phone activation API."""
from native_http import make_response, add_headers, legacy_compatible
import os
import hmac
import hashlib
import smtplib
import ssl
import subprocess
import io
import json
import logging
import uuid
from email.parser import BytesParser
from email.policy import default as default_email_policy
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import parse_qsl
import database
from core import PHP_TRIM_CHARS, device_display_label, device_hash, device_reference, first_non_empty, hash_secret, is_valid_device_fingerprint, is_valid_license_key_format, license_key_hash, normalize_device_fingerprint, normalize_digits, normalize_license_key, normalize_text, normalize_app_version, parse_utc_datetime, normalize_email_address, mask_email_address, phone_email_encrypt, phone_confirmation_code, random_digits, token_hash, key_pepper, random_token
from http_utils import MAX_JSON_BYTES, RequestError, read_bounded_body, v2_response
from v2_handlers import V2Error, _attempt_count, _clear_auth_attempts, _record_auth_attempt, _runtime_config, _license_payload, ACCESS_TTL, REFRESH_TTL, _non_writable_role
from v3_handlers import _assert_write_fence
_log = logging.getLogger(__name__)
_ASCII_LOWER = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')

def _phone_php_string(value):
    if value is None or value is False:
        return ''
    if value is True:
        return '1'
    if isinstance(value, (list, dict)):
        return 'Array'
    return str(value)

def _phone_trim(value):
    return _phone_php_string(value).strip(PHP_TRIM_CHARS)

@legacy_compatible(callback_index=None, request_index=0)
def _phone_client_ip(request_context):
    value = request_context.get('client_address')
    return '0.0.0.0' if value is None else str(value)

def _reject_json_constant(value):
    raise ValueError('invalid_json_constant')

def _php_form_key(value):
    """PHP parse_str converts spaces and dots in input names to underscores."""
    return str(value).replace(' ', '_').replace('.', '_')

@legacy_compatible(callback_index=None, request_index=0)
def _phone_request_data(request_context):
    """Match v2_request_data(): JSON only for JSON media, otherwise $_POST + $_GET."""
    content_type = str(request_context.get('content_type') or request_context.get('header:content-type') or '').translate(_ASCII_LOWER)
    if 'application/json' in content_type:
        raw = read_bounded_body(request_context, MAX_JSON_BYTES)
        try:
            decoded = json.loads(raw.decode('utf-8'), parse_constant=_reject_json_constant)
        except (UnicodeDecodeError, ValueError, RecursionError):
            raise RequestError('invalid_json')
        if isinstance(decoded, list):
            decoded = {str(i): value for i, value in enumerate(decoded)}
        if not isinstance(decoded, dict):
            raise RequestError('invalid_request_shape')
        data = decoded
    else:
        raw = read_bounded_body(request_context, MAX_JSON_BYTES)
        post = {}
        if content_type.startswith('application/x-www-form-urlencoded'):
            try:
                pairs = parse_qsl(raw.decode('utf-8'), keep_blank_values=True)
            except UnicodeDecodeError:
                raise RequestError('invalid_request_shape')
            post = {_php_form_key(key): value for key, value in pairs}
            if any(('[' in key or ']' in key for key, _ in pairs)):
                raise RequestError('invalid_request_shape')
        elif content_type.startswith('multipart/form-data'):
            try:
                header = ('Content-Type: ' + str(request_context.get('content_type', '')) + '\r\nMIME-Version: 1.0\r\n\r\n').encode('ascii')
                message = BytesParser(policy=default_email_policy).parsebytes(header + raw)
                for part in message.iter_parts():
                    if part.get_content_disposition() != 'form-data' or part.get_filename() is not None:
                        continue
                    key = part.get_param('name', header='content-disposition')
                    if not isinstance(key, str) or '[' in key or ']' in key:
                        raise RequestError('invalid_request_shape')
                    payload = part.get_payload(decode=True) or b''
                    charset = part.get_content_charset() or 'utf-8'
                    post[_php_form_key(key)] = payload.decode(charset)
            except RequestError:
                raise
            except Exception:
                raise RequestError('invalid_request_shape')
        query = {}
        try:
            pairs = parse_qsl(str(request_context.get('query', '')), keep_blank_values=True)
        except Exception:
            pairs = []
        if any(('[' in key or ']' in key for key, _ in pairs)):
            raise RequestError('invalid_request_shape')
        query = {_php_form_key(key): value for key, value in pairs}
        data = dict(query)
        data.update(post)
    if len(data) > 100:
        raise RequestError('too_many_fields')
    for value in data.values():
        if isinstance(value, (dict, list)):
            raise RequestError('invalid_request_shape')
        if isinstance(value, str) and len(value.encode('utf-8')) > 4096:
            raise RequestError('value_too_long')
    return data

def _ensure_phone_schema(connection):
    """Port v2_ensure_schema's phone activation tables and additive columns."""
    statements = ('CREATE TABLE IF NOT EXISTS licenses (\n            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,key_hash CHAR(64) NOT NULL,\n            label VARCHAR(100) NULL,active TINYINT(1) NOT NULL DEFAULT 1,\n            max_devices INT NOT NULL DEFAULT 1,expires_at DATETIME NULL,revoked_at DATETIME NULL,\n            last_activated_at DATETIME NULL,last_seen_at DATETIME NULL,reissue_used_at DATETIME NULL,\n            offline_lookup CHAR(20) NULL,offline_secret_enc TEXT NULL,offline_epoch INT UNSIGNED NOT NULL DEFAULT 1,\n            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,\n            PRIMARY KEY(id),UNIQUE KEY uq_licenses_key_hash(key_hash),\n            UNIQUE KEY uq_licenses_offline_lookup(offline_lookup)\n        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci', 'CREATE TABLE IF NOT EXISTS license_devices (\n            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,license_id BIGINT UNSIGNED NOT NULL,\n            device_hash CHAR(64) NOT NULL,device_label VARCHAR(120) NULL,\n            access_token_hash CHAR(64) NOT NULL,refresh_token_hash CHAR(64) NOT NULL,\n            access_expires_at DATETIME NOT NULL,refresh_expires_at DATETIME NOT NULL,\n            first_activated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n            last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,revoked_at DATETIME NULL,\n            last_ip_hash CHAR(64) NULL,app_version VARCHAR(40) NULL,token_version INT NOT NULL DEFAULT 1,\n            PRIMARY KEY(id),UNIQUE KEY uq_license_device(license_id,device_hash),\n            UNIQUE KEY uq_license_access_token(access_token_hash),UNIQUE KEY uq_license_refresh_token(refresh_token_hash),\n            KEY idx_license_devices_license_revoked(license_id,revoked_at),\n            KEY idx_license_devices_access_expires(access_expires_at),\n            KEY idx_license_devices_refresh_expires(refresh_expires_at)\n        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci', "CREATE TABLE IF NOT EXISTS auth_attempts (\n            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,ip_hash CHAR(64) NOT NULL,\n            action VARCHAR(32) NOT NULL DEFAULT 'generic',subject_type VARCHAR(32) NOT NULL DEFAULT 'ip',\n            subject_hash CHAR(64) NULL,success TINYINT(1) NOT NULL DEFAULT 0,error_code VARCHAR(64) NULL,\n            attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(id),\n            KEY idx_attempts_ip_time(ip_hash,attempted_at),\n            KEY idx_attempts_action_subject_time(action,subject_type,subject_hash,attempted_at),\n            KEY idx_attempts_success_time(success,attempted_at)\n        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci", "CREATE TABLE IF NOT EXISTS phone_activation_requests (\n            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,license_id BIGINT UNSIGNED NOT NULL,\n            device_hash CHAR(64) NOT NULL,installation_id VARCHAR(80) NOT NULL,\n            device_label VARCHAR(120) NULL,app_version VARCHAR(40) NULL,\n            status VARCHAR(20) NOT NULL DEFAULT 'requested',requested_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,\n            expires_at DATETIME NOT NULL,email_enc TEXT NULL,email_masked VARCHAR(254) NULL,email_sent_at DATETIME NULL,\n            confirmation_code_hash CHAR(64) NULL,confirmation_code_expires_at DATETIME NULL,\n            confirmation_code_issued_at DATETIME NULL,confirmation_code_issue_count INT NOT NULL DEFAULT 0,\n            confirmation_fail_count INT NOT NULL DEFAULT 0,confirmed_at DATETIME NULL,\n            last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,last_ip_hash CHAR(64) NULL,\n            confirmed_ip_hash CHAR(64) NULL,cancelled_at DATETIME NULL,cancelled_reason VARCHAR(120) NULL,\n            PRIMARY KEY(id),UNIQUE KEY uq_phone_activation_installation(installation_id),\n            KEY idx_phone_activation_license_status(license_id,status),\n            KEY idx_phone_activation_device(license_id,device_hash),KEY idx_phone_activation_expires(expires_at),\n            KEY idx_phone_activation_code_expires(confirmation_code_expires_at),\n            KEY idx_phone_activation_cancelled(cancelled_at)\n        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci")
    with connection.cursor() as cursor:
        for statement in statements:
            cursor.execute(statement)
        additions = {'licenses': {'max_devices': 'INT NOT NULL DEFAULT 1', 'evaluation_days': 'INT NULL', 'evaluation_started_at': 'DATETIME NULL', 'revoked_at': 'DATETIME NULL', 'deleted_at': 'DATETIME NULL', 'deleted_reason': 'VARCHAR(200) NULL', 'deleted_by': 'CHAR(64) NULL', 'last_activated_at': 'DATETIME NULL', 'last_seen_at': 'DATETIME NULL', 'updated_at': 'DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP'}, 'auth_attempts': {'action': "VARCHAR(32) NOT NULL DEFAULT 'generic'", 'subject_type': "VARCHAR(32) NOT NULL DEFAULT 'ip'", 'subject_hash': 'CHAR(64) NULL', 'success': 'TINYINT(1) NOT NULL DEFAULT 0', 'error_code': 'VARCHAR(64) NULL'}, 'phone_activation_requests': {'email_enc': 'TEXT NULL', 'email_masked': 'VARCHAR(254) NULL', 'email_sent_at': 'DATETIME NULL', 'confirmation_code_issued_at': 'DATETIME NULL', 'confirmation_code_issue_count': 'INT NOT NULL DEFAULT 0', 'confirmation_fail_count': 'INT NOT NULL DEFAULT 0', 'cancelled_at': 'DATETIME NULL', 'cancelled_reason': 'VARCHAR(120) NULL'}}
        for table, columns in additions.items():
            for column, definition in columns.items():
                cursor.execute('SELECT COUNT(*) AS n FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=%s AND column_name=%s', (table, column))
                if int((cursor.fetchone() or {}).get('n') or 0) == 0:
                    cursor.execute(f'ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}')
        foreign_keys = (('license_devices', 'fk_license_devices_license', 'license_id'), ('phone_activation_requests', 'fk_phone_activation_requests_license', 'license_id'))
        for table, name, column in foreign_keys:
            cursor.execute("SELECT COUNT(*) AS n FROM information_schema.table_constraints WHERE table_schema=DATABASE() AND table_name=%s AND constraint_name=%s AND constraint_type='FOREIGN KEY'", (table, name))
            if int((cursor.fetchone() or {}).get('n') or 0) == 0:
                try:
                    cursor.execute(f'ALTER TABLE `{table}` ADD CONSTRAINT `{name}` FOREIGN KEY (`{column}`) REFERENCES licenses(id) ON DELETE CASCADE')
                except Exception:
                    pass

def _expire_phone_requests(connection):
    with connection.cursor() as cursor:
        cursor.execute("UPDATE phone_activation_requests SET status='expired' WHERE confirmed_at IS NULL AND status<>'expired' AND expires_at<UTC_TIMESTAMP()")
    connection.commit()

def _error_id():
    return uuid.uuid4().hex[:8]

@legacy_compatible(callback_index=0, request_index=None)
def _error_response(status, stage, rid, extra=None):
    error_id = _error_id()
    _log.error('phone activation failure error_id=%s stage=%s', error_id, stage)
    payload = {'success': False, 'error_id': error_id}
    if extra:
        payload.update(extra)
    return v2_response(status, payload, rid)
_log = logging.getLogger(__name__)

def _request_payload(row):
    return {'request_id': int(row.get('id') or 0), 'license_id': int(row.get('license_id') or 0), 'installation_id': '-'.join((normalize_digits(row.get('installation_id') or '')[i:i + 6] for i in range(0, 54, 6))), 'device_ref': device_reference(str(row.get('device_hash') or '')), 'device_display_label': device_display_label(str(row.get('device_label') or ''), str(row.get('device_hash') or '')), 'device_label': row.get('device_label'), 'app_version': row.get('app_version'), 'status': row.get('status'), 'requested_at': row.get('requested_at'), 'expires_at': row.get('expires_at'), 'confirmation_code_expires_at': row.get('confirmation_code_expires_at'), 'confirmation_code_issued_at': row.get('confirmation_code_issued_at'), 'email_masked': row.get('email_masked'), 'email_sent_at': row.get('email_sent_at'), 'confirmation_code_issue_count': int(row.get('confirmation_code_issue_count') or 0), 'confirmation_fail_count': int(row.get('confirmation_fail_count') or 0), 'confirmed_at': row.get('confirmed_at'), 'cancelled_at': row.get('cancelled_at'), 'cancelled_reason': row.get('cancelled_reason')}

@legacy_compatible(callback_index=1, request_index=0)
def _phone_status(request_context, data, rid):
    connection = None
    try:
        config = _runtime_config()
        connection = database.connect()
        _ensure_phone_schema(connection)
        _expire_phone_requests(connection)
        ip_hash = hash_secret(_phone_client_ip(request_context))
        installation_id = normalize_digits(first_non_empty(data, ('installation_id', 'installation', 'phone_installation_id')))
        if installation_id:
            if len(installation_id) != 54:
                return v2_response(400, {'success': False, 'error': 'installation_id の形式が正しくありません。'}, rid)
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM phone_activation_requests WHERE installation_id=%s LIMIT 1', (installation_id,))
                row = cursor.fetchone()
            if not row:
                return v2_response(404, {'success': False, 'error': 'installation ID が見つかりません。'}, rid)
            return v2_response(200, {'success': True, 'api_version': '2.0', 'fallback_mode': True, 'request': _request_payload(row)}, rid)
        license_key = normalize_license_key(first_non_empty(data, ('license_key', 'product_key', 'key')))
        if not license_key:
            return v2_response(400, {'success': False, 'error': 'license_key か installation_id が必要です。'}, rid)
        if not is_valid_license_key_format(license_key):
            return v2_response(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'}, rid)
        subject = hash_secret(license_key)
        if _attempt_count(connection, 'phone_status', 'license_key', subject) >= 5:
            _record_auth_attempt(connection, ip_hash, 'phone_status', 'license_key', subject, False, 'locked')
            connection.commit()
            return v2_response(429, {'success': False, 'error': '試行回数が多すぎます。しばらくしてから再試行してください。'}, rid)
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM licenses WHERE key_hash=%s AND deleted_at IS NULL LIMIT 1', (license_key_hash(config, license_key),))
            license_row = cursor.fetchone()
        if not license_row:
            _record_auth_attempt(connection, ip_hash, 'phone_status', 'license_key', subject, False, 'not_found')
            connection.commit()
            return v2_response(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'}, rid)
        _clear_auth_attempts(connection, 'phone_status', 'license_key', subject)
        _record_auth_attempt(connection, ip_hash, 'phone_status', 'license_key', subject, True, 'ok')
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS cnt FROM license_devices WHERE license_id=%s AND revoked_at IS NULL AND refresh_expires_at>UTC_TIMESTAMP()', (int(license_row['id']),))
            active_sessions = int((cursor.fetchone() or {}).get('cnt') or 0)
        connection.commit()
        return v2_response(200, {'success': True, 'api_version': '2.0', 'fallback_mode': True, 'license': _license_payload(config, license_row), 'active_sessions': active_sessions}, rid)
    except database.DatabaseConfigurationError:
        return _error_response(503, 'phone_status_bootstrap', rid)
    except Exception:
        if connection:
            connection.rollback()
        return _error_response(503, 'phone_status', rid)
    finally:
        if connection:
            connection.close()

def _mail_confirmation_code(recipient, installation_id, code):
    """Deliver through explicitly configured SMTP or the production host MTA."""
    host = os.environ.get('PYTHON_MIGRATION_SMTP_HOST', '').strip()
    transport = os.environ.get('PYTHON_MIGRATION_MAIL_TRANSPORT', 'smtp')
    sender = os.environ.get('PYTHON_MIGRATION_MAIL_FROM', 'no-reply@2415.jp').strip()
    if transport not in {'smtp', 'sendmail'} or not normalize_email_address(sender) or (not normalize_email_address(recipient)):
        return False
    if transport == 'smtp' and (not host):
        return False
    message = EmailMessage()
    message['Subject'] = 'TUTI LICENSE 電話認証コード'
    message['From'] = f'TUTI LICENSE <{sender}>'
    message['To'] = recipient
    grouped = '-'.join((installation_id[i:i + 6] for i in range(0, 54, 6)))
    message.set_content(f'TUTI LICENSE 電話認証\n\n確認コード: {code}\nインストールID: {grouped}\n\nこのコードは10分間有効です。心当たりがない場合は、このメールを破棄してください。\n')
    try:
        timeout = max(1, min(30, int(os.environ.get('PYTHON_MIGRATION_SMTP_TIMEOUT', '10'))))
        if transport == 'sendmail':
            if os.environ.get('PYTHON_MIGRATION_PROFILE') != 'production':
                return False
            executable = os.environ.get('PYTHON_MIGRATION_SENDMAIL_PATH', '/usr/sbin/sendmail')
            if executable not in {'/usr/sbin/sendmail', '/usr/lib/sendmail'}:
                return False
            result = subprocess.run([executable, '-t', '-oi'], input=message.as_bytes(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
            return result.returncode == 0
        port = int(os.environ.get('PYTHON_MIGRATION_SMTP_PORT', '587'))
        username = os.environ.get('PYTHON_MIGRATION_SMTP_USER', '')
        from migration_config import secret_value
        password = secret_value('smtp_password')
        implicit_tls = os.environ.get('PYTHON_MIGRATION_SMTP_SSL', '0') == '1'
        tls = ssl.create_default_context()
        client_factory = smtplib.SMTP_SSL if implicit_tls else smtplib.SMTP
        options = {'context': tls} if implicit_tls else {}
        with client_factory(host, port, timeout=timeout, **options) as client:
            if not implicit_tls and os.environ.get('PYTHON_MIGRATION_SMTP_STARTTLS', '1') == '1':
                client.starttls(context=tls)
            if username:
                client.login(username, password)
            client.send_message(message)
        return True
    except Exception:
        return False

def _phone_ip_rate_limited(connection, ip_hash):
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) AS n FROM auth_attempts WHERE ip_hash=%s AND attempted_at >= (UTC_TIMESTAMP() - INTERVAL 15 MINUTE)', (ip_hash,))
        limited = int((cursor.fetchone() or {}).get('n') or 0) >= 30
        if limited:
            cursor.execute("INSERT INTO auth_attempts(ip_hash,action,subject_type,subject_hash,success,attempted_at) VALUES(%s,'generic','ip',%s,0,UTC_TIMESTAMP())", (ip_hash, ip_hash))
    if limited:
        connection.commit()
    return limited

@legacy_compatible(callback_index=4, request_index=2)
def _request_phone_activation(connection, config, request_context, data, rid):
    license_key = normalize_license_key(first_non_empty(data, ('license_key', 'product_key', 'key')))
    fingerprint = normalize_device_fingerprint(first_non_empty(data, ('device_fingerprint', 'device_id', 'device')))
    email = normalize_email_address(first_non_empty(data, ('email', 'email_address')))
    label = normalize_text(first_non_empty(data, ('device_label', 'device_name')))[:120]
    app_version = normalize_app_version(first_non_empty(data, ('app_version', 'client_version')))
    if not email:
        return v2_response(400, {'success': False, 'error': '有効な email が必要です。'}, rid)
    if not license_key:
        return v2_response(400, {'success': False, 'error': 'license_key が必要です。'}, rid)
    if not is_valid_license_key_format(license_key):
        return v2_response(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'}, rid)
    if not fingerprint:
        return v2_response(400, {'success': False, 'error': 'device_fingerprint が必要です。'}, rid)
    if not is_valid_device_fingerprint(fingerprint):
        return v2_response(400, {'success': False, 'error': 'device_fingerprint の形式が正しくありません。'}, rid)
    ip_hash = hash_secret(_phone_client_ip(request_context))
    key_subject, device_subject = (hash_secret(license_key), hash_secret(fingerprint))
    if _phone_ip_rate_limited(connection, ip_hash):
        return v2_response(429, {'success': False, 'error': '試行回数が多すぎます。しばらくしてから再試行してください。'}, rid)
    for kind, subject in (('license_key', key_subject), ('device_fingerprint', device_subject)):
        if _attempt_count(connection, 'phone_request', kind, subject) >= 5:
            _record_auth_attempt(connection, ip_hash, 'phone_request', kind, subject, False, 'locked')
            connection.commit()
            return v2_response(429, {'success': False, 'error': '試行回数が多すぎます。しばらくしてから再試行してください。'}, rid)
    with connection.cursor() as cursor:
        cursor.execute('SELECT * FROM licenses WHERE key_hash=%s AND deleted_at IS NULL LIMIT 1', (license_key_hash(config, license_key),))
        license_row = cursor.fetchone()
    if not license_row:
        for kind, subject in (('license_key', key_subject), ('device_fingerprint', device_subject)):
            _record_auth_attempt(connection, ip_hash, 'phone_request', kind, subject, False, 'not_found')
        connection.commit()
        return v2_response(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'}, rid)
    expires = parse_utc_datetime(str(license_row.get('expires_at') or ''))
    if int(license_row.get('active') or 0) != 1 or license_row.get('revoked_at') or (expires and expires <= datetime.now(timezone.utc)):
        _record_auth_attempt(connection, ip_hash, 'phone_request', 'license_key', key_subject, False, 'inactive')
        _record_auth_attempt(connection, ip_hash, 'phone_request', 'device_fingerprint', device_subject, False, 'inactive')
        connection.commit()
        return v2_response(400, {'success': False, 'error': 'ライセンスキーが正しくありません。'}, rid)
    device_digest = device_hash(config, fingerprint)
    installation_id = random_digits(54)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM licenses WHERE id=%s AND deleted_at IS NULL LIMIT 1 FOR UPDATE', (int(license_row['id']),))
            license_row = cursor.fetchone()
            if not license_row:
                raise RuntimeError('license_missing')
            cursor.execute('SELECT * FROM license_devices WHERE license_id=%s AND device_hash=%s LIMIT 1 FOR UPDATE', (int(license_row['id']), device_digest))
            device_row = cursor.fetchone()
            cursor.execute('SELECT COUNT(*) AS n FROM license_devices WHERE license_id=%s AND revoked_at IS NULL AND refresh_expires_at>UTC_TIMESTAMP()', (int(license_row['id']),))
            active_count = int((cursor.fetchone() or {}).get('n') or 0)
            if not (device_row and (not device_row.get('revoked_at'))) and active_count >= max(1, int(license_row.get('max_devices') or 1)):
                raise RuntimeError('device_limit_reached')
            cursor.execute('SELECT * FROM phone_activation_requests WHERE license_id=%s AND device_hash=%s AND confirmed_at IS NULL AND cancelled_at IS NULL AND expires_at>UTC_TIMESTAMP() ORDER BY id DESC LIMIT 1 FOR UPDATE', (int(license_row['id']), device_digest))
            old = cursor.fetchone()
            encrypted_email = phone_email_encrypt(config, email)
            if old:
                request_id = int(old['id'])
                installation_id = str(old['installation_id'])
                cursor.execute('UPDATE phone_activation_requests SET email_enc=%s,email_masked=%s WHERE id=%s', (encrypted_email, mask_email_address(email), request_id))
            else:
                cursor.execute("INSERT INTO phone_activation_requests(license_id,device_hash,installation_id,device_label,app_version,status,requested_at,expires_at,last_ip_hash,last_seen_at,email_enc,email_masked) VALUES(%s,%s,%s,%s,%s,'requested',UTC_TIMESTAMP(),%s,%s,UTC_TIMESTAMP(),%s,%s)", (int(license_row['id']), device_digest, installation_id, label or None, app_version or None, (now + timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S'), ip_hash, encrypted_email, mask_email_address(email)))
                request_id = int(cursor.lastrowid)
            email_subject = hmac.new(key_pepper(config).encode('utf-8'), email.encode('utf-8'), hashlib.sha256).hexdigest()
            cursor.execute("SELECT COUNT(*) AS n FROM auth_attempts WHERE action='phone_email_send' AND subject_type='email' AND subject_hash=%s AND attempted_at >= (UTC_TIMESTAMP() - INTERVAL 3600 SECOND)", (email_subject,))
            if int((cursor.fetchone() or {}).get('n') or 0) >= 3:
                connection.rollback()
                return v2_response(429, {'success': False, 'error': 'このメールアドレスへの送信回数が上限に達しました。1時間後に再試行してください。'}, rid)
            cursor.execute('SELECT * FROM phone_activation_requests WHERE id=%s LIMIT 1', (request_id,))
            request_row = cursor.fetchone()
            if int(request_row.get('confirmation_code_issue_count') or 0) >= 5:
                connection.rollback()
                return v2_response(400, {'success': False, 'error': 'confirmation code の再発行回数の上限に達しています。'}, rid)
            code = phone_confirmation_code()
            cursor.execute("UPDATE phone_activation_requests SET confirmation_code_hash=%s,confirmation_code_expires_at=%s,confirmation_code_issued_at=UTC_TIMESTAMP(),confirmation_code_issue_count=confirmation_code_issue_count+1,confirmation_fail_count=0,cancelled_at=NULL,cancelled_reason=NULL,status='code_issued' WHERE id=%s AND confirmed_at IS NULL", (token_hash(config, code), (now + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S'), request_id))
            cursor.execute("INSERT INTO auth_attempts(ip_hash,action,subject_type,subject_hash,success,error_code,attempted_at) VALUES(%s,'phone_email_send','email',%s,0,'reserved',UTC_TIMESTAMP())", (ip_hash, email_subject))
            email_attempt_id = int(cursor.lastrowid)
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    if not _mail_confirmation_code(email, installation_id, code):
        with connection.cursor() as cursor:
            cursor.execute("UPDATE phone_activation_requests SET confirmation_code_hash=NULL,confirmation_code_expires_at=NULL,status='requested' WHERE id=%s AND confirmed_at IS NULL", (request_id,))
            cursor.execute("UPDATE auth_attempts SET success=0,error_code='delivery_failed' WHERE id=%s", (email_attempt_id,))
        connection.commit()
        return _error_response(503, 'confirmation_email_delivery_failed', rid, {'error': '確認コードメールを送信できませんでした。時間をおいて再試行してください。'})
    with connection.cursor() as cursor:
        cursor.execute('UPDATE phone_activation_requests SET email_sent_at=UTC_TIMESTAMP() WHERE id=%s', (request_id,))
        cursor.execute("UPDATE auth_attempts SET success=1,error_code='sent' WHERE id=%s", (email_attempt_id,))
        cursor.execute('SELECT * FROM phone_activation_requests WHERE id=%s LIMIT 1', (request_id,))
        request_row = cursor.fetchone() or request_row
    _clear_auth_attempts(connection, 'phone_request', 'license_key', key_subject)
    _clear_auth_attempts(connection, 'phone_request', 'device_fingerprint', device_subject)
    for kind, subject in (('license_key', key_subject), ('device_fingerprint', device_subject)):
        _record_auth_attempt(connection, ip_hash, 'phone_request', kind, subject, True, 'ok')
    connection.commit()
    return v2_response(200, {'success': True, 'api_version': '2.0', 'fallback_mode': True, 'message': '確認コードをメールで送信しました。', 'email_masked': mask_email_address(email), 'request': _request_payload(request_row), 'license': _license_payload(config, license_row)}, rid)

@legacy_compatible(callback_index=4, request_index=2)
def _confirm_phone_activation(connection, config, request_context, data, rid):
    installation_id = normalize_digits(first_non_empty(data, ('installation_id', 'installation', 'phone_installation_id')))
    code = normalize_digits(first_non_empty(data, ('confirmation_code', 'code', 'phone_code')))
    fingerprint = normalize_device_fingerprint(first_non_empty(data, ('device_fingerprint', 'device_id', 'device')))
    label = normalize_text(first_non_empty(data, ('device_label', 'device_name')))[:120]
    app_version = normalize_app_version(first_non_empty(data, ('app_version', 'client_version')))
    for value, message in ((installation_id, 'installation_id が必要です。'), (fingerprint, 'device_fingerprint が必要です。'), (code, 'confirmation_code が必要です。')):
        if not value:
            return v2_response(400, {'success': False, 'error': message}, rid)
    if len(installation_id) != 54:
        return v2_response(400, {'success': False, 'error': 'installation_id の形式が正しくありません。'}, rid)
    if len(code) != 6:
        return v2_response(400, {'success': False, 'error': 'confirmation_code の形式が正しくありません。'}, rid)
    if not is_valid_device_fingerprint(fingerprint):
        return v2_response(400, {'success': False, 'error': 'device_fingerprint の形式が正しくありません。'}, rid)
    ip_hash = hash_secret(_phone_client_ip(request_context))
    subject = hash_secret(installation_id)
    if _phone_ip_rate_limited(connection, ip_hash):
        return v2_response(429, {'success': False, 'error': '試行回数が多すぎます。しばらくしてから再試行してください。'}, rid)
    if _attempt_count(connection, 'phone_confirm', 'installation_id', subject) >= 5:
        _record_auth_attempt(connection, ip_hash, 'phone_confirm', 'installation_id', subject, False, 'locked')
        connection.commit()
        return v2_response(429, {'success': False, 'error': '試行回数が多すぎます。しばらくしてから再試行してください。'}, rid)
    now = datetime.now(timezone.utc)
    device_digest = device_hash(config, fingerprint)
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM phone_activation_requests WHERE installation_id=%s LIMIT 1 FOR UPDATE', (installation_id,))
            request_row = cursor.fetchone()
            if not request_row:
                connection.rollback()
                return v2_response(404, {'success': False, 'error': 'installation ID が見つかりません。'}, rid)
            expires = parse_utc_datetime(str(request_row.get('expires_at') or ''))
            code_expires = parse_utc_datetime(str(request_row.get('confirmation_code_expires_at') or ''))
            valid = request_row.get('status') == 'code_issued' and (not request_row.get('confirmed_at')) and (not request_row.get('cancelled_at')) and bool(request_row.get('confirmation_code_hash')) and (expires is None or expires >= now) and (code_expires is None or code_expires >= now)
            if not valid:
                connection.rollback()
                return v2_response(400, {'success': False, 'error': '確認待ちの有効期限が切れています。'}, rid)
            if str(request_row.get('device_hash') or '') != device_digest:
                connection.rollback()
                return v2_response(400, {'success': False, 'error': '端末情報が一致しません。'}, rid)
            if token_hash(config, code) != str(request_row['confirmation_code_hash']):
                fails = int(request_row.get('confirmation_fail_count') or 0) + 1
                cursor.execute("UPDATE phone_activation_requests SET confirmation_fail_count=%s,status=IF(%s>=5,'cancelled',status),cancelled_at=IF(%s>=5,UTC_TIMESTAMP(),cancelled_at),cancelled_reason=IF(%s>=5,'too_many_confirmation_failures',cancelled_reason) WHERE id=%s AND confirmed_at IS NULL", (fails, fails, fails, fails, int(request_row['id'])))
                _record_auth_attempt(connection, ip_hash, 'phone_confirm', 'installation_id', subject, False, 'wrong_code')
                connection.commit()
                return v2_response(400, {'success': False, 'error': 'confirmation code が一致しません。'}, rid)
            cursor.execute('SELECT * FROM licenses WHERE id=%s AND deleted_at IS NULL LIMIT 1 FOR UPDATE', (int(request_row['license_id']),))
            license_row = cursor.fetchone()
            if not license_row:
                raise RuntimeError('license_missing')
            expiry = parse_utc_datetime(str(license_row.get('expires_at') or ''))
            if int(license_row.get('active') or 0) != 1 or license_row.get('revoked_at') or (expiry and expiry <= now):
                raise RuntimeError('license_inactive')
            if license_row.get('evaluation_days') is not None and (not license_row.get('evaluation_started_at')):
                trial_start = now.replace(microsecond=0)
                trial_expiry = trial_start + timedelta(days=max(1, min(3650, int(license_row['evaluation_days']))))
                cursor.execute('UPDATE licenses SET evaluation_started_at=%s,expires_at=%s WHERE id=%s AND evaluation_started_at IS NULL', (trial_start.strftime('%Y-%m-%d %H:%M:%S'), trial_expiry.strftime('%Y-%m-%d %H:%M:%S'), int(license_row['id'])))
                license_row['evaluation_started_at'] = trial_start.strftime('%Y-%m-%d %H:%M:%S')
                license_row['expires_at'] = trial_expiry.strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('SELECT * FROM license_devices WHERE license_id=%s AND device_hash=%s LIMIT 1 FOR UPDATE', (int(license_row['id']), device_digest))
            device_row = cursor.fetchone()
            cursor.execute('SELECT COUNT(*) AS n FROM license_devices WHERE license_id=%s AND revoked_at IS NULL AND refresh_expires_at>UTC_TIMESTAMP()', (int(license_row['id']),))
            active_count = int((cursor.fetchone() or {}).get('n') or 0)
            if not (device_row and (not device_row.get('revoked_at'))) and active_count >= max(1, int(license_row.get('max_devices') or 1)):
                raise RuntimeError('device_limit_reached')
            access_expiry = now + timedelta(seconds=ACCESS_TTL)
            refresh_expiry = now + timedelta(seconds=REFRESH_TTL)
            license_expiry = parse_utc_datetime(str(license_row.get('expires_at') or ''))
            if license_expiry:
                access_expiry, refresh_expiry = (min(access_expiry, license_expiry), min(refresh_expiry, license_expiry))
            access_token, refresh_token = (random_token(), random_token(48))
            final_label = device_display_label(label or str(request_row.get('device_label') or ''), device_digest)
            access_at = access_expiry.strftime('%Y-%m-%d %H:%M:%S')
            refresh_at = refresh_expiry.strftime('%Y-%m-%d %H:%M:%S')
            if device_row:
                cursor.execute('UPDATE license_devices SET device_label=%s,access_token_hash=%s,refresh_token_hash=%s,access_expires_at=%s,refresh_expires_at=%s,revoked_at=NULL,last_seen_at=UTC_TIMESTAMP(),last_ip_hash=%s,app_version=%s,token_version=token_version+1 WHERE id=%s', (final_label, token_hash(config, access_token), token_hash(config, refresh_token), access_at, refresh_at, ip_hash, app_version or request_row.get('app_version'), int(device_row['id'])))
            else:
                cursor.execute('INSERT INTO license_devices(license_id,device_hash,device_label,access_token_hash,refresh_token_hash,access_expires_at,refresh_expires_at,first_activated_at,last_seen_at,revoked_at,last_ip_hash,app_version,token_version) VALUES(%s,%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP(),UTC_TIMESTAMP(),NULL,%s,%s,1)', (int(license_row['id']), device_digest, final_label, token_hash(config, access_token), token_hash(config, refresh_token), access_at, refresh_at, ip_hash, app_version or request_row.get('app_version')))
            cursor.execute('UPDATE licenses SET last_activated_at=UTC_TIMESTAMP(),last_seen_at=UTC_TIMESTAMP() WHERE id=%s', (int(license_row['id']),))
            cursor.execute("UPDATE phone_activation_requests SET status='confirmed',confirmed_at=UTC_TIMESTAMP(),confirmed_ip_hash=%s,last_seen_at=UTC_TIMESTAMP() WHERE id=%s AND confirmed_at IS NULL AND status='code_issued'", (ip_hash, int(request_row['id'])))
            cursor.execute('SELECT * FROM license_devices WHERE license_id=%s AND device_hash=%s LIMIT 1', (int(license_row['id']), device_digest))
            device_row = cursor.fetchone() or {'device_hash': device_digest, 'device_label': final_label, 'access_expires_at': access_at, 'refresh_expires_at': refresh_at}
            cursor.execute('SELECT * FROM phone_activation_requests WHERE id=%s LIMIT 1', (int(request_row['id']),))
            request_row = cursor.fetchone() or request_row
        _clear_auth_attempts(connection, 'phone_confirm', 'installation_id', subject)
        _record_auth_attempt(connection, ip_hash, 'phone_confirm', 'installation_id', subject, True, 'ok')
        connection.commit()
    except V2Error:
        connection.rollback()
        raise
    except Exception:
        connection.rollback()
        raise
    with connection.cursor() as cursor:
        cursor.execute('SELECT COUNT(*) AS n FROM license_devices WHERE license_id=%s AND revoked_at IS NULL AND refresh_expires_at>UTC_TIMESTAMP()', (int(license_row['id']),))
        active_count = int((cursor.fetchone() or {}).get('n') or 0)
    return v2_response(200, {'success': True, 'api_version': '2.0', 'fallback_mode': True, 'message': 'confirmation code を受け付けました。セッションを発行しました。', 'request': _request_payload(request_row), 'license': _license_payload(config, license_row, device_row), 'active_sessions': active_count, 'remaining_slots': max(0, int(license_row.get('max_devices') or 1) - active_count), 'session': {'access_token': access_token, 'refresh_token': refresh_token, 'access_expires_at': access_at, 'refresh_expires_at': refresh_at, 'device_ref': device_reference(device_digest), 'device_label': final_label, 'app_version': app_version or request_row.get('app_version')}}, rid)

@legacy_compatible(callback_index=1, request_index=0)
def _delegate_session_action(request_context, data, action, rid):
    if action == 'phone_verify':
        if not _phone_trim(data.get('access_token')):
            return v2_response(400, {'success': False, 'error': 'access_token が必要です。'}, rid)
        if _phone_trim(data.get('refresh_token')):
            return v2_response(400, {'success': False, 'error': 'access_token のみを使用してください。'}, rid)
        mapped_action = 'verify'
    elif action == 'phone_refresh':
        if not _phone_trim(data.get('refresh_token')):
            return v2_response(400, {'success': False, 'error': 'refresh_token が必要です。'}, rid)
        if _phone_trim(data.get('access_token')):
            return v2_response(400, {'success': False, 'error': 'refresh_token のみを使用してください。'}, rid)
        mapped_action = 'refresh'
    else:
        if not _phone_trim(data.get('refresh_token')):
            return v2_response(400, {'success': False, 'error': 'refresh_token が必要です。'}, rid)
        if _phone_trim(data.get('access_token')):
            return v2_response(400, {'success': False, 'error': 'refresh_token のみを使用してください。'}, rid)
        mapped_action = 'deactivate'
    child = dict(request_context)
    body = dict(data)
    body['api_action'] = mapped_action
    encoded = json.dumps(body, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    child['content_type'] = 'application/json'
    child['content_length'] = str(len(encoded))
    child['body_stream'] = io.BytesIO(encoded)
    from v2_handlers import activate
    response = activate(child)
    try:
        payload = json.loads(response.body.decode('utf-8'))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return response
    if response.status_code < 400:
        payload['fallback_mode'] = True
    encoded_response = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    headers = [(key.decode('latin-1'), value.decode('latin-1')) for key, value in response.raw_headers if key.lower() != b'content-length']
    headers.append(('Content-Length', str(len(encoded_response))))
    return make_response(encoded_response, response.status_code, headers)

@legacy_compatible(callback_index=1, request_index=0)
def phone_activate(request_context):
    rid = uuid.uuid4().hex[:16]
    if str(request_context.get('method', '')) != 'POST':
        return v2_response(405, {'success': False, 'error': 'POST で送信してください。'}, rid)
    bootstrap_connection = None
    try:
        _runtime_config()
        bootstrap_connection = database.connect()
        _ensure_phone_schema(bootstrap_connection)
        _expire_phone_requests(bootstrap_connection)
    except Exception:
        return _error_response(503, 'phone_activation_bootstrap', rid)
    finally:
        if bootstrap_connection:
            bootstrap_connection.close()
    try:
        data = _phone_request_data(request_context)
    except RequestError as error:
        if str(error) == 'request_too_large':
            return v2_response(413, {'success': False, 'error': 'リクエストが大きすぎます。'}, rid)
        return _error_response(400, 'phone_activation_input', rid)
    action_value = data.get('api_action')
    action = _phone_trim('phone_request' if action_value is None else action_value).translate(_ASCII_LOWER)
    fingerprint = normalize_device_fingerprint(first_non_empty(data, ('device_fingerprint', 'device_id', 'device')))
    if fingerprint and (not is_valid_device_fingerprint(fingerprint)):
        return v2_response(400, {'success': False, 'error': 'device_fingerprint の形式が正しくありません。'}, rid)
    if action in ('phone_verify', 'phone_refresh', 'phone_deactivate'):
        if not fingerprint:
            return v2_response(400, {'success': False, 'error': 'device_fingerprint が必要です。'}, rid)
        return _delegate_session_action(request_context, data, action, rid)
    if action == 'phone_status':
        return _phone_status(request_context, data, rid)
    if action in ('phone_request', 'phone_activate', 'phone_confirm'):
        if _non_writable_role():
            return v2_response(503, {'success': False, 'error': 'server_not_writable'}, rid)
        connection = None
        try:
            config = _runtime_config()
            connection = database.connect()
            _ensure_phone_schema(connection)
            _expire_phone_requests(connection)
            _assert_write_fence(connection)
            if action == 'phone_confirm':
                return _confirm_phone_activation(connection, config, request_context, data, rid)
            return _request_phone_activation(connection, config, request_context, data, rid)
        except V2Error as exc:
            return v2_response(exc.status, exc.payload, rid)
        except database.DatabaseConfigurationError:
            return _error_response(503, 'phone_activation_bootstrap', rid)
        except Exception as exc:
            if connection:
                connection.rollback()
            if str(exc) == 'confirmation_email_delivery_failed':
                return _error_response(503, 'confirmation_email_delivery_failed', rid, {'error': '確認コードメールを送信できませんでした。時間をおいて再試行してください。'})
            return _error_response(400, 'phone_activation', rid)
        finally:
            if connection:
                connection.close()
    return v2_response(400, {'success': False, 'error': '不明な api_action です。'}, rid)
