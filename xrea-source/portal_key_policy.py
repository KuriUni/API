"""SSO-authenticated, billed API key reissue with idempotent receipts."""
from native_http import make_response, add_headers, legacy_compatible
import base64
import hashlib
import hmac
import json
import re
import time
from datetime import datetime, timezone, timedelta
from core import parse_utc_datetime
from migration_config import secret_value
from tenant_sso_contracts import ALLOWED_SCOPES

def scope_subset(raw):
    try:
        values = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return []
    return [s for s in ALLOWED_SCOPES if s in values] if isinstance(values, list) else []

def reissued_token(row, environment):
    context = f"TUTI-PORTAL-KEY-REISSUE-V1|{row['tenant_id']}|{row['passkey_id']}|{row['request_hash']}"
    secret = secret_value('token_secret')
    if not secret:
        raise RuntimeError('key_reissue_not_available')
    digest = hmac.new(secret.encode(), context.encode(), hashlib.sha256).digest()
    return ('baas_sandbox_' if environment == 'sandbox' else 'baas_prod_') + base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

def fee_period(cursor, account):
    now = datetime.now(timezone.utc)
    year, month = (now.year, now.month)
    for _ in range(120):
        period = f'{year:04d}-{month:02d}'
        cursor.execute('SELECT status FROM api_billing_invoices WHERE account_tenant_id=%s AND billing_period=%s', (account, period))
        row = cursor.fetchone()
        if row is None or row['status'] == 'draft':
            return period
        year, month = (year + 1, 1) if month == 12 else (year, month + 1)
    raise RuntimeError('key_reissue_billing_unavailable')

@legacy_compatible(callback_index=None, request_index=3)
def reissue_key(connection, client, data, request_context):
    from admin_oidc import session_status
    from baas_handlers import _baas_require_writable
    if client.get('key_kind') != 'tenant_sso' or not client.get('tenant_sso_session_id'):
        raise RuntimeError('tenant_sso_session_required')
    status = session_status(str(client.get('sso_oidc_sid') or ''))
    authenticated = int((status or {}).get('auth_time') or 0)
    if not status or authenticated < time.time() - 300 or authenticated > time.time() + 30:
        raise RuntimeError('sso_reauthentication_required')
    _baas_require_writable()
    if type(data.get('confirm_fee_yen')) is not int or data['confirm_fee_yen'] != 500:
        raise RuntimeError('key_reissue_fee_confirmation_required')
    request = str(request_context.get('header:idempotency-key') or '')
    if not re.fullmatch('[A-Za-z0-9_-]{32,80}', request):
        raise RuntimeError('key_reissue_request_id_required')
    tenant = int(client['tenant_id'])
    subject = str(client['sso_subject_hash'])
    account = int(client.get('parent_tenant_id') or tenant)
    environment = client['tenant_environment']
    request_hash = hashlib.sha256(f'sso|{subject}|{request}'.encode()).hexdigest()
    pepper = secret_value('key_pepper')
    if not pepper:
        raise RuntimeError('key_reissue_not_available')

    def key_hash(token):
        return hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()
    replayed = False
    connection.begin()
    try:
        with connection.cursor() as cursor:
            for owner_id in (account, tenant):
                cursor.execute('SELECT id,status FROM tenants WHERE id=%s FOR UPDATE', (owner_id,))
                owner = cursor.fetchone()
                if not owner or owner['status'] != 'active':
                    raise RuntimeError('key_reissue_not_available')
            cursor.execute('SELECT m.source_client_id,m.scopes_json,s.created_at FROM tenant_sso_sessions s JOIN tenant_sso_memberships m ON m.subject_hash=s.subject_hash AND m.tenant_id=s.tenant_id WHERE s.token_hash=%s AND s.subject_hash=%s AND s.tenant_id=%s AND s.revoked_at IS NULL AND s.expires_at>UTC_TIMESTAMP() FOR UPDATE', (client['tenant_sso_session_id'], subject, tenant))
            credential = cursor.fetchone()
            if not credential:
                raise RuntimeError('invalid_portal_session')
            cursor.execute('SELECT * FROM tenant_portal_key_reissues WHERE tenant_id=%s AND request_hash=%s FOR UPDATE', (tenant, request_hash))
            receipt = cursor.fetchone()
            if receipt:
                if int(receipt['passkey_id']) != 0:
                    raise RuntimeError('key_reissue_request_owner_mismatch')
                expiry = parse_utc_datetime(str(receipt['response_expires_at']))
                if expiry is None or expiry <= datetime.now(timezone.utc):
                    raise RuntimeError('key_reissue_result_expired')
                cursor.execute("SELECT * FROM tenant_api_clients WHERE id=%s AND tenant_id=%s AND status='active' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP()) FOR UPDATE", (receipt['new_client_id'], tenant))
                replacement = cursor.fetchone()
                token = reissued_token(receipt, environment)
                if not replacement or not hmac.compare_digest(str(replacement['key_hash']), key_hash(token)):
                    raise RuntimeError('key_reissue_result_expired')
                scopes = scope_subset(replacement['scopes_json'])
                replayed = True
            else:
                source = int(credential['source_client_id'])
                cursor.execute("SELECT * FROM tenant_api_clients WHERE id=%s AND tenant_id=%s AND status='active' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>UTC_TIMESTAMP()) FOR UPDATE", (source, tenant))
                old = cursor.fetchone()
                if not old or (old.get('key_kind') or 'standard') != 'standard':
                    raise RuntimeError('key_reissue_not_available')
                try:
                    original = json.loads(old['scopes_json'])
                except (ValueError, TypeError):
                    original = None
                scopes = scope_subset(old['scopes_json'])
                allowed = scope_subset(credential['scopes_json'])
                if not isinstance(original, list) or len(scopes) != len(original) or any((s not in allowed for s in scopes)) or ('tenant:read' not in scopes):
                    raise RuntimeError('key_reissue_scope_mismatch')
                now = datetime.now(timezone.utc)
                receipt = {'tenant_id': tenant, 'passkey_id': 0, 'request_hash': request_hash, 'billing_period': fee_period(cursor, account), 'grace_expires_at': (now + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S'), 'response_expires_at': (now + timedelta(minutes=10)).strftime('%Y-%m-%d %H:%M:%S')}
                token = reissued_token(receipt, environment)
                cursor.execute('INSERT INTO tenant_api_clients(tenant_id,name,key_prefix,key_hash,scopes_json,rate_limit_per_minute,expires_at) VALUES(%s,%s,%s,%s,%s,%s,%s)', (tenant, str(old['name'])[:120], token[:12], key_hash(token), json.dumps(scopes), min(600, int(old['rate_limit_per_minute'])), old['expires_at']))
                receipt['new_client_id'] = cursor.lastrowid
                cursor.execute("UPDATE tenant_api_clients SET status='retiring',replacement_client_id=%s,grace_expires_at=%s WHERE id=%s AND tenant_id=%s", (receipt['new_client_id'], receipt['grace_expires_at'], source, tenant))
                cursor.execute('INSERT INTO tenant_portal_key_reissues(tenant_id,account_tenant_id,passkey_id,request_hash,source_client_id,new_client_id,amount_units,billing_period,grace_expires_at,response_expires_at) VALUES(%s,%s,0,%s,%s,%s,500000,%s,%s,%s)', (tenant, account, request_hash, source, receipt['new_client_id'], receipt['billing_period'], receipt['grace_expires_at'], receipt['response_expires_at']))
                receipt['id'] = cursor.lastrowid
                cursor.execute('UPDATE tenant_sso_memberships SET source_client_id=%s WHERE tenant_id=%s AND source_client_id=%s', (receipt['new_client_id'], tenant, source))
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    from ha_handlers import _append_ha_audit, ha_sync_peer
    if not replayed:
        _append_ha_audit('tenant_portal_api_key_reissued', {'tenant_id': tenant, 'reissue_id': int(receipt['id']), 'new_client_id': int(receipt['new_client_id']), 'fee_yen': 500, 'billing_period': receipt['billing_period']}, request_context)
    sync = ha_sync_peer('tenant_portal_api_key_reissued', request_context)

    def date_string(value):
        return value.strftime('%Y-%m-%d %H:%M:%S') if isinstance(value, datetime) else str(value)
    return {'ok': True, 'api_key': token, 'client_id': int(receipt['new_client_id']), 'scopes': scopes, 'fee_yen': 500, 'fee_tax_included': True, 'billing_period': receipt['billing_period'], 'old_key_expires_at_utc': date_string(receipt['grace_expires_at']), 'retry_until_utc': date_string(receipt['response_expires_at']), 'replayed': replayed, 'peer_synced': bool(sync.get('ok'))}
