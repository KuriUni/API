"""Python port of the HA administrator invoice lifecycle API."""
from native_http import make_response, add_headers, legacy_compatible
import json
import re
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
import database
from core import PHP_TRIM_CHARS, php_int_cast
from billing_policy import RULES, credit, key_reissue_fees, period_bounds, summarize_tenant
from http_utils import json_response as _base_json_response

class InvoiceError(Exception):

    def __init__(self, status, error):
        super().__init__(error)
        self.status = status
        self.error = error

@legacy_compatible(callback_index=0, request_index=None)
def json_response(status, payload, headers=()):
    return _base_json_response(status, _safe(payload), headers)

def _safe(value):
    if isinstance(value, dict):
        return {key: _safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in value]
    if isinstance(value, (datetime, date)):
        return value.strftime('%Y-%m-%d %H:%M:%S') if isinstance(value, datetime) else value.isoformat()
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value

@legacy_compatible(callback_index=None, request_index=0)
def _input(request_context):
    stream = request_context.get('body_stream')
    raw = stream.read(262145) if stream is not None else b''
    if len(raw) > 262144:
        raise ValueError('request_too_large')
    try:
        data = json.loads(raw.decode('utf-8'), parse_constant=lambda _: (_ for _ in ()).throw(ValueError())) if raw else {}
    except json.JSONDecodeError:
        raise ValueError('Syntax error')
    except UnicodeDecodeError:
        raise ValueError('Malformed UTF-8 characters, possibly incorrectly encoded')
    except ValueError:
        raise ValueError('Syntax error')
    pending = [(data, 0)]
    while pending:
        item, parent_depth = pending.pop()
        if isinstance(item, (dict, list)):
            depth = parent_depth + 1
            if depth > 32:
                raise ValueError('Maximum stack depth exceeded')
            children = item.values() if isinstance(item, dict) else item
            pending.extend(((child, depth) for child in children))
    if isinstance(data, list):
        return {}
    if not isinstance(data, dict):
        raise ValueError('invalid_request')
    return data

def _php_string(value):
    if value is None or value is False:
        return ''
    if value is True:
        return '1'
    if isinstance(value, (dict, list)):
        return 'Array'
    return str(value)

def _php_trim(value):
    return _php_string(value).strip(PHP_TRIM_CHARS)

def _php_trim_lower(value):
    return _php_trim(value).translate(str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'))

def _is_integrity_conflict(error):
    if str(getattr(error, 'sqlstate', '')) == '23000':
        return True
    args = getattr(error, 'args', ())
    return bool(args and args[0] in (1062, '23000'))

def _date(value, fallback):
    value = _php_trim(value) or fallback
    if re.fullmatch('[0-9]{4}-[0-9]{2}-[0-9]{2}', value) is None:
        raise ValueError('invalid_date')
    try:
        datetime.strptime(value, '%Y-%m-%d')
    except ValueError:
        raise ValueError('invalid_date')
    return value

def _yen_units(value):
    text = _php_trim('0' if value is None else value)
    if not text:
        return 0
    if re.fullmatch('-?[0-9]{1,9}(?:\\.[0-9]{1,3})?', text) is None:
        raise ValueError('invalid_adjustment')
    negative = text.startswith('-')
    text = text.lstrip('-')
    whole, _, fraction = text.partition('.')
    units = int(whole) * 1000 + int((fraction + '000')[:3])
    return -units if negative else units

def _cursor_one(connection, sql, params=()):
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        return cursor.fetchone()

def _resolve_account(connection, tenant_id):
    if tenant_id < 1:
        raise ValueError('invalid_tenant')
    selected = _cursor_one(connection, 'SELECT id,slug,name,status,plan_code,environment,parent_tenant_id FROM tenants WHERE id=%s', (tenant_id,))
    if not selected:
        raise ValueError('tenant_not_found')
    root_id = int(selected.get('parent_tenant_id') or selected['id'])
    root = _cursor_one(connection, "SELECT id,slug,name,status,plan_code,environment,parent_tenant_id FROM tenants WHERE id=%s AND (parent_tenant_id IS NULL OR environment='production')", (root_id,))
    if not root:
        raise ValueError('billing_account_not_found')
    with connection.cursor() as cursor:
        cursor.execute("SELECT id,slug,name,status,plan_code,CASE WHEN parent_tenant_id IS NOT NULL OR environment='sandbox' THEN 'sandbox' ELSE 'production' END environment,parent_tenant_id FROM tenants WHERE id=%s OR parent_tenant_id=%s ORDER BY CASE WHEN id=%s THEN 0 ELSE 1 END,id", (root_id, root_id, root_id))
        members = cursor.fetchall()
    return {'root': root, 'members': members}

def _preview(connection, data):
    now = datetime.now(timezone.utc)
    default_period = now.strftime('%Y-%m')
    try:
        raw_period = data.get('period')
        period, start, end = period_bounds(_php_string(default_period if raw_period is None else raw_period))
    except ValueError:
        raise ValueError('invalid_period')
    account = _resolve_account(connection, php_int_cast(data.get('tenant_id')))
    tax_value = data.get('tax_rate_basis_points')
    tax_rate = php_int_cast(1000 if tax_value is None else tax_value)
    if not 0 <= tax_rate <= 10000:
        raise ValueError('invalid_tax_rate')
    adjustment = _yen_units(data.get('adjustment_yen', '0'))
    today = now.strftime('%Y-%m-%d')
    issue_date = _date(data.get('issue_date'), today)
    due_default = (datetime.strptime(issue_date, '%Y-%m-%d') + timedelta(days=30)).strftime('%Y-%m-%d')
    due_date = _date(data.get('due_date'), due_default)
    if due_date < issue_date:
        raise ValueError('due_date_before_issue_date')
    root = account['root']
    customer_value = data.get('customer_name')
    customer_name = _php_trim(root['name'] if customer_value is None else customer_value) or str(root['name'])
    issuer_value = data.get('issuer_name')
    issuer_name = _php_trim('TUTI License' if issuer_value is None else issuer_value) or 'TUTI License'
    registration = _php_trim(data.get('issuer_registration_number', ''))
    notes = _php_trim(data.get('notes', ''))
    if len(notes) > 2000:
        raise ValueError('notes_too_long')
    sections, line_items, unmapped = ([], [], {})
    subtotal = requests = billable = non_billable = 0
    for member in account['members']:
        environment = str(member['environment'])
        summary = summarize_tenant(connection, int(member['id']), environment, start, end, RULES)
        sections.append({'tenant_id': int(member['id']), 'tenant_slug': str(member['slug']), 'tenant_name': str(member['name']), 'environment': environment, 'total_requests': summary['total_requests'], 'billable_requests': summary['billable_requests'], 'non_billable_requests': summary['non_billable_requests'], 'total_charge_units': summary['total_charge_units'], 'total_charge_yen': credit(summary['total_charge_units'])})
        for row in summary['details']:
            line_items.append({'tenant_id': int(member['id']), 'environment': environment, **row})
        for operation, count in summary['unmapped_operations'].items():
            key = environment + ':' + operation
            unmapped[key] = unmapped.get(key, 0) + int(count)
        subtotal += int(summary['total_charge_units'])
        requests += int(summary['total_requests'])
        billable += int(summary['billable_requests'])
        non_billable += int(summary['non_billable_requests'])
    line_items.sort(key=lambda row: (row['environment'], -row['charge_units'], row['api']))
    fees = key_reissue_fees(connection, int(root['id']), period, account=True)
    fee_net = fees['amount_units'] * 10000 // (10000 + tax_rate)
    fee_tax = fees['amount_units'] - fee_net
    tax_units = subtotal * tax_rate // 10000 + fee_tax
    subtotal += fee_net
    total = subtotal + tax_units + adjustment
    if total < 0:
        raise ValueError('negative_invoice_total')
    invoice_items = [{'description': 'API利用料 · ' + row['api'], 'environment': row['environment'], 'quantity': row['requests'], 'unit': '回', 'unit_price_yen': row['unit_credit'], 'amount_yen': row['charge_credit']} for row in line_items]
    if not invoice_items:
        invoice_items.append({'description': 'API利用料（対象期間の利用なし）', 'environment': '—', 'quantity': 0, 'unit': '回', 'unit_price_yen': '0.000', 'amount_yen': '0.000'})
    if fees['count'] > 0:
        invoice_items.append({'description': 'APIキー再発行料（1回500円・税込）', 'environment': '—', 'quantity': fees['count'], 'unit': '回', 'unit_price_yen': credit(fee_net // fees['count']), 'amount_yen': credit(fee_net), 'gross_amount_yen': fees['amount_yen']})
    if adjustment:
        invoice_items.append({'description': '個別調整額', 'environment': '—', 'quantity': 1, 'unit': '式', 'unit_price_yen': credit(adjustment), 'amount_yen': credit(adjustment)})
    return {'invoice_number': 'API-' + period.replace('-', '') + '-T' + str(int(root['id'])).zfill(6), 'mode': RULES['mode'], 'production_ready': RULES['production_ready'], 'currency': RULES['currency'], 'pricing_schema': RULES.get('schema'), 'period': period, 'period_start_utc': start, 'period_end_utc': end, 'issue_date': issue_date, 'due_date': due_date, 'account_tenant_id': int(root['id']), 'account_slug': str(root['slug']), 'customer_name': customer_name[:160], 'issuer_name': issuer_name[:160], 'issuer_registration_number': registration[:32], 'notes': notes, 'tax_rate_basis_points': tax_rate, 'tax_rate_percent': '%.2f' % (tax_rate / 100), 'adjustment_units': adjustment, 'adjustment_yen': credit(adjustment), 'subtotal_units': subtotal, 'subtotal_yen': credit(subtotal), 'tax_units': tax_units, 'tax_yen': credit(tax_units), 'total_units': total, 'total_yen': credit(total), 'total_requests': requests, 'billable_requests': billable, 'non_billable_requests': non_billable, 'api_key_reissue_fees': fees, 'api_key_reissue_fee_tax_yen': credit(fee_tax), 'sections': sections, 'items': invoice_items, 'line_items': line_items, 'unmapped_operations': unmapped, 'generated_at_utc': now.isoformat(timespec='seconds')}

def _invoice_row(row):
    row = dict(row)
    try:
        snapshot = json.loads(str(row.pop('snapshot_json', '')))
    except (TypeError, json.JSONDecodeError):
        snapshot = None
    for field in ('id', 'account_tenant_id', 'subtotal_units', 'tax_units', 'adjustment_units', 'total_units', 'tax_rate_basis_points'):
        row[field] = int(row.get(field) or 0)
    row.update({'subtotal_yen': credit(row['subtotal_units']), 'tax_yen': credit(row['tax_units']), 'adjustment_yen': credit(row['adjustment_units']), 'total_yen': credit(row['total_units']), 'snapshot': snapshot if isinstance(snapshot, (dict, list)) else []})
    return row

def _get_invoice(connection, invoice_id):
    row = _cursor_one(connection, 'SELECT * FROM api_billing_invoices WHERE id=%s', (invoice_id,))
    if not row:
        raise ValueError('invoice_not_found')
    return _invoice_row(row)

@legacy_compatible(callback_index=None, request_index=3)
def _save_draft(connection, data, issue, request_context):
    account = _resolve_account(connection, php_int_cast(data.get('tenant_id')))
    root_id = int(account['root']['id'])
    connection.begin()
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT id FROM tenants WHERE id=%s FOR UPDATE', (root_id,))
        preview = _preview(connection, data)
        period = preview['period']
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM api_billing_invoices WHERE account_tenant_id=%s AND billing_period=%s', (root_id, period))
            existing = cursor.fetchone()
        if existing and existing['status'] != 'draft':
            raise RuntimeError('invoice_locked_after_issue')
        status = 'issued' if issue else 'draft'
        issued_at = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S') if issue else None
        snapshot = json.dumps(preview, ensure_ascii=False, separators=(',', ':'))
        values = (preview['invoice_number'], preview['customer_name'], preview['issuer_name'], preview['issuer_registration_number'], preview['issue_date'], preview['due_date'], preview['tax_rate_basis_points'], preview['subtotal_units'], preview['tax_units'], preview['adjustment_units'], preview['total_units'], status, preview['notes'], snapshot, issued_at)
        with connection.cursor() as cursor:
            if existing:
                cursor.execute('UPDATE api_billing_invoices SET invoice_number=%s,customer_name=%s,issuer_name=%s,issuer_registration_number=%s,issue_date=%s,due_date=%s,tax_rate_basis_points=%s,subtotal_units=%s,tax_units=%s,adjustment_units=%s,total_units=%s,status=%s,notes=%s,snapshot_json=%s,issued_at=%s,updated_at=UTC_TIMESTAMP() WHERE id=%s', values + (int(existing['id']),))
                invoice_id = int(existing['id'])
            else:
                cursor.execute('INSERT INTO api_billing_invoices(invoice_number,account_tenant_id,billing_period,customer_name,issuer_name,issuer_registration_number,issue_date,due_date,tax_rate_basis_points,subtotal_units,tax_units,adjustment_units,total_units,status,notes,snapshot_json,issued_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)', (preview['invoice_number'], root_id, period) + values[1:])
                invoice_id = int(connection.insert_id())
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    from ha_handlers import _append_ha_audit, ha_sync_peer
    event = 'api_billing_invoice_issued' if issue else 'api_billing_invoice_draft_saved'
    _append_ha_audit(event, {'invoice_id': invoice_id, 'invoice_number': preview['invoice_number'], 'tenant_id': root_id, 'period': period, 'total_units': preview['total_units']}, request_context)
    ha_sync_peer(event, request_context)
    return _get_invoice(connection, invoice_id)

def _table_exists(connection, table):
    row = _cursor_one(connection, 'SELECT COUNT(*) AS n FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name=%s', (table,))
    return int((row or {}).get('n', 0)) > 0

def _store_diagnostic(connection, request_id, error, stage, action):
    if connection is None:
        return
    try:
        context = json.dumps({'endpoint': 'api-billing-admin', 'action': action, 'stage': stage}, ensure_ascii=False, separators=(',', ':'))
        with connection.cursor() as cursor:
            cursor.execute('INSERT INTO admin_error_diagnostics(error_id,error_type,message,file_path,line_number,context_json,created_at) VALUES(%s,%s,%s,%s,%s,%s,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE error_type=VALUES(error_type),message=VALUES(message),file_path=VALUES(file_path),line_number=VALUES(line_number),context_json=VALUES(context_json),created_at=VALUES(created_at)', (request_id, type(error).__name__, str(error)[:2000], str(getattr(error, 'filename', '') or '')[:512], max(0, int(getattr(error, 'lineno', 0) or 0)), context))
        connection.commit()
    except Exception:
        try:
            connection.rollback()
        except Exception:
            pass

@legacy_compatible(callback_index=1, request_index=0)
def invoice_admin(request_context):
    from ha_handlers import _append_ha_audit, _ha_authorized_scope, ha_sync_peer
    rid = uuid.uuid4().hex[:8]
    if not _ha_authorized_scope(request_context, 'admin:manage'):
        return json_response('404 Not Found', {'ok': False, 'error': 'not_found'})
    if request_context.get('method', 'POST') != 'POST':
        return json_response('405 Method Not Allowed', {'ok': False, 'error': 'method_not_allowed'})
    connection = None
    action = 'unknown'
    stage = 'database_connect'
    try:
        connection = database.connect()
        stage = 'request_parse'
        data = _input(request_context)
        action_value = data.get('action')
        action = 'list' if action_value is None else _php_string(action_value)
        stage = 'authorization_check'
        if action == 'diagnostics':
            request_id = _php_trim_lower(data.get('request_id', ''))
            if re.fullmatch('[a-f0-9]{8}', request_id) is None:
                raise ValueError('invalid_request_id')
            stage = 'diagnostic_query'
            if not _table_exists(connection, 'admin_error_diagnostics'):
                raise InvoiceError(404, 'diagnostic_not_found')
            row = _cursor_one(connection, 'SELECT error_type,message,file_path,line_number,context_json,created_at FROM admin_error_diagnostics WHERE error_id=%s AND created_at>=UTC_TIMESTAMP()-INTERVAL 7 DAY LIMIT 1', (request_id,))
            if not row:
                raise InvoiceError(404, 'diagnostic_not_found')
            try:
                context = json.loads(str(row.get('context_json') or '{}'))
            except json.JSONDecodeError:
                context = {}
            diagnostic = {'type': str(row['error_type']), 'message': str(row['message']), 'file': str(row['file_path']), 'line': int(row['line_number']), 'stage': context.get('stage', ''), 'action': context.get('action', ''), 'created_at': row['created_at']}
            return json_response('200 OK', {'ok': True, 'diagnostic': diagnostic})
        mutation = action in {'save_draft', 'issue', 'mark_paid', 'void', 'delete_draft'}
        if mutation:
            try:
                from baas_handlers import _decode_admin_session
                claims = _decode_admin_session(_php_trim(request_context.get('header:x-ha-session', '')))
            except Exception:
                claims = None
            if isinstance(claims, dict) and claims.get('source') == 'admin_api':
                try:
                    issued_at = int(claims.get('issued_at', 0))
                except (TypeError, ValueError):
                    issued_at = 0
                if issued_at < int(time.time()) - 120 or issued_at > int(time.time()) + 5:
                    return json_response('428 Precondition Required', {'ok': False, 'error': 'passkey_reauthentication_required'})
        if action == 'tenants':
            stage = 'tenant_query'
            with connection.cursor() as cursor:
                cursor.execute("SELECT t.id,t.slug,t.name,t.status,t.plan_code,(SELECT id FROM tenants s WHERE s.parent_tenant_id=t.id AND s.environment='sandbox' ORDER BY s.id LIMIT 1) sandbox_tenant_id FROM tenants t WHERE t.parent_tenant_id IS NULL AND t.environment='production' ORDER BY t.name,t.id")
                rows = cursor.fetchall()
            return json_response('200 OK', {'ok': True, 'tenants': rows, 'mode': RULES['mode']})
        if action == 'preview':
            stage = 'invoice_preview'
            return json_response('200 OK', {'ok': True, 'invoice': _preview(connection, data)})
        stage = 'invoice_table_check'
        if not _table_exists(connection, 'api_billing_invoices'):
            raise RuntimeError('billing_invoice_migration_required')
        if action == 'list':
            stage = 'invoice_list_query'
            tenant = max(0, php_int_cast(data.get('tenant_id')))
            page = max(1, php_int_cast(data.get('page', 1)))
            raw_limit = data.get('limit', 25)
            limit = max(1, min(100, php_int_cast(25 if raw_limit is None else raw_limit)))
            offset = (page - 1) * limit
            query_text = str(data.get('q', '') or '').strip()[:120]
            status = str(data.get('status', '') or '').strip()
            where, args = [], []
            if tenant:
                where.append('i.account_tenant_id=%s')
                args.append(tenant)
            if query_text:
                where.append('(i.invoice_number LIKE %s OR i.customer_name LIKE %s OR t.slug LIKE %s)')
                args.extend(['%' + query_text + '%'] * 3)
            if status in {'draft', 'issued', 'paid', 'void'}:
                where.append('i.status=%s')
                args.append(status)
            where_sql = (' WHERE ' + ' AND '.join(where)) if where else ''
            base_from = ' FROM api_billing_invoices i JOIN tenants t ON t.id=i.account_tenant_id'
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) total_count,"
                               " SUM(CASE WHEN i.status='draft' THEN 1 ELSE 0 END) draft_count,"
                               " SUM(CASE WHEN i.status='issued' THEN 1 ELSE 0 END) issued_count,"
                               " SUM(CASE WHEN i.status='paid' THEN 1 ELSE 0 END) paid_count,"
                               " SUM(CASE WHEN i.status='void' THEN 1 ELSE 0 END) void_count,"
                               " COALESCE(SUM(CASE WHEN i.status='paid' THEN i.total_units ELSE 0 END),0) paid_units"
                               + base_from + where_sql, tuple(args))
                summary_row = cursor.fetchone() or {}
                sql = 'SELECT i.*,t.slug account_slug' + base_from + where_sql + ' ORDER BY i.billing_period DESC,i.id DESC LIMIT %s OFFSET %s'
                cursor.execute(sql, tuple(args) + (limit + 1, offset))
                all_rows = cursor.fetchall()
            has_next = len(all_rows) > limit
            rows = [_invoice_row(row) for row in all_rows[:limit]]
            summary = {
                'total': int(summary_row.get('total_count') or 0),
                'draft': int(summary_row.get('draft_count') or 0),
                'issued': int(summary_row.get('issued_count') or 0),
                'paid': int(summary_row.get('paid_count') or 0),
                'void': int(summary_row.get('void_count') or 0),
                'paid_total_yen': credit(int(summary_row.get('paid_units') or 0)),
            }
            return json_response('200 OK', {'ok': True, 'invoices': rows, 'page': page, 'limit': limit,
                                             'has_next': has_next, 'summary': summary})
        if action == 'get':
            stage = 'invoice_get'
            return json_response('200 OK', {'ok': True, 'invoice': _get_invoice(connection, php_int_cast(data.get('invoice_id')))})
        if mutation:
            stage = 'write_fence'
            from v3_handlers import _assert_write_fence
            _assert_write_fence(connection)
        if action in ('save_draft', 'issue'):
            stage = 'invoice_save'
            invoice = _save_draft(connection, data, action == 'issue', request_context)
            return json_response('200 OK', {'ok': True, 'invoice': invoice})
        if action in ('mark_paid', 'void'):
            stage = 'invoice_status_update'
            invoice_id = php_int_cast(data.get('invoice_id'))
            current = _get_invoice(connection, invoice_id)
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    cursor.execute('SELECT id FROM tenants WHERE id=%s FOR UPDATE', (current['account_tenant_id'],))
                current = _get_invoice(connection, invoice_id)
                old_status = str(current['status'])
                if action == 'mark_paid' and old_status not in ('issued', 'paid'):
                    raise RuntimeError('invoice_must_be_issued')
                if action == 'void' and old_status not in ('draft', 'issued', 'void'):
                    raise RuntimeError('paid_invoice_cannot_be_voided')
                status = 'paid' if action == 'mark_paid' else 'void'
                field = 'paid_at' if status == 'paid' else 'voided_at'
                with connection.cursor() as cursor:
                    cursor.execute('UPDATE api_billing_invoices SET status=%s,' + field + '=COALESCE(' + field + ',UTC_TIMESTAMP()),updated_at=UTC_TIMESTAMP() WHERE id=%s', (status, invoice_id))
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            event = 'api_billing_invoice_' + status
            _append_ha_audit(event, {'invoice_id': invoice_id, 'from': old_status}, request_context)
            ha_sync_peer(event, request_context)
            return json_response('200 OK', {'ok': True, 'invoice': _get_invoice(connection, invoice_id)})
        if action == 'delete_draft':
            stage = 'invoice_delete_draft'
            invoice_id = php_int_cast(data.get('invoice_id'))
            current = _get_invoice(connection, invoice_id)
            connection.begin()
            try:
                with connection.cursor() as cursor:
                    cursor.execute('SELECT id FROM tenants WHERE id=%s FOR UPDATE', (current['account_tenant_id'],))
                current = _get_invoice(connection, invoice_id)
                if current['status'] != 'draft':
                    raise RuntimeError('only_draft_can_be_deleted')
                with connection.cursor() as cursor:
                    cursor.execute("DELETE FROM api_billing_invoices WHERE id=%s AND status='draft'", (invoice_id,))
                    deleted = cursor.rowcount
                connection.commit()
            except Exception:
                connection.rollback()
                raise
            _append_ha_audit('api_billing_invoice_draft_deleted', {'invoice_id': invoice_id, 'invoice_number': current['invoice_number']}, request_context)
            ha_sync_peer('api_billing_invoice_draft_deleted', request_context)
            return json_response('200 OK', {'ok': True, 'invoice_id': invoice_id, 'deleted': deleted})
        raise ValueError('unknown_action')
    except InvoiceError as exc:
        status_name = {404: '404 Not Found', 409: '409 Conflict', 500: '500 Internal Server Error', 503: '503 Service Unavailable'}.get(exc.status, '%d Error' % exc.status)
        return json_response(status_name, {'ok': False, 'error': exc.error})
    except ValueError as exc:
        return json_response('400 Bad Request', {'ok': False, 'error': str(exc)})
    except RuntimeError as exc:
        known = {'billing_invoice_migration_required', 'invoice_locked_after_issue', 'invoice_must_be_issued', 'paid_invoice_cannot_be_voided', 'only_draft_can_be_deleted'}
        if str(exc) in known:
            return json_response('409 Conflict', {'ok': False, 'error': str(exc)})
        _store_diagnostic(connection, rid, exc, stage, action)
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'billing_invoice_failed', 'request_id': rid})
    except database.DatabaseConfigurationError:
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'billing_invoice_failed', 'request_id': rid})
    except Exception as exc:
        if connection is not None:
            try:
                connection.rollback()
            except Exception:
                pass
        if _is_integrity_conflict(exc):
            _store_diagnostic(connection, rid, exc, stage, action)
            return json_response('409 Conflict', {'ok': False, 'error': 'invoice_conflict', 'request_id': rid})
        _store_diagnostic(connection, rid, exc, stage, action)
        return json_response('503 Service Unavailable', {'ok': False, 'error': 'billing_invoice_failed', 'request_id': rid})
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
