"""Python implementation of the BaaS adaptive issuance assessment route."""
from native_http import make_response, add_headers, legacy_compatible
import time
import uuid
import math
import database
from http_utils import RequestError, json_response
from baas_handlers import BaaSError, _authorize_key, _baas_json_input, _column_value, _usage, _reply, _sample_sdk_php_int
AUTO_ROUTER_VERSION = 'auto-router-v2-cost-aware'
MAX_COUNT = 10000

def _php_round(value, places=0):
    factor = 10 ** places
    return math.floor(float(value) * factor + 0.5) / factor

def _auto_level(score):
    return 'critical' if score >= 70 else 'high' if score >= 45 else 'normal' if score >= 20 else 'low'

def _auto_price(version, environment, count, tier):
    sandbox = environment == 'sandbox'
    if version in ('v1', 'v2'):
        return (0.2 if sandbox else 2.0) * count
    if version == 'v3':
        return 1.0 if sandbox else 10.0
    base = 20.0 if sandbox else 200.0
    multiplier = {'light': 1.0, 'middle': 1.5, 'high': 2.0, 'max': 3.0, 'maxx5': 5.0, 'max10': 10.0, 'max20': 20.0}
    return base * multiplier.get(tier or 'light', 1.0)

def _auto_column_exists(connection, table, column):
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS n FROM information_schema.columns WHERE table_schema=DATABASE() AND table_name=%s AND column_name=%s', (table, column))
            row = cursor.fetchone()
        return int(_column_value(row) or 0) > 0
    except Exception:
        return False

def _auto_measure(connection):
    started = time.perf_counter()
    with connection.cursor() as cursor:
        cursor.execute('SELECT 1')
        cursor.fetchone()
    db_ms = (time.perf_counter() - started) * 1000.0
    v3_ready = _auto_column_exists(connection, 'product_key_issue_batches', 'client_id')
    v4_ready = _auto_column_exists(connection, 'product_key_issue_jobs_v4', 'queue_priority') and _auto_column_exists(connection, 'product_key_issue_jobs_v4', 'speed_tier')
    attempts_60 = active_jobs = pending_items = 0
    throughput = 250.0
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT COUNT(*) AS n FROM tenant_api_attempts WHERE attempted_at>=UTC_TIMESTAMP()-INTERVAL 1 MINUTE')
            attempts_60 = int(_column_value(cursor.fetchone()) or 0)
    except Exception:
        pass
    if v4_ready:
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT COUNT(*) AS jobs,COALESCE(SUM(GREATEST(requested_count-processed_count,0)),0) AS pending FROM product_key_issue_jobs_v4 WHERE status IN ('queued','processing','cancel_requested')")
                row = cursor.fetchone() or {}
                active_jobs = int(row.get('jobs') or 0)
                pending_items = int(row.get('pending') or 0)
                cursor.execute('SELECT COALESCE(SUM(processed_count),0) AS processed,COALESCE(SUM(GREATEST(TIMESTAMPDIFF(MICROSECOND,started_at,COALESCE(completed_at,heartbeat_at,UTC_TIMESTAMP()))/1000000.0,0.001)),0) AS seconds FROM product_key_issue_jobs_v4 WHERE started_at IS NOT NULL AND created_at>=UTC_TIMESTAMP()-INTERVAL 10 MINUTE')
                rate = cursor.fetchone() or {}
                seconds = float(rate.get('seconds') or 0.0)
                processed = int(rate.get('processed') or 0)
                if seconds > 0 and processed > 0:
                    throughput = max(10.0, min(10000.0, processed / seconds))
        except Exception:
            pass
    return (db_ms, v3_ready, v4_ready, attempts_60, active_jobs, pending_items, throughput)

def _auto_decision(count, policy, environment, db_ms, v3_ready, v4_ready, attempts_60, active_jobs, pending_items, throughput):
    score = 0
    if db_ms > 120:
        score += 40
    elif db_ms > 60:
        score += 28
    elif db_ms > 30:
        score += 16
    elif db_ms > 15:
        score += 7
    if attempts_60 > 500:
        score += 30
    elif attempts_60 > 250:
        score += 20
    elif attempts_60 > 100:
        score += 10
    elif attempts_60 > 40:
        score += 4
    if active_jobs > 15:
        score += 25
    elif active_jobs > 8:
        score += 16
    elif active_jobs > 3:
        score += 8
    if pending_items > 50000:
        score += 25
    elif pending_items > 20000:
        score += 16
    elif pending_items > 5000:
        score += 8
    score = min(100, score)
    level = _auto_level(score)
    threshold = {'low': 800, 'normal': 650, 'high': 350, 'critical': 150}[level]
    if active_jobs >= 8 or pending_items >= 20000:
        threshold += 250
    if active_jobs >= 15 or pending_items >= 50000:
        threshold += 250
    threshold = max(100, min(1000, threshold))
    technical_version, technical_tier = ('v2', None)
    technical_reason = '単発発行のため発行専用V2を選択しました。'
    if count == 1:
        pass
    elif count <= 1000:
        if not v3_ready and v4_ready:
            technical_version = 'v4'
            technical_reason = 'V3基盤を利用できないためV4へ切り替えました。'
        elif not v4_ready and v3_ready:
            technical_version = 'v3'
            technical_reason = 'V4基盤を利用できないためV3を選択しました。'
        elif count >= threshold and v4_ready:
            technical_version = 'v4'
            technical_reason = f'現在のサーバー負荷と{count}件の要求量ではV4が技術的に高速です。'
        else:
            technical_version = 'v3'
            technical_reason = f'現在の処理余力では{count}件をV3で処理できます。'
    else:
        if not v4_ready:
            raise BaaSError(503, 'v4_required_but_unavailable')
        technical_version = 'v4'
        technical_reason = '1,000件を超えるためV4が必要です。'
    if technical_version == 'v4':
        technical_tier = {'critical': 'light', 'high': 'middle', 'normal': 'high'}.get(level, 'maxx5' if count >= 5000 else 'max')
    economic_version = 'v2' if count == 1 else 'v3' if count <= 1000 and v3_ready else 'v4'
    economic_tier = 'light' if economic_version == 'v4' else None
    technical_cost = _auto_price(technical_version, environment, count, technical_tier)
    economic_cost = _auto_price(economic_version, environment, count, economic_tier)
    version, tier, reason = (technical_version, technical_tier, technical_reason)
    if policy == 'economy':
        version, tier, reason = (economic_version, economic_tier, '料金を優先し、利用可能な最安ルートを選択しました。')
    elif policy == 'fastest':
        if version == 'v4':
            tier = 'max10' if level == 'low' and count >= 5000 else 'high' if level == 'critical' else 'maxx5'
        reason = '処理時間を優先し、技術的に高速なルートを選択しました。'
    else:
        premium = technical_cost - economic_cost
        ratio = technical_cost / economic_cost if economic_cost > 0 else 9999.0
        upgrade_allowed = technical_version != economic_version and premium <= 25.0 and (ratio <= 2.0)
        if technical_version == economic_version or upgrade_allowed:
            version, tier = (technical_version, technical_tier)
            reason = technical_reason if technical_version == economic_version else '速度向上に対する追加料金が小さいため高速ルートを選択しました。'
        else:
            version, tier = (economic_version, economic_tier)
            reason = f'高速ルートは {technical_cost:.3f} Cr（差額 +{max(0.0, premium):.3f} Cr）のため、Balancedでは {economic_cost:.3f} Cr の低料金ルートを選択しました。'
    cost = _auto_price(version, environment, count, tier)
    estimated_ms = int(_php_round(1000.0 * (count / max(10.0, throughput))))
    if version == 'v4':
        estimated_ms += int(_php_round(min(60000.0, 1000.0 * (pending_items / max(10.0, throughput)))))
    return {'selection': {'version': version, 'speed_tier': tier, 'count': count, 'estimated_cost_cr': _php_round(cost, 3), 'reason': reason}, 'alternatives': {'economic': {'version': economic_version, 'speed_tier': economic_tier, 'estimated_cost_cr': _php_round(economic_cost, 3)}, 'performance': {'version': technical_version, 'speed_tier': technical_tier, 'estimated_cost_cr': _php_round(technical_cost, 3), 'premium_cr': _php_round(max(0.0, technical_cost - economic_cost), 3)}}, 'server': {'load_level': level, 'load_score': score, 'db_latency_ms': _php_round(db_ms, 2), 'estimated_throughput_items_per_sec': _php_round(throughput, 1), 'estimated_completion_ms': estimated_ms, 'v3_ready': v3_ready, 'v4_ready': v4_ready, 'v3_v4_dynamic_threshold': threshold, 'queue_pressure': 'high' if active_jobs >= 15 or pending_items >= 50000 else 'medium' if active_jobs >= 8 or pending_items >= 20000 else 'low'}, 'policy': {'mode': policy, 'reassess_each_request': True, 'max20_requires_manual_selection': True, 'decision_ttl_seconds': 15}}

@legacy_compatible(callback_index=1, request_index=0)
def assess(request_context):
    rid = uuid.uuid4().hex[:16]
    connection = None
    try:
        if str(request_context.get('method', '')) != 'POST':
            raise BaaSError(405, 'method_not_allowed')
        connection = database.connect()
        client, headers, ip_hash = _authorize_key(connection, request_context, 'licenses:write', 'licenses.issue.auto.assess', rid)
        data = _baas_json_input(request_context)
        count_value = data.get('count', 1)
        count = _sample_sdk_php_int(count_value)
        if count < 1 or count > MAX_COUNT:
            raise BaaSError(400, 'invalid_issue_count')
        policy_value = data.get('policy', 'balanced')
        policy = str('balanced' if policy_value is None else policy_value).strip().lower()
        if policy not in {'balanced', 'fastest', 'economy'}:
            raise BaaSError(400, 'invalid_auto_policy')
        try:
            metrics = _auto_measure(connection)
        except Exception:
            raise BaaSError(503, 'auto_assessment_unavailable')
        db_ms, v3_ready, v4_ready, attempts, active_jobs, pending, throughput = metrics
        result = _auto_decision(count, policy, str(client.get('tenant_environment') or 'production'), db_ms, v3_ready, v4_ready, attempts, active_jobs, pending, throughput)
        _usage(connection, client, 'licenses.issue.auto.assess', 200, rid, ip_hash)
        return json_response('200 OK', {'ok': True, 'router_version': AUTO_ROUTER_VERSION, **result}, headers)
    except BaaSError as exc:
        return _reply(exc.status, {'ok': False, 'error': exc.error, **exc.extra})
    except RequestError as exc:
        return _reply(400, {'ok': False, 'error': str(exc)})
    except database.DatabaseConfigurationError:
        return _reply(503, {'ok': False, 'error': 'service_unavailable'})
    except Exception:
        if connection:
            connection.rollback()
        return _reply(503, {'ok': False, 'error': 'auto_assessment_unavailable'})
    finally:
        if connection:
            connection.close()
