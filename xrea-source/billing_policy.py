"""Python equivalents of the TEST_ONLY BaaS billing policy helpers."""
import calendar
import json
import re
from datetime import datetime
from pathlib import Path

from core import PHP_TRIM_CHARS

RULES = json.loads((Path(__file__).resolve().parent / "billing-rules.json").read_text(encoding="utf-8"))


def credit(units):
    negative = units < 0
    units = abs(int(units))
    return ("-" if negative else "") + str(units // 1000) + ".%03d" % (units % 1000)


def period_bounds(period):
    period = str(period).strip(PHP_TRIM_CHARS)
    if not re.fullmatch(r"[0-9]{4}-(0[1-9]|1[0-2])", period):
        raise ValueError("invalid_period")
    year, month = map(int, period.split("-"))
    if month == 12:
        next_year, next_month = year + 1, 1
    else:
        next_year, next_month = year, month + 1
    return period, period + "-01 00:00:00", "%04d-%02d-01 00:00:00" % (next_year, next_month)


def issue_submit_units(count, discount_percent=0):
    count = max(1, min(100000, int(count)))
    if count <= 200:
        units = 2000
    elif count <= 25000:
        units = 2000 + (count - 200) * 10
    elif count <= 50000:
        units = 250000 + (count - 25000) * 6
    else:
        units = 400000 + (count - 50000) * 4
    if discount_percent > 0:
        units = (units * (100 - discount_percent) + 50) // 100
    return units


def issue_submit_operation(version, count):
    if version not in (6, 7, 8):
        raise ValueError("invalid_issue_pricing_version")
    units = issue_submit_units(count, 10 if version == 7 else 0)
    return "licenses.issue.v%d.submit.units.%d" % (version, units)


def status_billable(status, rules=RULES):
    policy = rules["status_policy"]
    if int(status) in [int(value) for value in policy["non_billable_status_codes"]]:
        return False
    for low, high in policy["non_billable_status_ranges"]:
        if int(low) <= int(status) <= int(high):
            return False
    return int(policy["billable_status_min"]) <= int(status) <= int(policy["billable_status_max"])


def summarize_rows(tenant, environment, rows, rules=RULES):
    if environment not in ("production", "sandbox"):
        raise ValueError("invalid_environment")
    details, unmapped = {}, {}
    total, requests, billable, non_billable = 0, 0, 0, 0
    for row in rows:
        operation, status, count = str(row["operation"]), int(row["status_code"]), int(row["request_count"])
        requests += count
        dynamic_units, api = None, ""
        match = re.fullmatch(r"licenses\.issue\.v([678])\.submit\.units\.([1-9][0-9]{0,5})", operation)
        if match:
            api = "license.issue.v%d.submit" % int(match.group(1))
            dynamic_units = int(match.group(2))
        else:
            api = rules["operation_map"].get(operation, operation if operation in rules["api_pricing"] else "")
        if not api or (dynamic_units is None and api not in rules["api_pricing"]):
            unmapped[operation] = unmapped.get(operation, 0) + count
            non_billable += count
            continue
        if not status_billable(status, rules):
            non_billable += count
            continue
        units = (dynamic_units + 5) // 10 if dynamic_units is not None and environment == "sandbox" else (
            dynamic_units if dynamic_units is not None else int(rules["api_pricing"][api][environment + "_units"]))
        charge = units * count
        total += charge
        billable += count
        key = (api, units)
        if key not in details:
            details[key] = {"api": api, "unit_units": units, "unit_credit": credit(units),
                            "requests": 0, "charge_units": 0, "charge_credit": "0.000"}
        details[key]["requests"] += count
        details[key]["charge_units"] += charge
        details[key]["charge_credit"] = credit(details[key]["charge_units"])
    detail_rows = sorted(details.values(), key=lambda row: (-row["charge_units"], row["api"]))
    return {"tenant_id": int(tenant), "environment": environment, "total_requests": requests,
            "billable_requests": billable, "non_billable_requests": non_billable,
            "total_charge_units": total, "total_charge_credit": credit(total),
            "total_charge_yen_equivalent": credit(total), "details": detail_rows,
            "unmapped_operations": unmapped}


def summarize_tenant(connection, tenant, environment, start, end, rules=RULES):
    """Read and summarize one tenant's usage for a UTC interval."""
    if environment not in ("production", "sandbox"):
        raise ValueError("invalid_environment")
    with connection.cursor() as cursor:
        cursor.execute("SELECT environment FROM tenants WHERE id=%s LIMIT 1", (int(tenant),))
        row = cursor.fetchone()
        stored_environment = (row.get("environment") if isinstance(row, dict)
                              else row[0] if row else None)
        if stored_environment != environment:
            raise ValueError("tenant_environment_mismatch")
        cursor.execute(
            "SELECT operation,status_code,COUNT(*) request_count FROM tenant_api_usage "
            "WHERE tenant_id=%s AND used_at>=%s AND used_at<%s "
            "GROUP BY operation,status_code ORDER BY operation,status_code",
            (int(tenant), start, end),
        )
        rows = cursor.fetchall()
    return summarize_rows(tenant, environment, rows, rules)


def key_reissue_fees(connection, tenant, period, account=False):
    """Return the legacy key-reissue fee aggregate, including absent-table behavior."""
    period, _start, _end = period_bounds(period)
    column = "account_tenant_id" if account else "tenant_id"
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*) AS n FROM information_schema.tables "
            "WHERE table_schema=DATABASE() AND table_name='tenant_portal_key_reissues'"
        )
        exists_row = cursor.fetchone()
        exists = (exists_row.get("n", 0) if isinstance(exists_row, dict)
                  else exists_row[0] if exists_row else 0)
        if int(exists or 0) == 0:
            return {"count": 0, "amount_units": 0, "amount_yen": "0.000"}
        # Column name is selected from a fixed allowlist; all values remain parameters.
        cursor.execute(
            "SELECT COUNT(*) AS quantity,COALESCE(SUM(amount_units),0) AS amount "
            "FROM tenant_portal_key_reissues WHERE " + column + "=%s AND billing_period=%s",
            (int(tenant), period),
        )
        row = cursor.fetchone() or {}
    if not isinstance(row, dict):
        row = {"quantity": row[0], "amount": row[1]}
    amount = int(row.get("amount") or 0)
    return {"count": int(row.get("quantity") or 0), "amount_units": amount,
            "amount_yen": credit(amount)}
