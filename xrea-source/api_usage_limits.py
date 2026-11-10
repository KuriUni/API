"""Tenant monthly API spend limits based on the published billing rules."""
from datetime import datetime, timezone
import re


def ensure_schema(connection):
    with connection.cursor() as cursor:
        cursor.execute("""CREATE TABLE IF NOT EXISTS tenant_api_usage_limits (
            tenant_id BIGINT UNSIGNED NOT NULL,
            monthly_limit_units BIGINT UNSIGNED NULL DEFAULT NULL,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (tenant_id),
            CONSTRAINT fk_tenant_api_usage_limits_tenant FOREIGN KEY (tenant_id)
                REFERENCES tenants(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS tenant_api_usage_reservations (
            request_id CHAR(16) NOT NULL,
            tenant_id BIGINT UNSIGNED NOT NULL,
            reserved_units BIGINT UNSIGNED NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (request_id),
            KEY idx_api_usage_reservations_tenant_time (tenant_id,created_at),
            CONSTRAINT fk_tenant_api_usage_reservations_tenant FOREIGN KEY (tenant_id)
                REFERENCES tenants(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""")
    connection.commit()


def get_limit_units(connection, tenant_id):
    with connection.cursor() as cursor:
        cursor.execute("SELECT monthly_limit_units FROM tenant_api_usage_limits WHERE tenant_id=%s LIMIT 1",
                       (int(tenant_id),))
        row = cursor.fetchone()
    return int(row["monthly_limit_units"]) if row and row.get("monthly_limit_units") is not None else None


def set_limit_units(connection, tenant_id, limit_units):
    with connection.cursor() as cursor:
        cursor.execute("INSERT INTO tenant_api_usage_limits(tenant_id,monthly_limit_units) VALUES(%s,%s) "
                       "ON DUPLICATE KEY UPDATE monthly_limit_units=VALUES(monthly_limit_units),updated_at=UTC_TIMESTAMP()",
                       (int(tenant_id), limit_units))


def _monthly_spend(connection, tenant_id, environment):
    from billing_policy import RULES, summarize_rows
    now = datetime.now(timezone.utc)
    start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if start.month == 12:
        end = start.replace(year=start.year + 1, month=1)
    else:
        end = start.replace(month=start.month + 1)
    with connection.cursor() as cursor:
        cursor.execute("SELECT operation,status_code,COUNT(*) AS request_count "
                       "FROM tenant_api_usage WHERE tenant_id=%s AND used_at>=%s AND used_at<%s "
                       "GROUP BY operation,status_code", (tenant_id, start, end))
        rows = cursor.fetchall()
    return summarize_rows(tenant_id, environment, rows, RULES)["total_charge_units"]


def check_monthly_limit(connection, tenant_id, environment, requested_units=0, request_id=None):
    """Reject a request when current billable usage plus its known cost exceeds the cap.

    Missing migration/table means limits have not been configured yet; the
    administrator endpoint creates the table before any limit can be enabled.
    """
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT monthly_limit_units FROM tenant_api_usage_limits WHERE tenant_id=%s LIMIT 1",
                           (int(tenant_id),))
            row = cursor.fetchone()
    except Exception as exc:
        if getattr(exc, "args", ()) and exc.args[0] == 1146:
            return None
        raise
    if not row or row.get("monthly_limit_units") is None:
        return None
    requested = max(0, int(requested_units or 0))
    import database
    budget_connection = database.connect()
    try:
        # A separate transaction gives this check a fresh read view and locks
        # the tenant's budget row, so concurrent requests cannot all spend the
        # same remaining balance.
        with budget_connection.cursor() as cursor:
            cursor.execute("SELECT monthly_limit_units FROM tenant_api_usage_limits WHERE tenant_id=%s LIMIT 1 FOR UPDATE",
                           (int(tenant_id),))
            current = cursor.fetchone()
        if not current or current.get("monthly_limit_units") is None:
            budget_connection.commit()
            return None
        limit = int(current["monthly_limit_units"])
        used = int(_monthly_spend(budget_connection, int(tenant_id), environment))
        reserved = 0
        prior_reservation = 0
        if request_id and requested:
            with budget_connection.cursor() as cursor:
                cursor.execute("DELETE FROM tenant_api_usage_reservations WHERE tenant_id=%s AND created_at<UTC_TIMESTAMP()-INTERVAL 15 MINUTE",
                               (int(tenant_id),))
                cursor.execute("SELECT COALESCE(SUM(reserved_units),0) AS n FROM tenant_api_usage_reservations WHERE tenant_id=%s",
                               (int(tenant_id),))
                reserved = int((cursor.fetchone() or {}).get("n") or 0)
                cursor.execute("SELECT reserved_units FROM tenant_api_usage_reservations WHERE request_id=%s AND tenant_id=%s LIMIT 1",
                               (str(request_id), int(tenant_id)))
                prior = cursor.fetchone()
                prior_reservation = int(prior["reserved_units"]) if prior else 0
        period = datetime.now(timezone.utc).strftime("%Y-%m")
        if used + reserved - prior_reservation + requested > limit or used >= limit:
            budget_connection.rollback()
            from baas_handlers import BaaSError
            raise BaaSError(429, "api_monthly_limit_reached", {
                "period": period, "monthly_limit_units": limit,
                "used_units": used, "reserved_units": reserved - prior_reservation,
                "requested_units": requested,
                "retry_after_seconds": 3600,
            })
        if request_id and requested:
            with budget_connection.cursor() as cursor:
                cursor.execute("INSERT INTO tenant_api_usage_reservations(request_id,tenant_id,reserved_units) VALUES(%s,%s,%s) "
                               "ON DUPLICATE KEY UPDATE reserved_units=VALUES(reserved_units),created_at=UTC_TIMESTAMP()",
                               (str(request_id), int(tenant_id), requested))
        budget_connection.commit()
        return {"period": period, "monthly_limit_units": limit,
                "used_units": used, "reserved_units": reserved - prior_reservation,
                "requested_units": requested}
    except Exception:
        budget_connection.rollback()
        raise
    finally:
        budget_connection.close()


def request_charge_units(operation, environment):
    """Resolve static or progressive API cost using exactly the billing rules."""
    from billing_policy import RULES
    match = re.fullmatch(r"licenses\.issue\.v([678])\.submit\.units\.([1-9][0-9]{0,5})", str(operation))
    if match:
        units = int(match.group(2))
        return (units + 5) // 10 if environment == "sandbox" else units
    if operation in {"licenses.issue.v6.submit", "licenses.issue.v7.submit", "licenses.issue.v8.submit"}:
        return 0  # The handler checks these after it has safely parsed the requested count.
    value = str(operation)
    value = {"licenses.get": "licenses.list", "licenses.post": "licenses.issue"}.get(value, value)
    if re.fullmatch(r"licenses\.v[0-9]+\.(?:quote|status|results|cancel)", value):
        value = value.replace("licenses.v", "licenses.issue.v", 1)
    api = RULES["operation_map"].get(value, value if value in RULES["api_pricing"] else "")
    if not api or api not in RULES["api_pricing"]:
        return 0
    return int(RULES["api_pricing"][api][environment + "_units"])


def submit_charge_units(version, count, environment):
    from billing_policy import issue_submit_units
    units = issue_submit_units(int(count), 10 if int(version) == 7 else 0)
    return (units + 5) // 10 if environment == "sandbox" else units


def credits_to_units(value):
    """Parse a non-negative decimal credit amount into exact milli-credit units."""
    from decimal import Decimal, InvalidOperation
    try:
        amount = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError("invalid_monthly_api_limit") from None
    if not amount.is_finite() or amount < 0 or amount > Decimal("1000000000"):
        raise ValueError("invalid_monthly_api_limit")
    units = amount * 1000
    if units != units.to_integral_value():
        raise ValueError("monthly_api_limit_precision_exceeded")
    return int(units) if amount else None


def units_to_credits(value):
    from billing_policy import credit
    return credit(int(value))
