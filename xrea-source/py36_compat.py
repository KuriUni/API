"""Small ISO date parsers for XREA's Python 3.6 CGI runtime."""
import re
from datetime import date, datetime, timedelta, timezone


_DATETIME = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})"
    r"(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}:?\d{2})?$"
)


def parse_iso_date(value):
    """Parse the YYYY-MM-DD format accepted by date.fromisoformat."""
    if not isinstance(value, str) or not re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        raise ValueError("Invalid isoformat string")
    return datetime.strptime(value, "%Y-%m-%d").date()


def parse_iso_datetime(value):
    """Parse the ISO date/time forms used by the PHP API and MySQL rows."""
    if not isinstance(value, str):
        raise TypeError("fromisoformat: argument must be str")
    if re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        return datetime.strptime(value, "%Y-%m-%d")
    match = _DATETIME.match(value)
    if not match:
        raise ValueError("Invalid isoformat string")
    date_part, time_part, seconds, fraction, offset = match.groups()
    time_part += ":" + (seconds or "00")
    parsed = datetime.strptime(date_part + "T" + time_part, "%Y-%m-%dT%H:%M:%S")
    if fraction:
        parsed = parsed.replace(microsecond=int((fraction + "000000")[:6]))
    if offset == "Z":
        tzinfo = timezone.utc
    elif offset:
        sign = 1 if offset[0] == "+" else -1
        digits = offset[1:].replace(":", "")
        hours, minutes = int(digits[:2]), int(digits[2:])
        tzinfo = timezone(sign * timedelta(hours=hours, minutes=minutes))
    else:
        tzinfo = None
    return parsed.replace(tzinfo=tzinfo)
