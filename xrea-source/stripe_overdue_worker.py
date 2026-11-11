"""Periodic worker that suspends API keys for overdue tenant invoices.

Run from the deployed xrea-source directory every five minutes using the
same protected production database configuration as the API application.
"""
import json
import sys

import database
from stripe_billing import suspend_overdue_invoices, restore_paid_invoice_keys


def main():
    connection = None
    try:
        connection = database.connect()
        result = suspend_overdue_invoices(connection, limit=1000)
        recovery = restore_paid_invoice_keys(connection, limit=1000)
        print(json.dumps({'ok': True, **result, **recovery}, ensure_ascii=False, separators=(',', ':')))
        return 0
    except Exception as exc:
        # Keep credentials and SQL details out of cron output.
        print(json.dumps({'ok': False, 'error': type(exc).__name__},
                         ensure_ascii=False, separators=(',', ':')))
        return 1
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


if __name__ == '__main__':
    sys.exit(main())
