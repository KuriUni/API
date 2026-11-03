#!/bin/sh
APP_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
for PY in /opt/alt/python311/bin/python3.11 /opt/alt/python310/bin/python3.10 /opt/alt/python39/bin/python3.9 /usr/local/bin/python3 /usr/bin/python3 /usr/bin/python3.6 /opt/alt/python36/usr/bin/python3.6; do
  if [ -x "$PY" ]; then exec "$PY" "$APP_DIR/oidc.py"; fi
done
printf 'Status: 500 Internal Server Error\r\nContent-Type: application/json\r\n\r\n{"error":"python3_unavailable"}'