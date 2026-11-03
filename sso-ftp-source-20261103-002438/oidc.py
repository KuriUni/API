#!/usr/bin/python3.6
import io
import os
import sys

APP_DIR = os.path.dirname(os.path.realpath(__file__))
if not os.path.isfile(os.path.join(APP_DIR, "server.py")):
    APP_DIR = os.path.dirname(APP_DIR)
sys.path.insert(0, APP_DIR)

try:
    from server import app

    length = int(os.environ.get("CONTENT_LENGTH") or "0")
    if length < 0 or length > 16384:
        length = 0
    environ = dict(os.environ)
    environ["PATH_INFO"] = os.environ.get("PATH_INFO", "") or "/"
    environ["wsgi.input"] = io.BytesIO(sys.stdin.buffer.read(length))
    status_headers = []

    def start_response(status, headers, exc_info=None):
        status_headers.append((status, headers))

    chunks = app(environ, start_response)
    status, headers = status_headers[0]
    sys.stdout.write("Status: %s\r\n" % status)
    for name, value in headers:
        sys.stdout.write("%s: %s\r\n" % (name, value))
    sys.stdout.write("\r\n")
    sys.stdout.flush()
    for chunk in chunks:
        sys.stdout.buffer.write(chunk)
except Exception:
    sys.stdout.write("Status: 500 Internal Server Error\r\nContent-Type: application/json\r\nCache-Control: no-store\r\n\r\n{\"error\":\"server_error\"}")
