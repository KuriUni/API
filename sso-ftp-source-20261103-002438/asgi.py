"""ASGI/FastAPI entry point for the standalone SSO Core.

The identity provider currently exposes its handler as WSGI for the existing
CGI deployment. Keep that handler authoritative and bridge it to ASGI so both
deployment styles execute the same routes, cookies, headers, and DB logic.
"""

from a2wsgi import WSGIMiddleware
from fastapi import FastAPI

from server import app as wsgi_app


app = FastAPI(
    title="2415.jp SSO Core",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# The SSO issuer is mounted at the domain root. WSGIMiddleware forwards every
# HTTP method and path to the established WSGI application. FastAPI's own
# interactive API/docs endpoints are disabled because this is an identity
# provider, not a public API explorer.
app.mount("/", WSGIMiddleware(wsgi_app), name="sso-core")
