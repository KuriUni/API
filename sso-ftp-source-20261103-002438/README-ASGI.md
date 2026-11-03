# SSO Core: FastAPI / ASGI compatibility entry

This describes an optional ASGI entry point for the SSO Core source. It does not establish that FastAPI is the live production deployment. The existing `server.py` WSGI application remains the source of truth, and the CGI/WSGI deployment can continue to run independently. Do not start a second public service for the same issuer without deliberately switching the production entry point.

`asgi.py` wraps the existing WSGI handler with FastAPI and `a2wsgi`; it does not reimplement OIDC endpoints. FastAPI's generated docs and OpenAPI routes are disabled.

## Requirements

- Python 3.11 is recommended for the ASGI runtime.
- Install optional ASGI dependencies from this directory:

```sh
python3.11 -m pip install -r requirements-asgi.txt
```

The classic WSGI/CGI path uses its own runtime and dependency configuration.

## Reverse-proxy deployment

Use this entry only when the hosting environment can supervise a persistent ASGI process and proxy HTTPS traffic to it. Keep Uvicorn bound to loopback. Point `SSO_DATA_DIR` at the same private persistent directory used by the active service; it contains the SQLite database and signing/email keys.

```sh
export SSO_DATA_DIR=/path/outside/public_html/sso-data
python3.11 -m uvicorn asgi:app \
  --host 127.0.0.1 --port 8765 \
  --proxy-headers --forwarded-allow-ips=127.0.0.1
```

The trusted reverse proxy must forward the original HTTPS scheme and host. The public issuer remains `https://sso.2415.jp`; do not expose the Uvicorn port directly to the internet. Ensure only one service deployment owns the issuer.

## Readiness

`GET /healthz` forwards to the existing readiness handler. It checks database/schema availability and a signing-key probe. A ready service returns HTTP 200 and `ok: true`; a failed required check returns HTTP 503 and `ok: false`, with per-check status. It does not test email delivery or complete an interactive login.

The provider's OpenID Connect discovery document is `/.well-known/openid-configuration`.
