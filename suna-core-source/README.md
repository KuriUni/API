# Sunabar Core Server

Python CGI API emulator for `https://suna.2415.jp/suna/`. It uses the dedicated
MySQL/MariaDB database `qowcpjnw_suna` for API-key, license, and demo device-session
records. It never calls production BaaS or Sandbox APIs.

## API

- `GET /suna/api/v1/healthz` — checks API, database connectivity, and required schema; no API key required.
- `POST /suna/api/v1/key` — issue a Sunabar-only key (24 hours; at most 10 per IP per hour).
- `GET /suna/api/v1/products` — list demo products.
- `POST /suna/api/v1/licenses` — persist and issue a demo license (30 days).
- `POST /suna/api/v1/verify` — verify the stored license and its current status.
- `GET /suna/api/v1/licenses/list` — list up to 100 licenses for the authenticated workspace.
- `POST /suna/api/v1/licenses/revoke` — revoke a license by `license_id` within the authenticated workspace.
- `POST /suna/api/v1/activate` — activate a license for a device and issue an access/refresh token pair.
- `POST /suna/api/v1/session/check` — validate an access token for its device.
- `POST /suna/api/v1/session/refresh` — rotate both tokens using a refresh token.
- `POST /suna/api/v1/session/deactivate` — revoke a device session using its refresh token.

License API v4 emulation (online sessions only):

- `POST /suna/api/v4/challenge` — issue an activation challenge for a device public key.
- `POST /suna/api/v4/activate` — verify the challenge signature and issue a v4 session.
- `POST /suna/api/v4/verify` / `introspect` / `refresh` / `reauth` / `revoke` — signed device-bound session operations.
- `GET /suna/api/v4/offline-public-key` and offline ticket/migration endpoints return 501; Sunabar emulates online sessions only.

The v4 endpoints require the Sunabar API key in `X-Sunabar-API-Key` and use the v4 token in `Authorization`. Device signatures are verified with the host OpenSSL command; if OpenSSL is unavailable, signed v4 requests return 503.

Authenticated calls use `X-Sunabar-API-Key` or `Authorization: Bearer <key>` and are limited to 120 requests per minute per workspace and client IP. Only hashes of API and license keys are stored in MySQL. Device IDs accept 1–128 ASCII letters, digits, dots, colons, underscores, or hyphens. Session tokens are opaque random values; only SHA-256 hashes are stored. Access TTL is at most one hour, refresh TTL at most seven days, both capped by demo license and API-key expiry. Refresh rotates both tokens, so the previous pair cannot be reused.

Expired API-key hash rows are removed automatically at most once per hour during database-backed requests. The expiry column is indexed so cleanup does not scan the full key table. A workspace can issue at most 20 demo licenses per hour. When a device is activated again, its expired session rows for that license are removed before the device limit is checked. License history is retained for the workspace.

Schema setup and additive index migrations are serialized and recorded in MySQL. Normal requests check the schema version instead of repeating table and index DDL. Responses include an `X-Request-ID`; unexpected server errors log that ID, the route, and the exception class to the CGI error log without logging keys, tokens, request bodies, or exception messages. Include the ID when reporting an unavailable response.

The browser Playground offers all operations, carries freshly issued license/session values into the next request, and keeps API keys in tab-scoped `sessionStorage`; license and session token values stay in page memory. The 2415.jp Playground uses same-origin relay endpoints under `/license/api/sunabar/v1/`.

PyMySQL 1.2.3 is vendored in `pymysql_vendor.zip` (MIT license, Python 3.9+). The first database-backed request creates the application tables if needed. The FTP deployment script prompts for FTP and DB passwords in masked fields and streams database configuration directly from memory to `.sunabar/database.json`; that directory and file are set to modes 0700 and 0600. The folder is denied by `.htaccess`, as are the vendored library and Python source.

All keys, licenses, and sessions are simulation-only and cannot activate production software or access production data.
