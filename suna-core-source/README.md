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

Authenticated calls use `X-Sunabar-API-Key` or `Authorization: Bearer <key>` and are limited to 120 requests per minute per workspace and client IP. Only hashes of API and license keys are stored in MySQL. Device IDs accept 1–128 ASCII letters, digits, dots, colons, underscores, or hyphens. Session tokens are opaque random values; only SHA-256 hashes are stored. Access TTL is at most one hour, refresh TTL at most seven days, both capped by demo license and API-key expiry. Refresh rotates both tokens, so the previous pair cannot be reused.

The browser Playground offers all operations, carries freshly issued license/session values into the next request, and keeps API keys in tab-scoped `sessionStorage`; license and session token values stay in page memory. The 2415.jp Playground uses same-origin relay endpoints under `/license/api/sunabar/v1/`.

PyMySQL 1.2.3 is vendored in `pymysql_vendor.zip` (MIT license, Python 3.9+). The first database-backed request creates the application tables if needed. The FTP deployment script prompts for FTP and DB passwords in masked fields and streams database configuration directly from memory to `.sunabar/database.json`; that directory and file are set to modes 0700 and 0600. The folder is denied by `.htaccess`, as are the vendored library and Python source.

All keys, licenses, and sessions are simulation-only and cannot activate production software or access production data.
