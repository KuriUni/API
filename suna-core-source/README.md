# Sunabar Core Server

Python CGI API emulator for `https://suna.2415.jp/suna/`. It uses the dedicated
MySQL/MariaDB database `qowcpjnw_suna` for API-key and license records. It never
calls production BaaS or Sandbox APIs.

## API

- `GET /suna/api/v1/healthz` — confirms that the API and database/schema are ready.
- `POST /suna/api/v1/key` — issue a Sunabar-only key (24 hours; at most 10 per IP per hour).
- `GET /suna/api/v1/products` — list demo products.
- `POST /suna/api/v1/licenses` — persist and issue a demo license (30 days).
- `POST /suna/api/v1/verify` — verify the stored license and its current status.
- `GET /suna/api/v1/licenses/list` — list up to 100 licenses for the authenticated workspace.
- `POST /suna/api/v1/licenses/revoke` — revoke a license by `license_id` within the authenticated workspace.

Use `X-Sunabar-API-Key` or `Authorization: Bearer <key>`. Authenticated requests
are limited to 120 per minute per workspace and client IP. Only hashes of API and
license keys are stored in MySQL; license status can be revoked in the database.
New demo licenses expose a `SUNABAR-` product key as both `product_key` and
`license_key`. Verification still accepts previously issued signed license tokens.

PyMySQL 1.2.3 is vendored in `pymysql_vendor.zip` (MIT license, Python 3.9+). The first
database-backed request creates the two application tables if needed. The FTP
deployment script prompts for FTP and DB passwords in masked fields and streams
the database configuration directly from memory to `.sunabar/database.json`;
that directory and file are set to modes 0700 and 0600. The folder is denied by
`.htaccess`, as is the vendored library and Python source.


## Device session endpoints

The emulator supports `POST /api/v1/activate`, `/api/v1/session/check`, `/api/v1/session/refresh`, and `/api/v1/session/deactivate`. Session tokens are opaque random values; only SHA-256 hashes are stored. Access TTL is at most one hour, refresh TTL at most seven days, both capped by demo license and API key expiry. Every request requires the same valid API key/workspace.
