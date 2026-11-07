# SSO SQLite database operations

The SSO provider stores its database in the private `SSO_DATA_DIR` directory. Keep the database and signing/email keys outside the public document root.

## Schema upgrades

`server.py` stores the provider schema version in SQLite `PRAGMA user_version`. The first request after an upgrade acquires a write lock, applies schema changes in one transaction, then advances the version. Concurrent CGI requests wait for that migration and recheck the version before continuing. Normal requests skip table and index inspection. Increment `SSO_DATABASE_SCHEMA_VERSION` whenever a future release changes this schema; do not reuse an existing version number.

The recovery-email lookup index covers the newly added hash and active-user filter. The session list index matches the account page's user/revocation filters and newest-first ordering; the existing active-session index remains for other session lookups. Expiry indexes let the periodic cleanup find stale rows without scanning the full temporary-flow tables, and user indexes keep targeted flow replacement efficient.

## Expired authentication state

`/authorize` removes expired login flows, passkey flows, onboarding state, codes, access tokens, sessions, login limits, recovery flows, email-setup flows, and contractor invites at most once every five minutes. Expired security rate-limit rows are swept hourly. Authentication queries still enforce each record's expiry on every request; cleanup timing does not extend a credential, flow, or session's validity. Sweeps run in short serialized transactions and record their last run in `database_maintenance`. Per-request flow creation no longer repeats global expiry sweeps; targeted user/address cleanup remains indexed.

## Backup handling

Back up the private data directory using SQLite-aware backup or snapshot tooling. If WAL mode is enabled in a future change, include the live database through SQLite's backup API rather than copying only the main database file.
