# Sunabar v2 — API Verification Workbench

Sunabar v2 is a browser-based practice environment for learning the complete Sunabar API workflow. The interface runs against the same-origin Sunabar relay and its isolated demo database. Demo credentials must not be used with real products.

## What's included

- Guided license practice: list products, issue a demo license, and verify it.
- Guided device practice: activate, check, rotate tokens, and deactivate a session.
- Explorer for all ten API operations, editable JSON bodies, response diagnostics, request IDs, and a 20-second timeout.
- Searchable, filterable in-tab history capped at 50 requests. API keys and token/license secrets are redacted from history and JSON exports.
- Responsive layout for desktop and mobile; all interface assets are local.

## Install on the existing Sunabar site

Copy `index.html`, `sunabar-v2.css`, and `sunabar-v2.js` into the existing `xrea-source/sunabar/` web directory, replacing its `index.html` and adding the two v2 assets. Keep the existing same-origin relay at `/license/api/sunabar/v1/` in place. The files are also usable as a static offline preview; API requests require the deployed same-origin relay.

## Security and storage

The dedicated API key is kept in `sessionStorage` for the current tab and expires according to the API response. License keys and session tokens stay in JavaScript memory. History stays in memory and is cleared when the page is reloaded or the tab closes. Exported history is redacted. The app sends requests only to relative `/license/api/sunabar/v1/` paths, with `credentials: omit`; it does not target the production BaaS or Sandbox API.

## Operations

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `health.php` | Check relay and database readiness |
| GET | `products.php` | List sample products |
| POST | `licenses.php` | Issue demo license |
| POST | `verify.php` | Verify demo license |
| GET | `license-list.php` | List licenses in the current workspace |
| POST | `license-revoke.php` | Revoke a demo license |
| POST | `activate.php` | Start a device session |
| POST | `session-check.php` | Check a device session |
| POST | `session-refresh.php` | Rotate session tokens |
| POST | `session-deactivate.php` | End a device session |

The API contract and relay configuration are documented in `docs/SUNABAR.md` and `xrea-source/sunabar_api.py` in the repository.
