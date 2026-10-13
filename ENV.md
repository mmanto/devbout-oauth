# Environment variables

## Nango server (`deploy/nango/.env`)

| Var | Required | Notes |
|-----|----------|-------|
| `NANGO_ENCRYPTION_KEY` | ✓ | base64 32-byte key (`openssl rand -base64 32`). **Not rotatable.** |
| `NANGO_SECRET_KEY` | ✓ | API secret used by consumers (`openssl rand -hex 32`). No placeholder values. |
| `NANGO_DB_USER` / `NANGO_DB_PASSWORD` / `NANGO_DB_NAME` | – | default `nango`; override for managed Postgres. |
| `NANGO_SERVER_URL` | – | public backend URL, default `http://localhost:3003`. |
| `NANGO_PUBLIC_CONNECT_URL` | – | public Connect UI URL, default `http://localhost:3009`. |

## Consumer app (gestion.ar / nexsure)

| Var | Required | Notes |
|-----|----------|-------|
| `NANGO_HOST` | ✓ | base URL of the Nango backend API, e.g. `http://localhost:3003`. |
| `NANGO_SECRET_KEY` | ✓ | same secret as the server; authenticates backend → Nango calls. |
| `FRONTEND_URL` | ✓ | consumer frontend base URL. |
| `STATE_SIGNING_KEY` | ✓ | signs the short-lived login nonce **and the passkey challenges** (HS256). Keep separate from the app SECRET_KEY. |
| `WEBAUTHN_RP_ID` | ✓ (passkeys) | registrable domain the passkeys are bound to, bare — no scheme, no port. Prod `gestion.ar`, dev `localhost`. |
| `WEBAUTHN_RP_NAME` | ✓ (passkeys) | name the browser/OS shows when creating a passkey, e.g. `Gestion.ar`. |
| `WEBAUTHN_ORIGINS` | ✓ (passkeys) | comma-separated exact origins the frontend is served from, e.g. `https://gestion.ar,https://app.gestion.ar`. Must match what the browser reports, so localhost dev needs `http://localhost:5173`. |
| `WEBAUTHN_USER_VERIFICATION` | – | `preferred` (default) or `required` (reject authenticators that don't verify the user). |

`NangoConfig.google_integration_key` / `microsoft_integration_key` default to
`google` / `microsoft`; override only if the Nango Integration IDs differ.

The `WEBAUTHN_*` vars feed `PasskeyConfig` — the library itself reads no env
vars, the consumer builds it (and can skip passkeys entirely by not passing
`passkeys=` to `create_router`). A wrong `WEBAUTHN_ORIGINS` shows up as a 401 on
`*/verify` (`Unexpected client data origin`), not at startup.
