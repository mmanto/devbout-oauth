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
| `STATE_SIGNING_KEY` | ✓ | signs the short-lived login nonce (HS256). Keep separate from the app SECRET_KEY. |

`NangoConfig.google_integration_key` / `microsoft_integration_key` default to
`google` / `microsoft`; override only if the Nango Integration IDs differ.
