# devbout-oauth

Central **authentication + integrations** library for Devbout apps
(`gestion.ar`, `nexsure`). It lets users **log in and send email with Google or
Microsoft**, delegating the entire OAuth dance and token storage/refresh to a
**self-hosted [Nango](https://nango.dev)** instance. This library never stores
provider refresh tokens — Nango custodies them and hands out fresh access tokens
on demand.

Optionally, on top of that, users can register a **passkey** (WebAuthn: Face ID,
huella, Windows Hello, llave de seguridad) and log in with it — see §5.

Consumed by other projects **via pip (git+https by tag)**:

```
# requirements.txt
devbout-oauth @ git+https://<your-remote>/devbout-oauth@v0.3.0
```

---

## 1. Run Nango (self-hosted)

```bash
cd deploy/nango
cp .env.example .env        # fill NANGO_ENCRYPTION_KEY + NANGO_SECRET_KEY
docker network create nango_network   # once — shared with consumers on this host
docker compose up -d
```

- Backend API → `http://localhost:3003` (see note below re: `NANGO_HOST`)
- Connect UI → `http://localhost:3009`

Sign up in the dashboard (`http://localhost:3003`) the first time — self-hosted
has no seeded account. **The `NANGO_SECRET_KEY` env var in `.env` does NOT
become the API secret**: Nango generates a random one per environment when you
sign up (dashboard → Settings → Environment). Use *that* value as `NANGO_HOST`'s
sibling `NANGO_SECRET_KEY` in each consumer app, not the one from `deploy/nango/.env`.

**Production**: the Connect UI and the API need to be reachable from a real
user's browser, not just from the host's Docker network — see
`deploy/nango/docker-compose.prod.yaml` for exposing both behind a shared
Traefik with public subdomains. The dashboard is protected by Nango's own login
(in the catch-all router, no reverse-proxy BasicAuth), and the consumer-facing
routes (`/oauth`, `/connect`, `/connections`, `/environment`) are open because
they already authenticate via `Authorization: Bearer <secret>` or a one-time
session token.

## 2. Create the integrations in Nango

In the Nango dashboard/Connect UI create two integrations whose **Integration ID**
matches the keys in `NangoConfig` (defaults `google` and `microsoft`):

| Provider  | Nango template | OAuth scopes |
|-----------|----------------|--------------|
| google    | Google         | `openid email profile https://www.googleapis.com/auth/gmail.send` |
| microsoft | Microsoft (`common` tenant) | `openid email profile offline_access User.Read Mail.Send` |

Set the OAuth client id/secret for each, and register Nango's callback URL
(`<NANGO_HOST>/oauth/callback`) in the Google Cloud Console / Azure App
Registration. For Microsoft use the **`common`** tenant (work/school + personal).

> Scopes are configured in the dashboard (source of truth). `NangoConfig` also
> carries them as documentation and for any consumer that wants to push them via
> `integrations_config_defaults`.

## 3. Wire the router in a consumer

```python
from devbout_oauth import NangoConfig, create_router
from myapp.storage import MyConnectionStorage   # implements ConnectionStorage

config = NangoConfig(
    nango_host=os.environ["NANGO_HOST"],
    nango_secret_key=os.environ["NANGO_SECRET_KEY"],
    frontend_url=os.environ["FRONTEND_URL"],
    state_signing_key=os.environ["STATE_SIGNING_KEY"],
)

router = create_router(
    config=config,
    storage=MyConnectionStorage(),
    get_current_user_id=my_auth_dependency,   # -> str
    prefix="/api/v1/auth",
)
app.include_router(router)
```

### Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/connect/login/session`  | – | mint a connect-session token for **login** |
| POST | `/connect/login/finalize` | – | exchange `connectionId` → app token + identity |
| POST | `/connect/email/session`  | ✓ | mint a token to **connect an email account** |
| POST | `/connect/email/finalize` | ✓ | persist the connected email account |
| DELETE | `/disconnect`           | ✓ | revoke the Nango connection + clear locally |
| POST | `/webhook/nango`          | sig | opt-in lifecycle webhook (only if a handler is passed) |

Request bodies: sessions take `{provider}`; finalize takes
`{connectionId, provider, nonce?}`.

### Frontend (per consumer)

```ts
import Nango from '@nangohq/frontend'

const { sessionToken, nonce, provider } =
  await api.post('/api/v1/auth/connect/login/session', { provider: 'google' })

const nango = new Nango()
const connect = nango.openConnectUI({
  onEvent: async (e) => {
    if (e.type === 'connect') {
      const { token } = await api.post('/api/v1/auth/connect/login/finalize', {
        connectionId: e.payload.connectionId, provider, nonce,
      })
      // store app token, redirect…
    }
  },
})
connect.setSessionToken(sessionToken)
```

## 4. Send email as the user

```python
from devbout_oauth import DevboutAuth

auth = DevboutAuth(config, storage)
await auth.send_email(user_id, to="x@y.com", subject="Hi", body_html="<p>…</p>")
```

It resolves the user's connection → fresh access token (Google or Microsoft) →
sends via Gmail API or Microsoft Graph automatically.

---

## 5. Log in with a passkey (rostro / huella / llave de seguridad)

Opt-in, on top of the Nango flow. A user who already has an account registers a
**passkey** and afterwards signs in with Face ID / Touch ID / Windows Hello /
Android biometrics / a hardware key, with no OAuth round-trip.

| Layer | Library |
|-------|---------|
| Server | [`webauthn`](https://github.com/duo-labs/webauthn) (py_webauthn) — the Python library behind [webauthn.io](https://webauthn.io) |
| Browser | [`@simplewebauthn/browser`](https://simplewebauthn.dev) (`startRegistration` / `startAuthentication`) |

Only the credential's **public** key and signature counter are stored; the
private key never leaves the user's device. A passkey login authenticates an
existing account — it never creates one.

### Backend

```python
from devbout_oauth import PasskeyConfig, create_router

router = create_router(
    config=nango_config,
    storage=MyStorage(),            # must also implement PasskeyStorage
    get_current_user_id=my_auth_dependency,
    prefix="/api/v1/auth",
    passkeys=PasskeyConfig(
        rp_id="gestion.ar",                # bare domain: no scheme, no port
        rp_name="Gestion.ar",
        origins=["https://gestion.ar"],    # every origin the frontend runs on
    ),
)
```

Passkeys mount only when `passkeys=` is passed, and `create_router` raises at
startup if the storage given (or `passkey_storage=`) doesn't implement
`PasskeyStorage`.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/passkey/register/options` | ✓ | `navigator.credentials.create()` options + signed challenge |
| POST | `/passkey/register/verify` | ✓ | verify the attestation, store the credential |
| POST | `/passkey/login/options` | – | `navigator.credentials.get()` options (`username` optional) |
| POST | `/passkey/login/verify` | – | verify the assertion → app token |
| GET | `/passkey/credentials` | ✓ | list the user's passkeys |
| DELETE | `/passkey/credentials/{credential_id}` | ✓ | revoke one passkey |

Bodies: `register/verify` → `{credential, challengeToken, name?}`;
`login/verify` → `{credential, challengeToken}`; `login/options` → `{username?}`.
Both `*/options` answer `{options, challengeToken}`: `options` is what the SDK
consumes, and `challengeToken` is the signed 5-minute challenge (the same
stateless pattern as the login nonce) that must come back with the credential.
Omit `username` for a **usernameless** login: the browser then offers any passkey
registered for `rp_id` and the account is resolved from the assertion.

### Frontend (per consumer)

```ts
import { startRegistration, startAuthentication } from '@simplewebauthn/browser'

// register (user already logged in)
const { options, challengeToken } = await api.post('/api/v1/auth/passkey/register/options')
const credential = await startRegistration({ optionsJSON: options })
await api.post('/api/v1/auth/passkey/register/verify', {
  credential, challengeToken, name: 'Face ID del iPhone',
})

// login (from the sign-in screen)
const { options, challengeToken } = await api.post('/api/v1/auth/passkey/login/options', { username })
const credential = await startAuthentication({ optionsJSON: options })
const { token } = await api.post('/api/v1/auth/passkey/login/verify', { credential, challengeToken })
```

### Implementing `PasskeyStorage`

```python
async def get_passkey_user(user_id) -> PasskeyUser | None          # (user_id, username, display_name)
async def get_passkey_user_by_username(username) -> PasskeyUser | None
async def save_passkey(user_id, credential_id, public_key, sign_count, transports, name): ...
async def get_passkey(credential_id) -> PasskeyCredential | None
async def list_passkeys(user_id) -> list[PasskeyCredential]
async def update_passkey_sign_count(credential_id, sign_count): ...
async def delete_passkey(user_id, credential_id): ...
async def issue_app_token(user_id) -> str      # the app token for an existing user
```

`credential_id` and `public_key` are base64url strings (plain `TEXT` columns);
`sign_count` is the WebAuthn signature counter and must be persisted on every
login — a counter that doesn't advance past the stored one is rejected as a
possible cloned authenticator. See `InMemoryPasskeyStorage` for a reference.

### Caveats

- WebAuthn requires a secure context: `https://` in production, `localhost` in
  dev. The RP ID must be a domain — `localhost` works, IP literals don't.
- A passkey lives in the user's browser/OS keychain and syncs (or not) per
  vendor; `DELETE /passkey/credentials/{id}` removes only the server record.

---

## Implementing `ConnectionStorage`

Store the **mapping**, not tokens:

```python
async def save_connection(user_id, provider, connection_id, email): ...
async def get_connection(user_id) -> (provider, connection_id, email) | None: ...
async def clear_connection(user_id): ...
async def find_or_create_by_identity(provider, provider_user_id, email, given, family) -> (user_id, app_token): ...
```

See `InMemoryConnectionStorage` for a reference.

## Migration from 0.1.x (Google-only, direct OAuth)

- `GoogleOAuthConfig` → `NangoConfig`. `client_id/secret/redirect_uri/encryption_key`
  are gone (Nango owns them).
- `TokenStorage` → `ConnectionStorage`. Store `(provider, connection_id, email)`
  instead of an encrypted refresh token. DB: add `auth_provider` + `nango_connection_id`,
  drop the refresh-token column.
- `GmailSender(client_id, client_secret).send_message(refresh_token, msg)` →
  `DevboutAuth.send_email(user_id, …)` or `EmailSender.send(provider, access_token, …)`.
- `find_or_create_by_google(...)` → `find_or_create_by_identity(provider, provider_user_id, …)`.
- The redirect-based `GET /login-start` + `GET /callback` are replaced by the
  session/finalize POST pair driven by `@nangohq/frontend`.
- `encrypt_token` / `decrypt_token` are **unchanged** and still exported (consumers
  use them for app passwords).
