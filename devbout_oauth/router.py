"""
FastAPI router factory for Nango-backed auth + integrations, plus optional
passkey (WebAuthn) login.

Flow (frontend uses @nangohq/frontend `openConnectUI`):
  1. Frontend asks the backend for a connect session token.
  2. Frontend opens the Nango Connect UI with that token; the user authorizes
     Google or Microsoft. On success the SDK returns a `connectionId`.
  3. Frontend posts that `connectionId` back to `…/finalize`, where the backend
     fetches the connection from Nango, verifies it belongs to the initiating
     identity, and either logs the user in or records the email connection.

Two intents, kept on separate paths so auth requirements stay clean:
  - login  → no auth; bound to a signed login nonce.
  - email  → authenticated; bound to the current user id.

Passkeys are mounted only when a `PasskeyConfig` is passed (and storage
implements `PasskeyStorage`, see `_register_passkey_routes`): an already
authenticated user registers Face ID / Touch ID / Windows Hello / a security
key, and then logs in with it instead of the OAuth round-trip.
"""
import hashlib
import hmac
import logging
from typing import Awaitable, Callable, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from .config import SUPPORTED_PROVIDERS, NangoConfig
from .identity import fetch_identity
from .nango_client import NangoClient
from .passkeys import (
    PasskeyConfig,
    PasskeyError,
    authentication_options,
    credential_id_of,
    finish_authentication,
    finish_registration,
    registration_options,
)
from .state import create_login_nonce, verify_login_nonce
from .storage import ConnectionStorage, PasskeyStorage

logger = logging.getLogger(__name__)


class _SessionRequest(BaseModel):
    provider: str


class _LoginFinalizeRequest(BaseModel):
    connectionId: str
    provider: str
    nonce: str


class _EmailFinalizeRequest(BaseModel):
    connectionId: str
    provider: str


class _PasskeyRegisterVerifyRequest(BaseModel):
    credential: dict
    challengeToken: str
    name: Optional[str] = None


class _PasskeyLoginOptionsRequest(BaseModel):
    username: Optional[str] = None


class _PasskeyLoginVerifyRequest(BaseModel):
    credential: dict
    challengeToken: str


def _register_passkey_routes(
    router: APIRouter,
    nango_config: NangoConfig,
    passkeys: PasskeyConfig,
    storage: PasskeyStorage,
    get_current_user_id: Callable,
) -> None:
    """
    Mount the WebAuthn (passkey) endpoints.

    Registration and credential management require a logged-in user; the login
    ceremony doesn't, since it is the login. Both ceremonies are stateless: the
    signed challenge token returned by `*/options` travels back with the
    assertion to `*/verify`.
    """
    signing_key = nango_config.state_signing_key

    # ── Register a passkey (authenticated) ────────────────────────────────
    @router.post("/passkey/register/options")
    async def passkey_register_options(user_id: str = Depends(get_current_user_id)):
        user = await storage.get_passkey_user(user_id)
        if user is None:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        existing = await storage.list_passkeys(user_id)
        options, challenge_token = registration_options(passkeys, signing_key, user, existing)
        return {"options": options, "challengeToken": challenge_token}

    @router.post("/passkey/register/verify")
    async def passkey_register_verify(
        body: _PasskeyRegisterVerifyRequest,
        user_id: str = Depends(get_current_user_id),
    ):
        try:
            registered = finish_registration(
                passkeys, signing_key, body.credential, body.challengeToken
            )
        except PasskeyError as exc:
            logger.warning("Passkey register failed for user %s: %s", user_id, exc)
            raise HTTPException(status_code=400, detail="No se pudo verificar el passkey")
        if registered.user_id != user_id:
            logger.warning("Passkey register: challenge belongs to another user")
            raise HTTPException(status_code=403, detail="La ceremonia no corresponde al usuario")
        if await storage.get_passkey(registered.credential_id) is not None:
            raise HTTPException(status_code=409, detail="La credencial ya está registrada")

        name = body.name or (
            "Passkey sincronizada" if registered.backed_up else "Passkey de este dispositivo"
        )
        await storage.save_passkey(
            user_id,
            registered.credential_id,
            registered.public_key,
            registered.sign_count,
            registered.transports,
            name,
        )
        logger.info("Passkey registered for user %s (%s)", user_id, registered.device_type)
        return {
            "status": "registered",
            "credentialId": registered.credential_id,
            "name": name,
            "deviceType": registered.device_type,
            "backedUp": registered.backed_up,
        }

    # ── Login with a passkey (no auth) ─────────────────────────────────────
    @router.post("/passkey/login/options")
    async def passkey_login_options(body: _PasskeyLoginOptionsRequest):
        # An unknown username still gets usable options (empty allowCredentials →
        # any discoverable passkey for this RP), so this can't enumerate accounts.
        credentials = []
        user_id = ""
        if body.username:
            user = await storage.get_passkey_user_by_username(body.username)
            if user is not None:
                user_id = user.user_id
                credentials = await storage.list_passkeys(user_id)
        options, challenge_token = authentication_options(
            passkeys, signing_key, credentials, user_id
        )
        return {"options": options, "challengeToken": challenge_token}

    @router.post("/passkey/login/verify")
    async def passkey_login_verify(body: _PasskeyLoginVerifyRequest):
        try:
            credential_id = credential_id_of(body.credential)
        except PasskeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        stored = await storage.get_passkey(credential_id)
        if stored is None:
            logger.warning("Passkey login: unknown credential %s", credential_id)
            raise HTTPException(status_code=401, detail="Passkey no reconocido")
        try:
            new_sign_count = finish_authentication(
                passkeys, signing_key, body.credential, body.challengeToken, stored
            )
        except PasskeyError as exc:
            logger.warning("Passkey login failed for user %s: %s", stored.user_id, exc)
            raise HTTPException(status_code=401, detail="No se pudo verificar el passkey")

        await storage.update_passkey_sign_count(credential_id, new_sign_count)
        token = await storage.issue_app_token(stored.user_id)
        user = await storage.get_passkey_user(stored.user_id)
        logger.info("Login success via passkey: %s", user.username if user else stored.user_id)
        return {
            "token": token,
            "provider": "passkey",
            "username": user.username if user else "",
            "display_name": user.display_name if user else "",
        }

    # ── Manage registered passkeys (authenticated) ─────────────────────────
    @router.get("/passkey/credentials")
    async def passkey_credentials(user_id: str = Depends(get_current_user_id)):
        credentials = await storage.list_passkeys(user_id)
        return {
            "credentials": [
                {
                    "id": credential.credential_id,
                    "name": credential.name,
                    "transports": credential.transports,
                    "created_at": (
                        credential.created_at.isoformat() if credential.created_at else None
                    ),
                }
                for credential in credentials
            ]
        }

    @router.delete("/passkey/credentials/{credential_id}", status_code=204)
    async def passkey_delete(
        credential_id: str,
        user_id: str = Depends(get_current_user_id),
    ):
        stored = await storage.get_passkey(credential_id)
        if stored is None or stored.user_id != user_id:
            raise HTTPException(status_code=404, detail="Passkey no encontrado")
        await storage.delete_passkey(user_id, credential_id)
        logger.info("Passkey %s deleted for user %s", credential_id, user_id)


def create_router(
    config: NangoConfig,
    storage: ConnectionStorage,
    get_current_user_id: Callable,
    providers: frozenset[str] = frozenset({"google", "microsoft"}),
    prefix: str = "/auth",
    nango_webhook_handler: Optional[Callable[[dict], Awaitable[None]]] = None,
    passkeys: Optional[PasskeyConfig] = None,
    passkey_storage: Optional[PasskeyStorage] = None,
) -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["auth"])
    nango = NangoClient(config)

    enabled = providers & SUPPORTED_PROVIDERS

    if passkeys is not None:
        target = passkey_storage if passkey_storage is not None else storage
        if not isinstance(target, PasskeyStorage):
            raise ValueError(
                "passkeys requiere un storage que implemente PasskeyStorage; "
                f"a {type(target).__name__} le faltan métodos"
            )
        _register_passkey_routes(router, config, passkeys, target, get_current_user_id)

    def _check_provider(provider: str) -> str:
        if provider not in enabled:
            raise HTTPException(status_code=400, detail=f"Provider no soportado: {provider}")
        return config.integration_key(provider)

    async def _connection_end_user_id(connection_id: str, integration_key: str) -> tuple[str, dict]:
        """Fetch the connection and return (end_user_id, connection_dict)."""
        conn = await nango.get_connection(connection_id, integration_key)
        end_user_id = (conn.get("end_user") or {}).get("id", "")
        return end_user_id, conn

    # ── Login ───────────────────────────────────────────────────────────────
    @router.post("/connect/login/session")
    async def login_session(body: _SessionRequest):
        integration_key = _check_provider(body.provider)
        nonce_id, nonce_token = create_login_nonce(config.state_signing_key)
        session_token = await nango.create_connect_session(
            end_user={"id": nonce_id},
            allowed_integrations=[integration_key],
        )
        return {
            "sessionToken": session_token,
            "nonce": nonce_token,
            "provider": body.provider,
            "providerConfigKey": integration_key,
        }

    @router.post("/connect/login/finalize")
    async def login_finalize(body: _LoginFinalizeRequest):
        integration_key = _check_provider(body.provider)
        nonce_id = verify_login_nonce(body.nonce, config.state_signing_key)

        end_user_id, conn = await _connection_end_user_id(body.connectionId, integration_key)
        if end_user_id != nonce_id:
            logger.warning("Login finalize: connection end_user mismatch")
            raise HTTPException(status_code=400, detail="Connection no coincide con la sesión")

        access_token = (conn.get("credentials") or {}).get("access_token", "")
        identity = await fetch_identity(body.provider, access_token)
        if not identity.email or not identity.provider_user_id:
            logger.error("Login finalize: provider returned no identity: %s", identity)
            raise HTTPException(status_code=502, detail="No se pudo obtener la identidad del proveedor")

        user_id, app_token = await storage.find_or_create_by_identity(
            identity.provider, identity.provider_user_id,
            identity.email, identity.given_name, identity.family_name,
        )
        await storage.save_connection(user_id, body.provider, body.connectionId, identity.email)
        logger.info("Login success via %s: %s", body.provider, identity.email)
        return {
            "token": app_token,
            "email": identity.email,
            "given_name": identity.given_name,
            "family_name": identity.family_name,
            "provider": body.provider,
        }

    # ── Email connect (authenticated) ─────────────────────────────────────────
    @router.post("/connect/email/session")
    async def email_session(
        body: _SessionRequest,
        user_id: str = Depends(get_current_user_id),
    ):
        integration_key = _check_provider(body.provider)
        session_token = await nango.create_connect_session(
            end_user={"id": user_id},
            allowed_integrations=[integration_key],
        )
        return {
            "sessionToken": session_token,
            "provider": body.provider,
            "providerConfigKey": integration_key,
        }

    @router.post("/connect/email/finalize")
    async def email_finalize(
        body: _EmailFinalizeRequest,
        user_id: str = Depends(get_current_user_id),
    ):
        integration_key = _check_provider(body.provider)
        end_user_id, conn = await _connection_end_user_id(body.connectionId, integration_key)
        if end_user_id != user_id:
            logger.warning("Email finalize: connection end_user mismatch for user %s", user_id)
            raise HTTPException(status_code=403, detail="Connection no pertenece al usuario")

        access_token = (conn.get("credentials") or {}).get("access_token", "")
        identity = await fetch_identity(body.provider, access_token)
        await storage.save_connection(user_id, body.provider, body.connectionId, identity.email)
        logger.info("Email connected via %s for user %s (%s)", body.provider, user_id, identity.email)
        return {"status": "connected", "provider": body.provider, "email": identity.email}

    # ── Disconnect ─────────────────────────────────────────────────────────────
    @router.delete("/disconnect", status_code=204)
    async def disconnect(user_id: str = Depends(get_current_user_id)):
        existing = await storage.get_connection(user_id)
        if existing:
            provider, connection_id, _ = existing
            try:
                await nango.delete_connection(connection_id, config.integration_key(provider))
            except Exception as exc:  # don't block local cleanup on a Nango hiccup
                logger.error("Nango delete_connection failed for user %s: %s", user_id, exc)
        await storage.clear_connection(user_id)

    # ── Nango webhook (opt-in) ─────────────────────────────────────────────────
    # Redundant, reliable server-side capture of connection lifecycle events.
    # Only registered when the consumer supplies a handler. NOTE: confirm the
    # `X-Nango-Signature` scheme against your Nango version before relying on it.
    if nango_webhook_handler is not None:
        @router.post("/webhook/nango")
        async def nango_webhook(request: Request):
            raw = await request.body()
            signature = request.headers.get("X-Nango-Signature", "")
            expected = hmac.new(
                config.nango_secret_key.encode(), raw, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise HTTPException(status_code=401, detail="Firma de webhook inválida")
            await nango_webhook_handler(await request.json())
            return {"ok": True}

    return router
