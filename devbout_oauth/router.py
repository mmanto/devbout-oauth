"""
FastAPI router factory for Nango-backed auth + integrations.

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
from .state import create_login_nonce, verify_login_nonce
from .storage import ConnectionStorage

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


def create_router(
    config: NangoConfig,
    storage: ConnectionStorage,
    get_current_user_id: Callable,
    providers: frozenset[str] = frozenset({"google", "microsoft"}),
    prefix: str = "/auth",
    nango_webhook_handler: Optional[Callable[[dict], Awaitable[None]]] = None,
) -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["auth"])
    nango = NangoClient(config)

    enabled = providers & SUPPORTED_PROVIDERS

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
