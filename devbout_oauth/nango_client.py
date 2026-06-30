"""
Thin async client over the (self-hosted) Nango backend API.

All calls authenticate with the Nango secret key. The two endpoints we need:
  - POST /connect/sessions  → mint a short-lived session token for the frontend SDK
  - GET  /connections/{id}  → fetch credentials (Nango refreshes the access token)
  - DELETE /connections/{id} → revoke + delete a connection on disconnect
"""
import logging
from typing import Optional

import httpx

from .config import NangoConfig

logger = logging.getLogger(__name__)


class NangoError(RuntimeError):
    """Raised when the Nango API returns a non-success response."""


class NangoClient:
    def __init__(self, config: NangoConfig, timeout: float = 15.0) -> None:
        self._base = config.nango_host.rstrip("/")
        self._secret = config.nango_secret_key
        self._timeout = timeout

    @property
    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._secret}",
            "Content-Type": "application/json",
        }

    async def create_connect_session(
        self,
        end_user: dict,
        allowed_integrations: list[str],
        integrations_config_defaults: Optional[dict] = None,
    ) -> str:
        """Create a connect session and return its short-lived token."""
        body: dict = {
            "end_user": end_user,
            "allowed_integrations": allowed_integrations,
        }
        if integrations_config_defaults:
            body["integrations_config_defaults"] = integrations_config_defaults

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._base}/connect/sessions",
                headers=self._headers,
                json=body,
            )
        if resp.status_code >= 300:
            logger.error("Nango create_connect_session failed: %s %s", resp.status_code, resp.text)
            raise NangoError(f"connect/sessions returned {resp.status_code}")
        return resp.json()["data"]["token"]

    async def get_connection(
        self,
        connection_id: str,
        provider_config_key: str,
        force_refresh: bool = False,
    ) -> dict:
        """
        Fetch a connection. Nango checks token expiry and refreshes if needed,
        so the returned credentials.access_token is always fresh.
        """
        params = {"provider_config_key": provider_config_key, "refresh_token": "true"}
        if force_refresh:
            params["force_refresh"] = "true"

        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(
                f"{self._base}/connections/{connection_id}",
                headers=self._headers,
                params=params,
            )
        if resp.status_code >= 300:
            logger.error("Nango get_connection failed: %s %s", resp.status_code, resp.text)
            raise NangoError(f"connections/{connection_id} returned {resp.status_code}")
        return resp.json()

    async def get_access_token(self, connection_id: str, provider_config_key: str) -> str:
        conn = await self.get_connection(connection_id, provider_config_key)
        token = (conn.get("credentials") or {}).get("access_token")
        if not token:
            raise NangoError("connection has no access_token in credentials")
        return token

    async def delete_connection(self, connection_id: str, provider_config_key: str) -> None:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.delete(
                f"{self._base}/connections/{connection_id}",
                headers=self._headers,
                params={"provider_config_key": provider_config_key},
            )
        # 404 is fine — the connection is already gone.
        if resp.status_code >= 300 and resp.status_code != 404:
            logger.error("Nango delete_connection failed: %s %s", resp.status_code, resp.text)
            raise NangoError(f"delete connections/{connection_id} returned {resp.status_code}")
