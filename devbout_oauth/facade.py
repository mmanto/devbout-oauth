"""
Convenience facade for consumers that just want to send mail "as the user"
without touching Nango or token plumbing.
"""
import logging
from typing import Optional

from .config import NangoConfig
from .nango_client import NangoClient
from .services.email import EmailSender
from .storage import ConnectionStorage

logger = logging.getLogger(__name__)


class DevboutAuth:
    def __init__(self, config: NangoConfig, storage: ConnectionStorage) -> None:
        self._config = config
        self._storage = storage
        self.nango = NangoClient(config)

    async def send_email(
        self,
        user_id: str,
        to: str | list[str],
        subject: str,
        body_html: str,
        from_address: Optional[str] = None,
        from_name: Optional[str] = None,
        cc: Optional[str | list[str]] = None,
    ) -> None:
        """Resolve the user's connection → fresh access token → send via provider."""
        record = await self._storage.get_connection(user_id)
        if not record:
            raise RuntimeError(f"User {user_id} has no connected email provider")
        provider, connection_id, _email = record
        access_token = await self.nango.get_access_token(
            connection_id, self._config.integration_key(provider)
        )
        await EmailSender.send(
            provider, access_token, to, subject, body_html,
            from_address=from_address, from_name=from_name, cc=cc,
        )
