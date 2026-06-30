from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class ConnectionStorage(Protocol):
    """
    Persistence contract the consuming app implements.

    Nango custodies and refreshes the provider tokens, so the app only stores
    the *mapping* from its internal user to a Nango connection — never a refresh
    token. A connection is identified by (provider, connection_id).
    """

    async def save_connection(
        self,
        user_id: str,
        provider: str,
        connection_id: str,
        email: str,
    ) -> None:
        """Persist (or update) the Nango connection for this user."""
        ...

    async def get_connection(self, user_id: str) -> Optional[tuple[str, str, str]]:
        """Return (provider, connection_id, email) for the user, or None."""
        ...

    async def clear_connection(self, user_id: str) -> None:
        """Remove the stored connection for this user."""
        ...

    async def find_or_create_by_identity(
        self,
        provider: str,
        provider_user_id: str,
        email: str,
        given_name: str,
        family_name: str,
    ) -> tuple[str, str]:
        """
        Only required when the login flow is enabled.
        Find an existing user by (provider, provider_user_id) or email, or create
        one. Returns (internal_user_id, app_jwt_token).
        """
        ...


class InMemoryConnectionStorage:
    """Simple in-memory storage for unit tests."""

    def __init__(self) -> None:
        # user_id → (provider, connection_id, email)
        self._connections: dict[str, tuple[str, str, str]] = {}
        # (provider, provider_user_id) → (user_id, app_token)
        self._identities: dict[tuple[str, str], tuple[str, str]] = {}

    async def save_connection(
        self, user_id: str, provider: str, connection_id: str, email: str
    ) -> None:
        self._connections[user_id] = (provider, connection_id, email)

    async def get_connection(self, user_id: str) -> Optional[tuple[str, str, str]]:
        return self._connections.get(user_id)

    async def clear_connection(self, user_id: str) -> None:
        self._connections.pop(user_id, None)

    async def find_or_create_by_identity(
        self,
        provider: str,
        provider_user_id: str,
        email: str,
        given_name: str,
        family_name: str,
    ) -> tuple[str, str]:
        key = (provider, provider_user_id)
        if key in self._identities:
            return self._identities[key]
        user_id = f"user_{len(self._identities) + 1}"
        app_token = f"test_token_{user_id}"
        self._identities[key] = (user_id, app_token)
        return user_id, app_token
