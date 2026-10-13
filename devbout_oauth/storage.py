from dataclasses import dataclass, field
from datetime import datetime
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


# ── Passkeys (WebAuthn) ───────────────────────────────────────────────────────

@dataclass(frozen=True)
class PasskeyUser:
    """
    The account a passkey belongs to, in the shape WebAuthn needs.

    `user_id` is the WebAuthn user handle (persisted inside the credential, so
    it must stay stable for the account's lifetime); `username` (email) and
    `display_name` are the strings the browser/OS show when the credential is
    created.
    """

    user_id: str
    username: str
    display_name: str = ""


@dataclass(frozen=True)
class PasskeyCredential:
    """
    A registered passkey. Both keys are base64url strings (WebAuthn's wire
    format), so they fit in a plain TEXT column:

    - `credential_id`: lookup key the authenticator presents on each login.
    - `public_key`: COSE-encoded public key used to verify the assertion's
      signature. The private key never leaves the user's device.
    - `sign_count`: signature counter; a value that doesn't advance past the
      stored one means the credential may have been cloned.
    """

    credential_id: str
    user_id: str
    public_key: str
    sign_count: int = 0
    transports: list[str] = field(default_factory=list)
    name: Optional[str] = None
    created_at: Optional[datetime] = None


@runtime_checkable
class PasskeyStorage(Protocol):
    """
    Persistence contract the consuming app implements to enable passkeys.

    Only a credential's *public* key and counter are stored — never a secret.
    Required when `create_router(..., passkeys=PasskeyConfig(...))` is used:
    `storage` itself may implement this protocol, or a separate object may be
    passed as `passkey_storage`.
    """

    async def get_passkey_user(self, user_id: str) -> Optional[PasskeyUser]:
        """Return the account behind `user_id`, or None if it doesn't exist."""
        ...

    async def get_passkey_user_by_username(self, username: str) -> Optional[PasskeyUser]:
        """Return the account for `username` (usually the email), or None."""
        ...

    async def save_passkey(
        self,
        user_id: str,
        credential_id: str,
        public_key: str,
        sign_count: int,
        transports: list[str],
        name: Optional[str],
    ) -> None:
        """Persist a newly registered passkey for the user."""
        ...

    async def get_passkey(self, credential_id: str) -> Optional[PasskeyCredential]:
        """Return that credential, or None if it was never registered."""
        ...

    async def list_passkeys(self, user_id: str) -> list[PasskeyCredential]:
        """List the user's registered passkeys (metadata only)."""
        ...

    async def update_passkey_sign_count(self, credential_id: str, sign_count: int) -> None:
        """Store the counter the authenticator returned on the last login."""
        ...

    async def delete_passkey(self, user_id: str, credential_id: str) -> None:
        """Remove one of the user's passkeys."""
        ...

    async def issue_app_token(self, user_id: str) -> str:
        """
        Mint the app token for an *existing* user (no create): passkey login
        authenticates, it never provisions accounts.
        """
        ...


class InMemoryPasskeyStorage:
    """Simple in-memory passkey storage for unit tests."""

    def __init__(self) -> None:
        self.users: dict[str, PasskeyUser] = {}
        # credential_id → PasskeyCredential
        self.credentials: dict[str, PasskeyCredential] = {}

    async def get_passkey_user(self, user_id: str) -> Optional[PasskeyUser]:
        return self.users.get(user_id)

    async def get_passkey_user_by_username(self, username: str) -> Optional[PasskeyUser]:
        for user in self.users.values():
            if user.username == username:
                return user
        return None

    async def save_passkey(
        self,
        user_id: str,
        credential_id: str,
        public_key: str,
        sign_count: int,
        transports: list[str],
        name: Optional[str],
    ) -> None:
        self.credentials[credential_id] = PasskeyCredential(
            credential_id=credential_id,
            user_id=user_id,
            public_key=public_key,
            sign_count=sign_count,
            transports=list(transports),
            name=name,
        )

    async def get_passkey(self, credential_id: str) -> Optional[PasskeyCredential]:
        return self.credentials.get(credential_id)

    async def list_passkeys(self, user_id: str) -> list[PasskeyCredential]:
        return [c for c in self.credentials.values() if c.user_id == user_id]

    async def update_passkey_sign_count(self, credential_id: str, sign_count: int) -> None:
        current = self.credentials.get(credential_id)
        if current is None:
            return
        self.credentials[credential_id] = PasskeyCredential(
            credential_id=current.credential_id,
            user_id=current.user_id,
            public_key=current.public_key,
            sign_count=sign_count,
            transports=list(current.transports),
            name=current.name,
            created_at=current.created_at,
        )

    async def delete_passkey(self, user_id: str, credential_id: str) -> None:
        current = self.credentials.get(credential_id)
        if current is not None and current.user_id == user_id:
            del self.credentials[credential_id]

    async def issue_app_token(self, user_id: str) -> str:
        return f"test_token_{user_id}"
