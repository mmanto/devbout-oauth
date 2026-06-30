from dataclasses import dataclass, field

# Providers supported by this library. The values double as the canonical
# `provider` string stored per-user and used to route identity/email calls.
GOOGLE = "google"
MICROSOFT = "microsoft"
SUPPORTED_PROVIDERS = frozenset({GOOGLE, MICROSOFT})


@dataclass
class NangoConfig:
    """
    Configuration for the Nango-backed auth + integrations layer.

    Nango (self-hosted) brokers the OAuth dance and custodies/refreshes the
    provider tokens, so this library never stores refresh tokens of its own.
    `nango_host` is the base URL of the self-hosted Nango server (the backend
    API), e.g. http://localhost:3003.
    """

    nango_host: str
    nango_secret_key: str
    frontend_url: str
    state_signing_key: str    # signs the short-lived login nonce (HS256)

    # Provider config keys as defined in the Nango dashboard ("Integration ID").
    google_integration_key: str = GOOGLE
    microsoft_integration_key: str = MICROSOFT

    # Where the frontend lands after a successful login / service connect.
    login_success_redirect: str = "/auth/callback"
    connect_success_redirect: str = "/perfil?email=connected"

    # Scopes pushed to Nango via `integrations_config_defaults` on the connect
    # session. Usually also set in the Nango dashboard; sending them here keeps
    # the source of truth in code. `offline_access` (Microsoft) is what yields a
    # refresh token so Nango can keep the connection alive.
    google_scopes: list[str] = field(default_factory=lambda: [
        "openid",
        "email",
        "profile",
        "https://www.googleapis.com/auth/gmail.send",
    ])
    microsoft_scopes: list[str] = field(default_factory=lambda: [
        "openid",
        "email",
        "profile",
        "offline_access",
        "User.Read",
        "Mail.Send",
    ])

    def integration_key(self, provider: str) -> str:
        """Map a canonical provider name to its Nango integration key."""
        if provider == GOOGLE:
            return self.google_integration_key
        if provider == MICROSOFT:
            return self.microsoft_integration_key
        raise ValueError(f"Unsupported provider: {provider!r}")

    def provider_for_integration(self, integration_key: str) -> str:
        """Inverse of integration_key(): used by the Nango webhook receiver."""
        if integration_key == self.google_integration_key:
            return GOOGLE
        if integration_key == self.microsoft_integration_key:
            return MICROSOFT
        raise ValueError(f"Unknown integration key: {integration_key!r}")

    def scopes_for(self, provider: str) -> list[str]:
        if provider == GOOGLE:
            return self.google_scopes
        if provider == MICROSOFT:
            return self.microsoft_scopes
        raise ValueError(f"Unsupported provider: {provider!r}")
