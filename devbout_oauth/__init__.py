from .config import GOOGLE, MICROSOFT, SUPPORTED_PROVIDERS, NangoConfig
from .crypto import decrypt_token, encrypt_token
from .facade import DevboutAuth
from .identity import Identity, fetch_identity
from .nango_client import NangoClient, NangoError
from .router import create_router
from .services.email import EmailSender
from .storage import ConnectionStorage, InMemoryConnectionStorage

__all__ = [
    # config / providers
    "NangoConfig",
    "GOOGLE",
    "MICROSOFT",
    "SUPPORTED_PROVIDERS",
    # router + facade
    "create_router",
    "DevboutAuth",
    # nango client
    "NangoClient",
    "NangoError",
    # identity + email
    "Identity",
    "fetch_identity",
    "EmailSender",
    # storage
    "ConnectionStorage",
    "InMemoryConnectionStorage",
    # crypto (still used by consumers for app passwords, unrelated to OAuth)
    "encrypt_token",
    "decrypt_token",
]
