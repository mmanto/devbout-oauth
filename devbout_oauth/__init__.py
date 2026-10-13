from .config import GOOGLE, MICROSOFT, SUPPORTED_PROVIDERS, NangoConfig
from .crypto import decrypt_token, encrypt_token
from .facade import DevboutAuth
from .identity import Identity, fetch_identity
from .nango_client import NangoClient, NangoError
from .passkeys import (
    PasskeyConfig,
    PasskeyError,
    RegisteredPasskey,
    authentication_options,
    credential_id_of,
    finish_authentication,
    finish_registration,
    registration_options,
)
from .router import create_router
from .services.email import EmailSender
from .storage import (
    ConnectionStorage,
    InMemoryConnectionStorage,
    InMemoryPasskeyStorage,
    PasskeyCredential,
    PasskeyStorage,
    PasskeyUser,
)

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
    "PasskeyStorage",
    "PasskeyUser",
    "PasskeyCredential",
    "InMemoryPasskeyStorage",
    # passkeys (WebAuthn: huella, rostro, llave de seguridad)
    "PasskeyConfig",
    "PasskeyError",
    "RegisteredPasskey",
    "registration_options",
    "finish_registration",
    "authentication_options",
    "finish_authentication",
    "credential_id_of",
    # crypto (still used by consumers for app passwords, unrelated to OAuth)
    "encrypt_token",
    "decrypt_token",
]
