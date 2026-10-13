"""
Passkeys — WebAuthn authentication with Face ID, Touch ID, Windows Hello,
Android biometrics or a hardware security key, alongside the Nango OAuth flow.

Server side uses the `webauthn` package (Duo Labs' py_webauthn, the library
behind https://webauthn.io); the browser side is `@simplewebauthn/browser`
(`startRegistration` / `startAuthentication`), which produces exactly the JSON
this module verifies. No private key ever reaches the server: we store the
credential's public key and signature counter (see `PasskeyStorage`).

Both ceremonies are stateless: the challenge travels to the client inside a
signed, short-lived token (`devbout_oauth.state`) and comes back with the
assertion, so nothing has to be kept in a session store between the two calls.
"""
import json
from dataclasses import dataclass, field
from typing import Optional, Sequence

from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, options_to_json
from webauthn.helpers.exceptions import (
    InvalidAuthenticationResponse,
    InvalidCBORData,
    InvalidJSONStructure,
    InvalidRegistrationResponse,
    UnsupportedAlgorithm,
    UnsupportedPublicKey,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)

from .state import (
    PASSKEY_AUTHENTICATION,
    PASSKEY_REGISTRATION,
    create_passkey_challenge,
    verify_passkey_challenge,
)
from .storage import PasskeyCredential, PasskeyUser

# Any of these means "the assertion/attestation isn't acceptable", never a bug
# in our own code — the router turns them into a 401.
_VERIFICATION_ERRORS = (
    InvalidRegistrationResponse,
    InvalidAuthenticationResponse,
    InvalidJSONStructure,
    InvalidCBORData,
    UnsupportedAlgorithm,
    UnsupportedPublicKey,
    ValueError,
    KeyError,
    TypeError,
)


class PasskeyError(Exception):
    """The credential the client sent could not be verified."""


@dataclass(frozen=True)
class PasskeyConfig:
    """
    Relying Party (RP) identity, as the browser/OS see it.

    `rp_id` is the registrable domain the passkeys are bound to — a bare
    hostname, no scheme, no port, no path — and `origins` are the exact origins
    the consumer frontends are served from. WebAuthn requires both to match, so
    a credential created at `https://gestion.ar` cannot be used by
    `https://evil.example` (the RP ID is baked into the credential and covered
    by the signature).
    """

    rp_id: str
    rp_name: str
    origins: list[str]
    # "preferred" lets the OS decide (Touch ID / Windows Hello already verify the
    # user); "required" demands a UV-capable authenticator on every ceremony.
    user_verification: str = "preferred"
    # "preferred" asks for a discoverable (resident) credential, which is what
    # makes usernameless login possible: the passkey itself carries the account.
    resident_key: str = "preferred"
    challenge_ttl_minutes: int = 5
    timeout_ms: int = 60000

    def __post_init__(self) -> None:
        if not self.rp_id or "/" in self.rp_id or ":" in self.rp_id:
            raise ValueError(
                f"passkeys.rp_id debe ser un dominio sin esquema ni puerto: {self.rp_id!r}"
            )
        if not self.origins:
            raise ValueError("passkeys.origins requiere al menos un origin")
        for origin in self.origins:
            if not origin.startswith(("http://", "https://")) or origin.endswith("/"):
                raise ValueError(
                    f"passkeys.origins espera origins con esquema y sin barra final: {origin!r}"
                )
        if self.user_verification not in {v.value for v in UserVerificationRequirement}:
            raise ValueError(
                f"passkeys.user_verification debe ser uno de "
                f"{sorted(v.value for v in UserVerificationRequirement)}"
            )
        if self.resident_key not in {v.value for v in ResidentKeyRequirement}:
            raise ValueError(
                f"passkeys.resident_key debe ser uno de "
                f"{sorted(v.value for v in ResidentKeyRequirement)}"
            )
        if self.challenge_ttl_minutes <= 0 or self.timeout_ms <= 0:
            raise ValueError("passkeys: challenge_ttl_minutes y timeout_ms deben ser positivos")


@dataclass(frozen=True)
class RegisteredPasskey:
    """Outcome of a successful registration, ready to persist as-is."""

    user_id: str
    credential_id: str          # base64url
    public_key: str             # base64url, COSE key
    sign_count: int
    transports: list[str] = field(default_factory=list)
    device_type: str = ""       # "single_device" | "multi_device"
    backed_up: bool = False     # True ⇒ the passkey syncs across the user's devices


def registration_options(
    config: PasskeyConfig,
    signing_key: str,
    user: PasskeyUser,
    exclude: Sequence[PasskeyCredential] = (),
) -> tuple[dict, str]:
    """
    Start a registration ceremony. Return (options, challenge_token).

    `options` is the JSON the frontend hands to `startRegistration` verbatim;
    `challenge_token` must be posted back to `/passkey/register/verify`.
    Credentials the user already has are sent as `excludeCredentials` so an
    authenticator doesn't silently register the same device twice.
    """
    options = generate_registration_options(
        rp_id=config.rp_id,
        rp_name=config.rp_name,
        user_id=user.user_id.encode(),
        user_name=user.username,
        user_display_name=user.display_name or user.username,
        timeout=config.timeout_ms,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement(config.resident_key),
            user_verification=UserVerificationRequirement(config.user_verification),
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(credential.credential_id),
                transports=_known_transports(credential.transports),
            )
            for credential in exclude
        ] or None,
    )
    token = create_passkey_challenge(
        signing_key,
        options.challenge,
        PASSKEY_REGISTRATION,
        user_id=user.user_id,
        expire_minutes=config.challenge_ttl_minutes,
    )
    return _options_dict(options), token


def finish_registration(
    config: PasskeyConfig,
    signing_key: str,
    credential: dict,
    challenge_token: str,
) -> RegisteredPasskey:
    """
    Verify the attestation and return the passkey to persist.

    Raises `PasskeyError` (or HTTP 400 from the challenge token) if the
    challenge expired, was minted for another ceremony/user, or the attestation
    doesn't verify.
    """
    user_id, challenge = verify_passkey_challenge(
        challenge_token, signing_key, PASSKEY_REGISTRATION
    )
    try:
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=config.rp_id,
            expected_origin=config.origins,
            require_user_verification=config.user_verification == "required",
        )
    except _VERIFICATION_ERRORS as exc:
        raise PasskeyError(f"Registro de passkey inválido: {exc}") from exc

    return RegisteredPasskey(
        user_id=user_id,
        credential_id=bytes_to_base64url(verified.credential_id),
        public_key=bytes_to_base64url(verified.credential_public_key),
        sign_count=verified.sign_count,
        transports=_known_transports((credential.get("response") or {}).get("transports")),
        device_type=verified.credential_device_type.value,
        backed_up=verified.credential_backed_up,
    )


def authentication_options(
    config: PasskeyConfig,
    signing_key: str,
    credentials: Sequence[PasskeyCredential] = (),
    user_id: str = "",
) -> tuple[dict, str]:
    """
    Start a login ceremony. Return (options, challenge_token).

    With `credentials` empty the browser is free to offer any discoverable
    passkey for this RP at all (usernameless login — the account is resolved
    from the assertion's credential id); pass the user's credentials when the
    username is already known to pin the choice down to their passkeys.
    """
    options = generate_authentication_options(
        rp_id=config.rp_id,
        timeout=config.timeout_ms,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=base64url_to_bytes(credential.credential_id),
                transports=_known_transports(credential.transports),
            )
            for credential in credentials
        ] or None,
        user_verification=UserVerificationRequirement(config.user_verification),
    )
    token = create_passkey_challenge(
        signing_key,
        options.challenge,
        PASSKEY_AUTHENTICATION,
        user_id=user_id,
        expire_minutes=config.challenge_ttl_minutes,
    )
    return _options_dict(options), token


def finish_authentication(
    config: PasskeyConfig,
    signing_key: str,
    credential: dict,
    challenge_token: str,
    stored: PasskeyCredential,
) -> int:
    """
    Verify the assertion against the stored public key.

    Return the authenticator's new signature counter, to be persisted; a
    counter that didn't advance past `stored.sign_count` is rejected here (the
    usual symptom of a cloned credential).
    """
    expected_user_id, challenge = verify_passkey_challenge(
        challenge_token, signing_key, PASSKEY_AUTHENTICATION
    )
    if expected_user_id and expected_user_id != stored.user_id:
        raise PasskeyError("La credencial no pertenece al usuario de la sesión")
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=config.rp_id,
            expected_origin=config.origins,
            credential_public_key=base64url_to_bytes(stored.public_key),
            credential_current_sign_count=stored.sign_count,
            require_user_verification=config.user_verification == "required",
        )
    except _VERIFICATION_ERRORS as exc:
        raise PasskeyError(f"Autenticación con passkey inválida: {exc}") from exc

    return verified.new_sign_count


def credential_id_of(credential: dict) -> str:
    """
    Read the credential id from the client's JSON.

    `id` is base64url of `rawId` (py_webauthn enforces they match), and it's the
    value we store on registration, so it's also the login lookup key.
    """
    credential_id = credential.get("id")
    if not isinstance(credential_id, str) or not credential_id:
        raise PasskeyError("La credencial no incluye un id válido")
    return credential_id


def _known_transports(values: Optional[Sequence[str]]) -> Optional[list[AuthenticatorTransport]]:
    """Keep only transports WebAuthn defines; the value comes from the client."""
    known = {transport.value: transport for transport in AuthenticatorTransport}
    if not values:
        return None
    return [known[value] for value in values if value in known] or None


def _options_dict(options) -> dict:
    """Turn py_webauthn options (binary fields) into browser-ready JSON."""
    return json.loads(options_to_json(options))
