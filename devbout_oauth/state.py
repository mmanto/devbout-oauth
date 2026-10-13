"""
Short-lived signed state for the auth ceremonies.

Login and passkey ceremonies start before we know who the user is, so there is
no server-side session to hang state on. Instead we mint a signed, short-lived
JWT that the client round-trips, which makes both ceremonies stateless and
replay-proof:

- **login nonce** — used as the Nango `end_user.id` for the connect session; on
  finalize we check the resulting connection carries the same id. This stops a
  caller from finalizing an arbitrary connectionId they didn't initiate.
- **passkey challenge** — carries the WebAuthn challenge (plus the user it was
  minted for) so the server can verify the signed assertion it gets back
  without keeping a challenge store. The ceremony (`registration` |
  `authentication`) is part of the signed payload, so a registration challenge
  can't be replayed into a login.
"""
import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from jose import JWTError, jwt

_ALGORITHM = "HS256"
_LOGIN_EXPIRE_MINUTES = 5
_LOGIN_PURPOSE = "login_nonce"

PASSKEY_REGISTRATION = "passkey_registration"
PASSKEY_AUTHENTICATION = "passkey_authentication"
_PASSKEY_PURPOSES = frozenset({PASSKEY_REGISTRATION, PASSKEY_AUTHENTICATION})


def _encode(signing_key: str, purpose: str, expire_minutes: int, **claims: Any) -> str:
    payload = {
        "purpose": purpose,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=expire_minutes),
        **claims,
    }
    return jwt.encode(payload, signing_key, algorithm=_ALGORITHM)


def _decode(token: str, signing_key: str, purpose: str, error_detail: str) -> dict:
    try:
        payload = jwt.decode(token, signing_key, algorithms=[_ALGORITHM])
        if payload.get("purpose") != purpose:
            raise ValueError("wrong purpose")
        return payload
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=400, detail=error_detail)


# ── Login nonce ───────────────────────────────────────────────────────────────

def create_login_nonce(signing_key: str) -> tuple[str, str]:
    """Return (nonce_id, signed_token). nonce_id is used as Nango end_user.id."""
    nonce_id = f"login_{uuid.uuid4().hex}"
    return nonce_id, _encode(signing_key, _LOGIN_PURPOSE, _LOGIN_EXPIRE_MINUTES, sub=nonce_id)


def verify_login_nonce(token: str, signing_key: str) -> str:
    """Return the nonce_id, or raise HTTP 400 if invalid/expired."""
    payload = _decode(
        token, signing_key, _LOGIN_PURPOSE, "Login nonce inválido o expirado"
    )
    nonce_id = payload.get("sub")
    if not nonce_id:
        raise HTTPException(status_code=400, detail="Login nonce inválido o expirado")
    return nonce_id


# ── Passkey challenge ─────────────────────────────────────────────────────────

def create_passkey_challenge(
    signing_key: str,
    challenge: bytes,
    ceremony: str,
    user_id: str = "",
    expire_minutes: int = 5,
) -> str:
    """
    Sign a WebAuthn challenge (base64url-encoded inside the token).

    `user_id` is empty for a usernameless login (discoverable credential): the
    account is resolved from the credential id in the assertion instead.
    """
    if ceremony not in _PASSKEY_PURPOSES:
        raise ValueError(f"Ceremonia de passkey desconocida: {ceremony!r}")
    return _encode(
        signing_key,
        ceremony,
        expire_minutes,
        sub=user_id,
        challenge=base64.urlsafe_b64encode(challenge).decode().rstrip("="),
    )


def verify_passkey_challenge(token: str, signing_key: str, ceremony: str) -> tuple[str, bytes]:
    """Return (user_id, challenge_bytes), or raise HTTP 400 if invalid/expired."""
    payload = _decode(
        token, signing_key, ceremony, "Desafío de passkey inválido o expirado"
    )
    challenge = payload.get("challenge")
    if not challenge:
        raise HTTPException(status_code=400, detail="Desafío de passkey inválido o expirado")
    padded = challenge + "=" * (-len(challenge) % 4)
    return payload.get("sub", ""), base64.urlsafe_b64decode(padded)
