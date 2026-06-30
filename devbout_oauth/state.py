"""
Short-lived login nonce.

Login happens before we know who the user is, so we can't bind the connect
session to an internal user id. Instead we mint a signed, random, 5-minute
nonce, use it as the Nango `end_user.id` when creating the connect session, and
verify on finalize that the resulting connection carries the same id. This stops
a caller from finalizing an arbitrary connectionId they didn't initiate.
"""
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from jose import JWTError, jwt

_ALGORITHM = "HS256"
_EXPIRE_MINUTES = 5
_PURPOSE = "login_nonce"


def create_login_nonce(signing_key: str) -> tuple[str, str]:
    """Return (nonce_id, signed_token). nonce_id is used as Nango end_user.id."""
    nonce_id = f"login_{uuid.uuid4().hex}"
    payload = {
        "sub": nonce_id,
        "purpose": _PURPOSE,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=_EXPIRE_MINUTES),
    }
    return nonce_id, jwt.encode(payload, signing_key, algorithm=_ALGORITHM)


def verify_login_nonce(token: str, signing_key: str) -> str:
    """Return the nonce_id, or raise HTTP 400 if invalid/expired."""
    try:
        payload = jwt.decode(token, signing_key, algorithms=[_ALGORITHM])
        if payload.get("purpose") != _PURPOSE:
            raise ValueError("not a login nonce")
        return payload["sub"]
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=400, detail="Login nonce inválido o expirado")
