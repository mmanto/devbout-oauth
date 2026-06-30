"""
Provider-agnostic identity lookup.

Given a fresh access token (obtained from Nango), fetch the authenticated
user's profile and normalize it across Google and Microsoft.
"""
import logging
from dataclasses import dataclass

import httpx

from .config import GOOGLE, MICROSOFT

logger = logging.getLogger(__name__)


@dataclass
class Identity:
    provider: str
    provider_user_id: str   # stable id at the provider (Google `sub`, Graph `id`)
    email: str
    given_name: str
    family_name: str


async def fetch_identity(provider: str, access_token: str) -> Identity:
    if provider == GOOGLE:
        return await _google_identity(access_token)
    if provider == MICROSOFT:
        return await _microsoft_identity(access_token)
    raise ValueError(f"Unsupported provider: {provider!r}")


async def _google_identity(access_token: str) -> Identity:
    data = await _get_json(
        "https://www.googleapis.com/oauth2/v3/userinfo", access_token
    )
    return Identity(
        provider=GOOGLE,
        provider_user_id=data.get("sub", ""),
        email=data.get("email", ""),
        given_name=data.get("given_name") or "",
        family_name=data.get("family_name") or "",
    )


async def _microsoft_identity(access_token: str) -> Identity:
    data = await _get_json("https://graph.microsoft.com/v1.0/me", access_token)
    # Personal accounts often have `mail` null; fall back to UPN.
    email = data.get("mail") or data.get("userPrincipalName") or ""
    return Identity(
        provider=MICROSOFT,
        provider_user_id=data.get("id", ""),
        email=email,
        given_name=data.get("givenName") or "",
        family_name=data.get("surname") or "",
    )


async def _get_json(url: str, access_token: str) -> dict:
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {access_token}"})
    if resp.status_code != 200:
        logger.error("Identity fetch %s failed: %s %s", url, resp.status_code, resp.text)
        return {}
    return resp.json()
