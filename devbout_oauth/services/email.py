"""
Provider-agnostic transactional email.

Sends through whatever provider the user connected via Nango, using a fresh
access token (no refresh token / client secret needed here — Nango owns those):
  - Google:    Gmail API  POST users/me/messages/send  (raw RFC822 / base64url)
  - Microsoft: Graph API  POST /me/sendMail            (JSON message)
"""
import base64
import logging
from email.message import EmailMessage
from typing import Optional

import httpx

from ..config import GOOGLE, MICROSOFT

logger = logging.getLogger(__name__)

_GMAIL_SEND = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"
_GRAPH_SENDMAIL = "https://graph.microsoft.com/v1.0/me/sendMail"


def _as_list(value: Optional[str | list[str]]) -> list[str]:
    if not value:
        return []
    return value if isinstance(value, list) else [value]


class EmailSender:
    """Send email via the connected provider, given a fresh access token."""

    @classmethod
    async def send(
        cls,
        provider: str,
        access_token: str,
        to: str | list[str],
        subject: str,
        body_html: str,
        from_address: Optional[str] = None,
        from_name: Optional[str] = None,
        cc: Optional[str | list[str]] = None,
    ) -> None:
        if provider == GOOGLE:
            await cls._send_gmail(
                access_token, to, subject, body_html, from_address, from_name, cc
            )
        elif provider == MICROSOFT:
            await cls._send_graph(access_token, to, subject, body_html, cc)
        else:
            raise ValueError(f"Unsupported provider: {provider!r}")
        logger.info("Email sent via %s to %s", provider, to)

    # ── Google / Gmail ──────────────────────────────────────────────────────
    @classmethod
    async def _send_gmail(
        cls,
        access_token: str,
        to: str | list[str],
        subject: str,
        body_html: str,
        from_address: Optional[str],
        from_name: Optional[str],
        cc: Optional[str | list[str]],
    ) -> None:
        msg = EmailMessage()
        msg["Subject"] = subject
        if from_address:
            msg["From"] = f"{from_name} <{from_address}>" if from_name else from_address
        msg["To"] = ", ".join(_as_list(to))
        if cc:
            msg["Cc"] = ", ".join(_as_list(cc))
        msg.add_alternative(body_html, subtype="html")

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                _GMAIL_SEND,
                headers={"Authorization": f"Bearer {access_token}"},
                json={"raw": raw},
            )
        if resp.status_code >= 300:
            logger.error("Gmail send failed: %s %s", resp.status_code, resp.text)
            raise RuntimeError(f"Gmail send returned {resp.status_code}")

    # ── Microsoft / Graph ─────────────────────────────────────────────────────
    @classmethod
    async def _send_graph(
        cls,
        access_token: str,
        to: str | list[str],
        subject: str,
        body_html: str,
        cc: Optional[str | list[str]],
    ) -> None:
        # Graph sends from the authenticated mailbox; an arbitrary From would
        # require SendAs/SendOnBehalf permissions, so from_address is ignored.
        def recipients(values: list[str]) -> list[dict]:
            return [{"emailAddress": {"address": v}} for v in values]

        message: dict = {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body_html},
            "toRecipients": recipients(_as_list(to)),
        }
        if cc:
            message["ccRecipients"] = recipients(_as_list(cc))

        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                _GRAPH_SENDMAIL,
                headers={"Authorization": f"Bearer {access_token}"},
                json={"message": message, "saveToSentItems": True},
            )
        if resp.status_code >= 300:
            logger.error("Graph sendMail failed: %s %s", resp.status_code, resp.text)
            raise RuntimeError(f"Graph sendMail returned {resp.status_code}")
