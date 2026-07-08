"""Outbound notifications fan-out.

`notify()` sends a message to every configured channel — the existing Telegram
bot and, if an incoming webhook is set, Microsoft Teams. Each channel is
best-effort: a failure in one never blocks the other, and the function reports
which channels actually delivered so callers can record it.

Telegram already has a fire-and-forget sender (telegram_client.send_notification,
HTML parse mode). Teams had a webhook *setting* but no sender until now — this
module posts a simple MessageCard to the incoming webhook.
"""
import logging

import httpx

from app.config import settings

logger = logging.getLogger(__name__)


def _plainify(html: str) -> str:
    """Very small HTML→text reduction for channels that want plain text."""
    import re
    text = re.sub(r"<br\s*/?>", "\n", html, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    return (text.replace("&amp;", "&").replace("&lt;", "<")
                .replace("&gt;", ">").replace("&nbsp;", " "))


async def send_teams(text_html: str, title: str | None = None) -> None:
    """Post a MessageCard to the Teams incoming webhook. Raises on failure so the
    caller can record the error."""
    url = settings.teams_incoming_webhook
    if not url:
        return
    # Teams MessageCard uses \n\n for line breaks and a limited markdown subset;
    # convert our HTML to plain text and let Teams render the newlines.
    body = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "themeColor": "d13438",
        "summary": title or "Warroom",
        "title": title or "Warroom",
        "text": _plainify(text_html).replace("\n", "\n\n"),
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, json=body)
        resp.raise_for_status()


async def notify(text_html: str, title: str | None = None) -> dict:
    """Fan out to all configured channels. Never raises; returns
    {"channels": [...delivered...], "errors": {channel: msg}}."""
    delivered: list[str] = []
    errors: dict[str, str] = {}

    # Telegram (send_notification is a no-op when telegram is disabled).
    if settings.telegram_enabled and settings.telegram_bot_token and settings.telegram_chat_id:
        try:
            from app.telegram_client import send_notification
            await send_notification(text_html)
            delivered.append("telegram")
        except Exception as e:  # pragma: no cover - network best-effort
            errors["telegram"] = str(e)[:200]
            logger.warning(f"telegram notify failed: {e}")

    # Teams (only when a webhook is configured).
    if settings.teams_incoming_webhook:
        try:
            await send_teams(text_html, title=title)
            delivered.append("teams")
        except Exception as e:  # pragma: no cover - network best-effort
            errors["teams"] = str(e)[:200]
            logger.warning(f"teams notify failed: {e}")

    return {"channels": delivered, "errors": errors}
