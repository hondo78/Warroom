"""Telegram notifier + interactive approval bot.

Two scheduled jobs drive this (registered in main.py):

  * ``telegram_push_pending`` — finds pending agent_decisions that haven't been
    sent yet and posts an approval prompt with ✅/❌ inline buttons.
  * ``telegram_poll_updates`` — long-polls getUpdates and turns button taps
    (callback queries) into execute_decision / reject calls.

No public webhook is required: the bot pulls updates with getUpdates, so it
works behind NAT. Auth is the bot token; only the configured chat id may act.
"""

import logging
from datetime import datetime, timezone

import httpx
from sqlalchemy import select

from app.config import settings
from app.database import async_session
from app.models import AgentDecision

logger = logging.getLogger(__name__)

_API = "https://api.telegram.org/bot{token}/{method}"
# getUpdates offset cursor — only kept in memory; on restart we resume from
# Telegram's own backlog (confirmed updates are dropped once acknowledged).
_update_offset: int | None = None


def _enabled() -> bool:
    return bool(settings.telegram_enabled and settings.telegram_bot_token and settings.telegram_chat_id)


# Language-aware notification strings (follows settings.agent_language).
_TG_STRINGS = {
    "approval_required": {"de": "🛡 <b>Warroom — Freigabe erforderlich</b>",
                          "en": "🛡 <b>Warroom — Approval required</b>"},
    "action":   {"de": "Aktion", "en": "Action"},
    "source":   {"de": "Quelle", "en": "Source"},
    "decision": {"de": "Decision", "en": "Decision"},
    "not_authorized": {"de": "Nicht autorisiert.", "en": "Not authorized."},
    "unknown_action": {"de": "Unbekannte Aktion.", "en": "Unknown action."},
    "invalid_id": {"de": "Ungültige Decision-ID.", "en": "Invalid decision ID."},
    "not_found": {"de": "Decision nicht gefunden.", "en": "Decision not found."},
    "already": {"de": "Bereits {s}.", "en": "Already {s}."},
    "already_tag": {"de": "— bereits <b>{s}</b>", "en": "— already <b>{s}</b>"},
    "approved_executed": {"de": "✅ <b>FREIGEGEBEN & ausgeführt</b>", "en": "✅ <b>APPROVED & executed</b>"},
    "approve_failed": {"de": "⚠️ Freigabe fehlgeschlagen: {e}", "en": "⚠️ Approve failed: {e}"},
    "approved": {"de": "Freigegeben.", "en": "Approved."},
    "exec_error": {"de": "Fehler beim Ausführen.", "en": "Execution error."},
    "rejected_tag": {"de": "❌ <b>ABGELEHNT</b>", "en": "❌ <b>REJECTED</b>"},
    "rejected": {"de": "Abgelehnt.", "en": "Rejected."},
    "by": {"de": "von", "en": "by"},
}


def _tg(key: str, **vars) -> str:
    lang = "de" if getattr(settings, "agent_language", "en") == "de" else "en"
    s = _TG_STRINGS.get(key, {}).get(lang, key)
    return s.format(**vars) if vars else s


async def _call(method: str, payload: dict, timeout: float = 15.0) -> dict | None:
    url = _API.format(token=settings.telegram_bot_token, method=method)
    try:
        async with httpx.AsyncClient(timeout=timeout) as c:
            r = await c.post(url, json=payload)
            data = r.json()
            if not data.get("ok"):
                logger.warning(f"telegram {method} failed: {data.get('description')}")
                return None
            return data.get("result")
    except Exception as e:
        logger.warning(f"telegram {method} error: {e}")
        return None


def _decision_caption(rec: AgentDecision, ip: str | None) -> str:
    src = rec.source_type or "alert"
    reason = (rec.reasoning or "").strip()
    if len(reason) > 600:
        reason = reason[:600] + "…"
    lines = [
        _tg("approval_required"),
        f"<b>{_tg('action')}:</b> {rec.action}",
    ]
    if ip:
        lines.append(f"<b>IP:</b> <code>{ip}</code>")
    lines += [
        f"<b>{_tg('source')}:</b> {src}",
        f"<b>{_tg('decision')}:</b> #{rec.id}",
    ]
    if reason:
        lines.append(f"\n{reason}")
    return "\n".join(lines)


def _decision_ip(rec: AgentDecision) -> str | None:
    args = rec.action_args or {}
    return args.get("target_ip") or rec.source_ip or (
        ", ".join(args.get("target_ips")[:3]) if isinstance(args.get("target_ips"), list) else None
    )


async def send_decision_request(rec: AgentDecision) -> int | None:
    """Post an approval prompt with inline buttons. Returns the message id."""
    if not _enabled():
        return None
    ip = _decision_ip(rec)
    result = await _call("sendMessage", {
        "chat_id": settings.telegram_chat_id,
        "text": _decision_caption(rec, ip),
        "parse_mode": "HTML",
        "reply_markup": {
            "inline_keyboard": [[
                {"text": "✅ Approve", "callback_data": f"approve:{rec.id}"},
                {"text": "❌ Reject", "callback_data": f"reject:{rec.id}"},
            ]],
        },
    })
    return result.get("message_id") if result else None


async def send_notification(text: str) -> None:
    """Fire-and-forget plain notification (no buttons)."""
    if not _enabled():
        return
    await _call("sendMessage", {
        "chat_id": settings.telegram_chat_id,
        "text": text,
        "parse_mode": "HTML",
    })


async def telegram_push_pending() -> None:
    """Send approval prompts for pending, not-yet-notified decisions."""
    if not _enabled():
        return
    async with async_session() as db:
        rows = (await db.execute(
            select(AgentDecision)
            .where(
                AgentDecision.status == "pending",
                AgentDecision.telegram_message_id.is_(None),
            )
            .order_by(AgentDecision.created_at.desc())
            .limit(10)
        )).scalars().all()

    for rec in rows:
        mid = await send_decision_request(rec)
        if mid is None:
            continue
        async with async_session() as db:
            fresh = await db.get(AgentDecision, rec.id)
            if fresh:
                fresh.telegram_message_id = mid
                await db.commit()


async def _answer_callback(callback_id: str, text: str) -> None:
    await _call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text})


async def _edit_caption(message_id: int, text: str) -> None:
    await _call("editMessageText", {
        "chat_id": settings.telegram_chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": "HTML",
    })


def _actor_name(frm: dict | None) -> str:
    """First name of the Telegram user for the approver record, falling back to
    the @username and then a generic label."""
    frm = frm or {}
    return (frm.get("first_name") or "").strip() or frm.get("username") or "telegram"


async def _handle_callback(cb: dict) -> None:
    data = cb.get("data") or ""
    cb_id = cb.get("id")
    from_chat = str(((cb.get("message") or {}).get("chat") or {}).get("id"))
    message_id = (cb.get("message") or {}).get("message_id")

    # Only the configured chat may act on approvals.
    if from_chat != str(settings.telegram_chat_id):
        await _answer_callback(cb_id, _tg("not_authorized"))
        return
    if ":" not in data:
        await _answer_callback(cb_id, _tg("unknown_action"))
        return

    action, _, sid = data.partition(":")
    try:
        decision_id = int(sid)
    except ValueError:
        await _answer_callback(cb_id, _tg("invalid_id"))
        return

    actor = _actor_name(cb.get("from"))

    async with async_session() as db:
        rec = await db.get(AgentDecision, decision_id)
        if rec is None:
            await _answer_callback(cb_id, _tg("not_found"))
            return
        if rec.status not in ("pending", "approved"):
            await _answer_callback(cb_id, _tg("already", s=rec.status))
            if message_id:
                await _edit_caption(message_id, _decision_caption(rec, _decision_ip(rec)) + "\n\n" + _tg("already_tag", s=rec.status))
            return

    if action == "approve":
        from app.agent import execute_decision
        try:
            await execute_decision(decision_id)
            verdict = _tg("approved_executed")
            await _answer_callback(cb_id, _tg("approved"))
        except Exception as e:
            verdict = _tg("approve_failed", e=e)
            await _answer_callback(cb_id, _tg("exec_error"))
        async with async_session() as db:
            rec = await db.get(AgentDecision, decision_id)
            if rec and rec.human_comment is None:
                rec.human_comment = f"approved via Telegram by {actor}"
                await db.commit()
    elif action == "reject":
        async with async_session() as db:
            rec = await db.get(AgentDecision, decision_id)
            if rec:
                rec.status = "rejected"
                rec.decided_at = datetime.now(timezone.utc)
                rec.human_comment = f"rejected via Telegram by {actor}"
                await db.commit()
        verdict = _tg("rejected_tag")
        await _answer_callback(cb_id, _tg("rejected"))
    else:
        await _answer_callback(cb_id, _tg("unknown_action"))
        return

    if message_id:
        async with async_session() as db:
            rec = await db.get(AgentDecision, decision_id)
        await _edit_caption(message_id, _decision_caption(rec, _decision_ip(rec)) + f"\n\n{verdict} — {_tg('by')} @{actor}")


async def _handle_message(msg: dict) -> None:
    """Free-text message in the configured chat → run it through the command /
    analyst pipeline and reply. Commands (block/isolate/…) execute; everything
    else is a conversation with the analyst-persona LLM."""
    chat_id = str(((msg.get("chat") or {}).get("id")))
    if chat_id != str(settings.telegram_chat_id):
        return  # ignore other chats
    text = (msg.get("text") or "").strip()
    if not text or text.startswith("/"):  # ignore slash-commands / empty
        return
    actor = _actor_name(msg.get("from"))
    try:
        from app.command_service import run_command
        result = await run_command(text, actor=actor)
        await _call("sendMessage", {
            "chat_id": settings.telegram_chat_id,
            "text": result.get("reply") or "(keine Antwort)",
            "reply_to_message_id": msg.get("message_id"),
        })
    except Exception as e:
        logger.warning(f"telegram message handling failed: {e}")


async def telegram_poll_updates() -> None:
    """Pull queued updates and dispatch button callbacks and free-text messages."""
    global _update_offset
    if not _enabled():
        return
    payload = {"timeout": 0, "allowed_updates": ["callback_query", "message"]}
    if _update_offset is not None:
        payload["offset"] = _update_offset
    updates = await _call("getUpdates", payload, timeout=20.0)
    if not updates:
        return
    for upd in updates:
        _update_offset = upd["update_id"] + 1
        cb = upd.get("callback_query")
        if cb:
            try:
                await _handle_callback(cb)
            except Exception as e:
                logger.warning(f"telegram callback handling failed: {e}")
            continue
        msg = upd.get("message")
        if msg:
            await _handle_message(msg)


async def test_telegram() -> dict:
    """Admin 'test connection': verify token + send a probe message."""
    if not (settings.telegram_bot_token and settings.telegram_chat_id):
        return {"ok": False, "error": "bot_token/chat_id not set"}
    me = await _call("getMe", {})
    if not me:
        return {"ok": False, "error": "getMe failed — invalid bot token?"}
    sent = await _call("sendMessage", {
        "chat_id": settings.telegram_chat_id,
        "text": "✅ Warroom Telegram-Verbindung OK.",
    })
    if not sent:
        return {"ok": False, "error": "sendMessage failed — wrong chat_id or bot not started?"}
    return {"ok": True, "bot": me.get("username")}
