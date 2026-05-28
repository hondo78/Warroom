"""DB-backed override layer for the pydantic Settings singleton.

`config.settings` provides defaults (from `.env`); rows in `app_settings`
override those at boot via `apply_overrides_to_settings()`. Admin-API writes
go through `save_settings()`, which updates both the DB and the live
singleton, then reloads the Sophos client and reschedules the collector job
if the interval changed.
"""

import logging
import re
from typing import Any

from sqlalchemy import select

from app.config import settings
from app.database import async_session
from app.models import AppSetting

logger = logging.getLogger(__name__)


# key -> python type. Only these keys are exposed via the admin API.
MANAGED_KEYS: dict[str, type] = {
    "sophos_client_id": str,
    "sophos_client_secret": str,
    "sophos_tenant_id": str,
    "maxmind_license_key": str,
    "abuseipdb_api_key": str,
    "virustotal_api_key": str,
    "shodan_api_key": str,
    "sophos_intelix_client_id": str,
    "sophos_intelix_client_secret": str,
    "collector_interval": int,
    "log_level": str,
    "dashboard_title": str,
    # Agent
    "agent_enabled": bool,
    "agent_provider": str,
    "agent_base_url": str,
    "agent_api_key": str,
    "agent_model": str,
    "agent_interval_seconds": int,
    "agent_auto_execute": bool,
    "agent_auto_execute_threshold": int,
    "agent_system_prompt": str,
    "agent_waf_enabled": bool,
    "agent_waf_threshold": int,
    "agent_waf_interval_seconds": int,
    "agent_ips_enabled": bool,
    "agent_ips_threshold": int,
    "agent_ips_interval_seconds": int,
    "agent_failed_login_enabled": bool,
    "agent_failed_login_threshold": int,
    "agent_failed_login_interval_seconds": int,
    "agent_failed_login_subnet_attempts": int,
    "agent_failed_login_subnet_min_ips": int,
}

SECRET_KEYS: set[str] = {
    "sophos_client_secret",
    "maxmind_license_key",
    "abuseipdb_api_key",
    "virustotal_api_key",
    "shodan_api_key",
    "sophos_intelix_client_secret",
    "agent_api_key",
}


def _coerce(key: str, raw: str | None) -> Any:
    if raw is None:
        return None
    t = MANAGED_KEYS.get(key, str)
    if t is bool:
        return raw.strip().lower() in ("true", "1", "yes", "on")
    if t is int:
        try:
            return int(raw)
        except (ValueError, TypeError):
            return None
    return raw


def _to_str(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return ""
    return str(value)


async def load_overrides() -> dict[str, str]:
    async with async_session() as s:
        rows = (await s.execute(select(AppSetting))).scalars().all()
    return {r.key: r.value for r in rows if r.key in MANAGED_KEYS}


async def apply_overrides_to_settings() -> None:
    overrides = await load_overrides()
    for k, raw in overrides.items():
        coerced = _coerce(k, raw)
        if coerced is not None:
            setattr(settings, k, coerced)
    if overrides:
        logger.info(f"Applied {len(overrides)} setting override(s) from DB")


async def save_settings(updates: dict[str, Any]) -> dict[str, Any]:
    """Persist updates and apply them to the live singleton.

    Returns the sanitized payload that was actually stored.
    """
    sane: dict[str, str] = {}
    for k, v in updates.items():
        if k not in MANAGED_KEYS:
            continue
        sane[k] = _to_str(v)

    if not sane:
        return {}

    async with async_session() as s:
        for k, v in sane.items():
            existing = await s.get(AppSetting, k)
            if existing is None:
                s.add(AppSetting(key=k, value=v))
            else:
                existing.value = v
        await s.commit()

    interval_changed = "collector_interval" in sane
    log_level_changed = "log_level" in sane
    agent_interval_changed = "agent_interval_seconds" in sane

    for k, v in sane.items():
        coerced = _coerce(k, v)
        if coerced is None and MANAGED_KEYS[k] is not str:
            continue
        setattr(settings, k, coerced if coerced is not None else v)

    if log_level_changed:
        try:
            logging.getLogger().setLevel(settings.log_level.upper())
        except (ValueError, AttributeError):
            pass

    # Reload clients & reschedule. Imports are local to avoid cycles.
    try:
        from app.sophos_client import sophos_client
        sophos_client.reload()
    except Exception as e:
        logger.warning(f"sophos_client reload failed: {e}")

    if interval_changed:
        try:
            from app.main import scheduler
            from app.collector import collect_all
            scheduler.reschedule_job(
                "collector", trigger="interval", seconds=settings.collector_interval
            )
            logger.info(f"Rescheduled collector to {settings.collector_interval}s")
        except Exception as e:
            logger.warning(f"reschedule failed: {e}")

    if agent_interval_changed:
        try:
            from app.main import scheduler
            scheduler.reschedule_job(
                "agent_loop", trigger="interval",
                seconds=max(30, settings.agent_interval_seconds),
            )
            logger.info(f"Rescheduled agent_loop to {settings.agent_interval_seconds}s")
        except Exception as e:
            logger.warning(f"agent reschedule failed: {e}")

    for key, job_id, val_attr in (
        ("agent_waf_interval_seconds", "agent_waf_loop", "agent_waf_interval_seconds"),
        ("agent_ips_interval_seconds", "agent_ips_loop", "agent_ips_interval_seconds"),
        ("agent_failed_login_interval_seconds", "agent_failed_login_loop", "agent_failed_login_interval_seconds"),
    ):
        if key in sane:
            try:
                from app.main import scheduler
                scheduler.reschedule_job(
                    job_id, trigger="interval",
                    seconds=max(30, getattr(settings, val_attr)),
                )
                logger.info(f"Rescheduled {job_id} to {getattr(settings, val_attr)}s")
            except Exception as e:
                logger.warning(f"{job_id} reschedule failed: {e}")

    return sane


def _mask_db_url(url: str) -> str:
    return re.sub(r"(://[^:]+:)[^@]+(@)", r"\1***\2", url or "")


def serialize_settings(reveal_secrets: bool = False) -> dict[str, Any]:
    """Snapshot of the current effective settings, suitable for the admin UI."""
    out: dict[str, Any] = {}
    for k in MANAGED_KEYS:
        v = getattr(settings, k, None)
        if k in SECRET_KEYS and not reveal_secrets:
            out[k] = {"is_set": bool(v), "value": ""}
        else:
            out[k] = v
    out["_readonly"] = {
        "database_url": _mask_db_url(settings.database_url),
        "redis_url": settings.redis_url,
        "warroom_api_key_is_set": bool(settings.warroom_api_key),
    }
    return out
