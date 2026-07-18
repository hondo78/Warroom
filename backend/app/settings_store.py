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
    "firewall_threat_feed_enabled": bool,
    "firewall_mdr_feed_enabled": bool,
    "firewall_mdr_feed_firewall_ids": str,
    "firewall_mdr_feed_sync_interval_seconds": int,
    "o365_tenant_id": str,
    "o365_client_id": str,
    "o365_client_secret": str,
    "m365_login_watch_enabled": bool,
    "m365_login_watch_interval_seconds": int,
    "m365_login_watch_lookback_minutes": int,
    "hostname_resolve_enabled": bool,
    "internal_dns_servers": str,
    "hostname_netbios_enabled": bool,
    "hostname_cache_ttl_hours": int,
    "hostname_negative_ttl_hours": int,
    "firewall_api_enabled": bool,
    "firewall_api_host": str,
    "firewall_api_port": int,
    "firewall_api_user": str,
    "firewall_api_password": str,
    "firewall_api_verify_tls": bool,
    "firewall_dhcp_entity": str,
    "firewall_dhcp_refresh_seconds": int,
    "host_identity_monitor_enabled": bool,
    "host_identity_alarm": bool,
    "host_identity_scan_interval_seconds": int,
    "entra_block_enabled": bool,
    "entra_named_location_id": str,
    "entra_ca_policy_id": str,
    "entra_block_sync_interval_minutes": int,
    "entra_ca_exclude_users": str,
    "telegram_enabled": bool,
    "telegram_bot_token": str,
    "telegram_chat_id": str,
    "telegram_poll_interval_seconds": int,
    "teams_outgoing_secret": str,
    "teams_incoming_webhook": str,
    "maxmind_license_key": str,
    "abuseipdb_api_key": str,
    "virustotal_api_key": str,
    "shodan_api_key": str,
    "shodan_auto_every_lookup": bool,
    "shodan_auto_on_malicious": bool,
    "shodan_auto_abuse_threshold": int,
    "sophos_intelix_client_id": str,
    "sophos_intelix_client_secret": str,
    "collector_interval": int,
    "log_level": str,
    "dashboard_title": str,
    "firewall_log_retention_enabled": bool,
    "firewall_log_connection_retention_days": int,
    "firewall_log_retention_days": int,
    # Agent
    "agent_enabled": bool,
    "agent_provider": str,
    "agent_base_url": str,
    "agent_api_key": str,
    "agent_model": str,
    "agent_interval_seconds": int,
    "agent_temperature": float,
    "agent_max_tokens": int,
    "agent_structured_output": bool,
    "agent_language": str,
    "agent_auto_execute": bool,
    "agent_learning_enabled": bool,
    "agent_learning_threshold": int,
    "agent_system_prompt": str,
    "agent_waf_system_prompt": str,
    "agent_ips_system_prompt": str,
    "agent_failed_login_system_prompt": str,
    "agent_event_enabled": bool,
    "agent_event_interval_seconds": int,
    "agent_event_types": str,
    "agent_event_system_prompt": str,
    "agent_waf_enabled": bool,
    "agent_waf_threshold": int,
    "agent_waf_interval_seconds": int,
    "agent_ips_enabled": bool,
    "agent_ips_threshold": int,
    "agent_ips_interval_seconds": int,
    "agent_anomaly_enabled": bool,
    "agent_anomaly_interval_seconds": int,
    "agent_anomaly_hours": int,
    "agent_anomaly_min_flows": int,
    "agent_anomaly_max_ips": int,
    "agent_anomaly_system_prompt": str,
    "agent_connanom_enabled": bool,
    "agent_connanom_interval_seconds": int,
    "agent_connanom_hours": int,
    "agent_connanom_min_score": float,
    "agent_connanom_max_alerts": int,
    "agent_conntriage_enabled": bool,
    "agent_conntriage_interval_seconds": int,
    "agent_conntriage_min_score": float,
    "agent_conntriage_max": int,
    "agent_conntriage_alarm": bool,
    "agent_conntriage_system_prompt": str,
    "agent_failed_login_enabled": bool,
    "agent_failed_login_threshold": int,
    "agent_failed_login_interval_seconds": int,
    "agent_failed_login_subnet_attempts": int,
    "agent_failed_login_subnet_min_ips": int,
    "agent_failed_login_distributed_enabled": bool,
    "agent_failed_login_distributed_window_minutes": int,
    "agent_failed_login_distributed_attempts": int,
    "agent_failed_login_distributed_min_ips": int,
    "agent_failed_login_network_block_enabled": bool,
    "agent_failed_login_distributed_system_prompt": str,
    "agent_failed_login_user_alert_enabled": bool,
    "agent_failed_login_user_window_minutes": int,
    "agent_failed_login_user_min_attempts": int,
    "agent_failed_login_user_distributed_min_ips": int,
    "agent_failed_login_user_alert_cooldown_minutes": int,
    "agent_failed_login_user_system_prompt": str,
    "agent_triage_system_prompt": str,
    "analyst_system_prompt": str,
    "chat_sql_enabled": bool,
    # OSINT-Provider Quotas
    "osint_abuseipdb_daily_limit": int,
    "osint_abuseipdb_monthly_limit": int,
    "osint_virustotal_daily_limit": int,
    "osint_virustotal_monthly_limit": int,
    "osint_shodan_daily_limit": int,
    "osint_shodan_monthly_limit": int,
    "osint_greynoise_daily_limit": int,
    "osint_greynoise_monthly_limit": int,
    "osint_intelix_daily_limit": int,
    "osint_intelix_monthly_limit": int,
    "osint_ipinfo_daily_limit": int,
    "osint_ipinfo_monthly_limit": int,
}

SECRET_KEYS: set[str] = {
    "sophos_client_secret",
    "o365_client_secret",
    "telegram_bot_token",
    "teams_outgoing_secret",
    "maxmind_license_key",
    "abuseipdb_api_key",
    "virustotal_api_key",
    "shodan_api_key",
    "sophos_intelix_client_secret",
    "agent_api_key",
    "firewall_api_password",
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
    if t is float:
        try:
            return float(raw)
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

    try:
        from app.o365_client import o365_client
        o365_client.reload()
    except Exception as e:
        logger.warning(f"o365_client reload failed: {e}")

    try:
        from app.entra_client import entra_client
        entra_client.reload()
    except Exception as e:
        logger.warning(f"entra_client reload failed: {e}")

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
        ("agent_anomaly_interval_seconds", "agent_anomaly_loop", "agent_anomaly_interval_seconds"),
        ("m365_login_watch_interval_seconds", "m365_login_watch", "m365_login_watch_interval_seconds"),
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

    if "telegram_poll_interval_seconds" in sane:
        try:
            from app.main import scheduler
            scheduler.reschedule_job(
                "telegram_poll", trigger="interval",
                seconds=max(2, settings.telegram_poll_interval_seconds),
            )
        except Exception as e:
            logger.warning(f"telegram_poll reschedule failed: {e}")

    if "entra_block_sync_interval_minutes" in sane:
        try:
            from app.main import scheduler
            scheduler.reschedule_job(
                "entra_sync", trigger="interval",
                minutes=max(1, settings.entra_block_sync_interval_minutes),
            )
        except Exception as e:
            logger.warning(f"entra_sync reschedule failed: {e}")

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
