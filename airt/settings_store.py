"""Runtime settings: every Settings field plus free-form namespaces (analyzers, rules, integrations, ui)
can be changed live from the dashboard or API. Overrides persist in the app_settings table and are
re-applied at startup, so the precedence is: UI override > environment / .env > code default.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any, get_args, get_origin

from pydantic.fields import FieldInfo
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .config import Settings, get_settings
from .logging import broadcaster, get_logger
from .models import AppSetting, utcnow

log = get_logger("airt.settings")

SENSITIVE = re.compile(r"(password|secret|token|api_key|_key$)", re.IGNORECASE)
LOCKED = {"database_url", "host", "port", "workers", "base_dir", "data_dir", "log_dir", "secret_key", "encryption_key"}
GROUPS: dict[str, list[str]] = {
    "Service": ["app_name", "environment", "log_level", "log_json_console", "public_url"],
    "Gateway": ["approval_timeout_seconds", "hold_poll_interval_seconds", "max_request_body_bytes", "max_stored_response_bytes", "upstream_timeout_seconds", "upstream_connect_timeout_seconds", "default_auto_deny_risk_threshold", "default_auto_approve_risk_threshold", "ticket_retention_days", "require_approval_for_redteam_probes"],
    "Security": ["admin_username", "admin_password", "admin_api_token", "session_max_age_seconds", "cookie_secure"],
    "Notifications": ["notify_webhook_urls", "notify_events", "notify_min_risk"],
    "Analysis": ["enable_llm_judge", "judge_provider", "judge_base_url", "judge_api_key", "judge_model"],
    "Red team": ["redteam_concurrency", "redteam_probe_timeout_seconds"],
}

# Namespaces other than "core" hold arbitrary JSON documents with these defaults.
NAMESPACE_DEFAULTS: dict[str, dict[str, Any]] = {
    "analyzers": {"disabled": [], "severity_overrides": {}, "confidence_floor": 0.0, "category_weights": {}},
    "rules": {"custom": []},  # [{id, name, pattern, category, severity, scope: request|response|both, action: flag|deny, enabled}]
    "integrations": {
        "llm_guard": {"enabled": False, "input_scanners": ["PromptInjection", "Secrets", "Toxicity"], "output_scanners": ["Sensitive", "MaliciousURLs"], "threshold": 0.5},
        "nemo_guardrails": {"enabled": False, "config_path": "", "run_output_rails": False},
        "lakera": {"enabled": False, "api_key": "", "endpoint": "https://api.lakera.ai/v2/guard", "project_id": ""},
        "rebuff": {"enabled": True, "heuristic_threshold": 0.75, "use_llm": False, "canary_default": False},
        "garak": {"enabled": True, "default_probes": ["promptinject", "dan", "encoding", "leakreplay"], "generations": 1},
        "promptfoo": {"enabled": True, "binary": ".venv/node_modules/.bin/promptfoo", "default_plugins": ["harmful", "pii", "prompt-extraction", "hijacking"], "strategies": ["jailbreak", "base64"]},
        "pyrit": {"enabled": True, "default_converters": ["Base64Converter", "ROT13Converter"], "scorer": "SelfAskRefusalScorer"},
    },
    "ui": {"theme": "auto", "refresh_seconds": 5, "sound_on_new_ticket": True, "queue_default_status": "PENDING", "ticket_columns": [], "date_format": "relative", "brand_name": "AIRT", "accent_color": ""},
    "policy": {"global_auto_deny_patterns": [], "global_allowed_paths": [], "block_on_canary_leak": True, "quarantine_on_critical_response_finding": False},
}
_namespace_cache: dict[str, dict[str, Any]] = {}


def _type_name(annotation: Any) -> str:
    origin = get_origin(annotation)
    if origin is list:
        return "list"
    if origin is not None and origin.__name__ == "UnionType" or str(origin) == "typing.Union":
        args = [a for a in get_args(annotation) if a is not type(None)]
        return _type_name(args[0]) if args else "str"
    if annotation in (int,):
        return "int"
    if annotation in (float,):
        return "float"
    if annotation in (bool,):
        return "bool"
    return "str"


def schema() -> list[dict[str, Any]]:
    """Self-describing list of every core setting for the dashboard form."""
    s = get_settings()
    fields: dict[str, FieldInfo] = Settings.model_fields
    grouped: dict[str, str] = {name: group for group, names in GROUPS.items() for name in names}
    out = []
    for name, info in fields.items():
        if name in ("base_dir", "data_dir", "log_dir"):
            continue
        value = getattr(s, name)
        secret = bool(SENSITIVE.search(name))
        out.append(
            {
                "key": name,
                "group": grouped.get(name, "Advanced"),
                "type": _type_name(info.annotation),
                "description": info.description or "",
                "default": info.default if info.default_factory is None else info.default_factory(),
                "value": ("********" if value else "") if secret else value,
                "secret": secret,
                "locked": name in LOCKED,
                "env": f"AIRT_{name.upper()}",
            }
        )
    return out


def coerce(name: str, value: Any) -> Any:
    info = Settings.model_fields[name]
    kind = _type_name(info.annotation)
    if value is None:
        return None
    if kind == "bool":
        return value if isinstance(value, bool) else str(value).lower() in ("1", "true", "yes", "on")
    if kind == "int":
        return int(value)
    if kind == "float":
        return float(value)
    if kind == "list":
        if isinstance(value, list):
            return value
        return [x.strip() for x in str(value).replace("\n", ",").split(",") if x.strip()]
    return str(value)


async def load_overrides(session: AsyncSession) -> int:
    """Apply persisted overrides to the live Settings instance and namespace cache (called at startup)."""
    s = get_settings()
    rows = list((await session.execute(select(AppSetting))).scalars())
    applied = 0
    for row in rows:
        if row.namespace == "core":
            if row.key in Settings.model_fields and row.key not in LOCKED:
                setattr(s, row.key, coerce(row.key, row.value.get("v")))
                applied += 1
        else:
            _namespace_cache.setdefault(row.namespace, copy.deepcopy(NAMESPACE_DEFAULTS.get(row.namespace, {})))
            _namespace_cache[row.namespace][row.key] = row.value.get("v")
            applied += 1
    for ns, defaults in NAMESPACE_DEFAULTS.items():
        _namespace_cache.setdefault(ns, copy.deepcopy(defaults))
    if applied:
        log.info("settings.overrides_applied", count=applied)
    return applied


async def update_core(session: AsyncSession, changes: dict[str, Any], actor: str) -> dict[str, Any]:
    s = get_settings()
    applied: dict[str, Any] = {}
    for key, value in changes.items():
        if key not in Settings.model_fields:
            raise KeyError(f"unknown setting '{key}'")
        if key in LOCKED:
            raise PermissionError(f"setting '{key}' can only be changed through the environment")
        if SENSITIVE.search(key) and value == "********":
            continue
        coerced = coerce(key, value)
        setattr(s, key, coerced)
        row = await session.get(AppSetting, ("core", key))
        if row is None:
            session.add(AppSetting(key=key, namespace="core", value={"v": coerced}, updated_by=actor))
        else:
            row.value = {"v": coerced}
            row.updated_by = actor
            row.updated_at = utcnow()
        applied[key] = "********" if SENSITIVE.search(key) else coerced
    await session.flush()
    broadcaster.publish("settings", {"event": "settings.updated", "keys": list(applied), "by": actor})
    log.info("settings.updated", keys=list(applied), by=actor)
    return applied


async def reset_core(session: AsyncSession, keys: list[str] | None, actor: str) -> list[str]:
    """Drop overrides so env/.env/default values apply again."""
    from .config import reset_settings_cache

    q = delete(AppSetting).where(AppSetting.namespace == "core")
    if keys:
        q = q.where(AppSetting.key.in_(keys))
    await session.execute(q)
    await session.flush()
    reset_settings_cache()
    await load_overrides(session)
    log.info("settings.reset", keys=keys or "all", by=actor)
    return keys or ["*"]


def get_namespace(namespace: str) -> dict[str, Any]:
    if namespace not in _namespace_cache:
        _namespace_cache[namespace] = copy.deepcopy(NAMESPACE_DEFAULTS.get(namespace, {}))
    return _namespace_cache[namespace]


def get_value(namespace: str, key: str, default: Any = None) -> Any:
    return get_namespace(namespace).get(key, default)


async def update_namespace(session: AsyncSession, namespace: str, changes: dict[str, Any], actor: str) -> dict[str, Any]:
    ns = get_namespace(namespace)
    for key, value in changes.items():
        json.dumps(value)  # must be JSON serialisable
        ns[key] = value
        row = await session.get(AppSetting, (namespace, key))
        if row is None:
            session.add(AppSetting(key=key, namespace=namespace, value={"v": value}, updated_by=actor))
        else:
            row.value = {"v": value}
            row.updated_by = actor
    await session.flush()
    broadcaster.publish("settings", {"event": "settings.updated", "namespace": namespace, "keys": list(changes), "by": actor})
    log.info("settings.namespace_updated", namespace=namespace, keys=list(changes), by=actor)
    return ns


async def reset_namespace(session: AsyncSession, namespace: str, actor: str) -> dict[str, Any]:
    await session.execute(delete(AppSetting).where(AppSetting.namespace == namespace))
    await session.flush()
    _namespace_cache[namespace] = copy.deepcopy(NAMESPACE_DEFAULTS.get(namespace, {}))
    log.info("settings.namespace_reset", namespace=namespace, by=actor)
    return _namespace_cache[namespace]


def export_all(include_secrets: bool = False) -> dict[str, Any]:
    s = get_settings()
    core = {}
    for name in Settings.model_fields:
        if name in ("base_dir", "data_dir", "log_dir"):
            continue
        v = getattr(s, name)
        if SENSITIVE.search(name) and not include_secrets:
            continue
        core[name] = v
    return {"core": core, "namespaces": {k: copy.deepcopy(v) for k, v in _namespace_cache.items()}}


async def import_all(session: AsyncSession, payload: dict[str, Any], actor: str) -> dict[str, Any]:
    applied: dict[str, Any] = {"core": {}, "namespaces": {}}
    core = {k: v for k, v in (payload.get("core") or {}).items() if k in Settings.model_fields and k not in LOCKED}
    if core:
        applied["core"] = await update_core(session, core, actor)
    for ns, doc in (payload.get("namespaces") or {}).items():
        if isinstance(doc, dict):
            applied["namespaces"][ns] = list((await update_namespace(session, ns, doc, actor)).keys())
    return applied
