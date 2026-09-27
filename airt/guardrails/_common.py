"""Helpers shared by the defense framework integrations: live settings access, rate-limited logging and text extraction.

Everything here is deliberately light so that importing the guardrails package never pulls in torch,
transformers or NeMo. Heavy third-party imports live inside functions in the individual modules.
"""
from __future__ import annotations

import importlib.util
import time
from typing import Any

from ..analysis.base import Severity
from ..logging import get_logger

log = get_logger("airt.guardrails")

# Highest-scoring layers use these breakpoints to turn a 0..1 score into a severity.
_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_last_errors: dict[str, str] = {}
_last_logged: dict[str, float] = {}


def integration_config(name: str) -> dict[str, Any]:
    """Return the live (UI editable) config dict for one integration. Never cached: admins change it at runtime."""
    from .. import settings_store

    try:
        cfg = settings_store.get_namespace("integrations").get(name)
    except Exception:  # settings store unavailable during very early startup
        return {}
    return cfg if isinstance(cfg, dict) else {}


def is_enabled(name: str) -> bool:
    return bool(integration_config(name).get("enabled"))


def library_installed(module: str) -> bool:
    """True when the module can be imported. Uses find_spec so the (possibly heavy) import is not triggered."""
    try:
        return importlib.util.find_spec(module) is not None
    except Exception:
        return False


def set_error(name: str, error: str | None) -> None:
    if error:
        _last_errors[name] = error[:500]
    else:
        _last_errors.pop(name, None)


def last_error(name: str) -> str | None:
    return _last_errors.get(name)


def log_throttled(key: str, event: str, interval: float = 60.0, **fields: Any) -> None:
    """Log a warning at most once per `interval` seconds for a given key (used for repeated integration failures)."""
    now = time.monotonic()
    if now - _last_logged.get(key, 0.0) < interval:
        return
    _last_logged[key] = now
    log.warning(event, **fields)


def severity_for_score(score: float, floor: Severity = Severity.INFO, cap: Severity = Severity.CRITICAL) -> Severity:
    """Map a 0..1 risk score onto a severity, bounded by floor and cap."""
    if score >= 0.95:
        sev = Severity.CRITICAL
    elif score >= 0.8:
        sev = Severity.HIGH
    elif score >= 0.5:
        sev = Severity.MEDIUM
    elif score >= 0.2:
        sev = Severity.LOW
    else:
        sev = Severity.INFO
    idx = max(_SEVERITY_ORDER.index(floor), min(_SEVERITY_ORDER.index(cap), _SEVERITY_ORDER.index(sev)))
    return _SEVERITY_ORDER[idx]


def at_least(sev: Severity, floor: Severity) -> Severity:
    return _SEVERITY_ORDER[max(_SEVERITY_ORDER.index(sev), _SEVERITY_ORDER.index(floor))]


def conversation_messages(normalized: dict[str, Any] | None, include_system: bool = True, limit: int = 40) -> list[dict[str, str]]:
    """Flatten the normalized request into simple {role, content} chat messages (system, user, assistant, tool)."""
    from ..analysis.analyzers.common import safe_text

    out: list[dict[str, str]] = []
    if not isinstance(normalized, dict):
        return out
    system = safe_text(normalized.get("system"), 20000)
    if include_system and system.strip():
        out.append({"role": "system", "content": system})
    messages = normalized.get("messages")
    if isinstance(messages, list):
        for m in messages:
            if not isinstance(m, dict):
                continue
            role = str(m.get("role") or "user").lower()
            if role in ("system", "developer"):
                continue
            text = safe_text(m.get("content"), 20000)
            if not text.strip():
                continue
            out.append({"role": "assistant" if role == "assistant" else "user", "content": text})
    if not any(m["role"] == "user" for m in out):
        last = safe_text(normalized.get("last_user_message") or normalized.get("prompt_text"), 20000)
        if last.strip():
            out.append({"role": "user", "content": last})
    return out[-limit:]


def primary_text(normalized: dict[str, Any] | None, limit: int = 20000) -> str:
    """The text a single-input scanner should look at: the last user message, falling back to the whole prompt."""
    from ..analysis.analyzers.common import safe_text

    if not isinstance(normalized, dict):
        return ""
    text = safe_text(normalized.get("last_user_message"), limit)
    if not text.strip():
        text = safe_text(normalized.get("prompt_text"), limit)
    return text


def response_text(context: dict[str, Any] | None, limit: int = 40000) -> str:
    from ..analysis.analyzers.common import safe_text

    return safe_text((context or {}).get("response_text"), limit)
