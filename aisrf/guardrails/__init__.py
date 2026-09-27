"""Defense framework integrations: LLM Guard, NeMo Guardrails, Lakera Guard and Rebuff.

Importing this package registers the analyzers with the analysis runner (the runner imports it from
`_load_builtin`). Every analyzer reads its integration config from settings at analyze time and is a
no-op while the integration is disabled or its library is missing, so importing here is cheap: the
heavy third-party imports (torch, transformers, nemoguardrails) happen lazily on first use.

    status()        -> per-integration installed / enabled / configured / last_error
    health_check()  -> runs a tiny scan through every enabled integration
"""

from __future__ import annotations

import asyncio
from typing import Any

from ..analysis.runner import register
from . import lakera, llm_guard, nemo, rebuff

REQUEST_ANALYZERS = [rebuff.analyzer, llm_guard.input_analyzer, nemo.input_analyzer, lakera.request_analyzer]
RESPONSE_ANALYZERS = [llm_guard.output_analyzer, nemo.output_analyzer, lakera.response_analyzer]
for _a in REQUEST_ANALYZERS:
    register(_a)
for _a in RESPONSE_ANALYZERS:
    register(_a, response=True)

INTEGRATIONS: dict[str, Any] = {
    "rebuff": rebuff,
    "llm_guard": llm_guard,
    "nemo_guardrails": nemo,
    "lakera": lakera,
}
GUARDRAIL_NAMES: list[str] = [a.name for a in REQUEST_ANALYZERS] + [a.name for a in RESPONSE_ANALYZERS]


def status() -> list[dict[str, Any]]:
    """Installed / enabled / configured / last_error for each integration (safe to call from the settings UI)."""
    out: list[dict[str, Any]] = []
    for name, module in INTEGRATIONS.items():
        try:
            out.append(module.status())
        except Exception as exc:  # status must never fail the settings page
            out.append(
                {
                    "name": name,
                    "installed": False,
                    "enabled": False,
                    "configured": False,
                    "last_error": str(exc)[:300],
                }
            )
    return out


async def health_check(names: list[str] | None = None, timeout: float = 120.0) -> list[dict[str, Any]]:
    """Run a tiny scan through every enabled integration (or the given names) and report ok / detail per integration."""
    selected = [n for n in INTEGRATIONS if (names is None or n in names)]
    results: list[dict[str, Any]] = []
    for name in selected:
        module = INTEGRATIONS[name]
        try:
            enabled = bool(module.status().get("enabled"))
        except Exception:
            enabled = False
        if names is None and not enabled:
            results.append({"name": name, "ok": None, "detail": "disabled", "skipped": True})
            continue
        try:
            results.append(await asyncio.wait_for(module.health_check(), timeout=timeout))
        except Exception as exc:
            results.append({"name": name, "ok": False, "detail": f"{type(exc).__name__}: {str(exc)[:300]}"})
    return results


__all__ = [
    "GUARDRAIL_NAMES",
    "INTEGRATIONS",
    "REQUEST_ANALYZERS",
    "RESPONSE_ANALYZERS",
    "health_check",
    "lakera",
    "llm_guard",
    "nemo",
    "rebuff",
    "status",
]
