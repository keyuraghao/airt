"""Runs every registered analyzer over a normalized request (or a response) and aggregates a risk score.

Execution is phased so the expensive LLM judge only runs when it is needed:

    phase 1  every analyzer except the LLM judge, concurrently in one ``asyncio.gather``; this includes
             the deterministic analyzers, the guardrail integrations and, when ``integrations.typesafe``
             is enabled and a key exists, ``typesafe_guard`` (or ``typesafe_response_guard``), which
             writes its verdict (``malicious`` | ``benign`` | ``uncertain`` plus a confidence) to
             ``context["typesafe"]`` (``context["typesafe_response"]`` for responses);
    phase 2  ``llm_judge`` / ``llm_judge_response``, gated by ``llm_judge_gate``: with TypeSafe disabled
             the judge runs as it always did; with TypeSafe enabled it runs only when
             ``escalate_to_llm_judge`` is true and the verdict is uncertain or missing (call failed).

The reason for a skipped judge is stored in ``context["llm_judge_skipped"]``. See docs/TYPESAFE.md.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import time
from typing import Any

from ..logging import get_logger
from .base import AnalysisResult, Finding, Severity, level_for_score, score_findings

log = get_logger("aisrf.analysis")
_REGISTRY: dict[str, Any] = {}
_RESPONSE_REGISTRY: dict[str, Any] = {}
_loaded = False


def register(analyzer: Any, *, response: bool = False) -> Any:
    (_RESPONSE_REGISTRY if response else _REGISTRY)[analyzer.name] = analyzer
    return analyzer


def list_analyzers() -> list[dict[str, Any]]:
    _load_builtin()
    out = []
    for kind, reg in (("request", _REGISTRY), ("response", _RESPONSE_REGISTRY)):
        for name, a in reg.items():
            out.append(
                {
                    "name": name,
                    "kind": kind,
                    "description": (getattr(a, "description", "") or (a.__doc__ or "")).strip()[:200],
                }
            )
    return out


def _load_builtin() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    from . import analyzers  # noqa: F401  registers everything on import
    from .custom_rules import CustomRulesRequest, CustomRulesResponse

    register(CustomRulesRequest())
    register(CustomRulesResponse(), response=True)
    try:
        from .. import (
            guardrails,  # noqa: F401  optional defense integrations (LLM Guard, NeMo, Lakera, Rebuff)
        )
    except Exception as exc:  # pragma: no cover
        log.warning("guardrails.load_failed", error=str(exc))
    try:
        from .. import (
            typesafe,  # noqa: F401  TypeSafe decision layer (typesafe_guard, typesafe_response_guard)
        )
    except Exception as exc:  # pragma: no cover
        log.warning("typesafe.load_failed", error=str(exc))


def _active(registry: dict[str, Any]) -> list[Any]:
    from .. import settings_store

    disabled = set(settings_store.get_value("analyzers", "disabled", []) or [])
    return [a for name, a in registry.items() if name not in disabled]


def _apply_overrides(findings: list[Finding]) -> list[Finding]:
    from .. import settings_store

    cfg = settings_store.get_namespace("analyzers")
    overrides = cfg.get("severity_overrides") or {}
    floor = float(cfg.get("confidence_floor") or 0.0)
    out = []
    for f in findings:
        if f.confidence < floor:
            continue
        ov = overrides.get(f.category) or overrides.get(f.analyzer)
        if ov:
            with contextlib.suppress(ValueError):
                f.severity = Severity(str(ov).upper())
        out.append(f)
    return out


# The LLM judge is the expensive path. When the TypeSafe decision layer is enabled it runs first (with
# every other analyzer, in the same gather) and the judge only runs afterwards if TypeSafe was uncertain
# and integrations.typesafe.escalate_to_llm_judge is true. A missing verdict (call failed, no key) counts
# as uncertain so the judge remains the fallback. With TypeSafe disabled the judge behaves as before.
LLM_JUDGE_ANALYZERS = frozenset({"llm_judge", "llm_judge_response"})


def llm_judge_gate(context: dict[str, Any], kind: str) -> tuple[bool, str]:
    """(run the judge?, reason). ``kind`` is "request" or "response"."""
    from .. import settings_store

    cfg = settings_store.get_value("integrations", "typesafe", {}) or {}
    if not cfg.get("enabled"):
        return True, "typesafe disabled"
    if not cfg.get("escalate_to_llm_judge"):
        return False, "typesafe enabled and escalate_to_llm_judge is false"
    verdict = (context.get("typesafe" if kind == "request" else "typesafe_response") or {}).get("verdict")
    if verdict in (None, "uncertain"):
        return True, "typesafe uncertain" if verdict else "typesafe gave no verdict"
    return False, f"typesafe verdict {verdict}"


async def _run_phased(
    registry: dict[str, Any], normalized: dict[str, Any], context: dict[str, Any], kind: str
) -> list[Finding]:
    """Phase 1: every analyzer except the LLM judge, concurrently. Phase 2: the judge, if the gate allows."""
    active = _active(registry)
    first = [a for a in active if a.name not in LLM_JUDGE_ANALYZERS]
    judges = [a for a in active if a.name in LLM_JUDGE_ANALYZERS]
    results = await asyncio.gather(*(_run(a, normalized, context) for a in first))
    findings = [f for group in results for f in group]
    if judges:
        allowed, reason = llm_judge_gate(context, kind)
        if allowed:
            results = await asyncio.gather(*(_run(a, normalized, context) for a in judges))
            findings.extend(f for group in results for f in group)
        else:
            context["llm_judge_skipped"] = reason
            log.debug("llm_judge.skipped", kind=kind, reason=reason)
    return findings


async def _run(analyzer: Any, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
    try:
        result = analyzer.analyze(normalized, context)
        if inspect.isawaitable(result):
            result = await result
        return list(result or [])
    except Exception as exc:  # one broken analyzer must never block the gateway
        log.warning("analyzer.failed", analyzer=getattr(analyzer, "name", "?"), error=str(exc))
        return []


async def analyze_request(
    normalized: dict[str, Any], context: dict[str, Any] | None = None
) -> AnalysisResult:
    _load_builtin()
    context = context or {}
    start = time.perf_counter()
    findings = _apply_overrides(await _run_phased(_REGISTRY, normalized, context, "request"))
    findings.sort(
        key=lambda f: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[f.severity.value],
            -f.confidence,
        )
    )
    score = score_findings(findings)
    return AnalysisResult(
        score=score,
        level=level_for_score(score),
        findings=findings,
        duration_ms=round((time.perf_counter() - start) * 1000, 2),
        analyzers_run=list(_REGISTRY),
    )


async def analyze_response(
    normalized: dict[str, Any], response_text: str, context: dict[str, Any] | None = None
) -> AnalysisResult:
    _load_builtin()
    context = {**(context or {}), "response_text": response_text}
    start = time.perf_counter()
    findings = _apply_overrides(await _run_phased(_RESPONSE_REGISTRY, normalized, context, "response"))
    score = score_findings(findings)
    return AnalysisResult(
        score=score,
        level=level_for_score(score),
        findings=findings,
        duration_ms=round((time.perf_counter() - start) * 1000, 2),
        analyzers_run=list(_RESPONSE_REGISTRY),
    )
