"""Runs every registered analyzer over a normalized request (or a response) and aggregates a risk score."""
from __future__ import annotations

import asyncio
import inspect
import time
from typing import Any

from ..logging import get_logger
from .base import AnalysisResult, Finding, Severity, level_for_score, score_findings

log = get_logger("airt.analysis")
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
            out.append({"name": name, "kind": kind, "description": (getattr(a, "description", "") or (a.__doc__ or "")).strip()[:200]})
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
        from .. import guardrails  # noqa: F401  optional defense integrations (LLM Guard, NeMo, Lakera, Rebuff)
    except Exception as exc:  # pragma: no cover
        log.warning("guardrails.load_failed", error=str(exc))


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
            try:
                f.severity = Severity(str(ov).upper())
            except ValueError:
                pass
        out.append(f)
    return out


async def _run(analyzer: Any, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
    try:
        result = analyzer.analyze(normalized, context)
        if inspect.isawaitable(result):
            result = await result
        return list(result or [])
    except Exception as exc:  # one broken analyzer must never block the gateway
        log.warning("analyzer.failed", analyzer=getattr(analyzer, "name", "?"), error=str(exc))
        return []


async def analyze_request(normalized: dict[str, Any], context: dict[str, Any] | None = None) -> AnalysisResult:
    _load_builtin()
    context = context or {}
    start = time.perf_counter()
    results = await asyncio.gather(*(_run(a, normalized, context) for a in _active(_REGISTRY)))
    findings = _apply_overrides([f for group in results for f in group])
    findings.sort(key=lambda f: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[f.severity.value], -f.confidence))
    score = score_findings(findings)
    return AnalysisResult(score=score, level=level_for_score(score), findings=findings, duration_ms=round((time.perf_counter() - start) * 1000, 2), analyzers_run=list(_REGISTRY))


async def analyze_response(normalized: dict[str, Any], response_text: str, context: dict[str, Any] | None = None) -> AnalysisResult:
    _load_builtin()
    context = {**(context or {}), "response_text": response_text}
    start = time.perf_counter()
    results = await asyncio.gather(*(_run(a, normalized, context) for a in _active(_RESPONSE_REGISTRY)))
    findings = _apply_overrides([f for group in results for f in group])
    score = score_findings(findings)
    return AnalysisResult(score=score, level=level_for_score(score), findings=findings, duration_ms=round((time.perf_counter() - start) * 1000, 2), analyzers_run=list(_RESPONSE_REGISTRY))
