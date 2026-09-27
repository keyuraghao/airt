"""LLM Guard (Protect AI) input and output scanners as gateway analyzers.

Scanners are constructed lazily on first use from the live settings (integrations.llm_guard) and cached
per config, so changing the scanner list or threshold from the Settings page rebuilds them. Model backed
scanners (PromptInjection, Toxicity, BanTopics, Jailbreak, Code, NoRefusal, Relevance) download weights
from the Hugging Face hub on first construction; Anonymize and Sensitive need presidio plus the spaCy
`en_core_web_lg` model. Every failure is logged once and turns the analyzer into a no-op, so an
unreachable hub never blocks the gateway. Scans run in a worker thread with a time limit.

The scanner API differs between llm-guard releases: 0.0.x `scan` returns (sanitized, is_valid), newer
releases return (sanitized, is_valid, risk_score) and ship extra scanners (Secrets, Regex, MaliciousURLs).
Both shapes are handled and unknown scanner names are reported instead of raising.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import threading
import time
from typing import Any

from ..analysis.analyzers.common import make_finding, snippet
from ..analysis.base import Finding, Severity
from ._common import (
    integration_config,
    last_error,
    library_installed,
    log,
    log_throttled,
    primary_text,
    response_text,
    set_error,
    severity_for_score,
)

NAME = "llm_guard"
NAME_INPUT = "llm_guard_input"
NAME_OUTPUT = "llm_guard_output"
DEFAULT_TIMEOUT = 20.0
BUILD_RETRY_SECONDS = 300.0
LIGHTWEIGHT_SCANNERS: frozenset[str] = frozenset(
    {
        "BanSubstrings",
        "Regex",
        "TokenLimit",
        "Secrets",
        "InvisibleText",
        "Language",
        "Deanonymize",
        "JSON",
        "ReadingTime",
        "URLReachability",
    }
)

# scanner class name -> (finding category, severity floor, severity cap)
CATEGORY_MAP: dict[str, tuple[str, Severity, Severity]] = {
    "PromptInjection": ("prompt_injection", Severity.MEDIUM, Severity.HIGH),
    "Jailbreak": ("jailbreak", Severity.MEDIUM, Severity.HIGH),
    "Secrets": ("secrets", Severity.MEDIUM, Severity.HIGH),
    "Anonymize": ("pii", Severity.LOW, Severity.HIGH),
    "Sensitive": ("pii", Severity.LOW, Severity.HIGH),
    "Toxicity": ("harmful_content", Severity.LOW, Severity.HIGH),
    "Bias": ("harmful_content", Severity.LOW, Severity.MEDIUM),
    "Sentiment": ("harmful_content", Severity.INFO, Severity.LOW),
    "MaliciousURLs": ("data_exfil", Severity.MEDIUM, Severity.HIGH),
    "URLReachability": ("data_exfil", Severity.INFO, Severity.LOW),
    "BanSubstrings": ("policy", Severity.LOW, Severity.HIGH),
    "BanTopics": ("policy", Severity.LOW, Severity.HIGH),
    "BanCode": ("policy", Severity.LOW, Severity.MEDIUM),
    "BanCompetitors": ("policy", Severity.LOW, Severity.MEDIUM),
    "Regex": ("policy", Severity.LOW, Severity.HIGH),
    "Code": ("tool_abuse", Severity.LOW, Severity.MEDIUM),
    "TokenLimit": ("anomaly", Severity.LOW, Severity.MEDIUM),
    "InvisibleText": ("obfuscation", Severity.LOW, Severity.MEDIUM),
    "Language": ("anomaly", Severity.INFO, Severity.LOW),
    "NoRefusal": ("guardrail", Severity.INFO, Severity.LOW),
    "Relevance": ("guardrail", Severity.INFO, Severity.LOW),
    "FactualConsistency": ("misinformation", Severity.LOW, Severity.MEDIUM),
    "JSON": ("output_handling", Severity.LOW, Severity.LOW),
}
# Substrings used when BanSubstrings is configured without an explicit list.
DEFAULT_BANNED_SUBSTRINGS: list[str] = [
    "ignore all previous instructions",
    "ignore previous instructions",
    "you are now dan",
    "developer mode enabled",
    "i have been pwned",
]
DEFAULT_BAD_PATTERNS: list[str] = [r"AISRF-CANARY-[0-9a-f]{16}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"]

_lock = threading.Lock()
_cache: dict[
    str, dict[str, Any]
] = {}  # config key -> {"scanners": [(name, instance)], "unavailable": {...}, "failed": {...}, "built_at": float}


def _config_key(kind: str, cfg: dict[str, Any]) -> str:
    names = cfg.get("input_scanners" if kind == "input" else "output_scanners") or []
    return json.dumps(
        {
            "kind": kind,
            "scanners": names,
            "threshold": cfg.get("threshold"),
            "options": cfg.get("scanner_options") or {},
        },
        sort_keys=True,
        default=str,
    )


def _scanner_kwargs(name: str, cls: Any, threshold: float | None, options: dict[str, Any]) -> dict[str, Any]:
    params = inspect.signature(cls.__init__).parameters
    kwargs: dict[str, Any] = {k: v for k, v in (options.get(name) or {}).items() if k in params}
    if "threshold" in params and threshold is not None and "threshold" not in kwargs:
        kwargs["threshold"] = threshold
    if name == "BanSubstrings" and not kwargs.get("substrings"):
        kwargs["substrings"] = list(DEFAULT_BANNED_SUBSTRINGS)
    if (
        name == "Regex"
        and not kwargs.get("bad_patterns")
        and not kwargs.get("good_patterns")
        and not kwargs.get("patterns")
    ):
        kwargs["bad_patterns" if "bad_patterns" in params else "patterns"] = list(DEFAULT_BAD_PATTERNS)
    if name == "BanTopics" and not kwargs.get("topics"):
        kwargs["topics"] = ["violence", "weapons", "illegal drugs", "self harm"]
    if name in ("Anonymize", "Deanonymize") and "vault" in params and "vault" not in kwargs:
        from llm_guard.vault import Vault

        kwargs["vault"] = Vault()
    return kwargs


def _build(kind: str, cfg: dict[str, Any]) -> dict[str, Any]:
    """Construct the configured scanners. Runs in a worker thread; individual scanner failures are recorded, not raised."""
    import importlib

    module = importlib.import_module(
        "llm_guard.input_scanners" if kind == "input" else "llm_guard.output_scanners"
    )
    names = [str(n) for n in (cfg.get("input_scanners" if kind == "input" else "output_scanners") or [])]
    try:
        threshold: float | None = float(cfg["threshold"]) if cfg.get("threshold") is not None else None
    except (TypeError, ValueError):
        threshold = None
    options = cfg.get("scanner_options") if isinstance(cfg.get("scanner_options"), dict) else {}
    built: list[tuple[str, Any]] = []
    unavailable: dict[str, str] = {}
    failed: dict[str, str] = {}
    for name in names:
        cls = getattr(module, name, None)
        if cls is None:
            unavailable[name] = f"scanner '{name}' is not available in the installed llm-guard"
            continue
        try:
            built.append((name, cls(**_scanner_kwargs(name, cls, threshold, options))))
        except Exception as exc:
            failed[name] = f"{type(exc).__name__}: {str(exc)[:200]}"
    return {"scanners": built, "unavailable": unavailable, "failed": failed, "built_at": time.monotonic()}


def _get_scanners_sync(kind: str, cfg: dict[str, Any]) -> dict[str, Any]:
    key = _config_key(kind, cfg)
    with _lock:
        entry = _cache.get(key)
        if entry is not None and not (
            entry["failed"] and time.monotonic() - entry["built_at"] > BUILD_RETRY_SECONDS
        ):
            return entry
        entry = _build(kind, cfg)
        _cache[key] = entry
        for name, err in {**entry["unavailable"], **entry["failed"]}.items():
            log.warning("guardrails.llm_guard.scanner_unavailable", scanner=name, kind=kind, error=err)
        if entry["failed"]:
            set_error(NAME, "; ".join(f"{n}: {e}" for n, e in entry["failed"].items()))
        return entry


def _parse_result(result: Any) -> tuple[str, bool, float]:
    """Normalise (sanitized, is_valid) and (sanitized, is_valid, risk_score) into (sanitized, is_valid, risk 0..1)."""
    if not isinstance(result, tuple) or len(result) < 2:
        return "", True, 0.0
    sanitized = result[0] if isinstance(result[0], str) else ""
    valid = bool(result[1])
    if len(result) >= 3:
        try:
            risk = float(result[2])
        except (TypeError, ValueError):
            risk = 1.0 if not valid else 0.0
        risk = max(0.0, min(1.0, risk))
    else:
        risk = 1.0 if not valid else 0.0
    return sanitized, valid, risk


def _run_scanners(entry: dict[str, Any], prompt: str, output: str | None) -> list[dict[str, Any]]:
    """Execute every scanner (worker thread). Returns one row per scanner with the raw verdict."""
    rows: list[dict[str, Any]] = []
    for name, scanner in entry["scanners"]:
        start = time.perf_counter()
        try:
            result = scanner.scan(prompt, output) if output is not None else scanner.scan(prompt)
            sanitized, valid, risk = _parse_result(result)
            rows.append(
                {
                    "scanner": name,
                    "is_valid": valid,
                    "risk_score": risk,
                    "sanitized": sanitized,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 1),
                }
            )
        except Exception as exc:
            rows.append({"scanner": name, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
    return rows


def _findings(
    rows: list[dict[str, Any]], text: str, location: str, analyzer: str, kind: str
) -> list[Finding]:
    findings: list[Finding] = []
    for row in rows:
        if row.get("error"):
            log_throttled(
                f"llm_guard.scan.{row['scanner']}",
                "guardrails.llm_guard.scan_failed",
                scanner=row["scanner"],
                error=row["error"],
            )
            continue
        if row["is_valid"]:
            continue
        name = row["scanner"]
        category, floor, cap = CATEGORY_MAP.get(name, ("guardrail", Severity.LOW, Severity.HIGH))
        risk = float(row["risk_score"])
        sev = severity_for_score(risk, floor=floor, cap=cap)
        sanitized = row.get("sanitized") or ""
        evidence = snippet(text, 0, min(len(text), 120)) if text else ""
        if sanitized and sanitized != text and name in ("Anonymize", "Sensitive", "Deanonymize"):
            evidence = snippet(sanitized, 0, min(len(sanitized), 120))
        findings.append(
            make_finding(
                analyzer,
                category,
                sev,
                f"LLM Guard {name} flagged the {kind}",
                f"The LLM Guard {name} scanner marked the {kind} as invalid (risk score {risk:.2f}).",
                evidence,
                location,
                max(0.4, min(0.95, risk if risk > 0 else 0.6)),
                tags=["llm_guard", name.lower()],
                metadata={
                    "scanner": name,
                    "risk_score": round(risk, 3),
                    "duration_ms": row.get("duration_ms"),
                    "sanitized_changed": bool(sanitized and sanitized != text),
                },
            )
        )
    return findings


async def _scan(kind: str, prompt: str, output: str | None, location: str, analyzer: str) -> list[Finding]:
    cfg = integration_config(NAME)
    if not cfg.get("enabled"):
        return []
    if not library_installed("llm_guard"):
        set_error(NAME, "llm_guard is not installed")
        log_throttled("llm_guard.missing", "guardrails.llm_guard.not_installed")
        return []
    if not (prompt.strip() or (output or "").strip()):
        return []
    try:
        timeout = float(cfg.get("timeout_seconds") or DEFAULT_TIMEOUT)
    except (TypeError, ValueError):
        timeout = DEFAULT_TIMEOUT
    try:
        entry = await asyncio.wait_for(
            asyncio.to_thread(_get_scanners_sync, kind, cfg), timeout=max(timeout, 60.0)
        )
    except Exception as exc:
        set_error(NAME, f"build: {exc}")
        log_throttled("llm_guard.build", "guardrails.llm_guard.build_failed", error=str(exc)[:300])
        return []
    if not entry["scanners"]:
        return []
    try:
        rows = await asyncio.wait_for(
            asyncio.to_thread(_run_scanners, entry, prompt, output), timeout=timeout
        )
    except Exception as exc:
        set_error(NAME, f"scan: {exc}")
        log_throttled("llm_guard.scan", "guardrails.llm_guard.scan_timeout", error=str(exc)[:300])
        return []
    return _findings(
        rows,
        output if output is not None else prompt,
        location,
        analyzer,
        "response" if output is not None else "request",
    )


class LLMGuardInputAnalyzer:
    name = NAME_INPUT
    description = "Runs the configured LLM Guard input scanners (PromptInjection, Toxicity, BanSubstrings, TokenLimit, ...) over the last user message."

    async def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        try:
            return await _scan("input", primary_text(normalized), None, "last_user_message", self.name)
        except Exception as exc:
            set_error(NAME, str(exc))
            log_throttled(
                "llm_guard.input", "guardrails.llm_guard.failed", analyzer=self.name, error=str(exc)[:300]
            )
            return []


class LLMGuardOutputAnalyzer:
    name = NAME_OUTPUT
    description = "Runs the configured LLM Guard output scanners (Sensitive, Regex, NoRefusal, Relevance, ...) over the model response."

    async def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        try:
            return await _scan(
                "output", primary_text(normalized), response_text(context), "response", self.name
            )
        except Exception as exc:
            set_error(NAME, str(exc))
            log_throttled(
                "llm_guard.output", "guardrails.llm_guard.failed", analyzer=self.name, error=str(exc)[:300]
            )
            return []


input_analyzer = LLMGuardInputAnalyzer()
output_analyzer = LLMGuardOutputAnalyzer()


def sanitize(text: str) -> str:
    """Anonymize `text` with LLM Guard's Anonymize scanner when the integration is enabled and lists it; otherwise return it unchanged."""
    cfg = integration_config(NAME)
    if not cfg.get("enabled") or not library_installed("llm_guard") or not text:
        return text
    if "Anonymize" not in (cfg.get("input_scanners") or []):
        return text
    try:
        entry = _get_scanners_sync("input", cfg)
        for name, scanner in entry["scanners"]:
            if name == "Anonymize":
                sanitized, _valid, _risk = _parse_result(scanner.scan(text))
                return sanitized or text
    except Exception as exc:
        set_error(NAME, f"sanitize: {exc}")
        log_throttled("llm_guard.sanitize", "guardrails.llm_guard.sanitize_failed", error=str(exc)[:300])
    return text


def scanner_state() -> dict[str, Any]:
    """Cached build state for the status endpoint: which configured scanners are built, missing or broken."""
    out: dict[str, Any] = {"built": [], "unavailable": {}, "failed": {}}
    with _lock:
        for entry in _cache.values():
            out["built"].extend(n for n, _ in entry["scanners"])
            out["unavailable"].update(entry["unavailable"])
            out["failed"].update(entry["failed"])
    return out


def status() -> dict[str, Any]:
    cfg = integration_config(NAME)
    installed = library_installed("llm_guard")
    inputs = list(cfg.get("input_scanners") or [])
    outputs = list(cfg.get("output_scanners") or [])
    return {
        "name": NAME,
        "installed": installed,
        "enabled": bool(cfg.get("enabled")),
        "configured": installed and bool(inputs or outputs),
        "input_scanners": inputs,
        "output_scanners": outputs,
        "needs_model_download": sorted({n for n in inputs + outputs if n not in LIGHTWEIGHT_SCANNERS}),
        "scanners": scanner_state(),
        "analyzers": [NAME_INPUT, NAME_OUTPUT],
        "last_error": last_error(NAME),
    }


async def health_check() -> dict[str, Any]:
    start = time.perf_counter()
    cfg = integration_config(NAME)
    if not library_installed("llm_guard"):
        return {"name": NAME, "ok": False, "detail": "llm_guard is not installed"}
    try:
        entry = await asyncio.wait_for(asyncio.to_thread(_get_scanners_sync, "input", cfg), timeout=120.0)
        rows = await asyncio.wait_for(
            asyncio.to_thread(_run_scanners, entry, "hello, what is the weather today?", None), timeout=60.0
        )
    except Exception as exc:
        return {
            "name": NAME,
            "ok": False,
            "detail": str(exc)[:300],
            "duration_ms": round((time.perf_counter() - start) * 1000, 1),
        }
    errors = [r for r in rows if r.get("error")]
    problems = {**entry["unavailable"], **entry["failed"], **{r["scanner"]: r["error"] for r in errors}}
    return {
        "name": NAME,
        "ok": bool(entry["scanners"]) and not problems,
        "detail": f"{len(entry['scanners'])} input scanner(s) ready"
        + (f", problems: {problems}" if problems else ""),
        "duration_ms": round((time.perf_counter() - start) * 1000, 1),
    }
