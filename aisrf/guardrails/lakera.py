"""Lakera Guard (hosted API) as request and response analyzers.

POST {endpoint} (default https://api.lakera.ai/v2/guard) with `Authorization: Bearer <api_key>` and
{"messages": [{"role", "content"}], "project_id"?: ...}. The response carries `flagged` plus a
`breakdown` of detectors ({detector_type, detected, ...}); each detected entry becomes a finding whose
category follows the detector type and a flagged screening is always at least HIGH. Network or API
failures are logged at most once per minute and yield no findings. Nothing runs when api_key is empty.
"""
from __future__ import annotations

import time
from typing import Any

import httpx

from ..analysis.analyzers.common import make_finding, snippet
from ..analysis.base import Finding, Severity
from ._common import (
    at_least,
    conversation_messages,
    integration_config,
    last_error,
    log_throttled,
    primary_text,
    response_text,
    set_error,
)

NAME = "lakera"
NAME_REQUEST = "lakera_guard"
NAME_RESPONSE = "lakera_guard_output"
DEFAULT_ENDPOINT = "https://api.lakera.ai/v2/guard"
TIMEOUT = 8.0
MAX_CONTENT_CHARS = 20000
# detector_type -> (category, base severity)
DETECTOR_MAP: dict[str, tuple[str, Severity]] = {
    "prompt_attack": ("prompt_injection", Severity.HIGH),
    "jailbreak": ("jailbreak", Severity.HIGH),
    "pii": ("pii", Severity.MEDIUM),
    "unknown_links": ("data_exfil", Severity.MEDIUM),
    "moderated_content": ("harmful_content", Severity.HIGH),
    "custom": ("policy", Severity.MEDIUM),
}
# Tests and air-gapped deployments can swap the transport (httpx.MockTransport) without touching the network.
_TRANSPORT: httpx.AsyncBaseTransport | None = None


def _client(cfg: dict[str, Any]) -> httpx.AsyncClient:
    try:
        timeout = float(cfg.get("timeout_seconds") or TIMEOUT)
    except (TypeError, ValueError):
        timeout = TIMEOUT
    headers = {"Authorization": f"Bearer {cfg.get('api_key', '')}", "Content-Type": "application/json"}
    return httpx.AsyncClient(timeout=timeout, headers=headers, transport=_TRANSPORT)


async def screen(messages: list[dict[str, str]], cfg: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Call Lakera Guard for a list of chat messages. Returns the parsed JSON or None on any failure."""
    cfg = cfg if cfg is not None else integration_config(NAME)
    api_key = str(cfg.get("api_key") or "").strip()
    if not api_key or not messages:
        return None
    payload: dict[str, Any] = {"messages": [{"role": m["role"], "content": m["content"][:MAX_CONTENT_CHARS]} for m in messages]}
    project_id = str(cfg.get("project_id") or "").strip()
    if project_id:
        payload["project_id"] = project_id
    if cfg.get("breakdown", True):
        payload["breakdown"] = True
    endpoint = str(cfg.get("endpoint") or DEFAULT_ENDPOINT).strip() or DEFAULT_ENDPOINT
    try:
        async with _client(cfg) as client:
            resp = await client.post(endpoint, json=payload)
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        set_error(NAME, f"{type(exc).__name__}: {str(exc)[:200]}")
        log_throttled("lakera.api", "guardrails.lakera.request_failed", endpoint=endpoint, error=str(exc)[:300], interval=60.0)
        return None
    if not isinstance(data, dict):
        set_error(NAME, "unexpected response shape")
        return None
    set_error(NAME, None)
    return data


def _findings(data: dict[str, Any], analyzer: str, text: str, location: str, kind: str) -> list[Finding]:
    flagged = bool(data.get("flagged"))
    breakdown = [b for b in (data.get("breakdown") or []) if isinstance(b, dict)]
    detected = [b for b in breakdown if b.get("detected")]
    evidence = snippet(text, 0, min(len(text), 120)) if text else ""
    findings: list[Finding] = []
    payload = data.get("payload") if isinstance(data.get("payload"), list) else []
    for b in detected[:10]:
        dtype = str(b.get("detector_type") or "unknown").lower()
        category, base = DETECTOR_MAP.get(dtype, ("guardrail", Severity.MEDIUM))
        sev = at_least(base, Severity.HIGH) if flagged else base
        findings.append(
            make_finding(
                analyzer, category, sev, f"Lakera Guard detected {dtype.replace('_', ' ')} in the {kind}",
                f"Lakera Guard detector '{b.get('detector_id') or dtype}' ({dtype}) fired on the {kind}" + (" and the screening was flagged." if flagged else "."),
                evidence, location, 0.9 if flagged else 0.7, tags=["lakera", dtype],
                metadata={"detector_type": dtype, "detector_id": b.get("detector_id"), "policy_id": b.get("policy_id"), "project_id": b.get("project_id"), "flagged": flagged, "payload": payload[:10]},
            )
        )
    if flagged and not findings:
        findings.append(
            make_finding(
                analyzer, "guardrail", Severity.HIGH, f"Lakera Guard flagged the {kind}",
                f"Lakera Guard flagged the {kind} without a detector breakdown.", evidence, location, 0.85,
                tags=["lakera"], metadata={"flagged": True, "payload": payload[:10]},
            )
        )
    return findings


class LakeraRequestAnalyzer:
    name = NAME_REQUEST
    description = "Screens the conversation with the Lakera Guard API (prompt attacks, PII, unknown links, moderated content, custom detectors)."

    async def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        try:
            cfg = integration_config(NAME)
            if not cfg.get("enabled") or not str(cfg.get("api_key") or "").strip():
                return []
            messages = conversation_messages(normalized, include_system=bool(cfg.get("include_system", True)))
            if not messages:
                return []
            data = await screen(messages, cfg)
            if not data:
                return []
            return _findings(data, self.name, primary_text(normalized), "last_user_message", "request")
        except Exception as exc:
            set_error(NAME, str(exc))
            log_throttled("lakera.request", "guardrails.lakera.failed", analyzer=self.name, error=str(exc)[:300])
            return []


class LakeraResponseAnalyzer:
    name = NAME_RESPONSE
    description = "Screens the model response (with its conversation) through the Lakera Guard API."

    async def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        try:
            cfg = integration_config(NAME)
            if not cfg.get("enabled") or not str(cfg.get("api_key") or "").strip():
                return []
            text = response_text(context)
            if not text.strip():
                return []
            messages = conversation_messages(normalized, include_system=bool(cfg.get("include_system", True)))
            messages.append({"role": "assistant", "content": text})
            data = await screen(messages, cfg)
            if not data:
                return []
            return _findings(data, self.name, text, "response", "response")
        except Exception as exc:
            set_error(NAME, str(exc))
            log_throttled("lakera.response", "guardrails.lakera.failed", analyzer=self.name, error=str(exc)[:300])
            return []


request_analyzer = LakeraRequestAnalyzer()
response_analyzer = LakeraResponseAnalyzer()


def status() -> dict[str, Any]:
    cfg = integration_config(NAME)
    has_key = bool(str(cfg.get("api_key") or "").strip())
    return {
        "name": NAME,
        "installed": True,  # httpx based, always available
        "enabled": bool(cfg.get("enabled")),
        "configured": has_key,
        "endpoint": str(cfg.get("endpoint") or DEFAULT_ENDPOINT),
        "project_id": str(cfg.get("project_id") or ""),
        "analyzers": [NAME_REQUEST, NAME_RESPONSE],
        "last_error": last_error(NAME),
    }


async def health_check() -> dict[str, Any]:
    start = time.perf_counter()
    cfg = integration_config(NAME)
    if not str(cfg.get("api_key") or "").strip():
        return {"name": NAME, "ok": False, "detail": "api_key is empty"}
    data = await screen([{"role": "user", "content": "hello"}], cfg)
    ms = round((time.perf_counter() - start) * 1000, 1)
    if data is None:
        return {"name": NAME, "ok": False, "detail": last_error(NAME) or "request failed", "duration_ms": ms}
    return {"name": NAME, "ok": True, "detail": f"API reachable, benign probe flagged={bool(data.get('flagged'))}", "duration_ms": ms}
