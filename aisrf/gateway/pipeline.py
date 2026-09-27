"""Programmatic submission through the full interception pipeline (used by the red-team engine and SDK helpers).

Same steps as an HTTP call through the gateway: ticket, analysis, policy, human hold, forward, response analysis.
Non-streaming only.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from .. import settings_store
from ..agents import service as agents
from ..analysis import analyze_request, analyze_response
from ..db import session_scope
from ..logging import get_logger
from ..metrics import metrics
from ..models import Agent, Ticket, TicketStatus
from ..security import redact_headers
from ..tickets import service as tickets
from . import canary as canary_mod
from . import forwarder, policy
from .hold import hold_registry
from .parser import extract_response_text, normalize

log = get_logger("aisrf.pipeline")


@dataclass
class SubmitResult:
    ticket_id: str
    status: str
    http_status: int | None = None
    response_text: str = ""
    response_json: Any = None
    error: str = ""
    latency_ms: float | None = None
    risk_score: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    response_findings: list[dict[str, Any]] = field(default_factory=list)
    decided_by: str | None = None
    decision_note: str = ""


async def submit(
    http: httpx.AsyncClient,
    agent_id: str,
    *,
    path: str,
    body: dict[str, Any],
    method: str = "POST",
    headers: dict[str, str] | None = None,
    source: str = "sdk",
    campaign_id: str | None = None,
    probe_id: str | None = None,
    correlation_id: str | None = None,
    wait_timeout: float | None = None,
) -> SubmitResult:
    body = {**body, "stream": False} if isinstance(body, dict) and "stream" in body else body
    raw = json.dumps(body).encode()
    inbound = {"content-type": "application/json", **(headers or {})}
    async with session_scope() as session:
        agent = await session.get(Agent, agent_id)
        if agent is None or not agent.is_active:
            raise ValueError(f"agent {agent_id} not found or inactive")
        normalized = normalize(path, raw, provider_hint=agent.upstream_provider)
        canary = None
        if agent.inject_canary or settings_store.get_value("integrations", "rebuff", {}).get("canary_default"):
            canary = canary_mod.new_canary()
            injected = canary_mod.inject(raw, canary)
            if injected != raw:
                raw = injected
                normalized["canary"] = canary
            else:
                canary = None
        upstream_url = forwarder.build_upstream_url(agent, path)
        ticket = await tickets.create_ticket(
            session,
            agent,
            method=method,
            path=path,
            upstream_url=upstream_url,
            request_headers=redact_headers(inbound),
            request_body=raw.decode(),
            request_json=body if isinstance(body, dict) else None,
            normalized=normalized,
            source=source,
            correlation_id=correlation_id,
            campaign_id=campaign_id,
            probe_id=probe_id,
        )
        await agents.touch_agent(session, agent.id)
        analysis = await analyze_request(
            normalized, {"agent": agents.agent_to_dict(agent), "path": path, "headers": inbound}
        )
        await tickets.set_analysis(session, ticket, analysis.to_dict())
        decision = policy.evaluate(agent, normalized, path, ticket.risk_score, ticket.findings)
        await tickets.apply_policy(session, ticket, decision.to_dict())
        metrics.inc("gateway_requests_total")
        metrics.inc("gateway_policy_total", labels={"action": decision.action})
        ticket_id = ticket.id
        status = ticket.status
        risk = ticket.risk_score
        findings = list(ticket.findings or [])
        note = ticket.decision_note

    if status == TicketStatus.DENIED.value:
        return SubmitResult(
            ticket_id, status, risk_score=risk, findings=findings, decided_by="policy", decision_note=note
        )

    if status == TicketStatus.PENDING.value:
        final = await hold_registry.wait(ticket_id, wait_timeout)
        async with session_scope() as session:
            ticket = await session.get(Ticket, ticket_id)
            if final == TicketStatus.EXPIRED.value or ticket.status == TicketStatus.PENDING.value:
                await tickets.mark_expired(session, ticket)
                return SubmitResult(
                    ticket_id,
                    TicketStatus.EXPIRED.value,
                    risk_score=risk,
                    findings=findings,
                    decided_by="timeout",
                )
            if ticket.status == TicketStatus.DENIED.value:
                return SubmitResult(
                    ticket_id,
                    ticket.status,
                    risk_score=risk,
                    findings=findings,
                    decided_by=ticket.decided_by,
                    decision_note=ticket.decision_note,
                )
            decided_by, note = ticket.decided_by, ticket.decision_note
    else:
        decided_by = "policy"

    async with session_scope() as session:
        ticket = await session.get(Ticket, ticket_id)
        agent = await session.get(Agent, agent_id)
        await tickets.mark_forwarding(session, ticket)
    req = forwarder.build_request(http, agent, method, path, "", inbound, raw)
    started = time.perf_counter()
    try:
        resp = await http.send(req)
        raw_resp = resp.content
        status_code = resp.status_code
        resp_headers = forwarder.filter_response_headers(resp.headers)
    except Exception as exc:
        msg = forwarder.summarize_error(exc)
        async with session_scope() as session:
            ticket = await session.get(Ticket, ticket_id)
            await tickets.mark_failed(session, ticket, msg)
        metrics.inc("gateway_upstream_errors_total")
        return SubmitResult(
            ticket_id,
            TicketStatus.FAILED.value,
            error=msg,
            risk_score=risk,
            findings=findings,
            decided_by=decided_by,
            decision_note=note,
        )
    latency = round((time.perf_counter() - started) * 1000, 1)
    text = extract_response_text(raw_resp, normalized.get("endpoint", ""))
    response_findings: list[dict[str, Any]] = []
    if text:
        try:
            res = await analyze_response(
                normalized, text, {"agent_id": agent_id, "canaries": [canary] if canary else []}
            )
            response_findings = [f.to_dict() for f in res.findings]
        except Exception as exc:
            log.warning("response.analysis.failed", ticket_id=ticket_id, error=str(exc))
        if canary_mod.leaked(text, canary) and not any(
            f.get("category") == "canary_leak" for f in response_findings
        ):
            response_findings.insert(
                0,
                {
                    "analyzer": "canary",
                    "category": "canary_leak",
                    "severity": "CRITICAL",
                    "title": "Canary token leaked in response",
                    "description": "The secret canary injected into the system prompt appears in the model output.",
                    "evidence": canary,
                    "location": "response",
                    "confidence": 1.0,
                    "tags": ["rebuff"],
                    "metadata": {},
                },
            )
    async with session_scope() as session:
        ticket = await session.get(Ticket, ticket_id)
        await tickets.mark_completed(
            session,
            ticket,
            status_code=status_code,
            headers=resp_headers,
            body=raw_resp.decode("utf-8", "replace"),
            latency_ms=latency,
            response_findings=response_findings,
            response_preview=text[:500],
        )
        final_status = ticket.status
    metrics.inc("gateway_upstream_responses_total", labels={"status": str(status_code)})
    metrics.observe("gateway_upstream_latency_ms", latency)
    try:
        rj = json.loads(raw_resp)
    except Exception:
        rj = None
    return SubmitResult(
        ticket_id,
        final_status,
        http_status=status_code,
        response_text=text,
        response_json=rj,
        latency_ms=latency,
        risk_score=risk,
        findings=findings,
        response_findings=response_findings,
        decided_by=decided_by,
        decision_note=note,
    )
