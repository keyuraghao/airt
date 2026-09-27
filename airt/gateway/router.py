"""The interception endpoints. Point any LLM client at this server and every call becomes a ticket.

    OpenAI SDK:     base_url="http://gateway:8080/v1",  api_key="<AIRT agent key>"
    Anthropic SDK:  base_url="http://gateway:8080",     api_key="<AIRT agent key>"
    Anything else:  http://gateway:8080/proxy/<path>    with  X-AIRT-Key: <AIRT agent key>

Synchronous mode (default): the HTTP call blocks until a reviewer decides or the timeout elapses.
Asynchronous mode (header X-AIRT-Async: 1): returns 202 with the ticket id; poll /gateway/tickets/{id}.
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from .. import settings_store
from ..agents import service as agents
from ..analysis import analyze_request, analyze_response
from ..config import get_settings
from ..db import get_session, session_scope
from ..logging import get_logger
from ..metrics import metrics
from ..models import Agent, Ticket, TicketStatus
from ..security import redact_headers
from ..tickets import service as tickets
from . import canary as canary_mod
from . import forwarder, policy
from .hold import hold_registry
from .parser import extract_response_text, normalize

log = get_logger("airt.gateway")
router = APIRouter(tags=["gateway"])
METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


def _extract_key(request: Request) -> str | None:
    for header in ("x-airt-key", "x-api-key", "api-key", "x-goog-api-key"):
        v = request.headers.get(header)
        if v and v.startswith("airt_"):
            return v
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    for header in ("x-airt-key", "x-api-key", "api-key"):
        v = request.headers.get(header)
        if v:
            return v
    return None


async def _authenticate(request: Request, session: AsyncSession) -> Agent:
    agent = await agents.authenticate_api_key(session, _extract_key(request))
    if agent is None:
        raise GatewayAuthError()
    return agent


class GatewayAuthError(Exception):
    pass


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


async def intercept(request: Request, path: str, session: AsyncSession) -> Response:
    settings = get_settings()
    metrics.inc("gateway_requests_total")
    try:
        agent = await _authenticate(request, session)
    except GatewayAuthError:
        metrics.inc("gateway_auth_failures_total")
        return JSONResponse(
            {
                "error": {
                    "message": "invalid or missing AIRT agent key",
                    "type": "airt_gateway",
                    "code": "unauthorized",
                }
            },
            status_code=401,
        )

    if not agents.check_rate_limit(agent):
        await agents.log_agent_event(agent.id, "rate_limited", level="WARNING", session=session, path=path)
        await session.commit()
        return JSONResponse(
            {
                "error": {
                    "message": "agent rate limit exceeded",
                    "type": "airt_gateway",
                    "code": "rate_limited",
                }
            },
            status_code=429,
        )

    body = await request.body()
    if len(body) > settings.max_request_body_bytes:
        return JSONResponse(
            {
                "error": {
                    "message": "request body too large",
                    "type": "airt_gateway",
                    "code": "payload_too_large",
                }
            },
            status_code=413,
        )

    inbound_headers = dict(request.headers)
    normalized = normalize(path, body, provider_hint=agent.upstream_provider)
    canary = None
    if agent.inject_canary and body:
        canary = canary_mod.new_canary()
        injected = canary_mod.inject(body, canary)
        if injected != body:
            body = injected
            normalized["canary"] = canary
        else:
            canary = None
    upstream_url = forwarder.build_upstream_url(agent, path, request.url.query)
    try:
        request_json = json.loads(body) if body else None
        if not isinstance(request_json, dict):
            request_json = {"_value": request_json} if request_json is not None else None
    except Exception:
        request_json = None
    async_mode = request.headers.get("x-airt-async", "").lower() in ("1", "true", "yes")
    correlation_id = request.headers.get("x-airt-correlation-id") or request.headers.get("x-request-id")
    source = request.headers.get("x-airt-source", "gateway")
    campaign_id = request.headers.get("x-airt-campaign-id")
    probe_id = request.headers.get("x-airt-probe-id")

    ticket = await tickets.create_ticket(
        session,
        agent,
        method=request.method,
        path=path,
        upstream_url=upstream_url,
        request_headers=redact_headers(inbound_headers),
        request_body=body.decode("utf-8", "replace"),
        request_json=request_json,
        normalized=normalized,
        client_ip=_client_ip(request),
        user_agent=request.headers.get("user-agent", ""),
        source=source if source in ("gateway", "mitm", "sdk", "redteam") else "gateway",
        correlation_id=correlation_id,
        campaign_id=campaign_id,
        probe_id=probe_id,
    )
    await agents.touch_agent(session, agent.id)

    analysis = await analyze_request(
        normalized,
        {"agent": agents.agent_to_dict(agent), "path": path, "headers": redact_headers(inbound_headers)},
    )
    await tickets.set_analysis(session, ticket, analysis.to_dict())
    metrics.observe("gateway_risk_score", ticket.risk_score)

    decision = policy.evaluate(agent, normalized, path, ticket.risk_score, ticket.findings)
    await tickets.apply_policy(session, ticket, decision.to_dict())
    await session.commit()
    metrics.inc("gateway_policy_total", labels={"action": decision.action})

    if ticket.status == TicketStatus.DENIED.value:
        metrics.inc("gateway_denied_total")
        return JSONResponse(
            forwarder.error_json(
                ticket.id,
                "denied",
                "request blocked by AIRT policy: " + ticket.decision_note,
                {"risk_score": ticket.risk_score},
            ),
            status_code=403,
        )

    if ticket.status == TicketStatus.PENDING.value:
        if async_mode:
            return JSONResponse(
                {
                    "ticket_id": ticket.id,
                    "status": "PENDING",
                    "poll_url": f"/gateway/tickets/{ticket.id}",
                    "expires_at": ticket.expires_at.isoformat() if ticket.expires_at else None,
                },
                status_code=202,
                headers={"X-AIRT-Ticket": ticket.id},
            )
        log.info(
            "ticket.waiting", ticket_id=ticket.id, agent=agent.name, timeout=settings.approval_timeout_seconds
        )
        wait_started = time.perf_counter()
        status = await hold_registry.wait(ticket.id)
        metrics.observe("gateway_wait_seconds", time.perf_counter() - wait_started)
        await session.refresh(ticket)
        if status == TicketStatus.EXPIRED.value or ticket.status == TicketStatus.PENDING.value:
            await tickets.mark_expired(session, ticket)
            await session.commit()
            metrics.inc("gateway_expired_total")
            return JSONResponse(
                forwarder.error_json(
                    ticket.id,
                    "expired",
                    "no reviewer decision before the approval timeout; nothing was sent upstream",
                ),
                status_code=504,
            )
        if ticket.status == TicketStatus.DENIED.value:
            metrics.inc("gateway_denied_total")
            return JSONResponse(
                forwarder.error_json(
                    ticket.id,
                    "denied",
                    "request denied by reviewer: " + (ticket.decision_note or ""),
                    {"decided_by": ticket.decided_by},
                ),
                status_code=403,
            )

    return await forward_ticket(
        request.app, session, ticket, agent, request.method, path, request.url.query, inbound_headers, body
    )


async def forward_ticket(
    app: Any,
    session: AsyncSession,
    ticket: Ticket,
    agent: Agent,
    method: str,
    path: str,
    query: str,
    inbound_headers: dict[str, str],
    body: bytes,
) -> Response:
    """Ticket is APPROVED: send it upstream, record the outcome, relay the answer (streaming aware)."""
    settings = get_settings()
    client: httpx.AsyncClient = app.state.http
    await tickets.mark_forwarding(session, ticket)
    await session.commit()
    req = forwarder.build_request(client, agent, method, path, query, inbound_headers, body)
    started = time.perf_counter()
    try:
        upstream = await client.send(req, stream=True)
    except Exception as exc:
        msg = forwarder.summarize_error(exc)
        await tickets.mark_failed(session, ticket, msg)
        await session.commit()
        metrics.inc("gateway_upstream_errors_total")
        return JSONResponse(forwarder.error_json(ticket.id, "upstream_error", msg), status_code=502)

    resp_headers = forwarder.filter_response_headers(upstream.headers)
    resp_headers["X-AIRT-Ticket"] = ticket.id
    content_type = upstream.headers.get("content-type", "")
    is_stream = ticket.is_stream or "text/event-stream" in content_type

    if not is_stream:
        try:
            raw = await upstream.aread()
        finally:
            await upstream.aclose()
        latency = round((time.perf_counter() - started) * 1000, 1)
        withheld = await _finish(session, ticket, upstream.status_code, resp_headers, raw, latency)
        await session.commit()
        if withheld:
            metrics.inc("gateway_responses_withheld_total")
            return JSONResponse(
                forwarder.error_json(ticket.id, "response_withheld", withheld),
                status_code=403,
                headers={"X-AIRT-Ticket": ticket.id},
            )
        return Response(
            content=raw,
            status_code=upstream.status_code,
            headers=resp_headers,
            media_type=content_type or None,
        )

    ticket_id = ticket.id
    captured = bytearray()
    status_code = upstream.status_code

    async def relay():
        try:
            async for chunk in _iter_upstream(upstream):
                if len(captured) < settings.max_stored_response_bytes:
                    captured.extend(chunk)
                yield chunk
        finally:
            await upstream.aclose()
            latency = round((time.perf_counter() - started) * 1000, 1)
            async with session_scope() as s:
                t = await s.get(Ticket, ticket_id)
                if t is not None:
                    await _finish(s, t, status_code, resp_headers, bytes(captured), latency)

    return StreamingResponse(
        relay(), status_code=status_code, headers=resp_headers, media_type=content_type or "text/event-stream"
    )


async def _iter_upstream(upstream: httpx.Response):
    """Iterate the upstream body; tolerates transports that already buffered the whole response."""
    if getattr(upstream, "_content", None) is not None:
        yield upstream.content
        return
    async for chunk in upstream.aiter_raw():
        yield chunk


async def _finish(
    session: AsyncSession,
    ticket: Ticket,
    status_code: int,
    headers: dict[str, str],
    raw: bytes,
    latency_ms: float,
) -> str | None:
    """Record the upstream outcome. Returns a reason string when policy says the response must be withheld from the client."""
    normalized = ticket.normalized or {}
    text = extract_response_text(raw, normalized.get("endpoint", ""))
    response_findings: list[dict[str, Any]] = []
    canary = normalized.get("canary")
    if text:
        try:
            res = await analyze_response(
                normalized, text, {"agent_id": ticket.agent_id, "canaries": [canary] if canary else []}
            )
            response_findings = [f.to_dict() for f in res.findings]
        except Exception as exc:
            log.warning("response.analysis.failed", ticket_id=ticket.id, error=str(exc))
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
                    "description": "The secret canary injected into the system prompt appears in the model output: the system prompt was disclosed.",
                    "evidence": canary,
                    "location": "response",
                    "confidence": 1.0,
                    "tags": ["rebuff"],
                    "metadata": {},
                },
            )
    metrics.inc("gateway_upstream_responses_total", labels={"status": str(status_code)})
    metrics.observe("gateway_upstream_latency_ms", latency_ms)
    await tickets.mark_completed(
        session,
        ticket,
        status_code=status_code,
        headers=headers,
        body=raw.decode("utf-8", "replace"),
        latency_ms=latency_ms,
        response_findings=response_findings,
        response_preview=text.replace("\n", " ")[:500],
    )
    pol = settings_store.get_namespace("policy")
    if pol.get("block_on_canary_leak", True) and any(
        f.get("category") == "canary_leak" for f in response_findings
    ):
        reason = "response withheld: system prompt canary leaked in the model output"
        ticket.error = reason
        await tickets.add_event(session, ticket, "withheld", actor="policy", reason=reason)
        return reason
    if pol.get("quarantine_on_critical_response_finding") and any(
        f.get("severity") == "CRITICAL" for f in response_findings
    ):
        reason = "response withheld: critical finding in the model output"
        ticket.error = reason
        await tickets.add_event(session, ticket, "withheld", actor="policy", reason=reason)
        return reason
    return None


@router.api_route("/v1/{path:path}", methods=METHODS, include_in_schema=False)
async def openai_compatible(
    path: str, request: Request, session: AsyncSession = Depends(get_session)
) -> Response:
    return await intercept(request, "v1/" + path, session)


@router.api_route("/proxy/{path:path}", methods=METHODS, include_in_schema=False)
async def generic_proxy(
    path: str, request: Request, session: AsyncSession = Depends(get_session)
) -> Response:
    return await intercept(request, path, session)


@router.get("/gateway/tickets/{ticket_id}", summary="Poll an asynchronous ticket (agent authenticated)")
async def poll_ticket(
    ticket_id: str, request: Request, session: AsyncSession = Depends(get_session)
) -> Response:
    try:
        agent = await _authenticate(request, session)
    except GatewayAuthError:
        return JSONResponse(
            {"error": {"message": "invalid or missing AIRT agent key", "code": "unauthorized"}},
            status_code=401,
        )
    ticket = await tickets.get_ticket(session, ticket_id)
    if ticket is None or ticket.agent_id != agent.id:
        return JSONResponse({"error": {"message": "ticket not found", "code": "not_found"}}, status_code=404)
    if ticket.status == TicketStatus.APPROVED.value:
        headers = {k: v for k, v in (ticket.request_headers or {}).items()}
        body = (ticket.request_body or "").encode()
        return await forward_ticket(
            request.app, session, ticket, agent, ticket.method, ticket.path, "", headers, body
        )
    payload: dict[str, Any] = {
        "ticket_id": ticket.id,
        "status": ticket.status,
        "decided_by": ticket.decided_by,
        "decision_note": ticket.decision_note,
    }
    if ticket.status in (TicketStatus.COMPLETED.value, TicketStatus.FAILED.value) and ticket.response_status:
        try:
            payload["response"] = json.loads(ticket.response_body)
        except Exception:
            payload["response_text"] = ticket.response_body
        payload["response_status"] = ticket.response_status
    if ticket.status == TicketStatus.COMPLETED.value:
        code = 200
    elif ticket.status in (TicketStatus.PENDING.value, TicketStatus.FORWARDING.value):
        code = 202
    elif ticket.status in (TicketStatus.DENIED.value, TicketStatus.EXPIRED.value):
        code = 403
    else:
        code = 502
    return JSONResponse(payload, status_code=code)
