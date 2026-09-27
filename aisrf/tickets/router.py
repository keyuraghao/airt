"""Reviewer REST API for tickets, plus live SSE streams."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sse_starlette.sse import EventSourceResponse

from ..agents import service as agents
from ..audit import service as audit
from ..auth import Principal, current_principal, require_role
from ..db import get_session
from ..logging import broadcaster
from . import service as tickets

router = APIRouter(prefix="/api", tags=["tickets"])


class DecisionIn(BaseModel):
    note: str = ""


class BulkDecisionIn(BaseModel):
    ticket_ids: list[str]
    note: str = ""


@router.get("/tickets")
async def list_tickets(
    status: list[str] | None = Query(default=None),
    agent_id: str | None = None,
    min_risk: int | None = None,
    model: str | None = None,
    source: str | None = None,
    campaign_id: str | None = None,
    search: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=50, le=500),
    offset: int = 0,
    order: str = "desc",
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    rows, total = await tickets.list_tickets(
        session,
        status=status,
        agent_id=agent_id,
        min_risk=min_risk,
        model=model,
        source=source,
        campaign_id=campaign_id,
        search=search,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
        order=order,
    )
    return {
        "items": [tickets.ticket_to_dict(t, brief=True) for t in rows],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/tickets/stats")
async def ticket_stats(
    _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    return await tickets.stats(session)


@router.post("/tickets/bulk/approve")
async def bulk_approve(
    payload: BulkDecisionIn,
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    return await tickets.bulk_decide(session, payload.ticket_ids, True, p.username, payload.note)


@router.post("/tickets/bulk/deny")
async def bulk_deny(
    payload: BulkDecisionIn,
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    return await tickets.bulk_decide(session, payload.ticket_ids, False, p.username, payload.note)


@router.get("/tickets/{ticket_id}")
async def get_ticket(
    ticket_id: str, _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    t = await tickets.get_ticket(session, ticket_id)
    if t is None:
        raise HTTPException(404, "ticket not found")
    d = tickets.ticket_to_dict(t)
    d["events"] = [tickets.event_to_dict(e) for e in await tickets.list_events(session, t.id)]
    d["agent"] = agents.agent_to_dict(t.agent) if t.agent else None
    return d


@router.get("/tickets/{ticket_id}/events")
async def get_ticket_events(
    ticket_id: str, _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)
) -> list[dict[str, Any]]:
    t = await tickets.get_ticket(session, ticket_id)
    if t is None:
        raise HTTPException(404, "ticket not found")
    return [tickets.event_to_dict(e) for e in await tickets.list_events(session, t.id)]


async def _decide(
    ticket_id: str, approve: bool, payload: DecisionIn, p: Principal, session: AsyncSession
) -> dict[str, Any]:
    t = await tickets.get_ticket(session, ticket_id)
    if t is None:
        raise HTTPException(404, "ticket not found")
    try:
        t = await tickets.decide(session, t.id, approve, p.username, payload.note)
    except tickets.InvalidTransition as exc:
        raise HTTPException(409, str(exc))
    return tickets.ticket_to_dict(t, brief=True)


@router.post("/tickets/{ticket_id}/approve")
async def approve_ticket(
    ticket_id: str,
    payload: DecisionIn = DecisionIn(),
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    return await _decide(ticket_id, True, payload, p, session)


@router.post("/tickets/{ticket_id}/deny")
async def deny_ticket(
    ticket_id: str,
    payload: DecisionIn = DecisionIn(),
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    return await _decide(ticket_id, False, payload, p, session)


@router.get("/audit")
async def list_audit(
    limit: int = Query(200, le=2000),
    offset: int = 0,
    action: str | None = None,
    actor: str | None = None,
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    rows = await audit.list_entries(session, limit=limit, offset=offset, action=action, actor=actor)
    return {
        "items": [
            {
                "id": r.id,
                "ts": r.ts.isoformat(),
                "actor": r.actor,
                "action": r.action,
                "target_type": r.target_type,
                "target_id": r.target_id,
                "detail": r.detail,
                "hash": r.hash,
                "prev_hash": r.prev_hash,
            }
            for r in rows
        ],
        "total": await audit.count_entries(session),
    }


@router.get("/audit/verify")
async def verify_audit(
    _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    return await audit.verify_chain(session)


async def _stream(request: Request, channel: str, replay: int, filt: dict[str, Any] | None = None):
    q = broadcaster.subscribe(channel, replay=replay)
    try:
        while True:
            if await request.is_disconnected():
                break
            try:
                item = await asyncio.wait_for(q.get(), timeout=15)
            except TimeoutError:
                yield {"event": "ping", "data": "{}"}
                continue
            if filt and any(item.get(k) != v for k, v in filt.items() if v):
                continue
            yield {"event": item.get("event", channel), "data": json.dumps(item, default=str)}
    finally:
        broadcaster.unsubscribe(channel, q)


@router.get("/stream/tickets")
async def stream_tickets(request: Request, replay: int = 20, _: Principal = Depends(current_principal)):
    return EventSourceResponse(_stream(request, "tickets", replay))


@router.get("/stream/logs")
async def stream_logs(
    request: Request, agent_id: str | None = None, replay: int = 50, _: Principal = Depends(current_principal)
):
    return EventSourceResponse(_stream(request, "logs", replay, {"agent_id": agent_id}))


@router.get("/stream/campaigns")
async def stream_campaigns(request: Request, replay: int = 20, _: Principal = Depends(current_principal)):
    return EventSourceResponse(_stream(request, "campaigns", replay))
