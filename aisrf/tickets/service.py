"""Ticket lifecycle: creation, decisions, forwarding bookkeeping, queries and expiry."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..agents.service import log_agent_event
from ..audit import service as audit
from ..config import get_settings
from ..gateway.hold import hold_registry
from ..logging import broadcaster, get_logger
from ..models import Agent, Counter, Ticket, TicketEvent, TicketStatus, utcnow

log = get_logger("aisrf.tickets")


class TicketError(Exception):
    pass


class InvalidTransition(TicketError):
    pass


async def _next_number(session: AsyncSession) -> int:
    """Allocate the next ticket number atomically.

    The UPDATE takes the write lock on the counter row for the rest of the transaction, so concurrent
    ticket creations are serialized by the database instead of racing on max(number) + 1.
    """
    res = await session.execute(update(Counter).where(Counter.name == "ticket").values(value=Counter.value + 1))
    if not res.rowcount:
        current = (await session.execute(select(func.max(Ticket.number)))).scalar_one()
        session.add(Counter(name="ticket", value=int(current or 0) + 1))
        await session.flush()
    return int((await session.execute(select(Counter.value).where(Counter.name == "ticket"))).scalar_one())


async def add_event(
    session: AsyncSession, ticket: Ticket, event_type: str, actor: str = "system", **detail: Any
) -> TicketEvent:
    ev = TicketEvent(ticket_id=ticket.id, event_type=event_type, actor=actor, detail=detail)
    session.add(ev)
    await session.flush()
    return ev


def _publish(ticket: Ticket, event: str, **extra: Any) -> None:
    broadcaster.publish("tickets", {"event": event, "ticket": ticket_to_dict(ticket, brief=True), **extra})


async def create_ticket(
    session: AsyncSession,
    agent: Agent,
    *,
    method: str,
    path: str,
    upstream_url: str,
    request_headers: dict[str, str],
    request_body: str,
    request_json: dict | None,
    normalized: dict[str, Any],
    client_ip: str = "",
    user_agent: str = "",
    source: str = "gateway",
    correlation_id: str | None = None,
    campaign_id: str | None = None,
    probe_id: str | None = None,
) -> Ticket:
    settings = get_settings()
    ticket = Ticket(
        number=await _next_number(session),
        agent_id=agent.id,
        source=source,
        client_ip=client_ip,
        user_agent=user_agent[:300],
        method=method,
        path=path,
        upstream_url=upstream_url,
        request_headers=request_headers,
        request_body=request_body[: settings.max_request_body_bytes],
        request_json=request_json,
        normalized=normalized,
        prompt_preview=normalized.get("preview", ""),
        model=normalized.get("model", ""),
        is_stream=bool(normalized.get("stream")),
        expires_at=utcnow() + timedelta(seconds=settings.approval_timeout_seconds),
        campaign_id=campaign_id,
        probe_id=probe_id,
    )
    if correlation_id:
        ticket.correlation_id = correlation_id
    session.add(ticket)
    await session.flush()
    ticket.agent = agent
    await add_event(session, ticket, "created", detail_path=path, model=ticket.model, stream=ticket.is_stream)
    await log_agent_event(
        agent.id,
        "request.intercepted",
        ticket_id=ticket.id,
        correlation_id=ticket.correlation_id,
        session=session,
        path=path,
        model=ticket.model,
        method=method,
        chars=normalized.get("char_count", 0),
    )
    return ticket


async def set_analysis(session: AsyncSession, ticket: Ticket, analysis: dict[str, Any]) -> None:
    ticket.risk_score = int(analysis.get("score", 0))
    ticket.risk_level = analysis.get("level", "NONE")
    ticket.findings = analysis.get("findings", [])
    ticket.analysis_ms = float(analysis.get("duration_ms", 0))
    await add_event(
        session,
        ticket,
        "analyzed",
        score=ticket.risk_score,
        level=ticket.risk_level,
        findings=len(ticket.findings),
    )
    await log_agent_event(
        ticket.agent_id,
        "request.analyzed",
        ticket_id=ticket.id,
        correlation_id=ticket.correlation_id,
        session=session,
        risk_score=ticket.risk_score,
        risk_level=ticket.risk_level,
        findings=[f.get("title") for f in ticket.findings[:8]],
    )


async def apply_policy(session: AsyncSession, ticket: Ticket, decision: dict[str, Any]) -> None:
    ticket.policy_decision = decision
    action = decision.get("action")
    if action == "deny":
        ticket.status = TicketStatus.DENIED.value
        ticket.decided_by = "policy"
        ticket.decided_at = utcnow()
        ticket.decision_note = "; ".join(decision.get("reasons", []))
    elif action == "approve":
        ticket.status = TicketStatus.APPROVED.value
        ticket.decided_by = "policy"
        ticket.decided_at = utcnow()
        ticket.decision_note = "; ".join(decision.get("reasons", []))
    else:
        ticket.status = TicketStatus.PENDING.value
        hold_registry.register(ticket.id)
    await add_event(session, ticket, "policy", actor="policy", **decision)
    await log_agent_event(
        ticket.agent_id,
        f"policy.{action}",
        ticket_id=ticket.id,
        correlation_id=ticket.correlation_id,
        session=session,
        reasons=decision.get("reasons", []),
    )
    _publish(ticket, "created")


async def decide(session: AsyncSession, ticket_id: str, approve: bool, actor: str, note: str = "") -> Ticket:
    ticket = await session.get(Ticket, ticket_id)
    if ticket is None:
        raise TicketError(f"ticket {ticket_id} not found")
    if ticket.status != TicketStatus.PENDING.value:
        raise InvalidTransition(f"ticket {ticket_id} is {ticket.status}, only PENDING tickets can be decided")
    new_status = TicketStatus.APPROVED.value if approve else TicketStatus.DENIED.value
    ticket.status = new_status
    ticket.decided_by = actor
    ticket.decided_at = utcnow()
    ticket.decision_note = note or ""
    await add_event(session, ticket, "approved" if approve else "denied", actor=actor, note=note)
    await audit.record(
        session,
        actor,
        "ticket.approve" if approve else "ticket.deny",
        "ticket",
        ticket.id,
        {"note": note, "agent_id": ticket.agent_id, "risk_score": ticket.risk_score},
    )
    await log_agent_event(
        ticket.agent_id,
        "decision." + new_status.lower(),
        ticket_id=ticket.id,
        correlation_id=ticket.correlation_id,
        session=session,
        by=actor,
        note=note,
    )
    await session.commit()
    hold_registry.resolve(ticket.id, new_status)
    _publish(ticket, "decided", by=actor)
    log.info("ticket.decided", ticket_id=ticket.id, status=new_status, by=actor)
    return ticket


async def bulk_decide(
    session: AsyncSession, ticket_ids: list[str], approve: bool, actor: str, note: str = ""
) -> dict[str, str]:
    results: dict[str, str] = {}
    for tid in ticket_ids:
        try:
            t = await decide(session, tid, approve, actor, note)
            results[tid] = t.status
        except TicketError as exc:
            results[tid] = f"error: {exc}"
    return results


async def mark_forwarding(session: AsyncSession, ticket: Ticket) -> None:
    ticket.status = TicketStatus.FORWARDING.value
    ticket.forwarded_at = utcnow()
    await add_event(session, ticket, "forwarding", upstream=ticket.upstream_url)
    await log_agent_event(
        ticket.agent_id,
        "request.forwarding",
        ticket_id=ticket.id,
        correlation_id=ticket.correlation_id,
        session=session,
        upstream=ticket.upstream_url,
    )
    _publish(ticket, "forwarding")


async def mark_completed(
    session: AsyncSession,
    ticket: Ticket,
    *,
    status_code: int,
    headers: dict[str, str],
    body: str,
    latency_ms: float,
    response_findings: list[dict[str, Any]] | None = None,
    response_preview: str = "",
) -> None:
    settings = get_settings()
    ticket.status = TicketStatus.COMPLETED.value if status_code < 500 else TicketStatus.FAILED.value
    ticket.response_status = status_code
    ticket.response_headers = headers
    ticket.response_body = body[: settings.max_stored_response_bytes]
    ticket.response_preview = response_preview[:500]
    ticket.response_findings = response_findings or []
    ticket.latency_ms = latency_ms
    await add_event(
        session,
        ticket,
        "completed",
        status_code=status_code,
        latency_ms=latency_ms,
        response_findings=len(ticket.response_findings),
    )
    await log_agent_event(
        ticket.agent_id,
        "request.completed",
        ticket_id=ticket.id,
        correlation_id=ticket.correlation_id,
        session=session,
        status_code=status_code,
        latency_ms=latency_ms,
        response_findings=[f.get("title") for f in ticket.response_findings[:8]],
    )
    _publish(ticket, "completed")


async def mark_failed(session: AsyncSession, ticket: Ticket, error: str) -> None:
    ticket.status = TicketStatus.FAILED.value
    ticket.error = error[:4000]
    await add_event(session, ticket, "failed", error=error[:500])
    await log_agent_event(
        ticket.agent_id,
        "request.failed",
        level="ERROR",
        ticket_id=ticket.id,
        correlation_id=ticket.correlation_id,
        session=session,
        error=error[:500],
    )
    _publish(ticket, "failed")


async def mark_expired(session: AsyncSession, ticket: Ticket) -> None:
    if ticket.status != TicketStatus.PENDING.value:
        return
    ticket.status = TicketStatus.EXPIRED.value
    ticket.decided_by = "timeout"
    ticket.decided_at = utcnow()
    await add_event(session, ticket, "expired")
    await log_agent_event(
        ticket.agent_id,
        "request.expired",
        level="WARNING",
        ticket_id=ticket.id,
        correlation_id=ticket.correlation_id,
        session=session,
    )
    hold_registry.resolve(ticket.id, TicketStatus.EXPIRED.value)
    _publish(ticket, "expired")


async def expire_stale(session: AsyncSession) -> int:
    """Background sweep: any PENDING ticket past expires_at becomes EXPIRED."""
    now = utcnow()
    rows = list(
        (
            await session.execute(
                select(Ticket).where(Ticket.status == TicketStatus.PENDING.value, Ticket.expires_at < now)
            )
        ).scalars()
    )
    for t in rows:
        await mark_expired(session, t)
    return len(rows)


async def purge_old(session: AsyncSession, days: int) -> int:
    cutoff = utcnow() - timedelta(days=days)
    rows = list((await session.execute(select(Ticket.id).where(Ticket.created_at < cutoff))).scalars())
    for tid in rows:
        t = await session.get(Ticket, tid)
        if t:
            await session.delete(t)
    return len(rows)


async def get_ticket(session: AsyncSession, ticket_id: str) -> Ticket | None:
    if ticket_id.isdigit():
        return (
            await session.execute(select(Ticket).where(Ticket.number == int(ticket_id)))
        ).scalar_one_or_none()
    return await session.get(Ticket, ticket_id)


async def list_tickets(
    session: AsyncSession,
    *,
    status: str | list[str] | None = None,
    agent_id: str | None = None,
    min_risk: int | None = None,
    model: str | None = None,
    source: str | None = None,
    campaign_id: str | None = None,
    search: str | None = None,
    since: Any = None,
    until: Any = None,
    limit: int = 50,
    offset: int = 0,
    order: str = "desc",
) -> tuple[list[Ticket], int]:
    q = select(Ticket)
    if status:
        statuses = [status] if isinstance(status, str) else status
        q = q.where(Ticket.status.in_([s.upper() for s in statuses]))
    if agent_id:
        q = q.where(Ticket.agent_id == agent_id)
    if min_risk is not None:
        q = q.where(Ticket.risk_score >= min_risk)
    if model:
        q = q.where(Ticket.model == model)
    if source:
        q = q.where(Ticket.source == source)
    if campaign_id:
        q = q.where(Ticket.campaign_id == campaign_id)
    if search:
        like = f"%{search}%"
        q = q.where(
            (Ticket.prompt_preview.ilike(like))
            | (Ticket.id.ilike(like))
            | (Ticket.path.ilike(like))
            | (Ticket.correlation_id.ilike(like))
        )
    if since is not None:
        q = q.where(Ticket.created_at >= since)
    if until is not None:
        q = q.where(Ticket.created_at <= until)
    total = int((await session.execute(select(func.count()).select_from(q.subquery()))).scalar_one())
    q = (
        q.order_by(Ticket.created_at.desc() if order == "desc" else Ticket.created_at.asc())
        .limit(limit)
        .offset(offset)
    )
    return list((await session.execute(q)).scalars().unique()), total


async def list_events(session: AsyncSession, ticket_id: str) -> list[TicketEvent]:
    return list(
        (
            await session.execute(
                select(TicketEvent).where(TicketEvent.ticket_id == ticket_id).order_by(TicketEvent.id.asc())
            )
        ).scalars()
    )


async def stats(session: AsyncSession) -> dict[str, Any]:
    by_status = {
        s: int(c)
        for s, c in (
            await session.execute(select(Ticket.status, func.count(Ticket.id)).group_by(Ticket.status))
        ).all()
    }
    by_level = {
        s: int(c)
        for s, c in (
            await session.execute(
                select(Ticket.risk_level, func.count(Ticket.id)).group_by(Ticket.risk_level)
            )
        ).all()
    }
    day_ago = utcnow() - timedelta(hours=24)
    last_24h = int(
        (
            await session.execute(select(func.count(Ticket.id)).where(Ticket.created_at >= day_ago))
        ).scalar_one()
    )
    avg_latency = (
        await session.execute(select(func.avg(Ticket.latency_ms)).where(Ticket.latency_ms.is_not(None)))
    ).scalar_one()
    avg_decision = (
        (
            await session.execute(
                select(func.avg(func.julianday(Ticket.decided_at) - func.julianday(Ticket.created_at))).where(
                    Ticket.decided_by.is_not(None), Ticket.decided_by != "policy"
                )
            )
        ).scalar_one()
        if get_settings().database_url.startswith("sqlite")
        else None
    )
    by_agent = [
        {"agent_id": a, "count": int(c)}
        for a, c in (
            await session.execute(select(Ticket.agent_id, func.count(Ticket.id)).group_by(Ticket.agent_id))
        ).all()
    ]
    return {
        "total": sum(by_status.values()),
        "pending": by_status.get("PENDING", 0),
        "by_status": by_status,
        "by_risk_level": by_level,
        "last_24h": last_24h,
        "avg_upstream_latency_ms": round(float(avg_latency), 1) if avg_latency else None,
        "avg_human_decision_seconds": round(float(avg_decision) * 86400, 1) if avg_decision else None,
        "by_agent": by_agent,
    }


def ticket_to_dict(t: Ticket, brief: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {
        "id": t.id,
        "number": t.number,
        "agent_id": t.agent_id,
        "agent_name": getattr(getattr(t, "agent", None), "name", None),
        "status": t.status,
        "source": t.source,
        "correlation_id": t.correlation_id,
        "method": t.method,
        "path": t.path,
        "model": t.model,
        "is_stream": t.is_stream,
        "prompt_preview": t.prompt_preview,
        "risk_score": t.risk_score,
        "risk_level": t.risk_level,
        "finding_count": len(t.findings or []),
        "policy_action": (t.policy_decision or {}).get("action"),
        "decided_by": t.decided_by,
        "decision_note": t.decision_note,
        "decided_at": t.decided_at.isoformat() if t.decided_at else None,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "response_status": t.response_status,
        "latency_ms": t.latency_ms,
        "campaign_id": t.campaign_id,
        "probe_id": t.probe_id,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }
    if brief:
        return d
    d.update(
        {
            "client_ip": t.client_ip,
            "user_agent": t.user_agent,
            "upstream_url": t.upstream_url,
            "request_headers": t.request_headers,
            "request_body": t.request_body,
            "request_json": t.request_json,
            "normalized": t.normalized,
            "findings": t.findings or [],
            "analysis_ms": t.analysis_ms,
            "policy_decision": t.policy_decision or {},
            "forwarded_at": t.forwarded_at.isoformat() if t.forwarded_at else None,
            "response_headers": t.response_headers or {},
            "response_body": t.response_body,
            "response_preview": t.response_preview,
            "response_findings": t.response_findings or [],
            "error": t.error,
        }
    )
    return d


def event_to_dict(e: TicketEvent) -> dict[str, Any]:
    return {
        "id": e.id,
        "ticket_id": e.ticket_id,
        "ts": e.ts.isoformat() if e.ts else None,
        "event_type": e.event_type,
        "actor": e.actor,
        "detail": e.detail or {},
    }
