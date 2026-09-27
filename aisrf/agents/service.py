"""Agent registry and the per-agent activity logger."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import timedelta
from typing import Any

from sqlalchemy import desc, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import session_scope
from ..logging import agent_file_logger, broadcaster, get_logger, json_dumps
from ..models import Agent, AgentEvent, ScanToken, utcnow
from ..security import api_key_prefix, decrypt_secret, encrypt_secret, generate_api_key, hash_api_key

log = get_logger("aisrf.agents")

PROVIDER_DEFAULTS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "azure": "",
    "ollama": "http://localhost:11434/v1",
    "custom": "",
}


class AgentNotFound(Exception):
    pass


async def create_agent(
    session: AsyncSession,
    name: str,
    *,
    description: str = "",
    owner: str = "",
    tags: list[str] | None = None,
    upstream_provider: str = "openai",
    upstream_base_url: str | None = None,
    upstream_api_key: str | None = None,
    upstream_auth_header: str = "",
    upstream_extra_headers: dict[str, str] | None = None,
    require_approval: bool = True,
    auto_approve_below_risk: int = 0,
    auto_deny_at_risk: int = 90,
    auto_deny_patterns: list[str] | None = None,
    allowed_paths: list[str] | None = None,
    allowed_models: list[str] | None = None,
    rate_limit_per_minute: int = 0,
    inject_canary: bool = False,
) -> tuple[Agent, str]:
    raw_key = generate_api_key()
    agent = Agent(
        name=name,
        description=description,
        owner=owner,
        tags=tags or [],
        api_key_hash=hash_api_key(raw_key),
        api_key_prefix=api_key_prefix(raw_key),
        upstream_provider=upstream_provider,
        upstream_base_url=(upstream_base_url or PROVIDER_DEFAULTS.get(upstream_provider, "")).rstrip("/"),
        upstream_api_key_encrypted=encrypt_secret(upstream_api_key),
        upstream_auth_header=upstream_auth_header,
        upstream_extra_headers=upstream_extra_headers or {},
        require_approval=require_approval,
        auto_approve_below_risk=auto_approve_below_risk,
        auto_deny_at_risk=auto_deny_at_risk,
        auto_deny_patterns=auto_deny_patterns or [],
        allowed_paths=allowed_paths or [],
        allowed_models=allowed_models or [],
        rate_limit_per_minute=rate_limit_per_minute,
        inject_canary=inject_canary,
    )
    session.add(agent)
    await session.flush()
    log.info("agent.created", agent_id=agent.id, name=name, provider=upstream_provider)
    return agent, raw_key


async def rotate_api_key(session: AsyncSession, agent: Agent) -> str:
    raw_key = generate_api_key()
    agent.api_key_hash = hash_api_key(raw_key)
    agent.api_key_prefix = api_key_prefix(raw_key)
    await session.flush()
    return raw_key


async def update_agent(session: AsyncSession, agent: Agent, changes: dict[str, Any]) -> Agent:
    for key, value in changes.items():
        if value is None:
            continue
        if key == "upstream_api_key":
            agent.upstream_api_key_encrypted = encrypt_secret(value)
        elif key == "upstream_base_url":
            agent.upstream_base_url = value.rstrip("/")
        elif hasattr(agent, key) and key not in {"id", "api_key_hash", "api_key_prefix", "created_at"}:
            setattr(agent, key, value)
    agent.updated_at = utcnow()
    await session.flush()
    return agent


async def get_agent(session: AsyncSession, agent_id: str) -> Agent | None:
    return await session.get(Agent, agent_id)


async def get_agent_by_name(session: AsyncSession, name: str) -> Agent | None:
    return (await session.execute(select(Agent).where(Agent.name == name))).scalar_one_or_none()


async def list_agents(session: AsyncSession, include_inactive: bool = True) -> list[Agent]:
    q = select(Agent).order_by(Agent.created_at.asc())
    if not include_inactive:
        q = q.where(Agent.is_active.is_(True))
    return list((await session.execute(q)).scalars())


async def authenticate_api_key(session: AsyncSession, raw_key: str | None) -> Agent | None:
    if not raw_key:
        return None
    digest = hash_api_key(raw_key)
    agent = (await session.execute(select(Agent).where(Agent.api_key_hash == digest))).scalar_one_or_none()
    if agent is None and raw_key.startswith(SCAN_TOKEN_PREFIX):
        tok = (
            await session.execute(select(ScanToken).where(ScanToken.token_hash == digest))
        ).scalar_one_or_none()
        if tok is None or tok.revoked:
            return None
        exp = tok.expires_at if tok.expires_at.tzinfo else tok.expires_at.replace(tzinfo=utcnow().tzinfo)
        if exp < utcnow():
            return None
        agent = await session.get(Agent, tok.agent_id)
    if agent is None or not agent.is_active:
        return None
    return agent


SCAN_TOKEN_PREFIX = "aisrf_scan_"


async def mint_scan_token(
    session: AsyncSession,
    agent_id: str,
    *,
    ttl_seconds: int = 3600,
    purpose: str = "",
    campaign_id: str | None = None,
    created_by: str = "system",
) -> tuple[ScanToken, str]:
    """Create a short-lived token that external scanners use to send traffic through the gateway as this agent."""
    import secrets as _secrets

    raw = SCAN_TOKEN_PREFIX + _secrets.token_urlsafe(32)
    tok = ScanToken(
        agent_id=agent_id,
        token_hash=hash_api_key(raw),
        purpose=purpose,
        campaign_id=campaign_id,
        created_by=created_by,
        expires_at=utcnow() + timedelta(seconds=ttl_seconds),
    )
    session.add(tok)
    await session.flush()
    log.info(
        "agent.scan_token_minted",
        agent_id=agent_id,
        purpose=purpose,
        campaign_id=campaign_id,
        ttl=ttl_seconds,
    )
    return tok, raw


async def revoke_scan_tokens(
    session: AsyncSession, *, campaign_id: str | None = None, agent_id: str | None = None
) -> int:
    q = update(ScanToken).where(ScanToken.revoked.is_(False))
    if campaign_id:
        q = q.where(ScanToken.campaign_id == campaign_id)
    if agent_id:
        q = q.where(ScanToken.agent_id == agent_id)
    res = await session.execute(q.values(revoked=True))
    return int(res.rowcount or 0)


async def touch_agent(session: AsyncSession, agent_id: str) -> None:
    await session.execute(
        update(Agent)
        .where(Agent.id == agent_id)
        .values(request_count=Agent.request_count + 1, last_seen_at=utcnow())
    )


def upstream_api_key(agent: Agent) -> str | None:
    return decrypt_secret(agent.upstream_api_key_encrypted)


def agent_to_dict(agent: Agent, include_stats: bool = True) -> dict[str, Any]:
    return {
        "id": agent.id,
        "name": agent.name,
        "description": agent.description,
        "owner": agent.owner,
        "tags": agent.tags or [],
        "api_key_prefix": agent.api_key_prefix,
        "upstream_provider": agent.upstream_provider,
        "upstream_base_url": agent.upstream_base_url,
        "has_upstream_key": bool(agent.upstream_api_key_encrypted),
        "upstream_auth_header": agent.upstream_auth_header,
        "upstream_extra_headers": agent.upstream_extra_headers or {},
        "require_approval": agent.require_approval,
        "auto_approve_below_risk": agent.auto_approve_below_risk,
        "auto_deny_at_risk": agent.auto_deny_at_risk,
        "auto_deny_patterns": agent.auto_deny_patterns or [],
        "allowed_paths": agent.allowed_paths or [],
        "allowed_models": agent.allowed_models or [],
        "rate_limit_per_minute": agent.rate_limit_per_minute,
        "inject_canary": bool(agent.inject_canary),
        "is_active": agent.is_active,
        "request_count": agent.request_count if include_stats else None,
        "last_seen_at": agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
    }


# --- rate limiting (in-process sliding window) ----------------------------------
_windows: dict[str, deque] = defaultdict(deque)


def check_rate_limit(agent: Agent) -> bool:
    """Returns True when the request is allowed."""
    if not agent.rate_limit_per_minute:
        return True
    now = time.monotonic()
    window = _windows[agent.id]
    while window and now - window[0] > 60:
        window.popleft()
    if len(window) >= agent.rate_limit_per_minute:
        return False
    window.append(now)
    return True


# --- per-agent activity log ------------------------------------------------------
async def log_agent_event(
    agent_id: str,
    event: str,
    *,
    level: str = "INFO",
    ticket_id: str | None = None,
    correlation_id: str | None = None,
    session: AsyncSession | None = None,
    **detail: Any,
) -> None:
    """Write one agent-scoped event to structlog, the agent's own log file, the DB and the live stream."""
    record = {
        "ts": utcnow().isoformat(),
        "agent_id": agent_id,
        "level": level,
        "event": event,
        "ticket_id": ticket_id,
        "correlation_id": correlation_id,
        **detail,
    }
    getattr(log, level.lower(), log.info)(
        f"agent.{event}", **{k: v for k, v in record.items() if k not in {"ts", "level", "event"}}
    )
    agent_file_logger(agent_id).info(json_dumps(record))
    broadcaster.publish("logs", record)
    row = AgentEvent(
        agent_id=agent_id,
        level=level,
        event=event,
        ticket_id=ticket_id,
        correlation_id=correlation_id,
        detail=detail,
    )
    if session is not None:
        session.add(row)
        await session.flush()
    else:
        async with session_scope() as s:
            s.add(row)


async def list_agent_events(
    session: AsyncSession,
    agent_id: str | None = None,
    ticket_id: str | None = None,
    limit: int = 200,
    offset: int = 0,
    level: str | None = None,
) -> list[AgentEvent]:
    q = select(AgentEvent).order_by(desc(AgentEvent.id))
    if agent_id:
        q = q.where(AgentEvent.agent_id == agent_id)
    if ticket_id:
        q = q.where(AgentEvent.ticket_id == ticket_id)
    if level:
        q = q.where(AgentEvent.level == level.upper())
    return list((await session.execute(q.limit(limit).offset(offset))).scalars())


async def agent_stats(session: AsyncSession, agent_id: str) -> dict[str, Any]:
    from ..models import Ticket

    rows = (
        await session.execute(
            select(Ticket.status, func.count(Ticket.id))
            .where(Ticket.agent_id == agent_id)
            .group_by(Ticket.status)
        )
    ).all()
    by_status = {status: int(count) for status, count in rows}
    avg_risk = (
        await session.execute(select(func.avg(Ticket.risk_score)).where(Ticket.agent_id == agent_id))
    ).scalar_one()
    return {
        "by_status": by_status,
        "total": sum(by_status.values()),
        "avg_risk": round(float(avg_risk or 0), 1),
    }


def event_to_dict(e: AgentEvent) -> dict[str, Any]:
    return {
        "id": e.id,
        "agent_id": e.agent_id,
        "ts": e.ts.isoformat() if e.ts else None,
        "level": e.level,
        "event": e.event,
        "ticket_id": e.ticket_id,
        "correlation_id": e.correlation_id,
        "detail": e.detail or {},
    }
