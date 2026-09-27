"""Admin REST API for agents (registered clients) and their activity logs."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..audit import service as audit
from ..auth import Principal, current_principal, require_role
from ..db import get_session
from . import service as agents

router = APIRouter(prefix="/api/agents", tags=["agents"])


class AgentIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    owner: str = ""
    tags: list[str] = []
    upstream_provider: str = "openai"
    upstream_base_url: str | None = None
    upstream_api_key: str | None = None
    upstream_auth_header: str = ""
    upstream_extra_headers: dict[str, str] = {}
    require_approval: bool = True
    auto_approve_below_risk: int = Field(default=0, ge=0, le=100)
    auto_deny_at_risk: int = Field(default=90, ge=0, le=101)
    auto_deny_patterns: list[str] = []
    allowed_paths: list[str] = []
    allowed_models: list[str] = []
    rate_limit_per_minute: int = Field(default=0, ge=0)
    inject_canary: bool = False


class AgentPatch(BaseModel):
    name: str | None = None
    description: str | None = None
    owner: str | None = None
    tags: list[str] | None = None
    upstream_provider: str | None = None
    upstream_base_url: str | None = None
    upstream_api_key: str | None = None
    upstream_auth_header: str | None = None
    upstream_extra_headers: dict[str, str] | None = None
    require_approval: bool | None = None
    auto_approve_below_risk: int | None = Field(default=None, ge=0, le=100)
    auto_deny_at_risk: int | None = Field(default=None, ge=0, le=101)
    auto_deny_patterns: list[str] | None = None
    allowed_paths: list[str] | None = None
    allowed_models: list[str] | None = None
    rate_limit_per_minute: int | None = Field(default=None, ge=0)
    inject_canary: bool | None = None
    is_active: bool | None = None


@router.get("")
async def list_agents(include_inactive: bool = True, _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    return [agents.agent_to_dict(a) for a in await agents.list_agents(session, include_inactive)]


@router.post("", status_code=201)
async def create_agent(payload: AgentIn, p: Principal = Depends(require_role("admin")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    if await agents.get_agent_by_name(session, payload.name):
        raise HTTPException(409, "an agent with this name already exists")
    agent, raw_key = await agents.create_agent(session, **payload.model_dump())
    await audit.record(session, p.username, "agent.create", "agent", agent.id, {"name": agent.name, "provider": agent.upstream_provider})
    await session.commit()
    return {**agents.agent_to_dict(agent), "api_key": raw_key}


@router.get("/{agent_id}")
async def get_agent(agent_id: str, _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    a = await agents.get_agent(session, agent_id) or await agents.get_agent_by_name(session, agent_id)
    if a is None:
        raise HTTPException(404, "agent not found")
    return {**agents.agent_to_dict(a), "stats": await agents.agent_stats(session, a.id)}


@router.patch("/{agent_id}")
async def patch_agent(agent_id: str, payload: AgentPatch, p: Principal = Depends(require_role("admin")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    a = await agents.get_agent(session, agent_id)
    if a is None:
        raise HTTPException(404, "agent not found")
    changes = payload.model_dump(exclude_none=True)
    await agents.update_agent(session, a, changes)
    await audit.record(session, p.username, "agent.update", "agent", a.id, {k: ("[secret]" if k == "upstream_api_key" else v) for k, v in changes.items()})
    await session.commit()
    return agents.agent_to_dict(a)


@router.post("/{agent_id}/rotate-key")
async def rotate_key(agent_id: str, p: Principal = Depends(require_role("admin")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    a = await agents.get_agent(session, agent_id)
    if a is None:
        raise HTTPException(404, "agent not found")
    key = await agents.rotate_api_key(session, a)
    await audit.record(session, p.username, "agent.rotate_key", "agent", a.id)
    await session.commit()
    return {"id": a.id, "api_key": key}


@router.delete("/{agent_id}")
async def disable_agent(agent_id: str, p: Principal = Depends(require_role("admin")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    a = await agents.get_agent(session, agent_id)
    if a is None:
        raise HTTPException(404, "agent not found")
    a.is_active = False
    await audit.record(session, p.username, "agent.disable", "agent", a.id)
    await session.commit()
    return {"id": a.id, "is_active": False}


@router.get("/{agent_id}/events")
async def agent_events(agent_id: str, limit: int = Query(200, le=2000), offset: int = 0, level: str | None = None, _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    return [agents.event_to_dict(e) for e in await agents.list_agent_events(session, agent_id=agent_id, limit=limit, offset=offset, level=level)]


@router.get("/{agent_id}/stats")
async def agent_stats(agent_id: str, _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return await agents.agent_stats(session, agent_id)
