"""Reviewer REST API for the red-team engine: corpus browsing, campaign lifecycle and results."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..agents import service as agents
from ..audit import service as audit
from ..auth import Principal, current_principal, require_role
from ..db import get_session
from ..models import CampaignStatus
from . import service
from .corpus import get_probes, list_categories
from .engine import campaign_runner
from .mutators import MUTATOR_NAMES

router = APIRouter(prefix="/api/redteam", tags=["redteam"])


class CampaignIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    agent_id: str
    target_model: str = ""
    categories: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)
    max_probes: int | None = None
    mutators: list[str] = Field(default_factory=list)
    system_prompt: str = ""
    path: str = "v1/chat/completions"
    concurrency: int | None = None
    seed: int | None = None
    extra_body: dict[str, Any] = Field(default_factory=dict)
    auto_start: bool = False


@router.get("/corpus")
async def get_corpus(_: Principal = Depends(current_principal)) -> dict[str, Any]:
    categories = list_categories()
    return {"categories": categories, "total": sum(c["probe_count"] for c in categories), "mutators": MUTATOR_NAMES}


@router.get("/corpus/probes")
async def corpus_probes(
    category: str | None = None,
    technique: str | None = None,
    severity: str | None = None,
    search: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _: Principal = Depends(current_principal),
) -> dict[str, Any]:
    probes = get_probes(
        categories=category or None,
        techniques=technique or None,
        severities=severity or None,
        search=search or None,
    )
    total = len(probes)
    window = probes[offset : offset + limit]
    return {"items": [p.to_dict() for p in window], "total": total}


@router.get("/campaigns")
async def list_campaigns(
    status: str | None = None,
    agent_id: str | None = None,
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    return await service.list_campaigns(session, status=status, agent_id=agent_id)


@router.post("/campaigns", status_code=201)
async def create_campaign(
    payload: CampaignIn,
    request: Request,
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    agent = await agents.get_agent(session, payload.agent_id)
    if agent is None:
        raise HTTPException(404, f"agent {payload.agent_id} not found")
    campaign = await campaign_runner.create_campaign(
        session,
        name=payload.name,
        agent_id=payload.agent_id,
        target_model=payload.target_model,
        categories=payload.categories,
        techniques=payload.techniques,
        max_probes=payload.max_probes,
        mutators=payload.mutators,
        system_prompt=payload.system_prompt,
        path=payload.path,
        concurrency=payload.concurrency,
        created_by=p.username,
        seed=payload.seed,
        extra_body=payload.extra_body,
    )
    await audit.record(session, p.username, "redteam.campaign.create", "campaign", campaign.id, {"agent_id": payload.agent_id, "total_probes": campaign.total_probes})
    await session.commit()
    campaign_id = campaign.id
    if payload.auto_start:
        await campaign_runner.start(campaign_id, request.app.state.http)
        await audit.record(session, p.username, "redteam.campaign.start", "campaign", campaign_id)
        await session.commit()
    result = await service.get_campaign_dict(session, campaign_id)
    if result is None:
        raise HTTPException(404, "campaign not found")
    return result


async def _campaign_or_404(session: AsyncSession, campaign_id: str) -> dict[str, Any]:
    result = await service.get_campaign_dict(session, campaign_id)
    if result is None:
        raise HTTPException(404, "campaign not found")
    return result


@router.get("/campaigns/{campaign_id}")
async def get_campaign(campaign_id: str, _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    return await _campaign_or_404(session, campaign_id)


@router.post("/campaigns/{campaign_id}/start")
async def start_campaign(campaign_id: str, request: Request, p: Principal = Depends(require_role("reviewer")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    campaign = await service.get_campaign(session, campaign_id)
    if campaign is None:
        raise HTTPException(404, "campaign not found")
    if campaign.status in (CampaignStatus.RUNNING.value, CampaignStatus.COMPLETED.value):
        raise HTTPException(409, f"campaign is {campaign.status}")
    await campaign_runner.start(campaign_id, request.app.state.http)
    await audit.record(session, p.username, "redteam.campaign.start", "campaign", campaign_id)
    await session.commit()
    return await _campaign_or_404(session, campaign_id)


@router.post("/campaigns/{campaign_id}/pause")
async def pause_campaign(campaign_id: str, p: Principal = Depends(require_role("reviewer")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    campaign = await service.get_campaign(session, campaign_id)
    if campaign is None:
        raise HTTPException(404, "campaign not found")
    await campaign_runner.pause(campaign_id)
    return await _campaign_or_404(session, campaign_id)


@router.post("/campaigns/{campaign_id}/resume")
async def resume_campaign(campaign_id: str, request: Request, p: Principal = Depends(require_role("reviewer")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    campaign = await service.get_campaign(session, campaign_id)
    if campaign is None:
        raise HTTPException(404, "campaign not found")
    await campaign_runner.resume(campaign_id, request.app.state.http)
    return await _campaign_or_404(session, campaign_id)


@router.post("/campaigns/{campaign_id}/cancel")
async def cancel_campaign(campaign_id: str, p: Principal = Depends(require_role("reviewer")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    campaign = await service.get_campaign(session, campaign_id)
    if campaign is None:
        raise HTTPException(404, "campaign not found")
    await campaign_runner.cancel(campaign_id)
    await audit.record(session, p.username, "redteam.campaign.cancel", "campaign", campaign_id)
    await session.commit()
    return await _campaign_or_404(session, campaign_id)


@router.delete("/campaigns/{campaign_id}")
async def delete_campaign(campaign_id: str, p: Principal = Depends(require_role("reviewer")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    await campaign_runner.cancel(campaign_id)
    deleted = await service.delete_campaign(session, campaign_id)
    if not deleted:
        raise HTTPException(404, "campaign not found")
    await audit.record(session, p.username, "redteam.campaign.delete", "campaign", campaign_id)
    await session.commit()
    return {"deleted": campaign_id}


@router.get("/campaigns/{campaign_id}/results")
async def campaign_results(
    campaign_id: str,
    verdict: str | None = None,
    category: str | None = None,
    technique: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    campaign = await service.get_campaign(session, campaign_id)
    if campaign is None:
        raise HTTPException(404, "campaign not found")
    items, total = await service.list_results(session, campaign_id, verdict=verdict, category=category, technique=technique, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/campaigns/{campaign_id}/summary")
async def campaign_summary(campaign_id: str, _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    campaign = await service.get_campaign(session, campaign_id)
    if campaign is None:
        raise HTTPException(404, "campaign not found")
    if campaign.summary:
        return campaign.summary
    summary = await service.recompute_summary(session, campaign_id)
    await session.commit()
    return summary or {}
