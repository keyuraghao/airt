"""Query and serialisation helpers for campaigns and probe results."""
from __future__ import annotations

from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Agent, Campaign, ProbeResult
from .corpus import get_probe
from .engine import build_summary


def _progress(campaign: Campaign) -> float:
    total = int(campaign.total_probes or 0)
    if total <= 0:
        return 0.0
    return round(100.0 * int(campaign.completed_probes or 0) / total, 1)


def campaign_to_dict(campaign: Campaign, agent_name: str | None = None) -> dict[str, Any]:
    return {
        "id": campaign.id,
        "name": campaign.name,
        "agent_id": campaign.agent_id,
        "agent_name": agent_name,
        "target_model": campaign.target_model,
        "status": campaign.status,
        "config": campaign.config or {},
        "summary": campaign.summary or {},
        "total_probes": campaign.total_probes,
        "completed_probes": campaign.completed_probes,
        "progress": _progress(campaign),
        "created_by": campaign.created_by,
        "created_at": campaign.created_at.isoformat() if campaign.created_at else None,
        "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
        "finished_at": campaign.finished_at.isoformat() if campaign.finished_at else None,
        "error": campaign.error or "",
    }


def result_to_dict(result: ProbeResult) -> dict[str, Any]:
    probe = get_probe(str(result.probe_id).split("+", 1)[0])
    return {
        "id": result.id,
        "campaign_id": result.campaign_id,
        "probe_id": result.probe_id,
        "category": result.category,
        "technique": result.technique,
        "severity": result.severity,
        "name": probe.name if probe else "",
        "prompt": result.prompt,
        "messages": result.messages or [],
        "response": result.response or "",
        "verdict": result.verdict,
        "confidence": round(float(result.confidence or 0), 3),
        "evidence": result.evidence or {},
        "ticket_id": result.ticket_id,
        "latency_ms": result.latency_ms,
        "ts": result.ts.isoformat() if result.ts else None,
    }


async def _agent_names(session: AsyncSession, campaigns: list[Campaign]) -> dict[str, str]:
    ids = {c.agent_id for c in campaigns}
    if not ids:
        return {}
    rows = (await session.execute(select(Agent.id, Agent.name).where(Agent.id.in_(ids)))).all()
    return {aid: name for aid, name in rows}


async def list_campaigns(session: AsyncSession, *, status: str | None = None, agent_id: str | None = None) -> list[dict[str, Any]]:
    q = select(Campaign).order_by(Campaign.created_at.desc())
    if status:
        q = q.where(Campaign.status == status.upper())
    if agent_id:
        q = q.where(Campaign.agent_id == agent_id)
    campaigns = list((await session.execute(q)).scalars())
    names = await _agent_names(session, campaigns)
    return [campaign_to_dict(c, names.get(c.agent_id)) for c in campaigns]


async def get_campaign(session: AsyncSession, campaign_id: str) -> Campaign | None:
    return await session.get(Campaign, campaign_id)


async def get_campaign_dict(session: AsyncSession, campaign_id: str) -> dict[str, Any] | None:
    campaign = await session.get(Campaign, campaign_id)
    if campaign is None:
        return None
    agent = await session.get(Agent, campaign.agent_id)
    return campaign_to_dict(campaign, agent.name if agent else None)


async def list_results(
    session: AsyncSession,
    campaign_id: str,
    *,
    verdict: str | None = None,
    category: str | None = None,
    technique: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    q = select(ProbeResult).where(ProbeResult.campaign_id == campaign_id)
    if verdict:
        q = q.where(ProbeResult.verdict == verdict.upper())
    if category:
        q = q.where(ProbeResult.category == category)
    if technique:
        q = q.where(ProbeResult.technique == technique)
    total = int((await session.execute(select(func.count()).select_from(q.subquery()))).scalar_one())
    q = q.order_by(ProbeResult.ts.asc(), ProbeResult.id.asc()).limit(limit).offset(offset)
    rows = list((await session.execute(q)).scalars())
    return [result_to_dict(r) for r in rows], total


async def delete_campaign(session: AsyncSession, campaign_id: str) -> bool:
    campaign = await session.get(Campaign, campaign_id)
    if campaign is None:
        return False
    await session.execute(delete(ProbeResult).where(ProbeResult.campaign_id == campaign_id))
    await session.delete(campaign)
    return True


async def recompute_summary(session: AsyncSession, campaign_id: str) -> dict[str, Any] | None:
    campaign = await session.get(Campaign, campaign_id)
    if campaign is None:
        return None
    rows = list((await session.execute(select(ProbeResult).where(ProbeResult.campaign_id == campaign_id))).scalars())
    duration = None
    if campaign.started_at and campaign.finished_at:
        duration = round((campaign.finished_at - campaign.started_at).total_seconds(), 2)
    summary = build_summary(rows, duration)
    campaign.summary = summary
    await session.flush()
    return summary
