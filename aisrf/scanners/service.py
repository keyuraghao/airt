"""Service layer for scan campaigns: creation, single runs, matrix runs and cross-target comparison."""

from __future__ import annotations

from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..logging import get_logger
from ..models import Agent, Campaign, CampaignStatus, ProbeResult, new_id, utcnow
from . import base

log = get_logger("aisrf.scanners.service")


async def create_scan_campaign(
    session: AsyncSession,
    *,
    engine: str,
    name: str,
    agent_id: str,
    target_model: str,
    options: dict[str, Any] | None = None,
    created_by: str = "",
    group_id: str | None = None,
) -> Campaign:
    """Create a Campaign row for an external scan engine and materialise its planned probe count."""
    scan_engine = base.get_engine(engine)
    if scan_engine is None:
        raise ValueError(f"unknown scan engine {engine!r}")
    options = dict(options or {})
    try:
        planned = scan_engine.plan(options)
    except Exception as exc:
        log.warning("scanners.plan.failed", engine=engine, error=str(exc))
        planned = []
    config: dict[str, Any] = {
        "engine": engine,
        "options": options,
        "targets": [{"agent_id": agent_id, "target_model": target_model}],
        "planned_probes": planned,
    }
    if group_id:
        config["group_id"] = group_id
    campaign = Campaign(
        name=name,
        agent_id=agent_id,
        target_model=target_model,
        status=CampaignStatus.CREATED.value,
        config=config,
        summary={},
        total_probes=len(planned),
        completed_probes=0,
        created_by=created_by,
    )
    session.add(campaign)
    await session.flush()
    log.info(
        "scanners.campaign.created",
        campaign_id=campaign.id,
        engine=engine,
        agent_id=agent_id,
        planned=len(planned),
    )
    from ..logging import broadcaster

    broadcaster.publish(
        "campaigns", {"event": "campaign.status", "campaign_id": campaign.id, "status": campaign.status}
    )
    return campaign


async def start_campaign(campaign_id: str, http: httpx.AsyncClient) -> None:
    await base.scan_runner.start(campaign_id, http)


async def cancel_campaign(campaign_id: str) -> None:
    await base.scan_runner.cancel(campaign_id)
    await base.revoke_tokens(campaign_id)


async def run_matrix(
    session: AsyncSession,
    *,
    engine: str,
    name: str,
    targets: list[dict[str, str]],
    options: dict[str, Any] | None = None,
    created_by: str = "",
) -> tuple[str, list[Campaign]]:
    """Create one sibling campaign per target, all sharing config["group_id"], for a concurrent matrix run."""
    if not targets:
        raise ValueError("matrix run needs at least one target")
    group_id = new_id("grp_")
    campaigns: list[Campaign] = []
    for target in targets:
        agent_id = target.get("agent_id")
        if not agent_id:
            raise ValueError("each matrix target needs an agent_id")
        agent = await session.get(Agent, agent_id)
        target_model = target.get("target_model") or ""
        label = f"{name} [{agent.name if agent else agent_id}:{target_model or 'default'}]"
        campaign = await create_scan_campaign(
            session,
            engine=engine,
            name=label,
            agent_id=agent_id,
            target_model=target_model,
            options=options,
            created_by=created_by,
            group_id=group_id,
        )
        campaigns.append(campaign)
    log.info("scanners.matrix.created", group_id=group_id, engine=engine, targets=len(campaigns))
    return group_id, campaigns


async def start_group(group_id: str, http: httpx.AsyncClient) -> None:
    for campaign_id in await _group_campaign_ids(group_id):
        await base.scan_runner.start(campaign_id, http)


async def _group_campaign_ids(group_id: str) -> list[str]:
    from ..db import session_scope

    async with session_scope() as session:
        campaigns = await _group_campaigns(session, group_id)
        return [c.id for c in campaigns]


async def _group_campaigns(session: AsyncSession, group_id: str) -> list[Campaign]:
    rows = list((await session.execute(select(Campaign).order_by(Campaign.created_at.asc()))).scalars())
    return [c for c in rows if (c.config or {}).get("group_id") == group_id]


async def compare(session: AsyncSession, group_id: str) -> dict[str, Any]:
    """Side-by-side comparison of every campaign in a matrix group for the dashboard and reports."""
    campaigns = await _group_campaigns(session, group_id)
    if not campaigns:
        return {"group_id": group_id, "targets": [], "categories": [], "matrix": {}, "ranking": []}
    agent_names = await _agent_names(session, campaigns)
    categories: set[str] = set()
    verdict_keys: set[str] = set()
    targets: list[dict[str, Any]] = []
    per_target_cat: dict[str, dict[str, dict[str, Any]]] = {}
    for campaign in campaigns:
        summary = campaign.summary or {}
        if not summary:
            rows = list(
                (
                    await session.execute(select(ProbeResult).where(ProbeResult.campaign_id == campaign.id))
                ).scalars()
            )
            summary = base.build_summary(rows)
        per_category = summary.get("per_category") or {}
        by_verdict = summary.get("by_verdict") or {}
        categories.update(per_category)
        verdict_keys.update(by_verdict)
        per_target_cat[campaign.id] = per_category
        targets.append(
            {
                "campaign_id": campaign.id,
                "agent_id": campaign.agent_id,
                "agent_name": agent_names.get(campaign.agent_id),
                "target_model": campaign.target_model,
                "status": campaign.status,
                "total_probes": campaign.total_probes,
                "completed_probes": campaign.completed_probes,
                "vulnerable": summary.get("vulnerable", 0),
                "vulnerability_rate": summary.get("vulnerability_rate", 0.0),
                "severity_weighted_score": summary.get("severity_weighted_score", 0.0),
                "false_refusal_rate": summary.get("false_refusal_rate", 0.0),
                "by_verdict": by_verdict,
            }
        )
    ordered_categories = sorted(categories)
    matrix: dict[str, dict[str, Any]] = {}
    for category in ordered_categories:
        matrix[category] = {}
        for campaign in campaigns:
            stats = per_target_cat.get(campaign.id, {}).get(category)
            matrix[category][campaign.id] = (
                {"tested": stats["tested"], "vulnerable": stats["vulnerable"], "rate": stats["rate"]}
                if stats
                else None
            )
    verdict_totals = {
        campaign.id: {
            vk: (campaign.summary or {}).get("by_verdict", {}).get(vk, 0) for vk in sorted(verdict_keys)
        }
        for campaign in campaigns
    }
    ranking = sorted(
        targets, key=lambda t: (t["severity_weighted_score"], t["vulnerability_rate"]), reverse=True
    )
    engine = str((campaigns[0].config or {}).get("engine") or "")
    return {
        "group_id": group_id,
        "engine": engine,
        "created_at": min((c.created_at for c in campaigns if c.created_at), default=utcnow()).isoformat(),
        "targets": targets,
        "categories": ordered_categories,
        "verdict_keys": sorted(verdict_keys),
        "matrix": matrix,
        "verdict_totals": verdict_totals,
        "ranking": [
            {
                "campaign_id": t["campaign_id"],
                "agent_name": t["agent_name"],
                "target_model": t["target_model"],
                "severity_weighted_score": t["severity_weighted_score"],
                "vulnerability_rate": t["vulnerability_rate"],
            }
            for t in ranking
        ],
        "most_vulnerable": ranking[0]["campaign_id"] if ranking else None,
        "least_vulnerable": ranking[-1]["campaign_id"] if ranking else None,
    }


async def _agent_names(session: AsyncSession, campaigns: list[Campaign]) -> dict[str, str]:
    ids = {c.agent_id for c in campaigns}
    if not ids:
        return {}
    rows = (await session.execute(select(Agent.id, Agent.name).where(Agent.id.in_(ids)))).all()
    return dict(rows)


def campaign_to_dict(campaign: Campaign, agent_name: str | None = None) -> dict[str, Any]:
    """Reuse the native serialisation so the dashboard, reports and MCP tools render scan campaigns."""
    try:
        from ..redteam.service import campaign_to_dict as native

        data = native(campaign, agent_name)
    except Exception:
        total = int(campaign.total_probes or 0)
        data = {
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
            "progress": round(100.0 * int(campaign.completed_probes or 0) / total, 1) if total else 0.0,
            "created_by": campaign.created_by,
            "created_at": campaign.created_at.isoformat() if campaign.created_at else None,
            "started_at": campaign.started_at.isoformat() if campaign.started_at else None,
            "finished_at": campaign.finished_at.isoformat() if campaign.finished_at else None,
            "error": campaign.error or "",
        }
    data["engine"] = str((campaign.config or {}).get("engine") or "")
    data["group_id"] = (campaign.config or {}).get("group_id")
    data["running"] = base.scan_runner.is_running(campaign.id)
    return data


async def get_campaign_dict(session: AsyncSession, campaign_id: str) -> dict[str, Any] | None:
    campaign = await session.get(Campaign, campaign_id)
    if campaign is None:
        return None
    agent = await session.get(Agent, campaign.agent_id)
    return campaign_to_dict(campaign, agent.name if agent else None)
