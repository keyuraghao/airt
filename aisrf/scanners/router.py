"""Reviewer REST API for the external scan engines, plus the PyRIT-Ship compatible surface."""
from __future__ import annotations

import contextlib
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..agents import service as agents
from ..audit import service as audit
from ..auth import Principal, current_principal, require_role
from ..db import get_session
from ..models import Campaign, CampaignStatus
from . import base, pyrit_ship, service

# ensure every engine registers itself when this module is imported
from . import garak as _garak  # noqa: F401
from . import promptfoo as _promptfoo  # noqa: F401
from . import pyrit as _pyrit  # noqa: F401
from . import pyrit_ship as _pyrit_ship  # noqa: F401
from .base import registry

router = APIRouter(prefix="/api/scanners", tags=["scanners"])


class CampaignIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    agent_id: str
    target_model: str = ""
    options: dict[str, Any] = Field(default_factory=dict)
    auto_start: bool = False


class TargetIn(BaseModel):
    agent_id: str
    target_model: str = ""


class MatrixIn(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    targets: list[TargetIn] = Field(min_length=1)
    options: dict[str, Any] = Field(default_factory=dict)
    auto_start: bool = False


def _engine_or_404(name: str) -> base.ScanEngine:
    engine = base.get_engine(name)
    if engine is None:
        raise HTTPException(404, f"unknown scan engine {name!r}")
    return engine


@router.get("")
@router.get("/")
async def list_engines(_: Principal = Depends(current_principal)) -> dict[str, Any]:
    engines = []
    for name in base.ENGINE_NAMES:
        engine = registry.get(name)
        if engine is None:
            continue
        try:
            installed = engine.installed()
        except Exception:
            installed = False
        entry: dict[str, Any] = {"name": name, "description": engine.description, "installed": installed, "enabled": base.engine_enabled(name)}
        if installed:
            try:
                entry["capabilities"] = engine.capabilities()
            except Exception as exc:
                entry["capabilities"] = {"error": str(exc)}
        engines.append(entry)
    return {"engines": engines}


@router.get("/{engine}/probes")
async def engine_probes(engine: str, _: Principal = Depends(current_principal)) -> dict[str, Any]:
    scan_engine = _engine_or_404(engine)
    if not scan_engine.installed():
        raise HTTPException(409, f"{engine} is not installed")
    probes = scan_engine.list_probes()
    return {"engine": engine, "total": len(probes), "items": probes}


@router.post("/{engine}/campaigns", status_code=201)
async def create_campaign(
    engine: str,
    payload: CampaignIn,
    request: Request,
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    scan_engine = _engine_or_404(engine)
    if not scan_engine.installed():
        raise HTTPException(409, f"{engine} is not installed")
    if (await agents.get_agent(session, payload.agent_id)) is None:
        raise HTTPException(404, f"agent {payload.agent_id} not found")
    campaign = await service.create_scan_campaign(session, engine=engine, name=payload.name, agent_id=payload.agent_id, target_model=payload.target_model, options=payload.options, created_by=p.username)
    await audit.record(session, p.username, "scanners.campaign.create", "campaign", campaign.id, {"engine": engine, "agent_id": payload.agent_id, "target_model": payload.target_model})
    await session.commit()
    campaign_id = campaign.id
    if payload.auto_start:
        await service.start_campaign(campaign_id, request.app.state.http)
        await audit.record(session, p.username, "scanners.campaign.start", "campaign", campaign_id, {"engine": engine})
        await session.commit()
    result = await service.get_campaign_dict(session, campaign_id)
    if result is None:
        raise HTTPException(404, "campaign not found")
    return result


@router.post("/{engine}/matrix", status_code=201)
async def create_matrix(
    engine: str,
    payload: MatrixIn,
    request: Request,
    p: Principal = Depends(require_role("reviewer")),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    scan_engine = _engine_or_404(engine)
    if not scan_engine.installed():
        raise HTTPException(409, f"{engine} is not installed")
    for target in payload.targets:
        if (await agents.get_agent(session, target.agent_id)) is None:
            raise HTTPException(404, f"agent {target.agent_id} not found")
    group_id, campaigns = await service.run_matrix(session, engine=engine, name=payload.name, targets=[t.model_dump() for t in payload.targets], options=payload.options, created_by=p.username)
    await audit.record(session, p.username, "scanners.matrix.create", "campaign_group", group_id, {"engine": engine, "targets": len(campaigns)})
    await session.commit()
    ids = [c.id for c in campaigns]
    if payload.auto_start:
        for campaign_id in ids:
            await service.start_campaign(campaign_id, request.app.state.http)
        await audit.record(session, p.username, "scanners.matrix.start", "campaign_group", group_id, {"engine": engine})
        await session.commit()
    out = [await service.get_campaign_dict(session, cid) for cid in ids]
    return {"group_id": group_id, "engine": engine, "campaigns": out}


@router.get("/groups/{group_id}")
async def group_comparison(group_id: str, _: Principal = Depends(current_principal), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    comparison = await service.compare(session, group_id)
    if not comparison["targets"]:
        raise HTTPException(404, "campaign group not found")
    return comparison


@router.post("/campaigns/{campaign_id}/start")
async def start_campaign(campaign_id: str, request: Request, p: Principal = Depends(require_role("reviewer")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    campaign = await session.get(Campaign, campaign_id)
    if campaign is None or not (campaign.config or {}).get("engine"):
        raise HTTPException(404, "scan campaign not found")
    if campaign.status in (CampaignStatus.RUNNING.value, CampaignStatus.COMPLETED.value):
        raise HTTPException(409, f"campaign is {campaign.status}")
    await service.start_campaign(campaign_id, request.app.state.http)
    await audit.record(session, p.username, "scanners.campaign.start", "campaign", campaign_id, {"engine": (campaign.config or {}).get("engine")})
    await session.commit()
    result = await service.get_campaign_dict(session, campaign_id)
    if result is None:
        raise HTTPException(404, "campaign not found")
    return result


@router.post("/campaigns/{campaign_id}/cancel")
async def cancel_campaign(campaign_id: str, p: Principal = Depends(require_role("reviewer")), session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    campaign = await session.get(Campaign, campaign_id)
    if campaign is None or not (campaign.config or {}).get("engine"):
        raise HTTPException(404, "scan campaign not found")
    await service.cancel_campaign(campaign_id)
    await audit.record(session, p.username, "scanners.campaign.cancel", "campaign", campaign_id, {"engine": (campaign.config or {}).get("engine")})
    await session.commit()
    session.expire_all()  # cancel committed the new status in a separate session
    result = await service.get_campaign_dict(session, campaign_id)
    if result is None:
        raise HTTPException(404, "campaign not found")
    return result


# --- PyRIT-Ship compatible surface ------------------------------------------------
ship_router = APIRouter(prefix="/api/pyrit-ship", tags=["pyrit-ship"])


class ConvertIn(BaseModel):
    text: str


class GenerateIn(BaseModel):
    prompt_goal: str


class ScoreIn(BaseModel):
    scoring_true: str
    scoring_false: str = ""
    prompt_response: str


async def _ship_agent(request: Request, session: AsyncSession) -> tuple[str | None, str | None]:
    """A scan token in the Authorization header (or X-AISRF-Campaign-Id) enables ticketed submission."""
    key = None
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        key = auth[7:].strip()
    agent = await agents.authenticate_api_key(session, key) if key else None
    return (agent.id if agent else None), request.headers.get("x-aisrf-campaign-id")


@ship_router.get("/prompt/convert")
async def ship_list_converters() -> list[str]:
    if not pyrit_ship.pyrit_engine.pyrit_available():
        raise HTTPException(503, "pyrit is not installed")
    return pyrit_ship.list_converters()


@ship_router.post("/prompt/convert/{converter_name}")
async def ship_convert(converter_name: str, payload: ConvertIn, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    try:
        converted = await pyrit_ship.convert_text(converter_name, payload.text)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    result: dict[str, Any] = {"converted_text": converted}
    agent_id, campaign_id = await _ship_agent(request, session)
    if agent_id:
        with contextlib.suppress(Exception):
            result["ticket_id"] = await pyrit_ship.submit_converted_prompt(request.app.state.http, agent_id, converted, campaign_id=campaign_id)
    return result


@ship_router.post("/prompt/generate")
async def ship_generate(payload: GenerateIn, request: Request, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    agent_id, campaign_id = await _ship_agent(request, session)
    prompt = await pyrit_ship.generate_prompt(payload.prompt_goal, request.app.state.http if agent_id else None, agent_id, campaign_id=campaign_id)
    return {"prompt": prompt}


@ship_router.post("/prompt/score/SelfAskTrueFalseScorer")
async def ship_score(payload: ScoreIn) -> list[dict[str, Any]]:
    return await pyrit_ship.score_true_false(payload.scoring_true, payload.scoring_false, payload.prompt_response)


@ship_router.get("/external/health")
async def ship_external_health(_: Principal = Depends(current_principal)) -> dict[str, Any]:
    return await pyrit_ship.ShipClient().health()

