"""Reporting REST API: every report kind in every supported format."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from ..auth import Principal, current_principal
from ..db import get_session
from . import builders
from .model import Report
from .renderers import FORMATS, UnknownFormat, negotiate, render

router = APIRouter(prefix="/api/reports", tags=["reports"])


def _pick_format(request: Request, explicit: str | None) -> str:
    try:
        return negotiate(request.headers.get("accept"), explicit)
    except UnknownFormat as exc:
        raise HTTPException(400, str(exc))


def _respond(report: Report, fmt: str, kind: str, inline: bool) -> Response:
    payload, media_type, ext = render(report, fmt)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    filename = f"aisrf-{kind}-{stamp}.{ext}"
    disposition = "inline" if inline else "attachment"
    return Response(
        content=payload,
        media_type=media_type,
        headers={
            "Content-Disposition": f'{disposition}; filename="{filename}"',
            "X-Report-Kind": kind,
            "X-Report-Format": fmt,
        },
    )


async def _build(kind: str, session: AsyncSession, **params: Any) -> Report:
    try:
        return await builders.BUILDERS[kind](session, **params)
    except builders.NotFound as exc:
        raise HTTPException(404, str(exc))


@router.get("")
async def list_reports(_: Principal = Depends(current_principal)) -> dict[str, Any]:
    return {"kinds": builders.KINDS, "formats": FORMATS}


@router.get("/summary")
async def summary_report(
    request: Request,
    format: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    inline: bool = False,
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    fmt = _pick_format(request, format)
    report = await _build("summary", session, since=since, until=until)
    return _respond(report, fmt, "summary", inline)


@router.get("/tickets")
async def tickets_report(
    request: Request,
    format: str | None = None,
    status: list[str] | None = Query(default=None),
    agent_id: str | None = None,
    min_risk: int | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(default=500, le=5000),
    inline: bool = False,
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    fmt = _pick_format(request, format)
    report = await _build(
        "tickets",
        session,
        status=status,
        agent_id=agent_id,
        min_risk=min_risk,
        since=since,
        until=until,
        limit=limit,
    )
    return _respond(report, fmt, "tickets", inline)


@router.get("/ticket/{ticket_id}")
async def ticket_report(
    request: Request,
    ticket_id: str,
    format: str | None = None,
    inline: bool = False,
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    fmt = _pick_format(request, format)
    report = await _build("ticket", session, ticket_id=ticket_id)
    return _respond(report, fmt, f"ticket-{report.meta.get('number') or ticket_id}", inline)


@router.get("/agent/{agent_id}")
async def agent_report(
    request: Request,
    agent_id: str,
    format: str | None = None,
    since: datetime | None = None,
    inline: bool = False,
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    fmt = _pick_format(request, format)
    report = await _build("agent", session, agent_id=agent_id, since=since)
    return _respond(report, fmt, f"agent-{agent_id}", inline)


@router.get("/campaign/{campaign_id}")
async def campaign_report(
    request: Request,
    campaign_id: str,
    format: str | None = None,
    inline: bool = False,
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    fmt = _pick_format(request, format)
    report = await _build("campaign", session, campaign_id=campaign_id)
    return _respond(report, fmt, f"campaign-{campaign_id}", inline)


@router.get("/audit")
async def audit_report(
    request: Request,
    format: str | None = None,
    limit: int = Query(default=500, le=10000),
    inline: bool = False,
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    fmt = _pick_format(request, format)
    report = await _build("audit", session, limit=limit)
    return _respond(report, fmt, "audit", inline)


@router.get("/codereview/{run_id}")
async def codereview_report(
    request: Request,
    run_id: str,
    format: str | None = None,
    inline: bool = False,
    include_dismissed: bool = False,
    _: Principal = Depends(current_principal),
    session: AsyncSession = Depends(get_session),
) -> Response:
    fmt = _pick_format(request, format)
    if fmt == "sarif":
        # the code review SARIF carries physical locations, rule metadata and stable fingerprints
        from ..codereview.report import RunNotFound, build_codereview_sarif

        try:
            payload = await build_codereview_sarif(session, run_id, include_dismissed=include_dismissed)
        except RunNotFound as exc:
            raise HTTPException(404, str(exc))
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        return Response(
            content=payload,
            media_type=FORMATS["sarif"]["media_type"],
            headers={
                "Content-Disposition": f'{"inline" if inline else "attachment"}; filename="aisrf-codereview-{run_id}-{stamp}.sarif"',
                "X-Report-Kind": f"codereview-{run_id}",
                "X-Report-Format": "sarif",
            },
        )
    report = await _build("codereview", session, run_id=run_id)
    return _respond(report, fmt, f"codereview-{run_id}", inline)
