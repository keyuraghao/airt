"""Reporting subsystem: build a format-agnostic Report from the database and render it in any format.

Programmatic entry point (used by the CLI and the MCP server):

    payload, media_type, ext = await aisrf.reports.generate(session, "summary", "pdf")
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from .builders import BUILDERS, KINDS, NotFound
from .model import ChartSection, FindingsSection, KeyValueSection, Report, Section, TableSection, TextSection
from .renderers import FORMATS, UnknownFormat, negotiate, render

__all__ = [
    "BUILDERS",
    "FORMATS",
    "KINDS",
    "ChartSection",
    "FindingsSection",
    "KeyValueSection",
    "NotFound",
    "Report",
    "Section",
    "TableSection",
    "TextSection",
    "UnknownFormat",
    "build",
    "generate",
    "negotiate",
    "render",
]


async def build(session: AsyncSession, kind: str, **params: Any) -> Report:
    """Build the Report for `kind` (summary, tickets, ticket, agent, campaign, audit, codereview)."""
    try:
        builder = BUILDERS[kind]
    except KeyError:
        raise ValueError(f"unknown report kind '{kind}'; known: {', '.join(BUILDERS)}") from None
    return await builder(session, **params)


async def generate(session: AsyncSession, kind: str, fmt: str = "json", **params: Any) -> tuple[bytes, str, str]:
    """Build and render a report. Returns (payload, media_type, file_extension).

    Raises ValueError for an unknown kind or format and NotFound when the entity is missing.
    """
    if kind == "codereview" and negotiate(None, fmt) == "sarif" and params.get("run_id"):
        from ..codereview.report import build_codereview_sarif

        payload = await build_codereview_sarif(session, str(params["run_id"]), include_dismissed=bool(params.get("include_dismissed")))
        return payload, FORMATS["sarif"]["media_type"], FORMATS["sarif"]["extension"]
    report = await build(session, kind, **params)
    return render(report, fmt)
