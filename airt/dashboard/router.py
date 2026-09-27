"""Server-rendered shell for the reviewer dashboard.

Jinja2 only renders the page shell and the authenticated principal; every page then loads its
data from the REST API and the SSE streams so that views stay live without reloads.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..auth import Principal, optional_principal
from ..config import get_settings

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
router = APIRouter(include_in_schema=False, tags=["dashboard"])

PAGES: dict[str, str] = {
    "overview": "Overview",
    "tickets": "Review queue",
    "ticket": "Ticket",
    "agents": "Agents",
    "agent": "Agent",
    "logs": "Logs",
    "redteam": "Red team",
    "campaign": "Campaign",
    "reports": "Reports",
    "audit": "Audit log",
    "settings": "Settings",
}


def _login_redirect(request: Request) -> RedirectResponse:
    nxt = request.url.path
    if request.url.query:
        nxt += "?" + request.url.query
    return RedirectResponse(url=f"/login?next={quote(nxt, safe='')}", status_code=303)


def _render(request: Request, template: str, page: str, principal: Principal | None, **extra: object) -> Response:
    settings = get_settings()
    context = {
        "principal": principal,
        "page": page,
        "page_title": PAGES.get(page, page.title()),
        "app_name": settings.app_name,
        "version": __version__,
        "environment": settings.environment,
        "approval_timeout": settings.approval_timeout_seconds,
        **extra,
    }
    return templates.TemplateResponse(request, template, context)


def _page(request: Request, template: str, page: str, principal: Principal | None, **extra: object) -> Response:
    if principal is None:
        return _login_redirect(request)
    return _render(request, template, page, principal, **extra)


@router.get("/login")
async def login_page(request: Request, next: str = "/", p: Principal | None = Depends(optional_principal)) -> Response:
    if p is not None:
        target = next if next.startswith("/") and not next.startswith("//") else "/"
        return RedirectResponse(url=target, status_code=303)
    return _render(request, "login.html", "login", None, next=next)


@router.get("/")
async def overview_page(request: Request, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "overview.html", "overview", p)


@router.get("/tickets")
async def tickets_page(request: Request, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "tickets.html", "tickets", p)


@router.get("/tickets/{ticket_id}")
async def ticket_page(request: Request, ticket_id: str, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "ticket.html", "ticket", p, ticket_id=ticket_id)


@router.get("/agents")
async def agents_page(request: Request, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "agents.html", "agents", p)


@router.get("/agents/{agent_id}")
async def agent_page(request: Request, agent_id: str, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "agent.html", "agent", p, agent_id=agent_id)


@router.get("/logs")
async def logs_page(request: Request, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "logs.html", "logs", p)


@router.get("/redteam")
async def redteam_page(request: Request, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "redteam.html", "redteam", p)


@router.get("/redteam/{campaign_id}")
async def campaign_page(request: Request, campaign_id: str, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "campaign.html", "campaign", p, campaign_id=campaign_id)


@router.get("/reports")
async def reports_page(request: Request, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "reports.html", "reports", p)


@router.get("/audit")
async def audit_page(request: Request, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "audit.html", "audit", p)


@router.get("/settings")
async def settings_page(request: Request, p: Principal | None = Depends(optional_principal)) -> Response:
    return _page(request, "settings.html", "settings", p)


def mount_dashboard(app: FastAPI) -> None:
    """Attach the static files and the HTML routes to the application."""
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(router)
