"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import contextlib
import secrets
import uuid
from collections.abc import AsyncIterator

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

from . import __version__, settings_store
from .agents import router as agents_router
from .agents import service as agent_service
from .auth import ensure_admin
from .auth import router as auth_router
from .config import get_settings
from .db import dispose_db, get_sessionmaker, init_db
from .gateway import forwarder
from .gateway import router as gateway_router
from .logging import configure_logging, get_logger
from .metrics import metrics
from .notifications import notifier
from .settings_router import router as settings_router
from .tickets import router as tickets_router
from .tickets import service as ticket_service

log = get_logger("airt.main")


class CorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=rid, path=request.url.path, method=request.method)
        try:
            response = await call_next(request)
        except Exception:
            log.exception("request.unhandled")
            return JSONResponse({"error": {"message": "internal error", "request_id": rid}}, status_code=500)
        response.headers["X-Request-ID"] = rid
        return response


async def _background_sweeper(stop: asyncio.Event) -> None:
    settings = get_settings()
    counter = 0
    while not stop.is_set():
        try:
            async with get_sessionmaker()() as session:
                n = await ticket_service.expire_stale(session)
                await session.commit()
                if n:
                    log.info("sweeper.expired", count=n)
                counter += 1
                if counter % 720 == 0 and settings.ticket_retention_days > 0:
                    purged = await ticket_service.purge_old(session, settings.ticket_retention_days)
                    await session.commit()
                    if purged:
                        log.info("sweeper.purged", count=purged)
        except Exception as exc:
            log.warning("sweeper.error", error=str(exc))
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=5)


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    settings = get_settings()
    await init_db()
    async with get_sessionmaker()() as session:
        await ensure_admin(session)
        await settings_store.load_overrides(session)
    app.state.http = forwarder.make_client()
    app.state.internal_token = secrets.token_urlsafe(32)
    stop = asyncio.Event()
    app.state.sweeper = asyncio.create_task(_background_sweeper(stop))
    from .redteam.engine import campaign_runner

    app.state.campaign_runner = campaign_runner
    await notifier.start()
    log.info(
        "airt.started",
        version=__version__,
        env=settings.environment,
        port=settings.port,
        approval_timeout=settings.approval_timeout_seconds,
    )
    try:
        yield
    finally:
        stop.set()
        app.state.sweeper.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await app.state.sweeper
        await notifier.stop()
        await campaign_runner.shutdown()
        await app.state.http.aclose()
        await dispose_db()
        log.info("airt.stopped")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="Human-in-the-loop interception, analysis and red teaming gateway for LLM traffic.",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(CorrelationMiddleware)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", tags=["ops"])
    async def readyz() -> dict:
        async with get_sessionmaker()() as session:
            await agent_service.list_agents(session)
        return {"status": "ready"}

    @app.get("/metrics", tags=["ops"], response_class=PlainTextResponse)
    async def prometheus() -> str:
        metrics.inc("metrics_scrapes_total")
        return metrics.render()

    app.include_router(auth_router)
    app.include_router(tickets_router.router)
    app.include_router(agents_router.router)
    app.include_router(settings_router)
    from .redteam.router import router as redteam_router
    from .reports.router import router as reports_router

    app.include_router(redteam_router)
    app.include_router(reports_router)
    from .dashboard.router import mount_dashboard

    mount_dashboard(app)
    from .mcp_server import mount_mcp

    mount_mcp(app)
    app.include_router(gateway_router.router)  # catch-all proxy routes go last
    return app
