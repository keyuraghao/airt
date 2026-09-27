"""Tests for the MCP server (in-process and mounted at /mcp) and the typer CLI."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import types
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import pytest

_TMP = Path(tempfile.mkdtemp(prefix="aisrf-test-"))
# setdefault so that this module and tests/conftest.py agree whichever is imported first
os.environ.setdefault("AISRF_DATABASE_URL", f"sqlite+aiosqlite:///{_TMP / 'aisrf.db'}")
os.environ.setdefault("AISRF_ADMIN_API_TOKEN", "test-token")
os.environ.setdefault("AISRF_DATA_DIR", str(_TMP / "data"))
os.environ.setdefault("AISRF_LOG_DIR", str(_TMP / "logs"))
os.environ.setdefault("AISRF_LOG_LEVEL", "WARNING")
ADMIN_TOKEN = os.environ["AISRF_ADMIN_API_TOKEN"]

import aisrf.config

aisrf.config.reset_settings_cache()


def _install_stand_ins() -> None:
    """Other builders create these modules in parallel; provide minimal stand-ins only when they are missing."""
    from fastapi import APIRouter, Response

    if importlib.util.find_spec("aisrf.redteam.router") is None:
        mod = types.ModuleType("aisrf.redteam.router")
        router = APIRouter(prefix="/api/redteam")

        @router.get("/corpus")
        async def corpus() -> dict[str, Any]:
            return {"categories": [], "techniques": [], "probes": 0}

        mod.router = router  # type: ignore[attr-defined]
        sys.modules["aisrf.redteam.router"] = mod
    if importlib.util.find_spec("aisrf.redteam.engine") is None:
        mod = types.ModuleType("aisrf.redteam.engine")

        class _Runner:
            async def shutdown(self) -> None:
                return None

        mod.campaign_runner = _Runner()  # type: ignore[attr-defined]
        sys.modules["aisrf.redteam.engine"] = mod
    if importlib.util.find_spec("aisrf.reports.router") is None:
        mod = types.ModuleType("aisrf.reports.router")
        router = APIRouter(prefix="/api/reports")

        @router.get("")
        async def kinds() -> list[dict[str, Any]]:
            return [{"kind": "summary", "formats": ["json", "txt"]}]

        @router.get("/{kind:path}")
        async def render(kind: str, format: str = "json") -> Response:
            body = json.dumps({"kind": kind, "format": format}).encode()
            return Response(body, media_type="application/json" if format == "json" else "text/plain")

        mod.router = router  # type: ignore[attr-defined]
        sys.modules["aisrf.reports.router"] = mod
    if importlib.util.find_spec("aisrf.dashboard.router") is None:
        mod = types.ModuleType("aisrf.dashboard.router")
        mod.mount_dashboard = lambda app: None  # type: ignore[attr-defined]
        sys.modules["aisrf.dashboard.router"] = mod


_install_stand_ins()

from aisrf import __version__
from aisrf.main import create_app
from aisrf.mcp_server import build_server

INIT_BODY = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "pytest", "version": "0"}}}
MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture
async def app() -> AsyncIterator[Any]:
    from aisrf import db

    aisrf.config.reset_settings_cache()
    await db.dispose_db()
    application = create_app()
    async with application.router.lifespan_context(application):
        yield application


@pytest.fixture
async def client(app: Any) -> AsyncIterator[httpx.AsyncClient]:
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://aisrf.internal") as c:
        yield c


def _payload(result: Any) -> Any:
    if isinstance(result, tuple):  # mcp 1.x returns (content, structured_content)
        content, structured = result
        return structured if structured is not None else json.loads(content[0].text)
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)


async def test_tools_in_process(app: Any, client: httpx.AsyncClient) -> None:
    server = build_server("http://aisrf.internal", ADMIN_TOKEN, transport_client=client)
    names = {t.name for t in await server.list_tools()}
    assert {"list_tickets", "approve_ticket", "create_agent", "create_campaign", "generate_report", "verify_audit", "health", "metrics"} <= names
    stats = _payload(await server.call_tool("ticket_stats", {}))
    assert isinstance(stats, dict) and "pending" in stats
    tickets = _payload(await server.call_tool("list_tickets", {"status": "PENDING", "limit": 5}))
    assert isinstance(tickets, dict) and "items" in tickets and tickets["total"] >= 0
    created = _payload(await server.call_tool("create_agent", {"name": "mcp-agent", "upstream_provider": "anthropic", "require_approval": False}))
    assert created.get("api_key", "").startswith("aisrf_"), created
    assert created["upstream_provider"] == "anthropic"
    fetched = _payload(await server.call_tool("get_agent", {"agent_id": created["id"]}))
    assert fetched["name"] == "mcp-agent" and "stats" in fetched
    patched = _payload(await server.call_tool("update_agent", {"agent_id": created["id"], "changes": {"description": "patched"}}))
    assert patched["description"] == "patched"
    listing = _payload(await server.call_tool("list_agents", {}))
    assert listing["count"] >= 1 and any(a["id"] == created["id"] for a in listing["items"])
    missing = _payload(await server.call_tool("get_ticket", {"ticket_id": "tkt_missing"}))
    assert missing == {"error": "ticket not found", "status": 404}
    audit = _payload(await server.call_tool("verify_audit", {}))
    assert audit["ok"] is True
    health = _payload(await server.call_tool("health", {}))
    assert health["status"] == "ok"
    report = _payload(await server.call_tool("generate_report", {"kind": "summary", "format": "json", "output_path": str(_TMP / "out" / "summary.json")}))
    assert report["bytes"] > 0 and Path(report["path"]).exists() and report["media_type"] == "application/json"
    corpus = _payload(await server.call_tool("list_corpus", {}))
    assert isinstance(corpus, dict)
    bad_token = build_server("http://aisrf.internal", "wrong", transport_client=client)
    denied = _payload(await bad_token.call_tool("ticket_stats", {}))
    assert denied["status"] == 401 and "error" in denied


async def test_resources_and_prompt(app: Any, client: httpx.AsyncClient) -> None:
    server = build_server("http://aisrf.internal", ADMIN_TOKEN, transport_client=client)
    assert {str(r.uri) for r in await server.list_resources()} == {"aisrf://tickets/pending", "aisrf://stats"}
    pending = json.loads(next(iter(await server.read_resource("aisrf://tickets/pending"))).content)
    assert "items" in pending
    stats = json.loads(next(iter(await server.read_resource("aisrf://stats"))).content)
    assert "pending" in stats
    prompt = await server.get_prompt("review_ticket", {"ticket_id": "tkt_missing"})
    text = prompt.messages[0].content.text
    assert "tkt_missing" in text and "list_tickets" in text


async def test_mcp_endpoint_requires_token(app: Any, client: httpx.AsyncClient) -> None:
    assert (await client.get("/mcp")).status_code == 401
    assert (await client.post("/mcp", json=INIT_BODY, headers=MCP_HEADERS)).status_code == 401
    wrong = await client.post("/mcp", json=INIT_BODY, headers={**MCP_HEADERS, "Authorization": "Bearer nope"})
    assert wrong.status_code == 401 and "error" in wrong.json()
    settings = aisrf.config.get_settings()
    settings.admin_api_token = None
    try:
        disabled = await client.post("/mcp", json=INIT_BODY, headers={**MCP_HEADERS, "Authorization": f"Bearer {ADMIN_TOKEN}"})
        assert disabled.status_code == 503 and "error" in disabled.json()
    finally:
        settings.admin_api_token = ADMIN_TOKEN


async def test_mcp_endpoint_handshake(app: Any, client: httpx.AsyncClient) -> None:
    headers = {**MCP_HEADERS, "Authorization": f"Bearer {ADMIN_TOKEN}"}
    response = await client.post("/mcp", json=INIT_BODY, headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == 1 and body["result"]["serverInfo"]["name"] == "aisrf"
    assert "protocolVersion" in body["result"]
    listed = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, headers=headers)
    assert listed.status_code == 200
    names = {t["name"] for t in listed.json()["result"]["tools"]}
    assert "list_tickets" in names and "generate_report" in names
    called = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "health", "arguments": {}}}, headers=headers)
    assert called.status_code == 200
    assert called.json()["result"]["structuredContent"]["status"] == "ok"


def test_cli_version_and_agent_create() -> None:
    from typer.testing import CliRunner

    from aisrf.cli import app as cli

    runner = CliRunner(env={"COLUMNS": "200"})
    result = runner.invoke(cli, ["version"])
    assert result.exit_code == 0 and __version__ in result.output
    result = runner.invoke(cli, ["agent", "create", "cli-agent", "--provider", "openai", "--no-approval", "--auto-deny-at", "80", "--tag", "ci"])
    assert result.exit_code == 0, result.output
    assert "API key: aisrf_" in result.output
    result = runner.invoke(cli, ["agent", "list"])
    assert result.exit_code == 0 and "cli-agent" in result.output
    result = runner.invoke(cli, ["agent", "create", "cli-agent"])
    assert result.exit_code == 1 and "already exists" in result.output
    result = runner.invoke(cli, ["create-reviewer", "cli-reviewer", "--password", "secret123", "--role", "viewer"])
    assert result.exit_code == 0 and "cli-reviewer" in result.output
    result = runner.invoke(cli, ["tickets", "list", "--url", "http://127.0.0.1:1", "--token", "x"])
    assert result.exit_code == 1 and "cannot reach" in result.output
    for cmd in (["--help"], ["tickets", "--help"], ["redteam", "run", "--help"], ["mcp", "--help"]):
        assert runner.invoke(cli, cmd).exit_code == 0
