"""Tests for the external scan engines: registry, probe listing, end-to-end runs and comparisons.

The garak and promptfoo runs launch the real scanner binaries against a live uvicorn instance of
the app (with a MockTransport upstream), so their traffic flows through the gateway as tickets. The
PyRIT run drives AISRFGatewayTarget in-process. The whole module stays well under 3 minutes.
"""
from __future__ import annotations

import asyncio
import contextlib
import shutil
import socket
from typing import Any

import httpx
import pytest
import uvicorn

from tests.conftest import _install_stand_ins, openai_upstream_handler

# Register stand-ins for optional modules that cannot import here (e.g. mcp_server); this only
# stubs modules whose real import fails, so the native redteam engine and router stay real.
_install_stand_ins()

import aisrf.scanners as scanners
from aisrf.scanners import base as sbase


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _mock_upstream() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(openai_upstream_handler), timeout=30.0)


@pytest.fixture
async def scan_app():
    """The full app with the scanners routers mounted, sharing the test DB and a mock upstream."""
    from aisrf import config, db

    config.reset_settings_cache()
    await db.dispose_db()
    from aisrf.main import create_app

    app = create_app()
    app.include_router(scanners.router)
    app.include_router(scanners.ship_router)
    async with app.router.lifespan_context(app):
        await app.state.http.aclose()
        app.state.http = _mock_upstream()
        yield app
        await sbase.scan_runner.shutdown()
        await app.state.http.aclose()
    await db.dispose_db()


@pytest.fixture
async def api(scan_app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=scan_app), base_url="http://testserver") as c:
        yield c


@pytest.fixture
def admin():
    return {"Authorization": "Bearer test-admin-token"}


@pytest.fixture
async def live_server(scan_app):
    """Serve `scan_app` over real TCP so scanner subprocesses can reach the gateway."""
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(scan_app, host="127.0.0.1", port=port, log_level="warning", lifespan="off"))
    task = asyncio.create_task(server.serve())
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.05)
    assert server.started, "uvicorn did not start"
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await asyncio.wait_for(task, timeout=10)


async def _make_agent(api: httpx.AsyncClient, admin: dict[str, str], *, require_approval: bool = False, name: str = "scan-target") -> dict[str, Any]:
    import os

    r = await api.post(
        "/api/agents",
        headers=admin,
        json={"name": f"{name}-{os.urandom(3).hex()}", "upstream_provider": "openai", "upstream_base_url": "https://upstream.example/v1", "upstream_api_key": "sk-upstream-secret", "require_approval": require_approval},
    )
    assert r.status_code == 201, r.text
    return r.json()


async def _wait_done(api: httpx.AsyncClient, admin: dict[str, str], campaign_id: str, tries: int = 900) -> dict[str, Any]:
    for _ in range(tries):
        r = await api.get(f"/api/redteam/campaigns/{campaign_id}", headers=admin)
        assert r.status_code == 200, r.text
        data = r.json()
        if data["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            return data
        await asyncio.sleep(0.1)
    raise AssertionError(f"campaign {campaign_id} did not finish; last status {data['status']}")


GARAK = shutil.which("garak") is not None or scanners.registry["garak"].installed()
PROMPTFOO = scanners.registry["promptfoo"].installed()
PYRIT = scanners.registry["pyrit"].installed()
INSTALLED = {"garak": GARAK, "promptfoo": PROMPTFOO, "pyrit": PYRIT, "pyrit_ship": PYRIT}
needs_pyrit = pytest.mark.skipif(not PYRIT, reason="pyrit is not installed in this environment")


# --- registry and probe listing --------------------------------------------------
async def test_engine_registry_and_capabilities(api, admin):
    r = await api.get("/api/scanners", headers=admin)
    assert r.status_code == 200, r.text
    engines = {e["name"]: e for e in r.json()["engines"]}
    assert set(engines) == {"garak", "promptfoo", "pyrit", "pyrit_ship"}
    for name, entry in engines.items():
        assert entry["installed"] is INSTALLED[name], f"{name} installed flag must reflect the environment"
        assert "enabled" in entry
        assert entry["capabilities"], f"{name} exposes capabilities"


async def test_probe_listing_for_all_engines(api, admin):
    for engine in ("garak", "promptfoo", "pyrit", "pyrit_ship"):
        r = await api.get(f"/api/scanners/{engine}/probes", headers=admin)
        if not INSTALLED[engine]:
            assert r.status_code in (200, 501, 503), r.text
            continue
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] > 0
        item = body["items"][0]
        for key in ("id", "category", "technique", "severity"):
            assert key in item, f"{engine} probe missing {key}"


async def test_reads_need_auth(api):
    r = await api.get("/api/scanners")
    assert r.status_code == 401


async def test_mutations_need_reviewer(api):
    r = await api.post("/api/scanners/garak/campaigns", json={"name": "x", "agent_id": "nope"})
    assert r.status_code == 401


@pytest.mark.skipif(not GARAK, reason="garak binary not available")
async def test_garak_end_to_end(api, admin, live_server):
    agent = await _make_agent(api, admin, require_approval=False, name="garak")
    r = await api.post(
        "/api/scanners/garak/campaigns",
        headers=admin,
        json={"name": "garak smoke", "agent_id": agent["id"], "target_model": "mock-model", "options": {"probes": ["test.Test"], "generations": 1, "gateway_url": live_server, "parallel_attempts": 2}, "auto_start": True},
    )
    assert r.status_code == 201, r.text
    campaign = r.json()
    assert campaign["engine"] == "garak"
    cid = campaign["id"]
    final = await _wait_done(api, admin, cid)
    assert final["status"] == "COMPLETED", final
    assert final["summary"]["engine"] == "garak"
    results = (await api.get(f"/api/redteam/campaigns/{cid}/results", headers=admin, params={"limit": 1000})).json()
    assert results["total"] >= 1, results
    assert all(item["verdict"] != "PENDING" for item in results["items"])
    linked = [item for item in results["items"] if item["ticket_id"]]
    assert linked, "at least one garak result must link to a gateway ticket"
    ticket = (await api.get(f"/api/tickets/{linked[0]['ticket_id']}", headers=admin)).json()
    assert ticket["campaign_id"] == cid
    assert ticket["source"] == "redteam"


@pytest.mark.skipif(not PROMPTFOO, reason="promptfoo binary not available")
async def test_promptfoo_end_to_end(api, admin, live_server):
    agent = await _make_agent(api, admin, require_approval=False, name="promptfoo")
    r = await api.post(
        "/api/scanners/promptfoo/campaigns",
        headers=admin,
        json={"name": "promptfoo corpus", "agent_id": agent["id"], "target_model": "mock-model", "options": {"mode": "corpus", "categories": ["benign_control", "prompt_injection"], "max_probes": 6, "seed": 5, "gateway_url": live_server, "concurrency": 4}, "auto_start": True},
    )
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    final = await _wait_done(api, admin, cid)
    assert final["status"] == "COMPLETED", final
    assert final["summary"]["engine"] == "promptfoo"
    results = (await api.get(f"/api/redteam/campaigns/{cid}/results", headers=admin, params={"limit": 1000})).json()
    assert results["total"] == 6, results
    verdicts = {item["verdict"] for item in results["items"]}
    assert verdicts.issubset({"VULNERABLE", "RESISTED", "BLOCKED", "ERROR", "INCONCLUSIVE"})
    linked = [item for item in results["items"] if item["ticket_id"]]
    assert linked, "promptfoo results must link to gateway tickets via the X-AISRF-Ticket header"


@needs_pyrit
async def test_pyrit_in_process_run(api, admin):
    agent = await _make_agent(api, admin, require_approval=False, name="pyrit")
    r = await api.post(
        "/api/scanners/pyrit/campaigns",
        headers=admin,
        json={"name": "pyrit inproc", "agent_id": agent["id"], "target_model": "mock-model", "options": {"mode": "inprocess", "converters": ["Base64Converter"], "scorer": "CorpusIndicatorScorer", "categories": ["benign_control", "prompt_injection"], "max_probes": 4, "seed": 3}, "auto_start": True},
    )
    assert r.status_code == 201, r.text
    cid = r.json()["id"]
    final = await _wait_done(api, admin, cid)
    assert final["status"] == "COMPLETED", final
    assert final["summary"]["engine"] == "pyrit"
    assert final["summary"]["pyrit"]["converters"] == ["Base64Converter"]
    results = (await api.get(f"/api/redteam/campaigns/{cid}/results", headers=admin, params={"limit": 1000})).json()
    assert results["total"] == 4, results
    for item in results["items"]:
        assert item["probe_id"].endswith("+Base64Converter")
        assert item["ticket_id"], "every in-process PyRIT probe must create a ticket"
        assert item["verdict"] in ("VULNERABLE", "RESISTED", "BLOCKED", "ERROR", "INCONCLUSIVE")
        assert item["evidence"]["engine"] == "pyrit"
    ticket = (await api.get(f"/api/tickets/{results['items'][0]['ticket_id']}", headers=admin)).json()
    assert ticket["campaign_id"] == cid and ticket["source"] == "redteam"


@needs_pyrit
async def test_pyrit_ship_convert_and_score(api, admin):
    converters = (await api.get("/api/pyrit-ship/prompt/convert")).json()
    assert "ROT13Converter" in converters and "Base64Converter" in converters
    r = await api.post("/api/pyrit-ship/prompt/convert/ROT13Converter", json={"text": "hello [CONVERT]secret[/CONVERT] world"})
    assert r.status_code == 200, r.text
    assert r.json()["converted_text"] == "hello frperg world"
    r = await api.post("/api/pyrit-ship/prompt/convert/Base64Converter", json={"text": "abc"})
    assert r.status_code == 200
    import base64

    assert r.json()["converted_text"].strip() == base64.b64encode(b"abc").decode()
    r = await api.post("/api/pyrit-ship/prompt/convert/NotAConverter", json={"text": "x"})
    assert r.status_code == 404
    r = await api.post("/api/pyrit-ship/prompt/score/SelfAskTrueFalseScorer", json={"scoring_true": "there is a password in the text", "scoring_false": "there is no password", "prompt_response": "the password is PYRITSHIP"})
    assert r.status_code == 200, r.text
    scores = r.json()
    assert isinstance(scores, list) and scores
    for key in ("scoring_text", "scoring_metadata", "scoring_rationale"):
        assert key in scores[0]


@needs_pyrit
async def test_pyrit_ship_convert_creates_ticket(api, admin):
    """A scan token on the convert call submits the converted prompt through the gateway as a ticket."""
    agent = await _make_agent(api, admin, require_approval=False, name="ship")
    from aisrf.agents import service as agent_service
    from aisrf.db import session_scope

    async with session_scope() as session:
        _, raw = await agent_service.mint_scan_token(session, agent["id"], ttl_seconds=600, purpose="pyrit_ship")
    r = await api.post("/api/pyrit-ship/prompt/convert/ROT13Converter", headers={"Authorization": f"Bearer {raw}"}, json={"text": "attack payload"})
    assert r.status_code == 200, r.text
    assert r.json().get("ticket_id"), "converted prompt should be submitted as a ticket"
    ticket = (await api.get(f"/api/tickets/{r.json()['ticket_id']}", headers=admin)).json()
    assert ticket["agent_id"] == agent["id"]


@needs_pyrit
async def test_matrix_run_and_comparison(api, admin):
    agent_a = await _make_agent(api, admin, require_approval=False, name="matrix-a")
    agent_b = await _make_agent(api, admin, require_approval=False, name="matrix-b")
    r = await api.post(
        "/api/scanners/pyrit/matrix",
        headers=admin,
        json={
            "name": "cross-target",
            "targets": [{"agent_id": agent_a["id"], "target_model": "model-a"}, {"agent_id": agent_b["id"], "target_model": "model-b"}],
            "options": {"mode": "inprocess", "categories": ["benign_control", "prompt_injection"], "max_probes": 3, "seed": 1},
            "auto_start": True,
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    group_id = body["group_id"]
    assert len(body["campaigns"]) == 2
    for campaign in body["campaigns"]:
        assert campaign["group_id"] == group_id
        await _wait_done(api, admin, campaign["id"])
    r = await api.get(f"/api/scanners/groups/{group_id}", headers=admin)
    assert r.status_code == 200, r.text
    comparison = r.json()
    assert comparison["group_id"] == group_id
    assert len(comparison["targets"]) == 2
    assert comparison["categories"], "comparison lists the tested categories"
    assert set(comparison["matrix"]) == set(comparison["categories"])
    assert comparison["verdict_totals"] and comparison["ranking"]
    for target in comparison["targets"]:
        assert "severity_weighted_score" in target and "vulnerability_rate" in target
        assert "by_verdict" in target


@needs_pyrit
async def test_cancel_campaign(api, admin):
    agent = await _make_agent(api, admin, require_approval=True, name="cancel")
    r = await api.post(
        "/api/scanners/pyrit/campaigns",
        headers=admin,
        json={"name": "to cancel", "agent_id": agent["id"], "target_model": "mock", "options": {"mode": "inprocess", "categories": ["jailbreak"], "max_probes": 3}, "auto_start": False},
    )
    cid = r.json()["id"]
    assert r.json()["status"] == "CREATED"
    r = await api.post(f"/api/scanners/campaigns/{cid}/cancel", headers=admin)
    assert r.status_code == 200
    assert r.json()["status"] == "CANCELLED"
