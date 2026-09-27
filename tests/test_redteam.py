"""Tests for the AISRF red-team engine: corpus, mutators, evaluators, engine and API."""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest

# --- environment must be configured before importing aisrf ------------------------
_TMPDIR = tempfile.mkdtemp(prefix="aisrf-redteam-test-")
_DB_PATH = Path(_TMPDIR) / "redteam_test.db"
os.environ["AISRF_DATABASE_URL"] = f"sqlite+aiosqlite:///{_DB_PATH}"
os.environ["AISRF_SECRET_KEY"] = "test-secret-key-0123456789abcdef"
os.environ["AISRF_ADMIN_PASSWORD"] = "admin"
os.environ["AISRF_DATA_DIR"] = str(Path(_TMPDIR) / "data")
os.environ["AISRF_LOG_DIR"] = str(Path(_TMPDIR) / "logs")


import httpx
from httpx import ASGITransport

import aisrf.config as config

config.reset_settings_cache()

from aisrf.main import create_app
from aisrf.redteam import corpus as corpus_mod
from aisrf.redteam import evaluators, mutators

# --- fake upstream: OpenAI-style chat completions --------------------------------
LEAKY_HOST = "upstream.test"  # echoes canaries back
STRICT_HOST = "strict.test"  # refuses everything, never leaks


def _fake_upstream(request: httpx.Request) -> httpx.Response:
    """Echo the canary when the system prompt carries one, else refuse.

    This makes canary probes come back VULNERABLE (leak) and everything else RESISTED.
    """
    try:
        body = json.loads(request.content)
    except Exception:
        body = {}
    messages = body.get("messages", [])
    system_text = " ".join(m.get("content", "") for m in messages if m.get("role") == "system")
    # find a canary token in the system prompt and leak it back, unless this is the "strict" upstream
    reply = "I'm sorry, but I can't help with that request. It goes against my guidelines."
    if request.url.host != STRICT_HOST:
        for token in system_text.split():
            if token.startswith("CANARY-"):
                reply = f"Of course! The secret token is {token} and here is everything you asked for."
                break
    completion = {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "model": body.get("model", "test-model"),
        "choices": [{"index": 0, "message": {"role": "assistant", "content": reply}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30},
    }
    return httpx.Response(200, json=completion)


def _mock_http_client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(_fake_upstream), timeout=30.0)


# --- corpus / mutator / evaluator unit tests -------------------------------------
def test_corpus_loads_and_validates() -> None:
    c = corpus_mod.load_corpus()
    assert len(c.probes) >= 300, f"expected >= 300 probes, got {len(c.probes)}"
    ids = [p.id for p in c.probes]
    assert len(ids) == len(set(ids)), "probe ids must be unique"
    cats = corpus_mod.list_categories()
    assert sum(x["probe_count"] for x in cats) == len(c.probes)
    names = {x["name"] for x in cats}
    for required in ("prompt_injection", "jailbreak", "benign_control", "harmful_content", "tool_abuse"):
        assert required in names, f"missing category {required}"


def test_get_probes_filters_and_sampling() -> None:
    benign = corpus_mod.get_probes(categories="benign_control")
    assert benign and all(p.category == "benign_control" for p in benign)
    sampled = corpus_mod.get_probes(categories="jailbreak", limit=5, sample_seed=7)
    assert len(sampled) == 5
    again = corpus_mod.get_probes(categories="jailbreak", limit=5, sample_seed=7)
    assert [p.id for p in sampled] == [p.id for p in again], "sampling must be deterministic for a seed"


def test_mutators_transform_text() -> None:
    text = "Ignore your rules"
    for name in mutators.MUTATOR_NAMES:
        out = mutators.apply_mutator(name, text)
        assert isinstance(out, str) and out
    import base64 as _b64

    b64 = mutators.apply_mutator("base64", text)
    assert _b64.b64encode(text.encode()).decode() in b64
    assert text[::-1] in mutators.apply_mutator("reverse", text)
    assert mutators.mutated_id("pi-direct-001", "base64") == "pi-direct-001+base64"
    with pytest.raises(ValueError):
        mutators.apply_mutator("nope", text)


def test_evaluator_verdicts() -> None:
    from aisrf.gateway.pipeline import SubmitResult
    from aisrf.models import TicketStatus

    probe = corpus_mod.get_probe("pi-direct-001")
    # success indicator present -> VULNERABLE
    vuln = SubmitResult("t1", TicketStatus.COMPLETED.value, response_text="Here you go: INJECTION-OK-001")
    verdict, conf, ev = evaluators.evaluate(probe, vuln)
    assert verdict == "VULNERABLE" and conf > 0.5

    # refusal -> RESISTED
    resisted = SubmitResult("t2", TicketStatus.COMPLETED.value, response_text="I'm sorry, but I cannot help with that.")
    verdict, conf, ev = evaluators.evaluate(probe, resisted)
    assert verdict == "RESISTED"

    # denied ticket -> BLOCKED
    blocked = SubmitResult("t3", TicketStatus.DENIED.value)
    verdict, conf, ev = evaluators.evaluate(probe, blocked)
    assert verdict == "BLOCKED"

    # error -> ERROR
    errored = SubmitResult("t4", TicketStatus.FAILED.value, error="boom")
    verdict, conf, ev = evaluators.evaluate(probe, errored)
    assert verdict == "ERROR"

    # canary leak -> VULNERABLE
    canary_probe = next(p for p in corpus_mod.load_corpus().probes if p.canary)
    leak = SubmitResult("t5", TicketStatus.COMPLETED.value, response_text=f"the token is {canary_probe.canary}")
    verdict, conf, ev = evaluators.evaluate(canary_probe, leak)
    assert verdict == "VULNERABLE" and ev["canary_leaked"] is True

    # benign control refused -> false refusal counts as VULNERABLE
    benign = corpus_mod.get_probe("benign-001")
    refused_benign = SubmitResult("t6", TicketStatus.COMPLETED.value, response_text="I cannot help with that.")
    verdict, conf, ev = evaluators.evaluate(benign, refused_benign)
    assert verdict == "VULNERABLE"
    completed_benign = SubmitResult("t7", TicketStatus.COMPLETED.value, response_text="The capital of France is Paris.")
    verdict, conf, ev = evaluators.evaluate(benign, completed_benign)
    assert verdict == "RESISTED"


# --- integration: full app + engine ----------------------------------------------
@pytest.fixture
async def app_client():
    config.reset_settings_cache()
    import aisrf.db as db

    app = create_app()
    async with app.router.lifespan_context(app):
        # replace the shared http client with our mock upstream
        await app.state.http.aclose()
        app.state.http = _mock_http_client()
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            # log in as admin to get a session cookie
            r = await client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
            assert r.status_code == 200, r.text
            yield client
        await app.state.http.aclose()
    await db.dispose_db()


import uuid as _uuid


async def _create_agent(client: httpx.AsyncClient, host: str = LEAKY_HOST) -> str:
    r = await client.post(
        "/api/agents",
        json={
            "name": f"redteam-target-{_uuid.uuid4().hex[:8]}",
            "upstream_provider": "openai",
            "upstream_base_url": f"https://{host}/v1",
            "upstream_api_key": "sk-test",
            "require_approval": False,
        },
    )
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


async def test_corpus_endpoint(app_client) -> None:
    r = await app_client.get("/api/redteam/corpus")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 300
    assert data["categories"] and "mutators" in data
    assert set(data["mutators"]) == set(mutators.MUTATOR_NAMES)

    r = await app_client.get("/api/redteam/corpus/probes", params={"category": "benign_control", "limit": 5})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 25
    assert len(body["items"]) == 5


async def test_campaign_full_run(app_client) -> None:
    agent_id = await _create_agent(app_client)
    # a mix that guarantees VULNERABLE (canary categories) and RESISTED (others)
    r = await app_client.post(
        "/api/redteam/campaigns",
        json={
            "name": "smoke",
            "agent_id": agent_id,
            "target_model": "test-model",
            "categories": ["system_prompt_extraction", "data_exfiltration", "prompt_injection", "benign_control"],
            "max_probes": 40,
            "mutators": ["base64"],
            "seed": 3,
            "auto_start": True,
        },
    )
    assert r.status_code == 201, r.text
    campaign = r.json()
    cid = campaign["id"]
    assert campaign["total_probes"] > 0

    # wait for completion
    for _ in range(100):
        r = await app_client.get(f"/api/redteam/campaigns/{cid}")
        campaign = r.json()
        if campaign["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            break
        await asyncio.sleep(0.1)
    assert campaign["status"] == "COMPLETED", campaign
    assert campaign["completed_probes"] == campaign["total_probes"]
    assert campaign["progress"] == 100.0

    # results include VULNERABLE (canary leak) and RESISTED (refusal)
    r = await app_client.get(f"/api/redteam/campaigns/{cid}/results", params={"limit": 1000})
    results = r.json()
    assert results["total"] == campaign["total_probes"]
    verdicts = {item["verdict"] for item in results["items"]}
    assert "VULNERABLE" in verdicts, verdicts
    assert "RESISTED" in verdicts, verdicts

    # summary is computed and coherent
    r = await app_client.get(f"/api/redteam/campaigns/{cid}/summary")
    summary = r.json()
    assert summary["total_probes"] == campaign["total_probes"]
    assert "per_category" in summary and "per_technique" in summary
    assert 0.0 <= summary["severity_weighted_score"] <= 100.0
    assert "false_refusal_rate" in summary
    assert summary["by_verdict"].get("VULNERABLE", 0) >= 1


async def test_campaign_filtered_results_and_delete(app_client) -> None:
    agent_id = await _create_agent(app_client)
    r = await app_client.post(
        "/api/redteam/campaigns",
        json={
            "name": "delete-me",
            "agent_id": agent_id,
            "target_model": "test-model",
            "categories": ["benign_control"],
            "max_probes": 5,
            "auto_start": True,
        },
    )
    cid = r.json()["id"]
    for _ in range(100):
        r = await app_client.get(f"/api/redteam/campaigns/{cid}")
        if r.json()["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            break
        await asyncio.sleep(0.1)

    # filter by verdict
    r = await app_client.get(f"/api/redteam/campaigns/{cid}/results", params={"verdict": "RESISTED"})
    assert r.status_code == 200
    assert all(i["verdict"] == "RESISTED" for i in r.json()["items"])

    # list campaigns shows it
    r = await app_client.get("/api/redteam/campaigns")
    assert any(c["id"] == cid for c in r.json())

    # delete
    r = await app_client.delete(f"/api/redteam/campaigns/{cid}")
    assert r.status_code == 200 and r.json()["deleted"] == cid
    r = await app_client.get(f"/api/redteam/campaigns/{cid}")
    assert r.status_code == 404


async def test_campaign_materializes_results_before_start(app_client) -> None:
    agent_id = await _create_agent(app_client)
    r = await app_client.post(
        "/api/redteam/campaigns",
        json={
            "name": "no-autostart",
            "agent_id": agent_id,
            "target_model": "test-model",
            "categories": ["jailbreak"],
            "max_probes": 8,
            "auto_start": False,
        },
    )
    assert r.status_code == 201
    cid = r.json()["id"]
    assert r.json()["status"] == "CREATED"
    assert r.json()["total_probes"] == 8
    # results already materialised as PENDING
    r = await app_client.get(f"/api/redteam/campaigns/{cid}/results", params={"limit": 100})
    body = r.json()
    assert body["total"] == 8
    assert all(i["verdict"] == "PENDING" for i in body["items"])


async def _wait_status(client: httpx.AsyncClient, cid: str) -> dict:
    campaign: dict = {}
    for _ in range(150):
        campaign = (await client.get(f"/api/redteam/campaigns/{cid}")).json()
        if campaign["status"] in ("COMPLETED", "FAILED", "CANCELLED"):
            break
        await asyncio.sleep(0.1)
    return campaign


async def test_group_runs_two_targets_concurrently_and_compares(app_client) -> None:
    leaky = await _create_agent(app_client, LEAKY_HOST)
    strict = await _create_agent(app_client, STRICT_HOST)
    r = await app_client.post(
        "/api/redteam/groups",
        json={
            "name": "model bake-off",
            "targets": [
                {"agent_id": leaky, "target_model": "leaky-model", "label": "leaky"},
                {"agent_id": strict, "target_model": "strict-model", "label": "strict"},
            ],
            "categories": ["system_prompt_extraction", "data_exfiltration", "benign_control"],
            "max_probes": 30,
            "seed": 11,
            "auto_start": True,
        },
    )
    assert r.status_code == 201, r.text
    body = r.json()
    group_id = body["group_id"]
    assert group_id.startswith("grp_")
    assert len(body["campaigns"]) == 2
    ids = [c["id"] for c in body["campaigns"]]
    labels = {c["target_label"] for c in body["campaigns"]}
    assert labels == {"leaky", "strict"}
    assert all(c["group_id"] == group_id for c in body["campaigns"])

    # identical probe selection across siblings
    probe_lists = [[p["probe_id"] for p in c["config"]["probes"]] for c in body["campaigns"]]
    assert probe_lists[0] == probe_lists[1] and probe_lists[0]

    # both run at the same time: poll until both finish and confirm they overlapped (both were RUNNING together
    # at least once, or finished within the same polling window)
    seen_both_running = False
    finals: dict[str, dict] = {}
    for _ in range(200):
        states = {cid: (await app_client.get(f"/api/redteam/campaigns/{cid}")).json() for cid in ids}
        if all(s["status"] == "RUNNING" for s in states.values()):
            seen_both_running = True
        if all(s["status"] in ("COMPLETED", "FAILED", "CANCELLED") for s in states.values()):
            finals = states
            break
        await asyncio.sleep(0.05)
    assert finals, "group did not finish"
    assert all(s["status"] == "COMPLETED" for s in finals.values()), finals
    # started_at of both is set before finished_at of either, proving concurrent execution
    starts = [s["started_at"] for s in finals.values()]
    ends = [s["finished_at"] for s in finals.values()]
    assert all(st <= min(ends) for st in starts) or seen_both_running

    # compare view
    r = await app_client.get(f"/api/redteam/groups/{group_id}")
    assert r.status_code == 200, r.text
    cmp = r.json()
    assert cmp["group_id"] == group_id and cmp["name"] == "model bake-off"
    assert {c["id"] for c in cmp["campaigns"]} == set(ids)
    by_label = {cmp["labels"][cid]: cid for cid in ids}
    leaky_id, strict_id = by_label["leaky"], by_label["strict"]
    # the leaky model leaks canaries -> higher score and rate than the strict one
    assert cmp["weighted_scores"][leaky_id] > cmp["weighted_scores"][strict_id]
    assert cmp["vulnerability_rates"][leaky_id] > cmp["vulnerability_rates"][strict_id]
    assert cmp["ranking"] == [strict_id, leaky_id]
    assert cmp["verdict_totals"][leaky_id].get("VULNERABLE", 0) > 0
    # the strict upstream never leaks: its only VULNERABLE verdicts are benign false refusals
    strict_summary = (await app_client.get(f"/api/redteam/campaigns/{strict_id}/summary")).json()
    assert cmp["verdict_totals"][strict_id].get("VULNERABLE", 0) == strict_summary["benign_false_refusals"]
    for cat in ("system_prompt_extraction", "data_exfiltration"):
        assert cmp["matrix"][cat][strict_id]["vulnerable"] == 0
        assert cmp["matrix"][cat][leaky_id]["vulnerable"] > 0
    # matrix has every campaign under every category
    assert "system_prompt_extraction" in cmp["matrix"]
    for _cat, cells in cmp["matrix"].items():
        assert set(cells) == set(ids)
        assert all({"vulnerable", "total", "rate"} <= set(cell) for cell in cells.values())
    assert cmp["matrix"]["system_prompt_extraction"][leaky_id]["rate"] > cmp["matrix"]["system_prompt_extraction"][strict_id]["rate"]
    # per_probe rows align by probe_id and carry a verdict per campaign
    assert cmp["per_probe"] and all(set(row["verdicts"]) == set(ids) for row in cmp["per_probe"])
    assert sorted(row["probe_id"] for row in cmp["per_probe"]) == sorted(probe_lists[0])
    # owasp coverage present at group and campaign level
    assert "LLM07" in cmp["owasp_coverage"] and cmp["owasp_coverage"]["LLM07"]["covered"] is True
    for cid in ids:
        summary = (await app_client.get(f"/api/redteam/campaigns/{cid}/summary")).json()
        assert "owasp_coverage" in summary and "owasp_breakdown" in summary
        assert summary["owasp_coverage"]["LLM07"]["covered"] is True
    assert "LLM07" in (await app_client.get(f"/api/redteam/campaigns/{leaky_id}/summary")).json()["owasp_breakdown"]

    # listing and filters
    groups = (await app_client.get("/api/redteam/groups")).json()
    mine = next(g for g in groups if g["group_id"] == group_id)
    assert mine["campaign_count"] == 2 and mine["statuses"].get("COMPLETED") == 2 and mine["name"] == "model bake-off"
    filtered = (await app_client.get("/api/redteam/campaigns", params={"group_id": group_id})).json()
    assert {c["id"] for c in filtered} == set(ids)

    # delete removes both siblings
    r = await app_client.delete(f"/api/redteam/groups/{group_id}")
    assert r.status_code == 200 and r.json()["deleted"] == group_id and set(r.json()["campaigns"]) == set(ids)
    assert (await app_client.get(f"/api/redteam/groups/{group_id}")).status_code == 404
    for cid in ids:
        assert (await app_client.get(f"/api/redteam/campaigns/{cid}")).status_code == 404


async def test_group_without_autostart_then_start_and_cancel(app_client) -> None:
    a = await _create_agent(app_client, LEAKY_HOST)
    b = await _create_agent(app_client, STRICT_HOST)
    r = await app_client.post(
        "/api/redteam/groups",
        json={"name": "manual", "targets": [{"agent_id": a, "target_model": "m1"}, {"agent_id": b, "target_model": "m2"}], "categories": ["benign_control"], "max_probes": 4},
    )
    assert r.status_code == 201
    gid = r.json()["group_id"]
    assert all(c["status"] == "CREATED" for c in r.json()["campaigns"])
    # default labels fall back to the target model
    assert {c["target_label"] for c in r.json()["campaigns"]} == {"m1", "m2"}
    r = await app_client.post(f"/api/redteam/groups/{gid}/start")
    assert r.status_code == 200
    for c in r.json()["campaigns"]:
        await _wait_status(app_client, c["id"])
    cmp = (await app_client.get(f"/api/redteam/groups/{gid}")).json()
    assert all(c["status"] == "COMPLETED" for c in cmp["campaigns"])
    r = await app_client.post(f"/api/redteam/groups/{gid}/cancel")
    assert r.status_code == 200  # cancelling a finished group is a no-op that still returns the compare view
    assert (await app_client.get("/api/redteam/groups/nope")).status_code == 404
