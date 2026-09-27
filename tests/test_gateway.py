"""End-to-end interception tests: every request becomes a ticket and nothing reaches upstream without approval."""

from __future__ import annotations

import asyncio

CHAT = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "What is the capital of France?"}]}


async def _wait_pending(client, admin_headers, agent_id: str, attempts: int = 50):
    for _ in range(attempts):
        r = await client.get(
            "/api/tickets", headers=admin_headers, params={"status": "PENDING", "agent_id": agent_id}
        )
        items = r.json()["items"]
        if items:
            return items[0]
        await asyncio.sleep(0.05)
    raise AssertionError("no pending ticket appeared")


async def test_unauthenticated_request_is_rejected(client):
    r = await client.post("/v1/chat/completions", json=CHAT)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


async def test_request_is_held_until_approved_then_forwarded(client, admin_headers, agent):
    key = agent["api_key"]
    task = asyncio.create_task(
        client.post("/v1/chat/completions", json=CHAT, headers={"Authorization": f"Bearer {key}"})
    )
    pending = await _wait_pending(client, admin_headers, agent["id"])
    assert pending["status"] == "PENDING"
    assert pending["model"] == "gpt-4o-mini"
    assert "capital of France" in pending["prompt_preview"]
    detail = (await client.get(f"/api/tickets/{pending['id']}", headers=admin_headers)).json()
    assert detail["request_headers"]["authorization"].endswith("[redacted]")
    assert detail["normalized"]["messages"][0]["role"] == "user"
    assert detail["policy_decision"]["action"] == "review"
    assert any(e["event_type"] == "created" for e in detail["events"])
    r = await client.post(
        f"/api/tickets/{pending['id']}/approve", headers=admin_headers, json={"note": "looks fine"}
    )
    assert r.status_code == 200, r.text
    resp = await task
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["choices"][0]["message"]["content"] == "echo: What is the capital of France?"
    assert body["seen_auth"] == "Bearer sk-upstream-secret", (
        "gateway must swap the AISRF key for the upstream key"
    )
    assert resp.headers["x-aisrf-ticket"] == pending["id"]
    final = (await client.get(f"/api/tickets/{pending['id']}", headers=admin_headers)).json()
    assert final["status"] == "COMPLETED"
    assert final["decided_by"] == "api-token"
    assert final["decision_note"] == "looks fine"
    assert final["response_status"] == 200
    assert "echo:" in final["response_preview"]
    assert final["upstream_url"] == "https://upstream.example/v1/chat/completions"
    r = await client.post(f"/api/tickets/{pending['id']}/approve", headers=admin_headers, json={})
    assert r.status_code == 409


async def test_denied_request_never_reaches_upstream(client, admin_headers, agent):
    key = agent["api_key"]
    task = asyncio.create_task(
        client.post("/v1/chat/completions", json=CHAT, headers={"Authorization": f"Bearer {key}"})
    )
    pending = await _wait_pending(client, admin_headers, agent["id"])
    r = await client.post(
        f"/api/tickets/{pending['id']}/deny", headers=admin_headers, json={"note": "not allowed"}
    )
    assert r.status_code == 200
    resp = await task
    assert resp.status_code == 403
    err = resp.json()["error"]
    assert err["code"] == "denied"
    assert err["ticket_id"] == pending["id"]
    final = (await client.get(f"/api/tickets/{pending['id']}", headers=admin_headers)).json()
    assert final["status"] == "DENIED"
    assert final["response_status"] is None
    assert final["forwarded_at"] is None


async def test_timeout_expires_ticket(client, admin_headers, agent, monkeypatch):
    from aisrf import config

    monkeypatch.setattr(config.get_settings(), "approval_timeout_seconds", 1)
    key = agent["api_key"]
    resp = await client.post("/v1/chat/completions", json=CHAT, headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 504
    assert resp.json()["error"]["code"] == "expired"
    tid = resp.json()["error"]["ticket_id"]
    final = (await client.get(f"/api/tickets/{tid}", headers=admin_headers)).json()
    assert final["status"] == "EXPIRED"


async def test_policy_auto_deny_pattern(client, admin_headers, agent):
    await client.patch(
        f"/api/agents/{agent['id']}", headers=admin_headers, json={"auto_deny_patterns": ["drop\\s+table"]}
    )
    body = {"model": "m", "messages": [{"role": "user", "content": "please DROP TABLE users;"}]}
    resp = await client.post(
        "/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {agent['api_key']}"}
    )
    assert resp.status_code == 403
    tid = resp.json()["error"]["ticket_id"]
    t = (await client.get(f"/api/tickets/{tid}", headers=admin_headers)).json()
    assert t["status"] == "DENIED"
    assert t["decided_by"] == "policy"
    assert t["policy_decision"]["matched_rules"] == ["agent.auto_deny_patterns"]


async def test_policy_auto_approve_when_not_required(client, admin_headers, agent):
    await client.patch(f"/api/agents/{agent['id']}", headers=admin_headers, json={"require_approval": False})
    resp = await client.post(
        "/v1/chat/completions", json=CHAT, headers={"Authorization": f"Bearer {agent['api_key']}"}
    )
    assert resp.status_code == 200
    tid = resp.headers["x-aisrf-ticket"]
    t = (await client.get(f"/api/tickets/{tid}", headers=admin_headers)).json()
    assert t["status"] == "COMPLETED"
    assert t["policy_decision"]["action"] == "approve"


async def test_allowed_paths_and_models(client, admin_headers, agent):
    await client.patch(
        f"/api/agents/{agent['id']}",
        headers=admin_headers,
        json={"require_approval": False, "allowed_models": ["gpt-4o*"]},
    )
    bad = {"model": "claude-3", "messages": [{"role": "user", "content": "hi"}]}
    resp = await client.post(
        "/v1/chat/completions", json=bad, headers={"Authorization": f"Bearer {agent['api_key']}"}
    )
    assert resp.status_code == 403
    await client.patch(
        f"/api/agents/{agent['id']}",
        headers=admin_headers,
        json={"allowed_models": [], "allowed_paths": ["v1/embeddings"]},
    )
    resp = await client.post(
        "/v1/chat/completions", json=CHAT, headers={"Authorization": f"Bearer {agent['api_key']}"}
    )
    assert resp.status_code == 403
    assert "allowed paths" in resp.json()["error"]["message"]


async def test_async_mode_returns_ticket_and_polls(client, admin_headers, agent):
    headers = {"Authorization": f"Bearer {agent['api_key']}", "X-AISRF-Async": "1"}
    resp = await client.post("/v1/chat/completions", json=CHAT, headers=headers)
    assert resp.status_code == 202
    tid = resp.json()["ticket_id"]
    poll = await client.get(f"/gateway/tickets/{tid}", headers=headers)
    assert poll.status_code == 202
    await client.post(f"/api/tickets/{tid}/approve", headers=admin_headers, json={})
    poll = await client.get(f"/gateway/tickets/{tid}", headers=headers)
    assert poll.status_code == 200, poll.text
    assert poll.json()["choices"][0]["message"]["content"].startswith("echo:")
    again = await client.get(f"/gateway/tickets/{tid}", headers=headers)
    assert again.status_code == 200
    assert again.json()["status"] == "COMPLETED"
    assert again.json()["response"]["choices"][0]["message"]["content"].startswith("echo:")


async def test_streaming_response_is_relayed_and_captured(client, admin_headers, agent):
    await client.patch(f"/api/agents/{agent['id']}", headers=admin_headers, json={"require_approval": False})
    body = {**CHAT, "stream": True}
    async with client.stream(
        "POST", "/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {agent['api_key']}"}
    ) as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        raw = b"".join([chunk async for chunk in resp.aiter_bytes()])
        tid = resp.headers["x-aisrf-ticket"]
    assert b"[DONE]" in raw
    for _ in range(50):
        t = (await client.get(f"/api/tickets/{tid}", headers=admin_headers)).json()
        if t["status"] == "COMPLETED":
            break
        await asyncio.sleep(0.05)
    assert t["status"] == "COMPLETED"
    assert t["is_stream"] is True
    assert t["response_preview"] == "Hello from upstream"


async def test_generic_proxy_path_and_custom_headers(client, admin_headers, agent):
    await client.patch(f"/api/agents/{agent['id']}", headers=admin_headers, json={"require_approval": False})
    resp = await client.get("/proxy/v1/models", headers={"X-AISRF-Key": agent["api_key"]})
    assert resp.status_code == 200
    assert resp.json()["data"][0]["id"] == "mock-model"
    tid = resp.headers["x-aisrf-ticket"]
    t = (await client.get(f"/api/tickets/{tid}", headers=admin_headers)).json()
    assert t["method"] == "GET"
    assert t["path"] == "v1/models"


async def test_anthropic_style_request_normalizes(client, admin_headers, agent):
    body = {
        "model": "claude-3-5-sonnet",
        "system": "You are terse.",
        "max_tokens": 10,
        "messages": [{"role": "user", "content": [{"type": "text", "text": "Say hi"}]}],
    }
    headers = {"x-api-key": agent["api_key"], "X-AISRF-Async": "1", "anthropic-version": "2023-06-01"}
    resp = await client.post("/v1/messages", json=body, headers=headers)
    assert resp.status_code == 202
    t = (await client.get(f"/api/tickets/{resp.json()['ticket_id']}", headers=admin_headers)).json()
    assert t["normalized"]["system"] == "You are terse."
    assert t["normalized"]["messages"][0]["content"] == "Say hi"
    assert t["normalized"]["endpoint"] == "messages"


async def test_bulk_decisions_and_stats(client, admin_headers, agent):
    headers = {"Authorization": f"Bearer {agent['api_key']}", "X-AISRF-Async": "1"}
    ids = []
    for _ in range(3):
        r = await client.post("/v1/chat/completions", json=CHAT, headers=headers)
        ids.append(r.json()["ticket_id"])
    r = await client.post(
        "/api/tickets/bulk/deny", headers=admin_headers, json={"ticket_ids": ids, "note": "batch"}
    )
    assert set(r.json().values()) == {"DENIED"}
    stats = (await client.get("/api/tickets/stats", headers=admin_headers)).json()
    assert stats["by_status"]["DENIED"] >= 3
    assert stats["total"] >= 3


async def test_agent_logs_and_events_are_recorded(client, admin_headers, agent):
    headers = {"Authorization": f"Bearer {agent['api_key']}", "X-AISRF-Async": "1"}
    r = await client.post("/v1/chat/completions", json=CHAT, headers=headers)
    tid = r.json()["ticket_id"]
    await client.post(f"/api/tickets/{tid}/deny", headers=admin_headers, json={"note": "x"})
    events = (await client.get(f"/api/agents/{agent['id']}/events", headers=admin_headers)).json()
    names = {e["event"] for e in events}
    assert {"request.intercepted", "request.analyzed", "policy.review", "decision.denied"} <= names
    from aisrf.config import get_settings

    log_files = list((get_settings().log_dir / "agents").glob("*.jsonl"))
    assert log_files, "per-agent log file must exist"
    text = "\n".join(p.read_text() for p in log_files)
    assert "request.intercepted" in text


async def test_audit_chain_is_verifiable(client, admin_headers, agent):
    headers = {"Authorization": f"Bearer {agent['api_key']}", "X-AISRF-Async": "1"}
    r = await client.post("/v1/chat/completions", json=CHAT, headers=headers)
    await client.post(f"/api/tickets/{r.json()['ticket_id']}/approve", headers=admin_headers, json={})
    audit = (await client.get("/api/audit", headers=admin_headers)).json()
    actions = [a["action"] for a in audit["items"]]
    assert "ticket.approve" in actions and "agent.create" in actions
    verify = (await client.get("/api/audit/verify", headers=admin_headers)).json()
    assert verify["ok"] is True and verify["checked"] >= 2


async def test_reviewer_login_and_roles(client, admin_headers):
    r = await client.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"
    me = await client.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["username"] == "admin"
    r = await client.post(
        "/api/auth/reviewers", json={"username": "viewer1", "password": "pw", "role": "viewer"}
    )
    assert r.status_code == 201
    async with __import__("httpx").AsyncClient(
        transport=__import__("httpx").ASGITransport(app=client._transport.app), base_url="http://testserver"
    ) as c2:
        r = await c2.post("/api/auth/login", json={"username": "viewer1", "password": "pw"})
        assert r.status_code == 200
        r = await c2.post("/api/tickets/nonexistent/approve", json={})
        assert r.status_code == 403
        r = await c2.post("/api/agents", json={"name": "x"})
        assert r.status_code == 403
    r = await client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


async def test_rate_limit(client, admin_headers, agent):
    await client.patch(
        f"/api/agents/{agent['id']}",
        headers=admin_headers,
        json={"rate_limit_per_minute": 2, "require_approval": False},
    )
    h = {"Authorization": f"Bearer {agent['api_key']}"}
    codes = [(await client.post("/v1/chat/completions", json=CHAT, headers=h)).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


async def test_metrics_and_health(client):
    assert (await client.get("/healthz")).json()["status"] == "ok"
    assert (await client.get("/readyz")).status_code == 200
    m = await client.get("/metrics")
    assert m.status_code == 200 and "aisrf_" in m.text


async def test_key_rotation_invalidates_old_key(client, admin_headers, agent):
    old = agent["api_key"]
    r = await client.post(f"/api/agents/{agent['id']}/rotate-key", headers=admin_headers)
    new = r.json()["api_key"]
    assert new != old
    h_old = {"Authorization": f"Bearer {old}", "X-AISRF-Async": "1"}
    h_new = {"Authorization": f"Bearer {new}", "X-AISRF-Async": "1"}
    assert (await client.post("/v1/chat/completions", json=CHAT, headers=h_old)).status_code == 401
    assert (await client.post("/v1/chat/completions", json=CHAT, headers=h_new)).status_code == 202


async def test_scan_tokens_authenticate_until_revoked(client, admin_headers, agent, app):
    from aisrf.agents import service as agents
    from aisrf.db import get_sessionmaker

    async with get_sessionmaker()() as s:
        _tok, raw = await agents.mint_scan_token(
            s, agent["id"], ttl_seconds=60, purpose="garak", campaign_id="cmp_test"
        )
        await s.commit()
    assert raw.startswith("aisrf_scan_")
    h = {"Authorization": f"Bearer {raw}", "X-AISRF-Async": "1"}
    r = await client.post("/v1/chat/completions", json=CHAT, headers=h)
    assert r.status_code == 202
    t = (await client.get(f"/api/tickets/{r.json()['ticket_id']}", headers=admin_headers)).json()
    assert t["agent_id"] == agent["id"]
    async with get_sessionmaker()() as s:
        assert await agents.revoke_scan_tokens(s, campaign_id="cmp_test") == 1
        await s.commit()
    assert (await client.post("/v1/chat/completions", json=CHAT, headers=h)).status_code == 401


async def test_concurrent_tickets_get_unique_numbers(client, admin_headers, agent):
    h = {"Authorization": f"Bearer {agent['api_key']}", "X-AISRF-Async": "1"}
    responses = await asyncio.gather(
        *(client.post("/v1/chat/completions", json=CHAT, headers=h) for _ in range(25))
    )
    assert all(r.status_code == 202 for r in responses), [r.status_code for r in responses]
    ids = [r.json()["ticket_id"] for r in responses]
    numbers = []
    for tid in ids:
        numbers.append((await client.get(f"/api/tickets/{tid}", headers=admin_headers)).json()["number"])
    assert len(set(numbers)) == 25
    assert all(isinstance(n, int) for n in numbers)
