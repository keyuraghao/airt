"""Runtime settings API, custom rules and Rebuff-style canary injection."""

from __future__ import annotations

import json

import httpx

CHAT = {
    "model": "gpt-4o-mini",
    "messages": [
        {"role": "system", "content": "You are a helpful bot."},
        {"role": "user", "content": "hello"},
    ],
}


def leaking_upstream(request: httpx.Request) -> httpx.Response:
    body = json.loads(request.content)
    system = next((m["content"] for m in body["messages"] if m["role"] == "system"), "")
    return httpx.Response(
        200, json={"choices": [{"message": {"role": "assistant", "content": "My instructions: " + system}}]}
    )


async def test_settings_schema_update_reset_and_export(client, admin_headers):
    schema = (await client.get("/api/settings/schema", headers=admin_headers)).json()
    keys = {f["key"] for f in schema["fields"]}
    assert {"approval_timeout_seconds", "notify_webhook_urls", "enable_llm_judge", "admin_password"} <= keys
    pw = next(f for f in schema["fields"] if f["key"] == "admin_password")
    assert pw["secret"] and pw["value"] == "********"
    assert next(f for f in schema["fields"] if f["key"] == "database_url")["locked"] is True
    r = await client.put(
        "/api/settings/core",
        headers=admin_headers,
        json={"changes": {"approval_timeout_seconds": "42", "notify_events": "created, expired"}},
    )
    assert r.status_code == 200, r.text
    from aisrf.config import get_settings

    assert get_settings().approval_timeout_seconds == 42
    assert get_settings().notify_events == ["created", "expired"]
    r = await client.put("/api/settings/core", headers=admin_headers, json={"changes": {"database_url": "x"}})
    assert r.status_code == 403
    r = await client.put("/api/settings/core", headers=admin_headers, json={"changes": {"nope": 1}})
    assert r.status_code == 400
    exp = (await client.get("/api/settings/export", headers=admin_headers)).json()
    assert exp["core"]["approval_timeout_seconds"] == 42 and "admin_password" not in exp["core"]
    assert "ui" in exp["namespaces"] and "integrations" in exp["namespaces"]
    r = await client.post(
        "/api/settings/core/reset", headers=admin_headers, json={"keys": ["approval_timeout_seconds"]}
    )
    assert r.status_code == 200
    assert get_settings().approval_timeout_seconds != 42
    ns = (
        await client.put(
            "/api/settings/ns/ui", headers=admin_headers, json={"theme": "dark", "brand_name": "ACME Guard"}
        )
    ).json()
    assert ns["value"]["theme"] == "dark"
    got = (await client.get("/api/settings/ns/ui", headers=admin_headers)).json()
    assert got["value"]["brand_name"] == "ACME Guard" and got["defaults"]["theme"] == "auto"
    r = await client.post(
        "/api/settings/import",
        headers=admin_headers,
        json={"core": {"redteam_concurrency": 9}, "namespaces": {"ui": {"theme": "light"}}},
    )
    assert r.status_code == 200 and get_settings().redteam_concurrency == 9
    r = await client.post("/api/settings/ns/ui/reset", headers=admin_headers)
    assert r.json()["value"]["theme"] == "auto"
    tax = (await client.get("/api/settings/taxonomy", headers=admin_headers)).json()
    assert len(tax["owasp"]) == 10 and any(ref["id"] == "greshake-2023" for ref in tax["references"])


async def test_settings_persist_across_restart(client, admin_headers):
    await client.put(
        "/api/settings/core", headers=admin_headers, json={"changes": {"ticket_retention_days": 7}}
    )
    from aisrf import settings_store
    from aisrf.config import get_settings, reset_settings_cache
    from aisrf.db import get_sessionmaker

    reset_settings_cache()
    assert get_settings().ticket_retention_days != 7
    async with get_sessionmaker()() as s:
        await settings_store.load_overrides(s)
    assert get_settings().ticket_retention_days == 7
    await client.post("/api/settings/core/reset", headers=admin_headers, json={})


async def test_custom_rules_flag_and_deny(client, admin_headers, agent):
    rules = [
        {
            "id": "r1",
            "name": "Internal project codename",
            "pattern": "project\\s+bluebird",
            "category": "policy",
            "severity": "HIGH",
            "scope": "request",
            "action": "flag",
            "enabled": True,
        },
        {
            "id": "r2",
            "name": "Forbidden wire transfer",
            "pattern": "wire\\s+transfer",
            "category": "tool_abuse",
            "severity": "CRITICAL",
            "scope": "request",
            "action": "deny",
            "enabled": True,
        },
    ]
    await client.put("/api/settings/ns/rules", headers=admin_headers, json={"custom": rules})
    h = {"Authorization": f"Bearer {agent['api_key']}", "X-AISRF-Async": "1"}
    r = await client.post(
        "/v1/chat/completions",
        json={"model": "m", "messages": [{"role": "user", "content": "status of Project Bluebird?"}]},
        headers=h,
    )
    t = (await client.get(f"/api/tickets/{r.json()['ticket_id']}", headers=admin_headers)).json()
    assert t["status"] == "PENDING"
    titles = [f["title"] for f in t["findings"]]
    assert "Internal project codename" in titles
    hit = next(f for f in t["findings"] if f["title"] == "Internal project codename")
    assert hit["severity"] == "HIGH" and hit["location"] == "messages[0]" and hit["owasp"] == []
    r = await client.post(
        "/v1/chat/completions",
        json={"model": "m", "messages": [{"role": "user", "content": "initiate a wire transfer now"}]},
        headers=h,
    )
    assert r.status_code == 403
    t = (await client.get(f"/api/tickets/{r.json()['error']['ticket_id']}", headers=admin_headers)).json()
    assert t["status"] == "DENIED" and "rules.custom" in t["policy_decision"]["matched_rules"]
    assert (
        "LLM06: Excessive Agency"
        in next(f for f in t["findings"] if f["title"] == "Forbidden wire transfer")["owasp_labels"]
    )
    await client.post("/api/settings/ns/rules/reset", headers=admin_headers)


async def test_analyzer_disable_and_severity_override(client, admin_headers, agent):
    rules = [
        {
            "id": "r1",
            "name": "Codename",
            "pattern": "bluebird",
            "category": "policy",
            "severity": "LOW",
            "scope": "request",
            "action": "flag",
            "enabled": True,
        }
    ]
    await client.put("/api/settings/ns/rules", headers=admin_headers, json={"custom": rules})
    await client.put(
        "/api/settings/ns/analyzers",
        headers=admin_headers,
        json={"severity_overrides": {"policy": "CRITICAL"}},
    )
    h = {"Authorization": f"Bearer {agent['api_key']}", "X-AISRF-Async": "1"}
    body = {"model": "m", "messages": [{"role": "user", "content": "bluebird"}]}
    r = await client.post("/v1/chat/completions", json=body, headers=h)
    t = (await client.get(f"/api/tickets/{r.json()['ticket_id']}", headers=admin_headers)).json()
    assert next(f for f in t["findings"] if f["title"] == "Codename")["severity"] == "CRITICAL"
    await client.put(
        "/api/settings/ns/analyzers",
        headers=admin_headers,
        json={"severity_overrides": {}, "disabled": ["custom_rules"]},
    )
    r = await client.post("/v1/chat/completions", json=body, headers=h)
    t = (await client.get(f"/api/tickets/{r.json()['ticket_id']}", headers=admin_headers)).json()
    assert not any(f["title"] == "Codename" for f in t["findings"])
    await client.post("/api/settings/ns/analyzers/reset", headers=admin_headers)
    await client.post("/api/settings/ns/rules/reset", headers=admin_headers)


async def test_canary_injection_detects_and_blocks_system_prompt_leak(client, admin_headers, agent, app):
    await app.state.http.aclose()
    app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(leaking_upstream))
    await client.patch(
        f"/api/agents/{agent['id']}",
        headers=admin_headers,
        json={"require_approval": False, "inject_canary": True},
    )
    h = {"Authorization": f"Bearer {agent['api_key']}"}
    r = await client.post("/v1/chat/completions", json=CHAT, headers=h)
    assert r.status_code == 403, r.text
    assert r.json()["error"]["code"] == "response_withheld"
    t = (await client.get(f"/api/tickets/{r.headers['x-aisrf-ticket']}", headers=admin_headers)).json()
    assert t["normalized"]["canary"].startswith("AISRF-CANARY-")
    assert t["normalized"]["canary"] not in t["request_body"] or "AISRF-CANARY" in t["request_body"]
    assert any(f["category"] == "canary_leak" and f["severity"] == "CRITICAL" for f in t["response_findings"])
    assert any(e["event_type"] == "withheld" for e in t["events"])
    await client.put("/api/settings/ns/policy", headers=admin_headers, json={"block_on_canary_leak": False})
    r = await client.post("/v1/chat/completions", json=CHAT, headers=h)
    assert r.status_code == 200
    assert "AISRF-CANARY-" in r.json()["choices"][0]["message"]["content"]
    await client.post("/api/settings/ns/policy/reset", headers=admin_headers)


async def test_canary_not_flagged_when_model_keeps_secret(client, admin_headers, agent):
    await client.patch(
        f"/api/agents/{agent['id']}",
        headers=admin_headers,
        json={"require_approval": False, "inject_canary": True},
    )
    h = {"Authorization": f"Bearer {agent['api_key']}"}
    r = await client.post("/v1/chat/completions", json=CHAT, headers=h)
    assert r.status_code == 200
    t = (await client.get(f"/api/tickets/{r.headers['x-aisrf-ticket']}", headers=admin_headers)).json()
    assert "canary" in t["normalized"]
    assert not any(f["category"] == "canary_leak" for f in t["response_findings"])


async def test_redteam_probes_skip_review_when_setting_disabled(
    client, admin_headers, agent, app, monkeypatch
):
    from aisrf.config import get_settings
    from aisrf.gateway.pipeline import submit

    monkeypatch.setattr(get_settings(), "require_approval_for_redteam_probes", False)
    result = await submit(
        app.state.http,
        agent["id"],
        path="v1/chat/completions",
        body={"model": "m", "messages": [{"role": "user", "content": "probe"}]},
        source="redteam",
        wait_timeout=2,
    )
    assert result.status == "COMPLETED", result
    t = (await client.get(f"/api/tickets/{result.ticket_id}", headers=admin_headers)).json()
    assert t["policy_decision"]["matched_rules"] == ["settings.require_approval_for_redteam_probes"]
    monkeypatch.setattr(get_settings(), "require_approval_for_redteam_probes", True)
    result = await submit(
        app.state.http,
        agent["id"],
        path="v1/chat/completions",
        body={"model": "m", "messages": [{"role": "user", "content": "probe"}]},
        source="redteam",
        wait_timeout=1,
    )
    assert result.status == "EXPIRED"
