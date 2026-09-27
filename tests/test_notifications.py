"""Webhook notifier delivers Slack-style and generic payloads for ticket events."""

from __future__ import annotations

import asyncio
import json

import httpx

from aisrf import notifications
from aisrf.logging import broadcaster


async def test_notifier_posts_to_webhooks(monkeypatch):
    from aisrf.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(
        settings, "notify_webhook_urls", ["https://hooks.slack.com/services/x", "https://example.com/hook"]
    )
    monkeypatch.setattr(settings, "notify_events", ["created"])
    monkeypatch.setattr(settings, "notify_min_risk", 10)
    received: list[tuple[str, dict]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append((str(request.url), json.loads(request.content)))
        return httpx.Response(200)

    n = notifications.Notifier()
    await n.start()
    await n._client.aclose()
    n._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ticket = {
        "id": "tkt_1",
        "number": 7,
        "agent_name": "bot",
        "model": "m",
        "risk_score": 55,
        "risk_level": "HIGH",
        "prompt_preview": "hi",
        "path": "v1/chat/completions",
        "policy_action": "review",
    }
    broadcaster.publish("tickets", {"event": "created", "ticket": ticket})
    broadcaster.publish("tickets", {"event": "created", "ticket": {**ticket, "risk_score": 1}})
    broadcaster.publish("tickets", {"event": "decided", "ticket": ticket})
    for _ in range(50):
        if len(received) >= 2:
            break
        await asyncio.sleep(0.02)
    await n.stop()
    assert len(received) == 2
    slack = next(p for u, p in received if "slack" in u)
    generic = next(p for u, p in received if "example.com" in u)
    assert "#7" in slack["text"] and slack["blocks"]
    assert (
        generic["event"] == "created"
        and generic["ticket"]["id"] == "tkt_1"
        and generic["link"].endswith("/tickets/tkt_1")
    )
