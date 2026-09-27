"""Shared fixtures: an isolated SQLite database per test, a mocked upstream and an ASGI client with lifespan."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import types
from pathlib import Path

import httpx
import pytest

_TMP = Path(tempfile.mkdtemp(prefix="aisrf-test-"))
os.environ.setdefault("AISRF_DATABASE_URL", f"sqlite+aiosqlite:///{_TMP / 'test.db'}")
os.environ.setdefault("AISRF_DATA_DIR", str(_TMP / "data"))
os.environ.setdefault("AISRF_LOG_DIR", str(_TMP / "logs"))
os.environ.setdefault("AISRF_ADMIN_API_TOKEN", "test-admin-token")
os.environ.setdefault("AISRF_APPROVAL_TIMEOUT_SECONDS", "5")
os.environ.setdefault("AISRF_HOLD_POLL_INTERVAL_SECONDS", "0.2")
os.environ.setdefault("AISRF_LOG_LEVEL", "WARNING")


def _stand_in(name: str, **attrs):
    if name in sys.modules:
        return
    try:
        __import__(name)
        return
    except Exception:
        pass
    mod = types.ModuleType(name)
    for k, v in attrs.items():
        setattr(mod, k, v)
    sys.modules[name] = mod


def _install_stand_ins() -> None:
    from fastapi import APIRouter

    _stand_in(
        "aisrf.redteam.engine", campaign_runner=types.SimpleNamespace(shutdown=lambda: asyncio.sleep(0))
    )
    _stand_in("aisrf.redteam.router", router=APIRouter())
    _stand_in("aisrf.reports.router", router=APIRouter())
    _stand_in("aisrf.dashboard.router", mount_dashboard=lambda app: None)
    _stand_in("aisrf.mcp_server", mount_mcp=lambda app: None)


def openai_upstream_handler(request: httpx.Request) -> httpx.Response:
    """Fake OpenAI-compatible upstream used as app.state.http transport."""
    body = json.loads(request.content or b"{}") if request.content else {}
    auth = request.headers.get("authorization", "")
    last = ""
    for m in body.get("messages", []):
        if m.get("role") == "user":
            last = m.get("content") if isinstance(m.get("content"), str) else ""
    if request.url.path.endswith("/models"):
        return httpx.Response(200, json={"object": "list", "data": [{"id": "mock-model"}], "auth": auth})
    if body.get("stream"):
        chunks = []
        for word in ("Hello", " from", " upstream"):
            chunks.append("data: " + json.dumps({"choices": [{"delta": {"content": word}}]}) + "\n\n")
        chunks.append("data: [DONE]\n\n")
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, content="".join(chunks).encode()
        )
    return httpx.Response(
        200,
        json={
            "id": "chatcmpl-mock",
            "object": "chat.completion",
            "model": body.get("model", "mock"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": f"echo: {last}"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1},
            "seen_auth": auth,
        },
    )


@pytest.fixture
async def app():
    _install_stand_ins()
    from aisrf import config, db

    config.reset_settings_cache()
    await db.dispose_db()
    from aisrf.main import create_app

    application = create_app()
    async with application.router.lifespan_context(application):
        await application.state.http.aclose()
        application.state.http = httpx.AsyncClient(transport=httpx.MockTransport(openai_upstream_handler))
        yield application
    await db.dispose_db()


@pytest.fixture
async def client(app):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as c:
        yield c


@pytest.fixture
def admin_headers():
    return {"Authorization": "Bearer test-admin-token"}


@pytest.fixture
async def agent(client, admin_headers):
    r = await client.post(
        "/api/agents",
        headers=admin_headers,
        json={
            "name": f"test-agent-{os.urandom(3).hex()}",
            "upstream_provider": "openai",
            "upstream_base_url": "https://upstream.example/v1",
            "upstream_api_key": "sk-upstream-secret",
            "require_approval": True,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()
