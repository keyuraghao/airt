"""Builds and executes the upstream request after a ticket is approved.

The frontend never holds real provider credentials: the gateway swaps the agent's AIRT
key for the encrypted upstream key stored on the agent record.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx

from ..agents.service import upstream_api_key
from ..config import get_settings
from ..models import Agent

HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "accept-encoding",
}
STRIP_INBOUND = HOP_BY_HOP | {
    "authorization",
    "x-api-key",
    "x-airt-key",
    "x-airt-async",
    "x-airt-agent",
    "cookie",
    "x-goog-api-key",
    "api-key",
}


def build_upstream_url(agent: Agent, path: str, query: str = "") -> str:
    base = (agent.upstream_base_url or "").rstrip("/")
    path = path.strip("/")
    base_last = urlsplit(base).path.rstrip("/").split("/")[-1] if base else ""
    if base_last and path.split("/")[0] == base_last:
        path = "/".join(path.split("/")[1:])
    url = f"{base}/{path}" if path else base
    if query:
        url += f"?{query}"
    return url


def build_upstream_headers(agent: Agent, inbound: dict[str, str]) -> dict[str, str]:
    headers = {k: v for k, v in inbound.items() if k.lower() not in STRIP_INBOUND}
    key = upstream_api_key(agent)
    provider = (agent.upstream_provider or "custom").lower()
    if key:
        if provider in (
            "openai",
            "ollama",
            "azure_openai_compat",
            "groq",
            "together",
            "mistral",
            "deepseek",
            "openrouter",
        ):
            headers["Authorization"] = f"Bearer {key}"
        elif provider == "anthropic":
            headers["x-api-key"] = key
            headers.setdefault("anthropic-version", inbound.get("anthropic-version", "2023-06-01"))
        elif provider == "azure":
            headers["api-key"] = key
        elif provider in ("google", "gemini"):
            headers["x-goog-api-key"] = key
        elif agent.upstream_auth_header:
            name = agent.upstream_auth_header
            headers[name] = f"Bearer {key}" if name.lower() == "authorization" else key
        else:
            headers["Authorization"] = f"Bearer {key}"
    for k, v in (agent.upstream_extra_headers or {}).items():
        headers[k] = v
    headers.setdefault("user-agent", "airt-gateway/1.0")
    return headers


def filter_response_headers(headers: httpx.Headers) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in HOP_BY_HOP or k.lower() in ("content-encoding", "content-length"):
            continue
        out[k] = v
    return out


@dataclass
class UpstreamResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes
    latency_ms: float


def make_client() -> httpx.AsyncClient:
    s = get_settings()
    timeout = httpx.Timeout(s.upstream_timeout_seconds, connect=s.upstream_connect_timeout_seconds)
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        limits=httpx.Limits(max_connections=200, max_keepalive_connections=50),
    )


def build_request(
    client: httpx.AsyncClient,
    agent: Agent,
    method: str,
    path: str,
    query: str,
    inbound_headers: dict[str, str],
    body: bytes,
) -> httpx.Request:
    url = build_upstream_url(agent, path, query)
    headers = build_upstream_headers(agent, inbound_headers)
    return client.build_request(method, url, headers=headers, content=body if body else None)


def summarize_error(exc: Exception) -> str:
    if isinstance(exc, httpx.ConnectError):
        return f"upstream connection failed: {exc}"
    if isinstance(exc, httpx.TimeoutException):
        return f"upstream timed out: {exc}"
    return f"{type(exc).__name__}: {exc}"


def error_json(
    ticket_id: str, status: str, message: str, extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    return {
        "error": {
            "message": message,
            "type": "airt_gateway",
            "code": status.lower(),
            "ticket_id": ticket_id,
            **(extra or {}),
        }
    }
