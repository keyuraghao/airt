"""Python client helpers for the AISRF gateway.

Four ways to get traffic through the gateway, from least to most intrusive:

1. ``configure(gateway_url, agent_key)`` sets the environment variables the official
   ``openai`` and ``anthropic`` SDKs read (``OPENAI_BASE_URL`` / ``OPENAI_API_KEY`` and
   ``ANTHROPIC_BASE_URL`` / ``ANTHROPIC_API_KEY``). Call it before the SDK client is built.

2. ``patch_httpx()`` installs an httpx request hook on every ``httpx.Client`` and
   ``httpx.AsyncClient`` created afterwards. Requests to a known provider host
   (api.openai.com, api.anthropic.com, ...) are rewritten to
   ``<gateway>/proxy/<original path>`` with the AISRF headers. This catches SDKs and
   libraries you cannot reconfigure, as long as they use httpx (the OpenAI, Anthropic,
   Mistral and Groq SDKs all do).

3. ``patch_requests()`` does the same for the ``requests`` library.

4. ``AISRFClient`` / ``AsyncAISRFClient`` talk to the gateway explicitly, understand the
   asynchronous ticket flow (``X-AISRF-Async: 1`` -> 202 -> poll ``/gateway/tickets/{id}``)
   and return a small ``AISRFResponse`` with the ticket id, final status and upstream body.

LangChain: nothing special is needed. Point the provider integration at the gateway::

    from langchain_openai import ChatOpenAI
    llm = ChatOpenAI(model="gpt-4o-mini", base_url="http://localhost:8080/v1", api_key="aisrf_...")

    from langchain_anthropic import ChatAnthropic
    llm = ChatAnthropic(model="claude-3-5-haiku-latest", base_url="http://localhost:8080", api_key="aisrf_...")

Or call ``configure(...)`` first and build the LangChain objects with no arguments; they pick
up the same environment variables as the official SDKs.

Gateway contract used here (see aisrf/gateway/router.py):

* agent key: header ``X-AISRF-Key`` (also accepted in ``Authorization: Bearer``);
* ``X-AISRF-Source``: one of gateway, sdk, mitm, redteam (anything else is stored as gateway);
* ``X-AISRF-Correlation-Id``: optional, ties several tickets to one logical operation;
* ``X-AISRF-Async: 1``: return ``202 {"ticket_id", "status": "PENDING", "poll_url"}`` instead of
  blocking until a reviewer decides;
* ``GET /gateway/tickets/{id}``: ``202`` while PENDING, the relayed upstream response once the
  ticket is APPROVED (the poll itself triggers the upstream call), ``200`` with the stored
  response once COMPLETED, ``403`` for DENIED/EXPIRED, ``502`` for FAILED;
* every relayed response carries ``X-AISRF-Ticket: <ticket id>``.

Only the standard library and (optionally) httpx / requests are imported; both are guarded so
the module imports cleanly in any environment.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Self
from urllib.parse import urlsplit

try:  # httpx is a hard dependency of the aisrf package but optional for this module
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore[assignment]

__all__ = [
    "DEFAULT_PROVIDER_HOSTS",
    "FINAL_TICKET_STATUSES",
    "AISRFClient",
    "AISRFError",
    "AISRFResponse",
    "AsyncAISRFClient",
    "configure",
    "default_headers",
    "get_config",
    "patch_httpx",
    "patch_requests",
    "unpatch_httpx",
    "unpatch_requests",
]

# Hosts whose traffic is redirected by patch_httpx / patch_requests. Entries may carry a port;
# "localhost:11434" only matches Ollama on its default port, while "api.openai.com" matches on any port.
DEFAULT_PROVIDER_HOSTS: tuple[str, ...] = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.groq.com",
    "openrouter.ai",
    "localhost:11434",
)
TICKET_STATUSES = frozenset({"PENDING", "APPROVED", "DENIED", "EXPIRED", "FORWARDING", "COMPLETED", "FAILED"})
FINAL_TICKET_STATUSES = frozenset({"COMPLETED", "DENIED", "EXPIRED", "FAILED"})
_ENV_URL = "AISRF_GATEWAY_URL"
_ENV_KEY = "AISRF_AGENT_KEY"
_ENV_ASYNC = "AISRF_ASYNC_MODE"
_ENV_SOURCE = "AISRF_SOURCE"


class AISRFError(RuntimeError):
    """Raised by AISRFClient.raise_for_status style helpers and on misconfiguration."""

    def __init__(self, message: str, response: AISRFResponse | None = None) -> None:
        super().__init__(message)
        self.response = response


@dataclass
class _Config:
    gateway_url: str = ""
    agent_key: str = ""
    async_mode: bool = False
    source: str = "sdk"
    hosts: tuple[str, ...] = DEFAULT_PROVIDER_HOSTS
    correlation_id: str | None = None

    @property
    def configured(self) -> bool:
        return bool(self.gateway_url and self.agent_key)


_config = _Config(
    gateway_url=os.environ.get(_ENV_URL, "").rstrip("/"),
    agent_key=os.environ.get(_ENV_KEY, ""),
    async_mode=os.environ.get(_ENV_ASYNC, "").lower() in ("1", "true", "yes"),
    source=os.environ.get(_ENV_SOURCE, "sdk") or "sdk",
)


def configure(
    gateway_url: str,
    agent_key: str,
    *,
    async_mode: bool = False,
    source: str = "sdk",
    hosts: tuple[str, ...] | list[str] | None = None,
    correlation_id: str | None = None,
    set_env: bool = True,
) -> dict[str, str]:
    """Point the official SDKs (and this module) at the gateway.

    Sets ``OPENAI_BASE_URL=<gateway>/v1``, ``OPENAI_API_KEY=<agent key>``,
    ``ANTHROPIC_BASE_URL=<gateway>`` and ``ANTHROPIC_API_KEY=<agent key>`` so that
    ``openai.OpenAI()`` and ``anthropic.Anthropic()`` built afterwards go through AISRF without
    any code change. Also records ``AISRF_GATEWAY_URL`` / ``AISRF_AGENT_KEY`` for child processes.

    ``async_mode`` and ``source`` cannot be expressed through the SDK environment variables (there
    is no env var for extra headers). They apply to ``patch_httpx()``, ``patch_requests()`` and
    ``AISRFClient``; for the plain SDKs pass ``default_headers=default_headers()`` to the client.

    Returns the environment mapping that was applied (useful for subprocess.Popen(env=...)).
    """
    if not gateway_url or not agent_key:
        raise AISRFError("configure() needs both gateway_url and agent_key")
    gateway_url = gateway_url.rstrip("/")
    _config.gateway_url = gateway_url
    _config.agent_key = agent_key
    _config.async_mode = bool(async_mode)
    _config.source = source or "sdk"
    _config.hosts = tuple(hosts) if hosts else DEFAULT_PROVIDER_HOSTS
    _config.correlation_id = correlation_id
    env = {
        "OPENAI_BASE_URL": gateway_url + "/v1",
        "OPENAI_API_KEY": agent_key,
        "ANTHROPIC_BASE_URL": gateway_url,
        "ANTHROPIC_API_KEY": agent_key,
        _ENV_URL: gateway_url,
        _ENV_KEY: agent_key,
        _ENV_ASYNC: "1" if async_mode else "0",
        _ENV_SOURCE: _config.source,
    }
    if set_env:
        os.environ.update(env)
    return env


def get_config() -> dict[str, Any]:
    """Current module configuration (agent key is masked)."""
    key = _config.agent_key
    return {
        "gateway_url": _config.gateway_url,
        "agent_key": (key[:10] + "...") if len(key) > 10 else ("set" if key else ""),
        "async_mode": _config.async_mode,
        "source": _config.source,
        "hosts": list(_config.hosts),
        "correlation_id": _config.correlation_id,
    }


def default_headers(
    *, async_mode: bool | None = None, source: str | None = None, correlation_id: str | None = None
) -> dict[str, str]:
    """AISRF headers for an SDK client, e.g. ``OpenAI(default_headers=default_headers())``."""
    _require_config()
    headers = {"X-AISRF-Key": _config.agent_key, "X-AISRF-Source": source or _config.source}
    if async_mode if async_mode is not None else _config.async_mode:
        headers["X-AISRF-Async"] = "1"
    cid = correlation_id or _config.correlation_id
    if cid:
        headers["X-AISRF-Correlation-Id"] = cid
    return headers


def _require_config() -> None:
    if not _config.configured:
        raise AISRFError(
            "AISRF is not configured: call configure(gateway_url, agent_key) or set AISRF_GATEWAY_URL and AISRF_AGENT_KEY"
        )


# --- URL rewriting ------------------------------------------------------------------
def _host_matches(host: str, port: int | None, patterns: tuple[str, ...]) -> bool:
    host = (host or "").lower()
    if not host:
        return False
    with_port = f"{host}:{port}" if port else host
    for pat in patterns:
        pat = pat.lower()
        if ":" in pat:
            if with_port == pat:
                return True
        elif host == pat or host.endswith("." + pat):
            return True
    return False


def _gateway_target(original_url: str, gateway_url: str | None = None) -> str | None:
    """Return the gateway URL for ``original_url`` when its host is a provider host, else None."""
    parts = urlsplit(original_url)
    if not _host_matches(parts.hostname or "", parts.port, _config.hosts):
        return None
    base = (gateway_url or _config.gateway_url).rstrip("/")
    path = parts.path.lstrip("/")
    target = f"{base}/proxy/{path}"
    if parts.query:
        target += "?" + parts.query
    return target


def _apply_headers(headers: Any, *, async_mode: bool | None = None, source: str | None = None) -> None:
    """Set the AISRF headers on any mutable mapping-like header container."""
    for k, v in default_headers(async_mode=async_mode, source=source).items():
        headers[k] = v


# --- httpx ------------------------------------------------------------------------------
_httpx_original_init: dict[str, Callable[..., None]] = {}


def _httpx_rewrite(request: Any) -> None:
    if not _config.configured:
        return
    target = _gateway_target(str(request.url))
    if target is None:
        return
    new_url = httpx.URL(target)
    request.url = new_url
    request.headers["Host"] = new_url.netloc.decode("ascii")
    _apply_headers(request.headers)


async def _httpx_rewrite_async(request: Any) -> None:
    _httpx_rewrite(request)


def patch_httpx(
    gateway_url: str | None = None,
    agent_key: str | None = None,
    *,
    async_mode: bool | None = None,
    source: str | None = None,
) -> bool:
    """Monkeypatch ``httpx.Client`` and ``httpx.AsyncClient`` so every client created afterwards
    rewrites provider requests to ``<gateway>/proxy/<path>`` and adds the AISRF headers.

    Arguments are optional when ``configure()`` was already called. Returns True when the patch
    was installed, False when it was already active. Clients created *before* the call are not
    affected; use ``client.event_hooks["request"].append(...)`` for those or create them later.
    """
    if httpx is None:
        raise AISRFError("httpx is not installed; pip install httpx")
    if gateway_url and agent_key:
        configure(
            gateway_url,
            agent_key,
            async_mode=bool(async_mode),
            source=source or _config.source,
            set_env=False,
        )
    else:
        if async_mode is not None:
            _config.async_mode = bool(async_mode)
        if source:
            _config.source = source
    _require_config()
    if _httpx_original_init:
        return False
    for cls_name, hook in (("Client", _httpx_rewrite), ("AsyncClient", _httpx_rewrite_async)):
        cls = getattr(httpx, cls_name)
        original = cls.__init__
        _httpx_original_init[cls_name] = original

        def make_init(orig: Callable[..., None], request_hook: Callable[..., Any]) -> Callable[..., None]:
            def __init__(self: Any, *args: Any, **kwargs: Any) -> None:
                orig(self, *args, **kwargs)
                hooks = dict(self.event_hooks)
                request_hooks = list(hooks.get("request", []))
                if request_hook not in request_hooks:
                    request_hooks.append(request_hook)
                hooks["request"] = request_hooks
                self.event_hooks = hooks

            __init__.__wrapped__ = orig  # type: ignore[attr-defined]
            return __init__

        cls.__init__ = make_init(original, hook)  # type: ignore[method-assign]
    return True


def unpatch_httpx() -> None:
    """Restore the original httpx constructors."""
    if httpx is None:
        return
    for cls_name, original in _httpx_original_init.items():
        getattr(httpx, cls_name).__init__ = original
    _httpx_original_init.clear()


# --- requests ------------------------------------------------------------------------------
_requests_original_send: Callable[..., Any] | None = None


def _requests_rewrite(prepared: Any) -> None:
    if not _config.configured:
        return
    target = _gateway_target(prepared.url)
    if target is None:
        return
    prepared.url = target
    prepared.headers.pop("Host", None)
    _apply_headers(prepared.headers)


def patch_requests(
    gateway_url: str | None = None,
    agent_key: str | None = None,
    *,
    async_mode: bool | None = None,
    source: str | None = None,
) -> bool:
    """Same as ``patch_httpx`` for the ``requests`` library (wraps ``requests.Session.send``).

    Also see ``AISRFAdapter`` for an explicit ``session.mount("https://api.openai.com", AISRFAdapter())``
    style installation that does not touch global state.
    """
    global _requests_original_send
    try:
        import requests
    except ImportError as exc:
        raise AISRFError("requests is not installed; pip install requests") from exc
    if gateway_url and agent_key:
        configure(
            gateway_url,
            agent_key,
            async_mode=bool(async_mode),
            source=source or _config.source,
            set_env=False,
        )
    else:
        if async_mode is not None:
            _config.async_mode = bool(async_mode)
        if source:
            _config.source = source
    _require_config()
    if _requests_original_send is not None:
        return False
    original = requests.Session.send
    _requests_original_send = original

    def send(self: Any, request: Any, **kwargs: Any) -> Any:
        _requests_rewrite(request)
        return original(self, request, **kwargs)

    requests.Session.send = send  # type: ignore[method-assign]
    return True


def unpatch_requests() -> None:
    global _requests_original_send
    if _requests_original_send is None:
        return
    import requests

    requests.Session.send = _requests_original_send  # type: ignore[method-assign]
    _requests_original_send = None


def make_requests_adapter(**adapter_kwargs: Any) -> Any:
    """Build a ``requests`` HTTPAdapter subclass instance that rewrites provider URLs.

    Usage::

        s = requests.Session()
        adapter = make_requests_adapter()
        for host in DEFAULT_PROVIDER_HOSTS:
            s.mount("https://" + host, adapter)
    """
    try:
        from requests.adapters import HTTPAdapter
    except ImportError as exc:
        raise AISRFError("requests is not installed; pip install requests") from exc

    class AISRFAdapter(HTTPAdapter):
        def send(self, request: Any, **kwargs: Any) -> Any:  # type: ignore[override]
            _requests_rewrite(request)
            return super().send(request, **kwargs)

    return AISRFAdapter(**adapter_kwargs)


# --- explicit client --------------------------------------------------------------------
@dataclass
class AISRFResponse:
    """Outcome of one gateway submission."""

    ticket_id: str | None
    status: str  # PENDING | APPROVED | FORWARDING | COMPLETED | DENIED | EXPIRED | FAILED | UNKNOWN
    http_status: int
    data: Any = None  # parsed JSON body of the upstream response (or gateway envelope)
    text: str = ""  # raw body when it is not JSON
    headers: dict[str, str] = field(default_factory=dict)
    decided_by: str | None = None
    decision_note: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "COMPLETED" and 200 <= self.http_status < 300

    @property
    def is_final(self) -> bool:
        return self.status in FINAL_TICKET_STATUSES

    def raise_for_status(self) -> AISRFResponse:
        if self.ok:
            return self
        raise AISRFError(
            f"ticket {self.ticket_id or '?'} {self.status} (http {self.http_status}): {self.error or self.decision_note or self.text[:200]}",
            self,
        )

    @property
    def content_text(self) -> str:
        """Assistant text for OpenAI chat, OpenAI responses, Anthropic messages and Ollama bodies."""
        d = self.data
        if not isinstance(d, dict):
            return self.text
        try:
            if "choices" in d:
                msg = d["choices"][0].get("message") or {}
                return msg.get("content") or d["choices"][0].get("text") or ""
            if isinstance(d.get("content"), list):
                return "".join(p.get("text", "") for p in d["content"] if isinstance(p, dict))
            if "output_text" in d:
                return str(d["output_text"])
            if isinstance(d.get("output"), list):
                return "".join(
                    c.get("text", "")
                    for item in d["output"]
                    for c in (item.get("content") or [])
                    if isinstance(c, dict)
                )
            if isinstance(d.get("message"), dict):
                return str(d["message"].get("content", ""))
            if "response" in d and isinstance(d["response"], str):
                return d["response"]
        except (KeyError, IndexError, AttributeError, TypeError):
            return ""
        return ""


def _parse_gateway_response(
    status_code: int, headers: Any, body: bytes, fallback_ticket: str | None = None
) -> AISRFResponse:
    """Classify an HTTP response from the gateway into an AISRFResponse."""
    hdrs = dict(dict(headers).items())
    ticket = hdrs.get("x-aisrf-ticket") or hdrs.get("X-AISRF-Ticket") or fallback_ticket
    text = body.decode("utf-8", "replace") if body else ""
    data: Any = None
    if text:
        try:
            data = json.loads(text)
        except ValueError:
            data = None
    if isinstance(data, dict) and "ticket_id" in data and data.get("status") in TICKET_STATUSES:
        # gateway envelope: 202 pending, or the poll endpoint's terminal payload
        resp = AISRFResponse(
            ticket_id=data["ticket_id"],
            status=data["status"],
            http_status=int(data.get("response_status") or status_code),
            headers=hdrs,
            decided_by=data.get("decided_by"),
            decision_note=data.get("decision_note") or "",
        )
        if "response" in data:
            resp.data = data["response"]
        elif "response_text" in data:
            resp.text = str(data["response_text"])
        if resp.status == "FAILED":
            resp.error = data.get("decision_note") or "upstream request failed"
        return resp
    if (
        isinstance(data, dict)
        and isinstance(data.get("error"), dict)
        and data["error"].get("type") == "aisrf_gateway"
    ):
        err = data["error"]
        code = str(err.get("code", "")).lower()
        status = {"denied": "DENIED", "expired": "EXPIRED", "upstream_error": "FAILED"}.get(
            code, "FAILED" if status_code >= 500 else "DENIED"
        )
        return AISRFResponse(
            ticket_id=err.get("ticket_id") or ticket,
            status=status,
            http_status=status_code,
            data=data,
            headers=hdrs,
            decided_by=err.get("decided_by"),
            error=err.get("message", ""),
        )
    # relayed upstream response (sync mode, or a poll that just forwarded an APPROVED ticket)
    status = (
        "COMPLETED" if ticket and status_code < 500 else ("FAILED" if status_code >= 500 else "COMPLETED")
    )
    return AISRFResponse(
        ticket_id=ticket,
        status=status,
        http_status=status_code,
        data=data,
        text="" if data is not None else text,
        headers=hdrs,
    )


class _ClientBase:
    def __init__(
        self,
        gateway_url: str | None = None,
        agent_key: str | None = None,
        *,
        async_mode: bool | None = None,
        source: str | None = None,
        correlation_id: str | None = None,
        timeout: float = 330.0,
        poll_interval: float = 2.0,
        max_wait: float = 900.0,
    ) -> None:
        if httpx is None:
            raise AISRFError("httpx is not installed; pip install httpx")
        self.gateway_url = (gateway_url or _config.gateway_url).rstrip("/")
        self.agent_key = agent_key or _config.agent_key
        if not self.gateway_url or not self.agent_key:
            raise AISRFError("AISRFClient needs gateway_url and agent_key (or call configure() first)")
        self.async_mode = _config.async_mode if async_mode is None else bool(async_mode)
        self.source = source or _config.source or "sdk"
        self.correlation_id = correlation_id or _config.correlation_id
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.max_wait = max_wait

    def headers(
        self,
        *,
        async_mode: bool | None = None,
        correlation_id: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> dict[str, str]:
        h = {"X-AISRF-Key": self.agent_key, "X-AISRF-Source": self.source, "Content-Type": "application/json"}
        if self.async_mode if async_mode is None else async_mode:
            h["X-AISRF-Async"] = "1"
        cid = correlation_id or self.correlation_id
        if cid:
            h["X-AISRF-Correlation-Id"] = cid
        if extra:
            h.update(extra)
        return h

    def _url(self, path: str) -> str:
        path = path.lstrip("/")
        if path.startswith(("gateway/", "proxy/")):
            return f"{self.gateway_url}/{path}"
        return f"{self.gateway_url}/proxy/{path}"


class AISRFClient(_ClientBase):
    """Synchronous, ticket aware gateway client.

    ::

        client = AISRFClient("http://localhost:8080", "aisrf_...", async_mode=True)
        r = client.submit("v1/chat/completions", {"model": "gpt-4o-mini", "messages": [...]})
        print(r.ticket_id, r.status, r.content_text)

    ``submit(..., wait=True)`` returns once the ticket is final. In synchronous gateway mode the
    HTTP call itself blocks until the reviewer decides (up to AISRF_APPROVAL_TIMEOUT_SECONDS). In
    asynchronous mode the gateway answers 202 immediately and the client polls
    ``/gateway/tickets/{id}`` every ``poll_interval`` seconds for at most ``max_wait`` seconds.
    """

    def __init__(self, *args: Any, client: Any = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._client = client or httpx.Client(timeout=httpx.Timeout(self.timeout, connect=10.0))
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def submit(
        self,
        path: str,
        body: Any = None,
        *,
        wait: bool = True,
        method: str = "POST",
        async_mode: bool | None = None,
        correlation_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> AISRFResponse:
        """Send ``body`` (dict or raw bytes) to ``<gateway>/proxy/<path>`` and return an AISRFResponse."""
        content = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
        resp = self._client.request(
            method,
            self._url(path),
            content=content,
            headers=self.headers(async_mode=async_mode, correlation_id=correlation_id, extra=headers),
        )
        parsed = _parse_gateway_response(resp.status_code, resp.headers, resp.content)
        if resp.status_code == 202 and parsed.ticket_id and wait:
            return self.wait_for(parsed.ticket_id)
        return parsed

    def poll(self, ticket_id: str) -> AISRFResponse:
        resp = self._client.get(
            self._url(f"gateway/tickets/{ticket_id}"), headers=self.headers(async_mode=False)
        )
        return _parse_gateway_response(
            resp.status_code, resp.headers, resp.content, fallback_ticket=ticket_id
        )

    def wait_for(
        self, ticket_id: str, *, timeout: float | None = None, interval: float | None = None
    ) -> AISRFResponse:
        deadline = time.monotonic() + (self.max_wait if timeout is None else timeout)
        interval = self.poll_interval if interval is None else interval
        last: AISRFResponse | None = None
        while time.monotonic() < deadline:
            last = self.poll(ticket_id)
            if last.is_final:
                return last
            time.sleep(interval)
        assert last is not None
        last.error = last.error or f"client gave up waiting after {self.max_wait}s"
        return last

    def chat(self, model: str, messages: list[dict[str, Any]], **params: Any) -> AISRFResponse:
        """OpenAI style chat completion through the gateway."""
        return self.submit("v1/chat/completions", {"model": model, "messages": messages, **params})

    def messages(
        self, model: str, messages: list[dict[str, Any]], max_tokens: int = 1024, **params: Any
    ) -> AISRFResponse:
        """Anthropic style messages call through the gateway (agent must target the anthropic provider)."""
        return self.submit(
            "v1/messages",
            {"model": model, "messages": messages, "max_tokens": max_tokens, **params},
            headers={"anthropic-version": "2023-06-01"},
        )


class AsyncAISRFClient(_ClientBase):
    """asyncio variant of AISRFClient with the same methods (all awaitable)."""

    def __init__(self, *args: Any, client: Any = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(self.timeout, connect=10.0))
        self._owns_client = client is None

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    async def submit(
        self,
        path: str,
        body: Any = None,
        *,
        wait: bool = True,
        method: str = "POST",
        async_mode: bool | None = None,
        correlation_id: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> AISRFResponse:
        content = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
        resp = await self._client.request(
            method,
            self._url(path),
            content=content,
            headers=self.headers(async_mode=async_mode, correlation_id=correlation_id, extra=headers),
        )
        parsed = _parse_gateway_response(resp.status_code, resp.headers, resp.content)
        if resp.status_code == 202 and parsed.ticket_id and wait:
            return await self.wait_for(parsed.ticket_id)
        return parsed

    async def poll(self, ticket_id: str) -> AISRFResponse:
        resp = await self._client.get(
            self._url(f"gateway/tickets/{ticket_id}"), headers=self.headers(async_mode=False)
        )
        return _parse_gateway_response(
            resp.status_code, resp.headers, resp.content, fallback_ticket=ticket_id
        )

    async def wait_for(
        self, ticket_id: str, *, timeout: float | None = None, interval: float | None = None
    ) -> AISRFResponse:
        import asyncio

        deadline = time.monotonic() + (self.max_wait if timeout is None else timeout)
        interval = self.poll_interval if interval is None else interval
        last: AISRFResponse | None = None
        while time.monotonic() < deadline:
            last = await self.poll(ticket_id)
            if last.is_final:
                return last
            await asyncio.sleep(interval)
        assert last is not None
        last.error = last.error or f"client gave up waiting after {self.max_wait}s"
        return last

    async def chat(self, model: str, messages: list[dict[str, Any]], **params: Any) -> AISRFResponse:
        return await self.submit("v1/chat/completions", {"model": model, "messages": messages, **params})

    async def messages(
        self, model: str, messages: list[dict[str, Any]], max_tokens: int = 1024, **params: Any
    ) -> AISRFResponse:
        return await self.submit(
            "v1/messages",
            {"model": model, "messages": messages, "max_tokens": max_tokens, **params},
            headers={"anthropic-version": "2023-06-01"},
        )
