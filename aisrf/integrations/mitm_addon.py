"""mitmproxy addon: transparently route LLM provider traffic through an AISRF gateway.

Use this when you cannot change the client at all (a compiled binary, a third-party desktop
app, a container you do not control). mitmproxy terminates TLS for the provider host and this
addon rewrites the request so it reaches ``<gateway>/proxy/<original path>`` carrying the
agent key. The gateway then creates a ticket, waits for the human decision and forwards the
request upstream with the real provider credentials stored on the agent record. The original
provider key sent by the client is stripped by the gateway and never leaves it.

Run::

    pip install "aisrf[mitm]"           # or: pip install mitmproxy
    export AISRF_GATEWAY_URL=http://localhost:8080
    export AISRF_AGENT_KEY=aisrf_...
    export AISRF_INTERCEPT_HOSTS=api.openai.com,api.anthropic.com    # optional, defaults below
    mitmdump -s aisrf/integrations/mitm_addon.py --listen-port 8081

Then point the client at the proxy and trust the mitmproxy CA::

    export HTTPS_PROXY=http://127.0.0.1:8081 HTTP_PROXY=http://127.0.0.1:8081
    # Python (httpx / requests / openai / anthropic):
    export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem
    export REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem
    # Node:
    export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem
    # System wide (Debian/Ubuntu):
    sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt && sudo update-ca-certificates
    # macOS:
    sudo security add-trusted-cert -d -p ssl -p basic -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem

The CA is generated on the first mitmproxy start in ``~/.mitmproxy``. Transparent mode
(``mitmdump --mode transparent``) works the same way but needs iptables/pf redirection, see
https://docs.mitmproxy.org/stable/howto-transparent/.

Environment variables read by the addon:

    AISRF_GATEWAY_URL        gateway base URL (default http://localhost:8080)
    AISRF_AGENT_KEY          agent key issued by AISRF (required)
    AISRF_INTERCEPT_HOSTS    comma separated hosts (host or host:port) to intercept
    AISRF_ASYNC_MODE         1/true to add X-AISRF-Async: 1 (client must then poll the ticket)
    AISRF_CORRELATION_ID     optional X-AISRF-Correlation-Id for every intercepted request
    AISRF_MITM_PASSTHROUGH   1/true to leave requests untouched when no agent key is configured

The module imports without mitmproxy installed so it can be unit tested and documented; the
``addons`` list is only populated when mitmproxy is importable.
"""

from __future__ import annotations

import logging
import os
from typing import Any
from urllib.parse import urlsplit

try:
    from mitmproxy import http as _http
except ImportError:  # pragma: no cover - mitmproxy is an optional extra
    _http = None

DEFAULT_HOSTS = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.mistral.ai",
    "api.cohere.ai",
    "api.groq.com",
    "openrouter.ai",
    "localhost:11434",
)
_log = logging.getLogger("aisrf.mitm")


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in ("1", "true", "yes", "on")


def parse_hosts(raw: str | None) -> tuple[str, ...]:
    if not raw or not raw.strip():
        return DEFAULT_HOSTS
    return tuple(h.strip().lower() for h in raw.split(",") if h.strip())


def host_matches(host: str, port: int | None, patterns: tuple[str, ...]) -> bool:
    host = (host or "").lower()
    with_port = f"{host}:{port}" if port else host
    for pat in patterns:
        if ":" in pat:
            if with_port == pat:
                return True
        elif host == pat or host.endswith("." + pat):
            return True
    return False


class AISRFRedirect:
    """The addon object. mitmproxy calls ``request`` for every client request."""

    def __init__(
        self,
        gateway_url: str | None = None,
        agent_key: str | None = None,
        hosts: tuple[str, ...] | None = None,
        async_mode: bool | None = None,
    ) -> None:
        self.gateway_url = (
            gateway_url or os.environ.get("AISRF_GATEWAY_URL") or "http://localhost:8080"
        ).rstrip("/")
        self.agent_key = agent_key or os.environ.get("AISRF_AGENT_KEY", "")
        self.hosts = hosts or parse_hosts(os.environ.get("AISRF_INTERCEPT_HOSTS"))
        self.async_mode = _truthy(os.environ.get("AISRF_ASYNC_MODE")) if async_mode is None else async_mode
        self.correlation_id = os.environ.get("AISRF_CORRELATION_ID", "")
        self.passthrough = _truthy(os.environ.get("AISRF_MITM_PASSTHROUGH"))
        gw = urlsplit(self.gateway_url)
        self.gw_scheme = gw.scheme or "http"
        self.gw_host = gw.hostname or "localhost"
        self.gw_port = gw.port or (443 if self.gw_scheme == "https" else 80)
        self.gw_prefix = gw.path.rstrip("/")
        self.intercepted = 0

    # --- mitmproxy hooks ------------------------------------------------------------
    def load(self, loader: Any) -> None:  # pragma: no cover - only called by mitmproxy
        self._info(
            f"AISRF addon loaded: gateway={self.gateway_url} hosts={','.join(self.hosts)} async={self.async_mode}"
        )
        if not self.agent_key:
            self._warn(
                "AISRF_AGENT_KEY is not set; requests will be rejected by the gateway (401)"
                + (" or passed through" if self.passthrough else "")
            )

    def request(self, flow: Any) -> None:
        req = flow.request
        if not host_matches(req.pretty_host, req.port, self.hosts):
            return
        if not self.agent_key and self.passthrough:
            self._warn(f"passthrough (no agent key): {req.method} {req.pretty_url}")
            return
        original = f"{req.scheme}://{req.pretty_host}:{req.port}{req.path}"
        self.rewrite(req)
        self.intercepted += 1
        self._info(f"AISRF intercept #{self.intercepted}: {req.method} {original} -> {req.pretty_url}")

    def response(self, flow: Any) -> None:
        resp = flow.response
        ticket = resp.headers.get("X-AISRF-Ticket") if resp is not None else None
        if ticket:
            self._info(
                f"AISRF ticket {ticket}: {resp.status_code} for {flow.request.method} {flow.request.path}"
            )

    # --- pure logic (unit testable without mitmproxy) -------------------------------
    def rewrite(self, req: Any) -> None:
        """Mutate a mitmproxy Request (or any object with scheme/host/port/path/headers) in place."""
        path = req.path if req.path.startswith("/") else "/" + req.path
        req.scheme = self.gw_scheme
        req.host = self.gw_host
        req.port = self.gw_port
        req.path = f"{self.gw_prefix}/proxy{path}"
        req.headers["Host"] = self.gw_host if self.gw_port in (80, 443) else f"{self.gw_host}:{self.gw_port}"
        req.headers["X-AISRF-Key"] = self.agent_key
        req.headers["X-AISRF-Source"] = "mitm"
        if self.async_mode:
            req.headers["X-AISRF-Async"] = "1"
        if self.correlation_id:
            req.headers["X-AISRF-Correlation-Id"] = self.correlation_id
        # the gateway strips these anyway; dropping them here keeps provider keys off the wire
        for h in ("Authorization", "x-api-key", "api-key", "x-goog-api-key"):
            if h in req.headers:
                del req.headers[h]

    @staticmethod
    def _info(msg: str) -> None:  # mitmproxy 9+ captures the standard logging module
        _log.info(msg)

    @staticmethod
    def _warn(msg: str) -> None:
        _log.warning(msg)


addons: list[Any] = [AISRFRedirect()] if _http is not None else []
