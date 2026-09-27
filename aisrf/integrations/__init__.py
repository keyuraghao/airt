"""Client-side integrations for routing LLM traffic through an AISRF gateway.

Everything in this package runs on the *client* side (inside the application or agent that
calls a model provider). None of it imports the gateway server code, so it can be copied into
any Python 3.9+ project or installed with the `aisrf` package.

    from aisrf.integrations import configure, patch_httpx, AISRFClient

    configure("http://localhost:8080", "aisrf_...")   # official OpenAI / Anthropic SDKs via env vars
    patch_httpx()                                     # any httpx based client, transparently
    AISRFClient(...).submit("v1/chat/completions", {...})  # explicit ticket aware client

See aisrf/integrations/python_sdk.py for details and aisrf/integrations/mitm_addon.py for the
mitmproxy transparent mode.
"""

from .python_sdk import (
    DEFAULT_PROVIDER_HOSTS,
    FINAL_TICKET_STATUSES,
    AISRFClient,
    AISRFError,
    AISRFResponse,
    AsyncAISRFClient,
    configure,
    default_headers,
    get_config,
    patch_httpx,
    patch_requests,
    unpatch_httpx,
    unpatch_requests,
)

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
