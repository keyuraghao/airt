# Integrations: getting traffic into the gateway

Every mode ends up doing the same thing: send the request to `<gateway>/v1/<path>` or
`<gateway>/proxy/<path>` with an `X-AISRF-Key` header. Pick the least intrusive one that fits.

| Mode | Change needed | Best for |
| --- | --- | --- |
| SDK `base_url` | one constructor argument or env var | your own code, LangChain, LlamaIndex |
| Generic `/proxy/<path>` | change the URL, add a header | curl, custom HTTP clients, non-OpenAI providers |
| Python `patch_httpx()` / `patch_requests()` | one import at startup | third-party Python libraries you cannot configure |
| Node `aisrf-intercept` | one `install()` call | Node apps using fetch based SDKs |
| mitmproxy addon | none in the client, trust a CA | binaries, containers, desktop apps |
| In-process `pipeline.submit` | Python code running inside the gateway | red-team engine, plugins |

Headers understood by the gateway:

| Header | Purpose |
| --- | --- |
| `X-AISRF-Key` | agent key. Also accepted as `Authorization: Bearer aisrf_...`, `x-api-key`, `api-key`, `x-goog-api-key`, so the SDK's `api_key` argument can simply be the agent key. |
| `X-AISRF-Async: 1` | asynchronous ticket mode (202 + polling). |
| `X-AISRF-Source` | `sdk`, `mitm`, `gateway` (default) or `redteam`; shown in the dashboard. |
| `X-AISRF-Correlation-Id` | group tickets of one logical run; falls back to `X-Request-ID`. |

The gateway strips `Authorization`, `x-api-key`, `api-key`, `x-goog-api-key`, cookies and the
`X-AISRF-*` headers before forwarding and injects the agent's stored upstream credential, so clients
never need the real provider key.

## 1. SDK base_url

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="aisrf_...", timeout=330, max_retries=0)

from anthropic import Anthropic
client = Anthropic(base_url="http://localhost:8080", api_key="aisrf_...", timeout=330, max_retries=0)
```

* `timeout` must exceed `AISRF_APPROVAL_TIMEOUT_SECONDS` (default 300 s) or the SDK gives up before
  the reviewer decides.
* `max_retries=0`: SDKs retry 5xx and connection errors; a 504 (expired) or 502 would otherwise be
  resubmitted as a brand new ticket.
* Extra headers: `default_headers={"X-AISRF-Source": "sdk", "X-AISRF-Correlation-Id": "run-1"}`.

Environment variables do the same without code changes:

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1 OPENAI_API_KEY=aisrf_...
export ANTHROPIC_BASE_URL=http://localhost:8080 ANTHROPIC_API_KEY=aisrf_...
```

`aisrf.integrations.configure(gateway_url, agent_key)` sets exactly these variables (plus
`AISRF_GATEWAY_URL` / `AISRF_AGENT_KEY`) and returns the mapping for child processes.

LangChain: `ChatOpenAI(base_url=..., api_key=...)`, `ChatAnthropic(base_url=..., api_key=...)`, or
call `configure()` first and construct them with no URL arguments. See `examples/langchain_example.py`.

Node: `new OpenAI({ baseURL: "http://localhost:8080/v1", apiKey: "aisrf_..." })` or
`configureOpenAI()` from `aisrf-intercept`.

## 2. Generic proxy

```bash
curl -X POST http://localhost:8080/proxy/v1/messages \
  -H "X-AISRF-Key: aisrf_..." -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" \
  -d '{"model":"claude-3-5-haiku-latest","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}'
```

The path after `/proxy/` is appended to the agent's `upstream_base_url`. If the base already ends
with the first path segment (base `https://api.openai.com/v1`, path `v1/chat/completions`) the
duplicate segment is dropped, so both `/v1/...` and `/proxy/v1/...` work for OpenAI style agents.
Query strings are forwarded. Bodies up to `AISRF_MAX_REQUEST_BODY_BYTES` (4 MiB) are accepted.

Natively normalised request shapes (for analysis and the review UI): OpenAI chat completions,
completions, responses, embeddings; Anthropic messages; Gemini `generateContent`; Ollama chat and
generate; Cohere chat. Anything else is analysed by walking every string in the JSON body.

## 3. Python monkeypatch (`aisrf.integrations.python_sdk`)

```python
from aisrf.integrations import patch_httpx, patch_requests
patch_httpx("http://localhost:8080", "aisrf_...", source="sdk")      # before creating SDK clients
patch_requests()                                                     # optional, same config
```

`patch_httpx` wraps `httpx.Client.__init__` and `httpx.AsyncClient.__init__` so every client built
afterwards has a request hook. The hook rewrites requests whose host is one of
`DEFAULT_PROVIDER_HOSTS` (`api.openai.com`, `api.anthropic.com`,
`generativelanguage.googleapis.com`, `api.mistral.ai`, `api.cohere.ai`, `api.groq.com`,
`openrouter.ai`, `localhost:11434`) to `<gateway>/proxy/<original path>?<query>`, fixes the `Host`
header and adds `X-AISRF-Key`, `X-AISRF-Source` and, when `async_mode=True`, `X-AISRF-Async`. Hosts
without a port match any port and subdomains; `localhost:11434` matches Ollama only on that port.
Pass `hosts=[...]` to `configure()` for a custom list (for example an internal vLLM endpoint).
`unpatch_httpx()` / `unpatch_requests()` restore the originals. `make_requests_adapter()` returns a
`requests` `HTTPAdapter` for explicit `session.mount(...)` without global patching.

### AISRFClient

An explicit client that understands tickets:

```python
from aisrf.integrations import AISRFClient
with AISRFClient("http://localhost:8080", "aisrf_...", async_mode=True, poll_interval=2, max_wait=600) as c:
    r = c.chat("gpt-4o-mini", [{"role": "user", "content": "hello"}])   # or c.submit(path, body)
    print(r.ticket_id, r.status, r.http_status, r.decided_by, r.content_text)
    r.raise_for_status()                                                 # AISRFError unless COMPLETED
```

`submit(path, body, wait=True)` posts to `/proxy/<path>` (or `/gateway/...` verbatim) and, on a 202,
polls `/gateway/tickets/{id}` until `COMPLETED`, `DENIED`, `EXPIRED` or `FAILED`. `wait=False`
returns the PENDING response for later `wait_for(ticket_id)`. `AsyncAISRFClient` is the asyncio twin.
`AISRFResponse.data` holds the upstream JSON, `content_text` extracts the assistant text for OpenAI,
Anthropic, Responses API and Ollama shapes.

## 4. Node (`sdk/node`, package `aisrf-intercept`)

```js
require("aisrf-intercept").install({ gatewayUrl: "http://localhost:8080", agentKey: "aisrf_...", asyncMode: false });
```

Wraps `globalThis.fetch` (and `undici.fetch` when installed) with the same host list and headers as
the Python patch. `configureOpenAI()` / `configureAnthropic()` return `{baseURL, apiKey,
defaultHeaders}` for the official packages; `waitForTicket(id)` polls async tickets. Details in
`sdk/node/README.md`; self-test with `node sdk/node/test.js`.

## 5. mitmproxy transparent mode (`aisrf/integrations/mitm_addon.py`)

```bash
pip install "aisrf[mitm]"
export AISRF_GATEWAY_URL=http://localhost:8080 AISRF_AGENT_KEY=aisrf_...
export AISRF_INTERCEPT_HOSTS=api.openai.com,api.anthropic.com      # optional
mitmdump -s aisrf/integrations/mitm_addon.py --listen-port 8081
```

Client side: `HTTPS_PROXY=http://127.0.0.1:8081` and trust `~/.mitmproxy/mitmproxy-ca-cert.pem`
(`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` for Python, `NODE_EXTRA_CA_CERTS` for Node, or install it
system wide). The addon rewrites scheme/host/port/path to `<gateway>/proxy/<path>`, sets
`X-AISRF-Key`, `X-AISRF-Source: mitm`, optionally `X-AISRF-Async: 1` (`AISRF_ASYNC_MODE=1`) and
`X-AISRF-Correlation-Id` (`AISRF_CORRELATION_ID`), drops the client's provider key headers and logs
each intercept and the resulting ticket id. Method, body and query string are preserved. Set
`AISRF_MITM_PASSTHROUGH=1` to let provider traffic through untouched when no agent key is configured
(default: the gateway answers 401). `mitmdump --mode transparent` works the same way with OS level
redirection.

## 6. In-process submission

Code running inside the gateway process (plugins, custom runners) can call
`aisrf.gateway.pipeline.submit(http, agent_id, path=..., body=..., source="sdk")`, which executes the
identical pipeline (ticket, analysis, policy, hold, forward, response analysis) and returns a
`SubmitResult`. The red-team engine uses this.

## Streaming

`stream: true` requests are supported in synchronous mode: after approval the SSE stream is relayed
as it arrives and the first `AISRF_MAX_STORED_RESPONSE_BYTES` are stored and analysed. In
asynchronous mode the poll endpoint replays the stored request without streaming semantics; prefer
sync mode for streaming clients.

## Timeouts and retries summary

| Setting | Where | Recommendation |
| --- | --- | --- |
| client timeout | SDK / httpx | > `AISRF_APPROVAL_TIMEOUT_SECONDS` + `AISRF_UPSTREAM_TIMEOUT_SECONDS` |
| client retries | SDK | 0 (each retry is a new ticket) |
| `AISRF_APPROVAL_TIMEOUT_SECONDS` | gateway | as long as reviewers realistically need |
| async `max_wait` | AISRFClient / waitForTicket | any; the ticket itself expires after the approval timeout |
