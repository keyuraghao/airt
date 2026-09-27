# Integrations and SDKs

Every integration ends up doing the same thing: sending the request to `<gateway>/v1/<path>` or `<gateway>/proxy/<path>` with an agent key. Pick the least intrusive option that fits.

| Mode | Change needed | Best for |
| --- | --- | --- |
| SDK `base_url` and `api_key` | one constructor argument or environment variable | Your own code, LangChain, LlamaIndex |
| Generic `/proxy/<path>` | change the URL, add `X-AISRF-Key` | curl, custom HTTP clients, non-OpenAI providers |
| Python `patch_httpx()` / `patch_requests()` | one call at startup | Third-party Python libraries you cannot configure |
| `AISRFClient` / `AsyncAISRFClient` | explicit client | Code that wants ticket ids, statuses and async polling |
| Node `aisrf-intercept` | one `install()` call | Node applications using fetch-based SDKs |
| mitmproxy addon | none in the client, trust a CA | Binaries, containers, desktop applications |
| In-process `pipeline.submit()` | Python inside the gateway process | Red-team engine, plugins |

Two client settings apply everywhere: a timeout larger than `AISRF_APPROVAL_TIMEOUT_SECONDS` plus the upstream time (the module defaults to 330 s), and zero retries, because a `504 expired` or `502 upstream_error` resubmitted by an SDK becomes a brand new ticket.

## Python SDK (`aisrf.integrations.python_sdk`)

Re-exported from `aisrf.integrations`. Only the standard library is required; `httpx` and `requests` are imported lazily. Module-level configuration is also read from the environment at import: `AISRF_GATEWAY_URL`, `AISRF_AGENT_KEY`, `AISRF_ASYNC_MODE` (`1`, `true`, `yes`) and `AISRF_SOURCE` (default `sdk`).

### `configure()`

```python
configure(gateway_url, agent_key, *, async_mode=False, source="sdk", hosts=None, correlation_id=None, set_env=True) -> dict[str, str]
```

Stores the configuration for the module and, when `set_env` is true, exports `OPENAI_BASE_URL=<gateway>/v1`, `OPENAI_API_KEY=<agent key>`, `ANTHROPIC_BASE_URL=<gateway>`, `ANTHROPIC_API_KEY=<agent key>`, `AISRF_GATEWAY_URL`, `AISRF_AGENT_KEY`, `AISRF_ASYNC_MODE` and `AISRF_SOURCE`. Returns that mapping, which is handy for `subprocess.Popen(env=...)`. Raises `AISRFError` when either argument is empty. `hosts` replaces the provider host list used by the patches (for example to add an internal vLLM endpoint). Because the official SDKs have no environment variable for extra headers, `async_mode` and `source` only affect the patches and the explicit clients; for a plain SDK client pass `default_headers=default_headers()`.

```python
from openai import OpenAI
from aisrf.integrations import configure, default_headers
configure("http://localhost:8080", "aisrf_...", source="sdk", correlation_id="run-42")
client = OpenAI(timeout=330, max_retries=0, default_headers=default_headers())
```

`default_headers(*, async_mode=None, source=None, correlation_id=None)` returns `X-AISRF-Key`, `X-AISRF-Source` and, when enabled, `X-AISRF-Async: 1` and `X-AISRF-Correlation-Id`. `get_config()` returns the current configuration with the key masked.

### `patch_httpx()`

```python
patch_httpx(gateway_url=None, agent_key=None, *, async_mode=None, source=None) -> bool
```

Wraps `httpx.Client.__init__` and `httpx.AsyncClient.__init__` so every client created afterwards carries a request hook. The hook rewrites any request whose host matches `DEFAULT_PROVIDER_HOSTS` (`api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `api.mistral.ai`, `api.cohere.ai`, `api.groq.com`, `openrouter.ai`, `localhost:11434`) or the `hosts` given to `configure()` to `<gateway>/proxy/<original path>?<query>`, fixes the `Host` header and sets the AISRF headers. Entries without a port match any port and any subdomain; `localhost:11434` matches Ollama only on that port. Arguments are optional when `configure()` was already called (they call `configure(..., set_env=False)`). Returns `True` when installed, `False` when already active. Clients created before the call are not affected; the OpenAI, Anthropic, Mistral and Groq SDKs create theirs lazily, so call `patch_httpx()` before constructing them. `unpatch_httpx()` restores the original constructors.

```python
from aisrf.integrations import patch_httpx
patch_httpx("http://localhost:8080", "aisrf_...", source="sdk")
from openai import OpenAI
OpenAI(api_key="unused").chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hi"}])
```

### `patch_requests()`

```python
patch_requests(gateway_url=None, agent_key=None, *, async_mode=None, source=None) -> bool
```

Same contract for the `requests` library: wraps `requests.Session.send`, rewrites the prepared request URL, drops its `Host` header and sets the AISRF headers. `unpatch_requests()` restores it. For an explicit, non-global installation, `make_requests_adapter(**adapter_kwargs)` returns an `HTTPAdapter` subclass instance to mount:

```python
import requests
from aisrf.integrations.python_sdk import DEFAULT_PROVIDER_HOSTS, make_requests_adapter
s = requests.Session()
adapter = make_requests_adapter()
for host in DEFAULT_PROVIDER_HOSTS:
    s.mount("https://" + host, adapter)
```

### `AISRFClient`

```python
AISRFClient(gateway_url=None, agent_key=None, *, async_mode=None, source=None, correlation_id=None,
            timeout=330.0, poll_interval=2.0, max_wait=900.0, client=None)
```

A synchronous, ticket-aware client over `httpx.Client` (connect timeout 10 s). Usable as a context manager; `close()` closes an owned client. Methods:

| Method | Behaviour |
| --- | --- |
| `submit(path, body=None, *, wait=True, method="POST", async_mode=None, correlation_id=None, headers=None)` | Sends `body` (dict or list serialised as JSON, or raw bytes) to `<gateway>/proxy/<path>`; paths starting with `gateway/` or `proxy/` are used verbatim. On a `202` with `wait=True` it calls `wait_for()`; otherwise returns the parsed `AISRFResponse` |
| `poll(ticket_id)` | `GET /gateway/tickets/{id}` once |
| `wait_for(ticket_id, *, timeout=None, interval=None)` | Polls until a final status (`COMPLETED`, `DENIED`, `EXPIRED`, `FAILED`) or `max_wait`; on give-up the last response has `error` set to `client gave up waiting after <max_wait>s` |
| `chat(model, messages, **params)` | `submit("v1/chat/completions", {...})` |
| `messages(model, messages, max_tokens=1024, **params)` | `submit("v1/messages", {...})` with `anthropic-version: 2023-06-01`; the agent must target the Anthropic provider |
| `headers(*, async_mode=None, correlation_id=None, extra=None)` | The headers used: `X-AISRF-Key`, `X-AISRF-Source`, `Content-Type`, optional `X-AISRF-Async` and `X-AISRF-Correlation-Id` |

`AISRFResponse` fields: `ticket_id`, `status` (`PENDING`, `APPROVED`, `FORWARDING`, `COMPLETED`, `DENIED`, `EXPIRED`, `FAILED` or `UNKNOWN`), `http_status`, `data` (parsed JSON of the upstream body or the gateway envelope), `text` (raw body when not JSON), `headers`, `decided_by`, `decision_note`, `error`. Properties: `ok` (`COMPLETED` and 2xx), `is_final`, `content_text` (assistant text for OpenAI chat, OpenAI responses, Anthropic messages and Ollama bodies). `raise_for_status()` returns the response when `ok`, otherwise raises `AISRFError` carrying the response.

Gateway error envelopes (`error.type == "aisrf_gateway"`) are mapped to statuses: `denied` to `DENIED`, `expired` to `EXPIRED`, `upstream_error` to `FAILED`; other codes become `FAILED` for 5xx and `DENIED` otherwise (so `response_withheld` shows as `DENIED` with the withholding message in `error`).

```python
from aisrf.integrations import AISRFClient, AISRFError
with AISRFClient("http://localhost:8080", "aisrf_...", async_mode=True, poll_interval=2, max_wait=600) as c:
    r = c.chat("gpt-4o-mini", [{"role": "user", "content": "hello"}])
    print(r.ticket_id, r.status, r.http_status, r.decided_by, r.content_text)
    try:
        r.raise_for_status()
    except AISRFError as exc:
        print("not completed:", exc)
    pending = c.submit("v1/chat/completions", {"model": "gpt-4o-mini", "messages": []}, wait=False)
    later = c.wait_for(pending.ticket_id, timeout=120)
```

### `AsyncAISRFClient`

The asyncio twin over `httpx.AsyncClient` with the same constructor and the same methods, all awaitable (`submit`, `poll`, `wait_for`, `chat`, `messages`), plus `aclose()` and `async with` support.

```python
import asyncio
from aisrf.integrations import AsyncAISRFClient

async def main():
    async with AsyncAISRFClient("http://localhost:8080", "aisrf_...") as c:
        r = await c.messages("claude-3-5-haiku-latest", [{"role": "user", "content": "hi"}], max_tokens=64)
        print(r.status, r.content_text)

asyncio.run(main())
```

## Node package (`sdk/node`, `aisrf-intercept`)

Zero-dependency, Node 18+. Install from a checkout with `npm install /path/to/aisrf/sdk/node` (or from npm once published). Self-test: `node sdk/node/test.js`.

| Export | Description |
| --- | --- |
| `install({gatewayUrl, agentKey, hosts?, asyncMode?, correlationId?})` | Wraps `globalThis.fetch` and `undici.fetch` when resolvable; provider-host requests are rewritten to `<gateway>/proxy/<path>` with `X-AISRF-Key`, `X-AISRF-Source: sdk` and optionally `X-AISRF-Async: 1` and `X-AISRF-Correlation-Id`. Returns `uninstall` |
| `uninstall()` | Restores the original fetch functions |
| `isInstalled()` | Whether the interceptor is active |
| `rewriteUrl(url, options?)` | The gateway URL for a provider URL, or `null` |
| `rewriteRequest(input, init, options?)` | Rewritten `(input, init)` plus an `intercepted` flag |
| `configureOpenAI(options)` | `{baseURL: "<gateway>/v1", apiKey: "<agent key>", defaultHeaders: {"X-AISRF-Key", "X-AISRF-Source": "sdk"}}` for the `openai` package |
| `configureAnthropic(options)` | Same for `@anthropic-ai/sdk` (base URL is the gateway root) |
| `waitForTicket(ticketId, {pollIntervalMs?})` | Polls `/gateway/tickets/{id}` until a final status; resolves `{status, body}` |
| `DEFAULT_HOSTS` | Same list as the Python `DEFAULT_PROVIDER_HOSTS` |

```js
const aisrf = require("aisrf-intercept");
aisrf.install({ gatewayUrl: "http://localhost:8080", agentKey: process.env.AISRF_AGENT_KEY });
const OpenAI = require("openai");
const client = new OpenAI({ apiKey: "anything", timeout: 330000, maxRetries: 0 });
const r = await client.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] });
```

Without monkeypatching:

```js
const { configureOpenAI, configureAnthropic } = require("aisrf-intercept");
const client = new OpenAI(configureOpenAI({ gatewayUrl: "http://localhost:8080", agentKey: "aisrf_..." }));
const anthropic = new Anthropic(configureAnthropic({ gatewayUrl: "http://localhost:8080", agentKey: "aisrf_..." }));
```

Async mode: the official SDKs treat a `202` as a malformed success, so use plain `fetch` and `waitForTicket`:

```js
aisrf.install({ gatewayUrl, agentKey, asyncMode: true });
const res = await fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: JSON.stringify(payload) });
if (res.status === 202) {
  const { ticket_id } = await res.json();
  const result = await aisrf.waitForTicket(ticket_id, { pollIntervalMs: 2000 });
}
```

## mitmproxy addon (`aisrf/integrations/mitm_addon.py`)

For clients you cannot change at all. mitmproxy terminates TLS for the provider host and the addon rewrites scheme, host, port and path to `<gateway>/proxy/<original path>` (query string, method and body preserved), sets `X-AISRF-Key`, `X-AISRF-Source: mitm`, optionally `X-AISRF-Async: 1` and `X-AISRF-Correlation-Id`, and deletes `Authorization`, `x-api-key`, `api-key` and `x-goog-api-key` so the client's provider key never leaves the proxy. It logs each intercept and, from the `X-AISRF-Ticket` response header, the resulting ticket id.

| Env var | Default | Meaning |
| --- | --- | --- |
| `AISRF_GATEWAY_URL` | `http://localhost:8080` | Gateway base URL (a path prefix is honoured) |
| `AISRF_AGENT_KEY` | empty (required) | Agent key; without it requests reach the gateway and get `401` |
| `AISRF_INTERCEPT_HOSTS` | the default host list | Comma-separated `host` or `host:port` entries to intercept |
| `AISRF_ASYNC_MODE` | off | `1`, `true`, `yes`, `on` adds `X-AISRF-Async: 1` (the client must then poll) |
| `AISRF_CORRELATION_ID` | empty | Sent as `X-AISRF-Correlation-Id` on every intercepted request |
| `AISRF_MITM_PASSTHROUGH` | off | When no agent key is configured, leave provider traffic untouched instead of forwarding it |

```bash
pip install "aisrf[mitm]"
export AISRF_GATEWAY_URL=http://localhost:8080 AISRF_AGENT_KEY=aisrf_...
mitmdump -s aisrf/integrations/mitm_addon.py --listen-port 8081
```

Client side: `HTTPS_PROXY=http://127.0.0.1:8081` (and `HTTP_PROXY`) and trust `~/.mitmproxy/mitmproxy-ca-cert.pem`: `SSL_CERT_FILE` and `REQUESTS_CA_BUNDLE` for Python, `NODE_EXTRA_CA_CERTS` for Node, or install it system-wide. `mitmdump --mode transparent` works the same way with OS-level redirection. Keep this mode to development and lab networks.

## LangChain and other frameworks

Anything built on the official SDKs takes a base URL and key:

```python
from langchain_openai import ChatOpenAI
llm = ChatOpenAI(model="gpt-4o-mini", base_url="http://localhost:8080/v1", api_key="aisrf_...", timeout=330, max_retries=0)

from langchain_anthropic import ChatAnthropic
llm = ChatAnthropic(model="claude-3-5-haiku-latest", base_url="http://localhost:8080", api_key="aisrf_...", timeout=330, max_retries=0)
```

Or call `configure()` first and build them without URL arguments; they read the same environment variables as the SDKs (`examples/langchain_example.py` in the repository does this). LlamaIndex, the Vercel AI SDK, Semantic Kernel and similar frameworks expose the same two settings. For libraries that use httpx or requests internally but give you no configuration hook, `patch_httpx()` and `patch_requests()` catch them. For Ollama clients, point them at an agent with `upstream_provider` `ollama` and base URL `http://localhost:11434/v1` through `/v1/chat/completions`, or through `/proxy/api/chat` with base URL `http://localhost:11434`.

## In-process submission

Code running inside the gateway process (plugins, custom runners, the red-team engine) calls the pipeline directly:

```python
from aisrf.gateway.pipeline import submit
result = await submit(app.state.http, "agt_...", path="v1/chat/completions",
                      body={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]},
                      source="sdk", correlation_id="batch-7", wait_timeout=120)
print(result.ticket_id, result.status, result.http_status, result.response_text, result.risk_score)
```

`SubmitResult` carries `ticket_id`, `status`, `http_status`, `response_text`, `response_json`, `error`, `latency_ms`, `risk_score`, `findings`, `response_findings`, `decided_by` and `decision_note`. Streaming is forced off.

## curl recipes

Synchronous chat call (blocks until decided):

```bash
curl -i -X POST http://localhost:8080/v1/chat/completions \
  -H "X-AISRF-Key: $AISRF_AGENT_KEY" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

Same, with the key in the OpenAI header and a correlation id:

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $AISRF_AGENT_KEY" -H "X-AISRF-Correlation-Id: nightly-run" \
  -H "Content-Type: application/json" -d @request.json
```

Anthropic messages through the generic proxy:

```bash
curl -X POST http://localhost:8080/proxy/v1/messages \
  -H "X-AISRF-Key: $AISRF_AGENT_KEY" -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" \
  -d '{"model":"claude-3-5-haiku-latest","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}'
```

Gemini through an agent with `upstream_provider` `gemini` and base URL `https://generativelanguage.googleapis.com`:

```bash
curl -X POST "http://localhost:8080/proxy/v1beta/models/gemini-1.5-flash:generateContent" \
  -H "X-AISRF-Key: $AISRF_AGENT_KEY" -H "Content-Type: application/json" \
  -d '{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}'
```

Streaming (synchronous mode only):

```bash
curl -N -X POST http://localhost:8080/v1/chat/completions \
  -H "X-AISRF-Key: $AISRF_AGENT_KEY" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"count to five"}]}'
```

Async submit, then poll until the status is final:

```bash
TICKET=$(curl -s -X POST http://localhost:8080/v1/chat/completions \
  -H "X-AISRF-Key: $AISRF_AGENT_KEY" -H "X-AISRF-Async: 1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}' | python -c 'import json,sys; print(json.load(sys.stdin)["ticket_id"])')
curl -i "http://localhost:8080/gateway/tickets/$TICKET" -H "X-AISRF-Key: $AISRF_AGENT_KEY"
```

Approve from a script with the admin token:

```bash
curl -X POST "http://localhost:8080/api/tickets/$TICKET/approve" \
  -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" -H "Content-Type: application/json" -d '{"note":"batch approved"}'
```

Related: [[Gateway-Endpoints-and-Headers]], [[Getting-Started]], [[MCP-Server]], [[CLI-Reference]].
