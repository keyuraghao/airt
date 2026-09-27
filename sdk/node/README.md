# aisrf-intercept

Zero-dependency Node 18+ package that routes `fetch` based LLM SDK traffic through an
[AISRF](../../README.md) human-in-the-loop gateway. Every request to a provider host becomes a
reviewable ticket on the gateway; the real provider credentials stay on the gateway.

## Install

```bash
npm install aisrf-intercept          # once published
npm install /path/to/AISRF/sdk/node  # from a checkout
```

## Usage

### 1. Wrap global fetch (works for the openai, @anthropic-ai/sdk, @google/generative-ai, groq-sdk packages and plain fetch)

```js
const aisrf = require("aisrf-intercept");
aisrf.install({
  gatewayUrl: "http://localhost:8080",
  agentKey: process.env.AISRF_AGENT_KEY,   // "aisrf_..." created in the AISRF dashboard or CLI
  // hosts: ["api.openai.com", "llm.internal:8443"],  optional, see DEFAULT_HOSTS
  // asyncMode: true,                                  202 + polling instead of blocking
  // correlationId: "run-42",                          groups tickets in the dashboard
});

const OpenAI = require("openai");
const client = new OpenAI({ apiKey: "anything" });   // the key is replaced, the URL is rewritten
const r = await client.chat.completions.create({ model: "gpt-4o-mini", messages: [{ role: "user", content: "hi" }] });
```

`https://api.openai.com/v1/chat/completions` is sent to `http://localhost:8080/proxy/v1/chat/completions`
with `X-AISRF-Key`, `X-AISRF-Source: sdk` and (optionally) `X-AISRF-Async: 1`. The call blocks until a
reviewer approves or denies the ticket (or the gateway's approval timeout elapses).

### 2. Configure the SDK explicitly (no monkeypatching)

```js
const { configureOpenAI, configureAnthropic } = require("aisrf-intercept");
const client = new OpenAI(configureOpenAI({ gatewayUrl: "http://localhost:8080", agentKey: "aisrf_..." }));
// { baseURL: "http://localhost:8080/v1", apiKey: "aisrf_...", defaultHeaders: { "X-AISRF-Key": ..., "X-AISRF-Source": "sdk" } }
const anthropic = new Anthropic(configureAnthropic({ gatewayUrl: "http://localhost:8080", agentKey: "aisrf_..." }));
```

### 3. Asynchronous mode

```js
aisrf.install({ gatewayUrl, agentKey, asyncMode: true });
const res = await fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: JSON.stringify(payload) });
if (res.status === 202) {
  const { ticket_id } = await res.json();
  const result = await aisrf.waitForTicket(ticket_id, { pollIntervalMs: 2000 });
  // result.status: COMPLETED | DENIED | EXPIRED | FAILED, result.body: upstream JSON
}
```

Note: the official SDKs treat a 202 as an error-free response with an unexpected shape, so in
async mode use plain `fetch` or handle the 202 yourself.

## API

| Export | Description |
| --- | --- |
| `install(options)` | Wraps `globalThis.fetch` and `undici.fetch` (if resolvable). Returns `uninstall`. |
| `uninstall()` | Restores the original fetch functions. |
| `isInstalled()` | Whether the interceptor is active. |
| `rewriteUrl(url, options?)` | Gateway URL for a provider URL or `null`. |
| `rewriteRequest(input, init, options?)` | Rewritten `(input, init)` pair plus `intercepted` flag. |
| `configureOpenAI(options)` | `{ baseURL, apiKey, defaultHeaders }` for the `openai` package. |
| `configureAnthropic(options)` | Same for `@anthropic-ai/sdk`. |
| `waitForTicket(ticketId, options?)` | Polls `/gateway/tickets/{id}` until a final status. |
| `DEFAULT_HOSTS` | `api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, api.mistral.ai, api.cohere.ai, api.groq.com, openrouter.ai, localhost:11434` |

Host entries with a port (`localhost:11434`) match only that port; entries without a port match
any port and any subdomain.

## Test

```bash
node test.js
```

## License

Apache-2.0
