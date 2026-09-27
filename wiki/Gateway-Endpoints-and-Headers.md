# Gateway endpoints and headers

The interception surface, as implemented in `aisrf/gateway/router.py` and `aisrf/gateway/forwarder.py`. Everything here is authenticated with an agent key, never with a reviewer session.

## Routes

| Route | Methods | Stored path | Purpose |
| --- | --- | --- | --- |
| `/v1/{path}` | GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD | `v1/<path>` | OpenAI and Anthropic compatible shortcut; the SDKs' base URL points here |
| `/proxy/{path}` | GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD | `<path>` verbatim | Generic proxy for any HTTP backend |
| `/gateway/tickets/{ticket_id}` | GET | n/a | Poll an asynchronous ticket |

Both interception routes call the same `intercept()` function; the only difference is the stored path (`v1/` is prefixed for the first route). The routes are registered last in the app, after the reviewer API, dashboard and MCP, and are hidden from the OpenAPI schema. Query strings are preserved and forwarded.

## Agent key extraction

`_extract_key()` checks, in this order:

1. `x-aisrf-key`, `x-api-key`, `api-key`, `x-goog-api-key`: the first header whose value starts with `aisrf_` wins.
2. `Authorization: Bearer <value>`: the bearer value, whatever its prefix.
3. `x-aisrf-key`, `x-api-key`, `api-key`: the first non-empty value, whatever its prefix.

Step 1 lets an SDK that puts the agent key in its native header (OpenAI: `Authorization: Bearer`, Anthropic: `x-api-key`, Azure: `api-key`, Gemini: `x-goog-api-key`) work unchanged. The value is SHA-256 hashed and looked up in `agents.api_key_hash`; if that fails and the value starts with `aisrf_scan_` it is looked up in `scan_tokens`. Inactive agents, revoked or expired scan tokens and unknown values yield `401`.

## Request headers

| Header | Values | Effect |
| --- | --- | --- |
| `X-AISRF-Key` | `aisrf_...` or `aisrf_scan_...` | Agent authentication (see above for alternatives) |
| `X-AISRF-Async` | `1`, `true`, `yes` (case insensitive) | Return `202` for a PENDING ticket instead of blocking |
| `X-AISRF-Source` | `gateway`, `sdk`, `mitm`, `redteam` | Stored as the ticket `source`; anything else becomes `gateway` |
| `X-AISRF-Correlation-Id` | any string | Stored as `correlation_id`; falls back to `X-Request-ID`, else a generated `corr_...` |
| `X-AISRF-Campaign-Id` | `cmp_...` | Stored as `campaign_id` (set by the red-team engine and scanners) |
| `X-AISRF-Probe-Id` | probe id | Stored as `probe_id` |
| `X-Request-ID` | any string | Request id for logs and the response header; also the correlation fallback |
| `X-Forwarded-For` | client ip list | The first entry is stored as `client_ip` |
| `User-Agent` | | Stored as `user_agent` (truncated to 300 characters) |

All inbound headers are stored on the ticket after `redact_headers()`, which keeps only the first 10 characters followed by `[redacted]` for `authorization`, `x-api-key`, `x-aisrf-key`, `cookie`, `set-cookie`, `proxy-authorization`, `x-goog-api-key` and `api-key`.

## Response headers

| Header | When | Meaning |
| --- | --- | --- |
| `X-AISRF-Ticket` | Every forwarded response, the `202` async acknowledgement and the `403 response_withheld` error | The ticket id |
| `X-Request-ID` | Every response from the process | Request id bound to every log line of that request |

Upstream response headers are relayed except hop-by-hop headers (`connection`, `keep-alive`, `proxy-authenticate`, `proxy-authorization`, `te`, `trailer`, `transfer-encoding`, `upgrade`, `host`, `content-length`, `accept-encoding`) plus `content-encoding` and `content-length`, which are dropped because the body is re-served by the gateway.

## Gateway-generated responses

Error bodies use `forwarder.error_json()`: `{"error": {"message", "type": "aisrf_gateway", "code", "ticket_id", ...extra}}`. The two pre-ticket errors (401 and 429) and the 413 have no `ticket_id`.

| Status | `code` | When | Body |
| --- | --- | --- | --- |
| 401 | `unauthorized` | Missing, unknown, inactive or expired credential | `{"error": {"message": "invalid or missing AISRF agent key", "type": "aisrf_gateway", "code": "unauthorized"}}` |
| 429 | `rate_limited` | The agent's `rate_limit_per_minute` sliding window is full | `{"error": {"message": "agent rate limit exceeded", "type": "aisrf_gateway", "code": "rate_limited"}}` |
| 413 | `payload_too_large` | Body larger than `AISRF_MAX_REQUEST_BODY_BYTES` | `{"error": {"message": "request body too large", "type": "aisrf_gateway", "code": "payload_too_large"}}` |
| 403 | `denied` | Policy denied the ticket | `{"error": {"message": "request blocked by AISRF policy: <reasons>", "type": "aisrf_gateway", "code": "denied", "ticket_id": "tkt_...", "risk_score": 72}}` |
| 403 | `denied` | A reviewer denied the ticket (sync wait) | `{"error": {"message": "request denied by reviewer: <note>", "type": "aisrf_gateway", "code": "denied", "ticket_id": "tkt_...", "decided_by": "alice"}}` |
| 403 | `response_withheld` | The upstream answered but the `policy` namespace withholds the body (canary leak, or a CRITICAL response finding with quarantine on) | `{"error": {"message": "response withheld: ...", "type": "aisrf_gateway", "code": "response_withheld", "ticket_id": "tkt_..."}}` plus `X-AISRF-Ticket` |
| 502 | `upstream_error` | Connection failure, timeout or other exception while sending upstream after approval | `{"error": {"message": "upstream connection failed: ..." or "upstream timed out: ...", "type": "aisrf_gateway", "code": "upstream_error", "ticket_id": "tkt_..."}}` |
| 504 | `expired` | No decision before the approval timeout (sync wait) | `{"error": {"message": "no reviewer decision before the approval timeout; nothing was sent upstream", "type": "aisrf_gateway", "code": "expired", "ticket_id": "tkt_..."}}` |
| 202 | n/a | Async mode and the ticket is PENDING | `{"ticket_id": "tkt_...", "status": "PENDING", "poll_url": "/gateway/tickets/tkt_...", "expires_at": "<iso>"}` plus `X-AISRF-Ticket` |
| upstream status | n/a | Approved and forwarded | The upstream body verbatim (JSON or SSE) with filtered upstream headers plus `X-AISRF-Ticket` |

Note that a `FAILED` ticket caused by an upstream 5xx (not a transport error) relays the upstream status and body as is; only transport exceptions produce the gateway `502`.

Metrics incremented along the way: `gateway_requests_total`, `gateway_auth_failures_total`, `gateway_policy_total{action}`, `gateway_denied_total`, `gateway_expired_total`, `gateway_upstream_errors_total`, `gateway_upstream_responses_total{status}`, `gateway_responses_withheld_total`, histograms `gateway_risk_score`, `gateway_wait_seconds`, `gateway_upstream_latency_ms` (all rendered with the `aisrf_` prefix, see [[Logging-Metrics-and-Audit]]).

## The poll endpoint

`GET /gateway/tickets/{ticket_id}` requires the same agent key; a ticket that does not exist or belongs to another agent returns `404 {"error": {"message": "ticket not found", "code": "not_found"}}`. Otherwise:

| Ticket status | HTTP | Body |
| --- | --- | --- |
| `APPROVED` | upstream status | The poll itself forwards the stored request (method, path, redacted stored headers, stored body) and relays the upstream response with `X-AISRF-Ticket` |
| `PENDING`, `FORWARDING` | 202 | `{"ticket_id", "status", "decided_by", "decision_note"}` |
| `COMPLETED` | 200 | Same fields plus `response` (parsed JSON) or `response_text`, and `response_status` |
| `DENIED`, `EXPIRED` | 403 | `{"ticket_id", "status", "decided_by", "decision_note"}` |
| `FAILED` | 502 | Same fields, plus `response`/`response_status` when an upstream status was recorded |

Because the async forward uses the stored, redacted request headers, provider-specific headers such as `anthropic-version` are preserved but any client credential header is not (it is stripped anyway).

## Streaming behaviour

A response is treated as a stream when the normalized request had `stream: true` or the upstream `content-type` contains `text/event-stream`. The gateway returns a `StreamingResponse` with the upstream status and filtered headers, relays each chunk as it arrives (`aiter_raw`), and captures the first `AISRF_MAX_STORED_RESPONSE_BYTES` (default 524288). When the stream ends, a fresh database session records the captured bytes, runs the response analyzers and marks the ticket COMPLETED or FAILED. Response withholding cannot apply to a stream already relayed, so canary and quarantine checks only produce findings and events for streamed responses. In asynchronous mode the poll endpoint does not stream; prefer synchronous mode for streaming clients. `pipeline.submit()` forces `stream: false`.

## Size limits

| Limit | Setting | Default | Effect |
| --- | --- | --- | --- |
| Request body | `AISRF_MAX_REQUEST_BODY_BYTES` | 4194304 (4 MiB) | `413` above; the stored `request_body` is also truncated to this length |
| Stored response | `AISRF_MAX_STORED_RESPONSE_BYTES` | 524288 (512 KiB) | Only this many bytes are kept on the ticket and analysed; the client still receives the whole body |
| Prompt preview | constant | 480 characters (`MAX_PREVIEW`), stored column 500 | `prompt_preview` and `response_preview` |
| Upstream read timeout | `AISRF_UPSTREAM_TIMEOUT_SECONDS` | 120.0 | `502 upstream_error` on expiry |
| Upstream connect timeout | `AISRF_UPSTREAM_CONNECT_TIMEOUT_SECONDS` | 10.0 | Same |

## Upstream URL joining rule

`build_upstream_url(agent, path, query)`:

1. `base = agent.upstream_base_url` with trailing slashes removed; `path` with surrounding slashes removed.
2. Take the last path segment of the base URL (for `https://api.openai.com/v1` that is `v1`). If the request path's first segment equals it, drop that first segment from the path.
3. URL is `base/path` (or just `base` when the path is empty), plus `?query` when a query string exists.

Examples with base `https://api.openai.com/v1`: `/v1/chat/completions` and `/proxy/v1/chat/completions` both become `https://api.openai.com/v1/chat/completions`; `/proxy/chat/completions` does too. With base `https://api.anthropic.com/v1`, the Anthropic SDK's `/v1/messages` becomes `https://api.anthropic.com/v1/messages`. With base `http://localhost:11434/v1` (the Ollama default) `/v1/chat/completions` maps to Ollama's OpenAI-compatible endpoint. The agent cannot influence the host: only an admin editing `upstream_base_url` can.

## Provider auth header mapping

`build_upstream_headers()` first removes every header in `STRIP_INBOUND` (the hop-by-hop set above plus `authorization`, `x-api-key`, `x-aisrf-key`, `x-aisrf-async`, `x-aisrf-agent`, `cookie`, `x-goog-api-key`, `api-key`), then injects the decrypted upstream key according to `upstream_provider` (lower-cased):

| `upstream_provider` | Injected header |
| --- | --- |
| `openai`, `ollama`, `azure_openai_compat`, `groq`, `together`, `mistral`, `deepseek`, `openrouter` | `Authorization: Bearer <key>` |
| `anthropic` | `x-api-key: <key>` and `anthropic-version` (kept from the inbound request, else `2023-06-01`) |
| `azure` | `api-key: <key>` |
| `google`, `gemini` | `x-goog-api-key: <key>` |
| anything else with `upstream_auth_header` set | `<upstream_auth_header>: <key>`, or `Bearer <key>` when that header name is `authorization` |
| anything else | `Authorization: Bearer <key>` |

When the agent has no upstream key, no credential header is added. `upstream_extra_headers` are applied last and override anything above. `user-agent` defaults to `aisrf-gateway/1.0` when the client sent none. Other `X-AISRF-*` headers not in the strip list (`x-aisrf-source`, `x-aisrf-correlation-id`, `x-aisrf-campaign-id`, `x-aisrf-probe-id`) are forwarded as ordinary headers.

## Examples

Synchronous OpenAI-style call:

```bash
curl -i -X POST http://localhost:8080/v1/chat/completions \
  -H "X-AISRF-Key: aisrf_..." -H "Content-Type: application/json" \
  -H "X-AISRF-Source: sdk" -H "X-AISRF-Correlation-Id: run-42" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

Anthropic through the generic proxy:

```bash
curl -X POST http://localhost:8080/proxy/v1/messages \
  -H "X-AISRF-Key: aisrf_..." -H "anthropic-version: 2023-06-01" -H "Content-Type: application/json" \
  -d '{"model":"claude-3-5-haiku-latest","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}'
```

Async submit and poll:

```bash
curl -s -X POST http://localhost:8080/v1/chat/completions \
  -H "X-AISRF-Key: aisrf_..." -H "X-AISRF-Async: 1" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
curl -i http://localhost:8080/gateway/tickets/tkt_... -H "X-AISRF-Key: aisrf_..."
```

Related: [[Request-Normalization]], [[Policy-Engine]], [[Integrations-and-SDKs]], [[REST-API-Reference]].
