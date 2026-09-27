# Architecture

AISRF is a single FastAPI process (`aisrf.main.create_app`) that exposes three surfaces on one port:

1. the **gateway** (`/v1/*`, `/proxy/*`, `/gateway/tickets/*`) that agents and applications call
   instead of the model provider,
2. the **reviewer API + dashboard** (`/api/*`, `/`, `/tickets`, ...) that humans use to decide,
3. the **MCP server** (`/mcp`) that exposes the reviewer actions to LLM based operators.

```
                 +--------------------------------------------------------------------+
  clients        |                          AISRF gateway process                       |
                 |                                                                    |
  OpenAI SDK --->| /v1/{path}      +---------+   +----------+   +--------+            |
  Anthropic SDK->| /proxy/{path} ->| parser  |-->| analysis |-->| policy |--+         |
  curl / node -->| X-AISRF-Key      |normalize|   | runner   |   | engine |  |         |
  mitmproxy ---->|                 +---------+   +----------+   +--------+  |         |
                 |                                                         v         |
                 |         +---------- ticket (PENDING / APPROVED / DENIED) --------+ |
                 |         |                                                        | |
                 |         v                                                        | |
                 |   +-----------+  decision  +-----------+   +-----------+         | |
   reviewers --->|   | dashboard |----------->|  tickets  |<--| hold      |<--------+ |
   (browser)     |   | /api/*    |            |  service  |   | registry  | wait      |
   MCP client -->|   | /mcp      |            +-----+-----+   +-----------+           |
   aisrf CLI ---->|   +-----------+                  |                                 |
                 |                                  v                                 |
                 |   +----------+   +-----------+  +-----------+   +---------------+  |
                 |   | audit    |   | agent     |  | forwarder |-->| upstream      |--+--> api.openai.com
                 |   | (hash    |   | logs      |  | (swaps    |   | httpx client  |  |    api.anthropic.com
                 |   |  chain)  |   | jsonl+db  |  |  creds)   |<--|               |<-+--- any HTTP API
                 |   +----------+   +-----------+  +-----------+   +---------------+  |
                 |                                                                    |
                 |   redteam engine: corpus -> mutators -> campaign -> pipeline.submit |
                 |   reports: builders -> Report model -> renderers (13 formats)      |
                 |   SQLAlchemy async (SQLite / PostgreSQL), structlog, metrics       |
                 +--------------------------------------------------------------------+
```

## Components

| Module | Responsibility |
| --- | --- |
| `aisrf/config.py` | `Settings` (pydantic-settings, prefix `AISRF_`, `.env` file). `get_settings()` is cached. |
| `aisrf/main.py` | App factory, lifespan (DB init, admin bootstrap, shared upstream `httpx.AsyncClient`, background sweeper, campaign runner shutdown), `/healthz`, `/readyz`, `/metrics`, correlation middleware (`X-Request-ID`). |
| `aisrf/gateway/router.py` | Interception endpoints and the sync/async decision flow. |
| `aisrf/gateway/parser.py` | `normalize(path, body, provider_hint)` turns any provider body into `{provider, endpoint, model, stream, system, messages, tools, extra, prompt_text, last_user_message, preview, message_count, char_count}`. `extract_response_text` does the reverse for JSON and SSE responses. |
| `aisrf/analysis/base.py`, `runner.py` | `Finding`, `AnalysisResult`, scoring; `analyze_request` / `analyze_response` run every registered analyzer concurrently and isolate failures. |
| `aisrf/analysis/analyzers/` | Built-in request analyzers (prompt injection, jailbreak, PII, secrets, data exfiltration, tool abuse, harmful content, obfuscation, anomaly, optional LLM judge) and response analyzers (system prompt leak, refusal detection, canary leak). |
| `aisrf/gateway/policy.py` | `evaluate(agent, normalized, path, risk_score, findings) -> PolicyDecision(action, reasons, matched_rules)`. |
| `aisrf/gateway/hold.py` | `HoldRegistry`: one `asyncio.Event` per waiting ticket plus DB polling fallback. |
| `aisrf/gateway/forwarder.py` | Upstream URL/header construction, credential swap, header filtering, shared client. |
| `aisrf/gateway/pipeline.py` | `submit()`: the same pipeline as an HTTP call, callable in-process (used by the red-team engine). |
| `aisrf/tickets/` | Ticket lifecycle service and reviewer REST API + SSE streams. |
| `aisrf/agents/` | Agent registry (keys, upstream config, policy fields), per-agent activity log, rate limiting. |
| `aisrf/auth.py`, `aisrf/security.py` | Reviewer sessions, bearer tokens, roles; hashing, Fernet, redaction. |
| `aisrf/audit/service.py` | Hash-chained audit entries and chain verification. |
| `aisrf/logging.py` | structlog configuration, rotating JSONL sinks, `EventBroadcaster` for SSE. |
| `aisrf/metrics.py` | Dependency-free counters/histograms rendered in Prometheus text format. |
| `aisrf/redteam/` | YAML probe corpus, mutators, campaign engine and REST API. |
| `aisrf/reports/` | `Report` / `Section` model, builders, renderers. |
| `aisrf/dashboard/` | Jinja2 server-rendered reviewer UI. |
| `aisrf/mcp_server.py` | MCP tools mirroring the reviewer API (streamable HTTP at `/mcp`, stdio via `aisrf mcp`). |
| `aisrf/cli.py` | Typer CLI (`aisrf serve`, `init-db`, `create-reviewer`, `agent ...`, `tickets ...`, `redteam ...`, `report`, `audit verify`, `mcp`, `version`). |
| `aisrf/integrations/` | Client side helpers: Python SDK patching and the mitmproxy addon. |

## Data model

All tables are defined in `aisrf/models.py` (SQLAlchemy 2 declarative, JSON columns for flexible data).

| Table | Key fields |
| --- | --- |
| `reviewers` | `id (usr_)`, `username`, `password_hash`, `role` (viewer / reviewer / admin), `is_active`, `last_login_at` |
| `agents` | `id (agt_)`, `name`, `api_key_hash`, `api_key_prefix`, `upstream_provider`, `upstream_base_url`, `upstream_api_key_encrypted`, `upstream_auth_header`, `upstream_extra_headers`, policy: `require_approval`, `auto_approve_below_risk`, `auto_deny_at_risk`, `auto_deny_patterns`, `allowed_paths`, `allowed_models`, `rate_limit_per_minute`, `is_active`, stats: `request_count`, `last_seen_at` |
| `tickets` | `id (tkt_)`, `number`, `agent_id`, `status`, `source` (gateway / mitm / sdk / redteam), `correlation_id`, `client_ip`, `user_agent`, `method`, `path`, `upstream_url`, `request_headers` (redacted), `request_body`, `request_json`, `normalized`, `prompt_preview`, `model`, `is_stream`, `risk_score`, `risk_level`, `findings`, `analysis_ms`, `policy_decision`, `decided_by`, `decision_note`, `decided_at`, `expires_at`, `forwarded_at`, `response_status`, `response_headers`, `response_body` (truncated), `response_preview`, `response_findings`, `latency_ms`, `error`, `campaign_id`, `probe_id` |
| `ticket_events` | append-only timeline per ticket: `event_type`, `actor`, `detail` |
| `agent_events` | durable copy of the per-agent activity log: `level`, `event`, `ticket_id`, `correlation_id`, `detail` |
| `audit_log` | `actor`, `action`, `target_type`, `target_id`, `detail`, `prev_hash`, `hash` (SHA-256 chain, genesis `0*64`) |
| `campaigns` | `id (cmp_)`, `name`, `agent_id`, `target_model`, `status` (CREATED / RUNNING / PAUSED / COMPLETED / FAILED / CANCELLED), `config`, `summary`, `total_probes`, `completed_probes`, timestamps |
| `probe_results` | `id (prb_)`, `campaign_id`, `probe_id`, `category`, `technique`, `severity`, `prompt`, `messages`, `response`, `verdict` (VULNERABLE / RESISTED / BLOCKED / ERROR / PENDING / INCONCLUSIVE), `confidence`, `evidence`, `ticket_id`, `latency_ms` |

## Request lifecycle (synchronous mode)

```
client                 gateway router              analysis/policy          reviewer            upstream
  |  POST /v1/chat/completions                          |                      |                   |
  |  X-AISRF-Key: aisrf_...  ---------------------------> |                      |                   |
  |                        authenticate agent (sha256)  |                      |                   |
  |                        rate limit, size limit       |                      |                   |
  |                        normalize(body) ------------>|                      |                   |
  |                        create ticket PENDING        |                      |                   |
  |                        analyze_request ------------>| findings, score      |                   |
  |                        policy.evaluate ------------>| deny / approve / review                  |
  |                                                      |                      |                   |
  |   [deny]  <-- 403 {error.code=denied, ticket_id}     |                      |                   |
  |   [review] hold_registry.wait(ticket) ..........................> SSE "ticket.created"         |
  |                                                      |   POST /api/tickets/{id}/approve        |
  |                        <---------- hold resolved ----------------+                             |
  |                        mark FORWARDING                                                         |
  |                        build upstream request (swap creds) ----------------------------------->|
  |                        <------------------------------------------------- 200 / SSE stream ---|
  |                        analyze_response, mark COMPLETED (or FAILED)                           |
  |  <-- upstream body + X-AISRF-Ticket ------------------|                                        |
```

Step details (all in `aisrf/gateway/router.py::intercept`):

1. **Authenticate** with `_extract_key`: `X-AISRF-Key`, `x-api-key`, `api-key` or `x-goog-api-key`
   holding an `aisrf_` prefixed value win; then `Authorization: Bearer`; then the same headers with
   any value. The SHA-256 hash is looked up in `agents.api_key_hash`; inactive agents fail.
2. **Rate limit** (`agents.check_rate_limit`, in-process sliding window per minute) -> 429.
3. **Body size** > `AISRF_MAX_REQUEST_BODY_BYTES` -> 413.
4. **Normalize** the body with the agent's `upstream_provider` as hint; compute the upstream URL
   (`build_upstream_url` de-duplicates a trailing `/v1` on the base with a leading `v1/` in the path).
5. **Create the ticket** with redacted headers, `source` (only gateway / mitm / sdk / redteam are
   accepted), `correlation_id` (`X-AISRF-Correlation-Id` or `X-Request-ID`), optional campaign and
   probe ids, and `expires_at = now + AISRF_APPROVAL_TIMEOUT_SECONDS`.
6. **Analyze** (`analyze_request`) and store `risk_score`, `risk_level`, `findings`.
7. **Policy** (`policy.evaluate`) sets the ticket to DENIED, APPROVED or leaves it PENDING.
8. DENIED -> `403`. PENDING in async mode -> `202`. PENDING in sync mode -> wait on the hold
   registry until decided, EXPIRED (`504`) or DENIED (`403`).
9. APPROVED -> `forward_ticket`: FORWARDING, upstream call through the shared client, response
   headers filtered (hop-by-hop, `content-encoding`, `content-length` removed), `X-AISRF-Ticket`
   added. Non-streaming responses are read fully; SSE streams are relayed chunk by chunk while the
   first `AISRF_MAX_STORED_RESPONSE_BYTES` are captured. Then `analyze_response` runs and the ticket
   becomes COMPLETED (status < 500) or FAILED.

Asynchronous mode differs only at step 8: the client gets `202 {ticket_id, status, poll_url,
expires_at}` and later calls `GET /gateway/tickets/{id}` with its agent key. The poll returns
`202` while PENDING; the first poll after approval performs steps 9 itself and relays the upstream
body; later polls return `200 {ticket_id, status: COMPLETED, response, response_status}`;
DENIED / EXPIRED return `403`; FAILED returns `502`.

## Ticket state machine

```
                      policy: deny
        +----------------------------------------> DENIED (403, nothing sent upstream)
        |                     reviewer: deny  /
  request --> PENDING -------------------------+
        |        |   \ timeout (sweeper or hold) \
        |        |    +--------------------------> EXPIRED (504, nothing sent upstream)
        |        | reviewer: approve
        |        v
        +---> APPROVED --> FORWARDING --> COMPLETED (upstream answered, status < 500)
       policy: approve            \
                                   +--> FAILED (network error or upstream status >= 500)
```

* Only PENDING tickets can be decided (`InvalidTransition` -> HTTP 409 otherwise).
* The background sweeper (every 5 s) moves PENDING tickets past `expires_at` to EXPIRED, and roughly
  hourly purges tickets older than `AISRF_TICKET_RETENTION_DAYS`.
* Every transition writes a `ticket_events` row, a per-agent log line, an SSE event on the
  `tickets` channel and, for human decisions, an audit entry.

## Hold registry

`HoldRegistry.wait(ticket_id)` blocks the gateway coroutine on an `asyncio.Event`. `decide()` calls
`hold_registry.resolve()` in the same process, which wakes the waiter immediately (fast path). If
the decision was made elsewhere (MCP server in another process, a second uvicorn worker, direct DB
write), the waiter notices on its next DB poll (`AISRF_HOLD_POLL_INTERVAL_SECONDS`). This is why
`AISRF_WORKERS=1` is the default and why horizontal scaling needs an external notification
mechanism (see README > Limitations and roadmap).

## Red-team engine

Campaigns select probes from the YAML corpus (by category, technique, severity, sampling), apply
mutators (base64, rot13, leetspeak, reverse, split, suffix) and submit each probe through
`aisrf.gateway.pipeline.submit` with `source=redteam`, `campaign_id` and `probe_id`. Every probe is
therefore a normal ticket: analysed, subject to the agent's policy and, when
`AISRF_REQUIRE_APPROVAL_FOR_REDTEAM_PROBES` is true, held for a human. The engine grades the
response into a verdict and aggregates the campaign summary. See `docs/REDTEAM.md`.

## Reports

`aisrf/reports/model.py` defines a format-agnostic `Report` made of sections (`KeyValueSection`,
`TableSection`, `TextSection`). Builders query the database; renderers serialise the same report to
json, yaml, csv, tsv, md, html, pdf, xlsx, txt, xml, sarif and junit. See `docs/REPORTS.md`.

## Observability

* structlog with three sinks (console, `logs/aisrf.jsonl`, `logs/agents/<agent_id>.jsonl`).
* `EventBroadcaster` channels `tickets`, `logs`, `campaigns` feed the SSE endpoints
  `/api/stream/tickets`, `/api/stream/logs`, `/api/stream/campaigns` (with replay).
* `/metrics` renders counters (`aisrf_gateway_requests_total`, `aisrf_gateway_policy_total{action}`,
  `aisrf_gateway_denied_total`, `aisrf_gateway_expired_total`, `aisrf_gateway_auth_failures_total`,
  `aisrf_gateway_upstream_errors_total`, `aisrf_gateway_upstream_responses_total{status}`) and
  histogram summaries (`aisrf_gateway_risk_score`, `aisrf_gateway_wait_seconds`,
  `aisrf_gateway_upstream_latency_ms`: `_count`, `_sum`, `_p50`, `_p95`).
* Every response carries `X-Request-ID`; the same id is bound to every log line of that request.
