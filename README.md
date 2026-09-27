# AIRT - AI Security & Research Framework

**Human-in-the-loop interception, analysis and red teaming for LLM traffic.**

AIRT sits between your applications or autonomous agents and the model providers they call
(OpenAI, Anthropic, Gemini, Mistral, Groq, Ollama, any HTTP API). Every outbound request becomes a
**ticket**: it is normalised, scanned by a set of security analyzers, scored, checked against the
agent's policy and, unless the policy decides on its own, **held until a human approves or denies
it**. Approved requests are forwarded with credentials the client never sees; everything is logged,
audited with a hash chain and reportable in a dozen formats. The same pipeline runs a 300+ probe
red-team corpus against your models, one reviewable ticket per probe.

* Python 3.11+, FastAPI, SQLAlchemy async (SQLite or PostgreSQL), structlog. Apache-2.0.
* Zero code change for OpenAI / Anthropic SDKs (`base_url`), generic `/proxy/` for anything else,
  Python and Node interceptors, mitmproxy transparent mode.
* Dashboard, REST API, CLI and an MCP server so Claude Desktop / Claude Code can review tickets.

## Architecture

```
  applications / agents                 AIRT gateway (one process, one port)               providers
  ---------------------      +--------------------------------------------------+      -----------------
  OpenAI SDK  base_url ----->| /v1/*  /proxy/*                                  |      api.openai.com
  Anthropic SDK base_url --->|   authenticate agent key -> rate limit -> size   |      api.anthropic.com
  curl / httpx / fetch ----->|   normalize -> analyzers -> risk score -> policy |----->generativelanguage
  airt-intercept (node) ---->|      |                                     |      |      api.mistral.ai
  patch_httpx (python) ----->|      v                                     v      |      localhost:11434
  mitmproxy addon ---------->|   ticket PENDING ---(human)---> APPROVED -> forward (swap creds, relay, analyse response)
                             |      |                          DENIED  -> 403                 |
                             |      +---- timeout ------------> EXPIRED -> 504                 |
  reviewers                  |                                                                 |
  browser  ----------------->| dashboard  /tickets /agents /logs /redteam /reports /audit      |
  airt CLI ----------------->| REST API   /api/tickets /api/agents /api/redteam /api/reports  |
  Claude (MCP) ------------->| MCP        /mcp  (or `airt mcp` stdio)                          |
                             |                                                                 |
                             | red team: corpus -> mutators -> campaign -> tickets -> verdicts  |
                             | audit hash chain | structlog JSONL | SSE streams | /metrics      |
                             +-----------------------------------------------------------------+
```

More detail (components, data model, sequence diagrams, ticket state machine): `docs/ARCHITECTURE.md`.

## The human-in-the-loop flow

1. A registered **agent** (an app, a bot, a red-team runner) sends its usual request to the gateway
   with its `airt_...` key instead of the provider key.
2. The gateway creates a ticket, runs the analyzers (prompt injection, jailbreak, PII, secrets,
   exfiltration, tool abuse, harmful content, obfuscation, anomaly, optional LLM judge) and computes
   a **risk score** 0..100 with findings.
3. The **policy engine** applies the agent's rules: allowed paths and models, deny regexes,
   auto-deny at or above a risk threshold, auto-approve below another, mandatory review of critical
   secret / exfiltration findings, or `require_approval`.
4. If a human is needed, the request **waits** (sync mode) or the client gets a **202 with a ticket
   id** (async mode). Reviewers see the ticket live in the dashboard (or via CLI / MCP / webhook),
   read the normalised conversation and findings, and approve or deny with a note.
5. Approved: the gateway forwards the request with the agent's encrypted upstream credential,
   relays the response (streaming included), scans the response (system prompt leak, refusal,
   canary), and closes the ticket. Denied or expired: the client receives a 403 / 504 with the
   ticket id and nothing reaches the provider.
6. Every step is recorded: ticket timeline, per-agent log, service log, and a tamper-evident audit
   entry for each human decision.

## Quick start

```bash
git clone <repo> && cd AI_RedTeam
uv venv .venv --python 3.12 && uv pip install --python .venv/bin/python -e ".[dev]"
# or: python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
cp .env.example .env                 # optional; defaults work for a local trial
.venv/bin/airt serve                 # http://localhost:8080
```

1. Open http://localhost:8080 and log in with `admin` / `admin` (change it: `AIRT_ADMIN_PASSWORD`).
2. Create an agent (Agents page, or the CLI). The API key is shown once:

   ```bash
   .venv/bin/airt agent create demo --provider openai --upstream-key sk-...   # prints airt_...
   ```

3. Point an SDK at the gateway:

   ```python
   from openai import OpenAI
   client = OpenAI(base_url="http://localhost:8080/v1", api_key="airt_...", timeout=330, max_retries=0)
   client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hello"}])
   ```

4. The call blocks. Go to http://localhost:8080/tickets, open the ticket, read the findings and
   click **Approve**. The SDK call returns the model's answer with an `X-AIRT-Ticket` header.

Runnable examples for OpenAI, Anthropic, LangChain, async mode, curl and a tool-using agent loop are
in `examples/`.

## Interception modes

| Mode | Change in the client | Details |
| --- | --- | --- |
| SDK `base_url` | `base_url="http://gw:8080/v1"` (OpenAI style) or `"http://gw:8080"` (Anthropic), `api_key="airt_..."` | works for the official SDKs, LangChain, LlamaIndex, anything with a configurable endpoint |
| Generic proxy | `POST http://gw:8080/proxy/<provider path>` + `X-AIRT-Key` | any provider or internal API; the path is appended to the agent's `upstream_base_url` |
| Python patch | `from airt.integrations import patch_httpx; patch_httpx(gw, key)` | httpx (and `patch_requests()` for requests) hook that rewrites known provider hosts to `<gw>/proxy/<path>`; `AirtClient` for explicit ticket handling |
| Node package | `require("airt-intercept").install({ gatewayUrl, agentKey })` | wraps global `fetch` / undici; `configureOpenAI()` helper; `sdk/node` |
| mitmproxy | none; trust the mitmproxy CA | `mitmdump -s airt/integrations/mitm_addon.py`, transparent redirect with `X-AIRT-Source: mitm` |

Headers: `X-AIRT-Key` (also `Authorization: Bearer airt_...`), `X-AIRT-Async: 1`,
`X-AIRT-Source` (`sdk` / `mitm` / `gateway` / `redteam`), `X-AIRT-Correlation-Id`. Full guide:
`docs/INTEGRATIONS.md`.

## Sync vs async mode

* **Synchronous (default)**: the HTTP call blocks until a reviewer decides or
  `AIRT_APPROVAL_TIMEOUT_SECONDS` (300 s) elapses. Give the SDK a timeout above that and disable
  retries. Streaming responses work in this mode.
* **Asynchronous** (`X-AIRT-Async: 1`): the gateway answers `202 {"ticket_id", "status": "PENDING",
  "poll_url": "/gateway/tickets/<id>", "expires_at"}`. Poll `GET /gateway/tickets/<id>` with the
  agent key: `202` while pending; the first poll after approval forwards the request and relays
  the provider response (`X-AIRT-Ticket` header); afterwards `200 {"status": "COMPLETED",
  "response": ...}`; `403` for DENIED / EXPIRED; `502` for FAILED. `AirtClient` (Python) and
  `waitForTicket` (Node) implement the polling.

## Policy engine and thresholds

Per agent (`POST /api/agents`, dashboard, CLI flags), evaluated in order:

| Rule | Effect |
| --- | --- |
| `is_active = false` | deny |
| `allowed_paths` (globs) not matched | deny |
| `allowed_models` (globs) not matched | deny |
| `auto_deny_patterns` (regex on system + user text) matched | deny |
| `risk_score >= auto_deny_at_risk` (default 90) | deny |
| CRITICAL finding in `secrets` or `data_exfil` | review (always) |
| `require_approval = false` | approve |
| `risk_score < auto_approve_below_risk` (default 0 = off) | approve |
| otherwise | review by a human |

Plus `rate_limit_per_minute` (429) and `AIRT_MAX_REQUEST_BODY_BYTES` (413). Risk levels:
NONE 0, LOW < 25, MEDIUM < 50, HIGH < 80, CRITICAL >= 80. Scores come from finding severities
(INFO 0, LOW 10, MEDIUM 30, HIGH 60, CRITICAL 90) weighted by confidence, the strongest finding
dominating and the rest adding diminishing increments.

## Analyzers

Request analyzers (`airt/analysis/analyzers/`): **prompt_injection** (direct overrides, delimiter and
role spoofing, multilingual, indirect injection in tool results), **jailbreak** (DAN and friends,
persona hijack, refusal suppression, fiction framing, multi-turn escalation), **pii** (emails,
phones, SSNs, cards with Luhn, IBANs, national ids, medical record numbers, masked evidence),
**secrets** (API keys, cloud credentials, JWTs, private keys, connection strings), **data_exfil**
(system prompt extraction, conversation forwarding, markdown/image beacons, data in URLs),
**tool_abuse** (dangerous tools, command/SQL injection, path traversal, SSRF), **harmful_content**
(weighted lexicons with intent verbs), **obfuscation** (base64, hex, rot13, leetspeak, reversed
text, homoglyphs, zero-width characters, payload splitting), **anomaly** (role spoofing, extreme
parameters, unknown models, odd paths) and the optional **llm_judge**
(`AIRT_ENABLE_LLM_JUDGE`). Response analyzers: **system prompt leak**, **refusal detection**,
**canary leak**, and the judge's response variant. Findings carry OWASP LLM Top 10 (2025) ids via
`airt/taxonomy.py`. Analyzers run concurrently and a failing analyzer never blocks the gateway.

## Red teaming

`airt/redteam/corpus/` holds 300+ YAML probes across `prompt_injection`, `jailbreak`,
`system_prompt_extraction`, `data_exfiltration`, `pii_leakage`, `tool_abuse`, `harmful_content`,
`encoding_attacks`, `multi_turn`, `many_shot`, `misinformation_hallucination`, `bias_fairness`,
`privacy_memorization`, `code_safety`, `denial_of_wallet` and `benign_control` (to measure
over-refusal). Mutators: `base64`, `rot13`, `leetspeak`, `reverse`, `split`, `suffix`.

Campaigns run every probe **through the gateway**, so each probe is a ticket a human approves (or
auto-runs when `AIRT_REQUIRE_APPROVAL_FOR_REDTEAM_PROBES=false`). Verdicts: VULNERABLE, RESISTED,
BLOCKED, ERROR, INCONCLUSIVE.

```bash
airt redteam run --agent agt_... --model gpt-4o-mini --category prompt_injection --mutator base64 --max-probes 50 --wait
```

REST: `/api/redteam/corpus`, `/api/redteam/corpus/probes`, `/api/redteam/campaigns` (CRUD,
`start` / `pause` / `resume` / `cancel`, `results`, `summary`). Dashboard: `/redteam`. See `docs/REDTEAM.md`.

## Reports and formats

`GET /api/reports/{summary|tickets|ticket/{id}|agent/{id}|campaign/{id}|audit}?format=<fmt>` with
`json`, `yaml`, `csv`, `tsv`, `md`, `html`, `pdf`, `xlsx`, `txt`, `xml`, `sarif` (code scanning)
and `junit` (CI gating). Also `airt report <kind> -f <fmt> -o file`, the `/reports` page and the
`generate_report` MCP tool. See `docs/REPORTS.md`.

## MCP server

Every human action is an MCP tool: list / get / approve / deny tickets (and bulk), agents CRUD and
key rotation, campaigns, reports, audit, reviewers, health and metrics. Two transports:

* streamable HTTP at `http://localhost:8080/mcp` with `Authorization: Bearer <AIRT_ADMIN_API_TOKEN>`;
* stdio: `airt mcp --url http://localhost:8080 --token <AIRT_ADMIN_API_TOKEN>`.

Claude Desktop (`claude_desktop_config.json`) or Claude Code (`.mcp.json` / `claude mcp add`):

```json
{"mcpServers": {"airt": {"command": "airt", "args": ["mcp", "--url", "http://localhost:8080", "--token", "<AIRT_ADMIN_API_TOKEN>"]}}}
```

Ready-made config: `examples/mcp_client_config.json`. Details: `docs/MCP.md`.

## CLI reference

```
airt serve [--host] [--port] [--workers] [--reload]      run the gateway
airt init-db                                             create schema and the admin reviewer
airt create-reviewer <username> [--role viewer|reviewer|admin]
airt agent create <name> [--provider openai|anthropic|azure|ollama|custom] [--base-url] [--upstream-key]
                  [--approval/--no-approval] [--auto-deny-at 90] [--auto-approve-below 0]
                  [--deny-pattern RE]... [--allowed-path GLOB]... [--allowed-model NAME]... [--rate-limit N]
airt agent list [--all/--active-only]
airt agent rotate-key <id or name>
airt tickets list [--status PENDING,DENIED] [--agent id] [--min-risk N] [--limit N]
airt tickets show <id or number>
airt tickets approve|deny <id> [--note TEXT]
airt tickets watch [--status PENDING] [--replay N]      tail the live SSE stream
airt redteam corpus
airt redteam run --agent ID --model NAME [--category C]... [--technique T]... [--mutator M]...
                 [--max-probes N] [--system-prompt TEXT] [--path P] [--concurrency N] [--seed N] [--wait/--no-wait]
airt report <summary|tickets|audit|ticket/ID|agent/ID|campaign/ID> [-f FORMAT] [-o FILE]
airt audit verify                                        exit 2 if the chain is broken
airt mcp --url URL --token TOKEN                         stdio MCP server
airt version
```

`serve`, `init-db`, `create-reviewer` and `agent ...` use the database directly (same `.env`);
the others talk to a running gateway with `--url` / `--token` (env `AIRT_URL`,
`AIRT_ADMIN_API_TOKEN`).

## Logging

structlog with three sinks: console (pretty in development, JSON in production or with
`AIRT_LOG_JSON_CONSOLE=true`), `logs/airt.jsonl` (rotating 50 MB x 10) for the whole service, and
`logs/agents/<agent_id>.jsonl` (20 MB x 5) per agent, mirrored to the `agent_events` table. Every
line carries the request id (`X-Request-ID` response header). Live streams for dashboards and
tooling: `GET /api/stream/tickets`, `/api/stream/logs?agent_id=...`, `/api/stream/campaigns`
(Server-Sent Events with replay). Webhook notifications (Slack or generic JSON) on ticket events:
`AIRT_NOTIFY_WEBHOOK_URLS`.

## Metrics

`GET /metrics` (Prometheus text): `airt_gateway_requests_total`, `airt_gateway_auth_failures_total`,
`airt_gateway_policy_total{action}`, `airt_gateway_denied_total`, `airt_gateway_expired_total`,
`airt_gateway_upstream_errors_total`, `airt_gateway_upstream_responses_total{status}`, and
summaries (`_count`, `_sum`, `_p50`, `_p95`) for `airt_gateway_risk_score`,
`airt_gateway_wait_seconds` and `airt_gateway_upstream_latency_ms`.

## Security model

* Agents hold only an AIRT key (SHA-256 hashed at rest); **upstream provider keys are stored
  Fernet-encrypted** and injected by the gateway at forward time.
* Reviewer passwords: PBKDF2-HMAC-SHA256 (390k rounds). Sessions: signed `HttpOnly` cookies.
  Roles `viewer` < `reviewer` < `admin`. `AIRT_ADMIN_API_TOKEN` gives automation the admin role.
* **Hash-chained audit log** of every privileged action, verifiable with `GET /api/audit/verify`.
* Client credential headers are stripped before forwarding; stored headers are redacted.
* Denied and expired tickets never reach the provider; only PENDING tickets can be decided.

Threat model and controls: `docs/SECURITY.md`. Hardening checklist and disclosure: `SECURITY.md`.

## Configuration

All settings are `AIRT_*` environment variables or `.env` entries (`.env.example` documents each).

| Variable | Default | Purpose |
| --- | --- | --- |
| `AIRT_APP_NAME` | `AIRT Gateway` | display name |
| `AIRT_ENVIRONMENT` | `development` | `development` / `staging` / `production` |
| `AIRT_HOST` / `AIRT_PORT` | `0.0.0.0` / `8080` | bind address |
| `AIRT_WORKERS` | `1` | uvicorn workers (keep 1, see Limitations) |
| `AIRT_BASE_DIR` / `AIRT_DATA_DIR` / `AIRT_LOG_DIR` | cwd / `./data` / `./logs` | paths |
| `AIRT_LOG_LEVEL` / `AIRT_LOG_JSON_CONSOLE` | `INFO` / `false` | logging |
| `AIRT_DATABASE_URL` | `sqlite+aiosqlite:///./data/airt.db` | or `postgresql+asyncpg://...` |
| `AIRT_DB_ECHO` | `false` | SQL logging |
| `AIRT_SECRET_KEY` | change-me... | session signing, derives the Fernet key |
| `AIRT_ENCRYPTION_KEY` | unset | explicit Fernet key for upstream credentials |
| `AIRT_ADMIN_USERNAME` / `AIRT_ADMIN_PASSWORD` | `admin` / `admin` | bootstrap reviewer |
| `AIRT_ADMIN_API_TOKEN` | unset | bearer token for MCP / CLI / CI |
| `AIRT_SESSION_MAX_AGE_SECONDS` | `43200` | dashboard session lifetime |
| `AIRT_COOKIE_SECURE` | `false` | `Secure` cookie flag |
| `AIRT_NOTIFY_WEBHOOK_URLS` | `[]` | Slack / JSON webhooks |
| `AIRT_NOTIFY_EVENTS` | `["created","expired","failed"]` | events that notify |
| `AIRT_NOTIFY_MIN_RISK` | `0` | notification risk floor |
| `AIRT_PUBLIC_URL` | empty | base URL for links in notifications |
| `AIRT_APPROVAL_TIMEOUT_SECONDS` | `300` | human decision window |
| `AIRT_HOLD_POLL_INTERVAL_SECONDS` | `1.0` | cross-process decision polling |
| `AIRT_MAX_REQUEST_BODY_BYTES` | `4194304` | 413 above |
| `AIRT_MAX_STORED_RESPONSE_BYTES` | `524288` | response capture size |
| `AIRT_UPSTREAM_TIMEOUT_SECONDS` / `AIRT_UPSTREAM_CONNECT_TIMEOUT_SECONDS` | `120` / `10` | upstream timeouts |
| `AIRT_DEFAULT_AUTO_DENY_RISK_THRESHOLD` | `90` | default for new agents |
| `AIRT_DEFAULT_AUTO_APPROVE_RISK_THRESHOLD` | `0` | default for new agents (0 = off) |
| `AIRT_TICKET_RETENTION_DAYS` | `90` | purge horizon (0 = keep) |
| `AIRT_REQUIRE_APPROVAL_FOR_REDTEAM_PROBES` | `true` | probes wait for a human |
| `AIRT_ENABLE_LLM_JUDGE` | `false` | LLM judge analyzer |
| `AIRT_JUDGE_PROVIDER` / `AIRT_JUDGE_BASE_URL` / `AIRT_JUDGE_API_KEY` / `AIRT_JUDGE_MODEL` | `openai` / unset / unset / `gpt-4o-mini` | judge endpoint |
| `AIRT_REDTEAM_CONCURRENCY` | `4` | parallel probes |
| `AIRT_REDTEAM_PROBE_TIMEOUT_SECONDS` | `90` | per-probe wait |

Full descriptions and the per-agent policy fields: `docs/CONFIGURATION.md`.

## Deployment

```bash
docker build -t airt . && docker run -d -p 127.0.0.1:8080:8080 --env-file .env -v airt-data:/app/data -v airt-logs:/app/logs airt
docker compose up -d                       # SQLite volume
docker compose --profile postgres up -d    # with PostgreSQL (set AIRT_DATABASE_URL in .env)
```

The image is multi-stage on `python:3.12-slim`, runs as a non-root user, has a `/healthz`
HEALTHCHECK and volumes for `/app/data` and `/app/logs`. Put TLS in a reverse proxy with long read
timeouts and no buffering for SSE; PostgreSQL via `pip install "airt[postgres]"`. `make` targets:
`install`, `dev`, `run`, `test`, `lint`, `docker-build`, `docker-run`, `compose-up`. See
`docs/DEPLOYMENT.md`.

## Limitations

* **Single-process hold registry**: a waiting synchronous request is woken instantly only when the
  decision happens in the same process. Decisions from other processes (`--workers > 1`, separate
  MCP host) are picked up by DB polling every `AIRT_HOLD_POLL_INTERVAL_SECONDS`. The in-process
  rate limiter, SSE broadcaster and metrics are also per process.
* No schema migrations yet (`create_all` on start); no built-in TLS; no CSRF token beyond
  `SameSite=Lax` cookies and JSON-only mutations.
* Analyzers are heuristic: they rank and gate, they do not replace the reviewer.
* Async mode replays the stored request on the first poll after approval; streaming clients should
  use sync mode.
* Restarting the gateway drops in-flight synchronous waits (the tickets expire).

## Roadmap

* Redis / PostgreSQL LISTEN-NOTIFY based hold registry for multi-worker deployments.
* Alembic migrations.
* Per-reviewer MCP tokens and SSO (OIDC) for the dashboard.
* Semantic (embedding based) analyzers and adaptive multi-turn red-team strategies.
* Policy simulation ("what would this rule set have done to last week's traffic").
* OpenTelemetry traces.

## Documentation

`docs/ARCHITECTURE.md`, `docs/API.md`, `docs/CONFIGURATION.md`, `docs/INTEGRATIONS.md`,
`docs/DEPLOYMENT.md`, `docs/SECURITY.md`, `docs/MCP.md`, `docs/REDTEAM.md`, `docs/REPORTS.md`,
`examples/README.md`, `sdk/node/README.md`, `CONTRIBUTING.md`, `SECURITY.md`.

## License

Apache License 2.0, see `LICENSE`.
