# Getting started

This page takes a fresh checkout to a first approved ticket. It uses a source install into a virtual environment; other install paths (binaries, pip, Docker, Helm) are in [[Installation]].

## Prerequisites

* Python 3.11 or 3.12.
* `uv` (used below) or plain `python -m venv` and `pip`.
* A provider API key (OpenAI, Anthropic, or any HTTP API you want to gate). Not needed to see tickets appear; needed for a ticket to complete.

## 1. Install from source into a venv

```bash
git clone https://github.com/keyuraghao/aisrf.git && cd aisrf
uv venv .venv
uv pip install --python .venv/bin/python -e ".[dev]"
```

Optional extras: `.[postgres]` for `asyncpg`, `.[mitm]` for the mitmproxy addon, `.[desktop]` for `aisrf desktop`, `.[all]` for everything including scanner and guardrail dependencies.

## 2. First run

```bash
.venv/bin/aisrf serve
```

`serve` accepts `--host`, `--port`, `--workers` and `--reload`; the defaults come from `AISRF_HOST` (`0.0.0.0`), `AISRF_PORT` (`8080`) and `AISRF_WORKERS` (`1`). On startup the lifespan in `aisrf/main.py`:

1. configures logging (console plus `logs/aisrf.jsonl`),
2. creates the database schema (`init_db`, SQLite with WAL and foreign keys on by default),
3. creates the bootstrap admin reviewer if it does not exist (`ensure_admin`) and logs `auth.default_admin_password` while the password is still `admin`,
4. applies settings overrides persisted in the `app_settings` table,
5. creates the shared upstream `httpx.AsyncClient`, a per-process internal token for the MCP server, and starts the background sweeper (every 5 s) and the notifier.

The log line `aisrf.started` shows the version, environment, port and approval timeout.

Before exposing the service to anyone else, set at least these in the environment or a `.env` file in the working directory:

```bash
AISRF_SECRET_KEY=$(openssl rand -hex 32)
AISRF_ADMIN_PASSWORD=<strong password>
AISRF_ADMIN_API_TOKEN=$(openssl rand -hex 32)   # needed by the CLI ticket commands and MCP
```

Changing `AISRF_SECRET_KEY` after agents exist makes their encrypted upstream keys unreadable unless `AISRF_ENCRYPTION_KEY` was set explicitly; see [[Security-Model]].

## 3. Log in

Open http://localhost:8080. The dashboard redirects to `/login`; sign in with `admin` / `admin` (or the values of `AISRF_ADMIN_USERNAME` and `AISRF_ADMIN_PASSWORD`). Login sets the `aisrf_session` cookie (`HttpOnly`, `SameSite=Lax`, lifetime `AISRF_SESSION_MAX_AGE_SECONDS`, default 43200).

From a script:

```bash
curl -c jar -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}'
curl -b jar http://localhost:8080/api/auth/me
```

## 4. Create an agent

An agent is a registered client identity: it owns an `aisrf_` key that your application presents, and an upstream configuration (provider, base URL, encrypted provider key) that the gateway uses when forwarding. Every field is described in [[Agents-and-Credentials]].

### Dashboard

Agents > New agent. Fill in a unique name, pick the upstream provider (`openai`, `anthropic`, `azure`, `ollama` or `custom`), paste the provider key into the upstream key field and save. The dialog shows the `aisrf_...` key once; copy it now. Afterwards the API and UI only expose `api_key_prefix` (the first 12 characters).

### CLI

The CLI talks to the database directly for agent creation, so run it on the gateway host with the same environment:

```bash
.venv/bin/aisrf agent create support-bot \
  --provider openai --upstream-key sk-... \
  --allowed-path 'v1/chat/*' --allowed-model 'gpt-4o*' --rate-limit 60
```

Options: `--provider`, `--base-url`, `--upstream-key`, `--approval/--no-approval`, `--auto-deny-at` (default 90, 101 disables), `--auto-approve-below` (default 0, disabled), `--deny-pattern` (repeatable), `--allowed-path` (repeatable), `--allowed-model` (repeatable), `--rate-limit`, `--description`, `--owner`, `--tag` (repeatable). The command prints the key once. `aisrf agent list` and `aisrf agent rotate-key <id>` complete the set.

### API

```bash
curl -b jar -X POST http://localhost:8080/api/agents -H 'Content-Type: application/json' -d '{
  "name": "support-bot",
  "upstream_provider": "openai",
  "upstream_api_key": "sk-...",
  "allowed_paths": ["v1/chat/*"],
  "allowed_models": ["gpt-4o*"],
  "rate_limit_per_minute": 60
}'
```

The response is `201` with the agent record plus `api_key`. Creating agents requires the `admin` role; an automation token (`Authorization: Bearer <AISRF_ADMIN_API_TOKEN>`) works in place of the cookie.

## 5. Point the SDKs at the gateway

The gateway accepts the agent key wherever the SDK would put a provider key, so the only change is the base URL and the key.

OpenAI SDK (the `/v1` prefix is part of the base URL):

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="aisrf_...", timeout=330, max_retries=0)
r = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hello"}])
```

Anthropic SDK (the SDK appends `/v1/messages` itself, so the base URL is the gateway root; the agent must have `upstream_provider` `anthropic`):

```python
from anthropic import Anthropic
client = Anthropic(base_url="http://localhost:8080", api_key="aisrf_...", timeout=330, max_retries=0)
r = client.messages.create(model="claude-3-5-haiku-latest", max_tokens=100, messages=[{"role": "user", "content": "hello"}])
```

Two settings matter. `timeout` must exceed `AISRF_APPROVAL_TIMEOUT_SECONDS` (default 300 s) plus the upstream time, otherwise the SDK gives up before the reviewer decides. `max_retries=0` prevents the SDK from resubmitting a `504` (expired) or `502` (upstream error) as a brand new ticket.

Environment variables work too and are what `aisrf.integrations.configure()` sets:

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1 OPENAI_API_KEY=aisrf_...
export ANTHROPIC_BASE_URL=http://localhost:8080 ANTHROPIC_API_KEY=aisrf_...
```

Other clients and frameworks are in [[Integrations-and-SDKs]].

## 6. Approve the first ticket

Run the client. The call blocks. In the dashboard, `/tickets` shows the new ticket in the PENDING tab with a countdown to `expires_at`, the model, the path, the risk badge and the prompt preview; the queue beeps if the sound toggle is on. Click the row (or press `j` to move the cursor onto it) and press `a` to approve, or open it and read the findings, the reconstructed conversation, the policy decision and the timeline first (see [[Tickets-and-Review-Workflow]]).

On approval the gateway marks the ticket `FORWARDING`, sends the request upstream with the agent's decrypted provider key, stores the response (truncated to `AISRF_MAX_STORED_RESPONSE_BYTES`), runs the response analyzers and marks the ticket `COMPLETED`. The client receives the upstream body and status unchanged plus the header `X-AISRF-Ticket: tkt_...`.

The same decision from the CLI (needs `AISRF_ADMIN_API_TOKEN` on the server and `--token` or the same variable on the client):

```bash
.venv/bin/aisrf tickets list --status PENDING
.venv/bin/aisrf tickets approve 1 --note "reviewed, benign"
```

Or the API:

```bash
curl -b jar -X POST http://localhost:8080/api/tickets/tkt_.../approve \
  -H 'Content-Type: application/json' -d '{"note":"reviewed, benign"}'
```

Deny instead and the client receives `403` with `{"error": {"code": "denied", ...}}`. Let it wait and after 300 s it receives `504` with `code: expired`. In both cases nothing was sent upstream.

## 7. Asynchronous mode walkthrough

Synchronous mode ties up a client connection for as long as the reviewer takes. Asynchronous mode returns immediately and lets the client poll.

1. Send the request with `X-AISRF-Async: 1` (also `true` or `yes`):

   ```bash
   curl -i -X POST http://localhost:8080/v1/chat/completions \
     -H "X-AISRF-Key: aisrf_..." -H "X-AISRF-Async: 1" -H "Content-Type: application/json" \
     -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
   ```

   If policy leaves the ticket PENDING the answer is `202`:

   ```json
   {"ticket_id": "tkt_...", "status": "PENDING", "poll_url": "/gateway/tickets/tkt_...", "expires_at": "2026-09-27T10:05:00+00:00"}
   ```

   with `X-AISRF-Ticket` set. Policy denials still return `403` immediately, and policy approvals are forwarded at once and return the upstream response.

2. Poll with the same agent key:

   ```bash
   curl -i http://localhost:8080/gateway/tickets/tkt_... -H "X-AISRF-Key: aisrf_..."
   ```

   * `202` while `PENDING` (body `{"ticket_id", "status": "PENDING", "decided_by": null, "decision_note": ""}`).
   * After approval, the first poll performs the upstream call itself and relays the upstream body and status with `X-AISRF-Ticket`.
   * Later polls return `200` with `{"ticket_id", "status": "COMPLETED", "decided_by", "decision_note", "response": {...}, "response_status": 200}` (`response_text` instead of `response` when the stored body is not JSON).
   * `403` for `DENIED` or `EXPIRED`, `502` for `FAILED`, `202` for `FORWARDING` (another poll is in flight), `404` when the ticket belongs to a different agent.

3. Or let the Python client do it:

   ```python
   from aisrf.integrations import AISRFClient
   with AISRFClient("http://localhost:8080", "aisrf_...", async_mode=True, poll_interval=2, max_wait=600) as c:
       r = c.chat("gpt-4o-mini", [{"role": "user", "content": "hello"}])
       print(r.ticket_id, r.status, r.http_status, r.content_text)
   ```

Streaming (`stream: true`) is relayed in synchronous mode only; the async poll replays the stored request without streaming semantics.

## What the first run creates

Relative to the working directory (`AISRF_BASE_DIR` defaults to the current directory):

| Path | Created by | Content |
| --- | --- | --- |
| `data/` | `Settings.ensure_dirs()` | `AISRF_DATA_DIR`; holds the SQLite file |
| `data/aisrf.db` (plus `-wal` and `-shm`) | `init_db()` | All tables: `reviewers`, `agents`, `scan_tokens`, `tickets`, `ticket_events`, `agent_events`, `audit_log`, `campaigns`, `probe_results`, `app_settings`, `counters`, `codereview_runs`, `codereview_findings` |
| `logs/` | `ensure_dirs()` | `AISRF_LOG_DIR` |
| `logs/aisrf.jsonl` | `configure_logging()` | Service log, JSON lines, rotated at 50 MiB with 10 backups |
| `logs/agents/` | `ensure_dirs()` | One `<agent_id>.jsonl` per agent that has sent traffic, rotated at 20 MiB with 5 backups |

In the database, the first run inserts the admin reviewer (`usr_...`), the `counters` row named `ticket`, and audit entries for every login and agent creation. `aisrf desktop` differs: it writes a per-user `aisrf.env` with a generated secret key and admin token and binds to 127.0.0.1 (see [[Desktop-Mode]]).

## Next steps

* [[Core-Concepts]] for the vocabulary, then [[Policy-Engine]] to decide what should not need a human.
* [[Settings-Center]] to change the approval timeout, notifications and guardrails live.
* [[Red-Teaming]] to run the probe corpus against the agent you just created.
