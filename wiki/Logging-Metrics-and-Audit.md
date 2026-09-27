# Logging, metrics and audit

Three trails exist side by side: structured service logs (structlog), per-agent activity (file, database and live stream), and the hash-chained audit log for privileged actions. Prometheus-style metrics are rendered at `/metrics`.

## Log files and formats

`configure_logging()` in `aisrf/logging.py` installs three sinks on the root logger:

| Sink | Location | Format | Rotation |
| --- | --- | --- | --- |
| Console | stdout | Coloured console renderer in development; JSON lines when `AISRF_LOG_JSON_CONSOLE=true` or `AISRF_ENVIRONMENT=production` | none |
| Service log | `<AISRF_LOG_DIR>/aisrf.jsonl` | JSON lines | 50 MiB, 10 backups |
| Agent logs | `<AISRF_LOG_DIR>/agents/<agent_id>.jsonl` | JSON lines (one record per line, no wrapper) | 20 MiB, 5 backups |

Every service log line carries `event`, `level`, `logger`, `service` (`aisrf`), `timestamp` (ISO 8601 UTC) and, inside a request, the context bound by the correlation middleware: `request_id`, `path`, `method`. Exceptions are rendered with `exc_info`. Loggers `uvicorn.access`, `httpx`, `httpcore`, `aiosqlite` and `watchfiles` are raised to WARNING; `sqlalchemy.engine` is INFO only when `AISRF_DB_ECHO` is on. The level is `AISRF_LOG_LEVEL` (default `INFO`).

Example service line:

```json
{"event": "ticket.decided", "ticket_id": "tkt_5f...", "status": "APPROVED", "by": "alice", "level": "info", "logger": "aisrf.tickets", "service": "aisrf", "timestamp": "2026-09-27T10:04:12.113Z", "request_id": "a1b2c3d4e5f60718", "path": "/api/tickets/tkt_5f.../approve", "method": "POST"}
```

Notable service event names: `aisrf.started`, `aisrf.stopped`, `auth.admin_created`, `auth.default_admin_password`, `settings.overrides_applied`, `settings.updated`, `settings.namespace_updated`, `settings.reset`, `settings.namespace_reset`, `ticket.waiting`, `ticket.decided`, `sweeper.expired`, `sweeper.purged`, `sweeper.error`, `agent.created`, `agent.scan_token_minted`, `notify.started`, `notify.webhook_failed`, `notify.webhook_error`, `notify.error`, `response.analysis.failed`, `request.unhandled`, `audit`.

## Per-agent log files and events

`log_agent_event(agent_id, event, level=, ticket_id=, correlation_id=, **detail)` in `aisrf/agents/service.py` writes one record to four places at once: the service logger (as `agent.<event>`), the agent's JSONL file, the `logs` broadcaster channel and the `agent_events` table. The record shape:

```json
{"ts": "2026-09-27T10:03:58.002Z", "agent_id": "agt_...", "level": "INFO", "event": "request.analyzed", "ticket_id": "tkt_...", "correlation_id": "corr_...", "risk_score": 72, "risk_level": "HIGH", "findings": ["Instruction override attempt", "Base64 payload"]}
```

Event names per stage:

| Stage | Event | Level | Detail keys |
| --- | --- | --- | --- |
| Rate limit rejected | `rate_limited` | WARNING | `path` |
| Ticket created | `request.intercepted` | INFO | `path`, `model`, `method`, `chars` |
| Analysis stored | `request.analyzed` | INFO | `risk_score`, `risk_level`, `findings` (up to 8 titles) |
| Policy applied | `policy.deny`, `policy.approve`, `policy.review` | INFO | `reasons` |
| Human decision | `decision.approved`, `decision.denied` | INFO | `by`, `note` |
| Forwarding | `request.forwarding` | INFO | `upstream` |
| Upstream answered | `request.completed` | INFO | `status_code`, `latency_ms`, `response_findings` (up to 8 titles) |
| Transport failure | `request.failed` | ERROR | `error` |
| Timed out | `request.expired` | WARNING | none |

Query them with `GET /api/agents/{id}/events?limit=&offset=&level=` (newest first, `limit` <= 2000) or read the file. The `/logs` dashboard page and the agent detail page render the live stream.

## Ticket timeline events

Separate from agent events, each ticket has an append-only `ticket_events` list (`GET /api/tickets/{id}/events`): `created` (path, model, stream), `analyzed` (score, level, findings count), `policy` (actor `policy`, full decision), `approved` or `denied` (actor username, note), `forwarding` (upstream URL), `completed` (status code, latency, response finding count), `failed` (error), `expired`, `withheld` (actor `policy`, reason).

## SSE streams and payloads

`EventBroadcaster` keeps three channels (`tickets`, `logs`, `campaigns`; a fourth, `settings`, is published but has no HTTP endpoint) with a 500-entry ring buffer each and per-subscriber queues of 1000 (events are dropped for slow consumers rather than blocking the gateway). Endpoints in `aisrf/tickets/router.py`, all requiring any authenticated principal:

| Endpoint | Query | Events |
| --- | --- | --- |
| `GET /api/stream/tickets` | `replay=20` | `created`, `decided`, `forwarding`, `completed`, `failed`, `expired` |
| `GET /api/stream/logs` | `agent_id=`, `replay=50` | one event per agent log record; `agent_id` filters |
| `GET /api/stream/campaigns` | `replay=20` | campaign progress events from the red-team engine |

Each SSE message has `event: <name>` and `data: <json>`. Ticket payloads are `{"ts": <unix time>, "event": "<name>", "ticket": {<brief ticket>}, ...}` where the brief ticket is `ticket_to_dict(brief=True)`: `id`, `number`, `agent_id`, `agent_name`, `status`, `source`, `correlation_id`, `method`, `path`, `model`, `is_stream`, `prompt_preview`, `risk_score`, `risk_level`, `finding_count`, `policy_action`, `decided_by`, `decision_note`, `decided_at`, `expires_at`, `response_status`, `latency_ms`, `campaign_id`, `probe_id`, `created_at`, `updated_at`. `decided` events add `by`. Log payloads are the agent record shown above with `ts` as a Unix timestamp added by the broadcaster. A `ping` event with `{}` is sent after 15 s without traffic; `replay` returns the last N buffered events on connect.

```bash
curl -N -b jar "http://localhost:8080/api/stream/tickets?replay=5"
```

The notifier subscribes to the `tickets` channel to drive webhooks, and `aisrf tickets watch` consumes the same stream.

## Prometheus metrics

`aisrf/metrics.py` is a dependency-free registry. `GET /metrics` (no auth) renders every counter as `aisrf_<name>{labels} <value>` and every histogram as `aisrf_<name>_count`, `_sum`, `_p50` and `_p95` computed over the last 5000 observations. The scrape itself increments `aisrf_metrics_scrapes_total`.

| Metric | Type | Labels | Incremented when |
| --- | --- | --- | --- |
| `aisrf_gateway_requests_total` | counter | | Every interception (HTTP or `pipeline.submit`) |
| `aisrf_gateway_auth_failures_total` | counter | | Agent authentication failed |
| `aisrf_gateway_policy_total` | counter | `action` = `deny`, `approve`, `review` | Policy evaluated |
| `aisrf_gateway_denied_total` | counter | | Client received `403 denied` |
| `aisrf_gateway_expired_total` | counter | | Client received `504 expired` |
| `aisrf_gateway_upstream_errors_total` | counter | | Transport error after approval |
| `aisrf_gateway_upstream_responses_total` | counter | `status` = HTTP status | Upstream answered |
| `aisrf_gateway_responses_withheld_total` | counter | | Response withheld by policy |
| `aisrf_metrics_scrapes_total` | counter | | `/metrics` scraped |
| `aisrf_gateway_risk_score` | histogram | | Score of every analysed ticket |
| `aisrf_gateway_wait_seconds` | histogram | | Time a synchronous request spent waiting for a decision |
| `aisrf_gateway_upstream_latency_ms` | histogram | | Upstream round trip |

Counters are per process and reset on restart. The `/healthz` (`{"status": "ok", "version": "1.0.0"}`) and `/readyz` (runs a database query, `{"status": "ready"}`) endpoints complement them for probes.

## Audit log

`aisrf/audit/service.py` writes `audit_log` rows for privileged actions. Each row hashes `{"prev": prev_hash, "ts": <canonical timestamp>, "actor", "action", "tt": target_type, "tid": target_id, "d": detail}` (JSON with sorted keys) with SHA-256; the first row uses the genesis `prev_hash` of 64 zeros. Timestamps are canonicalised to naive UTC with microseconds so SQLite and PostgreSQL produce identical hashes.

Audit actions recorded in the code base:

| Area | Actions |
| --- | --- |
| Authentication | `auth.login`, `auth.login_failed` |
| Reviewers | `reviewer.create`, `reviewer.password_change`, `reviewer.deactivate` |
| Tickets | `ticket.approve`, `ticket.deny` (detail: `note`, `agent_id`, `risk_score`) |
| Agents | `agent.create`, `agent.update` (`upstream_api_key` shown as `[secret]`), `agent.rotate_key`, `agent.disable` |
| Settings | `settings.update`, `settings.reset`, `settings.import` |
| Red team | `redteam.campaign.create`, `redteam.campaign.start`, `redteam.campaign.cancel`, `redteam.campaign.delete`, `redteam.group.create`, `redteam.group.start`, `redteam.group.cancel`, `redteam.group.delete` |
| Scanners | `scanners.campaign.create`, `scanners.campaign.start`, `scanners.campaign.cancel`, `scanners.matrix.create`, `scanners.matrix.start` |
| Code review | `codereview.run.create`, `codereview.run.completed`, `codereview.run.failed`, `codereview.run.cancel`, `codereview.run.delete`, `codereview.finding.status`, `codereview.credential.create`, `codereview.credential.delete` |

Actors are reviewer usernames, `api-token` for the static admin token, `mcp-internal` for the in-process MCP transport, `cli` for direct CLI database commands, or `system`.

### Reading and verifying the chain

* `GET /api/audit?limit=200&offset=0&action=ticket.approve&actor=alice` (any role; `limit` <= 2000) returns `{"items": [{"id", "ts", "actor", "action", "target_type", "target_id", "detail", "hash", "prev_hash"}], "total": n}` newest first.
* `GET /api/audit/verify` recomputes every hash from the genesis forward and returns `{"ok": true, "checked": n, "head": "<sha256>"}` or `{"ok": false, "checked": n, "broken_at": <row id>}` for the first row whose `prev_hash` or `hash` does not match.
* `aisrf audit verify` calls the same endpoint from the CLI; the audit report (`GET /api/reports/audit?format=...`) exports the entries.
* Record the `head` hash out of band (for example in your ticketing system) after each review shift; a later verification whose head differs without new entries means rows were altered or removed at the tail, and a `broken_at` result pinpoints tampering inside the chain. Deleting rows at the very end of the chain is not detectable by verification alone, hence the out-of-band head.

## Request ids

`CorrelationMiddleware` in `aisrf/main.py` takes `X-Request-ID` from the inbound request or generates a 16-character hex id, binds it as `request_id` in the structlog context (together with `path` and `method`) for the whole request, and sets `X-Request-ID` on the response. Gateway tickets reuse it as the ticket `correlation_id` when `X-AISRF-Correlation-Id` is absent, so a client that sets `X-Request-ID` can join its own logs, the gateway log lines and the ticket. Unhandled exceptions are logged as `request.unhandled` and answered with `500 {"error": {"message": "internal error", "request_id": "..."}}`.

Related: [[Architecture]], [[Security-Model]], [[Operations-and-Maintenance]], [[Reports]].
