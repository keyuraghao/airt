# Architecture

AISRF is one FastAPI application (`aisrf.main.create_app`) serving three surfaces on one port: the gateway that clients call instead of the provider, the reviewer API and dashboard that humans use, and the MCP server that exposes reviewer actions to AI assistants.

![Architecture](https://raw.githubusercontent.com/keyuraghao/aisrf/main/docs/images/architecture.png)

## Components and interactions

| Component | Module | Role |
| --- | --- | --- |
| Gateway router | `aisrf/gateway/router.py` | `/v1/{path}`, `/proxy/{path}`, `/gateway/tickets/{id}`; authenticates the agent key, applies rate and size limits, drives the ticket through analysis, policy, hold and forwarding |
| Parser | `aisrf/gateway/parser.py` | `normalize()` turns any provider body into one structure; `extract_response_text()` pulls assistant text out of JSON or SSE responses |
| Analysis runner | `aisrf/analysis/runner.py` | `analyze_request` and `analyze_response` run every registered analyzer concurrently, isolate failures, apply the `analyzers` settings namespace and custom rules, and score the result |
| Policy engine | `aisrf/gateway/policy.py` | `evaluate()` returns `deny`, `approve` or `review` with reasons and matched rule names |
| Hold registry | `aisrf/gateway/hold.py` | Parks a synchronous request until its ticket is decided |
| Forwarder | `aisrf/gateway/forwarder.py` | Builds the upstream URL and headers, swaps credentials, filters response headers |
| Canary | `aisrf/gateway/canary.py` | Injects and detects Rebuff-style canary tokens |
| Pipeline | `aisrf/gateway/pipeline.py` | `submit()`: the same steps callable in-process, used by the red-team engine and scanners |
| Ticket service | `aisrf/tickets/service.py` | State transitions, timeline events, queries, expiry, purge |
| Agent service | `aisrf/agents/service.py` | Agent CRUD, key hashing, scan tokens, in-process rate limiter, per-agent activity logger |
| Auth and security | `aisrf/auth.py`, `aisrf/security.py` | Sessions, bearer tokens, roles; PBKDF2 passwords, SHA-256 key hashes, Fernet, header redaction |
| Audit | `aisrf/audit/service.py` | SHA-256 hash chain and verification |
| Settings store | `aisrf/settings_store.py`, `aisrf/settings_router.py` | Live overrides of `Settings` fields and JSON namespaces, persisted in `app_settings` |
| Logging and metrics | `aisrf/logging.py`, `aisrf/metrics.py` | structlog sinks, `EventBroadcaster` for SSE, Prometheus text rendering |
| Notifications | `aisrf/notifications.py` | Subscribes to the `tickets` channel and posts to webhooks |
| Guardrails | `aisrf/guardrails/` | LLM Guard, NeMo Guardrails, Lakera and Rebuff adapters, exposed as analyzers |
| Red team | `aisrf/redteam/` | Corpus, mutators, campaign engine, evaluators, comparison groups |
| Scanners | `aisrf/scanners/` | garak, promptfoo, PyRIT and PyRIT-Ship runners that mint scan tokens and import results |
| Code review | `aisrf/codereview/` | Intake, inventory, rule packs, semgrep, bandit and LLM engines, SARIF |
| Reports | `aisrf/reports/` | `Report` model, builders per report type, renderers for 13 formats |
| Dashboard | `aisrf/dashboard/` | Jinja2 templates and vanilla JS pages |
| MCP server | `aisrf/mcp_server.py` | Tools mirroring the reviewer API over streamable HTTP at `/mcp` and stdio |
| CLI | `aisrf/cli.py` | Typer commands |
| Client integrations | `aisrf/integrations/` | Python SDK helpers and the mitmproxy addon |

### Request lifecycle

![Request lifecycle](https://raw.githubusercontent.com/keyuraghao/aisrf/main/docs/images/request-lifecycle.png)

`intercept()` in the gateway router performs these steps in order:

1. `metrics.inc("gateway_requests_total")`, then authenticate the agent key (401 on failure, `gateway_auth_failures_total`).
2. In-process rate limit per agent (429) and body size against `AISRF_MAX_REQUEST_BODY_BYTES` (413).
3. `normalize(path, body, provider_hint=agent.upstream_provider)`.
4. If `agent.inject_canary` or the `rebuff.canary_default` integration setting is on, inject a canary into the system prompt and record it as `normalized["canary"]`.
5. Compute the upstream URL, parse the JSON body, read `X-AISRF-Async`, `X-AISRF-Correlation-Id` (falls back to `X-Request-ID`), `X-AISRF-Source`, `X-AISRF-Campaign-Id` and `X-AISRF-Probe-Id`.
6. `create_ticket()` with redacted headers and `expires_at = now + AISRF_APPROVAL_TIMEOUT_SECONDS`; `touch_agent()` bumps `request_count` and `last_seen_at`.
7. `analyze_request()`; store score, level, findings, duration; `metrics.observe("gateway_risk_score")`.
8. `policy.evaluate()`; `apply_policy()` sets DENIED, APPROVED or PENDING (PENDING also registers the hold) and publishes the `created` event.
9. DENIED: 403. PENDING and async: 202. PENDING and sync: `hold_registry.wait()`, then 504 if expired, 403 if denied.
10. APPROVED: `forward_ticket()` marks FORWARDING, sends through the shared client, filters response headers, adds `X-AISRF-Ticket`, reads the body (or relays the stream while capturing the first `AISRF_MAX_STORED_RESPONSE_BYTES`), runs `analyze_response()`, marks COMPLETED (status < 500) or FAILED, and withholds the body with 403 when the `policy` namespace says so.

## Process model

* One process, one uvicorn worker by default (`AISRF_WORKERS=1`). The app is created by `create_app()`; `aisrf serve` runs uvicorn on it.
* The lifespan owns a shared upstream `httpx.AsyncClient` (timeouts from `AISRF_UPSTREAM_TIMEOUT_SECONDS` and `AISRF_UPSTREAM_CONNECT_TIMEOUT_SECONDS`, `follow_redirects=False`, 200 max connections, 50 keep-alive), the campaign runner, the scan runner, the code review runner and the notifier, and shuts them down in reverse.
* Background sweeper: a task that loops every 5 s, calling `expire_stale()` (PENDING tickets past `expires_at` become EXPIRED, which also resolves any waiter) and, every 720th iteration (about an hour), `purge_old()` when `AISRF_TICKET_RETENTION_DAYS > 0`. Errors are logged as `sweeper.error` and the loop continues.
* Hold registry fast path plus DB polling fallback: `wait()` blocks on an `asyncio.Event` for at most `AISRF_HOLD_POLL_INTERVAL_SECONDS` (default 1.0) at a time; on each timeout it reads the ticket status from the database and returns when it is no longer PENDING; when the total deadline (the approval timeout, or the `wait_timeout` passed by `pipeline.submit`) passes it returns `EXPIRED`. `decide()` and `mark_expired()` call `resolve()` in the same process, which wakes the waiter immediately.
* Multi-worker caveats: with `AISRF_WORKERS > 1`, or with the MCP server or CLI deciding from another process, decisions are still honoured but only on the next DB poll; the in-process rate limiter (`agents.check_rate_limit`) and the `EventBroadcaster` (SSE streams, notifier, live dashboard updates) are per worker, so a dashboard connected to worker A does not see events produced by worker B. Keep one worker unless you accept those semantics, or scale by running several independent instances behind a path-sticky proxy.
* Correlation middleware: every request gets `request_id` (from `X-Request-ID` or a generated 16-hex id) bound into structlog context and echoed as the `X-Request-ID` response header; unhandled exceptions become `500 {"error": {"message": "internal error", "request_id": ...}}`.

## Data model

All tables are declared in `aisrf/models.py` (SQLAlchemy 2, JSON columns for flexible data, timezone-aware datetimes). Ids are prefixed UUID hex strings.

| Table | Id prefix | Important columns |
| --- | --- | --- |
| `reviewers` | `usr_` | `username` (unique), `password_hash` (PBKDF2), `role` (`admin`, `reviewer`, `viewer`), `is_active`, `created_at`, `last_login_at` |
| `agents` | `agt_` | `name` (unique), `description`, `owner`, `tags`, `api_key_hash` (unique SHA-256), `api_key_prefix`, `upstream_provider`, `upstream_base_url`, `upstream_api_key_encrypted`, `upstream_auth_header`, `upstream_extra_headers`, `require_approval`, `auto_approve_below_risk`, `auto_deny_at_risk`, `auto_deny_patterns`, `allowed_paths`, `allowed_models`, `rate_limit_per_minute`, `inject_canary`, `is_active`, `request_count`, `last_seen_at`, `created_at`, `updated_at` |
| `scan_tokens` | `scn_` | `agent_id`, `token_hash` (unique), `purpose`, `campaign_id`, `created_by`, `created_at`, `expires_at`, `revoked` |
| `tickets` | `tkt_` | `number` (unique sequence), `agent_id`, `status`, `source`, `correlation_id`, `client_ip`, `user_agent`, `method`, `path`, `upstream_url`, `request_headers` (redacted), `request_body`, `request_json`, `normalized`, `prompt_preview`, `model`, `is_stream`, `risk_score`, `risk_level`, `findings`, `analysis_ms`, `policy_decision`, `decided_by`, `decision_note`, `decided_at`, `expires_at`, `forwarded_at`, `response_status`, `response_headers`, `response_body` (truncated), `response_preview`, `response_findings`, `latency_ms`, `error`, `campaign_id`, `probe_id`, `created_at`, `updated_at`; index on `(agent_id, status)` |
| `ticket_events` | integer | `ticket_id` (cascade delete), `ts`, `event_type`, `actor`, `detail` |
| `agent_events` | integer | `agent_id`, `ts`, `level`, `event`, `ticket_id`, `correlation_id`, `detail` |
| `audit_log` | integer | `ts`, `actor`, `action`, `target_type`, `target_id`, `detail`, `prev_hash`, `hash` (unique) |
| `campaigns` | `cmp_` | `name`, `agent_id`, `target_model`, `status` (`CREATED`, `RUNNING`, `PAUSED`, `COMPLETED`, `FAILED`, `CANCELLED`), `config`, `summary`, `total_probes`, `completed_probes`, `created_by`, `created_at`, `started_at`, `finished_at`, `error` |
| `probe_results` | `prb_` | `campaign_id` (cascade delete), `probe_id`, `category`, `technique`, `severity`, `prompt`, `messages`, `response`, `verdict` (`VULNERABLE`, `RESISTED`, `BLOCKED`, `ERROR`, `PENDING`, `INCONCLUSIVE`), `confidence`, `evidence`, `ticket_id`, `latency_ms`, `ts` |
| `app_settings` | composite | primary key (`namespace`, `key`), `value` as `{"v": ...}`, `updated_by`, `updated_at` |
| `counters` | name | `name` (`ticket`), `value`; the ticket number sequence, incremented with a row-locking UPDATE so concurrent writers never collide |
| `codereview_runs` | `crv_` | `name`, `source_type` (`git`, `url`, `zip`, `path`, `snippet`), `source_ref` (never carries credentials), `status` (`CREATED`, `FETCHING`, `ANALYZING`, `COMPLETED`, `FAILED`, `CANCELLED`), `stage`, `inventory`, `summary`, `config`, `created_by`, timestamps, `error`, `work_dir`, `file_count`, `loc`, `finding_count` |
| `codereview_findings` | `crf_` | `run_id` (cascade delete), `rule_id`, `pack`, `engine` (`rules`, `semgrep`, `bandit`, `llm`), `severity`, `confidence`, `title`, `description`, `remediation`, `file`, `line_start`, `line_end`, `snippet` (secret-masked), `language`, `owasp`, `cwe`, `fingerprint`, `status` (`open`, `false_positive`, `accepted`), `reviewer_note`, `reviewed_by`, `ts`; index on `(run_id, severity)` |

The database URL is `AISRF_DATABASE_URL` (`sqlite+aiosqlite:///./data/aisrf.db` by default, or `postgresql+asyncpg://...`). SQLite connections use a 30 s busy timeout and `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON` are executed at init. Schema creation is `Base.metadata.create_all`; there is no migration tool.

## Code layout

| Path | Responsibility |
| --- | --- |
| `aisrf/__init__.py` | Package docstring and `__version__` (`1.0.0`) |
| `aisrf/config.py` | `Settings` (pydantic-settings, prefix `AISRF_`, `.env`), `get_settings()` cache, `fernet_key` derivation, `ensure_dirs()` |
| `aisrf/main.py` | App factory, `CorrelationMiddleware`, lifespan, `_background_sweeper`, `/healthz`, `/readyz`, `/metrics`, router registration (gateway last, as catch-all) |
| `aisrf/db.py` | Async engine and sessionmaker, `session_scope()`, `get_session()` dependency, `init_db()`, counter seeding, `dispose_db()` |
| `aisrf/models.py` | All ORM models and the `TicketStatus`, `RiskLevel`, `CampaignStatus`, `CodeReviewStatus` enums |
| `aisrf/auth.py` | `/api/auth/*` router, `Principal`, `ensure_admin`, `current_principal`, `require_role`, session cookie handling |
| `aisrf/security.py` | Password hashing and verification, agent key generation and hashing, session token serializer, Fernet encrypt and decrypt, `redact_headers` |
| `aisrf/settings_store.py` | `LOCKED`, `GROUPS`, `NAMESPACE_DEFAULTS`, schema, coercion, load, update, reset, export, import |
| `aisrf/settings_router.py` | `/api/settings/*` |
| `aisrf/logging.py` | `configure_logging`, `get_logger`, `agent_file_logger`, `EventBroadcaster`, `json_dumps` |
| `aisrf/metrics.py` | `Metrics` registry (`inc`, `observe`, `render`, `snapshot`) |
| `aisrf/notifications.py` | `Notifier`, Slack Block Kit and generic payloads |
| `aisrf/taxonomy.py` | OWASP LLM Top 10, Greshake and Thacker maps, `classify`, `enrich`, `coverage`, `catalogue` |
| `aisrf/desktop.py` | `aisrf desktop` local mode |
| `aisrf/cli.py` | Typer CLI |
| `aisrf/mcp_server.py` | MCP tools and `mount_mcp` |
| `aisrf/gateway/router.py` | Interception endpoints, `intercept`, `forward_ticket`, `_finish`, `poll_ticket` |
| `aisrf/gateway/parser.py` | `normalize`, `detect_endpoint`, `extract_response_text` |
| `aisrf/gateway/policy.py` | `PolicyDecision`, `evaluate` |
| `aisrf/gateway/hold.py` | `HoldRegistry`, `hold_registry` singleton |
| `aisrf/gateway/forwarder.py` | `HOP_BY_HOP`, `STRIP_INBOUND`, URL and header construction, `make_client`, `error_json` |
| `aisrf/gateway/canary.py` | `new_canary`, `inject`, `leaked` |
| `aisrf/gateway/pipeline.py` | `submit`, `SubmitResult` |
| `aisrf/tickets/service.py` | Ticket lifecycle and queries |
| `aisrf/tickets/router.py` | `/api/tickets*`, `/api/audit*`, `/api/stream/*` |
| `aisrf/agents/service.py` | Agent registry, scan tokens, rate limiter, `log_agent_event`, stats |
| `aisrf/agents/router.py` | `/api/agents*` |
| `aisrf/audit/service.py` | `record`, `list_entries`, `count_entries`, `verify_chain` |
| `aisrf/analysis/base.py` | `Severity`, `SEVERITY_WEIGHT`, `Finding`, `AnalysisResult`, `level_for_score`, `score_findings` |
| `aisrf/analysis/runner.py` | Analyzer registry and the request and response runners |
| `aisrf/analysis/custom_rules.py` | Regex rules from the `rules` namespace |
| `aisrf/analysis/analyzers/` | `prompt_injection`, `jailbreak`, `pii`, `secrets`, `data_exfil`, `tool_abuse`, `harmful_content`, `obfuscation`, `anomaly`, `llm_judge`, `response_analyzers` (`system_prompt_leak`, `pii_leak`, `secrets_leak`, `refusal_detection`, `harmful_compliance`, `exfil_markers_in_response`, `canary_leak`), `common` |
| `aisrf/guardrails/` | `llm_guard.py`, `nemo.py` (with `nemo_default/` bundled rails), `lakera.py`, `rebuff.py`, `_common.py` |
| `aisrf/redteam/` | `corpus/` (YAML probes), `corpus.py`, `mutators.py`, `evaluators.py`, `engine.py` (campaign runner), `service.py`, `router.py` |
| `aisrf/scanners/` | `base.py` (scan runner, token issuance), `garak.py`, `promptfoo.py`, `pyrit.py`, `pyrit_ship.py`, `service.py`, `router.py` |
| `aisrf/codereview/` | `intake.py`, `inventory.py`, `rules/`, `engines/` (`rules_engine`, `semgrep_engine`, `bandit_engine`, `llm_engine`), `findings.py`, `secrets.py`, `sarif.py`, `report.py`, `service.py`, `router.py`, `config.py` |
| `aisrf/reports/` | `model.py`, `builders.py`, `renderers.py`, `router.py` |
| `aisrf/dashboard/` | `router.py` (page routes), `templates/` (`base`, `login`, `overview`, `tickets`, `ticket`, `agents`, `agent`, `logs`, `redteam`, `campaign`, `group`, `codereview`, `codereview_run`, `reports`, `audit`, `settings`), `static/` (one JS file per page plus `app.js` and `style.css`) |
| `aisrf/integrations/` | `python_sdk.py`, `mitm_addon.py` |
| `sdk/node/` | The `aisrf-intercept` Node package |

Related pages: [[Core-Concepts]], [[Gateway-Endpoints-and-Headers]], [[Logging-Metrics-and-Audit]], [[Development-Guide]].
