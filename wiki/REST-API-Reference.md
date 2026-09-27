# REST API Reference

Every function of AISRF is available over HTTP: the dashboard, the CLI and the MCP server are all clients of this API. Interactive documentation is generated from the same code and served at `/api/docs` (Swagger UI), `/api/redoc` and `/api/openapi.json`.

Base URL in the examples: `http://localhost:8080`. Responses are JSON unless stated otherwise. Every response carries an `X-Request-ID` header (taken from the inbound `X-Request-ID` or generated); unhandled errors return `500 {"error": {"message": "internal error", "request_id": "..."}}`.

Related pages: [[Gateway-Endpoints-and-Headers]] for the interception surface in depth, [[Security-Model]] for roles and tokens, [[MCP-Server]] and [[CLI-Reference]] for the clients built on this API, [[Reports]] for the export endpoints.

## Authentication

Four credentials exist. Reviewer endpoints (`/api/...`) accept the first three; gateway endpoints (`/v1/...`, `/proxy/...`, `/gateway/...`) accept only agent keys.

| Credential | How it is sent | Principal | Where it comes from |
| --- | --- | --- | --- |
| Session cookie | `Cookie: aisrf_session=<signed token>` | the reviewer account (`via: "session"`) | `POST /api/auth/login`. `HttpOnly`, `SameSite=Lax`, `Secure` when `AISRF_COOKIE_SECURE=true`, lifetime `AISRF_SESSION_MAX_AGE_SECONDS` (default 43200, 12 hours) |
| Admin API token | `Authorization: Bearer <token>` or `X-AISRF-Admin-Token: <token>` | `api-token`, role `admin` (`via: "token"`) | `AISRF_ADMIN_API_TOKEN` on the server. Used by the CLI, the stdio MCP server and CI |
| Internal token | `Authorization: Bearer <token>` | `mcp-internal`, role `admin` | Generated per process at startup (`app.state.internal_token`); only the in-process MCP endpoint uses it. It never leaves the process |
| Agent key | `X-AISRF-Key: aisrf_...` (also `Authorization: Bearer aisrf_...`, `x-api-key`, `api-key`, `x-goog-api-key`) | the registered agent | `POST /api/agents`, `aisrf agent create`, or the `rotate-key` endpoint. Shown once |

Token headers are checked before the cookie; a request that carries a valid bearer token is an admin even if a cookie is present.

### Roles

| Role | Rank | Can |
| --- | --- | --- |
| `viewer` | 1 | read everything: tickets, agents, audit, reports, settings, campaigns, code review |
| `reviewer` | 2 | viewer plus approve or deny tickets, create and control campaigns and groups, run code review, change finding status |
| `admin` | 3 | everything: reviewers, agents, settings writes, credentials, local path intake, settings export and import |

Failures: `401 {"detail": "authentication required"}` when no credential is valid, `403 {"detail": "role 'reviewer' required"}` when the role rank is too low. Validation errors are `422 {"detail": [{"loc": [...], "msg": "...", "type": "..."}]}`. All other reviewer errors use `{"detail": "<message>"}`. Gateway errors use `{"error": {"message", "type": "aisrf_gateway", "code", "ticket_id", ...}}`.

```bash
# session login, cookie stored in a jar
curl -c jar -X POST http://localhost:8080/api/auth/login \
  -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}'
curl -b jar http://localhost:8080/api/auth/me

# admin token
curl -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" http://localhost:8080/api/tickets/stats
```

## Auth and reviewers

Prefix `/api/auth`. Source: `aisrf/auth.py`.

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | none | Body `LoginIn {username, password}`. Sets the `aisrf_session` cookie and returns `{"id", "username", "role"}`. `401 invalid credentials` (audited as `auth.login_failed`); inactive accounts also get 401 |
| POST | `/api/auth/logout` | any | Deletes the cookie. Returns `{"status": "logged_out"}` |
| GET | `/api/auth/me` | any | `Principal {id, username, role, via}` where `via` is `session` or `token` |
| GET | `/api/auth/reviewers` | admin | `[{id, username, role, is_active, last_login_at}]` ordered by creation |
| POST | `/api/auth/reviewers` | admin | Body `ReviewerIn {username, password, role="reviewer"}`. `201 {"id", "username", "role"}`. `400` unknown role, `409 username already exists` |
| POST | `/api/auth/reviewers/{reviewer_id}/password` | self or admin | Body `PasswordIn {password}`. `{"status": "ok"}`. `403 cannot change another user's password`, `404 reviewer not found` |
| DELETE | `/api/auth/reviewers/{reviewer_id}` | admin | Deactivates the account (`is_active=false`). Admins cannot deactivate themselves (`400`). `404` when unknown |

## Tickets and streams

Prefix `/api`. Source: `aisrf/tickets/router.py`. Ticket lifecycle states: `PENDING`, `APPROVED`, `DENIED`, `EXPIRED`, `FORWARDING`, `COMPLETED`, `FAILED` (see [[Tickets-and-Review-Workflow]]).

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/tickets` | viewer | Paginated list, newest first. Returns `{"items": [brief ticket], "total", "limit", "offset"}` |
| GET | `/api/tickets/stats` | viewer | `{"total", "pending", "by_status": {...}, "by_risk_level": {...}, "last_24h", "avg_upstream_latency_ms", "avg_human_decision_seconds", "by_agent": [{"agent_id", "count"}]}` |
| GET | `/api/tickets/{ticket_id}` | viewer | Full ticket. `ticket_id` is the id (`tkt_...`) or the short number. Adds `findings`, `normalized`, `request_headers` (redacted), `request_json` or `request_body`, `response_preview`, `response_body`, `response_headers`, `response_findings`, `policy_decision`, `events`, `agent`. `404 ticket not found` |
| GET | `/api/tickets/{ticket_id}/events` | viewer | Timeline only: `[{ts, event_type, actor, detail}]` |
| POST | `/api/tickets/{ticket_id}/approve` | reviewer | Body `DecisionIn {note=""}`. Returns the brief ticket. `404`, `409` when the ticket is not `PENDING` (invalid transition) |
| POST | `/api/tickets/{ticket_id}/deny` | reviewer | Same shape as approve |
| POST | `/api/tickets/bulk/approve` | reviewer | Body `BulkDecisionIn {ticket_ids: [...], note=""}`. Returns `{ticket_id: "<resulting status or error text>"}` |
| POST | `/api/tickets/bulk/deny` | reviewer | Same as bulk approve |

Query parameters of `GET /api/tickets`:

| Parameter | Type | Default | Meaning |
| --- | --- | --- | --- |
| `status` | string, repeatable | all | lifecycle state, `?status=PENDING&status=DENIED` |
| `agent_id` | string | | agent id |
| `min_risk` | int | | keep `risk_score >= min_risk` (0 to 100) |
| `model` | string | | model name |
| `source` | string | | `gateway`, `sdk`, `mitm`, `redteam` |
| `campaign_id` | string | | tickets created by a red-team campaign |
| `search` | string | | substring of prompt preview, ticket id, path or correlation id |
| `since`, `until` | ISO 8601 datetime | | creation window |
| `limit` | int | 50 | maximum 500 |
| `offset` | int | 0 | |
| `order` | string | `desc` | `desc` or `asc` by creation time |

Brief ticket fields: `id`, `number`, `agent_id`, `agent_name`, `status`, `source`, `correlation_id`, `campaign_id`, `probe_id`, `method`, `path`, `model`, `is_stream`, `prompt_preview`, `risk_score`, `risk_level` (`NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `finding_count`, `policy_action`, `decided_by`, `decided_at`, `decision_note`, `expires_at`, `created_at`, `updated_at`, `forwarded_at`, `response_status`, `latency_ms`, `analysis_ms`, `error`.

```bash
curl -b jar "http://localhost:8080/api/tickets?status=PENDING&min_risk=50&limit=20"
curl -b jar -X POST http://localhost:8080/api/tickets/tkt_5f3a.../deny \
  -H 'Content-Type: application/json' -d '{"note":"indirect prompt injection in retrieved document"}'
curl -b jar -X POST http://localhost:8080/api/tickets/bulk/approve \
  -H 'Content-Type: application/json' -d '{"ticket_ids":["tkt_1","tkt_2"],"note":"benign batch"}'
```

### Server-sent event streams

All streams need the viewer role, send `Content-Type: text/event-stream`, emit `event: ping` with `data: {}` after 15 seconds without traffic, and replay the last `replay` buffered events on connect. Each `data` payload is the JSON object that was published, including its `event` name.

| Path | Query | Events | Payload |
| --- | --- | --- | --- |
| `GET /api/stream/tickets` | `replay=20` | `created`, `analyzed`, `policy`, `decided`, `approved`, `denied`, `forwarding`, `completed`, `failed`, `expired`, `updated` | `{"event", "ts", "ticket": {brief ticket}}` |
| `GET /api/stream/logs` | `agent_id` (filter), `replay=50` | one event per agent log record | `{"event", "ts", "level", "agent_id", "ticket_id", "detail", ...}` |
| `GET /api/stream/campaigns` | `replay=20` | `campaign.status`, `progress`, `result`, `completed` | `{"event", "campaign_id", "status", "completed_probes", "total_probes", ...}` |
| `GET /api/codereview/stream` | `replay=20`, `run_id` (filter) | `run.status`, `run.progress`, `run.deleted`, `finding.status` | `{"event", "run_id", "status", "stage", "done", "total", ...}` |

```bash
curl -N -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" "http://localhost:8080/api/stream/tickets?replay=5"
```

## Audit

Source: `aisrf/tickets/router.py`, backed by `aisrf/audit/service.py`. See [[Logging-Metrics-and-Audit]].

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/audit` | viewer | `{"items": [{id, ts, actor, action, target_type, target_id, detail, hash, prev_hash}], "total"}` newest first. Query `limit` (default 200, max 2000), `offset` (0), `action` (exact, for example `ticket.deny`), `actor` |
| GET | `/api/audit/verify` | viewer | Recomputes the SHA-256 chain. `{"ok": true, "checked": n, "head": "<hash>"}` or `{"ok": false, "checked": n, "broken_at": <entry id>}` |

## Agents

Prefix `/api/agents`. Source: `aisrf/agents/router.py`. See [[Agents-and-Credentials]].

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/agents` | viewer | `[agent]`. Query `include_inactive` (bool, default `true`) |
| POST | `/api/agents` | admin | Body `AgentIn`. `201` agent plus `api_key` (raw key, shown once). `409 an agent with this name already exists` |
| GET | `/api/agents/{agent_id}` | viewer | Agent by id or name, plus `stats` (`total`, `avg_risk`, `by_status`). `404 agent not found` |
| PATCH | `/api/agents/{agent_id}` | admin | Body `AgentPatch` (every field optional, plus `is_active`). Returns the agent. `404` |
| POST | `/api/agents/{agent_id}/rotate-key` | admin | `{"id", "api_key"}`; the old key stops working immediately |
| DELETE | `/api/agents/{agent_id}` | admin | Disables the agent (`is_active=false`); re-enable with `PATCH {"is_active": true}` |
| GET | `/api/agents/{agent_id}/events` | viewer | `[{ts, level, event, ticket_id, detail}]`. Query `limit` (200), `offset` (0), `level` (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| GET | `/api/agents/{agent_id}/stats` | viewer | `{"total", "avg_risk", "by_status": {...}}` |

`AgentIn` body:

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `name` | string, max 120 | required | unique name |
| `description`, `owner` | string | `""` | free text |
| `tags` | list of string | `[]` | |
| `upstream_provider` | string | `openai` | `openai`, `anthropic`, `azure`, `google`, `gemini`, `ollama`, `groq`, `together`, `mistral`, `deepseek`, `openrouter`, `azure_openai_compat` or `custom` |
| `upstream_base_url` | string or null | provider default | base URL the gateway forwards to |
| `upstream_api_key` | string or null | null | stored encrypted; when absent the client must send its own provider key |
| `upstream_auth_header` | string | `""` | header name for `custom` providers |
| `upstream_extra_headers` | object | `{}` | added to every upstream request |
| `require_approval` | bool | `true` | hold every request for a human |
| `auto_approve_below_risk` | int 0 to 100 | 0 | auto approve below this score (0 disables) |
| `auto_deny_at_risk` | int 0 to 101 | 90 | auto deny at or above this score (101 disables) |
| `auto_deny_patterns` | list of regex | `[]` | matching prompts are denied by policy |
| `allowed_paths` | list of glob | `[]` | upstream paths allowed (empty = all) |
| `allowed_models` | list of string | `[]` | model allow-list (empty = all) |
| `rate_limit_per_minute` | int >= 0 | 0 | 0 = unlimited |
| `inject_canary` | bool | `false` | inject a canary word into system prompts ([[Canary-Words]]) |

Agent response fields: `id`, `name`, `description`, `owner`, `tags`, `api_key_prefix`, `upstream_provider`, `upstream_base_url`, `has_upstream_key`, `upstream_auth_header`, `upstream_extra_headers`, `require_approval`, `auto_approve_below_risk`, `auto_deny_at_risk`, `auto_deny_patterns`, `allowed_paths`, `allowed_models`, `rate_limit_per_minute`, `inject_canary`, `is_active`, `request_count`, `last_seen_at`, `created_at`.

```bash
curl -b jar -X POST http://localhost:8080/api/agents -H 'Content-Type: application/json' \
  -d '{"name":"support-bot","upstream_provider":"openai","upstream_api_key":"sk-...","auto_approve_below_risk":20,"allowed_models":["gpt-4o*"]}'
```

## Settings

Prefix `/api/settings`. Source: `aisrf/settings_router.py` and `aisrf/settings_store.py`. See [[Settings-Center]] and [[Configuration-Reference]].

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/settings/schema` | viewer | `{"fields": [{key, group, type, description, value, default, secret, locked, env}], "groups": [...], "namespaces": [...]}`. Groups: `Service`, `Gateway`, `Security`, `Notifications`, `Analysis`, `Red team`, `Advanced`. Namespaces: `analyzers`, `rules`, `integrations`, `ui`, `policy` |
| GET | `/api/settings/analyzers` | viewer | `{"analyzers": [{name, kind, description, ...}], "config": <analyzers namespace>}` |
| GET | `/api/settings/guardrails` | viewer | `{"integrations": <status of each guardrail integration>}` |
| POST | `/api/settings/guardrails/health` | admin | `{"results": {...}}`, actively probes every enabled integration |
| GET | `/api/settings/taxonomy` | viewer | OWASP LLM Top 10, Greshake and Thacker catalogues and the category map ([[Taxonomy-and-OWASP-Mapping]]) |
| PUT | `/api/settings/core` | admin | Body `CoreUpdate {changes: {key: value}}`. `{"applied": {key: value}}`. `400` unknown key or invalid value, `403` locked key (environment only: `database_url`, `host`, `port`, ...) |
| POST | `/api/settings/core/reset` | admin | Body `ResetIn {keys: [...] or null}` (null = every override). `{"reset": [keys]}` |
| GET | `/api/settings/ns/{namespace}` | viewer | `{"namespace", "defaults", "value"}`; `integrations` api keys are masked as `********` |
| PUT | `/api/settings/ns/{namespace}` | admin | Body is the document (merged). `{"namespace", "value"}`. `400 use PUT /api/settings/core for core settings` for `core`. A masked `********` api key keeps the stored value |
| POST | `/api/settings/ns/{namespace}/reset` | admin | Restores `NAMESPACE_DEFAULTS` |
| GET | `/api/settings/export` | admin | `{"core": {...}, "namespaces": {...}}`. Query `include_secrets` (bool, default `false`) |
| POST | `/api/settings/import` | admin | Body is an export document. `{"applied": {"core": {...}, "namespaces": {...}}}` |

## Red team

Prefix `/api/redteam`. Source: `aisrf/redteam/router.py`. Campaign states: `CREATED`, `RUNNING`, `PAUSED`, `COMPLETED`, `FAILED`, `CANCELLED`. Verdicts: `VULNERABLE`, `RESISTED`, `BLOCKED`, `INCONCLUSIVE`, `ERROR`, `PENDING`. See [[Red-Teaming]], [[Probe-Corpus]], [[Comparison-Groups]].

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/redteam/corpus` | viewer | `{"categories": [{name, description, techniques, probe_count, ...}], "total", "mutators": [...]}` |
| GET | `/api/redteam/corpus/probes` | viewer | `{"items": [probe], "total"}`. Query `category`, `technique`, `severity`, `search`, `limit` (100, max 1000), `offset` |
| GET | `/api/redteam/campaigns` | viewer | `[campaign]`. Query `status`, `agent_id`, `group_id` |
| POST | `/api/redteam/campaigns` | reviewer | Body `CampaignIn`. `201` campaign. `404 agent ... not found` |
| GET | `/api/redteam/campaigns/{campaign_id}` | viewer | campaign with `summary`. `404 campaign not found` |
| POST | `/api/redteam/campaigns/{campaign_id}/start` | reviewer | `409 campaign is RUNNING` (or COMPLETED) |
| POST | `/api/redteam/campaigns/{campaign_id}/pause` | reviewer | in-flight probes finish, no new ones start |
| POST | `/api/redteam/campaigns/{campaign_id}/resume` | reviewer | |
| POST | `/api/redteam/campaigns/{campaign_id}/cancel` | reviewer | results gathered so far are kept |
| DELETE | `/api/redteam/campaigns/{campaign_id}` | reviewer | deletes the campaign and its results. `{"status": "deleted", "id"}` |
| GET | `/api/redteam/campaigns/{campaign_id}/results` | viewer | `{"items": [result], "total"}`. Query `verdict`, `category`, `technique`, `limit` (100), `offset` |
| GET | `/api/redteam/campaigns/{campaign_id}/summary` | viewer | verdict counts, rate per category and technique, weighted score, OWASP breakdown, worst findings |
| GET | `/api/redteam/groups` | viewer | `[{group_id, name, campaign_count, statuses, created_at, ...}]` |
| POST | `/api/redteam/groups` | reviewer | Body `GroupIn`. `201 {"group_id", "campaigns": [...]}` |
| GET | `/api/redteam/groups/{group_id}` | viewer | comparison: `targets`, per-target progress and scores, category heatmap, OWASP coverage, per-probe matrix. `404 group not found` |
| POST | `/api/redteam/groups/{group_id}/start` | reviewer | starts every `CREATED` or `PAUSED` campaign |
| POST | `/api/redteam/groups/{group_id}/cancel` | reviewer | |
| DELETE | `/api/redteam/groups/{group_id}` | reviewer | deletes every campaign in the group |

`CampaignIn` and `GroupIn`:

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `name` | string, 1 to 160 | required | |
| `agent_id` | string | required (campaign) | `GroupIn` uses `targets: [{agent_id, target_model="", label}]` instead (at least 1, the dashboard requires 2) |
| `target_model` | string | `""` | model sent in the request body |
| `categories`, `techniques` | list of string | `[]` | empty = all |
| `max_probes` | int or null | null | cap the probe set |
| `mutators` | list of string | `[]` | names from `/api/redteam/corpus` |
| `system_prompt` | string | `""` | |
| `path` | string | `v1/chat/completions` | upstream path |
| `concurrency` | int or null | server default (`redteam_concurrency`) | |
| `seed` | int or null | null | reproducible sampling |
| `extra_body` | object | `{}` | merged into every request body |
| `auto_start` | bool | `false` | |

Campaign response fields: `id`, `name`, `agent_id`, `agent_name`, `target_model`, `status`, `config`, `group_id`, `target_label`, `summary`, `total_probes`, `completed_probes`, `progress`, `created_by`, `created_at`, `started_at`, `finished_at`, `error`. Result fields: `id`, `campaign_id`, `probe_id`, `category`, `technique`, `severity`, `verdict`, `confidence`, `latency_ms`, `ticket_id`, `prompt`, `messages`, `response`, `evidence`, `created_at`.

```bash
curl -b jar -X POST http://localhost:8080/api/redteam/campaigns -H 'Content-Type: application/json' \
  -d '{"name":"nightly","agent_id":"agt_...","target_model":"gpt-4o-mini","categories":["prompt_injection","jailbreak"],"max_probes":50,"auto_start":true}'
curl -b jar http://localhost:8080/api/redteam/campaigns/cmp_.../summary
```

## Scanners

Prefix `/api/scanners`. Source: `aisrf/scanners/router.py`. Engines: `garak`, `promptfoo`, `pyrit`, `pyrit_ship` (see [[Scanner-Engines]]). Scan campaigns share the campaign table and the `/api/stream/campaigns` channel with red-team campaigns.

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/scanners` (also `/api/scanners/`) | viewer | `{"engines": [{name, description, installed, enabled, capabilities}]}` |
| GET | `/api/scanners/{engine}/probes` | viewer | `{"engine", "total", "items"}`. `404 unknown scan engine`, `409 <engine> is not installed` |
| POST | `/api/scanners/{engine}/campaigns` | reviewer | Body `{name (1 to 160), agent_id, target_model="", options={}, auto_start=false}`. `201` campaign. `404 agent not found`, `409` not installed |
| POST | `/api/scanners/{engine}/matrix` | reviewer | Body `{name, targets: [{agent_id, target_model=""}] (min 1), options={}, auto_start=false}`. `201 {"group_id", "engine", "campaigns": [...]}` |
| GET | `/api/scanners/groups/{group_id}` | viewer | engine comparison for a matrix. `404 campaign group not found` |
| POST | `/api/scanners/campaigns/{campaign_id}/start` | reviewer | `404 scan campaign not found`, `409 campaign is RUNNING` |
| POST | `/api/scanners/campaigns/{campaign_id}/cancel` | reviewer | |

### PyRIT-Ship compatible surface

Prefix `/api/pyrit-ship`. These endpoints mirror the PyRIT-Ship HTTP contract so an external PyRIT deployment can use AISRF as converter, generator and scorer. They do not require a reviewer login; when `Authorization: Bearer <agent key>` is present the converted or generated prompt is also submitted through the gateway as a ticket (`X-AISRF-Campaign-Id` attaches it to a campaign).

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/api/pyrit-ship/prompt/convert` | none | `["Base64Converter", ...]`. `503 pyrit is not installed` |
| POST | `/api/pyrit-ship/prompt/convert/{converter_name}` | optional agent key | Body `{text}`. `{"converted_text", "ticket_id"?}`. `404` unknown converter, `503` pyrit missing |
| POST | `/api/pyrit-ship/prompt/generate` | optional agent key | Body `{prompt_goal}`. `{"prompt"}` |
| POST | `/api/pyrit-ship/prompt/score/SelfAskTrueFalseScorer` | none | Body `{scoring_true, scoring_false="", prompt_response}`. `[{score_value, score_rationale, ...}]` |
| GET | `/api/pyrit-ship/external/health` | viewer | health of the external PyRIT-Ship target configured in the `integrations` namespace |

## Code review

Prefix `/api/codereview`. Source: `aisrf/codereview/router.py`. Run states: `CREATED`, `FETCHING`, `ANALYZING`, `COMPLETED`, `FAILED`, `CANCELLED`; stages: `created`, `intake`, `inventory`, `rules`, `semgrep`, `bandit`, `llm`, `persist`, `completed`. Packs: `prompt_injection`, `agent_tool_abuse`, `llm_output`, `model_supply_chain`, `rag_poisoning_exfil`, `general`. Engines: `rules`, `semgrep`, `bandit`, `llm`. See [[Code-Review]] and [[Code-Review-Rules]].

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/codereview/rules` | viewer | `{"packs": [{name, title, rule_count, rules: [{id, severity, confidence, cwe, owasp, title, why, remediation, languages, engines}]}], "engines": [...]}`. Query `pack` |
| POST | `/api/codereview/runs` | reviewer | Body `RunIn {name="", source: SourceIn, options: OptionsIn}`. `201` run. Errors below |
| POST | `/api/codereview/runs/upload` | reviewer | `multipart/form-data`: `file` (zip, tar, tar.gz, tbz2, txz), `name` (""), `options` (JSON string, `{}`). `201` run. `400 archive rejected`, `413 archive exceeds the <n> byte limit` |
| GET | `/api/codereview/runs` | viewer | `{"items": [brief run], "total", "limit", "offset"}`. Query `status`, `source_type`, `limit` (50, 1 to 500), `offset` |
| GET | `/api/codereview/runs/{run_id}` | viewer | full run: `status`, `stage`, `inventory` (languages, frameworks, model artifacts, manifests, intake), `summary` (`risk_score`, `risk_level`, `by_severity`, `by_pack`, `by_engine`, `by_owasp`, `top_rules`, `engines`), `file_count`, `loc`, `work_dir_available`. `404 run not found` |
| POST | `/api/codereview/runs/{run_id}/cancel` | reviewer | `409 run is already COMPLETED` (or other terminal state) |
| DELETE | `/api/codereview/runs/{run_id}` | reviewer | deletes run, findings and working copy |
| GET | `/api/codereview/runs/{run_id}/findings` | viewer | `{"items": [finding], "total", "limit", "offset"}`. Query `severity` (comma separated), `pack`, `engine`, `file`, `status` (`open`, `false_positive`, `accepted`), `rule_id`, `search`, `limit` (100, max 2000), `offset` |
| POST | `/api/codereview/findings/{finding_id}/status` | reviewer | Body `StatusIn {status, note=""}`; status `open`, `false_positive` or `accepted`. `400` invalid status, `404 finding not found` |
| GET | `/api/codereview/runs/{run_id}/file` | viewer | Query `path` (required). `{"path", "language", "lines", "truncated", "content", "findings": [...]}`. `404 file not found in this run`, `410 the source tree of this run has been cleaned up` |
| GET | `/api/codereview/runs/{run_id}/sarif` | viewer | SARIF 2.1.0 download (`application/sarif+json`). Query `include_dismissed` (bool, default `false`) |
| GET | `/api/codereview/credentials` | admin | `[{id, label, provider, username, created_at, created_by}]` (tokens never returned) |
| POST | `/api/codereview/credentials` | admin | Body `CredentialIn {label (1 to 80), provider="github", token (min 4), username=""}`. `201` |
| DELETE | `/api/codereview/credentials/{credential_id}` | admin | `{"status": "deleted"}`. `404 credential not found` |
| GET | `/api/codereview/stream` | viewer | SSE, see the streams table |

`SourceIn`: `type` (`git`, `url`, `zip`, `path`, `snippet`), `url`, `ref`, `token`, `credential_id`, `username`, `provider`, `ssh_key_path`, `path`, `code`, `language`. `OptionsIn`: `packs`, `engines`, `include`, `exclude` (lists), `max_files` (int or null).

Validation errors of `POST /api/codereview/runs`: `400 source.type must be one of git, url, zip, path, snippet`, `400 archives are uploaded with POST /api/codereview/runs/upload`, `400 source.url is required`, `400 archive URL must use http or https`, `400 git URL must be http(s), ssh, git or file`, `400 source.code is required for a snippet`, `400 unknown packs ...`, `400 unknown engines ...`, `403 local path intake is restricted to administrators`, `403 stored credentials can only be used by administrators`, `403 ssh deploy keys can only be used by administrators`, `404 credential not found`.

Finding fields: `id`, `run_id`, `rule_id`, `title`, `description`, `why`, `remediation`, `severity`, `confidence`, `pack`, `engine`, `file`, `line_start`, `line_end`, `snippet`, `cwe`, `owasp`, `fingerprint`, `status`, `reviewer_note`, `reviewed_by`, `category`.

```bash
curl -b jar -X POST http://localhost:8080/api/codereview/runs -H 'Content-Type: application/json' \
  -d '{"name":"rag-app","source":{"type":"git","url":"https://github.com/org/rag-app.git","ref":"main"},"options":{"engines":["rules","semgrep"]}}'
curl -b jar -o run.sarif "http://localhost:8080/api/codereview/runs/crr_.../sarif"
```

## Reports

Prefix `/api/reports`. Source: `aisrf/reports/router.py`. All report endpoints need the viewer role. The format comes from `?format=` or the `Accept` header (see [[Reports]] for negotiation rules, the 12 formats and their media types).

| Method | Path | Filters | Description |
| --- | --- | --- | --- |
| GET | `/api/reports` | | `{"kinds": [{kind, description, params}], "formats": {name: {media_type, extension, description}}}` |
| GET | `/api/reports/summary` | `since`, `until` | platform overview |
| GET | `/api/reports/tickets` | `status` (repeatable), `agent_id`, `min_risk`, `since`, `until`, `limit` (500, max 5000) | ticket table plus findings |
| GET | `/api/reports/ticket/{ticket_id}` | | one ticket dossier |
| GET | `/api/reports/agent/{agent_id}` | `since` | one agent |
| GET | `/api/reports/campaign/{campaign_id}` | | one campaign |
| GET | `/api/reports/audit` | `limit` (500, max 10000) | audit entries plus chain verification |
| GET | `/api/reports/codereview/{run_id}` | `include_dismissed` (bool, default `false`, SARIF only) | one code review run; `format=sarif` uses the dedicated code review SARIF with physical locations |

Common query parameters: `format` (default `json`), `inline` (bool, default `false`; `true` sends `Content-Disposition: inline`). Response headers: `Content-Disposition: attachment; filename="aisrf-<kind>-<YYYYMMDD-HHMMSS>.<ext>"`, `X-Report-Kind`, `X-Report-Format`. Errors: `400 unknown report format`, `404` when the ticket, agent, campaign or run does not exist.

```bash
curl -b jar -o weekly.pdf "http://localhost:8080/api/reports/summary?format=pdf&since=2026-09-20T00:00:00Z"
curl -b jar -H 'Accept: text/csv' "http://localhost:8080/api/reports/tickets?status=DENIED&limit=1000" > denied.csv
```

## Gateway

Source: `aisrf/gateway/router.py`. Agent key authentication only. Full header and body semantics are on [[Gateway-Endpoints-and-Headers]]; the summary here covers status codes.

| Method | Path | Description |
| --- | --- | --- |
| GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD | `/v1/{path}` | OpenAI compatible shortcut; the ticket path is stored as `v1/...` |
| same | `/proxy/{path}` | forwards the path verbatim to the agent's upstream |
| GET | `/gateway/tickets/{ticket_id}` | poll an asynchronous ticket; only the creating agent may read it |

Request headers: `X-AISRF-Key` (required), `X-AISRF-Async` (`1`, `true`, `yes` for 202 mode), `X-AISRF-Source` (`gateway` default, `sdk`, `mitm`, `redteam`), `X-AISRF-Correlation-Id` (fallback `X-Request-ID`, else generated `corr_...`), `X-AISRF-Campaign-Id`, `X-AISRF-Probe-Id`. Every gateway response for a ticketed request carries `X-AISRF-Ticket: tkt_...`.

| Status | `error.code` | When |
| --- | --- | --- |
| upstream status | | approved and forwarded; upstream body relayed verbatim (JSON or SSE) |
| 202 | | async mode while `PENDING`: `{"ticket_id", "status": "PENDING", "poll_url": "/gateway/tickets/<id>", "expires_at"}` |
| 401 | `unauthorized` | missing, unknown or disabled agent key |
| 403 | `denied` | policy denial (`risk_score` included) or reviewer denial (`decided_by` included) |
| 403 | `response_withheld` | the upstream answered but the response was blocked (canary leak or quarantine) |
| 413 | `payload_too_large` | body above `max_request_body_bytes` |
| 429 | `rate_limited` | agent rate limit |
| 502 | `upstream_error` | network or upstream failure after approval |
| 504 | `expired` | no decision within `approval_timeout_seconds` |

`GET /gateway/tickets/{ticket_id}` maps the ticket state to a status: `PENDING` and `FORWARDING` return 202 with `{"ticket_id", "status", "decided_by", "decision_note"}`; `APPROVED` forwards the stored request now and relays the upstream response; `COMPLETED` returns 200 with `response` (parsed JSON) or `response_text` plus `response_status`; `DENIED` and `EXPIRED` return 403; `FAILED` returns 502; an unknown id or another agent's ticket returns `404 {"error": {"message": "ticket not found", "code": "not_found"}}`.

```bash
curl -i -X POST http://localhost:8080/v1/chat/completions \
  -H "X-AISRF-Key: aisrf_..." -H "X-AISRF-Async: 1" -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
curl -H "X-AISRF-Key: aisrf_..." http://localhost:8080/gateway/tickets/tkt_...
```

## MCP endpoint

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| POST, GET, DELETE | `/mcp` | `Authorization: Bearer <AISRF_ADMIN_API_TOKEN>` | MCP streamable HTTP transport (stateless, JSON responses). `503 {"error": "MCP endpoint disabled: set AISRF_ADMIN_API_TOKEN to enable it"}` until the token is configured, `401 {"error": "invalid or missing bearer token"}` with `WWW-Authenticate: Bearer realm="aisrf-mcp"` |

Details on [[MCP-Server]].

## Ops

Source: `aisrf/main.py`. No authentication.

| Method | Path | Description |
| --- | --- | --- |
| GET | `/healthz` | `{"status": "ok", "version": "<aisrf version>"}` |
| GET | `/readyz` | runs a database query; `{"status": "ready"}` or 500 |
| GET | `/metrics` | Prometheus text format (`text/plain`); see [[Logging-Metrics-and-Audit]] |

## Dashboard pages

The HTML pages (`/login`, `/`, `/tickets`, `/tickets/{id}`, `/agents`, `/agents/{id}`, `/logs`, `/redteam`, `/redteam/{campaign_id}`, `/redteam/groups/{group_id}`, `/codereview`, `/codereview/{run_id}`, `/reports`, `/audit`, `/settings`) are served by `aisrf/dashboard/router.py`, are excluded from the OpenAPI schema and redirect to `/login?next=<path>` (303) when no principal is present. They are documented on [[Dashboard-Guide]].
