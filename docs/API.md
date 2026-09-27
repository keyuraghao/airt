# REST API reference

Interactive documentation is served at `/api/docs` (Swagger UI), `/api/redoc` and
`/api/openapi.json`. This page lists every endpoint with example requests and responses.

Base URL in the examples: `http://localhost:8080`.

## Authentication

| Caller | Mechanism |
| --- | --- |
| Agents (gateway endpoints) | `X-AIRT-Key: airt_...` (also accepted: `Authorization: Bearer airt_...`, `x-api-key`, `api-key`, `x-goog-api-key`). |
| Reviewers (dashboard) | Session cookie `airt_session` from `POST /api/auth/login`. |
| Automation (MCP, CLI, CI) | `Authorization: Bearer <AIRT_ADMIN_API_TOKEN>` or `X-AIRT-Admin-Token: <token>` (admin role). |

Roles: `viewer` (read), `reviewer` (read + approve/deny), `admin` (everything). Errors use FastAPI's
`{"detail": "..."}` shape for reviewer endpoints and `{"error": {"message", "type": "airt_gateway",
"code", "ticket_id"}}` for gateway endpoints.

## Ops

| Method | Path | Auth | Description |
| --- | --- | --- | --- |
| GET | `/healthz` | none | `{"status": "ok", "version": "1.0.0"}` |
| GET | `/readyz` | none | Runs a DB query; `{"status": "ready"}` |
| GET | `/metrics` | none | Prometheus text format |

## Gateway (agent authenticated)

### `ANY /v1/{path}` and `ANY /proxy/{path}`

Intercept a request. `/v1/...` is the OpenAI compatible shortcut (path stored as `v1/...`);
`/proxy/...` forwards the path verbatim. Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD.

Request headers:

| Header | Meaning |
| --- | --- |
| `X-AIRT-Key` | agent key (required, see Authentication) |
| `X-AIRT-Async` | `1` / `true` / `yes`: return 202 instead of blocking |
| `X-AIRT-Source` | `gateway` (default), `sdk`, `mitm`, `redteam` |
| `X-AIRT-Correlation-Id` | groups tickets (falls back to `X-Request-ID`, else generated `corr_...`) |
| `X-AIRT-Campaign-Id`, `X-AIRT-Probe-Id` | set by the red-team engine |

```bash
curl -i -X POST http://localhost:8080/v1/chat/completions \
  -H "X-AIRT-Key: airt_abc..." -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

Responses:

| Status | When | Body |
| --- | --- | --- |
| upstream status | approved and forwarded | upstream body verbatim (JSON or SSE), header `X-AIRT-Ticket: tkt_...` |
| 202 | async mode, PENDING | `{"ticket_id": "tkt_...", "status": "PENDING", "poll_url": "/gateway/tickets/tkt_...", "expires_at": "..."}` + `X-AIRT-Ticket` |
| 401 | bad or missing key | `{"error": {"message": "invalid or missing AIRT agent key", "type": "airt_gateway", "code": "unauthorized"}}` |
| 403 | policy or reviewer denied | `{"error": {"message": "request denied by reviewer: ...", "type": "airt_gateway", "code": "denied", "ticket_id": "tkt_...", "decided_by": "alice"}}` (policy denials add `risk_score`) |
| 413 | body too large | `code: payload_too_large` |
| 429 | agent rate limit | `code: rate_limited` |
| 502 | upstream error after approval | `code: upstream_error` |
| 504 | no decision before timeout | `code: expired` |

### `GET /gateway/tickets/{ticket_id}`

Poll an asynchronous ticket. Only the agent that created it can read it (404 otherwise).

| Ticket status | HTTP | Body |
| --- | --- | --- |
| PENDING | 202 | `{"ticket_id", "status": "PENDING", "decided_by": null, "decision_note": ""}` |
| APPROVED | upstream status | the poll forwards the request now and relays the upstream body with `X-AIRT-Ticket` |
| FORWARDING | 502 | `{"ticket_id", "status": "FORWARDING", ...}` (another poll is in flight; retry) |
| COMPLETED | 200 | `{"ticket_id", "status": "COMPLETED", "decided_by", "decision_note", "response": {...}, "response_status": 200}` (`response_text` when the body is not JSON) |
| DENIED, EXPIRED | 403 | `{"ticket_id", "status": "DENIED", "decided_by", "decision_note"}` |
| FAILED | 502 | `{"ticket_id", "status": "FAILED", ...}` |

## Auth and reviewers (`/api/auth`)

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| POST | `/api/auth/login` | none | `{"username", "password"}` -> sets cookie, returns `{"id", "username", "role"}`; 401 on failure (audited) |
| POST | `/api/auth/logout` | any | clears the cookie |
| GET | `/api/auth/me` | any | current principal `{"id", "username", "role", "via": "session" or "token"}` |
| GET | `/api/auth/reviewers` | admin | list reviewers |
| POST | `/api/auth/reviewers` | admin | `{"username", "password", "role"}` -> 201 |
| POST | `/api/auth/reviewers/{id}/password` | self or admin | `{"password"}` |
| DELETE | `/api/auth/reviewers/{id}` | admin | deactivate (cannot deactivate yourself) |

```bash
curl -c jar -X POST http://localhost:8080/api/auth/login -H 'Content-Type: application/json' -d '{"username":"admin","password":"admin"}'
curl -b jar http://localhost:8080/api/auth/me
```

## Tickets (`/api/tickets`)

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/tickets` | viewer | list; filters `status` (repeatable), `agent_id`, `min_risk`, `model`, `source`, `campaign_id`, `search`, `since`, `until`, `limit` (<= 500), `offset`, `order` (`desc` / `asc`) |
| GET | `/api/tickets/stats` | viewer | totals, by status, by risk level, last 24 h, average latency and human decision time, by agent |
| GET | `/api/tickets/{id}` | viewer | full ticket incl. `findings`, `normalized`, `response_body`, `events`, `agent` |
| GET | `/api/tickets/{id}/events` | viewer | timeline only |
| POST | `/api/tickets/{id}/approve` | reviewer | `{"note": ""}`; 409 if not PENDING |
| POST | `/api/tickets/{id}/deny` | reviewer | `{"note": ""}`; 409 if not PENDING |
| POST | `/api/tickets/bulk/approve` | reviewer | `{"ticket_ids": [...], "note": ""}` -> `{ticket_id: resulting status or error}` |
| POST | `/api/tickets/bulk/deny` | reviewer | same |

```bash
curl -b jar "http://localhost:8080/api/tickets?status=PENDING&min_risk=50&limit=20"
```

```json
{"items": [{"id": "tkt_5f...", "number": 42, "agent_id": "agt_...", "agent_name": "demo", "status": "PENDING", "source": "sdk",
  "correlation_id": "corr_...", "method": "POST", "path": "v1/chat/completions", "model": "gpt-4o-mini", "is_stream": false,
  "prompt_preview": "Ignore all previous instructions and ...", "risk_score": 72, "risk_level": "HIGH", "finding_count": 3,
  "policy_action": "review", "decided_by": null, "decision_note": "", "expires_at": "2026-09-26T10:05:00+00:00", ...}],
 "total": 1, "limit": 20, "offset": 0}
```

```bash
curl -b jar -X POST http://localhost:8080/api/tickets/tkt_5f.../approve -H 'Content-Type: application/json' -d '{"note":"reviewed, benign"}'
```

## Live streams (SSE, viewer role)

| Path | Events |
| --- | --- |
| `GET /api/stream/tickets?replay=20` | `ticket.created`, `ticket.decided`, `ticket.completed`, ... with `ticket` payload |
| `GET /api/stream/logs?agent_id=agt_...&replay=50` | per-agent log events |
| `GET /api/stream/campaigns?replay=20` | campaign progress |

A `ping` event is sent every 15 s of inactivity. `replay` returns the last N buffered events first.

## Agents (`/api/agents`)

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/agents?include_inactive=true` | viewer | list |
| POST | `/api/agents` | admin | create -> 201 with the raw `api_key` (shown once) |
| GET | `/api/agents/{id_or_name}` | viewer | agent + `stats` |
| PATCH | `/api/agents/{id}` | admin | partial update (same fields as create plus `is_active`) |
| POST | `/api/agents/{id}/rotate-key` | admin | `{"id", "api_key"}` |
| DELETE | `/api/agents/{id}` | admin | disable (`is_active=false`) |
| GET | `/api/agents/{id}/events?limit=200&level=WARNING` | viewer | activity log |
| GET | `/api/agents/{id}/stats` | viewer | request counts and outcomes |

Create body (all optional except `name`):

```json
{"name": "support-bot", "description": "", "owner": "team-x", "tags": ["prod"],
 "upstream_provider": "openai", "upstream_base_url": "https://api.openai.com/v1", "upstream_api_key": "sk-...",
 "upstream_auth_header": "", "upstream_extra_headers": {},
 "require_approval": true, "auto_approve_below_risk": 0, "auto_deny_at_risk": 90,
 "auto_deny_patterns": ["(?i)drop table"], "allowed_paths": ["v1/chat/*"], "allowed_models": ["gpt-4o*"],
 "rate_limit_per_minute": 60}
```

`upstream_provider` values understood by the forwarder: `openai`, `ollama`, `azure_openai_compat`,
`groq`, `together`, `mistral`, `deepseek`, `openrouter` (Bearer), `anthropic` (`x-api-key` +
`anthropic-version`), `azure` (`api-key`), `google` / `gemini` (`x-goog-api-key`), anything else
uses `upstream_auth_header` or Bearer.

## Audit (`/api/audit`)

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/audit?limit=200&offset=0&action=ticket.approve&actor=alice` | viewer | entries with `hash` and `prev_hash` |
| GET | `/api/audit/verify` | viewer | `{"ok": true, "checked": 1234, "head": "<sha256>"}` or `{"ok": false, "checked": n, "broken_at": id}` |

## Red team (`/api/redteam`)

| Method | Path | Role | Description |
| --- | --- | --- | --- |
| GET | `/api/redteam/corpus` | viewer | categories, techniques, counts |
| GET | `/api/redteam/corpus/probes?category=&technique=&severity=&search=` | viewer | probe list |
| GET | `/api/redteam/campaigns` | viewer | list campaigns |
| POST | `/api/redteam/campaigns` | reviewer | create `{"name", "agent_id", "target_model", "categories": [...], "techniques": [...], "mutators": [...], "max_probes": n, "system_prompt": "...", "path": "v1/chat/completions", "concurrency": 4, "seed": 1, "auto_start": false}` (all but the first three optional) |
| GET | `/api/redteam/campaigns/{id}` | viewer | campaign with summary |
| DELETE | `/api/redteam/campaigns/{id}` | admin | delete campaign and results |
| POST | `/api/redteam/campaigns/{id}/start` | reviewer | run (probes become tickets) |
| POST | `/api/redteam/campaigns/{id}/pause` | reviewer | pause after in-flight probes |
| POST | `/api/redteam/campaigns/{id}/resume` | reviewer | resume |
| POST | `/api/redteam/campaigns/{id}/cancel` | reviewer | cancel |
| GET | `/api/redteam/campaigns/{id}/results?verdict=&category=` | viewer | probe results |
| GET | `/api/redteam/campaigns/{id}/summary` | viewer | aggregated verdicts per category / technique |

## Reports (`/api/reports`)

`GET /api/reports/{summary|tickets|ticket/{id}|agent/{id}|campaign/{id}|audit}?format=<fmt>` with
`format` in `json yaml csv tsv md html pdf xlsx txt xml sarif junit` (default `json`). List style
reports accept the same filters as their list endpoints (`status`, `since`, `until`, `agent_id`, ...).

```bash
curl -b jar -o campaign.pdf "http://localhost:8080/api/reports/campaign/cmp_123?format=pdf"
curl -b jar "http://localhost:8080/api/reports/tickets?format=sarif&min_risk=50" > findings.sarif
```

## MCP

`POST /mcp` (streamable HTTP, `Authorization: Bearer <AIRT_ADMIN_API_TOKEN>`). See `docs/MCP.md`.

## Dashboard pages (session cookie)

`/login`, `/`, `/tickets`, `/tickets/{id}`, `/agents`, `/agents/{id}`, `/logs`, `/redteam`,
`/redteam/{id}`, `/reports`, `/audit`, `/settings`.
