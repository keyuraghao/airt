# Agents and credentials

Everything stored on an agent record (`aisrf/models.py::Agent`), how it is managed (`aisrf/agents/service.py`, `aisrf/agents/router.py`, `aisrf agent ...`) and how each field is used by the gateway.

## Every agent field

| Field | Type | Default | Meaning and where it is used |
| --- | --- | --- | --- |
| `id` | string | generated `agt_<uuid hex>` | Primary key; used in ticket `agent_id`, log file names, URLs |
| `name` | string (1..120) | required | Unique; `GET /api/agents/{id_or_name}` also resolves names |
| `description` | text | `""` | Free text |
| `owner` | string | `""` | Owning team or person |
| `tags` | list of strings | `[]` | Free-form labels |
| `api_key_hash` | string | set at creation | SHA-256 hex digest of the raw `aisrf_` key; unique; never returned |
| `api_key_prefix` | string | set at creation | First 12 characters of the raw key (`aisrf_` plus 6), shown in the UI to identify which key is in use |
| `upstream_provider` | string | `openai` | Selects the auth header injected by the forwarder (see below) and the default base URL |
| `upstream_base_url` | string | per provider (`https://api.openai.com/v1`) | Base of every forwarded URL; trailing slashes are stripped; see the joining rule in [[Gateway-Endpoints-and-Headers]] |
| `upstream_api_key_encrypted` | text or null | null | Fernet ciphertext of the provider key; the API exposes only `has_upstream_key` |
| `upstream_auth_header` | string | `""` | Header name used for the key when the provider is not one of the built-in ones |
| `upstream_extra_headers` | dict | `{}` | Added to every forwarded request after the credential, overriding anything with the same name |
| `require_approval` | bool | `true` | `false` lets policy approve without a human (except CRITICAL secrets or exfiltration findings) |
| `auto_approve_below_risk` | int 0..100 | `0` | When > 0, tickets with `risk_score` below it are approved by policy; 0 disables |
| `auto_deny_at_risk` | int 0..101 | `90` | When > 0, tickets with `risk_score` at or above it are denied by policy; 0 or 101 disables |
| `auto_deny_patterns` | list of regex | `[]` | Case-insensitive, DOTALL regexes searched in `prompt_text`; any match denies |
| `allowed_paths` | list of globs | `[]` (all) | fnmatch patterns against the stored path (`v1/chat/completions`) and `/`-prefixed path; no match denies |
| `allowed_models` | list of globs | `[]` (all) | fnmatch patterns against `normalized.model`; only checked when the body carries a model |
| `rate_limit_per_minute` | int >= 0 | `0` (unlimited) | In-process sliding 60 s window; exceeding it returns `429` before a ticket is created |
| `inject_canary` | bool | `false` | Append a Rebuff-style canary to the system prompt of every forwarded request |
| `is_active` | bool | `true` | `false` makes the key fail with `401` and policy deny; set through `DELETE /api/agents/{id}` or `PATCH` with `is_active` |
| `request_count` | int | `0` | Incremented on every intercepted request (`touch_agent`) |
| `last_seen_at` | datetime or null | null | Updated on every intercepted request |
| `created_at`, `updated_at` | datetime | now | Bookkeeping |

The defaults for `auto_deny_at_risk` and `auto_approve_below_risk` in the service and API are the literal 90 and 0; the settings `AISRF_DEFAULT_AUTO_DENY_RISK_THRESHOLD` and `AISRF_DEFAULT_AUTO_APPROVE_RISK_THRESHOLD` carry the same values and are the intended source for UI defaults.

## Creating and updating

`POST /api/agents` (admin) accepts every field above except the generated and stats fields, with `upstream_api_key` as the plaintext provider key. `PATCH /api/agents/{id}` accepts the same fields plus `is_active`; fields set to `null` or omitted are left unchanged, `upstream_api_key` is re-encrypted, `upstream_base_url` is stripped of trailing slashes, and `id`, `api_key_hash`, `api_key_prefix` and `created_at` cannot be changed. Both are audited (`agent.create` with name and provider; `agent.update` with the changed keys, `upstream_api_key` replaced by `[secret]`). A duplicate name returns `409`.

```bash
curl -b jar -X PATCH http://localhost:8080/api/agents/agt_... -H 'Content-Type: application/json' \
  -d '{"allowed_models": ["gpt-4o*", "o3-mini"], "inject_canary": true, "upstream_extra_headers": {"OpenAI-Organization": "org_..."}}'
```

CLI (`aisrf agent create <name>` writes directly to the database and needs the same environment as the server):

```bash
aisrf agent create research-bot --provider anthropic --upstream-key sk-ant-... \
  --no-approval --auto-deny-at 70 --tag lab --owner research
aisrf agent list --all
```

`agent create` does not expose `inject_canary`, `upstream_auth_header` or `upstream_extra_headers`; set those with `PATCH` or the dashboard.

Dashboard: Agents > New agent, and the agent detail page (`/agents/{id}`) for editing, key rotation, disabling, live logs and stats.

## Key rotation

`POST /api/agents/{id}/rotate-key` (admin) or `aisrf agent rotate-key <id>` generates a new `aisrf_` key, replaces `api_key_hash` and `api_key_prefix`, writes audit `agent.rotate_key`, and returns `{"id", "api_key"}`. The previous key stops authenticating as soon as the transaction commits; in-flight synchronous requests already holding a ticket are unaffected. Scan tokens minted for the agent are separate and keep working until they expire or are revoked.

There is no key recovery: the raw key exists only in the creation or rotation response.

## Upstream providers

`PROVIDER_DEFAULTS` in the service supplies the base URL when none is given:

| `upstream_provider` | Default `upstream_base_url` | Credential header injected |
| --- | --- | --- |
| `openai` | `https://api.openai.com/v1` | `Authorization: Bearer` |
| `anthropic` | `https://api.anthropic.com/v1` | `x-api-key`, plus `anthropic-version` (`2023-06-01` unless the client sent one) |
| `azure` | empty (must be set) | `api-key` |
| `ollama` | `http://localhost:11434/v1` | `Authorization: Bearer` (harmless when Ollama ignores it) |
| `custom` | empty (must be set) | `upstream_auth_header: <key>`, or `Authorization: Bearer` when unset |
| `azure_openai_compat`, `groq`, `together`, `mistral`, `deepseek`, `openrouter` | none (set `upstream_base_url`) | `Authorization: Bearer` |
| `google`, `gemini` | none (set `upstream_base_url`) | `x-goog-api-key` |

Any other string is treated like `custom`. The comparison is case-insensitive. Without an upstream key no credential header is injected at all, which is the right setting for local models or backends that authenticate by network position.

Example: Azure OpenAI.

```json
{"name": "azure-bot", "upstream_provider": "azure",
 "upstream_base_url": "https://myres.openai.azure.com/openai/deployments/gpt4o",
 "upstream_api_key": "<azure key>"}
```

A client calling `/proxy/chat/completions?api-version=2024-02-01` reaches `https://myres.openai.azure.com/openai/deployments/gpt4o/chat/completions?api-version=2024-02-01` with `api-key` set.

Example: an internal API with a custom header.

```json
{"name": "crm-agent", "upstream_provider": "custom", "upstream_base_url": "https://crm.internal/api",
 "upstream_api_key": "svc-token", "upstream_auth_header": "X-Service-Token"}
```

## Extra headers

`upstream_extra_headers` is a flat string map applied after the credential header. Typical uses: `OpenAI-Organization`, `OpenAI-Project`, `HTTP-Referer` and `X-Title` for OpenRouter, `anthropic-beta`, or a static tenant header. Because they are applied last they can also override the injected credential header, which is a way to send a differently named credential without `upstream_auth_header`. They are visible to every viewer through `GET /api/agents`, so do not put secrets in them; use `upstream_api_key` for the secret.

## Rate limits

`check_rate_limit()` keeps a per-agent deque of request timestamps in process memory, drops entries older than 60 s and rejects when the deque already holds `rate_limit_per_minute` entries. Rejections log `rate_limited` at WARNING on the agent and return `429 rate_limited` without creating a ticket. The window is per worker process and resets on restart.

## Canary flag

`inject_canary=true` makes the gateway (and `pipeline.submit`) call `canary.inject()` on every request body with a recognisable shape: a new `AISRF-CANARY-<16 hex>` token is appended to the system or developer message, the Anthropic `system` field, the responses API `instructions` or the Gemini `systemInstruction`. The token is remembered in `normalized.canary` and checked against the response text; a hit produces a CRITICAL `canary_leak` finding and, by default, a withheld response. The `rebuff.canary_default` integration setting turns this on for every agent. See [[Canary-Words]].

## Allowed paths and models globs

Both use Python `fnmatch` semantics: `*` matches any run of characters including `/`, `?` one character, `[abc]` a set. Matching is case-sensitive.

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `v1/chat/*` | `v1/chat/completions` | `v1/completions` |
| `/v1/chat/completions` | `v1/chat/completions` (the `/`-prefixed form is also tried) | `v1/chat/completions/extra` |
| `v1/*` | any `v1/...` path including `v1/files` | `openai/deployments/...` |
| `gpt-4o*` | `gpt-4o`, `gpt-4o-mini` | `gpt-4-turbo` |
| `claude-3-5-*` | `claude-3-5-haiku-latest` | `claude-3-opus` |

Paths are matched against the stored path (`v1/...` for the `/v1` route, verbatim for `/proxy`). The global `policy.global_allowed_paths` list is checked before the agent's list.

## Per-agent logs and stats endpoints

| Endpoint | Role | Returns |
| --- | --- | --- |
| `GET /api/agents/{id}/events?limit=200&offset=0&level=WARNING` | viewer | Rows from `agent_events` newest first: `id`, `agent_id`, `ts`, `level`, `event`, `ticket_id`, `correlation_id`, `detail`; `limit` at most 2000 |
| `GET /api/agents/{id}/stats` | viewer | `{"by_status": {...}, "total": n, "avg_risk": x}` over the agent's tickets |
| `GET /api/agents/{id}` | viewer | The agent record plus `stats` |
| `GET /api/stream/logs?agent_id=agt_...&replay=50` | viewer | SSE of the same events as they happen |
| `logs/agents/<id>.jsonl` | filesystem | The same records as JSON lines, rotated at 20 MiB with 5 backups |

Event names written by the gateway: `request.intercepted`, `request.analyzed`, `policy.deny`, `policy.approve`, `policy.review`, `decision.approved`, `decision.denied`, `request.forwarding`, `request.completed`, `request.failed` (ERROR), `request.expired` (WARNING), `rate_limited` (WARNING). Each record carries `ts`, `agent_id`, `level`, `event`, `ticket_id`, `correlation_id` and event-specific detail (path, model, risk score, finding titles, status code, latency). See [[Logging-Metrics-and-Audit]].

Related: [[Core-Concepts]], [[Policy-Engine]], [[Security-Model]], [[Scanner-Engines]].
