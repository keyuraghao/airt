# Configuration reference

Every setting comes from `aisrf/config.py::Settings` (pydantic-settings). Each field is an environment variable named `AISRF_<FIELD>` (case-insensitive) or a line in a `.env` file in the working directory. Most fields can also be overridden live from the Settings page or `PUT /api/settings/core`; those overrides are stored in the `app_settings` table and reapplied at startup. Free-form JSON namespaces (`analyzers`, `rules`, `integrations`, `ui`, `policy`) live only in the settings store.

## Precedence

From highest to lowest:

1. Dashboard or API override (`app_settings`, namespace `core`), except for locked fields.
2. Environment variable.
3. `.env` file.
4. Code default.

`get_settings()` caches one `Settings` object per process; `load_overrides()` mutates it at startup and `update_core()` mutates it on every change, so changes apply to the next request without a restart. `reset_core()` deletes the overrides, clears the cache and reloads, so environment values apply again.

Locked fields (`settings_store.LOCKED`) can only be set through the environment: `database_url`, `host`, `port`, `workers`, `base_dir`, `data_dir`, `log_dir`, `secret_key`, `encryption_key`. Attempting to change one through the API returns `403`. `base_dir`, `data_dir` and `log_dir` are also hidden from the schema and export.

Fields whose name matches `password`, `secret`, `token`, `api_key` or ends in `_key` are secret: the schema and export return `********` (or an empty string when unset), and sending `********` back leaves the stored value unchanged.

List fields (`notify_webhook_urls`, `notify_events`) are parsed as JSON by pydantic-settings when they come from the environment, so quote them: `AISRF_NOTIFY_WEBHOOK_URLS='["https://hooks.slack.com/services/..."]'`. Through the API and UI they also accept comma- or newline-separated strings.

## Core settings by group

Groups are `settings_store.GROUPS`; fields not listed in a group appear under Advanced. Types are what `coerce()` enforces on API input (`bool` accepts `1`, `true`, `yes`, `on`).

### Service

| Field | Env var | Type | Default | Live | Description |
| --- | --- | --- | --- | --- | --- |
| `app_name` | `AISRF_APP_NAME` | str | `AISRF` | yes | Title of the FastAPI app and OpenAPI document |
| `environment` | `AISRF_ENVIRONMENT` | str | `development` | yes | `development`, `staging` or `production`; `production` forces JSON console logs (`is_production`) |
| `log_level` | `AISRF_LOG_LEVEL` | str | `INFO` | yes (takes effect for new loggers) | Upper-cased automatically; root logger level |
| `log_json_console` | `AISRF_LOG_JSON_CONSOLE` | bool | `false` | yes | JSON lines on stdout instead of the coloured console renderer |
| `public_url` | `AISRF_PUBLIC_URL` | str | `""` | yes | Externally reachable base URL used for ticket links in notifications; falls back to `http://localhost:<port>` |

### Gateway

| Field | Env var | Type | Default | Live | Description |
| --- | --- | --- | --- | --- | --- |
| `approval_timeout_seconds` | `AISRF_APPROVAL_TIMEOUT_SECONDS` | int | `300` | yes | How long a synchronous request waits for a decision; also sets `expires_at` on every ticket |
| `hold_poll_interval_seconds` | `AISRF_HOLD_POLL_INTERVAL_SECONDS` | float | `1.0` | yes | Database polling cadence while waiting, for decisions made in another process |
| `max_request_body_bytes` | `AISRF_MAX_REQUEST_BODY_BYTES` | int | `4194304` | yes | `413` above this; stored `request_body` truncated to it |
| `max_stored_response_bytes` | `AISRF_MAX_STORED_RESPONSE_BYTES` | int | `524288` | yes | Bytes of the upstream response kept on the ticket and analysed |
| `upstream_timeout_seconds` | `AISRF_UPSTREAM_TIMEOUT_SECONDS` | float | `120.0` | at next restart (the shared client is built at startup) | Upstream read timeout |
| `upstream_connect_timeout_seconds` | `AISRF_UPSTREAM_CONNECT_TIMEOUT_SECONDS` | float | `10.0` | at next restart | Upstream connect timeout |
| `default_auto_deny_risk_threshold` | `AISRF_DEFAULT_AUTO_DENY_RISK_THRESHOLD` | int | `90` | yes | Suggested `auto_deny_at_risk` for new agents |
| `default_auto_approve_risk_threshold` | `AISRF_DEFAULT_AUTO_APPROVE_RISK_THRESHOLD` | int | `0` | yes | Suggested `auto_approve_below_risk` for new agents (0 = never) |
| `ticket_retention_days` | `AISRF_TICKET_RETENTION_DAYS` | int | `90` | yes | Sweeper purges tickets older than this about once an hour; 0 keeps forever |
| `require_approval_for_redteam_probes` | `AISRF_REQUIRE_APPROVAL_FOR_REDTEAM_PROBES` | bool | `true` | yes | Red-team probes wait for a human like any other ticket |

### Security

| Field | Env var | Type | Default | Live | Description |
| --- | --- | --- | --- | --- | --- |
| `admin_username` | `AISRF_ADMIN_USERNAME` | str | `admin` | yes (bootstrap only runs at startup) | Bootstrap admin reviewer created when missing |
| `admin_password` | `AISRF_ADMIN_PASSWORD` | str (secret) | `admin` | yes (bootstrap only) | Bootstrap password; `auth.default_admin_password` is logged while it is `admin` |
| `admin_api_token` | `AISRF_ADMIN_API_TOKEN` | str or null (secret) | unset | yes | Static bearer token granting `admin` on `/api/*` and `/mcp`; compared with `hmac.compare_digest` |
| `session_max_age_seconds` | `AISRF_SESSION_MAX_AGE_SECONDS` | int | `43200` | yes | Cookie lifetime and signed-token max age |
| `cookie_secure` | `AISRF_COOKIE_SECURE` | bool | `false` | yes | `Secure` flag on `aisrf_session`; set when serving over HTTPS |

### Notifications

| Field | Env var | Type | Default | Live | Description |
| --- | --- | --- | --- | --- | --- |
| `notify_webhook_urls` | `AISRF_NOTIFY_WEBHOOK_URLS` | list | `[]` | at next restart (the notifier subscribes at startup only when the list is non-empty) | Slack incoming webhooks or generic JSON endpoints |
| `notify_events` | `AISRF_NOTIFY_EVENTS` | list | `["created", "expired", "failed"]` | yes | Ticket events that notify: `created`, `decided`, `completed`, `expired`, `failed` (`forwarding` is published but rarely useful) |
| `notify_min_risk` | `AISRF_NOTIFY_MIN_RISK` | int | `0` | yes | Only notify for tickets at or above this risk score |

### Analysis

| Field | Env var | Type | Default | Live | Description |
| --- | --- | --- | --- | --- | --- |
| `enable_llm_judge` | `AISRF_ENABLE_LLM_JUDGE` | bool | `false` | yes | Enable the LLM judge request and response analyzers |
| `judge_provider` | `AISRF_JUDGE_PROVIDER` | str | `openai` | yes | `openai` or `anthropic` |
| `judge_base_url` | `AISRF_JUDGE_BASE_URL` | str or null | unset | yes | Judge endpoint override |
| `judge_api_key` | `AISRF_JUDGE_API_KEY` | str or null (secret) | unset | yes | Judge credential |
| `judge_model` | `AISRF_JUDGE_MODEL` | str | `gpt-4o-mini` | yes | Judge model |

### Red team

| Field | Env var | Type | Default | Live | Description |
| --- | --- | --- | --- | --- | --- |
| `redteam_concurrency` | `AISRF_REDTEAM_CONCURRENCY` | int | `4` | yes | Parallel probes per campaign unless the campaign sets its own |
| `redteam_probe_timeout_seconds` | `AISRF_REDTEAM_PROBE_TIMEOUT_SECONDS` | float | `90.0` | yes | Per-probe wait for approval and answer (`wait_timeout` passed to `pipeline.submit`) |

### Advanced

| Field | Env var | Type | Default | Live | Description |
| --- | --- | --- | --- | --- | --- |
| `host` | `AISRF_HOST` | str | `0.0.0.0` | locked | Bind address for `aisrf serve` |
| `port` | `AISRF_PORT` | int | `8080` | locked | Bind port; also used for the notification link fallback |
| `workers` | `AISRF_WORKERS` | int | `1` | locked | uvicorn workers; see the multi-worker caveats in [[Architecture]] |
| `database_url` | `AISRF_DATABASE_URL` | str | `sqlite+aiosqlite:///./data/aisrf.db` | locked | Async SQLAlchemy URL; `postgresql+asyncpg://user:pass@host:5432/aisrf` needs the `postgres` extra |
| `db_echo` | `AISRF_DB_ECHO` | bool | `false` | yes (engine option applies at next restart; the SQLAlchemy logger level is set at logging configuration) | Log SQL statements |
| `secret_key` | `AISRF_SECRET_KEY` | str (secret, min 16 chars) | `change-me-in-production-please-0123456789` | locked | Signs session cookies (salt `aisrf-session`); derives the Fernet key when `encryption_key` is unset |
| `encryption_key` | `AISRF_ENCRYPTION_KEY` | str or null (secret) | unset | locked | Explicit Fernet key (urlsafe base64, 32 bytes) for upstream credentials |

### Paths (environment only, not in the schema)

| Field | Env var | Default | Description |
| --- | --- | --- | --- |
| `base_dir` | `AISRF_BASE_DIR` | current working directory | Base directory |
| `data_dir` | `AISRF_DATA_DIR` | `<cwd>/data` | Created at startup; the default SQLite file lives here |
| `log_dir` | `AISRF_LOG_DIR` | `<cwd>/logs` | Created at startup with an `agents/` subdirectory |

Note that `database_url` defaults to a relative path `./data/aisrf.db` and is not derived from `data_dir`; change both when relocating data.

## Settings namespaces

Each namespace is a JSON document with the defaults below (`settings_store.NAMESPACE_DEFAULTS`). `GET /api/settings/ns/{namespace}` returns `{"namespace", "defaults", "value"}`; `PUT /api/settings/ns/{namespace}` (admin) merges the given top-level keys; `POST /api/settings/ns/{namespace}/reset` restores the defaults. Values must be JSON-serialisable. Changes apply live and are audited as `settings.update` and `settings.reset`.

### `analyzers`

| Key | Default | Meaning |
| --- | --- | --- |
| `disabled` | `[]` | Analyzer names that are skipped (for example `llm_judge`, `pii`, `harmful_compliance`) |
| `severity_overrides` | `{}` | Map of analyzer name or finding category to a severity (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) applied to their findings |
| `confidence_floor` | `0.0` | Findings with lower confidence are dropped before scoring |
| `category_weights` | `{}` | Reserved per-category weight multipliers |

### `rules`

| Key | Default | Meaning |
| --- | --- | --- |
| `custom` | `[]` | List of `{id, name, pattern, category, severity, scope, action, enabled}`; `scope` is `request`, `response` or `both`; `action` is `flag` or `deny`; evaluated in list order. See [[Custom-Rules]] |

### `integrations`

| Integration | Key | Default | Meaning |
| --- | --- | --- | --- |
| `llm_guard` | `enabled` | `false` | Run LLM Guard scanners as analyzers |
| | `input_scanners` | `["PromptInjection", "Secrets", "Toxicity"]` | Input scanner names |
| | `output_scanners` | `["Sensitive", "MaliciousURLs"]` | Output scanner names |
| | `threshold` | `0.5` | Scanner threshold |
| `nemo_guardrails` | `enabled` | `false` | Run NeMo Guardrails |
| | `config_path` | `""` | Rails config directory; empty uses the bundled `aisrf/guardrails/nemo_default` |
| | `run_output_rails` | `false` | Also run output rails on responses |
| `lakera` | `enabled` | `false` | Call the Lakera Guard API |
| | `api_key` | `""` | Lakera credential (masked in the API) |
| | `endpoint` | `https://api.lakera.ai/v2/guard` | API endpoint |
| | `project_id` | `""` | Optional Lakera project |
| `rebuff` | `enabled` | `true` | Rebuff-style layered detection |
| | `heuristic_threshold` | `0.75` | Heuristic score threshold |
| | `use_llm` | `false` | Use the LLM judge as the Rebuff model layer |
| | `canary_default` | `false` | Inject canaries for every agent regardless of `inject_canary` |
| `typesafe` | `enabled` | `false` | TypeSafe (Jev) decision layer ([[TypeSafe-Integration]]) |
| | `api_key` | `""` | TypeSafe credential (masked); falls back to `TYPESAFE_API_KEY` |
| | `base_url`, `model`, `timeout_seconds` | `https://api.typesafe.ai`, `jev-latest`, `8` | Endpoint, model and per-attempt timeout |
| | `cache_ttl_seconds`, `max_state_chars` | `300`, `12000` | Result cache TTL and state budget |
| | `noul_threshold`, `benign_confidence`, `malicious_confidence` | `0.7`, `0.85`, `0.9` | Finding threshold and verdict confidences |
| | `escalate_to_llm_judge` | `false` | Run the LLM judge only for uncertain verdicts |
| | `auto_route`, `auto_deny_confidence`, `auto_approve_confidence` | `false`, `0.95`, `0.9` | Confidence-gated policy routing |
| | `redteam_evaluator`, `redteam_confidence` | `true`, `0.8` | Red-team evaluation and override confidence |
| | `max_findings`, `triage_min_severity`, `triage_confidence`, `triage_concurrency` | `200`, `LOW`, `0.8`, `8` | Code review triage |
| | `judge_input_price_per_million`, `judge_output_price_per_million`, `price_per_million_input` | `0.15`, `0.6`, `0.042` | Prices behind the savings estimate |
| `garak` | `enabled` | `true` | Allow garak scanner runs |
| | `default_probes` | `["promptinject", "dan", "encoding", "leakreplay"]` | Default garak probes |
| | `generations` | `1` | Generations per probe |
| `promptfoo` | `enabled` | `true` | Allow promptfoo runs |
| | `binary` | `.venv/node_modules/.bin/promptfoo` | Path to the promptfoo executable |
| | `default_plugins` | `["harmful", "pii", "prompt-extraction", "hijacking"]` | Default red-team plugins |
| | `strategies` | `["jailbreak", "base64"]` | Default strategies |
| `pyrit` | `enabled` | `true` | Allow PyRIT runs |
| | `default_converters` | `["Base64Converter", "ROT13Converter"]` | Default converters |
| | `scorer` | `SelfAskRefusalScorer` | Scorer class |

The dashboard also shows a `pyrit_ship` card; it has no defaults in the store and is created with `enabled: false` until saved. Any integration key named `api_key` is returned as `********` and preserved when `********` is sent back.

### `ui`

| Key | Default | Meaning |
| --- | --- | --- |
| `theme` | `auto` | `auto`, `dark` or `light` |
| `refresh_seconds` | `5` | Fallback stats polling interval when SSE is unavailable; 0 disables |
| `sound_on_new_ticket` | `true` | Default for the queue beep (each browser can override) |
| `queue_default_status` | `PENDING` | Tab selected when the queue opens; empty string means All |
| `ticket_columns` | `[]` | Reserved column selection |
| `date_format` | `relative` | `relative` or `absolute` timestamps |
| `brand_name` | `AISRF` | Name in the navigation and page titles |
| `accent_color` | `""` | Hex colour applied to the CSS accent variables; empty keeps the built-in accent |

### `policy`

| Key | Default | Meaning |
| --- | --- | --- |
| `global_auto_deny_patterns` | `[]` | Regexes denied for every agent |
| `global_allowed_paths` | `[]` | Globs restricting every agent's paths |
| `block_on_canary_leak` | `true` | Withhold responses containing the canary |
| `quarantine_on_critical_response_finding` | `false` | Withhold responses with a CRITICAL response finding |

Semantics are in [[Policy-Engine]].

## Export and import

`GET /api/settings/export?include_secrets=false` (admin) returns:

```json
{"core": {"app_name": "AISRF", "approval_timeout_seconds": 300, "...": "..."},
 "namespaces": {"analyzers": {...}, "rules": {...}, "integrations": {...}, "ui": {...}, "policy": {...}}}
```

`core` holds the effective value of every non-path field; secret fields are omitted unless `include_secrets=true`. Locked fields are included for information. `namespaces` holds the full current documents, including integration `api_key` values (they are stored in plain JSON in `app_settings`; protect the export file accordingly).

`POST /api/settings/import` (admin) takes the same shape: `core` keys that exist and are not locked are applied through `update_core` (values `********` are skipped), and every namespace document is merged through `update_namespace`. The response lists what was applied and the action is audited as `settings.import`. The Settings page wraps both in Download settings.json and an Import file picker with a confirmation dialog.

## Example `.env`

```bash
AISRF_ENVIRONMENT=production
AISRF_SECRET_KEY=replace-with-openssl-rand-hex-32
AISRF_ENCRYPTION_KEY=replace-with-a-fernet-key
AISRF_ADMIN_PASSWORD=replace-me
AISRF_ADMIN_API_TOKEN=replace-with-openssl-rand-hex-32
AISRF_DATABASE_URL=postgresql+asyncpg://aisrf:secret@db:5432/aisrf
AISRF_PUBLIC_URL=https://aisrf.example.com
AISRF_COOKIE_SECURE=true
AISRF_APPROVAL_TIMEOUT_SECONDS=600
AISRF_NOTIFY_WEBHOOK_URLS='["https://hooks.slack.com/services/T000/B000/xxxx"]'
AISRF_NOTIFY_MIN_RISK=25
```

Generate a Fernet key with `.venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.

Related: [[Settings-Center]], [[Security-Model]], [[Deployment]], [[Notifications]].
