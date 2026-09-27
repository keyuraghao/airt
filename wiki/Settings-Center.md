# Settings center

The dashboard page at `/settings` (`templates/settings.html`, `static/settings.js`). It exposes every runtime setting, the five JSON namespaces, reviewer management, export and import, and reference material. Viewers and reviewers see everything read-only; only admins can change values. Every section has a sub-navigation entry and a URL hash (`/settings#policy`); the last visited section is remembered in the browser.

## How the core sections work

The first seven sections (General, Gateway, Security, Notifications, Analysis, Red team, Advanced) are generated from `GET /api/settings/schema`, which returns one entry per `Settings` field with `key`, `group`, `type`, `description`, `default`, `value`, `secret`, `locked` and `env`. Each row shows the key, its description, the default and the environment variable name, and a control chosen by type:

| Field type | Control |
| --- | --- |
| locked | Read-only text with a lock icon; tooltip `Set AISRF_... in the environment and restart` |
| bool | Toggle switch |
| int, float | Number input |
| list | Textarea, one value per line or comma-separated |
| secret | Password input showing `********` when a value is stored; leaving it unchanged keeps the stored value |
| other | Text input |

Per row, Reset calls `POST /api/settings/core/reset` with `{"keys": ["<key>"]}` and drops that override so the environment or default applies again. Per section, Save `<group>` collects the modified rows and calls `PUT /api/settings/core` with `{"changes": {...}}`; Reset group to defaults confirms and resets every unlocked key of the group. Changes apply live and persist across restarts.

| Section | Group | Fields |
| --- | --- | --- |
| General | Service | `app_name`, `environment`, `log_level`, `log_json_console`, `public_url` |
| Gateway | Gateway | `approval_timeout_seconds`, `hold_poll_interval_seconds`, `max_request_body_bytes`, `max_stored_response_bytes`, `upstream_timeout_seconds`, `upstream_connect_timeout_seconds`, `default_auto_deny_risk_threshold`, `default_auto_approve_risk_threshold`, `ticket_retention_days`, `require_approval_for_redteam_probes` |
| Security | Security | `admin_username`, `admin_password`, `admin_api_token`, `session_max_age_seconds`, `cookie_secure` |
| Notifications | Notifications | `notify_webhook_urls`, `notify_events`, `notify_min_risk` |
| Analysis | Analysis | `enable_llm_judge`, `judge_provider`, `judge_base_url`, `judge_api_key`, `judge_model` |
| Red team | Red team | `redteam_concurrency`, `redteam_probe_timeout_seconds` |
| Advanced | Advanced | `host`, `port`, `workers`, `database_url`, `db_echo`, `secret_key`, `encryption_key` (all locked except `db_echo`) |

Defaults, types and semantics of every field: [[Configuration-Reference]].

## UI

Namespace `ui`, loaded with `GET /api/settings/ns/ui`, saved with `PUT /api/settings/ns/ui`, reset with `POST /api/settings/ns/ui/reset`.

| Control | Effect |
| --- | --- |
| `theme` select (`auto`, `dark`, `light`) | Applied live as a preview; `auto` follows the operating system; users can still toggle locally |
| `brand_name` text | Shown in the navigation and browser titles |
| `accent_color` colour picker plus hex text and Clear | Primary accent applied live to the CSS variables; empty keeps the built-in accent |
| `refresh_seconds` number | Fallback polling interval for stats when the live stream is unavailable; 0 disables |
| `sound_on_new_ticket` toggle | Default for the audible alert on the review queue |
| `queue_default_status` select (`PENDING`, All, `DENIED`, `COMPLETED`, `EXPIRED`, `FAILED`) | Tab selected when the queue opens |
| `date_format` select (`relative`, `absolute`) | Timestamp style in tables |
| Save UI | Persists the document and applies it for every user |
| Preview reset | Reverts the live preview to the saved values |
| Raw JSON editor | Edit the whole namespace document; validated as a JSON object before Save raw document |

## Policy

Namespace `policy`.

| Control | Effect |
| --- | --- |
| `global_auto_deny_patterns` textarea | One regex per line, denied for every agent before a reviewer sees the ticket; the Regex test box below evaluates every pattern (case-insensitive, in the browser) against a pasted prompt fragment |
| `global_allowed_paths` textarea | One glob per line; empty allows all paths |
| `block_on_canary_leak` toggle | Withhold the upstream response when an injected canary appears in it |
| `quarantine_on_critical_response_finding` toggle | Withhold responses that carry a CRITICAL response finding |
| Save policy | Validates every regex, then `PUT /api/settings/ns/policy` |
| Reset namespace, Raw JSON editor | As above |

## Rules

Namespace `rules`, key `custom`. A table with one row per rule and these columns: reorder buttons (up, down; order is evaluation order), `Id` (must be unique and non-empty), `Name`, `Pattern` (regex, border turns red when invalid), `Category` (from the taxonomy category map, loaded from `GET /api/settings/taxonomy`), `Severity` (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), `Scope` (`request`, `response`, `both`), `Action` (`flag`, `deny`), `On` toggle, Delete. Add rule appends a row with id `rule-<n>`, severity `MEDIUM`, scope `request`, action `flag`. The Test rule box runs every enabled regex against typed text in the browser and shows the action and the match. Save rules validates patterns and ids and calls `PUT /api/settings/ns/rules` with `{"custom": [...]}`. See [[Custom-Rules]].

## Analyzers

Namespace `analyzers`, loaded with `GET /api/settings/analyzers`, which returns the registered analyzers (`name`, `kind`, `description`) plus the current config.

| Control | Effect |
| --- | --- |
| Enabled toggle per analyzer | Adds or removes the name from `disabled` |
| Severity override select per analyzer | `severity_overrides[<analyzer>]` |
| Severity override per category table plus Add category override | `severity_overrides[<category>]` for taxonomy categories |
| `confidence_floor` slider (0 to 1, step 0.05) | Findings below this confidence are dropped before scoring |
| Save analyzers | `PUT /api/settings/ns/analyzers` with `disabled`, `severity_overrides`, `confidence_floor`, `category_weights` |

See [[Analyzers]].

## Integrations

Namespace `integrations`. One card per integration: `llm_guard`, `nemo_guardrails`, `lakera`, `rebuff`, `garak`, `promptfoo`, `pyrit`, `pyrit_ship`, plus any extra key present in the stored document. Each card has an Enabled toggle in its header and one control per key, chosen by the type of the default value: toggle for booleans, number input for numbers, textarea (one per line) for lists, password input for keys matching `api_key`, `secret`, `token` or `password` (masked as `********`, unchanged when left masked), JSON textarea for objects, text input otherwise. When a value differs from the default the label shows `(default: ...)`. Save `<name>` sends only that integration's document to `PUT /api/settings/ns/integrations`. Guardrail status and health checks use `GET /api/settings/guardrails` and `POST /api/settings/guardrails/health` (admin) from the guardrails pages. See [[Guardrails]] and [[Scanner-Engines]].

## Reviewers

Not a namespace; backed by `/api/auth`.

| Control | API |
| --- | --- |
| Reviewer table (username, role badge, active or inactive, last login) | `GET /api/auth/reviewers` (admin) |
| Password button per reviewer | `POST /api/auth/reviewers/{id}/password` |
| Deactivate button (not for yourself) | `DELETE /api/auth/reviewers/{id}` |
| New reviewer form (username, password, role) | `POST /api/auth/reviewers` |
| Change your own password form | `POST /api/auth/reviewers/{your id}/password` (any role) |

## Export / Import

| Control | API |
| --- | --- |
| Download settings.json, with an include secrets checkbox | `GET /api/settings/export?include_secrets=<bool>`; the file is named `aisrf-settings-<date>.json` |
| Import file picker, preview of core key count and namespaces, Import button with confirmation | `POST /api/settings/import` |

Import replaces existing overrides for the keys present in the file and is audited as `settings.import`.

## About

Reference material rendered from `GET /api/settings/taxonomy`: the OWASP Top 10 for LLM Applications table with links, the category mapping table (category to OWASP, Greshake and Thacker chips with tooltips), the Greshake threat and delivery definitions, the Thacker technique definitions and the references list (OWASP, Greshake et al. 2023, Thacker primer, garak, promptfoo, PyRIT, Rebuff, LLM Guard, NeMo Guardrails, Lakera Guard). The Integration panel on the same page shows ready-to-copy snippets for the current origin: OpenAI style base URL (`<origin>/v1/...`), Anthropic style (`<origin>/v1/messages`), generic proxy (`<origin>/proxy/<path>` with `X-AISRF-Key`), the async header, and the automation token hint.

## Audit and live update

Every save and reset writes an audit entry (`settings.update` or `settings.reset` with the namespace and keys, `settings.import` for imports) and publishes `settings.updated` on the `settings` broadcaster channel. The status line at the top of the page reports the number of core settings and namespaces loaded from the schema endpoint.

Related: [[Configuration-Reference]], [[Dashboard-Guide]], [[Security-Model]].
