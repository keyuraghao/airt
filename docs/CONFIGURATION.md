# Configuration

All settings live in `airt/config.py` (`Settings`, pydantic-settings). Each field can be set as an
environment variable prefixed with `AIRT_` (case insensitive) or in a `.env` file in the working
directory; environment variables win. `.env.example` is a commented template.

Precedence: environment variable > `.env` > default. `get_settings()` caches the object for the
process lifetime (`reset_settings_cache()` exists for tests).

## Service

| Variable | Default | Description |
| --- | --- | --- |
| `AIRT_APP_NAME` | `AIRT Gateway` | Title in the dashboard and OpenAPI |
| `AIRT_ENVIRONMENT` | `development` | `development`, `staging`, `production`; production forces JSON console logs |
| `AIRT_HOST` | `0.0.0.0` | Bind address |
| `AIRT_PORT` | `8080` | Port |
| `AIRT_WORKERS` | `1` | uvicorn workers (see the hold registry note below) |
| `AIRT_BASE_DIR` | cwd | Base directory |
| `AIRT_DATA_DIR` | `./data` | SQLite file and state; created on start |
| `AIRT_LOG_DIR` | `./logs` | `airt.jsonl` and `agents/<id>.jsonl`; created on start |
| `AIRT_LOG_LEVEL` | `INFO` | Upper-cased automatically |
| `AIRT_LOG_JSON_CONSOLE` | `false` | JSON lines on stdout |

## Persistence

| Variable | Default | Description |
| --- | --- | --- |
| `AIRT_DATABASE_URL` | `sqlite+aiosqlite:///./data/airt.db` | Async SQLAlchemy URL; PostgreSQL: `postgresql+asyncpg://user:pass@host:5432/airt` (`pip install "airt[postgres]"`). SQLite runs with WAL and foreign keys on |
| `AIRT_DB_ECHO` | `false` | Log SQL |

## Security

| Variable | Default | Description |
| --- | --- | --- |
| `AIRT_SECRET_KEY` | `change-me-in-production-please-0123456789` | Session signing key (min 16 chars); also derives the Fernet key when `AIRT_ENCRYPTION_KEY` is unset |
| `AIRT_ENCRYPTION_KEY` | unset | Explicit Fernet key for upstream credentials |
| `AIRT_ADMIN_USERNAME` | `admin` | Bootstrap admin (created on first start if missing) |
| `AIRT_ADMIN_PASSWORD` | `admin` | Bootstrap admin password; warning logged while default |
| `AIRT_ADMIN_API_TOKEN` | unset | Static admin bearer token for MCP / CLI / CI |
| `AIRT_SESSION_MAX_AGE_SECONDS` | `43200` | Dashboard session lifetime |
| `AIRT_COOKIE_SECURE` | `false` | `Secure` flag on the session cookie |

## Notifications

| Variable | Default | Description |
| --- | --- | --- |
| `AIRT_NOTIFY_WEBHOOK_URLS` | `[]` | JSON list of webhook URLs; Slack incoming webhooks receive Block Kit messages, others the raw event JSON |
| `AIRT_NOTIFY_EVENTS` | `["created","expired","failed"]` | Ticket events that page reviewers (`created`, `decided`, `completed`, `expired`, `failed`) |
| `AIRT_NOTIFY_MIN_RISK` | `0` | Only notify at or above this risk score |
| `AIRT_PUBLIC_URL` | empty | Base URL for ticket links in notifications (falls back to `http://localhost:<port>`) |

List valued settings are parsed as JSON by pydantic-settings, so quote them:
`AIRT_NOTIFY_WEBHOOK_URLS='["https://hooks.slack.com/services/..."]'`.

## Gateway behaviour

| Variable | Default | Description |
| --- | --- | --- |
| `AIRT_APPROVAL_TIMEOUT_SECONDS` | `300` | Sync wait for a decision; also the `expires_at` of every ticket |
| `AIRT_HOLD_POLL_INTERVAL_SECONDS` | `1.0` | DB polling cadence while waiting (cross-process decisions) |
| `AIRT_MAX_REQUEST_BODY_BYTES` | `4194304` | 413 above this |
| `AIRT_MAX_STORED_RESPONSE_BYTES` | `524288` | Response bytes kept on the ticket |
| `AIRT_UPSTREAM_TIMEOUT_SECONDS` | `120` | Upstream read timeout |
| `AIRT_UPSTREAM_CONNECT_TIMEOUT_SECONDS` | `10` | Upstream connect timeout |
| `AIRT_DEFAULT_AUTO_DENY_RISK_THRESHOLD` | `90` | Default `auto_deny_at_risk` for new agents |
| `AIRT_DEFAULT_AUTO_APPROVE_RISK_THRESHOLD` | `0` | Default `auto_approve_below_risk` (0 = never) |
| `AIRT_TICKET_RETENTION_DAYS` | `90` | Purge horizon (0 = keep forever) |
| `AIRT_REQUIRE_APPROVAL_FOR_REDTEAM_PROBES` | `true` | Red-team probes wait for a human like any ticket |

## Analysis

| Variable | Default | Description |
| --- | --- | --- |
| `AIRT_ENABLE_LLM_JUDGE` | `false` | Enable the LLM judge analyzer |
| `AIRT_JUDGE_PROVIDER` | `openai` | `openai` or `anthropic` |
| `AIRT_JUDGE_BASE_URL` | unset | Judge endpoint |
| `AIRT_JUDGE_API_KEY` | unset | Judge credential |
| `AIRT_JUDGE_MODEL` | `gpt-4o-mini` | Judge model |

## Red team

| Variable | Default | Description |
| --- | --- | --- |
| `AIRT_REDTEAM_CONCURRENCY` | `4` | Parallel probes per campaign |
| `AIRT_REDTEAM_PROBE_TIMEOUT_SECONDS` | `90` | Per-probe wait for approval and answer |

## Per-agent policy fields

These are not environment variables; they are stored on each agent (`POST /api/agents`, `PATCH`,
dashboard, CLI) and evaluated in this order by `airt/gateway/policy.py`:

1. `is_active` false -> deny.
2. `allowed_paths` (fnmatch globs, matched against `path` and `/path`) -> deny when not matched.
3. `allowed_models` (globs against the normalized `model`) -> deny when not matched.
4. `auto_deny_patterns` (regexes, case insensitive, DOTALL, against system + user text) -> deny.
5. `auto_deny_at_risk` (> 0 and `risk_score >=`) -> deny.
6. A CRITICAL finding in category `secrets` or `data_exfil` -> review, regardless of the next rules.
7. `require_approval` false -> approve.
8. `auto_approve_below_risk` (> 0 and `risk_score <`) -> approve.
9. otherwise review (human).

`rate_limit_per_minute` (0 = unlimited) is enforced before the ticket is created.

## Multi-process note

The hold registry resolves waiting requests in-process. With `AIRT_WORKERS>1` or a separate MCP
process, decisions are still picked up, but only on the next DB poll
(`AIRT_HOLD_POLL_INTERVAL_SECONDS`), and the in-process rate limiter and SSE broadcaster are per
worker. Keep one worker unless you accept those semantics.
