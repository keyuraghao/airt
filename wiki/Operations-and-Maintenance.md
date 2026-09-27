# Operations and Maintenance

Day-two tasks for a running gateway: reviewers, keys, retention, logs, audit verification, metrics, backups, upgrades, schema notes, monitoring and disaster recovery. Deployment topologies are in [[Deployment]]; symptom-based fixes in [[Troubleshooting]].

Every remote CLI command below takes `--url` (default `http://localhost:8080`, or `AISRF_URL`) and `--token` (or `AISRF_ADMIN_API_TOKEN`). Local commands (`init-db`, `create-reviewer`, `agent ...`) open the database directly and need the same `AISRF_*` environment as the service (for a binary or service install export `AISRF_HOME` first, for example `sudo -u aisrf AISRF_HOME=/var/lib/aisrf aisrf agent list`).

## Reviewer management

Roles: `viewer` (read tickets, logs, reports) < `reviewer` (approve and deny) < `admin` (agents, reviewers, settings, campaigns, code review, audit). The admin bearer token `AISRF_ADMIN_API_TOKEN` carries the admin role and is accepted as `Authorization: Bearer <token>` or `X-AISRF-Admin-Token: <token>`.

| Task | Dashboard | API | CLI |
| --- | --- | --- | --- |
| List reviewers | Settings > Reviewers | `GET /api/auth/reviewers` (admin) | |
| Create | Settings > Reviewers | `POST /api/auth/reviewers` `{"username","password","role"}` | `aisrf create-reviewer alice --role reviewer` (password prompted, or `--password`) |
| Change password | Settings > Reviewers | `POST /api/auth/reviewers/{id}/password` `{"password"}` | |
| Deactivate | Settings > Reviewers | `DELETE /api/auth/reviewers/{id}` | |
| Current identity | | `GET /api/auth/me` | |

Passwords are hashed with PBKDF2-HMAC-SHA256 (390k rounds, per-user salt). The bootstrap admin is created on start from `AISRF_ADMIN_USERNAME` / `AISRF_ADMIN_PASSWORD` if the username does not exist; changing `AISRF_ADMIN_PASSWORD` later does not change an existing account, use the API or dashboard. Session cookies are signed with `AISRF_SECRET_KEY` and live `AISRF_SESSION_MAX_AGE_SECONDS` (43200, 12 hours). Every reviewer action lands in the audit log with the actor name.

## Key rotation

| Key | Where | How to rotate | Consequences |
| --- | --- | --- | --- |
| Agent key (`aisrf_...`) | hashed (SHA-256) in `agents.api_key_hash` | `POST /api/agents/{id}/rotate-key`, `aisrf agent rotate-key <id or name>`, Agents page, MCP `rotate_agent_key` | the old key stops working immediately; the new key is shown once; audit action `agent.rotate_key` |
| Upstream provider key | Fernet-encrypted on the agent | `PATCH /api/agents/{id}` with `upstream_api_key` or edit the agent in the dashboard | no client change needed; the gateway swaps it in at forward time |
| Admin API token | `AISRF_ADMIN_API_TOKEN` (env, `aisrf.env`, Secret) | set a new value and restart; in desktop or binary installs delete the line in `aisrf.env` to regenerate | update every MCP client and CI job |
| Admin password | database | Settings > Reviewers or `POST /api/auth/reviewers/{id}/password` | sessions stay valid until they expire |
| `AISRF_SECRET_KEY` | env or file | set a new value and restart | all sessions are invalidated; if no `AISRF_ENCRYPTION_KEY` is set, every stored upstream key becomes unreadable (re-enter them on each agent) |
| `AISRF_ENCRYPTION_KEY` | env or file | there is no automatic re-encryption: export the agent list, set the new key, re-enter each upstream key | plan a maintenance window |
| Scan tokens | `scan_tokens` table | minted per scanner run, revoked when the run ends (`revoke_scan_tokens`) | nothing to do; stale tokens are revoked on `finish` |

Recommended order when adopting a dedicated encryption key on an existing install: generate the Fernet key, set `AISRF_ENCRYPTION_KEY`, restart, then re-save the upstream key of every agent (the old ciphertext was derived from the secret key and will fail to decrypt until re-entered).

## Retention and purge

The background sweeper in `aisrf/main.py` runs every 5 seconds:

- every cycle: `expire_stale()` turns PENDING tickets whose `expires_at` has passed into EXPIRED (the `expired` notification fires, waiting clients receive 504);
- every 720th cycle (about one hour): when `AISRF_TICKET_RETENTION_DAYS` > 0, `purge_old()` deletes tickets with `created_at` older than that many days (default 90; `0` keeps everything). Ticket events cascade with the ticket; audit entries, agents, campaigns and code review runs are not purged.

Change retention live under Settings > Core (group Gateway) or with `AISRF_TICKET_RETENTION_DAYS`. Code review work directories under `<data dir>/codereview/` are cleaned by `intake.cleanup_expired()`. Campaigns, groups and code review runs are deleted explicitly (`DELETE /api/redteam/campaigns/{id}`, `DELETE /api/redteam/groups/{id}`, `DELETE /api/codereview/runs/{id}`). Reclaim SQLite space after a large purge with `sqlite3 data/aisrf.db "VACUUM;"` while the service is stopped.

## Log rotation

`aisrf/logging.py` configures three sinks:

1. console: coloured in development, JSON lines when `AISRF_LOG_JSON_CONSOLE=true` or `AISRF_ENVIRONMENT=production`;
2. `<log dir>/aisrf.jsonl`, `RotatingFileHandler` with `maxBytes` 50 MiB and `backupCount` 10 (at most about 550 MB);
3. `<log dir>/agents/<agent_id>.jsonl`, one file per agent, 20 MiB x 5 (at most about 120 MB per agent).

Rotation is built in; do not add logrotate on those files (copytruncate would race the handler). Ship the JSON lines to your pipeline: `journalctl -u aisrf -o cat` under systemd, `docker logs`, the stdout collector in Kubernetes, or a file tailer on `aisrf.jsonl`. Every line carries `request_id` (from `X-Request-ID` or generated), `path`, `method` and `service=aisrf`. Set `AISRF_LOG_LEVEL=DEBUG` temporarily to see analyzer and forwarder detail. Noisy loggers (`uvicorn.access`, `httpx`, `httpcore`, `aiosqlite`, `watchfiles`) are pinned to WARNING. NSSM-managed Windows services additionally rotate `service.out.log` and `service.err.log` at 50 MB.

## Audit verification

Every privileged action (decisions, agent changes, key rotations, reviewer changes, settings changes, campaign and code review operations) is written by `aisrf.audit.service.record` as a SHA-256 hash chain over (previous hash, timestamp, actor, action, target type, target id, detail).

```bash
aisrf audit verify --url https://aisrf.example.com --token "$AISRF_ADMIN_API_TOKEN"
curl -fsS -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" https://aisrf.example.com/api/audit/verify
```

Response: `{"ok": true, "checked": <n>, "head": "<hash>"}` or `{"ok": false, "checked": <n>, "broken_at": <entry id>}`. The CLI exits with status 2 when the chain is broken. Schedule the check (cron, a CI job, or an MCP client) and store the `head` hash off-box after each run; a changed history shows up either as `ok: false` or as a head that no longer matches the previously recorded prefix. Browse entries at `GET /api/audit` or the Audit page and export them with `aisrf report audit --format json`.

## Prometheus scrape config

`GET /metrics` is unauthenticated Prometheus text rendered by `aisrf/metrics.py` (counters, gauges and a small summary with `_count`, `_sum`, `_p50`, `_p95` for observed values). Restrict it at the proxy if the host is public.

```yaml
scrape_configs:
  - job_name: aisrf
    metrics_path: /metrics
    scheme: https
    static_configs:
      - targets: ["aisrf.example.com:443"]
```

Metrics exported (all prefixed `aisrf_`): `gateway_requests_total`, `gateway_auth_failures_total`, `gateway_policy_total` (labelled by decision), `gateway_denied_total`, `gateway_expired_total`, `gateway_upstream_responses_total`, `gateway_upstream_errors_total`, `gateway_responses_withheld_total`, `gateway_risk_score` (summary), `gateway_wait_seconds` (summary, human decision latency), `gateway_upstream_latency_ms` (summary), `metrics_scrapes_total`. The registry is per process and resets on restart.

Alert suggestions: `increase(aisrf_gateway_expired_total[15m]) > 0` (reviewers too slow or nobody on duty), `rate(aisrf_gateway_auth_failures_total[5m]) > 1` (key scanning), `increase(aisrf_gateway_upstream_errors_total[10m]) > 5` (provider or credential trouble), `aisrf_gateway_wait_seconds_p95 > 240` (approaching the 300 s timeout), and a blackbox probe on `/readyz`.

## Monitoring queue depth and expiry

- `GET /api/tickets/stats` returns counts per status and risk level; `GET /api/tickets?status=PENDING&limit=1` returns `total` for the queue depth. Poll either from your monitoring or an MCP client (`list_tickets`, `ticket_stats`).
- `aisrf tickets watch --status PENDING` tails `/api/stream/tickets` and prints tickets as they are created and decided.
- Webhook notifications: `AISRF_NOTIFY_WEBHOOK_URLS=["https://hooks.slack.com/services/..."]`, `AISRF_NOTIFY_EVENTS=["created","expired","failed"]` (also `decided`, `completed`), `AISRF_NOTIFY_MIN_RISK` to page only above a risk score; `AISRF_PUBLIC_URL` builds the "Open ticket" links. See [[Notifications]].
- Expiry is governed by `AISRF_APPROVAL_TIMEOUT_SECONDS` (300): synchronous callers wait that long, async tickets get the same `expires_at`. Raise it (and the proxy timeouts) if reviewers legitimately need more time; lower it for interactive agents.
- Queue hygiene: bulk approve or deny from the Tickets page, `POST /api/tickets/bulk/approve` and `/api/tickets/bulk/deny`, or the MCP bulk tools.

## Backup and restore

What to back up: the database and the key material (`AISRF_SECRET_KEY`, `AISRF_ENCRYPTION_KEY` if set, `AISRF_ADMIN_API_TOKEN`) from `aisrf.env`, `.env`, `/etc/aisrf/aisrf.env` or the Kubernetes Secret. Logs are useful but reproducible from your log pipeline.

Backup:

```bash
# SQLite (online, WAL mode)
sqlite3 /var/lib/aisrf/data/aisrf.db ".backup '/backup/aisrf-$(date +%F).db'"
cp /etc/aisrf/aisrf.env /backup/aisrf-$(date +%F).env && chmod 600 /backup/*.env
# PostgreSQL
pg_dump -Fc "postgresql://aisrf:secret@db.internal:5432/aisrf" > /backup/aisrf-$(date +%F).dump
# Docker volume
docker run --rm -v aisrf-data:/data -v "$PWD":/backup alpine tar czf /backup/aisrf-data-$(date +%F).tgz -C /data .
# Runtime settings as JSON (analyzer toggles, custom rules, integrations, UI)
curl -fsS -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" https://aisrf.example.com/api/settings/export > settings.json
```

Restore:

1. Stop the service (`systemctl stop aisrf`, `docker stop aisrf`, scale the Deployment to 0).
2. Put the key material back exactly as it was (same `AISRF_SECRET_KEY` and `AISRF_ENCRYPTION_KEY`), otherwise the upstream keys inside the database cannot be decrypted.
3. SQLite: copy the backup file to `<data dir>/aisrf.db` and delete stale `aisrf.db-wal` and `aisrf.db-shm`. PostgreSQL: `pg_restore --clean --if-exists -d aisrf backup.dump`. Docker: `docker run --rm -v aisrf-data:/data -v "$PWD":/backup alpine sh -c "cd /data && tar xzf /backup/aisrf-data-<date>.tgz"`.
4. Start the service, check `/readyz`, run `aisrf audit verify`, sign in and confirm an agent can still forward (the upstream key decrypts).
5. Re-import runtime settings with `curl -X POST -H "Authorization: Bearer ..." -H "Content-Type: application/json" --data @settings.json https://aisrf.example.com/api/settings/import` if the database backup predates a settings change.

## Upgrades per install method

Read `CHANGELOG.md` for the target version first; breaking configuration changes are listed under `Changed` with a migration note. Back up before major versions.

| Method | Steps |
| --- | --- |
| Binary (Linux, macOS) | `curl -fsSL .../scripts/install.sh \| bash` (or with `AISRF_VERSION=x.y.z`); for a service `sudo systemctl stop aisrf` first, then `sudo systemctl start aisrf` |
| Binary (Windows) | `Stop-Service AISRF`, re-run `install.ps1`, `Start-Service AISRF` |
| pip, pipx | `pipx upgrade aisrf` or `uv pip install --python .venv/bin/python -U "git+https://github.com/keyuraghao/aisrf.git"`; from a clone `git pull && uv pip install --python .venv/bin/python -e ".[dev]"`; restart |
| Docker | `docker pull ghcr.io/keyuraghao/aisrf:<version>`, `docker rm -f aisrf`, run again with the same volumes and env |
| docker compose | bump the tag or `docker compose pull`, then `docker compose up -d` (or `up -d --build` when building locally) |
| Kubernetes | `kubectl -n aisrf set image deploy/aisrf aisrf=ghcr.io/keyuraghao/aisrf:<version>` then `kubectl -n aisrf rollout status deploy/aisrf` |
| Helm | `helm upgrade aisrf deploy/helm/aisrf -n aisrf --set image.tag=<version> --reuse-values` |
| launchd | upgrade the binary, `launchctl kickstart -k gui/$(id -u)/com.aisrf.gateway` |

After any upgrade: `aisrf version`, `curl /healthz` shows the new version, sign in, approve one ticket end to end. Rollback is the same procedure with the previous version plus the pre-upgrade database backup if the schema gained columns the old code does not know (extra columns are harmless for SQLAlchemy, missing ones are not).

## Schema notes

- Tables are created and extended by `Base.metadata.create_all` in `aisrf.db.init_db()` at every start and by `aisrf init-db`. New tables appear automatically; new columns on existing tables do not (`create_all` never alters). Until Alembic migrations ship, a release that adds a column documents the `ALTER TABLE` in its notes.
- SQLite is opened with `timeout=30`, `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON`. Expect `aisrf.db-wal` and `aisrf.db-shm` next to the file while the service runs.
- Ticket numbers come from the `counters` table (`_seed_counters` initialises it from `max(tickets.number)`), which keeps numbering atomic across processes.
- Models (`aisrf/models.py`): `reviewers`, `agents`, `scan_tokens`, `tickets`, `ticket_events`, `agent_events`, `audit_entries`, `campaigns`, `probe_results`, `app_settings`, `counters`, `codereview_runs`, `codereview_findings`.
- Runtime setting overrides live in `app_settings` and are applied on start (`settings_store.load_overrides`), with precedence UI override > environment or `.env` > code default. Locked fields that can only come from the environment: `database_url`, `host`, `port`, `workers`, `base_dir`, `data_dir`, `log_dir`, `secret_key`, `encryption_key`.

## Disaster recovery

Recovery point: the last database backup plus the key material. Recovery steps for a lost host:

1. Provision the new host with the same install method ([[Installation]]).
2. Restore the key material first (`aisrf.env`, `/etc/aisrf/aisrf.env`, `.env` or the Secret). Without the original `AISRF_SECRET_KEY` (or `AISRF_ENCRYPTION_KEY`) the restored agents have unusable upstream credentials and every upstream key must be re-entered; agent keys held by applications keep working because only their hash is stored.
3. Restore the database (previous section), start the service, verify `/readyz` and `aisrf audit verify`.
4. Point DNS or the proxy at the new host; keep `AISRF_PUBLIC_URL` unchanged so notification links stay valid.
5. Tickets that were PENDING at the time of the loss expire through the sweeper; tell agent owners that synchronous calls in flight were lost and that async tickets can still be polled by id.
6. Reconnect MCP clients and CI with the same admin token (or rotate it if the host compromise is the reason for the recovery, then rotate every agent key and upstream key as well).

Test the procedure periodically on a scratch machine: restore, sign in, forward one request through a test agent, generate a summary report (`aisrf report summary --format pdf`).
