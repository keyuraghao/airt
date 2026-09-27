# Troubleshooting

Symptom, cause, fix. Each entry names the component and the exact setting, file or command involved. Collecting logs is described at the end; for install questions see [[Installation]], for proxy and service details [[Deployment]].

## Gateway responses

| Symptom | Cause | Fix |
| --- | --- | --- |
| `401 {"error": {"code": "unauthorized"}}` on `/v1/*` or `/proxy/*` | missing or unknown agent key, or the agent is inactive. The key is read from `X-AISRF-Key`, `x-api-key`, `api-key`, `x-goog-api-key` (when the value starts with `aisrf_`) or `Authorization: Bearer`; only its SHA-256 hash is stored | check the key was copied once at creation, `aisrf agent list` shows the agent as active, rotate with `aisrf agent rotate-key <id>` if lost. `aisrf_gateway_auth_failures_total` rises on every failure |
| `401` on `/api/*` from the CLI or MCP | no admin token, wrong token, or the token was regenerated (`aisrf.env` line deleted) | pass `--token` or export `AISRF_ADMIN_API_TOKEN`; the value must equal the one the server was started with |
| `403 {"error": {"code": "denied"}}` before any ticket wait | policy auto-denied: risk score >= `auto_deny_at_risk`, an `auto_deny_patterns` regex matched, the path or model is not in `allowed_paths` / `allowed_models`, or a critical secrets or exfiltration finding forced review | open the ticket in the dashboard, the `policy` block names the reason; adjust the agent policy or the custom rules under Settings > Rules |
| `403` with `code: "denied"` after a wait | a reviewer denied the ticket | the note is in the ticket events; nothing was sent upstream |
| `403 {"error": {"code": "response_withheld"}}` | the upstream answered but the response was withheld: canary leak with `block_on_canary_leak`, or a critical output finding under the policy namespace | inspect the ticket's response findings; the withheld body is stored on the ticket (up to `AISRF_MAX_STORED_RESPONSE_BYTES`) for reviewers |
| `504 {"error": {"code": "expired"}}` "no reviewer decision before the approval timeout" | nobody decided within `AISRF_APPROVAL_TIMEOUT_SECONDS` (300) | staff the queue, enable webhooks (`AISRF_NOTIFY_WEBHOOK_URLS`), raise the timeout together with the proxy timeouts, or use async mode (`X-AISRF-Async: 1`) and poll `/gateway/tickets/{id}` |
| `504` from the proxy (nginx `upstream timed out`) instead of from AISRF | the reverse proxy read timeout is shorter than approval plus upstream timeouts | `proxy_read_timeout 600s` (nginx), `read_timeout 10m` (Caddy), `nginx.ingress.kubernetes.io/proxy-read-timeout: "600"` |
| `502 {"error": {"code": "upstream_error"}}` | the approved request could not reach the provider: DNS, TLS, connect timeout (`AISRF_UPSTREAM_CONNECT_TIMEOUT_SECONDS` 10), read timeout (`AISRF_UPSTREAM_TIMEOUT_SECONDS` 120), or the provider rejected the upstream key | the ticket's `error` field and the `aisrf.jsonl` lines for its request id hold the message; test the `upstream_base_url` and key from the host; `aisrf_gateway_upstream_errors_total` counts them |
| `413` | body larger than `AISRF_MAX_REQUEST_BODY_BYTES` (4 MiB) or the agent's `max_request_bytes` | raise the setting and `client_max_body_size` on the proxy |
| `429` | the agent's `rate_limit_per_minute` was hit (per process, in memory) | raise it on the agent or slow the client |
| `404 ticket not found` on `/gateway/tickets/{id}` | wrong id, or the ticket belongs to another agent key | use the `ticket_id` from the 202 body and the same agent key |
| Client gets a connection reset while waiting | the gateway restarted; in-flight synchronous waits are dropped | the ticket stays PENDING and expires via the sweeper; retry deliberately or switch to async mode which survives restarts |

## Tickets missing from the queue

- The request never reached AISRF: the SDK still points at the provider. Check `base_url` (OpenAI SDK: `http://gw/v1`; Anthropic SDK: `http://gw`, the SDK appends `/v1/messages`) or that `patch_httpx()` runs before the SDK is imported.
- The request was auto-approved: `auto_approve_below_risk` on the agent or `require_approval=false`. The ticket exists with status APPROVED or COMPLETED; filter the Tickets page by status.
- A filter is active: the queue defaults to PENDING; `GET /api/tickets?status=PENDING,APPROVED,DENIED,EXPIRED,COMPLETED,FAILED` lists everything.
- Retention purged it: tickets older than `AISRF_TICKET_RETENTION_DAYS` are deleted hourly.
- You are looking at another database: the binary uses the app directory, pip uses `./data` of the working directory, the service uses `/var/lib/aisrf`; compare `AISRF_DATABASE_URL` in the startup log line `aisrf.started`.

## SSE behind proxies

Symptoms: the queue does not update live, "Live" indicator stuck, `aisrf tickets watch` prints nothing, campaign progress frozen while the run completes.

- Buffering: nginx needs `proxy_buffering off` and `proxy_cache off` on `/api/stream/`; Caddy `flush_interval -1`; ingress-nginx annotation `proxy-buffering: "off"`; Cloudflare and some WAFs buffer by default (exclude the `/api/stream/` prefix).
- Idle timeouts: the stream emits a `ping` event every 15 s; set proxy read timeouts above that (the recommended 600 s covers it). HTTP/1.1 with `proxy_http_version 1.1` is required for chunked responses on nginx.
- Authentication: the stream endpoints need a reviewer session cookie or the admin bearer token; a 401 in the browser console means the session expired (`AISRF_SESSION_MAX_AGE_SECONDS`).
- Multiple workers or replicas: the broadcaster is per process, so a decision made in one replica is not streamed by another. Keep one process, see [[Deployment]].

## Streaming responses cut short

- The proxy buffered or timed out the model stream: same fixes as SSE (`proxy_buffering off`, long timeouts, `flush_interval -1`).
- The captured copy is truncated on purpose: the relayed stream is complete, but only the first `AISRF_MAX_STORED_RESPONSE_BYTES` (512 KiB) are stored on the ticket.
- Upstream read timeout: a slow model exceeded `AISRF_UPSTREAM_TIMEOUT_SECONDS` (120); raise it.
- Streams are detected from the request (`stream: true`) or the upstream `content-type: text/event-stream`; a provider that streams with another content type is relayed as a whole body.

## Optional engines and imports

| Symptom | Cause | Fix |
| --- | --- | --- |
| `ImportError` around `mcp.server.mcpserver` or `mcp.server.fastmcp` | AISRF supports both mcp layouts: 2.x exposes `MCPServer` in `mcp.server.mcpserver`, 1.x exposes `FastMCP` in `mcp.server.fastmcp` (`aisrf/mcp_server.py` tries 2.x first). A broken or very old `mcp` package fails both | `uv pip install --python .venv/bin/python -U "mcp>=1.10"`; check with `.venv/bin/python -c "import mcp; print(mcp.__version__)"` |
| Installing the `codereview` extra downgrades `mcp` to 1.29 | `semgrep` pins `mcp==1.29.0` (visible with `pip show semgrep`), so it overrides the 2.x version installed by the core `mcp>=1.10` requirement | expected and supported: AISRF runs on mcp 1.x with the same tools. Tests tolerate both return shapes (1.x returns `(content, structured_content)` tuples). If you need mcp 2.x features, install semgrep in a separate virtualenv or via `pipx install semgrep` and set `semgrep_binary` in Settings > Code review |
| MCP tool result looks different between installs | mcp 1.x returns tool results as a tuple, 2.x as a structured result | client side handling only; the JSON payload is the same |
| `semgrep binary not found` in a code review run | the engine looks for an explicit `semgrep_binary` setting, then `<venv>/bin/semgrep` next to the running interpreter, then `PATH` (`aisrf/codereview/config.py`, `scanner_binary()`). Binaries never bundle semgrep | `uv pip install --python .venv/bin/python "aisrf[codereview]"` or `pipx install semgrep`, then set `semgrep_binary` (and `bandit_binary`) under Settings > Code review to the absolute path when it is outside the venv and `PATH` |
| semgrep runs but reports no AISRF rules | semgrep could not load the rule files or `validate_rules` failed | run `semgrep --validate --config aisrf/codereview/rules/semgrep/` and check the run log in the dashboard; the built-in rules engine still produces findings |
| garak or PyRIT shown as "not installed" | `garak` is detected with `importlib.util.find_spec("garak")`, PyRIT with `pyrit_available()`; neither is in the binaries | `uv pip install --python .venv/bin/python "aisrf[scanners]"` (multi-gigabyte, needs Python 3.11 or 3.12) in the environment that runs the gateway; promptfoo is a Node binary: `npm install -g promptfoo` or set `binary_path` in Settings > Integrations |
| garak run fails immediately | wrong generator URI or the scan token was revoked | the engine points garak's `OpenAICompatible` generator at `<gateway>/v1/`; make sure `AISRF_PUBLIC_URL` or the gateway base URL in Settings is reachable from the gateway host itself |
| LLM Guard analyzer stays a no-op, throttled log lines `llm_guard.missing` or `llm_guard.build` | scanners such as PromptInjection, Toxicity, BanTopics, Jailbreak, Code, NoRefusal and Relevance download Hugging Face weights on first use; Sensitive needs spaCy `en_core_web_lg`. Offline hosts fail the download and the analyzer disables itself | pre-download on a connected machine (`python -c "from llm_guard.input_scanners import PromptInjection; PromptInjection()"`), copy `~/.cache/huggingface` and set `HF_HUB_OFFLINE=1`; or enable only the lightweight scanners (Settings > Integrations > LLM Guard, `needs_model_download` in the status lists the heavy ones) |
| NeMo Guardrails "cannot load config" or slow first request | the bundled default config in `aisrf/guardrails/nemo_default/` (`config.yml`, `rails.co`, `actions.py`) runs fully offline with no `models` section; a custom `config_path` that declares a model needs network access and credentials | keep the default for offline hosts; for a custom config set `integrations.nemo_guardrails.config_path` to a directory NeMo can load and test it with `nemoguardrails chat --config <dir>`; `GET /api/settings/guardrails` shows installed, enabled, configured and `last_error` per integration and `POST /api/settings/guardrails/health` (admin) runs a tiny scan through each enabled one |
| Lakera Guard errors | no `api_key`, or the endpoint (`https://api.lakera.ai/v2/guard`) is unreachable | set the key under Settings > Integrations > Lakera; the analyzer never blocks the gateway, failures are logged once (`log_throttled`) |
| pywebview window does not open | GTK, Qt or WebView2 runtime missing, or the binary is in use (it excludes pywebview) | the browser opens instead; install `pip install "aisrf[desktop]"` plus the GUI bindings, or accept the browser fallback |

## Database and process

| Symptom | Cause | Fix |
| --- | --- | --- |
| `sqlite3.OperationalError: database is locked` | another process holds a write lock longer than the 30 s busy timeout: a second `aisrf serve`, a CLI command running `init-db` during heavy load, a backup tool copying without `.backup`, or two pods sharing one PVC | run one process per SQLite file (Kubernetes uses `Recreate` for that reason), use `sqlite3 ... ".backup"` for backups, switch to PostgreSQL for multi-process setups |
| `attempt to write a readonly database` | wrong file ownership (service runs as `aisrf`, file created by root) or `ProtectSystem=strict` without the path in `ReadWritePaths` | `chown -R aisrf:aisrf /var/lib/aisrf`; keep the data directory under `/var/lib/aisrf` or add it to `ReadWritePaths` |
| `no such column` after an upgrade | `create_all` adds tables but never columns | apply the `ALTER TABLE` from the release notes, or start from a fresh database and import settings and agents |
| `[Errno 98] Address already in use` (`WinError 10048` on Windows) | port 8080 (or the requested `--port`) is taken, often by a previous instance | `ss -ltnp | grep 8080` or `netstat -ano | findstr :8080`, stop the other process, or use `aisrf serve --port 9000` / `AISRF_PORT`; desktop mode picks a free port unless `--port` is given |
| `/readyz` returns 500 while `/healthz` is fine | the database is unreachable (PostgreSQL down, wrong URL, missing `asyncpg`) | check `AISRF_DATABASE_URL`, `pip install "aisrf[postgres]"`, `psql` from the host |
| Gateway starts but logs the `auth.default_admin_password` warning | `AISRF_ADMIN_PASSWORD` is still `admin` | change it under Settings > Reviewers or set the variable before the first start |
| Stored upstream keys fail to decrypt (`cryptography.fernet.InvalidToken`) | `AISRF_SECRET_KEY` changed without a fixed `AISRF_ENCRYPTION_KEY`, or `aisrf.env` was regenerated | restore the old key from backup, or re-enter the upstream key on every agent |
| Second uvicorn worker never wakes waiting requests | the hold registry is in-process; other workers only poll the DB every `AISRF_HOLD_POLL_INTERVAL_SECONDS` | keep `AISRF_WORKERS=1` or accept up to one poll interval of extra latency |

## Platform specific

- Windows: `aisrf` is not recognised after `install.ps1` because the user `PATH` change applies to new terminals only; open a new PowerShell or run `%LOCALAPPDATA%\Programs\AISRF\aisrf\aisrf.exe` directly. With `-NoPath` add the folder yourself. SmartScreen: "More info > Run anyway". The installer refuses to overwrite while `aisrf.exe` runs: `Stop-Service AISRF` or close the desktop window first.
- macOS: "aisrf cannot be opened because the developer cannot be verified" means the quarantine attribute is set on a manual download; `xattr -dr com.apple.quarantine /usr/local/lib/aisrf` or allow it under System Settings > Privacy & Security. Intel Macs are not supported by the binaries; install with pip. launchd logs go to `/tmp/aisrf.launchd.log`.
- Linux: `ProtectHome=true` in the systemd unit hides `/home`, so a binary installed under `~/.local/lib/aisrf` cannot be executed by the service; install with `sudo` (to `/usr/local/lib/aisrf`) or under `/opt`. `~/.local/bin` is often not on `PATH` for non-login shells.
- Docker: `permission denied` on `/app/data` with a bind mount means the host directory is not writable by uid 10001; `chown -R 10001:10001 ./data ./logs` or use named volumes.

## CI failures

| Job | Typical failure | Fix |
| --- | --- | --- |
| `style guard` | an em dash (U+2014) anywhere in the tree, a merge marker, `ruff check scripts` | replace the character with a hyphen or comma; `python scripts/check_style.py` reproduces it locally |
| `ruff + pytest (py3.11 / py3.12)` | `ruff check aisrf tests examples` errors, a failing test, `tests/test_style.py` whitespace rules (trailing whitespace, consecutive blank lines in Markdown, YAML, TOML, HTML, JS, CSS, shell) | `make lint`, `.venv/bin/ruff check --fix`, fix the whitespace; run `.venv/bin/python -m pytest tests/test_style.py -q` |
| `binary smoke (linux x86_64)` | a lazily imported module missing from `HIDDEN_IMPORTS`, a package-data directory missing from `PACKAGE_DATA_DIRS`, or a traceback in the built binary's log | add the import or directory to `packaging/pyinstaller/manifest.py`; `tests/test_packaging.py::test_manifest_covers_every_package_data_directory` catches the second case without a build |
| `node sdk self-test` | `node sdk/node/test.js` failure or `npm pack --dry-run` including unwanted files | fix `sdk/node/index.js`, check `sdk/node/package.json` `files` |
| `docker build` | Dockerfile or dependency resolution error, `aisrf:ci version` or `init-db` failing | build locally with `docker build -t aisrf .` and run `docker run --rm -e AISRF_SECRET_KEY=x aisrf init-db` |
| `heavy extras` (weekly or manual) | garak, PyRIT, LLM Guard or NeMo API change | the tests skip when an engine is absent; a real failure needs a code change in `aisrf/scanners/` or `aisrf/guardrails/` |
| `Release / verify version` | tag `vX.Y.Z` does not match `aisrf.__version__` and `pyproject.toml` | `.venv/bin/python scripts/bump_version.py X.Y.Z`, commit, retag (see [[Releasing]]) |
| `Dependency review` | a new dependency with a high severity advisory | pin a fixed version or drop the dependency |
| `Wiki sync` | the wiki repository does not exist yet | create the first page in the GitHub UI once, then re-run the workflow |

## Collecting logs

1. Service log: `<log dir>/aisrf.jsonl` (JSON lines, rotating). Locations: `./logs` (pip), the app directory (binary, desktop), `/var/log/aisrf` (systemd), `/app/logs` volume (Docker), stdout in Kubernetes (`kubectl -n aisrf logs deploy/aisrf`). systemd also has `journalctl -u aisrf`, launchd `/tmp/aisrf.launchd.log`, Windows services `logs\service.out.log` and `service.err.log`.
2. Per-agent log: `<log dir>/agents/<agent_id>.jsonl`, and the same events in the database (`GET /api/agents/{id}/events`, Agent page, `aisrf/agents/service.py` AgentLogger).
3. Correlate with `request_id`: every response carries `X-Request-ID`; grep for it in `aisrf.jsonl`. Send your own `X-Request-ID` from clients to correlate multi-step agent runs.
4. Verbose: `AISRF_LOG_LEVEL=DEBUG` (restart), `AISRF_DB_ECHO=true` for SQL.
5. Ticket detail: `aisrf tickets show <id>` or `GET /api/tickets/{id}` includes the normalized request, findings, policy decision, events and the stored response.
6. Dashboard "Logs" page streams `/api/stream/logs` live and filters by agent.
7. When reporting a bug include `aisrf version`, the install method, the `aisrf.started` log line (version, environment, port, approval timeout) and the redacted `aisrf.jsonl` lines for the request id. Never paste `aisrf.env`, agent keys or upstream keys; headers stored on tickets are already redacted by `aisrf.security.redact_headers`.
