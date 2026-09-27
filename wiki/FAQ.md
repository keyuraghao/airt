# FAQ

Short answers with pointers to the detailed pages. Concepts are defined in [[Glossary]].

## General

**What is AISRF?**
AISRF, the AI Security & Research Framework, is a human-in-the-loop gateway between LLM-powered applications or agents and the backends they call. Every outbound request becomes a ticket a reviewer approves or denies; around that gate it adds analyzers, guardrail integrations, a red-team engine, scanner integrations, source code review, reports and an MCP server. See [[Home]] and [[Architecture]].

**Is it a general-purpose API gateway or load balancer?**
No. `docs/ROADMAP.md` lists that explicitly under "Not planned". It forwards one request to the provider recorded on the agent and holds it for review; it does not route, cache or balance.

**Does it replace the human reviewer?**
No. Analyzers rank and gate through the configured thresholds (`auto_deny_at_risk`, `auto_approve_below_risk`, patterns, allowed paths and models); everything between the thresholds waits for a person.

**What is the license?**
Apache License 2.0, copyright 2026 Keyur Aghao. Source: github.com/keyuraghao/aisrf.

**Which Python versions are supported?**
3.11 and 3.12 (`requires-python = ">=3.11"`, CI matrix 3.11 and 3.12). The binaries and the container image need no Python at all.

## Installing and running

**Which install path should I choose?**
Laptop or evaluation: a binary plus `aisrf desktop`. Server: binary with systemd, launchd or the Windows service. Containers: `ghcr.io/keyuraghao/aisrf`. Clusters: the Helm chart. Development or optional engines: pip with extras. [[Installation]].

**Where is my data?**
pip: `./data` and `./logs` in the working directory. Binary and desktop mode: `~/.local/share/aisrf` (Linux), `~/Library/Application Support/AISRF` (macOS), `%LOCALAPPDATA%\AISRF` (Windows). Services: `/var/lib/aisrf`, `%ProgramData%\AISRF`. Containers: `/app/data`, `/app/logs`. `AISRF_HOME` relocates the app directory. [[Desktop-Mode]].

**What are the default credentials?**
`admin` / `admin`. A warning (`auth.default_admin_password`) is logged until you change it under Settings > Reviewers or set `AISRF_ADMIN_PASSWORD` before the first start.

**Why does the binary generate an `aisrf.env`?**
So a first run is secure without configuration: it holds a random `AISRF_SECRET_KEY` (session signing and credential encryption) and `AISRF_ADMIN_API_TOKEN` (CLI and MCP). Keep the file private and back it up with the database.

**Can I run it on an Intel Mac?**
Not from the binaries (Apple silicon only). Use `pipx install "git+https://github.com/keyuraghao/aisrf.git"` or Docker.

**How much disk and memory does it need?**
The binary is about 130 MB unpacked; the container requests 256Mi and is limited to 1Gi in the manifests. The optional ML extras (`guardrails`, `scanners`) add several gigabytes of dependencies and model weights.

**Can I run more than one worker or replica?**
Supported topology is one process. Decisions wake waiting requests through an in-process registry; other processes fall back to DB polling every `AISRF_HOLD_POLL_INTERVAL_SECONDS`, and the rate limiter, SSE broadcaster and metrics are per process. Use PostgreSQL if you do scale out. [[Deployment]].

**SQLite or PostgreSQL?**
SQLite (WAL mode) for one host and one process. PostgreSQL (`aisrf[postgres]`, `postgresql+asyncpg://...`) when several processes share the database, for rolling updates or autoscaling, or for point-in-time recovery.

## Gateway behaviour

**How do I point my application at the gateway?**
OpenAI SDK: `base_url="http://gw:8080/v1"`, `api_key="aisrf_..."`. Anthropic SDK: `base_url="http://gw:8080"`. Any other HTTP API: `POST /proxy/<provider path>` with `X-AISRF-Key`. Python without code changes: `aisrf.integrations.python_sdk.patch_httpx()`. Node: the `aisrf-intercept` package. Nothing else: the mitmproxy addon. [[Integrations-and-SDKs]].

**Where does the real provider key live?**
On the agent record, Fernet-encrypted with `AISRF_ENCRYPTION_KEY` or a key derived from `AISRF_SECRET_KEY`. Clients only hold the `aisrf_...` agent key; the gateway swaps in the provider key at forward time and strips client credential headers.

**What happens while a request waits?**
Synchronous mode: the HTTP call blocks up to `AISRF_APPROVAL_TIMEOUT_SECONDS` (300 s) and then receives 504 with code `expired`. Asynchronous mode (`X-AISRF-Async: 1`): the gateway answers 202 with a ticket id and the client polls `GET /gateway/tickets/{id}`. [[Tickets-and-Review-Workflow]].

**Why did my request get a 403 without anyone reviewing it?**
Policy auto-denied it: risk score at or above the agent's `auto_deny_at_risk`, an `auto_deny_patterns` match, a path or model outside `allowed_paths` / `allowed_models`, or a custom rule with action `deny`. The ticket shows the reason. [[Policy-Engine]].

**Are streaming responses supported?**
Yes. Approved `stream: true` requests are relayed chunk by chunk and captured up to `AISRF_MAX_STORED_RESPONSE_BYTES` (512 KiB). Proxies must not buffer (`proxy_buffering off`, Caddy `flush_interval -1`).

**Which providers are normalised natively?**
OpenAI chat, completions, responses and embeddings, Anthropic messages, plus Gemini, Ollama and Cohere shapes; anything else goes through `/proxy/<path>` and is analysed as generic JSON. [[Request-Normalization]].

**Can a denied request still reach the provider?**
No. Denied and expired tickets never leave the gateway; the client receives 403 or 504.

**What is a canary word?**
A unique secret token appended to the system prompt when the agent has `inject_canary` enabled. If it shows up in the response, the response analyzers flag a leak and the policy (`block_on_canary_leak`, default true) withholds the response with 403 `response_withheld`. [[Canary-Words]].

## Review, analysis and reporting

**What roles exist?**
`viewer` < `reviewer` < `admin`. The static `AISRF_ADMIN_API_TOKEN` carries the admin role for automation. [[Security-Model]].

**Can I review from the terminal or from an AI assistant?**
Yes: `aisrf tickets list | show | approve | deny | watch` against a running gateway, and 44 MCP tools over `/mcp` (streamable HTTP) or `aisrf mcp` (stdio) for Claude Desktop, Claude Code or any MCP client. [[CLI-Reference]], [[MCP-Server]].

**How is the risk score computed?**
Every registered analyzer returns findings with a severity and confidence; `score_findings` aggregates them into 0..100 with levels NONE, LOW, MEDIUM, HIGH, CRITICAL. Analyzer weights, severity overrides and a confidence floor are editable under Settings > Analyzers. [[Analyzers]].

**Do the analyzers call an external model?**
Only the optional LLM judge (`AISRF_ENABLE_LLM_JUDGE=true`, `AISRF_JUDGE_PROVIDER`, `AISRF_JUDGE_API_KEY`, `AISRF_JUDGE_MODEL`) and the hosted Lakera Guard integration. Everything else is local heuristics or local models (LLM Guard, NeMo).

**Can I add my own detection rules without code?**
Yes: Settings > Rules stores regex rules with a category, severity, scope (`request`, `response`, `both`) and action (`flag` or `deny`) in the `rules` namespace. [[Custom-Rules]].

**Which report formats exist?**
json, yaml, csv, tsv, md, html, pdf, xlsx, txt, xml, sarif and junit for the kinds summary, tickets, ticket, agent, campaign, audit and codereview, via `GET /api/reports/...`, `aisrf report`, the Reports page and the MCP `generate_report` tool. [[Reports]].

**Is the audit log tamper-evident?**
Yes. Entries form a SHA-256 hash chain; `GET /api/audit/verify` or `aisrf audit verify` recomputes it and reports the first broken link. [[Logging-Metrics-and-Audit]].

**How do I get notified about new tickets?**
`AISRF_NOTIFY_WEBHOOK_URLS` with Slack incoming webhooks (Block Kit messages) or any JSON endpoint; events `created`, `decided`, `completed`, `expired`, `failed`; `AISRF_NOTIFY_MIN_RISK` filters by score. [[Notifications]].

## Red teaming and code review

**Do red-team probes need approval too?**
By default yes (`AISRF_REQUIRE_APPROVAL_FOR_REDTEAM_PROBES=true`): every probe is a ticket. Set it to `false` to run campaigns unattended; probes are still analysed, logged and audited. [[Red-Teaming]].

**How big is the probe corpus?**
303 probes in 16 YAML categories under `aisrf/redteam/corpus/`, with mutators base64, rot13, leetspeak, reverse, split and suffix. [[Probe-Corpus]].

**Can I run garak, promptfoo or PyRIT through AISRF?**
Yes. `/api/scanners/{garak|promptfoo|pyrit|pyrit_ship}` mints a short-lived scan token for the target agent, runs the tool against the gateway and imports the results as probe results with linked tickets. garak and PyRIT need `aisrf[scanners]`; promptfoo is a Node binary. [[Scanner-Engines]].

**What does source code review scan?**
A zip, tar, archive URL, git repository (token or SSH), local path or pasted snippet, with 92 original rules in six packs, semgrep taint rules, bandit and an optional LLM pass; SARIF output uploads to GitHub code scanning. [[Code-Review]].

**Why does installing semgrep change my `mcp` version?**
`semgrep` pins `mcp==1.29.0`. AISRF supports both mcp 1.x and 2.x, so this is harmless. [[Troubleshooting]].

## Operations

**How do I rotate a leaked agent key?**
`POST /api/agents/{id}/rotate-key`, `aisrf agent rotate-key <id>`, the Agents page or the MCP tool `rotate_agent_key`. The old key stops immediately. [[Operations-and-Maintenance]].

**What must I back up?**
The database and the key material (`AISRF_SECRET_KEY`, `AISRF_ENCRYPTION_KEY` if set). Without the key the encrypted upstream credentials cannot be recovered.

**How long are tickets kept?**
`AISRF_TICKET_RETENTION_DAYS` (default 90; 0 keeps everything). The sweeper purges older tickets hourly; logs rotate at 50 MB x 10 and 20 MB x 5 per agent.

**Are there database migrations?**
Not yet. `create_all` creates new tables on start; column changes ship with notes until Alembic migrations arrive (listed under "Later" in the roadmap).

**How do I upgrade?**
Re-run the installer (binary), `pipx upgrade aisrf` (pip), pull the new image tag (Docker, Kubernetes, Helm), then restart. Back up first before a major version. [[Operations-and-Maintenance]].

**How do I report a security issue?**
Privately, through GitHub's "Report a vulnerability" under the Security tab or by email to the maintainers; do not open a public issue. Acknowledgement within 3 business days, fix or mitigation within 30 days for high severity. `SECURITY.md`.

**Where do I find the full configuration list?**
`.env.example` and `docs/CONFIGURATION.md` in the repository, or [[Configuration-Reference]] here. Most values are also editable live from Settings, except the locked ones (`database_url`, `host`, `port`, `workers`, directories, `secret_key`, `encryption_key`).
