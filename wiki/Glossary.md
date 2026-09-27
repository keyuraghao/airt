# Glossary

Domain terms used across AISRF and this wiki, each with a short definition and where it lives in the code.

**Agent**: a registered client application identified by an agent key. It carries the upstream provider, base URL, encrypted upstream key, policy settings, rate limit and tags (`aisrf/models.py::Agent`, [[Agents-and-Credentials]]).

**Agent key**: the `aisrf_` + `token_urlsafe(32)` credential a client sends instead of a provider key. Only its SHA-256 hash is stored; it is shown once at creation or rotation.

**Agent event**: a per-agent activity record written to `logs/agents/<id>.jsonl` and the `agent_events` table, streamed live on `/api/stream/logs`.

**Allowed paths and models**: per-agent globs (`allowed_paths`, `allowed_models`) that the policy engine checks before anything else; a mismatch auto-denies.

**Analyzer**: a pure, bounded callable with `name` and `analyze(normalized, context) -> list[Finding]`, registered with the runner as a request or response analyzer (`aisrf/analysis/`, [[Analyzers]]).

**App directory**: the per-user state directory used by binaries and desktop mode (`~/.local/share/aisrf`, `~/Library/Application Support/AISRF`, `%LOCALAPPDATA%\AISRF`), relocated with `AISRF_HOME` ([[Desktop-Mode]]).

**Approval timeout**: `AISRF_APPROVAL_TIMEOUT_SECONDS` (300), the time a synchronous request waits for a decision and the `expires_at` of async tickets.

**Async mode**: sending `X-AISRF-Async: 1`; the gateway returns 202 with a ticket id and the client polls `GET /gateway/tickets/{id}` instead of blocking.

**Audit log**: the hash-chained record of every privileged action (`audit_entries`), verified with `GET /api/audit/verify` or `aisrf audit verify` ([[Logging-Metrics-and-Audit]]).

**Auto-approve and auto-deny thresholds**: `auto_approve_below_risk` and `auto_deny_at_risk` on the agent (defaults from `AISRF_DEFAULT_AUTO_APPROVE_RISK_THRESHOLD` 0 and `AISRF_DEFAULT_AUTO_DENY_RISK_THRESHOLD` 90) that let policy decide without a human.

**Auto-deny patterns**: regexes on the agent or in the global policy namespace that deny a matching prompt outright.

**Bandit**: the Python security linter run as a code review engine when installed (`aisrf[codereview]`).

**Benign control**: probes in `benign_control.yaml` that a well-behaved model should answer; campaigns use them to measure over-blocking.

**Bulk decision**: approving or denying several tickets at once (`POST /api/tickets/bulk/approve`, `bulk/deny`, MCP bulk tools).

**Campaign**: a red-team run that drives a selected set of probes (optionally mutated) through the pipeline against one agent and model, with start, pause, resume and cancel ([[Red-Teaming]]).

**Canary word**: a unique secret token injected into the system prompt when `inject_canary` is on; its appearance in a response is a canary leak ([[Canary-Words]]).

**Code review run**: a static analysis job over source code from an archive, URL, git repository, local path or snippet, producing findings from the rules, semgrep, bandit and LLM engines ([[Code-Review]]).

**Comparison group**: several campaigns with the same probe set against different agents or models run in parallel, ranked with a heatmap and per-probe matrix ([[Comparison-Groups]]).

**Correlation id**: the `X-Request-ID` value echoed on every response and bound into every log line; clients may send their own to group multi-step runs.

**Custom rule**: a user-defined regex rule stored in the `rules` settings namespace with category, severity, scope (`request`, `response`, `both`) and action (`flag`, `deny`) ([[Custom-Rules]]).

**Decision**: the reviewer's approve or deny on a PENDING ticket, with an optional note, recorded as a ticket event and an audit entry.

**Desktop mode**: `aisrf desktop`, a loopback-only gateway with generated secrets that opens the dashboard in a window or browser ([[Desktop-Mode]]).

**Evaluator**: the verdict logic that turns a probe's `SubmitResult` into VULNERABLE, RESISTED, BLOCKED, ERROR or INCONCLUSIVE using refusal detection, success indicators, canary leaks and guardrail findings (`aisrf/redteam/evaluators.py`).

**Expired ticket**: a PENDING ticket past `expires_at`; the sweeper marks it EXPIRED and the synchronous caller receives 504.

**Fernet**: the symmetric encryption (AES-128-CBC + HMAC-SHA256) used for upstream keys and stored git credentials, keyed by `AISRF_ENCRYPTION_KEY` or a key derived from `AISRF_SECRET_KEY`.

**Finding**: one detection result with analyzer, category, severity, title, evidence, location, confidence, tags and taxonomy fields (OWASP, Greshake, Thacker).

**Forwarder**: the component that builds the upstream request with the agent's decrypted credential, sends it and relays the response (`aisrf/gateway/forwarder.py`).

**garak**: NVIDIA's LLM vulnerability scanner, driven as a subprocess against the gateway through its OpenAI-compatible generator ([[Scanner-Engines]]).

**Gateway**: the interception service as a whole, and specifically the `/v1/*`, `/proxy/*` and `/gateway/*` endpoints ([[Gateway-Endpoints-and-Headers]]).

**Generic proxy**: `POST /proxy/<provider path>` with `X-AISRF-Key`, for any HTTP backend not covered by the native `/v1` endpoints.

**Greshake taxonomy**: threat and delivery categories from "Not what you've signed up for" (2023) attached to findings and probes ([[Taxonomy-and-OWASP-Mapping]]).

**Guardrail**: an external defense framework wired in as analyzers: LLM Guard, NeMo Guardrails, Lakera Guard, Rebuff ([[Guardrails]]).

**Hold registry**: the in-process asyncio events (with DB polling fallback) that wake a waiting request when its ticket is decided (`aisrf/gateway/hold.py`).

**Interception mode**: how traffic reaches the gateway: SDK base URL, generic proxy, Python httpx patch, Node package, mitmproxy addon or programmatic `pipeline.submit()` ([[Integrations-and-SDKs]]).

**Judge (LLM judge)**: the optional analyzer pair that asks a configured model to grade requests and responses (`AISRF_ENABLE_LLM_JUDGE`).

**Lakera Guard**: a hosted prompt injection API used as request and response analyzers when an API key is configured.

**LLM Guard**: Protect AI's input and output scanners (PromptInjection, Toxicity, Secrets, Sensitive, ...) run as analyzers; most download model weights on first use.

**Matrix run**: a scanner run repeated across several target agents for side-by-side comparison.

**MCP server**: the Model Context Protocol surface exposing 44 tools mirroring every human action, over streamable HTTP at `/mcp` or stdio via `aisrf mcp` ([[MCP-Server]]).

**Mutator**: a text transform applied to probes to derive obfuscated variants: base64, rot13, leetspeak, reverse, split, suffix.

**NeMo Guardrails**: NVIDIA's rails framework; AISRF bundles an offline default config in `aisrf/guardrails/nemo_default/`.

**Normalized request**: the provider-agnostic shape (`messages`, `system`, `tools`, `model`, parameters) produced by `parser.normalize()` from OpenAI, Anthropic, Gemini, Ollama, Cohere or generic JSON bodies ([[Request-Normalization]]).

**OWASP LLM Top 10**: the 2025 list (LLM01 to LLM10) every finding category, probe and code review rule maps to.

**Policy engine**: `policy.evaluate()`, which decides auto-deny, auto-approve or human review from the agent settings, thresholds, patterns and global policy namespace ([[Policy-Engine]]).

**Principal**: the authenticated reviewer identity (username, role) resolved from a session cookie or the admin bearer token.

**Probe**: one attack (or benign control) from the YAML corpus with id, category, technique, severity, prompt or messages, expected behaviour and success indicators ([[Probe-Corpus]]).

**Probe result**: the stored outcome of one probe in a campaign, linked to its ticket, with verdict and evidence.

**promptfoo**: a Node-based evaluation and red-team tool run as a subprocess engine (`promptfoo eval`, optional `promptfoo redteam generate`).

**PyRIT and PyRIT-Ship**: Microsoft's red-team toolkit run in process or over HTTP, and the PyRIT-Ship compatible API that lets the Burp Suite extension target AISRF.

**Rate limit**: per-agent `rate_limit_per_minute`, enforced in memory per process; exceeding it returns 429.

**Rebuff**: layered prompt injection detection (heuristics, optional LLM and SDK layers) plus canary words, implemented natively in `aisrf/guardrails/rebuff.py`.

**Report**: a format-agnostic document (sections of key-values, tables, text, findings, charts) built per kind and rendered to twelve formats ([[Reports]]).

**Response withholding**: refusing to relay an approved upstream response (403 `response_withheld`) because of a canary leak or a critical output finding, while storing it for reviewers.

**Reviewer**: a dashboard user with role `viewer`, `reviewer` or `admin` ([[Security-Model]]).

**Risk score**: 0..100 aggregated from findings by `score_findings`, with levels NONE, LOW, MEDIUM, HIGH, CRITICAL.

**Rule pack**: one of six groups of original code review rules: prompt injection (PI), agent and tool abuse (AT), LLM output handling (LO), model and supply chain (MS), RAG poisoning and exfiltration (RG), general (GN) ([[Code-Review-Rules]]).

**Runtime settings**: overrides stored in `app_settings` and editable live under Settings, with precedence UI override > environment > code default ([[Settings-Center]]).

**SARIF**: Static Analysis Results Interchange Format 2.1.0; the code review export format accepted by GitHub code scanning.

**Scan token**: a short-lived agent credential minted for one scanner run and revoked when it ends, so external tools are ticketed like any client.

**Scanner engine**: an external tool integration implementing the `ScanEngine` protocol: garak, promptfoo, PyRIT, PyRIT-Ship ([[Scanner-Engines]]).

**Semgrep**: the pattern and taint analysis engine run over the AISRF rule files in `aisrf/codereview/rules/semgrep/`.

**Session cookie**: the itsdangerous-signed, HttpOnly, SameSite=Lax cookie for dashboard logins, `Secure` when `AISRF_COOKIE_SECURE=true`.

**SSE (Server-Sent Events)**: the live streams `/api/stream/tickets`, `/api/stream/logs` and `/api/stream/campaigns` used by the dashboard and `aisrf tickets watch`.

**Sweeper**: the background task in `aisrf/main.py` that expires stale tickets every 5 s and purges old ones hourly.

**Synchronous mode**: the default where the client's HTTP call blocks until a decision or the approval timeout.

**Taxonomy**: the shared mapping of categories and techniques to OWASP, Greshake and Thacker identifiers in `aisrf/taxonomy.py` ([[Taxonomy-and-OWASP-Mapping]]).

**Thacker techniques**: prompt injection technique labels from Joseph Thacker's Prompt Injection Primer attached to findings.

**Ticket**: the unit of review: one intercepted request with its normalized body, findings, risk score, policy decision, status and events; identified by `tkt_...` id and a sequential number ([[Tickets-and-Review-Workflow]]).

**Ticket status**: PENDING, APPROVED, DENIED, EXPIRED, FORWARDING, COMPLETED or FAILED (`aisrf/models.py::TicketStatus`).

**Upstream**: the model provider or enterprise backend the gateway forwards to, defined per agent by `upstream_provider` and `upstream_base_url`.

**Upstream key**: the real provider credential stored Fernet-encrypted on the agent and injected only at forward time; clients never see it.

**Verdict**: the campaign-level outcome of a probe: VULNERABLE, RESISTED, BLOCKED, ERROR, INCONCLUSIVE.

**Webhook notification**: Slack Block Kit or raw JSON messages sent for ticket events (`created`, `decided`, `completed`, `expired`, `failed`) to `AISRF_NOTIFY_WEBHOOK_URLS` ([[Notifications]]).
