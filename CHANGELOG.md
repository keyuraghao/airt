# Changelog

All notable changes to AISRF, the AI Security & Research Framework, are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each release tag `vX.Y.Z` corresponds to
a section below; `scripts/bump_version.py` turns the Unreleased section into the next release
heading (see `docs/RELEASING.md`).

## [Unreleased]

### Added

- TypeSafe decision layer (`aisrf/typesafe/`): `typesafe_guard` and `typesafe_response_guard`
  analyzers judge each request and response with one TypeSafe (Jev) call of typed questions and set
  a `malicious`, `benign` or `uncertain` verdict with a confidence; the analysis runner is phased so
  the LLM judge runs only for uncertain verdicts (`escalate_to_llm_judge`); optional confidence-gated
  policy routing (`typesafe.auto_deny`, `typesafe.auto_approve`); red-team evaluation that overrides
  the heuristics when confident; a `typesafe` code review engine that triages findings and introduces
  the `likely_false_positive` status (hidden by the default filter); `integrations.typesafe`
  settings, `GET /api/settings/typesafe/status` and `POST /api/settings/typesafe/health`; TypeSafe
  chips and answer tables on tickets and code review findings, a savings tile on the overview, new
  Prometheus metrics and `docs/TYPESAFE.md`.
- Repository governance: strict CI (ruff, pytest with coverage on Python 3.11 and 3.12, Node
  self-test, Docker build, style guard), tag-driven release workflow (wheel, sdist, CycloneDX SBOM,
  checksums, multi-arch image on GHCR, GitHub Release), CodeQL, dependency review, Dependabot,
  stale bot, label sync, issue and pull request templates, CODEOWNERS, Code of Conduct, release
  procedure and roadmap.
- `scripts/bump_version.py`, `scripts/check_style.py` and `scripts/changelog_notes.py`.

## [1.0.0] - 2026-09-26

Initial public release of AISRF, the AI Security & Research Framework.

### Added

- Self-contained native builds for Windows, macOS and Linux (PyInstaller bundles attached to every
  release), a `desktop` mode with per-user data directory and generated secrets, install scripts,
  and server deployment assets: systemd unit, launchd plist, Windows service scripts, Kubernetes
  manifests and a Helm chart.
- Source code review: static analysis of LLM application code from a zip, archive URL, git
  repository (token or SSH, credentials encrypted at rest), local path or pasted snippet, with
  92 original rules in six packs (prompt injection, agent and tool abuse, LLM output handling,
  model and supply chain, RAG poisoning and exfiltration, general), semgrep taint rules, bandit,
  an optional LLM-assisted pass, a findings triage UI, a file viewer and SARIF export for GitHub
  code scanning.
- Scanner engines driven through the gateway with short-lived scan tokens: garak, promptfoo, PyRIT
  (in-process target and HTTP mode) and a PyRIT-Ship compatible API for the Burp Suite extension;
  matrix runs compare several targets.
- Multi-model comparison groups for native campaigns with a heatmap, ranking, per-probe matrix
  and OWASP coverage; runtime settings center where every setting, analyzer, rule, integration and
  UI option is editable live, persisted and exportable; Rebuff-style canary injection with response
  withholding; defense integrations for Rebuff, LLM Guard, NeMo Guardrails and Lakera Guard.
- Gateway interception with human approval: every outbound LLM request from a registered agent
  becomes a ticket that is normalised, analysed, scored and held until a reviewer approves or
  denies it (`/v1/*` for OpenAI and Anthropic style SDKs via `base_url`, generic `/proxy/<path>` for
  any HTTP API). Synchronous mode blocks the caller; asynchronous mode (`X-AISRF-Async: 1`) returns
  `202` with a ticket id and `/gateway/tickets/{id}` polling. Approved requests are forwarded with
  the agent's Fernet-encrypted upstream credential (clients never see provider keys), streaming
  responses are relayed, denied and expired tickets never reach the provider (`403` / `504`).
- Request analyzers: prompt injection, jailbreak, PII (with Luhn and masked evidence), secrets,
  data exfiltration, tool abuse, harmful content, obfuscation (base64, hex, rot13, leetspeak,
  reversed text, homoglyphs, zero-width characters, payload splitting), anomaly and an optional
  LLM judge. Response analyzers: system prompt leak, refusal detection, canary leak and the judge's
  response variant. Findings carry OWASP LLM Top 10 (2025) ids; analyzers run concurrently and a
  failing analyzer never blocks the gateway. Risk score 0..100 with NONE / LOW / MEDIUM / HIGH /
  CRITICAL levels.
- Policy engine per agent: active flag, `allowed_paths` and `allowed_models` globs,
  `auto_deny_patterns` regexes, `auto_deny_at_risk` and `auto_approve_below_risk` thresholds,
  mandatory review of critical secret or exfiltration findings, `require_approval`, per-agent
  rate limit and request body size limit.
- Rebuff-style canary tokens: a canary can be injected into system prompts and a canary leak in
  the response is detected by the response analyzers; `block_on_canary_leak` policy setting.
- Runtime settings API and dashboard page (`/api/settings`): core settings with schema, per
  namespace documents for analyzers (disable, severity overrides, confidence floor, category
  weights), custom rules (flag or deny, request or response scope), integrations, UI and policy,
  with export and import and audit-logged changes.
- Red team corpus and engine: 300+ YAML probes across prompt injection, jailbreak, system prompt
  extraction, data exfiltration, PII leakage, tool abuse, harmful content, encoding attacks,
  multi-turn, many-shot, misinformation and hallucination, bias and fairness, privacy and
  memorisation, code safety, denial of wallet and benign controls. Mutators: base64, rot13,
  leetspeak, reverse, split, suffix. Campaigns run every probe through the gateway (one reviewable
  ticket per probe, or auto-run with `AISRF_REQUIRE_APPROVAL_FOR_REDTEAM_PROBES=false`) with
  start / pause / resume / cancel, results, summaries and VULNERABLE / RESISTED / BLOCKED / ERROR /
  INCONCLUSIVE verdicts.
- Guardrail integration settings for LLM Guard, NeMo Guardrails, Lakera Guard and Rebuff, and
  scanner integration settings for garak, promptfoo and PyRIT, with the matching optional
  extras (`aisrf[guardrails]`, `aisrf[scanners]`, `aisrf[all]`).
- Reports in 12 formats (`json`, `yaml`, `csv`, `tsv`, `md`, `html`, `pdf`, `xlsx`, `txt`, `xml`,
  `sarif`, `junit`) for summary, tickets, single ticket, agent, campaign and audit, via REST, the
  CLI, the dashboard and the MCP `generate_report` tool.
- Dashboard: server-rendered reviewer UI for tickets (live queue, findings, approve / deny with a
  note), agents, logs, red team campaigns, reports, audit and settings; roles `viewer` <
  `reviewer` < `admin`; signed `HttpOnly` session cookies; PBKDF2 password hashing.
- MCP server exposing every human action as a tool (tickets list / get / approve / deny and bulk,
  agents CRUD and key rotation, campaigns, reports, audit, reviewers, health, metrics) over
  streamable HTTP at `/mcp` and stdio (`aisrf mcp`), ready for Claude Desktop and Claude Code.
- CLI (`aisrf`): `serve`, `init-db`, `create-reviewer`, `agent create / list / rotate-key`,
  `tickets list / show / approve / deny / watch`, `redteam corpus / run`, `report`, `audit
  verify`, `mcp`, `version`.
- SDKs and interception helpers: Python `patch_httpx()` / `patch_requests()`, `AISRFClient` and
  `configure()`; the `aisrf-intercept` Node package (global `fetch` / undici wrapper,
  `configureOpenAI()`, `waitForTicket`); a mitmproxy addon for transparent interception.
- Hash-chained audit log of every privileged action with `GET /api/audit/verify` and `aisrf audit
  verify`; structlog JSONL logging (service and per-agent sinks, `X-Request-ID` correlation);
  Server-Sent Event streams for tickets, logs and campaigns; Slack and generic JSON webhook
  notifications; Prometheus metrics at `/metrics`; `/healthz` and `/readyz`.
- Docker: multi-stage image on `python:3.12-slim` running as a non-root user with a `/healthz`
  HEALTHCHECK and volumes for `/app/data` and `/app/logs`; `docker-compose.yml` with an optional
  PostgreSQL profile; SQLite by default, PostgreSQL via `aisrf[postgres]`.
- Documentation: architecture, API, configuration, integrations, deployment, security model,
  MCP, red teaming, reports, runnable examples (OpenAI sync and async, Anthropic, LangChain,
  tool-using agent loop, curl).

### Security

- Agent keys are stored as SHA-256 hashes; upstream provider keys are Fernet-encrypted at rest and
  injected only at forward time; client credential headers are stripped before forwarding and
  stored headers are redacted; bearer token comparison is constant time.

[Unreleased]: https://github.com/keyuraghao/aisrf/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/keyuraghao/aisrf/releases/tag/v1.0.0
