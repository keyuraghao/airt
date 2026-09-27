# Roadmap

This page lists what the maintainers of Airt, the AI Security & Research Framework, intend to work on next. It is a statement of direction, not a
schedule; items move as feedback comes in. Discuss an item by opening an issue with the `roadmap`
label, or a Discussion for early ideas. Shipped items move to `CHANGELOG.md`.

## Near term

| Item | Why | Notes |
| --- | --- | --- |
| PostgreSQL and Redis hold registry | Today a waiting synchronous request is woken instantly only by a decision in the same process; other workers rely on DB polling. A shared registry (PostgreSQL `LISTEN` / `NOTIFY` or Redis pub/sub) makes `--workers > 1` and separate MCP hosts first class. | Keep the in-process registry as the default for single-node deployments. Rate limiter, SSE broadcaster and metrics follow the same path. |
| SSO / OIDC for the dashboard | Reviewer accounts with local passwords do not fit enterprises. | OIDC login with role mapping from groups, per-reviewer MCP tokens, local accounts kept for break-glass. |
| More providers | Native normalisation for Gemini, Mistral, Groq, Cohere, Bedrock and Azure OpenAI endpoints beyond the generic `/proxy/` path. | Parser and forwarder work; provider specific streaming formats. |
| More scanners | Deeper garak, promptfoo and PyRIT integration: launch scans from the dashboard and CLI, import their findings as campaign results. | Runtime settings already hold the integration configuration. |
| RBAC per agent | Restrict which reviewers may see and decide tickets of a given agent (team or tenant boundaries). | Agent ownership, reviewer groups, enforced in the API, dashboard and MCP tools. |
| Fine-grained retention | Per-agent retention, redaction of stored prompts and responses after N days while keeping ticket metadata and the audit chain. | Extends `AIRT_TICKET_RETENTION_DAYS`. |
| Webhooks for decisions | Notify external systems (SIEM, ticketing, chat) when a ticket is approved, denied or expired, with signed payloads and retries. | Builds on the existing Slack / JSON notifications for created, expired and failed tickets. |
| Helm chart | Kubernetes deployment with PostgreSQL, ingress timeouts suited to long held requests, and secrets management. | Published from this repository alongside the container image. |

## Later

* Alembic schema migrations.
* Semantic (embedding based) analyzers and adaptive multi-turn red-team strategies.
* Policy simulation: replay last week's traffic against a proposed rule set.
* OpenTelemetry traces across the gateway and upstream calls.
* Signed release artifacts (Sigstore) and PyPI publishing through trusted publishing.

## Not planned

* Acting as a general purpose API gateway or load balancer.
* Replacing the human reviewer: analyzers rank and gate, they do not decide on their own beyond the
  configured thresholds.
