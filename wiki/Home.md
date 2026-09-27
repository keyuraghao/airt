# AISRF wiki

AISRF (AI Security & Research Framework, package `aisrf`, release v1.0.0) is a human-in-the-loop gateway that sits between LLM-powered applications or autonomous agents and the model providers or enterprise APIs they call. Every outbound request becomes a ticket. A ticket is analyzed, scored, run through a policy engine and, unless policy decides on its own, parked until a reviewer approves or denies it. Around that gate the project adds guardrail integrations, a red-team engine that drives its own probe corpus and external scanners through the same pipeline, static analysis of LLM application source code, reports in 13 formats, and an MCP server that exposes every reviewer action to AI assistants.

Source: https://github.com/keyuraghao/aisrf. License: Apache-2.0.

## The core guarantee

Nothing reaches the upstream without a decision. In `aisrf/gateway/router.py` the only path to the forwarder is through a ticket whose status is `APPROVED`, either because a reviewer approved it or because the agent's policy returned `approve`. Tickets that are `DENIED` (by policy or by a reviewer) or `EXPIRED` (no decision before `AISRF_APPROVAL_TIMEOUT_SECONDS`) are answered with an error and are never forwarded, and only `PENDING` tickets can be decided, so a ticket that expired cannot be approved afterwards. The client never holds the provider credential: the gateway strips the client's auth headers and injects the agent's Fernet-encrypted upstream key at forward time.

## Wiki map

### Start here

| Page | What it covers |
| --- | --- |
| [[Getting-Started]] | Install from source, first run, first agent, first approved ticket, async mode |
| [[Installation]] | Binaries, pip, Docker, Helm, service installs |
| [[Core-Concepts]] | Agents, tickets and statuses, risk, findings, policy, reviewers, scan tokens, canaries, campaigns |
| [[Glossary]] | Short definitions of every term |
| [[FAQ]] | Common questions |

### Gateway

| Page | What it covers |
| --- | --- |
| [[Architecture]] | Components, process model, data model, code layout |
| [[Gateway-Endpoints-and-Headers]] | `/v1/{path}`, `/proxy/{path}`, `/gateway/tickets/{id}`, every header and error body |
| [[Request-Normalization]] | What the parser understands and the normalized structure |
| [[Policy-Engine]] | Evaluation order, every rule, response withholding |
| [[Agents-and-Credentials]] | Every agent field, key rotation, upstream providers |
| [[Integrations-and-SDKs]] | Python SDK, Node package, mitmproxy addon, LangChain, curl |

### Review

| Page | What it covers |
| --- | --- |
| [[Tickets-and-Review-Workflow]] | Queue, ticket detail, decisions, bulk actions, keyboard shortcuts, expiry |
| [[Dashboard-Guide]] | Every dashboard page |
| [[Notifications]] | Slack and generic webhooks |
| [[Reports]] | Report types and the 13 output formats |

### Analysis and defense

| Page | What it covers |
| --- | --- |
| [[Analyzers]] | Request and response analyzers |
| [[Taxonomy-and-OWASP-Mapping]] | OWASP LLM Top 10, Greshake and Thacker mappings |
| [[Guardrails]] | LLM Guard, NeMo Guardrails, Lakera, Rebuff |
| [[TypeSafe-Integration]] | TypeSafe (Jev) decision layer: verdicts, confidence-gated escalation and routing, red-team and code review triage |
| [[Canary-Words]] | Canary injection and leak detection |
| [[Custom-Rules]] | Regex rules with flag or deny actions |

### Offense

| Page | What it covers |
| --- | --- |
| [[Red-Teaming]] | Campaigns, mutators, evaluators |
| [[Probe-Corpus]] | The probe corpus and its categories |
| [[Comparison-Groups]] | Same probes against several models |
| [[Scanner-Engines]] | garak, promptfoo, PyRIT, PyRIT-Ship |
| [[Code-Review]] | Static analysis of LLM application code |
| [[Code-Review-Rules]] | The rule packs |

### Operate

| Page | What it covers |
| --- | --- |
| [[Configuration-Reference]] | Every `AISRF_*` setting and every settings namespace |
| [[Settings-Center]] | The dashboard settings page, section by section |
| [[Logging-Metrics-and-Audit]] | Log files, event names, SSE streams, Prometheus metrics, audit chain |
| [[Security-Model]] | Threat model, secrets handling, roles, hardening checklist |
| [[Deployment]] | Compose, Postgres, TLS, Kubernetes |
| [[Desktop-Mode]] | `aisrf desktop` |
| [[Operations-and-Maintenance]] | Backups, retention, upgrades |
| [[Troubleshooting]] | Symptoms and fixes |

### Interfaces

| Page | What it covers |
| --- | --- |
| [[REST-API-Reference]] | Every endpoint |
| [[MCP-Server]] | MCP tools over streamable HTTP and stdio |
| [[CLI-Reference]] | Every `aisrf` command |

### Contribute

| Page | What it covers |
| --- | --- |
| [[Development-Guide]] | Repository layout, conventions, adding analyzers |
| [[Testing]] | Running the test suite |
| [[Releasing]] | Tagging and the release workflow |

## The 10-minute path

1. Clone and install into a virtual environment, then start the server (about two minutes):

   ```bash
   git clone https://github.com/keyuraghao/aisrf.git && cd aisrf
   uv venv .venv && uv pip install --python .venv/bin/python -e ".[dev]"
   .venv/bin/aisrf serve
   ```

2. Open http://localhost:8080 and sign in with `admin` / `admin` (the bootstrap account from `AISRF_ADMIN_USERNAME` and `AISRF_ADMIN_PASSWORD`).
3. Create an agent under Agents, paste your provider key as the upstream key, and copy the `aisrf_...` agent key. It is shown once.
4. Point a client at the gateway:

   ```python
   from openai import OpenAI
   client = OpenAI(base_url="http://localhost:8080/v1", api_key="aisrf_...", timeout=330, max_retries=0)
   client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hello"}])
   ```

5. The call blocks. A ticket appears in the queue at `/tickets` with its risk score and findings. Press `a` to approve it. The response arrives at the client with an `X-AISRF-Ticket` header.
6. Open `/audit` to see the hash-chained record of your decision.

The full walkthrough, including the asynchronous mode and the files the first run creates, is in [[Getting-Started]].

## Where to get help

* This wiki, starting with [[FAQ]] and [[Troubleshooting]].
* The interactive API documentation served by every instance at `/api/docs` (Swagger UI), `/api/redoc` and `/api/openapi.json`.
* The `docs/` directory of the repository, which holds the architecture, API, configuration, deployment, integrations, guardrails, red team, scanners, code review, reports, MCP and security documents.
* Every CLI command answers `--help`.
* Issues and discussions on GitHub: https://github.com/keyuraghao/aisrf/issues. Security reports follow the process in the repository's top-level `SECURITY.md`.
