<p align="center">
  <img src="docs/images/brand/README-hero.png" alt="AISRF, AI Security & Research Framework" width="100%">
</p>

<p align="center">
  <a href="https://github.com/keyuraghao/aisrf/actions/workflows/ci.yml"><img src="https://github.com/keyuraghao/aisrf/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/keyuraghao/aisrf/releases"><img src="https://img.shields.io/github/v/release/keyuraghao/aisrf?include_prereleases&label=release" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12-3776AB?logo=python&logoColor=white" alt="Python">
  <a href="https://github.com/keyuraghao/aisrf/pkgs/container/aisrf"><img src="https://img.shields.io/badge/ghcr.io-keyuraghao%2Faisrf-24292e?logo=docker" alt="Container"></a>
</p>

# AISRF, the AI Security & Research Framework

AISRF sits between your LLM-powered applications or autonomous agents and the backends they call. Every outbound request, from any agent, through any SDK, becomes a ticket that a human must approve or deny before it reaches the model provider or your enterprise systems. Around that gate it adds automated risk analysis, defense guardrails, a red-team engine that drives the industry's scanners through the same review pipeline, static analysis of LLM application source code, reporting in every practical format, and an MCP server that exposes every human action to AI assistants.

## Why

Agentic systems issue thousands of model calls nobody reads. Prompt injection, data exfiltration and tool abuse ride along inside them. AISRF makes the traffic visible and reviewable, records everything with a tamper-evident audit trail, and lets a security team test the same models offensively with a corpus of 300+ probes plus garak, promptfoo and PyRIT, all through one gateway with one set of logs.

## Screenshots

| Review queue | Ticket detail with findings and OWASP mapping |
| --- | --- |
| ![Queue](docs/images/screenshots/tickets.png) | ![Ticket](docs/images/screenshots/ticket-detail.png) |

| Red team campaigns | Campaign results |
| --- | --- |
| ![Red team](docs/images/screenshots/redteam.png) | ![Campaign](docs/images/screenshots/campaign.png) |

| Overview | Source code review |
| --- | --- |
| ![Overview](docs/images/screenshots/overview.png) | ![Code review](docs/images/screenshots/codereview.png) |

| Agents and live logs | Settings center |
| --- | --- |
| ![Agent](docs/images/screenshots/agent-detail.png) | ![Settings](docs/images/screenshots/settings.png) |

Every setting is editable live. The settings center has fifteen sections; a few of them:

| Integrations (TypeSafe, LLM Guard, NeMo, Lakera, scanners) | Custom detection rules |
| --- | --- |
| ![Integrations](docs/images/screenshots/settings-integrations.png) | ![Rules](docs/images/screenshots/settings-rules.png) |

| Analyzers | Policy |
| --- | --- |
| ![Analyzers](docs/images/screenshots/settings-analyzers.png) | ![Policy](docs/images/screenshots/settings-policy.png) |

## Architecture

![Architecture](docs/images/architecture.png)

Every request follows the same lifecycle: authenticate the agent key, normalize the body (OpenAI, Anthropic, Gemini, Ollama, Cohere or any JSON), run the analyzers and guardrails, apply policy, park the request as a PENDING ticket until a reviewer decides, inject a canary into the system prompt, forward with the agent's encrypted upstream credential, scan the response, then relay it or withhold it.

![Request lifecycle](docs/images/request-lifecycle.png)

The TypeSafe decision layer (request and response guard, confidence-gated routing, red-team evaluator, code review triage, savings model):

![TypeSafe decision layer](docs/images/typesafe-decision-layer.png)

More diagrams in [docs/DIAGRAMS.md](docs/DIAGRAMS.md): ticket state machine, red-team flow, deployment topology and the OWASP taxonomy matrix.

## Capabilities

- **Interception gateway**: OpenAI and Anthropic compatible endpoints under `/v1/*`, a generic `/proxy/<path>` for any HTTP backend, synchronous hold (the client blocks until a human decides) or asynchronous mode (`X-AISRF-Async: 1`, then poll). Streaming responses are relayed and captured. Denied or expired tickets never reach the provider.
- **Human review**: dashboard queue with live updates, keyboard shortcuts, bulk decisions, notes for the audit trail; the same actions via REST, CLI, MCP tools and Slack or webhook notifications.
- **Analysis**: prompt injection, jailbreak, PII (with Luhn, IBAN and national id validation), secrets, data exfiltration, tool abuse, harmful content, obfuscation, anomalies, optional LLM judge; response analyzers for system prompt leaks, PII and secret leaks, refusals, harmful compliance, exfil markers and canary leaks. Every finding carries OWASP LLM Top 10, Greshake and Thacker taxonomy tags.
- **Defense integrations**: Rebuff-style layered detection and canary words, LLM Guard input and output scanners, NeMo Guardrails (bundled offline rails), Lakera Guard API. All are toggled and configured live from Settings.
- **TypeSafe decision layer**: one call to TypeSafe AI's Jev model judges every request and response with typed questions (nine attack nouls, an intent choice, a severity score) in about 100 ms; confident verdicts skip the LLM judge, optionally auto-deny or auto-approve tickets, override red-team heuristics and mark code review findings as likely false positives, with a live savings estimate versus an LLM judge.
- **Policy engine**: per-agent allowed paths and models, auto-deny regexes, risk thresholds for auto-deny and auto-approve, global rules, custom regex rules with flag or deny actions, response withholding on canary leaks or critical output findings.
- **Red teaming**: 303-probe corpus in 16 categories with mutators (base64, rot13, leetspeak, reverse, split, suffix), campaigns that run every probe through the ticket pipeline, evaluators (refusal, canary, success indicators, guardrail findings), summaries with OWASP coverage, and comparison groups that run the same probe set against several models in parallel with a heatmap and ranking.
- **Scanner engines**: garak, promptfoo, PyRIT (in-process target and HTTP mode) and a PyRIT-Ship compatible API so the Burp Suite extension can point at AISRF. External tools authenticate with short-lived scan tokens, so their traffic is ticketed like anything else. Matrix runs compare targets side by side.
- **Source code review**: static analysis of LLM application code from a zip, an archive URL, a git repository (token or SSH), a local path or a pasted snippet. 92 original rules in six packs (prompt injection, agent and tool abuse, LLM output handling, model and supply chain, RAG poisoning and exfiltration, general), plus semgrep taint rules, bandit and an optional LLM-assisted pass. SARIF output uploads to GitHub code scanning.
- **Reports**: every report (platform summary, tickets, single ticket dossier, agent, campaign, code review, audit) in json, yaml, csv, tsv, md, html, pdf, xlsx, txt, xml, sarif and junit.
- **Settings center**: every configuration value, analyzer toggle, severity override, custom rule, integration credential, UI theme and brand is editable from the dashboard, persisted in the database, exportable and importable as JSON.
- **Logging and audit**: structured JSON logs for the service and one file per agent, per-agent event history in the database, live SSE streams, Prometheus metrics, and a SHA-256 hash-chained audit log with on-demand verification.
- **MCP server**: 44 tools mirroring every human action (tickets, agents, campaigns, scanners, code review, reports, audit, reviewers), over streamable HTTP at `/mcp` or stdio via `aisrf mcp`.

## Quick start

```bash
git clone https://github.com/keyuraghao/aisrf.git && cd aisrf
uv venv .venv && uv pip install --python .venv/bin/python -e ".[dev]"
.venv/bin/aisrf serve
```

Open http://localhost:8080, sign in with `admin` / `admin` (set `AISRF_ADMIN_PASSWORD` before exposing the service), create an agent under Agents and copy its key once. Then point any client at the gateway:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="aisrf_...")
client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hello"}])
```

The call blocks, a ticket appears in the queue, and the response arrives when a reviewer approves it. The frontend never holds the real provider key; the gateway swaps it in from the agent's encrypted credential.

Docker:

```bash
docker run -p 8080:8080 -v aisrf-data:/app/data -v aisrf-logs:/app/logs -e AISRF_ADMIN_PASSWORD=change-me ghcr.io/keyuraghao/aisrf:latest
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for compose, Postgres and TLS.

## Install

No Python required: every release ships self-contained binaries for Linux (x86_64, arm64), macOS (Apple silicon) and Windows (x86_64), verified by SHA256.

```bash
# Linux and macOS
curl -fsSL https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.sh | bash
aisrf desktop                                  # local dashboard in a window or your browser
```

```powershell
# Windows (PowerShell)
irm https://raw.githubusercontent.com/keyuraghao/aisrf/main/scripts/install.ps1 | iex
aisrf desktop
```

```bash
# Containers and clusters
docker run -d -p 127.0.0.1:8080:8080 -v aisrf-data:/app/data -e AISRF_ADMIN_PASSWORD=change-me ghcr.io/keyuraghao/aisrf:latest
helm install aisrf deploy/helm/aisrf -n aisrf --create-namespace --set secretEnv.AISRF_SECRET_KEY=$(openssl rand -hex 32)
```

`aisrf desktop` (or `aisrf-desktop` from a `pip install "aisrf[desktop]"`) starts the gateway on 127.0.0.1, generates a random secret key and admin API token in a per-user `aisrf.env` on first run and opens the dashboard. Server installs (systemd, launchd, Windows service, Kubernetes manifests), pip/pipx, upgrade and uninstall steps for every path: [docs/INSTALL.md](docs/INSTALL.md).

## Interception modes

| Mode | How |
| --- | --- |
| SDK base URL | OpenAI SDK `base_url=http://gw/v1`, Anthropic SDK `base_url=http://gw`, key = agent key |
| Generic proxy | `POST http://gw/proxy/<provider path>` with `X-AISRF-Key` |
| Python patch | `aisrf.integrations.python_sdk.patch_httpx()` rewrites provider hosts for httpx and requests |
| Node package | `sdk/node`: `install({gatewayUrl, agentKey})` wraps global fetch and undici |
| Transparent | `mitmdump -s aisrf/integrations/mitm_addon.py` with the mitmproxy CA on the client |
| Programmatic | `aisrf.gateway.pipeline.submit()` from inside the process (used by the red-team engines) |

## Works with any provider

The gateway is provider-agnostic. The client keeps using its normal SDK and request format; the agent record decides where the request goes and which credential is swapped in. One agent equals one upstream, so create one agent per provider (or per application and provider).

| `upstream_provider` | Typical `upstream_base_url` | Header AISRF injects | Client |
| --- | --- | --- | --- |
| `openai` | `https://api.openai.com/v1` | `Authorization: Bearer` | OpenAI SDK, `base_url=http://gw/v1` |
| `anthropic` | `https://api.anthropic.com/v1` | `x-api-key` and `anthropic-version` | Anthropic SDK, `base_url=http://gw` |
| `groq`, `together`, `mistral`, `deepseek`, `openrouter` | the provider's OpenAI-compatible URL | `Authorization: Bearer` | OpenAI SDK |
| `ollama` | `http://localhost:11434/v1` | `Authorization: Bearer` (optional) | OpenAI SDK |
| `azure` | your Azure OpenAI deployment URL | `api-key` | OpenAI SDK or curl via `/proxy/` |
| `google` | `https://generativelanguage.googleapis.com` | `x-goog-api-key` | Gemini SDK or curl via `/proxy/` |
| `custom` | any HTTP API | the header you name in `upstream_auth_header` | anything, via `/proxy/<path>` |

Requests are forwarded unchanged. AISRF analyzes OpenAI chat, completions, responses and embeddings, Anthropic messages, Gemini, Ollama, Cohere and generic JSON bodies, but it does not translate between formats, so the SDK must speak the format of the upstream the agent points at.

```python
# OpenAI, or any OpenAI-compatible provider (Groq, Together, Mistral, DeepSeek, OpenRouter, Ollama, vLLM)
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="aisrf_...", timeout=330, max_retries=0)
client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "hello"}])
```

```python
# Anthropic: agent created with upstream_provider="anthropic"
from anthropic import Anthropic
client = Anthropic(base_url="http://localhost:8080", api_key="aisrf_...", timeout=330, max_retries=0)
client.messages.create(model="claude-3-5-sonnet-latest", max_tokens=200, messages=[{"role": "user", "content": "hello"}])
```

```bash
# Gemini, or any other HTTP API, through the generic proxy: agent created with upstream_provider="google"
curl -X POST http://localhost:8080/proxy/v1beta/models/gemini-1.5-flash:generateContent \
  -H "X-AISRF-Key: aisrf_..." -H "Content-Type: application/json" \
  -d '{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}'
```

```bash
# Local Ollama: agent created with upstream_provider="ollama" and upstream_base_url="http://localhost:11434/v1"
curl http://localhost:8080/v1/chat/completions -H "Authorization: Bearer aisrf_..." -H "Content-Type: application/json" \
  -d '{"model":"llama3.1","messages":[{"role":"user","content":"hello"}]}'
```

Set `timeout` above the approval hold (300 seconds by default) and `max_retries=0`, otherwise the SDK retries a request a human is still deciding on. Applications that cannot wait send `X-AISRF-Async: 1` and poll `/gateway/tickets/{id}` instead.

### TypeSafe decision layer

Optionally, AISRF asks [TypeSafe AI](https://typesafe.ai)'s System One model (Jev) to judge each intercepted conversation. Rather than generating text, Jev answers a battery of typed questions in one parallel call (yes/no probabilities, a choice with per-option probabilities, a score on a rubric), each with a confidence, in roughly 100 ms and at about $0.042 per million input tokens with free output. AISRF turns the answers into findings with a `malicious`, `benign` or `uncertain` verdict; when the verdict is confident the LLM judge is skipped (`escalate_to_llm_judge` runs it only for uncertain cases), and with `auto_route` on the policy engine denies malicious requests and approves benign ones above configurable confidences so the human queue only receives what the model could not settle. The same layer evaluates red-team probe results and triages code review findings (`likely_false_positive`). Export `TYPESAFE_API_KEY` or paste the key in Settings > Integrations > typesafe, switch it on, and watch the savings tile on the overview page. Details in [docs/TYPESAFE.md](docs/TYPESAFE.md).

## Red teaming and scanners

```bash
aisrf redteam run --agent <agent id> --model gpt-4o-mini --category prompt_injection --category system_prompt_extraction --wait
```

Campaigns and comparison groups are created from the dashboard, the API or MCP. Each probe is a ticket: reviewers see exactly what is sent, and policy can block probes automatically. Scanner runs (`/api/scanners/{garak|promptfoo|pyrit|pyrit_ship}`) mint a scan token for the target agent, execute the tool, and import its results as probe results with linked tickets. Details in [docs/REDTEAM.md](docs/REDTEAM.md) and [docs/SCANNERS.md](docs/SCANNERS.md).

## Source code review

```bash
aisrf codereview run --git https://github.com/org/app --ref main --token-env GITHUB_TOKEN --wait --format sarif --out app.sarif
```

Rules are mapped to OWASP LLM Top 10 ids and CWEs, findings can be triaged as false positive or accepted, and a file viewer highlights the exact lines. Details and the full rule table in [docs/CODE_REVIEW.md](docs/CODE_REVIEW.md).

## MCP server

Add AISRF to Claude Desktop, Claude Code or any MCP client:

```json
{"mcpServers": {"aisrf": {"command": "aisrf", "args": ["mcp", "--url", "http://localhost:8080", "--token", "<AISRF_ADMIN_API_TOKEN>"]}}}
```

Or connect over HTTP to `http://localhost:8080/mcp` with `Authorization: Bearer <AISRF_ADMIN_API_TOKEN>`. See [docs/MCP.md](docs/MCP.md).

## CLI

`aisrf serve | init-db | create-reviewer | agent create/list/rotate-key | tickets list/show/approve/deny/watch | redteam corpus/run | codereview run/list/show/rules | report | audit verify | mcp | version`. Every command has `--help`.

## Configuration

All settings are environment variables with the `AISRF_` prefix (see [.env.example](.env.example) and [docs/CONFIGURATION.md](docs/CONFIGURATION.md)) and most can be overridden live from Settings. The important ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `AISRF_DATABASE_URL` | `sqlite+aiosqlite:///./data/aisrf.db` | SQLite or `postgresql+asyncpg://...` |
| `AISRF_SECRET_KEY` | change it | sessions and credential encryption key derivation |
| `AISRF_ADMIN_PASSWORD` | `admin` | first admin password |
| `AISRF_ADMIN_API_TOKEN` | unset | bearer token for CLI, MCP and automation |
| `AISRF_APPROVAL_TIMEOUT_SECONDS` | `300` | how long a synchronous request waits for a human |
| `AISRF_NOTIFY_WEBHOOK_URLS` | empty | Slack or JSON webhooks for pending tickets |
| `AISRF_ENABLE_LLM_JUDGE` | `false` | LLM-as-judge analyzer and rubric passes |

## Security model

Upstream provider keys are stored encrypted (Fernet) and never sent to clients. Agent keys are stored hashed. Reviewer roles are viewer, reviewer and admin. Every privileged action is written to a hash-chained audit log. Scan tokens are short-lived and revoked when a run ends. Request headers are redacted before storage. See [SECURITY.md](SECURITY.md) and [docs/SECURITY.md](docs/SECURITY.md).

## Development

```bash
uv pip install --python .venv/bin/python -e ".[dev,all]"
.venv/bin/python -m pytest tests -q
.venv/bin/ruff check aisrf tests examples scripts
make lint
```

CI runs lint, style guards, the test suite on Python 3.11 and 3.12, the Node SDK self-test and a Docker build. Releases are cut by tagging `vX.Y.Z` (see [docs/RELEASING.md](docs/RELEASING.md)); the release workflow publishes the wheel, an SBOM, checksums and a multi-arch image to GHCR with notes from [CHANGELOG.md](CHANGELOG.md).

## Documentation

[Architecture](docs/ARCHITECTURE.md), [API](docs/API.md), [Configuration](docs/CONFIGURATION.md), [Deployment](docs/DEPLOYMENT.md), [Integrations](docs/INTEGRATIONS.md), [Guardrails](docs/GUARDRAILS.md), [TypeSafe](docs/TYPESAFE.md), [Red team](docs/REDTEAM.md), [Scanners](docs/SCANNERS.md), [Code review](docs/CODE_REVIEW.md), [Reports](docs/REPORTS.md), [MCP](docs/MCP.md), [Security](docs/SECURITY.md), [Brand](docs/BRAND.md), [Roadmap](docs/ROADMAP.md), [Releasing](docs/RELEASING.md).

## References

OWASP Top 10 for LLM Applications 2025; Greshake et al., Not what you've signed up for (2023); Joseph Thacker, Prompt Injection Primer; garak; promptfoo; PyRIT and PyRIT-Ship; Rebuff; LLM Guard; NeMo Guardrails; Lakera Guard. Links are collected in the Settings > About page and in `aisrf/taxonomy.py`.

## License

Apache License 2.0. See [LICENSE](LICENSE). Copyright 2026 Keyur Aghao.
