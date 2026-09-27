# Contributing to AIRT

Thanks for helping make LLM traffic reviewable. This page covers the workflow; the architecture is
described in `docs/ARCHITECTURE.md`.

## Development setup

```bash
git clone <your fork>
cd AI_RedTeam
uv venv .venv --python 3.12            # or: python3 -m venv .venv
uv pip install --python .venv/bin/python -e ".[dev,postgres,mitm]"
cp .env.example .env
.venv/bin/airt serve                     # http://localhost:8080, admin / admin
```

`make dev`, `make run`, `make test`, `make lint` wrap the same commands. Node 18+ is needed only
for `sdk/node` (`node sdk/node/test.js`).

## Project layout

| Path | Purpose |
| --- | --- |
| `airt/gateway/` | Interception: router, parser (request normalisation), policy engine, forwarder, hold registry |
| `airt/analysis/` | Analyzer framework and built-in analyzers (`analyzers/`) |
| `airt/tickets/`, `airt/agents/`, `airt/audit/` | Ticket lifecycle, agent registry, hash-chained audit log |
| `airt/redteam/` | Probe corpus (YAML), mutators, campaign engine, REST API |
| `airt/reports/` | Format-agnostic report model, builders, renderers |
| `airt/dashboard/` | Server rendered reviewer UI |
| `airt/mcp_server.py`, `airt/cli.py` | MCP server and Typer CLI |
| `airt/integrations/` | Client side helpers (Python SDK patching, mitmproxy addon) |
| `sdk/node/` | `airt-intercept` npm package |
| `docs/`, `examples/` | Documentation and runnable examples |
| `tests/` | pytest suite (`asyncio_mode = auto`) |

## Coding rules

* Python 3.11+, type hints everywhere, `from __future__ import annotations` at the top of modules.
* `ruff check` and `ruff format` must pass (line length 110, see `pyproject.toml`).
* No em dash characters anywhere (code, comments, docs, strings, config); use a hyphen or a comma.
* No unnecessary blank lines; keep modules compact and readable.
* Never log or store raw secrets. Use `airt.security.redact_headers` for headers and the Fernet
  helpers for upstream credentials.
* An analyzer must never raise into the gateway: the runner already isolates exceptions, but keep
  analyzers pure and bounded (see `MAX_SCAN_CHARS` in `airt/analysis/analyzers/common.py`).
* Every privileged action goes through `airt.audit.service.record` so the hash chain stays complete.
* Do not edit `pyproject.toml` dependencies without discussing it in the PR; keep the core free of
  heavyweight runtime dependencies.

## Adding an analyzer

1. Create `airt/analysis/analyzers/<name>.py` with an object exposing `name`, `description` and
   `analyze(normalized, context) -> list[Finding]` (sync or async).
2. Register it in `airt/analysis/analyzers/__init__.py` with `register(analyzer)` or
   `register(analyzer, response=True)` for response analyzers.
3. Add tests with both a positive and a benign sample; false positives cost reviewer time.

## Adding red-team probes

Probes live in `airt/redteam/corpus/*.yaml`. Each probe needs a unique `id`, a `category`, a
`technique`, a `severity`, the `messages` (or `prompt`) and the success criteria used by the verdict
logic. Keep benign controls in `benign_control` so campaigns can measure over-blocking.

## Pull requests

1. Branch from `main`, keep PRs focused.
2. Add or update tests and docs for behaviour changes (`docs/API.md` for new endpoints,
   `docs/CONFIGURATION.md` and `.env.example` for new settings).
3. Run `make lint test` locally; CI runs ruff and pytest on Python 3.11 and 3.12, the Node self-test
   and a Docker build.
4. Describe the security impact of the change in the PR description when it touches the gateway
   path, authentication, the audit log or credential handling.

## Reporting security issues

Please do not open public issues for vulnerabilities. See `SECURITY.md`.
