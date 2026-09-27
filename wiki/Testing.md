# Testing

The pytest suite, its fixtures, how to run subsets, what is skipped when optional tools are missing, the style guard, coverage, every CI job and how to write a new test.

## Test layout

`tests/` (pytest, `asyncio_mode = "auto"`, `testpaths = ["tests"]`, `DeprecationWarning` ignored, from `[tool.pytest.ini_options]`):

| File | Tests | Covers |
| --- | --- | --- |
| `conftest.py` | fixtures | isolated SQLite database, mocked upstream, ASGI client with lifespan, admin headers, a registered agent |
| `test_analysis.py` | 42 | request and response analyzers, scoring, taxonomy enrichment, obfuscation and PII validators |
| `test_gateway.py` | 20 | interception end to end: auth, normalisation, hold and decide, async mode, streaming relay, denied and expired outcomes, credential swap, canary |
| `test_parser_policy.py` | 5 | `parser.normalize` shapes and `policy.evaluate` outcomes |
| `test_settings_canary.py` | 6 | runtime settings store, namespaces, export and import, canary injection and withholding |
| `test_redteam.py` | 10 | corpus validity, mutators, evaluators, campaign runner and comparison groups |
| `test_scanners.py` | 11 | engine registry, scan tokens, garak, promptfoo and PyRIT engines (skipped when absent), PyRIT-Ship surface |
| `test_guardrails.py` | 26 | Rebuff heuristics, LLM Guard, NeMo and Lakera analyzers, status and health |
| `test_codereview.py` | 11 | intake, inventory, rules engine, semgrep and bandit (following tool availability), SARIF, API and MCP tools |
| `test_reports.py` | 21 | every builder and every renderer, format negotiation |
| `test_notifications.py` | 1 | Slack and JSON webhook payloads |
| `test_mcp_cli.py` | 5 | MCP server tools in process and Typer CLI commands |
| `test_packaging.py` | 23 | PyInstaller manifest coverage, desktop app directory and `aisrf.env`, install script syntax, systemd unit, Kubernetes manifests, Helm chart, the built binary when present |
| `test_style.py` | 4 | em dashes, merge markers, whitespace rules, private data never tracked |

## conftest fixtures

`tests/conftest.py` sets the environment before anything imports the package: a temporary directory `aisrf-test-*` holds `test.db`, `data/` and `logs/`; `AISRF_ADMIN_API_TOKEN=test-admin-token`; `AISRF_APPROVAL_TIMEOUT_SECONDS=5`; `AISRF_HOLD_POLL_INTERVAL_SECONDS=0.2`; `AISRF_LOG_LEVEL=WARNING`. All are `setdefault`, so CI can override (`AISRF_SECRET_KEY`, `AISRF_LOG_JSON_CONSOLE=true`).

`_install_stand_ins()` substitutes lightweight modules for `aisrf.redteam.engine`, `aisrf.redteam.router`, `aisrf.reports.router`, `aisrf.dashboard.router` and `aisrf.mcp_server` only when the real module fails to import, so the gateway tests still run in a minimal environment.

| Fixture | Scope | What it gives |
| --- | --- | --- |
| `app` | function | `create_app()` entered through its lifespan (schema, admin, sweeper), with `app.state.http` replaced by an `httpx.AsyncClient` whose `MockTransport` is `openai_upstream_handler`; settings cache reset and DB disposed before and after |
| `client` | function | `httpx.AsyncClient` on `ASGITransport(app)` with base URL `http://testserver` |
| `admin_headers` | function | `{"Authorization": "Bearer test-admin-token"}` |
| `agent` | function | JSON of an agent created through `POST /api/agents` (provider `openai`, upstream `https://upstream.example/v1`, key `sk-upstream-secret`, `require_approval=True`) including its one-time `api_key` |

`openai_upstream_handler` fakes an OpenAI-compatible provider: `/models` lists `mock-model`, `stream: true` returns three SSE chunks and `[DONE]`, otherwise a chat completion echoing the last user message and reporting the `Authorization` header it saw (`seen_auth`), which lets tests assert the credential swap.

## Running subsets

```bash
.venv/bin/python -m pytest -q                                   # everything (make test)
.venv/bin/python -m pytest tests/test_gateway.py -q             # one file
.venv/bin/python -m pytest tests/test_analysis.py -k pii -q     # by keyword
.venv/bin/python -m pytest -q -x --lf                           # stop at first failure, rerun last failed
.venv/bin/python -m pytest tests/test_scanners.py tests/test_guardrails.py tests/test_codereview.py -q   # the heavy extras job
.venv/bin/python -m pytest -q -rs                               # show skip reasons
```

Tests run against a fresh temporary database per session; parallelism with `pytest-xdist` is not configured.

## Skips for optional tools

Tests that need an optional engine skip instead of failing, so a plain `.[dev]` environment stays green:

| Condition | Where |
| --- | --- |
| `pytest.importorskip("llm_guard")`, and a skip when a scanner cannot be used offline | `test_guardrails.py` |
| `pytest.importorskip("nemoguardrails")`, skip when the bundled offline config cannot be loaded by the installed version | `test_guardrails.py` |
| garak: `shutil.which("garak")` or `registry["garak"].installed()` | `test_scanners.py` (`skipif(not GARAK)`) |
| promptfoo binary on `PATH` or configured | `test_scanners.py` (`skipif(not PROMPTFOO)`) |
| PyRIT importable | `test_scanners.py` (`needs_pyrit`) |
| semgrep and bandit: expectations follow `scanner_binary()` availability | `test_codereview.py` |
| MCP server import (`mcp` 1.x or 2.x) | `test_codereview.py`, `test_mcp_cli.py` (tuple results from 1.x are accepted) |
| `bash` present (install script syntax) | `test_packaging.py` |
| `helm` installed (`helm lint` and template rendering) | `test_packaging.py` |
| built binary in `dist/aisrf` (`aisrf version` from the bundle) | `test_packaging.py` |

Install `.[all]` (or `.[codereview]`, `.[scanners]`, `.[guardrails]` individually) to exercise the skipped tests; CI does this in the weekly `heavy extras` job.

## Style test

`tests/test_style.py` walks the repository (skipping `.venv`, `node_modules`, `data`, `logs`, `.git`, caches, `dist`, `build`, egg-info) and checks text files (`.py`, `.md`, `.yaml`, `.yml`, `.toml`, `.txt`, `.html`, `.js`, `.ts`, `.mjs`, `.css`, `.json`, `.sh`, `.cfg`, `.ini`, `.env`, `.example`, `Dockerfile`, `Makefile`, `LICENSE`):

- `test_no_em_dashes_in_repo`: no U+2014 anywhere;
- `test_no_merge_markers`: no `<<<<<<<` in Python files;
- `test_private_knowledge_base_is_never_tracked`: `git ls-files Code_review_Data` is empty and `.gitignore` lists `Code_review_Data/`;
- `test_no_unnecessary_blank_lines_or_trailing_whitespace`: no trailing whitespace; at most one consecutive blank line in `.md`, `.yaml`, `.yml`, `.toml`, `.txt`, `.html`, `.css`, `.js`, `.ts`, `.sh`; at most two in `.py`.

`scripts/check_style.py` is the pytest-free twin used by `make lint`, the CI `style guard` job and the release workflow; it prints `path:line` per offence and exits 1.

## Coverage

CI runs `pytest --cov=aisrf --cov-branch --cov-report=term-missing:skip-covered --cov-report=xml:coverage.xml --junitxml=pytest-junit.xml` on Python 3.11 and 3.12, appends a Markdown coverage table to the job summary and uploads `coverage-py3.11` and `coverage-py3.12` artifacts (14 days). Locally:

```bash
uv pip install --python .venv/bin/python pytest-cov
.venv/bin/python -m pytest -q --cov=aisrf --cov-branch --cov-report=term-missing:skip-covered
.venv/bin/python -m pytest -q --cov=aisrf --cov-report=html && xdg-open htmlcov/index.html
```

There is no enforced threshold; keep new modules covered by at least one positive and one negative case.

## CI jobs

`.github/workflows/ci.yml` runs on push to `main`, pull requests, weekly (Monday 06:00 UTC) and manually; `concurrency` cancels superseded runs; `permissions: contents: read`.

| Job | Runs on | Checks |
| --- | --- | --- |
| `style guard` | ubuntu, 5 min | `grep` for the U+2014 byte sequence across the tree (excluding `.venv`, `node_modules`, `.git`), `python scripts/check_style.py`, `ruff check scripts`, `ruff format --check scripts` (non-blocking until `scripts/screenshots.py` is formatted) |
| `ruff + pytest (py3.11, py3.12)` | ubuntu, 20 min, matrix | `uv venv` + `.[dev,codereview]` + `pytest-cov`; `ruff check --output-format=github aisrf tests examples` (blocking); `ruff format --check aisrf tests examples` (non-blocking for now); pytest with coverage under `AISRF_SECRET_KEY` and JSON console; coverage summary and artifacts; `python -c "import aisrf.integrations.python_sdk, aisrf.integrations.mitm_addon"` (imports without extras); `aisrf version` and `aisrf --help` |
| `binary smoke (linux x86_64)` | ubuntu, 30 min, needs `python` | `uv pip install -e . pyinstaller`, `scripts/build_binary.py --skip-archive` (PyInstaller build plus the smoke test: `version`, `init-db`, `serve` with GET `/healthz`, `/login`, `/static/style.css`, `/api/redteam/corpus`, `/api/codereview/rules`, PDF, XLSX and HTML summary reports, bundled data directories, no traceback in the log), bundle size in the summary |
| `heavy extras (scanners + guardrails)` | ubuntu, 60 min, only on `workflow_dispatch` or schedule | `.[dev,all]`, then `tests/test_scanners.py tests/test_guardrails.py tests/test_codereview.py` |
| `node sdk self-test` | ubuntu, Node 20, 5 min | `node sdk/node/test.js`, `npm pack --dry-run` in `sdk/node` |
| `docker build` | ubuntu, 20 min, needs `python` | Buildx build with GHA cache, `docker run --rm aisrf:ci version`, `docker run --rm -e AISRF_SECRET_KEY=... aisrf:ci init-db` |

Other workflows: `codeql.yml` (python and javascript-typescript, `security-and-quality` queries, weekly, ignores `.venv`, `node_modules`, `tests`), `dependency-review.yml` (PRs, fails on high severity advisories, comments on failure), `docs-check.yml` (lychee link check over README, CONTRIBUTING, SECURITY, CHANGELOG, CODE_OF_CONDUCT, `docs/**`, `examples/**`, `sdk/node/**`; advisory only), `labels.yml` (syncs `.github/labels.yml`), `stale.yml` (issues stale after 60 days and closed after 21 more, PRs after 45 and 21; exempt labels `pinned`, `security`, `roadmap`, `help wanted`, `good first issue`, `work in progress`, milestones and drafts), `wiki-sync.yml` (pushes `wiki/` to the GitHub wiki on changes to `wiki/**`), `release.yml` ([[Releasing]]).

## Writing a new test

1. Put it in the file that matches the subsystem, or create `tests/test_<area>.py`; module docstring first line describes the scope.
2. Async tests need no marker (`asyncio_mode = auto`). Use the `client`, `admin_headers` and `agent` fixtures for HTTP-level tests; call service functions with `get_sessionmaker()()` for unit-level tests.
3. For gateway behaviour: send through `client.post("/v1/chat/completions", headers={"Authorization": f"Bearer {agent['api_key']}"}, json=...)`; decide with `client.post(f"/api/tickets/{tid}/approve", headers=admin_headers, json={"note": "ok"})` from a concurrent task, or use `X-AISRF-Async: 1` and poll. The approval timeout is 5 s in tests.
4. Optional dependencies: `pytest.importorskip("<module>")` or a `skipif(shutil.which("<binary>") is None, reason=...)` marker so the suite stays green without them.
5. Analyzers: assert both a positive sample (finding present, expected severity) and a benign sample (no finding).
6. Keep files free of em dashes and trailing whitespace; `tests/test_style.py` runs on the tests too. `tests/*` may ignore `E402`, `F401`, `B011`, `F841`, `RUF018`, `SIM117`, `PIE` per the ruff config.
7. Run `make lint test` before pushing; if you touched packaging or deploy files, `tests/test_packaging.py` validates manifests, the systemd unit, the Kubernetes YAML and the Helm chart.
