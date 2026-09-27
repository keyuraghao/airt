# Development Guide

How the repository is organised, how to set up an environment, a walkthrough of every package and module, recipes for extending each subsystem, and the coding and commit conventions. Tests are covered in [[Testing]], releases in [[Releasing]].

## Repository layout

| Path | Purpose |
| --- | --- |
| `aisrf/` | the Python package (105 modules) |
| `aisrf/gateway/` | interception: router, parser (request normalisation), policy engine, forwarder, hold registry, canary, programmatic pipeline |
| `aisrf/analysis/` | analyzer framework (`base.py`, `runner.py`, `custom_rules.py`) and the built-in analyzers in `analyzers/` |
| `aisrf/guardrails/` | LLM Guard, NeMo Guardrails, Lakera Guard and Rebuff integrations, plus the bundled offline NeMo config in `nemo_default/` |
| `aisrf/tickets/`, `aisrf/agents/`, `aisrf/audit/` | ticket lifecycle and SSE streams, agent registry and scan tokens, hash-chained audit log |
| `aisrf/redteam/` | corpus loader, YAML corpus (`corpus/*.yaml`), mutators, evaluators, campaign engine, comparison groups, REST API |
| `aisrf/scanners/` | garak, promptfoo, PyRIT and PyRIT-Ship engines, the scan runner and REST API |
| `aisrf/codereview/` | source code review: intake, inventory, engines (`engines/`), rule packs (`rules/`), semgrep rules (`rules/semgrep/*.yaml`), SARIF, REST API |
| `aisrf/reports/` | format-agnostic report model, builders, renderers, REST API |
| `aisrf/dashboard/` | server-rendered reviewer UI: `router.py`, Jinja templates in `templates/`, page scripts and CSS in `static/` |
| `aisrf/integrations/` | client-side helpers: `python_sdk.py` (httpx and requests patching, `AISRFClient`), `mitm_addon.py` |
| `aisrf/cli.py`, `aisrf/mcp_server.py`, `aisrf/desktop.py` | Typer CLI, MCP server (HTTP and stdio), desktop mode and app directory |
| `aisrf/config.py`, `aisrf/settings_store.py`, `aisrf/settings_router.py` | pydantic settings, runtime overrides, Settings API |
| `aisrf/models.py`, `aisrf/db.py`, `aisrf/security.py`, `aisrf/auth.py`, `aisrf/logging.py`, `aisrf/metrics.py`, `aisrf/notifications.py`, `aisrf/taxonomy.py`, `aisrf/main.py` | ORM, engine, crypto, reviewer auth, structured logging, Prometheus registry, webhooks, OWASP taxonomy, app factory |
| `sdk/node/` | the `aisrf-intercept` npm package (`index.js`, `index.d.ts`, `test.js`) |
| `examples/` | runnable clients: OpenAI sync and async, Anthropic, LangChain, tool-using agent loop, curl, MCP client config |
| `tests/` | pytest suite, `asyncio_mode = auto` |
| `docs/` | Markdown documentation and images; `wiki/` is synced to the GitHub wiki by `.github/workflows/wiki-sync.yml` |
| `deploy/` | systemd, launchd, Windows service, Kubernetes manifests, Helm chart |
| `packaging/pyinstaller/` | `aisrf.spec`, `launcher.py`, `manifest.py` for the binaries |
| `scripts/` | `install.sh`, `install.ps1`, `build_binary.py`, `bump_version.py`, `check_style.py`, `changelog_notes.py`, `brand_assets.py`, `screenshots.py` |
| `Dockerfile`, `docker-compose.yml`, `Makefile`, `.env.example`, `pyproject.toml` | build and configuration entry points |

## Environment setup with uv

The project convention is a single virtualenv at `.venv`, created and populated with `uv`; never use another interpreter path.

```bash
git clone https://github.com/keyuraghao/aisrf.git && cd aisrf
uv venv .venv --python 3.12
uv pip install --python .venv/bin/python -e ".[dev,postgres,mitm]"      # what `make dev` runs
uv pip install --python .venv/bin/python -e ".[dev,all]"                # every engine (large)
cp .env.example .env                                                    # edit AISRF_SECRET_KEY, AISRF_ADMIN_PASSWORD, AISRF_ADMIN_API_TOKEN
.venv/bin/aisrf init-db
.venv/bin/aisrf serve
```

Makefile targets: `make venv`, `make install`, `make dev`, `make run` (`PORT=8080`), `make test`, `make lint`, `make style`, `make fmt`, `make bump VERSION=x.y.z [DRY=1]`, `make node-test`, `make docker-build`, `make docker-run`, `make compose-up [PROFILE=postgres]`, `make compose-down`, `make clean`. Node 18+ is only needed for `sdk/node` (`node sdk/node/test.js`).

## Reload mode

```bash
.venv/bin/aisrf serve --host 127.0.0.1 --port 8080 --reload
```

`--reload` passes uvicorn's reloader for `aisrf.main:create_app` (factory mode); workers are forced to 1 when reloading. Templates are re-read by Jinja and static files are served from disk, so dashboard edits appear on refresh; Python edits restart the process (in-flight synchronous waits are dropped, tickets stay PENDING). `AISRF_LOG_LEVEL=DEBUG` and `AISRF_DB_ECHO=true` help while developing. `watchfiles` is silenced to WARNING by the logging setup.

## Code walkthrough

Every request follows `aisrf/gateway/router.py::intercept`: extract the agent key, authenticate, enforce rate limit and body size, `parser.normalize()`, `analysis.runner.analyze_request()`, `policy.evaluate()`, `tickets.service.create_ticket()` and the hold, then `forward_ticket()` with `forwarder`, response analysis and `_finish()`. Modules by package:

### Top level

- `aisrf/__init__.py`: `__version__`.
- `main.py`: `create_app()` factory, `CorrelationMiddleware` (binds `request_id`, `path`, `method` in structlog contextvars, echoes `X-Request-ID`), `lifespan()` (logging, `init_db`, `ensure_admin`, `settings_store.load_overrides`, shared httpx client, internal token, sweeper task, notifier, runner shutdowns), `_background_sweeper()`, `/healthz`, `/readyz`, `/metrics`, router registration order (gateway catch-all last).
- `config.py`: `Settings(BaseSettings)` with env prefix `AISRF_` and `.env` support, `fernet_key`, `is_production`, `ensure_dirs()`, cached `get_settings()`, `reset_settings_cache()`.
- `settings_store.py`: `LOCKED` fields, `GROUPS` for the Settings page, `NAMESPACE_DEFAULTS` (`analyzers`, `rules`, `integrations`, `ui`, `policy`), `schema()`, `coerce()`, `load_overrides()`, `update_core()`, `reset_core()`, `get_namespace()`, `get_value()`, `update_namespace()`, `reset_namespace()`, `export_all()`, `import_all()`.
- `settings_router.py`: `/api/settings` schema, analyzers, guardrails status and health, taxonomy, core update and reset, namespace get, update and reset, export and import.
- `models.py`: `utcnow`, `new_id`, enums `TicketStatus`, `RiskLevel`, `CampaignStatus`, `CodeReviewStatus`; tables `Reviewer`, `Agent`, `ScanToken`, `Ticket`, `TicketEvent`, `AgentEvent`, `AuditEntry`, `Campaign`, `ProbeResult`, `AppSetting`, `Counter`, `CodeReviewRun`, `CodeReviewFinding`.
- `db.py`: `Base`, `get_engine()` (SQLite `timeout=30`), `get_sessionmaker()`, `session_scope()`, `get_session()` dependency, `init_db()` (WAL, foreign keys, `create_all`, counter seeding), `dispose_db()`.
- `security.py`: `hash_password` and `verify_password` (PBKDF2), `generate_api_key`, `hash_api_key`, `api_key_prefix`, session token create and read (itsdangerous), `encrypt_secret` and `decrypt_secret` (Fernet), `redact_headers`.
- `auth.py`: `Principal`, `ensure_admin`, `optional_principal`, `current_principal`, `require_role`, `/api/auth/login`, `/logout`, `/me`, `/reviewers` CRUD and password endpoints.
- `logging.py`: `configure_logging()` (console, `aisrf.jsonl`, per-agent files), `get_logger()`, `agent_file_logger()`, `EventBroadcaster` (SSE pub-sub with replay), `json_dumps`.
- `metrics.py`: `Metrics.inc()`, `observe()`, `render()` in Prometheus text.
- `notifications.py`: `Notifier` queue, Slack Block Kit payloads for `hooks.slack.com`, raw JSON elsewhere.
- `taxonomy.py`: `OWASP_LLM_TOP10`, `GRESHAKE_THREATS`, `GRESHAKE_DELIVERY`, `THACKER_TECHNIQUES`, `CATEGORY_MAP`, `classify()`, `owasp_ids()`, `owasp_label()`, `enrich()`, `coverage()`, `catalogue()`.
- `cli.py`: Typer app with sub-apps `agent`, `tickets`, `redteam`, `audit`, `codereview`; local commands use `_run_db`, remote ones the `Remote` REST client (`--url`, `--token`).
- `mcp_server.py`: `MCPServer` import shim for mcp 2.x and 1.x, `ApiClient`, `build_server()` with 44 `@server.tool()` functions plus resources and the `review_ticket` prompt, `BearerGuard` ASGI wrapper, `mount_mcp()` at `/mcp`, `SessionManagerRunner`, `run_stdio()`.
- `desktop.py`: see [[Desktop-Mode]].

### `gateway/`

- `router.py`: `_extract_key`, `_authenticate`, `_client_ip`, `intercept`, `forward_ticket`, `_iter_upstream`, `_finish`, routes `openai_compatible` (`/v1/{path}`), `generic_proxy` (`/proxy/{path}`), `poll_ticket` (`/gateway/tickets/{id}`).
- `parser.py`: `detect_endpoint`, `normalize` (OpenAI chat, completions, responses, embeddings, Anthropic messages, Gemini, Ollama, Cohere, generic JSON), `extract_response_text`.
- `policy.py`: `PolicyDecision`, `evaluate` (active flag, allowed paths and models, deny patterns, thresholds, mandatory review for critical secrets or exfiltration, global policy namespace).
- `forwarder.py`: `build_upstream_url`, `build_upstream_headers` (credential swap), `filter_response_headers`, `make_client`, `build_request`, `summarize_error`, `error_json`.
- `hold.py`: `HoldRegistry` (asyncio.Event fast path, DB polling slow path).
- `canary.py`: `new_canary`, `inject`, `leaked`.
- `pipeline.py`: `submit()` and `SubmitResult`, the programmatic path used by the red-team and scanner engines.

### `analysis/`

- `base.py`: `Severity`, `Finding` (analyzer, category, severity, title, description, evidence, location, confidence, tags, metadata; `to_dict()` enriches with taxonomy), `AnalysisResult`, `Analyzer` protocol, `level_for_score`, `score_findings`.
- `runner.py`: `register(analyzer, response=False)`, `list_analyzers`, `_load_builtin` (imports `analyzers`, custom rules and `guardrails`), `_active` and `_apply_overrides` (Settings > Analyzers), `analyze_request`, `analyze_response`; every analyzer runs concurrently and isolated.
- `custom_rules.py`: `CustomRulesRequest`, `CustomRulesResponse` over the `rules.custom` namespace.
- `analyzers/common.py`: text normalisation, homoglyph folding, zero-width stripping, leet folding, masking, `iter_messages`, `iter_tools`, `make_finding`, `Signature`, `compile_signatures`, `MAX_SCAN_CHARS`.
- `analyzers/`: `prompt_injection`, `jailbreak`, `pii` (`scan_pii`, Luhn, IBAN, national ids), `secrets` (`scan_secrets`, entropy), `data_exfil`, `tool_abuse`, `harmful_content`, `obfuscation`, `anomaly`, `llm_judge` (registered only with `enable_llm_judge`), `response_analyzers` (system prompt leak, PII leak, secrets leak, refusal, harmful compliance, exfil markers, canary leak).

### `guardrails/`

`__init__.py` registers `rebuff.analyzer`, `llm_guard.input_analyzer`, `nemo.input_analyzer`, `lakera.request_analyzer` and the three output analyzers, exposes `status()` and `health_check()`. `_common.py` gives `integration_config`, `is_enabled`, `library_installed`, throttled logging, `severity_for_score`, text extraction. Each integration module implements analyzer classes plus `status()` and `health_check()`; heavy imports happen lazily. `rebuff.py` reimplements the heuristic layer natively (`heuristic_score`, `detect_injection`, canary helpers) with optional SDK and LLM layers.

### `tickets/`, `agents/`, `audit/`

- `tickets/service.py`: `create_ticket`, `set_analysis`, `apply_policy`, `decide`, `bulk_decide`, `mark_forwarding`, `mark_completed`, `mark_failed`, `mark_expired`, `expire_stale`, `purge_old`, `get_ticket` (id or number), `list_tickets`, `list_events`, `stats`, `ticket_to_dict`.
- `tickets/router.py`: `/api/tickets` list, stats, bulk approve and deny, get, events, approve, deny; `/api/audit` and `/api/audit/verify`; SSE `/api/stream/tickets`, `/logs`, `/campaigns`.
- `agents/service.py`: `create_agent`, `rotate_api_key`, `update_agent`, `authenticate_api_key`, `mint_scan_token`, `revoke_scan_tokens`, `check_rate_limit`, `log_agent_event`, `list_agent_events`, `agent_stats`.
- `agents/router.py`: `/api/agents` CRUD, `rotate-key`, disable, events, stats.
- `audit/service.py`: `record`, `list_entries`, `count_entries`, `verify_chain`.

### `redteam/`

`corpus.py` (`Probe` pydantic model, `Corpus`, `load_corpus`, `get_probes`), `mutators.py` (`base64_wrap`, `rot13`, `leetspeak`, `reverse_text`, `payload_split`, `prefix_suffix_jailbreak`, `apply_mutator`, `mutated_id`), `evaluators.py` (`evaluate` gives VULNERABLE, RESISTED, BLOCKED, ERROR or INCONCLUSIVE), `engine.py` (`CampaignRunner`, `build_summary`, `compare_group`), `service.py`, `router.py` (`/api/redteam/corpus`, campaigns lifecycle, groups).

### `scanners/`

`base.py` (`ScanEngine` protocol, `registry`, `register`, `ScanRunner`, `TicketMatcher`, token issue and revoke, `run_subprocess`), `garak.py`, `promptfoo.py`, `pyrit.py`, `pyrit_ship.py`, `service.py` (campaigns, matrix, compare), `router.py` (`/api/scanners/...` plus the PyRIT-Ship compatible surface).

### `codereview/`

`config.py` (defaults, `scanner_binary`), `intake.py` (archives, URLs, git, local paths, snippets), `inventory.py` (files, languages, manifests, framework detection), `engines/` (`rules_engine`, `semgrep_engine`, `bandit_engine`, `llm_engine`), `rules/base.py` (`Rule`, `FileContext`, `Match`, matchers `lines`, `near`, `absence`, `py`, `any_of`, `node_match`, factory `rule()`), six packs, `rules/semgrep/*.yaml`, `findings.py` (fingerprint, dedupe, risk score), `secrets.py` (masking), `sarif.py`, `service.py`, `engine.py` (`CodeReviewRunner`), `report.py`, `router.py` (`/api/codereview`).

### `reports/`, `dashboard/`, `integrations/`

`reports/model.py` (`Report`, `KeyValueSection`, `TableSection`, `TextSection`, `FindingsSection`, `ChartSection`), `builders.py` (`BUILDERS`, `KINDS`), `renderers.py` (`FORMATS`, `RENDERERS`, `render`, `negotiate`), `router.py` (`/api/reports/{kind}`). `dashboard/router.py` renders only the shell (`_page` with the principal); each page template extends `base.html` and its script in `static/<page>.js` loads data from `/api/*`. `integrations/python_sdk.py` and `mitm_addon.py` are client side and must import without optional extras (CI checks this).

## Extension recipes

### Add an analyzer

1. Create `aisrf/analysis/analyzers/<name>.py` with an object exposing `name`, `description` and `analyze(normalized, context) -> list[Finding]` (sync or async). Use `common.iter_messages`, `make_finding`, `snippet` and respect `MAX_SCAN_CHARS`; never raise (the runner isolates exceptions, but keep it pure and bounded).
2. Register it: add the module to `_REQUEST_ANALYZERS` in `aisrf/analysis/analyzers/__init__.py`, or `register(obj, response=True)` for a response analyzer.
3. Map its `category` in `aisrf/taxonomy.py::CATEGORY_MAP` so findings carry OWASP, Greshake and Thacker tags.
4. Tests in `tests/test_analysis.py`: one positive sample and one benign sample (false positives cost reviewer time). Document it in `docs/ARCHITECTURE.md` and the [[Analyzers]] page.

### Add a guardrail integration

1. Create `aisrf/guardrails/<vendor>.py` with request and response analyzer classes whose `analyze` reads `integration_config("<vendor>")`, returns `[]` when `is_enabled()` is false or the library is missing, imports the vendor SDK lazily, and logs failures with `log_throttled`. Provide `status()` and `health_check()`.
2. Add default settings under `NAMESPACE_DEFAULTS["integrations"]["<vendor>"]` in `aisrf/settings_store.py`.
3. Register in `aisrf/guardrails/__init__.py` (`REQUEST_ANALYZERS`, `RESPONSE_ANALYZERS`, `INTEGRATIONS`).
4. Optional dependency: add it to the `guardrails` and `all` extras in `pyproject.toml` (discuss in the PR) and to `EXCLUDES` in `packaging/pyinstaller/manifest.py` if heavy.
5. Tests in `tests/test_guardrails.py` with `pytest.importorskip`.

### Add a probe category

1. Create `aisrf/redteam/corpus/<category>.yaml` with `category`, `description`, optional `defaults` (`severity`, `expected`) and `probes`. Each probe needs a unique `id`, `technique`, `name`, `description`, `prompt` or `messages`, `success_indicators` (valid regexes), optional `canary`, `tags`; `severity` in the allowed set and `expected` in `EXPECTED_VALUES`.
2. Map the category and techniques in `aisrf/taxonomy.py` so summaries show OWASP coverage.
3. `aisrf redteam corpus` lists it; `tests/test_redteam.py` validates the corpus loads.

### Add a scanner engine

1. Create `aisrf/scanners/<engine>.py` implementing the `ScanEngine` protocol: `name`, `description`, `installed()`, `capabilities()`, `list_probes()`, `plan(options)`, `async run(campaign_id, http)`. Use `ScanRunner` helpers (`issue_token`, `run_subprocess`, `record_results`, `finish`) so tickets are linked and tokens revoked.
2. Call `base.register(<Engine>())` at import time and import the module from `aisrf/scanners/__init__.py`.
3. Defaults under `NAMESPACE_DEFAULTS["integrations"]["<engine>"]`.
4. Tests in `tests/test_scanners.py`, skipped when the tool is absent.

### Add a code review rule and a semgrep rule

1. Pick the pack file in `aisrf/codereview/rules/` and append a `rule(...)` to its `RULES` list: id `AISRF-<PACK>-NNN`, `severity`, `confidence`, `category`, `cwe`, `description`, `why`, `remediation`, `languages`, `matcher` built from `lines()`, `near()`, `absence()`, `py()` (AST callback using `rules/pyast.py`), `any_of()`, `node_match()`; `engines=("rules",)` or `("rules", "semgrep")`.
2. For the semgrep counterpart add an entry to `aisrf/codereview/rules/semgrep/<pack>.yaml` with `metadata.aisrf_rule` set to the same id, `pack`, `severity`, `confidence`, `cwe`, `owasp`, `category`; validate with `semgrep --validate --config aisrf/codereview/rules/semgrep/`.
3. `RULES_BY_ID` asserts unique ids at import. Add a fixture to `tests/test_codereview.py` and a row to the rule table in `docs/CODE_REVIEW.md` and [[Code-Review-Rules]].

### Add a report format

1. Implement `render_<fmt>(report: Report) -> bytes` in `aisrf/reports/renderers.py` walking `report.sections` (`KeyValueSection`, `TableSection`, `TextSection`, `FindingsSection`, `ChartSection`).
2. Add the format to `FORMATS` (media type, extension, description), `RENDERERS`, and aliases in `ALIASES` and `MEDIA_TO_FORMAT`.
3. The REST API, CLI (`--format`), dashboard and MCP pick it up automatically. Test in `tests/test_reports.py`. Add a report kind by writing `build_<kind>_report` in `builders.py` and listing it in `BUILDERS` and `KINDS`.

### Add a dashboard page

1. Template `aisrf/dashboard/templates/<page>.html` extending `base.html`; script `aisrf/dashboard/static/<page>.js` fetching `/api/...` with the helpers from `app.js`.
2. Route in `aisrf/dashboard/router.py`: `@router.get("/<page>")` calling `_page(request, "<page>.html", "<page>", p)`; add the navigation entry in `base.html`.
3. Any new data needs an `/api/*` endpoint guarded by `current_principal` or `require_role`.
4. Both directories are already in `PACKAGE_DATA_DIRS` and `[tool.setuptools.package-data]`, so nothing to add for packaging.

### Add an MCP tool and a CLI command

- MCP: inside `build_server()` in `aisrf/mcp_server.py` add an `@server.tool()` async function with typed parameters and a docstring (the docstring becomes the tool description) that calls `api.call(method, path, params=..., json_body=...)`. Update the tool count in `docs/MCP.md` and `tests/test_mcp_cli.py`.
- CLI: in `aisrf/cli.py` add `@<sub>_app.command("<name>")`; remote commands take `url: UrlOpt = DEFAULT_URL, token: TokenOpt = None` and use `Remote(url, token).json(...)`; local commands use `_run_db(coro)`. Print with `console` and the `_kv_table` or `_rows_table` helpers. Document in [[CLI-Reference]] and the README command list.

### Add a setting

1. Add a typed field with a default to `Settings` in `aisrf/config.py` (env name is `AISRF_<FIELD>` upper-cased).
2. Add it to a group in `settings_store.GROUPS` so it appears on the Settings page (or to `LOCKED` if it must only come from the environment); `SENSITIVE` masks names matching password, secret, token or key.
3. Document it in `.env.example` and `docs/CONFIGURATION.md`, and in the Helm `values.yaml` comment if operators need it.
4. Read it through `get_settings()` (process defaults) or `settings_store.get_value()` (live override).

## Coding standards

- Python 3.11+, type hints everywhere, `from __future__ import annotations` at the top of every module.
- Ruff (`pyproject.toml`): line length 110, target `py311`, rule sets `E, F, W, I, B, UP, SIM, RUF, C4, PIE, T20`; ignored `B008`, `E501`, `RUF012`, `SIM108`, `B904`, `RUF001`-`RUF003`, `T201`; per-file ignores for `tests/*`, `examples/*` and `aisrf/analysis/analyzers/*`; excludes `docs/images`, `sdk`, `.venv`. `ruff format --check` runs on `aisrf/integrations` and `examples` in `make lint`.
- Style guard (`scripts/check_style.py`, `tests/test_style.py`, CI job `style guard`): no em dash character (U+2014) anywhere in the tree, no merge markers, no trailing whitespace, no two consecutive blank lines in Markdown, YAML, TOML, TXT, HTML, CSS, JS, TS and shell files, no three consecutive blank lines in Python, and `Code_review_Data/` must never be tracked.
- Keep modules compact; no unnecessary blank lines.
- Never log or store raw secrets: `aisrf.security.redact_headers` for headers, Fernet helpers for upstream credentials, `aisrf.codereview.secrets.mask_secrets` for snippets.
- Analyzers never raise into the gateway; keep them pure and bounded by `MAX_SCAN_CHARS`.
- Every privileged action goes through `aisrf.audit.service.record`.
- Do not change `pyproject.toml` dependencies without discussing it in the PR; the core stays free of heavyweight runtime dependencies (optional engines go behind extras and lazy imports).
- Client-side modules (`aisrf/integrations/*`) must import without optional extras.

Run before pushing:

```bash
make lint            # ruff check, ruff format --check (integrations, examples), scripts/check_style.py
make test            # .venv/bin/python -m pytest -q
node sdk/node/test.js
```

## Commit conventions

- Subject line: `Area: what changed`, imperative or descriptive, no trailing period, no em dashes. Areas used in history: `Tests`, `Release`, `CI`, `Docs`, `Gateway`, `Dashboard`, or a plain sentence for cross-cutting work (for example `Native binaries for Windows, macOS and Linux, desktop mode, install scripts, ...`).
- One logical change per commit; keep PRs focused and branched from `main`.
- Add or update tests and docs for behaviour changes: `docs/API.md` for endpoints, `docs/CONFIGURATION.md` and `.env.example` for settings, the matching wiki page.
- Add a line to the `Unreleased` section of `CHANGELOG.md` under `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed` or `Security` for user-visible changes; label the PR `skip-changelog` otherwise.
- Describe the security impact in the PR description when the change touches the gateway path, authentication, the audit log or credential handling.
- CI on every PR: style guard, ruff and pytest with coverage on 3.11 and 3.12, binary smoke build, Node self-test, Docker build, CodeQL (python and javascript-typescript), dependency review (fails on high severity). Release commits are `Release X.Y.Z` with tag `vX.Y.Z` ([[Releasing]]).
