# Code Review

The code review module (`aisrf/codereview/`) runs static analysis of LLM-integrated applications: prompt assembly, agent tools, output handling, model loading and dependencies, retrieval pipelines and general hygiene. A run takes a source tree from an archive, a URL, a git repository, a local directory or a pasted snippet, inventories it, runs up to three engines plus an optional LLM-assisted pass, de-duplicates and persists the findings, computes a risk score and serves everything through the REST API, the dashboard, the CLI, MCP tools and the report subsystem (every report format plus SARIF for GitHub code scanning). The rule catalogue itself is documented in [[Code-Review-Rules]].

Modules: `intake.py` (source acquisition and safety checks), `inventory.py` (file walk, languages, manifests, frameworks, artifacts), `rules/` (six packs, 92 rules, plus semgrep YAML), `engines/` (rules engine, semgrep and bandit adapters, LLM pass), `findings.py` (finding record, fingerprints, de-duplication, risk score), `service.py` (serialisation, summaries, credentials), `engine.py` (`CodeReviewRunner`), `router.py`, `report.py`, `sarif.py`, `secrets.py` (masking), `config.py` (defaults and the `codereview` settings namespace).

## Intake types

`POST /api/codereview/runs` takes `{name, source, options}`; `POST /api/codereview/runs/upload` is multipart (`file`, `name`, `options` as JSON). `source.type` is one of `git`, `url`, `zip`, `path`, `snippet` (`SOURCE_TYPES`).

| Type | Source fields | Notes |
|---|---|---|
| `zip` | multipart `file` (zip, tar, tar.gz/tgz, tar.bz2/tbz2, tar.xz/txz) | The upload is saved into the run directory and extracted; the archive is deleted afterwards. |
| `url` | `url`, optional `token` | Streamed HTTP(S) download of an archive with a size limit and `download_timeout_seconds`; the token is sent as `Authorization: Bearer`. Credentials embedded in the URL are split off. |
| `git` | `url`, optional `ref` (branch, tag or 7 to 40 hex commit), `token` or `credential_id`, `username`, `provider` (`github`, `gitlab`, `bitbucket`, `azure` or `generic`; auto-detected from the host and used to pick the token username such as `x-access-token` or `oauth2`), `ssh_key_path` | Shallow clone with `git_timeout_seconds`. When `git` is missing, or the clone fails for an `https://` GitHub URL, the GitHub tarball API is used instead (`detail.method` is `git` or `github-api`). |
| `path` | `path` | Administrators only. The directory must be under the data directory or one of `codereview.path_allowlist`; files are copied into the run directory honouring include and exclude globs. |
| `snippet` | `code`, `language` | One file named after the language (default `python`). |

Every intake ends with the code under `<data_dir>/codereview/<run_id>/src`. Working copies are removed when a run is deleted and expire after `retention_days` (default 7, `cleanup_expired`).

### Credential handling

* Git tokens are never placed on the command line or in the URL. They reach git through a temporary `GIT_ASKPASS` helper script that reads environment variables; the helper is removed after the clone and the `.git` directory is deleted. User info embedded in a URL is split off and treated the same way.
* Stored `source_ref` values, audit entries, error messages and log lines pass through `secrets.redact_url` and `secrets.mask_secrets`; the persisted `source` keeps only `type`, `url`, `ref`, `provider`, `path`, `filename`, `language`, `credential_id` and `username`, redacted.
* Saved credentials (`GET`, `POST`, `DELETE /api/codereview/credentials`, administrators only) are stored in the `codereview` settings namespace under `credentials` as `{id (cred_<12 hex>), label (80 chars), provider (default github), username, token_encrypted, created_by, created_at}`; the token is encrypted with the application secret (`encrypt_secret`) and the API only ever returns `has_token`. Using a saved credential (`credential_id`) or an SSH deploy key (`ssh_key_path`) on a run is restricted to administrators; the CLI exposes them as `--credential`.
* The file viewer (`GET /api/codereview/runs/{id}/file?path=`) resolves paths inside the run directory only.
* Every snippet stored with a finding is passed through the secret masker (`mask_secrets`, which replaces assignment values and URL credentials with `[masked]`).

## Safety limits (`codereview` namespace)

Defaults from `config.py`, overridable live through `PUT /api/settings/ns/codereview` ([[Settings-Center]]); `get_config()` merges the namespace over the defaults (`llm_review` is merged key by key).

| Key | Default | Meaning |
|---|---|---|
| `max_archive_bytes` | 200 MiB (209715200) | Uncompressed archive size bound checked before extraction. |
| `max_files` | 20000 | Maximum files extracted or walked; also the cap for the per-run `max_files` option. |
| `max_file_bytes` | 2 MiB | Larger files are skipped. |
| `exclude_dirs` | `node_modules`, `.venv`, `venv`, `.git`, `.hg`, `.svn`, `dist`, `build`, `__pycache__`, `.tox`, `.mypy_cache`, `.ruff_cache`, `.pytest_cache`, `site-packages`, `vendor`, `.next`, `coverage`, `.idea`, `.vscode` | Directories never walked. |
| `path_allowlist` | `[]` | Extra local directories a `path` run may read. |
| `retention_days` | 7 | Working copy lifetime. |
| `git_timeout_seconds` | 300 | Clone timeout. |
| `download_timeout_seconds` | 120 | Archive download timeout. |
| `semgrep_timeout_seconds` | 180 | Semgrep subprocess timeout. |
| `bandit_timeout_seconds` | 120 | Bandit subprocess timeout. |
| `default_engines` | `["rules", "semgrep", "bandit"]` | Engines used when a run does not list any. |
| `semgrep_binary`, `bandit_binary` | `""` | Explicit binaries; empty means auto-detect (project venv `bin/` first, then `PATH`). |
| `llm_review` | `{"enabled": false, "max_files": 12, "max_chars_per_file": 6000, "confidence": 0.45, "timeout_seconds": 60}` | LLM-assisted pass. |
| `credentials` | `[]` | Saved credentials (see above). |

Archive members with absolute paths, drive letters or `..` segments, symbolic and hard links, devices and fifos are rejected; a single top-level directory is unwrapped.

## Inventory

`build_inventory` walks the tree with the limits above and produces the run's `inventory`: `files`, `loc`, `bytes`, `languages` (`{language: {files, loc}}` sorted by LOC), `manifests` (requirements, pyproject, package.json, lock files and similar, with parsed dependencies and a `pinned` flag), `frameworks` (detected AI SDKs, agent frameworks, ML libraries, vector stores, MCP and guardrail libraries from `FRAMEWORKS`, each with `kind`, sample `files` and `count`; for example `openai`, `anthropic`, `google-generativeai`, `langchain`, `langgraph`, `llama-index`, `crewai`, `autogen`, `semantic-kernel`, `transformers`, `torch`, `pinecone`, `chromadb`, `qdrant`, `pgvector`, `mcp`, `guardrails`), `model_artifacts` (files by extension with a format such as `pytorch-pickle`, `safetensors`, `gguf`), `prompt_files` (files whose text looks like a system prompt), `secret_files` (`.env`, `secrets.json`, PEM keys, SSH keys and similar names), `ci_configs`, `dockerfiles`, `tool_calling` (`{detected, files}` from tool-calling markers), `mcp_servers`, `notebooks`, `skipped` and `truncated`. The inventory also drives inventory-scoped rules (for example pickle artifacts committed to the repository) and the LLM pass file selection.

## Engines and options

Run options (`OptionsIn`, normalised by `normalize_options`):

| Option | Default | Meaning |
|---|---|---|
| `packs` | all six packs | Subset of `prompt_injection`, `agent_tool_abuse`, `llm_output`, `model_supply_chain`, `rag_poisoning_exfil`, `general`; unknown names are dropped. |
| `engines` | `codereview.default_engines` | Subset of `rules`, `semgrep`, `bandit`, `llm`. |
| `include`, `exclude` | `[]` | Glob patterns relative to the source root. |
| `max_files` | `codereview.max_files` | Per-run cap, never above the namespace value. |

| Engine | What it does | Availability |
|---|---|---|
| `rules` | The AISRF catalogue: line regexes with context flags, file-level presence and absence checks and Python AST matchers (taint-like tracking of model output, tool parameters and request data inside functions). Reports progress per file. | built in, always available |
| `semgrep` | The rule files under `rules/semgrep/` (one per pack, taint mode where the framework supports it) in a subprocess. The adapter starts the OCaml binary shipped with the semgrep package in `--experimental` mode with its bundled libraries, so it keeps working when the Python CLI cannot start, and falls back to the `semgrep` command otherwise. Findings with an `aisrf_rule` metadata key are mapped onto the catalogue entry. | `codereview` extra (`semgrep>=1.100`) |
| `bandit` | General Python security checks (subprocess, pickle, yaml, weak hashes, requests without TLS verification, ...) mapped onto taxonomy categories with ids `BANDIT-Bxxx`. | `codereview` extra (`bandit>=1.7`) |
| `llm` | Optional LLM-assisted review (below). | judge model configured |

Each engine records `{engine, available, findings, seconds, error?}` in the summary's `engines` map; an engine that raises is reported as unavailable and never fails the run.

Validate the shipped semgrep rules with `semgrep --validate --config aisrf/codereview/rules/semgrep/` or, when the Python CLI is unavailable, `.venv/bin/python -c "import asyncio; from aisrf.codereview.engines.semgrep_engine import validate_rules; print(asyncio.run(validate_rules()))"`.

### LLM-assisted pass

When the core setting `enable_llm_judge` is set (or `codereview.llm_review.enabled` is true) and a judge model is configured ([[Analyzers]], LLM judge configuration), the highest-signal files (most findings, most AI, tool, RAG, agent and route markers) are sent to the judge with a fixed rubric covering the six packs. Excerpts are secret-masked and bounded by `max_chars_per_file` (6000); at most `max_files` (12) files are reviewed within `timeout_seconds` (60). The answer must be a JSON array and is turned into findings with `engine=llm`, rule ids `AISRF-LLM-<PI|AT|LO|MS|RG|GN>` and a confidence capped at `llm_review.confidence` (0.45) so they never outrank a deterministic rule. Masked source excerpts leave the environment; do not enable the pass for code that must stay in place.

## Run lifecycle and SSE events

Statuses (`CodeReviewStatus`): `CREATED`, `FETCHING`, `ANALYZING`, `COMPLETED`, `FAILED`, `CANCELLED`. The run also carries a `stage` string. `CodeReviewRunner` publishes on the SSE channel `codereview` (`GET /api/codereview/stream?replay=&run_id=`):

| Event | When | Payload |
|---|---|---|
| `run.status` | every status change | `run_id`, `status`, `stage` (`created`, `intake`, `rules`, `completed`, `cancelled`, `failed`), plus `files` and `loc` when analysis starts, `findings`, `risk_score` and `summary` on completion, `error` on failure |
| `run.progress` | during work | `run_id`, `status`, `stage` (`inventory`, `rules`, `semgrep`, `bandit`, `llm`, `persist`), `done`, `total` (0 when unknown; for `rules` the file counter) |
| `finding.status` | a finding's review status changes | `run_id`, `finding_id`, `status` |
| `run.deleted` | a run is deleted | `run_id` |

Sequence: `CREATED` (row stored with redacted `source` and normalised `config`) -> `FETCHING` with stage `intake` (acquire in a worker thread) -> stage `inventory` -> `ANALYZING` with stage `rules`, then `semgrep`, `bandit`, `llm` as selected -> `dedupe` -> stage `persist` -> `COMPLETED` with `summary`, `finding_count` and an audit entry `codereview.run.completed`. `POST /api/codereview/runs/{id}/cancel` flips a state flag and sets `CANCELLED` for runs in `CREATED`, `FETCHING` or `ANALYZING`; an exception sets `FAILED` with the message in `error`. Findings kept after de-duplication are those whose pack was selected, plus every `bandit` and `llm` finding.

Run dict (`run_to_dict`): `id`, `name`, `source_type`, `source_ref`, `status`, `stage`, `created_by`, `created_at`, `started_at`, `finished_at`, `error`, `file_count`, `loc`, `finding_count`, `summary`, `config`, and for the detail view `inventory` and `work_dir_available`.

## Findings model and statuses

A finding (`Finding` dataclass, persisted as `CodeReviewFinding`) stores `rule_id`, `pack`, `engine`, `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`; unknown values become MEDIUM), `confidence` (0 to 1), `title`, `description`, `remediation`, `file`, `line_start`, `line_end`, `snippet` (masked, at most 1200 characters), `language`, `owasp`, `cwe`, `category`, `fingerprint` and `metadata` (including `engines`, the list of engines that agreed). The API dict adds `why`, `owasp_labels`, `cwe_url`, `references`, `status`, `reviewer_note`, `reviewed_by` and `ts`.

* **Fingerprint**: SHA-256 of `rule_id`, `file` and the whitespace-normalised, lower-cased snippet; stable across runs of the same code, used by SARIF `partialFingerprints`.
* **De-duplication** (`dedupe`): identical fingerprints and near duplicates (same rule, file and start line) are merged; the first finding wins, its confidence becomes the maximum and `metadata.engines` lists every engine. A bandit finding on a line already covered by a catalogue finding with the same CWE is folded into that finding.
* **Review status** (`FINDING_STATUSES`): `open`, `false_positive`, `accepted`, set with `POST /api/codereview/findings/{id}/status` `{status, note}` (reviewer role); the reviewer name and note are stored, a `finding.status` event is published and the run summary is refreshed.

## Risk score

`risk_score(findings)` considers open findings only. Each contributes `SEVERITY_WEIGHT[severity] * clamp(confidence, 0.2, 1.0)` with weights CRITICAL 90, HIGH 60, MEDIUM 30, LOW 10, INFO 0; the weights are sorted descending and summed as `w0 + w1/2 + w2/4 + ...` over at most the 13 strongest findings, rounded and capped at 100. One CRITICAL finding dominates; dismissing findings lowers the score. `risk_level` reuses `level_for_score` from the analyzers (`NONE`, `LOW` < 25, `MEDIUM` < 50, `HIGH` < 80, `CRITICAL`).

The summary (`compute_summary`) holds `total`, `open`, `by_severity`, `by_pack`, `by_engine`, `by_owasp` (all ten ids with `name` and `count`), `by_status`, `risk_score`, `risk_level`, `top_rules` (10, by count then severity), `top_files` (10, with `max_severity`), `engines` (per engine status and timing), `duration_seconds`, `computed_at`.

## SARIF structure

`GET /api/codereview/runs/{id}/sarif` (and `GET /api/reports/codereview/{id}?format=sarif`) returns a SARIF 2.1.0 document (`$schema` `https://json.schemastore.org/sarif-2.1.0.json`) with one run:

* `tool.driver`: name `AISRF Code Review`, `version`, `informationUri`, `supportedTaxonomies` (`OWASP LLM Top 10 2025`) and `rules`: one entry per rule that produced a result, with `shortDescription` (title), `fullDescription`, `help` (description, why it matters, remediation bullets), `helpUri`, `defaultConfiguration.level` and `properties` (`tags` such as `security`, `llm`, the pack, `owasp-llm01`, `external/cwe/cwe-74`; `precision` high for confidence >= 0.7, medium >= 0.45, else low; `security-severity` CRITICAL 9.5, HIGH 8.0, MEDIUM 5.5, LOW 3.0, INFO 1.0; `pack`, `owasp`, `cwe`). Unknown rule ids (bandit, llm) get a generic entry.
* `taxonomies`: the OWASP LLM Top 10 as taxa with descriptions and URLs.
* `results`: `ruleId`, `ruleIndex`, `level` (CRITICAL and HIGH -> `error`, MEDIUM -> `warning`, LOW and INFO -> `note`), `message` (title plus first description line; markdown with the snippet), `locations[0].physicalLocation` with `artifactLocation.uri` (relative, `uriBaseId` `%SRCROOT%`) and `region` (`startLine`, `endLine`, `startColumn` 1, `snippet.text`), `partialFingerprints` (`aisrf/v1` fingerprint and `primaryLocationLineHash` `path:line`), `properties` (`severity`, `confidence`, `engine`, `pack`, `owasp`, `cwe`, `status`, `fingerprint`), `fixes` with the remediation text, and `suppressions` (`kind: external`, `status: accepted`, justification from the reviewer note) for dismissed findings, which are included only with `include_dismissed=true`.
* `automationDetails.id` `aisrf/codereview/<run id>`, `invocations` (`executionSuccessful` when the run is `COMPLETED`, `endTimeUtc`), `originalUriBaseIds`, `versionControlProvenance` (repository URI and commit for `git` sources) and run `properties` (`run_id`, `name`, `source_type`, `source_ref`, `risk_score`, `files`, `loc`).

Upload from CI:

```yaml
- name: Review with AISRF
  run: |
    aisrf codereview run --git "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" --ref "$GITHUB_SHA" \
      --token-env GITHUB_TOKEN --wait --format sarif --out aisrf.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aisrf.sarif
```

## REST API

Reads need a principal, run and finding mutations need the `reviewer` role, credentials and `path` intake need `admin`. Every mutation writes an audit entry ([[Logging-Metrics-and-Audit]]).

| Method and path | Purpose |
|---|---|
| `GET /api/codereview/rules?pack=` | Catalogue (`packs`, `total`, `engines`) and effective configuration; see [[Code-Review-Rules]]. |
| `POST /api/codereview/runs` | `{name, source: {type, url, ref, token, credential_id, username, provider, ssh_key_path, path, code, language}, options: {packs, engines, include, exclude, max_files}}`; returns the run (201) and starts it. |
| `POST /api/codereview/runs/upload` | Multipart `file`, `name`, `options` (JSON string). |
| `GET /api/codereview/runs?status=&source_type=&limit=50&offset=0` | Paginated runs (`limit` 1 to 500). |
| `GET /api/codereview/runs/{id}` | Run with inventory and summary. |
| `DELETE /api/codereview/runs/{id}` | Delete run, findings and working copy. |
| `POST /api/codereview/runs/{id}/cancel` | Cancel. |
| `GET /api/codereview/runs/{id}/findings?severity=&pack=&engine=&file=&status=&rule_id=&search=&limit=100&offset=0` | Findings (`severity` accepts a comma list; `limit` up to 2000). |
| `POST /api/codereview/findings/{id}/status` | `{status, note}`. |
| `GET /api/codereview/runs/{id}/file?path=` | File content plus its findings. |
| `GET /api/codereview/runs/{id}/sarif?include_dismissed=` | SARIF document. |
| `GET`, `POST`, `DELETE /api/codereview/credentials[/{id}]` | Saved credentials, `{label, provider, token, username}` on create. |
| `GET /api/codereview/stream?replay=&run_id=` | SSE. |
| `GET /api/reports/codereview/{id}?format=` | Report in `json`, `yaml`, `csv`, `tsv`, `md`, `html`, `pdf`, `xlsx`, `txt`, `xml`, `sarif` or `junit` ([[Reports]]). |

## CLI

```bash
aisrf codereview rules --pack model_supply_chain
aisrf codereview run --git https://github.com/org/app.git --ref main --token-env GH_TOKEN --wait --format sarif --out app.sarif
aisrf codereview run --zip ./app.zip --packs prompt_injection --packs llm_output --engines rules --engines semgrep
aisrf codereview run --url https://example.com/app.tar.gz --no-wait
aisrf codereview run --path /var/lib/aisrf/checkouts/app        # admin, allowlisted directory on the server
aisrf codereview list --status COMPLETED --limit 50
aisrf codereview show crv_... --limit 50
```

`aisrf codereview run` options: exactly one of `--git` (with `--ref`, `--token-env`, `--credential`), `--zip`, `--url`/`--archive-url` (with `--token-env`), `--path`; plus `--name`, repeatable `--packs`, `--engines`, `--include`, `--exclude`, `--wait/--no-wait` (default wait, `--poll-interval` 2.0 s), `--format`/`-f` and `--out`/`-o` to download a report after completion. Remote commands take `--url` and `--token` (or `AISRF_URL` and `AISRF_ADMIN_API_TOKEN`); `--token-env` names an environment variable holding the git or archive token so it never appears in shell history ([[CLI-Reference]]).

## MCP

The [[MCP-Server]] exposes `codereview_rules(pack)`, `codereview_start(source, name, options)` (same `source` and `options` shape as `POST /api/codereview/runs`), `codereview_runs(status, limit, offset)`, `codereview_run(run_id)`, `codereview_findings(run_id, severity, pack, engine, file, status, limit, offset)`, `codereview_set_finding_status(finding_id, status, note)` and `codereview_report(run_id, format="sarif", output_path)`. Archive uploads are not available over MCP; use a URL or repository.

## Dashboard usage

`/codereview` ([[Dashboard-Guide]]) has four sections: **New review run** (tabs for git repository, archive URL, upload, local path and snippet; pack and engine selection; include and exclude globs), **Runs** (live table fed by the SSE stream with status, stage, findings, risk score and actions), **Saved credentials** (administrators) and **Rule catalogue** (searchable, with OWASP and CWE chips). `/codereview/<run_id>` shows **Progress**, summary tiles, **Open findings** by severity and pack, **OWASP LLM Top 10** counts, the **Inventory** (frameworks, manifests, model artifacts, prompt and secrets files, MCP servers), **Engines** status and timings, the **Findings** table with filters and expandable rows (description, why, remediation, numbered snippet, taxonomy chips, CWE link, false positive and accepted actions with a note), a **File** viewer that highlights finding lines, **Details** and **Reports** download links for every format.

## Limitations

* The engines are static and heuristic. Name based matching and absence checks produce false positives on unusual code layouts; confidence and the review status exist to triage them. Absence rules (missing rate limit, missing confirmation gate and similar) only see one file at a time.
* Taint tracking in the rules engine is intra-procedural and Python only; the semgrep rules add intra-file taint for Python, JavaScript and TypeScript. Nothing follows data across services.
* Only Python is parsed into an AST; other languages rely on regular expressions.
* Binary model artifacts are inventoried, not scanned; pair the module with a pickle scanner for that.
* Working copies live on the gateway host under the data directory; size the disk and the retention period accordingly ([[Operations-and-Maintenance]]).
