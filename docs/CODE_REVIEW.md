# Code review

The code review module runs static analysis of LLM-integrated applications: prompt assembly,
agent tools, output handling, model loading and dependencies, retrieval pipelines and general
hygiene. A run takes a source tree from an archive, a URL, a git repository, a local directory or a
pasted snippet, inventories it, runs three engines plus an optional LLM-assisted pass, de-duplicates
and persists the findings, computes a risk score and serves everything through the REST API, the
dashboard, the CLI, MCP tools and the report subsystem (all twelve formats plus SARIF for GitHub
code scanning).

Code lives under `aisrf/codereview/`:

- `intake.py` source acquisition with the safety checks described below.
- `inventory.py` file walk with limits, language and LOC counts, dependency manifests, AI framework
  detection, model artifacts, prompt files, secrets files, CI and container configuration.
- `rules/` the AISRF rule catalogue (six packs, 92 rules) plus the semgrep rule files.
- `engines/` the rules engine, the semgrep and bandit adapters and the LLM-assisted pass.
- `findings.py`, `service.py`, `engine.py` finding records, fingerprints, de-duplication, risk
  scoring, persistence, summaries and the run orchestrator.
- `router.py`, `report.py`, `sarif.py` the REST API, the report builder and SARIF output.

## Intake types and credential handling

| Type | Source | Notes |
| --- | --- | --- |
| `zip` | `POST /api/codereview/runs/upload` (multipart) | zip, tar, tar.gz, tar.bz2, tar.xz |
| `url` | `{"type": "url", "url": ..., "token": ...}` | http(s) archive download, optional bearer token |
| `git` | `{"type": "git", "url": ..., "ref": ..., "token": ... or "credential_id": ...}` | shallow clone of a branch, tag or commit; GitHub tarball fallback when git is missing |
| `path` | `{"type": "path", "path": ...}` | administrators only; the directory must sit under the data directory or `codereview.path_allowlist` |
| `snippet` | `{"type": "snippet", "code": ..., "language": ...}` | one file named after the language |

Every intake ends with the code under `<data_dir>/codereview/<run_id>/src`. Working copies are
removed when a run is deleted and expire after `retention_days` (default 7).

Safety properties:

- archives are inspected before extraction: members with absolute paths, drive letters or `..`
  segments, symbolic and hard links, devices and fifos are rejected; the uncompressed size and file
  count are bounded by `max_archive_bytes` and `max_files`; a single top-level directory is
  unwrapped;
- downloads are streamed with a size limit and a timeout;
- git tokens are never placed on the command line or in the URL. They are handed to git through a
  temporary `GIT_ASKPASS` helper that reads environment variables, the helper is removed after the
  clone and the `.git` directory is deleted. User info embedded in a URL is split off and treated the
  same way. Stored `source_ref` values, audit entries, error messages and log lines pass through
  `secrets.redact_url` and `secrets.mask_secrets`;
- saved credentials (`GET/POST/DELETE /api/codereview/credentials`, administrators only) are
  encrypted with the application secret in the `codereview` settings namespace; the API never
  returns the token, only `has_token`. Using a saved credential or an SSH deploy key on a run is
  restricted to administrators;
- the file viewer resolves paths inside the run directory only and refuses anything else;
- every snippet stored with a finding is passed through the secret masker.

## Rule catalogue

Rule ids are `AISRF-<PACK>-<nnn>`. Every rule carries a severity, a default confidence, a taxonomy
category (which gives the OWASP LLM Top 10 mapping through `aisrf.taxonomy`), a CWE, a description,
why it matters, remediation steps and the engines that can report it. Findings from semgrep that
carry an `aisrf_rule` metadata key are mapped onto the same catalogue entry so the dashboard, SARIF
and reports show one rule regardless of the engine that found it. Bandit findings keep their
`BANDIT-Bxxx` id and are mapped onto taxonomy categories.

### Prompt injection (`prompt_injection`, 14 rules)

How untrusted text reaches the model: prompt assembly, system role hygiene, request pass-through, indirect channels and history replay.

| Rule | Title | Severity | OWASP | CWE | Engines |
| --- | --- | --- | --- | --- | --- |
| AISRF-PI-001 | Untrusted input interpolated into a prompt | HIGH | LLM01 | CWE-74 | rules, semgrep |
| AISRF-PI-002 | Runtime data placed in the system role | HIGH | LLM01 | CWE-74 | rules, semgrep |
| AISRF-PI-003 | HTTP request data passed straight to the model call | HIGH | LLM01 | CWE-20 | rules, semgrep |
| AISRF-PI-004 | Prompt assembled by string concatenation | MEDIUM | LLM01 | CWE-74 | rules |
| AISRF-PI-005 | Template engine compiles untrusted text as a prompt template | HIGH | LLM01 | CWE-1336 | rules, semgrep |
| AISRF-PI-006 | No length limit on input before the model call | LOW | LLM10 | CWE-770 | rules |
| AISRF-PI-007 | Secrets or personal data embedded in the system prompt | HIGH | LLM02, LLM07 | CWE-200 | rules |
| AISRF-PI-008 | Stored conversation history replayed into the prompt unchecked | MEDIUM | LLM01 | CWE-74 | rules |
| AISRF-PI-009 | Fetched web or mailbox content summarised without isolation | MEDIUM | LLM01, LLM08 | CWE-74 | rules |
| AISRF-PI-010 | External content processed with tools enabled and no confirmation | HIGH | LLM01, LLM08 | CWE-807 | rules |
| AISRF-PI-011 | Prompt-only defence against injection | INFO | LLM01 | CWE-693 | rules |
| AISRF-PI-012 | Client controls the whole message list | HIGH | LLM01 | CWE-602 | rules, semgrep |
| AISRF-PI-013 | User input reaches the model without control-token or role-marker screening | LOW | LLM01 | CWE-20 | rules |
| AISRF-PI-014 | User-supplied images or files sent to a multimodal model | MEDIUM | LLM01, LLM08 | CWE-20 | rules, semgrep |

### Agent and tool abuse (`agent_tool_abuse`, 20 rules)

What the model is allowed to do: shell, code, file, network and SQL sinks in tools, confirmation gates, loop limits, dispatch safety and MCP exposure.

| Rule | Title | Severity | OWASP | CWE | Engines |
| --- | --- | --- | --- | --- | --- |
| AISRF-AT-001 | Shell command executed with model-controlled arguments | CRITICAL | LLM06, LLM05 | CWE-78 | rules, semgrep, bandit |
| AISRF-AT-002 | Dynamic code evaluation of tool or model data | CRITICAL | LLM06, LLM05 | CWE-95 | rules, semgrep, bandit |
| AISRF-AT-003 | File system tool without path containment | HIGH | LLM06, LLM05 | CWE-22 | rules, semgrep |
| AISRF-AT-004 | Outbound HTTP tool without a URL allowlist | HIGH | LLM06, LLM05 | CWE-918 | rules, semgrep |
| AISRF-AT-005 | SQL statement built from tool or model data | CRITICAL | LLM06, LLM05 | CWE-89 | rules, semgrep, bandit |
| AISRF-AT-006 | Over-broad tool description or capability | MEDIUM | LLM06 | CWE-250 | rules |
| AISRF-AT-007 | Destructive or financial tool without a confirmation gate | HIGH | LLM06 | CWE-862 | rules |
| AISRF-AT-008 | Agent loop without an iteration or cost limit | HIGH | LLM10 | CWE-835 | rules |
| AISRF-AT-009 | Tool output returned to the model unsanitised | MEDIUM | LLM01, LLM08 | CWE-74 | rules |
| AISRF-AT-010 | Model tool calls dispatched by name without an allowlist | HIGH | LLM06 | CWE-470 | rules, semgrep |
| AISRF-AT-011 | MCP server exposes a dangerous capability | CRITICAL | LLM06 | CWE-749 | rules |
| AISRF-AT-012 | Messaging or payment tool without a destination allowlist | HIGH | LLM02, LLM05 | CWE-284 | rules |
| AISRF-AT-013 | Tool reads data without a user or tenant scope | MEDIUM | LLM06 | CWE-639 | rules |
| AISRF-AT-014 | Framework tool with code or shell execution enabled | CRITICAL | LLM06, LLM05 | CWE-94 | rules, semgrep |
| AISRF-AT-015 | Tools attached without per-user permission scoping | MEDIUM | LLM06 | CWE-285 | rules |
| AISRF-AT-016 | Tool arguments used without schema or value validation | MEDIUM | LLM06, LLM05 | CWE-20 | rules |
| AISRF-AT-017 | Tool execution without a per-session call budget | LOW | LLM10 | CWE-770 | rules |
| AISRF-AT-018 | Agent-to-agent delegation without an allowlist, depth limit or message screening | MEDIUM | LLM06 | CWE-284 | rules, semgrep |
| AISRF-AT-019 | Tool calls executed without an audit trail | LOW | LLM06 | CWE-778 | rules |
| AISRF-AT-020 | Tool set combines file writes with command or code execution | HIGH | LLM06, LLM05 | CWE-94 | rules |

### LLM output handling (`llm_output`, 14 rules)

Model output as untrusted input: HTML and DOM sinks, markdown rendering, code and SQL execution, paths and URLs, schema validation and chained prompts.

| Rule | Title | Severity | OWASP | CWE | Engines |
| --- | --- | --- | --- | --- | --- |
| AISRF-LO-001 | Model output rendered as HTML without escaping | CRITICAL | LLM05 | CWE-79 | rules, semgrep |
| AISRF-LO-002 | innerHTML or dangerouslySetInnerHTML with model text | CRITICAL | LLM05 | CWE-79 | rules, semgrep |
| AISRF-LO-003 | Markdown rendered with raw HTML allowed or without sanitisation | HIGH | LLM05 | CWE-79 | rules |
| AISRF-LO-004 | Model output executed as code or shell command | CRITICAL | LLM05 | CWE-94 | rules, semgrep |
| AISRF-LO-005 | Model output used inside a SQL query | CRITICAL | LLM05 | CWE-89 | rules, semgrep |
| AISRF-LO-006 | Model output used as a file path or fetch target | HIGH | LLM05 | CWE-73 | rules |
| AISRF-LO-007 | Structured model output parsed without schema validation | MEDIUM | LLM05 | CWE-20 | rules |
| AISRF-LO-008 | Generated code executed outside a sandbox | HIGH | LLM09, LLM05 | CWE-94 | rules |
| AISRF-LO-009 | Model output chained into a further prompt without validation | MEDIUM | LLM01 | CWE-74 | rules |
| AISRF-LO-010 | Model output returned to the client without output filtering | LOW | LLM02, LLM05 | CWE-200 | rules |
| AISRF-LO-011 | Model-supplied URL used as a link, redirect or navigation target | HIGH | LLM05 | CWE-601 | rules |
| AISRF-LO-012 | Packages installed from model-suggested names | HIGH | LLM03 | CWE-829 | rules, semgrep |
| AISRF-LO-013 | Structured output requested by prompt wording only | LOW | LLM05 | CWE-20 | rules |
| AISRF-LO-014 | Model output placed in email or notification fields | MEDIUM | LLM05 | CWE-93 | rules |

### Model security and supply chain (`model_supply_chain`, 19 rules)

Model files are code: pickle loaders, remote code, unpinned revisions and dependencies, transport and integrity, serving exposure, build hygiene and provenance.

| Rule | Title | Severity | OWASP | CWE | Engines |
| --- | --- | --- | --- | --- | --- |
| AISRF-MS-001 | torch.load without weights_only=True | CRITICAL | LLM03 | CWE-502 | rules, semgrep, bandit |
| AISRF-MS-002 | Pickle-family deserialization of model or data files | CRITICAL | LLM03 | CWE-502 | rules, semgrep, bandit |
| AISRF-MS-003 | trust_remote_code=True enabled | HIGH | LLM03 | CWE-829 | rules, semgrep |
| AISRF-MS-004 | Hub artifact loaded without a pinned revision | MEDIUM | LLM03 | CWE-494 | rules |
| AISRF-MS-005 | Model or weights fetched over plain HTTP | HIGH | LLM03 | CWE-319 | rules |
| AISRF-MS-006 | Remote checkpoint downloaded without integrity verification | MEDIUM | LLM03 | CWE-494 | rules |
| AISRF-MS-007 | Unpinned AI or ML dependency | MEDIUM | LLM03 | CWE-1104 | rules |
| AISRF-MS-008 | Model serving endpoint without authentication | MEDIUM | LLM10 | CWE-306 | rules |
| AISRF-MS-009 | Model weights or data published with public access | HIGH | LLM03 | CWE-284 | rules |
| AISRF-MS-010 | Unpinned base image or unverified download in a build | MEDIUM | LLM03 | CWE-494 | rules |
| AISRF-MS-011 | Training or fine-tuning data ingested from untrusted sources | MEDIUM | LLM08, LLM04 | CWE-345 | rules |
| AISRF-MS-012 | Model artifacts without provenance metadata | INFO | LLM03 | CWE-1059 | rules |
| AISRF-MS-013 | Pickle-based model artifact committed to the repository | LOW | LLM03 | CWE-502 | rules |
| AISRF-MS-014 | Hub model loaded without forcing the safetensors format | LOW | LLM03 | CWE-502 | rules, semgrep |
| AISRF-MS-015 | Additional package index configured (dependency confusion exposure) | MEDIUM | LLM03 | CWE-427 | rules |
| AISRF-MS-016 | Model upload endpoint stores artifacts without format checks or review | HIGH | LLM03 | CWE-434 | rules |
| AISRF-MS-017 | Inference endpoint returns full probability vectors | LOW | LLM02, LLM04 | CWE-200 | rules |
| AISRF-MS-018 | Notebook committed with HTML or JavaScript cell outputs | MEDIUM | LLM03 | CWE-79 | rules |
| AISRF-MS-019 | Container image runs as root | LOW | LLM03 | CWE-250 | rules |

### RAG poisoning and data exfiltration (`rag_poisoning_exfil`, 14 rules)

Every retrieved chunk is untrusted: ingestion sanitisation, tenant scoping, filters, vector store auth, prompt delimiters, markdown exfiltration, logging, caching and memory isolation.

| Rule | Title | Severity | OWASP | CWE | Engines |
| --- | --- | --- | --- | --- | --- |
| AISRF-RG-001 | Documents indexed without content sanitisation or provenance | MEDIUM | LLM08, LLM04 | CWE-20 | rules |
| AISRF-RG-002 | Retrieval without a tenant or user scope | HIGH | LLM08, LLM04 | CWE-284 | rules, semgrep |
| AISRF-RG-003 | Metadata filter or namespace built from request data | HIGH | LLM08, LLM04 | CWE-639 | rules, semgrep |
| AISRF-RG-004 | Vector database client connected without authentication | MEDIUM | LLM08, LLM04 | CWE-306 | rules |
| AISRF-RG-005 | Retrieved chunks inlined into the prompt without delimiters or provenance | HIGH | LLM01, LLM08 | CWE-74 | rules, semgrep |
| AISRF-RG-006 | Answers rendered as Markdown with images or external links allowed | HIGH | LLM02, LLM05 | CWE-200 | rules |
| AISRF-RG-007 | Prompts or model responses written to logs | MEDIUM | LLM02 | CWE-532 | rules |
| AISRF-RG-008 | Query results or prompts cached without a user scope | MEDIUM | LLM02, LLM05 | CWE-524 | rules |
| AISRF-RG-009 | No PII scrubbing before indexing sensitive records | LOW | LLM02 | CWE-359 | rules |
| AISRF-RG-010 | Vector store or embedding service credential hardcoded | HIGH | LLM02, LLM07 | CWE-798 | rules |
| AISRF-RG-011 | Web crawl ingestion without a domain allowlist | MEDIUM | LLM08, LLM04 | CWE-345 | rules |
| AISRF-RG-012 | Conversation memory shared across users | MEDIUM | LLM02, LLM05 | CWE-668 | rules |
| AISRF-RG-013 | User uploads indexed into a shared collection | HIGH | LLM08, LLM04 | CWE-284 | rules |
| AISRF-RG-014 | File names or document metadata interpolated into the prompt | MEDIUM | LLM01, LLM08 | CWE-74 | rules |

### General AI application hygiene (`general`, 11 rules)

Credentials, debug exposure, CORS, rate limits, token and time limits, streaming, runtime key handling, tracing and transport security.

| Rule | Title | Severity | OWASP | CWE | Engines |
| --- | --- | --- | --- | --- | --- |
| AISRF-GN-001 | Hardcoded AI provider credential | CRITICAL | LLM02, LLM07 | CWE-798 | rules, semgrep |
| AISRF-GN-002 | Secret in a prompt, environment or configuration file | HIGH | LLM02, LLM07 | CWE-312 | rules |
| AISRF-GN-003 | Debug mode or introspection endpoint enabled | MEDIUM | LLM07 | CWE-489 | rules |
| AISRF-GN-004 | Permissive CORS on an AI API | MEDIUM | LLM02, LLM05 | CWE-942 | rules |
| AISRF-GN-005 | Model endpoint without rate limiting | MEDIUM | LLM10 | CWE-770 | rules |
| AISRF-GN-006 | Model call without max_tokens or timeout | LOW | LLM10 | CWE-400 | rules |
| AISRF-GN-007 | Streaming response without abort or timeout handling | LOW | LLM10 | CWE-400 | rules |
| AISRF-GN-008 | API key handled unsafely at runtime | HIGH | LLM02, LLM07 | CWE-532 | rules |
| AISRF-GN-009 | Verbose agent tracing enabled | LOW | LLM07 | CWE-532 | rules |
| AISRF-GN-010 | TLS verification disabled for model or tool traffic | MEDIUM | LLM03 | CWE-295 | rules, bandit |
| AISRF-GN-011 | Model name or provider endpoint controlled by the client | MEDIUM | LLM10 | CWE-20 | rules |

Confidence is adjusted per hit: matches inside decorated tool functions, request handlers or files
that import an AI SDK are boosted, weak name-based matches are reduced. Lines that carry an
`aisrf: ignore` (or `nosec`) marker are skipped by the rules engine.

## Engines

| Engine | What it does | Availability |
| --- | --- | --- |
| `rules` | The catalogue above: line regexes with context flags, file-level presence and absence checks and Python AST matchers (taint-like tracking of model output, tool parameters and request data inside functions). Always on. | built in |
| `semgrep` | The rule files under `rules/semgrep/` (53 rules, taint mode where the framework supports it) run in a subprocess. The engine starts the OCaml binary shipped with the semgrep package in `--experimental` mode with its bundled libraries, so it keeps working when the Python CLI cannot start, and falls back to the `semgrep` command otherwise. | `semgrep` extra |
| `bandit` | General Python security checks (subprocess, pickle, yaml, hashes, requests without TLS verification and so on) mapped onto the taxonomy. A bandit hit on the same line and CWE as a catalogue finding is merged into it. | `bandit` extra |
| `llm` | Optional LLM-assisted review, see below. | judge model configured |

Engine selection, packs, include and exclude globs and the file cap are per run options. Defaults
and limits live in the `codereview` settings namespace (`GET /api/settings/ns/codereview`):
`max_archive_bytes`, `max_files`, `max_file_bytes`, `exclude_dirs`, `path_allowlist`,
`retention_days`, the per engine timeouts, `default_engines`, `semgrep_binary`, `bandit_binary` and
the `llm_review` block.

Validate the shipped semgrep rules with `semgrep --validate --config aisrf/codereview/rules/semgrep/`
or, when the Python CLI is unavailable, through the engine itself:

```bash
.venv/bin/python -c "import asyncio; from aisrf.codereview.engines.semgrep_engine import validate_rules; print(asyncio.run(validate_rules()))"
```

## LLM-assisted pass

When `enable_llm_judge` is set (or `codereview.llm_review.enabled` is true) and a judge model is
configured, the highest-signal files (most findings, most AI, tool, RAG, agent and route markers) are
sent to the judge with a fixed rubric covering the six packs. Excerpts are secret-masked and bounded
by `max_chars_per_file`; at most `max_files` files are reviewed. The answer must be a JSON array and
is turned into findings with `engine=llm`, rule ids `AISRF-LLM-<pack code>` (PI, AT, LO, MS, RG, GN) and a confidence capped at
`llm_review.confidence` (0.45 by default) so they never outrank a deterministic rule. Any failure is
recorded in the engine status and never fails the run.

## Findings, summary and risk score

Each finding stores rule, pack, engine, severity, confidence, title, description, remediation, file,
line range, masked snippet, language, OWASP ids, CWE, a stable fingerprint (rule, path and
whitespace-normalised snippet) and a review status (`open`, `false_positive`, `accepted`) with a
note and reviewer. Duplicates across engines are merged; the merged finding lists every engine that
agreed.

The run summary counts open findings by severity, pack, engine, OWASP item and status, lists the top
rules and files and records per engine timings. The risk score (0 to 100) takes the strongest open
finding weighted by confidence and adds the others with halving increments, so one critical finding
dominates and dismissed findings drop out. `risk_level` reuses the analyzer levels.

## REST API

Reads need a principal, run and finding mutations need the `reviewer` role, credentials and local
path intake need `admin`. Every mutation writes an audit entry.

```
GET    /api/codereview/rules?pack=                catalogue, engines and effective configuration
POST   /api/codereview/runs                       {name, source, options} for git, url, path, snippet
POST   /api/codereview/runs/upload                multipart: file, name, options (JSON)
GET    /api/codereview/runs?status=&source_type=  paginated runs
GET    /api/codereview/runs/{id}                  run with inventory and summary
DELETE /api/codereview/runs/{id}                  delete the run, findings and working copy
POST   /api/codereview/runs/{id}/cancel
GET    /api/codereview/runs/{id}/findings         filters: severity (comma list), pack, engine, file, status, rule_id, search
POST   /api/codereview/findings/{id}/status       {status, note}
GET    /api/codereview/runs/{id}/file?path=       file content plus its findings
GET    /api/codereview/runs/{id}/sarif            SARIF 2.1.0 (include_dismissed=true keeps suppressed results)
GET    /api/codereview/credentials                admin
POST   /api/codereview/credentials                admin, {label, provider, token, username}
DELETE /api/codereview/credentials/{id}           admin
GET    /api/codereview/stream?replay=&run_id=     SSE on channel "codereview": run.status, run.progress, finding.status, run.deleted
```

## Dashboard

`/codereview` offers the new run form (tabs for git repository, archive URL, upload, local path and
snippet, pack and engine selection, include and exclude globs), a live runs table fed by the SSE
stream, the credentials manager for administrators and a searchable rule catalogue with OWASP and
CWE chips. `/codereview/<run_id>` shows summary tiles, severity and pack breakdowns, OWASP coverage,
the inventory (frameworks, manifests, model artifacts, prompt and secrets files, MCP servers), engine
status, a filterable findings table with expandable rows (description, why, remediation, numbered
snippet, taxonomy chips, CWE link, false positive and accepted actions with a note), a file viewer
that highlights finding lines and download links for every report format.

## Reports and GitHub code scanning

`GET /api/reports/codereview/<run_id>?format=<json|yaml|csv|tsv|md|html|pdf|xlsx|txt|xml|sarif|junit>`
renders the run through the report subsystem. The SARIF document (also at `.../sarif`) carries the
catalogue as `tool.driver.rules`, a `physicalLocation` with line region and snippet for every
result, `partialFingerprints` with the AISRF fingerprint, `security-severity` and OWASP tags,
suppressions for dismissed findings and the git revision when the source was a repository. Upload
it from CI with the code scanning action:

```yaml
- name: Review with AISRF
  run: |
    aisrf codereview run --git "$GITHUB_SERVER_URL/$GITHUB_REPOSITORY" --ref "$GITHUB_SHA" \
      --token-env GITHUB_TOKEN --wait --format sarif --out aisrf.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: aisrf.sarif
```

## CLI

```bash
aisrf codereview rules --pack model_supply_chain
aisrf codereview run --git https://github.com/org/app.git --ref main --token-env GH_TOKEN --wait --format sarif --out app.sarif
aisrf codereview run --zip ./app.zip --packs prompt_injection --packs llm_output --engines rules --engines semgrep
aisrf codereview run --url https://example.com/app.tar.gz --no-wait
aisrf codereview run --path /var/lib/aisrf/checkouts/app        # admin, allowlisted directory on the server
aisrf codereview list --status COMPLETED
aisrf codereview show crv_...
```

Remote commands take `--url` and `--token` (or `AISRF_URL` and `AISRF_ADMIN_API_TOKEN`). `--token-env`
names an environment variable holding the git or archive token so it never appears in shell history.

## MCP

The MCP server exposes `codereview_rules`, `codereview_start` (same `source` and `options` shape as
`POST /api/codereview/runs`), `codereview_runs`, `codereview_run`, `codereview_findings` (with the
same filters as the API), `codereview_set_finding_status` and `codereview_report` (saves any format,
SARIF by default). Archive uploads are not available over MCP; use a URL or repository instead.

## Limitations

- The engines are static and heuristic. Name based matching and absence checks produce false
  positives on unusual code layouts; confidence and the review status exist to triage them. Absence
  rules (missing rate limit, missing confirmation gate and similar) only see one file at a time.
- Taint tracking in the rules engine is intra-procedural and Python only; the semgrep rules add
  intra-file taint for Python, JavaScript and TypeScript. Nothing follows data across services.
- Only Python code is parsed into an AST. Other languages rely on regular expressions.
- Binary model artifacts are inventoried, not scanned; pair the module with a pickle scanner for
  that.
- The LLM-assisted pass sends masked source excerpts to the configured judge provider; do not enable
  it for code that must not leave the environment.
- Working copies live on the gateway host under the data directory; size the disk and the retention
  period accordingly.
