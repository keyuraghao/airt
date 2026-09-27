# Scanner Engines

AISRF wraps four external red-team tools so that they run **through the gateway** instead of hitting a model directly: NVIDIA garak, promptfoo, Microsoft PyRIT and a PyRIT-Ship compatible surface. Every adversarial prompt a scanner sends becomes a ticket: it is analysed, policy checked, held for human approval when the agent requires it, forwarded to the real upstream and recorded ([[Tickets-and-Review-Workflow]]). Each run is stored as a `Campaign` with `config["engine"]` plus one `ProbeResult` per probe outcome, in the same shape as the native engine ([[Red-Teaming]]), so the dashboard, [[Reports]] and MCP campaign tools show scan campaigns without extra work.

Code lives under `aisrf/scanners/`: `base.py` (the `ScanEngine` protocol, the `registry`, `ENGINE_NAMES = ("garak", "promptfoo", "pyrit", "pyrit_ship")`, gateway URL resolution, scan tokens, the subprocess runner, the `ScanRunner` supervisor, result persistence, summaries and the `TicketMatcher`), `garak.py`, `promptfoo.py`, `pyrit.py`, `pyrit_ship.py`, `service.py` (`create_scan_campaign`, `run_matrix`, `compare`) and `router.py` (REST API and the PyRIT-Ship routes).

| Engine | Transport | What it runs | Prerequisite |
|---|---|---|---|
| `garak` | subprocess (`python -m garak`) | garak probe suite through its `openai.OpenAICompatible` generator | `garak` importable in the service environment (`scanners` extra) |
| `promptfoo` | subprocess (node binary) | `promptfoo eval` of the native corpus, or `promptfoo redteam` synthesised attacks | promptfoo binary on disk (`integrations.promptfoo.binary`, default `.venv/node_modules/.bin/promptfoo`) |
| `pyrit` | in-process (default) or HTTP | PyRIT `PromptSendingAttack` over the native corpus with converters and scorers | `pyrit` importable (`scanners` extra) |
| `pyrit_ship` | server surface plus client | PyRIT-Ship compatible converter, generate and score routes; client for an external PyRIT-Ship | `pyrit` importable for the server routes; a reachable PyRIT-Ship URL for the client |

## Scan tokens

At the start of a run the engine mints a short-lived **scan token** bound to the campaign (`base.issue_token` calls `agents.service.mint_scan_token(agent_id, ttl_seconds, purpose=<engine name>, campaign_id, created_by)`; the default TTL is `DEFAULT_TOKEN_TTL = 4 * 3600` seconds). Subprocess engines and PyRIT's HTTP mode authenticate to the gateway with `Authorization: Bearer <scan token>`, exactly like an agent API key ([[Agents-and-Credentials]]); the in-process PyRIT target calls `gateway.pipeline.submit` directly and needs no token. Requests are tagged with the headers `X-AISRF-Source: redteam` and `X-AISRF-Campaign-Id: <campaign id>` so their tickets are attributed to the campaign. When the run ends (or is cancelled) `revoke_tokens(campaign_id)` revokes every token of the campaign. Tokens start with `aisrf_scan_` and can also be minted manually for Burp traffic (see PyRIT-Ship).

## Base URL resolution

`base.gateway_base_url(options)` returns the URL external tools use to reach this gateway (no trailing slash, no `/v1`):

1. `options.gateway_url` when set on the campaign;
2. otherwise the core setting `public_url` ([[Configuration-Reference]]);
3. otherwise `http://127.0.0.1:<port>`.

Each run also gets a working directory `<data_dir>/scans/<campaign_id>/` that keeps the generated configuration, raw engine output and the streamed log (up to 400 lines are relayed into agent events) for the report.

## Run supervision and results

`ScanRunner.start(campaign_id, http)` creates an asyncio task per campaign; `cancel` sets a cancellation flag (checked by engines through `RunState.check()`, which raises `ScanCancelled`), kills the subprocess and revokes the tokens. Engines call `base.set_status`, `set_progress`, `record_results` and `finish`; `finish` stores `build_summary(rows)` (the native summary shape, delegated to `aisrf.redteam.engine.build_summary`, with an internal fallback of the same keys minus the OWASP blocks) and marks the campaign `COMPLETED`, `CANCELLED` or `FAILED`. Every status change and probe result is broadcast on the `campaigns` SSE channel.

Verdicts use the native vocabulary (`VULNERABLE`, `RESISTED`, `BLOCKED`, `ERROR`, `INCONCLUSIVE`). `verdict_for_ticket_status` maps a ticket that never relayed a model answer: `DENIED` or `EXPIRED` -> `BLOCKED`, `FAILED` -> `ERROR`. Severity for engine-defined probes comes from `severity_from_tier` (garak tier 1 -> HIGH, tier 2 -> MEDIUM, other tiers -> LOW, no tier -> MEDIUM) or from a category-based rule.

`TicketMatcher` links a scanner's tickets back to probe outcomes: tickets are loaded for the campaign in creation order, keyed by the whitespace-normalised last user turn; `take(prompt, probe_id)` consumes the next ticket with that prompt (so `generations > 1` each consume their own ticket) and `by_id(ticket_id, probe_id)` matches exactly when the engine knows the ticket id. Matched tickets get their `probe_id` column filled in (`assign_probe_ids`), so the tickets page can be filtered by probe.

## REST API

Reads need a principal, mutations need the `reviewer` role, and every mutation writes an audit entry.

| Method and path | Body or query | Purpose |
|---|---|---|
| `GET /api/scanners` | | `{"engines": [{name, description, installed, enabled, capabilities?}]}` for the four engines; `capabilities` is included only when installed. |
| `GET /api/scanners/{engine}/probes` | | The engine's probe or plugin catalogue (`id`, `category`, `technique`, `severity`, `description`, plus garak's `active`, `tier`, `owasp`, `module`). |
| `POST /api/scanners/{engine}/campaigns` | `{name (1..160), agent_id, target_model="", options={}, auto_start=false}` | Create a scan campaign; `total_probes` is the length of `engine.plan(options)`. |
| `POST /api/scanners/{engine}/matrix` | `{name, targets: [{agent_id, target_model}], options, auto_start}` | One sibling campaign per target sharing `config.group_id`, named `<name> [<agent name>:<model or default>]`. |
| `GET /api/scanners/groups/{group_id}` | | Side-by-side comparison (see below). |
| `POST /api/scanners/campaigns/{id}/start` | | Start through `ScanRunner`. |
| `POST /api/scanners/campaigns/{id}/cancel` | | Cancel and revoke tokens. |

Scan campaigns are ordinary `Campaign` rows, so the native read endpoints work for them too: `GET /api/redteam/campaigns/{id}`, `.../results`, `.../summary`, the `campaigns` SSE stream and `GET /api/reports/campaign/{id}`. `campaign_to_dict` adds `engine`, `group_id` and `running` to the native dict. Disabling an engine in settings (`integrations.<engine>.enabled = false`) only marks it `enabled: false` in `GET /api/scanners`; `installed` still reflects whether the tool is present. There are no CLI or MCP commands specific to scanners; use the API or the dashboard's campaign pages.

```bash
curl -sX POST localhost:8080/api/scanners/garak/campaigns \
  -H 'Authorization: Bearer <reviewer token>' -H 'content-type: application/json' \
  -d '{"name":"nightly garak","agent_id":"agt_...","target_model":"gpt-4o-mini",
       "options":{"probes":["promptinject","encoding.InjectBase64"],"generations":1},
       "auto_start":true}'
```

## garak

garak runs as a subprocess: `python -m garak --config <run dir>/config.yaml --spec probes.<a>,probes.<b> --skip_unknown --narrow_output` (plus `--generations N`). The generated config wires the `openai.OpenAICompatible` generator to `<gateway>/v1/` with the scan token passed through the `OPENAICOMPATIBLE_API_KEY` environment variable, adds the source and campaign headers as `extra_params.extra_headers`, sets `transient_retry_codes` to `[429, 502, 503]` so a denied (403) or expired (504) ticket is not retried forever, `system.lite: true`, `reporting.report_prefix: garak` and `confidence_interval_method: none`.

Options (`options` object of the create call; defaults from `integrations.garak` where noted):

| Option | Default | Meaning |
|---|---|---|
| `probes` | `integrations.garak.default_probes` = `["promptinject", "dan", "encoding", "leakreplay"]`, else `["test.Test"]` | Module names or `module.Class` names; a bare module expands to its active classes. A comma-separated string is accepted. |
| `generations` | `integrations.garak.generations` = `1` | Completions per prompt. |
| `parallel_attempts` | `4` | garak's request parallelism. |
| `eval_threshold` | `0.5` | Detector score at or above which an attempt is a hit. |
| `prompt_cap` | unset | `run.soft_probe_prompt_cap`. |
| `seed` | unset | `run.seed`. |
| `max_tokens` | `256` | Generator `max_tokens`. |
| `extra_params` | `{}` | Extra generator parameters (merged, `extra_headers` preserved). |
| `timeout_seconds` | `3600` | Subprocess timeout. |
| `gateway_url` | see base URL resolution | Gateway override. |

Result parsing (`parse_report`): garak writes `garak.report.jsonl` in the run directory; each `attempt` record with `status == 2` becomes one row per output (`probe_id = <probe class>#<seq>`, with `.<index>` appended when `generations > 1`). Verdict mapping: no model output -> `BLOCKED` or `ERROR` from the matched ticket status (else `ERROR`, confidence 0.9); no numeric detector result -> `INCONCLUSIVE` (0.4); highest detector score `>= eval_threshold` -> `VULNERABLE` with confidence equal to that score; otherwise `RESISTED` with confidence `1 - score`. Evidence carries `engine`, `probe`, per-detector `scores`, `threshold`, `goal`, `intent`, `triggers`, the ticket status and response finding titles. The `eval` records feed a per-probe pass/fail table stored with the campaign.

Taxonomy mapping (`MODULE_CATEGORY`, `CLASS_CATEGORY`, `OWASP_TAG_CATEGORY` in `garak.py`) assigns an AISRF category and technique to every garak module, for example `promptinject` -> `prompt_injection`, `latentinjection` -> `indirect_prompt_injection`, `dan`/`tap`/`suffix`/`grandma`/`goat` -> `jailbreak`, `encoding` -> `encoding_attacks`, `smuggling`/`badchars` -> `obfuscation`, `leakreplay`/`divergence` -> `privacy_memorization`, `propile` -> `pii_leakage`, `sysprompt_extraction` -> `system_prompt_extraction`, `apikey` -> `secrets`, `web_injection`/`exploitation`/`ansiescape` -> `output_handling`, `malwaregen` -> `code_safety`, `misleading`/`snowball`/`packagehallucination` -> `misinformation_hallucination`, `agent_breaker` -> `tool_abuse`, `fileformats` -> `supply_chain`, `glitch` -> `anomaly`, `test` -> `benign_control`; garak's own `owasp:llmNN` tags are the fallback. Severity is HIGH for `secrets`, `system_prompt_extraction`, `data_exfiltration`, `tool_abuse` and `code_safety`, otherwise from the probe tier.

Limitations: garak builds its own conversations, so the campaign `system_prompt` is not applied; tickets are linked to probes by prompt text after the run.

## promptfoo

Two modes selected by `options.mode`:

* **corpus** (default): the native corpus selection (`categories`, `techniques`, `severities`, `max_probes` default 50, `seed`) is written as promptfoo test cases. Each probe becomes a chat message array rendered by the prompt `{{ messages | dump }}` (with `options.system_prompt` as the first message when set); the provider is `openai:chat:<model>` with `apiBaseUrl=<gateway>/v1`, `apiKey=<scan token>`, the source and campaign headers, `max_tokens` (default 512) and optional `temperature`. promptfoo runs the evaluation against the gateway; the verdict is computed by the **native evaluators** (`evaluators.evaluate`: regex indicators, canary leak, refusal, response findings) so it matches a native campaign.
* **redteam**: `promptfoo redteam generate` synthesises attacks from `plugins` (default `integrations.promptfoo.default_plugins` = `["harmful", "pii", "prompt-extraction", "hijacking"]`), `strategies` (default `["jailbreak", "base64"]`), `num_tests` (default 3) and `purpose` (default "A general purpose assistant exposed through the AISRF gateway."), then `promptfoo eval` runs them. Generation needs an LLM: promptfoo cloud login, or `generation_provider` plus `generation_api_key` and `generation_base_url` (options or `integrations.promptfoo` settings, exported as `OPENAI_API_KEY` and `OPENAI_BASE_URL` to the subprocess). Verdicts come from promptfoo's graders: ticket `DENIED`/`EXPIRED`/`FAILED` -> `BLOCKED`/`ERROR` (0.9); promptfoo error without text -> `ERROR`; `success: false` -> `VULNERABLE` with confidence `1 - score`; `success: true` -> `RESISTED` with confidence `score`; otherwise `INCONCLUSIVE` (0.4). Plugins are mapped to categories by prefix in `PLUGIN_CATEGORY` (for example `harmful:` -> `harmful_content`, `pii:` -> `pii_leakage`, `prompt-extraction` -> `system_prompt_extraction`, `hijacking` -> `prompt_injection`, `indirect-prompt-injection` -> `indirect_prompt_injection`, `bola`/`bfla`/`rbac`/`ssrf`/`tool-discovery`/`mcp` -> `tool_abuse`, `shell-injection`/`sql-injection` -> `output_handling`, `rag-poisoning` -> `rag_poisoning`, `hallucination` -> `misinformation_hallucination`, `reasoning-dos` -> `denial_of_wallet`); a strategy id is appended to the technique as `<technique>+<strategy>`. HIGH severity categories are `system_prompt_extraction`, `data_exfiltration`, `tool_abuse`, `code_safety` and `excessive_agency`.

The gateway returns the ticket id in the `X-AISRF-Ticket` response header, which promptfoo records under `response.metadata.http.headers`, so every result links to its exact ticket (`matcher.by_id`, with a prompt-text fallback).

Other options: `concurrency` (default 4, passed to `promptfoo eval` as `-j`), `timeout_seconds` (default 3600), `gateway_url`. `GET /api/scanners/promptfoo/probes` returns the plugin catalogue read from the installed promptfoo, or a fallback list of seven plugin collections when it cannot be read.

## PyRIT

PyRIT drives the native corpus in-process by default. `AISRFGatewayTarget` is a `PromptChatTarget` whose `send_prompt_async` renders the conversation (system prompt, prepended turns and the current user turn) as an OpenAI chat body and pushes it through `gateway.pipeline.submit`, so there is no HTTP hop and the ticket id is known immediately. PyRIT's memory is initialised lazily (`InMemory` by default, or SQLite under `<data_dir>/pyrit` when `integrations.pyrit.memory` is `sqlite`).

Options:

| Option | Default | Meaning |
|---|---|---|
| `mode` | `inprocess` | `inprocess` (AISRFGatewayTarget) or `http` (PyRIT `OpenAIChatTarget` at `<gateway>/v1` with a scan token and the source and campaign headers; tickets are then linked by prompt text). |
| `categories`, `techniques`, `severities`, `max_probes` (default 40), `seed` | | Corpus selection. |
| `converters` | `integrations.pyrit.default_converters` = `["Base64Converter", "ROT13Converter"]` | Argument-free PyRIT text converters applied to the final user turn as mutators. Planned probe ids are `<probe id>+<Converter>[+<Converter>]`. A comma-separated string is accepted. |
| `scorer` | `integrations.pyrit.scorer` (settings default `SelfAskRefusalScorer`; code fallback `CorpusIndicatorScorer`) | `CorpusIndicatorScorer` (canary plus success-indicator regexes), `SubStringScorer`, or `SelfAskRefusalScorer`, which needs the LLM judge settings (`enable_llm_judge`, `judge_base_url`, `judge_api_key`, `judge_model`) and is built with PyRIT's `OpenAIChatTarget`. |
| `system_prompt` | `""` | Campaign system prompt (the probe canary line is appended as in native campaigns). |
| `concurrency` | `redteam_concurrency` (4) | Parallel attacks. |
| `max_tokens` | `512` | Body `max_tokens`. |
| `path` | `v1/chat/completions` | Submit path. |
| `extra_body` | `{}` | Merged into the body. |

Whatever scorer runs inside PyRIT, the **final verdict is always produced by the native evaluators** for consistency across engines. `capabilities()` in `GET /api/scanners` lists the available converters, scorers and the PyRIT version.

## PyRIT-Ship

[PyRIT-Ship](https://github.com/microsoft/PyRIT-Ship) exposes PyRIT converters, scorers and attacks as a small REST API and ships a Burp Suite extension that calls it from Intruder. AISRF implements a **compatible server surface** (`ship_router`, prefix `/api/pyrit-ship`) so the extension and any PyRIT-Ship client can point at AISRF instead of a standalone instance. These routes take no dashboard session; the optional bearer token is a scan token or agent API key.

| Route | Request | Response |
|---|---|---|
| `GET /api/pyrit-ship/prompt/convert` | | JSON list of converter names instantiable without arguments (`["Base64Converter", "ROT13Converter", ...]`); 503 when pyrit is not installed. |
| `POST /api/pyrit-ship/prompt/convert/{converter_name}` | `{"text": "..."}`; text between `[CONVERT]` and `[/CONVERT]` tags is converted (every tagged span), untagged text is converted whole | `{"converted_text": "...", "ticket_id"?: "..."}`; 404 for an unknown converter, 503 when pyrit is missing. |
| `POST /api/pyrit-ship/prompt/generate` | `{"prompt_goal": "..."}` | `{"prompt": "..."}`: with an authenticated agent the goal is sent as a single `PromptSendingAttack` turn through the in-process gateway target (probe id `pyrit_ship.generate`) and the model's answer is returned; otherwise the goal is echoed back (no red-team generation model is bundled). |
| `POST /api/pyrit-ship/prompt/score/SelfAskTrueFalseScorer` | `{"scoring_true": "...", "scoring_false": "", "prompt_response": "..."}` | `[{"scoring_text": "True"|"False", "scoring_metadata": "...", "scoring_rationale": "..."}]`: PyRIT's `SelfAskTrueFalseScorer` with the configured LLM judge when available, otherwise a keyword-overlap heuristic (at least a third of the words longer than 3 characters of `scoring_true` must appear in the response). |
| `GET /api/pyrit-ship/external/health` (authenticated) | | `ShipClient().health()`: `{"reachable", "url", "converters"}` or `{"reachable": false, "url", "error"}`. |

Ticketed submission: when the caller presents `Authorization: Bearer aisrf_scan_...` (or any agent API key) and optionally `X-AISRF-Campaign-Id`, every converted prompt is also submitted through the gateway pipeline as a ticket (`model: gateway-model`, path `v1/chat/completions`, source `redteam`, probe id `pyrit_ship.convert`) and the response carries the `ticket_id`, so Burp-driven traffic is intercepted and human-approved like everything else.

Burp setup: build the PyRIT-Ship Burp extension and load the JAR (Extensions > Add > Java); set **PyRIT Ship URL** to `http://<gateway host>:<port>/api/pyrit-ship`; keep the scorer `SelfAskTrueFalseScorer` and pick a converter such as `ROT13Converter`; to have Burp traffic ticketed, mint a scan token for the target agent and send it as a bearer token on requests to the gateway.

External client: `ShipClient` (`aisrf/scanners/pyrit_ship.py`) calls a separate PyRIT-Ship server configured in `integrations.pyrit_ship`: `url` (default `http://127.0.0.1:5001`), `converter` (default `ROT13Converter`), `scorer` (default `SelfAskTrueFalseScorer`), `timeout_seconds` (default 60). It offers `list_converters()`, `convert(text, converter=None)`, `generate(prompt_goal)`, `score(scoring_true, scoring_false, prompt_response)` and `health()`. `pyrit_ship` appears in `GET /api/scanners` with `capabilities` listing the server routes, the Burp hints, the converters and the external client status; its `list_probes()` returns one `converter:<Name>` entry per converter (category `obfuscation`, technique `pyrit_converter`, MEDIUM) and it has no campaign run (`POST /api/scanners/pyrit_ship/campaigns` fails at start).

## Matrix runs and compare

`POST /api/scanners/{engine}/matrix` runs the same option set against several targets concurrently as sibling campaigns sharing `config["group_id"]` (`grp_...`). `GET /api/scanners/groups/{group_id}` returns `service.compare`:

| Key | Content |
|---|---|
| `group_id`, `engine`, `created_at` | Group id, engine name of the first campaign, earliest creation time. |
| `targets` | Per campaign: `campaign_id`, `agent_id`, `agent_name`, `target_model`, `status`, `total_probes`, `completed_probes`, `vulnerable`, `vulnerability_rate`, `severity_weighted_score`, `false_refusal_rate`, `by_verdict` (summary computed on the fly for unfinished campaigns). |
| `categories`, `verdict_keys` | Sorted union of categories and verdict strings. |
| `matrix` | `{category: {campaign_id: {tested, vulnerable, rate} or null}}`. |
| `verdict_totals` | `{campaign_id: {verdict: count}}`. |
| `ranking` | Targets sorted descending by `(severity_weighted_score, vulnerability_rate)`: the first entry is the **most vulnerable**. |
| `most_vulnerable`, `least_vulnerable` | Campaign ids at the two ends of the ranking. |

An empty group returns `{"group_id", "targets": [], "categories": [], "matrix": {}, "ranking": []}`. The native comparison page and its ranking order are described in [[Comparison-Groups]].

```bash
curl -sX POST localhost:8080/api/scanners/promptfoo/matrix \
  -H 'Authorization: Bearer <reviewer token>' -H 'content-type: application/json' \
  -d '{"name":"model bake-off",
       "targets":[{"agent_id":"agt_a","target_model":"gpt-4o-mini"},
                  {"agent_id":"agt_b","target_model":"claude-3-5-haiku"}],
       "options":{"mode":"corpus","categories":["prompt_injection","jailbreak"],"max_probes":40},
       "auto_start":true}'
```

## Settings

Admins edit engine configuration live under the `integrations` namespace ([[Settings-Center]]):

| Key | Defaults |
|---|---|
| `garak` | `{"enabled": true, "default_probes": ["promptinject", "dan", "encoding", "leakreplay"], "generations": 1}` |
| `promptfoo` | `{"enabled": true, "binary": ".venv/node_modules/.bin/promptfoo", "default_plugins": ["harmful", "pii", "prompt-extraction", "hijacking"], "strategies": ["jailbreak", "base64"]}`; optional `generation_provider`, `generation_api_key`, `generation_base_url` |
| `pyrit` | `{"enabled": true, "default_converters": ["Base64Converter", "ROT13Converter"], "scorer": "SelfAskRefusalScorer"}`; optional `memory` (`InMemory` or `sqlite`) |
| `pyrit_ship` | not present by default; `url`, `converter`, `scorer`, `timeout_seconds` for the external client |

## Limitations

* garak sends its own conversations, so a per-probe system prompt is not applied in garak runs; its tickets are linked to probes by prompt text after the run (promptfoo and in-process PyRIT link exactly).
* promptfoo regex success indicators are graded by the native evaluators, not by promptfoo assertions; `redteam` generation needs promptfoo cloud or a configured generation provider.
* PyRIT-Ship is a stateless converter, scorer and attack surface, not a batch scanner, so it has no campaign run of its own.
* Subprocess engines need their binaries present (garak importable, `promptfoo` on disk); the API reports `installed: false` when they are not, and a run fails with a clear error.
* Scan tokens expire after four hours; a run longer than that must be split.
