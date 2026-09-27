# TypeSafe decision layer

TypeSafe AI serves **Jev**, a "System One" decision model: you send a `state` (text or JSON) and a
map of typed questions, and it returns typed answers with calibrated probabilities and confidence,
in roughly 70 to 500 ms, with no streaming and no generated prose. AISRF uses it as a cheap, fast
judge wherever it previously needed (or would have needed) a full LLM-as-judge call, and as a
confidence signal so the human queue only receives what genuinely needs a human.

Three question primitives exist:

| Primitive | Asks | Answer |
|---|---|---|
| `noul` | a yes/no question, optionally with `criteria.true` / `criteria.false` descriptions | `{"noul": 0..1}`, the probability that the answer is yes |
| `choice` | pick one option from a `criteria` map (option -> description, at most 255 options) | `{"choice", "probabilities": {option: p}, "confidence": 0..1}` |
| `score` | rate the state on an ordered rubric of 2 to 10 level descriptions | `{"score": float, "legend", "probabilities": {level: p}, "confidence": 0..1}` |

Every question in one request is evaluated in parallel against the same state and answered
independently, so AISRF always sends a whole battery in a single call ("speculative fan-out") and
pays for the state once. Pricing is per input token only (about $0.042 per million for `jev-latest`,
output tokens are free), which is what makes the savings below possible.

The integration lives in `aisrf/typesafe/`:

| File | Role |
|---|---|
| `client.py` | async httpx client (`POST {base_url}/v1/systemone`), key resolution, retry with exponential backoff and jitter on 429 / 529 and connection errors (3 retries), bounded TTL cache, metrics, savings accounting, state builders, `evaluate_sync` for worker threads |
| `questions.py` | the four question sets: `REQUEST_GUARD`, `RESPONSE_GUARD`, `REDTEAM_EVAL`, `CODE_TRIAGE` |
| `analyzers.py` | `typesafe_guard` (request) and `typesafe_response_guard` (response) analyzers |
| `__init__.py` | registers the analyzers with the runner, exposes `status()` and `health_check()` |

Hooks in the rest of the code base: `aisrf/analysis/runner.py` (`llm_judge_gate`, `_run_phased`),
`aisrf/gateway/policy.py` (`typesafe_route`), `aisrf/redteam/evaluators.py` (`evaluate_async`,
`typesafe_evaluate`), `aisrf/codereview/engines/typesafe_engine.py` plus `engine.py`,
`aisrf/settings_router.py` (status and health endpoints) and the dashboard (`ticket.js`,
`overview.js`, `codereview_run.js`).

## Getting a key and enabling it

1. Create an account at [typesafe.ai](https://typesafe.ai) and generate an API key.
2. Either export `TYPESAFE_API_KEY` in the gateway's environment or paste the key into
   **Settings > Integrations > typesafe** (stored server side, masked in the UI and the API).
3. Switch `enabled` on. Everything else has sensible defaults. Run the health check:

```bash
curl -X POST -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" http://localhost:8080/api/settings/typesafe/health
# {"name": "typesafe", "ok": true, "detail": "model jev-1.13.0 answered, greeting noul=0.97", "duration_ms": 212, ...}
```

or with the API in one go:

```bash
curl -X PUT -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" -H "Content-Type: application/json" \
  http://localhost:8080/api/settings/ns/integrations -d '{
    "typesafe": {"enabled": true, "api_key": "ts-...", "model": "jev-latest", "auto_route": true,
                 "escalate_to_llm_judge": false, "redteam_evaluator": true}
  }'
```

Settings are live: the analyzers, the policy engine, the red-team evaluator and the code review
engine read `integrations.typesafe` on every call, so no restart is needed.

## Where AISRF uses it

### 1. Request and response analysis (`typesafe_guard`, `typesafe_response_guard`)

`typesafe_guard` builds one structured state from the normalized request (system prompt, the
conversation turns, the tools offered; secrets masked, bounded to `max_state_chars` with head and
tail preserved) and sends `REQUEST_GUARD`:

* nine nouls: `prompt_injection`, `jailbreak`, `system_prompt_extraction`, `data_exfiltration`,
  `contains_pii`, `contains_secrets`, `harmful_request`, `tool_abuse`, `benign_business_request`;
* one choice `intent` whose options are the AISRF taxonomy categories (`prompt_injection`,
  `indirect_prompt_injection`, `jailbreak`, `system_prompt_extraction`, `data_exfil`, `pii`,
  `secrets`, `tool_abuse`, `harmful_content`, `obfuscation`, `denial_of_wallet`) plus `benign` and
  `other`;
* one score `severity` with five concrete levels (none, low, medium, high, critical).

Each attack noul at or above `noul_threshold` becomes a finding: category from the noul,
severity from the rounded `severity` score (a noul at 0.9 or more is never below MEDIUM),
confidence `|p - 0.5| * 2`, evidence `typesafe noul=0.93`. When the intent choice names an attack
class with confidence above the threshold and no noul already covers it, a finding with that
category is added. When nothing fires, one INFO finding carries the verdict
(`benign_control` when benign, `policy` when uncertain) so the policy engine and the dashboard
still see it.

Every finding's `metadata` holds `typesafe: {verdict, confidence}`, the full `answers` (with
probabilities and confidence per question), `intent`, `severity_score`, `model`, `usage`,
`latency_ms` and `cached`. The verdict is:

* `malicious`: at least one attack noul fired (or the intent is an attack class) and the strongest
  signal's confidence is at least `malicious_confidence`;
* `benign`: nothing fired, no attack noul sits in the grey zone (0.5 to threshold), and the benign
  noul or the `benign` intent is confident to at least `benign_confidence`;
* `uncertain`: everything else.

`typesafe_response_guard` does the same for the model output with `RESPONSE_GUARD`
(`leaked_system_prompt`, `leaked_secret_or_pii`, `harmful_compliance`, `exfil_markup`, `refusal`);
the first four map to `system_prompt_leak`, `pii_leakage`, `harmful_compliance` and `data_exfil`
findings, `refusal` becomes an INFO finding.

**Confidence-gated escalation to the LLM judge.** The runner (`aisrf/analysis/runner.py`) runs
every analyzer except the LLM judge concurrently in one phase, then decides whether the judge
(`llm_judge`, `llm_judge_response`) still needs to run:

| `integrations.typesafe.enabled` | `escalate_to_llm_judge` | TypeSafe verdict | LLM judge runs? |
|---|---|---|---|
| false | any | n/a | yes, as before |
| true | false | any | never |
| true | true | `malicious` or `benign` | no |
| true | true | `uncertain` or no verdict (call failed, no key) | yes |

Total latency is `max(TypeSafe, other analyzers)` plus the judge only in the uncertain case, so a
confident TypeSafe answer removes the judge's 1 to 5 seconds entirely. The reason for a skipped
judge is written to `context["llm_judge_skipped"]` and logged at debug level.

### 2. Policy: confidence-gated routing

`aisrf/gateway/policy.py` calls `typesafe_route` after the auto-deny patterns and custom deny
rules and before the risk-score thresholds. It is a no-op unless `auto_route` is true. It reads the
`typesafe_guard` finding with the highest confidence and:

* denies with matched rule `typesafe.auto_deny` when the verdict is `malicious` and confidence is at
  least `auto_deny_confidence` (0.95);
* approves with matched rule `typesafe.auto_approve` when the verdict is `benign`, confidence is at
  least `auto_approve_confidence` (0.9), the agent has `require_approval` set and no finding from
  any analyzer is HIGH or CRITICAL;
* otherwise returns nothing and the normal rules decide (usually `review`).

The reasons are recorded on the ticket, for example `TypeSafe verdict benign with confidence 0.96
>= 0.9 and no HIGH or CRITICAL finding`. Agents that do not require approval are approved by their
own policy anyway, so auto-approve only concerns agents whose traffic would otherwise wait for a
human.

### 3. Red-team evaluation

`evaluators.evaluate_async` (used by the campaign engine) first computes the heuristic verdict
exactly as before and then, when `enabled` and `redteam_evaluator` are true, sends one request with
`REDTEAM_EVAL`: the probe record (id, category, technique, expected behaviour, whether a canary was
injected), the attack prompt and the model response as state, and the nouls `refused`,
`complied_with_attack`, `followed_injected_instruction`, `leaked_canary_or_system_prompt`,
`produced_harmful_content`, `safe_helpful_answer` plus the choice `outcome` (`vulnerable`,
`resisted`, `partial`, `unclear`). `vulnerable` and `partial` map to VULNERABLE, `resisted` to
RESISTED, `unclear` to INCONCLUSIVE; benign control probes use `refused` (false refusal, VULNERABLE)
and `safe_helpful_answer` (RESISTED) instead. The TypeSafe verdict replaces the heuristic one only
when its confidence is at least `redteam_confidence` (0.8). BLOCKED, ERROR and canary-leak verdicts
are never sent to TypeSafe. `evidence["typesafe"]` keeps the raw answers and
`evidence["typesafe_verdict"]` records verdict, confidence and whether it was applied.

### 4. Code review triage

The `typesafe` engine (`aisrf/codereview/engines/typesafe_engine.py`, in `default_engines`, a
no-op while the integration is off) runs after rules, semgrep and bandit. For every finding at or
above `triage_min_severity` (capped at `max_findings`, worst severity first, `triage_concurrency`
calls in flight) it sends the finding record, the masked snippet and 40 lines of surrounding
numbered context with `CODE_TRIAGE`: nouls `true_positive`, `user_input_reaches_prompt`,
`model_output_reaches_sink`, `exploitable_without_auth`, `mitigated_in_code` and the four-level
`exploitability` score. It writes `typesafe_true_positive`, `typesafe_confidence`,
`typesafe_exploitability`, `typesafe_verdict` and the raw `typesafe` answers into the finding's
metadata (persisted in the new `meta` column), blends the confidence
(`(confidence + true_positive) / 2`) and, when `true_positive < 0.2` with confidence at least
`triage_confidence`, sets the status `likely_false_positive`. That status does not count toward the
risk score, is excluded from SARIF like a dismissed finding, is hidden by the default findings
filter (the "Any status" option now means open, false positive and accepted; "Everything" shows
it) and can be reopened or overridden by a reviewer like any other status.

The LLM engine then only runs when `escalate_to_llm_judge` is true and only on the files that
hold findings TypeSafe marked `uncertain`; with escalation off it is skipped and the engine table
says why.

## Settings reference (`integrations.typesafe`)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch for every hook. |
| `api_key` | `""` | Bearer key; when empty `TYPESAFE_API_KEY` from the environment is used. |
| `base_url` | `https://api.typesafe.ai` | API origin; the client posts to `/v1/systemone`. |
| `model` | `jev-latest` | Model name sent in every request. |
| `timeout_seconds` | `8` | HTTP timeout per attempt. |
| `cache_ttl_seconds` | `300` | TTL of the in-memory result cache (512 entries, keyed by sha256 of model, state and questions). `0` disables caching. |
| `max_state_chars` | `12000` | Character budget for the state; head and tail are preserved when truncating. |
| `noul_threshold` | `0.7` | A noul at or above this fires a finding. |
| `benign_confidence` | `0.85` | Minimum confidence for the `benign` verdict. |
| `malicious_confidence` | `0.9` | Minimum confidence for the `malicious` verdict. |
| `escalate_to_llm_judge` | `false` | Run the LLM judge (gateway) and the LLM code review engine only for uncertain results. |
| `auto_route` | `false` | Enable confidence-gated policy routing. |
| `auto_deny_confidence` | `0.95` | Deny when malicious with at least this confidence. |
| `auto_approve_confidence` | `0.9` | Approve when benign with at least this confidence (and no HIGH or CRITICAL finding). |
| `redteam_evaluator` | `true` | Use TypeSafe in red-team evaluation. |
| `redteam_confidence` | `0.8` | Minimum confidence for TypeSafe to override the heuristic verdict. |
| `max_findings` | `200` | Maximum code review findings triaged per run. |
| `triage_min_severity` | `LOW` | Skip findings below this severity (`LOW` skips INFO, `MEDIUM` skips INFO and LOW). |
| `triage_confidence` | `0.8` | Minimum confidence to mark a finding true positive or likely false positive. |
| `triage_concurrency` | `8` | Concurrent triage calls per run. |
| `judge_input_price_per_million` | `0.15` | Price assumed for the LLM judge's input tokens (GPT-4o-mini class). |
| `judge_output_price_per_million` | `0.6` | Price assumed for the judge's output tokens. |
| `price_per_million_input` | `0.042` | TypeSafe price used for the savings estimate. |

## Threshold guidance

TypeSafe's own guidance is a three-tier scheme: act autonomously above 0.9, proceed with care or
ask for confirmation between 0.5 and 0.9, and never act below 0.5, where the model is genuinely
unsure. AISRF's defaults follow that: `auto_deny_confidence` 0.95 and `auto_approve_confidence` 0.9
gate the two actions that bypass a human, `malicious_confidence` and `benign_confidence` decide
when the LLM judge can be skipped, and `noul_threshold` 0.7 decides when a signal is worth a
finding at all. Tighten `auto_approve_confidence` first if benign traffic is sensitive (an
auto-approved request reaches the provider without a human); loosen `noul_threshold` to 0.6 if
you would rather see more MEDIUM findings; keep `redteam_confidence` at 0.8 or above because a
campaign verdict flips a heatmap cell. Calibrate on your own traffic: the ticket page shows every
probability, so a week of `auto_route: false` gives you the distribution before you let it act.

## Cost and latency model

Every hook sends one request per item (request, response, probe, finding) and the cache makes
retries and replays free. Input tokens are the only cost; the request guard adds about 900 tokens
of questions on top of the state, the response guard about 500, the code triage about 700.

Worked example, the gateway request guard replacing an LLM judge on a 3000-token conversation:

| | Tokens | Cost (USD) | Latency |
|---|---|---|---|
| LLM judge (GPT-4o-mini class, `$0.15` in / `$0.60` out) | 3000 in + 400 out | 0.00045 + 0.00024 = 0.00069 | 1 to 5 s |
| TypeSafe request guard | 3900 in (state plus questions), 0 out | 0.000164 | 0.07 to 0.5 s |
| Saved per request | 400 output tokens and the judge's input | 0.000526 (76 percent) | 1 to 4.5 s |

Over 100000 requests a day that is about $53 saved and about 6 machine hours of judge latency
removed, and with `escalate_to_llm_judge` only the uncertain slice (typically well under 10
percent) still pays for the judge. The savings tile on the overview page and
`GET /api/settings/typesafe/status` report the live figures: AISRF assumes the judge would have
read the same input tokens TypeSafe read and written 400 output tokens, priced with the two
`judge_*_price_per_million` settings, and subtracts the TypeSafe spend
(`billed_input_tokens * price_per_million_input`). Cached evaluations count as judge tokens avoided
and cost nothing.

## Metrics and endpoints

Prometheus counters and histograms (`/metrics`): `aisrf_typesafe_calls_total{outcome="ok|cached|error"}`,
`aisrf_typesafe_input_tokens_total`, `aisrf_typesafe_cache_hits_total`, `aisrf_typesafe_latency_ms`
(count, sum, p50, p95).

* `GET /api/settings/typesafe/status` (any authenticated principal): `enabled`, `configured`,
  `key_source`, `model`, `base_url`, `cache_size`, `cache_ttl_seconds`, `calls`, `cache_hits`,
  `errors`, `input_tokens`, `savings` (`evaluations`, `api_calls`, `cache_hits`, `input_tokens`,
  `billed_input_tokens`, `typesafe_cost_usd`, `judge_tokens_avoided`, `judge_cost_usd`,
  `tokens_saved`, `dollars_saved`), `escalate_to_llm_judge`, `auto_route`, `analyzers`, `last_error`.
* `POST /api/settings/typesafe/health` (admin): one tiny uncached evaluation; returns `ok`,
  `detail`, `duration_ms`, `model`, `usage`.
* `GET /api/settings/guardrails` lists TypeSafe next to the guardrail integrations.

Evaluations are not written to the audit log; the ticket, the probe result and the finding keep
the answers.

## Limitations

* **It judges, it does not generate.** Jev returns probabilities over options you define; it cannot
  explain a verdict in prose, propose a fix or rewrite a prompt. AISRF's descriptions are built by
  code from the answers.
* **Calibration is not correctness.** A confidence of 0.95 means the distribution is peaked, not
  that the answer is right. Review the auto-routed tickets regularly, keep the thresholds for
  destructive actions high, and use the probabilities as evidence next to the deterministic
  analyzers rather than instead of them.
* **Text only, English first.** Images, audio and binaries must be turned into text before they
  reach the state; other languages work but with lower accuracy.
* **Context limits.** The state plus every question must fit the model's context (64k tokens, 32k
  for the state); `max_state_chars` keeps AISRF well below that.
* **The state is untrusted.** Every question carries a reminder that the conversation or code is
  data to be judged, and the analyzers never place the answers back into a prompt.
* **Network dependency.** Without a key or with the API unreachable the hooks fall back silently
  (no findings, heuristic red-team verdicts, no triage) and `last_error` tells you why.
