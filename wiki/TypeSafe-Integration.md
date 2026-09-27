# TypeSafe Integration

AISRF can use **TypeSafe AI** (the System One decision model **Jev**) as a fast, cheap decision layer next to its own [[Analyzers]] and the [[Guardrails]] integrations. Instead of asking a generative model to write a verdict, AISRF sends the intercepted conversation (or a model response, a red-team probe result, or a static analysis finding) as an untrusted `state` together with a battery of typed questions, and Jev answers every question in parallel with a calibrated probability and a confidence in roughly 100 ms. Code then decides what to do with the answers. The integration is a silent no-op until `integrations.typesafe.enabled` is true and a key exists, it never raises (a failed call yields no findings, a heuristic red-team verdict, no triage), and errors are logged at most once per minute and kept as `last_error`.

All code lives in `aisrf/typesafe/` (`client.py`, `questions.py`, `analyzers.py`, `__init__.py`) with hooks in `aisrf/analysis/runner.py`, `aisrf/gateway/policy.py`, `aisrf/redteam/evaluators.py`, `aisrf/codereview/engines/typesafe_engine.py` and `aisrf/settings_router.py`. The long form reference is `docs/TYPESAFE.md` in the repository.

| Where | Question set | What it decides | Cost per item |
|---|---|---|---|
| Request analysis (`typesafe_guard`) | `REQUEST_GUARD`: nine nouls, an `intent` choice over the taxonomy categories, a five level `severity` score | Findings per attack class, a `malicious` / `benign` / `uncertain` verdict with a confidence | one call, state plus about 900 question tokens |
| Response analysis (`typesafe_response_guard`) | `RESPONSE_GUARD`: leaked system prompt, leaked secret or PII, harmful compliance, exfiltration markup, refusal | Findings on the model output | one call, state plus about 500 question tokens |
| Red-team evaluation | `REDTEAM_EVAL`: refused, complied, followed injected instruction, leaked canary, harmful content, safe helpful answer, `outcome` choice | VULNERABLE / RESISTED / INCONCLUSIVE when confident enough to override the heuristics | one call per probe result |
| Code review (`typesafe` engine) | `CODE_TRIAGE`: true positive, user input reaches prompt, model output reaches sink, exploitable without auth, mitigated in code, four level `exploitability` score | Confidence adjustment and the `likely_false_positive` status | one call per finding, up to `max_findings` |

## The three primitives

| Primitive | Asks | Answer |
|---|---|---|
| `noul` | a yes/no question with optional `criteria.true` and `criteria.false` descriptions | `noul` in 0..1, the probability of yes |
| `choice` | one option out of a `criteria` map of option to description (at most 255) | `choice`, `probabilities` per option, `confidence` |
| `score` | a rating on an ordered rubric of 2 to 10 level descriptions | `score`, `legend`, `probabilities` per level, `confidence` |

A confidence below 0.5 means the model is genuinely unsure. AISRF turns a noul into a confidence with `abs(p - 0.5) * 2` and uses the returned `confidence` for choices and scores. Every instruction reminds the model that the state is untrusted material to be judged, never followed.

## Enabling it

1. Create an API key at typesafe.ai.
2. Export `TYPESAFE_API_KEY` in the gateway environment, or paste the key into **Settings > Integrations > typesafe** (stored server side, masked in the UI and the API). The settings key wins when both exist.
3. Switch `enabled` on and run the health check:

```bash
curl -X PUT -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" -H "Content-Type: application/json" \
  http://localhost:8080/api/settings/ns/integrations -d '{"typesafe": {"enabled": true, "api_key": "ts-..."}}'
curl -X POST -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" http://localhost:8080/api/settings/typesafe/health
```

Settings are live; every hook reads `integrations.typesafe` at call time ([[Settings-Center]]).

## Confidence-gated escalation and routing

The analysis runner executes in two phases: every analyzer except the LLM judge runs concurrently first (TypeSafe among them), then the judge runs only if `llm_judge_gate` allows it. With TypeSafe disabled the judge behaves as before. With TypeSafe enabled the judge runs only when `escalate_to_llm_judge` is true and the verdict is `uncertain` (or missing because the call failed). The skip reason is stored in `context["llm_judge_skipped"]`.

The [[Policy-Engine]] gains one step between the deny patterns and the risk thresholds when `auto_route` is true:

| Verdict | Condition | Decision | Matched rule |
|---|---|---|---|
| `malicious` | confidence >= `auto_deny_confidence` (0.95) | deny | `typesafe.auto_deny` |
| `benign` | confidence >= `auto_approve_confidence` (0.9), agent requires approval, no HIGH or CRITICAL finding from any analyzer | approve | `typesafe.auto_approve` |
| anything else | | unchanged, the normal rules decide | |

In red teaming the TypeSafe verdict replaces the heuristic one only when its confidence is at least `redteam_confidence` (0.8); BLOCKED, ERROR and canary-leak verdicts are never sent. In code review a finding becomes `likely_false_positive` when `true_positive` is below 0.2 with confidence at least `triage_confidence`; that status is excluded from the risk score and SARIF, hidden by the default findings filter, and can be reopened by a reviewer. The LLM code review engine then only sees the findings TypeSafe left uncertain, and only when `escalate_to_llm_judge` is true.

## What you see on a ticket

Every TypeSafe finding carries `metadata.typesafe = {"verdict", "confidence"}` plus the full `answers` (probabilities and confidence per question), `intent`, `severity_score`, `model`, `usage` and `latency_ms`. The ticket page shows a `TypeSafe: malicious 96%` chip on the finding and an expandable table with every answer; the overview page shows a **TypeSafe savings** tile while the integration is enabled.

## Settings (`integrations.typesafe`)

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Master switch. |
| `api_key` | `""` | Bearer key; falls back to `TYPESAFE_API_KEY`. |
| `base_url` | `https://api.typesafe.ai` | The client posts to `/v1/systemone`. |
| `model` | `jev-latest` | Model name. |
| `timeout_seconds` | `8` | HTTP timeout per attempt; 3 retries with backoff and jitter on 429, 529 and connection errors. |
| `cache_ttl_seconds` | `300` | TTL of the bounded result cache (sha256 of model, state and questions). |
| `max_state_chars` | `12000` | State budget; head and tail are kept when truncating, secrets are masked. |
| `noul_threshold` | `0.7` | A noul at or above this fires a finding. |
| `benign_confidence`, `malicious_confidence` | `0.85`, `0.9` | Minimum confidence for the two decisive verdicts. |
| `escalate_to_llm_judge` | `false` | Run the LLM judge and the LLM code review engine for uncertain results only. |
| `auto_route`, `auto_deny_confidence`, `auto_approve_confidence` | `false`, `0.95`, `0.9` | Policy routing. |
| `redteam_evaluator`, `redteam_confidence` | `true`, `0.8` | Red-team evaluation. |
| `max_findings`, `triage_min_severity`, `triage_confidence`, `triage_concurrency` | `200`, `LOW`, `0.8`, `8` | Code review triage. |
| `judge_input_price_per_million`, `judge_output_price_per_million`, `price_per_million_input` | `0.15`, `0.6`, `0.042` | Prices for the savings estimate. |

## Savings, metrics and endpoints

TypeSafe bills input tokens only. The savings estimate assumes the LLM judge would have read the same input tokens and written 400 output tokens at the two judge prices, and subtracts the TypeSafe spend (`billed_input_tokens * price_per_million_input`); cached evaluations count as judge tokens avoided at no cost. Prometheus exposes `aisrf_typesafe_calls_total{outcome}`, `aisrf_typesafe_input_tokens_total`, `aisrf_typesafe_cache_hits_total` and `aisrf_typesafe_latency_ms` ([[Logging-Metrics-and-Audit]]).

* `GET /api/settings/typesafe/status`: `enabled`, `configured`, `key_source`, `model`, `cache_size`, `calls`, `cache_hits`, `errors`, `input_tokens`, `savings`, `last_error`.
* `POST /api/settings/typesafe/health` (admin): one tiny uncached evaluation.
* `GET /api/settings/guardrails` lists TypeSafe next to the guardrail integrations.

## Limitations

Jev judges, it does not generate: it cannot explain a verdict in prose. Calibration is not correctness, so keep the thresholds for the two actions that bypass a human high and review auto-routed tickets. The state is text only and must fit the model context; `max_state_chars` keeps it well below. Without network access every hook degrades to the previous behaviour.

See also: [[Analyzers]], [[Guardrails]], [[Policy-Engine]], [[Red-Teaming]], [[Code-Review]], [[Configuration-Reference]].
