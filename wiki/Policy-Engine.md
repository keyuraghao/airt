# Policy engine

`aisrf/gateway/policy.py` decides, after analysis and before anyone waits, whether a ticket is denied outright, approved without a human, or held for review. It is deterministic, ordered and has no side effects; its output is stored on the ticket as `policy_decision` and applied by `tickets.apply_policy()`.

```python
evaluate(agent, normalized, path, risk_score, findings) -> PolicyDecision(action, reasons, matched_rules)
```

`action` is `deny`, `approve` or `review`. Inputs: the `Agent` row, the normalized request (see [[Request-Normalization]]), the stored path (`v1/chat/completions` style, no leading slash), the integer risk score and the serialised request findings. Global settings are read from the `policy` namespace of the settings store (`settings_store.get_namespace("policy")`).

## Evaluation order

Exactly as in the code; the first rule that returns ends evaluation.

| # | Rule | Driven by | Outcome | `matched_rules` entry |
| --- | --- | --- | --- | --- |
| 1 | Agent disabled | `agent.is_active == False` | `deny`, reason `agent is disabled` | `agent.is_active` |
| 2 | Global path allow-list | `policy.global_allowed_paths` (non-empty list of fnmatch globs); the path must match at least one pattern either as `path` or as `/path` | `deny`, reason `path '<path>' is not in the global allowed paths` | `policy.global_allowed_paths` |
| 3 | Agent path allow-list | `agent.allowed_paths` (same matching) | `deny`, reason `path '<path>' is not in the agent's allowed paths` | `agent.allowed_paths` |
| 4 | Agent model allow-list | `agent.allowed_models` (fnmatch globs against `normalized.model`); only evaluated when the request carries a non-empty model | `deny`, reason `model '<model>' is not in the agent's allowed models` | `agent.allowed_models` |
| 5 | Auto-deny regexes | `agent.auto_deny_patterns` then `policy.global_auto_deny_patterns`, each applied with `re.search(pat, prompt_text, re.IGNORECASE \| re.DOTALL)`; invalid regexes are skipped | Every match adds reason `prompt matches auto-deny pattern /<pat>/`; evaluation continues to rule 6 before returning | `agent.auto_deny_patterns`, `policy.global_auto_deny_patterns` |
| 6 | Custom rule with deny action | Any finding whose `metadata.action == "deny"` (produced by the custom rules analyzer from the `rules` namespace) | Adds reason `a custom rule with action=deny matched`; if rules 5 or 6 collected any reason, return `deny` with all of them | `rules.custom` |
| 7 | Risk auto-deny | `agent.auto_deny_at_risk > 0` and `risk_score >= agent.auto_deny_at_risk` | `deny`, reason `risk score <n> >= auto-deny threshold <t>` | `agent.auto_deny_at_risk` |
| 8 | Mandatory review of critical leaks | Any finding with `severity == "CRITICAL"` and `category` in (`secrets`, `data_exfil`) | `review`, reason `critical secret/exfiltration finding requires human review`; this rule wins over rules 9 and 10 | `finding.critical` |
| 9 | Approval not required | `agent.require_approval == False` | `approve`, reason `agent policy does not require approval` | `agent.require_approval=false` |
| 10 | Risk auto-approve | `agent.auto_approve_below_risk > 0` and `risk_score < agent.auto_approve_below_risk` | `approve`, reason `risk score <n> < auto-approve threshold <t>` | `agent.auto_approve_below_risk` |
| 11 | Default | everything else | `review`, reason `human approval required by agent policy` | `agent.require_approval=true` |

Notes:

* `prompt_text` in rule 5 is the concatenation of the system prompt and every non-system message (see [[Request-Normalization]]); it does not include tool definitions.
* `auto_deny_at_risk` accepts 0 to 101 in the API; 0 disables the rule, and since scores are capped at 100, 101 also disables it (the CLI documents `101 disables`). The default for new agents is 90, which corresponds to the `CRITICAL` band starting at 80 only when a single CRITICAL finding has confidence 1.0; combinations of HIGH findings can reach it too.
* `auto_approve_below_risk` accepts 0 to 100; 0 disables. A value of 1 approves only tickets with score 0 (`NONE`).
* The rate limit (`rate_limit_per_minute`) and the body size limit are enforced before a ticket exists and are not part of policy.
* Rule 8 exists so that a permissive agent (`require_approval=false`, or a generous auto-approve threshold) still puts a human in front of a request that appears to carry credentials or an exfiltration payload.

## What happens with each outcome

`apply_policy()` in `aisrf/tickets/service.py`:

| Action | Ticket status | `decided_by` | `decision_note` | Gateway behaviour |
| --- | --- | --- | --- | --- |
| `deny` | `DENIED` | `policy` | reasons joined with `; ` | `403` with `code: denied` and `risk_score`; nothing is sent upstream |
| `approve` | `APPROVED` | `policy` | reasons joined with `; ` | Forwarded immediately |
| `review` | `PENDING` | null | empty | Hold registered; sync clients wait, async clients get `202` |

In every case a `policy` timeline event (actor `policy`, detail = the decision dict), a per-agent log event `policy.<action>` and a `created` SSE event are emitted, and `gateway_policy_total{action}` is incremented.

## Example agent policies

Strict production assistant (everything human-reviewed, narrow surface):

```json
{"name": "support-bot", "upstream_provider": "openai", "upstream_api_key": "sk-...",
 "require_approval": true, "auto_deny_at_risk": 80,
 "allowed_paths": ["v1/chat/completions"], "allowed_models": ["gpt-4o-mini"],
 "auto_deny_patterns": ["(?i)ignore (all )?previous instructions", "(?i)drop\\s+table"],
 "rate_limit_per_minute": 60}
```

Low-friction internal tool (auto-approve benign traffic, keep humans for anything suspicious):

```json
{"name": "docs-search", "require_approval": true, "auto_approve_below_risk": 25, "auto_deny_at_risk": 90,
 "allowed_paths": ["v1/embeddings", "v1/chat/*"]}
```

Tickets scoring 0 to 24 (`NONE` and `LOW`) are approved by policy; 25 to 89 wait for a reviewer; 90 and above are denied; a CRITICAL `secrets` or `data_exfil` finding always waits regardless of score.

Monitoring only (no gate, full record):

```json
{"name": "batch-summariser", "require_approval": false, "auto_deny_at_risk": 0}
```

Everything is approved and forwarded at once, still ticketed, analysed, logged and audited, except requests with a CRITICAL secrets or exfiltration finding, which are held.

Red-team target with canaries:

```json
{"name": "redteam-target", "require_approval": false, "auto_deny_at_risk": 0, "inject_canary": true}
```

Combine with `AISRF_REQUIRE_APPROVAL_FOR_REDTEAM_PROBES` to decide whether probes still wait for a human.

CLI equivalent of the first example:

```bash
aisrf agent create support-bot --provider openai --upstream-key sk-... \
  --auto-deny-at 80 --allowed-path v1/chat/completions --allowed-model gpt-4o-mini \
  --deny-pattern '(?i)ignore (all )?previous instructions' --rate-limit 60
```

## Global policy namespace

Stored in `app_settings` under namespace `policy`, edited in Settings > Policy or with `PUT /api/settings/ns/policy` (admin). Defaults from `settings_store.NAMESPACE_DEFAULTS`:

| Key | Type | Default | Used by |
| --- | --- | --- | --- |
| `global_auto_deny_patterns` | list of regex strings | `[]` | Rule 5, after the agent's own patterns |
| `global_allowed_paths` | list of globs | `[]` (all paths) | Rule 2, before the agent's allow-list |
| `block_on_canary_leak` | bool | `true` | Response withholding (below) |
| `quarantine_on_critical_response_finding` | bool | `false` | Response withholding (below) |

Example:

```bash
curl -b jar -X PUT http://localhost:8080/api/settings/ns/policy -H 'Content-Type: application/json' -d '{
  "global_allowed_paths": ["v1/chat/*", "v1/messages", "v1/embeddings"],
  "global_auto_deny_patterns": ["(?i)reveal (your|the) system prompt"],
  "block_on_canary_leak": true,
  "quarantine_on_critical_response_finding": true
}'
```

Changes apply live to the next request and persist across restarts. The Settings page includes a browser-side regex tester for the deny patterns.

## Response withholding rules

Policy also runs after the upstream answers, in `_finish()` of the gateway router (non-streaming responses only; streams are already relayed by the time the body is complete):

1. The response text is extracted and the response analyzers run; if the injected canary appears in the text a `CRITICAL` `canary_leak` finding is inserted first when no analyzer already reported one.
2. The ticket is marked `COMPLETED` (or `FAILED` for status >= 500) with the findings.
3. If `block_on_canary_leak` is true and any response finding has category `canary_leak`: the ticket gets `error = "response withheld: system prompt canary leaked in the model output"`, a `withheld` timeline event (actor `policy`), `gateway_responses_withheld_total` is incremented, and the client receives `403 {"error": {"code": "response_withheld", ...}}` instead of the body.
4. Else if `quarantine_on_critical_response_finding` is true and any response finding has severity `CRITICAL` (for example `secrets_leak`, `pii_leak`, `system_prompt_leak` at critical severity): same treatment with the reason `response withheld: critical finding in the model output`.

The full upstream body remains stored on the ticket (truncated to `AISRF_MAX_STORED_RESPONSE_BYTES`) so a reviewer can read what was withheld; there is no release action, the client has to resubmit. `pipeline.submit()` does not withhold; it returns the response findings to the caller (the red-team evaluators use them).

## Custom rules and guardrails as policy inputs

Regex rules from the `rules` namespace run as an analyzer and produce findings; a rule with `action: deny` adds `metadata.action = "deny"` to its finding, which rule 6 turns into a denial. Guardrail integrations (LLM Guard, NeMo, Lakera, Rebuff) also surface as findings and therefore influence the score used by rules 7 and 10. See [[Custom-Rules]] and [[Guardrails]].

Related: [[Core-Concepts]], [[Agents-and-Credentials]], [[Configuration-Reference]], [[Canary-Words]].
