# Custom Rules

Custom rules are user-defined regular expressions that the analysis pipeline evaluates on every request and response next to the built-in [[Analyzers]]. They live in the `rules` settings namespace under the key `custom`, are edited live in **Settings > Rules** ([[Settings-Center]]) or through `PUT /api/settings/ns/rules`, and take effect on the next request without a restart. The implementation is `aisrf/analysis/custom_rules.py`, registered as the analyzers `custom_rules` (request) and `custom_rules_response` (response).

## Rule schema

`rules.custom` is a JSON list; every entry is one rule with these fields:

| Field | Type | Default | Meaning |
|---|---|---|---|
| `id` | string | required by the UI | Unique identifier, for example `rule-1` or `no-internal-hosts`. Stored on findings as `metadata.rule_id`. The dashboard refuses to save when an id is missing or duplicated. |
| `name` | string | `""` | Human-readable title. Used as the finding title; when empty the title becomes `Custom rule <id>`. |
| `pattern` | string | required | Python regular expression compiled with `re.IGNORECASE` and `re.MULTILINE`. A pattern that fails to compile is skipped silently by the analyzer (the UI highlights invalid patterns and refuses to save them). Compiled patterns are cached per pattern string. |
| `category` | string | `policy` | Finding category. Any key of the taxonomy `CATEGORY_MAP` ([[Taxonomy-and-OWASP-Mapping]]) is offered in the UI; the category decides the OWASP labels and how the [[Policy-Engine]] treats the finding (a CRITICAL finding in `secrets` or `data_exfil` forces human review). |
| `severity` | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | `MEDIUM` | Severity of the finding, and therefore its weight in the risk score. Unknown values fall back to MEDIUM. |
| `confidence` | number 0 to 1 | `0.9` | Confidence of the finding; used by the score formula and by `analyzers.confidence_floor`. |
| `scope` | `request`, `response`, `both` | `request` | Where the rule is evaluated. |
| `action` | `flag`, `deny` | `flag` | `flag` only produces a finding; `deny` also makes the policy engine deny the request. Stored as `metadata.action`. |
| `enabled` | boolean | `true` | Disabled rules are ignored. |
| `description` | string | `""` | Optional finding description; defaults to `Matched custom rule pattern /<pattern>/`. Not shown as a column in the table editor but preserved by the raw JSON editor. |

Example document:

```json
{
  "custom": [
    {"id": "internal-hosts", "name": "Internal hostname in prompt", "pattern": "\\b[a-z0-9-]+\\.corp\\.example\\.com\\b",
     "category": "data_exfil", "severity": "HIGH", "confidence": 0.9, "scope": "both", "action": "flag", "enabled": true},
    {"id": "project-codename", "name": "Project codename", "pattern": "\\bproject\\s+nightjar\\b",
     "category": "policy", "severity": "CRITICAL", "scope": "request", "action": "deny", "enabled": true},
    {"id": "competitor-mention", "name": "Competitor named in answer", "pattern": "\\b(acme|globex)\\b",
     "category": "policy", "severity": "LOW", "scope": "response", "action": "flag", "enabled": true}
  ]
}
```

## Scopes

* `request` rules run inside `custom_rules`. They are applied to the merged system prompt (location `system`) and to every message whose role is not `system` or `developer` (location `messages[i]`), including `assistant` and tool messages. One finding is produced per rule per text segment that matches (first match only within a segment).
* `response` rules run inside `custom_rules_response` against the extracted response text (location `response`).
* `both` rules run in both places.

Rules are evaluated in list order, which the dashboard lets you change with the up and down buttons; order only affects the order of findings, not the score.

## Findings produced

Each match becomes a `Finding` with:

* `analyzer`: `custom_rules` or `custom_rules_response`;
* `category`, `severity`, `confidence`: from the rule;
* `title`: the rule `name` (or `Custom rule <id>`);
* `description`: the rule `description` (or `Matched custom rule pattern /<pattern>/`);
* `evidence`: 60 characters before and after the match, unmasked, truncated to 400 characters when serialized;
* `tags`: `["custom_rule"]`;
* `metadata`: `{"rule_id": ..., "action": "flag" | "deny"}`.

Findings are scored with everything else (see the formula in [[Analyzers]]) and enriched with OWASP labels through the chosen category. Severity overrides in `analyzers.severity_overrides` apply to custom rules too, keyed by category or by the analyzer name `custom_rules`.

## Actions and the interaction with policy

The policy engine (`aisrf/gateway/policy.py`, `evaluate`) inspects the request findings after the allowed-path and allowed-model checks:

1. Agent `auto_deny_patterns` and `policy.global_auto_deny_patterns` are matched against the prompt text.
2. If any finding has `metadata.action == "deny"`, the reason `a custom rule with action=deny matched` is added with the matched rule `rules.custom`.
3. If any reason was collected, the decision is `deny`; the ticket is denied by `policy` and the client receives a 403 style error without anything reaching the upstream.

Consequences:

* `action: deny` on a `request` or `both` rule denies the request regardless of the risk score, of the agent's `require_approval` flag and of `auto_approve_below_risk`.
* `action: deny` on a `response` scoped rule does not block anything: the policy engine only evaluates request findings. Response findings can only withhold a response through `policy.quarantine_on_critical_response_finding` (any CRITICAL response finding) or `block_on_canary_leak` ([[Canary-Words]]). To make a response rule quarantine the answer, give it severity `CRITICAL` and enable the quarantine setting.
* `action: flag` contributes to the score like any finding. A `flag` rule with severity CRITICAL and confidence 0.9 alone gives a score of 81 (level CRITICAL), which typically exceeds an agent's `auto_deny_at_risk` threshold; a `flag` rule with category `secrets` or `data_exfil` and severity CRITICAL forces `review` even for agents that do not require approval.
* Custom rules are visible in the ticket's findings list with the `custom_rule` tag, and the policy reasons list names `rules.custom`, so a reviewer can see exactly why a request was denied ([[Tickets-and-Review-Workflow]]).

## Examples

| Goal | Rule |
|---|---|
| Deny any prompt that mentions an unreleased product name | `pattern: "\\bproject\\s+nightjar\\b"`, `scope: request`, `action: deny`, `severity: CRITICAL` |
| Flag internal hostnames in prompts and answers | `pattern: "\\b[a-z0-9-]+\\.corp\\.example\\.com\\b"`, `category: data_exfil`, `scope: both`, `severity: HIGH` |
| Detect a home-grown ticket number format in responses | `pattern: "\\bINC-\\d{7}\\b"`, `category: pii`, `scope: response`, `severity: MEDIUM` |
| Block a specific jailbreak phrase your users keep trying | `pattern: "developer\\s+mode\\s+(?:enabled|on)"`, `category: jailbreak`, `scope: request`, `action: deny` |
| Quarantine answers that contain your own canary phrase | `pattern: "AISRF-CANARY-[0-9a-f]{16}"`, `category: canary_leak`, `scope: response`, `severity: CRITICAL` (with `quarantine_on_critical_response_finding: true`, or rely on the built-in canary block) |

Patterns are Python `re` syntax: escape backslashes in JSON, use `(?i)` only if you need to override the default case-insensitivity (it is already on), and prefer `\b` word boundaries to avoid matching inside longer words.

## Testing rules in the UI

The Rules tab of the Settings Center (`renderRules` in `aisrf/dashboard/static/settings.js`) provides:

* a table with the columns Id, Name, Pattern, Category, Severity, Scope, Action and On, with up and down buttons to change evaluation order and a Delete button per row; the pattern field turns red while the regex does not compile;
* a **Test rule** box: type any text and every enabled rule with a pattern is executed in the browser (JavaScript regex, case-insensitive) with a 150 ms debounce; each rule is listed with `flag: <match>` or `deny: <match>` on a hit or "no match" otherwise. The test runs client side and does not create tickets or findings;
* **Add rule** (pre-fills `id: rule-<n>`, severity MEDIUM, scope request, action flag) and **Save rules**, which validates that every rule has a compilable pattern and a unique id before calling `PUT /api/settings/ns/rules` with `{"custom": [...]}`;
* a raw JSON editor for the whole namespace, useful for the `description` field and for bulk edits;
* read-only mode for non-admin users.

JavaScript and Python regex dialects differ slightly (lookbehind, `\A`, inline flags, possessive quantifiers); the server always uses Python `re`. For an authoritative test, send a request through the gateway with one of the SDKs ([[Integrations-and-SDKs]]) or plain `curl` against a test agent and inspect the ticket's findings (`GET /api/tickets/{id}` or the MCP `get_ticket` tool); there is no analyze-only endpoint.

## API

```bash
# read
curl -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" http://localhost:8080/api/settings/ns/rules

# replace the rule list (the value of "custom" is replaced as a whole)
curl -X PUT -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" -H "Content-Type: application/json" \
  http://localhost:8080/api/settings/ns/rules -d '{"custom": [{"id": "r1", "name": "Codename", "pattern": "\\bnightjar\\b", "category": "policy", "severity": "HIGH", "scope": "request", "action": "deny", "enabled": true}]}'

# reset to the default (no rules)
curl -X POST -H "Authorization: Bearer $AISRF_ADMIN_API_TOKEN" http://localhost:8080/api/settings/ns/rules/reset
```

Namespace changes are persisted in the `app_settings` table, broadcast on the `settings` SSE channel and written to the audit log ([[Logging-Metrics-and-Audit]]). The same document is included in `GET /api/settings/export` and can be re-imported with `POST /api/settings/import`, which is the simplest way to move a rule set between deployments ([[Configuration-Reference]]).
