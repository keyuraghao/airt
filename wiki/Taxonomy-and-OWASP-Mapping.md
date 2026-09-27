# Taxonomy and OWASP Mapping

`aisrf/taxonomy.py` is the single security taxonomy shared by analyzers, probes, policy, campaign summaries and reports. Every finding category and every probe category is mapped to three external frameworks:

* the OWASP Top 10 for LLM Applications, 2025 edition (`LLM01` to `LLM10`);
* the threat model of Greshake et al. 2023, "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection" (threat classes and delivery methods);
* the technique classes of Joseph Thacker's Prompt Injection Primer for Engineers.

The full catalogue is served by `GET /api/settings/taxonomy` (`taxonomy.catalogue()`), which returns `owasp`, `greshake_threats`, `greshake_delivery`, `thacker_techniques`, `category_map` and `references`. The dashboard uses it to render taxonomy chips next to findings, probe categories and heatmap rows, and to populate the category selector in [[Custom-Rules]] and the severity override table in [[Settings-Center]].

## OWASP LLM Top 10 (2025)

`OWASP_LLM_TOP10` holds name, description and URL for each id. The last column lists every AISRF category mapped to the id in `CATEGORY_MAP`.

| Id | Name | Description | AISRF categories |
|---|---|---|---|
| LLM01 | Prompt Injection | User or third-party content manipulates model behaviour, bypassing intent and controls. | `prompt_injection`, `indirect_prompt_injection`, `jailbreak`, `harmful_content`, `harmful_compliance`, `obfuscation`, `encoding_attacks`, `multi_turn`, `many_shot`, `guardrail` |
| LLM02 | Sensitive Information Disclosure | PII, credentials, proprietary data or confidential business information exposed via outputs. | `system_prompt_extraction`, `data_exfil`, `data_exfiltration`, `pii`, `pii_leakage`, `secrets`, `privacy_memorization` |
| LLM03 | Supply Chain | Compromised models, datasets, plugins or third-party components. | `supply_chain` |
| LLM04 | Data and Model Poisoning | Manipulated training, fine-tuning or embedding data introduces vulnerabilities, backdoors or bias. | `bias_fairness`, `privacy_memorization`, `rag_poisoning` |
| LLM05 | Improper Output Handling | Model output is passed to downstream systems without validation, enabling XSS, SSRF, code execution. | `data_exfil`, `data_exfiltration`, `tool_abuse`, `output_handling`, `code_safety` |
| LLM06 | Excessive Agency | Over-permissioned tools, functionality or autonomy let the model take damaging actions. | `tool_abuse`, `excessive_agency` |
| LLM07 | System Prompt Leakage | Secrets, credentials or sensitive logic contained in system prompts are exposed. | `system_prompt_extraction`, `system_prompt_leak`, `secrets`, `canary_leak` |
| LLM08 | Vector and Embedding Weaknesses | Weaknesses in retrieval augmented generation pipelines: poisoned or leaked embeddings, cross-tenant access. | `indirect_prompt_injection`, `rag_poisoning` |
| LLM09 | Misinformation | Confident false or misleading output, hallucinated facts, unsafe code suggestions. | `harmful_content`, `misinformation`, `misinformation_hallucination`, `bias_fairness`, `code_safety` |
| LLM10 | Unbounded Consumption | Resource exhaustion, denial of wallet, model extraction through excessive or uncontrolled usage. | `denial_of_wallet`, `anomaly` |

Reference URLs follow the pattern `https://genai.owasp.org/llmrisk/llm01-prompt-injection/` and `https://genai.owasp.org/llmrisk/llm0N2025-<slug>/` for the other ids.

## Greshake threat classes

`GRESHAKE_THREATS` describes what an injection achieves once it lands in an LLM-integrated application.

| Class | Description |
|---|---|
| `information_gathering` | Exfiltrating user data, credentials or conversation history to the attacker. |
| `fraud` | Phishing, scams and social engineering delivered through the trusted assistant. |
| `intrusion` | Gaining persistence or control over the application, its tools or the user's systems. |
| `malware` | Spreading injections to other users, agents or documents (worm-like propagation). |
| `manipulated_content` | Biased, wrong or attacker-controlled answers, ads or summaries. |
| `availability` | Denial of service: blocking, slowing or breaking the assistant for the user. |

## Greshake delivery methods

`GRESHAKE_DELIVERY` describes how an injection reaches the model. These are part of the catalogue for reference and reporting; `CATEGORY_MAP` only uses `hidden` (for `obfuscation` and `encoding_attacks`).

| Method | Description |
|---|---|
| `passive` | Injection placed in public content the model later retrieves (web pages, documents). |
| `active` | Injection actively delivered to the model (emails, messages, tickets processed by the agent). |
| `user_driven` | The victim is tricked into pasting the injection themselves. |
| `hidden` | Injection concealed from humans: white text, comments, encodings, multi-stage payloads. |

## Thacker technique classes

`THACKER_TECHNIQUES` classifies the attacker's technique.

| Class | Description |
|---|---|
| `direct_injection` | Attacker types the injection into the model input directly. |
| `indirect_injection` | Injection arrives through data the model consumes (retrieval, tools, browsing). |
| `context_leak` | Extracting system prompts, hidden context or previous conversations. |
| `data_exfiltration` | Using markdown images, links or tool calls to send data to the attacker. |
| `privilege_escalation` | Abusing tools, plugins or agents to act beyond the user's intent. |
| `persistence` | Storing an injection in memory, documents or databases to re-trigger later. |
| `obfuscation` | Encodings, translations, token smuggling and splitting to evade filters. |
| `social_engineering` | Role play, authority claims and urgency to talk the model out of its rules. |

## The category map

`CATEGORY_MAP` is keyed by AISRF category. Analyzer findings use the first block of keys ([[Analyzers]]), probe corpus files use the second ([[Probe-Corpus]]); some names exist in both spellings so that findings and probes line up in reports.

| Category | OWASP | Greshake threats | Thacker techniques |
|---|---|---|---|
| `prompt_injection` | LLM01 | intrusion, manipulated_content | direct_injection, social_engineering |
| `indirect_prompt_injection` | LLM01, LLM08 | intrusion, malware, information_gathering | indirect_injection, persistence |
| `jailbreak` | LLM01 | manipulated_content | social_engineering, direct_injection |
| `system_prompt_extraction` | LLM07, LLM02 | information_gathering | context_leak |
| `system_prompt_leak` | LLM07 | information_gathering | context_leak |
| `data_exfil` | LLM02, LLM05 | information_gathering | data_exfiltration |
| `data_exfiltration` | LLM02, LLM05 | information_gathering | data_exfiltration |
| `pii` | LLM02 | information_gathering | data_exfiltration |
| `pii_leakage` | LLM02 | information_gathering | context_leak |
| `secrets` | LLM02, LLM07 | information_gathering | context_leak |
| `canary_leak` | LLM07 | information_gathering | context_leak |
| `tool_abuse` | LLM06, LLM05 | intrusion | privilege_escalation |
| `excessive_agency` | LLM06 | intrusion | privilege_escalation |
| `harmful_content` | LLM01, LLM09 | manipulated_content | social_engineering |
| `harmful_compliance` | LLM01 | manipulated_content | social_engineering |
| `obfuscation` | LLM01 | hidden | obfuscation |
| `encoding_attacks` | LLM01 | hidden | obfuscation |
| `output_handling` | LLM05 | intrusion | data_exfiltration |
| `misinformation` | LLM09 | manipulated_content | (none) |
| `misinformation_hallucination` | LLM09 | manipulated_content | (none) |
| `bias_fairness` | LLM09, LLM04 | manipulated_content | (none) |
| `privacy_memorization` | LLM02, LLM04 | information_gathering | context_leak |
| `code_safety` | LLM09, LLM05 | intrusion | (none) |
| `denial_of_wallet` | LLM10 | availability | (none) |
| `anomaly` | LLM10 | availability | (none) |
| `rag_poisoning` | LLM08, LLM04 | malware, manipulated_content | indirect_injection, persistence |
| `supply_chain` | LLM03 | intrusion | (none) |
| `multi_turn` | LLM01 | manipulated_content | social_engineering |
| `many_shot` | LLM01 | manipulated_content | social_engineering |
| `policy` | (none) | (none) | (none) |
| `benign_control` | (none) | (none) | (none) |
| `refusal` | (none) | (none) | (none) |
| `guardrail` | LLM01 | (none) | (none) |

`policy` (custom rules, refusal findings), `benign_control` (the false-refusal control set) and `refusal` intentionally carry no mapping so they never inflate OWASP coverage. `guardrail` is the fallback category for external guardrail findings that cannot be mapped to a more specific one ([[Guardrails]]). The `greshake` column in the map mixes threat classes and, for the obfuscation categories, the delivery method `hidden`.

### Lookup rules

* `classify(category)` lower-cases and strips the key, tries an exact match, then falls back to the first entry whose key is a substring of the category or contains it (so `llm_guard_pii` resolves to `pii`, and `secret` resolves to `secrets`). Unknown categories return empty lists.
* `owasp_ids(category)` returns the OWASP id list; `owasp_label("LLM07")` returns `LLM07: System Prompt Leakage`.

## Enrichment of findings and probes

`enrich(dict)` attaches four keys in place: `owasp` (list of ids), `owasp_labels` (list of `LLMnn: Name` strings), `greshake` and `thacker`.

* Every `Finding.to_dict()` call in `aisrf/analysis/base.py` runs `enrich`, so each finding stored on a ticket, returned by the API, shown in the dashboard or exported in a report carries the labels. Custom rule findings are enriched through the category chosen in the rule editor.
* Probe results and campaign categories are labelled through the same map. The dashboard's `A.taxonomyChips({category})` helper renders the chips for probe categories on the campaign page, the corpus browser and the heatmap rows of a [[Comparison-Groups]] page; reports ([[Reports]]) group findings and probe outcomes by OWASP id with the same function.
* Guardrail integrations map their own detector names onto AISRF categories first (for example Lakera `prompt_attack` to `prompt_injection`, LLM Guard `MaliciousURLs` to `data_exfil`), so their findings inherit the OWASP mapping of that category.

## Coverage computation

`coverage(categories)` answers "which OWASP items does this set of categories exercise". For every id in `OWASP_LLM_TOP10` it returns:

```json
"LLM07": {"name": "System Prompt Leakage", "covered": true, "categories": ["system_prompt_extraction"]}
```

An id is `covered` when at least one input category maps to it; `categories` lists the sorted contributing categories. Ids that no category maps to are returned with `covered: false` and an empty list, so consumers always see all ten rows.

Where it is used:

* `build_summary` in `aisrf/redteam/engine.py` stores `owasp_coverage` (computed over the categories present in the campaign) and `owasp_breakdown` (tested, vulnerable, rate and categories per OWASP id, aggregated over the probe results mapped to it) in every campaign summary. See [[Red-Teaming]] for the exact keys.
* `compare_group` stores `owasp_coverage` for the union of categories in a comparison group; the group page renders covered and uncovered chips under "OWASP LLM Top 10 coverage".
* Reports use the coverage rows to show which parts of the Top 10 a campaign or a code review actually tested; an uncovered id is a gap in the test plan, not a clean result.

Because analyzers, probes and code review rules ([[Code-Review-Rules]]) all speak this vocabulary, a single OWASP id can be followed from a static finding in a repository, through a live gateway finding, to a red-team probe verdict in the same report.

## References

`REFERENCES` lists the sources cited in reports: OWASP Top 10 for LLM Applications 2025, Greshake et al. 2023 (arXiv 2302.12173), Thacker's Prompt Injection Primer, garak, promptfoo, PyRIT, Rebuff, LLM Guard, NeMo Guardrails and Lakera Guard.
