"""Security taxonomy shared by analyzers, probes, policy and reports.

Every finding category and probe technique is mapped to:
  * OWASP Top 10 for LLM Applications (2025 edition, LLM01..LLM10),
  * the indirect prompt injection threat model of Greshake et al. 2023
    ("Not what you've signed up for", https://arxiv.org/abs/2302.12173),
  * the technique classes of Joseph Thacker's Prompt Injection Primer
    (https://josephthacker.com/ai/2023/09/11/prompt-injection-primer.html).
"""
from __future__ import annotations

from typing import Any

OWASP_LLM_TOP10: dict[str, dict[str, str]] = {
    "LLM01": {"name": "Prompt Injection", "description": "User or third-party content manipulates model behaviour, bypassing intent and controls.", "url": "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"},
    "LLM02": {"name": "Sensitive Information Disclosure", "description": "PII, credentials, proprietary data or confidential business information exposed via outputs.", "url": "https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/"},
    "LLM03": {"name": "Supply Chain", "description": "Compromised models, datasets, plugins or third-party components.", "url": "https://genai.owasp.org/llmrisk/llm032025-supply-chain/"},
    "LLM04": {"name": "Data and Model Poisoning", "description": "Manipulated training, fine-tuning or embedding data introduces vulnerabilities, backdoors or bias.", "url": "https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/"},
    "LLM05": {"name": "Improper Output Handling", "description": "Model output is passed to downstream systems without validation, enabling XSS, SSRF, code execution.", "url": "https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/"},
    "LLM06": {"name": "Excessive Agency", "description": "Over-permissioned tools, functionality or autonomy let the model take damaging actions.", "url": "https://genai.owasp.org/llmrisk/llm062025-excessive-agency/"},
    "LLM07": {"name": "System Prompt Leakage", "description": "Secrets, credentials or sensitive logic contained in system prompts are exposed.", "url": "https://genai.owasp.org/llmrisk/llm072025-system-prompt-leakage/"},
    "LLM08": {"name": "Vector and Embedding Weaknesses", "description": "Weaknesses in retrieval augmented generation pipelines: poisoned or leaked embeddings, cross-tenant access.", "url": "https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/"},
    "LLM09": {"name": "Misinformation", "description": "Confident false or misleading output, hallucinated facts, unsafe code suggestions.", "url": "https://genai.owasp.org/llmrisk/llm092025-misinformation/"},
    "LLM10": {"name": "Unbounded Consumption", "description": "Resource exhaustion, denial of wallet, model extraction through excessive or uncontrolled usage.", "url": "https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/"},
}

# Greshake et al. threat taxonomy for LLM-integrated applications
GRESHAKE_THREATS: dict[str, str] = {
    "information_gathering": "Exfiltrating user data, credentials or conversation history to the attacker.",
    "fraud": "Phishing, scams and social engineering delivered through the trusted assistant.",
    "intrusion": "Gaining persistence or control over the application, its tools or the user's systems.",
    "malware": "Spreading injections to other users, agents or documents (worm-like propagation).",
    "manipulated_content": "Biased, wrong or attacker-controlled answers, ads or summaries.",
    "availability": "Denial of service: blocking, slowing or breaking the assistant for the user.",
}

# Greshake et al. injection delivery methods
GRESHAKE_DELIVERY: dict[str, str] = {
    "passive": "Injection placed in public content the model later retrieves (web pages, documents).",
    "active": "Injection actively delivered to the model (emails, messages, tickets processed by the agent).",
    "user_driven": "The victim is tricked into pasting the injection themselves.",
    "hidden": "Injection concealed from humans: white text, comments, encodings, multi-stage payloads.",
}

# Thacker primer technique classes
THACKER_TECHNIQUES: dict[str, str] = {
    "direct_injection": "Attacker types the injection into the model input directly.",
    "indirect_injection": "Injection arrives through data the model consumes (retrieval, tools, browsing).",
    "context_leak": "Extracting system prompts, hidden context or previous conversations.",
    "data_exfiltration": "Using markdown images, links or tool calls to send data to the attacker.",
    "privilege_escalation": "Abusing tools, plugins or agents to act beyond the user's intent.",
    "persistence": "Storing an injection in memory, documents or databases to re-trigger later.",
    "obfuscation": "Encodings, translations, token smuggling and splitting to evade filters.",
    "social_engineering": "Role play, authority claims and urgency to talk the model out of its rules.",
}

CATEGORY_MAP: dict[str, dict[str, list[str]]] = {
    "prompt_injection": {"owasp": ["LLM01"], "greshake": ["intrusion", "manipulated_content"], "thacker": ["direct_injection", "social_engineering"]},
    "indirect_prompt_injection": {"owasp": ["LLM01", "LLM08"], "greshake": ["intrusion", "malware", "information_gathering"], "thacker": ["indirect_injection", "persistence"]},
    "jailbreak": {"owasp": ["LLM01"], "greshake": ["manipulated_content"], "thacker": ["social_engineering", "direct_injection"]},
    "system_prompt_extraction": {"owasp": ["LLM07", "LLM02"], "greshake": ["information_gathering"], "thacker": ["context_leak"]},
    "system_prompt_leak": {"owasp": ["LLM07"], "greshake": ["information_gathering"], "thacker": ["context_leak"]},
    "data_exfil": {"owasp": ["LLM02", "LLM05"], "greshake": ["information_gathering"], "thacker": ["data_exfiltration"]},
    "data_exfiltration": {"owasp": ["LLM02", "LLM05"], "greshake": ["information_gathering"], "thacker": ["data_exfiltration"]},
    "pii": {"owasp": ["LLM02"], "greshake": ["information_gathering"], "thacker": ["data_exfiltration"]},
    "pii_leakage": {"owasp": ["LLM02"], "greshake": ["information_gathering"], "thacker": ["context_leak"]},
    "secrets": {"owasp": ["LLM02", "LLM07"], "greshake": ["information_gathering"], "thacker": ["context_leak"]},
    "canary_leak": {"owasp": ["LLM07"], "greshake": ["information_gathering"], "thacker": ["context_leak"]},
    "tool_abuse": {"owasp": ["LLM06", "LLM05"], "greshake": ["intrusion"], "thacker": ["privilege_escalation"]},
    "excessive_agency": {"owasp": ["LLM06"], "greshake": ["intrusion"], "thacker": ["privilege_escalation"]},
    "harmful_content": {"owasp": ["LLM01", "LLM09"], "greshake": ["manipulated_content"], "thacker": ["social_engineering"]},
    "harmful_compliance": {"owasp": ["LLM01"], "greshake": ["manipulated_content"], "thacker": ["social_engineering"]},
    "obfuscation": {"owasp": ["LLM01"], "greshake": ["hidden"], "thacker": ["obfuscation"]},
    "encoding_attacks": {"owasp": ["LLM01"], "greshake": ["hidden"], "thacker": ["obfuscation"]},
    "output_handling": {"owasp": ["LLM05"], "greshake": ["intrusion"], "thacker": ["data_exfiltration"]},
    "misinformation": {"owasp": ["LLM09"], "greshake": ["manipulated_content"], "thacker": []},
    "misinformation_hallucination": {"owasp": ["LLM09"], "greshake": ["manipulated_content"], "thacker": []},
    "bias_fairness": {"owasp": ["LLM09", "LLM04"], "greshake": ["manipulated_content"], "thacker": []},
    "privacy_memorization": {"owasp": ["LLM02", "LLM04"], "greshake": ["information_gathering"], "thacker": ["context_leak"]},
    "code_safety": {"owasp": ["LLM09", "LLM05"], "greshake": ["intrusion"], "thacker": []},
    "denial_of_wallet": {"owasp": ["LLM10"], "greshake": ["availability"], "thacker": []},
    "anomaly": {"owasp": ["LLM10"], "greshake": ["availability"], "thacker": []},
    "rag_poisoning": {"owasp": ["LLM08", "LLM04"], "greshake": ["malware", "manipulated_content"], "thacker": ["indirect_injection", "persistence"]},
    "supply_chain": {"owasp": ["LLM03"], "greshake": ["intrusion"], "thacker": []},
    "multi_turn": {"owasp": ["LLM01"], "greshake": ["manipulated_content"], "thacker": ["social_engineering"]},
    "many_shot": {"owasp": ["LLM01"], "greshake": ["manipulated_content"], "thacker": ["social_engineering"]},
    "policy": {"owasp": [], "greshake": [], "thacker": []},
    "benign_control": {"owasp": [], "greshake": [], "thacker": []},
    "refusal": {"owasp": [], "greshake": [], "thacker": []},
    "guardrail": {"owasp": ["LLM01"], "greshake": [], "thacker": []},
}

REFERENCES: list[dict[str, str]] = [
    {"id": "owasp-llm-top10-2025", "title": "OWASP Top 10 for LLM Applications 2025", "url": "https://genai.owasp.org/llm-top-10/"},
    {"id": "greshake-2023", "title": "Greshake et al., Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection (2023)", "url": "https://arxiv.org/abs/2302.12173"},
    {"id": "thacker-primer", "title": "Joseph Thacker, Prompt Injection Primer for Engineers", "url": "https://josephthacker.com/ai/2023/09/11/prompt-injection-primer.html"},
    {"id": "garak", "title": "garak, LLM vulnerability scanner (NVIDIA)", "url": "https://github.com/NVIDIA/garak"},
    {"id": "promptfoo", "title": "promptfoo, LLM evaluation and red teaming", "url": "https://www.promptfoo.dev/"},
    {"id": "pyrit", "title": "PyRIT, Python Risk Identification Toolkit (Microsoft)", "url": "https://github.com/Azure/PyRIT"},
    {"id": "rebuff", "title": "Rebuff, prompt injection detector with canary words", "url": "https://github.com/protectai/rebuff"},
    {"id": "llm-guard", "title": "LLM Guard (Protect AI), input and output scanners", "url": "https://github.com/protectai/llm-guard"},
    {"id": "nemo-guardrails", "title": "NeMo Guardrails (NVIDIA), programmable guardrails", "url": "https://github.com/NVIDIA/NeMo-Guardrails"},
    {"id": "lakera-guard", "title": "Lakera Guard, real-time prompt attack detection API", "url": "https://www.lakera.ai/lakera-guard"},
]


def classify(category: str) -> dict[str, list[str]]:
    key = (category or "").lower().strip()
    entry = CATEGORY_MAP.get(key)
    if entry is None:
        for k, v in CATEGORY_MAP.items():
            if k in key or key in k:
                entry = v
                break
    return dict(entry) if entry else {"owasp": [], "greshake": [], "thacker": []}


def owasp_ids(category: str) -> list[str]:
    return classify(category)["owasp"]


def owasp_label(owasp_id: str) -> str:
    e = OWASP_LLM_TOP10.get(owasp_id)
    return f"{owasp_id}: {e['name']}" if e else owasp_id


def enrich(finding: dict[str, Any]) -> dict[str, Any]:
    """Attach taxonomy fields to a serialized finding or probe dict in place."""
    tax = classify(finding.get("category", ""))
    finding["owasp"] = tax["owasp"]
    finding["owasp_labels"] = [owasp_label(i) for i in tax["owasp"]]
    finding["greshake"] = tax["greshake"]
    finding["thacker"] = tax["thacker"]
    return finding


def coverage(categories: list[str]) -> dict[str, Any]:
    """Which OWASP items a set of categories exercises (used by campaign summaries and reports)."""
    hit: dict[str, set[str]] = {k: set() for k in OWASP_LLM_TOP10}
    for c in categories:
        for oid in owasp_ids(c):
            hit[oid].add(c)
    return {
        oid: {"name": OWASP_LLM_TOP10[oid]["name"], "covered": bool(cats), "categories": sorted(cats)}
        for oid, cats in hit.items()
    }


def catalogue() -> dict[str, Any]:
    return {
        "owasp": [{"id": k, **v} for k, v in OWASP_LLM_TOP10.items()],
        "greshake_threats": GRESHAKE_THREATS,
        "greshake_delivery": GRESHAKE_DELIVERY,
        "thacker_techniques": THACKER_TECHNIQUES,
        "category_map": CATEGORY_MAP,
        "references": REFERENCES,
    }
