"""Custom NeMo Guardrails actions for the default AIRT rails configuration.

NeMo loads this file from the config directory by path (not as part of the airt package), so it must be
self-contained: regex heuristics only, no model downloads, no LLM. Each action returns a dict with
`blocked`, `reason` (label plus score, embedded in the rail exception message) and `score`.
"""
from __future__ import annotations

import re
from typing import Any

from nemoguardrails.actions import action

_JAILBREAK_ROWS: list[tuple[str, float, str]] = [
    (r"\bDAN\b", 0.7, "DAN persona"),
    (r"\bdo\s+anything\s+now\b", 0.95, "DAN persona"),
    (r"\b(?:DAN|STAN|DUDE|AIM|UCAR|JAILBREAK|EVIL|OPPOSITE)\s+mode\b", 0.9, "Named jailbreak persona"),
    (r"\bdeveloper\s+mode\s+(?:enabled|on|output|activated)\b", 0.9, "Developer mode"),
    (r"\b(?:enable|enter|activate|switch\s+to)\s+(?:the\s+)?(?:developer|dan|jailbreak|unrestricted|unfiltered|uncensored|god|sudo)\s+mode\b", 0.9, "Mode switch"),
    (r"\bevil\s+confidant\b", 0.85, "Evil confidant persona"),
    (r"\byou\s+are\s+(?:now\s+)?(?:free|unrestricted|unfiltered|uncensored|jailbroken|no\s+longer\s+bound)\b", 0.85, "Unrestricted persona"),
    (r"\b(?:pretend|act|behave|respond)\s+(?:as\s+if|like)\s+(?:you\s+)?(?:have|had|there\s+(?:are|were))\s+no\s+(?:rules|restrictions|limits|guidelines|filters|content\s+policy)\b", 0.9, "Act as if unrestricted"),
    (r"\bwithout\s+(?:any\s+)?(?:restrictions|limitations|filters|censorship|ethical\s+(?:guidelines|concerns)|moral(?:s|ity)?)\b", 0.6, "Unrestricted request"),
    (r"\b(?:bypass|disable|override|remove|turn\s+off)\s+(?:all\s+|your\s+|the\s+)?(?:safety|content|ethical)?\s*(?:filters?|restrictions?|guardrails?|safeguards?|alignment|moderation)\b", 0.85, "Safety control bypass"),
    (r"\bstay\s+in\s+character\b", 0.55, "Persona lock"),
    (r"\bno\s+ethical\s+(?:guidelines|boundaries|concerns)\b", 0.8, "No ethics persona"),
    (r"\bjailbr(?:eak|oken)\b", 0.65, "Jailbreak keyword"),
]
_INJECTION_ROWS: list[tuple[str, float, str]] = [
    (r"\b(?:ignore|disregard|forget|discard|override|bypass|skip)\s+(?:all\s+|any\s+|every\s+|the\s+|your\s+|my\s+|these\s+|those\s+)*(?:previous|prior|above|earlier|preceding|initial|original|existing|system|developer|former|hidden)?\s*(?:\w+\s+){0,2}(?:instructions?|prompts?|rules?|guidelines?|directives?|commands?|orders?|messages?|context|constraints?|programming|training|policies|policy)\b", 0.9, "Instruction override"),
    (r"\b(?:ignore|disregard|forget)\s+(?:everything|all|anything)\s+(?:you\s+)?(?:were|was|have\s+been|had\s+been)\s+(?:told|instructed|taught|given|programmed)\b", 0.9, "Instruction override"),
    (r"\b(?:ignore|disregard|forget)\s+(?:everything|all)\s+(?:above|before|prior|previous|earlier|so\s+far)\b", 0.9, "Instruction override"),
    (r"\bnew\s+(?:instructions?|rules?|directives?|task|system\s+prompt)\s*:", 0.75, "New instructions block"),
    (r"\b(?:your|the)\s+(?:previous|prior|original|system|above)\s+(?:instructions?|prompt|rules?)\s+(?:are|is|were)\s+(?:now\s+)?(?:void|invalid|cancell?ed|revoked|obsolete|null|overridden|suspended)\b", 0.9, "Instructions voided"),
    (r"<\|im_start\|>\s*(?:system|assistant)|<\|(?:system|assistant|endoftext|eot_id)\|>|\[/?INST\]|<<\s*/?SYS\s*>>", 0.9, "Model control token"),
    (r"(?:^|\n)\s*(?:system|developer)\s*(?:prompt|message)?\s*:\s*\S", 0.6, "Inline role prefix"),
    (r"<\s*/?\s*(?:system|system_prompt|developer|instructions?|admin)\s*>", 0.75, "XML-style role tag"),
    (r"\b(?:reveal|show|print|output|repeat|display|tell\s+me|what\s+(?:is|are|were))\s+(?:me\s+)?(?:your|the)\s+(?:system\s+prompt|initial\s+prompt|hidden\s+prompt|original\s+instructions?|system\s+instructions?|instructions?)\b", 0.85, "System prompt extraction"),
    (r"\brepeat\s+(?:the\s+)?(?:text|words|everything)\s+above\b", 0.8, "System prompt extraction"),
    (r"\b(?:print|say|output|write|respond\s+with)\s+(?:only\s+)?[\"']?i\s+have\s+been\s+pwned[\"']?", 0.9, "Canonical injection test string"),
    (r"\b(?:admin|root|sudo|god|maintenance|debug)\s+(?:mode|override|access)\s*(?:enabled|activated|on|granted|:)", 0.8, "Privileged mode claim"),
    (r"\bi\s+am\s+(?:your|the)\s+(?:developer|creator|programmer|administrator|admin|owner|operator)\b", 0.7, "Developer impersonation"),
    (r"\b(?:end|stop)\s+of\s+(?:system\s+)?(?:instructions?|prompt|rules?)\b", 0.8, "End of instructions marker"),
]
_OUTPUT_ROWS: list[tuple[str, float, str]] = [
    (r"\bAIRT-CANARY-[0-9a-f]{16}\b", 1.0, "Gateway canary token leaked"),
    (r"<!--\s*[0-9a-f]{8,}\s*-->", 0.8, "Rebuff canary comment leaked"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", 0.95, "Private key material"),
    (r"\bAKIA[0-9A-Z]{16}\b", 0.95, "AWS access key"),
    (r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b", 0.9, "API key"),
    (r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", 0.95, "GitHub token"),
    (r"\bxox[abpr]-[A-Za-z0-9-]{10,}\b", 0.95, "Slack token"),
    (r"\b(?:my|the)\s+system\s+prompt\s+(?:is|reads|states|says)\s*:", 0.75, "System prompt disclosure"),
]
_JAILBREAK = [(re.compile(p, re.IGNORECASE), w, label) for p, w, label in _JAILBREAK_ROWS]
_INJECTION = [(re.compile(p, re.IGNORECASE), w, label) for p, w, label in _INJECTION_ROWS]
_OUTPUT = [(re.compile(p, re.IGNORECASE), w, label) for p, w, label in _OUTPUT_ROWS]
THRESHOLD = 0.6
MAX_CHARS = 100_000


def _scan(rows: list[tuple[re.Pattern[str], float, str]], text: Any, threshold: float = THRESHOLD) -> dict[str, Any]:
    s = text if isinstance(text, str) else ("" if text is None else str(text))
    s = s[:MAX_CHARS]
    best = 0.0
    labels: list[str] = []
    for rx, weight, label in rows:
        if rx.search(s):
            labels.append(label)
            best = max(best, weight)
            if best >= 0.9 and len(labels) >= 2:
                break
    # two independent medium signals are as convincing as one strong one
    if len(set(labels)) >= 2:
        best = min(1.0, best + 0.15)
    blocked = best >= threshold
    reason = f"{labels[0]} (score {best:.2f})" if labels else ""
    return {"blocked": blocked, "score": round(best, 3), "labels": sorted(set(labels)), "reason": reason}


@action(name="airt_check_jailbreak")
async def airt_check_jailbreak(text: str = "", context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Regex heuristics for jailbreak personas. Blocks when the best weight reaches 0.6."""
    return _scan(_JAILBREAK, text or (context or {}).get("user_message", ""))


@action(name="airt_check_injection")
async def airt_check_injection(text: str = "", context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Regex heuristics for instruction override, delimiter spoofing and system prompt extraction."""
    return _scan(_INJECTION, text or (context or {}).get("user_message", ""))


@action(name="airt_check_output")
async def airt_check_output(text: str = "", context: dict[str, Any] | None = None) -> dict[str, Any]:
    """Blocks bot output that leaks a canary token, credentials or the system prompt."""
    return _scan(_OUTPUT, text or (context or {}).get("bot_message", ""), threshold=0.7)
