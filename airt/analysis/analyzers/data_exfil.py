"""Data exfiltration detection: markdown/link beacons, system prompt extraction and conversation forwarding to external endpoints."""
from __future__ import annotations

import re
from typing import Any

from ...analysis.base import Finding, Severity
from .common import (
    Signature,
    bump_severity,
    compile_signatures,
    is_tool_context,
    iter_messages,
    make_finding,
    normalize_text,
    severity_from_weight,
    snippet,
)

NAME = "data_exfil"

_EXFIL_DOMAINS = r"(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net|burpcollaborator\.net|oast\.(?:fun|live|site|pro|me|online)|interact\.sh|canarytokens\.(?:com|org)|ngrok(?:-free)?\.(?:io|app|dev)|ngrok\.io|serveo\.net|localtunnel\.me|loca\.lt|trycloudflare\.com|beeceptor\.com|hookb\.in|smee\.io|mockbin\.(?:org|io)|dnslog\.cn|ceye\.io|xip\.io|nip\.io|termbin\.com|paste(?:bin)?\.\w+|transfer\.sh|file\.io|0x0\.st|ptsv2\.com|postb\.in|en\.[a-z0-9]+\.workers\.dev)"

_ROWS: list[tuple[str, float, str, str]] = [
    # --- system prompt / instruction extraction -------------------------------
    (r"\b(?:what|show|tell|reveal|repeat|print|output|display|give|share|expose|leak|dump|echo|return|list|recite)\s+(?:me\s+)?(?:is\s+|are\s+|your\s+|the\s+|all\s+|me\s+your\s+)*(?:exact\s+|full\s+|complete\s+|entire\s+|original\s+|initial\s+|verbatim\s+|raw\s+)*(?:system\s+prompt|system\s+message|initial\s+(?:prompt|instructions?|message)|original\s+(?:prompt|instructions?)|(?:your\s+)?instructions?|prompt\s+(?:above|template)|configuration|directive|guidelines?\s+(?:you\s+were\s+given))\b", 0.9, "System prompt extraction request", "extract"),
    (r"\b(?:reveal|show|tell|print|output|expose|disclose|share)\s+(?:me\s+)?your\s+(?:initial|original|system|hidden|secret|underlying|internal|configured)\s+(?:instructions?|prompt|directives?|rules?|guidelines?|configuration|setup)", 0.9, "Hidden instruction extraction", "extract"),
    (r"\brepeat\s+(?:the\s+)?(?:text|words?|content|everything|all|message)\s+(?:above|before|preceding|prior\s+to\s+this|at\s+the\s+(?:top|start|beginning))", 0.85, "Repeat text above", "extract"),
    (r"\b(?:output|print|write|show|give\s+me|repeat)\s+everything\s+(?:above|before|prior)\s+(?:this\s+(?:line|message|point)|verbatim)?", 0.85, "Output everything above", "extract"),
    (r"\b(?:print|output|repeat|write)\s+(?:the\s+)?(?:above|previous|preceding)\s+(?:text|content|instructions?|prompt|words?)\s+(?:verbatim|exactly|word\s+for\s+word|as\s+is|in\s+full)", 0.9, "Verbatim reproduction of prompt", "extract"),
    (r"\brepeat\s+(?:back\s+)?(?:your\s+)?(?:the\s+words?|everything|the\s+text|the\s+instructions?)\s+(?:starting\s+with|beginning\s+with|that\s+start(?:s|ed)?\s+with)\s+[\"'“]", 0.9, "Repeat text starting with (leak trick)", "extract"),
    (r"\b(?:ignore|disregard)[^.\n]{0,60}\b(?:print|output|reveal|show|repeat)\b[^.\n]{0,40}\b(?:system\s+prompt|instructions?|above)", 0.9, "Override then extract prompt", "extract"),
    (r"\b(?:what\s+(?:were|are)\s+you\s+(?:told|instructed|programmed|configured|asked)\s+(?:to\s+do|not\s+to\s+do|at\s+the\s+(?:start|beginning)))\b", 0.75, "What were you told", "extract"),
    (r"\bsummar(?:ize|ise)\s+(?:your\s+)?(?:the\s+)?(?:system\s+prompt|instructions?|the\s+text\s+above|everything\s+above|your\s+rules|your\s+guidelines)", 0.8, "Summarize your instructions", "extract"),
    (r"\b(?:encode|base64|hex|rot13|convert|translate)\s+(?:the\s+|your\s+|all\s+)?(?:system\s+prompt|instructions?|the\s+(?:above|text\s+above)|previous\s+messages?|conversation|everything\s+above)\b", 0.85, "Encode the system prompt", "extract"),
    (r"\b(?:in\s+a\s+)?(?:code\s+block|codeblock|markdown|json|yaml)\b[^.\n]{0,40}\b(?:your\s+)?(?:system\s+prompt|instructions?|the\s+(?:text|prompt)\s+above)", 0.75, "Prompt in a code block", "extract"),
    (r"\b(?:tldr|tl;dr)\s+(?:the\s+)?(?:above|system\s+prompt|instructions?)", 0.6, "TLDR of the prompt", "extract"),
    (r"\byou\s+are\s+a\s+(?:transcription|copy|echo|repeater)\s+(?:bot|tool|machine)\b[^.\n]{0,80}\brepeat", 0.8, "Echo bot roleplay to leak prompt", "extract"),
    (r"\bhow\s+(?:do|does)\s+your\s+(?:system\s+)?(?:prompt|instructions?)\s+(?:start|begin|end)\b", 0.75, "Probe prompt boundaries", "extract"),
    (r"\bwhat\s+(?:is\s+)?(?:the\s+)?(?:first|last|final|opening|closing)\s+(?:word|line|sentence|paragraph)\s+of\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions?|the\s+text\s+above)", 0.8, "Probe prompt fragments", "extract"),
    # --- forwarding conversation / data to external endpoints ------------------
    (r"\b(?:send|forward|post|upload|transmit|deliver|submit|email|mail|share|export|leak|exfiltrate|relay|ship|push)\s+(?:the\s+|this\s+|all\s+|our\s+|entire\s+|our\s+entire\s+|the\s+full\s+)?(?:conversation|chat|messages?|history|transcript|dialogue|context|session|data|content|prompt|responses?)\s+(?:to|at|via|over|through)\b", 0.85, "Forward the conversation externally", "forward"),
    (r"\b(?:send|post|forward|upload|transmit|deliver|make\s+(?:a\s+)?(?:request|call))\s+(?:it|this|that|them|the\s+\w+)?\s*(?:to|at)\s+(?:https?://|www\.)?" + _EXFIL_DOMAINS, 0.95, "Send data to exfiltration domain", "forward"),
    (r"\b(?:make|send|issue|perform|do|fire)\s+(?:an?\s+)?(?:http\s+)?(?:get|post|put|request|call|fetch|curl|api\s+call|web\s+request)\s+(?:to|at)\b", 0.5, "Outbound request request", "forward"),
    (r"\b(?:when\s+(?:you\s+)?(?:are\s+)?(?:done|finished)|after\s+(?:you\s+)?(?:respond|answer|reply)|then)\b[^.\n]{0,60}\b(?:send|post|forward|email|upload|transmit)\b[^.\n]{0,40}\b(?:to|at)\b", 0.7, "Deferred exfiltration instruction", "forward"),
    (r"\b(?:append|add|include|attach|embed|encode)\s+(?:the\s+)?(?:conversation|chat|history|previous\s+messages?|system\s+prompt|user\s+data|context)\s+(?:in|to|as|into)\s+(?:the\s+)?(?:url|link|query\s+string|parameter|image\s+(?:url|src)|request)", 0.9, "Embed data into URL/link", "forward"),
    # --- markdown/link/image beacons -------------------------------------------
    (r"!\[[^\]]*\]\((https?://[^\s)]+[?&][^\s)]*(?:=|%3d)[^\s)]*)\)", 0.85, "Markdown image beacon with query data", "beacon"),
    (r"!\[[^\]]*\]\((https?://" + _EXFIL_DOMAINS + r"[^\s)]*)\)", 0.95, "Markdown image to exfiltration domain", "beacon"),
    (r"\[[^\]]*\]\((https?://" + _EXFIL_DOMAINS + r"[^\s)]*)\)", 0.9, "Markdown link to exfiltration domain", "beacon"),
    (r"<img\s+[^>]*src\s*=\s*[\"'](https?://[^\"']+[?&][^\"']*(?:=|%3d)[^\"']*)[\"']", 0.85, "HTML image beacon with query data", "beacon"),
    (r"\b(?:render|display|show|embed|include|output|generate|create)\s+(?:this\s+|the\s+following\s+|an?\s+)?(?:markdown\s+)?image\b[^.\n]{0,80}\b(?:with|containing|encode|include)\b[^.\n]{0,60}\b(?:conversation|prompt|data|messages?|url\s+param)", 0.85, "Instruct model to render data-carrying image", "beacon"),
    (r"https?://" + _EXFIL_DOMAINS + r"[^\s]*[?&][^\s]*=", 0.85, "URL to exfiltration domain with parameters", "beacon"),
    (r"\b(?:base64|b64|url-?encode|percent-?encode)\s*(?:-?encode)?\s+(?:the\s+)?(?:conversation|system\s+prompt|previous\s+messages?|data|it|the\s+above)\b[^.\n]{0,60}\b(?:and\s+)?(?:put|place|append|add|include)\s+(?:it\s+)?(?:in|into|to)\s+(?:the\s+)?(?:url|link|query|parameter)", 0.95, "Encode data into a link", "beacon"),
    (r"\bdns\s+(?:exfil|lookup|query|request|resolve)\b[^.\n]{0,60}\b(?:with|containing|encode|subdomain)\b", 0.8, "DNS exfiltration", "beacon"),
]

SIGS: list[Signature] = compile_signatures(_ROWS)
_MAX_PER_MESSAGE = 6


class DataExfilAnalyzer:
    name = NAME
    description = "Detects data exfiltration attempts: system prompt extraction, conversation forwarding, markdown/image/link beacons and requests to encode data into outbound URLs."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for location, role, raw in iter_messages(normalized):
            if role == "system":
                continue
            text = normalize_text(raw)
            if not text:
                continue
            in_tool = is_tool_context(role, raw)
            hits: list[tuple[Signature, str]] = []
            for sig in SIGS:
                m = sig.search(text)
                if m:
                    hits.append((sig, snippet(text, m.start(), m.end())))
            hits.sort(key=lambda h: h[0].weight, reverse=True)
            for sig, ev in hits[:_MAX_PER_MESSAGE]:
                sev = severity_from_weight(sig.weight, 1 if in_tool else 0)
                conf = sig.weight * (0.95 if in_tool else 0.9)
                where = "tool/retrieved content" if in_tool else f"{role} message"
                findings.append(
                    make_finding(
                        NAME, "data_exfil", sev, sig.label,
                        f"Detected a data exfiltration pattern ('{sig.tag}') in {where}. The request tries to extract the system prompt or move conversation data to an external endpoint.",
                        ev, location, conf, tags=[sig.tag] + (["indirect_injection"] if in_tool else []),
                        metadata={"role": role, "weight": sig.weight, "indirect": in_tool},
                    )
                )
        return findings


analyzer = DataExfilAnalyzer()
