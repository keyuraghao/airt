"""Structural / metadata anomaly detection: role spoofing, parameter extremes, odd models, suspicious paths and headers."""
from __future__ import annotations

import re
from typing import Any

from ...analysis.base import Finding, Severity
from .common import iter_messages, make_finding, normalize_text, safe_text, snippet

NAME = "anomaly"

_ROLE_CLAIM_RE = re.compile(
    r"\b(?:i\s+am|this\s+is|as\s+(?:the|your)|acting\s+as)\s+(?:the\s+|your\s+)?(?:system|developer|admin(?:istrator)?|root|operator|maintainer)\b"
    r"|(?:^|\n)\s*(?:system|developer)\s*:",
    re.IGNORECASE,
)
_KNOWN_MODEL_RE = re.compile(
    r"^(?:gpt-|o1|o3|o4|chatgpt|text-|davinci|claude-|claude[\s.]|anthropic|gemini|palm|bison|models/gemini|llama|mistral|mixtral|command|cohere|qwen|deepseek|phi-|gemma|grok|titan|nova|jamba|dbrx|yi-|glm-|ernie)",
    re.IGNORECASE,
)
_SUSPICIOUS_MODEL_RE = re.compile(r"(?:jailbr|uncensor|unfilter|dolphin|wizard-?vicuna|nsfw|abliterated|unaligned|evil|dan\b|:ft-|ft:|finetune|custom|:latest-nsfw)", re.IGNORECASE)
_PROVIDER_PATHS: dict[str, tuple[str, ...]] = {
    "openai": ("/v1/chat/completions", "/v1/completions", "/v1/responses", "/v1/embeddings", "/v1/moderations", "/chat/completions", "/completions", "/responses", "/embeddings"),
    "anthropic": ("/v1/messages", "/v1/complete", "/messages"),
    "google": ("generatecontent", "streamgeneratecontent", ":generatecontent"),
}
_SENSITIVE_HEADERS = ("x-forwarded-for", "x-real-ip", "x-forwarded-host", "x-original-url", "x-rewrite-url", "x-forwarded-server", "forwarded", "x-custom-ip-authorization", "x-originating-ip", "client-ip")


def _to_float(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _to_int(v: Any) -> int | None:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


class AnomalyAnalyzer:
    name = NAME
    description = "Flags structural and metadata anomalies: user-as-system role spoofing, empty user content, excessive tool results, extreme sampling parameters, unknown/suspicious models, unusual paths and spoofable headers."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        messages = normalized.get("messages") if isinstance(normalized.get("messages"), list) else []
        roles = [str(m.get("role", "")).lower() for m in messages if isinstance(m, dict)]

        # --- user message claiming to be system/developer -----------------------
        for location, role, raw in iter_messages(normalized):
            if role in ("user", "tool", "function"):
                m = _ROLE_CLAIM_RE.search(raw[:600])
                if m:
                    findings.append(
                        make_finding(
                            NAME, "anomaly", Severity.LOW, "User content claims a system/developer role",
                            "A non-privileged message asserts a system, developer or admin identity. This is a role-spoofing attempt and often precedes prompt injection.",
                            snippet(raw, m.start(), m.end()), location, 0.55, tags=["role_spoof"], metadata={"role": role},
                        )
                    )
                    break

        # --- empty / missing user content ---------------------------------------
        user_content = [safe_text(m.get("content")).strip() for m in messages if isinstance(m, dict) and str(m.get("role", "")).lower() == "user"]
        if normalized.get("system") and not any(user_content) and not any(r in ("user",) for r in roles):
            findings.append(
                make_finding(
                    NAME, "anomaly", Severity.INFO, "System prompt present with no user message",
                    "The request carries a system prompt but no user turn. Unusual for normal chat traffic; can indicate probing or a malformed client.",
                    "", "messages", 0.4, tags=["structure"], metadata={"message_count": len(messages)},
                )
            )

        # --- tool result flood ---------------------------------------------------
        tool_results = sum(1 for m in messages if isinstance(m, dict) and str(m.get("role", "")).lower() in ("tool", "function", "tool_result"))
        if tool_results > 15:
            findings.append(
                make_finding(
                    NAME, "anomaly", Severity.LOW, "Unusually many tool results in one request",
                    f"{tool_results} tool/function result messages in a single request. A large volume of retrieved content widens the indirect-injection surface.",
                    "", "messages", 0.5, tags=["structure", "tool_results"], metadata={"tool_result_count": tool_results},
                )
            )

        # --- alternating anomalies / role diversity ------------------------------
        distinct_roles = set(roles)
        if len(roles) >= 6:
            consecutive_user = max((len(list(g)) for g in _runs(roles, "user")), default=0)
            if consecutive_user >= 5:
                findings.append(
                    make_finding(
                        NAME, "anomaly", Severity.INFO, "Many consecutive user turns without assistant replies",
                        f"{consecutive_user} user messages in a row. Can indicate a scripted many-shot prompt rather than an interactive conversation.",
                        "", "messages", 0.4, tags=["structure"], metadata={"consecutive_user": consecutive_user},
                    )
                )
        if distinct_roles - {"user", "assistant", "system", "developer", "tool", "function", "tool_result", "model"}:
            odd = sorted(distinct_roles - {"user", "assistant", "system", "developer", "tool", "function", "tool_result", "model"})
            findings.append(
                make_finding(
                    NAME, "anomaly", Severity.LOW, "Unexpected message role(s)",
                    f"Non-standard role value(s) present: {', '.join(odd)[:120]}. Custom roles can be used to spoof trusted turns.",
                    "", "messages", 0.5, tags=["structure", "role_spoof"], metadata={"roles": odd},
                )
            )

        # --- extreme parameters --------------------------------------------------
        extra = normalized.get("extra") if isinstance(normalized.get("extra"), dict) else {}
        temp = _to_float(extra.get("temperature"))
        if temp is not None and temp > 1.5:
            findings.append(
                make_finding(
                    NAME, "anomaly", Severity.INFO, "Very high temperature",
                    f"temperature={temp}. Extreme sampling temperature increases unpredictable / unsafe output.",
                    f"temperature={temp}", "extra.temperature", 0.4, tags=["parameter"], metadata={"temperature": temp},
                )
            )
        top_p = _to_float(extra.get("top_p"))
        if top_p is not None and (top_p < 0 or top_p > 1):
            findings.append(
                make_finding(
                    NAME, "anomaly", Severity.LOW, "Out-of-range top_p", f"top_p={top_p} is outside [0,1].", f"top_p={top_p}", "extra.top_p", 0.5, tags=["parameter"], metadata={"top_p": top_p})
            )
        n = _to_int(extra.get("n"))
        if n is not None and n > 10:
            findings.append(
                make_finding(
                    NAME, "anomaly", Severity.LOW, "High completion count (n)",
                    f"n={n} completions requested. Large n can be used to brute-force an unsafe sample or to amplify cost.",
                    f"n={n}", "extra.n", 0.5, tags=["parameter", "abuse"], metadata={"n": n},
                )
            )
        max_tokens = _to_int(extra.get("max_tokens") or extra.get("max_completion_tokens"))
        if max_tokens is not None and max_tokens > 32000:
            findings.append(
                make_finding(
                    NAME, "anomaly", Severity.INFO, "Very high max_tokens",
                    f"max_tokens={max_tokens}. Unusually large output budget; can indicate data-dump or cost-abuse attempts.",
                    f"max_tokens={max_tokens}", "extra.max_tokens", 0.35, tags=["parameter"], metadata={"max_tokens": max_tokens},
                )
            )

        # --- suspicious / unknown model -----------------------------------------
        model = safe_text(normalized.get("model"), 200).strip()
        if model:
            if _SUSPICIOUS_MODEL_RE.search(model):
                findings.append(
                    make_finding(
                        NAME, "anomaly", Severity.MEDIUM, "Model name suggests an uncensored/fine-tuned target",
                        f"Model '{model}' matches naming for uncensored or jailbreak-tuned models.",
                        model, "model", 0.6, tags=["model"], metadata={"model": model},
                    )
                )
            elif not _KNOWN_MODEL_RE.match(model):
                findings.append(
                    make_finding(
                        NAME, "anomaly", Severity.INFO, "Unrecognized model name",
                        f"Model '{model}' does not match known provider families; may be a custom or fine-tuned endpoint.",
                        model, "model", 0.35, tags=["model"], metadata={"model": model},
                    )
                )

        # --- unusual request path for the provider ------------------------------
        path = safe_text(context.get("path"), 500).lower() if context else ""
        provider = safe_text(normalized.get("provider"), 60).lower()
        if path and provider in _PROVIDER_PATHS:
            if not any(seg in path for seg in _PROVIDER_PATHS[provider]):
                findings.append(
                    make_finding(
                        NAME, "anomaly", Severity.LOW, "Unusual request path for provider",
                        f"Path '{path[:80]}' is not a standard {provider} endpoint. Review for path confusion or an unexpected upstream.",
                        path[:100], "path", 0.45, tags=["path"], metadata={"provider": provider, "path": path[:120]},
                    )
                )
        if path and re.search(r"\.\./|%2e%2e|/admin\b|/internal\b|/\.env\b|/debug\b", path):
            findings.append(
                make_finding(
                    NAME, "anomaly", Severity.MEDIUM, "Suspicious characters in request path",
                    "The request path contains traversal or sensitive-endpoint markers.",
                    path[:100], "path", 0.6, tags=["path", "traversal"], metadata={"path": path[:120]},
                )
            )

        # --- suspicious headers --------------------------------------------------
        headers = context.get("headers") if context and isinstance(context.get("headers"), dict) else {}
        lower_headers = {str(k).lower(): safe_text(v, 300) for k, v in headers.items()}
        for h in _SENSITIVE_HEADERS:
            if h in lower_headers:
                val = lower_headers[h]
                # multiple values in a forwarding header can indicate spoofing
                if h in ("x-forwarded-for", "forwarded") and "," in val:
                    findings.append(
                        make_finding(
                            NAME, "anomaly", Severity.LOW, f"Multiple values in {h} header",
                            f"The '{h}' header carries multiple addresses ('{val[:60]}'); can indicate IP spoofing or a rebuilt forwarding chain.",
                            f"{h}: {val[:80]}", "headers", 0.45, tags=["header", "spoof"], metadata={"header": h, "value": val[:120]},
                        )
                    )
                else:
                    findings.append(
                        make_finding(
                            NAME, "anomaly", Severity.INFO, f"Client-supplied {h} header",
                            f"The request includes a client-controllable '{h}' header, which can be used to spoof source identity if trusted downstream.",
                            f"{h}: {val[:80]}", "headers", 0.3, tags=["header"], metadata={"header": h, "value": val[:120]},
                        )
                    )
        return findings


def _runs(seq: list[str], value: str):
    run: list[str] = []
    for item in seq:
        if item == value:
            run.append(item)
        else:
            if run:
                yield run
                run = []
    if run:
        yield run


analyzer = AnomalyAnalyzer()
