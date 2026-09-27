"""User-defined detection rules, edited live in Settings > Rules. Each rule is a regex with a category,
severity, scope (request, response or both) and action (flag or deny)."""
from __future__ import annotations

import re
from typing import Any

from .. import settings_store
from .base import Finding, Severity

_cache: dict[str, re.Pattern] = {}


def _compile(pattern: str) -> re.Pattern | None:
    if pattern in _cache:
        return _cache[pattern]
    try:
        _cache[pattern] = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except re.error:
        return None
    return _cache[pattern]


def _rules(scope: str) -> list[dict[str, Any]]:
    return [r for r in settings_store.get_value("rules", "custom", []) or [] if r.get("enabled", True) and r.get("pattern") and r.get("scope", "request") in (scope, "both")]


def _apply(rules: list[dict[str, Any]], text: str, location: str) -> list[Finding]:
    out: list[Finding] = []
    for r in rules:
        rx = _compile(r["pattern"])
        if rx is None:
            continue
        m = rx.search(text or "")
        if not m:
            continue
        try:
            sev = Severity(str(r.get("severity", "MEDIUM")).upper())
        except ValueError:
            sev = Severity.MEDIUM
        out.append(
            Finding(
                analyzer="custom_rules",
                category=r.get("category") or "policy",
                severity=sev,
                title=r.get("name") or f"Custom rule {r.get('id', '')}".strip(),
                description=r.get("description") or f"Matched custom rule pattern /{r['pattern']}/",
                evidence=text[max(0, m.start() - 60): m.end() + 60],
                location=location,
                confidence=float(r.get("confidence", 0.9)),
                tags=["custom_rule"],
                metadata={"rule_id": r.get("id"), "action": r.get("action", "flag")},
            )
        )
    return out


class CustomRulesRequest:
    name = "custom_rules"
    description = "User-defined regex rules from Settings > Rules applied to the request."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        rules = _rules("request")
        if not rules:
            return []
        findings = _apply(rules, normalized.get("system") or "", "system")
        for i, m in enumerate(normalized.get("messages") or []):
            if m.get("role") in ("system", "developer"):
                continue
            findings.extend(_apply(rules, m.get("content") or "", f"messages[{i}]"))
        return findings


class CustomRulesResponse:
    name = "custom_rules_response"
    description = "User-defined regex rules from Settings > Rules applied to the model output."

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        rules = _rules("response")
        return _apply(rules, context.get("response_text") or "", "response") if rules else []
