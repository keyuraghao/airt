"""Policy engine: decides whether an intercepted request is auto-denied, auto-approved or needs a human."""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any

from .. import settings_store
from ..models import Agent


@dataclass
class PolicyDecision:
    action: str  # "deny" | "approve" | "review"
    reasons: list[str] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"action": self.action, "reasons": self.reasons, "matched_rules": self.matched_rules}


def evaluate(agent: Agent, normalized: dict[str, Any], path: str, risk_score: int, findings: list[dict[str, Any]]) -> PolicyDecision:
    reasons: list[str] = []
    rules: list[str] = []

    if not agent.is_active:
        return PolicyDecision("deny", ["agent is disabled"], ["agent.is_active"])

    global_pol = settings_store.get_namespace("policy")
    g_paths = global_pol.get("global_allowed_paths") or []
    if g_paths and not any(fnmatch.fnmatch(path, pat) or fnmatch.fnmatch("/" + path, pat) for pat in g_paths):
        return PolicyDecision("deny", [f"path '{path}' is not in the global allowed paths"], ["policy.global_allowed_paths"])

    if agent.allowed_paths and not any(fnmatch.fnmatch(path, pat) or fnmatch.fnmatch("/" + path, pat) for pat in agent.allowed_paths):
        return PolicyDecision("deny", [f"path '{path}' is not in the agent's allowed paths"], ["agent.allowed_paths"])

    model = normalized.get("model") or ""
    if agent.allowed_models and model and not any(fnmatch.fnmatch(model, pat) for pat in agent.allowed_models):
        return PolicyDecision("deny", [f"model '{model}' is not in the agent's allowed models"], ["agent.allowed_models"])

    text = normalized.get("prompt_text") or ""
    for source, patterns in (("agent.auto_deny_patterns", agent.auto_deny_patterns or []), ("policy.global_auto_deny_patterns", global_pol.get("global_auto_deny_patterns") or [])):
        for pat in patterns:
            try:
                if re.search(pat, text, re.IGNORECASE | re.DOTALL):
                    reasons.append(f"prompt matches auto-deny pattern /{pat}/")
                    rules.append(source)
            except re.error:
                continue
    if any(f.get("metadata", {}).get("action") == "deny" for f in findings):
        reasons.append("a custom rule with action=deny matched")
        rules.append("rules.custom")
    if reasons:
        return PolicyDecision("deny", reasons, rules)

    if agent.auto_deny_at_risk and risk_score >= agent.auto_deny_at_risk:
        return PolicyDecision("deny", [f"risk score {risk_score} >= auto-deny threshold {agent.auto_deny_at_risk}"], ["agent.auto_deny_at_risk"])

    if any(f.get("severity") == "CRITICAL" and f.get("category") in ("secrets", "data_exfil") for f in findings):
        reasons.append("critical secret/exfiltration finding requires human review")
        rules.append("finding.critical")
        return PolicyDecision("review", reasons, rules)

    if not agent.require_approval:
        return PolicyDecision("approve", ["agent policy does not require approval"], ["agent.require_approval=false"])

    if agent.auto_approve_below_risk and risk_score < agent.auto_approve_below_risk:
        return PolicyDecision("approve", [f"risk score {risk_score} < auto-approve threshold {agent.auto_approve_below_risk}"], ["agent.auto_approve_below_risk"])

    return PolicyDecision("review", ["human approval required by agent policy"], ["agent.require_approval=true"])
