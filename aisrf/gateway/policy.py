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


def typesafe_route(agent: Agent, findings: list[dict[str, Any]]) -> PolicyDecision | None:
    """Confidence-gated routing on the TypeSafe verdict (integrations.typesafe.auto_route).

    Runs after the auto-deny patterns and before the risk thresholds. A ``typesafe_guard`` finding
    whose verdict is malicious with confidence >= auto_deny_confidence denies the request
    (rule ``typesafe.auto_deny``); a benign verdict with confidence >= auto_approve_confidence approves
    it for agents that require approval (rule ``typesafe.auto_approve``), unless any finding is HIGH or
    CRITICAL. Everything else falls through to the normal rules, so the human queue only receives what
    TypeSafe could not settle.
    """
    cfg = settings_store.get_value("integrations", "typesafe", {}) or {}
    if not cfg.get("auto_route"):
        return None
    best: dict[str, Any] | None = None
    for f in findings:
        if f.get("analyzer") != "typesafe_guard":
            continue
        ts = (f.get("metadata") or {}).get("typesafe")
        if isinstance(ts, dict) and (
            best is None or float(ts.get("confidence") or 0) > float(best.get("confidence") or 0)
        ):
            best = ts
    if not best:
        return None
    verdict = str(best.get("verdict") or "")
    confidence = float(best.get("confidence") or 0)
    try:
        deny_at = float(cfg.get("auto_deny_confidence", 0.95))
        approve_at = float(cfg.get("auto_approve_confidence", 0.9))
    except (TypeError, ValueError):
        deny_at, approve_at = 0.95, 0.9
    if verdict == "malicious" and confidence >= deny_at:
        return PolicyDecision(
            "deny",
            [f"TypeSafe verdict malicious with confidence {confidence:.2f} >= {deny_at}"],
            ["typesafe.auto_deny"],
        )
    if verdict == "benign" and confidence >= approve_at and agent.require_approval:
        severe = [f for f in findings if str(f.get("severity")) in ("HIGH", "CRITICAL")]
        if severe:
            return None
        return PolicyDecision(
            "approve",
            [
                f"TypeSafe verdict benign with confidence {confidence:.2f} >= {approve_at} and no HIGH or CRITICAL finding"
            ],
            ["typesafe.auto_approve"],
        )
    return None


def evaluate(
    agent: Agent, normalized: dict[str, Any], path: str, risk_score: int, findings: list[dict[str, Any]]
) -> PolicyDecision:
    reasons: list[str] = []
    rules: list[str] = []

    if not agent.is_active:
        return PolicyDecision("deny", ["agent is disabled"], ["agent.is_active"])

    global_pol = settings_store.get_namespace("policy")
    g_paths = global_pol.get("global_allowed_paths") or []
    if g_paths and not any(fnmatch.fnmatch(path, pat) or fnmatch.fnmatch("/" + path, pat) for pat in g_paths):
        return PolicyDecision(
            "deny", [f"path '{path}' is not in the global allowed paths"], ["policy.global_allowed_paths"]
        )

    if agent.allowed_paths and not any(
        fnmatch.fnmatch(path, pat) or fnmatch.fnmatch("/" + path, pat) for pat in agent.allowed_paths
    ):
        return PolicyDecision(
            "deny", [f"path '{path}' is not in the agent's allowed paths"], ["agent.allowed_paths"]
        )

    model = normalized.get("model") or ""
    if (
        agent.allowed_models
        and model
        and not any(fnmatch.fnmatch(model, pat) for pat in agent.allowed_models)
    ):
        return PolicyDecision(
            "deny", [f"model '{model}' is not in the agent's allowed models"], ["agent.allowed_models"]
        )

    text = normalized.get("prompt_text") or ""
    for source, patterns in (
        ("agent.auto_deny_patterns", agent.auto_deny_patterns or []),
        ("policy.global_auto_deny_patterns", global_pol.get("global_auto_deny_patterns") or []),
    ):
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

    routed = typesafe_route(agent, findings)
    if routed is not None:
        return routed

    if agent.auto_deny_at_risk and risk_score >= agent.auto_deny_at_risk:
        return PolicyDecision(
            "deny",
            [f"risk score {risk_score} >= auto-deny threshold {agent.auto_deny_at_risk}"],
            ["agent.auto_deny_at_risk"],
        )

    if any(
        f.get("severity") == "CRITICAL" and f.get("category") in ("secrets", "data_exfil") for f in findings
    ):
        reasons.append("critical secret/exfiltration finding requires human review")
        rules.append("finding.critical")
        return PolicyDecision("review", reasons, rules)

    if not agent.require_approval:
        return PolicyDecision(
            "approve", ["agent policy does not require approval"], ["agent.require_approval=false"]
        )

    if agent.auto_approve_below_risk and risk_score < agent.auto_approve_below_risk:
        return PolicyDecision(
            "approve",
            [f"risk score {risk_score} < auto-approve threshold {agent.auto_approve_below_risk}"],
            ["agent.auto_approve_below_risk"],
        )

    return PolicyDecision(
        "review", ["human approval required by agent policy"], ["agent.require_approval=true"]
    )
