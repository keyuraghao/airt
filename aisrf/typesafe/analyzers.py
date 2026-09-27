"""TypeSafe request and response analyzers for the analysis runner.

``typesafe_guard`` sends the whole conversation once with the REQUEST_GUARD fan-out (nine nouls, an
intent choice and a severity score) and turns the answers into findings: one per attack noul above
``noul_threshold``, category from the noul (or the intent choice when it names an attack class),
severity from the score level, confidence from the returned confidence or the noul's distance from
0.5. Every finding carries ``metadata["typesafe"] = {"verdict", "confidence"}`` where the verdict is
``malicious``, ``benign`` or ``uncertain``; the same summary is written to ``context["typesafe"]`` so
the runner can decide whether the LLM judge still needs to run (confidence-gated escalation).

``typesafe_response_guard`` does the same for the model response with RESPONSE_GUARD.

Both are silent no-ops while ``integrations.typesafe.enabled`` is false or no key is configured, and
they never raise: a failed call yields no findings and no verdict (which the runner treats as uncertain).
"""

from __future__ import annotations

from typing import Any

from ..analysis.analyzers.common import make_finding
from ..analysis.base import Finding, Severity
from ..guardrails._common import log_throttled, response_text, set_error
from . import client as ts
from . import questions as q

NAME_REQUEST = "typesafe_guard"
NAME_RESPONSE = "typesafe_response_guard"
_LEVELS = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_LABELS = {
    "prompt_injection": "prompt injection",
    "jailbreak": "jailbreak attempt",
    "system_prompt_extraction": "system prompt extraction",
    "data_exfiltration": "data exfiltration attempt",
    "contains_pii": "personal data in the request",
    "contains_secrets": "credentials in the request",
    "harmful_request": "harmful request",
    "tool_abuse": "tool abuse",
    "leaked_system_prompt": "system prompt leaked in the response",
    "leaked_secret_or_pii": "secret or personal data leaked in the response",
    "harmful_compliance": "harmful compliance in the response",
    "exfil_markup": "exfiltration markup in the response",
    "refusal": "the model refused",
}
# response nouls carry a base severity that the severity score does not cover
_RESPONSE_BASE = {
    "leaked_system_prompt": Severity.HIGH,
    "leaked_secret_or_pii": Severity.HIGH,
    "harmful_compliance": Severity.HIGH,
    "exfil_markup": Severity.MEDIUM,
}


# ---------------------------------------------------------------------------
# answer helpers
# ---------------------------------------------------------------------------


def noul_value(answers: dict[str, Any], name: str) -> float | None:
    a = answers.get(name)
    if not isinstance(a, dict):
        return None
    try:
        p = float(a.get("noul"))
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, p))


def noul_confidence(p: float) -> float:
    """How far a yes/no probability is from the coin flip, scaled to 0..1."""
    return round(min(1.0, abs(p - 0.5) * 2), 3)


def choice_value(answers: dict[str, Any], name: str) -> tuple[str, float, float, dict[str, float]]:
    """(choice, probability of that choice, confidence, all probabilities)."""
    a = answers.get(name)
    if not isinstance(a, dict):
        return "", 0.0, 0.0, {}
    probs = {str(k): float(v) for k, v in (a.get("probabilities") or {}).items() if isinstance(v, (int, float))}
    chosen = str(a.get("choice") or "")
    try:
        conf = float(a.get("confidence") or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    return chosen, float(probs.get(chosen, 0.0)), max(0.0, min(1.0, conf)), probs


def score_value(answers: dict[str, Any], name: str) -> tuple[float | None, float, dict[str, float]]:
    """(score, confidence, probabilities per level)."""
    a = answers.get(name)
    if not isinstance(a, dict):
        return None, 0.0, {}
    try:
        s = float(a.get("score"))
    except (TypeError, ValueError):
        s = None
    try:
        conf = float(a.get("confidence") or 0.0)
    except (TypeError, ValueError):
        conf = 0.0
    probs = {str(k): float(v) for k, v in (a.get("probabilities") or {}).items() if isinstance(v, (int, float))}
    return s, max(0.0, min(1.0, conf)), probs


def severity_from_score(score: float | None, fallback: Severity) -> Severity:
    if score is None:
        return fallback
    idx = round(max(0.0, min(float(len(_LEVELS) - 1), score)))
    return _LEVELS[idx]


def _thresholds(cfg: dict[str, Any]) -> tuple[float, float, float]:
    return (
        ts._num(cfg, "noul_threshold", 0.7),
        ts._num(cfg, "benign_confidence", 0.85),
        ts._num(cfg, "malicious_confidence", 0.9),
    )


def summarize(
    answers: dict[str, Any],
    attack_nouls: dict[str, str],
    cfg: dict[str, Any],
    *,
    benign_noul: str | None = None,
    intent_name: str | None = None,
) -> dict[str, Any]:
    """Collapse a fan-out into a verdict (malicious | benign | uncertain) with a confidence in 0..1."""
    thr, benign_at, malicious_at = _thresholds(cfg)
    fired: dict[str, float] = {}
    grey = False
    for name in attack_nouls:
        p = noul_value(answers, name)
        if p is None:
            continue
        if p >= thr:
            fired[name] = round(p, 3)
        elif p >= 0.5:
            grey = True
    intent, intent_p, intent_conf, intent_probs = choice_value(answers, intent_name) if intent_name else ("", 0.0, 0.0, {})
    attack_intent = bool(intent) and intent not in ("benign", "other") and intent_conf >= thr
    severity, severity_conf, _ = score_value(answers, "severity")
    benign_p = noul_value(answers, benign_noul) if benign_noul else None
    if fired or attack_intent:
        signals = [noul_confidence(p) for p in fired.values()]
        if attack_intent:
            signals.append(intent_conf)
        confidence = max(signals)
        verdict = "malicious" if confidence >= malicious_at else "uncertain"
    else:
        signals = []
        if benign_p is not None and benign_p >= 0.5:
            signals.append(noul_confidence(benign_p))
        if intent == "benign":
            signals.append(intent_conf)
        if severity is not None and severity <= 0.5 and severity_conf:
            signals.append(severity_conf)
        confidence = max(signals) if signals else 0.0
        verdict = "benign" if confidence >= benign_at and not grey else "uncertain"
    return {
        "verdict": verdict,
        "confidence": round(confidence, 3),
        "fired": fired,
        "intent": intent,
        "intent_probability": round(intent_p, 3),
        "intent_confidence": round(intent_conf, 3),
        "intent_probabilities": intent_probs,
        "severity_score": severity,
        "severity_confidence": round(severity_conf, 3),
        "benign_probability": benign_p,
        "threshold": thr,
    }


def _metadata(result: dict[str, Any], summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "typesafe": {"verdict": summary["verdict"], "confidence": summary["confidence"]},
        "answers": result.get("answers") or {},
        "intent": summary["intent"],
        "intent_confidence": summary["intent_confidence"],
        "severity_score": summary["severity_score"],
        "fired": summary["fired"],
        "threshold": summary["threshold"],
        "model": result.get("model"),
        "usage": result.get("usage"),
        "latency_ms": result.get("latency_ms"),
        "cached": bool(result.get("cached")),
    }


# ---------------------------------------------------------------------------
# request analyzer
# ---------------------------------------------------------------------------


def request_findings(result: dict[str, Any], cfg: dict[str, Any], location: str = "prompt_text") -> tuple[list[Finding], dict[str, Any]]:
    answers = result.get("answers") or {}
    summary = summarize(answers, q.REQUEST_NOUL_CATEGORY, cfg, benign_noul=q.REQUEST_BENIGN_NOUL, intent_name="intent")
    meta = _metadata(result, summary)
    findings: list[Finding] = []
    covered: set[str] = set()
    for name, p in summary["fired"].items():
        category = q.REQUEST_NOUL_CATEGORY[name]
        covered.add(category)
        sev = severity_from_score(summary["severity_score"], Severity.MEDIUM)
        if p >= 0.9 and sev in (Severity.INFO, Severity.LOW):
            sev = Severity.MEDIUM  # a near certain attack signal is never merely informational
        findings.append(
            make_finding(
                NAME_REQUEST, category, sev, f"TypeSafe: {_LABELS.get(name, name)} (noul {p:.2f})",
                f"TypeSafe (model {result.get('model')}) answered yes with probability {p:.2f} to the question '{name}'. "
                f"Intent: {summary['intent'] or 'n/a'} (confidence {summary['intent_confidence']:.2f}), severity score "
                f"{summary['severity_score'] if summary['severity_score'] is not None else 'n/a'} on a 0 to 4 scale. Verdict: {summary['verdict']}.",
                f"typesafe noul={p:.2f}", location, noul_confidence(p), tags=["typesafe", name], metadata=meta,
            )
        )
    intent = summary["intent"]
    if intent and intent not in ("benign", "other") and summary["intent_confidence"] >= summary["threshold"] and intent not in covered:
        sev = severity_from_score(summary["severity_score"], Severity.MEDIUM)
        findings.append(
            make_finding(
                NAME_REQUEST, intent, sev, f"TypeSafe: intent classified as {intent.replace('_', ' ')} (p={summary['intent_probability']:.2f})",
                f"TypeSafe's intent choice selected '{intent}' with probability {summary['intent_probability']:.2f} and confidence {summary['intent_confidence']:.2f}. Verdict: {summary['verdict']}.",
                f"typesafe choice={intent} p={summary['intent_probability']:.2f}", location, summary["intent_confidence"],
                tags=["typesafe", "intent"], metadata=meta,
            )
        )
    if not findings:
        # carry the verdict for the policy engine, the dashboard chip and the judge gate
        benign = summary["verdict"] == "benign"
        findings.append(
            make_finding(
                NAME_REQUEST, "benign_control" if benign else "policy", Severity.INFO,
                f"TypeSafe judged the request {'benign' if benign else 'uncertain'} (confidence {summary['confidence']:.2f})",
                f"No attack noul reached the threshold {summary['threshold']}. Intent: {summary['intent'] or 'n/a'} "
                f"(confidence {summary['intent_confidence']:.2f}); benign probability "
                f"{summary['benign_probability'] if summary['benign_probability'] is not None else 'n/a'}.",
                f"typesafe verdict={summary['verdict']} confidence={summary['confidence']:.2f}", location, summary["confidence"],
                tags=["typesafe", "verdict"], metadata=meta,
            )
        )
    return findings, summary


class TypeSafeRequestAnalyzer:
    name = NAME_REQUEST
    description = "Judges the conversation with one TypeSafe (Jev) call: nine attack nouls, an intent choice and a severity score; sets a confidence-gated verdict used by policy and the LLM judge gate."

    async def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        try:
            cfg = ts.config()
            if not ts.is_configured(cfg):
                return []
            state = ts.conversation_state(normalized)
            if not state.get("conversation"):
                return []
            result = await ts.evaluate(state, q.REQUEST_GUARD, purpose="request")
            if not result:
                return []
            findings, summary = request_findings(result, cfg)
            context["typesafe"] = {"verdict": summary["verdict"], "confidence": summary["confidence"], "intent": summary["intent"]}
            return findings
        except Exception as exc:
            set_error(ts.NAME, str(exc))
            log_throttled("typesafe.request", "typesafe.analyzer_failed", analyzer=self.name, error=str(exc)[:300])
            return []


# ---------------------------------------------------------------------------
# response analyzer
# ---------------------------------------------------------------------------


def response_findings(result: dict[str, Any], cfg: dict[str, Any]) -> tuple[list[Finding], dict[str, Any]]:
    answers = result.get("answers") or {}
    summary = summarize(answers, q.RESPONSE_NOUL_CATEGORY, cfg)
    meta = _metadata(result, summary)
    findings: list[Finding] = []
    for name, p in summary["fired"].items():
        base = _RESPONSE_BASE.get(name, Severity.MEDIUM)
        sev = base if p >= 0.9 else _LEVELS[max(0, _LEVELS.index(base) - 1)]
        findings.append(
            make_finding(
                NAME_RESPONSE, q.RESPONSE_NOUL_CATEGORY[name], sev, f"TypeSafe: {_LABELS.get(name, name)} (noul {p:.2f})",
                f"TypeSafe (model {result.get('model')}) answered yes with probability {p:.2f} to '{name}' about the model response. Verdict: {summary['verdict']}.",
                f"typesafe noul={p:.2f}", "response", noul_confidence(p), tags=["typesafe", name], metadata=meta,
            )
        )
    refusal = noul_value(answers, "refusal")
    if refusal is not None and refusal >= summary["threshold"]:
        findings.append(
            make_finding(
                NAME_RESPONSE, "refusal", Severity.INFO, f"TypeSafe: the model refused (noul {refusal:.2f})",
                "TypeSafe judged the response to be a refusal. Informational; useful for red-team evaluation and false refusal tracking.",
                f"typesafe noul={refusal:.2f}", "response", noul_confidence(refusal), tags=["typesafe", "refusal"], metadata=meta,
            )
        )
    return findings, summary


class TypeSafeResponseAnalyzer:
    name = NAME_RESPONSE
    description = "Judges the model response with one TypeSafe (Jev) call: system prompt leak, secret or PII leak, harmful compliance, exfiltration markup and refusal."

    async def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]:
        try:
            cfg = ts.config()
            if not ts.is_configured(cfg):
                return []
            text = response_text(context)
            if not text.strip():
                return []
            state = ts.conversation_state(normalized, response_text=text)
            result = await ts.evaluate(state, q.RESPONSE_GUARD, purpose="response")
            if not result:
                return []
            findings, summary = response_findings(result, cfg)
            context["typesafe_response"] = {"verdict": summary["verdict"], "confidence": summary["confidence"]}
            return findings
        except Exception as exc:
            set_error(ts.NAME, str(exc))
            log_throttled("typesafe.response", "typesafe.analyzer_failed", analyzer=self.name, error=str(exc)[:300])
            return []


request_analyzer = TypeSafeRequestAnalyzer()
response_analyzer = TypeSafeResponseAnalyzer()
