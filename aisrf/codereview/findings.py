"""Engine-neutral finding record plus fingerprinting and de-duplication helpers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .secrets import mask_secrets

SEVERITIES: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}
SEVERITY_WEIGHT: dict[str, int] = {"CRITICAL": 90, "HIGH": 60, "MEDIUM": 30, "LOW": 10, "INFO": 0}
_WS = re.compile(r"\s+")


def normalize_snippet(snippet: str) -> str:
    return _WS.sub(" ", snippet or "").strip().lower()


def fingerprint(rule_id: str, path: str, snippet: str) -> str:
    payload = f"{rule_id}\n{path}\n{normalize_snippet(snippet)}"
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


@dataclass
class Finding:
    rule_id: str
    pack: str
    engine: str
    severity: str
    confidence: float
    title: str
    description: str
    remediation: str
    file: str
    line_start: int
    line_end: int
    snippet: str
    language: str = ""
    owasp: list[str] = field(default_factory=list)
    cwe: str = ""
    category: str = ""
    fingerprint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.severity = str(self.severity or "MEDIUM").upper()
        if self.severity not in SEVERITY_RANK:
            self.severity = "MEDIUM"
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        self.snippet = mask_secrets((self.snippet or "")[:1200])
        self.line_end = max(self.line_end or 0, self.line_start or 0)
        if not self.fingerprint:
            self.fingerprint = fingerprint(self.rule_id, self.file, self.snippet)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse identical findings (same fingerprint) and near duplicates (same rule, file and line).

    When two engines agree on a location the first one wins and the confidence becomes the maximum.
    Bandit findings that sit on a line already covered by a catalogue rule with the same CWE are dropped.
    """
    by_fp: dict[str, Finding] = {}
    by_loc: dict[tuple[str, str, int], Finding] = {}
    covered_cwe: dict[tuple[str, int, str], Finding] = {}
    out: list[Finding] = []
    for f in findings:
        loc = (f.rule_id, f.file, f.line_start)
        if f.fingerprint in by_fp or loc in by_loc:
            keep = by_fp.get(f.fingerprint) or by_loc[loc]
            keep.confidence = max(keep.confidence, f.confidence)
            engines = keep.metadata.setdefault("engines", [keep.engine])
            if f.engine not in engines:
                engines.append(f.engine)
            continue
        if f.engine == "bandit" and f.cwe:
            twin = covered_cwe.get((f.file, f.line_start, f.cwe))
            if twin is not None and twin.engine != "bandit":
                twin.metadata.setdefault("engines", [twin.engine]).append("bandit")
                twin.confidence = max(twin.confidence, f.confidence)
                continue
        by_fp[f.fingerprint] = f
        by_loc[loc] = f
        if f.cwe and f.engine != "bandit":
            covered_cwe.setdefault((f.file, f.line_start, f.cwe), f)
        out.append(f)
    return out


def risk_score(findings: list[dict[str, Any]] | list[Finding]) -> int:
    """0..100: the worst finding dominates, further ones add diminishing increments."""
    weights: list[float] = []
    for f in findings:
        d = f if isinstance(f, dict) else f.to_dict()
        if str(d.get("status", "open")) != "open":
            continue
        w = SEVERITY_WEIGHT.get(str(d.get("severity", "MEDIUM")).upper(), 30)
        weights.append(w * max(0.2, min(1.0, float(d.get("confidence") or 0.5))))
    if not weights:
        return 0
    weights.sort(reverse=True)
    score = weights[0]
    for i, w in enumerate(weights[1:], start=1):
        score += w / (2**i)
        if i > 12:
            break
    return int(min(100, round(score)))
