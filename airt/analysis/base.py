"""Shared analysis types. Analyzers are pure, synchronous or async callables that inspect a normalized request."""
from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol, runtime_checkable


class Severity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_WEIGHT = {Severity.INFO: 0, Severity.LOW: 10, Severity.MEDIUM: 30, Severity.HIGH: 60, Severity.CRITICAL: 90}


@dataclass
class Finding:
    analyzer: str
    category: str            # prompt_injection | jailbreak | pii | secrets | tool_abuse | data_exfil | harmful_content | policy | anomaly ...
    severity: Severity
    title: str
    description: str = ""
    evidence: str = ""        # short snippet that triggered the finding
    location: str = ""        # e.g. "messages[3].content" or "system"
    confidence: float = 0.7   # 0..1
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        from ..taxonomy import enrich

        d = asdict(self)
        d["severity"] = self.severity.value
        d["evidence"] = (self.evidence or "")[:400]
        return enrich(d)


@dataclass
class AnalysisResult:
    score: int
    level: str
    findings: list[Finding]
    duration_ms: float
    analyzers_run: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "level": self.level,
            "findings": [f.to_dict() for f in self.findings],
            "duration_ms": self.duration_ms,
            "analyzers_run": self.analyzers_run,
        }


@runtime_checkable
class Analyzer(Protocol):
    name: str

    def analyze(self, normalized: dict[str, Any], context: dict[str, Any]) -> list[Finding]: ...


def level_for_score(score: int) -> str:
    if score <= 0:
        return "NONE"
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 80:
        return "HIGH"
    return "CRITICAL"


def score_findings(findings: list[Finding]) -> int:
    """Highest weighted finding dominates; additional findings add diminishing increments. Capped at 100."""
    if not findings:
        return 0
    weighted = sorted((SEVERITY_WEIGHT[f.severity] * max(0.2, min(1.0, f.confidence)) for f in findings), reverse=True)
    score = weighted[0]
    for i, w in enumerate(weighted[1:], start=1):
        score += w / (2 ** i)
    return int(min(100, round(score)))
