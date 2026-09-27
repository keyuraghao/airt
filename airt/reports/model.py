"""Format-agnostic report document.

A Report is a titled list of Sections. Builders (airt/reports/builders.py) produce
Reports from the database; renderers (airt/reports/renderers.py) turn a Report into
bytes in any supported format. Nothing here knows about formats or the database.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4, "NONE": 5}


def _fmt(value: Any) -> Any:
    """Make a cell value JSON friendly without losing information."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, tuple):
        return list(value)
    return value


@dataclass
class Section:
    """Base class for all section kinds. `kind` is a stable discriminator used by renderers."""

    title: str
    kind: str = field(default="base", init=False)

    def to_dict(self) -> dict[str, Any]:
        return {"title": self.title, "kind": self.kind}

    def as_table(self) -> tuple[list[str], list[list[Any]]]:
        """Every section can be flattened into (columns, rows) for tabular formats."""
        return [], []


@dataclass
class KeyValueSection(Section):
    rows: list[tuple[str, Any]] = field(default_factory=list)
    kind: str = field(default="keyvalue", init=False)

    def to_dict(self) -> dict[str, Any]:
        return {**super().to_dict(), "rows": [[k, _fmt(v)] for k, v in self.rows]}

    def as_table(self) -> tuple[list[str], list[list[Any]]]:
        return ["Key", "Value"], [[k, _fmt(v)] for k, v in self.rows]


@dataclass
class TableSection(Section):
    columns: list[str] = field(default_factory=list)
    rows: list[list[Any]] = field(default_factory=list)
    notes: str = ""
    # "cases" marks the table whose rows become JUnit testcases (one per probe result or ticket)
    role: str = ""
    kind: str = field(default="table", init=False)

    def to_dict(self) -> dict[str, Any]:
        d = {**super().to_dict(), "columns": list(self.columns), "rows": [[_fmt(c) for c in r] for r in self.rows]}
        if self.notes:
            d["notes"] = self.notes
        if self.role:
            d["role"] = self.role
        return d

    def as_table(self) -> tuple[list[str], list[list[Any]]]:
        return list(self.columns), [[_fmt(c) for c in r] for r in self.rows]


@dataclass
class TextSection(Section):
    text: str = ""
    markdown: bool = True
    kind: str = field(default="text", init=False)

    def to_dict(self) -> dict[str, Any]:
        return {**super().to_dict(), "text": self.text, "markdown": self.markdown}

    def as_table(self) -> tuple[list[str], list[list[Any]]]:
        return ["Text"], [[line] for line in self.text.splitlines() if line.strip()]


FINDING_COLUMNS: list[str] = ["severity", "category", "title", "description", "evidence", "location", "ticket_id", "probe_id", "verdict", "confidence"]


@dataclass
class FindingsSection(Section):
    """A list of finding dicts. Each dict should carry at least category, severity and title.

    Optional keys used by the SARIF and JUnit renderers: description, message, evidence,
    location, ticket_id, probe_id, verdict, confidence, technique, analyzer.
    """

    findings: list[dict[str, Any]] = field(default_factory=list)
    kind: str = field(default="findings", init=False)

    def to_dict(self) -> dict[str, Any]:
        return {**super().to_dict(), "findings": [dict(f) for f in self.findings]}

    def as_table(self) -> tuple[list[str], list[list[Any]]]:
        used = [c for c in FINDING_COLUMNS if any(f.get(c) not in (None, "") for f in self.findings)]
        if not used:
            used = ["severity", "category", "title"]
        return used, [[_fmt(f.get(c, "")) for c in used] for f in self.findings]

    def sorted(self) -> list[dict[str, Any]]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(str(f.get("severity", "")).upper(), 9))


@dataclass
class ChartSection(Section):
    """A bar or pie chart. Text formats render it as a label/value table."""

    chart: str = "bar"
    labels: list[str] = field(default_factory=list)
    values: list[float] = field(default_factory=list)
    kind: str = field(default="chart", init=False)

    def __post_init__(self) -> None:
        if self.chart not in ("bar", "pie"):
            raise ValueError(f"unsupported chart kind: {self.chart}")

    def to_dict(self) -> dict[str, Any]:
        return {**super().to_dict(), "chart": self.chart, "labels": list(self.labels), "values": [float(v) for v in self.values]}

    def as_table(self) -> tuple[list[str], list[list[Any]]]:
        return ["Label", "Value"], [[label, value] for label, value in zip(self.labels, self.values, strict=False)]

    @property
    def total(self) -> float:
        return float(sum(self.values)) if self.values else 0.0


@dataclass
class Report:
    title: str
    subtitle: str = ""
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    generated_by: str = "airt"
    sections: list[Section] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add(self, section: Section) -> Section:
        self.sections.append(section)
        return section

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "subtitle": self.subtitle,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "meta": dict(self.meta),
            "sections": [s.to_dict() for s in self.sections],
        }

    def findings(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for s in self.sections:
            if isinstance(s, FindingsSection):
                out.extend(s.findings)
        return out

    def tables(self) -> list[TableSection]:
        return [s for s in self.sections if isinstance(s, TableSection)]


def section_from_dict(d: dict[str, Any]) -> Section:
    """Inverse of Section.to_dict(), useful for round-tripping JSON reports."""
    kind = d.get("kind", "text")
    title = d.get("title", "")
    if kind == "keyvalue":
        return KeyValueSection(title, rows=[(str(k), v) for k, v in d.get("rows", [])])
    if kind == "table":
        return TableSection(title, columns=list(d.get("columns", [])), rows=[list(r) for r in d.get("rows", [])], notes=d.get("notes", ""), role=d.get("role", ""))
    if kind == "findings":
        return FindingsSection(title, findings=[dict(f) for f in d.get("findings", [])])
    if kind == "chart":
        return ChartSection(title, chart=d.get("chart", "bar"), labels=list(d.get("labels", [])), values=[float(v) for v in d.get("values", [])])
    return TextSection(title, text=str(d.get("text", "")), markdown=bool(d.get("markdown", True)))


def report_from_dict(d: dict[str, Any]) -> Report:
    generated = d.get("generated_at")
    ts = datetime.fromisoformat(generated) if isinstance(generated, str) else datetime.now(UTC)
    return Report(
        title=d.get("title", "Report"),
        subtitle=d.get("subtitle", ""),
        generated_at=ts,
        generated_by=d.get("generated_by", "airt"),
        sections=[section_from_dict(s) for s in d.get("sections", [])],
        meta=dict(d.get("meta", {})),
    )
