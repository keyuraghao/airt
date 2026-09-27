"""Attack corpus loader and query API.

Reads every YAML file in aisrf/redteam/corpus/, validates each probe with pydantic and exposes
cached query helpers. A corpus file has an optional top-level `category`, `description` and
`defaults` mapping (fields merged into every probe that omits them) plus a `probes` list.
"""

from __future__ import annotations

import functools
import random
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator

from ..logging import get_logger

log = get_logger("aisrf.redteam.corpus")

CORPUS_DIR = Path(__file__).parent / "corpus"
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
EXPECTED_VALUES = ("refuse", "ignore_injection", "no_leak", "no_tool_call", "safe_completion")


class Message(BaseModel):
    role: str = "user"
    content: str = ""


class Probe(BaseModel):
    id: str
    category: str
    technique: str = ""
    severity: str = "MEDIUM"
    name: str = ""
    description: str = ""
    prompt: str = ""
    messages: list[Message] = Field(default_factory=list)
    expected: str = "refuse"
    success_indicators: list[str] = Field(default_factory=list)
    canary: str | None = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("severity")
    @classmethod
    def _sev(cls, v: str) -> str:
        v = (v or "MEDIUM").upper()
        if v not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {v!r}")
        return v

    @field_validator("expected")
    @classmethod
    def _expected(cls, v: str) -> str:
        v = (v or "refuse").strip()
        if v not in EXPECTED_VALUES:
            raise ValueError(f"expected must be one of {EXPECTED_VALUES}, got {v!r}")
        return v

    @field_validator("success_indicators")
    @classmethod
    def _regexes(cls, v: list[str]) -> list[str]:
        for pattern in v:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid success_indicator regex {pattern!r}: {exc}") from exc
        return v

    @model_validator(mode="after")
    def _has_content(self) -> Probe:
        if not self.prompt and not self.messages:
            raise ValueError(f"probe {self.id} has neither prompt nor messages")
        return self

    def to_messages(self) -> list[dict[str, str]]:
        """The conversation turns for this probe, excluding any system prompt."""
        if self.messages:
            return [{"role": m.role, "content": m.content} for m in self.messages]
        return [{"role": "user", "content": self.prompt}]

    def prompt_text(self) -> str:
        if self.messages:
            return "\n".join(m.content for m in self.messages)
        return self.prompt

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "technique": self.technique,
            "severity": self.severity,
            "name": self.name,
            "description": self.description,
            "prompt": self.prompt,
            "messages": [{"role": m.role, "content": m.content} for m in self.messages],
            "expected": self.expected,
            "success_indicators": self.success_indicators,
            "canary": self.canary,
            "tags": self.tags,
        }


class Corpus:
    def __init__(self, probes: list[Probe], categories: dict[str, str]) -> None:
        self.probes = probes
        self._by_id = {p.id: p for p in probes}
        self._category_descriptions = categories

    def get(self, probe_id: str) -> Probe | None:
        return self._by_id.get(probe_id)

    def categories(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        seen: dict[str, dict[str, Any]] = {}
        for p in self.probes:
            entry = seen.get(p.category)
            if entry is None:
                entry = {
                    "name": p.category,
                    "description": self._category_descriptions.get(p.category, ""),
                    "probe_count": 0,
                    "techniques": [],
                }
                seen[p.category] = entry
                out.append(entry)
            entry["probe_count"] += 1
            if p.technique and p.technique not in entry["techniques"]:
                entry["techniques"].append(p.technique)
        return out


def _merge_defaults(raw: dict[str, Any], defaults: dict[str, Any], category: str) -> dict[str, Any]:
    merged = {**defaults, **raw}
    merged.setdefault("category", category)
    if not merged.get("category"):
        merged["category"] = category
    return merged


@functools.lru_cache(maxsize=1)
def load_corpus() -> Corpus:
    probes: list[Probe] = []
    categories: dict[str, str] = {}
    seen_ids: set[str] = set()
    for path in sorted(CORPUS_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            log.error("corpus.parse_failed", file=path.name, error=str(exc))
            continue
        category = str(data.get("category") or path.stem)
        categories[category] = str(data.get("description") or "")
        defaults = data.get("defaults") or {}
        for raw in data.get("probes") or []:
            if not isinstance(raw, dict):
                continue
            try:
                probe = Probe(**_merge_defaults(raw, defaults, category))
            except Exception as exc:
                log.error("corpus.invalid_probe", file=path.name, probe=raw.get("id"), error=str(exc))
                continue
            if probe.id in seen_ids:
                log.error("corpus.duplicate_id", file=path.name, probe=probe.id)
                continue
            seen_ids.add(probe.id)
            probes.append(probe)
    log.info("corpus.loaded", probes=len(probes), categories=len(categories))
    return Corpus(probes, categories)


def reload_corpus() -> Corpus:
    load_corpus.cache_clear()
    return load_corpus()


def list_categories() -> list[dict[str, Any]]:
    return load_corpus().categories()


def get_probe(probe_id: str) -> Probe | None:
    return load_corpus().get(probe_id)


def _as_set(value: str | list[str] | None) -> set[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return {value}
    return set(value)


def get_probes(
    categories: str | list[str] | None = None,
    techniques: str | list[str] | None = None,
    severities: str | list[str] | None = None,
    tags: str | list[str] | None = None,
    search: str | None = None,
    limit: int | None = None,
    sample_seed: int | None = None,
) -> list[Probe]:
    corpus = load_corpus()
    cats = _as_set(categories)
    techs = _as_set(techniques)
    sevs = {s.upper() for s in _as_set(severities)} if severities is not None else None
    wanted_tags = _as_set(tags)
    needle = search.lower() if search else None

    selected: list[Probe] = []
    for p in corpus.probes:
        if cats is not None and p.category not in cats:
            continue
        if techs is not None and p.technique not in techs:
            continue
        if sevs is not None and p.severity not in sevs:
            continue
        if wanted_tags is not None and not wanted_tags.intersection(p.tags):
            continue
        if (
            needle is not None
            and needle not in (p.id + " " + p.name + " " + p.description + " " + p.prompt_text()).lower()
        ):
            continue
        selected.append(p)

    if limit is not None and limit >= 0 and len(selected) > limit:
        if sample_seed is not None:
            rng = random.Random(sample_seed)
            selected = rng.sample(selected, limit)
            selected.sort(key=lambda p: p.id)
        else:
            selected = selected[:limit]
    return selected
