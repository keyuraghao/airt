"""Rule catalogue: six packs of original AISRF rules plus the semgrep rule files shipped next to them."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import agent_tool_abuse, general, llm_output, model_supply_chain, prompt_injection, rag_poisoning_exfil
from .base import FileContext, Match, PackInfo, Rule

SEMGREP_DIR = Path(__file__).parent / "semgrep"
PACK_CODES: dict[str, str] = {
    "prompt_injection": "PI",
    "agent_tool_abuse": "AT",
    "llm_output": "LO",
    "model_supply_chain": "MS",
    "rag_poisoning_exfil": "RG",
    "general": "GN",
}
PACKS: dict[str, PackInfo] = {
    "prompt_injection": PackInfo("prompt_injection", "Prompt injection", "How untrusted text reaches the model: prompt assembly, system role hygiene, request pass-through, indirect channels and history replay.", prompt_injection.RULES),
    "agent_tool_abuse": PackInfo("agent_tool_abuse", "Agent and tool abuse", "What the model is allowed to do: shell, code, file, network and SQL sinks in tools, confirmation gates, loop limits, dispatch safety and MCP exposure.", agent_tool_abuse.RULES),
    "llm_output": PackInfo("llm_output", "LLM output handling", "Model output as untrusted input: HTML and DOM sinks, markdown rendering, code and SQL execution, paths and URLs, schema validation and chained prompts.", llm_output.RULES),
    "model_supply_chain": PackInfo("model_supply_chain", "Model security and supply chain", "Model files are code: pickle loaders, remote code, unpinned revisions and dependencies, transport and integrity, serving exposure, build hygiene and provenance.", model_supply_chain.RULES),
    "rag_poisoning_exfil": PackInfo("rag_poisoning_exfil", "RAG poisoning and data exfiltration", "Every retrieved chunk is untrusted: ingestion sanitisation, tenant scoping, filters, vector store auth, prompt delimiters, markdown exfiltration, logging, caching and memory isolation.", rag_poisoning_exfil.RULES),
    "general": PackInfo("general", "General AI application hygiene", "Credentials, debug exposure, CORS, rate limits, token and time limits, streaming, runtime key handling, tracing and transport security.", general.RULES),
}
ALL_RULES: list[Rule] = [r for p in PACKS.values() for r in p.rules]
RULES_BY_ID: dict[str, Rule] = {r.id: r for r in ALL_RULES}
INVENTORY_MATCHERS: dict[str, Any] = {**model_supply_chain.INVENTORY_MATCHERS}
assert len(RULES_BY_ID) == len(ALL_RULES), "duplicate rule ids"


def rules_for(packs: list[str] | None = None) -> list[Rule]:
    wanted = set(packs or PACKS)
    return [r for r in ALL_RULES if r.pack in wanted]


def semgrep_configs(packs: list[str] | None = None) -> list[Path]:
    wanted = set(packs or PACKS)
    return sorted(p for p in SEMGREP_DIR.glob("*.yaml") if p.stem in wanted)


def catalogue() -> dict[str, Any]:
    packs = []
    for name, info in PACKS.items():
        packs.append(
            {
                "name": name,
                "code": PACK_CODES[name],
                "title": info.title,
                "description": info.description,
                "rule_count": len(info.rules),
                "semgrep_file": (SEMGREP_DIR / f"{name}.yaml").name if (SEMGREP_DIR / f"{name}.yaml").exists() else None,
                "rules": [r.to_dict() for r in info.rules],
            }
        )
    return {"packs": packs, "total": len(ALL_RULES), "engines": ["rules", "semgrep", "bandit", "llm"]}


__all__ = ["ALL_RULES", "INVENTORY_MATCHERS", "PACKS", "PACK_CODES", "RULES_BY_ID", "SEMGREP_DIR", "FileContext", "Match", "Rule", "catalogue", "rules_for", "semgrep_configs"]
