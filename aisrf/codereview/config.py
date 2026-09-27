"""Code review module configuration.

Defaults live here; the ``codereview`` settings namespace (editable at runtime through the
settings API) is merged on top, so operators can tune limits, exclusions, engines and the
optional LLM-assisted pass without touching code.
"""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from ..config import get_settings
from ..settings_store import get_namespace

NAMESPACE = "codereview"
PACKS: list[str] = [
    "prompt_injection",
    "agent_tool_abuse",
    "llm_output",
    "model_supply_chain",
    "rag_poisoning_exfil",
    "general",
]
ENGINES: list[str] = ["rules", "semgrep", "bandit", "typesafe", "llm"]
DEFAULTS: dict[str, Any] = {
    "max_archive_bytes": 200 * 1024 * 1024,
    "max_files": 20000,
    "max_file_bytes": 2 * 1024 * 1024,
    "exclude_dirs": [
        "node_modules",
        ".venv",
        "venv",
        ".git",
        ".hg",
        ".svn",
        "dist",
        "build",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "site-packages",
        "vendor",
        ".next",
        "coverage",
        ".idea",
        ".vscode",
    ],
    "path_allowlist": [],  # extra local directories a local-path run may read (admin only)
    "retention_days": 7,
    "git_timeout_seconds": 300,
    "download_timeout_seconds": 120,
    "semgrep_timeout_seconds": 180,
    "bandit_timeout_seconds": 120,
    "default_engines": [
        "rules",
        "semgrep",
        "bandit",
        "typesafe",
    ],  # typesafe is a no-op until integrations.typesafe is enabled
    "semgrep_binary": "",  # empty = auto-detect (project venv first, then PATH)
    "bandit_binary": "",
    "llm_review": {
        "enabled": False,
        "max_files": 12,
        "max_chars_per_file": 6000,
        "confidence": 0.45,
        "timeout_seconds": 60,
    },
    "credentials": [],  # [{id, label, provider, token_encrypted, created_by, created_at}]
}


def get_config() -> dict[str, Any]:
    """Effective configuration: module defaults overlaid with the runtime namespace."""
    cfg = copy.deepcopy(DEFAULTS)
    overrides = get_namespace(NAMESPACE) or {}
    for key, value in overrides.items():
        if key == "llm_review" and isinstance(value, dict):
            cfg["llm_review"].update(value)
        else:
            cfg[key] = value
    return cfg


def work_root() -> Path:
    root = get_settings().data_dir / "codereview"
    root.mkdir(parents=True, exist_ok=True)
    return root


def scanner_binary(name: str, cfg: dict[str, Any] | None = None) -> str | None:
    """Locate semgrep or bandit: explicit setting, then the project venv, then PATH."""
    import shutil
    import sys

    cfg = cfg or get_config()
    explicit = str(cfg.get(f"{name}_binary") or "").strip()
    if explicit:
        return explicit if Path(explicit).exists() else None
    candidate = Path(sys.executable).parent / name
    if candidate.exists():
        return str(candidate)
    return shutil.which(name)
