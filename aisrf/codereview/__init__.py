"""AISRF source code review: static analysis of LLM-integrated applications.

Intake (archives, URLs, git repositories, local directories, snippets), inventory, three
combined engines (built-in rules, semgrep, bandit) plus an optional LLM-assisted pass,
persisted runs and findings, SARIF and every report format, a REST API, dashboard pages,
MCP tools and CLI commands.

Wire it into the application with::

    from .codereview.router import router as codereview_router
    app.include_router(codereview_router)
"""

from __future__ import annotations

from .config import DEFAULTS, ENGINES, PACKS, get_config
from .rules import ALL_RULES, RULES_BY_ID, catalogue

__all__ = ["ALL_RULES", "DEFAULTS", "ENGINES", "PACKS", "RULES_BY_ID", "catalogue", "get_config"]
