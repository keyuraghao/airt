"""TypeSafe (System One model Jev) decision layer for AISRF.

Importing this package registers the ``typesafe_guard`` request analyzer and the
``typesafe_response_guard`` response analyzer with the analysis runner (the runner imports it from
``_load_builtin`` exactly like the guardrails package). Everything reads the live
``integrations.typesafe`` settings document at call time and is a no-op until ``enabled`` is true and
an API key is present in settings or in ``TYPESAFE_API_KEY``.

    client.evaluate(state, questions)   one call, every question in parallel, cached, never raises
    questions.*                         the four question sets (request, response, red team, code triage)
    status() / health_check()           for the settings API
"""

from __future__ import annotations

from ..analysis.runner import register
from . import analyzers, client, questions
from .client import evaluate, evaluate_sync, health_check, savings, status

register(analyzers.request_analyzer)
register(analyzers.response_analyzer, response=True)

ANALYZER_NAMES: list[str] = [analyzers.NAME_REQUEST, analyzers.NAME_RESPONSE]

__all__ = ["ANALYZER_NAMES", "analyzers", "client", "evaluate", "evaluate_sync", "health_check", "questions", "savings", "status"]
