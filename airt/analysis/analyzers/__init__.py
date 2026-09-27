"""Built-in analyzers. Importing this package registers every analyzer with the runner.

Request analyzers inspect the normalized request; response analyzers (registered with response=True)
inspect the model response. The optional LLM-as-judge is registered only when Settings.enable_llm_judge
is true.
"""
from __future__ import annotations

from ..runner import register
from . import (
    anomaly,
    data_exfil,
    harmful_content,
    jailbreak,
    obfuscation,
    pii,
    prompt_injection,
    response_analyzers,
    secrets,
    tool_abuse,
)

# --- request analyzers ------------------------------------------------------
_REQUEST_ANALYZERS = [
    prompt_injection.analyzer,
    jailbreak.analyzer,
    pii.analyzer,
    secrets.analyzer,
    data_exfil.analyzer,
    tool_abuse.analyzer,
    harmful_content.analyzer,
    obfuscation.analyzer,
    anomaly.analyzer,
]
for _a in _REQUEST_ANALYZERS:
    register(_a)

# --- response analyzers -----------------------------------------------------
for _a in response_analyzers.RESPONSE_ANALYZERS:
    register(_a, response=True)

# --- optional LLM-as-judge (request + response) -----------------------------
try:
    from ...config import get_settings

    if get_settings().enable_llm_judge:
        from . import llm_judge

        register(llm_judge.request_analyzer)
        register(llm_judge.response_analyzer, response=True)
except Exception:  # judge is strictly optional and must never block registration
    pass

__all__ = ["prompt_injection", "jailbreak", "pii", "secrets", "data_exfil", "tool_abuse", "harmful_content", "obfuscation", "anomaly", "response_analyzers"]
