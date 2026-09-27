"""PyRIT-Ship compatibility: a server surface AISRF exposes and a client for an external instance.

The server surface reproduces the PyRIT-Ship REST schemas so the PyRIT-Ship Burp Suite extension
(and any PyRIT-Ship client) can point at AISRF instead of a standalone PyRIT-Ship server:
  GET  /api/pyrit-ship/prompt/convert                        -> ["Base64Converter", ...]
  POST /api/pyrit-ship/prompt/convert/<converter_name>       {"text": "..[CONVERT]x[/CONVERT].."} -> {"converted_text": ".."}
  POST /api/pyrit-ship/prompt/generate                       {"prompt_goal": ".."} -> {"prompt": ".."}
  POST /api/pyrit-ship/prompt/score/SelfAskTrueFalseScorer   {scoring_true, scoring_false, prompt_response} -> [{scoring_text, scoring_metadata, scoring_rationale}]

Converters run through PyRIT. When a scan token authenticates the caller (Authorization: Bearer
<scan token>) or a campaign id is supplied, every converted prompt is also submitted through the
gateway pipeline as a ticket, so Burp-driven traffic is intercepted and human-approved too.

The client adapter (ShipClient) calls an external PyRIT-Ship server configured in
settings integrations.pyrit_ship (url, converter, scorer, ...).
"""

from __future__ import annotations

from typing import Any

import httpx

from ..logging import get_logger
from . import base
from . import pyrit as pyrit_engine

log = get_logger("aisrf.scanners.pyrit_ship")

CONVERT_TAG_OPEN = "[CONVERT]"
CONVERT_TAG_CLOSE = "[/CONVERT]"


def list_converters() -> list[str]:
    """PyRIT converters instantiable without arguments (the shape PyRIT-Ship's /prompt/convert returns)."""
    return sorted(pyrit_engine.converter_catalogue())


async def convert_text(converter_name: str, text: str) -> str:
    """Convert text between [CONVERT]..[/CONVERT] tags with a PyRIT converter (whole string if untagged)."""
    if not pyrit_engine.pyrit_available():
        raise RuntimeError("pyrit is not installed")
    await pyrit_engine.ensure_memory()
    converters = pyrit_engine.instantiate_converters([converter_name])
    if CONVERT_TAG_OPEN in text and CONVERT_TAG_CLOSE in text:
        out = text
        while CONVERT_TAG_OPEN in out and CONVERT_TAG_CLOSE in out:
            start = out.index(CONVERT_TAG_OPEN)
            end = out.index(CONVERT_TAG_CLOSE, start)
            inner = out[start + len(CONVERT_TAG_OPEN) : end]
            converted = await pyrit_engine.apply_converters(inner, converters)
            out = out[:start] + converted + out[end + len(CONVERT_TAG_CLOSE) :]
        return out
    return await pyrit_engine.apply_converters(text, converters)


async def score_true_false(
    true_description: str, false_description: str, prompt_response: str
) -> list[dict[str, Any]]:
    """SelfAskTrueFalseScorer-compatible scoring via the configured LLM judge, with a heuristic fallback."""
    judge = pyrit_engine.judge_target() if pyrit_engine.pyrit_available() else None
    if judge is not None:
        await pyrit_engine.ensure_memory()
        try:
            from pyrit.score import SelfAskTrueFalseScorer, TrueFalseQuestion

            scorer = SelfAskTrueFalseScorer(
                chat_target=judge,
                true_false_question=TrueFalseQuestion(
                    category="pyritship",
                    true_description=true_description,
                    false_description=false_description,
                ),
            )
            score = (await scorer.score_text_async(text=prompt_response))[0]
            return [
                {
                    "scoring_text": str(score.get_value()),
                    "scoring_metadata": score.score_metadata or "",
                    "scoring_rationale": score.score_rationale or "",
                }
            ]
        except Exception as exc:
            log.warning("pyrit_ship.score.judge_failed", error=str(exc))
    value, rationale = _heuristic_true_false(true_description, prompt_response)
    return [{"scoring_text": str(value), "scoring_metadata": "", "scoring_rationale": rationale}]


def _heuristic_true_false(true_description: str, prompt_response: str) -> tuple[bool, str]:
    """Fallback when no LLM judge is configured: keyword overlap between the criterion and the text."""
    text = (prompt_response or "").lower()
    words = [w for w in true_description.lower().replace(".", " ").split() if len(w) > 3]
    hits = [w for w in words if w in text]
    matched = len(hits) >= max(1, len(words) // 3)
    return matched, (
        "matched terms: " + ", ".join(hits)
    ) if matched else "no LLM judge configured; keyword heuristic found no match"


async def generate_prompt(
    prompt_goal: str,
    http: httpx.AsyncClient | None = None,
    agent_id: str | None = None,
    *,
    campaign_id: str | None = None,
) -> str:
    """PyRIT-Ship /prompt/generate is a single PromptSendingAttack turn.

    When an agent is supplied the attack target is the in-process gateway (AISRFGatewayTarget), so
    the generated prompt is produced by the target model behind a ticket; otherwise the prompt_goal
    is echoed back (no red-team generation model is bundled).
    """
    if agent_id and http is not None and pyrit_engine.pyrit_available():
        await pyrit_engine.ensure_memory()
        from pyrit.executor.attack import PromptSendingAttack

        cls = pyrit_engine.classes()
        target = cls["AISRFGatewayTarget"](
            http, agent_id, model="", campaign_id=campaign_id, probe_id="pyrit_ship.generate"
        )
        attack = PromptSendingAttack(objective_target=target)
        result = await attack.execute_async(objective=prompt_goal)
        if result.last_response is not None:
            return str(result.last_response.converted_value or prompt_goal)
    return prompt_goal


async def submit_converted_prompt(
    http: httpx.AsyncClient, agent_id: str, converted_text: str, *, campaign_id: str | None = None
) -> str | None:
    """Push a converted prompt through the gateway pipeline as a ticket. Returns the ticket id."""
    from ..gateway.pipeline import submit

    body = {
        "model": "gateway-model",
        "messages": [{"role": "user", "content": converted_text}],
        "stream": False,
    }
    result = await submit(
        http,
        agent_id,
        path="v1/chat/completions",
        body=body,
        source=base.SOURCE,
        campaign_id=campaign_id,
        probe_id="pyrit_ship.convert",
    )
    return result.ticket_id


# --- client adapter for an external PyRIT-Ship server -------------------------------
class ShipClient:
    """Calls an external PyRIT-Ship server configured in settings integrations.pyrit_ship."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = config if config is not None else base.engine_settings("pyrit_ship")
        self.url = str(cfg.get("url") or "http://127.0.0.1:5001").rstrip("/")
        self.converter = str(cfg.get("converter") or "ROT13Converter")
        self.scorer = str(cfg.get("scorer") or "SelfAskTrueFalseScorer")
        self.timeout = float(cfg.get("timeout_seconds") or 60.0)

    def configured(self) -> bool:
        return bool(base.engine_settings("pyrit_ship").get("url"))

    async def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(base_url=self.url, timeout=self.timeout)

    async def list_converters(self) -> list[str]:
        async with await self._client() as client:
            resp = await client.get("/prompt/convert")
            resp.raise_for_status()
            return list(resp.json())

    async def convert(self, text: str, converter: str | None = None) -> str:
        async with await self._client() as client:
            resp = await client.post(f"/prompt/convert/{converter or self.converter}", json={"text": text})
            resp.raise_for_status()
            return str(resp.json().get("converted_text", ""))

    async def generate(self, prompt_goal: str) -> str:
        async with await self._client() as client:
            resp = await client.post("/prompt/generate", json={"prompt_goal": prompt_goal})
            resp.raise_for_status()
            return str(resp.json().get("prompt", ""))

    async def score(
        self, scoring_true: str, scoring_false: str, prompt_response: str
    ) -> list[dict[str, Any]]:
        async with await self._client() as client:
            resp = await client.post(
                f"/prompt/score/{self.scorer}",
                json={
                    "scoring_true": scoring_true,
                    "scoring_false": scoring_false,
                    "prompt_response": prompt_response,
                },
            )
            resp.raise_for_status()
            return list(resp.json())

    async def health(self) -> dict[str, Any]:
        try:
            converters = await self.list_converters()
            return {"reachable": True, "url": self.url, "converters": converters}
        except Exception as exc:
            return {"reachable": False, "url": self.url, "error": str(exc)}


class PyritShipEngine:
    """Registry entry describing the PyRIT-Ship surface (server routes + external client).

    PyRIT-Ship is a stateless converter/scorer/attack proxy, not a batch scanner, so it has no
    campaign run of its own; capabilities() advertises the compatible routes and the client status.
    """

    name = "pyrit_ship"
    description = (
        "PyRIT-Ship compatible converter/scorer surface plus a client for an external PyRIT-Ship server."
    )

    def installed(self) -> bool:
        return pyrit_engine.pyrit_available()

    def capabilities(self) -> dict[str, Any]:
        cfg = base.engine_settings(self.name)
        client = ShipClient(cfg)
        return {
            "version": pyrit_engine.pyrit_version(),
            "server_routes": [
                "GET /api/pyrit-ship/prompt/convert",
                "POST /api/pyrit-ship/prompt/convert/{converter}",
                "POST /api/pyrit-ship/prompt/generate",
                "POST /api/pyrit-ship/prompt/score/SelfAskTrueFalseScorer",
            ],
            "burp_extension": {
                "pyrit_ship_url": "point the extension's 'PyRIT Ship URL' at <gateway>/api/pyrit-ship",
                "converter": cfg.get("converter") or "ROT13Converter",
                "scorer": cfg.get("scorer") or "SelfAskTrueFalseScorer",
            },
            "converters": list_converters() if pyrit_engine.pyrit_available() else [],
            "external_client": {"configured": client.configured(), "url": client.url},
            "gateway_submission": "converted prompts are submitted as tickets when a scan token authenticates the caller or X-AISRF-Campaign-Id is supplied",
        }

    def list_probes(self) -> list[dict[str, Any]]:
        return [
            {
                "id": f"converter:{c}",
                "category": "obfuscation",
                "technique": "pyrit_converter",
                "severity": "MEDIUM",
                "description": f"PyRIT {c} exposed through the PyRIT-Ship surface",
            }
            for c in (list_converters() if pyrit_engine.pyrit_available() else [])
        ]

    def plan(self, options: dict[str, Any]) -> list[str]:
        return []

    async def run(self, campaign_id: str, http: httpx.AsyncClient) -> None:
        raise RuntimeError(
            "pyrit_ship is a converter/scorer surface, not a batch scan engine; it has no campaign run"
        )


engine = PyritShipEngine()
