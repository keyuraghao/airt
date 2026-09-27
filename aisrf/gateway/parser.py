"""Normalises any LLM API request body into a provider-agnostic shape for analysis and review.

Supported natively: OpenAI chat/completions/responses/embeddings, Anthropic messages,
Google Gemini generateContent, Ollama chat/generate, Cohere chat. Unknown JSON bodies
fall back to a generic walk that collects every string value.
"""

from __future__ import annotations

import json
from typing import Any

MAX_PREVIEW = 480


def _text_of(content: Any) -> str:
    """Flatten OpenAI/Anthropic style content (str or list of parts) into text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, str):
                parts.append(p)
            elif isinstance(p, dict):
                t = p.get("type", "")
                if t in ("text", "input_text", "output_text") or "text" in p:
                    parts.append(str(p.get("text", "")))
                elif t == "tool_result":
                    parts.append(_text_of(p.get("content")))
                elif t == "tool_use":
                    parts.append(f"[tool_use {p.get('name')}] {json.dumps(p.get('input', {}), default=str)}")
                elif t in ("image_url", "image", "input_image"):
                    parts.append("[image]")
                elif t in ("input_audio", "audio"):
                    parts.append("[audio]")
                elif t == "file":
                    parts.append("[file]")
        return "\n".join(x for x in parts if x)
    if isinstance(content, dict):
        return _text_of([content])
    return str(content)


def _walk_strings(obj: Any, out: list[str], depth: int = 0) -> None:
    if depth > 12:
        return
    if isinstance(obj, str):
        if obj.strip():
            out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_strings(v, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            _walk_strings(v, out, depth + 1)


def detect_endpoint(path: str, body: dict | None) -> str:
    p = path.lower()
    if "chat/completions" in p:
        return "chat"
    if "/responses" in p or p.endswith("responses"):
        return "responses"
    if "/messages" in p or p.endswith("messages"):
        return "messages"
    if "embeddings" in p or "embed" in p:
        return "embeddings"
    if "completions" in p or p.endswith("generate"):
        return "completion"
    if "generatecontent" in p:
        return "gemini"
    if body and "messages" in body:
        return "chat"
    if body and "prompt" in body:
        return "completion"
    return "other"


def normalize(path: str, body_bytes: bytes, provider_hint: str = "") -> dict[str, Any]:
    body: Any = None
    if body_bytes:
        try:
            body = json.loads(body_bytes)
        except Exception:
            body = None
    endpoint = detect_endpoint(path, body if isinstance(body, dict) else None)
    messages: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    system = ""
    model = ""
    stream = False
    extra: dict[str, Any] = {}

    if isinstance(body, dict):
        model = str(body.get("model") or "")
        stream = bool(body.get("stream", False))
        # system prompt (Anthropic top-level, Gemini systemInstruction)
        if body.get("system"):
            system = _text_of(body["system"])
        if isinstance(body.get("systemInstruction"), dict):
            system = _text_of(body["systemInstruction"].get("parts"))
        # tools
        for t in body.get("tools") or []:
            if isinstance(t, dict):
                fn = t.get("function") if isinstance(t.get("function"), dict) else t
                tools.append(
                    {"name": fn.get("name", t.get("type", "tool")), "description": fn.get("description", "")}
                )
        if body.get("tool_choice") is not None:
            extra["tool_choice"] = body["tool_choice"]
        # messages
        if isinstance(body.get("messages"), list):
            for m in body["messages"]:
                if not isinstance(m, dict):
                    continue
                role = str(m.get("role", "user"))
                text = _text_of(m.get("content"))
                if m.get("tool_calls"):
                    text += "\n" + "\n".join(
                        f"[tool_call {tc.get('function', {}).get('name')}] {tc.get('function', {}).get('arguments', '')}"
                        for tc in m["tool_calls"]
                        if isinstance(tc, dict)
                    )
                if role == "system" or role == "developer":
                    system = (system + "\n" + text).strip()
                messages.append({"role": role, "content": text, "name": m.get("name")})
        elif "input" in body and endpoint in ("responses", "embeddings", "other"):
            inp = body["input"]
            if isinstance(inp, list) and inp and isinstance(inp[0], dict) and "role" in inp[0]:
                for m in inp:
                    messages.append(
                        {"role": str(m.get("role", "user")), "content": _text_of(m.get("content"))}
                    )
            else:
                messages.append(
                    {
                        "role": "user",
                        "content": _text_of(inp) if not isinstance(inp, list) else "\n".join(map(str, inp)),
                    }
                )
            if body.get("instructions"):
                system = str(body["instructions"])
        elif "prompt" in body:
            pr = body["prompt"]
            messages.append(
                {
                    "role": "user",
                    "content": pr
                    if isinstance(pr, str)
                    else "\n".join(map(str, pr))
                    if isinstance(pr, list)
                    else str(pr),
                }
            )
        elif isinstance(body.get("contents"), list):  # Gemini
            for c in body["contents"]:
                if isinstance(c, dict):
                    messages.append({"role": str(c.get("role", "user")), "content": _text_of(c.get("parts"))})
        elif "message" in body:  # Cohere
            messages.append({"role": "user", "content": str(body["message"])})
            for h in body.get("chat_history") or []:
                if isinstance(h, dict):
                    messages.insert(
                        -1, {"role": str(h.get("role", "user")).lower(), "content": str(h.get("message", ""))}
                    )
        if not messages and not system:
            strings: list[str] = []
            _walk_strings(body, strings)
            if strings:
                messages.append({"role": "user", "content": "\n".join(strings)})
        for k in (
            "temperature",
            "max_tokens",
            "max_completion_tokens",
            "top_p",
            "n",
            "user",
            "metadata",
            "response_format",
        ):
            if k in body:
                extra[k] = body[k]
    elif body_bytes:
        messages.append({"role": "user", "content": body_bytes[:20000].decode("utf-8", "replace")})

    user_texts = [
        m["content"] for m in messages if m["role"] not in ("system", "developer") and m.get("content")
    ]
    last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
    prompt_text = "\n\n".join(x for x in [system, *user_texts] if x)
    preview = (last_user or prompt_text or "").strip().replace("\n", " ")
    return {
        "provider": provider_hint,
        "endpoint": endpoint,
        "model": model,
        "stream": stream,
        "system": system,
        "messages": messages,
        "tools": tools,
        "extra": extra,
        "prompt_text": prompt_text,
        "last_user_message": last_user,
        "preview": preview[:MAX_PREVIEW],
        "message_count": len(messages),
        "char_count": len(prompt_text),
    }


def extract_response_text(body_bytes: bytes, endpoint: str = "") -> str:
    """Pull assistant text out of a JSON (non-streamed) or SSE (streamed) response body."""
    if not body_bytes:
        return ""
    raw = body_bytes.decode("utf-8", "replace")
    if raw.lstrip().startswith("data:") or "\ndata:" in raw:
        chunks: list[str] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            payload = line[5:].strip()
            if payload in ("[DONE]", ""):
                continue
            try:
                obj = json.loads(payload)
            except Exception:
                continue
            # OpenAI chat chunk
            for ch in obj.get("choices", []) if isinstance(obj, dict) else []:
                delta = ch.get("delta") or {}
                if delta.get("content"):
                    chunks.append(delta["content"])
                if ch.get("text"):
                    chunks.append(ch["text"])
            # Anthropic stream
            if isinstance(obj, dict) and obj.get("type") == "content_block_delta":
                d = obj.get("delta") or {}
                if d.get("text"):
                    chunks.append(d["text"])
            # OpenAI responses API stream
            if isinstance(obj, dict) and obj.get("type") == "response.output_text.delta" and obj.get("delta"):
                chunks.append(str(obj["delta"]))
        return "".join(chunks)
    try:
        obj = json.loads(raw)
    except Exception:
        return raw[:20000]
    if not isinstance(obj, dict):
        return raw[:20000]
    if "choices" in obj:
        out = []
        for ch in obj["choices"]:
            msg = ch.get("message") or {}
            if msg.get("content"):
                out.append(_text_of(msg["content"]))
            for tc in msg.get("tool_calls") or []:
                out.append(
                    f"[tool_call {tc.get('function', {}).get('name')}] {tc.get('function', {}).get('arguments', '')}"
                )
            if ch.get("text"):
                out.append(ch["text"])
        return "\n".join(out)
    if "content" in obj and isinstance(obj["content"], list):  # Anthropic
        return _text_of(obj["content"])
    if "output" in obj and isinstance(obj["output"], list):  # OpenAI responses
        parts = []
        for item in obj["output"]:
            if isinstance(item, dict):
                parts.append(_text_of(item.get("content")))
        return "\n".join(p for p in parts if p)
    if "output_text" in obj:
        return str(obj["output_text"])
    if "candidates" in obj:  # Gemini
        return "\n".join(
            _text_of(c.get("content", {}).get("parts")) for c in obj["candidates"] if isinstance(c, dict)
        )
    if "message" in obj and isinstance(obj["message"], dict):  # Ollama
        return str(obj["message"].get("content", ""))
    if "response" in obj and isinstance(obj["response"], str):
        return obj["response"]
    if "text" in obj and isinstance(obj["text"], str):
        return obj["text"]
    strings: list[str] = []
    _walk_strings(obj, strings)
    return "\n".join(strings)[:20000]
