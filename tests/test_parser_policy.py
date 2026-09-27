"""Unit tests for request normalization, response extraction, policy and security helpers."""
from __future__ import annotations

import json

from airt.gateway.parser import extract_response_text, normalize
from airt.gateway.policy import evaluate
from airt.models import Agent
from airt.security import decrypt_secret, encrypt_secret, hash_password, redact_headers, verify_password


def test_normalize_openai_chat_with_parts_and_tools():
    body = {
        "model": "gpt-4o",
        "stream": True,
        "tools": [{"type": "function", "function": {"name": "run_shell", "description": "run a command"}}],
        "messages": [
            {"role": "system", "content": "Be helpful"},
            {"role": "user", "content": [{"type": "text", "text": "hello"}, {"type": "image_url", "image_url": {"url": "x"}}]},
            {"role": "assistant", "content": None, "tool_calls": [{"function": {"name": "run_shell", "arguments": "{\"cmd\": \"ls\"}"}}]},
        ],
    }
    n = normalize("v1/chat/completions", json.dumps(body).encode(), "openai")
    assert n["endpoint"] == "chat" and n["model"] == "gpt-4o" and n["stream"] is True
    assert n["system"] == "Be helpful"
    assert n["messages"][1]["content"] == "hello\n[image]"
    assert "[tool_call run_shell]" in n["messages"][2]["content"]
    assert n["tools"][0]["name"] == "run_shell"
    assert n["last_user_message"] == "hello\n[image]"


def test_normalize_responses_completion_gemini_and_unknown():
    r = normalize("v1/responses", json.dumps({"model": "o3", "instructions": "sys", "input": "do it"}).encode())
    assert r["endpoint"] == "responses" and r["system"] == "sys" and r["messages"][0]["content"] == "do it"
    c = normalize("v1/completions", json.dumps({"model": "davinci", "prompt": "once upon"}).encode())
    assert c["endpoint"] == "completion" and c["messages"][0]["content"] == "once upon"
    g = normalize("v1beta/models/gemini:generateContent", json.dumps({"contents": [{"role": "user", "parts": [{"text": "hey"}]}]}).encode())
    assert g["messages"][0]["content"] == "hey"
    u = normalize("custom/endpoint", json.dumps({"foo": {"bar": "deep string"}}).encode())
    assert "deep string" in u["prompt_text"]
    assert normalize("x", b"not json")["messages"][0]["content"] == "not json"
    assert normalize("x", b"")["messages"] == []


def test_extract_response_text_variants():
    openai = json.dumps({"choices": [{"message": {"role": "assistant", "content": "hi there"}}]}).encode()
    assert extract_response_text(openai) == "hi there"
    anthropic = json.dumps({"content": [{"type": "text", "text": "yo"}]}).encode()
    assert extract_response_text(anthropic) == "yo"
    sse = b"data: " + json.dumps({"choices": [{"delta": {"content": "a"}}]}).encode() + b"\n\ndata: " + json.dumps({"choices": [{"delta": {"content": "b"}}]}).encode() + b"\n\ndata: [DONE]\n\n"
    assert extract_response_text(sse) == "ab"
    anth_sse = b"data: " + json.dumps({"type": "content_block_delta", "delta": {"text": "z"}}).encode() + b"\n\n"
    assert extract_response_text(anth_sse) == "z"


def _agent(**kw) -> Agent:
    base = dict(name="a", api_key_hash="h", api_key_prefix="p", is_active=True, require_approval=True, auto_approve_below_risk=0, auto_deny_at_risk=90, auto_deny_patterns=[], allowed_paths=[], allowed_models=[])
    base.update(kw)
    return Agent(**base)


def test_policy_matrix():
    n = {"model": "gpt-4o", "prompt_text": "hello world"}
    assert evaluate(_agent(), n, "v1/chat/completions", 10, []).action == "review"
    assert evaluate(_agent(require_approval=False), n, "v1/chat/completions", 10, []).action == "approve"
    assert evaluate(_agent(require_approval=False), n, "v1/chat/completions", 95, []).action == "deny"
    assert evaluate(_agent(auto_approve_below_risk=20), n, "v1/chat/completions", 10, []).action == "approve"
    assert evaluate(_agent(auto_approve_below_risk=20), n, "v1/chat/completions", 30, []).action == "review"
    assert evaluate(_agent(is_active=False), n, "v1/x", 0, []).action == "deny"
    assert evaluate(_agent(auto_deny_patterns=["hello\\s+world"]), n, "v1/x", 0, []).action == "deny"
    assert evaluate(_agent(allowed_models=["claude*"]), n, "v1/x", 0, []).action == "deny"
    assert evaluate(_agent(allowed_paths=["v1/chat/*"]), n, "v1/chat/completions", 0, []).action == "review"
    crit = [{"severity": "CRITICAL", "category": "secrets"}]
    assert evaluate(_agent(require_approval=False), n, "v1/x", 50, crit).action == "review"


def test_security_helpers():
    h = hash_password("s3cret")
    assert verify_password("s3cret", h) and not verify_password("nope", h)
    assert decrypt_secret(encrypt_secret("upstream-key")) == "upstream-key"
    assert encrypt_secret("") is None and decrypt_secret("garbage") is None
    red = redact_headers({"Authorization": "Bearer abcdefghijklmnop", "Content-Type": "json"})
    assert red["Authorization"].endswith("[redacted]") and "klmnop" not in red["Authorization"]
    assert red["Content-Type"] == "json"
