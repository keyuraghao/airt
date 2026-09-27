"""Anthropic SDK through the AIRT gateway.

The agent must be created with upstream_provider=anthropic (the gateway then sends x-api-key and
anthropic-version upstream). The Anthropic SDK builds URLs as <base_url>/v1/messages, so the
base_url is the bare gateway origin, not <gateway>/v1.

    pip install anthropic
    airt agent create claude-app --provider anthropic --base-url https://api.anthropic.com --upstream-key sk-ant-...
    export AIRT_GATEWAY_URL=http://localhost:8080 AIRT_AGENT_KEY=airt_...
    python examples/anthropic_client.py
"""

from __future__ import annotations

import os
import sys

from anthropic import Anthropic, APIStatusError

GATEWAY = os.environ.get("AIRT_GATEWAY_URL", "http://localhost:8080").rstrip("/")
AGENT_KEY = os.environ.get("AIRT_AGENT_KEY") or sys.exit("set AIRT_AGENT_KEY")

client = Anthropic(
    base_url=GATEWAY,
    api_key=AGENT_KEY,
    default_headers={"X-AIRT-Source": "sdk"},
    timeout=330.0,
    max_retries=0,
)

print("submitting; approve the ticket at", f"{GATEWAY}/tickets")
try:
    raw = client.messages.with_raw_response.create(
        model=os.environ.get("MODEL", "claude-3-5-haiku-latest"),
        max_tokens=200,
        system="You are a concise security assistant.",
        messages=[{"role": "user", "content": "Explain prompt injection in two sentences."}],
    )
    print("ticket:", raw.headers.get("X-AIRT-Ticket"))
    msg = raw.parse()
    print("answer:", "".join(block.text for block in msg.content if getattr(block, "type", "") == "text"))
except APIStatusError as exc:
    err = exc.body.get("error", {}) if isinstance(exc.body, dict) else {}
    print(
        f"gateway refused ({exc.status_code}) ticket={err.get('ticket_id')} code={err.get('code')}: {err.get('message')}"
    )

# Streaming works too: the gateway relays the SSE stream after approval and stores the first
# AIRT_MAX_STORED_RESPONSE_BYTES for review.
if os.environ.get("STREAM"):
    with client.messages.stream(
        model=os.environ.get("MODEL", "claude-3-5-haiku-latest"),
        max_tokens=100,
        messages=[{"role": "user", "content": "Count to five."}],
    ) as stream:
        for text in stream.text_stream:
            print(text, end="", flush=True)
    print()
