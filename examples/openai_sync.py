"""OpenAI SDK through the AIRT gateway, synchronous mode.

The SDK is pointed at the gateway with base_url; the AIRT agent key replaces the OpenAI key.
The call blocks until a reviewer approves the ticket in the dashboard (http://localhost:8080/tickets)
or the gateway's AIRT_APPROVAL_TIMEOUT_SECONDS (default 300 s) elapses.

    pip install openai
    export AIRT_GATEWAY_URL=http://localhost:8080
    export AIRT_AGENT_KEY=airt_...          # from `airt agent create` or the Agents page
    python examples/openai_sync.py
"""

from __future__ import annotations

import os
import sys

from openai import APIStatusError, OpenAI

GATEWAY = os.environ.get("AIRT_GATEWAY_URL", "http://localhost:8080").rstrip("/")
AGENT_KEY = os.environ.get("AIRT_AGENT_KEY")
if not AGENT_KEY:
    sys.exit("set AIRT_AGENT_KEY to an agent key issued by the gateway")

client = OpenAI(
    base_url=f"{GATEWAY}/v1",
    api_key=AGENT_KEY,
    # optional: tag the ticket so reviewers can group related calls
    default_headers={"X-AIRT-Source": "sdk", "X-AIRT-Correlation-Id": "example-openai-sync"},
    timeout=330.0,  # must exceed the gateway approval timeout
    max_retries=0,  # a denied/expired ticket must not be retried automatically
)

print("submitting request; approve it at", f"{GATEWAY}/tickets")
try:
    completion = client.chat.completions.with_raw_response.create(
        model=os.environ.get("MODEL", "gpt-4o-mini"),
        messages=[{"role": "user", "content": "In one sentence, what does a red team do?"}],
    )
    print("ticket:", completion.headers.get("X-AIRT-Ticket"))
    print("answer:", completion.parse().choices[0].message.content)
except APIStatusError as exc:
    # 403 = denied by policy or reviewer, 504 = no decision before timeout, 502 = upstream error
    err = exc.body.get("error", {}) if isinstance(exc.body, dict) else {}
    print(
        f"gateway refused ({exc.status_code}) ticket={err.get('ticket_id')} code={err.get('code')}: {err.get('message')}"
    )
