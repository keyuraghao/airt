"""Asynchronous ticket mode: submit, get a 202 with the ticket id, poll until decided.

Useful when the caller cannot hold an HTTP connection open for minutes (serverless, message
queues, batch jobs). Two flavours are shown:

1. AISRFClient from aisrf.integrations does the polling for you.
2. Raw httpx, to show exactly what happens on the wire.

    export AISRF_GATEWAY_URL=http://localhost:8080
    export AISRF_AGENT_KEY=aisrf_...
    python examples/openai_async_mode.py
"""

from __future__ import annotations

import os
import sys
import time

import httpx

from aisrf.integrations import AISRFClient

GATEWAY = os.environ.get("AISRF_GATEWAY_URL", "http://localhost:8080").rstrip("/")
AGENT_KEY = os.environ.get("AISRF_AGENT_KEY") or sys.exit("set AISRF_AGENT_KEY")
BODY = {
    "model": os.environ.get("MODEL", "gpt-4o-mini"),
    "messages": [{"role": "user", "content": "Name three OWASP LLM Top 10 risks."}],
}

# --- 1. helper client ---------------------------------------------------------------
with AISRFClient(GATEWAY, AGENT_KEY, async_mode=True, poll_interval=2.0, max_wait=600) as client:
    pending = client.submit("v1/chat/completions", BODY, wait=False)
    print(
        f"[client] ticket {pending.ticket_id} is {pending.status}; approve it at {GATEWAY}/tickets/{pending.ticket_id}"
    )
    final = client.wait_for(pending.ticket_id)
    print(f"[client] final status={final.status} http={final.http_status} decided_by={final.decided_by}")
    if final.ok:
        print("[client] answer:", final.content_text)
    else:
        print("[client] no answer:", final.error or final.decision_note)

# --- 2. raw HTTP ----------------------------------------------------------------------
headers = {
    "X-AISRF-Key": AGENT_KEY,
    "X-AISRF-Async": "1",
    "X-AISRF-Source": "sdk",
    "Content-Type": "application/json",
}
with httpx.Client(timeout=60) as http:
    r = http.post(f"{GATEWAY}/v1/chat/completions", json=BODY, headers=headers)
    if r.status_code == 403:
        sys.exit(f"[raw] denied by policy before review: {r.json()['error']['message']}")
    if r.status_code == 200:  # the agent policy auto-approved: the upstream answer comes back directly
        print("[raw] auto-approved, ticket", r.headers.get("X-AISRF-Ticket"))
        sys.exit(0)
    assert r.status_code == 202, (r.status_code, r.text)
    ticket_id = r.json()["ticket_id"]
    poll_url = GATEWAY + r.json()["poll_url"]
    print(f"[raw] ticket {ticket_id} pending, polling {poll_url}")
    deadline = time.time() + 600
    while time.time() < deadline:
        p = http.get(poll_url, headers={"X-AISRF-Key": AGENT_KEY})
        data = p.json() if "application/json" in p.headers.get("content-type", "") else {}
        status = data.get("status") if data.get("ticket_id") else "COMPLETED"
        # A poll of an APPROVED ticket forwards it upstream and relays the provider response
        # directly (no envelope), with X-AISRF-Ticket in the headers. COMPLETED tickets that were
        # already forwarded come back wrapped as {"ticket_id", "status": "COMPLETED", "response": ...}.
        if status == "PENDING" or status == "FORWARDING":
            time.sleep(2)
            continue
        if status == "COMPLETED":
            body = data.get("response", data)
            text = (
                body["choices"][0]["message"]["content"]
                if isinstance(body, dict) and "choices" in body
                else body
            )
            print(f"[raw] COMPLETED (http {p.status_code}):", text)
        else:
            print(
                f"[raw] {status} (http {p.status_code}) by {data.get('decided_by')}: {data.get('decision_note')}"
            )
        break
    else:
        print("[raw] gave up waiting")
