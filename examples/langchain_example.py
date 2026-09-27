"""LangChain through the AIRT gateway: only base_url / api_key change.

    pip install langchain-openai        # or langchain-anthropic
    export AIRT_GATEWAY_URL=http://localhost:8080 AIRT_AGENT_KEY=airt_...
    python examples/langchain_example.py

Every model invocation (including each step of an agent or chain) becomes its own ticket. Use a
correlation id header so reviewers can see which tickets belong to one chain run.
"""

from __future__ import annotations

import os
import sys
import uuid

GATEWAY = os.environ.get("AIRT_GATEWAY_URL", "http://localhost:8080").rstrip("/")
AGENT_KEY = os.environ.get("AIRT_AGENT_KEY") or sys.exit("set AIRT_AGENT_KEY")
RUN_ID = "langchain-" + uuid.uuid4().hex[:8]

# Option A: explicit arguments
try:
    from langchain_openai import ChatOpenAI
except ImportError:
    sys.exit("pip install langchain-openai")

llm = ChatOpenAI(
    model=os.environ.get("MODEL", "gpt-4o-mini"),
    base_url=f"{GATEWAY}/v1",
    api_key=AGENT_KEY,
    default_headers={"X-AIRT-Source": "sdk", "X-AIRT-Correlation-Id": RUN_ID},
    timeout=330,
    max_retries=0,
)

# Option B: environment variables, then ChatOpenAI() with no arguments
#   from airt.integrations import configure
#   configure(GATEWAY, AGENT_KEY)          # sets OPENAI_BASE_URL / OPENAI_API_KEY (and the Anthropic ones)
#   llm = ChatOpenAI(model="gpt-4o-mini")
#
# Anthropic:
#   from langchain_anthropic import ChatAnthropic
#   llm = ChatAnthropic(model="claude-3-5-haiku-latest", base_url=GATEWAY, api_key=AGENT_KEY)

from langchain_core.prompts import ChatPromptTemplate
from openai import APIStatusError

prompt = ChatPromptTemplate.from_messages(
    [
        ("system", "You are a terse assistant for a security team."),
        ("human", "Summarise the risk of {topic} in one sentence."),
    ]
)
chain = prompt | llm

print(f"run {RUN_ID}: two tickets will appear at {GATEWAY}/tickets (search for the correlation id)")
for topic in ("indirect prompt injection", "training data extraction"):
    try:
        result = chain.invoke({"topic": topic})
        print(f"- {topic}: {result.content}")
    except APIStatusError as exc:  # denied (403) / expired (504) tickets surface as API errors
        print(f"- {topic}: gateway refused ({exc.status_code}): {exc.message}")
