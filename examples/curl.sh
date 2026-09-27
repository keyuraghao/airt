#!/usr/bin/env bash
# AISRF gateway walk-through with curl only.
#   export AISRF_URL=http://localhost:8080 AISRF_ADMIN_TOKEN=<AISRF_ADMIN_API_TOKEN or omit to log in>
#   bash examples/curl.sh
set -euo pipefail
AISRF_URL="${AISRF_URL:-http://localhost:8080}"
ADMIN_USER="${AISRF_ADMIN_USERNAME:-admin}"
ADMIN_PASS="${AISRF_ADMIN_PASSWORD:-admin}"
JAR="$(mktemp)"
trap 'rm -f "$JAR"' EXIT

# --- 1. reviewer auth: bearer token (AISRF_ADMIN_API_TOKEN) or a session cookie from /api/auth/login
if [[ -n "${AISRF_ADMIN_TOKEN:-}" ]]; then
  AUTH=(-H "Authorization: Bearer ${AISRF_ADMIN_TOKEN}")
else
  curl -sS -c "$JAR" -X POST "$AISRF_URL/api/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}" >/dev/null
  AUTH=(-b "$JAR")
fi
echo "logged in as: $(curl -sS "${AUTH[@]}" "$AISRF_URL/api/auth/me")"

# --- 2. create an agent (upstream credentials are stored encrypted on the gateway)
AGENT_JSON=$(curl -sS "${AUTH[@]}" -X POST "$AISRF_URL/api/agents" -H 'Content-Type: application/json' -d "{
  \"name\": \"curl-demo-$(date +%s)\",
  \"upstream_provider\": \"openai\",
  \"upstream_base_url\": \"${UPSTREAM_BASE_URL:-https://api.openai.com/v1}\",
  \"upstream_api_key\": \"${OPENAI_API_KEY:-sk-replace-me}\",
  \"require_approval\": true,
  \"auto_deny_at_risk\": 90
}")
AGENT_ID=$(echo "$AGENT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
AGENT_KEY=$(echo "$AGENT_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["api_key"])')
echo "agent $AGENT_ID key ${AGENT_KEY:0:12}..."

# --- 3. submit a request in ASYNC mode (202 + ticket id) so this script can approve it itself
RESP=$(curl -sS -X POST "$AISRF_URL/v1/chat/completions" \
  -H "X-AISRF-Key: $AGENT_KEY" -H 'X-AISRF-Async: 1' -H 'X-AISRF-Source: sdk' -H 'X-AISRF-Correlation-Id: curl-demo' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Say hello in five words."}]}')
echo "gateway: $RESP"
TICKET=$(echo "$RESP" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("ticket_id",""))')
[[ -n "$TICKET" ]] || { echo "no ticket (policy denied or auto-approved)"; exit 0; }

# --- 4. inspect the ticket as a reviewer (analysis findings, risk score, policy decision)
curl -sS "${AUTH[@]}" "$AISRF_URL/api/tickets/$TICKET" | python3 -c 'import json,sys; t=json.load(sys.stdin); print("risk", t["risk_score"], t["risk_level"], "policy", t["policy_action"], "findings", t["finding_count"])'

# --- 5. approve (or deny) it
curl -sS "${AUTH[@]}" -X POST "$AISRF_URL/api/tickets/$TICKET/approve" -H 'Content-Type: application/json' -d '{"note":"looks fine"}' >/dev/null
echo "approved $TICKET"

# --- 6. the agent polls: the first poll of an APPROVED ticket forwards it upstream and relays the answer
curl -sS -D - "$AISRF_URL/gateway/tickets/$TICKET" -H "X-AISRF-Key: $AGENT_KEY" | sed -n '1,/^\r\{0,1\}$/p; $p'

# --- 7. the same request in SYNC mode blocks until a human decides (run in another shell and approve in the dashboard)
cat <<EOF

sync mode:
  curl -X POST $AISRF_URL/v1/chat/completions -H 'X-AISRF-Key: $AGENT_KEY' -H 'Content-Type: application/json' \\
    -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
generic proxy (any provider path, e.g. Anthropic):
  curl -X POST $AISRF_URL/proxy/v1/messages -H 'X-AISRF-Key: $AGENT_KEY' -H 'anthropic-version: 2023-06-01' -H 'Content-Type: application/json' -d '{...}'
reports:
  curl "${AUTH[*]}" "$AISRF_URL/api/reports/summary?format=md"
audit chain:
  curl "${AUTH[*]}" "$AISRF_URL/api/audit/verify"
EOF
