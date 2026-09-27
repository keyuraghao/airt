"use strict";
// Self-test: node sdk/node/test.js
const assert = require("node:assert/strict");
const airt = require("./index.js");

const calls = [];
const stubFetch = async function (input, init) {
  const url = input instanceof Request ? input.url : String(input);
  const headers = new Headers(input instanceof Request ? input.headers : (init && init.headers) || undefined);
  let body = null;
  if (input instanceof Request) body = await input.text();
  else if (init && init.body) body = String(init.body);
  calls.push({ url, method: (input instanceof Request ? input.method : init && init.method) || "GET", headers, body });
  if (url.includes("/gateway/tickets/")) {
    const n = calls.filter((c) => c.url.includes("/gateway/tickets/")).length;
    if (n === 1) return new Response(JSON.stringify({ ticket_id: "tkt_1", status: "PENDING" }), { status: 202, headers: { "content-type": "application/json" } });
    return new Response(JSON.stringify({ ticket_id: "tkt_1", status: "COMPLETED", decided_by: "admin", response: { choices: [{ message: { content: "hi" } }] }, response_status: 200 }), { status: 200 });
  }
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers: { "X-AIRT-Ticket": "tkt_sync" } });
};

async function main() {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = stubFetch;
  try {
    assert.throws(() => airt.install({}), /gatewayUrl is required/);
    airt.install({ gatewayUrl: "http://gw:8080/", agentKey: "airt_test", asyncMode: true, correlationId: "corr_1" });
    assert.equal(airt.isInstalled(), true);
    assert.ok(globalThis.fetch.__airtWrapped, "global fetch is wrapped");

    // string input with init
    let res = await fetch("https://api.openai.com/v1/chat/completions?x=1", { method: "POST", headers: { Authorization: "Bearer sk-real", "content-type": "application/json" }, body: "{\"a\":1}" });
    assert.equal(res.headers.get("x-airt-ticket"), "tkt_sync");
    let c = calls.at(-1);
    assert.equal(c.url, "http://gw:8080/proxy/v1/chat/completions?x=1");
    assert.equal(c.method, "POST");
    assert.equal(c.body, "{\"a\":1}");
    assert.equal(c.headers.get("x-airt-key"), "airt_test");
    assert.equal(c.headers.get("x-airt-source"), "sdk");
    assert.equal(c.headers.get("x-airt-async"), "1");
    assert.equal(c.headers.get("x-airt-correlation-id"), "corr_1");
    assert.equal(c.headers.get("authorization"), null, "provider key stripped");
    assert.equal(c.headers.get("content-type"), "application/json");

    // URL object input
    await fetch(new URL("https://api.anthropic.com/v1/messages"), { method: "POST", headers: { "x-api-key": "sk-ant" }, body: "{}" });
    c = calls.at(-1);
    assert.equal(c.url, "http://gw:8080/proxy/v1/messages");
    assert.equal(c.headers.get("x-api-key"), null);

    // Request object input keeps method and body
    await fetch(new Request("https://api.groq.com/openai/v1/chat/completions", { method: "POST", body: "{\"b\":2}", headers: { "content-type": "application/json" } }));
    c = calls.at(-1);
    assert.equal(c.url, "http://gw:8080/proxy/openai/v1/chat/completions");
    assert.equal(c.method, "POST");
    assert.equal(c.body, "{\"b\":2}");
    assert.equal(c.headers.get("x-airt-key"), "airt_test");

    // port sensitive host
    await fetch("http://localhost:11434/api/chat", { method: "POST", body: "{}" });
    assert.equal(calls.at(-1).url, "http://gw:8080/proxy/api/chat");
    await fetch("http://localhost:9999/api/chat");
    assert.equal(calls.at(-1).url, "http://localhost:9999/api/chat");

    // untouched host
    await fetch("https://example.com/health");
    c = calls.at(-1);
    assert.equal(c.url, "https://example.com/health");
    assert.equal(c.headers.get("x-airt-key"), null);

    // pure helpers
    assert.equal(airt.rewriteUrl("https://api.mistral.ai/v1/models"), "http://gw:8080/proxy/v1/models");
    assert.equal(airt.rewriteUrl("https://github.com"), null);
    assert.equal(airt.rewriteUrl("not a url"), null);
    const custom = airt.rewriteUrl("https://llm.internal.example/v1/x", { gatewayUrl: "https://airt.example", agentKey: "k", hosts: ["llm.internal.example"], source: "sdk" });
    assert.equal(custom, "https://airt.example/proxy/v1/x");

    // SDK option helpers
    const oa = airt.configureOpenAI({ gatewayUrl: "http://gw:8080", agentKey: "airt_test" });
    assert.deepEqual(oa, { baseURL: "http://gw:8080/v1", apiKey: "airt_test", defaultHeaders: { "X-AIRT-Key": "airt_test", "X-AIRT-Source": "sdk" } });
    const an = airt.configureAnthropic({ gatewayUrl: "http://gw:8080", agentKey: "airt_test", asyncMode: true });
    assert.equal(an.baseURL, "http://gw:8080");
    assert.equal(an.defaultHeaders["X-AIRT-Async"], "1");

    // async ticket polling
    const t = await airt.waitForTicket("tkt_1", { pollIntervalMs: 1 });
    assert.equal(t.status, "COMPLETED");
    assert.equal(t.decidedBy, "admin");
    assert.equal(t.body.choices[0].message.content, "hi");
    assert.ok(calls.at(-1).url.endsWith("/gateway/tickets/tkt_1"));
    assert.equal(calls.at(-1).headers.get("x-airt-key"), "airt_test");

    // uninstall restores fetch
    airt.uninstall();
    assert.equal(airt.isInstalled(), false);
    assert.equal(globalThis.fetch, stubFetch);
    await fetch("https://api.openai.com/v1/models");
    assert.equal(calls.at(-1).url, "https://api.openai.com/v1/models");
    console.log(`airt-intercept self-test passed (${calls.length} stubbed requests)`);
  } finally {
    airt.uninstall();
    globalThis.fetch = originalFetch;
  }
}

main().catch((err) => {
  console.error("airt-intercept self-test FAILED");
  console.error(err);
  process.exit(1);
});
