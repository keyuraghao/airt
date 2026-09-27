"use strict";
/**
 * aisrf-intercept: route fetch based LLM traffic through an AISRF gateway.
 *
 * Zero dependencies, Node 18+ (needs the global fetch / Request / Headers WHATWG classes).
 *
 *   const aisrf = require("aisrf-intercept");
 *   aisrf.install({ gatewayUrl: "http://localhost:8080", agentKey: "aisrf_..." });
 *   // every fetch("https://api.openai.com/v1/chat/completions", ...) now goes to
 *   // http://localhost:8080/proxy/v1/chat/completions with X-AISRF-Key / X-AISRF-Source headers.
 *
 * Gateway contract (see aisrf/gateway/router.py in the AISRF repository):
 *   X-AISRF-Key            agent key (also accepted as Authorization: Bearer aisrf_...)
 *   X-AISRF-Source         gateway | sdk | mitm | redteam
 *   X-AISRF-Async: 1       return 202 {ticket_id, status: "PENDING", poll_url} instead of blocking
 *   X-AISRF-Correlation-Id optional grouping id
 *   X-AISRF-Ticket         response header on every relayed upstream response
 */

const DEFAULT_HOSTS = Object.freeze([
  "api.openai.com",
  "api.anthropic.com",
  "generativelanguage.googleapis.com",
  "api.mistral.ai",
  "api.cohere.ai",
  "api.groq.com",
  "openrouter.ai",
  "localhost:11434",
]);

const FINAL_TICKET_STATUSES = Object.freeze(["COMPLETED", "DENIED", "EXPIRED", "FAILED"]);
const TICKET_STATUSES = Object.freeze(["PENDING", "APPROVED", "DENIED", "EXPIRED", "FORWARDING", "COMPLETED", "FAILED"]);

let state = null; // { options, originalFetch, originalUndiciFetch, undici }

function normalizeOptions(options) {
  if (!options || typeof options !== "object") {
    throw new TypeError("aisrf-intercept: install(options) requires an object");
  }
  const gatewayUrl = String(options.gatewayUrl || process.env.AISRF_GATEWAY_URL || "").replace(/\/+$/, "");
  const agentKey = String(options.agentKey || process.env.AISRF_AGENT_KEY || "");
  if (!gatewayUrl) throw new TypeError("aisrf-intercept: gatewayUrl is required (or set AISRF_GATEWAY_URL)");
  if (!agentKey) throw new TypeError("aisrf-intercept: agentKey is required (or set AISRF_AGENT_KEY)");
  const hosts = (options.hosts && options.hosts.length ? options.hosts : DEFAULT_HOSTS).map((h) => String(h).toLowerCase());
  return {
    gatewayUrl,
    agentKey,
    hosts,
    asyncMode: Boolean(options.asyncMode),
    source: options.source || "sdk",
    correlationId: options.correlationId || null,
    stripProviderAuth: options.stripProviderAuth !== false,
    onIntercept: typeof options.onIntercept === "function" ? options.onIntercept : null,
  };
}

function hostMatches(url, hosts) {
  const host = url.hostname.toLowerCase();
  const port = url.port || (url.protocol === "https:" ? "443" : url.protocol === "http:" ? "80" : "");
  const withPort = port ? `${host}:${port}` : host;
  for (const pattern of hosts) {
    if (pattern.includes(":")) {
      if (withPort === pattern) return true;
    } else if (host === pattern || host.endsWith("." + pattern)) {
      return true;
    }
  }
  return false;
}

/**
 * Compute the gateway URL for a provider URL, or null when the host is not intercepted.
 */
function rewriteUrl(originalUrl, options) {
  const opts = options && options.gatewayUrl ? options : state && state.options;
  if (!opts) return null;
  let url;
  try {
    url = new URL(String(originalUrl));
  } catch (e) {
    return null;
  }
  if (!hostMatches(url, opts.hosts)) return null;
  const path = url.pathname.replace(/^\/+/, "");
  return `${opts.gatewayUrl}/proxy/${path}${url.search}`;
}

function airtHeaders(opts) {
  const headers = { "X-AISRF-Key": opts.agentKey, "X-AISRF-Source": opts.source };
  if (opts.asyncMode) headers["X-AISRF-Async"] = "1";
  if (opts.correlationId) headers["X-AISRF-Correlation-Id"] = opts.correlationId;
  return headers;
}

/**
 * Rewrite a (input, init) fetch pair. Returns { input, init, intercepted, originalUrl }.
 * Exported so it can be unit tested and reused by custom fetch wrappers.
 */
function rewriteRequest(input, init, options) {
  const opts = options && options.gatewayUrl ? options : state && state.options;
  if (!opts) return { input, init, intercepted: false, originalUrl: null };
  const isRequest = typeof Request !== "undefined" && input instanceof Request;
  const originalUrl = isRequest ? input.url : input instanceof URL ? input.href : String(input);
  const target = rewriteUrl(originalUrl, opts);
  if (!target) return { input, init, intercepted: false, originalUrl };
  const headers = new Headers(isRequest ? input.headers : undefined);
  if (init && init.headers) {
    new Headers(init.headers).forEach((v, k) => headers.set(k, v));
  }
  if (opts.stripProviderAuth) {
    for (const h of ["authorization", "x-api-key", "api-key", "x-goog-api-key"]) headers.delete(h);
  }
  for (const [k, v] of Object.entries(airtHeaders(opts))) headers.set(k, v);
  const newInit = Object.assign({}, init || {}, { headers });
  if (isRequest) {
    // Preserve method/body/signal from the Request object; init overrides win.
    const merged = new Request(target, input);
    return { input: new Request(merged, newInit), init: undefined, intercepted: true, originalUrl };
  }
  return { input: target, init: newInit, intercepted: true, originalUrl };
}

function wrapFetch(originalFetch) {
  const wrapped = async function airtFetch(input, init) {
    const r = rewriteRequest(input, init);
    if (r.intercepted && state && state.options.onIntercept) {
      try {
        state.options.onIntercept({ originalUrl: r.originalUrl, gatewayUrl: typeof r.input === "string" ? r.input : r.input.url });
      } catch (e) {
        // user callback errors must not break the request
      }
    }
    return originalFetch.call(this, r.input, r.init);
  };
  wrapped.__airtWrapped = true;
  wrapped.__airtOriginal = originalFetch;
  return wrapped;
}

/**
 * Install the interceptor on globalThis.fetch and, when the undici package is resolvable,
 * on undici.fetch as well. Calling install twice replaces the options without double wrapping.
 */
function install(options) {
  const opts = normalizeOptions(options);
  if (state) {
    state.options = opts;
    return uninstall;
  }
  if (typeof globalThis.fetch !== "function") {
    throw new Error("aisrf-intercept: globalThis.fetch is not available (Node 18+ required)");
  }
  state = { options: opts, originalFetch: globalThis.fetch, originalUndiciFetch: null, undici: null };
  globalThis.fetch = wrapFetch(state.originalFetch);
  try {
    const undici = require("undici");
    if (undici && typeof undici.fetch === "function" && !undici.fetch.__airtWrapped) {
      const desc = Object.getOwnPropertyDescriptor(undici, "fetch");
      if (!desc || desc.writable || desc.set) {
        state.undici = undici;
        state.originalUndiciFetch = undici.fetch;
        undici.fetch = wrapFetch(undici.fetch);
      }
    }
  } catch (e) {
    // undici not installed as a package: the global fetch (which is undici) is already wrapped
  }
  return uninstall;
}

function uninstall() {
  if (!state) return;
  if (globalThis.fetch && globalThis.fetch.__airtWrapped) globalThis.fetch = state.originalFetch;
  if (state.undici && state.originalUndiciFetch) state.undici.fetch = state.originalUndiciFetch;
  state = null;
}

function isInstalled() {
  return state !== null;
}

/**
 * Options for the official `openai` npm package:
 *   const OpenAI = require("openai");
 *   const client = new OpenAI(configureOpenAI({ gatewayUrl, agentKey }));
 */
function configureOpenAI(options) {
  const opts = normalizeOptions(Object.assign({}, options || {}, { agentKey: (options && options.agentKey) || process.env.AISRF_AGENT_KEY }));
  return { baseURL: `${opts.gatewayUrl}/v1`, apiKey: opts.agentKey, defaultHeaders: airtHeaders(opts) };
}

/**
 * Options for the official `@anthropic-ai/sdk` npm package:
 *   const client = new Anthropic(configureAnthropic({ gatewayUrl, agentKey }));
 */
function configureAnthropic(options) {
  const opts = normalizeOptions(Object.assign({}, options || {}, { agentKey: (options && options.agentKey) || process.env.AISRF_AGENT_KEY }));
  return { baseURL: opts.gatewayUrl, apiKey: opts.agentKey, defaultHeaders: airtHeaders(opts) };
}

/**
 * Poll an asynchronous ticket (created with asyncMode: true) until it reaches a final status.
 * Resolves to { ticketId, status, httpStatus, body } where body is the parsed JSON when possible.
 */
async function waitForTicket(ticketId, options) {
  const o = Object.assign({ pollIntervalMs: 2000, maxWaitMs: 900000 }, options || {});
  const gatewayUrl = String(o.gatewayUrl || (state && state.options.gatewayUrl) || process.env.AISRF_GATEWAY_URL || "").replace(/\/+$/, "");
  const agentKey = o.agentKey || (state && state.options.agentKey) || process.env.AISRF_AGENT_KEY;
  const doFetch = o.fetch || (state ? state.originalFetch : globalThis.fetch);
  const deadline = Date.now() + o.maxWaitMs;
  let last = null;
  while (Date.now() < deadline) {
    const res = await doFetch(`${gatewayUrl}/gateway/tickets/${ticketId}`, { headers: { "X-AISRF-Key": agentKey, "X-AISRF-Source": (state && state.options.source) || "sdk" } });
    const text = await res.text();
    let body = null;
    try {
      body = JSON.parse(text);
    } catch (e) {
      body = text;
    }
    const envelope = body && typeof body === "object" && body.ticket_id && TICKET_STATUSES.includes(body.status);
    if (envelope) {
      last = { ticketId: body.ticket_id, status: body.status, httpStatus: body.response_status || res.status, body: body.response !== undefined ? body.response : body, decidedBy: body.decided_by || null, decisionNote: body.decision_note || "" };
    } else if (body && typeof body === "object" && body.error && body.error.type === "aisrf_gateway") {
      const code = String(body.error.code || "").toLowerCase();
      last = { ticketId: body.error.ticket_id || ticketId, status: code === "denied" ? "DENIED" : code === "expired" ? "EXPIRED" : "FAILED", httpStatus: res.status, body, decidedBy: body.error.decided_by || null, decisionNote: body.error.message || "" };
    } else {
      // the poll forwarded an APPROVED ticket and relayed the upstream response
      last = { ticketId: res.headers.get("x-aisrf-ticket") || ticketId, status: res.status >= 500 ? "FAILED" : "COMPLETED", httpStatus: res.status, body, decidedBy: null, decisionNote: "" };
    }
    if (FINAL_TICKET_STATUSES.includes(last.status)) return last;
    await new Promise((resolve) => setTimeout(resolve, o.pollIntervalMs));
  }
  return Object.assign(last || { ticketId, status: "PENDING", httpStatus: 0, body: null }, { timedOut: true });
}

module.exports = {
  DEFAULT_HOSTS,
  FINAL_TICKET_STATUSES,
  install,
  uninstall,
  isInstalled,
  rewriteUrl,
  rewriteRequest,
  configureOpenAI,
  configureAnthropic,
  waitForTicket,
};
