/* AIRT dashboard core: API helper, DOM builder, toasts, relative time, SSE with reconnect. */
(function () {
  "use strict";
  var AIRT = window.AIRT = window.AIRT || {};
  AIRT.pages = {};
  AIRT.principal = null;
  try { AIRT.principal = JSON.parse(document.body.getAttribute("data-principal") || "null"); } catch (e) { AIRT.principal = null; }
  AIRT.isReviewer = function () { return !!AIRT.principal && (AIRT.principal.role === "reviewer" || AIRT.principal.role === "admin"); };
  AIRT.isAdmin = function () { return !!AIRT.principal && AIRT.principal.role === "admin"; };

  /* ---------- escaping and DOM ---------- */
  var ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  AIRT.escapeHtml = function (s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return ESC[c]; }); };
  AIRT.el = function (tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v == null || v === false) return;
        if (k === "class") node.className = v;
        else if (k === "text") node.textContent = v;
        else if (k === "html") node.innerHTML = v;
        else if (k.indexOf("on") === 0 && typeof v === "function") node.addEventListener(k.slice(2), v);
        else if (k === "dataset") Object.keys(v).forEach(function (d) { node.dataset[d] = v[d]; });
        else if (v === true) node.setAttribute(k, "");
        else node.setAttribute(k, v);
      });
    }
    AIRT.append(node, children);
    return node;
  };
  AIRT.append = function (node, children) {
    if (children == null) return node;
    if (!Array.isArray(children)) children = [children];
    children.forEach(function (c) {
      if (c == null || c === false) return;
      if (typeof c === "string" || typeof c === "number") node.appendChild(document.createTextNode(String(c)));
      else node.appendChild(c);
    });
    return node;
  };
  AIRT.clear = function (node) { while (node.firstChild) node.removeChild(node.firstChild); return node; };
  AIRT.$ = function (sel, root) { return (root || document).querySelector(sel); };
  AIRT.$$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  AIRT.qs = function (params) {
    var parts = [];
    Object.keys(params || {}).forEach(function (k) {
      var v = params[k];
      if (v == null || v === "" || v === false) return;
      if (Array.isArray(v)) v.forEach(function (x) { parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(x)); });
      else parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(v));
    });
    return parts.length ? "?" + parts.join("&") : "";
  };
  AIRT.param = function (name) { return new URLSearchParams(window.location.search).get(name); };

  /* ---------- API ---------- */
  AIRT.api = function (method, url, body, opts) {
    opts = opts || {};
    var init = { method: method, headers: { "Accept": "application/json" }, credentials: "same-origin" };
    if (body !== undefined) { init.headers["Content-Type"] = "application/json"; init.body = JSON.stringify(body); }
    return fetch(url, init).then(function (res) {
      if (res.status === 401 && !opts.noRedirect && window.location.pathname !== "/login") {
        window.location.href = "/login?next=" + encodeURIComponent(window.location.pathname + window.location.search);
        return new Promise(function () {});
      }
      var ct = res.headers.get("content-type") || "";
      var parse = ct.indexOf("json") >= 0 ? res.json() : res.text();
      return parse.then(function (data) {
        if (!res.ok) {
          var msg = (data && data.detail) ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : (data && data.error && data.error.message) || (typeof data === "string" && data) || ("HTTP " + res.status);
          var err = new Error(msg);
          err.status = res.status;
          err.data = data;
          throw err;
        }
        return data;
      });
    });
  };
  AIRT.get = function (url) { return AIRT.api("GET", url); };
  AIRT.post = function (url, body) { return AIRT.api("POST", url, body === undefined ? {} : body); };
  AIRT.patch = function (url, body) { return AIRT.api("PATCH", url, body); };
  AIRT.del = function (url) { return AIRT.api("DELETE", url); };

  /* ---------- toasts ---------- */
  var toastBox = null;
  AIRT.toast = function (msg, kind, ms) {
    if (!toastBox) { toastBox = AIRT.el("div", { class: "toasts", role: "status", "aria-live": "polite" }); document.body.appendChild(toastBox); }
    var t = AIRT.el("div", { class: "toast " + (kind || ""), text: msg });
    toastBox.appendChild(t);
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, ms || 4200);
    return t;
  };
  AIRT.fail = function (err) { AIRT.toast(err && err.message ? err.message : String(err), "error", 6000); if (window.console) console.warn(err); };

  /* ---------- modal ---------- */
  AIRT.modal = function (title, body, buttons) {
    var backdrop = AIRT.el("div", { class: "modal-backdrop" });
    var box = AIRT.el("div", { class: "modal", role: "dialog", "aria-modal": "true" });
    if (title) box.appendChild(AIRT.el("h2", { text: title }));
    AIRT.append(box, body);
    var actions = AIRT.el("div", { class: "actions" });
    var close = function () { if (backdrop.parentNode) backdrop.parentNode.removeChild(backdrop); document.removeEventListener("keydown", onKey); };
    (buttons || [{ label: "Close" }]).forEach(function (b) {
      actions.appendChild(AIRT.el("button", { class: "btn " + (b.class || ""), text: b.label, onclick: function () { if (b.onClick) { var r = b.onClick(close); if (r === false) return; } if (!b.keepOpen) close(); } }));
    });
    box.appendChild(actions);
    backdrop.appendChild(box);
    var onKey = function (e) { if (e.key === "Escape") close(); };
    document.addEventListener("keydown", onKey);
    backdrop.addEventListener("click", function (e) { if (e.target === backdrop) close(); });
    document.body.appendChild(backdrop);
    var first = box.querySelector("input, textarea, select, button");
    if (first) first.focus();
    return { close: close, box: box };
  };
  AIRT.promptNote = function (title, placeholder, confirmLabel, confirmClass) {
    return new Promise(function (resolve) {
      var ta = AIRT.el("textarea", { placeholder: placeholder || "Optional note for the audit trail", rows: 3 });
      var m = AIRT.modal(title, ta, [
        { label: "Cancel", onClick: function () { resolve(null); } },
        { label: confirmLabel || "Confirm", class: confirmClass || "primary", onClick: function () { resolve(ta.value); } }
      ]);
      ta.addEventListener("keydown", function (e) { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { resolve(ta.value); m.close(); } });
      ta.focus();
    });
  };
  AIRT.confirm = function (title, text, confirmLabel, confirmClass) {
    return new Promise(function (resolve) {
      AIRT.modal(title, AIRT.el("p", { text: text }), [
        { label: "Cancel", onClick: function () { resolve(false); } },
        { label: confirmLabel || "Confirm", class: confirmClass || "primary", onClick: function () { resolve(true); } }
      ]);
    });
  };
  AIRT.copy = function (text) {
    var done = function () { AIRT.toast("Copied to clipboard", "ok", 1800); };
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text).then(done, function () { fallback(); });
    fallback();
    function fallback() {
      var ta = AIRT.el("textarea", { style: "position:fixed;opacity:0", text: text });
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch (e) { AIRT.toast("Copy failed", "error"); }
      document.body.removeChild(ta);
    }
  };

  /* ---------- time ---------- */
  AIRT.parseTs = function (v) {
    if (v == null || v === "") return null;
    if (typeof v === "number") return new Date(v < 1e12 ? v * 1000 : v);
    var d = new Date(v);
    return isNaN(d.getTime()) ? null : d;
  };
  AIRT.relTime = function (v) {
    var d = AIRT.parseTs(v);
    if (!d) return "";
    var diff = (Date.now() - d.getTime()) / 1000;
    var future = diff < 0;
    diff = Math.abs(diff);
    var s;
    if (diff < 5) s = "just now";
    else if (diff < 60) s = Math.floor(diff) + "s";
    else if (diff < 3600) s = Math.floor(diff / 60) + "m";
    else if (diff < 86400) s = Math.floor(diff / 3600) + "h";
    else if (diff < 86400 * 30) s = Math.floor(diff / 86400) + "d";
    else s = d.toLocaleDateString();
    if (s === "just now") return s;
    return future ? "in " + s : s + " ago";
  };
  AIRT.fmtTs = function (v) {
    var d = AIRT.parseTs(v);
    if (!d) return "";
    return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };
  AIRT.fmtTime = function (v) {
    var d = AIRT.parseTs(v);
    return d ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
  };
  AIRT.countdown = function (v) {
    var d = AIRT.parseTs(v);
    if (!d) return "";
    var left = Math.floor((d.getTime() - Date.now()) / 1000);
    if (left <= 0) return "expired";
    var m = Math.floor(left / 60), s = left % 60;
    return (m > 0 ? m + "m " : "") + (s < 10 && m > 0 ? "0" : "") + s + "s";
  };
  AIRT.fmtMs = function (v) { if (v == null) return ""; v = Number(v); return v >= 1000 ? (v / 1000).toFixed(2) + " s" : Math.round(v) + " ms"; };
  AIRT.fmtSecs = function (v) { if (v == null) return "n/a"; v = Number(v); if (v < 60) return v.toFixed(1) + " s"; if (v < 3600) return (v / 60).toFixed(1) + " min"; return (v / 3600).toFixed(1) + " h"; };
  AIRT.timeEl = function (v, opts) {
    opts = opts || {};
    var absolute = opts.absolute || (AIRT.ui && AIRT.ui.date_format === "absolute");
    return AIRT.el("time", { class: (absolute ? "abs " : "rel ") + (opts.class || ""), datetime: v || "", title: absolute ? AIRT.relTime(v) : AIRT.fmtTs(v), text: absolute ? AIRT.fmtTs(v) : AIRT.relTime(v) });
  };
  setInterval(function () {
    AIRT.$$("time.rel").forEach(function (t) { var v = t.getAttribute("datetime"); if (v) t.textContent = AIRT.relTime(v); });
    AIRT.$$("[data-countdown]").forEach(function (n) {
      var v = n.getAttribute("data-countdown"); if (!v) return;
      var txt = AIRT.countdown(v);
      n.textContent = txt;
      var d = AIRT.parseTs(v);
      n.classList.toggle("soon", !!d && d.getTime() - Date.now() < 60000);
    });
  }, 1000);

  /* ---------- badges ---------- */
  AIRT.badge = function (value, extraClass) {
    var v = String(value == null ? "" : value);
    return AIRT.el("span", { class: "badge " + v.toLowerCase().replace(/[^a-z0-9_-]/g, "") + " " + (extraClass || ""), text: v || "n/a" });
  };
  AIRT.riskBadge = function (level, score) {
    var b = AIRT.badge(level || "NONE");
    if (score != null) b.appendChild(AIRT.el("span", { class: "score", text: " " + score }));
    b.title = "Risk score " + (score == null ? "n/a" : score);
    return b;
  };
  AIRT.verdictBadge = function (v) { return v === "PENDING" ? AIRT.el("span", { class: "badge pending-verdict", text: "PENDING" }) : AIRT.badge(v); };

  /* ---------- SSE with auto reconnect ---------- */
  /* Uses fetch + a streaming text/event-stream parser instead of EventSource so that every event
     name is delivered (the logs and campaigns channels use open-ended event names). handlers is a
     map of event name to function(data, name); the key "*" receives every event. */
  AIRT.sse = function (url, handlers, opts) {
    opts = opts || {};
    handlers = handlers || {};
    var closed = false, delay = 1000, timer = null, controller = null;
    var state = { connected: false, paused: false };
    var setStatus = function (on) { if (state.connected === on) return; state.connected = on; if (opts.onStatus) opts.onStatus(on); };
    function dispatch(name, raw) {
      if (name === "ping") return;
      if (state.paused && !opts.deliverWhenPaused) return;
      var data = null;
      try { data = raw ? JSON.parse(raw) : null; } catch (e) { data = raw; }
      var fn = handlers[name] || handlers["*"];
      if (handlers[name] && handlers["*"] && handlers[name] !== handlers["*"]) { try { handlers["*"](data, name); } catch (e) { if (window.console) console.error(e); } }
      if (fn) { try { fn(data, name); } catch (e) { if (window.console) console.error(e); } }
    }
    function parseChunk(buf, onEvent) {
      var idx;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        var block = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        var name = "message", data = [];
        block.split("\n").forEach(function (line) {
          if (line.indexOf("event:") === 0) name = line.slice(6).trim();
          else if (line.indexOf("data:") === 0) data.push(line.slice(5).replace(/^ /, ""));
        });
        if (data.length) onEvent(name, data.join("\n"));
      }
      return buf;
    }
    function open() {
      if (closed) return;
      controller = typeof AbortController !== "undefined" ? new AbortController() : null;
      fetch(url, { headers: { "Accept": "text/event-stream" }, credentials: "same-origin", cache: "no-store", signal: controller ? controller.signal : undefined }).then(function (res) {
        if (res.status === 401) { closed = true; setStatus(false); return; }
        if (!res.ok || !res.body) throw new Error("stream " + res.status);
        setStatus(true);
        delay = 1000;
        var reader = res.body.getReader(), dec = new TextDecoder(), buf = "";
        function pump() {
          return reader.read().then(function (r) {
            if (r.done) throw new Error("stream closed");
            buf = parseChunk(buf + dec.decode(r.value, { stream: true }).replace(/\r\n/g, "\n"), dispatch);
            return pump();
          });
        }
        return pump();
      }).catch(function () {
        setStatus(false);
        schedule();
      });
    }
    function schedule() {
      if (closed) return;
      clearTimeout(timer);
      timer = setTimeout(open, delay);
      delay = Math.min(delay * 2, 15000);
    }
    open();
    return {
      close: function () { closed = true; clearTimeout(timer); if (controller) controller.abort(); setStatus(false); },
      pause: function () { state.paused = true; },
      resume: function () { state.paused = false; },
      get paused() { return state.paused; },
      get connected() { return state.connected; }
    };
  };
  AIRT.TICKET_EVENTS = ["created", "analyzed", "policy", "decided", "approved", "denied", "forwarding", "completed", "failed", "expired", "updated"];
  AIRT.LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"];
  /* Subscribe to every event on a channel. */
  AIRT.streamAll = function (url, onItem, opts) {
    return AIRT.sse(url, { "*": function (data, name) { onItem(name, data); } }, opts);
  };

  /* ---------- sound ---------- */
  AIRT.soundEnabled = function () {
    var v = null;
    try { v = localStorage.getItem("airt.sound"); } catch (e) {}
    if (v === "on") return true;
    if (v === "off") return false;
    return !(AIRT.ui && AIRT.ui.sound_on_new_ticket === false);
  };
  AIRT.setSound = function (on) { try { localStorage.setItem("airt.sound", on ? "on" : "off"); } catch (e) {} };
  AIRT.beep = function () {
    if (!AIRT.soundEnabled()) return;
    try {
      var Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      AIRT._audio = AIRT._audio || new Ctx();
      var ctx = AIRT._audio, o = ctx.createOscillator(), g = ctx.createGain();
      o.type = "sine"; o.frequency.value = 880;
      g.gain.setValueAtTime(0.0001, ctx.currentTime);
      g.gain.exponentialRampToValueAtTime(0.2, ctx.currentTime + 0.01);
      g.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.25);
      o.connect(g); g.connect(ctx.destination);
      o.start(); o.stop(ctx.currentTime + 0.26);
    } catch (e) {}
  };

  /* ---------- shared tickets stream + nav badge ---------- */
  var ticketListeners = [];
  AIRT.onTicketEvent = function (fn) { ticketListeners.push(fn); return function () { ticketListeners = ticketListeners.filter(function (f) { return f !== fn; }); }; };
  var badge = AIRT.$("#nav-pending");
  var conn = AIRT.$("#nav-conn");
  var statsTimer = null;
  AIRT.refreshPending = function () {
    clearTimeout(statsTimer);
    statsTimer = setTimeout(function () {
      AIRT.get("/api/tickets/stats").then(function (s) { AIRT.setPending(s.pending || 0); AIRT.lastStats = s; }).catch(function () {});
    }, 300);
  };
  AIRT.setPending = function (n) {
    if (!badge) return;
    badge.textContent = String(n);
    badge.classList.toggle("zero", !n);
    var base = document.title.replace(/^\(\d+\)\s*/, "");
    document.title = n ? "(" + n + ") " + base : base;
  };
  if (AIRT.principal) {
    AIRT.refreshPending();
    AIRT.ticketStream = AIRT.sse("/api/stream/tickets?replay=0", { "*": function (data, name) {
      AIRT.refreshPending();
      ticketListeners.forEach(function (fn) { try { fn(name, data); } catch (e) { if (window.console) console.error(e); } });
    } }, {
      onStatus: function (on) { if (conn) { conn.classList.toggle("on", on); conn.classList.toggle("off", !on); conn.title = on ? "Live stream connected" : "Live stream disconnected, reconnecting"; } }
    });
  }

  /* ---------- UI namespace (branding, theme, accent), applied on every page ---------- */
  AIRT.ui = {};
  try { AIRT.ui = JSON.parse(localStorage.getItem("airt.ui") || "{}") || {}; } catch (e) { AIRT.ui = {}; }
  function hexToRgb(hex) {
    var m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex || "");
    return m ? [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16)] : null;
  }
  function mix(rgb, target, amount) { return "#" + rgb.map(function (c) { return ("0" + Math.round(c + (target - c) * amount).toString(16)).slice(-2); }).join(""); }
  AIRT.applyUi = function (ui, preview) {
    ui = ui || {};
    if (!preview) { AIRT.ui = ui; try { localStorage.setItem("airt.ui", JSON.stringify(ui)); } catch (e) {} }
    var root = document.documentElement;
    var rgb = hexToRgb(ui.accent_color);
    if (rgb) {
      root.style.setProperty("--accent", ui.accent_color);
      root.style.setProperty("--accent-strong", mix(rgb, 255, 0.25));
      root.style.setProperty("--accent-bg", "rgba(" + rgb.join(",") + ",0.14)");
    } else { root.style.removeProperty("--accent"); root.style.removeProperty("--accent-strong"); root.style.removeProperty("--accent-bg"); }
    var brand = ui.brand_name || "Airt";
    AIRT.$$(".nav .brand, .login-card .brand span").forEach(function (n) { var last = n.lastChild; if (last && last.nodeType === 3) last.textContent = " " + brand; else if (n.tagName === "SPAN") n.textContent = brand; });
    if (ui.brand_name && ui.brand_name !== "Airt") document.title = document.title.replace(/ - [^-]+$/, " - " + brand);
    var local = null;
    try { local = localStorage.getItem("airt.theme"); } catch (e) {}
    var theme = local || ui.theme;
    if (theme === "dark" || theme === "light") root.setAttribute("data-theme", theme); else root.removeAttribute("data-theme");
  };
  AIRT.applyUi(AIRT.ui, true);
  if (AIRT.principal) AIRT.get("/api/settings/ns/ui").then(function (r) { AIRT.applyUi(Object.assign({}, r.defaults || {}, r.value || {}), false); }).catch(function () {});

  /* ---------- logout and theme ---------- */
  var logoutBtn = AIRT.$("#nav-logout");
  if (logoutBtn) logoutBtn.addEventListener("click", function () {
    AIRT.post("/api/auth/logout").catch(function () {}).then(function () { window.location.href = "/login"; });
  });
  var themeBtn = AIRT.$("#nav-theme");
  var applyTheme = function () { AIRT.applyUi(AIRT.ui, true); };
  if (themeBtn) themeBtn.addEventListener("click", function () {
    var cur = document.documentElement.getAttribute("data-theme");
    var dark = cur ? cur === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
    try { localStorage.setItem("airt.theme", dark ? "light" : "dark"); } catch (e) {}
    applyTheme();
  });

  /* ---------- misc helpers for pages ---------- */
  AIRT.jsonPre = function (obj) { return AIRT.el("pre", { text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 2) }); };
  AIRT.emptyRow = function (cols, text) { return AIRT.el("tr", null, AIRT.el("td", { colspan: cols, class: "empty", text: text || "Nothing here yet" })); };
  AIRT.link = function (href, text, cls) { return AIRT.el("a", { href: href, text: text, class: cls || "" }); };
  AIRT.download = function (filename, text, type) {
    var blob = new Blob([text], { type: type || "application/json" });
    var a = AIRT.el("a", { href: URL.createObjectURL(blob), download: filename });
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
  };
  AIRT.agentOptions = function (select, agents, opts) {
    opts = opts || {};
    AIRT.clear(select);
    if (opts.blank !== false) select.appendChild(AIRT.el("option", { value: "", text: opts.blankLabel || "All agents" }));
    agents.forEach(function (a) { select.appendChild(AIRT.el("option", { value: a.id, text: a.name + (a.is_active ? "" : " (disabled)") })); });
    if (opts.value) select.value = opts.value;
  };
  AIRT.agentMap = function (agents) { var m = {}; (agents || []).forEach(function (a) { m[a.id] = a; }); return m; };
  AIRT.debounce = function (fn, ms) { var t; return function () { var args = arguments, self = this; clearTimeout(t); t = setTimeout(function () { fn.apply(self, args); }, ms || 250); }; };
  AIRT.pager = function (container, total, limit, offset, onPage) {
    AIRT.clear(container);
    if (total <= limit) { if (total) container.appendChild(AIRT.el("span", { class: "hint", text: total + " total" })); return; }
    var page = Math.floor(offset / limit) + 1, pages = Math.ceil(total / limit);
    container.appendChild(AIRT.el("button", { class: "btn sm", text: "Prev", disabled: page <= 1, onclick: function () { onPage(Math.max(0, offset - limit)); } }));
    container.appendChild(AIRT.el("span", { class: "hint", text: "Page " + page + " of " + pages + " (" + total + " total)" }));
    container.appendChild(AIRT.el("button", { class: "btn sm", text: "Next", disabled: page >= pages, onclick: function () { onPage(offset + limit); } }));
  };
  AIRT.reportLinks = function (kindPath, formats) {
    var wrap = AIRT.el("div", { class: "chips" });
    (formats || AIRT.REPORT_FORMATS).forEach(function (f) {
      var inline = (f === "html" || f === "pdf") ? "&inline=1" : "";
      wrap.appendChild(AIRT.el("a", { class: "btn xs", href: "/api/reports/" + kindPath + "?format=" + f + inline, target: inline ? "_blank" : null, text: f }));
    });
    return wrap;
  };
  AIRT.REPORT_FORMATS = ["json", "yaml", "csv", "tsv", "md", "html", "pdf", "xlsx", "txt", "xml", "sarif", "junit"];

  /* ---------- boot page module ---------- */
  document.addEventListener("DOMContentLoaded", function () {
    var page = document.body.getAttribute("data-page");
    if (page && typeof AIRT.pages[page] === "function") {
      try { AIRT.pages[page](); } catch (e) { AIRT.fail(e); }
    }
  });
})();
/* Taxonomy helpers shared by the ticket and campaign pages. */
(function () {
  "use strict";
  var AIRT = window.AIRT;
  AIRT.taxonomy = null;
  AIRT.loadTaxonomy = function () {
    if (AIRT.taxonomy) return Promise.resolve(AIRT.taxonomy);
    return AIRT.get("/api/settings/taxonomy").then(function (t) { AIRT.taxonomy = t; return t; }).catch(function () { return null; });
  };
  /* Small chips for OWASP / Greshake / Thacker labels. Uses the labels on the object when present,
     otherwise falls back to the category map from the loaded taxonomy. */
  AIRT.taxonomyChips = function (obj) {
    obj = obj || {};
    var t = AIRT.taxonomy, names = {};
    (t && t.owasp || []).forEach(function (o) { names[o.id] = o; });
    var owasp = obj.owasp_labels, greshake = obj.greshake, thacker = obj.thacker;
    var m = t && t.category_map && obj.category ? t.category_map[obj.category] : null;
    if ((!owasp || !owasp.length) && m) owasp = m.owasp;
    if ((!greshake || !greshake.length) && m) greshake = m.greshake;
    if ((!thacker || !thacker.length) && m) thacker = m.thacker;
    var wrap = AIRT.el("div", { class: "chips" });
    (owasp || []).forEach(function (id) {
      var o = names[id];
      var chip = AIRT.el(o && o.url ? "a" : "span", { class: "chip owasp", text: id, title: o ? o.name + ": " + (o.description || "") : id, href: o && o.url ? o.url : null, target: o && o.url ? "_blank" : null, rel: "noopener" });
      wrap.appendChild(chip);
    });
    (greshake || []).forEach(function (x) { wrap.appendChild(AIRT.el("span", { class: "chip greshake", text: x, title: t && ((t.greshake_threats || {})[x] || (t.greshake_delivery || {})[x]) || "Greshake et al. threat" })); });
    (thacker || []).forEach(function (x) { wrap.appendChild(AIRT.el("span", { class: "chip thacker", text: x, title: t && (t.thacker_techniques || {})[x] || "Thacker technique" })); });
    return wrap.children.length ? wrap : null;
  };
})();
