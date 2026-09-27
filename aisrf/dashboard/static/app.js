/* AISRF dashboard core: API helper, DOM builder, toasts, relative time, SSE with reconnect. */
(function () {
  "use strict";
  var AISRF = window.AISRF = window.AISRF || {};
  AISRF.pages = {};
  AISRF.principal = null;
  try { AISRF.principal = JSON.parse(document.body.getAttribute("data-principal") || "null"); } catch (e) { AISRF.principal = null; }
  AISRF.isReviewer = function () { return !!AISRF.principal && (AISRF.principal.role === "reviewer" || AISRF.principal.role === "admin"); };
  AISRF.isAdmin = function () { return !!AISRF.principal && AISRF.principal.role === "admin"; };

  /* ---------- escaping and DOM ---------- */
  var ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  AISRF.escapeHtml = function (s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return ESC[c]; }); };
  AISRF.el = function (tag, attrs, children) {
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
    AISRF.append(node, children);
    return node;
  };
  AISRF.append = function (node, children) {
    if (children == null) return node;
    if (!Array.isArray(children)) children = [children];
    children.forEach(function (c) {
      if (c == null || c === false) return;
      if (typeof c === "string" || typeof c === "number") node.appendChild(document.createTextNode(String(c)));
      else node.appendChild(c);
    });
    return node;
  };
  AISRF.clear = function (node) { while (node.firstChild) node.removeChild(node.firstChild); return node; };
  AISRF.$ = function (sel, root) { return (root || document).querySelector(sel); };
  AISRF.$$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };
  AISRF.qs = function (params) {
    var parts = [];
    Object.keys(params || {}).forEach(function (k) {
      var v = params[k];
      if (v == null || v === "" || v === false) return;
      if (Array.isArray(v)) v.forEach(function (x) { parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(x)); });
      else parts.push(encodeURIComponent(k) + "=" + encodeURIComponent(v));
    });
    return parts.length ? "?" + parts.join("&") : "";
  };
  AISRF.param = function (name) { return new URLSearchParams(window.location.search).get(name); };

  /* ---------- API ---------- */
  AISRF.api = function (method, url, body, opts) {
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
  AISRF.get = function (url) { return AISRF.api("GET", url); };
  AISRF.post = function (url, body) { return AISRF.api("POST", url, body === undefined ? {} : body); };
  AISRF.patch = function (url, body) { return AISRF.api("PATCH", url, body); };
  AISRF.del = function (url) { return AISRF.api("DELETE", url); };

  /* ---------- toasts ---------- */
  var toastBox = null;
  AISRF.toast = function (msg, kind, ms) {
    if (!toastBox) { toastBox = AISRF.el("div", { class: "toasts", role: "status", "aria-live": "polite" }); document.body.appendChild(toastBox); }
    var t = AISRF.el("div", { class: "toast " + (kind || ""), text: msg });
    toastBox.appendChild(t);
    setTimeout(function () { if (t.parentNode) t.parentNode.removeChild(t); }, ms || 4200);
    return t;
  };
  AISRF.fail = function (err) { AISRF.toast(err && err.message ? err.message : String(err), "error", 6000); if (window.console) console.warn(err); };

  /* ---------- modal ---------- */
  AISRF.modal = function (title, body, buttons) {
    var backdrop = AISRF.el("div", { class: "modal-backdrop" });
    var box = AISRF.el("div", { class: "modal", role: "dialog", "aria-modal": "true" });
    if (title) box.appendChild(AISRF.el("h2", { text: title }));
    AISRF.append(box, body);
    var actions = AISRF.el("div", { class: "actions" });
    var close = function () { if (backdrop.parentNode) backdrop.parentNode.removeChild(backdrop); document.removeEventListener("keydown", onKey); };
    (buttons || [{ label: "Close" }]).forEach(function (b) {
      actions.appendChild(AISRF.el("button", { class: "btn " + (b.class || ""), text: b.label, onclick: function () { if (b.onClick) { var r = b.onClick(close); if (r === false) return; } if (!b.keepOpen) close(); } }));
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
  AISRF.promptNote = function (title, placeholder, confirmLabel, confirmClass) {
    return new Promise(function (resolve) {
      var ta = AISRF.el("textarea", { placeholder: placeholder || "Optional note for the audit trail", rows: 3 });
      var m = AISRF.modal(title, ta, [
        { label: "Cancel", onClick: function () { resolve(null); } },
        { label: confirmLabel || "Confirm", class: confirmClass || "primary", onClick: function () { resolve(ta.value); } }
      ]);
      ta.addEventListener("keydown", function (e) { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { resolve(ta.value); m.close(); } });
      ta.focus();
    });
  };
  AISRF.confirm = function (title, text, confirmLabel, confirmClass) {
    return new Promise(function (resolve) {
      AISRF.modal(title, AISRF.el("p", { text: text }), [
        { label: "Cancel", onClick: function () { resolve(false); } },
        { label: confirmLabel || "Confirm", class: confirmClass || "primary", onClick: function () { resolve(true); } }
      ]);
    });
  };
  AISRF.copy = function (text) {
    var done = function () { AISRF.toast("Copied to clipboard", "ok", 1800); };
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text).then(done, function () { fallback(); });
    fallback();
    function fallback() {
      var ta = AISRF.el("textarea", { style: "position:fixed;opacity:0", text: text });
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy"); done(); } catch (e) { AISRF.toast("Copy failed", "error"); }
      document.body.removeChild(ta);
    }
  };

  /* ---------- time ---------- */
  AISRF.parseTs = function (v) {
    if (v == null || v === "") return null;
    if (typeof v === "number") return new Date(v < 1e12 ? v * 1000 : v);
    var d = new Date(v);
    return isNaN(d.getTime()) ? null : d;
  };
  AISRF.relTime = function (v) {
    var d = AISRF.parseTs(v);
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
  AISRF.fmtTs = function (v) {
    var d = AISRF.parseTs(v);
    if (!d) return "";
    return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };
  AISRF.fmtTime = function (v) {
    var d = AISRF.parseTs(v);
    return d ? d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "";
  };
  AISRF.countdown = function (v) {
    var d = AISRF.parseTs(v);
    if (!d) return "";
    var left = Math.floor((d.getTime() - Date.now()) / 1000);
    if (left <= 0) return "expired";
    var m = Math.floor(left / 60), s = left % 60;
    return (m > 0 ? m + "m " : "") + (s < 10 && m > 0 ? "0" : "") + s + "s";
  };
  AISRF.fmtMs = function (v) { if (v == null) return ""; v = Number(v); return v >= 1000 ? (v / 1000).toFixed(2) + " s" : Math.round(v) + " ms"; };
  AISRF.fmtSecs = function (v) { if (v == null) return "n/a"; v = Number(v); if (v < 60) return v.toFixed(1) + " s"; if (v < 3600) return (v / 60).toFixed(1) + " min"; return (v / 3600).toFixed(1) + " h"; };
  AISRF.timeEl = function (v, opts) {
    opts = opts || {};
    var absolute = opts.absolute || (AISRF.ui && AISRF.ui.date_format === "absolute");
    return AISRF.el("time", { class: (absolute ? "abs " : "rel ") + (opts.class || ""), datetime: v || "", title: absolute ? AISRF.relTime(v) : AISRF.fmtTs(v), text: absolute ? AISRF.fmtTs(v) : AISRF.relTime(v) });
  };
  setInterval(function () {
    AISRF.$$("time.rel").forEach(function (t) { var v = t.getAttribute("datetime"); if (v) t.textContent = AISRF.relTime(v); });
    AISRF.$$("[data-countdown]").forEach(function (n) {
      var v = n.getAttribute("data-countdown"); if (!v) return;
      var txt = AISRF.countdown(v);
      n.textContent = txt;
      var d = AISRF.parseTs(v);
      n.classList.toggle("soon", !!d && d.getTime() - Date.now() < 60000);
    });
  }, 1000);

  /* ---------- badges ---------- */
  AISRF.badge = function (value, extraClass) {
    var v = String(value == null ? "" : value);
    return AISRF.el("span", { class: "badge " + v.toLowerCase().replace(/[^a-z0-9_-]/g, "") + " " + (extraClass || ""), text: v || "n/a" });
  };
  AISRF.riskBadge = function (level, score) {
    var b = AISRF.badge(level || "NONE");
    if (score != null) b.appendChild(AISRF.el("span", { class: "score", text: " " + score }));
    b.title = "Risk score " + (score == null ? "n/a" : score);
    return b;
  };
  AISRF.verdictBadge = function (v) { return v === "PENDING" ? AISRF.el("span", { class: "badge pending-verdict", text: "PENDING" }) : AISRF.badge(v); };

  /* ---------- SSE with auto reconnect ---------- */
  /* Uses fetch + a streaming text/event-stream parser instead of EventSource so that every event
     name is delivered (the logs and campaigns channels use open-ended event names). handlers is a
     map of event name to function(data, name); the key "*" receives every event. */
  AISRF.sse = function (url, handlers, opts) {
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
  AISRF.TICKET_EVENTS = ["created", "analyzed", "policy", "decided", "approved", "denied", "forwarding", "completed", "failed", "expired", "updated"];
  AISRF.LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"];
  /* Subscribe to every event on a channel. */
  AISRF.streamAll = function (url, onItem, opts) {
    return AISRF.sse(url, { "*": function (data, name) { onItem(name, data); } }, opts);
  };

  /* ---------- sound ---------- */
  AISRF.soundEnabled = function () {
    var v = null;
    try { v = localStorage.getItem("aisrf.sound"); } catch (e) {}
    if (v === "on") return true;
    if (v === "off") return false;
    return !(AISRF.ui && AISRF.ui.sound_on_new_ticket === false);
  };
  AISRF.setSound = function (on) { try { localStorage.setItem("aisrf.sound", on ? "on" : "off"); } catch (e) {} };
  AISRF.beep = function () {
    if (!AISRF.soundEnabled()) return;
    try {
      var Ctx = window.AudioContext || window.webkitAudioContext;
      if (!Ctx) return;
      AISRF._audio = AISRF._audio || new Ctx();
      var ctx = AISRF._audio, o = ctx.createOscillator(), g = ctx.createGain();
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
  AISRF.onTicketEvent = function (fn) { ticketListeners.push(fn); return function () { ticketListeners = ticketListeners.filter(function (f) { return f !== fn; }); }; };
  var badge = AISRF.$("#nav-pending");
  var conn = AISRF.$("#nav-conn");
  var statsTimer = null;
  AISRF.refreshPending = function () {
    clearTimeout(statsTimer);
    statsTimer = setTimeout(function () {
      AISRF.get("/api/tickets/stats").then(function (s) { AISRF.setPending(s.pending || 0); AISRF.lastStats = s; }).catch(function () {});
    }, 300);
  };
  AISRF.setPending = function (n) {
    if (!badge) return;
    badge.textContent = String(n);
    badge.classList.toggle("zero", !n);
    var base = document.title.replace(/^\(\d+\)\s*/, "");
    document.title = n ? "(" + n + ") " + base : base;
  };
  if (AISRF.principal) {
    AISRF.refreshPending();
    AISRF.ticketStream = AISRF.sse("/api/stream/tickets?replay=0", { "*": function (data, name) {
      AISRF.refreshPending();
      ticketListeners.forEach(function (fn) { try { fn(name, data); } catch (e) { if (window.console) console.error(e); } });
    } }, {
      onStatus: function (on) { if (conn) { conn.classList.toggle("on", on); conn.classList.toggle("off", !on); conn.title = on ? "Live stream connected" : "Live stream disconnected, reconnecting"; } }
    });
  }

  /* ---------- UI namespace (branding, theme, accent), applied on every page ---------- */
  AISRF.ui = {};
  try { AISRF.ui = JSON.parse(localStorage.getItem("aisrf.ui") || "{}") || {}; } catch (e) { AISRF.ui = {}; }
  function hexToRgb(hex) {
    var m = /^#?([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(hex || "");
    return m ? [parseInt(m[1], 16), parseInt(m[2], 16), parseInt(m[3], 16)] : null;
  }
  function mix(rgb, target, amount) { return "#" + rgb.map(function (c) { return ("0" + Math.round(c + (target - c) * amount).toString(16)).slice(-2); }).join(""); }
  AISRF.applyUi = function (ui, preview) {
    ui = ui || {};
    if (!preview) { AISRF.ui = ui; try { localStorage.setItem("aisrf.ui", JSON.stringify(ui)); } catch (e) {} }
    var root = document.documentElement;
    var rgb = hexToRgb(ui.accent_color);
    if (rgb) {
      root.style.setProperty("--accent", ui.accent_color);
      root.style.setProperty("--accent-strong", mix(rgb, 255, 0.25));
      root.style.setProperty("--accent-bg", "rgba(" + rgb.join(",") + ",0.14)");
    } else { root.style.removeProperty("--accent"); root.style.removeProperty("--accent-strong"); root.style.removeProperty("--accent-bg"); }
    var brand = ui.brand_name || "AISRF";
    AISRF.$$(".brand .brand-name, .login-card .brand > span").forEach(function (n) { n.textContent = brand; });
    if (ui.brand_name && ui.brand_name !== "AISRF") document.title = document.title.replace(/ - [^-]+$/, " - " + brand);
    var local = null;
    try { local = localStorage.getItem("aisrf.theme"); } catch (e) {}
    var theme = local || ui.theme;
    if (theme === "dark" || theme === "light") root.setAttribute("data-theme", theme); else root.removeAttribute("data-theme");
  };
  AISRF.applyUi(AISRF.ui, true);
  if (AISRF.principal) AISRF.get("/api/settings/ns/ui").then(function (r) { AISRF.applyUi(Object.assign({}, r.defaults || {}, r.value || {}), false); }).catch(function () {});

  /* ---------- logout and theme ---------- */
  var logoutBtn = AISRF.$("#nav-logout");
  if (logoutBtn) logoutBtn.addEventListener("click", function () {
    AISRF.post("/api/auth/logout").catch(function () {}).then(function () { window.location.href = "/login"; });
  });
  var themeBtn = AISRF.$("#nav-theme");
  var applyTheme = function () { AISRF.applyUi(AISRF.ui, true); };
  if (themeBtn) themeBtn.addEventListener("click", function () {
    var cur = document.documentElement.getAttribute("data-theme");
    var dark = cur ? cur === "dark" : window.matchMedia("(prefers-color-scheme: dark)").matches;
    try { localStorage.setItem("aisrf.theme", dark ? "light" : "dark"); } catch (e) {}
    applyTheme();
  });

  /* ---------- misc helpers for pages ---------- */
  AISRF.jsonPre = function (obj) { return AISRF.el("pre", { text: typeof obj === "string" ? obj : JSON.stringify(obj, null, 2) }); };
  AISRF.emptyRow = function (cols, text) { return AISRF.el("tr", null, AISRF.el("td", { colspan: cols, class: "empty", text: text || "Nothing here yet" })); };
  AISRF.link = function (href, text, cls) { return AISRF.el("a", { href: href, text: text, class: cls || "" }); };
  AISRF.download = function (filename, text, type) {
    var blob = new Blob([text], { type: type || "application/json" });
    var a = AISRF.el("a", { href: URL.createObjectURL(blob), download: filename });
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 2000);
  };
  AISRF.agentOptions = function (select, agents, opts) {
    opts = opts || {};
    AISRF.clear(select);
    if (opts.blank !== false) select.appendChild(AISRF.el("option", { value: "", text: opts.blankLabel || "All agents" }));
    agents.forEach(function (a) { select.appendChild(AISRF.el("option", { value: a.id, text: a.name + (a.is_active ? "" : " (disabled)") })); });
    if (opts.value) select.value = opts.value;
  };
  AISRF.agentMap = function (agents) { var m = {}; (agents || []).forEach(function (a) { m[a.id] = a; }); return m; };
  AISRF.debounce = function (fn, ms) { var t; return function () { var args = arguments, self = this; clearTimeout(t); t = setTimeout(function () { fn.apply(self, args); }, ms || 250); }; };
  AISRF.pager = function (container, total, limit, offset, onPage) {
    AISRF.clear(container);
    if (total <= limit) { if (total) container.appendChild(AISRF.el("span", { class: "hint", text: total + " total" })); return; }
    var page = Math.floor(offset / limit) + 1, pages = Math.ceil(total / limit);
    container.appendChild(AISRF.el("button", { class: "btn sm", text: "Prev", disabled: page <= 1, onclick: function () { onPage(Math.max(0, offset - limit)); } }));
    container.appendChild(AISRF.el("span", { class: "hint", text: "Page " + page + " of " + pages + " (" + total + " total)" }));
    container.appendChild(AISRF.el("button", { class: "btn sm", text: "Next", disabled: page >= pages, onclick: function () { onPage(offset + limit); } }));
  };
  AISRF.reportLinks = function (kindPath, formats) {
    var wrap = AISRF.el("div", { class: "chips" });
    (formats || AISRF.REPORT_FORMATS).forEach(function (f) {
      var inline = (f === "html" || f === "pdf") ? "&inline=1" : "";
      wrap.appendChild(AISRF.el("a", { class: "btn xs", href: "/api/reports/" + kindPath + "?format=" + f + inline, target: inline ? "_blank" : null, text: f }));
    });
    return wrap;
  };
  AISRF.REPORT_FORMATS = ["json", "yaml", "csv", "tsv", "md", "html", "pdf", "xlsx", "txt", "xml", "sarif", "junit"];

  /* ---------- boot page module ---------- */
  document.addEventListener("DOMContentLoaded", function () {
    var page = document.body.getAttribute("data-page");
    if (page && typeof AISRF.pages[page] === "function") {
      try { AISRF.pages[page](); } catch (e) { AISRF.fail(e); }
    }
  });
})();
/* Taxonomy helpers shared by the ticket and campaign pages. */
(function () {
  "use strict";
  var AISRF = window.AISRF;
  AISRF.taxonomy = null;
  AISRF.loadTaxonomy = function () {
    if (AISRF.taxonomy) return Promise.resolve(AISRF.taxonomy);
    return AISRF.get("/api/settings/taxonomy").then(function (t) { AISRF.taxonomy = t; return t; }).catch(function () { return null; });
  };
  /* Small chips for OWASP / Greshake / Thacker labels. Uses the labels on the object when present,
     otherwise falls back to the category map from the loaded taxonomy. */
  AISRF.taxonomyChips = function (obj) {
    obj = obj || {};
    var t = AISRF.taxonomy, names = {};
    (t && t.owasp || []).forEach(function (o) { names[o.id] = o; });
    var owasp = obj.owasp_labels, greshake = obj.greshake, thacker = obj.thacker;
    var m = t && t.category_map && obj.category ? t.category_map[obj.category] : null;
    if ((!owasp || !owasp.length) && m) owasp = m.owasp;
    if ((!greshake || !greshake.length) && m) greshake = m.greshake;
    if ((!thacker || !thacker.length) && m) thacker = m.thacker;
    var wrap = AISRF.el("div", { class: "chips" });
    (owasp || []).forEach(function (id) {
      var o = names[id];
      var chip = AISRF.el(o && o.url ? "a" : "span", { class: "chip owasp", text: id, title: o ? o.name + ": " + (o.description || "") : id, href: o && o.url ? o.url : null, target: o && o.url ? "_blank" : null, rel: "noopener" });
      wrap.appendChild(chip);
    });
    (greshake || []).forEach(function (x) { wrap.appendChild(AISRF.el("span", { class: "chip greshake", text: x, title: t && ((t.greshake_threats || {})[x] || (t.greshake_delivery || {})[x]) || "Greshake et al. threat" })); });
    (thacker || []).forEach(function (x) { wrap.appendChild(AISRF.el("span", { class: "chip thacker", text: x, title: t && (t.thacker_techniques || {})[x] || "Thacker technique" })); });
    return wrap.children.length ? wrap : null;
  };
})();
