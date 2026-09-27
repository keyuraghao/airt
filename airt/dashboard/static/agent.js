(function () {
  "use strict";
  var A = window.AIRT;
  A.logLine = function (rec, agents) {
    var known = { ts: 1, agent_id: 1, level: 1, event: 1, ticket_id: 1, correlation_id: 1, id: 1 };
    var detail = rec.detail && typeof rec.detail === "object" ? rec.detail : {};
    Object.keys(rec).forEach(function (k) { if (!known[k]) detail[k] = rec[k]; });
    var dtext = Object.keys(detail).map(function (k) { var v = detail[k]; return k + "=" + (typeof v === "object" ? JSON.stringify(v) : String(v)); }).join(" ");
    var level = String(rec.level || "INFO").toUpperCase();
    var agentName = agents && agents[rec.agent_id] ? agents[rec.agent_id].name : (rec.agent_id || "");
    return A.el("div", { class: "log-line " + level }, [
      A.el("span", { class: "faint", text: A.fmtTs(rec.ts) }),
      A.el("span", { class: "lvl", text: level }),
      A.el("a", { href: "/agents/" + encodeURIComponent(rec.agent_id || ""), class: "truncate", text: agentName, title: rec.agent_id || "" }),
      A.el("span", null, [A.el("strong", { text: rec.event || "" }), rec.ticket_id ? A.el("a", { href: "/tickets/" + rec.ticket_id, class: "small", text: " " + rec.ticket_id.slice(0, 12), title: rec.ticket_id }) : null]),
      A.el("span", { class: "detail", text: dtext })
    ]);
  };
  A.logConsole = function (view, opts) {
    opts = opts || {};
    var buffer = [], max = opts.max || 2000, paused = false, filter = opts.filter || function () { return true; };
    var follow = function () { return opts.follow ? opts.follow() : true; };
    function push(rec, prepend) {
      buffer.push(rec);
      if (buffer.length > max) buffer.shift();
      if (!filter(rec)) return;
      var line = A.logLine(rec, opts.agents);
      if (prepend) view.insertBefore(line, view.firstChild); else view.appendChild(line);
      while (view.children.length > max) view.removeChild(view.firstChild);
      if (!prepend && follow()) view.scrollTop = view.scrollHeight;
    }
    function rerender() {
      A.clear(view);
      buffer.filter(filter).forEach(function (r) { view.appendChild(A.logLine(r, opts.agents)); });
      view.scrollTop = view.scrollHeight;
    }
    return {
      push: push,
      rerender: rerender,
      setFilter: function (f) { filter = f; rerender(); },
      clear: function () { buffer = []; A.clear(view); },
      buffer: function () { return buffer; },
      download: function (name) { A.download(name || "airt-logs.json", JSON.stringify(buffer.filter(filter), null, 2)); }
    };
  };
  A.pages.agent = function () {
    var id = document.body.getAttribute("data-agent-id");
    var form = A.$("#agent-form"), agent = null, isAdmin = A.isAdmin();
    if (!isAdmin) { A.$$("#agent-form input, #agent-form select, #agent-form textarea, #agent-form button").forEach(function (n) { n.disabled = true; }); A.$("#rotate-btn").disabled = true; A.$("#disable-btn").disabled = true; A.$("#save-hint").textContent = "admin role required to edit"; }
    function tile(label, value, cls) { return A.el("div", { class: "tile " + (cls || "") }, [A.el("div", { class: "label", text: label }), A.el("div", { class: "value", text: value })]); }
    function render(a) {
      agent = a;
      document.title = a.name + " - AIRT";
      A.$("#title").textContent = a.name;
      var hb = A.$("#head-badges");
      A.clear(hb);
      hb.appendChild(a.is_active ? A.badge("active", "ok") : A.badge("disabled", "expired"));
      hb.appendChild(A.badge(a.upstream_provider, "accent"));
      (a.tags || []).forEach(function (t) { hb.appendChild(A.el("span", { class: "chip", text: t })); });
      A.$("#disable-btn").classList.toggle("hidden", !a.is_active);
      A.$("#enable-btn").classList.toggle("hidden", a.is_active || !isAdmin);
      var rl = A.$("#report-links");
      A.clear(rl);
      rl.appendChild(A.el("a", { class: "btn sm", href: "/api/reports/agent/" + encodeURIComponent(a.id) + "?format=html&inline=1", target: "_blank", text: "Report" }));
      var st = a.stats || {}, bs = st.by_status || {};
      var tiles = A.$("#tiles");
      A.clear(tiles);
      tiles.appendChild(tile("Requests", a.request_count == null ? "0" : a.request_count));
      tiles.appendChild(tile("Tickets", st.total || 0));
      tiles.appendChild(tile("Pending", bs.PENDING || 0, bs.PENDING ? "hot" : ""));
      tiles.appendChild(tile("Completed", bs.COMPLETED || 0, "ok"));
      tiles.appendChild(tile("Denied", bs.DENIED || 0));
      tiles.appendChild(tile("Avg risk", st.avg_risk == null ? "0" : st.avg_risk));
      var idn = A.$("#identity");
      A.clear(idn);
      [["Id", a.id, "mono small"], ["Key prefix", a.api_key_prefix + "...", "mono"], ["Owner", a.owner], ["Upstream key", a.has_upstream_key ? "stored (encrypted)" : "none, client must send its own"], ["Created", A.fmtTs(a.created_at)], ["Last seen", a.last_seen_at ? A.fmtTs(a.last_seen_at) : "never"]].forEach(function (p) {
        if (p[1] == null || p[1] === "") return;
        idn.appendChild(A.el("dt", { text: p[0] })); idn.appendChild(A.el("dd", { class: p[2] || "", text: p[1] }));
      });
      var sn = A.$("#snippets");
      A.clear(sn);
      sn.appendChild(A.snippetPanel(null));
      var set = function (name, v) { var n = form.querySelector("[name=" + name + "]"); if (!n) return; if (n.type === "checkbox") n.checked = !!v; else n.value = v == null ? "" : v; };
      set("name", a.name); set("owner", a.owner); set("description", a.description); set("tags", (a.tags || []).join(", "));
      set("upstream_provider", a.upstream_provider); set("upstream_base_url", a.upstream_base_url); set("upstream_auth_header", a.upstream_auth_header);
      set("upstream_extra_headers", Object.keys(a.upstream_extra_headers || {}).length ? JSON.stringify(a.upstream_extra_headers) : "");
      set("auto_approve_below_risk", a.auto_approve_below_risk); set("auto_deny_at_risk", a.auto_deny_at_risk);
      set("auto_deny_patterns", (a.auto_deny_patterns || []).join("\n")); set("allowed_paths", (a.allowed_paths || []).join("\n")); set("allowed_models", (a.allowed_models || []).join("\n"));
      set("rate_limit_per_minute", a.rate_limit_per_minute); set("require_approval", a.require_approval);
      A.$("#all-tickets-link").href = "/tickets?status=&agent_id=" + encodeURIComponent(a.id);
    }
    function load() { return A.get("/api/agents/" + encodeURIComponent(id)).then(render).catch(A.fail); }
    function loadTickets() {
      A.get("/api/tickets?agent_id=" + encodeURIComponent(id) + "&limit=15").then(function (r) {
        var rows = A.$("#ticket-rows");
        A.clear(rows);
        if (!r.items.length) rows.appendChild(A.emptyRow(6, "No tickets from this agent"));
        r.items.forEach(function (t) {
          rows.appendChild(A.el("tr", null, [
            A.el("td", null, A.link("/tickets/" + t.id, "#" + (t.number || t.id.slice(-6)))),
            A.el("td", null, A.timeEl(t.created_at)),
            A.el("td", { class: "mono small", text: t.model || "" }),
            A.el("td", { class: "mono small truncate", text: t.path || "" }),
            A.el("td", null, A.riskBadge(t.risk_level, t.risk_score)),
            A.el("td", null, A.badge(t.status))
          ]));
        });
      }).catch(A.fail);
    }
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var payload;
      try { payload = A.listsFromForm(form); } catch (ex) { A.fail(ex); return; }
      if (!payload.upstream_api_key) delete payload.upstream_api_key;
      if (!payload.upstream_base_url) delete payload.upstream_base_url;
      A.patch("/api/agents/" + encodeURIComponent(id), payload).then(function (a) { A.toast("Agent updated", "ok"); form.querySelector("[name=upstream_api_key]").value = ""; return load(); }).catch(A.fail);
    });
    A.$("#rotate-btn").addEventListener("click", function () {
      A.confirm("Rotate API key", "The current key stops working immediately. Continue?", "Rotate", "danger").then(function (ok) {
        if (!ok) return;
        A.post("/api/agents/" + encodeURIComponent(id) + "/rotate-key").then(function (r) { A.showKeyModal(agent, r.api_key, "New API key for " + agent.name); load(); }).catch(A.fail);
      });
    });
    A.$("#disable-btn").addEventListener("click", function () {
      A.confirm("Disable agent", "Requests with this agent's key will be rejected. Continue?", "Disable", "danger").then(function (ok) {
        if (!ok) return;
        A.del("/api/agents/" + encodeURIComponent(id)).then(function () { A.toast("Agent disabled", "warn"); load(); }).catch(A.fail);
      });
    });
    A.$("#enable-btn").addEventListener("click", function () {
      A.patch("/api/agents/" + encodeURIComponent(id), { is_active: true }).then(function () { A.toast("Agent enabled", "ok"); load(); }).catch(A.fail);
    });
    load().then(loadTickets);
    A.onTicketEvent(function (name, data) { if (data && data.ticket && data.ticket.agent_id === id) { loadTickets(); if (name === "created" || name === "completed") load(); } });
    /* live log */
    var view = A.$("#log-view"), levelSel = A.$("#log-level"), status = A.$("#log-status");
    var LEVEL_RANK = { DEBUG: 0, INFO: 1, WARNING: 2, ERROR: 3, CRITICAL: 4 };
    var con = A.logConsole(view, { filter: function (r) { var min = levelSel.value; return !min || (LEVEL_RANK[String(r.level).toUpperCase()] || 0) >= LEVEL_RANK[min]; } });
    levelSel.addEventListener("change", function () { con.rerender(); });
    var stream = A.streamAll("/api/stream/logs?agent_id=" + encodeURIComponent(id) + "&replay=50", function (name, rec) { if (rec && rec.agent_id === id) con.push(rec); }, { onStatus: function (on) { status.textContent = on ? "live" : "reconnecting"; } });
    var pauseBtn = A.$("#log-pause");
    pauseBtn.addEventListener("click", function () { if (stream.paused) { stream.resume(); pauseBtn.textContent = "Pause"; } else { stream.pause(); pauseBtn.textContent = "Resume"; } });
    A.$("#log-clear").addEventListener("click", con.clear);
    A.$("#log-download").addEventListener("click", function () { con.download("airt-agent-" + id + ".json"); });
    A.$("#log-history").addEventListener("click", function () {
      A.get("/api/agents/" + encodeURIComponent(id) + "/events?limit=300" + (levelSel.value ? "&level=" + levelSel.value : "")).then(function (list) {
        con.clear();
        list.slice().reverse().forEach(function (r) { con.push(r); });
        A.toast("Loaded " + list.length + " historical events", "ok", 2000);
      }).catch(A.fail);
    });
  };
})();
