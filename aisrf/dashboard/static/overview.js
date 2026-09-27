(function () {
  "use strict";
  var A = window.AISRF;
  A.pages.overview = function () {
    var agents = {};
    var LEVELS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
    var STATUSES = ["PENDING", "APPROVED", "FORWARDING", "COMPLETED", "DENIED", "EXPIRED", "FAILED"];
    function tile(label, value, sub, cls) {
      return A.el("div", { class: "tile " + (cls || "") }, [A.el("div", { class: "label", text: label }), A.el("div", { class: "value", text: value }), sub ? A.el("div", { class: "sub", text: sub }) : null]);
    }
    function dist(container, counts, keys, cssPrefix) {
      A.clear(container);
      var total = keys.reduce(function (n, k) { return n + (counts[k] || 0); }, 0);
      var bar = A.el("div", { class: "dist" });
      var legend = A.el("div", { class: "legend" });
      keys.forEach(function (k) {
        var c = counts[k] || 0;
        if (c) bar.appendChild(A.el("span", { class: cssPrefix + k.toLowerCase(), style: "width:" + (100 * c / total) + "%", title: k + ": " + c }));
        legend.appendChild(A.el("span", null, [A.el("i", { class: cssPrefix + k.toLowerCase() }), k + " " + c + (total ? " (" + Math.round(100 * c / total) + "%)" : "")]));
      });
      if (!total) container.appendChild(A.el("div", { class: "empty", text: "No tickets yet" }));
      else container.appendChild(bar);
      container.appendChild(legend);
    }
    var typesafe = null;
    function typesafeTile() {
      /* "TypeSafe savings" tile fed by GET /api/settings/typesafe/status, only while the integration is enabled */
      if (!typesafe || !typesafe.enabled) return null;
      var sv = typesafe.savings || {};
      var dollars = Number(sv.dollars_saved || 0);
      var value = "$" + (dollars >= 100 ? dollars.toFixed(0) : dollars >= 1 ? dollars.toFixed(2) : dollars.toFixed(4)) + " saved";
      var tokens = Number(sv.tokens_saved || 0);
      var sub = (typesafe.calls || 0) + " calls, " + (typesafe.cache_hits || 0) + " cached, " + (tokens >= 1000000 ? (tokens / 1000000).toFixed(1) + "M" : tokens >= 1000 ? (tokens / 1000).toFixed(1) + "k" : tokens) + " judge tokens avoided";
      return tile("TypeSafe savings", value, sub, typesafe.last_error ? "hot" : "ok");
    }
    function render(s) {
      var tiles = A.$("#tiles");
      A.clear(tiles);
      var ts = typesafeTile();
      if (ts) tiles.appendChild(ts);
      tiles.appendChild(tile("Pending review", s.pending || 0, "waiting for a decision", s.pending ? "hot" : "ok"));
      tiles.appendChild(tile("Total tickets", s.total || 0, "all time"));
      tiles.appendChild(tile("Denied", (s.by_status && s.by_status.DENIED) || 0, "blocked before upstream"));
      tiles.appendChild(tile("Last 24h", s.last_24h || 0, "intercepted requests"));
      tiles.appendChild(tile("Avg decision time", A.fmtSecs(s.avg_human_decision_seconds), "human reviewers"));
      tiles.appendChild(tile("Avg upstream latency", s.avg_upstream_latency_ms == null ? "n/a" : A.fmtMs(s.avg_upstream_latency_ms), "forwarded requests"));
      dist(A.$("#risk-dist"), s.by_risk_level || {}, LEVELS, "c-");
      dist(A.$("#status-dist"), s.by_status || {}, STATUSES, "c-status-");
      var rows = A.$("#agent-rows");
      A.clear(rows);
      var counts = {};
      (s.by_agent || []).forEach(function (r) { counts[r.agent_id] = r.count; });
      var ids = Object.keys(agents);
      if (!ids.length) rows.appendChild(A.emptyRow(4, "No agents registered"));
      ids.sort(function (a, b) { return (counts[b] || 0) - (counts[a] || 0); }).forEach(function (id) {
        var a = agents[id];
        rows.appendChild(A.el("tr", null, [
          A.el("td", null, A.link("/agents/" + id, a.name)),
          A.el("td", { class: "right num", text: counts[id] || 0 }),
          A.el("td", { class: "right num", text: a.request_count == null ? "" : a.request_count }),
          A.el("td", null, a.last_seen_at ? A.timeEl(a.last_seen_at) : A.el("span", { class: "faint", text: "never" }))
        ]));
      });
    }
    function statusStyle() {
      var css = ".c-status-pending{background:var(--warn)}.c-status-approved{background:var(--accent)}.c-status-forwarding{background:var(--info)}.c-status-completed{background:var(--ok)}.c-status-denied{background:var(--danger)}.c-status-expired{background:var(--none)}.c-status-failed{background:var(--crit)}";
      document.head.appendChild(A.el("style", { text: css }));
    }
    statusStyle();
    function loadStats() {
      return A.get("/api/settings/typesafe/status").catch(function () { return null; }).then(function (t) { typesafe = t; return A.get("/api/tickets/stats"); }).then(render).catch(A.fail);
    }
    function loadPending() {
      A.get("/api/tickets?status=PENDING&limit=8").then(function (r) {
        var box = A.$("#recent-pending");
        A.clear(box);
        if (!r.items.length) box.appendChild(A.el("div", { class: "empty", text: "Queue is empty" }));
        r.items.forEach(function (t) {
          box.appendChild(A.el("div", { class: "flex" }, [
            A.riskBadge(t.risk_level, t.risk_score),
            A.link("/tickets/" + t.id, "#" + (t.number || t.id.slice(-6))),
            A.el("span", { class: "truncate grow", text: t.prompt_preview || t.path, title: t.prompt_preview }),
            A.timeEl(t.created_at, { class: "faint small" })
          ]));
        });
      }).catch(A.fail);
    }
    A.get("/api/agents").then(function (list) { agents = A.agentMap(list); return loadStats(); }).then(loadPending);
    var feed = A.$("#feed");
    function feedItem(name, data) {
      var t = (data && data.ticket) || {};
      var item = A.el("div", { class: "item" }, [
        A.el("time", { text: A.fmtTime(data && data.ts) }),
        A.badge(name),
        A.link("/tickets/" + t.id, "#" + (t.number || (t.id || "").slice(-6))),
        A.el("span", { class: "faint", text: agents[t.agent_id] ? agents[t.agent_id].name : (t.agent_name || "") }),
        A.riskBadge(t.risk_level, t.risk_score),
        A.el("span", { class: "truncate grow", text: t.prompt_preview || t.path || "", title: t.prompt_preview })
      ]);
      feed.insertBefore(item, feed.firstChild);
      while (feed.children.length > 60) feed.removeChild(feed.lastChild);
    }
    A.get("/api/tickets?limit=15").then(function (r) {
      r.items.slice().reverse().forEach(function (t) { feedItem(t.status.toLowerCase(), { ts: t.updated_at || t.created_at, ticket: t }); });
    }).catch(function () {});
    var refresh = A.debounce(function () { loadStats(); loadPending(); }, 800);
    A.onTicketEvent(function (name, data) { feedItem(name, data); refresh(); });
    var every = Number((A.ui && A.ui.refresh_seconds) || 0);
    if (every > 0) setInterval(function () { if (!A.ticketStream || !A.ticketStream.connected) refresh(); }, every * 1000);
  };
})();
