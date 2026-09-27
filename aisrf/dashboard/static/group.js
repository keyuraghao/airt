(function () {
  "use strict";
  var A = window.AISRF;
  A.pages.group = function () {
    var id = document.body.getAttribute("data-group-id");
    var group = null, agents = {}, results = {};
    var VERDICTS = ["VULNERABLE", "RESISTED", "BLOCKED", "INCONCLUSIVE", "ERROR", "PENDING"];
    function pct(r) { r = Number(r || 0); return Math.round(r * (r <= 1 ? 100 : 1)); }
    function heatColor(rate, tested) {
      if (!tested) return "";
      var p = Math.max(0, Math.min(1, Number(rate || 0)));
      var h = Math.round(120 - 120 * p);
      return "hsl(" + h + " 60% 38%)";
    }
    function label(cid) { var c = campaignById(cid); return (group.labels && group.labels[cid]) || (c && (c.target_label || c.target_model || c.name)) || cid; }
    function campaignById(cid) { var out = null; (group.campaigns || []).forEach(function (c) { if (c.id === cid) out = c; }); return out; }
    function ids() { return group.ranking && group.ranking.length ? group.ranking : (group.campaigns || []).map(function (c) { return c.id; }); }
    function render(g) {
      group = g;
      document.title = (g.name || "Comparison") + " - AISRF";
      A.$("#title").textContent = g.name || "Comparison group";
      var hb = A.$("#head-badges");
      A.clear(hb);
      var statuses = {};
      (g.campaigns || []).forEach(function (c) { statuses[c.status] = (statuses[c.status] || 0) + 1; });
      Object.keys(statuses).sort().forEach(function (k) { var b = A.badge(k); b.appendChild(A.el("span", { text: " " + statuses[k] })); hb.appendChild(b); });
      hb.appendChild(A.el("span", { class: "chip mono", text: g.group_id }));
      renderControls(statuses);
      renderPodium();
      renderTargets();
      renderHeatmap();
      renderCoverage();
      renderMatrix();
    }
    function renderControls(statuses) {
      var box = A.$("#controls");
      A.clear(box);
      box.appendChild(A.el("button", { class: "btn sm", text: "Download comparison JSON", onclick: function () { A.download("aisrf-comparison-" + id + ".json", JSON.stringify(group, null, 2)); } }));
      if (!A.isReviewer()) return;
      var running = (statuses.RUNNING || 0) > 0, startable = (statuses.CREATED || 0) + (statuses.PAUSED || 0) > 0;
      var act = function (action, cls, confirmText) {
        return A.el("button", { class: "btn sm " + cls, text: action.charAt(0).toUpperCase() + action.slice(1), onclick: function () {
          var go = confirmText ? A.confirm(action + " group", confirmText, action, cls === "danger" ? "danger" : "primary") : Promise.resolve(true);
          go.then(function (ok) {
            if (!ok) return;
            if (action === "delete") return A.del("/api/redteam/groups/" + encodeURIComponent(id)).then(function () { A.toast("Group deleted", "ok"); window.location.href = "/redteam"; });
            return A.post("/api/redteam/groups/" + encodeURIComponent(id) + "/" + action).then(function (r) { A.toast("Group " + action + " requested", "ok"); if (r && r.campaigns) render(r); else load(); });
          }).catch(A.fail);
        } });
      };
      if (startable) box.appendChild(act("start", "ok"));
      if (running) box.appendChild(act("cancel", "danger", "Stop every running campaign in this group?"));
      if (!running) box.appendChild(act("delete", "danger", "Delete every campaign in this group and all of their results?"));
    }
    function renderPodium() {
      var box = A.$("#podium");
      A.clear(box);
      var order = ids();
      if (!order.length) { box.appendChild(A.el("div", { class: "empty", text: "No campaigns in this group" })); return; }
      order.forEach(function (cid, i) {
        var score = (group.weighted_scores || {})[cid], rate = (group.vulnerability_rates || {})[cid];
        var c = campaignById(cid) || {};
        box.appendChild(A.el("a", { class: "place " + (i === 0 ? "first" : "") + (i === order.length - 1 && order.length > 1 ? " last" : ""), href: "/redteam/" + cid, style: "text-decoration:none;color:inherit" }, [
          A.el("div", { class: "rank", text: "#" + (i + 1) }),
          A.el("div", { class: "truncate", title: label(cid) }, A.el("strong", { text: label(cid) })),
          A.el("div", { class: "hint mono truncate", text: c.target_model || "" }),
          A.el("div", { class: "score", text: score == null ? "n/a" : Number(score).toFixed(1) }),
          A.el("div", { class: "small muted", text: "weighted score, " + (rate == null ? "n/a" : pct(rate) + "% vulnerable") }),
          A.el("div", { class: "mt" }, A.badge(c.status || ""))
        ]));
      });
    }
    function stackBar(totals) {
      var sum = VERDICTS.reduce(function (n, k) { return n + (totals[k] || 0); }, 0);
      var bar = A.el("div", { class: "stack-bar", title: VERDICTS.map(function (k) { return k + " " + (totals[k] || 0); }).join(", ") });
      if (!sum) return bar;
      VERDICTS.forEach(function (k) { var n = totals[k] || 0; if (n) bar.appendChild(A.el("span", { class: "c-" + k.toLowerCase(), style: "width:" + (100 * n / sum) + "%", title: k + ": " + n })); });
      return bar;
    }
    function renderTargets() {
      var rows = A.$("#target-rows");
      A.clear(rows);
      var done = 0, total = 0;
      (group.campaigns || []).forEach(function (c) {
        done += c.completed_probes || 0; total += c.total_probes || 0;
        var p = c.total_probes ? Math.round(100 * (c.completed_probes || 0) / c.total_probes) : 0;
        var score = (group.weighted_scores || {})[c.id], rate = (group.vulnerability_rates || {})[c.id];
        rows.appendChild(A.el("tr", { dataset: { id: c.id } }, [
          A.el("td", null, A.link("/redteam/" + c.id, label(c.id))),
          A.el("td", null, agents[c.agent_id] ? A.link("/agents/" + c.agent_id, agents[c.agent_id].name) : A.el("span", { text: c.agent_name || c.agent_id || "" })),
          A.el("td", { class: "mono small", text: c.target_model || "" }),
          A.el("td", null, A.badge(c.status)),
          A.el("td", { style: "min-width:150px" }, A.el("div", { class: "flex" }, [A.el("div", { class: "progress grow " + (c.status === "COMPLETED" ? "ok" : c.status === "FAILED" ? "danger" : "") }, A.el("span", { style: "width:" + p + "%" })), A.el("span", { class: "hint nowrap", text: (c.completed_probes || 0) + "/" + (c.total_probes || 0) })])),
          A.el("td", null, stackBar((group.verdict_totals || {})[c.id] || {})),
          A.el("td", { class: "num", text: score == null ? "" : Number(score).toFixed(1) }),
          A.el("td", { class: "num", text: rate == null ? "" : pct(rate) + "%" }),
          A.el("td", null, A.reportLinks("campaign/" + encodeURIComponent(c.id), ["json", "html", "pdf", "csv", "sarif"]))
        ]));
      });
      if (!(group.campaigns || []).length) rows.appendChild(A.emptyRow(9, "No campaigns"));
      A.$("#progress-hint").textContent = total ? done + " / " + total + " probes across " + (group.campaigns || []).length + " targets" : "";
    }
    function renderHeatmap() {
      var table = A.$("#heatmap"), thead = table.tHead, tbody = table.tBodies[0];
      A.clear(thead); A.clear(tbody);
      var order = ids(), cats = Object.keys(group.matrix || {}).sort();
      thead.appendChild(A.el("tr", null, [A.el("th", { text: "Category" })].concat(order.map(function (cid) { return A.el("th", { class: "col" }, A.link("/redteam/" + cid, label(cid))); }))));
      if (!cats.length) { tbody.appendChild(A.emptyRow(order.length + 1, "No results yet")); return; }
      cats.forEach(function (cat) {
        var row = A.el("tr", null, A.el("td", { class: "mono small" }, [cat, A.taxonomyChips({ category: cat })]));
        order.forEach(function (cid) {
          var cell = (group.matrix[cat] || {})[cid] || { vulnerable: 0, total: 0, tested: 0, rate: 0 };
          var td = A.el("td", { class: "cell " + (cell.tested ? "" : "untested"), style: cell.tested ? "background:" + heatColor(cell.rate, cell.tested) : "", title: cat + " on " + label(cid) + ": " + cell.vulnerable + " vulnerable of " + cell.tested + " tested (" + cell.total + " probes)" }, [A.el("div", null, A.el("strong", { text: cell.tested ? pct(cell.rate) + "%" : "-" })), A.el("div", { class: "small", text: cell.vulnerable + "/" + cell.tested })]);
          row.appendChild(td);
        });
        tbody.appendChild(row);
      });
    }
    function renderCoverage() {
      var box = A.$("#coverage");
      A.clear(box);
      var cov = group.owasp_coverage || {};
      Object.keys(cov).sort().forEach(function (oid) {
        var e = cov[oid] || {};
        box.appendChild(A.el("span", { class: "chip " + (e.covered ? "covered" : "uncovered"), text: oid + " " + (e.name || ""), title: e.covered ? "covered by: " + (e.categories || []).join(", ") : "not exercised by this probe set" }));
      });
      if (!Object.keys(cov).length) box.appendChild(A.el("span", { class: "hint", text: "No coverage data" }));
    }
    function renderMatrix() {
      var table = A.$("#matrix"), thead = table.tHead, tbody = table.tBodies[0];
      A.clear(thead); A.clear(tbody);
      var order = ids();
      var catSel = A.$("#m-category");
      var cats = {};
      (group.per_probe || []).forEach(function (p) { cats[p.category] = 1; });
      var current = catSel.value;
      A.clear(catSel);
      catSel.appendChild(A.el("option", { value: "", text: "All categories" }));
      Object.keys(cats).sort().forEach(function (c) { catSel.appendChild(A.el("option", { value: c, text: c })); });
      catSel.value = current;
      thead.appendChild(A.el("tr", null, [A.el("th", { text: "" }), A.el("th", { text: "Probe" }), A.el("th", { text: "Category" }), A.el("th", { text: "Severity" })].concat(order.map(function (cid) { return A.el("th", { class: "col", text: label(cid) }); }))));
      var onlyDiff = A.$("#m-differs").checked, shown = 0;
      (group.per_probe || []).forEach(function (p) {
        if (catSel.value && p.category !== catSel.value) return;
        var verdicts = order.map(function (cid) { return (p.verdicts || {})[cid] || "PENDING"; });
        var differs = verdicts.some(function (v) { return v !== verdicts[0]; });
        if (onlyDiff && !differs) return;
        shown += 1;
        var detail = A.el("tr", { class: "expand-row hidden" }, A.el("td", { colspan: order.length + 4 }));
        var toggle = A.el("button", { class: "btn xs", text: "+", onclick: function () {
          var open = detail.classList.contains("hidden");
          detail.classList.toggle("hidden", !open);
          toggle.textContent = open ? "-" : "+";
          if (open) loadProbeDetail(p, detail.firstChild, order);
        } });
        var tr = A.el("tr", { class: differs ? "differs" : "" }, [
          A.el("td", null, toggle),
          A.el("td", null, [A.el("div", { class: "mono small", text: p.probe_id }), p.technique ? A.el("div", { class: "hint", text: p.technique }) : null]),
          A.el("td", { class: "small", text: p.category || "" }),
          A.el("td", null, A.badge(p.severity || "MEDIUM"))
        ].concat(verdicts.map(function (v) { return A.el("td", { class: "center" }, A.verdictBadge(v)); })));
        tbody.appendChild(tr); tbody.appendChild(detail);
      });
      if (!shown) tbody.appendChild(A.emptyRow(order.length + 4, onlyDiff ? "No probes differ between targets" : "No probe results yet"));
      A.$("#m-count").textContent = shown + " of " + (group.per_probe || []).length + " probes";
    }
    function loadProbeDetail(p, td, order) {
      A.clear(td).appendChild(A.el("div", { class: "hint", text: "Loading results..." }));
      Promise.all(order.map(function (cid) {
        if (results[cid]) return results[cid];
        return A.get("/api/redteam/campaigns/" + encodeURIComponent(cid) + "/results?limit=500").then(function (r) { var m = {}; (r.items || []).forEach(function (x) { m[x.probe_id] = x; }); results[cid] = m; return m; }).catch(function () { return {}; });
      })).then(function (maps) {
        A.clear(td);
        var grid = A.el("div", { class: "grid cols-" + Math.min(order.length, 3) });
        order.forEach(function (cid, i) {
          var r = maps[i][p.probe_id];
          grid.appendChild(A.el("div", { class: "int-card" }, [
            A.el("div", { class: "card-head" }, [A.el("h2", { text: label(cid) }), A.verdictBadge(r ? r.verdict : "PENDING")]),
            r ? A.el("div", { class: "flex wrap small" }, [
              A.link("/redteam/" + cid, "campaign"),
              r.ticket_id ? A.link("/tickets/" + r.ticket_id, "ticket") : null,
              r.confidence != null ? A.el("span", { class: "hint", text: "confidence " + Math.round(Number(r.confidence) * 100) + "%" }) : null,
              r.latency_ms != null ? A.el("span", { class: "hint", text: A.fmtMs(r.latency_ms) }) : null
            ]) : A.el("div", { class: "hint", text: "no result recorded" }),
            r ? A.el("details", { class: "raw" }, [A.el("summary", { text: "Response" }), A.jsonPre(r.response || "(empty)")]) : null,
            r && r.evidence && Object.keys(r.evidence).length ? A.el("details", { class: "raw" }, [A.el("summary", { text: "Evidence" }), A.jsonPre(r.evidence)]) : null
          ]));
        });
        td.appendChild(A.el("div", { class: "small muted mb", text: "Prompt: " + p.probe_id }));
        var first = null;
        maps.forEach(function (m) { if (!first && m[p.probe_id]) first = m[p.probe_id]; });
        if (first && (first.prompt || (first.messages && first.messages.length))) td.appendChild(A.el("details", { class: "raw mb" }, [A.el("summary", { text: "Prompt text" }), A.jsonPre(first.messages && first.messages.length ? first.messages.map(function (m) { return "[" + m.role + "] " + m.content; }).join("\n\n") : first.prompt)]));
        td.appendChild(grid);
      });
    }
    A.$("#m-category").addEventListener("change", renderMatrix);
    A.$("#m-differs").addEventListener("change", renderMatrix);
    function load() { return A.get("/api/redteam/groups/" + encodeURIComponent(id)).then(function (g) { results = {}; render(g); }).catch(A.fail); }
    A.get("/api/agents").then(function (list) { agents = A.agentMap(list); }).catch(function () {}).then(A.loadTaxonomy).then(load);
    var refresh = A.debounce(load, 1000);
    A.streamAll("/api/stream/campaigns?replay=0", function (name, data) {
      if (!data || !group) return;
      var cid = data.campaign_id || (data.campaign && data.campaign.id);
      if (!cid || !campaignById(cid)) return;
      var c = campaignById(cid);
      if (data.status) c.status = data.status;
      if (data.completed != null) c.completed_probes = data.completed;
      if (data.total != null) c.total_probes = data.total;
      renderTargets();
      refresh();
    });
  };
})();
