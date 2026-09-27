(function () {
  "use strict";
  var A = window.AIRT;
  A.pages.campaign = function () {
    var id = document.body.getAttribute("data-campaign-id");
    var campaign = null, agents = {};
    var VERDICTS = ["VULNERABLE", "RESISTED", "BLOCKED", "INCONCLUSIVE", "ERROR", "PENDING"];
    var R = { limit: 25, offset: 0 };
    function tile(label, value, cls) { return A.el("div", { class: "tile " + (cls || "") }, [A.el("div", { class: "label", text: label }), A.el("div", { class: "value", text: value })]); }
    function verdictCounts(s) {
      var v = (s && (s.verdicts || s.by_verdict)) || {};
      VERDICTS.forEach(function (k) { if (v[k] == null && s && s[k.toLowerCase()] != null) v[k] = s[k.toLowerCase()]; });
      return v;
    }
    function render(c) {
      campaign = c;
      document.title = c.name + " - AIRT";
      A.$("#title").textContent = c.name;
      var hb = A.$("#head-badges");
      A.clear(hb);
      hb.appendChild(A.badge(c.status));
      var pct = c.total_probes ? Math.round(100 * (c.completed_probes || 0) / c.total_probes) : (c.progress != null ? Math.round(Number(c.progress) * (Number(c.progress) <= 1 ? 100 : 1)) : 0);
      A.$("#progress").className = "progress " + (c.status === "COMPLETED" ? "ok" : c.status === "FAILED" ? "danger" : "");
      A.$("#progress").firstElementChild.style.width = pct + "%";
      A.$("#progress-text").textContent = (c.completed_probes || 0) + " / " + (c.total_probes || 0) + " probes (" + pct + "%)";
      var s = c.summary || {}, v = verdictCounts(s);
      var total = VERDICTS.reduce(function (n, k) { return n + (v[k] || 0); }, 0);
      var tiles = A.$("#tiles");
      A.clear(tiles);
      tiles.appendChild(tile("Vulnerable", v.VULNERABLE || 0, v.VULNERABLE ? "hot" : ""));
      tiles.appendChild(tile("Resisted", v.RESISTED || 0, "ok"));
      tiles.appendChild(tile("Blocked", v.BLOCKED || 0));
      tiles.appendChild(tile("Errors", v.ERROR || 0));
      var rate = s.vulnerability_rate != null ? s.vulnerability_rate : (total ? (v.VULNERABLE || 0) / total : null);
      tiles.appendChild(tile("Vulnerability rate", rate == null ? "n/a" : Math.round(rate * (rate <= 1 ? 100 : 1)) + "%"));
      var score = s.weighted_score != null ? s.weighted_score : (s.score != null ? s.score : null);
      tiles.appendChild(tile("Weighted score", score == null ? "n/a" : (typeof score === "number" ? score.toFixed(1) : score)));
      var vd = A.$("#verdict-dist");
      A.clear(vd);
      if (total) {
        var bar = A.el("div", { class: "dist" });
        var legend = A.el("div", { class: "legend" });
        VERDICTS.forEach(function (k) { var n = v[k] || 0; if (n) bar.appendChild(A.el("span", { class: "c-" + k.toLowerCase(), style: "width:" + (100 * n / total) + "%", title: k + ": " + n })); legend.appendChild(A.el("span", null, [A.el("i", { class: "c-" + k.toLowerCase() }), k + " " + n])); });
        vd.appendChild(bar); vd.appendChild(legend);
      }
      var cb = A.$("#category-bars");
      A.clear(cb);
      var cats = s.by_category || s.categories || {};
      var names = Array.isArray(cats) ? cats.map(function (x) { return x.category || x.name; }) : Object.keys(cats);
      if (!names.length) cb.appendChild(A.el("div", { class: "empty", text: "No results yet" }));
      names.forEach(function (name, i) {
        var row = Array.isArray(cats) ? cats[i] : cats[name];
        var vul = row.vulnerable != null ? row.vulnerable : (row.VULNERABLE || 0), tot = row.total != null ? row.total : VERDICTS.reduce(function (n, k) { return n + (row[k] || 0); }, 0);
        var r = row.rate != null ? row.rate : (row.vulnerability_rate != null ? row.vulnerability_rate : (tot ? vul / tot : 0));
        var p = Math.round(r * (r <= 1 ? 100 : 1));
        cb.appendChild(A.el("div", { class: "hbar" }, [A.el("span", { class: "truncate", text: name, title: name }), A.el("div", { class: "track" }, A.el("span", { style: "width:" + p + "%" })), A.el("span", { class: "num small", text: p + "% (" + vul + "/" + tot + ")" })]));
        var sel = A.$("#r-category");
        if (!sel.querySelector("option[value=\"" + name + "\"]")) sel.appendChild(A.el("option", { value: name, text: name }));
      });
      var d = A.$("#details");
      A.clear(d);
      [["Id", c.id, "mono small"], ["Agent", agents[c.agent_id] ? A.link("/agents/" + c.agent_id, agents[c.agent_id].name) : (c.agent_name || c.agent_id)], ["Target model", c.target_model, "mono"], ["Created", A.fmtTs(c.created_at) + (c.created_by ? " by " + c.created_by : "")], ["Started", c.started_at ? A.fmtTs(c.started_at) : null], ["Finished", c.finished_at ? A.fmtTs(c.finished_at) : null], ["Error", c.error, "small"], ["Tickets", A.link("/tickets?status=&campaign_id=" + encodeURIComponent(c.id), "open in queue")]].forEach(function (p) {
        if (p[1] == null || p[1] === "") return;
        d.appendChild(A.el("dt", { text: p[0] })); d.appendChild(A.el("dd", { class: p[2] || "" }, p[1]));
      });
      A.clear(A.$("#config")).appendChild(A.jsonPre(c.config || {}));
      A.clear(A.$("#reports")).appendChild(A.reportLinks("campaign/" + encodeURIComponent(c.id)));
      renderControls(c);
    }
    function ctl(label, action, cls, confirmText) {
      return A.el("button", { class: "btn sm " + (cls || ""), text: label, onclick: function () {
        var go = confirmText ? A.confirm(label + " campaign", confirmText, label, cls === "danger" ? "danger" : "primary") : Promise.resolve(true);
        go.then(function (ok) {
          if (!ok) return;
          if (action === "delete") return A.del("/api/redteam/campaigns/" + encodeURIComponent(id)).then(function () { A.toast("Campaign deleted", "ok"); window.location.href = "/redteam"; });
          return A.post("/api/redteam/campaigns/" + encodeURIComponent(id) + "/" + action).then(function () { A.toast("Campaign " + action + " requested", "ok"); return load(); });
        }).catch(A.fail);
      } });
    }
    function renderControls(c) {
      var box = A.$("#controls");
      A.clear(box);
      if (!A.isReviewer()) return;
      if (c.status === "CREATED") box.appendChild(ctl("Start", "start", "ok"));
      if (c.status === "RUNNING") box.appendChild(ctl("Pause", "pause", ""));
      if (c.status === "PAUSED") box.appendChild(ctl("Resume", "resume", "ok"));
      if (c.status === "RUNNING" || c.status === "PAUSED" || c.status === "CREATED") box.appendChild(ctl("Cancel", "cancel", "danger", "Stop the campaign and keep the results gathered so far?"));
      if (c.status !== "RUNNING") box.appendChild(ctl("Delete", "delete", "danger", "Permanently delete this campaign and all of its results?"));
    }
    function resultRow(r) {
      var open = false;
      var detail = A.el("tr", { class: "expand-row hidden" }, A.el("td", { colspan: 10 }, [
        A.el("h3", { text: "Prompt" }), A.jsonPre(r.messages && r.messages.length ? r.messages.map(function (m) { return "[" + m.role + "] " + m.content; }).join("\n\n") : (r.prompt || "")),
        A.el("h3", { class: "mt", text: "Response" }), A.jsonPre(r.response || "(empty)"),
        A.el("h3", { class: "mt", text: "Evidence" }), A.jsonPre(r.evidence || {})
      ]));
      var toggle = A.el("button", { class: "btn xs", text: "+", onclick: function () { open = !open; detail.classList.toggle("hidden", !open); toggle.textContent = open ? "-" : "+"; } });
      var main = A.el("tr", null, [
        A.el("td", null, toggle),
        A.el("td", null, [A.el("div", { class: "mono small", text: r.probe_id || "" }), A.el("div", { class: "small muted truncate", text: r.name || "" })]),
        A.el("td", { class: "small" }, [r.category || "", A.taxonomyChips({ category: r.category, owasp_labels: r.owasp_labels })]),
        A.el("td", { class: "small", text: r.technique || "" }),
        A.el("td", null, A.badge(r.severity || "MEDIUM")),
        A.el("td", null, A.verdictBadge(r.verdict)),
        A.el("td", { class: "num", text: r.confidence != null ? Math.round(Number(r.confidence) * 100) + "%" : "" }),
        A.el("td", { class: "num small", text: r.latency_ms != null ? A.fmtMs(r.latency_ms) : "" }),
        A.el("td", null, r.ticket_id ? A.link("/tickets/" + r.ticket_id, "ticket") : A.el("span", { class: "faint", text: "-" })),
        A.el("td", null, A.timeEl(r.ts))
      ]);
      return [main, detail];
    }
    function loadResults() {
      var q = { verdict: A.$("#r-verdict").value, category: A.$("#r-category").value, limit: R.limit, offset: R.offset };
      return A.get("/api/redteam/campaigns/" + encodeURIComponent(id) + "/results" + A.qs(q)).then(function (r) {
        var rows = A.$("#result-rows");
        A.clear(rows);
        A.$("#r-count").textContent = r.total + " results";
        if (!r.items.length) rows.appendChild(A.emptyRow(10, "No results yet"));
        r.items.forEach(function (x) { resultRow(x).forEach(function (tr) { rows.appendChild(tr); }); });
        A.pager(A.$("#r-pager"), r.total, R.limit, R.offset, function (o) { R.offset = o; loadResults(); });
      }).catch(A.fail);
    }
    ["#r-verdict", "#r-category"].forEach(function (s) { A.$(s).addEventListener("change", function () { R.offset = 0; loadResults(); }); });
    function load() { return A.get("/api/redteam/campaigns/" + encodeURIComponent(id)).then(render).catch(A.fail); }
    A.get("/api/agents").then(function (list) { agents = A.agentMap(list); }).catch(function () {}).then(A.loadTaxonomy).then(load).then(loadResults);
    var refreshResults = A.debounce(loadResults, 1200);
    var refreshCampaign = A.debounce(load, 600);
    A.streamAll("/api/stream/campaigns?replay=0", function (name, data) {
      if (!data) return;
      var cid = data.campaign_id || (data.campaign && data.campaign.id);
      if (cid !== id) return;
      if (data.campaign) render(Object.assign({}, campaign || {}, data.campaign));
      else if (campaign) {
        var c = Object.assign({}, campaign);
        if (data.status) c.status = data.status;
        if (data.completed_probes != null) c.completed_probes = data.completed_probes;
        if (data.total_probes != null) c.total_probes = data.total_probes;
        if (data.progress != null) c.progress = data.progress;
        if (data.summary) c.summary = data.summary;
        render(c);
      }
      refreshCampaign();
      if (name === "result" || name === "completed" || name === "progress") refreshResults();
    });
  };
})();
