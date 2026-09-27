(function () {
  "use strict";
  var A = window.AIRT;
  A.campaignRow = function (c, agents) {
    var s = c.summary || {};
    var vuln = s.vulnerable != null ? s.vulnerable : (s.verdicts && s.verdicts.VULNERABLE) || 0;
    var pct = c.total_probes ? Math.round(100 * (c.completed_probes || 0) / c.total_probes) : (c.progress != null ? Math.round(Number(c.progress) * (Number(c.progress) <= 1 ? 100 : 1)) : 0);
    var prog = A.el("div", { class: "flex" }, [A.el("div", { class: "progress grow " + (c.status === "COMPLETED" ? "ok" : c.status === "FAILED" ? "danger" : "") }, A.el("span", { style: "width:" + pct + "%" })), A.el("span", { class: "hint nowrap", text: (c.completed_probes || 0) + "/" + (c.total_probes || 0) })]);
    return A.el("tr", { dataset: { id: c.id } }, [
      A.el("td", null, A.link("/redteam/" + c.id, c.name)),
      A.el("td", null, agents && agents[c.agent_id] ? A.link("/agents/" + c.agent_id, agents[c.agent_id].name) : A.el("span", { text: c.agent_name || c.agent_id || "" })),
      A.el("td", { class: "mono small", text: c.target_model || "" }),
      A.el("td", null, A.badge(c.status)),
      A.el("td", { style: "min-width:160px" }, prog),
      A.el("td", { class: "num" }, vuln ? A.el("span", { class: "badge vulnerable", text: String(vuln) }) : A.el("span", { class: "faint", text: "0" })),
      A.el("td", null, A.timeEl(c.created_at)),
      A.el("td", { class: "small", text: c.created_by || "" }),
      A.el("td", null, A.el("a", { class: "btn xs", href: "/redteam/" + c.id, text: "Open" }))
    ]);
  };
  A.pages.redteam = function () {
    var rows = A.$("#campaign-rows"), agents = {}, corpus = null, campaigns = {};
    var card = A.$("#create-card"), form = A.$("#campaign-form");
    var selectedCats = {}, selectedTech = {}, selectedMut = {};
    if (!A.isReviewer()) A.$("#new-campaign-btn").classList.add("hidden");
    A.$("#new-campaign-btn").addEventListener("click", function () { card.classList.remove("hidden"); form.querySelector("[name=name]").focus(); });
    A.$("#cancel-create").addEventListener("click", function () { card.classList.add("hidden"); });
    function renderCampaigns(list) {
      A.clear(rows);
      campaigns = {};
      if (!list.length) rows.appendChild(A.emptyRow(9, "No campaigns yet"));
      list.forEach(function (c) { campaigns[c.id] = c; rows.appendChild(A.campaignRow(c, agents)); });
    }
    function loadCampaigns() {
      return A.get("/api/redteam/campaigns").then(function (r) { renderCampaigns(Array.isArray(r) ? r : (r.items || [])); }).catch(function (e) { A.$("#campaign-status").textContent = "red team API unavailable: " + e.message; });
    }
    function upsertCampaign(c) {
      campaigns[c.id] = c;
      var existing = rows.querySelector("tr[data-id=\"" + c.id + "\"]");
      var tr = A.campaignRow(c, agents);
      if (existing) rows.replaceChild(tr, existing);
      else { var empty = rows.querySelector("td.empty"); if (empty) A.clear(rows); rows.insertBefore(tr, rows.firstChild); }
    }
    var refresh = A.debounce(loadCampaigns, 500);
    A.streamAll("/api/stream/campaigns?replay=0", function (name, data) {
      if (!data) return;
      var cid = data.campaign_id || (data.campaign && data.campaign.id);
      if (data.campaign && data.campaign.id) upsertCampaign(data.campaign);
      else if (cid && campaigns[cid]) {
        var c = campaigns[cid];
        if (data.status) c.status = data.status;
        if (data.completed_probes != null) c.completed_probes = data.completed_probes;
        if (data.total_probes != null) c.total_probes = data.total_probes;
        if (data.progress != null) c.progress = data.progress;
        if (data.summary) c.summary = data.summary;
        upsertCampaign(c);
        if (name === "completed" || name === "failed" || name === "result") refresh();
      } else refresh();
    }, { onStatus: function (on) { A.$("#campaign-status").textContent = on ? "live" : "reconnecting"; } });
    /* corpus */
    function chipToggle(container, name, store, extra) {
      var b = A.el("button", { type: "button", class: "btn xs" + (store[name] ? " active" : ""), text: name + (extra ? " (" + extra + ")" : ""), onclick: function () { store[name] = !store[name]; b.classList.toggle("active", !!store[name]); updateSummary(); } });
      container.appendChild(b);
      return b;
    }
    function renderCategories(filter) {
      var box = A.$("#c-categories");
      A.clear(box);
      if (!corpus) return;
      corpus.categories.filter(function (c) { return !filter || (c.name + " " + (c.description || "")).toLowerCase().indexOf(filter) >= 0; }).forEach(function (c) {
        var cb = A.el("input", { type: "checkbox", onchange: function (e) { selectedCats[c.name] = e.target.checked; updateSummary(); } });
        cb.checked = !!selectedCats[c.name];
        box.appendChild(A.el("label", { title: c.description || "" }, [cb, A.el("span", null, [A.el("div", { text: c.name }), A.el("div", { class: "hint clamp", text: c.description || "" })]), A.el("span", { class: "cnt", text: c.probe_count })]));
      });
    }
    function updateSummary() {
      if (!corpus) return;
      var cats = Object.keys(selectedCats).filter(function (k) { return selectedCats[k]; });
      var total = 0;
      corpus.categories.forEach(function (c) { if (!cats.length || selectedCats[c.name]) total += c.probe_count || 0; });
      var max = Number(form.querySelector("[name=max_probes]").value || 0);
      A.$("#c-summary").textContent = (cats.length || "all") + " categories, " + total + " probes in scope" + (max && max < total ? ", sampled to " + max : "");
    }
    form.querySelector("[name=max_probes]").addEventListener("input", updateSummary);
    A.$("#c-cat-search").addEventListener("input", function (e) { renderCategories(e.target.value.trim().toLowerCase()); });
    A.$("#c-cat-all").addEventListener("click", function () { (corpus ? corpus.categories : []).forEach(function (c) { selectedCats[c.name] = true; }); renderCategories(A.$("#c-cat-search").value.trim().toLowerCase()); updateSummary(); });
    A.$("#c-cat-none").addEventListener("click", function () { selectedCats = {}; renderCategories(A.$("#c-cat-search").value.trim().toLowerCase()); updateSummary(); });
    function loadCorpus() {
      return A.get("/api/redteam/corpus").then(function (c) {
        corpus = c;
        renderCategories("");
        var techs = {};
        (c.categories || []).forEach(function (cat) { (cat.techniques || []).forEach(function (t) { techs[t] = 1; }); });
        var tbox = A.$("#c-techniques");
        A.clear(tbox);
        Object.keys(techs).sort().forEach(function (t) { chipToggle(tbox, t, selectedTech); });
        var mbox = A.$("#c-mutators");
        A.clear(mbox);
        (c.mutators || []).forEach(function (m) { var name = typeof m === "string" ? m : m.name; chipToggle(mbox, name, selectedMut); });
        var pc = A.$("#p-category");
        (c.categories || []).forEach(function (cat) { pc.appendChild(A.el("option", { value: cat.name, text: cat.name + " (" + cat.probe_count + ")" })); });
        updateSummary();
      }).catch(function (e) { A.$("#c-summary").textContent = "corpus unavailable: " + e.message; });
    }
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var fd = new FormData(form), o = {};
      fd.forEach(function (v, k) { o[k] = v; });
      var payload = {
        name: o.name.trim(),
        agent_id: o.agent_id,
        target_model: o.target_model || "",
        categories: Object.keys(selectedCats).filter(function (k) { return selectedCats[k]; }),
        techniques: Object.keys(selectedTech).filter(function (k) { return selectedTech[k]; }),
        max_probes: Number(o.max_probes || 0),
        mutators: Object.keys(selectedMut).filter(function (k) { return selectedMut[k]; }),
        system_prompt: o.system_prompt || "",
        path: o.path || "",
        concurrency: Number(o.concurrency || 4),
        auto_start: !!form.querySelector("[name=auto_start]").checked
      };
      if (o.seed !== "") payload.seed = Number(o.seed);
      if (String(o.extra_body || "").trim()) { try { payload.extra_body = JSON.parse(o.extra_body); } catch (ex) { A.fail(new Error("Extra body must be valid JSON")); return; } }
      A.post("/api/redteam/campaigns", payload).then(function (c) { A.toast("Campaign created", "ok"); window.location.href = "/redteam/" + c.id; }).catch(A.fail);
    });
    /* probe browser */
    var P = { limit: 25, offset: 0 };
    function loadProbes() {
      var q = { category: A.$("#p-category").value, severity: A.$("#p-severity").value, search: A.$("#p-search").value.trim(), limit: P.limit, offset: P.offset };
      A.get("/api/redteam/corpus/probes" + A.qs(q)).then(function (r) {
        var pr = A.$("#probe-rows");
        A.clear(pr);
        A.$("#p-count").textContent = r.total + " probes";
        if (!r.items.length) pr.appendChild(A.emptyRow(6, "No probes match"));
        r.items.forEach(function (p) {
          var prompt = p.prompt || (p.messages && p.messages.length ? p.messages.map(function (m) { return m.content; }).join(" ") : "");
          pr.appendChild(A.el("tr", null, [
            A.el("td", { class: "mono small", text: p.id || p.probe_id || "" }),
            A.el("td", { class: "small", text: p.category || "" }),
            A.el("td", { class: "small", text: p.technique || "" }),
            A.el("td", null, A.badge(p.severity || "MEDIUM")),
            A.el("td", { text: p.name || "" }),
            A.el("td", null, A.el("details", { class: "raw" }, [A.el("summary", { class: "truncate", text: prompt.slice(0, 120) }), A.el("pre", { text: prompt })]))
          ]));
        });
        A.pager(A.$("#p-pager"), r.total, P.limit, P.offset, function (o) { P.offset = o; loadProbes(); });
      }).catch(function (e) { A.$("#p-count").textContent = e.message; });
    }
    ["#p-category", "#p-severity"].forEach(function (s) { A.$(s).addEventListener("change", function () { P.offset = 0; loadProbes(); }); });
    A.$("#p-search").addEventListener("input", A.debounce(function () { P.offset = 0; loadProbes(); }, 300));
    A.get("/api/agents?include_inactive=false").then(function (list) { agents = A.agentMap(list); A.agentOptions(A.$("#c-agent"), list, { blankLabel: "Select agent" }); }).catch(A.fail).then(loadCampaigns).then(loadCorpus).then(loadProbes);
  };
})();
