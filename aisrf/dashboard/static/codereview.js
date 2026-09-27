/* Code review list page: new run form (five intake types), live runs table, credentials, rule catalogue. */
(function () {
  "use strict";
  var A = window.AISRF;
  A.pages.codereview = function () {
    var catalogue = null, source = "git", packState = {}, engineState = {}, runs = {}, order = [];
    var R = { limit: 25, offset: 0, status: "" };
    var C = { pack: "", severity: "", search: "" };
    var STAGES = ["created", "intake", "inventory", "rules", "semgrep", "bandit", "typesafe", "llm", "persist", "completed"];
    var form = A.$("#run-form");

    /* ---------- helpers ---------- */
    function chipButton(store, name, label, onChange) {
      var b = A.el("button", { type: "button", class: "btn xs" + (store[name] ? " active" : ""), text: label, onclick: function () { store[name] = !store[name]; b.classList.toggle("active", !!store[name]); if (onChange) onChange(); } });
      return b;
    }
    function selected(store) { return Object.keys(store).filter(function (k) { return store[k]; }); }
    function splitGlobs(v) { return String(v || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean); }
    function sourceLabel(r) {
      var ref = r.source_ref || "";
      return A.el("span", { class: "flex", title: ref }, [A.el("span", { class: "chip", text: r.source_type }), A.el("span", { class: "truncate", style: "max-width:260px", text: ref })]);
    }
    function stageIndex(stage) { var i = STAGES.indexOf(stage); return i < 0 ? 0 : i; }
    function progressCell(r) {
      var wrap = A.el("div", { class: "stack", style: "gap:2px;min-width:140px" });
      var terminal = r.status === "COMPLETED" || r.status === "FAILED" || r.status === "CANCELLED";
      var pct = terminal ? 100 : Math.round(100 * stageIndex(r.stage) / (STAGES.length - 1));
      if (r.live && r.live.total) pct = Math.min(99, Math.round(100 * (stageIndex("rules") / (STAGES.length - 1)) + (100 / (STAGES.length - 1)) * (r.live.done / r.live.total)));
      var bar = A.el("div", { class: "progress " + (r.status === "COMPLETED" ? "ok" : r.status === "FAILED" ? "danger" : "") }, A.el("span", { style: "width:" + pct + "%" }));
      var text = r.stage || r.status.toLowerCase();
      if (r.live && r.live.total) text += " " + r.live.done + "/" + r.live.total + " files";
      wrap.appendChild(bar);
      wrap.appendChild(A.el("span", { class: "hint", text: text }));
      return wrap;
    }

    /* ---------- runs table ---------- */
    function renderRuns() {
      var body = A.$("#run-rows");
      A.clear(body);
      if (!order.length) { body.appendChild(A.emptyRow(10, "No review runs yet")); return; }
      order.forEach(function (id) {
        var r = runs[id];
        if (!r) return;
        var s = r.summary || {};
        var running = r.status === "CREATED" || r.status === "FETCHING" || r.status === "ANALYZING";
        var actions = A.el("span", { class: "flex" });
        if (running && A.isReviewer()) actions.appendChild(A.el("button", { class: "btn xs", text: "Cancel", onclick: function () { A.post("/api/codereview/runs/" + encodeURIComponent(id) + "/cancel").then(loadRuns, A.fail); } }));
        if (A.isReviewer()) actions.appendChild(A.el("button", { class: "btn xs danger", text: "Delete", onclick: function () { A.confirm("Delete run", "Delete this run, its findings and its working copy?", "Delete", "danger").then(function (ok) { if (ok) A.del("/api/codereview/runs/" + encodeURIComponent(id)).then(loadRuns, A.fail); }); } }));
        body.appendChild(A.el("tr", null, [
          A.el("td", null, A.link("/codereview/" + encodeURIComponent(id), r.name || id)),
          A.el("td", null, sourceLabel(r)),
          A.el("td", null, A.badge(r.status)),
          A.el("td", null, progressCell(r)),
          A.el("td", { class: "num", text: r.file_count != null ? r.file_count : "" }),
          A.el("td", { class: "num", text: r.finding_count != null ? r.finding_count : "" }),
          A.el("td", null, s.risk_score != null ? A.riskBadge(s.risk_level, s.risk_score) : A.el("span", { class: "faint", text: "n/a" })),
          A.el("td", null, A.timeEl(r.created_at)),
          A.el("td", { text: r.created_by || "" }),
          A.el("td", null, actions)
        ]));
      });
    }
    function loadRuns() {
      return A.get("/api/codereview/runs" + A.qs({ limit: R.limit, offset: R.offset, status: R.status })).then(function (res) {
        order = [];
        var fresh = {};
        (res.items || []).forEach(function (r) { r.live = runs[r.id] ? runs[r.id].live : null; fresh[r.id] = r; order.push(r.id); });
        runs = fresh;
        A.$("#runs-count").textContent = res.total + " run" + (res.total === 1 ? "" : "s");
        A.pager(A.$("#runs-pager"), res.total, R.limit, R.offset, function (o) { R.offset = o; loadRuns(); });
        renderRuns();
      }, A.fail);
    }
    A.$("#runs-status").addEventListener("change", function () { R.status = this.value; R.offset = 0; loadRuns(); });

    /* ---------- live events ---------- */
    A.sse("/api/codereview/stream?replay=0", { "*": function (data, name) {
      if (!data || !data.run_id) return;
      var r = runs[data.run_id];
      if (name === "run.deleted") { if (r) loadRuns(); return; }
      if (!r) { if (R.offset === 0 && !R.status) loadRuns(); return; }
      if (data.status) r.status = data.status;
      if (data.stage) r.stage = data.stage;
      if (name === "run.progress") r.live = { done: data.done || 0, total: data.total || 0 };
      if (data.files != null) r.file_count = data.files;
      if (data.findings != null) r.finding_count = data.findings;
      if (data.summary) r.summary = data.summary;
      if (data.status === "COMPLETED" || data.status === "FAILED" || data.status === "CANCELLED") { r.live = null; loadRuns(); return; }
      renderRuns();
    } }, { onStatus: function (on) { var conn = A.$("#nav-conn"); if (conn) { conn.classList.toggle("on", on); conn.classList.toggle("off", !on); } } });

    /* ---------- new run form ---------- */
    function setSource(name) {
      source = name;
      A.$$("#source-tabs button").forEach(function (b) { b.classList.toggle("active", b.dataset.source === name); });
      A.$$("#run-form .src").forEach(function (n) { n.classList.toggle("hidden", !n.classList.contains("src-" + name)); });
      updateSummary();
    }
    A.$$("#source-tabs button").forEach(function (b) { b.addEventListener("click", function () { setSource(b.dataset.source); }); });
    A.$("#new-run-btn").addEventListener("click", function () { A.$("#create-card").classList.remove("hidden"); A.$("#create-card").scrollIntoView({ behavior: "smooth" }); });
    A.$("#cancel-create").addEventListener("click", function () { A.$("#create-card").classList.add("hidden"); });
    A.$("#packs-all").addEventListener("click", function () { Object.keys(packState).forEach(function (k) { packState[k] = true; }); renderPackChips(); });
    A.$("#packs-none").addEventListener("click", function () { Object.keys(packState).forEach(function (k) { packState[k] = false; }); renderPackChips(); });
    function updateSummary() {
      var packs = selected(packState), engines = selected(engineState);
      A.$("#run-summary").textContent = (packs.length ? packs.length + " pack" + (packs.length === 1 ? "" : "s") : "all packs") + ", engines: " + (engines.length ? engines.join(", ") : "defaults");
    }
    function renderPackChips() {
      var box = A.$("#pack-checks");
      A.clear(box);
      (catalogue ? catalogue.packs : []).forEach(function (p) { box.appendChild(chipButton(packState, p.name, p.title + " (" + p.rule_count + ")", updateSummary)); });
      updateSummary();
    }
    function renderEngineChips() {
      var box = A.$("#engine-checks");
      A.clear(box);
      var labels = { rules: "AISRF rules", semgrep: "semgrep", bandit: "bandit", typesafe: "TypeSafe triage", llm: "LLM-assisted" };
      (catalogue ? catalogue.engines : ["rules", "semgrep", "bandit", "llm"]).forEach(function (e) { box.appendChild(chipButton(engineState, e, labels[e] || e, updateSummary)); });
      updateSummary();
    }
    function buildOptions() {
      return { packs: selected(packState), engines: selected(engineState), include: splitGlobs(form.include.value), exclude: splitGlobs(form.exclude.value) };
    }
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var name = form.name.value.trim(), options = buildOptions(), submit = A.$("#run-submit");
      var done = function (run) { submit.disabled = false; A.toast("Run " + run.id + " started", "ok"); form.token.value = ""; form.url_token.value = ""; A.$("#create-card").classList.add("hidden"); window.location.href = "/codereview/" + encodeURIComponent(run.id); };
      var fail = function (err) { submit.disabled = false; A.fail(err); };
      submit.disabled = true;
      if (source === "zip") {
        var file = form.file.files[0];
        if (!file) { submit.disabled = false; A.toast("Choose an archive first", "error"); return; }
        var fd = new FormData();
        fd.append("file", file, file.name);
        fd.append("name", name || file.name);
        fd.append("options", JSON.stringify(options));
        fetch("/api/codereview/runs/upload", { method: "POST", body: fd, credentials: "same-origin", headers: { "Accept": "application/json" } }).then(function (res) {
          return res.json().then(function (data) { if (!res.ok) throw new Error(data && data.detail ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : "HTTP " + res.status); return data; });
        }).then(done, fail);
        return;
      }
      var src = { type: source };
      if (source === "git") { src.url = form.git_url.value.trim(); src.ref = form.ref.value.trim() || null; if (form.credential_id.value) src.credential_id = form.credential_id.value; else if (form.token.value) src.token = form.token.value; }
      if (source === "url") { src.url = form.archive_url.value.trim(); if (form.url_token.value) src.token = form.url_token.value; }
      if (source === "path") src.path = form.path.value.trim();
      if (source === "snippet") { src.code = form.code.value; src.language = form.language.value; }
      A.post("/api/codereview/runs", { name: name, source: src, options: options }).then(done, fail);
    });

    /* ---------- credentials (admin) ---------- */
    function renderCredentials(items) {
      var body = A.$("#credential-rows"), sel = A.$("#credential-select");
      A.clear(body);
      A.clear(sel);
      sel.appendChild(A.el("option", { value: "", text: "none" }));
      if (!items.length) body.appendChild(A.emptyRow(6, "No saved credentials"));
      items.forEach(function (c) {
        sel.appendChild(A.el("option", { value: c.id, text: c.label + " (" + c.provider + ")" }));
        body.appendChild(A.el("tr", null, [
          A.el("td", { text: c.label }), A.el("td", null, A.el("span", { class: "chip", text: c.provider })), A.el("td", { text: c.username || "" }), A.el("td", null, A.timeEl(c.created_at)), A.el("td", { text: c.created_by || "" }),
          A.el("td", null, A.el("button", { class: "btn xs danger", text: "Delete", onclick: function () { A.confirm("Delete credential", "Remove " + c.label + "? Runs that reference it will fail to clone.", "Delete", "danger").then(function (ok) { if (ok) A.del("/api/codereview/credentials/" + encodeURIComponent(c.id)).then(loadCredentials, A.fail); }); } }))
        ]));
      });
    }
    function loadCredentials() {
      if (!A.isAdmin()) return Promise.resolve();
      A.$("#credentials-card").classList.remove("hidden");
      return A.get("/api/codereview/credentials").then(renderCredentials, A.fail);
    }
    A.$("#credential-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var f = e.target;
      A.post("/api/codereview/credentials", { label: f.label.value.trim(), provider: f.provider.value, username: f.username.value.trim(), token: f.token.value }).then(function () { f.reset(); A.toast("Credential saved", "ok"); loadCredentials(); }, A.fail);
    });

    /* ---------- catalogue ---------- */
    function ruleRows() {
      var rows = [];
      (catalogue ? catalogue.packs : []).forEach(function (p) { p.rules.forEach(function (r) { rows.push(r); }); });
      var q = C.search.toLowerCase();
      return rows.filter(function (r) {
        if (C.pack && r.pack !== C.pack) return false;
        if (C.severity && r.severity !== C.severity) return false;
        if (q && (r.id + " " + r.title + " " + r.description + " " + (r.tags || []).join(" ") + " " + r.cwe).toLowerCase().indexOf(q) < 0) return false;
        return true;
      });
    }
    function ruleDetail(r) {
      var box = A.el("div", { class: "finding-detail" });
      box.appendChild(A.el("p", { text: r.description }));
      box.appendChild(A.el("p", null, [A.el("strong", { text: "Why it matters: " }), r.why]));
      box.appendChild(A.el("div", null, [A.el("strong", { text: "Remediation" }), A.el("ul", null, (r.remediation || []).map(function (s) { return A.el("li", { text: s }); }))]));
      box.appendChild(A.taxonomyChips({ owasp_labels: r.owasp_labels, category: r.category }));
      var meta = A.el("div", { class: "chips" }, [A.el("span", { class: "chip", text: "confidence " + r.confidence }), A.el("span", { class: "chip", text: "languages: " + (r.languages || []).join(", ") }), A.el("span", { class: "chip", text: "scope: " + r.scope })]);
      (r.references || []).forEach(function (u) { meta.appendChild(A.el("a", { class: "chip", href: u, target: "_blank", rel: "noopener", text: u.replace(/^https?:\/\//, "").slice(0, 60) })); });
      box.appendChild(meta);
      return box;
    }
    function renderCatalogue() {
      var body = A.$("#rule-rows"), rows = ruleRows();
      A.clear(body);
      A.$("#cat-count").textContent = rows.length + " of " + (catalogue ? catalogue.total : 0) + " rules";
      if (!rows.length) { body.appendChild(A.emptyRow(8, "No rules match")); return; }
      rows.forEach(function (r) {
        var detail = null;
        var toggle = A.el("button", { class: "btn xs", text: "+", title: "Details" });
        var tr = A.el("tr", null, [
          A.el("td", null, toggle),
          A.el("td", { class: "mono nowrap", text: r.id }),
          A.el("td", null, A.el("span", { class: "chip", text: r.pack })),
          A.el("td", null, A.badge(r.severity)),
          A.el("td", { text: r.title }),
          A.el("td", null, A.el("div", { class: "chips" }, (r.owasp || []).map(function (o) { return A.el("span", { class: "chip owasp", text: o }); }))),
          A.el("td", null, r.cwe ? A.el("a", { href: "https://cwe.mitre.org/data/definitions/" + encodeURIComponent(r.cwe.split("-")[1] || "") + ".html", target: "_blank", rel: "noopener", text: r.cwe }) : ""),
          A.el("td", { class: "small", text: (r.engines || []).join(", ") })
        ]);
        toggle.addEventListener("click", function () {
          if (detail) { detail.parentNode.removeChild(detail); detail = null; toggle.textContent = "+"; return; }
          detail = A.el("tr", { class: "expand-row" }, A.el("td", { colspan: 8 }, ruleDetail(r)));
          tr.parentNode.insertBefore(detail, tr.nextSibling);
          toggle.textContent = "-";
        });
        body.appendChild(tr);
      });
    }
    A.$("#cat-pack").addEventListener("change", function () { C.pack = this.value; renderCatalogue(); });
    A.$("#cat-severity").addEventListener("change", function () { C.severity = this.value; renderCatalogue(); });
    A.$("#cat-search").addEventListener("input", A.debounce(function () { C.search = A.$("#cat-search").value.trim(); renderCatalogue(); }, 200));

    /* ---------- boot ---------- */
    A.loadTaxonomy();
    A.get("/api/codereview/rules").then(function (cat) {
      catalogue = cat;
      var sel = A.$("#cat-pack");
      cat.packs.forEach(function (p) { sel.appendChild(A.el("option", { value: p.name, text: p.title })); packState[p.name] = false; });
      (cat.engines || []).forEach(function (e) { engineState[e] = ((cat.config || {}).default_engines || ["rules", "semgrep", "bandit"]).indexOf(e) >= 0; });
      renderPackChips();
      renderEngineChips();
      renderCatalogue();
    }, A.fail);
    if (!A.isReviewer()) { A.$("#new-run-btn").classList.add("hidden"); }
    setSource("git");
    loadRuns();
    loadCredentials();
  };
})();
