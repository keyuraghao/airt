/* Code review run page: summary tiles, inventory, filterable findings with details, file viewer, reports. */
(function () {
  "use strict";
  var A = window.AISRF;
  A.pages.codereview_run = function () {
    var id = document.body.getAttribute("data-run-id");
    var run = null, expanded = {};
    /* the status filter starts on the select's first option, which hides TypeSafe "likely false positive" findings by default */
    var F = { limit: 50, offset: 0, severity: "", pack: "", engine: "", status: (A.$("#f-status") && A.$("#f-status").value) || "", file: "", search: "" };
    var SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    var STAGES = ["created", "intake", "inventory", "rules", "semgrep", "bandit", "typesafe", "llm", "persist", "completed"];
    var STATUS_LABELS = { false_positive: "false positive", likely_false_positive: "likely false positive" };
    function typesafeChip(md) {
      /* compact TypeSafe verdict chip plus a details table of the raw answers; textContent only, never HTML */
      var t = md && md.typesafe;
      if (!t || typeof t !== "object") return null;
      var pct = t.confidence != null ? Math.round(Number(t.confidence) * 100) + "%" : "";
      var box = A.el("div", { class: "typesafe" });
      var chips = A.el("div", { class: "chips" });
      chips.appendChild(A.el("span", { class: "chip typesafe-" + String(t.verdict || "uncertain"), text: "TypeSafe: " + (t.verdict || "n/a") + (pct ? " " + pct : "") }));
      if (md.typesafe_true_positive != null) chips.appendChild(A.el("span", { class: "chip", text: "true positive " + Number(md.typesafe_true_positive).toFixed(2) }));
      if (md.typesafe_exploitability != null) chips.appendChild(A.el("span", { class: "chip", text: "exploitability " + Number(md.typesafe_exploitability).toFixed(1) + " / 3" }));
      box.appendChild(chips);
      var answers = t.answers || {};
      var names = Object.keys(answers);
      if (names.length) {
        var tbody = A.el("tbody");
        names.forEach(function (n) {
          var a = answers[n] || {};
          var value = a.type === "noul" ? Number(a.noul).toFixed(2) : a.type === "choice" ? String(a.choice) : a.type === "score" ? Number(a.score).toFixed(2) : "";
          var probs = a.probabilities ? Object.keys(a.probabilities).map(function (k) { return k + " " + Math.round(Number(a.probabilities[k]) * 100) + "%"; }).join(", ") : "";
          tbody.appendChild(A.el("tr", null, [A.el("td", { class: "mono", text: n }), A.el("td", { text: a.type || "" }), A.el("td", { class: "num", text: value }), A.el("td", { class: "num", text: a.confidence != null ? Math.round(Number(a.confidence) * 100) + "%" : "" }), A.el("td", { class: "small", text: probs })]));
        });
        box.appendChild(A.el("details", { class: "raw" }, [A.el("summary", { text: "TypeSafe answers (" + names.length + ")" + (t.model ? ", model " + t.model : "") }), A.el("table", { class: "small" }, [A.el("thead", null, A.el("tr", null, [A.el("th", { text: "question" }), A.el("th", { text: "type" }), A.el("th", { class: "right", text: "answer" }), A.el("th", { class: "right", text: "confidence" }), A.el("th", { text: "probabilities" })])), tbody])]));
      }
      return box;
    }
    var terminal = function (s) { return s === "COMPLETED" || s === "FAILED" || s === "CANCELLED"; };

    function tile(label, value, cls, sub) { return A.el("div", { class: "tile " + (cls || "") }, [A.el("div", { class: "label", text: label }), A.el("div", { class: "value", text: value }), sub ? A.el("div", { class: "sub", text: sub }) : null]); }
    function kv(dl, rows) { A.clear(dl); rows.forEach(function (r) { if (r[1] == null || r[1] === "") return; dl.appendChild(A.el("dt", { text: r[0] })); dl.appendChild(A.el("dd", null, typeof r[1] === "string" || typeof r[1] === "number" ? String(r[1]) : r[1])); }); }
    function hbars(container, entries, total, cls) {
      A.clear(container);
      if (!entries.length) { container.appendChild(A.el("div", { class: "empty", text: "No open findings" })); return; }
      entries.forEach(function (e) {
        var p = total ? Math.round(100 * e[1] / total) : 0;
        container.appendChild(A.el("div", { class: "hbar" }, [A.el("span", { class: "truncate", text: e[0], title: e[0] }), A.el("div", { class: "track" }, A.el("span", { class: cls ? cls(e[0]) : "", style: "width:" + p + "%" })), A.el("span", { class: "num small", text: e[1] })]));
      });
    }

    /* ---------- run header, tiles, side cards ---------- */
    function render(r) {
      run = r;
      var s = r.summary || {}, inv = r.inventory || {}, sev = s.by_severity || {};
      document.title = (r.name || r.id) + " - AISRF";
      A.$("#title").textContent = r.name || r.id;
      var hb = A.$("#head-badges");
      A.clear(hb);
      hb.appendChild(A.badge(r.status));
      hb.appendChild(A.el("span", { class: "chip", text: r.source_type + ": " + (r.source_ref || "") }));
      if (inv.intake && inv.intake.commit) hb.appendChild(A.el("span", { class: "chip mono", title: inv.intake.commit, text: inv.intake.commit.slice(0, 10) }));
      var controls = A.$("#controls");
      A.clear(controls);
      if (A.isReviewer() && !terminal(r.status)) controls.appendChild(A.el("button", { class: "btn sm", text: "Cancel run", onclick: function () { A.post("/api/codereview/runs/" + encodeURIComponent(id) + "/cancel").then(load, A.fail); } }));
      controls.appendChild(A.el("a", { class: "btn sm", href: "/api/codereview/runs/" + encodeURIComponent(id) + "/sarif", text: "Download SARIF" }));
      if (A.isReviewer()) controls.appendChild(A.el("button", { class: "btn sm danger", text: "Delete", onclick: function () { A.confirm("Delete run", "Delete this run, its findings and its working copy?", "Delete", "danger").then(function (ok) { if (ok) A.del("/api/codereview/runs/" + encodeURIComponent(id)).then(function () { window.location.href = "/codereview"; }, A.fail); }); } }));
      var pct = terminal(r.status) ? 100 : Math.round(100 * Math.max(0, STAGES.indexOf(r.stage)) / (STAGES.length - 1));
      A.$("#progress").className = "progress " + (r.status === "COMPLETED" ? "ok" : r.status === "FAILED" ? "danger" : "");
      A.$("#progress").firstElementChild.style.width = pct + "%";
      A.$("#progress-text").textContent = r.status.toLowerCase() + (r.stage ? ", stage " + r.stage : "") + (s.duration_seconds != null ? ", " + A.fmtSecs(s.duration_seconds) : "");
      var errBox = A.$("#run-error");
      errBox.classList.toggle("hidden", !r.error);
      errBox.textContent = r.error || "";
      var tiles = A.$("#tiles");
      A.clear(tiles);
      tiles.appendChild(tile("Risk score", s.risk_score != null ? s.risk_score : "n/a", s.risk_score >= 60 ? "hot" : "", s.risk_level || ""));
      tiles.appendChild(tile("Critical", sev.CRITICAL || 0, sev.CRITICAL ? "hot" : ""));
      tiles.appendChild(tile("High", sev.HIGH || 0, sev.HIGH ? "hot" : ""));
      tiles.appendChild(tile("Medium", sev.MEDIUM || 0));
      tiles.appendChild(tile("Low and info", (sev.LOW || 0) + (sev.INFO || 0)));
      tiles.appendChild(tile("Files", r.file_count || 0, "", (inv.skipped && (inv.skipped.too_large || inv.skipped.binary)) ? (inv.skipped.too_large || 0) + " too large, " + (inv.skipped.binary || 0) + " binary" : ""));
      tiles.appendChild(tile("Lines of code", r.loc || 0));
      tiles.appendChild(tile("Languages", Object.keys(inv.languages || {}).length, "", Object.keys(inv.languages || {}).slice(0, 3).join(", ")));
      var openTotal = s.open || 0;
      hbars(A.$("#sev-bars"), SEVERITIES.filter(function (k) { return sev[k]; }).map(function (k) { return [k, sev[k]]; }), openTotal, function (k) { return "c-" + k.toLowerCase(); });
      hbars(A.$("#pack-bars"), Object.keys(s.by_pack || {}).map(function (k) { return [k, s.by_pack[k]]; }), openTotal);
      var oc = A.$("#owasp-chips");
      A.clear(oc);
      Object.keys(s.by_owasp || {}).forEach(function (oid) { var e = s.by_owasp[oid]; oc.appendChild(A.el("span", { class: "chip count " + (e.count ? "owasp" : ""), title: e.name, text: oid + " " + e.name + ": " + e.count })); });
      kv(A.$("#inventory"), [
        ["Files", r.file_count], ["Lines", r.loc], ["Languages", Object.keys(inv.languages || {}).map(function (k) { return k + " (" + inv.languages[k].files + ")"; }).join(", ")],
        ["Frameworks", (inv.frameworks || []).length ? A.el("div", { class: "chips" }, inv.frameworks.map(function (f) { return A.el("span", { class: "chip", title: f.kind + ", " + f.count + " file(s)", text: f.name }); })) : "none detected"],
        ["Tool calling", inv.tool_calling && inv.tool_calling.detected ? "yes (" + inv.tool_calling.files.length + " files)" : "no"],
        ["MCP servers", (inv.mcp_servers || []).length ? inv.mcp_servers.join(", ") : ""],
        ["Prompt files", (inv.prompt_files || []).length ? inv.prompt_files.slice(0, 8).join(", ") : ""],
        ["Secrets files", (inv.secret_files || []).length ? inv.secret_files.join(", ") : ""],
        ["CI configuration", (inv.ci_configs || []).length ? inv.ci_configs.join(", ") : ""],
        ["Containers", (inv.dockerfiles || []).length ? inv.dockerfiles.join(", ") : ""],
        ["Notebooks", (inv.notebooks || []).length ? inv.notebooks.length : ""],
        ["Truncated", inv.truncated ? "yes, the file limit was reached" : ""]
      ]);
      var lists = A.$("#inventory-lists");
      A.clear(lists);
      if ((inv.model_artifacts || []).length) {
        lists.appendChild(A.el("div", null, [A.el("strong", { text: "Model artifacts" }), A.el("table", null, [A.el("thead", null, A.el("tr", null, [A.el("th", { text: "Path" }), A.el("th", { text: "Format" }), A.el("th", { class: "right", text: "Bytes" })])), A.el("tbody", null, inv.model_artifacts.map(function (a) { return A.el("tr", null, [A.el("td", { class: "mono", text: a.path }), A.el("td", null, A.el("span", { class: "chip " + (a.pickle_based ? "owasp" : ""), text: a.format })), A.el("td", { class: "num", text: a.bytes })]); }))])]));
      }
      if ((inv.manifests || []).length) {
        lists.appendChild(A.el("div", null, [A.el("strong", { text: "Dependency manifests" }), A.el("table", null, [A.el("thead", null, A.el("tr", null, [A.el("th", { text: "Path" }), A.el("th", { text: "Kind" }), A.el("th", { class: "right", text: "Deps" }), A.el("th", { class: "right", text: "Unpinned" }), A.el("th", { text: "AI packages" })])), A.el("tbody", null, inv.manifests.map(function (m) { return A.el("tr", null, [A.el("td", { class: "mono", text: m.path }), A.el("td", { text: m.kind }), A.el("td", { class: "num", text: m.dependencies }), A.el("td", { class: "num", text: (m.unpinned || []).length }), A.el("td", { class: "small", text: (m.ai_packages || []).join(", ") })]); }))])]));
      }
      var eng = A.$("#engine-rows");
      A.clear(eng);
      Object.keys(s.engines || {}).forEach(function (k) { var e = s.engines[k]; eng.appendChild(A.el("tr", null, [A.el("td", null, [A.el("span", { class: "chip", text: k }), e.available === false ? A.el("span", { class: "badge failed", text: "unavailable" }) : null]), A.el("td", { class: "num", text: e.findings != null ? e.findings : "" }), A.el("td", { class: "num", text: e.seconds != null ? e.seconds : "" }), A.el("td", { class: "small", text: e.error || (e.mode ? "via " + e.mode : "") + (e.error_samples ? " " + e.error_samples.join("; ") : "") })])); });
      if (!Object.keys(s.engines || {}).length) eng.appendChild(A.emptyRow(4, "Engines have not run yet"));
      var cfg = r.config || {};
      kv(A.$("#details"), [["Id", r.id], ["Created", A.timeEl(r.created_at)], ["By", r.created_by], ["Started", r.started_at ? A.timeEl(r.started_at) : ""], ["Finished", r.finished_at ? A.timeEl(r.finished_at) : ""], ["Packs", (cfg.packs || []).join(", ")], ["Engines", (cfg.engines || []).join(", ")], ["Include", (cfg.include || []).join(", ")], ["Exclude", (cfg.exclude || []).join(", ")], ["Intake", inv.intake ? Object.keys(inv.intake).filter(function (k) { return inv.intake[k] !== "" && inv.intake[k] != null; }).map(function (k) { return k + "=" + inv.intake[k]; }).join(", ") : ""], ["Source tree", r.work_dir_available ? "available for the file viewer" : "cleaned up"]]);
      var rep = A.$("#reports");
      A.clear(rep);
      rep.appendChild(A.reportLinks("codereview/" + encodeURIComponent(id)));
      var packSel = A.$("#f-pack");
      if (packSel.options.length <= 1) (cfg.packs || []).forEach(function (p) { packSel.appendChild(A.el("option", { value: p, text: p })); });
    }
    function load() { return A.get("/api/codereview/runs/" + encodeURIComponent(id)).then(function (r) { render(r); loadFindings(); }, A.fail); }

    /* ---------- findings ---------- */
    function numbered(snippet, start) {
      var pre = A.el("pre", { class: "snippet" });
      String(snippet || "").split("\n").forEach(function (line, i) { pre.appendChild(A.el("span", { class: "ln", text: start + i })); pre.appendChild(document.createTextNode(line + "\n")); });
      return pre;
    }
    function setStatus(f, status, label) {
      A.promptNote(label + " " + f.rule_id, "Reviewer note (optional)", label).then(function (note) {
        if (note === null) return;
        A.post("/api/codereview/findings/" + encodeURIComponent(f.id) + "/status", { status: status, note: note || "" }).then(function () { A.toast("Finding updated", "ok"); load(); }, A.fail);
      });
    }
    function detail(f) {
      var box = A.el("div", { class: "finding-detail" });
      box.appendChild(A.el("p", { text: f.description }));
      if (f.why) box.appendChild(A.el("p", null, [A.el("strong", { text: "Why it matters: " }), f.why]));
      if (f.remediation) box.appendChild(A.el("div", null, [A.el("strong", { text: "Remediation" }), A.el("ul", null, f.remediation.split("\n").map(function (s) { return s.replace(/^-\s*/, "").trim(); }).filter(Boolean).map(function (s) { return A.el("li", { text: s }); }))]));
      if (f.snippet) box.appendChild(numbered(f.snippet, f.line_start));
      var chips = A.taxonomyChips({ owasp_labels: f.owasp_labels, category: f.category });
      if (f.cwe) chips.appendChild(A.el("a", { class: "chip", href: f.cwe_url, target: "_blank", rel: "noopener", text: f.cwe }));
      chips.appendChild(A.el("span", { class: "chip", text: "engine " + f.engine }));
      chips.appendChild(A.el("span", { class: "chip", text: "confidence " + f.confidence }));
      chips.appendChild(A.el("span", { class: "chip mono", title: f.fingerprint, text: "fp " + String(f.fingerprint || "").slice(0, 12) }));
      box.appendChild(chips);
      var tsChip = typesafeChip(f.metadata);
      if (tsChip) box.appendChild(tsChip);
      if (f.reviewer_note || f.reviewed_by) box.appendChild(A.el("p", { class: "hint", text: "Reviewed by " + (f.reviewed_by || "") + (f.reviewer_note ? ": " + f.reviewer_note : "") }));
      var actions = A.el("div", { class: "flex" });
      if (run && run.work_dir_available) actions.appendChild(A.el("button", { class: "btn xs", text: "Open file", onclick: function () { openFile(f.file, f.line_start); } }));
      if (A.isReviewer()) {
        if (f.status !== "false_positive") actions.appendChild(A.el("button", { class: "btn xs", text: "False positive", onclick: function () { setStatus(f, "false_positive", "Mark false positive"); } }));
        if (f.status !== "accepted") actions.appendChild(A.el("button", { class: "btn xs", text: "Accept risk", onclick: function () { setStatus(f, "accepted", "Accept"); } }));
        if (f.status !== "open") actions.appendChild(A.el("button", { class: "btn xs", text: "Reopen", onclick: function () { setStatus(f, "open", "Reopen"); } }));
      }
      box.appendChild(actions);
      return box;
    }
    function renderFindings(res) {
      var body = A.$("#finding-rows");
      A.clear(body);
      A.$("#f-count").textContent = res.total + " finding" + (res.total === 1 ? "" : "s");
      A.pager(A.$("#f-pager"), res.total, F.limit, F.offset, function (o) { F.offset = o; loadFindings(); });
      if (!res.items.length) { body.appendChild(A.emptyRow(9, run && !terminal(run.status) ? "Analysis in progress" : "No findings match")); return; }
      res.items.forEach(function (f) {
        var toggle = A.el("button", { class: "btn xs", text: expanded[f.id] ? "-" : "+" });
        var tr = A.el("tr", { class: f.status !== "open" ? "faint" : "" }, [
          A.el("td", null, toggle),
          A.el("td", null, A.badge(f.severity)),
          A.el("td", { class: "mono nowrap", text: f.rule_id }),
          A.el("td", { text: f.title }),
          A.el("td", null, A.el("a", { href: "#", class: "mono", text: f.file, onclick: function (e) { e.preventDefault(); if (run && run.work_dir_available) openFile(f.file, f.line_start); else { F.file = f.file; A.$("#f-file").value = f.file; F.offset = 0; loadFindings(); } } })),
          A.el("td", { class: "num", text: f.line_start }),
          A.el("td", null, A.el("span", { class: "chip", text: f.engine })),
          A.el("td", { class: "num", text: f.confidence }),
          A.el("td", null, A.badge(STATUS_LABELS[f.status] || f.status))
        ]);
        var detailRow = null;
        var show = function () { detailRow = A.el("tr", { class: "expand-row" }, A.el("td", { colspan: 9 }, detail(f))); tr.parentNode.insertBefore(detailRow, tr.nextSibling); toggle.textContent = "-"; expanded[f.id] = true; };
        toggle.addEventListener("click", function () { if (detailRow) { detailRow.parentNode.removeChild(detailRow); detailRow = null; toggle.textContent = "+"; delete expanded[f.id]; } else show(); });
        body.appendChild(tr);
        if (expanded[f.id]) show();
      });
    }
    function loadFindings() {
      return A.get("/api/codereview/runs/" + encodeURIComponent(id) + "/findings" + A.qs(F)).then(renderFindings, A.fail);
    }
    ["severity", "pack", "engine", "status"].forEach(function (k) { A.$("#f-" + k).addEventListener("change", function () { F[k] = this.value; F.offset = 0; loadFindings(); }); });
    A.$("#f-file").addEventListener("input", A.debounce(function () { F.file = A.$("#f-file").value.trim(); F.offset = 0; loadFindings(); }, 250));
    A.$("#f-search").addEventListener("input", A.debounce(function () { F.search = A.$("#f-search").value.trim(); F.offset = 0; loadFindings(); }, 250));

    /* ---------- file viewer ---------- */
    function openFile(path, line) {
      A.get("/api/codereview/runs/" + encodeURIComponent(id) + "/file?path=" + encodeURIComponent(path)).then(function (doc) {
        var marks = {};
        (doc.findings || []).forEach(function (f) { for (var n = f.line_start; n <= Math.max(f.line_start, f.line_end); n++) { marks[n] = marks[n] || []; marks[n].push(f.rule_id + " " + f.title); } });
        var view = A.$("#file-view");
        A.clear(view);
        var focus = null;
        doc.content.split("\n").forEach(function (text, i) {
          var n = i + 1;
          var row = A.el("div", { class: "line" + (marks[n] ? " hl" : "") + (n === line ? " focus" : ""), title: marks[n] ? marks[n].join("\n") : null }, [A.el("span", { class: "ln", text: n }), A.el("span", { text: text })]);
          if (n === line) focus = row;
          view.appendChild(row);
        });
        A.$("#file-path").textContent = doc.path + " (" + doc.language + ", " + doc.lines + " lines" + (doc.truncated ? ", truncated" : "") + ")";
        A.$("#file-card").classList.remove("hidden");
        A.$("#file-card").scrollIntoView({ behavior: "smooth", block: "start" });
        if (focus) setTimeout(function () { focus.scrollIntoView({ block: "center" }); }, 250);
      }, A.fail);
    }
    A.$("#file-close").addEventListener("click", function () { A.$("#file-card").classList.add("hidden"); });

    /* ---------- live updates ---------- */
    A.sse("/api/codereview/stream?replay=5&run_id=" + encodeURIComponent(id), { "*": function (data, name) {
      if (!data || data.run_id !== id || !run) return;
      if (name === "run.deleted") { window.location.href = "/codereview"; return; }
      if (name === "finding.status") { load(); return; }
      if (data.status) run.status = data.status;
      if (data.stage) run.stage = data.stage;
      if (name === "run.progress" && data.total) A.$("#progress-text").textContent = "analysing, " + data.stage + " " + data.done + "/" + data.total + " files";
      else A.$("#progress-text").textContent = run.status.toLowerCase() + (run.stage ? ", stage " + run.stage : "");
      var pct = terminal(run.status) ? 100 : Math.round(100 * Math.max(0, STAGES.indexOf(run.stage)) / (STAGES.length - 1));
      A.$("#progress").firstElementChild.style.width = pct + "%";
      A.$("#head-badges").replaceChild(A.badge(run.status), A.$("#head-badges").firstChild);
      if (terminal(data.status)) load();
    } }, { onStatus: function (on) { var conn = A.$("#nav-conn"); if (conn) { conn.classList.toggle("on", on); conn.classList.toggle("off", !on); } } });

    A.loadTaxonomy().then(load);
  };
})();
