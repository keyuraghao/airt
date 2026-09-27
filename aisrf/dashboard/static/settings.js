(function () {
  "use strict";
  var A = window.AISRF;
  var MASK = "********";
  var INTEGRATIONS = ["typesafe", "llm_guard", "nemo_guardrails", "lakera", "rebuff", "garak", "promptfoo", "pyrit", "pyrit_ship"];
  var SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

  /* ---------- generic controls ---------- */
  function toggle(checked, onChange, disabled) {
    var input = A.el("input", { type: "checkbox", role: "switch", disabled: !!disabled, onchange: function (e) { if (onChange) onChange(e.target.checked); } });
    input.checked = !!checked;
    var label = A.el("label", { class: "switch" }, [input, A.el("span", { class: "track" })]);
    label.input = input;
    return label;
  }
  function lockIcon() {
    return A.el("span", { class: "lock", title: "locked, environment only", html: "<svg viewBox='0 0 16 16' width='12' height='12' aria-hidden='true'><rect x='3' y='7' width='10' height='7' rx='1.5' fill='none' stroke='currentColor' stroke-width='1.5'/><path d='M5 7V5a3 3 0 0 1 6 0v2' fill='none' stroke='currentColor' stroke-width='1.5'/></svg>" });
  }
  function fmtDefault(v) {
    if (v == null || v === "") return "(empty)";
    if (Array.isArray(v)) return v.length ? v.join(", ") : "[]";
    if (typeof v === "object") return JSON.stringify(v);
    return String(v);
  }
  function linesToList(text) { return String(text || "").split(/[\n,]/).map(function (x) { return x.trim(); }).filter(Boolean); }
  function readOnlyAll(root) { A.$$("input, select, textarea, button", root).forEach(function (n) { if (!n.classList.contains("keep")) n.disabled = true; }); }
  function tryRegex(pattern, flags) { try { return new RegExp(pattern, flags || "i"); } catch (e) { return null; } }

  A.pages.settings = function () {
    var isAdmin = A.isAdmin();
    var status = A.$("#settings-status");
    var taxonomy = null;

    /* ---------- sub navigation ---------- */
    function show(section) {
      var found = false;
      A.$$(".settings-section").forEach(function (s) { var on = s.dataset.section === section; s.classList.toggle("active", on); if (on) found = true; });
      if (!found) return show("general");
      A.$$("#subnav a").forEach(function (a) { a.classList.toggle("active", a.dataset.section === section); });
      try { localStorage.setItem("aisrf.settings.section", section); } catch (e) {}
    }
    window.addEventListener("hashchange", function () { show((window.location.hash || "#general").slice(1)); });
    var initial = (window.location.hash || "").slice(1);
    if (!initial) { try { initial = localStorage.getItem("aisrf.settings.section") || "general"; } catch (e) { initial = "general"; } }
    show(initial);

    /* ---------- core schema sections ---------- */
    var schema = null;
    function fieldRow(f, dirty) {
      var row = A.el("div", { class: "setting " + (f.locked ? "locked" : "") });
      var left = A.el("div", null, [A.el("div", { class: "key" }, [f.locked ? lockIcon() : null, f.key]), f.description ? A.el("div", { class: "desc", text: f.description }) : null, A.el("div", { class: "meta", text: "default: " + fmtDefault(f.default) + "   env: " + f.env })]);
      var ctl = A.el("div", { class: "ctl" });
      var control;
      var mark = function () { row.classList.add("dirty"); dirty[f.key] = control.getValue(); };
      if (f.locked) {
        control = A.el("input", { type: "text", readonly: true, value: f.secret ? (f.value || "") : fmtDefault(f.value), title: "Set " + f.env + " in the environment and restart" });
        control.getValue = function () { return f.value; };
      } else if (f.type === "bool") {
        control = toggle(f.value, mark, !isAdmin);
        control.getValue = function () { return control.input.checked; };
      } else if (f.type === "int" || f.type === "float") {
        control = A.el("input", { type: "number", step: f.type === "float" ? "any" : "1", value: f.value == null ? "" : f.value, oninput: mark });
        control.getValue = function () { return control.value === "" ? null : Number(control.value); };
      } else if (f.type === "list") {
        control = A.el("textarea", { rows: 2, placeholder: "one per line or comma separated", oninput: mark, text: Array.isArray(f.value) ? f.value.join("\n") : (f.value || "") });
        control.getValue = function () { return linesToList(control.value); };
      } else if (f.secret) {
        control = A.el("input", { type: "password", autocomplete: "new-password", placeholder: f.value ? "stored, leave unchanged to keep" : "not set", value: f.value ? MASK : "", oninput: mark, onfocus: function () { if (control.value === MASK) control.select(); } });
        control.getValue = function () { return control.value; };
      } else {
        control = A.el("input", { type: "text", value: f.value == null ? "" : f.value, oninput: mark });
        control.getValue = function () { return control.value; };
      }
      if (!isAdmin && !f.locked) control.disabled = true;
      ctl.appendChild(control);
      var actions = A.el("div", null, (!f.locked && isAdmin) ? A.el("button", { class: "btn xs ghost", text: "Reset", title: "Reset " + f.key + " to its default / environment value", onclick: function () {
        A.post("/api/settings/core/reset", { keys: [f.key] }).then(function () { A.toast(f.key + " reset", "ok"); return loadSchema(); }).catch(A.fail);
      } }) : null);
      row.appendChild(left); row.appendChild(ctl); row.appendChild(actions);
      return row;
    }
    function renderGroup(section, group) {
      A.clear(section);
      var dirty = {};
      var fields = schema.fields.filter(function (f) { return f.group === group; });
      section.appendChild(A.el("div", { class: "card-head" }, [A.el("h2", { text: group }), A.el("span", { class: "hint", text: fields.length + " settings" + (isAdmin ? "" : ", read only for your role") })]));
      if (!fields.length) section.appendChild(A.el("div", { class: "empty", text: "No settings in this group" }));
      fields.forEach(function (f) { section.appendChild(fieldRow(f, dirty)); });
      if (isAdmin && fields.some(function (f) { return !f.locked; })) {
        section.appendChild(A.el("div", { class: "section-actions" }, [
          A.el("button", { class: "btn primary", text: "Save " + group, onclick: function () {
            var keys = Object.keys(dirty);
            if (!keys.length) { A.toast("Nothing changed", "warn", 2000); return; }
            var changes = {};
            keys.forEach(function (k) { changes[k] = dirty[k]; });
            A.api("PUT", "/api/settings/core", { changes: changes }).then(function (r) {
              var applied = Object.keys(r.applied || {});
              A.toast("Applied: " + (applied.length ? applied.join(", ") : "nothing"), "ok", 5000);
              return loadSchema();
            }).catch(A.fail);
          } }),
          A.el("button", { class: "btn", text: "Reset group to defaults", onclick: function () {
            A.confirm("Reset " + group, "Drop every dashboard override in this group so environment / default values apply again?", "Reset", "danger").then(function (ok) {
              if (!ok) return;
              A.post("/api/settings/core/reset", { keys: fields.filter(function (f) { return !f.locked; }).map(function (f) { return f.key; }) }).then(function () { A.toast(group + " reset", "ok"); return loadSchema(); }).catch(A.fail);
            });
          } }),
          A.el("span", { class: "hint", text: "changes apply live, overrides persist across restarts" })
        ]));
      }
    }
    function loadSchema() {
      return A.get("/api/settings/schema").then(function (s) {
        schema = s;
        A.$$(".settings-section[data-group]").forEach(function (sec) { renderGroup(sec, sec.dataset.group); });
        status.textContent = s.fields.length + " core settings, " + (s.namespaces || []).length + " namespaces";
      }).catch(function (e) { status.textContent = "settings API unavailable: " + e.message; });
    }

    /* ---------- namespace helpers ---------- */
    function nsLoad(ns) { return A.get("/api/settings/ns/" + ns); }
    function nsSave(ns, doc, label) {
      return A.api("PUT", "/api/settings/ns/" + ns, doc).then(function (r) { A.toast((label || ns) + " saved", "ok"); return r.value; });
    }
    function nsReset(ns, reload) {
      return A.confirm("Reset " + ns, "Restore the built-in defaults for the " + ns + " namespace?", "Reset", "danger").then(function (ok) {
        if (!ok) return;
        return A.post("/api/settings/ns/" + ns + "/reset").then(function () { A.toast(ns + " reset to defaults", "ok"); return reload(); }).catch(A.fail);
      });
    }
    function rawEditor(ns, doc, reload) {
      var ta = A.el("textarea", { class: "mono", text: JSON.stringify(doc, null, 2), disabled: !isAdmin });
      var msg = A.el("span", { class: "hint" });
      var validate = function () { try { var v = JSON.parse(ta.value); if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("document must be a JSON object"); msg.textContent = "valid JSON"; msg.style.color = ""; return v; } catch (e) { msg.textContent = "invalid: " + e.message; msg.style.color = "var(--danger)"; return null; } };
      ta.addEventListener("input", A.debounce(validate, 200));
      return A.el("details", { class: "raw raw-editor mt" }, [A.el("summary", { text: "Raw JSON editor" }), ta, A.el("div", { class: "section-actions" }, [
        isAdmin ? A.el("button", { class: "btn", text: "Save raw document", onclick: function () { var v = validate(); if (v) nsSave(ns, v, ns + " (raw)").then(reload).catch(A.fail); } }) : null,
        A.el("button", { class: "btn ghost sm", text: "Format", onclick: function () { var v = validate(); if (v) ta.value = JSON.stringify(v, null, 2); } }),
        msg
      ])]);
    }
    function sectionHead(section, title, hint, ns, reload) {
      A.clear(section);
      section.appendChild(A.el("div", { class: "card-head" }, [A.el("h2", { text: title }), A.el("span", { class: "hint grow", text: hint || "" }), isAdmin && ns ? A.el("button", { class: "btn xs ghost", text: "Reset namespace", onclick: function () { nsReset(ns, reload); } }) : null]));
    }
    function listBox(values, placeholder) { return A.el("textarea", { rows: 4, placeholder: placeholder || "one per line", text: (values || []).join("\n") }); }
    function settingRow(label, desc, control, extra) {
      return A.el("div", { class: "setting" }, [A.el("div", null, [A.el("div", { class: "key", text: label }), desc ? A.el("div", { class: "desc", text: desc }) : null]), A.el("div", { class: "ctl" }, control), A.el("div", null, extra || null)]);
    }

    /* ---------- UI namespace ---------- */
    function renderUi() {
      var section = A.$(".settings-section[data-ns=ui]");
      return nsLoad("ui").then(function (r) {
        var v = Object.assign({}, r.defaults, r.value);
        sectionHead(section, "UI preferences", "applied to every dashboard page for every user", "ui", renderUi);
        var theme = A.el("select", null, ["auto", "dark", "light"].map(function (t) { return A.el("option", { value: t, text: t }); }));
        theme.value = v.theme || "auto";
        var brand = A.el("input", { type: "text", value: v.brand_name || "", placeholder: "AISRF" });
        var color = A.el("input", { type: "color", value: /^#[0-9a-f]{6}$/i.test(v.accent_color || "") ? v.accent_color : "#4f8cff" });
        var colorText = A.el("input", { type: "text", value: v.accent_color || "", placeholder: "empty = built-in accent", style: "flex:1" });
        var live = function (val) { A.applyUi(Object.assign({}, v, { accent_color: val, brand_name: brand.value, theme: theme.value }), true); };
        color.addEventListener("input", function () { colorText.value = color.value; live(color.value); });
        colorText.addEventListener("input", function () { if (/^#[0-9a-f]{6}$/i.test(colorText.value)) color.value = colorText.value; live(colorText.value); });
        theme.addEventListener("change", function () { live(colorText.value); });
        brand.addEventListener("input", function () { live(colorText.value); });
        var refresh = A.el("input", { type: "number", min: 0, step: 1, value: v.refresh_seconds == null ? 5 : v.refresh_seconds });
        var sound = toggle(v.sound_on_new_ticket, null, !isAdmin);
        var qstatus = A.el("select", null, ["PENDING", "", "DENIED", "COMPLETED", "EXPIRED", "FAILED"].map(function (s) { return A.el("option", { value: s, text: s || "All" }); }));
        qstatus.value = v.queue_default_status == null ? "PENDING" : v.queue_default_status;
        var dateFmt = A.el("select", null, ["relative", "absolute"].map(function (s) { return A.el("option", { value: s, text: s }); }));
        dateFmt.value = v.date_format || "relative";
        section.appendChild(settingRow("theme", "auto follows the operating system; users can still toggle locally", theme));
        section.appendChild(settingRow("brand_name", "shown in the navigation and browser titles", brand));
        section.appendChild(settingRow("accent_color", "primary accent, applied live to the CSS variables", A.el("div", { class: "flex" }, [color, colorText, A.el("button", { class: "btn xs", text: "Clear", onclick: function () { colorText.value = ""; live(""); } })])));
        section.appendChild(settingRow("refresh_seconds", "fallback polling interval for stats when the live stream is unavailable (0 disables)", refresh));
        section.appendChild(settingRow("sound_on_new_ticket", "default for the audible alert on the review queue (each user can override)", sound));
        section.appendChild(settingRow("queue_default_status", "tab selected when the review queue opens", qstatus));
        section.appendChild(settingRow("date_format", "relative (5m ago) or absolute timestamps in tables", dateFmt));
        if (isAdmin) section.appendChild(A.el("div", { class: "section-actions" }, [A.el("button", { class: "btn primary", text: "Save UI", onclick: function () {
          var doc = { theme: theme.value, brand_name: brand.value.trim(), accent_color: colorText.value.trim(), refresh_seconds: Number(refresh.value || 0), sound_on_new_ticket: sound.input.checked, queue_default_status: qstatus.value, date_format: dateFmt.value, ticket_columns: v.ticket_columns || [] };
          nsSave("ui", doc, "UI preferences").then(function (val) { A.applyUi(val, false); return renderUi(); }).catch(A.fail);
        } }), A.el("button", { class: "btn", text: "Preview reset", onclick: function () { A.applyUi(A.ui || {}, true); } })]));
        else readOnlyAll(section);
        section.appendChild(rawEditor("ui", r.value, renderUi));
      }).catch(function (e) { sectionHead(section, "UI preferences"); section.appendChild(A.el("div", { class: "error-box", text: e.message })); });
    }

    /* ---------- policy namespace ---------- */
    function regexTester(getPatterns) {
      var input = A.el("input", { type: "text", class: "keep", placeholder: "paste a prompt fragment to test the patterns", style: "width:100%" });
      var out = A.el("div", { class: "small mt" });
      var run = function () {
        A.clear(out);
        var text = input.value;
        if (!text) return;
        var patterns = getPatterns();
        if (!patterns.length) { out.appendChild(A.el("span", { class: "hint", text: "no patterns" })); return; }
        patterns.forEach(function (p) {
          var re = tryRegex(p);
          var line = A.el("div", null, [A.el("code", { text: p }), " "]);
          if (!re) line.appendChild(A.el("span", { class: "match-ok", text: "invalid regex" }));
          else { var m = re.exec(text); line.appendChild(m ? A.el("span", { class: "match-ok", text: "matches: " + m[0].slice(0, 80) }) : A.el("span", { class: "match-no", text: "no match" })); }
          out.appendChild(line);
        });
      };
      input.addEventListener("input", A.debounce(run, 150));
      return { el: A.el("div", { class: "rule-test" }, [A.el("div", { class: "hint mb", text: "Regex test (case insensitive, evaluated in the browser)" }), input, out]), run: run };
    }
    function renderPolicy() {
      var section = A.$(".settings-section[data-ns=policy]");
      return nsLoad("policy").then(function (r) {
        var v = Object.assign({}, r.defaults, r.value);
        sectionHead(section, "Global policy", "applies to every agent in addition to the per-agent policy", "policy", renderPolicy);
        var deny = listBox(v.global_auto_deny_patterns, "regex per line, e.g. ignore (all )?previous instructions");
        var paths = listBox(v.global_allowed_paths, "glob per line, empty = all paths, e.g. /v1/chat/*");
        var canary = toggle(v.block_on_canary_leak, null, !isAdmin);
        var quarantine = toggle(v.quarantine_on_critical_response_finding, null, !isAdmin);
        var tester = regexTester(function () { return linesToList(deny.value); });
        deny.addEventListener("input", A.debounce(tester.run, 200));
        section.appendChild(settingRow("global_auto_deny_patterns", "requests matching any pattern are denied before reaching a reviewer", A.el("div", null, [deny, tester.el])));
        section.appendChild(settingRow("global_allowed_paths", "only these upstream paths may pass through the gateway", paths));
        section.appendChild(settingRow("block_on_canary_leak", "withhold the upstream response when an injected canary word appears in it", canary));
        section.appendChild(settingRow("quarantine_on_critical_response_finding", "hold responses with a CRITICAL response finding for review instead of relaying them", quarantine));
        if (isAdmin) section.appendChild(A.el("div", { class: "section-actions" }, A.el("button", { class: "btn primary", text: "Save policy", onclick: function () {
          var bad = linesToList(deny.value).filter(function (p) { return !tryRegex(p); });
          if (bad.length) { A.fail(new Error("Invalid regex: " + bad.join(", "))); return; }
          nsSave("policy", { global_auto_deny_patterns: linesToList(deny.value), global_allowed_paths: linesToList(paths.value), block_on_canary_leak: canary.input.checked, quarantine_on_critical_response_finding: quarantine.input.checked }, "Policy").then(renderPolicy).catch(A.fail);
        } })));
        else readOnlyAll(section);
        section.appendChild(rawEditor("policy", r.value, renderPolicy));
      }).catch(function (e) { sectionHead(section, "Global policy"); section.appendChild(A.el("div", { class: "error-box", text: e.message })); });
    }

    /* ---------- rules namespace ---------- */
    function renderRules() {
      var section = A.$(".settings-section[data-ns=rules]");
      return Promise.all([nsLoad("rules"), loadTaxonomy()]).then(function (res) {
        var r = res[0];
        var rules = ((r.value && r.value.custom) || []).map(function (x) { return Object.assign({}, x); });
        var categories = Object.keys((taxonomy && taxonomy.category_map) || {}).sort();
        sectionHead(section, "Custom detection rules", "regex rules evaluated by the analysis pipeline on requests and responses", "rules", renderRules);
        var tbody = A.el("tbody");
        var table = A.el("table", { class: "rules-table" }, [A.el("thead", null, A.el("tr", null, ["", "Id", "Name", "Pattern", "Category", "Severity", "Scope", "Action", "On", ""].map(function (h) { return A.el("th", { text: h }); }))), tbody]);
        function opts(list, value) { var s = A.el("select", null, list.map(function (x) { return A.el("option", { value: x, text: x || "(none)" }); })); if (list.indexOf(value) < 0 && value) s.appendChild(A.el("option", { value: value, text: value })); s.value = value || list[0]; return s; }
        function draw() {
          A.clear(tbody);
          if (!rules.length) tbody.appendChild(A.emptyRow(10, "No custom rules. Add one below."));
          rules.forEach(function (rule, i) {
            var pat = A.el("input", { type: "text", value: rule.pattern || "", placeholder: "regex", oninput: function (e) { rule.pattern = e.target.value; e.target.style.borderColor = tryRegex(rule.pattern) ? "" : "var(--danger)"; } });
            var cat = opts([""].concat(categories), rule.category || ""); cat.onchange = function (e) { rule.category = e.target.value; };
            var sev = opts(SEVERITIES, rule.severity || "MEDIUM"); sev.onchange = function (e) { rule.severity = e.target.value; };
            var scope = opts(["request", "response", "both"], rule.scope || "request"); scope.onchange = function (e) { rule.scope = e.target.value; };
            var action = opts(["flag", "deny"], rule.action || "flag"); action.onchange = function (e) { rule.action = e.target.value; };
            var en = toggle(rule.enabled !== false, function (c) { rule.enabled = c; }, !isAdmin);
            tbody.appendChild(A.el("tr", null, [
              A.el("td", { class: "nowrap" }, [A.el("button", { class: "btn xs ghost", text: "up", disabled: i === 0, onclick: function () { rules.splice(i - 1, 0, rules.splice(i, 1)[0]); draw(); } }), A.el("button", { class: "btn xs ghost", text: "down", disabled: i === rules.length - 1, onclick: function () { rules.splice(i + 1, 0, rules.splice(i, 1)[0]); draw(); } })]),
              A.el("td", null, A.el("input", { type: "text", value: rule.id || "", placeholder: "rule-id", oninput: function (e) { rule.id = e.target.value; } })),
              A.el("td", null, A.el("input", { type: "text", value: rule.name || "", placeholder: "name", oninput: function (e) { rule.name = e.target.value; } })),
              A.el("td", { style: "min-width:200px" }, pat),
              A.el("td", null, cat), A.el("td", null, sev), A.el("td", null, scope), A.el("td", null, action),
              A.el("td", null, en),
              A.el("td", null, A.el("button", { class: "btn xs danger", text: "Delete", onclick: function () { rules.splice(i, 1); draw(); } }))
            ]));
          });
          if (!isAdmin) readOnlyAll(table);
        }
        draw();
        section.appendChild(A.el("div", { class: "table-wrap" }, table));
        var tester = A.el("input", { type: "text", class: "keep", placeholder: "text to test against every enabled rule", style: "width:100%" });
        var testOut = A.el("div", { class: "small mt" });
        var runTest = function () {
          A.clear(testOut);
          if (!tester.value) return;
          rules.forEach(function (rule) {
            if (rule.enabled === false || !rule.pattern) return;
            var re = tryRegex(rule.pattern);
            var m = re ? re.exec(tester.value) : null;
            testOut.appendChild(A.el("div", null, [A.el("strong", { text: rule.name || rule.id || "(unnamed)" }), " ", re ? (m ? A.el("span", { class: "match-ok", text: (rule.action || "flag") + ": " + m[0].slice(0, 80) }) : A.el("span", { class: "match-no", text: "no match" })) : A.el("span", { class: "match-ok", text: "invalid regex" })]));
          });
          if (!testOut.children.length) testOut.appendChild(A.el("span", { class: "hint", text: "no enabled rules with a pattern" }));
        };
        tester.addEventListener("input", A.debounce(runTest, 150));
        section.appendChild(A.el("div", { class: "rule-test" }, [A.el("div", { class: "hint mb", text: "Test rule: runs every enabled regex in the browser (case insensitive)" }), tester, testOut]));
        section.appendChild(A.el("div", { class: "section-actions" }, [
          isAdmin ? A.el("button", { class: "btn", text: "Add rule", onclick: function () { rules.push({ id: "rule-" + (rules.length + 1), name: "", pattern: "", category: categories[0] || "", severity: "MEDIUM", scope: "request", action: "flag", enabled: true }); draw(); } }) : null,
          isAdmin ? A.el("button", { class: "btn primary", text: "Save rules", onclick: function () {
            var bad = rules.filter(function (x) { return !x.pattern || !tryRegex(x.pattern); });
            if (bad.length) { A.fail(new Error(bad.length + " rule(s) have an empty or invalid pattern")); return; }
            var ids = {};
            for (var i = 0; i < rules.length; i++) { var k = rules[i].id || ""; if (!k || ids[k]) { A.fail(new Error("Every rule needs a unique id")); return; } ids[k] = 1; }
            nsSave("rules", { custom: rules }, "Rules").then(renderRules).catch(A.fail);
          } }) : null,
          A.el("span", { class: "hint", text: rules.length + " rules, order is evaluation order" })
        ]));
        section.appendChild(rawEditor("rules", r.value, renderRules));
      }).catch(function (e) { sectionHead(section, "Custom detection rules"); section.appendChild(A.el("div", { class: "error-box", text: e.message })); });
    }

    /* ---------- analyzers namespace ---------- */
    function renderAnalyzers() {
      var section = A.$(".settings-section[data-ns=analyzers]");
      return Promise.all([A.get("/api/settings/analyzers"), loadTaxonomy()]).then(function (res) {
        var data = res[0];
        var cfg = Object.assign({ disabled: [], severity_overrides: {}, confidence_floor: 0, category_weights: {} }, data.config || {});
        cfg.disabled = (cfg.disabled || []).slice();
        cfg.severity_overrides = Object.assign({}, cfg.severity_overrides || {});
        sectionHead(section, "Analyzers", "enable or disable analyzers, override severities, set the confidence floor", "analyzers", renderAnalyzers);
        var tbody = A.el("tbody");
        function sevSelect(key) {
          var s = A.el("select", null, [A.el("option", { value: "", text: "(no override)" })].concat(SEVERITIES.map(function (x) { return A.el("option", { value: x, text: x }); })));
          s.value = cfg.severity_overrides[key] || "";
          s.onchange = function () { if (s.value) cfg.severity_overrides[key] = s.value; else delete cfg.severity_overrides[key]; };
          return s;
        }
        (data.analyzers || []).forEach(function (an) {
          var enabled = cfg.disabled.indexOf(an.name) < 0;
          tbody.appendChild(A.el("tr", null, [
            A.el("td", null, toggle(enabled, function (c) { cfg.disabled = cfg.disabled.filter(function (n) { return n !== an.name; }); if (!c) cfg.disabled.push(an.name); }, !isAdmin)),
            A.el("td", { class: "mono", text: an.name }),
            A.el("td", null, A.badge(an.kind, "accent")),
            A.el("td", { class: "small muted", text: an.description || "" }),
            A.el("td", null, sevSelect(an.name))
          ]));
        });
        if (!(data.analyzers || []).length) tbody.appendChild(A.emptyRow(5, "No analyzers registered"));
        section.appendChild(A.el("div", { class: "table-wrap" }, A.el("table", null, [A.el("thead", null, A.el("tr", null, ["Enabled", "Analyzer", "Kind", "Description", "Severity override"].map(function (h) { return A.el("th", { text: h }); }))), tbody])));
        var catBody = A.el("tbody");
        var cats = Object.keys((taxonomy && taxonomy.category_map) || {}).sort();
        var overriddenCats = Object.keys(cfg.severity_overrides).filter(function (k) { return cats.indexOf(k) >= 0; });
        function drawCats() {
          A.clear(catBody);
          overriddenCats.forEach(function (c) {
            catBody.appendChild(A.el("tr", null, [A.el("td", { class: "mono", text: c }), A.el("td", null, sevSelect(c)), A.el("td", null, A.el("button", { class: "btn xs ghost", text: "Remove", onclick: function () { delete cfg.severity_overrides[c]; overriddenCats = overriddenCats.filter(function (x) { return x !== c; }); drawCats(); } }))]));
          });
          if (!overriddenCats.length) catBody.appendChild(A.emptyRow(3, "No category overrides"));
        }
        drawCats();
        var catPick = A.el("select", null, cats.map(function (c) { return A.el("option", { value: c, text: c }); }));
        section.appendChild(A.el("h3", { class: "mt", text: "Severity override per category" }));
        section.appendChild(A.el("div", { class: "table-wrap" }, A.el("table", null, [A.el("thead", null, A.el("tr", null, ["Category", "Severity", ""].map(function (h) { return A.el("th", { text: h }); }))), catBody])));
        if (isAdmin) section.appendChild(A.el("div", { class: "flex mt" }, [catPick, A.el("button", { class: "btn sm", text: "Add category override", onclick: function () { var c = catPick.value; if (c && overriddenCats.indexOf(c) < 0) { overriddenCats.push(c); cfg.severity_overrides[c] = cfg.severity_overrides[c] || "MEDIUM"; drawCats(); } } })]));
        var floorVal = A.el("span", { class: "mono", text: Number(cfg.confidence_floor || 0).toFixed(2) });
        var floor = A.el("input", { type: "range", min: 0, max: 1, step: 0.05, value: cfg.confidence_floor || 0, oninput: function (e) { cfg.confidence_floor = Number(e.target.value); floorVal.textContent = cfg.confidence_floor.toFixed(2); } });
        section.appendChild(settingRow("confidence_floor", "findings below this confidence are dropped before scoring", A.el("div", { class: "flex" }, [floor, floorVal])));
        if (isAdmin) section.appendChild(A.el("div", { class: "section-actions" }, A.el("button", { class: "btn primary", text: "Save analyzers", onclick: function () {
          nsSave("analyzers", { disabled: cfg.disabled, severity_overrides: cfg.severity_overrides, confidence_floor: cfg.confidence_floor, category_weights: cfg.category_weights || {} }, "Analyzers").then(renderAnalyzers).catch(A.fail);
        } })));
        else readOnlyAll(section);
        section.appendChild(rawEditor("analyzers", data.config || {}, renderAnalyzers));
      }).catch(function (e) { sectionHead(section, "Analyzers"); section.appendChild(A.el("div", { class: "error-box", text: e.message })); });
    }

    /* ---------- integrations namespace ---------- */
    function renderIntegrations() {
      var section = A.$(".settings-section[data-ns=integrations]");
      return nsLoad("integrations").then(function (r) {
        var defaults = r.defaults || {}, value = r.value || {};
        sectionHead(section, "Integrations", "third party guardrails and red-team toolkits; api keys are stored server side and masked here", "integrations", renderIntegrations);
        var names = INTEGRATIONS.slice();
        Object.keys(defaults).concat(Object.keys(value)).forEach(function (n) { if (names.indexOf(n) < 0) names.push(n); });
        var grid = A.el("div", { class: "int-grid" });
        names.forEach(function (name) {
          var def = defaults[name] || { enabled: false };
          var cur = Object.assign({}, def, value[name] || {});
          var doc = Object.assign({}, cur);
          var card = A.el("div", { class: "int-card" });
          var en = toggle(cur.enabled, function (c) { doc.enabled = c; }, !isAdmin);
          card.appendChild(A.el("div", { class: "card-head" }, [A.el("h2", { text: name }), en]));
          Object.keys(cur).forEach(function (k) {
            if (k === "enabled") return;
            var dv = cur[k], ctl;
            if (typeof dv === "boolean") { ctl = toggle(dv, function (c) { doc[k] = c; }, !isAdmin); }
            else if (typeof dv === "number") { ctl = A.el("input", { type: "number", step: "any", value: dv, oninput: function (e) { doc[k] = Number(e.target.value); } }); }
            else if (Array.isArray(dv)) { ctl = A.el("textarea", { rows: 2, text: dv.join("\n"), oninput: function (e) { doc[k] = linesToList(e.target.value); } }); }
            else if (/api_key|secret|token|password/i.test(k)) { ctl = A.el("input", { type: "password", autocomplete: "new-password", value: dv ? MASK : "", placeholder: dv ? "stored, unchanged keeps it" : "not set", oninput: function (e) { doc[k] = e.target.value; } }); }
            else if (dv && typeof dv === "object") { ctl = A.el("textarea", { rows: 2, class: "mono", text: JSON.stringify(dv), oninput: function (e) { try { doc[k] = JSON.parse(e.target.value); e.target.style.borderColor = ""; } catch (ex) { e.target.style.borderColor = "var(--danger)"; } } }); }
            else { ctl = A.el("input", { type: "text", value: dv == null ? "" : dv, oninput: function (e) { doc[k] = e.target.value; } }); }
            card.appendChild(A.el("label", { class: "field mt" }, [k + (def[k] !== undefined && JSON.stringify(def[k]) !== JSON.stringify(cur[k]) ? " (default: " + fmtDefault(def[k]) + ")" : ""), ctl]));
          });
          if (isAdmin) card.appendChild(A.el("div", { class: "section-actions" }, A.el("button", { class: "btn primary sm", text: "Save " + name, onclick: function () { var p = {}; p[name] = doc; nsSave("integrations", p, name).then(renderIntegrations).catch(A.fail); } })));
          else readOnlyAll(card);
          grid.appendChild(card);
        });
        section.appendChild(grid);
        section.appendChild(rawEditor("integrations", value, renderIntegrations));
      }).catch(function (e) { sectionHead(section, "Integrations"); section.appendChild(A.el("div", { class: "error-box", text: e.message })); });
    }

    /* ---------- export / import ---------- */
    function renderExport() {
      var section = A.$(".settings-section[data-section=export]");
      A.clear(section);
      section.appendChild(A.el("div", { class: "card-head" }, [A.el("h2", { text: "Export / Import" }), A.el("span", { class: "hint", text: "admin only" })]));
      var secrets = A.el("input", { type: "checkbox" });
      var file = A.el("input", { type: "file", accept: "application/json,.json" });
      var preview = A.el("pre", { class: "hidden" });
      var importBtn = A.el("button", { class: "btn primary", text: "Import", disabled: true });
      var parsed = null;
      file.addEventListener("change", function () {
        parsed = null; importBtn.disabled = true; preview.classList.add("hidden");
        var f = file.files && file.files[0];
        if (!f) return;
        var reader = new FileReader();
        reader.onload = function () {
          try {
            parsed = JSON.parse(String(reader.result));
            if (!parsed || typeof parsed !== "object") throw new Error("not a JSON object");
            preview.textContent = "core keys: " + Object.keys(parsed.core || {}).length + "\nnamespaces: " + Object.keys(parsed.namespaces || {}).join(", ");
            preview.classList.remove("hidden");
            importBtn.disabled = !isAdmin;
          } catch (e) { A.fail(new Error("Invalid settings file: " + e.message)); }
        };
        reader.readAsText(f);
      });
      importBtn.addEventListener("click", function () {
        if (!parsed) return;
        A.confirm("Import settings", "Apply every core setting and namespace document in this file? Existing overrides are replaced.", "Import", "danger").then(function (ok) {
          if (!ok) return;
          A.post("/api/settings/import", parsed).then(function (r) {
            var ap = r.applied || {};
            A.toast("Imported " + Object.keys(ap.core || {}).length + " core keys and " + Object.keys(ap.namespaces || {}).length + " namespaces", "ok", 6000);
            loadAll();
          }).catch(A.fail);
        });
      });
      section.appendChild(settingRow("Export", "download every core setting and namespace document as JSON", A.el("div", { class: "flex wrap" }, [
        A.el("button", { class: "btn", text: "Download settings.json", disabled: !isAdmin, onclick: function () {
          A.get("/api/settings/export?include_secrets=" + (secrets.checked ? "true" : "false")).then(function (doc) { A.download("aisrf-settings-" + new Date().toISOString().slice(0, 10) + ".json", JSON.stringify(doc, null, 2)); }).catch(A.fail);
        } }),
        A.el("label", { class: "check" }, [secrets, "include secrets"])
      ])));
      section.appendChild(settingRow("Import", "upload a settings.json produced by the export", A.el("div", { class: "stack" }, [file, preview, A.el("div", null, importBtn)])));
    }

    /* ---------- taxonomy ---------- */
    function loadTaxonomy() {
      if (taxonomy) return Promise.resolve(taxonomy);
      return A.get("/api/settings/taxonomy").then(function (t) { taxonomy = t; A.taxonomy = t; return t; });
    }
    function renderTaxonomy() {
      var box = A.$("#taxonomy");
      return loadTaxonomy().then(function (t) {
        A.clear(box);
        box.appendChild(A.el("h3", { text: "OWASP Top 10 for LLM Applications" }));
        var tb = A.el("tbody");
        (t.owasp || []).forEach(function (o) { tb.appendChild(A.el("tr", null, [A.el("td", null, A.el("span", { class: "chip owasp", text: o.id })), A.el("td", null, o.url ? A.el("a", { href: o.url, target: "_blank", rel: "noopener", text: o.name }) : o.name), A.el("td", { class: "small muted", text: o.description || "" })])); });
        box.appendChild(A.el("div", { class: "table-wrap" }, A.el("table", null, [A.el("thead", null, A.el("tr", null, [A.el("th", { text: "Id" }), A.el("th", { text: "Name" }), A.el("th", { text: "Description" })])), tb])));
        box.appendChild(A.el("h3", { class: "mt", text: "Category mapping" }));
        var cb = A.el("tbody");
        Object.keys(t.category_map || {}).sort().forEach(function (c) {
          var m = t.category_map[c];
          cb.appendChild(A.el("tr", null, [A.el("td", { class: "mono", text: c }), A.el("td", null, A.el("div", { class: "chips" }, (m.owasp || []).map(function (x) { return A.el("span", { class: "chip owasp", text: x }); }))), A.el("td", null, A.el("div", { class: "chips" }, (m.greshake || []).map(function (x) { return A.el("span", { class: "chip greshake", text: x, title: (t.greshake_threats || {})[x] || (t.greshake_delivery || {})[x] || "" }); }))), A.el("td", null, A.el("div", { class: "chips" }, (m.thacker || []).map(function (x) { return A.el("span", { class: "chip thacker", text: x, title: (t.thacker_techniques || {})[x] || "" }); })))]));
        });
        box.appendChild(A.el("div", { class: "table-wrap" }, A.el("table", null, [A.el("thead", null, A.el("tr", null, ["Category", "OWASP", "Greshake et al.", "Thacker"].map(function (h) { return A.el("th", { text: h }); }))), cb])));
        var defs = function (title, map) {
          if (!map || !Object.keys(map).length) return;
          box.appendChild(A.el("h3", { class: "mt", text: title }));
          box.appendChild(A.el("dl", { class: "kv" }, Object.keys(map).reduce(function (acc, k) { acc.push(A.el("dt", { class: "mono", text: k })); acc.push(A.el("dd", { class: "small muted", text: map[k] })); return acc; }, [])));
        };
        defs("Greshake threats", t.greshake_threats);
        defs("Greshake delivery methods", t.greshake_delivery);
        defs("Thacker techniques", t.thacker_techniques);
        box.appendChild(A.el("h3", { class: "mt", text: "References" }));
        box.appendChild(A.el("ul", { class: "small" }, (t.references || []).map(function (ref) { return A.el("li", null, [A.el("a", { href: ref.url, target: "_blank", rel: "noopener", text: ref.title }), A.el("span", { class: "hint", text: " " + ref.id })]); })));
      }).catch(function (e) { A.clear(box).appendChild(A.el("div", { class: "error-box", text: "taxonomy unavailable: " + e.message })); });
    }

    /* ---------- reviewers (existing) ---------- */
    var rows = A.$("#reviewer-rows"), form = A.$("#reviewer-form");
    function loadReviewers() {
      if (!rows) return Promise.resolve();
      return A.get("/api/auth/reviewers").then(function (list) {
        A.clear(rows);
        list.forEach(function (r) {
          var self = A.principal && r.id === A.principal.id;
          rows.appendChild(A.el("tr", null, [
            A.el("td", null, [r.username, self ? A.el("span", { class: "hint", text: " (you)" }) : null]),
            A.el("td", null, A.badge(r.role, "role")),
            A.el("td", null, r.is_active ? A.badge("active", "ok") : A.badge("inactive", "expired")),
            A.el("td", null, r.last_login_at ? A.timeEl(r.last_login_at) : A.el("span", { class: "faint", text: "never" })),
            A.el("td", { class: "nowrap" }, [
              A.el("button", { class: "btn xs", text: "Password", onclick: function () { changePassword(r); } }), " ",
              r.is_active && !self ? A.el("button", { class: "btn xs danger", text: "Deactivate", onclick: function () {
                A.confirm("Deactivate " + r.username, "The account will no longer be able to sign in.", "Deactivate", "danger").then(function (ok) { if (ok) A.del("/api/auth/reviewers/" + r.id).then(function () { A.toast("Deactivated", "warn"); loadReviewers(); }).catch(A.fail); });
              } }) : null
            ])
          ]));
        });
      }).catch(A.fail);
    }
    function changePassword(r) {
      var input = A.el("input", { type: "password", placeholder: "new password", autocomplete: "new-password", style: "width:100%" });
      A.modal("Change password for " + r.username, input, [{ label: "Cancel" }, { label: "Save", class: "primary", onClick: function () {
        if (!input.value) { A.toast("Password required", "warn"); return false; }
        A.post("/api/auth/reviewers/" + r.id + "/password", { password: input.value }).then(function () { A.toast("Password updated", "ok"); }).catch(A.fail);
      } }]);
    }
    if (form) form.addEventListener("submit", function (e) {
      e.preventDefault();
      var fd = new FormData(form), o = {};
      fd.forEach(function (v, k) { o[k] = v; });
      A.post("/api/auth/reviewers", { username: o.username.trim(), password: o.password, role: o.role }).then(function () { A.toast("Reviewer created", "ok"); form.reset(); loadReviewers(); }).catch(A.fail);
    });
    A.$("#own-password-form").addEventListener("submit", function (e) {
      e.preventDefault();
      var pw = e.target.querySelector("[name=password]").value;
      A.post("/api/auth/reviewers/" + A.principal.id + "/password", { password: pw }).then(function () { A.toast("Your password was updated", "ok"); e.target.reset(); }).catch(A.fail);
    });
    var integ = A.$("#integration");
    integ.appendChild(A.snippetPanel(null));
    integ.appendChild(A.el("dl", { class: "kv mt" }, [
      A.el("dt", { text: "OpenAI style" }), A.el("dd", { class: "mono small", text: window.location.origin + "/v1/..." }),
      A.el("dt", { text: "Anthropic style" }), A.el("dd", { class: "mono small", text: window.location.origin + "/v1/messages" }),
      A.el("dt", { text: "Generic proxy" }), A.el("dd", { class: "mono small", text: window.location.origin + "/proxy/<path> with X-AISRF-Key" }),
      A.el("dt", { text: "Async mode" }), A.el("dd", { class: "small", text: "send X-AISRF-Async: 1 to get 202 + ticket id, poll /gateway/tickets/{id}" }),
      A.el("dt", { text: "Automation" }), A.el("dd", { class: "small", text: "set AISRF_ADMIN_API_TOKEN and send it as Authorization: Bearer for the reviewer REST API" })
    ]));

    function loadAll() {
      loadSchema();
      renderUi(); renderPolicy(); renderRules(); renderAnalyzers(); renderIntegrations();
      renderExport(); renderTaxonomy(); loadReviewers();
    }
    loadAll();
  };
})();
