(function () {
  "use strict";
  var A = window.AISRF;
  A.pages.reports = function () {
    var kinds = [], formats = {}, agents = [], campaigns = [];
    function filters() {
      var since = A.$("#f-since").value, until = A.$("#f-until").value;
      return {
        since: since ? new Date(since).toISOString() : "",
        until: until ? new Date(until).toISOString() : "",
        agent_id: A.$("#f-agent").value,
        campaign_id: A.$("#f-campaign").value,
        status: A.$("#f-status").value
      };
    }
    function urlFor(kind, fmt) {
      var f = filters(), path = "/api/reports/" + kind.kind, params = { format: fmt };
      if (kind.kind === "ticket") { if (!A.$("#f-ticket").value.trim()) return null; path += "/" + encodeURIComponent(A.$("#f-ticket").value.trim()); }
      else if (kind.kind === "agent") { if (!f.agent_id) return null; path += "/" + encodeURIComponent(f.agent_id); }
      else if (kind.kind === "campaign") { if (!f.campaign_id) return null; path += "/" + encodeURIComponent(f.campaign_id); }
      var accepted = kind.params || [];
      ["since", "until", "agent_id", "campaign_id", "status"].forEach(function (k) { if (f[k] && (accepted.indexOf(k) >= 0 || !accepted.length)) params[k] = f[k]; });
      if (fmt === "html" || fmt === "pdf") params.inline = 1;
      return path + A.qs(params);
    }
    function renderMatrix() {
      var head = A.$("#matrix-head"), body = A.$("#matrix-body");
      A.clear(head); A.clear(body);
      var fmts = Object.keys(formats);
      head.appendChild(A.el("tr", null, [A.el("th", { text: "Report" })].concat(fmts.map(function (f) { return A.el("th", { class: "center", text: f, title: formats[f].description || "" }); }))));
      if (!kinds.length) body.appendChild(A.emptyRow(fmts.length + 1, "Report service unavailable"));
      kinds.forEach(function (k) {
        var tr = A.el("tr", null, A.el("td", null, [A.el("div", null, A.el("strong", { text: k.kind })), A.el("div", { class: "hint", text: k.description || "" }), (k.params || []).length ? A.el("div", { class: "hint", text: "params: " + k.params.join(", ") }) : null]));
        fmts.forEach(function (f) {
          var u = urlFor(k, f);
          tr.appendChild(A.el("td", { class: "center" }, u ? A.el("a", { class: "btn xs", href: u, target: (f === "html" || f === "pdf") ? "_blank" : null, text: (formats[f].extension || f).replace(/^\./, "") }) : A.el("span", { class: "faint", text: "select " + (k.kind === "ticket" ? "ticket" : k.kind) })));
        });
        body.appendChild(tr);
      });
    }
    ["#f-since", "#f-until", "#f-agent", "#f-campaign", "#f-status", "#f-ticket"].forEach(function (s) { A.$(s).addEventListener("change", renderMatrix); A.$(s).addEventListener("input", A.debounce(renderMatrix, 300)); });
    A.get("/api/agents").then(function (list) { agents = list; A.agentOptions(A.$("#f-agent"), list); }).catch(function () {});
    A.get("/api/redteam/campaigns").then(function (r) { campaigns = Array.isArray(r) ? r : (r.items || []); var sel = A.$("#f-campaign"); campaigns.forEach(function (c) { sel.appendChild(A.el("option", { value: c.id, text: c.name + " (" + c.status + ")" })); }); }).catch(function () {});
    A.get("/api/reports").then(function (r) {
      kinds = r.kinds || []; formats = r.formats || {};
      var fb = A.$("#formats");
      Object.keys(formats).forEach(function (f) { fb.appendChild(A.el("span", { class: "chip", text: f + " (" + (formats[f].media_type || "") + ")", title: formats[f].description || "" })); });
      A.$("#matrix-status").textContent = kinds.length + " kinds x " + Object.keys(formats).length + " formats";
      renderMatrix();
    }).catch(function (e) {
      A.REPORT_FORMATS.forEach(function (f) { formats[f] = { extension: f }; });
      A.$("#matrix-status").textContent = "report service unavailable: " + e.message;
      renderMatrix();
    });
  };
})();
