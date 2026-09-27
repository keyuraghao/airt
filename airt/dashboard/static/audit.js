(function () {
  "use strict";
  var A = window.AIRT;
  A.pages.audit = function () {
    var LIMIT = 100, offset = 0;
    function load() {
      var q = { limit: LIMIT, offset: offset, action: A.$("#f-action").value.trim(), actor: A.$("#f-actor").value.trim() };
      A.get("/api/audit" + A.qs(q)).then(function (r) {
        var rows = A.$("#audit-rows");
        A.clear(rows);
        if (!r.items.length) rows.appendChild(A.emptyRow(8, "No audit entries"));
        r.items.forEach(function (e) {
          var target = e.target_type + ":" + e.target_id;
          var link = e.target_type === "ticket" ? "/tickets/" + e.target_id : e.target_type === "agent" ? "/agents/" + e.target_id : e.target_type === "campaign" ? "/redteam/" + e.target_id : null;
          rows.appendChild(A.el("tr", null, [
            A.el("td", { class: "num", text: e.id }),
            A.el("td", null, A.el("span", { title: A.fmtTs(e.ts), text: A.fmtTs(e.ts) })),
            A.el("td", { text: e.actor }),
            A.el("td", null, [A.badge(e.action.split(".").pop(), "accent"), A.el("span", { class: "hint", text: " " + e.action })]),
            A.el("td", { class: "mono small" }, link ? A.link(link, target) : target),
            A.el("td", { class: "small" }, Object.keys(e.detail || {}).length ? A.el("details", { class: "raw" }, [A.el("summary", { text: Object.keys(e.detail).length + " fields" }), A.jsonPre(e.detail)]) : ""),
            A.el("td", { class: "mono small faint", text: (e.prev_hash || "").slice(0, 12), title: e.prev_hash }),
            A.el("td", { class: "mono small copyable", text: (e.hash || "").slice(0, 12), title: e.hash + " (click to copy)", onclick: function () { A.copy(e.hash); } })
          ]));
        });
        A.pager(A.$("#pager"), r.total, LIMIT, offset, function (o) { offset = o; load(); });
      }).catch(A.fail);
    }
    A.$("#apply-btn").addEventListener("click", function () { offset = 0; load(); });
    A.$("#f-action").addEventListener("keydown", function (e) { if (e.key === "Enter") { offset = 0; load(); } });
    A.$("#f-actor").addEventListener("keydown", function (e) { if (e.key === "Enter") { offset = 0; load(); } });
    A.$("#verify-btn").addEventListener("click", function () {
      var box = A.$("#verify-result");
      A.clear(box).appendChild(A.el("div", { class: "hint", text: "Verifying chain..." }));
      A.get("/api/audit/verify").then(function (r) {
        var ok = r.ok !== undefined ? r.ok : (r.valid !== undefined ? r.valid : r.status === "ok");
        A.clear(box).appendChild(A.el("div", { class: "card", style: "border-color:" + (ok ? "var(--ok)" : "var(--danger)") }, [
          A.el("div", { class: "flex" }, [A.badge(ok ? "chain intact" : "chain broken", ok ? "ok" : "failed"), A.el("span", { class: "muted", text: (r.checked != null ? r.checked : r.entries != null ? r.entries : r.count != null ? r.count : "") + " entries checked" })]),
          !ok ? A.jsonPre(r) : null
        ]));
      }).catch(function (e) { A.clear(box).appendChild(A.el("div", { class: "error-box", text: e.message })); });
    });
    load();
  };
})();
