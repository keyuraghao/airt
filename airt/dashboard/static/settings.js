(function () {
  "use strict";
  var A = window.AIRT;
  A.pages.settings = function () {
    var rows = A.$("#reviewer-rows"), form = A.$("#reviewer-form");
    function load() {
      if (!rows) return;
      A.get("/api/auth/reviewers").then(function (list) {
        A.clear(rows);
        list.forEach(function (r) {
          var self = A.principal && r.id === A.principal.id;
          var actions = A.el("td", { class: "nowrap" }, [
            A.el("button", { class: "btn xs", text: "Password", onclick: function () { changePassword(r); } }),
            " ",
            r.is_active && !self ? A.el("button", { class: "btn xs danger", text: "Deactivate", onclick: function () {
              A.confirm("Deactivate " + r.username, "The account will no longer be able to sign in.", "Deactivate", "danger").then(function (ok) { if (ok) A.del("/api/auth/reviewers/" + r.id).then(function () { A.toast("Deactivated", "warn"); load(); }).catch(A.fail); });
            } }) : null
          ]);
          rows.appendChild(A.el("tr", null, [
            A.el("td", null, [r.username, self ? A.el("span", { class: "hint", text: " (you)" }) : null]),
            A.el("td", null, A.badge(r.role, "role")),
            A.el("td", null, r.is_active ? A.badge("active", "ok") : A.badge("inactive", "expired")),
            A.el("td", null, r.last_login_at ? A.timeEl(r.last_login_at) : A.el("span", { class: "faint", text: "never" })),
            actions
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
      A.post("/api/auth/reviewers", { username: o.username.trim(), password: o.password, role: o.role }).then(function () { A.toast("Reviewer created", "ok"); form.reset(); load(); }).catch(A.fail);
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
      A.el("dt", { text: "Generic proxy" }), A.el("dd", { class: "mono small", text: window.location.origin + "/proxy/<path> with X-AIRT-Key" }),
      A.el("dt", { text: "Async mode" }), A.el("dd", { class: "small", text: "send X-AIRT-Async: 1 to get 202 + ticket id, poll /gateway/tickets/{id}" }),
      A.el("dt", { text: "Automation" }), A.el("dd", { class: "small", text: "set AIRT_ADMIN_API_TOKEN and send it as Authorization: Bearer for the reviewer REST API" }),
      A.el("dt", { text: "Metrics" }), A.el("dd", null, [A.link("/metrics", "/metrics"), " (Prometheus), ", A.link("/healthz", "/healthz"), ", ", A.link("/api/docs", "/api/docs")])
    ]));
    load();
  };
})();
