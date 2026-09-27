(function () {
  "use strict";
  var A = window.AIRT;
  A.snippets = function (key, provider) {
    var origin = window.location.origin;
    var k = key || "<AIRT agent key>";
    return {
      "OpenAI SDK": "from openai import OpenAI\nclient = OpenAI(base_url=\"" + origin + "/v1\", api_key=\"" + k + "\")\nresp = client.chat.completions.create(model=\"gpt-4o-mini\", messages=[{\"role\": \"user\", \"content\": \"hello\"}])\nprint(resp.choices[0].message.content)",
      "Anthropic SDK": "import anthropic\nclient = anthropic.Anthropic(base_url=\"" + origin + "\", api_key=\"" + k + "\")\nmsg = client.messages.create(model=\"claude-sonnet-4-5\", max_tokens=256, messages=[{\"role\": \"user\", \"content\": \"hello\"}])\nprint(msg.content[0].text)",
      "curl": "curl " + origin + "/v1/chat/completions \\\n  -H \"Authorization: Bearer " + k + "\" \\\n  -H \"Content-Type: application/json\" \\\n  -d '{\"model\": \"gpt-4o-mini\", \"messages\": [{\"role\": \"user\", \"content\": \"hello\"}]}'",
      "Any HTTP client": "POST " + origin + "/proxy/<upstream path>\nX-AIRT-Key: " + k + "\nX-AIRT-Async: 1   (optional: returns 202 + ticket id, poll " + origin + "/gateway/tickets/{id})",
      "Environment": "export OPENAI_BASE_URL=" + origin + "/v1\nexport OPENAI_API_KEY=" + k + "\nexport ANTHROPIC_BASE_URL=" + origin + "\nexport ANTHROPIC_API_KEY=" + k
    };
  };
  A.snippetPanel = function (key) {
    var snippets = A.snippets(key);
    var names = Object.keys(snippets);
    var wrap = A.el("div");
    var tabs = A.el("div", { class: "snippet-tabs flex wrap" });
    var pre = A.el("pre", { text: snippets[names[0]] });
    names.forEach(function (n, i) {
      tabs.appendChild(A.el("button", { type: "button", class: "btn xs" + (i === 0 ? " active" : ""), text: n, onclick: function (e) { A.$$("button", tabs).forEach(function (b) { b.classList.remove("active"); }); e.target.classList.add("active"); pre.textContent = snippets[n]; } }));
    });
    tabs.appendChild(A.el("button", { type: "button", class: "btn xs ghost", text: "Copy", onclick: function () { A.copy(pre.textContent); } }));
    wrap.appendChild(tabs);
    wrap.appendChild(pre);
    return wrap;
  };
  A.showKeyModal = function (agent, key, title) {
    var input = A.el("input", { type: "text", readonly: true, value: key, class: "mono", style: "width:100%", onclick: function (e) { e.target.select(); } });
    var body = A.el("div", { class: "stack" }, [
      A.el("p", { class: "muted", text: "This key is shown only once. Store it in the agent's secret manager now; it cannot be recovered, only rotated." }),
      A.el("div", { class: "flex" }, [input, A.el("button", { class: "btn primary", text: "Copy", onclick: function () { A.copy(key); } })]),
      A.el("h3", { text: "Integration snippets for " + agent.name }),
      A.snippetPanel(key)
    ]);
    A.modal(title || "API key for " + agent.name, body, [{ label: "I stored the key", class: "primary" }]);
  };
  A.listsFromForm = function (form) {
    var fd = new FormData(form), out = {};
    fd.forEach(function (v, k) { out[k] = v; });
    var lines = function (s) { return String(s || "").split(/\r?\n/).map(function (x) { return x.trim(); }).filter(Boolean); };
    var payload = {
      name: out.name.trim(),
      description: out.description || "",
      owner: out.owner || "",
      tags: String(out.tags || "").split(",").map(function (x) { return x.trim(); }).filter(Boolean),
      upstream_provider: out.upstream_provider || "openai",
      upstream_base_url: out.upstream_base_url ? out.upstream_base_url.trim() : null,
      upstream_api_key: out.upstream_api_key ? out.upstream_api_key : null,
      upstream_auth_header: out.upstream_auth_header || "",
      require_approval: !!form.querySelector("[name=require_approval]").checked,
      auto_approve_below_risk: Number(out.auto_approve_below_risk || 0),
      auto_deny_at_risk: Number(out.auto_deny_at_risk || 90),
      auto_deny_patterns: lines(out.auto_deny_patterns),
      allowed_paths: lines(out.allowed_paths),
      allowed_models: lines(out.allowed_models),
      rate_limit_per_minute: Number(out.rate_limit_per_minute || 0)
    };
    var extra = String(out.upstream_extra_headers || "").trim();
    if (extra) { try { payload.upstream_extra_headers = JSON.parse(extra); } catch (e) { throw new Error("Extra upstream headers must be a JSON object"); } }
    else payload.upstream_extra_headers = {};
    return payload;
  };
  A.pages.agents = function () {
    var rows = A.$("#agent-rows"), card = A.$("#create-card"), form = A.$("#agent-form");
    var showInactive = A.$("#show-inactive");
    if (!A.isAdmin()) A.$("#new-agent-btn").classList.add("hidden");
    A.$("#new-agent-btn").addEventListener("click", function () { card.classList.remove("hidden"); form.querySelector("[name=name]").focus(); });
    A.$("#cancel-create").addEventListener("click", function () { card.classList.add("hidden"); });
    showInactive.addEventListener("change", load);
    function load() {
      A.get("/api/agents?include_inactive=" + (showInactive.checked ? "true" : "false")).then(function (list) {
        A.clear(rows);
        if (!list.length) rows.appendChild(A.emptyRow(9, "No agents registered yet"));
        list.forEach(function (a) {
          var thresholds = "approve <" + a.auto_approve_below_risk + ", deny >=" + a.auto_deny_at_risk + (a.rate_limit_per_minute ? ", " + a.rate_limit_per_minute + "/min" : "");
          rows.appendChild(A.el("tr", null, [
            A.el("td", null, [A.link("/agents/" + a.id, a.name), a.description ? A.el("div", { class: "hint truncate", text: a.description }) : null]),
            A.el("td", null, A.badge(a.upstream_provider, "accent")),
            A.el("td", { class: "mono small truncate", text: a.upstream_base_url || "", title: a.upstream_base_url || "" }),
            A.el("td", null, a.require_approval ? A.badge("required", "pending") : A.badge("auto", "low")),
            A.el("td", { class: "small", text: thresholds }),
            A.el("td", { class: "right num", text: a.request_count == null ? "" : a.request_count }),
            A.el("td", null, a.last_seen_at ? A.timeEl(a.last_seen_at) : A.el("span", { class: "faint", text: "never" })),
            A.el("td", null, a.is_active ? A.badge("active", "ok") : A.badge("disabled", "expired")),
            A.el("td", null, A.el("a", { class: "btn xs", href: "/agents/" + a.id, text: "Open" }))
          ]));
        });
      }).catch(A.fail);
    }
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var payload;
      try { payload = A.listsFromForm(form); } catch (ex) { A.fail(ex); return; }
      A.post("/api/agents", payload).then(function (a) {
        A.toast("Agent " + a.name + " created", "ok");
        form.reset();
        card.classList.add("hidden");
        load();
        A.showKeyModal(a, a.api_key);
      }).catch(A.fail);
    });
    load();
  };
})();
