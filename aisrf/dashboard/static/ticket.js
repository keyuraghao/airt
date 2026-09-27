(function () {
  "use strict";
  var A = window.AISRF;
  A.pages.ticket = function () {
    var id = document.body.getAttribute("data-ticket-id");
    var ticket = null, canDecide = A.isReviewer();
    function highlighted(text, snippets) {
      /* Build a text node sequence with <mark> around evidence snippets, never injecting HTML. */
      var frag = document.createDocumentFragment();
      text = String(text == null ? "" : text);
      var ranges = [];
      (snippets || []).forEach(function (s) {
        if (!s || s.length < 3) return;
        var lower = text.toLowerCase(), needle = s.toLowerCase(), from = 0, idx;
        while ((idx = lower.indexOf(needle, from)) >= 0 && ranges.length < 200) { ranges.push([idx, idx + s.length]); from = idx + s.length; }
      });
      ranges.sort(function (a, b) { return a[0] - b[0]; });
      var pos = 0;
      ranges.forEach(function (r) {
        if (r[0] < pos) return;
        if (r[0] > pos) frag.appendChild(document.createTextNode(text.slice(pos, r[0])));
        frag.appendChild(A.el("mark", { class: "ev", text: text.slice(r[0], r[1]) }));
        pos = r[1];
      });
      if (pos < text.length) frag.appendChild(document.createTextNode(text.slice(pos)));
      return frag;
    }
    function findingCard(f) {
      var sev = String(f.severity || "INFO").toLowerCase();
      return A.el("div", { class: "finding " + sev }, [
        A.el("div", { class: "flex wrap" }, [A.badge(f.severity || "INFO"), A.el("span", { class: "title", text: f.title || f.category || "finding" }), A.el("span", { class: "hint", text: (f.analyzer || "") + (f.category ? " / " + f.category : "") })]),
        A.taxonomyChips(f),
        f.description ? A.el("div", { class: "small muted", text: f.description }) : null,
        f.evidence ? A.el("div", { class: "evidence", text: f.evidence }) : null,
        A.el("div", { class: "hint" }, [f.location ? "at " + f.location + "  " : "", f.confidence != null ? "confidence " + Math.round(Number(f.confidence) * 100) + "%" : "", (f.tags || []).length ? "  tags: " + f.tags.join(", ") : ""])
      ]);
    }
    function renderFindings(container, list, countEl) {
      A.clear(container);
      if (countEl) countEl.textContent = list.length ? list.length + " finding" + (list.length > 1 ? "s" : "") : "";
      if (!list.length) { container.appendChild(A.el("div", { class: "empty", text: "No findings" })); return; }
      list.slice().sort(function (a, b) { return sevRank(b.severity) - sevRank(a.severity); }).forEach(function (f) { container.appendChild(findingCard(f)); });
    }
    function sevRank(s) { return { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }[s] || 0; }
    function kv(dl, pairs) {
      A.clear(dl);
      pairs.forEach(function (p) {
        if (p[1] == null || p[1] === "") return;
        dl.appendChild(A.el("dt", { text: p[0] }));
        dl.appendChild(A.el("dd", { class: p[2] || "" }, p[1]));
      });
    }
    function render(t) {
      ticket = t;
      document.title = "#" + (t.number || "") + " " + t.status + " - AISRF";
      A.$("#title").textContent = "Ticket #" + (t.number || t.id);
      var hb = A.$("#head-badges");
      A.clear(hb);
      hb.appendChild(A.badge(t.status));
      hb.appendChild(A.riskBadge(t.risk_level, t.risk_score));
      if (t.policy_action) hb.appendChild(A.badge(t.policy_action));
      if (t.source && t.source !== "gateway") hb.appendChild(A.badge(t.source, "accent"));
      var links = A.$("#head-links");
      A.clear(links);
      if (t.agent_id) links.appendChild(A.el("a", { class: "btn sm", href: "/agents/" + t.agent_id, text: "Agent: " + (t.agent ? t.agent.name : t.agent_name || t.agent_id) }));
      if (t.campaign_id) links.appendChild(A.el("a", { class: "btn sm", href: "/redteam/" + t.campaign_id, text: "Campaign" }));
      links.appendChild(A.el("a", { class: "btn sm", href: "/tickets?agent_id=" + encodeURIComponent(t.agent_id || ""), text: "More from this agent" }));
      kv(A.$("#summary"), [
        ["Id", A.el("span", { class: "mono copyable", text: t.id, title: "click to copy", onclick: function () { A.copy(t.id); } })],
        ["Correlation", t.correlation_id, "mono small"],
        ["Agent", t.agent ? A.link("/agents/" + t.agent_id, t.agent.name) : (t.agent_name || t.agent_id)],
        ["Model", t.model, "mono"],
        ["Endpoint", (t.method || "") + " " + (t.path || ""), "mono small"],
        ["Upstream", t.upstream_url, "mono small"],
        ["Provider", t.normalized && t.normalized.provider],
        ["Stream", t.is_stream ? "yes" : "no"],
        ["Client", [t.client_ip || "", t.user_agent ? " " + t.user_agent : ""].join(""), "small"],
        ["Created", A.fmtTs(t.created_at) + " (" + A.relTime(t.created_at) + ")"],
        ["Expires", t.status === "PENDING" && t.expires_at ? A.el("span", { class: "countdown", "data-countdown": t.expires_at, text: A.countdown(t.expires_at) }) : (t.expires_at ? A.fmtTs(t.expires_at) : null)],
        ["Decided", t.decided_at ? A.fmtTs(t.decided_at) + (t.decided_by ? " by " + t.decided_by : "") : null],
        ["Decision note", t.decision_note],
        ["Forwarded", t.forwarded_at ? A.fmtTs(t.forwarded_at) : null],
        ["Response", t.response_status != null ? "HTTP " + t.response_status + (t.latency_ms != null ? ", " + A.fmtMs(t.latency_ms) : "") : null],
        ["Analysis", t.analysis_ms != null ? A.fmtMs(t.analysis_ms) : null],
        ["Error", t.error, "small"],
        ["Probe", t.probe_id, "mono small"]
      ]);
      var evidence = (t.findings || []).map(function (f) { return f.evidence; }).filter(Boolean);
      var chat = A.$("#chat");
      A.clear(chat);
      var n = t.normalized || {};
      var msgs = n.messages || [];
      A.$("#conv-meta").textContent = msgs.length + " messages" + (n.tools && n.tools.length ? ", " + n.tools.length + " tools" : "") + (n.char_count ? ", " + n.char_count + " chars" : "");
      if (n.system && !msgs.some(function (m) { return m.role === "system" || m.role === "developer"; })) msgs = [{ role: "system", content: n.system }].concat(msgs);
      if (!msgs.length) chat.appendChild(A.el("div", { class: "empty", text: "No conversation could be extracted from this request" }));
      msgs.forEach(function (m) {
        var role = String(m.role || "user").toLowerCase();
        var cls = ["system", "developer", "user", "assistant", "tool"].indexOf(role) >= 0 ? role : "tool";
        var b = A.el("div", { class: "bubble " + cls }, A.el("div", { class: "role", text: role + (m.name ? " (" + m.name + ")" : "") }));
        b.appendChild(highlighted(m.content, evidence));
        chat.appendChild(b);
      });
      if (n.tools && n.tools.length) {
        chat.appendChild(A.el("details", { class: "raw" }, [A.el("summary", { text: "Tools offered (" + n.tools.length + ")" }), A.el("div", { class: "chips" }, n.tools.map(function (tl) { return A.el("span", { class: "chip", text: tl.name, title: tl.description || "" }); }))]));
      }
      renderFindings(A.$("#findings"), t.findings || [], A.$("#findings-count"));
      renderFindings(A.$("#response-findings"), t.response_findings || [], null);
      var pol = A.$("#policy");
      A.clear(pol);
      var pd = t.policy_decision || {};
      if (!pd.action) pol.appendChild(A.el("div", { class: "empty", text: "No policy decision recorded" }));
      else {
        pol.appendChild(A.el("div", { class: "flex" }, [A.badge(pd.action), A.el("span", { class: "hint", text: (pd.matched_rules || []).join(", ") })]));
        var ul = A.el("ul", { class: "small mt" });
        (pd.reasons || []).forEach(function (r) { ul.appendChild(A.el("li", { text: r })); });
        pol.appendChild(ul);
      }
      var tl = A.$("#timeline");
      A.clear(tl);
      (t.events || []).forEach(function (e) {
        var detail = Object.keys(e.detail || {}).map(function (k) { var v = e.detail[k]; return k + "=" + (typeof v === "object" ? JSON.stringify(v) : v); }).join("  ");
        tl.appendChild(A.el("li", { class: e.event_type }, [A.el("div", { class: "flex" }, [A.el("strong", { text: e.event_type }), A.el("span", { class: "hint", text: e.actor })]), A.el("div", { class: "hint", text: A.fmtTs(e.ts) }), detail ? A.el("div", { class: "small muted mono", text: detail }) : null]));
      });
      if (!(t.events || []).length) tl.appendChild(A.el("li", { class: "faint", text: "No events" }));
      var resp = A.$("#response");
      A.clear(resp);
      A.$("#resp-meta").textContent = t.response_status != null ? "HTTP " + t.response_status + (t.latency_ms != null ? ", " + A.fmtMs(t.latency_ms) : "") : "";
      if (t.response_preview) resp.appendChild(A.el("div", { class: "bubble assistant", style: "max-width:100%" }, [A.el("div", { class: "role", text: "assistant (preview)" }), highlighted(t.response_preview, (t.response_findings || []).map(function (f) { return f.evidence; }).filter(Boolean))]));
      if (t.response_body) resp.appendChild(A.el("details", { class: "raw" }, [A.el("summary", { text: "Raw response body (" + t.response_body.length + " chars)" }), A.jsonPre(pretty(t.response_body))]));
      if (t.response_headers && Object.keys(t.response_headers).length) resp.appendChild(A.el("details", { class: "raw" }, [A.el("summary", { text: "Response headers" }), A.jsonPre(t.response_headers)]));
      if (!t.response_preview && !t.response_body) resp.appendChild(A.el("div", { class: "empty", text: t.status === "DENIED" || t.status === "EXPIRED" ? "Nothing was sent upstream" : "No response recorded yet" }));
      var req = A.$("#request");
      A.clear(req);
      req.appendChild(A.el("details", { class: "raw" }, [A.el("summary", { text: "Request headers (redacted)" }), A.jsonPre(t.request_headers || {})]));
      req.appendChild(A.el("details", { class: "raw" }, [A.el("summary", { text: "Raw request JSON" }), A.jsonPre(t.request_json != null ? t.request_json : (t.request_body || ""))]));
      req.appendChild(A.el("details", { class: "raw" }, [A.el("summary", { text: "Normalized request" }), A.jsonPre(n)]));
      var rep = A.$("#reports");
      A.clear(rep);
      rep.appendChild(A.reportLinks("ticket/" + encodeURIComponent(t.id)));
      var pending = t.status === "PENDING";
      A.$("#approve-btn").disabled = !(pending && canDecide);
      A.$("#deny-btn").disabled = !(pending && canDecide);
      A.$("#decision-state").textContent = pending ? "waiting for a decision" : "closed";
      A.$("#decision-hint").textContent = !canDecide ? "Your role can only view tickets" : (pending ? "" : "This ticket is " + t.status.toLowerCase() + (t.decided_by ? " (by " + t.decided_by + ")" : ""));
    }
    function pretty(s) { try { return JSON.stringify(JSON.parse(s), null, 2); } catch (e) { return s; } }
    function decide(approve) {
      if (!ticket) return;
      var note = A.$("#note").value;
      A.$("#approve-btn").disabled = A.$("#deny-btn").disabled = true;
      A.post("/api/tickets/" + ticket.id + "/" + (approve ? "approve" : "deny"), { note: note }).then(function () {
        A.toast("Ticket " + (approve ? "approved" : "denied"), "ok");
        return load();
      }).catch(function (e) { A.fail(e); load(); });
    }
    A.$("#approve-btn").addEventListener("click", function () { decide(true); });
    A.$("#deny-btn").addEventListener("click", function () { decide(false); });
    document.addEventListener("keydown", function (e) {
      var tag = (e.target.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select" || e.ctrlKey || e.metaKey) return;
      if (e.key === "a" && !A.$("#approve-btn").disabled) decide(true);
      else if (e.key === "d" && !A.$("#deny-btn").disabled) decide(false);
    });
    function load() { return A.get("/api/tickets/" + encodeURIComponent(id)).then(render).catch(A.fail); }
    A.loadTaxonomy().then(load);
    A.onTicketEvent(function (name, data) { if (data && data.ticket && data.ticket.id === id) load(); });
  };
})();
