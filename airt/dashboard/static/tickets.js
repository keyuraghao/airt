(function () {
  "use strict";
  var A = window.AIRT;
  A.pages.tickets = function () {
    var LIMIT = 50;
    var state = { status: "PENDING", agent_id: "", min_risk: "", source: "", search: "", offset: 0, total: 0 };
    var rowsEl = A.$("#ticket-rows"), agents = {}, items = [], selected = {}, cursor = -1;
    var canDecide = A.isReviewer();
    var soundToggle = A.$("#sound-toggle");
    soundToggle.checked = A.soundEnabled();
    soundToggle.addEventListener("change", function () { A.setSound(soundToggle.checked); if (soundToggle.checked) A.beep(); });
    var initialStatus = A.param("status");
    if (initialStatus !== null) state.status = initialStatus.toUpperCase();
    if (A.param("agent_id")) state.agent_id = A.param("agent_id");
    if (A.param("campaign_id")) state.campaign_id = A.param("campaign_id");
    A.$$("#status-tabs button").forEach(function (b) {
      b.classList.toggle("active", b.dataset.status === state.status);
      b.addEventListener("click", function () {
        A.$$("#status-tabs button").forEach(function (x) { x.classList.remove("active"); });
        b.classList.add("active");
        state.status = b.dataset.status; state.offset = 0; load();
      });
    });
    A.$("#f-agent").addEventListener("change", function (e) { state.agent_id = e.target.value; state.offset = 0; load(); });
    A.$("#f-risk").addEventListener("change", function (e) { state.min_risk = e.target.value; state.offset = 0; load(); });
    A.$("#f-source").addEventListener("change", function (e) { state.source = e.target.value; state.offset = 0; load(); });
    A.$("#f-search").addEventListener("input", A.debounce(function (e) { state.search = e.target.value.trim(); state.offset = 0; load(); }, 300));
    A.$("#refresh-btn").addEventListener("click", load);
    A.$("#select-all").addEventListener("change", function (e) {
      items.forEach(function (t) { if (t.status === "PENDING") selected[t.id] = e.target.checked; });
      renderRows();
    });
    A.$("#bulk-approve").addEventListener("click", function () { bulk(true); });
    A.$("#bulk-deny").addEventListener("click", function () { bulk(false); });
    function selectedIds() { return Object.keys(selected).filter(function (k) { return selected[k]; }); }
    function updateBulk() {
      var ids = selectedIds();
      A.$("#bulk-bar").classList.toggle("hidden", !ids.length || !canDecide);
      A.$("#bulk-count").textContent = ids.length;
    }
    function bulk(approve) {
      var ids = selectedIds();
      if (!ids.length) return;
      A.promptNote((approve ? "Approve " : "Deny ") + ids.length + " tickets", "Note applied to every ticket", approve ? "Approve all" : "Deny all", approve ? "ok" : "danger").then(function (note) {
        if (note === null) return;
        A.post("/api/tickets/bulk/" + (approve ? "approve" : "deny"), { ticket_ids: ids, note: note }).then(function (r) {
          A.toast("Bulk " + (approve ? "approve" : "deny") + " done" + (r && r.decided != null ? " (" + r.decided + " decided)" : ""), "ok");
          selected = {}; load();
        }).catch(A.fail);
      });
    }
    function decide(t, approve) {
      if (!canDecide) { A.toast("Your role cannot decide tickets", "warn"); return; }
      A.promptNote((approve ? "Approve" : "Deny") + " ticket #" + (t.number || t.id), "Reason (optional)", approve ? "Approve" : "Deny", approve ? "ok" : "danger").then(function (note) {
        if (note === null) return;
        A.post("/api/tickets/" + t.id + "/" + (approve ? "approve" : "deny"), { note: note }).then(function (updated) {
          A.toast("Ticket #" + (updated.number || "") + " " + updated.status.toLowerCase(), "ok");
          upsert(updated, false);
        }).catch(A.fail);
      });
    }
    function matchesFilter(t) {
      if (state.status && t.status !== state.status) return false;
      if (state.agent_id && t.agent_id !== state.agent_id) return false;
      if (state.campaign_id && t.campaign_id !== state.campaign_id) return false;
      if (state.min_risk && (t.risk_score || 0) < Number(state.min_risk)) return false;
      if (state.source && t.source !== state.source) return false;
      if (state.search) {
        var s = state.search.toLowerCase();
        if ([t.prompt_preview, t.id, t.path, t.correlation_id].join(" ").toLowerCase().indexOf(s) < 0) return false;
      }
      return true;
    }
    function upsert(t, flash) {
      var idx = -1;
      items.forEach(function (x, i) { if (x.id === t.id) idx = i; });
      var keep = matchesFilter(t);
      if (idx >= 0) {
        if (keep) items[idx] = t; else { items.splice(idx, 1); delete selected[t.id]; }
      } else if (keep && state.offset === 0) {
        items.unshift(t);
        if (items.length > LIMIT) items.pop();
        state.total += 1;
      }
      renderRows(flash ? t.id : null);
    }
    function row(t, i) {
      var pending = t.status === "PENDING";
      var cb = A.el("input", { type: "checkbox", disabled: !pending, onchange: function (e) { selected[t.id] = e.target.checked; updateBulk(); } });
      cb.checked = !!selected[t.id];
      var created = A.el("div", null, [A.timeEl(t.created_at)]);
      if (pending && t.expires_at) created.appendChild(A.el("div", { class: "countdown", "data-countdown": t.expires_at, text: A.countdown(t.expires_at) }));
      var actions = A.el("td", { class: "nowrap" });
      if (pending && canDecide) {
        actions.appendChild(A.el("button", { class: "btn ok xs", text: "Approve", onclick: function (e) { e.stopPropagation(); decide(t, true); } }));
        actions.appendChild(document.createTextNode(" "));
        actions.appendChild(A.el("button", { class: "btn danger xs", text: "Deny", onclick: function (e) { e.stopPropagation(); decide(t, false); } }));
      } else if (t.decided_by) {
        actions.appendChild(A.el("span", { class: "hint", text: "by " + t.decided_by, title: t.decision_note || "" }));
      }
      var tr = A.el("tr", { class: (i === cursor ? "selected" : "") + " clickable", dataset: { id: t.id }, onclick: function (e) { if (e.target.tagName === "INPUT" || e.target.tagName === "BUTTON" || e.target.tagName === "A") return; cursor = i; renderRows(); } , ondblclick: function () { window.location.href = "/tickets/" + t.id; } }, [
        A.el("td", { class: "checkbox-cell" }, cb),
        A.el("td", { class: "num" }, A.link("/tickets/" + t.id, "#" + (t.number || t.id.slice(-6)))),
        A.el("td", null, created),
        A.el("td", null, agents[t.agent_id] ? A.link("/agents/" + t.agent_id, agents[t.agent_id].name) : A.el("span", { text: t.agent_name || t.agent_id || "" })),
        A.el("td", { class: "mono small", text: t.model || "" }),
        A.el("td", { class: "mono small truncate", text: t.path || "", title: t.path || "" }),
        A.el("td", null, A.riskBadge(t.risk_level, t.risk_score)),
        A.el("td", { class: "num center", text: t.finding_count || 0 }),
        A.el("td", null, t.policy_action ? A.badge(t.policy_action) : ""),
        A.el("td", null, A.el("div", { class: "truncate", text: t.prompt_preview || "", title: t.prompt_preview || "" })),
        A.el("td", null, A.badge(t.status)),
        actions
      ]);
      return tr;
    }
    function renderRows(flashId) {
      A.clear(rowsEl);
      if (!items.length) rowsEl.appendChild(A.emptyRow(12, state.status === "PENDING" ? "No tickets waiting for review" : "No tickets match"));
      items.forEach(function (t, i) { var tr = row(t, i); if (flashId === t.id) tr.classList.add("flash"); rowsEl.appendChild(tr); });
      A.$("#count").textContent = items.length + " of " + state.total;
      A.pager(A.$("#pager"), state.total, LIMIT, state.offset, function (o) { state.offset = o; load(); });
      updateBulk();
    }
    function load() {
      var q = { status: state.status || undefined, agent_id: state.agent_id, min_risk: state.min_risk, source: state.source, search: state.search, campaign_id: state.campaign_id, limit: LIMIT, offset: state.offset };
      return A.get("/api/tickets" + A.qs(q)).then(function (r) {
        items = r.items; state.total = r.total; cursor = Math.min(cursor, items.length - 1);
        renderRows();
      }).catch(A.fail);
    }
    A.get("/api/agents").then(function (list) { agents = A.agentMap(list); A.agentOptions(A.$("#f-agent"), list, { value: state.agent_id }); }).catch(A.fail).then(load);
    A.onTicketEvent(function (name, data) {
      var t = data && data.ticket;
      if (!t) return;
      var isNew = name === "created" && t.status === "PENDING";
      upsert(t, true);
      if (isNew && matchesFilter(t)) { A.beep(); A.toast("New ticket #" + (t.number || "") + " from " + (agents[t.agent_id] ? agents[t.agent_id].name : t.agent_name || "agent") + " (risk " + t.risk_score + ")", "warn", 3000); }
      if (A.lastStats) A.$("#tab-pending").textContent = A.lastStats.pending;
    });
    A.get("/api/tickets/stats").then(function (s) { A.$("#tab-pending").textContent = s.pending; A.$("#tab-pending").classList.toggle("zero", !s.pending); }).catch(function () {});
    setInterval(function () { if (A.lastStats) { A.$("#tab-pending").textContent = A.lastStats.pending; A.$("#tab-pending").classList.toggle("zero", !A.lastStats.pending); } }, 2000);
    document.addEventListener("keydown", function (e) {
      var tag = (e.target.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select" || e.ctrlKey || e.metaKey || e.altKey) return;
      if (!items.length) return;
      if (e.key === "j") { cursor = Math.min(items.length - 1, cursor + 1); renderRows(); scrollCursor(); }
      else if (e.key === "k") { cursor = Math.max(0, cursor - 1); renderRows(); scrollCursor(); }
      else if (e.key === "a" && cursor >= 0) decide(items[cursor], true);
      else if (e.key === "d" && cursor >= 0) decide(items[cursor], false);
      else if (e.key === "x" && cursor >= 0) { var t = items[cursor]; if (t.status === "PENDING") { selected[t.id] = !selected[t.id]; renderRows(); } }
      else if (e.key === "Enter" && cursor >= 0) window.location.href = "/tickets/" + items[cursor].id;
      else if (e.key === "r") load();
      else return;
      e.preventDefault();
    });
    function scrollCursor() { var tr = rowsEl.querySelector("tr.selected"); if (tr && tr.scrollIntoView) tr.scrollIntoView({ block: "nearest" }); }
  };
})();
