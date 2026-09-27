(function () {
  "use strict";
  var A = window.AIRT;
  A.pages.logs = function () {
    var view = A.$("#log-view"), agentSel = A.$("#f-agent"), levelSel = A.$("#f-level"), search = A.$("#f-search"), status = A.$("#log-status");
    var LEVEL_RANK = { DEBUG: 0, INFO: 1, WARNING: 2, ERROR: 3, CRITICAL: 4 };
    var agents = {};
    var con = A.logConsole(view, {
      max: 3000,
      agents: agents,
      follow: function () { return A.$("#autoscroll").checked; },
      filter: function (r) {
        if (agentSel.value && r.agent_id !== agentSel.value) return false;
        var min = levelSel.value;
        if (min && (LEVEL_RANK[String(r.level).toUpperCase()] || 0) < LEVEL_RANK[min]) return false;
        var q = search.value.trim().toLowerCase();
        if (q && JSON.stringify(r).toLowerCase().indexOf(q) < 0) return false;
        return true;
      }
    });
    A.get("/api/agents").then(function (list) { list.forEach(function (a) { agents[a.id] = a; }); A.agentOptions(agentSel, list, { value: A.param("agent_id") || "" }); con.rerender(); }).catch(A.fail);
    agentSel.addEventListener("change", con.rerender);
    levelSel.addEventListener("change", con.rerender);
    search.addEventListener("input", A.debounce(con.rerender, 200));
    var stream = A.streamAll("/api/stream/logs?replay=200", function (name, rec) { if (rec && typeof rec === "object") con.push(rec); }, { onStatus: function (on) { status.textContent = on ? "live" : "reconnecting"; } });
    var pauseBtn = A.$("#log-pause");
    pauseBtn.addEventListener("click", function () { if (stream.paused) { stream.resume(); pauseBtn.textContent = "Pause"; } else { stream.pause(); pauseBtn.textContent = "Resume"; } });
    A.$("#log-clear").addEventListener("click", con.clear);
    A.$("#log-download").addEventListener("click", function () { con.download("airt-logs-" + new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-") + ".json"); });
  };
})();
