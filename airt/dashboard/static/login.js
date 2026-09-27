(function () {
  "use strict";
  var A = window.AIRT;
  var form = A.$("#login-form"), err = A.$("#login-error"), btn = A.$("#login-btn");
  form.addEventListener("submit", function (e) {
    e.preventDefault();
    err.classList.add("hidden");
    btn.disabled = true;
    A.api("POST", "/api/auth/login", { username: A.$("#username").value.trim(), password: A.$("#password").value }, { noRedirect: true })
      .then(function () {
        var next = A.$("#next").value || "/";
        if (next.indexOf("/") !== 0 || next.indexOf("//") === 0) next = "/";
        window.location.href = next;
      })
      .catch(function (ex) {
        err.textContent = ex.status === 401 ? "Invalid username or password." : (ex.message || "Login failed");
        err.classList.remove("hidden");
        btn.disabled = false;
        A.$("#password").focus();
      });
  });
})();
