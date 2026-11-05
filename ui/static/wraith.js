/* Wraith Console — vanilla, CSP-safe (no eval, no inline handlers, no third-party JS).
   Server renders every result/table/log fragment; this just submits and swaps. */
(function () {
  "use strict";
  var CSRF = (document.querySelector('meta[name="csrf"]') || {}).content || "";

  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function toast(msg, bad) {
    var wrap = document.getElementById("toasts");
    if (!wrap) return;
    var t = document.createElement("div");
    t.className = "toast" + (bad ? " bad" : "");
    t.textContent = msg;
    wrap.appendChild(t);
    setTimeout(function () {
      t.style.opacity = "0";
      t.style.transition = ".3s";
      setTimeout(function () { t.remove(); }, 300);
    }, 3200);
  }

  async function swapFrom(url, sel) {
    try {
      var r = await fetch(url, { headers: { "X-Requested-With": "fetch" } });
      if (r.status === 401) { location.href = "/login"; return; }  // session expired -> re-login
      if (!r.ok) return;
      var el = document.querySelector(sel);
      var html = await r.text();
      if (el && el.innerHTML !== html) el.innerHTML = html;   // skip if unchanged (no flicker/scroll jump)
    } catch (e) { /* non-fatal */ }
  }

  async function refreshLog() {
    await swapFrom("/api/log", "#log");
    var l = document.getElementById("log");
    if (l) l.scrollTop = l.scrollHeight;   // auto-scroll to the newest line (live terminal feel)
  }
  function refreshScope() { swapFrom("/api/scope", "#scopebox"); }
  function refreshFindings() { swapFrom("/api/findings", "#findings"); }
  function refreshResults() { swapFrom("/api/results", "#resultsbox"); }

  // AJAX form submit: forms with class "ajax"; data-target = selector to swap the HTML into.
  document.addEventListener("submit", async function (e) {
    var f = e.target;
    if (!f.classList || !f.classList.contains("ajax")) return;
    e.preventDefault();
    var url = f.getAttribute("action");
    var targetSel = f.getAttribute("data-target");
    var label = f.getAttribute("data-label") || "done";
    var btn = f.querySelector("button[type=submit], button:not([type])");
    if (btn) btn.disabled = true;
    try {
      var fd = new FormData(f);
      if (f.classList.contains("bulk")) {
        var bt = document.getElementById("bulk-target");
        if (bt) fd.set("target", bt.value);   // phase buttons share one target field
      }
      fd.set("csrf", CSRF);   // carry the token in the body for every form — also gives a
                              // field-less form (STOP) a non-empty body so form parsing can't 400
      var r = await fetch(url, {
        method: "POST",
        body: fd,
        headers: { "X-CSRF-Token": CSRF }
      });
      if (r.status === 401) { location.href = "/login"; return; }  // session expired -> re-login
      var ct = r.headers.get("content-type") || "";
      var body = await r.text();
      if (ct.indexOf("application/json") !== -1) {
        var msg = body;
        try { msg = JSON.parse(body).error || body; } catch (_) {}
        if (targetSel) {
          var te = document.querySelector(targetSel);
          if (te) te.innerHTML = '<div class="err">✕ ' + esc(msg) + "</div>";
        }
        toast("✕ " + msg, true);
      } else {
        if (targetSel) {
          var el = document.querySelector(targetSel);
          if (el) el.innerHTML = body;
        }
        toast((r.ok ? "✓ " : "✕ ") + label, !r.ok);
      }
      refreshLog();
      refreshResults();   // a run just finished — keep the captured-results view current
    } catch (err) {
      toast("✕ " + err, true);
    } finally {
      if (btn) btn.disabled = false;
    }
  });

  // Scope add/remove refresh the scope box (their data-target already points at it);
  // also refresh findings after a record/report tool runs.
  document.addEventListener("submit", function (e) {
    var f = e.target;
    if (!f.classList || !f.classList.contains("ajax")) return;
    var act = f.getAttribute("action") || "";
    if (act.indexOf("/api/tool/record_finding") !== -1 ||
        act.indexOf("/api/tool/export_report") !== -1) {
      setTimeout(refreshFindings, 400);
    }
  });

  // Tab navigation.
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest(".nav button[data-view]") : null;
    if (!b) return;
    var view = b.getAttribute("data-view");
    document.querySelectorAll(".view").forEach(function (v) { v.classList.remove("active"); });
    var target = document.querySelector('.view[data-view="' + view + '"]');
    if (target) target.classList.add("active");
    document.querySelectorAll(".nav button").forEach(function (x) { x.classList.remove("on"); });
    b.classList.add("on");
    if (view === "scope") refreshScope();
    if (view === "findings") { refreshFindings(); refreshResults(); }
  });

  // manual results refresh button (evidence tab)
  document.addEventListener("click", function (e) {
    var b = e.target.closest ? e.target.closest("#refresh-results") : null;
    if (b) refreshResults();
  });

  window.addEventListener("DOMContentLoaded", function () {
    refreshLog();
    refreshScope();
    refreshFindings();
    refreshResults();
    setInterval(refreshLog, 1500);
    setInterval(refreshResults, 4000);   // keep Captured Runs live during background sweeps
  });
})();
