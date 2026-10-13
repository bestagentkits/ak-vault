// ak-vault landing: theme toggle, copy buttons, "copy page as Markdown", hero reveal.
// Loaded synchronously in <head> so a stored theme applies before first paint.
// No network requests except same-origin fetch of the page's Markdown twin on demand.
(function () {
  "use strict";
  var root = document.documentElement;
  var KEY = "akv-theme";

  try {
    var stored = localStorage.getItem(KEY);
    if (stored === "light" || stored === "dark") root.setAttribute("data-theme", stored);
  } catch (_) { /* storage blocked: follow prefers-color-scheme */ }
  root.classList.add("js");

  function currentTheme() {
    var explicit = root.getAttribute("data-theme");
    if (explicit) return explicit;
    return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  function syncToggleLabels() {
    var next = currentTheme() === "dark" ? "light" : "dark";
    document.querySelectorAll(".theme-toggle").forEach(function (btn) {
      btn.setAttribute("aria-label", "Switch to " + next + " theme");
    });
  }

  // Copy text to clipboard; falls back to a hidden textarea on older browsers.
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", ""); ta.style.position = "fixed"; ta.style.opacity = "0";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy") ? resolve() : reject(new Error("copy failed")); }
      catch (e) { reject(e); } finally { ta.remove(); }
    });
  }

  function flash(btn, label) {
    var labelEl = btn.querySelector("[data-label]") || btn;
    var original = labelEl.getAttribute("data-original") || labelEl.textContent;
    labelEl.setAttribute("data-original", original);
    labelEl.textContent = label;
    btn.setAttribute("data-state", "copied");
    var live = document.getElementById("live-region");
    if (live) live.textContent = label;
    setTimeout(function () { labelEl.textContent = original; btn.removeAttribute("data-state"); }, 1800);
  }

  document.addEventListener("DOMContentLoaded", function () {
    syncToggleLabels();
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", syncToggleLabels);

    document.querySelectorAll(".theme-toggle").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var next = currentTheme() === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try { localStorage.setItem(KEY, next); } catch (_) {}
        syncToggleLabels();
      });
    });

    // Copy buttons: data-copy-target="#id" copies that element's text, skipping prompts/comments.
    document.querySelectorAll("[data-copy-target]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var el = document.querySelector(btn.getAttribute("data-copy-target"));
        if (!el) return;
        var clone = el.cloneNode(true);
        clone.querySelectorAll(".p").forEach(function (n) { n.remove(); });
        copyText(clone.textContent.replace(/\n{3,}/g, "\n\n").trim() + "\n")
          .then(function () { flash(btn, "Copied"); })
          .catch(function () { flash(btn, "Copy failed"); });
      });
    });

    // Copy the Markdown twin of this page (same origin).
    document.querySelectorAll("[data-copy-markdown]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        fetch(btn.getAttribute("data-copy-markdown"), { credentials: "omit" })
          .then(function (r) { if (!r.ok) throw new Error(String(r.status)); return r.text(); })
          .then(copyText)
          .then(function () { flash(btn, "Copied Markdown"); })
          .catch(function () { flash(btn, "Copy failed"); });
      });
    });

    // Close the mobile menu after choosing a link.
    document.querySelectorAll(".nav-menu a").forEach(function (a) {
      a.addEventListener("click", function () { a.closest("details").removeAttribute("open"); });
    });

    requestAnimationFrame(function () {
      document.querySelectorAll(".reveal").forEach(function (el, i) {
        setTimeout(function () { el.classList.add("is-in"); }, 60 * i);
      });
    });
  });
})();
