// ak-vault site: theme toggle, copy buttons, "copy page as Markdown", scroll reveals,
// the sync-flow stepper, the ciphertext scramble and the SAS reveal.
// Loaded synchronously in <head> so a stored theme applies before first paint.
// Every page is complete without this file; it only adds motion and convenience.
// No network requests except a same-origin fetch of the page's Markdown twin on demand.
(function () {
  "use strict";
  var root = document.documentElement;
  var KEY = "akv-theme";

  try {
    var stored = localStorage.getItem(KEY);
    if (stored === "light" || stored === "dark") root.setAttribute("data-theme", stored);
  } catch (_) { /* storage blocked: follow prefers-color-scheme */ }
  root.classList.add("js");

  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

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

  function announce(text) {
    var live = document.getElementById("live-region");
    if (!live) return;
    live.textContent = "";
    setTimeout(function () { live.textContent = text; }, 30);
  }

  // Copy text to the clipboard; falls back to a hidden textarea on older browsers.
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text; ta.setAttribute("readonly", ""); ta.className = "visually-hidden";
      document.body.appendChild(ta); ta.select();
      try { document.execCommand("copy") ? resolve() : reject(new Error("copy failed")); }
      catch (e) { reject(e); } finally { ta.remove(); }
    });
  }

  function flash(btn, label, state) {
    var labelEl = btn.querySelector("[data-label]") || btn;
    var original = labelEl.getAttribute("data-original") || labelEl.textContent;
    labelEl.setAttribute("data-original", original);
    labelEl.textContent = label;
    btn.setAttribute("data-state", state);
    announce(label);
    clearTimeout(btn._flashTimer);
    btn._flashTimer = setTimeout(function () { labelEl.textContent = original; btn.removeAttribute("data-state"); }, 1800);
  }

  // Run fn(el) once when el scrolls into view; immediately when IntersectionObserver is missing.
  function whenVisible(els, fn, threshold) {
    if (!("IntersectionObserver" in window)) { els.forEach(fn); return; }
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { io.unobserve(e.target); fn(e.target); } });
    }, { threshold: threshold || 0.15, rootMargin: "0px 0px -5% 0px" });
    els.forEach(function (el) { io.observe(el); });
  }

  // Ciphertext scramble: decodes illustrative base64 strings once. Final text is already in the HTML.
  var ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  function scramble(el) {
    var target = el.textContent, frame = 0, frames = 22;
    function tick() {
      var settled = Math.floor((frame / frames) * target.length), out = "";
      for (var i = 0; i < target.length; i++) {
        out += i < settled || target[i] === "…" ? target[i] : ALPHABET[(Math.random() * ALPHABET.length) | 0];
      }
      el.textContent = out;
      if (frame++ < frames) requestAnimationFrame(function () { setTimeout(tick, 28); });
      else el.textContent = target;
    }
    tick();
  }

  // Sync-flow stepper: highlights one stage at a time; autoplays only while visible.
  function initFlow(fig) {
    var list = fig.querySelector(".flow");
    var controls = fig.querySelector(".flow-controls");
    var steps = Array.prototype.slice.call(fig.querySelectorAll("[data-flow-step]"));
    var play = fig.querySelector(".flow-play");
    if (!list || !controls || !steps.length || !play) return;
    controls.hidden = false;
    var current = 1, timer = null, visible = false;
    var paused = reduceMotion.matches;

    function show(n) {
      current = n;
      list.setAttribute("data-step", String(n));
      steps.forEach(function (b) {
        if (Number(b.getAttribute("data-flow-step")) === n) b.setAttribute("aria-current", "step");
        else b.removeAttribute("aria-current");
      });
    }
    function setPaused(p) {
      paused = p;
      play.setAttribute("aria-pressed", String(p));
      play.querySelector("[data-label]").textContent = p ? "Play" : "Pause";
      play.setAttribute("aria-label", p ? "Play the sync animation" : "Pause the sync animation");
      schedule();
    }
    function schedule() {
      clearInterval(timer);
      if (!paused && visible) timer = setInterval(function () { show(current % steps.length + 1); }, 2600);
    }
    steps.forEach(function (b, i) {
      b.addEventListener("click", function () { show(i + 1); setPaused(true); });
      b.addEventListener("keydown", function (e) {
        var d = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
        if (!d) return;
        e.preventDefault();
        var next = steps[(i + d + steps.length) % steps.length];
        next.focus(); next.click();
      });
    });
    play.addEventListener("click", function () { setPaused(!paused); });
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (entries) {
        visible = entries[0].isIntersecting; schedule();
      }, { threshold: 0.35 }).observe(fig);
    }
    show(1);
    setPaused(paused);
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
        btn.classList.remove("is-switching"); void btn.offsetWidth; btn.classList.add("is-switching");
        announce(next === "dark" ? "Dark theme" : "Light theme");
      });
    });

    // data-copy-target="#id" copies that element's text without prompts (.p).
    document.querySelectorAll("[data-copy-target]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var el = document.querySelector(btn.getAttribute("data-copy-target"));
        if (!el) return;
        var clone = el.cloneNode(true);
        clone.querySelectorAll(".p").forEach(function (n) { n.remove(); });
        copyText(clone.textContent.replace(/\n{3,}/g, "\n\n").trim() + "\n")
          .then(function () { flash(btn, "Copied", "copied"); })
          .catch(function () { flash(btn, "Copy failed", "failed"); });
      });
    });

    // Copy the Markdown twin of this page (same origin).
    document.querySelectorAll("[data-copy-markdown]").forEach(function (btn) {
      btn.addEventListener("click", function () {
        fetch(btn.getAttribute("data-copy-markdown"), { credentials: "omit" })
          .then(function (r) { if (!r.ok) throw new Error(String(r.status)); return r.text(); })
          .then(copyText)
          .then(function () { flash(btn, "Copied Markdown", "copied"); })
          .catch(function () { flash(btn, "Copy failed", "failed"); });
      });
    });

    // Mobile menu: close after choosing a link, on Escape, or on an outside click.
    document.querySelectorAll(".nav-menu").forEach(function (menu) {
      menu.querySelectorAll("a").forEach(function (a) { a.addEventListener("click", function () { menu.removeAttribute("open"); }); });
      document.addEventListener("keydown", function (e) {
        if (e.key === "Escape" && menu.open) { menu.removeAttribute("open"); menu.querySelector("summary").focus(); }
      });
      document.addEventListener("click", function (e) { if (menu.open && !menu.contains(e.target)) menu.removeAttribute("open"); });
    });

    document.querySelectorAll("[data-flow]").forEach(initFlow);

    var reveals = Array.prototype.slice.call(document.querySelectorAll(".reveal"));
    var heroReveals = reveals.filter(function (el) { return el.closest(".hero, .page-hero"); });
    requestAnimationFrame(function () {
      heroReveals.forEach(function (el, i) { setTimeout(function () { el.classList.add("is-in"); }, 60 * i); });
    });
    whenVisible(reveals.filter(function (el) { return heroReveals.indexOf(el) < 0; }), function (el) { el.classList.add("is-in"); }, 0.08);
    window.addEventListener("beforeprint", function () { reveals.forEach(function (el) { el.classList.add("is-in"); }); });

    var sas = Array.prototype.slice.call(document.querySelectorAll(".sas"));
    sas.forEach(function (el) { el.classList.add("is-armed"); });
    whenVisible(sas, function (el) { el.classList.add("is-in"); }, 0.4);

    if (!reduceMotion.matches) whenVisible(Array.prototype.slice.call(document.querySelectorAll("[data-scramble]")), scramble, 0.3);
  });
})();
