// ak-vault site behaviour: theme toggle, copy buttons, "copy page as Markdown", scroll
// reveals, the hero scene controls, the sync-flow stepper, the ciphertext scramble, the
// SAS reveal and pointer micro-interactions (card spotlight, button ripple, magnetic CTA).
// Loaded synchronously in <head> so a stored theme applies before first paint.
// Every page is complete without this file; it only adds motion and convenience.
// Styles are set through the CSSOM (style.setProperty), never through style attributes,
// so the CSP style-src 'self' holds. No network requests except a same-origin fetch of
// the page's Markdown twin on demand.
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
  var finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
  var toArray = function (list) { return Array.prototype.slice.call(list); };

  function currentTheme() {
    var explicit = root.getAttribute("data-theme");
    if (explicit) return explicit;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
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
    }, { threshold: threshold || 0.15, rootMargin: "0px 0px -6% 0px" });
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

  // Hero scene: CSS runs the timeline; JS adds a pause control and pauses it off-screen.
  function initStage(stage) {
    var btn = stage.querySelector(".scene-toggle");
    if (!btn) return;
    if (reduceMotion.matches) return; // static, complete scene; no control needed
    btn.hidden = false;
    btn.addEventListener("click", function () {
      var paused = stage.classList.toggle("is-paused");
      btn.setAttribute("aria-pressed", String(paused));
      btn.querySelector("[data-label]").textContent = paused ? "Play" : "Pause";
      btn.setAttribute("aria-label", paused ? "Play the sealing animation" : "Pause the sealing animation");
    });
    if ("IntersectionObserver" in window) {
      new IntersectionObserver(function (entries) {
        stage.classList.toggle("is-offscreen", !entries[0].isIntersecting);
      }, { threshold: 0 }).observe(stage);
    }
  }

  // Sync-flow stepper: highlights one stage at a time; autoplays only while visible.
  function initFlow(fig) {
    var list = fig.querySelector(".flow");
    var controls = fig.querySelector(".flow-controls");
    var steps = toArray(fig.querySelectorAll("[data-flow-step]"));
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
      play.setAttribute("aria-label", p ? "Play the sync walkthrough" : "Pause the sync walkthrough");
      schedule();
    }
    function schedule() {
      clearInterval(timer);
      if (!paused && visible) timer = setInterval(function () { show(current % steps.length + 1); }, 2800);
    }
    steps.forEach(function (b, i) {
      b.addEventListener("click", function () { show(i + 1); setPaused(true); });
      b.addEventListener("keydown", function (e) {
        var d = e.key === "ArrowRight" || e.key === "ArrowDown" ? 1 : e.key === "ArrowLeft" || e.key === "ArrowUp" ? -1 : 0;
        var target = e.key === "Home" ? 0 : e.key === "End" ? steps.length - 1 : d ? (i + d + steps.length) % steps.length : -1;
        if (target < 0) return;
        e.preventDefault();
        var next = steps[target];
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

  // Pointer micro-interactions. Skipped for touch and for reduced motion.
  function initPointerEffects() {
    if (!finePointer.matches || reduceMotion.matches) return;
    document.querySelectorAll(".spot").forEach(function (card) {
      card.addEventListener("pointermove", function (e) {
        var r = card.getBoundingClientRect();
        card.style.setProperty("--mx", (e.clientX - r.left) + "px");
        card.style.setProperty("--my", (e.clientY - r.top) + "px");
      });
    });
    document.querySelectorAll(".magnetic").forEach(function (btn) {
      btn.addEventListener("pointermove", function (e) {
        var r = btn.getBoundingClientRect();
        var x = (e.clientX - r.left - r.width / 2) * 0.18, y = (e.clientY - r.top - r.height / 2) * 0.3;
        btn.style.setProperty("translate", x.toFixed(1) + "px " + y.toFixed(1) + "px");
      });
      btn.addEventListener("pointerleave", function () { btn.style.removeProperty("translate"); });
    });
  }

  function addRipple(e) {
    if (reduceMotion.matches) return;
    var btn = e.currentTarget, r = btn.getBoundingClientRect();
    var dot = document.createElement("span");
    dot.className = "ripple";
    dot.setAttribute("aria-hidden", "true");
    var x = e.clientX ? e.clientX - r.left : r.width / 2, y = e.clientY ? e.clientY - r.top : r.height / 2;
    dot.style.setProperty("--rx", x + "px");
    dot.style.setProperty("--ry", y + "px");
    btn.appendChild(dot);
    setTimeout(function () { dot.remove(); }, 650);
  }

  document.addEventListener("DOMContentLoaded", function () {
    syncToggleLabels();
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", syncToggleLabels);

    document.querySelectorAll(".theme-toggle").forEach(function (btn) {
      btn.addEventListener("click", function () {
        var next = currentTheme() === "dark" ? "light" : "dark";
        root.setAttribute("data-theme", next);
        try { localStorage.setItem(KEY, next); } catch (_) {}
        syncToggleLabels();
        announce(next === "dark" ? "Dark theme" : "Light theme");
      });
    });

    // Header gains a hairline once the page scrolls.
    var header = document.querySelector(".site-header");
    if (header) {
      var onScroll = function () { header.classList.toggle("is-scrolled", window.scrollY > 8); };
      window.addEventListener("scroll", onScroll, { passive: true });
      onScroll();
    }

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

    document.querySelectorAll(".btn").forEach(function (b) { b.addEventListener("click", addRipple); });
    document.querySelectorAll(".stage").forEach(initStage);
    document.querySelectorAll("[data-flow]").forEach(initFlow);
    initPointerEffects();

    // Scroll reveals; siblings inside a [data-stagger] group cascade by 60ms.
    document.querySelectorAll("[data-stagger]").forEach(function (group) {
      toArray(group.querySelectorAll(":scope > .reveal")).forEach(function (el, i) { el.style.setProperty("--d", Math.min(i, 6) * 60 + "ms"); });
    });
    var reveals = toArray(document.querySelectorAll(".reveal"));
    var heroReveals = reveals.filter(function (el) { return el.closest(".hero, .page-hero"); });
    requestAnimationFrame(function () {
      heroReveals.forEach(function (el, i) { el.style.setProperty("--d", i * 70 + "ms"); el.classList.add("is-in"); });
    });
    whenVisible(reveals.filter(function (el) { return heroReveals.indexOf(el) < 0; }), function (el) { el.classList.add("is-in"); }, 0.08);
    window.addEventListener("beforeprint", function () { reveals.forEach(function (el) { el.classList.add("is-in"); }); });

    var sas = toArray(document.querySelectorAll(".sas"));
    sas.forEach(function (el) { el.classList.add("is-armed"); });
    whenVisible(sas, function (el) { el.classList.add("is-in"); }, 0.4);

    if (!reduceMotion.matches) whenVisible(toArray(document.querySelectorAll("[data-scramble]")), scramble, 0.3);
  });
})();
