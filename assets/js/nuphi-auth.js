/* ν-Φ sign-in and page unlock. Runs on every page.
 *
 * Sign-in derives a key from the password (PBKDF2-SHA256, same parameters as
 * tools/nuphi_crypto.py), opens the user's entry in access.json and keeps the tier
 * keys it contains for the session. Protected pages are decrypted in place with them.
 * Nothing is sent to any server: GitHub Pages only serves files.
 */
(function () {
  "use strict";
  var STORE = "nuphi.session";
  var TERMS = "nuphi.terms.v1";
  var USER_ID_PREFIX = "nu-phi-user:";
  var enc = new TextEncoder(), dec = new TextDecoder();

  function siteRoot() {
    var base = ".";
    try { base = JSON.parse(document.getElementById("__config").textContent).base || "."; } catch (e) {}
    return new URL(base.replace(/\/?$/, "/"), location.href);
  }
  function url(path) { return new URL(path, siteRoot()).href; }

  function b64(s) { var b = atob(s), a = new Uint8Array(b.length); for (var i = 0; i < b.length; i++) a[i] = b.charCodeAt(i); return a; }
  function hex(buf) { return Array.prototype.map.call(new Uint8Array(buf), function (x) { return x.toString(16).padStart(2, "0"); }).join(""); }

  function getSession() {
    try { return JSON.parse(sessionStorage.getItem(STORE) || localStorage.getItem(STORE)); } catch (e) { return null; }
  }
  function setSession(s, remember) {
    try {
      clearSession();
      (remember ? localStorage : sessionStorage).setItem(STORE, JSON.stringify(s));
    } catch (e) {}
  }
  function clearSession() {
    try { sessionStorage.removeItem(STORE); localStorage.removeItem(STORE); } catch (e) {}
  }

  async function aesOpen(rawKey, ivB64, ctB64) {
    var key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["decrypt"]);
    var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(ivB64) }, key, b64(ctB64));
    return dec.decode(pt);
  }

  async function signIn(username, password) {
    var res = await fetch(url("access.json"), { cache: "no-store" });
    if (!res.ok) throw new Error("unavailable");
    var access = await res.json();
    var id = hex(await crypto.subtle.digest("SHA-256", enc.encode(USER_ID_PREFIX + username.trim().toLowerCase())));
    var entry = access.users[id];
    if (!entry) throw new Error("nomatch");
    var base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    var bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: b64(entry.salt), iterations: access.iter }, base, 256);
    try { return JSON.parse(await aesOpen(new Uint8Array(bits), entry.iv, entry.ct)); }
    catch (e) { throw new Error("nomatch"); }
  }

  /* ---------- protected pages ---------- */

  function lockedMessage(el, text, withButton) {
    var msg = el.querySelector(".nuphi-locked__msg");
    if (msg) msg.textContent = text;
    if (withButton && !el.querySelector(".nuphi-locked__actions")) {
      var here = location.pathname + location.hash;
      var wrap = document.createElement("p");
      wrap.className = "nuphi-locked__actions";
      wrap.innerHTML = '<a class="md-button md-button--primary" href="' +
        url("login/") + "?next=" + encodeURIComponent(here) + '">Sign in</a> ' +
        '<a class="md-button" href="' + url("get-access/") + '">Request access</a>';
      el.appendChild(wrap);
    }
  }

  async function unlockPage() {
    var el = document.querySelector(".nuphi-locked");
    if (!el) return;
    var s = getSession(), tier = el.dataset.tier;
    if (!s) return lockedMessage(el, el.querySelector(".nuphi-locked__msg").textContent, true);
    if (String(s.kv) !== el.dataset.kv) {
      clearSession(); renderBadge();
      return lockedMessage(el, "Your sign-in is from an older version of the site. Sign in again.", true);
    }
    if (!s.k[tier]) {
      return lockedMessage(el, "Your account includes the user docs but not the developer pages. " +
        "Ask for developer access if you are building ν-Φ apps.", true);
    }
    try {
      var page = JSON.parse(await aesOpen(b64(s.k[tier]), el.dataset.iv, el.dataset.ct));
      var article = el.parentElement;
      article.innerHTML = page.article;
      if (page.toc) document.querySelectorAll("nav.md-nav--secondary").forEach(function (n) { n.innerHTML = page.toc; });
      document.body.dataset.nuphiUnlocked = tier;
      if (location.hash) {
        var target = document.getElementById(decodeURIComponent(location.hash.slice(1)));
        if (target) target.scrollIntoView();
      }
    } catch (e) {
      lockedMessage(el, "This page could not be opened with your sign-in. Sign in again.", true);
    }
  }

  /* ---------- header badge ---------- */

  function renderBadge() {
    var header = document.querySelector(".md-header__inner");
    if (!header) return;
    var old = header.querySelector(".nuphi-badge");
    if (old) old.remove();
    var s = getSession();
    var badge = document.createElement("div");
    badge.className = "nuphi-badge";
    if (s) {
      badge.innerHTML = '<span class="nuphi-badge__who"></span><button type="button">Sign out</button>';
      badge.querySelector(".nuphi-badge__who").textContent = s.u + (s.tier === "dev" ? " (developer)" : "");
      badge.querySelector("button").addEventListener("click", function () {
        clearSession();
        if (document.body.dataset.nuphiUnlocked) location.reload();
        else { renderBadge(); unlockPage(); }
      });
    } else {
      badge.innerHTML = '<a href="' + url("login/") + "?next=" + encodeURIComponent(location.pathname) + '">Sign in</a>';
    }
    header.appendChild(badge);
  }

  /* ---------- login page ---------- */

  function wireLoginForm() {
    var form = document.getElementById("nuphi-login");
    if (!form) return;
    var status = document.getElementById("nuphi-login-status");
    var terms = document.getElementById("nuphi-terms");
    var termsRow = document.getElementById("nuphi-terms-row");
    try { if (localStorage.getItem(TERMS)) { terms.checked = true; termsRow.hidden = true; } } catch (e) {}

    var s = getSession();
    if (s) status.textContent = "You are signed in as " + s.u + ". Signing in again replaces that session.";

    form.addEventListener("submit", async function (ev) {
      ev.preventDefault();
      var user = form.username.value, pass = form.password.value;
      if (!user || !pass) { status.textContent = "Enter your username and password."; return; }
      if (!terms.checked) { status.textContent = "Accept the access terms to continue."; terms.focus(); return; }
      var btn = form.querySelector("button[type=submit]");
      btn.disabled = true; status.textContent = "Checking…";
      try {
        var p = await signIn(user, pass);
        setSession({ u: p.u, tier: p.tier, kv: p.kv, k: p.k }, form.remember.checked);
        try { localStorage.setItem(TERMS, new Date().toISOString()); } catch (e) {}
        var next = new URLSearchParams(location.search).get("next");
        location.href = (next && next.charAt(0) === "/" && next.charAt(1) !== "/") ? next
          : url(p.tier === "dev" ? "dev/" : "docs/");
      } catch (e) {
        status.textContent = e.message === "nomatch"
          ? "That username and password don't match an approved account. Check both, or request access."
          : "The sign-in list could not be loaded. Check your connection and try again.";
        btn.disabled = false;
      }
    });
  }

  function start() { renderBadge(); wireLoginForm(); unlockPage(); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
