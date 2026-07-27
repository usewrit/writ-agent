// shared/otp_entry.js
//
// Canonical robust OTP-entry routine, shared 1:1 by the Python agent
// the legacy Python recorder and the Rust agent (this crate) so the
// behaviour can never diverge. Both wrap this expression and invoke it:
//
//   ((<this file>)(codeString, selectorHintOrNull))
//
// It returns a JSON-serializable {ok, kind, filled} and NEVER returns or logs
// the code. It handles the common 2FA UI shapes:
//   - a single text/tel/number input
//   - N single-character "segmented" boxes (rotating-PIN widgets, auto-advance)
//   - a contenteditable code field
//   - paste-driven widgets (a synthetic paste event is always tried first)
// across the main document, open dialogs/modals, and same-origin iframes.
//
// IMPORTANT: keep this file ESCAPE-FREE — no backslash escape sequences inside
// string or regex literals (use [0-9] not the backslash-d shorthand, and
// String.fromCharCode for control chars). The script is transported as JSON to
// the agents; backslash escapes get corrupted in transit and throw at runtime.
function (code, selectorHint) {
  code = String(code == null ? "" : code).trim();
  if (!code) { return { ok: false, kind: "none", filled: 0, reason: "empty_code" }; }

  var KW = ["otp", "one-time", "onetime", "one time", "code", "verif", "passcode",
            "pin", "mfa", "2fa", "two-factor", "two factor", "token", "auth",
            "confirm", "security"];

  function roots() {
    var rs = [document];
    try {
      var dl = document.querySelectorAll("dialog[open], [role=dialog], [aria-modal=true]");
      for (var i = 0; i < dl.length; i++) { rs.push(dl[i]); }
    } catch (e) {}
    try {
      var fr = document.querySelectorAll("iframe, frame");
      for (var j = 0; j < fr.length; j++) {
        try { var d = fr[j].contentDocument; if (d) { rs.push(d); } } catch (e) {}
      }
    } catch (e) {}
    return rs;
  }

  function viewOf(el) { return (el.ownerDocument && el.ownerDocument.defaultView) || window; }

  function visible(el) {
    if (!el) { return false; }
    try {
      var r = el.getBoundingClientRect();
      if (r.width <= 0 && r.height <= 0) { return false; }
      var st = viewOf(el).getComputedStyle(el);
      if (st && (st.display === "none" || st.visibility === "hidden")) { return false; }
    } catch (e) {}
    return true;
  }

  function attrText(el) {
    var parts = [el.getAttribute("name"), el.id, el.getAttribute("placeholder"),
                 el.getAttribute("aria-label"), el.getAttribute("autocomplete"),
                 el.getAttribute("inputmode"), el.className];
    return parts.join(" ").toLowerCase();
  }
  function looksLikeCode(el) {
    var t = attrText(el);
    if (t.indexOf("one-time-code") >= 0) { return true; }
    for (var i = 0; i < KW.length; i++) { if (t.indexOf(KW[i]) >= 0) { return true; } }
    return false;
  }

  function setNativeValue(el, val) {
    var view = viewOf(el);
    var proto = el.tagName === "TEXTAREA" ? view.HTMLTextAreaElement.prototype
                                          : view.HTMLInputElement.prototype;
    var desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && desc.set) { desc.set.call(el, val); } else { el.value = val; }
  }
  function fireInput(el) {
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  function firePaste(el, val) {
    try {
      var dt = new DataTransfer();
      dt.setData("text/plain", val);
      el.dispatchEvent(new ClipboardEvent("paste", { bubbles: true, cancelable: true, clipboardData: dt }));
    } catch (e) {}
  }

  function fillSingle(el) {
    try { el.focus(); } catch (e) {}
    firePaste(el, code);
    if ((el.value || "") !== code) {
      setNativeValue(el, "");
      setNativeValue(el, code);
      fireInput(el);
    }
    try { el.blur(); } catch (e) {}
    return (el.value || "") === code;
  }

  function fillContentEditable(el) {
    try { el.focus(); } catch (e) {}
    firePaste(el, code);
    try {
      el.dispatchEvent(new InputEvent("beforeinput", { bubbles: true, cancelable: true, inputType: "insertFromPaste", data: code }));
    } catch (e) {}
    var have = (el.textContent || "").indexOf(code) >= 0;
    if (!have) {
      var ok = false;
      try { ok = document.execCommand("insertText", false, code); } catch (e) {}
      if (!ok || (el.textContent || "").indexOf(code) < 0) { el.textContent = code; }
      el.dispatchEvent(new Event("input", { bubbles: true }));
    }
    try { el.blur(); } catch (e) {}
    return (el.textContent || "").indexOf(code) >= 0;
  }

  function fillSegmented(boxes) {
    var chars = code.split("");
    var n = Math.min(boxes.length, chars.length);
    // Many segmented widgets distribute a single paste across all boxes.
    try { boxes[0].focus(); } catch (e) {}
    firePaste(boxes[0], code);
    var distributed = true;
    for (var i = 0; i < n; i++) { if ((boxes[i].value || "") === "") { distributed = false; break; } }
    if (distributed) { return n; }
    // Fallback: type char-by-char with key events so auto-advance handlers fire.
    var filled = 0;
    for (var k = 0; k < n; k++) {
      var b = boxes[k];
      try { b.focus(); } catch (e) {}
      b.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true, key: chars[k] }));
      setNativeValue(b, chars[k]);
      b.dispatchEvent(new Event("input", { bubbles: true }));
      b.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true, key: chars[k] }));
      b.dispatchEvent(new Event("change", { bubbles: true }));
      if ((b.value || "") === chars[k]) { filled++; }
    }
    return filled;
  }

  // ---- find the target across all roots --------------------------------
  var rs = roots();

  // 1) explicit selector hint wins
  if (selectorHint) {
    for (var a = 0; a < rs.length; a++) {
      var hit = null;
      try { hit = rs[a].querySelector(selectorHint); } catch (e) { hit = null; }
      if (hit && visible(hit)) {
        if (hit.isContentEditable) { return { ok: fillContentEditable(hit), kind: "contenteditable", filled: code.length }; }
        if (hit.tagName === "INPUT" || hit.tagName === "TEXTAREA") {
          return { ok: fillSingle(hit), kind: "single", filled: code.length };
        }
        // hint pointed at a container — fall through to structural detection
      }
    }
  }

  // 2) autocomplete one-time-code (single or first of a group)
  for (var b2 = 0; b2 < rs.length; b2++) {
    var otc = [];
    try { otc = rs[b2].querySelectorAll("input[autocomplete=one-time-code], input[autocomplete~=one-time-code]"); } catch (e) { otc = []; }
    var vis = [];
    for (var c = 0; c < otc.length; c++) { if (visible(otc[c])) { vis.push(otc[c]); } }
    if (vis.length >= 4) { return { ok: fillSegmented(vis) >= code.length, kind: "segmented", filled: code.length }; }
    if (vis.length === 1) { return { ok: fillSingle(vis[0]), kind: "single", filled: code.length }; }
  }

  // 3) segmented single-character boxes (maxlength=1 cluster)
  for (var d2 = 0; d2 < rs.length; d2++) {
    var all = [];
    try { all = rs[d2].querySelectorAll("input"); } catch (e) { all = []; }
    var seg = [];
    for (var e2 = 0; e2 < all.length; e2++) {
      var el = all[e2];
      var ty = (el.getAttribute("type") || "text").toLowerCase();
      if (ty === "hidden" || ty === "checkbox" || ty === "radio" || ty === "submit" || ty === "button") { continue; }
      var ml = el.maxLength;
      var single = (ml === 1) || (el.getAttribute("maxlength") === "1");
      if (single && visible(el)) { seg.push(el); }
    }
    if (seg.length >= 4) { return { ok: fillSegmented(seg) >= code.length, kind: "segmented", filled: code.length }; }
  }

  // 4) single keyword/inputmode-numeric text-like input
  var candidate = null;
  for (var f2 = 0; f2 < rs.length; f2++) {
    var ins = [];
    try { ins = rs[f2].querySelectorAll("input, textarea"); } catch (e) { ins = []; }
    for (var g = 0; g < ins.length; g++) {
      var inp = ins[g];
      var tt = (inp.getAttribute("type") || "text").toLowerCase();
      if (tt === "hidden" || tt === "checkbox" || tt === "radio" || tt === "submit" || tt === "button") { continue; }
      if (!visible(inp)) { continue; }
      var textlike = (tt === "text" || tt === "tel" || tt === "number" || tt === "password" || tt === "");
      if (!textlike) { continue; }
      if (looksLikeCode(inp)) { return { ok: fillSingle(inp), kind: "single", filled: code.length }; }
      if (!candidate) { candidate = inp; }
    }
  }

  // 5) contenteditable code field
  for (var h = 0; h < rs.length; h++) {
    var ces = [];
    try { ces = rs[h].querySelectorAll("[contenteditable=true], [contenteditable=plaintext-only], [contenteditable='']"); } catch (e) { ces = []; }
    for (var i2 = 0; i2 < ces.length; i2++) {
      if (visible(ces[i2])) { return { ok: fillContentEditable(ces[i2]), kind: "contenteditable", filled: code.length }; }
    }
  }

  // 6) last resort: the only/first visible text-like input on the page
  if (candidate) { return { ok: fillSingle(candidate), kind: "single", filled: code.length }; }

  return { ok: false, kind: "none", filled: 0, reason: "no_field" };
}
