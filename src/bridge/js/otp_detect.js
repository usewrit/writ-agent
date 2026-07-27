// shared/otp_detect.js
//
// Canonical deterministic 2FA-challenge detector, shared 1:1 by the Python and
// Rust agents. Invoked as:  ((<this file>)())
//
// Returns {is_twofa, selector, submit_selector, reason}. It is used to:
//   - auto-emit a {"type":"twofa", config:{selector, submit_selector}} step
//     during recording when the user lands on a verification screen, and
//   - provide a selector fallback for the replay/entry path.
//
// It detects the OTP field whether the challenge is inline (a step after the
// password), inside a modal/dialog, or on a redirected page, scanning the main
// document, open dialogs, and same-origin iframes.
//
// IMPORTANT: keep this file ESCAPE-FREE (no backslash escapes in string/regex
// literals) — it is transported as JSON to the agents.
function () {
  var KW = ["otp", "one-time", "onetime", "one time", "verification code",
            "verification", "verify", "passcode", "security code", "login code",
            "authentication code", "auth code", "2fa", "two-factor", "two factor",
            "enter the code", "enter code", "we sent", "código", "codigo",
            "verificación", "verifizierung", "bestätigung", "vérification",
            "認証", "確認コード", "验证码", "인증", "رمز"];

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
                 el.className];
    return parts.join(" ").toLowerCase();
  }
  function hasKw(s) {
    s = (s || "").toLowerCase();
    for (var i = 0; i < KW.length; i++) { if (s.indexOf(KW[i]) >= 0) { return true; } }
    return false;
  }
  function cssPath(el) {
    if (el.id) {
      try { return "#" + (window.CSS && CSS.escape ? CSS.escape(el.id) : el.id); } catch (e) { return "#" + el.id; }
    }
    var nm = el.getAttribute("name");
    if (nm) { return el.tagName.toLowerCase() + "[name=" + JSON.stringify(nm) + "]"; }
    var ac = el.getAttribute("autocomplete");
    if (ac && ac.indexOf("one-time-code") >= 0) { return "input[autocomplete~=one-time-code]"; }
    // positional fallback within the element's parent
    var parts = [];
    var node = el;
    while (node && node.nodeType === 1 && parts.length < 4) {
      var tag = node.tagName.toLowerCase();
      var idx = 1;
      var sib = node;
      while ((sib = sib.previousElementSibling)) { if (sib.tagName === node.tagName) { idx++; } }
      parts.unshift(tag + ":nth-of-type(" + idx + ")");
      if (node.id) { parts.unshift("#" + node.id); break; }
      node = node.parentElement;
    }
    return parts.join(" > ");
  }

  function findField() {
    var rs = roots();
    // 1) autocomplete one-time-code
    for (var a = 0; a < rs.length; a++) {
      var otc = null;
      try { otc = rs[a].querySelector("input[autocomplete~=one-time-code]"); } catch (e) { otc = null; }
      if (otc && visible(otc)) { return otc; }
    }
    // 2) segmented single-char cluster (>=4 maxlength=1 inputs)
    for (var b = 0; b < rs.length; b++) {
      var all = [];
      try { all = rs[b].querySelectorAll("input"); } catch (e) { all = []; }
      var seg = [];
      for (var c = 0; c < all.length; c++) {
        var el = all[c];
        if (el.getAttribute("maxlength") === "1" || el.maxLength === 1) { if (visible(el)) { seg.push(el); } }
      }
      if (seg.length >= 4) { return seg[0]; }
    }
    // 3) keyword-matching text-like input
    for (var d = 0; d < rs.length; d++) {
      var ins = [];
      try { ins = rs[d].querySelectorAll("input"); } catch (e) { ins = []; }
      for (var e2 = 0; e2 < ins.length; e2++) {
        var inp = ins[e2];
        var ty = (inp.getAttribute("type") || "text").toLowerCase();
        if (ty === "hidden" || ty === "checkbox" || ty === "radio" || ty === "submit" || ty === "button" || ty === "password") { continue; }
        if (visible(inp) && (hasKw(attrText(inp)) || (inp.getAttribute("inputmode") === "numeric"))) { return inp; }
      }
    }
    return null;
  }

  function findSubmit(field) {
    var scope = (field && field.ownerDocument) || document;
    var btns = [];
    try { btns = scope.querySelectorAll("button, input[type=submit], [role=button], a[role=button]"); } catch (e) { btns = []; }
    var words = ["verify", "continue", "submit", "confirm", "next", "log in", "login",
                 "sign in", "signin", "validate", "ok", "done"];
    for (var i = 0; i < btns.length; i++) {
      var b = btns[i];
      if (!visible(b)) { continue; }
      var label = ((b.textContent || "") + " " + (b.getAttribute("value") || "") + " " + (b.getAttribute("aria-label") || "")).toLowerCase();
      for (var j = 0; j < words.length; j++) { if (label.indexOf(words[j]) >= 0) { return cssPath(b); } }
    }
    return null;
  }

  function pageHasKw() {
    var rs = roots();
    for (var i = 0; i < rs.length; i++) {
      var t = "";
      try { t = (rs[i].body ? rs[i].body.innerText : (rs[i].innerText || "")) || ""; } catch (e) { t = ""; }
      if (hasKw(t)) { return true; }
    }
    return false;
  }

  // Classify HOW the code is delivered, so the UI can pre-select the matching
  // persona 2FA method (authenticator/email/SMS). Best-effort HINT only — it is
  // NOT written into the step's runtime method, so a configured persona governs
  // execution. We read text from the challenge container nearest the field
  // (form/dialog/section) to avoid picking up an unrelated "Email" login label.
  function channelText(field) {
    var scope = null;
    try {
      scope = field.closest && (field.closest("form") || field.closest("[role=dialog]")
        || field.closest("section") || field.closest("main"));
    } catch (e) {}
    var t = "";
    try { t = (scope && scope.innerText) ? scope.innerText : ""; } catch (e) { t = ""; }
    if (!t || t.length < 8) {
      try { t = (document.body ? document.body.innerText : "") || ""; } catch (e) { t = ""; }
    }
    return (t || "").toLowerCase();
  }
  function detectChannel(field) {
    var t = channelText(field);
    // Multilingual, mirroring the languages KW covers (en/es/fr/de/ja/zh/ko/ar).
    // TOTP leans on app-specific phrases + brands so the generic word
    // "authentication" (true of ALL 2FA) does not over-classify as authenticator.
    var TOTP = ["authenticator", "authenticator app", "authentication app",
                "google authenticator", "microsoft authenticator", "authy", "1password",
                "totp", "code generator", "from your app", "in your app", "generated by your",
                "aplicación de autenticación", "app de autenticación", "autenticador",
                "application d'authentification", "appli d'authentification",
                "authentifizierungs-app", "authentifizierungsapp",
                "認証アプリ", "身份验证器", "验证器应用", "인증 앱", "인증앱", "تطبيق المصادقة"];
    var SMS = ["text message", "sms", "text you", "via text", "by text", "to your phone",
               "phone number", "mobile number", "texted", "to your mobile", "text a code",
               "sent by text", "phone ending", "by sms", "your phone ending",
               "mensaje de texto", "número de teléfono", "tu teléfono", "por sms",
               "message texte", "numéro de téléphone", "votre téléphone", "par sms",
               "textnachricht", "telefonnummer", "handynummer", "mobiltelefon", "per sms",
               "ショートメッセージ", "テキストメッセージ", "電話番号", "携帯電話",
               "短信", "手机号", "电话号码", "문자 메시지", "휴대폰", "전화번호",
               "رسالة نصية", "هاتف", "جوال"];
    var EMAIL = ["e-mail", "email", "sent to your email", "check your inbox", "emailed you",
                 "by email", "via email", "your mailbox", "to your inbox",
                 "correo electrónico", "correo", "bandeja de entrada",
                 "courriel", "boîte de réception", "par e-mail",
                 "postfach", "per e-mail",
                 "メール", "電子メール", "电子邮件", "邮箱", "邮件",
                 "이메일", "메일", "البريد الإلكتروني", "بريد"];
    function score(list) { var n = 0; for (var i = 0; i < list.length; i++) { if (t.indexOf(list[i]) >= 0) { n++; } } return n; }
    var cands = [["totp", score(TOTP)], ["sms", score(SMS)], ["email_otp", score(EMAIL)]];
    var best = "unknown", bestN = 0;
    // Strict > keeps array order on ties: totp (mirrorable seed) > sms > email_otp.
    for (var k = 0; k < cands.length; k++) { if (cands[k][1] > bestN) { bestN = cands[k][1]; best = cands[k][0]; } }
    return bestN > 0 ? best : "unknown";
  }

  var field = findField();
  if (!field) {
    return { is_twofa: false, selector: null, submit_selector: null, reason: "no_field" };
  }
  // Require either a code-shaped field OR corroborating page keyword text so a
  // generic numeric input on an unrelated form is not mistaken for 2FA.
  var corroborated = (field.getAttribute("autocomplete") || "").indexOf("one-time-code") >= 0
    || (field.maxLength === 1) || field.getAttribute("maxlength") === "1"
    || hasKw(attrText(field)) || pageHasKw();
  if (!corroborated) {
    return { is_twofa: false, selector: null, submit_selector: null, reason: "weak_signal" };
  }
  return {
    is_twofa: true,
    selector: cssPath(field),
    submit_selector: findSubmit(field),
    channel: detectChannel(field),
    reason: "ok"
  };
}
