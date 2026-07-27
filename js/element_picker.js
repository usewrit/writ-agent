// Shared element picker for the live check-wizard browser preview.
// SINGLE SOURCE for both agents: Python loads it via picker_js.py, the Rust
// agent embeds it via include_str! — keep behavior identical for both.
//
// Evaluates to a function expression taking one argument {mode, x, y, w, h}
// (viewport coordinates, 1280x800 recorder viewport):
//   mode "point"  → info for the element at (x, y), or null
//   mode "region" → {elements: [info, ...]} — top-level visible elements fully
//                   inside the rect (x, y, w, h), capped at 12
//
// info = {selector, tag, text, ariaLabel, rect:{x,y,w,h}, matchCount}
//
// Unlike the recording click path (which snaps to nearby interactive inputs),
// this returns the EXACT element under the point — monitoring wants the
// content node the user clicked, not the closest form control. Selector
// generation is tuned for uniqueness/stability (monitoring re-resolves the
// selector on every check), preferring id > stable attributes > classes >
// a bounded :nth-of-type ancestor path.
(function (arg) {
  arg = arg || {};
  var mode = arg.mode || 'point';

  function cssEscape(s) {
    s = String(s);
    if (window.CSS && CSS.escape) return CSS.escape(s);
    // Crude fallback for non-Chromium contexts (CSS.escape exists everywhere we run).
    return s.replace(/([^a-zA-Z0-9_-])/g, '\\$1');
  }
  function unique(sel) {
    if (!sel) return false;
    try { return document.querySelectorAll(sel).length === 1; } catch (e) { return false; }
  }
  function matchCount(sel) {
    try { return document.querySelectorAll(sel).length; } catch (e) { return 0; }
  }

  function buildSelector(el) {
    if (el.id && unique('#' + cssEscape(el.id))) return '#' + cssEscape(el.id);
    var tag = el.tagName.toLowerCase();
    var attrs = ['data-testid', 'data-test', 'data-qa', 'name', 'itemprop', 'aria-label'];
    for (var i = 0; i < attrs.length; i++) {
      var v = el.getAttribute && el.getAttribute(attrs[i]);
      if (v && v.length < 80) {
        var s = tag + '[' + attrs[i] + '="' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"]';
        if (unique(s)) return s;
      }
    }
    if (el.className && typeof el.className === 'string') {
      var classes = el.className.trim().split(/\s+/).filter(function (c) {
        // Skip framework-generated / state classes — they churn between loads.
        return c && !/^(ng-|v-|js-|is-|has-|css-|sc-|jsx-)/.test(c) && !/[[\]:()#%]/.test(c);
      }).slice(0, 3);
      for (var n = classes.length; n > 0; n--) {
        var cs = tag + '.' + classes.slice(0, n).map(cssEscape).join('.');
        if (unique(cs)) return cs;
      }
    }
    // Bounded ancestor path with :nth-of-type, stopping early once unique.
    var parts = [];
    var cur = el;
    var depth = 0;
    while (cur && cur.nodeType === 1 && depth < 8) {
      var t = cur.tagName.toLowerCase();
      if (t === 'html' || t === 'body') break;
      if (cur.id) {
        parts.unshift('#' + cssEscape(cur.id));
        var withId = parts.join(' > ');
        if (unique(withId)) return withId;
        break;
      }
      var part = t;
      var parent = cur.parentElement;
      if (parent) {
        var sibs = Array.prototype.filter.call(parent.children, function (c) { return c.tagName === cur.tagName; });
        if (sibs.length > 1) part += ':nth-of-type(' + (Array.prototype.indexOf.call(sibs, cur) + 1) + ')';
      }
      parts.unshift(part);
      var sel = parts.join(' > ');
      if (unique(sel)) return sel;
      cur = parent;
      depth++;
    }
    return parts.join(' > ') || tag;
  }

  function info(el) {
    // Prefer the recorder's selector engine when injected — but only keep its
    // answer if it's unique (it optimizes for click intent, not monitoring).
    var selector = null;
    try {
      if (window.__psRecorder && window.__psRecorder.getSelector) {
        var s = window.__psRecorder.getSelector(el);
        if (unique(s)) selector = s;
      }
    } catch (e) {}
    if (!selector) selector = buildSelector(el);
    var r = el.getBoundingClientRect();
    var text = (el.innerText || el.textContent || '').replace(/\s+/g, ' ').trim().slice(0, 140);
    return {
      selector: selector,
      tag: el.tagName.toLowerCase(),
      text: text,
      ariaLabel: (el.getAttribute && el.getAttribute('aria-label')) || '',
      rect: { x: Math.round(r.left), y: Math.round(r.top), w: Math.round(r.width), h: Math.round(r.height) },
      matchCount: matchCount(selector),
    };
  }

  function visible(el) {
    var r = el.getBoundingClientRect();
    if (r.width < 2 || r.height < 2) return false;
    var st = window.getComputedStyle(el);
    return st.display !== 'none' && st.visibility !== 'hidden' && st.opacity !== '0';
  }

  if (mode === 'region') {
    var rx = arg.x || 0, ry = arg.y || 0, rw = arg.w || 0, rh = arg.h || 0;
    function contained(r) {
      return r.left >= rx - 2 && r.top >= ry - 2 && r.right <= rx + rw + 2 && r.bottom <= ry + rh + 2;
    }
    var all = document.body ? document.body.getElementsByTagName('*') : [];
    var inRegion = [];
    for (var j = 0; j < all.length; j++) {
      var el2 = all[j];
      var tg = el2.tagName.toLowerCase();
      if (tg === 'script' || tg === 'style' || tg === 'noscript' || tg === 'svg' || tg === 'path') continue;
      if (!contained(el2.getBoundingClientRect())) continue;
      if (!visible(el2)) continue;
      inRegion.push(el2);
    }
    // Keep only top-level matches (drop descendants of another match) so a
    // drag over a product card yields the card pieces, not every nested span.
    var matchSet = new Set(inRegion);
    var top = inRegion.filter(function (e2) {
      var p = e2.parentElement;
      while (p && p !== document.body) {
        if (matchSet.has(p)) return false;
        p = p.parentElement;
      }
      return true;
    }).slice(0, 12);
    return { elements: top.map(info) };
  }

  var el = document.elementFromPoint(arg.x || 0, arg.y || 0);
  if (!el || el === document.documentElement || el === document.body) return null;
  return info(el);
})
