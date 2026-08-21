//! Frame flattening for browser-lane crawl renders.
//!
//! `page.content()` serializes the MAIN frame only, so anything a page shows
//! through an `<iframe>` or a legacy `<frameset>` never reaches extraction —
//! a framed docs viewer or frameset site crawls as an empty shell. Before
//! capture, this module folds the page's *own* frames back into the top
//! document, entirely inside the browser:
//!
//! 1. Each admitted frame is serialized in ITS OWN context ([`SERIALIZER_JS`]):
//!    body HTML with `href`/`src` absolutized against the frame's base, so
//!    links harvested from the flattened document resolve correctly.
//! 2. Bottom-up, each serialized frame is handed to its PARENT
//!    ([`MUTATOR_JS`]), which swaps the child's `<iframe>`/`<frame>` element
//!    for `<section data-writ-frame-src="…">…</section>` in its live DOM — a
//!    parent therefore serializes with its children already inline, so nested
//!    framesets compose.
//! 3. [`FINALIZE_JS`] runs in the main frame: a frameset root gets a
//!    synthesized `<body>` holding the sections, because HTML5 parsers DROP
//!    markup trailing a `<frameset>` (and the `<noframes>` junk goes with it).
//!
//! Admission is conservative: same-site frames (exact host or subdomain
//! relation) plus origin-inheriting `about:`/`data:`/`blob:` frames. Third-
//! party embeds — players, ads, captchas — stay out; their `src` URLs are
//! still harvested as frontier links by `extract.rs`, where coordinator scope
//! rules decide. Every browser call is best-effort: flattening must never fail
//! a page, so any error degrades to the plain unflattened capture.
//!
//! The three JS payloads are embedded VERBATIM from the canonical copies in
//! the Python agent (`pagesurveil-agent/pagesurveil_agent/frame_flatten.py`);
//! its `test_js_payloads_match_rust_agent` fails when the trees drift —
//! change BOTH or change neither. (The traversal differs in shape — Python
//! walks a flat depth-sorted list, this recurses — but the injection order,
//! admission, and caps agree.)

use playwright_rs::protocol::Frame;
use playwright_rs::Page;
use serde_json::json;

/// Frames deeper than this (main frame = depth 0) are ignored.
const MAX_FLATTEN_DEPTH: usize = 3;
/// At most this many frames are inlined per page.
const MAX_FLATTEN_FRAMES: usize = 20;
/// Total characters of frame HTML injected into one page. The PER-frame cap
/// (200k chars) is enforced inside `SERIALIZER_JS` itself.
const TOTAL_FLATTEN_CHAR_CAP: usize = 600_000;

pub const SERIALIZER_JS: &str = r#"() => {
  try {
    const root = document.body;
    if (!root) return "";
    let clone;
    if (root.tagName === "FRAMESET") {
      clone = document.createElement("div");
      root.querySelectorAll("section[data-writ-frame-src]").forEach((s) => clone.appendChild(s.cloneNode(true)));
    } else {
      clone = root.cloneNode(true);
    }
    clone.querySelectorAll("script,style,noscript,template,link").forEach((n) => n.remove());
    clone.querySelectorAll("[href]").forEach((el) => {
      try { el.setAttribute("href", new URL(el.getAttribute("href"), document.baseURI).href); } catch (e) {}
    });
    clone.querySelectorAll("[src]").forEach((el) => {
      try { el.removeAttribute("srcset"); el.setAttribute("src", new URL(el.getAttribute("src"), document.baseURI).href); } catch (e) {}
    });
    if (!clone.textContent.trim() && !clone.querySelector("img,table")) return "";
    const html = clone.innerHTML;
    return html.length > 200000 ? "" : html;
  } catch (e) { return ""; }
}"#;

pub const MUTATOR_JS: &str = r#"(arg) => {
  try {
    const els = Array.from(document.querySelectorAll("iframe,frame"));
    let target = null;
    for (const el of els) {
      const raw = el.getAttribute("src");
      if (!raw) continue;
      let u = "";
      try { u = new URL(raw, document.baseURI).href; } catch (e) { continue; }
      if (u === arg.url) { target = el; break; }
    }
    if (!target && (arg.url.startsWith("about:") || arg.url.startsWith("data:") || arg.url.startsWith("blob:"))) {
      for (const el of els) {
        const raw = el.getAttribute("src") || "";
        if (!raw || raw.startsWith("about:")) { target = el; break; }
      }
    }
    const sec = document.createElement("section");
    sec.setAttribute("data-writ-frame-src", arg.url);
    sec.innerHTML = arg.html;
    if (target) {
      target.replaceWith(sec);
    } else {
      const root = (document.body && document.body.tagName === "BODY") ? document.body : document.documentElement;
      root.appendChild(sec);
    }
    return true;
  } catch (e) { return false; }
}"#;

pub const FINALIZE_JS: &str = r#"() => {
  try {
    const root = document.body;
    if (root && root.tagName === "BODY") return true;
    const nb = document.createElement("body");
    document.querySelectorAll("section[data-writ-frame-src]").forEach((s) => nb.appendChild(s));
    if (root) root.remove();
    document.documentElement.appendChild(nb);
    return true;
  } catch (e) { return false; }
}"#;

fn host_of(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .unwrap_or_default()
}

/// Exact host match or a subdomain relation in either direction.
fn hosts_same_site(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    a == b || a.ends_with(&format!(".{b}")) || b.ends_with(&format!(".{a}"))
}

/// Should this frame's content be inlined into the page capture? Same-site
/// http(s) frames and origin-inheriting pseudo-URLs (`about:`/`data:`/`blob:`,
/// incl. srcdoc frames) are in; third-party embeds stay out.
fn frame_admitted(frame_url: &str, top_host: &str) -> bool {
    let u = frame_url.trim();
    if u.is_empty() || u.starts_with("about:") || u.starts_with("data:") || u.starts_with("blob:") {
        return true;
    }
    match url::Url::parse(u) {
        Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => {
            hosts_same_site(&host_of(u), top_host)
        }
        _ => false,
    }
}

/// Serialize `frame` with its admitted children already folded in
/// (deepest-first), spending from the shared char `budget`. `None` = empty or
/// failed — the caller simply leaves the frame's element in place (extraction
/// prunes the carcass).
async fn serialize_subtree(
    frame: &Frame,
    top_host: &str,
    depth: usize,
    budget: &mut usize,
    frames_left: &mut usize,
) -> Option<String> {
    if depth > MAX_FLATTEN_DEPTH || *frames_left == 0 {
        return None;
    }
    *frames_left -= 1;
    for child in frame.child_frames() {
        let child_url = child.url();
        if !frame_admitted(&child_url, top_host) {
            continue;
        }
        let Some(html) =
            Box::pin(serialize_subtree(&child, top_host, depth + 1, budget, frames_left)).await
        else {
            continue;
        };
        if html.len() > *budget {
            continue;
        }
        let arg = json!({ "url": child_url, "html": html });
        if let Ok(v) = frame.evaluate(MUTATOR_JS, Some(&arg)).await {
            if v.as_bool().unwrap_or(false) {
                *budget = budget.saturating_sub(html.len());
            }
        }
    }
    let v = frame.evaluate::<()>(SERIALIZER_JS, None).await.ok()?;
    let s = v.as_str().unwrap_or_default();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Inline admitted subframe content into the page's live DOM; returns the
/// number of top-level frames folded in. Never fails the page — every error
/// degrades to skipping a frame (at worst, to a plain unflattened capture).
pub async fn flatten_frames(page: &Page) -> usize {
    let Ok(main) = page.main_frame().await else {
        return 0;
    };
    let top_host = host_of(&page.url());
    let mut budget = TOTAL_FLATTEN_CHAR_CAP;
    let mut frames_left = MAX_FLATTEN_FRAMES;
    let mut injected = 0usize;
    for child in main.child_frames() {
        if frames_left == 0 {
            break;
        }
        let child_url = child.url();
        if !frame_admitted(&child_url, &top_host) {
            continue;
        }
        let Some(html) =
            serialize_subtree(&child, &top_host, 1, &mut budget, &mut frames_left).await
        else {
            continue;
        };
        if html.len() > budget {
            continue;
        }
        let arg = json!({ "url": child_url, "html": html });
        match main.evaluate(MUTATOR_JS, Some(&arg)).await {
            Ok(v) if v.as_bool().unwrap_or(false) => {
                budget = budget.saturating_sub(html.len());
                injected += 1;
            }
            _ => {}
        }
    }
    if injected > 0 {
        let _ = main.evaluate::<()>(FINALIZE_JS, None).await;
    }
    injected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_is_same_site_plus_inherited_origins() {
        assert!(frame_admitted("https://example.com/inner", "example.com"));
        assert!(frame_admitted("https://docs.example.com/inner", "example.com"));
        // Subdomain relation holds both ways (page on www, frame on apex).
        assert!(frame_admitted("https://example.com/x", "www.example.com"));
        assert!(frame_admitted("about:blank", "example.com"));
        assert!(frame_admitted("about:srcdoc", "example.com"));
        assert!(frame_admitted("", "example.com"));
        assert!(frame_admitted("data:text/html,<p>x</p>", "example.com"));
        assert!(!frame_admitted("https://evil.example.net/w", "example.com"));
        assert!(!frame_admitted("https://notexample.com/w", "example.com"));
        assert!(!frame_admitted("javascript:void(0)", "example.com"));
        assert!(!hosts_same_site("example.com", ""));
    }

    #[test]
    fn payloads_carry_the_contract_markers() {
        // The section marker is what extraction/link-harvest rely on, and the
        // per-frame char cap lives inside the serializer — guard both.
        for js in [SERIALIZER_JS, MUTATOR_JS, FINALIZE_JS] {
            assert!(js.contains("data-writ-frame-src"));
        }
        assert!(SERIALIZER_JS.contains("200000"));
    }
}
