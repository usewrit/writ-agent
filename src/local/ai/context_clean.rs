//! Shared DOM/text cleaner for AI context.
//!
//! Strips the noise that bloats prompts — `<script>`/`<style>`/`<svg>` bodies,
//! `data:` URIs / base64 blobs, inline `style=`/`on*=` handlers, HTML comments,
//! oversized attribute values — so the concierge and the `find-selectors` brain
//! feed the model the SAME lean HTML the Python AI assist does, instead of a raw
//! `page.content()` dump.
//!
//! This is a *token-budget* cleaner, NOT a security sanitizer — it uses regexes
//! and does not parse the DOM. Keep behaviour in sync with the Python
//! `strip_ai_noise` (agent_brain_core.py) and the TS `cleanDomForAi`
//! (frontend-desktop utils/aiContext.ts).

use lazy_static::lazy_static;
use regex::{Captures, Regex};

lazy_static! {
    /// Whole elements whose *contents* are pure noise for selector reasoning.
    /// One regex per tag because Rust's `regex` has no backreferences.
    static ref BLOCK_TAG_RES: Vec<Regex> = ["script", "style", "noscript", "template", "head"]
        .iter()
        .map(|t| Regex::new(&format!(r"(?is)<{t}\b[^>]*>.*?</\s*{t}\s*>")).unwrap())
        .collect();
    /// Inline SVG markup — path `d="…"` data is huge and carries no signal.
    static ref SVG_RE: Regex = Regex::new(r"(?is)<svg\b[^>]*>.*?</\s*svg\s*>").unwrap();
    /// `<link>` / `<meta>` void tags (no closing pair).
    static ref VOID_NOISE_RE: Regex = Regex::new(r"(?is)<(?:link|meta)\b[^>]*>").unwrap();
    /// HTML comments.
    static ref COMMENT_RE: Regex = Regex::new(r"(?s)<!--.*?-->").unwrap();
    /// `data:<mime>;base64,<payload>` — collapse the whole thing (mime + payload).
    static ref DATA_URI_RE: Regex =
        Regex::new(r#"(?i)data:[^\s"'()<>]{0,80};base64,[A-Za-z0-9+/=]+"#).unwrap();
    /// Any remaining long base64-ish run (inline images, tokens, encoded blobs).
    static ref BASE64_BLOB_RE: Regex = Regex::new(r"[A-Za-z0-9+/]{300,}={0,2}").unwrap();
    /// Inline `style="…"` and `on*="…"` handlers (both quote styles).
    static ref INLINE_ATTR_RE: Regex =
        Regex::new(r#"(?i)\s(?:style|on[a-z]+)\s*=\s*("[^"]*"|'[^']*')"#).unwrap();
    /// Over-long double-quoted attribute values (class lists, encoded state).
    static ref LONG_ATTR_RE: Regex =
        Regex::new(r#"(?i)(\s[a-z_:][\w:.\-]*\s*=\s*")([^"]{120,})(")"#).unwrap();
    /// Runs of whitespace.
    static ref WS_RE: Regex = Regex::new(r"\s{2,}").unwrap();
}

/// Strip DOM noise for AI: remove script/style/svg/etc. bodies, `data:` URIs and
/// base64 blobs, inline styles/handlers, comments; truncate oversized attribute
/// values; collapse whitespace. Purely a token-budget cleaner.
pub fn clean_dom_for_ai(html: &str) -> String {
    let mut s = html.to_string();
    for re in BLOCK_TAG_RES.iter() {
        s = re.replace_all(&s, " ").into_owned();
    }
    let s = SVG_RE.replace_all(&s, " ");
    let s = COMMENT_RE.replace_all(&s, " ");
    let s = VOID_NOISE_RE.replace_all(&s, " ");
    let s = INLINE_ATTR_RE.replace_all(&s, " ");
    let s = DATA_URI_RE.replace_all(&s, "[data-uri]"); // before the generic blob rule
    let s = BASE64_BLOB_RE.replace_all(&s, "[blob]");
    let s = LONG_ATTR_RE.replace_all(&s, |c: &Captures| {
        let val: String = c[2].chars().take(100).collect();
        format!("{}{}…\"", &c[1], val)
    });
    WS_RE.replace_all(&s, " ").trim().to_string()
}

/// Strip base64/data-URI/SVG noise from a plain text/value string (no HTML-tag
/// removal). Mirrors the Python `strip_ai_noise`.
pub fn strip_ai_noise(text: &str) -> String {
    let s = SVG_RE.replace_all(text, "[svg]");
    let s = DATA_URI_RE.replace_all(&s, "[data-uri]");
    BASE64_BLOB_RE.replace_all(&s, "[blob]").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_script_style_svg() {
        let html = r#"<html><head><title>T</title></head><body>
            <script>var x = 1; doStuff();</script>
            <style>.a{color:red}</style>
            <svg viewBox="0 0 1 1"><path d="M0 0L1 1Z"/></svg>
            <button id="buy">Buy</button></body></html>"#;
        let out = clean_dom_for_ai(html);
        assert!(!out.contains("doStuff"), "script body survived: {out}");
        assert!(!out.contains("color:red"), "style body survived: {out}");
        assert!(!out.contains("<path"), "svg survived: {out}");
        assert!(!out.to_lowercase().contains("<title"), "head survived: {out}");
        assert!(out.contains(r#"<button id="buy">Buy</button>"#), "lost real element: {out}");
    }

    #[test]
    fn collapses_data_uri_and_base64() {
        let big = "A".repeat(500);
        let html = format!(r#"<img src="data:image/png;base64,{big}"><i data-x="{big}"></i>"#);
        let out = clean_dom_for_ai(&html);
        assert!(out.contains("[data-uri]"), "data uri not collapsed: {out}");
        assert!(!out.contains(&big), "raw blob survived: {out}");
    }

    #[test]
    fn drops_inline_style_and_handlers() {
        let html = r#"<div style="display:none" onclick="hack()" class="card">hi</div>"#;
        let out = clean_dom_for_ai(html);
        assert!(!out.contains("display:none"), "inline style survived: {out}");
        assert!(!out.contains("hack()"), "handler survived: {out}");
        assert!(out.contains("class=\"card\""), "lost real attr: {out}");
    }

    #[test]
    fn truncates_long_attr_value() {
        // A realistic long class list (spaces/hyphens → not caught by the base64 rule).
        let cls = "cls-name ".repeat(40);
        let html = format!(r#"<div class="{cls}">t</div>"#);
        let out = clean_dom_for_ai(&html);
        assert!(out.contains('…'), "long attr not truncated: {out}");
        assert!(!out.contains(&cls), "full long attr survived");
    }

    #[test]
    fn preserves_row_collapse_marker() {
        // The in-page collapse inserts a <span data-collapsed> marker; the cleaner must keep it (and
        // its text) so the model knows there are more identical rows.
        let html = r#"<ul><li class="row">a</li><span data-collapsed="96">…+96 more <li> siblings, same structure…</span></ul>"#;
        let out = clean_dom_for_ai(html);
        assert!(out.contains("data-collapsed=\"96\""), "marker attr stripped: {out}");
        assert!(out.contains("more") && out.contains("same structure"), "marker text stripped: {out}");
        assert!(out.contains(r#"<li class="row">"#), "real sample row lost: {out}");
    }

    #[test]
    fn strip_ai_noise_text_only() {
        let big = "B".repeat(400);
        assert_eq!(strip_ai_noise("plain text"), "plain text");
        assert_eq!(
            strip_ai_noise(&format!("x data:image/png;base64,{big} y")),
            "x [data-uri] y"
        );
        assert!(strip_ai_noise("<svg><path d='M0 0'/></svg>").contains("[svg]"));
    }
}
