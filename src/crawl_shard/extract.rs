//! Per-page extraction for a Dragnet crawl: clean markdown (readability-lite) OR a replayed CSS
//! schema, plus link harvesting for the frontier. Pure + synchronous — every output is owned
//! (`String`/`Vec`/`usize`) so a worker future that calls this stays `Send` (the non-`Send`
//! `scraper::Html` is created and dropped entirely inside these fns, never across an `.await`).
//!
//! Markdown quality (parity with the cloud Python agent's `crawl_exec._to_markdown`):
//!   1. `strip_chrome` prunes the DOM — structural chrome tags (nav/header/footer/aside/form/
//!      script/…), ARIA landmark regions, `aria-hidden`, and class/id-flagged boilerplate
//!      (cookie bars, share widgets, related links, newsletters, ads …), while protecting the
//!      bulk-text block so a content wrapper whose class merely matches survives.
//!   2. the best main-content container (`<article>`/`<main>`/`<body>`) → `htmd` (GFM tables).
//!   3. `normalize_markdown` — setext→ATX h1, absolute links, drop data-URI images, collapse
//!      whitespace, and de-duplicate repeated content blocks.
//! Each markdown row is prefixed with a YAML frontmatter header
//! (`title`/`url`/`description`/`author`/`published`/`site`/`crawled_at`).

use lazy_static::lazy_static;
use regex::Regex;
use scraper::{ElementRef, Html, Selector};
use serde_json::{json, Value};
use std::collections::HashSet;
use url::Url;

// --------------------------------------------------------------------------- //
// Chrome/boilerplate removal + markdown cleanup config                         //
// --------------------------------------------------------------------------- //

/// Structural tags that are never main content — pruned wholesale.
const CHROME_TAGS: &[&str] = &[
    "script", "style", "noscript", "template", "nav", "header", "footer", "aside", "form", "svg",
    "iframe", "dialog", "menu", "button",
];
/// ARIA landmark roles that mark chrome regions.
const ROLE_JUNK: &[&str] = &[
    "navigation", "banner", "contentinfo", "complementary", "search", "dialog", "menubar", "menu",
    "tablist", "toolbar",
];
/// Block-level tag names — an element containing any of these isn't a leaf (judge its leaves instead).
/// A plain name list rather than a `Selector` because the chrome pass now tests it during ONE
/// bottom-up tree walk instead of running a descendant query per candidate (see [`subtree_stats`]).
const BLOCKISH_TAGS: &[&str] =
    &["p", "div", "section", "article", "table", "ul", "ol", "li", "td", "tr", "blockquote"];
/// A junk-classed element is only pruned when it holds less than this share of the page's text —
/// protects a main-content block whose class merely matches a junk pattern.
const JUNK_TEXT_SHARE: f64 = 0.4;
/// Single-line blocks must reach this length before duplicate-removal considers them.
const DEDUPE_MIN_LEN: usize = 40;
/// Multi-line blocks (tables/lists/code) de-dupe sooner than prose one-liners.
const DEDUPE_MULTILINE_MIN_LEN: usize = 12;
/// Link-list boilerplate removal (mirrors the Python agent). A short block with >= NAV_MIN_LINKS links
/// and no real word residue after removing links + separators is nav/footer/breadcrumb chrome; a block
/// with >= CONTENT_MIN_WORDS of prose is always kept.
const CONTENT_MIN_WORDS: usize = 25;
const NAV_MIN_LINKS: usize = 3;      // 1-2 links = a title+source line → keep.
const NAV_RESIDUE_MAX: usize = 4;    // alnum chars left after stripping links+separators; ≤ ⇒ chrome.

lazy_static! {
    /// Layout spacers / vote arrows / tracking pixels (HN s.gif indent + triangle upvotes).
    static ref SPACER_IMG_RE: Regex = Regex::new(
        r"(?i)(?:^|/)(?:s\.gif|spacer|pixel|blank|clear|triangle|grayarrow|upvote|downvote)"
    ).unwrap();
    static ref A_SEL: Selector = Selector::parse("a").unwrap();
    /// class/id substrings that flag boilerplate (matched case-insensitively).
    static ref ATTR_JUNK_RE: Regex = Regex::new(
        r"(?i)nav|navbar|menu|breadcrumb|pagination|pager|cookie|consent|gdpr|advert|\bads?\b|sponsor|promo|newsletter|subscribe|signup|social|share|sharing|related|recommend|popular|trending|sidebar|footer|masthead|toolbar|offcanvas|drawer|modal|popup|overlay|lightbox|skip|sr-only|visually-hidden|screen-reader|banner"
    )
    .unwrap();
    /// html2md renders `<h1>` as a setext underline (`Title\n==========`); rewrite to ATX `#`.
    static ref SETEXT_H1_RE: Regex = Regex::new(r"(?m)^(\S.*)\n=+[ \t]*$").unwrap();
    /// Inlined data-URI images (base64 bloat) and empty image artifacts.
    static ref DATA_IMG_RE: Regex = Regex::new(r"!\[[^\]]*\]\(\s*data:[^)]*\)").unwrap();
    static ref EMPTY_IMG_RE: Regex = Regex::new(r"!\[\s*\]\(\s*\)").unwrap();
    /// html2md emits raw `<img>` HTML (with EVERY attribute) whenever the tag has width/height/
    /// align — rewrite to markdown `![alt](src)`; `<br>` → newline; then strip the inline tags
    /// html2md passes through verbatim (sup/sub citations, spans, figures …) which otherwise
    /// leak megabytes of `data-*`/`srcset` markup into the output.
    static ref RAW_IMG_RE: Regex = Regex::new(r"(?is)<img\b[^>]*>").unwrap();
    static ref IMG_SRC_RE: Regex = Regex::new(r#"(?is)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap();
    static ref IMG_ALT_RE: Regex = Regex::new(r#"(?is)\balt\s*=\s*(?:"([^"]*)"|'([^']*)')"#).unwrap();
    static ref BR_RE: Regex = Regex::new(r"(?is)<br\s*/?>").unwrap();
    // NB: raw `<a>` here is only citation/name-anchor HTML that html2md left verbatim (inside a
    // stripped `<sup>`); real content links are already markdown `[text](url)`, so unwrapping raw
    // `<a>` to its text is safe.
    static ref STRAY_TAG_RE: Regex = Regex::new(
        r"(?is)</?(?:sup|sub|span|cite|abbr|small|mark|time|bdi|wbr|figure|figcaption|details|summary|section|article|div|font|center|ins|del|a)\b[^>]*>"
    )
    .unwrap();
    /// >2 blank lines collapse to one; block split for de-dupe.
    static ref MULTINL_RE: Regex = Regex::new(r"\n{3,}").unwrap();
    static ref BLOCK_SPLIT_RE: Regex = Regex::new(r"\n{2,}").unwrap();
    /// A markdown link/image opener + its target (up to whitespace or `)`), for absolutization.
    static ref LINK_RE: Regex = Regex::new(r"(!?\[[^\]]*\]\()([^)\s]+)").unwrap();
    /// A NON-image markdown link whose target is a bare fragment (`[label](#cite1)`). The fragment
    /// target is never part of a per-page extract, so the link cannot resolve — keep only the label.
    /// The label alternation `(?:\\.|[^\]\\])*` MUST allow escape sequences: a converter escapes a
    /// literal `]` inside the label (a `[1]` citation becomes `[\[1\]](#cite1)`), and a plain
    /// `[^\]]*` would stop dead at that escaped bracket and never match.
    static ref FRAGMENT_LINK_RE: Regex =
        Regex::new(r"\[((?:\\.|[^\]\\])*)\]\(#[^)\s]*\)").unwrap();
    /// Backslash-escaped markdown brackets, as a converter emits inside a link label that itself
    /// contains literal `[` / `]` (e.g. a `[1]` citation).
    static ref ESCAPED_BRACKET_RE: Regex = Regex::new(r"\\([\[\]])").unwrap();
}

/// Page metadata harvested from `<meta>`/`<title>` for the frontmatter header.
#[derive(Default)]
struct PageMeta {
    description: String,
    author: String,
    date: String,
    sitename: String,
}

/// One discovered link: its absolute URL plus the anchor's own text.
///
/// The text is what lets the coordinator RANK the frontier — a link labelled
/// "Pricing" scores against a "pricing plans" goal even when the URL is an opaque
/// `/p/48213`. The cloud wire contract calls this `discovered_links`; the bare
/// `discovered_urls` list is still emitted alongside it for older coordinators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageLink {
    pub url: String,
    pub text: String,
}

/// What one fetched page yields.
pub struct PageExtract {
    /// Page title (`<title>` → first `<h1>` → "").
    pub title: String,
    /// One-or-more `extracted_data` rows for this page (markdown mode = one row; schema mode = N).
    pub rows: Vec<Value>,
    /// Absolute, in-page-order, deduped discovered links (http/https only) to feed the frontier,
    /// each with its anchor text.
    pub links: Vec<PageLink>,
    /// The site's favicon URL — the page's `<link rel="…icon">` resolved absolute, else the
    /// conventional `/favicon.ico`. A plain public URL the UI can load directly; nothing is stored.
    pub favicon: Option<String>,
    /// Length of the main-content text — the browser-fallback signal (a JS-rendered SPA returns a
    /// near-empty shell over HTTP, so a tiny `text_len` on a 200 means "retry with a browser").
    pub text_len: usize,
}

/// Extract from raw HTML. `base_url` is the page's FINAL url (post-redirect) used for link
/// resolution + the row `url` field. `mode` = `"markdown"` | `"schema"`.
pub fn extract(
    html: &str,
    base_url: &str,
    depth: i64,
    fetched_at: &str,
    mode: &str,
    schema: Option<&Value>,
    content: Option<&Value>,
) -> PageExtract {
    let mut doc = Html::parse_document(html);
    // Everything derived from the ORIGINAL DOM (title/meta/links/text_len) is computed before
    // `markdown_row` prunes chrome — links must include nav/footer anchors (the orchestrator does
    // scope admission), and `text_len` is the pre-prune browser-fallback signal.
    let title = extract_title(&doc);
    let meta = extract_meta(&doc);
    let links = extract_links(&doc, base_url);
    let favicon = extract_favicon(&doc, base_url);
    let text_len = main_text_len(&doc);

    let rows = if mode == "schema" {
        let schema_rows = schema
            .map(|s| extract_schema(&doc, s, base_url, depth, fetched_at))
            .unwrap_or_default();
        // A schema crawl with no schema (e.g. the wizard picked "Structured" but no extractor is
        // attached yet) or a page that matches nothing must never yield an EMPTY dataset — fall
        // back to a markdown row so the page is still captured.
        if schema_rows.is_empty() {
            vec![markdown_row(&mut doc, base_url, &title, &meta, depth, fetched_at, content)]
        } else {
            schema_rows
        }
    } else {
        vec![markdown_row(&mut doc, base_url, &title, &meta, depth, fetched_at, content)]
    };

    PageExtract { title, rows, links, favicon, text_len }
}

/// Build the single markdown `extracted_data` row for a page (frontmatter + clean readability-lite
/// markdown + provenance columns). Prunes `doc` in place. Shared by markdown mode and the
/// schema-mode fallback. `word_count` counts the body only (frontmatter excluded).
fn markdown_row(
    doc: &mut Html,
    base_url: &str,
    title: &str,
    meta: &PageMeta,
    depth: i64,
    fetched_at: &str,
    content: Option<&Value>,
) -> Value {
    let body = to_markdown(doc, base_url, content);
    let word_count = body.split_whitespace().count();
    let frontmatter = render_frontmatter(title, meta, base_url, fetched_at);
    let markdown = if body.is_empty() {
        frontmatter
    } else {
        format!("{frontmatter}\n\n{body}")
    };
    json!({
        "url": base_url,
        "title": title,
        "markdown": markdown,
        "word_count": word_count,
        "depth": depth,
        "fetched_at": fetched_at,
    })
}

/// `<title>` text, falling back to the first `<h1>`, else "".
fn extract_title(doc: &Html) -> String {
    if let Ok(sel) = Selector::parse("title") {
        if let Some(el) = doc.select(&sel).next() {
            let t = el.text().collect::<String>();
            let t = t.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    if let Ok(sel) = Selector::parse("h1") {
        if let Some(el) = doc.select(&sel).next() {
            let t = el.text().collect::<String>();
            let t = t.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    String::new()
}

/// Page metadata from `<meta>` tags (description/author/date/sitename) for the frontmatter header.
fn extract_meta(doc: &Html) -> PageMeta {
    let content = |selectors: &[&str]| -> String {
        for s in selectors {
            let Ok(sel) = Selector::parse(s) else { continue };
            if let Some(el) = doc.select(&sel).next() {
                if let Some(c) = el.value().attr("content") {
                    let c = c.trim();
                    if !c.is_empty() {
                        return c.to_string();
                    }
                }
            }
        }
        String::new()
    };
    PageMeta {
        description: content(&[
            r#"meta[name="description"]"#,
            r#"meta[property="og:description"]"#,
            r#"meta[name="twitter:description"]"#,
        ]),
        author: content(&[r#"meta[name="author"]"#, r#"meta[property="article:author"]"#]),
        date: content(&[
            r#"meta[property="article:published_time"]"#,
            r#"meta[name="date"]"#,
            r#"meta[itemprop="datePublished"]"#,
        ]),
        sitename: content(&[r#"meta[property="og:site_name"]"#]),
    }
}

/// Max anchor-text kept per link — enough to rank on, short enough not to bloat the shard payload.
const ANCHOR_TEXT_MAX: usize = 120;

/// Collect in-scope-agnostic absolute links (`<a href>`) WITH their anchor text, resolved against
/// `base_url`, http/https only, fragment stripped, deduped preserving first-seen order (the first
/// occurrence's text wins). Scope/robots admission happens in the orchestrator — this only harvests
/// candidates; the text rides along so the coordinator can score them against the crawl's goal.
fn extract_links(doc: &Html, base_url: &str) -> Vec<PageLink> {
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };
    let sel = match Selector::parse("a[href]") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let mut out: Vec<PageLink> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for el in doc.select(&sel) {
        let Some(href) = el.value().attr("href") else { continue };
        let href = href.trim();
        if href.is_empty() || href.starts_with('#') {
            continue;
        }
        let lower = href.to_ascii_lowercase();
        if lower.starts_with("javascript:")
            || lower.starts_with("mailto:")
            || lower.starts_with("tel:")
            || lower.starts_with("data:")
        {
            continue;
        }
        let Ok(mut joined) = base.join(href) else { continue };
        if !matches!(joined.scheme(), "http" | "https") {
            continue;
        }
        joined.set_fragment(None);
        let s = joined.to_string();
        if seen.insert(s.clone()) {
            // Anchor text: collapse all whitespace, then clip on a char boundary
            // (a multi-byte glyph must not be split).
            let mut text: String = el.text().collect::<String>().split_whitespace()
                .collect::<Vec<_>>().join(" ");
            if text.chars().count() > ANCHOR_TEXT_MAX {
                text = text.chars().take(ANCHOR_TEXT_MAX).collect();
            }
            out.push(PageLink { url: s, text });
            if out.len() >= 2000 {
                return out; // one page can't flood the frontier
            }
        }
    }
    // Framed documents are pages too: harvest iframe/frame srcs so a document
    // shown only through an embed still enters the frontier as its own page
    // (the browser lane ALSO inlines same-site frame content — see `frames` —
    // but the frontier link works on every lane, and coordinator scope rules
    // decide cross-site srcs). Text: the frame's title/name, as the relevance
    // signal an anchor label would give.
    if let Ok(fsel) = Selector::parse("iframe[src], frame[src]") {
        for el in doc.select(&fsel) {
            let Some(src) = el.value().attr("src") else { continue };
            let src = src.trim();
            let lower = src.to_ascii_lowercase();
            if src.is_empty()
                || lower.starts_with("javascript:")
                || lower.starts_with("about:")
                || lower.starts_with("data:")
                || lower.starts_with("blob:")
            {
                continue;
            }
            let Ok(mut joined) = base.join(src) else { continue };
            if !matches!(joined.scheme(), "http" | "https") {
                continue;
            }
            joined.set_fragment(None);
            let s = joined.to_string();
            if seen.insert(s.clone()) {
                let mut text = el
                    .value()
                    .attr("title")
                    .or_else(|| el.value().attr("name"))
                    .unwrap_or("")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                if text.chars().count() > ANCHOR_TEXT_MAX {
                    text = text.chars().take(ANCHOR_TEXT_MAX).collect();
                }
                out.push(PageLink { url: s, text });
                if out.len() >= 2000 {
                    break;
                }
            }
        }
    }
    out
}

/// The site's favicon URL: the first `<link rel="…icon…">` href resolved against `base_url`, else
/// the conventional `/favicon.ico` on the page's origin. A `data:` icon is skipped (the UI wants a
/// loadable URL, and inlining bytes here would bloat every page's meta).
fn extract_favicon(doc: &Html, base_url: &str) -> Option<String> {
    let base = Url::parse(base_url).ok()?;
    if let Ok(sel) = Selector::parse("link[rel][href]") {
        for el in doc.select(&sel) {
            let rel = el.value().attr("rel").unwrap_or("").to_ascii_lowercase();
            if !rel.contains("icon") {
                continue;
            }
            let href = el.value().attr("href").unwrap_or("").trim();
            if href.is_empty() || href.to_ascii_lowercase().starts_with("data:") {
                continue;
            }
            if let Ok(joined) = base.join(href) {
                if matches!(joined.scheme(), "http" | "https") {
                    return Some(joined.to_string());
                }
            }
        }
    }
    base.join("/favicon.ico").ok().map(|u| u.to_string())
}

/// The main-content container's rendered length, for the browser-fallback heuristic.
fn main_text_len(doc: &Html) -> usize {
    main_container_text(doc).split_whitespace().collect::<Vec<_>>().join(" ").len()
}

/// The first element matching `pat`, if any.
fn select_first<'a>(doc: &'a Html, pat: &str) -> Option<ElementRef<'a>> {
    Selector::parse(pat).ok().and_then(|sel| doc.select(&sel).next())
}

/// Pick the main-content container: prefer `<article>`/`<main>`, but only when it holds the bulk of
/// the body text — a page with a small `<article>` teaser and its real content in `<main>` (or a
/// bare `<body>`) must not lose that content. Falls back to `<body>`, else the whole document.
fn pick_container<'a>(doc: &'a Html) -> Option<ElementRef<'a>> {
    let body = select_first(doc, "body");
    let body_len = body.as_ref().map_or(0, |e| e.text().map(str::len).sum::<usize>());
    // A semantic container must carry at least half the body's text to be trusted as "the content".
    let threshold = (body_len / 2).max(1);
    for pat in ["article", "main"] {
        if let Some(el) = select_first(doc, pat) {
            if el.text().map(str::len).sum::<usize>() >= threshold {
                return Some(el);
            }
        }
    }
    body
}

/// Pick the best main-content container and return its concatenated text.
fn main_container_text(doc: &Html) -> String {
    match pick_container(doc) {
        Some(el) => el.text().collect::<String>(),
        None => doc.root_element().text().collect::<String>(),
    }
}

/// Detach every element matching any of the CSS `selectors` (JSON strings) from `doc`. Mirrors the
/// Python agent's `_apply_content_selection` exclude path. A bad selector is skipped. Node ids are
/// gathered under an immutable borrow, then detached (same pattern as `strip_chrome`).
fn detach_selectors(doc: &mut Html, selectors: &[Value]) {
    let mut remove = Vec::new();
    for sv in selectors {
        let Some(s) = sv.as_str() else { continue };
        if let Ok(sel) = Selector::parse(s) {
            for el in doc.select(&sel) {
                remove.push(el.id());
            }
        }
    }
    for id in remove {
        if let Some(mut n) = doc.tree.get_mut(id) {
            n.detach();
        }
    }
}

/// Concatenated outer-HTML of every element matching any `include_selectors` (deduped, document
/// order per selector). Keeps ONLY those regions as the content root (the include path). Empty when
/// nothing matches (caller then falls back to the main container).
fn include_html(doc: &Html, selectors: &[Value]) -> String {
    let mut html = String::new();
    let mut seen = std::collections::HashSet::new();
    for sv in selectors {
        let Some(s) = sv.as_str() else { continue };
        if let Ok(sel) = Selector::parse(s) {
            for el in doc.select(&sel) {
                if seen.insert(el.id()) {
                    html.push_str(&el.html());
                }
            }
        }
    }
    html
}

/// Convert the page to clean markdown, honoring a content-selection `content` spec (preset +
/// include/exclude selectors + keep toggles). Mirrors the Python agent's `_to_markdown`:
///   - exclude_selectors → detached first; keep.images:false → `<img>` detached.
///   - strip_chrome always prunes nav/header/footer/aside/boilerplate.
///   - include_selectors → keep ONLY those regions; else preset "full" → whole `<body>` (no
///     main-content isolation, so comment/discussion threads survive); else "main" → the
///     `<article>`/`<main>` container.
/// Falls back to normalized plain text so a page is never a blank row.
fn to_markdown(doc: &mut Html, base_url: &str, content: Option<&Value>) -> String {
    let preset = content
        .and_then(|c| c.get("preset"))
        .and_then(|v| v.as_str())
        .unwrap_or("main");
    let keep_images = content
        .and_then(|c| c.get("keep"))
        .and_then(|k| k.get("images"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    // 1. exclude_selectors → detach matched elements.
    if let Some(exc) = content.and_then(|c| c.get("exclude_selectors")).and_then(|v| v.as_array()) {
        detach_selectors(doc, exc);
    }
    // 2. keep.images=false → drop images.
    if !keep_images {
        detach_selectors(doc, std::slice::from_ref(&Value::String("img".into())));
    }
    // 3. chrome prune (always).
    strip_chrome(doc);

    // 4. choose the content HTML.
    let inc = content
        .and_then(|c| c.get("include_selectors"))
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty());
    let inner_html = if let Some(sel_list) = inc {
        let h = include_html(doc, sel_list);
        if h.is_empty() { main_container_html(doc) } else { h }
    } else if preset == "full" {
        select_first(doc, "body")
            .map(|e| e.html())
            .unwrap_or_else(|| doc.root_element().html())
    } else {
        main_container_html(doc)
    };

    let inner_html = flatten_layout_tables(&inner_html);

    // DEPTH GATE — do NOT remove. HTML→markdown converters in this space (both `html2md` and
    // `htmd`) walk the DOM with one recursive call per child, so a deeply nested document
    // overflows the thread stack. A stack overflow is `SIGABRT`, NOT a catchable panic: it takes
    // the whole process down, `catch_unwind`/`JoinSet`/`timeout` cannot contain it, and it
    // crash-loops on every retry of that URL. `"<div>".repeat(10_000)` — an 88 KB response — was
    // enough to abort the agent on a default 2 MiB tokio worker stack.
    //
    // We measure depth on the tree `scraper` already built (an arena-backed `ego_tree`, so this
    // walk is iterative and cannot itself overflow) and degrade to plain text past the cap. Real
    // content does not nest anywhere near this deep; hostile markup does.
    if let Some(depth) = html_exceeds_depth(&inner_html, MAX_MARKDOWN_DOM_DEPTH) {
        tracing::warn!(
            depth_cap = MAX_MARKDOWN_DOM_DEPTH,
            observed_depth = depth,
            url = %base_url,
            "markdown conversion skipped: DOM nesting exceeds the depth cap; degrading to plain text"
        );
        return normalize_ws(&main_container_text(doc));
    }

    let md = normalize_markdown(&html_to_markdown(&inner_html), base_url);
    let body = if !md.is_empty() {
        md
    } else {
        // Degrade: collapse the container's text to a single normalized block.
        normalize_ws(&main_container_text(doc))
    };
    append_form_fields(doc, body)
}

/// A body under this many words is a candidate for field recovery.
const STARVED_BODY_MAX_WORDS: usize = 120;
/// ...but only when the page itself carries at least this much visible text, so a
/// genuinely short page is never scanned for nothing.
const STARVED_PAGE_MIN_WORDS: usize = 400;
/// One field value is a label, not a document: a <select> can carry thousands of
/// characters of options, and a textarea an entire article.
const FIELD_VALUE_MAX: usize = 300;

/// Append `label: value` lines for the page's form fields when the extracted body is
/// starved.
///
/// ON A SIGNED-IN PAGE THE FORM IS THE CONTENT. An account screen, a dashboard, a
/// settings panel — the email, the display name, the plan — none of it is text: an
/// `<input>`'s value is an ATTRIBUTE, so a readability/markdown pass drops it and the
/// page comes back as a list of empty headings even when the crawl is correctly
/// signed in. Measured on a real profile page (cloud edition, same defect): 591
/// visible words, of which the article extractor kept 53.
///
/// Only fires when the body is tiny in ABSOLUTE terms while the page clearly has text
/// — that combination means "no article found", not "short page" — so an ordinary
/// article is never touched. Password-ish fields are skipped entirely (never their
/// value, never their presence) and every value is length-capped.
fn append_form_fields(doc: &Html, body: String) -> String {
    if body.split_whitespace().count() >= STARVED_BODY_MAX_WORDS {
        return body;
    }
    if main_container_text(doc).split_whitespace().count() < STARVED_PAGE_MIN_WORDS {
        return body;
    }
    let fields = form_fields_markdown(doc);
    if fields.is_empty() {
        return body;
    }
    if body.is_empty() {
        fields
    } else {
        format!("{body}\n\n{fields}")
    }
}

/// True for a field name/type that must never be emitted — a password box may be
/// prefilled by a manager, and a crawl row is stored and exported like any other
/// content.
fn is_secret_field(name: &str, ty: &str) -> bool {
    if ty.eq_ignore_ascii_case("password") {
        return true;
    }
    let n = name.to_ascii_lowercase();
    [
        "pass", "pwd", "secret", "token", "csrf", "apikey", "api_key", "api-key", "cvv",
        "card", "otp", "code",
    ]
    .iter()
    .any(|h| n.contains(h))
}

/// `label: value` lines for every visible, non-secret form field. Empty when there is
/// nothing worth showing.
fn form_fields_markdown(doc: &Html) -> String {
    let sel = match Selector::parse("input, textarea, select") {
        Ok(s) => s,
        Err(_) => return String::new(),
    };
    let mut lines: Vec<String> = Vec::new();
    for el in doc.select(&sel) {
        let v = el.value();
        let ty = v.attr("type").unwrap_or("");
        if matches!(
            ty.to_ascii_lowercase().as_str(),
            "hidden" | "submit" | "button" | "image" | "reset"
        ) {
            continue;
        }
        let name = v.attr("name").or_else(|| v.attr("id")).unwrap_or("");
        if is_secret_field(name, ty) {
            continue;
        }
        // Prefer a real label; fall back to aria-label/placeholder/name.
        let label = el
            .value()
            .attr("aria-label")
            .or_else(|| v.attr("placeholder"))
            .unwrap_or(name)
            .trim()
            .to_string();
        if label.is_empty() {
            continue;
        }
        let value = match v.name() {
            "select" => el
                .select(&Selector::parse("option[selected]").unwrap_or_else(|_| {
                    Selector::parse("option").expect("option selector is valid")
                }))
                .next()
                .map(|o| o.text().collect::<String>())
                .unwrap_or_default(),
            "textarea" => el.text().collect::<String>(),
            _ if matches!(ty.to_ascii_lowercase().as_str(), "checkbox" | "radio") => {
                if v.attr("checked").is_some() { "yes".into() } else { "no".into() }
            }
            _ => v.attr("value").unwrap_or("").to_string(),
        };
        let mut value = normalize_ws(&value);
        if value.is_empty() {
            continue;
        }
        if value.chars().count() > FIELD_VALUE_MAX {
            value = value.chars().take(FIELD_VALUE_MAX).collect::<String>().trim_end().to_string();
            value.push('…');
        }
        let line = format!("- {label}: {value}");
        if !lines.contains(&line) {
            lines.push(line);
        }
    }
    if lines.is_empty() {
        String::new()
    } else {
        format!("## Form fields\n\n{}", lines.join("\n"))
    }
}

/// Maximum element nesting depth we will hand to the markdown converter. Chosen well above any
/// real-world document (deeply nested wrappers in the wild top out around 60–80) and far below the
/// ~7 500 that overflows a 2 MiB stack, so the guard never fires on legitimate content.
const MAX_MARKDOWN_DOM_DEPTH: usize = 512;

/// Convert HTML to markdown. Isolated in one place so the converter choice is swappable and so the
/// depth gate above is the single entry point that protects it.
fn html_to_markdown(html: &str) -> String {
    // `htmd` returns Err only for malformed-input edge cases; an empty string then makes
    // `to_markdown` fall through to its plain-text degrade path rather than losing the page.
    htmd::convert(html).unwrap_or_default()
}

/// If `html` nests elements deeper than `cap`, return the depth at which the cap was exceeded.
/// Iterative (explicit stack) so this check can never be the thing that overflows.
fn html_exceeds_depth(html: &str, cap: usize) -> Option<usize> {
    let frag = Html::parse_fragment(html);
    // (node, depth) — an explicit stack, never recursion. `NodeRef` is `Copy`, and the type is
    // inferred so this needs no direct `ego_tree` dependency (it is `scraper`'s tree).
    let mut stack = vec![(frag.tree.root(), 0usize)];
    while let Some((node, depth)) = stack.pop() {
        if depth > cap {
            return Some(depth);
        }
        for child in node.children() {
            // Only element nodes contribute to converter recursion depth.
            if child.value().is_element() {
                stack.push((child, depth + 1));
            }
        }
    }
    None
}

/// Outer HTML of the best main-content container (see `pick_container`), else the whole document.
fn main_container_html(doc: &Html) -> String {
    match pick_container(doc) {
        Some(el) => el.html(),
        None => doc.root_element().html(),
    }
}

/// Subtree metrics for one node, computed once for the whole document by [`subtree_stats`].
#[derive(Debug, Default, Clone, Copy)]
struct SubtreeStats {
    /// Total byte length of every `Text` descendant — identical to what
    /// `ElementRef::text().map(str::len).sum()` returns, without re-walking per candidate.
    text_len: usize,
    /// `<a>` elements strictly BELOW this node (matching `el.select(&A_SEL)`, which is descendants-only).
    anchors: usize,
    /// Whether any strict descendant is a [`BLOCKISH_TAGS`] element (matching `el.select(&BLOCKISH_SEL)`).
    has_block_descendant: bool,
}

/// Compute `SubtreeStats` for every node in ONE bottom-up pass — the O(n) replacement for
/// re-walking each candidate's subtree.
///
/// Written as a local closure so the returned map's key type (`scraper`'s tree node id) is INFERRED:
/// naming it would require a direct `ego_tree` dependency this crate deliberately does not have (same
/// reason `html_exceeds_depth` relies on inference).
///
/// Both traversals are ITERATIVE (explicit stack): a pathologically nested document must not be able
/// to overflow the thread stack here, since a stack overflow is a `SIGABRT` no `catch_unwind` can
/// contain — the exact hazard the markdown depth gate exists for. A reverse pre-order visit suffices:
/// pre-order emits every parent before its children, so walking it backwards visits every child
/// before its parent.
macro_rules! subtree_stats {
    ($doc:expr) => {{
        let doc: &Html = $doc;
        let mut order = Vec::new();
        let mut stack = vec![doc.tree.root()];
        while let Some(n) = stack.pop() {
            order.push(n);
            for c in n.children() {
                stack.push(c);
            }
        }
        let mut stats = std::collections::HashMap::with_capacity(order.len());
        for n in order.iter().rev() {
            let mut s = SubtreeStats {
                text_len: n.value().as_text().map_or(0, |t| t.text.len()),
                ..SubtreeStats::default()
            };
            for c in n.children() {
                let cs: SubtreeStats = stats.get(&c.id()).copied().unwrap_or_default();
                s.text_len += cs.text_len;
                s.anchors += cs.anchors;
                s.has_block_descendant |= cs.has_block_descendant;
                if let Some(el) = c.value().as_element() {
                    if el.name() == "a" {
                        s.anchors += 1;
                    }
                    if BLOCKISH_TAGS.contains(&el.name()) {
                        s.has_block_descendant = true;
                    }
                }
            }
            stats.insert(n.id(), s);
        }
        stats
    }};
}

/// Prune site chrome from the DOM in place: structural chrome tags, ARIA landmark regions,
/// `aria-hidden` nodes, and class/id-flagged boilerplate — while protecting the bulk-text block so
/// a content wrapper whose class merely matches a junk pattern survives. Mirrors the Python agent's
/// `_strip_chrome`. Node IDs are gathered under an immutable borrow, then detached.
fn strip_chrome(doc: &mut Html) {
    // ONE bottom-up pass computes every subtree metric the passes below need. WHY: this function used
    // to RE-WALK each candidate's entire subtree — `e.text().map(str::len).sum()` per junk-classed
    // element, then a `select(BLOCKISH)` + `text()` + `select(A)` triple-walk per nav candidate —
    // which is quadratic in (candidate x text-node) count. Measured: a 2.1 MB page took 4.18 s and
    // ~21 MB took ~40 s, all of it synchronous on a tokio worker that also serves the daemon's HTTP
    // API. The precompute is linear in node count; see [`subtree_stats`].
    let stats = subtree_stats!(&*doc);
    let total = stats
        .get(&doc.root_element().id())
        .map_or(0, |s| s.text_len)
        .max(1) as f64;
    let mut remove = Vec::new();
    for node in doc.tree.nodes() {
        let Some(el) = node.value().as_element() else { continue };
        let mut junk = CHROME_TAGS.contains(&el.name())
            || el
                .attr("role")
                .is_some_and(|r| ROLE_JUNK.contains(&r.trim().to_ascii_lowercase().as_str()))
            || el.attr("aria-hidden") == Some("true");
        if !junk {
            let class = el.attr("class").unwrap_or("");
            let id = el.attr("id").unwrap_or("");
            if (!class.is_empty() || !id.is_empty())
                && ATTR_JUNK_RE.is_match(&format!("{class} {id}"))
            {
                let tlen = stats.get(&node.id()).map_or(0, |s| s.text_len);
                junk = (tlen as f64) < JUNK_TEXT_SHARE * total;
            }
        }
        // Spacer / vote-arrow / tracking images (mirrors the Python agent) — they convert to noisy
        // `![](s.gif)` markdown otherwise. Folded into this same walk (it was a second full pass, and
        // detaching an image inside an already-detached subtree is a no-op either way).
        if !junk && el.name() == "img" {
            let src = el.attr("src").unwrap_or("").to_ascii_lowercase();
            let w = el.attr("width").unwrap_or("");
            let h = el.attr("height").unwrap_or("");
            junk = SPACER_IMG_RE.is_match(&src) || matches!(w, "0" | "1") || matches!(h, "0" | "1");
        }
        if junk {
            remove.push(node.id());
        }
    }
    for id in remove {
        if let Some(mut n) = doc.tree.get_mut(id) {
            n.detach();
        }
    }

    // Link-list boilerplate (nav bars, footers, breadcrumbs, pagination, action rows) — the
    // site-agnostic pass. A LEAF-ish block with >= NAV_MIN_LINKS links whose text, after removing the
    // link text + separators, has <= NAV_RESIDUE_MAX alnum chars is a list of links, i.e. chrome.
    // Titles (1-2 links) and metadata that mixes links with words ("4 points by X") are kept, as is
    // any prose block (>= CONTENT_MIN_WORDS).
    //
    // Stats are RECOMPUTED here rather than reused: this pass judges each block by what is LEFT after
    // the chrome prune above (a `<div>` wrapping a now-detached `<nav>` must be scored without that
    // nav's anchors), which is exactly what the old per-candidate live walks did.
    let stats = subtree_stats!(&*doc);
    let mut nav_remove = Vec::new();
    for node in doc.tree.nodes() {
        let Some(el) = ElementRef::wrap(node) else { continue };
        if !matches!(
            el.value().name(),
            "li" | "td" | "tr" | "div" | "p" | "span" | "ul" | "ol" | "nav" | "section" | "header" | "footer"
        ) {
            continue;
        }
        // Absent from `stats` ⇒ already detached above; re-detaching it would be a no-op, so skip.
        let Some(st) = stats.get(&node.id()) else { continue };
        if st.has_block_descendant {
            continue; // container — judge its leaves, not the whole subtree
        }
        // Cheap precomputed gates FIRST, so the string work below only ever runs on the handful of
        // genuinely link-dense leaf blocks rather than on every element in the document.
        if st.anchors < NAV_MIN_LINKS {
            continue; // a single link is a title/reference, not a nav list
        }
        let text = el.text().collect::<String>();
        let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if text.is_empty() || text.split_whitespace().count() >= CONTENT_MIN_WORDS {
            continue;
        }
        let anchors: Vec<_> = el.select(&A_SEL).collect();
        let mut non_link = text.clone();
        for a in &anchors {
            let at = a.text().collect::<String>();
            let at = at.split_whitespace().collect::<Vec<_>>().join(" ");
            if !at.is_empty() {
                if let Some(pos) = non_link.find(&at) {
                    non_link.replace_range(pos..pos + at.len(), " ");
                }
            }
        }
        let residue = non_link.chars().filter(|c| c.is_alphanumeric()).count();
        if residue <= NAV_RESIDUE_MAX {
            nav_remove.push(node.id());
        }
    }
    for id in nav_remove {
        if let Some(mut n) = doc.tree.get_mut(id) {
            n.detach();
        }
    }
}

/// Flatten LAYOUT tables at the string level before html2md (scraper can't cheaply rename nodes):
/// html2md renders every `<table>` as a `| | --- |` grid that buries text. When the content has NO
/// `<th>` data-header cell (i.e. only layout tables, e.g. HN), rewrite the table structural tags to
/// `<div>` so cells become flow blocks. A page with real data tables (has `<th>`) is left untouched.
fn flatten_layout_tables(html: &str) -> String {
    if html.contains("<th>") || html.contains("<th ") {
        return html.to_string(); // data-table headers present — keep tables intact
    }
    let mut s = html.to_string();
    for tag in ["table", "thead", "tbody", "tfoot", "tr", "td", "caption"] {
        s = s.replace(&format!("<{tag}"), "<div").replace(&format!("</{tag}>"), "</div>");
    }
    s
}

/// Render a value as a safely double-quoted, single-line YAML scalar.
fn yaml_scalar(value: &str) -> String {
    let flat = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let esc = flat.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{esc}\"")
}

/// YAML frontmatter header. Only non-empty fields are emitted; `url` + `crawled_at` always.
fn render_frontmatter(title: &str, meta: &PageMeta, base_url: &str, fetched_at: &str) -> String {
    let mut fm = String::from("---\n");
    if !title.is_empty() {
        fm.push_str(&format!("title: {}\n", yaml_scalar(title)));
    }
    fm.push_str(&format!("url: {}\n", yaml_scalar(base_url)));
    if !meta.description.is_empty() {
        fm.push_str(&format!("description: {}\n", yaml_scalar(&meta.description)));
    }
    if !meta.author.is_empty() {
        fm.push_str(&format!("author: {}\n", yaml_scalar(&meta.author)));
    }
    if !meta.date.is_empty() {
        fm.push_str(&format!("published: {}\n", yaml_scalar(&meta.date)));
    }
    if !meta.sitename.is_empty() {
        fm.push_str(&format!("site: {}\n", yaml_scalar(&meta.sitename)));
    }
    fm.push_str(&format!("crawled_at: {}\n", yaml_scalar(fetched_at)));
    fm.push_str("---");
    fm
}

/// Tidy converter output: setext→ATX h1, absolute links, drop data-URI/empty images, strip odd
/// whitespace, trim trailing spaces, collapse >2 blank lines, and drop duplicated content blocks.
fn normalize_markdown(md: &str, base_url: &str) -> String {
    // Strip invisible/odd whitespace: nbsp → space, zero-width space + BOM → dropped.
    let mut s: String = md
        .chars()
        .filter_map(|c| match c {
            '\u{00a0}' => Some(' '),
            '\u{200b}' | '\u{feff}' => None,
            _ => Some(c),
        })
        .collect();
    s = SETEXT_H1_RE.replace_all(&s, "# $1").into_owned();
    // html2md leaks raw HTML for some tags — convert raw <img> to markdown (dropping data-URIs),
    // turn <br> into a newline, then strip the remaining pass-through inline tags.
    s = BR_RE.replace_all(&s, "\n").into_owned();
    s = RAW_IMG_RE.replace_all(&s, |c: &regex::Captures| raw_img_to_md(&c[0])).into_owned();
    s = STRAY_TAG_RE.replace_all(&s, "").into_owned();
    // Fragment-only links (`[label](#cite1)`) are dead weight in a scraped corpus: the fragment
    // target is not part of the extract, so the link can never resolve. Collapse them to their
    // label text, and unescape the `\[`/`\]` the converter adds when a label contains literal
    // brackets — so a Wikipedia-style citation reads `[1]` rather than `[\[1\]](#cite1)`.
    s = FRAGMENT_LINK_RE
        .replace_all(&s, |c: &regex::Captures| unescape_md_brackets(&c[1]))
        .into_owned();
    s = absolutize_links(&s, base_url);
    s = DATA_IMG_RE.replace_all(&s, "").into_owned();
    s = EMPTY_IMG_RE.replace_all(&s, "").into_owned();
    s = s.lines().map(str::trim_end).collect::<Vec<_>>().join("\n");
    s = MULTINL_RE.replace_all(&s, "\n\n").into_owned();
    s = dedupe_blocks(&s);
    s.trim().to_string()
}

/// Unescape backslash-escaped markdown brackets, so a citation label reads `[1]` not `\[1\]`.
fn unescape_md_brackets(s: &str) -> String {
    ESCAPED_BRACKET_RE.replace_all(s, "$1").into_owned()
}

/// Convert one raw `<img …>` HTML tag (a converter's output when the image carries width/height/align)
/// into markdown `![alt](src)`. Returns "" for data-URI or src-less images so base64 bloat is
/// dropped rather than embedded verbatim.
fn raw_img_to_md(tag: &str) -> String {
    let cap = |re: &Regex| -> String {
        re.captures(tag)
            .and_then(|c| c.get(1).or_else(|| c.get(2)))
            .map(|m| m.as_str().trim().to_string())
            .unwrap_or_default()
    };
    let src = cap(&IMG_SRC_RE);
    // No src → likely a literal `<img>` shown as example/code text, not a rendered image; leave it
    // untouched rather than emitting empty markdown. A data-URI src is base64 bloat → drop it.
    if src.is_empty() {
        return tag.to_string();
    }
    if src.to_ascii_lowercase().starts_with("data:") {
        return String::new();
    }
    format!("![{}]({})", cap(&IMG_ALT_RE), src)
}

/// Resolve relative markdown link/image targets against `base_url`. Leaves absolute, protocol-
/// relative, anchor, and scheme (`mailto:`/`tel:`/`data:`) targets untouched.
fn absolutize_links(md: &str, base_url: &str) -> String {
    let base = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return md.to_string(),
    };
    LINK_RE
        .replace_all(md, |caps: &regex::Captures| {
            let prefix = &caps[1];
            let target = caps[2].trim();
            let low = target.to_ascii_lowercase();
            let keep = target.starts_with('#')
                || target.starts_with("//")
                || low.starts_with("http://")
                || low.starts_with("https://")
                || low.starts_with("mailto:")
                || low.starts_with("tel:")
                || low.starts_with("data:");
            let resolved = if keep {
                target.to_string()
            } else {
                base.join(target).map(|u| u.to_string()).unwrap_or_else(|_| target.to_string())
            };
            format!("{prefix}{resolved}")
        })
        .into_owned()
}

/// Remove exact-duplicate substantial blocks (order-preserving, first wins). Some pages emit the
/// main content twice (e.g. `<main>` mirroring an `<article>`); short single-line blocks (headings,
/// labels) are never deduped so a legitimately repeated one-liner survives.
fn dedupe_blocks(md: &str) -> String {
    let blocks: Vec<&str> = BLOCK_SPLIT_RE.split(md).collect();
    if blocks.len() < 2 {
        return md.to_string();
    }
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<&str> = Vec::new();
    for b in blocks {
        let key = b.split_whitespace().collect::<Vec<_>>().join(" ");
        let multiline = b.trim().contains('\n');
        let substantial =
            key.len() >= DEDUPE_MIN_LEN || (multiline && key.len() >= DEDUPE_MULTILINE_MIN_LEN);
        if substantial {
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);
        }
        out.push(b);
    }
    out.join("\n\n")
}

/// Ceiling on schema rows extracted from ONE page. Matches the spirit of the 2 000-link cap: a single
/// page can never be allowed to mint an unbounded number of records, because they are all retained
/// until the shard completes and then serialized onto the wire.
const MAX_SCHEMA_ROWS: usize = 2_000;

/// Replay a prebuilt CSS extractor across a page: `schema = {row_selector, fields:[{name, selector?,
/// attr?}]}`. One row per `row_selector` match; each field reads text (or an attribute) from the
/// row's sub-selector (or the row element itself when `selector` is omitted). Always includes the
/// crawl provenance columns (`url`/`depth`/`fetched_at`) so schema rows join the same dataset.
fn extract_schema(doc: &Html, schema: &Value, base_url: &str, depth: i64, fetched_at: &str) -> Vec<Value> {
    let Some(row_sel_str) = schema.get("row_selector").and_then(|v| v.as_str()) else {
        return Vec::new();
    };
    let Ok(row_sel) = Selector::parse(row_sel_str) else {
        return Vec::new();
    };
    let fields = schema.get("fields").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let mut rows = Vec::new();
    for row_el in doc.select(&row_sel) {
        // ROW CAP — one page must not be able to flood the shard payload. A hostile (or merely
        // generated) page can match a `row_selector` a hundred thousand times, and every row is held
        // in memory until the shard completes and is then serialized onto the wire. Mirrors the
        // 2 000-link harvest cap in `extract_links`.
        if rows.len() >= MAX_SCHEMA_ROWS {
            tracing::warn!(
                cap = MAX_SCHEMA_ROWS,
                url = %base_url,
                "schema extraction hit the per-page row cap; remaining matches dropped"
            );
            break;
        }
        let mut obj = serde_json::Map::new();
        obj.insert("url".into(), json!(base_url));
        obj.insert("depth".into(), json!(depth));
        obj.insert("fetched_at".into(), json!(fetched_at));
        for f in &fields {
            let Some(name) = f.get("name").and_then(|v| v.as_str()) else { continue };
            let sub = f.get("selector").and_then(|v| v.as_str());
            let attr = f.get("attr").and_then(|v| v.as_str());
            let value: Option<String> = match sub {
                Some(css) => Selector::parse(css).ok().and_then(|s| {
                    row_el.select(&s).next().map(|e| field_value(&e, attr))
                }),
                None => Some(field_value(&row_el, attr)),
            };
            obj.insert(name.to_string(), json!(value.unwrap_or_default().trim()));
        }
        rows.push(Value::Object(obj));
    }
    rows
}

/// Read a field value: an attribute when `attr` is set (resolving `href`/`src` against nothing — the
/// caller already has absolute base context via the row `url`), else the element's normalized text.
fn field_value(el: &scraper::ElementRef, attr: Option<&str>) -> String {
    match attr {
        Some(a) => el.value().attr(a).unwrap_or_default().trim().to_string(),
        None => normalize_ws(&el.text().collect::<String>()),
    }
}

/// Collapse all whitespace runs to a single space and trim.
fn normalize_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_mode_yields_one_row_with_provenance() {
        let html = r#"<html><head><title>Hello</title></head>
            <body><nav>menu junk</nav>
            <main><h1>Big Heading</h1><p>Some <b>bold</b> content here.</p>
            <a href="/next">next</a><a href="https://other.test/x">ext</a></main></body></html>"#;
        let ex = extract(html, "https://ex.test/page", 1, "2026-07-13T00:00:00Z", "markdown", None, None);
        assert_eq!(ex.title, "Hello");
        assert_eq!(ex.rows.len(), 1);
        let row = &ex.rows[0];
        assert_eq!(row["url"], json!("https://ex.test/page"));
        assert_eq!(row["depth"], json!(1));
        assert_eq!(row["fetched_at"], json!("2026-07-13T00:00:00Z"));
        let md = row["markdown"].as_str().unwrap();
        assert!(md.starts_with("---\n"), "frontmatter missing: {md}");
        assert!(md.contains("Big Heading"), "markdown: {md}");
        assert!(!md.to_lowercase().contains("menu junk"), "nav leaked: {md}");
        assert!(row["word_count"].as_i64().unwrap() > 0);
        // Links resolved to absolute, both same- and cross-origin harvested (scope is the orchestrator's job).
        let urls: Vec<&str> = ex.links.iter().map(|l| l.url.as_str()).collect();
        assert!(urls.contains(&"https://ex.test/next"), "links: {urls:?}");
        assert!(urls.contains(&"https://other.test/x"));
        assert!(ex.text_len > 0);
    }

    #[test]
    fn links_skip_fragments_mailto_and_dedupe() {
        let html = r##"<a href="#top">t</a><a href="mailto:a@b.c">m</a>
            <a href="/p">p</a><a href="/p">dup</a><a href="javascript:void(0)">j</a>"##;
        let ex = extract(html, "https://ex.test/", 0, "t", "markdown", None, None);
        // First-seen wins for the anchor text of a deduped link.
        assert_eq!(ex.links, vec![PageLink { url: "https://ex.test/p".into(), text: "p".into() }]);
    }

    #[test]
    fn links_carry_anchor_text_for_frontier_ranking() {
        let html = r##"<a href="/plans">  Pricing &amp;
            Plans </a><a href="/p/48213"><span>Enterprise</span> tier</a>"##;
        let ex = extract(html, "https://ex.test/", 0, "t", "markdown", None, None);
        let by_url: std::collections::HashMap<&str, &str> =
            ex.links.iter().map(|l| (l.url.as_str(), l.text.as_str())).collect();
        // Whitespace (including newlines) is collapsed to single spaces.
        assert_eq!(by_url["https://ex.test/plans"], "Pricing & Plans");
        // Nested markup contributes its text — this is what makes an opaque URL rankable.
        assert_eq!(by_url["https://ex.test/p/48213"], "Enterprise tier");
    }

    #[test]
    fn frame_srcs_join_the_frontier() {
        // A document shown only through an <iframe>/<frame> must still enter
        // the frontier as its own page; its title/name rides as link text.
        let html = r##"<html>
            <frameset rows="50%,50%">
              <frame src="/frame_top" name="top-frame">
              <frame src="https://sub.ex.test/frame_bottom">
              <noframes>Frames are not rendering.</noframes>
            </frameset></html>"##;
        let ex = extract(html, "https://ex.test/nested", 0, "t", "markdown", None, None);
        let by_url: std::collections::HashMap<&str, &str> =
            ex.links.iter().map(|l| (l.url.as_str(), l.text.as_str())).collect();
        assert_eq!(by_url["https://ex.test/frame_top"], "top-frame");
        assert!(by_url.contains_key("https://sub.ex.test/frame_bottom"));

        let html = r##"<body><a href="/about">About</a>
            <iframe src="/embed/report" title="Quarterly report"></iframe>
            <iframe src="https://third.party.test/widget"></iframe>
            <iframe src="javascript:void(0)"></iframe>
            <iframe src="about:blank"></iframe></body>"##;
        let ex = extract(html, "https://ex.test/page", 0, "t", "markdown", None, None);
        let by_url: std::collections::HashMap<&str, &str> =
            ex.links.iter().map(|l| (l.url.as_str(), l.text.as_str())).collect();
        assert_eq!(by_url["https://ex.test/embed/report"], "Quarterly report");
        // Cross-origin embeds are still harvested — coordinator scope decides.
        assert!(by_url.contains_key("https://third.party.test/widget"));
        assert!(!by_url.keys().any(|u| u.starts_with("javascript:") || u.starts_with("about:")));
    }

    #[test]
    fn flattened_frame_sections_reach_the_markdown() {
        // The browser lane replaces frame elements with
        // <section data-writ-frame-src> blocks (crawl_shard::frames); the
        // section content must survive chrome pruning while the leftover
        // un-inlined iframe carcass is dropped.
        let html = r#"<html><head><title>Wrap</title></head><body>
            <section data-writ-frame-src="https://ex.test/frame_middle">
              <h2>Middle pane</h2><p>Framed content the crawler used to lose entirely.</p>
              <a href="/from-frame">deeper</a>
            </section>
            <iframe src="https://third.party.test/ad"></iframe>
        </body></html>"#;
        let ex = extract(html, "https://ex.test/nested", 0, "t", "markdown", None, None);
        let md = ex.rows[0]["markdown"].as_str().unwrap();
        assert!(md.contains("Middle pane"), "flattened frame content lost: {md}");
        assert!(md.contains("Framed content the crawler used to lose"), "markdown: {md}");
        // Links inside flattened frames are harvested (already absolutized here).
        let urls: Vec<&str> = ex.links.iter().map(|l| l.url.as_str()).collect();
        assert!(urls.contains(&"https://ex.test/from-frame"), "links: {urls:?}");
    }

    #[test]
    fn anchor_text_is_clipped_on_a_char_boundary() {
        // Multi-byte glyphs must not be split when the text exceeds ANCHOR_TEXT_MAX.
        let long = "é".repeat(ANCHOR_TEXT_MAX + 40);
        let html = format!(r#"<a href="/x">{long}</a>"#);
        let ex = extract(&html, "https://ex.test/", 0, "t", "markdown", None, None);
        assert_eq!(ex.links[0].text.chars().count(), ANCHOR_TEXT_MAX);
    }

    #[test]
    fn favicon_prefers_declared_icon_then_falls_back() {
        let declared = extract(
            r#"<link rel="shortcut icon" href="/assets/fav.png">"#,
            "https://ex.test/page", 0, "t", "markdown", None, None);
        assert_eq!(declared.favicon.as_deref(), Some("https://ex.test/assets/fav.png"));

        // No <link rel=icon> → the conventional /favicon.ico on the page's origin.
        let bare = extract("<p>hi</p>", "https://ex.test/deep/page", 0, "t", "markdown", None, None);
        assert_eq!(bare.favicon.as_deref(), Some("https://ex.test/favicon.ico"));

        // A data: icon is not a loadable URL — skip it and fall back.
        let inline = extract(
            r#"<link rel="icon" href="data:image/png;base64,AAAA">"#,
            "https://ex.test/", 0, "t", "markdown", None, None);
        assert_eq!(inline.favicon.as_deref(), Some("https://ex.test/favicon.ico"));
    }

    #[test]
    fn schema_mode_replays_row_selector() {
        let html = r#"<ul>
            <li class="item"><span class="n">Apple</span><a class="l" href="/a">link</a></li>
            <li class="item"><span class="n">Pear</span><a class="l" href="/b">link</a></li>
        </ul>"#;
        let schema = json!({
            "row_selector": "li.item",
            "fields": [
                {"name": "name", "selector": ".n"},
                {"name": "href", "selector": "a.l", "attr": "href"}
            ]
        });
        let ex = extract(html, "https://ex.test/list", 2, "T", "schema", Some(&schema), None);
        assert_eq!(ex.rows.len(), 2);
        assert_eq!(ex.rows[0]["name"], json!("Apple"));
        assert_eq!(ex.rows[0]["href"], json!("/a"));
        assert_eq!(ex.rows[0]["url"], json!("https://ex.test/list"));
        assert_eq!(ex.rows[0]["depth"], json!(2));
        assert_eq!(ex.rows[1]["name"], json!("Pear"));
    }

    #[test]
    fn title_falls_back_to_h1() {
        let html = "<body><h1>Only Heading</h1></body>";
        let ex = extract(html, "https://ex.test/", 0, "t", "markdown", None, None);
        assert_eq!(ex.title, "Only Heading");
    }

    #[test]
    fn schema_mode_without_schema_falls_back_to_markdown() {
        // A "Structured" crawl with no extractor attached must still capture the page as a
        // markdown row (never an empty dataset).
        let html = "<body><main><h1>Doc</h1><p>Body text here.</p></main></body>";
        let ex = extract(html, "https://ex.test/p", 1, "T", "schema", None, None);
        assert_eq!(ex.rows.len(), 1, "fell back to a single markdown row");
        assert!(ex.rows[0]["markdown"].as_str().unwrap().contains("Doc"));
        assert_eq!(ex.rows[0]["url"], json!("https://ex.test/p"));
    }

    #[test]
    fn schema_mode_no_match_falls_back_to_markdown() {
        // Schema present but nothing on the page matches → markdown fallback, not empty.
        let html = "<body><main><p>No products here.</p></main></body>";
        let schema = json!({ "row_selector": "li.product", "fields": [{"name": "n", "selector": ".name"}] });
        let ex = extract(html, "https://ex.test/empty", 0, "T", "schema", Some(&schema), None);
        assert_eq!(ex.rows.len(), 1);
        assert!(ex.rows[0].get("markdown").is_some(), "fallback markdown row");
    }

    // ------------------------------------------------------------------- //
    // Markdown-quality: chrome removal, frontmatter, tables, dedupe        //
    // ------------------------------------------------------------------- //

    const RICH: &str = r#"<!doctype html><html><head>
        <title>Quarterly Pricing</title>
        <meta name="description" content="Acme pricing tiers.">
        <meta name="author" content="Jane Doe">
        <meta property="og:site_name" content="Acme"></head><body>
        <div class="cookie-consent">We use cookies to track you</div>
        <header><nav><a href="/">Home</a><a href="/docs">Docs</a></nav></header>
        <aside class="sidebar related-links"><a href="/blog/1">Related Post One</a></aside>
        <main><article>
            <h1>Quarterly Pricing</h1>
            <p>Our plans scale with your team and include unlimited crawls today.</p>
            <table><thead><tr><th>Plan</th><th>Price</th></tr></thead>
                <tbody><tr><td>Starter</td><td>$0</td></tr><tr><td>Scale</td><td>$199</td></tr></tbody></table>
            <ul><li>Scheduled crawls</li><li>API access</li></ul>
        </article></main>
        <div class="newsletter-signup">Subscribe to our newsletter now</div>
        <footer>Copyright 2026 Acme all rights reserved</footer>
        <script>var track = 'pixel-junk-xyz';</script>
        </body></html>"#;

    #[test]
    fn emits_frontmatter_with_metadata() {
        let ex = extract(RICH, "https://acme.test/pricing", 1, "2026-07-13T10:00:00Z", "markdown", None, None);
        let md = ex.rows[0]["markdown"].as_str().unwrap();
        assert!(md.starts_with("---\n"));
        assert!(md.contains(r#"url: "https://acme.test/pricing""#), "{md}");
        assert!(md.contains(r#"title: "Quarterly Pricing""#));
        assert!(md.contains(r#"description: "Acme pricing tiers.""#));
        assert!(md.contains(r#"author: "Jane Doe""#));
        assert!(md.contains(r#"site: "Acme""#));
        assert!(md.contains(r#"crawled_at: "2026-07-13T10:00:00Z""#));
    }

    #[test]
    fn strips_all_chrome_end_to_end() {
        let ex = extract(RICH, "https://acme.test/pricing", 1, "T", "markdown", None, None);
        let low = ex.rows[0]["markdown"].as_str().unwrap().to_lowercase();
        for junk in ["we use cookies", "all rights reserved", "related post one", "subscribe to our newsletter", "pixel-junk-xyz", "/docs"] {
            assert!(!low.contains(junk), "chrome leaked: {junk:?}\n{low}");
        }
        assert!(low.contains("quarterly pricing"));
    }

    #[test]
    fn keeps_table_headings_and_h1_atx() {
        let ex = extract(RICH, "https://acme.test/pricing", 1, "T", "markdown", None, None);
        let md = ex.rows[0]["markdown"].as_str().unwrap();
        assert!(md.contains("# Quarterly Pricing"), "h1 not ATX: {md}");
        // GFM-ish table: pipes + the data cells survive.
        assert!(md.contains("Plan") && md.contains("Price") && md.contains("Starter") && md.contains("$199"));
        assert!(md.matches('|').count() >= 4, "table pipes missing: {md}");
        assert!(md.contains("Scheduled crawls") && md.contains("API access"));
    }

    #[test]
    fn strip_chrome_protects_bulk_text_block() {
        // A content wrapper whose class matches a junk pattern ("share") must survive when it holds
        // the bulk of the text; a small sibling junk block is removed.
        let body = "real body content ".repeat(30);
        let html = format!(
            "<html><body><div class=\"share-page\"><h1>Title</h1><p>{body}</p></div>\
             <div class=\"share-buttons\">tweet facebook</div></body></html>"
        );
        let ex = extract(&html, "https://x.test/p", 0, "T", "markdown", None, None);
        let low = ex.rows[0]["markdown"].as_str().unwrap().to_lowercase();
        assert!(low.contains("real body content"), "bulk block dropped: {low}");
        assert!(!low.contains("tweet facebook"), "junk block leaked: {low}");
    }

    #[test]
    fn absolutizes_relative_links() {
        let html = r#"<body><main><p>see <a href="/docs/x">docs</a> and <a href="https://ext.test/y">ext</a></p></main></body>"#;
        let ex = extract(html, "https://acme.test/pricing", 0, "T", "markdown", None, None);
        let md = ex.rows[0]["markdown"].as_str().unwrap();
        assert!(md.contains("https://acme.test/docs/x"), "relative not absolutized: {md}");
        assert!(md.contains("https://ext.test/y"), "absolute mangled: {md}");
    }

    #[test]
    fn dedupe_drops_repeated_substantial_blocks() {
        let para = "This paragraph is definitely longer than the dedupe threshold value here.";
        let md = format!("# Heading\n\n{para}\n\n## Section\n\n{para}");
        let out = dedupe_blocks(&md);
        assert_eq!(out.matches(para).count(), 1, "duplicate not removed: {out}");
        assert!(out.contains("# Heading") && out.contains("## Section"));
    }

    #[test]
    fn dedupe_keeps_short_repeated_one_liners() {
        let md = "Learn more\n\nSome longer body paragraph that exceeds the threshold.\n\nLearn more";
        let out = dedupe_blocks(md);
        assert_eq!(out.matches("Learn more").count(), 2, "short label wrongly deduped: {out}");
    }

    // A discussion page: article + a comment thread + a sidebar/ads region.
    const DISCUSSION: &str = "<html><head><title>Cool Story</title></head><body>\
        <header><nav><a href=\"/\">Home</a></nav></header>\
        <aside class=\"sidebar ads\"><p>Sponsored buy this</p></aside>\
        <main><article><h1>Cool Story</h1><p>The main article body explains the thing.</p></article></main>\
        <section class=\"comments\"><div class=\"comment\">First insightful comment here.</div>\
        <div class=\"comment\">Second comment with a different take.</div></section></body></html>";

    #[test]
    fn content_full_preset_keeps_comments() {
        // preset "full" = whole (chrome-pruned) body → the comment thread survives.
        let spec = json!({"preset": "full"});
        let ex = extract(DISCUSSION, "https://x.test/item", 0, "T", "markdown", None, Some(&spec));
        let md = ex.rows[0]["markdown"].as_str().unwrap().to_lowercase();
        assert!(md.contains("first insightful comment"), "comments dropped in full: {md}");
        assert!(!md.contains("sponsored"), "chrome/ads leaked: {md}");
    }

    #[test]
    fn content_exclude_selectors_removes_region() {
        let spec = json!({"preset": "full", "exclude_selectors": [".comments"]});
        let ex = extract(DISCUSSION, "https://x.test/item", 0, "T", "markdown", None, Some(&spec));
        let md = ex.rows[0]["markdown"].as_str().unwrap().to_lowercase();
        assert!(!md.contains("first insightful comment"), "excluded region leaked: {md}");
        assert!(md.contains("main article body"), "article wrongly dropped: {md}");
    }

    #[test]
    fn layout_tables_flattened_and_nav_footer_pruned() {
        // HN-shaped: layout tables (no <th>) + nav bar (3+ links) + headline(link)+source + comment +
        // footer link-list. Expect: no `| |` grid, nav+footer gone, headline + comment kept.
        let html = "<html><body>\
            <table><tr><td><div class=\"nav\"><a href=/>Home</a> | <a href=/new>New</a> | <a href=/top>Top</a> | <a href=/login>Login</a></div></td></tr>\
            <tr><td><a href=\"https://ext.test/s\">A Real Headline Worth Reading</a> (<a href=/from>ext.test</a>)</td></tr>\
            <tr><td><img src=s.gif width=0><span>This is a genuine comment left by a reader on the thread.</span></td></tr></table>\
            <table><tr><td><div class=\"footer\"><a href=/g>Guidelines</a> | <a href=/f>FAQ</a> | <a href=/a>API</a> | <a href=/l>Legal</a></div></td></tr></table>\
            </body></html>";
        let ex = extract(html, "https://x.test/item", 0, "T", "markdown", None, Some(&json!({"preset":"full"})));
        let md = ex.rows[0]["markdown"].as_str().unwrap();
        assert!(!md.contains("| ---"), "table grid junk leaked: {md}");
        assert!(!md.contains("Home") && !md.contains("Login"), "nav leaked: {md}");
        assert!(!md.contains("Guidelines") && !md.contains("FAQ"), "footer leaked: {md}");
        assert!(md.contains("A Real Headline Worth Reading"), "headline dropped: {md}");
        assert!(md.contains("genuine comment left by a reader"), "comment dropped: {md}");
        assert!(!md.contains("s.gif"), "spacer image leaked: {md}");
    }

    #[test]
    fn content_include_selectors_scrapes_only_that_region() {
        let spec = json!({"include_selectors": [".comments"]});
        let ex = extract(DISCUSSION, "https://x.test/item", 0, "T", "markdown", None, Some(&spec));
        let md = ex.rows[0]["markdown"].as_str().unwrap().to_lowercase();
        assert!(md.contains("second comment with a different take"), "include region missing: {md}");
        assert!(!md.contains("main article body"), "non-included content leaked: {md}");
    }

    #[test]
    fn yaml_scalar_escapes_and_flattens() {
        assert_eq!(yaml_scalar("a \"b\" c"), "\"a \\\"b\\\" c\"");
        assert_eq!(yaml_scalar("x\ny"), "\"x y\"");
        assert_eq!(yaml_scalar("back\\slash"), "\"back\\\\slash\"");
    }

    #[test]
    fn hostile_title_stays_single_line() {
        let meta = PageMeta::default();
        let fm = render_frontmatter("Evil\"\n---\ninjected: true", &meta, "https://x.test/", "T");
        // The payload must stay inside the quoted title scalar — no standalone `---` line
        // (fence breakout) and no injected key line.
        assert_eq!(fm.lines().filter(|l| l.trim() == "---").count(), 2, "fence breakout: {fm}");
        assert!(!fm.lines().any(|l| l.trim_start().starts_with("injected:")));
    }

    #[test]
    fn cleans_raw_image_html_citations_and_bloat() {
        // html2md emits raw `<img>` HTML (with every attribute) for dimensioned images and raw
        // `<sup>`/`<a>` for citations. All of it must become clean markdown / plain text, and
        // data-URI bloat must be dropped — but a literal `<img>` shown as code stays untouched.
        let html = r##"<body><main>
            <p>Photo <img src="/pic.jpg" width="300" height="200" alt="A cat" srcset="/p2.jpg 2x" data-x="junk"> here now.</p>
            <p>Bloat <img src="data:image/png;base64,AAAABBBBCCCC" width="10" height="10"> is gone here.</p>
            <p>Fact<sup class="reference" data-mw="{&quot;n&quot;:1}"><a href="#cite1">[1]</a></sup> stated here.</p>
            <p>The <code>&lt;img&gt;</code> element embeds an image into a page.</p>
        </main></body>"##;
        let ex = extract(html, "https://ex.test/p", 0, "T", "markdown", None, None);
        let md = ex.rows[0]["markdown"].as_str().unwrap();
        // Real image → clean, absolutized markdown with none of the raw attributes.
        assert!(md.contains("![A cat](https://ex.test/pic.jpg)"), "img not clean md: {md}");
        assert!(!md.contains("srcset") && !md.contains("data-x") && !md.contains("width="), "raw img attrs leaked: {md}");
        // data-URI image dropped entirely (no base64 bloat).
        assert!(!md.contains("data:image"), "data uri kept: {md}");
        // Citation sup/a unwrapped to a plain marker — no raw tags or data-mw blob.
        assert!(!md.contains("<sup") && !md.contains("data-mw") && !md.to_lowercase().contains("<a "), "citation raw html: {md}");
        assert!(md.contains("[1]"), "citation marker lost: {md}");
        // A literal `<img>` shown as code text is preserved, not converted to an empty image.
        assert!(md.contains("<img>"), "code example mangled: {md}");
    }

    #[test]
    fn pathological_dom_nesting_degrades_instead_of_overflowing_the_stack() {
        // REGRESSION: HTML→markdown converters recurse once per child, so a deeply nested document
        // overflowed the thread stack — a SIGABRT that takes the whole process down and cannot be
        // caught by `catch_unwind`/`JoinSet`/`timeout`. `"<div>".repeat(10_000)` (an 88 KB response)
        // was enough. The depth gate must degrade to plain text instead, and must NOT lose the text.
        let depth = MAX_MARKDOWN_DOM_DEPTH * 20;
        let html = format!(
            "<body><main>{}the needle survives{}</main></body>",
            "<div>".repeat(depth),
            "</div>".repeat(depth)
        );
        let ex = extract(&html, "https://ex.test/deep", 0, "T", "markdown", None, None);
        let md = ex.rows[0]["markdown"].as_str().unwrap();
        assert!(md.contains("the needle survives"), "content lost on degrade: {md}");

        // And a normally-nested document still goes through the markdown converter.
        let shallow = "<body><main><h2>Heading</h2><p>Body text here.</p></main></body>";
        let ex = extract(shallow, "https://ex.test/ok", 0, "T", "markdown", None, None);
        let md = ex.rows[0]["markdown"].as_str().unwrap();
        assert!(md.contains("## Heading"), "shallow page should still convert: {md}");
    }

    #[test]
    fn depth_probe_is_iterative_and_only_counts_elements() {
        // Under the cap → None. Text nodes must not inflate the count.
        assert!(html_exceeds_depth("<div><p>hello <b>x</b></p></div>", 16).is_none());
        // Over the cap → Some(depth) rather than a stack overflow.
        let deep = format!("{}x{}", "<div>".repeat(200), "</div>".repeat(200));
        assert!(html_exceeds_depth(&deep, 8).is_some());
    }

    #[test]
    fn fragment_only_links_collapse_to_their_label() {
        // A converter turns `<a href="#cite1">[1]</a>` into `[\[1\]](#cite1)`. The fragment target
        // is never in the extract, so keep the label and drop the dead link + bracket escapes.
        let html = r##"<body><main><p>Fact<sup><a href="#cite1">[1]</a></sup> and
            <a href="#s2">Section two</a> and <a href="/real">a real link</a>.</p>
            <p>Padding text so the block is long enough to survive nav-chrome pruning heuristics.</p>
            </main></body>"##;
        let ex = extract(html, "https://ex.test/p", 0, "T", "markdown", None, None);
        let md = ex.rows[0]["markdown"].as_str().unwrap();
        assert!(md.contains("[1]"), "citation label lost: {md}");
        assert!(!md.contains("(#cite1)") && !md.contains("(#s2)"), "dead fragment link kept: {md}");
        assert!(!md.contains(r"\["), "bracket escapes leaked: {md}");
        assert!(md.contains("Section two"), "fragment link label lost: {md}");
        // A real link is untouched (and absolutized).
        assert!(md.contains("](https://ex.test/real)"), "real link damaged: {md}");
    }

    #[test]
    fn tiny_article_teaser_does_not_shadow_main_content() {
        // A small <article> teaser must not be chosen over the <main> that holds the real content.
        let long = "the real article body content goes on and on ".repeat(20);
        let html = format!(
            "<body><article>Teaser blurb.</article><main><h1>Story</h1><p>{long}</p></main></body>"
        );
        let ex = extract(&html, "https://ex.test/p", 0, "T", "markdown", None, None);
        let md = ex.rows[0]["markdown"].as_str().unwrap();
        assert!(md.contains("the real article body content"), "main content lost: {md}");
        assert!(ex.rows[0]["word_count"].as_i64().unwrap() > 50);
    }

    /// One page must not be able to mint an unbounded number of schema rows: every row is retained
    /// until the shard completes and is then serialized onto the wire.
    #[test]
    fn schema_rows_are_capped_per_page() {
        let items: String = (0..(MAX_SCHEMA_ROWS + 500))
            .map(|i| format!("<li class=\"item\"><span class=\"n\">{i}</span></li>"))
            .collect();
        let html = format!("<ul>{items}</ul>");
        let schema = json!({
            "row_selector": "li.item",
            "fields": [{"name": "name", "selector": ".n"}]
        });
        let ex = extract(&html, "https://ex.test/list", 0, "T", "schema", Some(&schema), None);
        assert_eq!(ex.rows.len(), MAX_SCHEMA_ROWS, "row cap not applied");
        // The cap keeps the FIRST matches (document order), so the page is still representative.
        assert_eq!(ex.rows[0]["name"], json!("0"));
    }

    /// The linear `subtree_stats` precompute must reproduce the old per-candidate live walks exactly.
    /// These four assertions pin the behaviours that depend on it:
    ///   * bulk-text protection uses PRE-prune subtree text length vs the whole document's,
    ///   * a link-dense LEAF block is chrome, a container is judged by its leaves,
    ///   * the nav pass sees the tree AFTER the chrome prune (a wrapper around a removed `<nav>` must
    ///     not still be scored on that nav's anchors),
    ///   * spacer images are still dropped now that pass folded into the main walk.
    #[test]
    fn chrome_pruning_metrics_match_the_live_walk_semantics() {
        // (1) bulk-text protection — a junk-CLASSED wrapper holding most of the text survives.
        let bulk = "genuine article sentence ".repeat(40);
        let html = format!(
            "<body><div class=\"promo-wrap\"><p>{bulk}</p></div>\
             <div class=\"promo-badge\">buy now today</div></body>"
        );
        let md = extract(&html, "https://x.test/p", 0, "T", "markdown", None, None).rows[0]
            ["markdown"]
            .as_str()
            .unwrap()
            .to_lowercase();
        assert!(md.contains("genuine article sentence"), "bulk block pruned: {md}");
        assert!(!md.contains("buy now today"), "small junk block kept: {md}");

        // (2) a link-dense LEAF is chrome; (3) its CONTAINER is judged by leaves, so the prose sibling
        // in the same container survives.
        let html = "<body><div><div class=\"x\"><a href=/a>One</a> <a href=/b>Two</a> \
                    <a href=/c>Three</a></div>\
                    <p>A paragraph of genuine prose that must survive the nav pruning heuristics.</p>\
                    </div></body>";
        let md = extract(html, "https://x.test/p", 0, "T", "markdown", None, Some(&json!({"preset":"full"})))
            .rows[0]["markdown"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!md.contains("One") && !md.contains("Three"), "link list kept: {md}");
        assert!(md.contains("genuine prose"), "sibling prose dropped: {md}");

        // (4) spacer images still dropped (that pass folded into the main chrome walk).
        let html = "<body><main><p>Body text that is definitely long enough to survive.\
                    <img src=\"/img/s.gif\"><img src=\"/img/tracker.png\" width=\"1\"></p></main></body>";
        let md = extract(html, "https://x.test/p", 0, "T", "markdown", None, None).rows[0]["markdown"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(!md.contains("s.gif"), "spacer image kept: {md}");
        assert!(!md.contains("tracker.png"), "1px tracker kept: {md}");
    }

    /// The pruning passes must stay LINEAR. This used to re-walk each candidate's subtree, making the
    /// cost quadratic in (candidate x text-node) count — a 2.1 MB page measured 4.18 s. A generous
    /// wall-clock bound catches a regression to quadratic without being flaky on slow CI.
    #[test]
    fn chrome_pruning_is_linear_not_quadratic() {
        // ~5 000 junk-classed leaf blocks, each with text and links: the exact shape that triggered
        // the re-walks (every one was a candidate for both the attr-junk and the nav pass).
        let block = "<div class=\"related-item\"><a href=/a>One</a><a href=/b>Two</a>\
                     <a href=/c>Three</a></div>";
        let filler = "<p>Some genuine sentence of prose content for this page.</p>";
        let html = format!("<body><main>{}{}</main></body>", block.repeat(5_000), filler.repeat(500));
        let started = std::time::Instant::now();
        let ex = extract(&html, "https://x.test/big", 0, "T", "markdown", None, None);
        let elapsed = started.elapsed();
        assert!(ex.rows[0]["markdown"].as_str().unwrap().contains("genuine sentence"));
        assert!(
            elapsed < std::time::Duration::from_secs(20),
            "chrome pruning looks quadratic again: {elapsed:?}"
        );
    }

    #[test]
    fn normalize_drops_data_uri_images() {
        let md = "Body text.\n\n![logo](data:image/png;base64,AAAABBBB)\n\n\n\n\nMore body text here.";
        let out = normalize_markdown(md, "https://x.test/");
        assert!(!out.contains("data:image"), "data uri kept: {out}");
        assert!(!out.contains("\n\n\n"), "blank lines not collapsed: {out}");
    }
}

#[cfg(test)]
mod form_field_tests {
    use super::*;

    const ACCOUNT_PAGE: &str = r#"<html><body>
      <h2>Mes informations</h2>
      <form>
        <input type="text" name="email" aria-label="Email" value="user@example.test">
        <input type="text" name="name" aria-label="Nom" value="Ben">
        <input type="checkbox" name="news" aria-label="Newsletter" checked>
        <input type="password" name="current_password" aria-label="Mot de passe" value="hunter2">
        <input type="hidden" name="_token" value="abc123">
      </form></body></html>"#;

    fn long_page(extra: &str) -> String {
        let filler = "<p>".to_string() + &"mot ".repeat(20) + "</p>";
        format!("<html><body>{}{}</body></html>", filler.repeat(40), extra)
    }

    #[test]
    fn field_values_are_recovered_because_extractors_cannot_see_them() {
        let doc = Html::parse_document(ACCOUNT_PAGE);
        let out = form_fields_markdown(&doc);
        assert!(out.contains("- Email: user@example.test"), "{out}");
        assert!(out.contains("- Nom: Ben"), "{out}");
        assert!(out.contains("- Newsletter: yes"), "{out}");
    }

    #[test]
    fn password_and_hidden_fields_are_never_emitted() {
        let doc = Html::parse_document(ACCOUNT_PAGE);
        let out = form_fields_markdown(&doc);
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("Mot de passe"));
        assert!(!out.contains("abc123"));
    }

    #[test]
    fn a_starved_body_on_a_text_rich_page_gets_the_fields_appended() {
        let doc = Html::parse_document(&long_page(
            r#"<input type="text" name="email" aria-label="Email" value="user@example.test">"#,
        ));
        let out = append_form_fields(&doc, "## A\n\n## B".into());
        assert!(out.contains("## Form fields"), "{out}");
    }

    #[test]
    fn a_normal_article_body_is_left_alone() {
        let doc = Html::parse_document(&long_page(""));
        let body = "mot ".repeat(500);
        assert_eq!(append_form_fields(&doc, body.clone()), body);
    }

    #[test]
    fn a_genuinely_short_page_is_not_scanned() {
        let doc = Html::parse_document(
            r#"<html><body><p>court</p><input name="email" aria-label="Email" value="a@b.c"></body></html>"#,
        );
        assert_eq!(append_form_fields(&doc, "## T".into()), "## T");
    }

    #[test]
    fn long_values_are_capped() {
        let big = "mot ".repeat(400);
        let doc = Html::parse_document(&long_page(&format!(
            r#"<textarea name="bio" aria-label="Bio">{big}</textarea>"#
        )));
        let out = form_fields_markdown(&doc);
        assert!(out.chars().count() < 500, "len {}", out.chars().count());
        assert!(out.trim_end().ends_with('…'), "{out}");
    }
}
