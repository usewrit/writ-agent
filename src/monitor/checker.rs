//! Tiered target checker — port of `desktop-agent/lib/checker.py` plus the
//! browser-fallback path the Python desktop-agent runs for auth/Playwright
//! targets.
//!
//! Routing (see [`Target::needs_browser`]):
//! * uptime               → HTTP DNS/TCP/TLS timing ([`check_uptime`])
//! * content, plain       → HTTP fetch + CSS extract ([`check_content_http`])
//! * content, JS/auth/pre → warm Chromium ([`check_content_browser`])

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::browser::manager::BrowserManager;
use crate::models::session::SessionState;
use super::models::{CheckOutcome, ReportItem, Selector, Target};

/// The Chrome major this agent presents as. MUST track the Chromium that the bundled Playwright
/// driver actually launches: the HTTP lane and the browser lane are two faces of ONE crawler, and a
/// site that sees `Chrome/120` over HTTP and Chrome/148 from the renderer has been handed a free
/// bot signal. `ua_matches_declared_major` pins the two together.
pub const CHROME_MAJOR: &str = "148";

/// A consistent, real-browser User-Agent. The desktop-agent picks one UA per
/// checker instance and sticks with it so content hashes don't flip from
/// UA-dependent server responses; we do the same.
pub const DEFAULT_UA: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36";

/// The request headers a real Chrome sends on a top-level navigation, minus the ones reqwest owns.
///
/// A bare `reqwest` request carries `accept: */*` and nothing else while CLAIMING to be Chrome in
/// its User-Agent. That contradiction — plus a rustls/native-tls handshake that does not look like
/// Chrome's — is what a bot-management edge scores on, and it is why an honest `curl` with NO
/// User-Agent is served a page that this lane gets a 403 for. Sending Chrome's actual header set
/// closes the cheap half of that gap.
///
/// Deliberately NOT set here:
/// * `accept-encoding` — reqwest derives it from its enabled codec features and decompresses to
///   match. Hand-writing Chrome's list would advertise br/zstd we might not be built to decode.
/// * `user-agent` — set via `ClientBuilder::user_agent` so there is one owner for it.
///
/// This does NOT change the TLS/HTTP2 fingerprint, which is the other half of the signal; see the
/// note on the crawl client builder.
pub fn browser_headers() -> reqwest::header::HeaderMap {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut h = HeaderMap::new();
    let sec_ch_ua = format!(
        "\"Not)A;Brand\";v=\"8\", \"Chromium\";v=\"{m}\", \"Google Chrome\";v=\"{m}\"",
        m = CHROME_MAJOR
    );
    // Insertion order is preserved by HeaderMap for distinct names, so this also reproduces
    // Chrome's ordering rather than an alphabetical giveaway.
    let pairs: [(HeaderName, HeaderValue); 10] = [
        (HeaderName::from_static("sec-ch-ua"),
         HeaderValue::from_str(&sec_ch_ua).unwrap_or(HeaderValue::from_static(""))),
        (HeaderName::from_static("sec-ch-ua-mobile"), HeaderValue::from_static("?0")),
        (HeaderName::from_static("sec-ch-ua-platform"), HeaderValue::from_static("\"macOS\"")),
        (HeaderName::from_static("upgrade-insecure-requests"), HeaderValue::from_static("1")),
        (HeaderName::from_static("accept"), HeaderValue::from_static(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,\
             image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")),
        (HeaderName::from_static("sec-fetch-site"), HeaderValue::from_static("none")),
        (HeaderName::from_static("sec-fetch-mode"), HeaderValue::from_static("navigate")),
        (HeaderName::from_static("sec-fetch-user"), HeaderValue::from_static("?1")),
        (HeaderName::from_static("sec-fetch-dest"), HeaderValue::from_static("document")),
        (HeaderName::from_static("accept-language"), HeaderValue::from_static("en-US,en;q=0.9")),
    ];
    for (k, v) in pairs {
        h.insert(k, v);
    }
    h
}

pub struct Checker {
    http: reqwest::Client,
    user_agent: String,
}

impl Checker {
    pub fn new(user_agent: Option<String>) -> Self {
        let ua = user_agent.unwrap_or_else(|| DEFAULT_UA.to_string());
        let http = reqwest::Client::builder()
            .user_agent(ua.clone())
            .timeout(Duration::from_secs(30))
            // reqwest's default connect timeout is None, so a black-holing target (SYN sent, nothing
            // back) would occupy the monitor lane for the FULL 30 s total budget on the handshake
            // alone. Bound the connect phase separately.
            .connect_timeout(Duration::from_secs(10))
            // SSRF: vet the address reqwest actually dials — for the INITIAL connection AND every
            // redirect hop — so a DNS rebind between the up-front guard and this fetch, or a redirect to
            // a hostname whose A-record is internal, cannot reach loopback/RFC1918/metadata. The
            // redirect policy below is a fast string/IP-literal pre-filter; this resolver is the
            // authoritative, resolve-time check that closes the rebind TOCTOU.
            .dns_resolver(crate::security::vetting_resolver::shared())
            // SSRF: re-vet every redirect hop. The fast-HTTP tier has no browser route-blocker, so a
            // public URL that 3xx-redirects to an internal/metadata target (e.g.
            // `Location: http://169.254.169.254/…`) must be stopped here rather than followed.
            // `stop()` returns the 3xx response itself, so no internal request is ever issued.
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.previous().len() >= 10 {
                    return attempt.stop(); // cap redirect chains (custom policy removes the default cap)
                }
                if crate::security::url_guard::is_redirect_target_safe(attempt.url().as_str()) {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { http, user_agent: ua }
    }

    /// Top-level dispatch for one target. Never panics; failures become error
    /// report items so the batch always carries a row per target/selector.
    pub async fn check_target(
        &self,
        target: &Target,
        browser: &Arc<BrowserManager>,
    ) -> CheckOutcome {
        if target.check_type == "uptime" {
            return self.check_uptime(target).await;
        }
        if target.needs_browser() {
            return self.check_content_browser(target, browser).await;
        }
        self.check_content_http(target).await
    }

    // ---- HTTP content -----------------------------------------------------

    async fn check_content_http(&self, target: &Target) -> CheckOutcome {
        // SECURITY (SSRF): vet the entry URL before fetching. This tier bypasses the browser
        // route-blocker, so this guard (fail-closed, DNS-resolving) plus the client's per-hop redirect
        // re-vetting are what stop a monitor target pointed at loopback / RFC1918 / cloud metadata.
        if !crate::security::url_guard::is_navigation_url_safe_async(&target.url).await {
            return content_error(target, &format!("refused unsafe URL: {}", target.url));
        }
        let req = self
            .http
            .get(&target.url)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.9");
        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => return content_error(target, &format!("fetch failed: {e}")),
        };
        let status = resp.status().as_u16() as i64;
        let headers: HashMap<String, String> = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.to_string(), s.to_string())))
            .collect();
        // BOUNDED body read (see `crawl_shard::body_limit`). reqwest transparently gunzips, so an
        // uncapped `text()` let a monitored site inflate ~1 MB on the wire into ~1 GB resident.
        let body = match crate::crawl_shard::body_limit::read_text_capped(
            resp,
            crate::crawl_shard::body_limit::HTML_MAX,
        )
        .await
        {
            Ok(b) => b,
            Err(e) => return content_error(target, &e.to_string()),
        };

        // Parsing + CSS extraction is pure CPU with no `.await` inside, so running it inline blocked a
        // tokio worker that also hosts the daemon's HTTP server — AND made the caller's
        // `CHECK_TIMEOUT_SECS` timeout unable to fire (a timer only fires at an await point).
        // Offload it; `scraper::Html` is not `Send`, so it is built and dropped inside the closure and
        // only owned Strings cross the boundary.
        let specs: Vec<(String, String)> = target
            .selectors
            .iter()
            .map(|s| (s.selector.clone(), s.content_type.clone()))
            .collect();
        let extracted = match extract_selectors_offloaded(body, specs).await {
            Ok(v) => v,
            Err(e) => return content_error(target, &e),
        };

        let mut outcome = CheckOutcome::default();
        for (sel, value) in target.selectors.iter().zip(extracted) {
            outcome
                .reports
                .push(self.finalize_selector(target, sel, value, Some(status), Some(&headers), &mut outcome.changed));
        }
        outcome
    }

    // ---- HTTP uptime ------------------------------------------------------

    /// DNS + TCP timing + HTTP status.
    ///
    /// TLS certificate-expiry checking is NOT YET IMPLEMENTED: `check_ssl` and every
    /// `ssl_cert_*` field on the report are always left `None`. reqwest still *verifies*
    /// the certificate chain (a bad/expired cert makes the request fail → `is_up = false`),
    /// but we do not yet surface expiry/issuer/subject metadata. A native-tls peer-cert
    /// path is a deliberate follow-up — the OSS disclosure docs reference this comment so
    /// the gap is not mistaken for a working-but-empty check.
    async fn check_uptime(&self, target: &Target) -> CheckOutcome {
        let mut item = ReportItem {
            target_url: target.url.clone(),
            target_id: target.id,
            check_type: "uptime".to_string(),
            is_up: Some(false),
            ..Default::default()
        };

        let parsed = match url::Url::parse(&target.url) {
            Ok(u) => u,
            Err(e) => {
                item.error_message = Some(format!("bad url: {e}"));
                return single(item);
            }
        };
        let host = parsed.host_str().unwrap_or("").to_string();
        let port = parsed
            .port_or_known_default()
            .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

        let timeout = Duration::from_millis(target.timeout_ms.unwrap_or(10_000) as u64);
        let started = Instant::now();

        // DNS
        let dns_start = Instant::now();
        let addrs = match tokio::net::lookup_host((host.as_str(), port)).await {
            Ok(a) => a.collect::<Vec<_>>(),
            Err(e) => {
                item.error_message = Some(format!("DNS resolution failed: {e}"));
                return single(item);
            }
        };
        item.dns_time_ms = Some(dns_start.elapsed().as_millis() as i64);
        // SECURITY (SSRF): refuse if the target resolves to an internal/metadata address. Vetting the
        // RESOLVED ips (not just the hostname) closes the DNS-rebind gap for the uptime tier, which —
        // unlike the browser path — has no route-blocker. Done here rather than via a fail-closed
        // upfront guard so a genuinely-unreachable host still reports as down, not "unsafe".
        if addrs.iter().any(|sa| crate::security::url_guard::is_blocked_ip(sa.ip())) {
            item.error_message = Some(format!("refused unsafe URL: {}", target.url));
            return single(item);
        }
        let Some(addr) = addrs.into_iter().next() else {
            item.error_message = Some("DNS returned no addresses".to_string());
            return single(item);
        };

        // TCP connect
        let connect_start = Instant::now();
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_stream)) => {
                item.connect_time_ms = Some(connect_start.elapsed().as_millis() as i64);
            }
            Ok(Err(e)) => {
                item.error_message = Some(format!("Connection failed: {e}"));
                return single(item);
            }
            Err(_) => {
                item.error_message = Some("Connection timed out".to_string());
                return single(item);
            }
        }

        // HTTP request for status. reqwest performs (and verifies) TLS for us.
        match self.http.get(&target.url).timeout(timeout).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16() as i64;
                item.status_code = Some(status);
                item.response_time_ms = Some(started.elapsed().as_millis() as i64);
                // A response arrived, but "responded" is not "up". When the target declares an
                // `expected_status_code`, only THAT code counts as up — otherwise a 500/404/403 would
                // be silently reported healthy. With no expectation set, treat any non-5xx response as
                // up (a 5xx is a server error → down), matching the common uptime-monitor default.
                match classify_uptime_status(status, target.expected_status_code) {
                    Ok(()) => item.is_up = Some(true),
                    Err((error_type, msg)) => {
                        item.is_up = Some(false);
                        item.error_type = Some(error_type.to_string());
                        item.error_message = Some(msg);
                    }
                }
            }
            Err(e) => {
                item.error_message = Some(format!("HTTP request failed: {e}"));
            }
        }
        single(item)
    }

    // ---- Browser content (JS / auth / pre-check) --------------------------

    async fn check_content_browser(
        &self,
        target: &Target,
        browser: &Arc<BrowserManager>,
    ) -> CheckOutcome {
        // Reuse a saved fingerprint if the auth session carried one, else random.
        let restored_fp = target
            .auth_session
            .as_ref()
            .and_then(|a| a.get("fingerprint"))
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        // Open the check at the viewport the target's visual zones were DRAWN at, so the
        // page lays out exactly as it did under the recorder's zone-drawing overlay and a
        // `visual_region` clips the same pixels. Targets with no zone (and zones saved
        // before the viewport was recorded) get the historical 1280x800 — see
        // `visual_region::context_viewport`.
        let (cvw, cvh) = super::visual_region::context_viewport(target);
        let (context, page, _fp) = match browser
            .create_stealth_context_full(
                restored_fp,
                Some(playwright_rs::Viewport { width: cvw, height: cvh }),
            )
            .await
        {
            Ok(cp) => cp,
            Err(e) => return content_error(target, &format!("browser context failed: {e}")),
        };

        // SECURITY: vet the URL before navigating (same guard as the workflow path).
        if !crate::security::url_guard::is_navigation_url_safe_async(&target.url).await {
            let _ = context.close().await;
            return content_error(target, &format!("refused unsafe URL: {}", target.url));
        }

        // Restore auth session (cookies before nav, storage after) if present.
        let saved_state: Option<SessionState> = target
            .auth_session
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let nav = if let Some(ref state) = saved_state {
            crate::automation::session_state::inject_session_state(
                &page, &context, state, Some(&target.url), 30_000,
            )
            .await
        } else {
            crate::browser::navigation::goto(
                &page, &target.url, "domcontentloaded", Duration::from_secs(30),
            )
            .await
        };
        if let Err(e) = nav {
            let _ = context.close().await;
            return content_error(target, &format!("navigation failed: {e}"));
        }

        // Optional pre-check workflow (login etc.) — run its steps in order. A pre-check that FAILS
        // (e.g. login didn't complete) must abort the check: extracting from a logged-out / wrong page
        // would hash unrelated content and either report a spurious "changed" or poison the baseline.
        // Return an error row per selector instead so the failure is recorded, not silently checked.
        if let Some(wf) = &target.pre_check_workflow {
            if let Err(e) = run_pre_check_steps(&page, wf).await {
                tracing::warn!(target = %target.url, error = %e, "pre-check workflow failed; aborting check");
                let _ = context.close().await;
                return content_error(target, &format!("pre-check failed: {e}"));
            }
        }

        // SETTLE before extracting. Navigation returned at `domcontentloaded` — the
        // raw HTML shell — but a JS/SPA target builds its real content afterward via
        // client-side rendering (and a pre-check workflow above may have just
        // navigated). Extracting now reads empty/placeholder DOM and reports a false
        // "changed" (or seeds a wrong baseline). Wait for the network to go quiet so
        // the first render has finished. Best-effort and bounded so a chatty page
        // (analytics/websocket polling that never idles) can't hang the check.
        let _ = crate::browser::navigation::wait_for_load_state(
            &page, "networkidle", Duration::from_secs(8),
        )
        .await;

        // Extract each selector via the live DOM (or screenshot, for visual zones).
        let mut outcome = CheckOutcome::default();
        for sel in &target.selectors {
            if sel.content_type == "visual" {
                let shot = extract_visual(&page, sel).await;
                outcome.reports.push(finalize_visual(target, sel, shot, &mut outcome.changed));
                continue;
            }
            let extracted = extract_in_page(&page, sel).await;
            outcome.reports.push(self.finalize_selector(
                target, sel, extracted, None, None, &mut outcome.changed,
            ));
        }

        // Harvest the (possibly refreshed) auth session so the backend can persist
        // it via precheck_complete — exactly like the workflow path.
        let captured: HashMap<String, String> = HashMap::new();
        let state = crate::automation::session_state::extract_session_state(&page, &context, &captured).await;
        outcome.auth_session = serde_json::to_value(&state).ok();

        let _ = context.close().await;
        outcome
    }

    // ---- shared finalization ---------------------------------------------

    /// Hash extracted content, compare to baseline, and build the per-selector
    /// report item. `extracted == None` means the selector matched nothing /
    /// extraction failed → reported as a `selector_missing` error row.
    fn finalize_selector(
        &self,
        target: &Target,
        sel: &Selector,
        extracted: Option<String>,
        status: Option<i64>,
        headers: Option<&HashMap<String, String>>,
        changed_flag: &mut bool,
    ) -> ReportItem {
        let _ = &self.user_agent; // UA is applied at the client level
        let Some(raw) = extracted else {
            return ReportItem {
                target_url: target.url.clone(),
            target_id: target.id,
                check_type: "content".to_string(),
                selector_id: sel.id,
                selector_name: sel.name.clone(),
                content_hash: Some("0".repeat(64)),
                error_type: Some("selector_missing".to_string()),
                error_message: Some(format!("no content for selector: {}", sel.selector)),
                status_code: status,
                ..Default::default()
            };
        };

        let content = finalize_content(&raw, sel);
        let hash = compute_hash(&content);
        let changed = match &sel.baseline_hash {
            Some(b) if !b.is_empty() => &hash != b,
            _ => false, // first check: establish baseline, not a change
        };
        if changed {
            *changed_flag = true;
        }
        let diff_snippet = if changed {
            sel.baseline_content
                .as_deref()
                .map(|prev| generate_diff(prev, &content, 10_000))
        } else {
            None
        };

        ReportItem {
            target_url: target.url.clone(),
            target_id: target.id,
            check_type: "content".to_string(),
            selector_id: sel.id,
            selector_name: sel.name.clone(),
            content_hash: Some(hash),
            diff_snippet,
            content: Some(truncate(&content, 5_000)),
            previous_content: sel.baseline_content.as_deref().map(|p| truncate(p, 5_000)),
            headers: headers.cloned(),
            status_code: status,
            ..Default::default()
        }
    }
}

// ---- free helpers ---------------------------------------------------------

fn single(item: ReportItem) -> CheckOutcome {
    CheckOutcome { reports: vec![item], ..Default::default() }
}

/// Decide whether an HTTP status counts as "up" for an uptime check. `Ok(())` = up; `Err((type,msg))`
/// = down with a classified reason. When `expected` is set, ONLY that exact code is up. Otherwise any
/// non-5xx is up and a 5xx is a server error (down). Kept as a pure fn so the policy is unit-testable
/// without a network round-trip.
fn classify_uptime_status(
    status: i64,
    expected: Option<i64>,
) -> Result<(), (&'static str, String)> {
    match expected {
        Some(exp) if status != exp => {
            Err(("unexpected_status", format!("expected HTTP {exp}, got {status}")))
        }
        None if status >= 500 => Err(("server_error", format!("server error: HTTP {status}"))),
        _ => Ok(()),
    }
}

/// An error outcome that still emits one row per selector (or a single row when
/// there are none) so the backend records the failure against every selector.
fn content_error(target: &Target, msg: &str) -> CheckOutcome {
    let mk = |sel: Option<&Selector>| ReportItem {
        target_url: target.url.clone(),
        target_id: target.id,
        check_type: "content".to_string(),
        selector_id: sel.and_then(|s| s.id),
        selector_name: sel.and_then(|s| s.name.clone()),
        content_hash: Some("0".repeat(64)),
        error_type: Some("check_failed".to_string()),
        error_message: Some(msg.to_string()),
        ..Default::default()
    };
    let reports = if target.selectors.is_empty() {
        vec![mk(None)]
    } else {
        target.selectors.iter().map(|s| mk(Some(s))).collect()
    };
    CheckOutcome { reports, ..Default::default() }
}

/// The selector extraction, expressed over plain `&str`s so it can run inside the `spawn_blocking`
/// closure (which owns only cloned selector strings, never the `Selector` model).
fn extract_css(doc: &scraper::Html, selector: &str, content_type: &str) -> Option<String> {
    let css = scraper::Selector::parse(selector).ok()?;
    let mut parts = Vec::new();
    for el in doc.select(&css) {
        if content_type == "html" {
            parts.push(el.html());
        } else {
            parts.push(el.text().collect::<Vec<_>>().join(""));
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n"))
    }
}

/// Wall-clock budget for parsing ONE page and running its selectors on the blocking pool. Page size
/// is bounded by `body_limit::HTML_MAX`, so this only ever trips on pathological markup.
const PARSE_BUDGET: Duration = Duration::from_secs(20);

/// Parse `html` and evaluate `specs` (`(selector, content_type)`) OFF the async runtime.
///
/// WHY: `Html::parse_document` + `select` are synchronous CPU work. Inline, they starve the tokio
/// worker they run on (the same threads serving the local daemon's HTTP API) and they render the
/// caller's `tokio::time::timeout` useless, because a timer cannot fire without an intervening await.
/// `spawn_blocking` moves the work to the blocking pool so both problems go away.
///
/// A blocking task is not cancellable, so on timeout the thread finishes in the background — bounded,
/// because the input was already capped before it got here.
async fn extract_selectors_offloaded(
    html: String,
    specs: Vec<(String, String)>,
) -> Result<Vec<Option<String>>, String> {
    let job = tokio::task::spawn_blocking(move || {
        let doc = scraper::Html::parse_document(&html);
        specs
            .iter()
            .map(|(css, ctype)| extract_css(&doc, css, ctype))
            .collect::<Vec<_>>()
    });
    match tokio::time::timeout(PARSE_BUDGET, job).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("content parse task failed: {e}")),
        Err(_) => Err(format!("content parse exceeded {}s", PARSE_BUDGET.as_secs())),
    }
}

async fn extract_in_page(page: &playwright_rs::Page, sel: &Selector) -> Option<String> {
    let want_html = sel.content_type == "html";
    let js = r#"(args) => {
        const [selector, wantHtml] = args;
        const els = Array.from(document.querySelectorAll(selector));
        if (!els.length) return null;
        return els.map(e => wantHtml ? e.outerHTML : (e.innerText || e.textContent || "")).join("\n");
    }"#;
    let args = serde_json::json!([sel.selector, want_html]);
    let result: Result<serde_json::Value, _> = page.evaluate(js, Some(&args)).await;
    match result {
        Ok(serde_json::Value::String(s)) => Some(s),
        _ => None,
    }
}

/// Visual (screenshot-region) check: clip the region, return (pixel_hash, png_bytes).
/// `None` if the region is malformed or the screenshot fails.
///
/// The clip resolves against the page's LIVE viewport rather than a hardcoded size —
/// `check_content_browser` opens the context at the zone's own viewport, and
/// [`visual_region::clip_rect`] rescales anything that still doesn't line up.
async fn extract_visual(page: &playwright_rs::Page, sel: &Selector) -> Option<(String, Vec<u8>)> {
    use super::visual_region;

    let region = sel.visual_region.as_ref()?;
    // The live viewport is the authority: the requested size can be refused, and a
    // pre-check workflow may have resized the page out from under us.
    let (vw, vh) = page
        .viewport_size()
        .map(|vp| (vp.width, vp.height))
        .unwrap_or(visual_region::DEFAULT_ZONE_VIEWPORT);
    let mut clip = visual_region::clip_rect(region, vw, vh)?;

    // Restore the scroll the zone was drawn at before clipping — the clip is
    // viewport-relative, so a zone the user drew below the fold only lines up once
    // we scroll back to where they drew it. Correct for scroll clamping on short
    // pages. Skip for top-of-page zones so legacy baselines stay byte-identical and
    // the check keeps its old timing.
    if clip.needs_scroll() {
        let (sx0, sy0) = (clip.scroll_x, clip.scroll_y);
        let js = format!(
            "() => {{ window.scrollTo({{left: {sx0}, top: {sy0}, behavior: 'instant'}}); \
             return {{x: window.scrollX, y: window.scrollY}}; }}"
        );
        if let Ok(pos) =
            crate::browser::page_query::evaluate::<serde_json::Value>(page, &js).await
        {
            visual_region::apply_scroll_shortfall(
                &mut clip,
                pos.get("x").and_then(|v| v.as_f64()).unwrap_or(sx0),
                pos.get("y").and_then(|v| v.as_f64()).unwrap_or(sy0),
                vw,
                vh,
            );
        }
        // let scroll-triggered content settle before the snapshot
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    let png = crate::browser::page_query::screenshot_png_clip(
        page, clip.x, clip.y, clip.width, clip.height,
    )
    .await
    .ok()?;
    let hash = pixel_hash(&png)?;
    Some((hash, png))
}

/// Hash the raw pixels of a region screenshot. Normalizes to 256x256 RGB then
/// SHA256s the pixel bytes — mirrors the Python agents' `_pixel_hash` so a
/// baseline is comparable across runs. (PIL vs `image` resize aren't byte-
/// identical, so a target that migrates Python<->Rust may re-baseline once.)
fn pixel_hash(png_bytes: &[u8]) -> Option<String> {
    let img = image::load_from_memory(png_bytes).ok()?;
    let rgb = img.to_rgb8();
    let resized =
        image::imageops::resize(&rgb, 256, 256, image::imageops::FilterType::Lanczos3);
    let mut h = Sha256::new();
    h.update(resized.as_raw());
    Some(hex(&h.finalize()))
}

/// Build the report row for a visual selector. Sends the screenshot (base64 PNG)
/// only on first run (to seed the baseline image) or on change (the "after"
/// image) so steady-state checks stay lightweight.
fn finalize_visual(
    target: &Target,
    sel: &Selector,
    result: Option<(String, Vec<u8>)>,
    changed_flag: &mut bool,
) -> ReportItem {
    use base64::Engine;
    let Some((hash, png)) = result else {
        return ReportItem {
            target_url: target.url.clone(),
            target_id: target.id,
            check_type: "content".to_string(),
            selector_id: sel.id,
            selector_name: sel.name.clone(),
            content_hash: Some("0".repeat(64)),
            error_type: Some("visual_capture_failed".to_string()),
            error_message: Some(format!("could not screenshot region for {:?}", sel.name)),
            ..Default::default()
        };
    };
    let baseline = sel.baseline_hash.as_deref().filter(|b| !b.is_empty());
    let changed = matches!(baseline, Some(b) if b != hash);
    if changed {
        *changed_flag = true;
    }
    let screenshot = if baseline.is_none() || changed {
        Some(base64::engine::general_purpose::STANDARD.encode(&png))
    } else {
        None
    };
    ReportItem {
        target_url: target.url.clone(),
        target_id: target.id,
        check_type: "content".to_string(),
        selector_id: sel.id,
        selector_name: sel.name.clone(),
        content_hash: Some(hash),
        screenshot,
        ..Default::default()
    }
}

/// Execute a pre-check workflow's steps (login etc.) before the content read.
async fn run_pre_check_steps(
    page: &playwright_rs::Page,
    workflow: &serde_json::Value,
) -> Result<(), String> {
    let steps = workflow
        .get("steps")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let creds: HashMap<String, String> = workflow
        .get("credentials")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let form: HashMap<String, String> = HashMap::new();
    // Monitoring checks carry no run-level files map; an inert RunFiles makes any
    // upload/wait_for_download step fail closed (File assets §6.3).
    let run_files = crate::automation::files::RunFiles::from_config(&serde_json::Value::Null, None);

    for raw_step in &steps {
        let step_type = raw_step.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if step_type.is_empty() {
            continue;
        }
        if !raw_step.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true) {
            continue;
        }
        // A step whose config won't deserialize can't be executed. Silently skipping it would let a
        // login pre-check "succeed" with a step missing → the content read runs on a logged-out page.
        // Fail the pre-check instead (fail-closed) so the caller records an error row for the target.
        let config: crate::models::workflow::WorkflowStepConfig = match serde_json::from_value(
            raw_step.get("config").cloned().unwrap_or_else(|| raw_step.clone()),
        ) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(step_type, error = %e, "pre-check step config failed to deserialize");
                return Err(format!("step '{step_type}' config invalid: {e}"));
            }
        };
        if let Err(e) = crate::automation::step_executor::execute_step(
            page, step_type, &config, &creds, &form, &run_files, 30_000, true,
        )
        .await
        {
            return Err(format!("step '{step_type}' failed: {e}"));
        }
    }
    Ok(())
}

/// Apply ignore-regex then normalize whitespace. Mirrors
/// `checker.extract_content` post-processing.
fn finalize_content(raw: &str, sel: &Selector) -> String {
    let mut content = raw.to_string();
    if let Some(pat) = &sel.ignore_regex {
        if !pat.is_empty() {
            if let Ok(re) = regex::Regex::new(pat) {
                content = re.replace_all(&content, "").to_string();
            }
        }
    }
    if sel.content_type != "html" {
        content = normalize_whitespace(&content);
    }
    content
}

/// Collapse all whitespace runs to a single space and trim — matches the Python
/// `_normalize_whitespace` net effect (it collapses newlines too).
fn normalize_whitespace(text: &str) -> String {
    let collapsed: String = {
        let mut out = String::with_capacity(text.len());
        let mut in_ws = false;
        for ch in text.chars() {
            if ch.is_whitespace() {
                if !in_ws {
                    out.push(' ');
                    in_ws = true;
                }
            } else {
                out.push(ch);
                in_ws = false;
            }
        }
        out
    };
    collapsed.trim().to_string()
}

fn compute_hash(content: &str) -> String {
    let mut h = Sha256::new();
    h.update(content.as_bytes());
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect()
    }
}

/// The largest index `<= idx` that is a UTF-8 char boundary of `s` (`str::floor_char_boundary` is
/// still unstable). Used wherever a BYTE budget has to be applied to attacker-controlled text.
fn floor_char_boundary(s: &str, idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    let mut i = idx;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// A small line-oriented diff snippet (faithful enough to Python's unified diff
/// for the human-readable "what changed" field; the backend stores full content
/// separately).
fn generate_diff(old: &str, new: &str, max_len: usize) -> String {
    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let mut out = String::new();
    let n = old_lines.len().max(new_lines.len());
    for i in 0..n {
        let o = old_lines.get(i).copied().unwrap_or("");
        let nw = new_lines.get(i).copied().unwrap_or("");
        if o != nw {
            if !o.is_empty() {
                out.push_str("- ");
                out.push_str(o);
                out.push('\n');
            }
            if !nw.is_empty() {
                out.push_str("+ ");
                out.push_str(nw);
                out.push('\n');
            }
        }
        if out.len() > max_len {
            // `String::truncate` PANICS off a UTF-8 char boundary, and every byte of `out` came from
            // scraped selector content. The monitor runner walks due targets sequentially with no
            // per-target isolation, so this unwind used to abort the whole tick and skip every target
            // ordered after the hostile one — repeatedly, for as long as the page stayed poisoned.
            // Truncate on the nearest boundary at or below `max_len` instead.
            out.truncate(floor_char_boundary(&out, max_len));
            out.push_str("\n... (truncated)");
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_64_hex() {
        let h = compute_hash("hello world");
        assert_eq!(h.len(), 64);
        assert_eq!(h, compute_hash("hello world"));
        assert_ne!(h, compute_hash("hello  world!"));
    }

    #[test]
    fn whitespace_normalization_collapses_runs() {
        assert_eq!(normalize_whitespace("  a\n\n  b\t c  "), "a b c");
    }

    #[test]
    fn scraper_extracts_text_and_html() {
        let html = r#"<html><body><div class="p">Hello <b>World</b></div></body></html>"#;
        let doc = scraper::Html::parse_document(html);
        assert_eq!(extract_css(&doc, ".p", "text").as_deref(), Some("Hello World"));
        assert_eq!(
            extract_css(&doc, ".p", "html").as_deref(),
            Some(r#"<div class="p">Hello <b>World</b></div>"#)
        );
        // A selector that matches nothing is a miss, and an unparseable one is too (never a panic).
        assert!(extract_css(&doc, ".nope", "text").is_none());
        assert!(extract_css(&doc, ":::garbage", "text").is_none());
    }

    /// REGRESSION: `generate_diff` byte-truncated a diff built entirely from scraped page content.
    /// A multi-byte glyph straddling the limit panicked, and because the local monitor runner walked
    /// due targets sequentially, that unwind aborted the ENTIRE tick — every target after the hostile
    /// one was skipped, every tick, for as long as the content stayed poisoned.
    #[test]
    fn diff_truncation_is_char_boundary_safe() {
        // 'é' is 2 bytes: with max_len = 101 the cut lands mid-codepoint on the old code.
        let old = "a".to_string();
        let new: String = "é".repeat(5_000);
        let out = generate_diff(&old, &new, 101);
        assert!(out.ends_with("... (truncated)"), "not truncated: {out}");
        // 3-byte and 4-byte sequences too (CJK + emoji).
        for pad in ["漢", "🙂"] {
            for max in 90..110 {
                let hostile: String = pad.repeat(500);
                let out = generate_diff("x", &hostile, max);
                assert!(out.ends_with("... (truncated)"), "max={max} pad={pad}");
            }
        }
    }

    #[test]
    fn floor_char_boundary_never_splits_a_codepoint() {
        let s = "aé漢🙂";
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(floor_char_boundary(s, 1), 1); // after 'a'
        assert_eq!(floor_char_boundary(s, 2), 1); // mid 'é' → back to 1
        assert_eq!(floor_char_boundary(s, 3), 3); // after 'é'
        assert_eq!(floor_char_boundary(s, 5), 3); // mid '漢' → back to 3
        assert_eq!(floor_char_boundary(s, 999), s.len());
        // Every index is a valid slice point.
        for i in 0..=s.len() {
            let _ = &s[..floor_char_boundary(s, i)];
        }
    }

    /// The offloaded parse must return one value per selector, in order, including misses.
    #[tokio::test]
    async fn offloaded_extraction_preserves_selector_order() {
        let html = r#"<html><body><div class="a">A</div><div class="c">C</div></body></html>"#;
        let specs = vec![
            ("div.a".to_string(), "text".to_string()),
            ("div.nope".to_string(), "text".to_string()),
            ("div.c".to_string(), "text".to_string()),
        ];
        let out = extract_selectors_offloaded(html.to_string(), specs).await.unwrap();
        assert_eq!(out, vec![Some("A".into()), None, Some("C".into())]);
    }

    #[test]
    fn uptime_status_classification() {
        // No expectation: 2xx/3xx/4xx are up, 5xx is down.
        assert!(classify_uptime_status(200, None).is_ok());
        assert!(classify_uptime_status(301, None).is_ok());
        assert!(classify_uptime_status(404, None).is_ok(), "no expectation → 4xx is still 'reachable'");
        let err = classify_uptime_status(503, None).unwrap_err();
        assert_eq!(err.0, "server_error", "a 5xx with no expectation is down");

        // With an expectation: only the exact code is up.
        assert!(classify_uptime_status(200, Some(200)).is_ok());
        let err = classify_uptime_status(500, Some(200)).unwrap_err();
        assert_eq!(err.0, "unexpected_status", "5xx when 200 expected is down");
        let err = classify_uptime_status(302, Some(200)).unwrap_err();
        assert_eq!(err.0, "unexpected_status", "even a 3xx mismatch is down when a code is expected");
        // Expecting a non-2xx (e.g. a maintenance 503) makes exactly that code up.
        assert!(classify_uptime_status(503, Some(503)).is_ok());
    }

    #[test]
    fn routing_is_tiered() {
        let mk = |ct: &str, pw: bool, auth: bool| Target {
            id: None, url: "https://x".into(), check_type: ct.into(),
            check_period_ms: None, requires_playwright: pw,
            pre_check_workflow: None,
            auth_session: if auth { Some(serde_json::json!({})) } else { None },
            timeout_ms: None, expected_status_code: None, check_ssl: true, selectors: vec![],
        };
        assert!(!mk("uptime", true, true).needs_browser());
        assert!(!mk("content", false, false).needs_browser());
        assert!(mk("content", true, false).needs_browser());
        assert!(mk("content", false, true).needs_browser());
    }

    /// The HTTP lane and the browser lane must present as ONE browser. A UA claiming a different
    /// Chrome major than the Chromium the bundled driver launches is a free bot signal, and it is
    /// exactly the drift this caught (UA said 120 while the shipped Chromium was 148).
    #[test]
    fn ua_matches_declared_major() {
        assert!(
            DEFAULT_UA.contains(&format!("Chrome/{}.", CHROME_MAJOR)),
            "DEFAULT_UA ({DEFAULT_UA}) must advertise Chrome major {CHROME_MAJOR}"
        );
    }

    /// Whatever we advertise must be decodable. `accept-encoding` is reqwest's to set (it derives it
    /// from the enabled codec features), so hand-setting it here would risk advertising br/zstd we
    /// cannot decompress and silently extracting binary garbage.
    #[test]
    fn browser_headers_leave_encoding_and_ua_to_reqwest() {
        let h = browser_headers();
        assert!(h.get("accept-encoding").is_none(), "accept-encoding must stay reqwest's to derive");
        assert!(h.get("user-agent").is_none(), "user-agent has exactly one owner: ClientBuilder");
        assert!(h.get("accept").unwrap().to_str().unwrap().starts_with("text/html"));
        let ua_ch = h.get("sec-ch-ua").unwrap().to_str().unwrap().to_string();
        assert!(ua_ch.contains(CHROME_MAJOR), "sec-ch-ua must agree with the UA major");
    }
}
