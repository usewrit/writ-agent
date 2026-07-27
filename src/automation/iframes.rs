use std::time::Duration;

use playwright_rs::protocol::Frame;

/// Does `frame_url` identify the frame a saved workflow's `iframe_pattern` refers to?
///
/// # Why this is not `frame_url.contains(pattern)`
///
/// It used to be, and that made frame selection attacker-steerable: any page can embed an iframe whose
/// URL merely *contains* the pattern somewhere — in the query string
/// (`https://evil.example/?next=payroll.internal/report.aspx`), in the fragment, or in userinfo
/// (`https://payroll.internal/report.aspx@evil.example/`). The recorded script — which typically reads
/// authenticated content and clicks through it — would then run inside the attacker's document.
///
/// So the pattern is matched against the parts of the URL that actually identify a document, never
/// against caller-suppliable trailing data:
///
/// * **Absolute pattern** (`https://host/path…`): the frame's ORIGIN must be equal (scheme, host, and
///   effective port), and the frame's path+query must start with the pattern's path+query. An origin
///   comparison is the only form of this check that a hostile page cannot satisfy.
/// * **Path pattern** (`/embed/report`): matched against the frame's path+query only. There is no
///   origin in the pattern to check, but the authority can no longer be used to smuggle a match.
/// * **Bare pattern** (`report.aspx`, `payroll.internal/report`): matched against `host + path` only —
///   query and fragment are excluded, which is where the smuggling happened.
///
/// A frame URL that does not parse (or a pattern that is empty) never matches.
fn frame_url_matches(frame_url: &str, pattern: &str) -> bool {
    let pattern = pattern.trim();
    if pattern.is_empty() {
        return false;
    }
    let Ok(fu) = url::Url::parse(frame_url) else {
        return false;
    };
    // `path` + `?query`: everything that identifies the document within its origin, fragment excluded
    // (the fragment never reaches the server and is fully page-controlled).
    let path_query = match fu.query() {
        Some(q) => format!("{}?{}", fu.path(), q),
        None => fu.path().to_string(),
    };

    // 1. Absolute pattern → strict origin equality + path prefix.
    if let Ok(pat) = url::Url::parse(pattern) {
        if pat.has_host() {
            let same_origin = fu.scheme() == pat.scheme()
                && fu.host_str() == pat.host_str()
                && fu.port_or_known_default() == pat.port_or_known_default();
            if !same_origin {
                return false;
            }
            let pat_path_query = match pat.query() {
                Some(q) => format!("{}?{}", pat.path(), q),
                None => pat.path().to_string(),
            };
            // A bare-origin pattern ("https://host/") pins the origin and nothing more.
            return pat_path_query == "/" || path_query.starts_with(&pat_path_query);
        }
    }

    // 2. Path pattern → path+query only, never the authority.
    if pattern.starts_with('/') {
        return path_query.contains(pattern);
    }

    // 3. Bare pattern → host + path. Query/fragment deliberately excluded.
    let host_path = match fu.host_str() {
        Some(h) => match fu.port() {
            Some(p) => format!("{h}:{p}{}", fu.path()),
            None => format!("{h}{}", fu.path()),
        },
        None => fu.path().to_string(),
    };
    host_path.contains(pattern)
}

/// Port of Python `_find_frame` (automation_engine.py lines 6346-6367), hardened.
///
/// Searches all non-main frames for the one identified by `pattern` — see [`frame_url_matches`] for
/// what "identified by" means and why it is not a plain substring test.
pub async fn find_frame_by_url_pattern(
    page: &playwright_rs::Page,
    pattern: &str,
) -> Option<Frame> {
    let frames = match page.frames().await {
        Ok(f) => f,
        Err(_) => return None,
    };

    let main_url = page.main_frame().await.ok().map(|f| f.url()).unwrap_or_default();

    let mut found: Option<Frame> = None;
    let mut frame_urls: Vec<String> = Vec::new();

    for frame in &frames {
        let url = frame.url();
        if url == main_url {
            continue;
        }
        frame_urls.push(url.chars().take(80).collect());
        if found.is_none() && frame_url_matches(&url, pattern) {
            found = Some(frame.clone());
        }
    }

    if found.is_none() {
        tracing::warn!(pattern = pattern, available = ?frame_urls, "Frame not found");
    }

    found
}

/// 1:1 port of Python _evaluate_in_iframe (automation_engine.py lines 6369-6590).
///
/// Executes a saved script inside an iframe using Playwright's Frame API.
/// For scripts without navigation: runs directly via frame.evaluate().
/// For scripts with navigation: extracts functions and drives from Rust.
pub async fn evaluate_in_iframe(
    page: &playwright_rs::Page,
    iframe_pattern: &str,
    script: &str,
) -> serde_json::Value {
    // Wait for iframe to appear — SPA may still be loading it (Python line 6386)
    let mut frame: Option<Frame> = None;
    for attempt in 0..20_u32 {
        frame = find_frame_by_url_pattern(page, iframe_pattern).await;
        if frame.is_some() {
            break;
        }
        if attempt == 0 {
            tracing::info!(pattern = iframe_pattern, "Iframe not found yet, waiting for SPA...");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;

        // After 3s, try re-triggering the SPA hash (Python line 6394)
        if attempt == 6 {
            let hash: Result<Option<String>, _> =
                page.evaluate("() => window.location.hash", None::<&()>).await;
            if let Ok(Some(h)) = hash {
                if !h.is_empty() {
                    tracing::debug!(hash = %h, "Re-triggering hash to force SPA reload");
                    let stripped = h.strip_prefix('#').unwrap_or(&h);
                    let _: Result<serde_json::Value, _> = page.evaluate(
                        "(h) => { window.location.hash = ''; setTimeout(() => { window.location.hash = h }, 100) }",
                        Some(&serde_json::json!(stripped)),
                    ).await;
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    let frame = match frame {
        Some(f) => f,
        None => {
            tracing::warn!(pattern = iframe_pattern, "Iframe not found after waiting, falling back to page.evaluate");
            return page.evaluate(script, None::<&()>).await.unwrap_or(serde_json::Value::Null);
        }
    };

    tracing::info!(url = %frame.url(), "Found iframe");

    let _ = tokio::time::timeout(
        Duration::from_secs(10),
        frame.wait_for_load_state(Some(playwright_rs::WaitUntil::DomContentLoaded)),
    ).await;

    // Adapt script: replace getDoc() references with document (Python line 6416-6442)
    let adapted = adapt_script_for_iframe(script);

    // Check if script has navigation (Python line 6444)
    let has_navigation = script.contains("btn.click")
        || script.contains("history.back")
        || script.contains(".click()");

    if !has_navigation {
        return frame.evaluate(&adapted, None::<&()>).await.unwrap_or(serde_json::Value::Null);
    }

    // Script has navigation — extract functions and drive from Rust (Python line 6451)
    tracing::info!("Script navigates iframe, using Rust-driven frame orchestration");

    let read_list_fn = extract_function(script, "readListPage");
    let read_detail_fn = extract_function(script, "readDetail");

    let Some(list_fn_body) = read_list_fn else {
        tracing::warn!("Could not extract readListPage, falling back to direct evaluate");
        return frame.evaluate(&adapted, None::<&()>).await.unwrap_or(serde_json::Value::Null);
    };

    // Build callable scripts (Python line 6489-6503)
    let list_eval = format!(
        r#"(() => {{
            {list_fn_body}
            const list = readListPage();
            const lastRow = document.querySelector('table tr:last-child');
            const pageLinks = lastRow ? Array.from(lastRow.querySelectorAll('a')).filter(a => /^\d+$/.test(a.innerText.trim())).map(a => parseInt(a.innerText.trim())) : [];
            return {{ employees: list.map(e => {{ delete e._btn; return e; }}), pages: pageLinks, count: list.length }};
        }})()"#
    );

    let detail_eval = read_detail_fn.map(|fn_body| {
        format!(
            r#"(() => {{
                {fn_body}
                return readDetail();
            }})()"#
        )
    });

    let mut all_items: Vec<serde_json::Value> = Vec::new();
    let mut page_num: u64 = 1;

    loop {
        // Re-find frame on each page iteration (Python line 6509)
        let current_frame = find_frame_by_url_pattern(page, iframe_pattern)
            .await
            .or_else(|| {
                // placeholder: we can't do async in or_else, handle below
                None
            });

        let current_frame = match current_frame {
            Some(f) => f,
            None => match find_any_content_frame(page).await {
                Some(f) => f,
                None => { tracing::warn!("Lost iframe"); break; }
            },
        };

        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            current_frame.wait_for_load_state(Some(playwright_rs::WaitUntil::DomContentLoaded)),
        ).await;

        // Read list page (Python line 6526)
        let list_data: serde_json::Value = current_frame
            .evaluate(&list_eval, None::<&()>)
            .await
            .unwrap_or(serde_json::Value::Null);

        let employees = list_data.get("employees").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        let available_pages = list_data.get("pages").and_then(|v| v.as_array()).cloned().unwrap_or_default();

        if employees.is_empty() {
            break;
        }

        tracing::info!(page = page_num, count = employees.len(), "Read list page");

        for (i, emp) in employees.iter().enumerate() {
            let mut emp_data = emp.clone();

            let Some(ref d_eval) = detail_eval else {
                all_items.push(emp_data);
                continue;
            };

            let btn_selector = format!("table tr:nth-child({}) input[type=\"button\"][value]", i + 3);
            let btn_exists = current_frame.query_selector(&btn_selector).await.map(|el| el.is_some()).unwrap_or(false);
            if !btn_exists {
                all_items.push(emp_data);
                continue;
            }

            // Click edit button (Python line 6549)
            if current_frame.locator(&btn_selector).click(None).await.is_err() {
                all_items.push(emp_data);
                continue;
            }

            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                current_frame.wait_for_load_state(Some(playwright_rs::WaitUntil::DomContentLoaded)),
            ).await;
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Read detail (Python line 6554)
            if let Ok(detail) = current_frame.evaluate(d_eval, None::<&()>).await {
                if let (Some(obj), serde_json::Value::Object(detail_map)) = (emp_data.as_object_mut(), detail) {
                    for (k, v) in detail_map {
                        obj.insert(k, v);
                    }
                }
            }

            // Navigate back (Python line 6558)
            let _: Result<serde_json::Value, _> = current_frame.evaluate("() => window.history.back()", None::<&()>).await;
            let _ = tokio::time::timeout(
                Duration::from_secs(10),
                current_frame.wait_for_load_state(Some(playwright_rs::WaitUntil::DomContentLoaded)),
            ).await;
            tokio::time::sleep(Duration::from_millis(500)).await;

            all_items.push(emp_data);
        }

        // Pagination (Python line 6575)
        page_num += 1;
        if !available_pages.iter().any(|p| p.as_u64() == Some(page_num)) {
            break;
        }

        let Some(next_frame) = find_frame_by_url_pattern(page, iframe_pattern).await else { break };
        let page_link_sel = format!("a:has-text(\"{}\")", page_num);
        if next_frame.locator(&page_link_sel).click(None).await.is_err() {
            tracing::warn!(page = page_num, "Pagination click failed");
            break;
        }
        let _ = tokio::time::timeout(
            Duration::from_secs(10),
            next_frame.wait_for_load_state(Some(playwright_rs::WaitUntil::DomContentLoaded)),
        ).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    serde_json::json!({ "total": all_items.len(), "employees": all_items })
}

/// Adapt a script to run inside an iframe — replace getDoc() with document.
fn adapt_script_for_iframe(script: &str) -> String {
    let mut adapted = script.to_string();

    // Replace getDoc() function body with one that returns document
    if let Some(start) = adapted.find("function getDoc()") {
        if let Some(end_offset) = find_matching_brace(&adapted[start..]) {
            let end = start + end_offset + 1;
            adapted.replace_range(start..end, "function getDoc() { return document; }");
        }
    }

    // Replace any remaining getDoc() calls
    adapted = adapted.replace("getDoc()", "(document)");
    adapted
}

/// Extract a named function body from script text.
fn extract_function(script: &str, name: &str) -> Option<String> {
    let pattern = format!("function {}", name);
    let start = script.find(&pattern)?;
    let fn_text = &script[start..];
    let end = find_matching_brace(fn_text)?;
    let mut fn_body = fn_text[..end + 1].to_string();

    fn_body = fn_body.replace("getDoc()", "(document)");
    if let Some(s) = fn_body.find("function getDoc()") {
        if let Some(e) = find_matching_brace(&fn_body[s..]) {
            let end = s + e + 1;
            fn_body.replace_range(s..end, "function getDoc() { return document; }");
        }
    }
    Some(fn_body)
}

/// Find position of matching closing brace for the first `{` in text.
fn find_matching_brace(text: &str) -> Option<usize> {
    let mut depth = 0i32;
    let mut started = false;
    for (i, ch) in text.char_indices() {
        match ch {
            '{' => { depth += 1; started = true; }
            '}' => {
                depth -= 1;
                if started && depth == 0 { return Some(i); }
            }
            _ => {}
        }
    }
    None
}

/// Find any non-main, non-about: frame.
async fn find_any_content_frame(page: &playwright_rs::Page) -> Option<Frame> {
    let frames = page.frames().await.ok()?;
    let main_url = page.main_frame().await.ok().map(|f| f.url()).unwrap_or_default();
    frames.into_iter().find(|f| {
        let url = f.url();
        url != main_url && !url.starts_with("about:")
    })
}

#[cfg(test)]
mod tests {
    use super::frame_url_matches;

    #[test]
    fn absolute_pattern_requires_the_same_origin() {
        let pat = "https://payroll.internal/report.aspx";
        assert!(frame_url_matches("https://payroll.internal/report.aspx", pat));
        assert!(frame_url_matches("https://payroll.internal/report.aspx?year=2026", pat));

        // Different host / scheme / port are all different origins.
        assert!(!frame_url_matches("https://evil.example/report.aspx", pat));
        assert!(!frame_url_matches("http://payroll.internal/report.aspx", pat));
        assert!(!frame_url_matches("https://payroll.internal:8443/report.aspx", pat));
        // Same host, different document.
        assert!(!frame_url_matches("https://payroll.internal/other.aspx", pat));
        // The default port is the same origin as no port.
        assert!(frame_url_matches("https://payroll.internal:443/report.aspx", pat));
    }

    /// THE BUG: a hostile page could put the pattern anywhere in an iframe URL and capture the script.
    #[test]
    fn attacker_controlled_positions_never_match() {
        for pat in ["https://payroll.internal/report.aspx", "payroll.internal/report.aspx"] {
            // Query string.
            assert!(
                !frame_url_matches("https://evil.example/?next=payroll.internal/report.aspx", pat),
                "{pat} matched via the query string"
            );
            // Fragment.
            assert!(
                !frame_url_matches("https://evil.example/#payroll.internal/report.aspx", pat),
                "{pat} matched via the fragment"
            );
            // Userinfo — the classic "everything before @ is not the host" trick. Here the real host
            // is `evil.example`; `payroll.internal` is only the username.
            assert!(
                !frame_url_matches("https://payroll.internal@evil.example/report.aspx", pat),
                "{pat} matched via userinfo"
            );
            assert!(
                !frame_url_matches(
                    "https://payroll.internal%2Freport.aspx@evil.example/",
                    pat
                ),
                "{pat} matched via percent-encoded userinfo"
            );
            // A host that merely ENDS with the pattern's host is a different host.
            assert!(
                !frame_url_matches("https://notpayroll.internal.evil.example/report.aspx", pat),
                "{pat} matched a lookalike host"
            );
        }
    }

    #[test]
    fn bare_and_path_patterns_match_the_document_parts() {
        // Bare token: host + path.
        assert!(frame_url_matches("https://payroll.internal/hr/report.aspx", "report.aspx"));
        assert!(frame_url_matches("https://payroll.internal/hr/report.aspx", "payroll.internal/hr"));
        assert!(frame_url_matches("https://host.test:8080/a/b", "host.test:8080/a"));
        assert!(!frame_url_matches("https://payroll.internal/hr/x?f=report.aspx", "report.aspx"));

        // Path pattern: path + query only.
        assert!(frame_url_matches("https://any.test/embed/report?y=1", "/embed/report"));
        assert!(frame_url_matches("https://any.test/embed/report?y=1", "/embed/report?y=1"));
        assert!(!frame_url_matches("https://embed.report.test/x", "/embed/report"));
    }

    #[test]
    fn degenerate_inputs_never_match() {
        assert!(!frame_url_matches("https://host.test/x", ""));
        assert!(!frame_url_matches("https://host.test/x", "   "));
        assert!(!frame_url_matches("about:blank", "report.aspx"));
        assert!(!frame_url_matches("not a url", "report.aspx"));
        // An origin-only pattern pins the origin and accepts any document under it.
        assert!(frame_url_matches("https://host.test/anything", "https://host.test/"));
        assert!(!frame_url_matches("https://other.test/anything", "https://host.test/"));
    }
}
