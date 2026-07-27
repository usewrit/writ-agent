use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Fingerprint pools — EXACT 1:1 with Python automation_engine._start_playwright_browser
// (lines 852-859). Python picks each field independently via random.choice and
// uses FIXED sec-ch-ua / sec-ch-ua-platform headers (see context.rs / manager.rs).
// ---------------------------------------------------------------------------

const USER_AGENT_POOL: &[&str] = &[
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
];

// UA templates by OS, with the Chrome major substituted at runtime so the advertised
// version matches the REAL browser binary (no stale "Chrome/120 on a 149 engine").
// 1:1 with Python automation_engine._UA_TEMPLATES.
const UA_TEMPLATES: &[&str] = &[
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36",
];

const LOCALE_POOL: &[&str] = &["en-US", "en-GB", "en"];

const TIMEZONE_POOL: &[&str] = &[
    "America/New_York",
    "America/Los_Angeles",
    "America/Chicago",
    "America/Toronto",
];

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

/// Per-context browser fingerprint. 1:1 with Python: each field is chosen
/// independently at random from its pool (random.choice) on every context.
///
/// Serializable so a workflow's "warm" session can persist the exact fingerprint
/// used when auth was captured and restore it on later runs (returning user).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fingerprint {
    pub user_agent: String,
    pub locale: String,
    pub timezone: String,
}

impl Fingerprint {
    /// Randomly choose user_agent / locale / timezone — matches Python's
    /// `random.choice(...)` for each field independently.
    pub fn random() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize;
        Self {
            user_agent: pick(USER_AGENT_POOL, seed).to_string(),
            locale: pick(LOCALE_POOL, seed.wrapping_mul(31)).to_string(),
            timezone: pick(TIMEZONE_POOL, seed.wrapping_mul(37)).to_string(),
        }
    }

    /// Like `random()` but builds the UA from the REAL browser's Chrome major
    /// version (so the advertised version matches the engine). Pair with
    /// `build_stealth_headers()` which derives the client hints from this UA.
    pub fn random_for_chrome_major(chrome_major: &str) -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as usize;
        let uas = build_user_agents(chrome_major);
        Self {
            user_agent: uas[seed % uas.len()].clone(),
            locale: pick(LOCALE_POOL, seed.wrapping_mul(31)).to_string(),
            timezone: pick(TIMEZONE_POOL, seed.wrapping_mul(37)).to_string(),
        }
    }
}

/// Chrome major version (e.g. "149") from a Browser.version() like "149.0.7827.53".
pub fn chrome_major_from_version(version: &str) -> String {
    let digits: String = version
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    if digits.is_empty() { "120".to_string() } else { digits }
}

/// Chrome major version extracted from a UA string ("...Chrome/149.0...").
fn chrome_major_from_ua(ua: &str) -> String {
    if let Some(idx) = ua.find("Chrome/") {
        let digits: String = ua[idx + 7..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if !digits.is_empty() {
            return digits;
        }
    }
    "120".to_string()
}

/// UA pool for a given Chrome major version.
pub fn build_user_agents(chrome_major: &str) -> Vec<String> {
    UA_TEMPLATES
        .iter()
        .map(|t| t.replace("{major}", chrome_major))
        .collect()
}

/// Context-wide HTTP headers SAFE to apply to every request, with UA client hints
/// (sec-ch-ua version + platform) DERIVED from the user_agent so they never
/// contradict navigator.userAgent. 1:1 with Python automation_engine.build_stealth_headers.
///
/// Per-request headers (Accept, Accept-Encoding, Upgrade-Insecure-Requests and the
/// Sec-Fetch-* family) are intentionally OMITTED — the browser sets those per request;
/// forcing static values onto sub-resources breaks loads on Chrome 148+
/// (net::ERR_INVALID_ARGUMENT) and is itself a bot signal.
pub fn build_stealth_headers(user_agent: &str) -> HashMap<String, String> {
    let major = chrome_major_from_ua(user_agent);
    let platform = if user_agent.contains("Windows") {
        "\"Windows\""
    } else if user_agent.contains("Android") {
        "\"Android\""
    } else if user_agent.contains("Linux") {
        "\"Linux\""
    } else {
        "\"macOS\""
    };
    let mut h = HashMap::new();
    h.insert("Accept-Language".to_string(), "en-US,en;q=0.9".to_string());
    h.insert(
        "sec-ch-ua".to_string(),
        format!(
            "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"{m}\", \"Google Chrome\";v=\"{m}\"",
            m = major
        ),
    );
    h.insert("sec-ch-ua-mobile".to_string(), "?0".to_string());
    h.insert("sec-ch-ua-platform".to_string(), platform.to_string());
    h
}

/// Deterministic pick from a pool given a seed value (cheap spread, no `rand` crate).
fn pick<'a>(pool: &[&'a str], seed: usize) -> &'a str {
    pool[seed % pool.len()]
}

// ---------------------------------------------------------------------------
// Chromium launch arguments
// ---------------------------------------------------------------------------

/// The ALWAYS-ON, hardened base flags passed to Chromium on launch. These are anti-detection and
/// stability tweaks only — none of them weaken an OS/browser security boundary. The dangerous flags
/// that DO weaken a boundary (sandbox / TLS validation / same-origin policy) were split out into the
/// opt-in [`SANDBOX_DISABLE_ARGS`] / [`IGNORE_CERT_ERRORS_ARGS`] / [`DISABLE_WEB_SECURITY_ARGS`]
/// groups below and are OFF by default; use [`build_launch_args`] to assemble the final argv.
pub const CHROMIUM_LAUNCH_ARGS: &[&str] = &[
    // Core anti-detection flags (matches Python recorder.py start_session)
    "--disable-blink-features=AutomationControlled",
    "--disable-features=IsolateOrigins,site-per-process",
    "--disable-site-isolation-trials",
    // Remove automation indicators
    "--disable-infobars",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--disable-component-update",
    "--disable-default-apps",
    "--disable-hang-monitor",
    "--disable-popup-blocking",
    "--disable-prompt-on-repost",
    "--disable-sync",
    "--disable-translate",
    // Performance and stability
    "--disable-dev-shm-usage",
    // Memory
    "--disable-features=TranslateUI",
    "--metrics-recording-only",
    "--no-first-run",
    "--safebrowsing-disable-auto-update",
    // Remove Chrome automation flags
    "--flag-switches-begin",
    "--flag-switches-end",
    // Additional hardening (from automation_engine.py)
    "--disable-background-networking",
    "--disable-breakpad",
    "--disable-client-side-phishing-detection",
    "--disable-component-extensions-with-background-pages",
    "--disable-extensions",
    "--disable-ipc-flooding-protection",
    "--enable-features=NetworkService,NetworkServiceInProcess",
    "--force-color-profile=srgb",
    "--password-store=basic",
    "--use-mock-keychain",
    "--disable-gpu",
    "--hide-scrollbars",
    "--mute-audio",
    "--window-size=1920,1080",
];

// ---------------------------------------------------------------------------
// DANGEROUS, opt-in launch flags — each disables a real security boundary.
//
// These default OFF and are turned on ONLY when the user explicitly enables the matching toggle in
// Settings → Runtime → "Browser security (advanced)" (see `local::config` `browser_disable_sandbox`
// / `browser_ignore_certificate_errors` / `browser_disable_web_security`, threaded through
// `config::env::AppConfig`). NEVER add any of these to `CHROMIUM_LAUNCH_ARGS`.
// ---------------------------------------------------------------------------

/// Disable Chromium's OS-level renderer sandbox. Removing it means a renderer exploit (a malicious
/// page hitting a Chromium bug) runs with the daemon user's FULL privileges — no OS containment.
/// Only enable on a platform/container where the sandbox genuinely cannot initialize.
pub const SANDBOX_DISABLE_ARGS: &[&str] =
    &["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu-sandbox"];

/// Make the browser accept ANY TLS certificate. Any on-path attacker can then MITM the sites an
/// automated session logs into (intercepting cookies / filled passwords / TOTP). Only for trusted
/// lab targets with self-signed certs.
pub const IGNORE_CERT_ERRORS_ARGS: &[&str] = &["--ignore-certificate-errors"];

/// Disable the same-origin policy for every page in the automation browser (cross-origin reads/writes
/// become possible inside a context that carries the user's real logged-in state).
pub const DISABLE_WEB_SECURITY_ARGS: &[&str] = &["--disable-web-security"];

/// Assemble the final Chromium argv: the always-on hardened [`CHROMIUM_LAUNCH_ARGS`] base plus any of
/// the DANGEROUS opt-in groups the user explicitly enabled. All three toggles default `false`
/// (secure); a plain call with everything `false` yields exactly the hardened base.
pub fn build_launch_args(
    disable_sandbox: bool,
    ignore_certificate_errors: bool,
    disable_web_security: bool,
) -> Vec<String> {
    let mut args: Vec<String> = CHROMIUM_LAUNCH_ARGS.iter().map(|s| s.to_string()).collect();
    if disable_sandbox {
        args.extend(SANDBOX_DISABLE_ARGS.iter().map(|s| s.to_string()));
    }
    if ignore_certificate_errors {
        args.extend(IGNORE_CERT_ERRORS_ARGS.iter().map(|s| s.to_string()));
    }
    if disable_web_security {
        args.extend(DISABLE_WEB_SECURITY_ARGS.iter().map(|s| s.to_string()));
    }
    args
}

// ---------------------------------------------------------------------------
// Context lifetime safety
// ---------------------------------------------------------------------------

/// RAII guard that CLOSES a [`playwright_rs::BrowserContext`] when it is dropped, unless it was
/// disarmed first.
///
/// ## Why this has to exist
/// The vendored `playwright-rs` implements `Drop` on exactly ONE type — `Playwright` itself.
/// `BrowserContext` and `Page` have **no** `Drop`, so dropping the Rust handle does nothing to the
/// browser: the context, its renderer processes and its memory stay alive inside Chromium until
/// somebody `await`s `close()`. Closing is therefore purely manual, and every path that unwinds or
/// is cancelled past its `close()` call strands a context.
///
/// That is not a theoretical edge: a task `abort()` (a lost coordinator connection, a shutdown, a
/// timeout) drops the future mid-flight, and a panic inside a step unwinds past the explicit close.
/// Each occurrence leaks one context; over a month of flappy connectivity RSS climbs until the
/// resource governor's memory watermark sheds all background work and the worker degrades into
/// "accepts dispatch, rejects everything" with nothing in the logs pointing at the cause.
///
/// ## Contract
/// * Arm it immediately after creating a context: `let mut g = ContextCloseGuard::new(ctx.clone());`
///   (`BrowserContext` is a cheap `Clone` handle over the same remote object.)
/// * On the deterministic exit paths call [`ContextCloseGuard::close`] (awaited — prompt cleanup) or
///   [`ContextCloseGuard::disarm`] when the caller closes the context itself.
/// * If neither happens (panic / cancellation), `Drop` detaches a best-effort close.
///
/// `Drop` cannot `await`, so it spawns the close onto the CURRENT tokio runtime. It uses
/// [`tokio::runtime::Handle::try_current`] rather than `tokio::spawn` because the latter PANICS when
/// no runtime is active (a drop during runtime teardown, or in a sync test) — a cleanup guard must
/// never turn a leak into a panic. With no runtime the close is skipped and logged: the process is
/// going away anyway, which closes the browser with it.
pub struct ContextCloseGuard {
    context: Option<playwright_rs::BrowserContext>,
}

impl ContextCloseGuard {
    /// Arm a guard over `context` (pass a clone; the handle is cheap).
    pub fn new(context: playwright_rs::BrowserContext) -> Self {
        Self { context: Some(context) }
    }

    /// Cancel the guard — the caller takes responsibility for closing the context. Drop becomes a
    /// no-op. Idempotent.
    pub fn disarm(&mut self) {
        self.context = None;
    }

    /// Close the context NOW (awaited) and disarm. Idempotent: a second call is a no-op, so this is
    /// safe on a path that may already have closed. Errors are swallowed — a close failure means the
    /// context is already gone, which is the outcome we wanted.
    pub async fn close(&mut self) {
        if let Some(context) = self.context.take() {
            let _ = context.close().await;
        }
    }

    /// Whether the guard still owns a context to close (for tests / assertions).
    pub fn is_armed(&self) -> bool {
        self.context.is_some()
    }
}

impl Drop for ContextCloseGuard {
    fn drop(&mut self) {
        let Some(context) = self.context.take() else { return };
        // Only reachable when a deterministic path did NOT run (panic unwind, future cancellation,
        // an early `?` that forgot to close). Say so at warn: a silent close here would hide the
        // very leak this guard exists to make visible.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                tracing::warn!(
                    "closing a browser context from its drop guard (the owning task unwound or was \
                     cancelled) — this is leak protection, not the normal path"
                );
                handle.spawn(async move {
                    let _ = context.close().await;
                });
            }
            Err(_) => {
                // No runtime to spawn onto (runtime teardown / sync drop). Nothing async can run;
                // the browser dies with the process.
                tracing::warn!(
                    "browser context dropped with no tokio runtime available — cannot close it \
                     (process teardown)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_fields_not_empty() {
        let fp = Fingerprint::random();
        assert!(!fp.user_agent.is_empty());
        assert!(!fp.locale.is_empty());
        assert!(!fp.timezone.is_empty());
    }

    #[test]
    fn launch_args_reasonable_count() {
        assert!(CHROMIUM_LAUNCH_ARGS.len() >= 30);
    }

    /// The hardened base must NEVER carry a security-boundary-disabling flag — those are opt-in only.
    #[test]
    fn base_args_contain_no_dangerous_flags() {
        for dangerous in ["--no-sandbox", "--disable-setuid-sandbox", "--disable-gpu-sandbox", "--ignore-certificate-errors", "--disable-web-security"] {
            assert!(
                !CHROMIUM_LAUNCH_ARGS.contains(&dangerous),
                "{dangerous} must not be in the always-on base"
            );
        }
    }

    /// `build_launch_args` = the base when all toggles are off, and appends exactly the enabled group.
    #[test]
    fn build_launch_args_gates_dangerous_flags() {
        let secure = build_launch_args(false, false, false);
        assert_eq!(secure.len(), CHROMIUM_LAUNCH_ARGS.len(), "all-off == the hardened base");
        for dangerous in ["--no-sandbox", "--ignore-certificate-errors", "--disable-web-security"] {
            assert!(!secure.iter().any(|a| a == dangerous), "{dangerous} absent by default");
        }

        let sandbox_off = build_launch_args(true, false, false);
        assert!(sandbox_off.iter().any(|a| a == "--no-sandbox"));
        assert!(sandbox_off.iter().any(|a| a == "--disable-setuid-sandbox"));
        assert!(!sandbox_off.iter().any(|a| a == "--ignore-certificate-errors"));

        let all_on = build_launch_args(true, true, true);
        assert!(all_on.iter().any(|a| a == "--ignore-certificate-errors"));
        assert!(all_on.iter().any(|a| a == "--disable-web-security"));
        assert_eq!(
            all_on.len(),
            CHROMIUM_LAUNCH_ARGS.len()
                + SANDBOX_DISABLE_ARGS.len()
                + IGNORE_CERT_ERRORS_ARGS.len()
                + DISABLE_WEB_SECURITY_ARGS.len()
        );
    }
}
