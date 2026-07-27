use std::path::{Path, PathBuf};

use playwright_rs::Page;
use tokio::sync::mpsc;

pub const STREAMING_RUNTIME_JS: &str = include_str!("../../js/streaming_runtime.js");

/// Placeholder in `streaming_runtime.js` replaced at injection time with the
/// per-session capability token. The trusted runtime captures this token in a
/// closure (it is NOT exposed on `window.ps`) and forwards it as the first
/// argument to EVERY bridge. See SECURITY note on [`check_token`].
const BRIDGE_TOKEN_PLACEHOLDER: &str = "__PS_BRIDGE_TOKEN__";

/// Placeholder in `streaming_runtime.js` replaced at injection time with the
/// per-session binding namespace, so the bridge globals do not have guessable
/// names (`window.__ps_pw_click` → `window.__ps_<32 hex>_pw_click`).
const BRIDGE_NS_PLACEHOLDER: &str = "__PS_BRIDGE_NS__";

/// The base names of every bridge exposed onto the page, in the order they are
/// registered. `js/streaming_runtime.js` carries the SAME list (`_names`) and
/// derives `window['__ps_' + ns + '_' + base]` from it — the unit test
/// `js_runtime_lists_every_binding_base_name` keeps the two in lockstep, because
/// a name that exists on only one side is a silently dead capability.
pub const BRIDGE_BASE_NAMES: &[&str] = &[
    // Relay bridges (page → coordinator).
    "emit",
    "respond",
    "stream",
    "log",
    // Playwright bridges (page → real Playwright, resolved against the MAIN frame).
    "pw_click",
    "pw_fill",
    "pw_type",
    "pw_press",
    "pw_wait_for",
    "pw_text_content",
    "pw_evaluate",
    "pw_select_option",
    "pw_screenshot",
    "pw_upload_file",
    "pw_upload_files_to_input",
];

/// The two per-session secrets guarding the page bridges.
///
/// SECURITY — why two, and why the token is on ALL of them:
///
/// Playwright's `exposeBinding` installs the global into **every frame** of the
/// page, while the Rust side of each bridge (`Page::locator`, `Page::screenshot`,
/// `Page::evaluate`) resolves against the **main frame**. A streaming target is by
/// design a logged-in site, so a third-party iframe (ad, embedded widget, an
/// injected `<iframe>` after XSS) that can call a bridge reads and drives the TOP
/// document — a same-origin-policy bypass. `__ps_respond` additionally lets any
/// frame fabricate a `command_response` back to the coordinator.
///
/// The vendored playwright crate cannot tell us which frame made a binding call
/// (see the module note on `expose_binding`), so the frame check is enforced
/// *inside* the injected runtime instead: `streaming_runtime.js` returns
/// immediately unless `window.top === window`, so only the main frame ever holds
/// `token` in a closure. A subframe therefore cannot supply argument 0 and every
/// bridge rejects it.
///
/// * `namespace` — randomises the binding NAMES. Blocks blind/drive-by calls to a
///   documented global (`window.__ps_pw_text_content('input[type=password]')`).
///   NOT sufficient alone: `Object.getOwnPropertyNames(window)` in any frame still
///   discloses the name, which is exactly why the token exists.
/// * `token` — required as argument 0 of every bridge. Never on `window`, never in
///   `window.ps`, and a different value from `namespace` so leaking the binding
///   name does not leak the token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeSecret {
    namespace: String,
    token: String,
}

impl BridgeSecret {
    /// Generate a fresh pair. 128 bits each from v4 UUIDs (hex, so the namespace is
    /// a legal JS identifier fragment).
    fn generate() -> Self {
        Self {
            namespace: uuid::Uuid::new_v4().simple().to_string(),
            token: uuid::Uuid::new_v4().simple().to_string(),
        }
    }

    /// Wire form. The public API carries the secret as ONE opaque `String` (through
    /// `StreamingSessionManager::set_bridge_token` and `reinject_runtime`), so both
    /// halves travel together and callers outside this module stay unchanged.
    pub fn encode(&self) -> String {
        format!("{}.{}", self.namespace, self.token)
    }

    /// Parse [`encode`](Self::encode). Returns `None` for anything that is not two
    /// non-empty ASCII-alphanumeric halves — the namespace is interpolated into JS
    /// as an identifier fragment, so it must never carry quotes/backslashes even
    /// though it is agent-generated (defence against a future caller passing
    /// something wire-derived).
    pub fn decode(s: &str) -> Option<Self> {
        let (namespace, token) = s.split_once('.')?;
        if namespace.is_empty() || token.is_empty() {
            return None;
        }
        if !namespace.bytes().all(|b| b.is_ascii_alphanumeric())
            || !token.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return None;
        }
        Some(Self {
            namespace: namespace.to_string(),
            token: token.to_string(),
        })
    }

    /// The `window` global name for one bridge.
    fn binding(&self, base: &str) -> String {
        format!("__ps_{}_{}", self.namespace, base)
    }
}

/// SECURITY: validate the capability token that the trusted runtime prepends to
/// EVERY bridge call. Bindings are installed in every frame of the page and are
/// reachable by any script there (the site itself, injected ads, XSS), so no
/// bridge — not the Playwright drivers, not the relay bridges — may act without
/// the per-session secret. Untrusted script cannot read the token because it
/// lives only in the main frame runtime's injection-time closure.
/// Returns the remaining args (with the token stripped) if valid, else None.
fn check_token<'a>(
    args: &'a [serde_json::Value],
    expected: &str,
) -> Option<&'a [serde_json::Value]> {
    match args.first().and_then(|v| v.as_str()) {
        Some(tok) if !expected.is_empty() && tok == expected => Some(&args[1..]),
        _ => None,
    }
}

/// Create a fresh, random, private directory for one bridge upload call.
///
/// SECURITY: `safe_temp_path` stops traversal, but the basename is still fully
/// page-chosen — writing it straight into the shared `$TMPDIR` lets the page
/// clobber a predictable path (or pre-create it as a symlink and have us write
/// through it). A random per-call directory makes the full path unpredictable and
/// unshared. Mode 0o700 on unix so other local users cannot pre-seed entries.
fn new_upload_dir() -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("writ-bridge-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

/// Derive a safe path inside `dir` from an attacker-controlled `name`.
/// SECURITY: `Path::join` with an absolute path or `..` components would escape
/// `dir` (arbitrary file write). We keep only the final path component and reject
/// anything that isn't a plain, non-traversing filename.
fn safe_temp_path(dir: &Path, name: &str) -> Option<PathBuf> {
    let file_name = Path::new(name).file_name()?;
    let file_name = file_name.to_str()?;
    if file_name.is_empty() || file_name == "." || file_name == ".." {
        return None;
    }
    // file_name() already strips directory components, but be explicit.
    if file_name.contains('/') || file_name.contains('\\') {
        return None;
    }
    Some(dir.join(file_name))
}

/// Render `streaming_runtime.js` with a session's secrets substituted in.
/// `None` renders an INERT runtime (blank namespace + blank token) for the
/// fallback paths that expose no bridges at all.
pub fn render_runtime_js(secret: Option<&BridgeSecret>) -> String {
    let (ns, tok) = match secret {
        Some(s) => (s.namespace.as_str(), s.token.as_str()),
        None => ("", ""),
    };
    STREAMING_RUNTIME_JS
        .replace(BRIDGE_NS_PLACEHOLDER, ns)
        .replace(BRIDGE_TOKEN_PLACEHOLDER, tok)
}

/// Render the runtime for an opaque encoded token (the form carried by the public
/// API). An unparseable/empty token renders the inert runtime.
pub fn render_runtime_js_for_token(bridge_token: &str) -> String {
    render_runtime_js(BridgeSecret::decode(bridge_token).as_ref())
}

/// Messages emitted by bridge functions back to the SaaS bridge.
#[derive(Debug, Clone)]
pub enum BridgeEvent {
    Emit { name: String, data: serde_json::Value },
    Respond { request_id: String, data: serde_json::Value },
    Stream { request_id: String, chunk: serde_json::Value },
    Log { message: String },
}

/// Set up the runtime bridge on a Playwright page.
///
/// Uses `page.expose_function()` to create real JS→Rust callbacks, then installs
/// the trusted runtime with `page.add_init_script()` so it runs BEFORE any page
/// script on every document (see [`install_runtime`]).
///
/// Returns the per-session bridge secret in its opaque encoded form, which the
/// caller must pass to `setup_reinject_listeners` / `set_bridge_token` so
/// re-injected runtimes use the same secrets.
///
/// CALL THIS BEFORE THE FIRST NAVIGATION when you can: `add_init_script` only
/// governs documents created after it is registered, so registering pre-navigation
/// is what guarantees the trusted runtime beats the target site's own scripts to
/// the bindings.
pub async fn setup_runtime_bridge(
    page: &Page,
    event_tx: mpsc::UnboundedSender<BridgeEvent>,
) -> Result<String, anyhow::Error> {
    setup_runtime_bridge_with_token(page, event_tx, None).await
}

/// Like `setup_runtime_bridge`, but lets the caller pin a shared per-session
/// secret across multiple tabs (e.g. multi-conversation thread tabs that belong
/// to one streaming session). When `None` (or unparseable), a fresh one is made.
pub async fn setup_runtime_bridge_with_token(
    page: &Page,
    event_tx: mpsc::UnboundedSender<BridgeEvent>,
    token: Option<String>,
) -> Result<String, anyhow::Error> {
    tracing::debug!("Setting up runtime bridge with expose_function");

    // Per-session capability secrets guarding EVERY bridge below. Injected into the
    // trusted runtime; untrusted page script and every subframe are shut out. See
    // BridgeSecret + check_token.
    let secret = match token.as_deref().map(BridgeSecret::decode) {
        Some(Some(s)) => s,
        Some(None) => {
            // A caller handed us something that isn't a bridge secret (e.g. a token
            // minted by an older build). Mint a fresh pair rather than running with a
            // half-parsed secret — the bindings and the runtime always agree because
            // both are derived from `secret` below.
            tracing::warn!("Pinned bridge token was not a valid bridge secret — generating a fresh one");
            BridgeSecret::generate()
        }
        None => BridgeSecret::generate(),
    };
    let tok = secret.token.clone();

    // 1. Expose emit/respond/stream/log bridges
    // expose_function passes args as serde_json::Value directly (already parsed).
    // If the JS side passes a string, it arrives as Value::String.
    // If it passes an object, it arrives as Value::Object.
    // We handle both cases. Argument 0 is ALWAYS the capability token.

    let tx = event_tx.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("emit"), move |args: Vec<serde_json::Value>| {
        let tx = tx.clone();
        let t = t.clone();
        async move {
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let name = value_to_string(args, 0);
            let data = value_to_json(args, 1);
            // Log hygiene: bridge payloads may carry user/page data and hit the
            // rolling file. Log only the event name + arg count at debug; the full
            // payload is trace-only.
            tracing::debug!(event = %name, args = args.len(), "emit bridge called");
            tracing::trace!(all_args = %serde_json::to_string(args).unwrap_or_default(), "emit bridge payload");
            let _ = tx.send(BridgeEvent::Emit { name, data });
            ok_str()
        }
    }).await.map_err(|e| anyhow::anyhow!("expose emit bridge failed: {}", e))?;

    let tx = event_tx.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("respond"), move |args: Vec<serde_json::Value>| {
        let tx = tx.clone();
        let t = t.clone();
        async move {
            // SECURITY: without this guard ANY frame could fabricate a
            // `command_response` for an in-flight turn back to the coordinator.
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let request_id = value_to_string(args, 0);
            let data = value_to_json(args, 1);
            // Log hygiene: the response payload can be large / carry user data. Log
            // only the request id + payload size at debug; full payload is trace.
            tracing::debug!(
                request_id = %request_id,
                args_len = args.len(),
                data_len = serde_json::to_string(&data).map(|s| s.len()).unwrap_or(0),
                "respond bridge called"
            );
            tracing::trace!(
                request_id = %request_id,
                parsed_data = %serde_json::to_string(&data).unwrap_or_default(),
                "respond bridge payload"
            );
            let _ = tx.send(BridgeEvent::Respond { request_id, data });
            ok_str()
        }
    }).await.map_err(|e| anyhow::anyhow!("expose respond bridge failed: {}", e))?;

    let tx = event_tx.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("stream"), move |args: Vec<serde_json::Value>| {
        let tx = tx.clone();
        let t = t.clone();
        async move {
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let request_id = value_to_string(args, 0);
            let chunk = value_to_json(args, 1);
            let _ = tx.send(BridgeEvent::Stream { request_id, chunk });
            ok_str()
        }
    }).await.map_err(|e| anyhow::anyhow!("expose stream bridge failed: {}", e))?;

    let tx = event_tx.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("log"), move |args: Vec<serde_json::Value>| {
        let tx = tx.clone();
        let t = t.clone();
        async move {
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let msg = value_to_string(args, 0);
            let _ = tx.send(BridgeEvent::Log { message: msg });
            ok_str()
        }
    }).await.map_err(|e| anyhow::anyhow!("expose log bridge failed: {}", e))?;

    // 2. Expose Playwright bridge functions (pw_click, pw_fill, …).
    // Each callback clones the page and calls the REAL Playwright API. NOTE these
    // resolve against the MAIN frame, which is precisely why the token gate above
    // and the main-frame gate in streaming_runtime.js are mandatory.

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_click"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let selector = value_to_string(args, 0);
            tracing::debug!(selector = %selector, "pw_click");
            match p.locator(&selector).await.click(None).await {
                Ok(_) => ok_str(),
                Err(e) => err_str(&e.to_string()),
            }
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_click failed: {}", e))?;

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_fill"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let selector = value_to_string(args, 0);
            let value = value_to_string(args, 1);
            tracing::debug!(selector = %selector, value_len = value.len(), "pw_fill");
            match p.locator(&selector).await.fill(&value, None).await {
                Ok(_) => ok_str(),
                Err(e) => err_str(&e.to_string()),
            }
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_fill failed: {}", e))?;

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_type"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let selector = value_to_string(args, 0);
            let text = value_to_string(args, 1);
            tracing::debug!(selector = %selector, text_len = text.len(), "pw_type");
            let _ = p.locator(&selector).await.click(None).await;
            match p.keyboard().type_text(&text, None).await {
                Ok(_) => ok_str(),
                Err(e) => err_str(&e.to_string()),
            }
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_type failed: {}", e))?;

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_press"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let key = value_to_string(args, 0);
            tracing::debug!(key = %key, "pw_press");
            match p.keyboard().press(&key, None).await {
                Ok(_) => ok_str(),
                Err(e) => err_str(&e.to_string()),
            }
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_press failed: {}", e))?;

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_wait_for"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let selector = value_to_string(args, 0);
            tracing::debug!(selector = %selector, "pw_wait_for");
            let opts = playwright_rs::WaitForOptions {
                state: Some(playwright_rs::WaitForState::Visible),
                timeout: Some(10000.0),
            };
            match p.locator(&selector).await.wait_for(Some(opts)).await {
                Ok(_) => ok_str(),
                Err(e) => err_str(&e.to_string()),
            }
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_wait_for failed: {}", e))?;

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_text_content"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            // SECURITY: this reads the MAIN frame. Ungated it let any iframe
            // exfiltrate the top document (e.g. `input[type=password]`).
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let selector = value_to_string(args, 0);
            tracing::debug!(selector = %selector, "pw_text_content");
            match p.locator(&selector).await.text_content().await {
                Ok(Some(text)) => {
                    // serde_json escapes control chars / unicode correctly; manual
                    // \ and " escaping leaves newlines etc. unescaped → invalid JSON.
                    serde_json::Value::String(
                        serde_json::json!({ "ok": true, "value": text }).to_string(),
                    )
                }
                Ok(None) => serde_json::Value::String(r#"{"ok":true,"value":null}"#.to_string()),
                Err(e) => err_str(&e.to_string()),
            }
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_text_content failed: {}", e))?;

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_evaluate"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            // SECURITY: gate arbitrary JS eval behind the per-session token.
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let js_code = value_to_string(args, 0);
            tracing::debug!(js_len = js_code.len(), "pw_evaluate");
            match p.evaluate::<(), serde_json::Value>(&js_code, None::<&()>).await {
                Ok(val) => {
                    let val_str = serde_json::to_string(&val).unwrap_or("null".to_string());
                    serde_json::Value::String(format!(r#"{{"ok":true,"value":{}}}"#, val_str))
                }
                Err(e) => err_str(&e.to_string()),
            }
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_evaluate failed: {}", e))?;

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_select_option"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let selector = value_to_string(args, 0);
            let value = value_to_string(args, 1);
            tracing::debug!(selector = %selector, value = %value, "pw_select_option");
            match p.locator(&selector).await.select_option(
                playwright_rs::SelectOption::Value(value), None
            ).await {
                Ok(_) => ok_str(),
                Err(e) => err_str(&e.to_string()),
            }
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_select_option failed: {}", e))?;

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_screenshot"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            // SECURITY: this captures the MAIN frame. Ungated it let any iframe
            // screenshot the logged-in top document.
            if check_token(&args, &t).is_none() {
                return err_str("unauthorized bridge call");
            }
            tracing::debug!("pw_screenshot");
            let opts = playwright_rs::ScreenshotOptions {
                screenshot_type: Some(playwright_rs::ScreenshotType::Jpeg),
                quality: Some(50),
                ..Default::default()
            };
            match p.screenshot(Some(opts)).await {
                Ok(bytes) => {
                    let b64 = base64::Engine::encode(
                        &base64::engine::general_purpose::STANDARD, &bytes
                    );
                    serde_json::Value::String(format!(r#"{{"ok":true,"value":"{}"}}"#, b64))
                }
                Err(e) => err_str(&e.to_string()),
            }
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_screenshot failed: {}", e))?;

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_upload_file"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            // SECURITY: gate file write/upload behind the per-session token.
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let trigger_selector = value_to_string(args, 0);
            let file_json_str = value_to_string(args, 1);
            tracing::debug!(trigger = %trigger_selector, "pw_upload_file");

            let file_info: serde_json::Value = match serde_json::from_str(&file_json_str) {
                Ok(v) => v,
                Err(e) => return err_str(&format!("Invalid file JSON: {}", e)),
            };

            let name = file_info["name"].as_str().unwrap_or("file.bin");
            let _mime = file_info["mime"].as_str().unwrap_or("application/octet-stream");
            let b64 = file_info["base64"].as_str().unwrap_or("");

            let bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
                Ok(b) => b,
                Err(e) => return err_str(&format!("Base64 decode failed: {}", e)),
            };

            // SECURITY: write into a fresh random private directory, using the
            // basename only — never an attacker-supplied absolute path, `..`
            // traversal, or a predictable path in the shared $TMPDIR.
            let dir = match new_upload_dir() {
                Ok(d) => d,
                Err(e) => return err_str(&format!("Temp dir failed: {}", e)),
            };
            let tmp_path = match safe_temp_path(&dir, name) {
                Some(p) => p,
                None => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return err_str("Invalid file name");
                }
            };
            if let Err(e) = std::fs::write(&tmp_path, &bytes) {
                let _ = std::fs::remove_dir_all(&dir);
                return err_str(&format!("Write temp file failed: {}", e));
            }

            let locator = p.locator(&trigger_selector).await;
            let result = match locator.set_input_files(&tmp_path, None).await {
                Ok(_) => ok_str(),
                Err(e) => err_str(&e.to_string()),
            };
            let _ = std::fs::remove_dir_all(&dir);
            result
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_upload_file failed: {}", e))?;

    let p = page.clone();
    let t = tok.clone();
    page.expose_function(&secret.binding("pw_upload_files_to_input"), move |args: Vec<serde_json::Value>| {
        let p = p.clone();
        let t = t.clone();
        async move {
            // SECURITY: gate file write/upload behind the per-session token.
            let Some(args) = check_token(&args, &t) else {
                return err_str("unauthorized bridge call");
            };
            let selector = value_to_string(args, 0);
            let files_json_str = value_to_string(args, 1);
            tracing::debug!(selector = %selector, "pw_upload_files_to_input");

            let files: Vec<serde_json::Value> = match serde_json::from_str(&files_json_str) {
                Ok(v) => v,
                Err(e) => return err_str(&format!("Invalid files JSON: {}", e)),
            };

            // One private directory for the whole batch (see new_upload_dir).
            let dir = match new_upload_dir() {
                Ok(d) => d,
                Err(e) => return err_str(&format!("Temp dir failed: {}", e)),
            };
            let mut paths = Vec::new();

            for file in &files {
                let name = file["name"].as_str().unwrap_or("file.bin");
                let b64 = file["base64"].as_str().unwrap_or("");
                let bytes = match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
                    Ok(b) => b,
                    Err(e) => {
                        let _ = std::fs::remove_dir_all(&dir);
                        return err_str(&format!("Base64 decode failed: {}", e));
                    }
                };
                // SECURITY: basename-only, inside the private dir (see safe_temp_path).
                let path = match safe_temp_path(&dir, name) {
                    Some(p) => p,
                    None => {
                        let _ = std::fs::remove_dir_all(&dir);
                        return err_str("Invalid file name");
                    }
                };
                if let Err(e) = std::fs::write(&path, &bytes) {
                    let _ = std::fs::remove_dir_all(&dir);
                    return err_str(&format!("Write temp file failed: {}", e));
                }
                paths.push(path);
            }

            let locator = p.locator(&selector).await;
            let path_refs: Vec<&PathBuf> = paths.iter().collect();
            let result = match locator.set_input_files_multiple(&path_refs, None).await {
                Ok(_) => ok_str(),
                Err(e) => err_str(&e.to_string()),
            };

            let _ = std::fs::remove_dir_all(&dir);
            result
        }
    }).await.map_err(|e| anyhow::anyhow!("expose pw_upload_files_to_input failed: {}", e))?;

    // 3. Install the trusted runtime (window.ps) with the per-session secrets.
    install_runtime(page, &secret).await?;

    tracing::info!(
        bindings = BRIDGE_BASE_NAMES.len(),
        "Runtime bridge set up (all bindings token-gated, main-frame only)"
    );
    Ok(secret.encode())
}

/// Install the trusted runtime so it wins the race against page script.
///
/// SECURITY: `add_init_script` runs the runtime BEFORE any script of every
/// document created afterwards, in each frame. That matters for two reasons:
///  * Playwright installs bindings as ordinary WRITABLE window properties. If page
///    script runs first it can wrap `window.__ps_<ns>_pw_click`, wait for the first
///    legitimate call, and capture argument 0 — the capability token. Running first
///    lets the runtime capture the genuine functions into its closure (and lock the
///    properties down) so a later wrapper is simply bypassed.
///  * The main-frame gate in the runtime relies on `window.top` not having been
///    shadowed yet, which only an init script can guarantee.
///
/// The `evaluate_expression` afterwards covers the CURRENT document, which already
/// exists and therefore cannot be reached by an init script. Callers should invoke
/// `setup_runtime_bridge` BEFORE the first navigation so that the only document
/// covered by the (inherently racy) immediate path is `about:blank`.
async fn install_runtime(page: &Page, secret: &BridgeSecret) -> Result<(), anyhow::Error> {
    let runtime_js = render_runtime_js(Some(secret));
    page.add_init_script(&runtime_js)
        .await
        .map_err(|e| anyhow::anyhow!("Streaming runtime add_init_script failed: {}", e))?;
    page.evaluate_expression(&runtime_js)
        .await
        .map_err(|e| anyhow::anyhow!("Streaming runtime JS injection failed: {}", e))?;
    Ok(())
}

/// Record that the caller-supplied advanced script has been injected into the page's
/// CURRENT document, so [`reinject_runtime`] does not inject it a second time.
///
/// Callers that inject the advanced script themselves (the SaaS/fleet bridge and the
/// session manager both do it once at start-up) MUST call this — otherwise the first
/// re-inject pass sees an unmarked document and runs the script again, registering
/// every `ps.on` handler twice. `js/streaming_runtime.js` resets the flag on each new
/// document, so a navigation still triggers exactly one re-injection.
pub async fn mark_advanced_injected(page: &Page) {
    let _ = page
        .evaluate_expression("try{window.ps._advInjected=true}catch(e){}")
        .await;
}

/// Re-inject the streaming runtime AND advanced script if the current document
/// lost them.
///
/// With `add_init_script` in place (see [`install_runtime`]) `window.ps` is
/// normally already present on a fresh document, so this is a cheap no-op for the
/// runtime — but the ADVANCED script is caller-supplied and not part of the init
/// script, so it is tracked separately via `window.ps._advInjected`. Checking only
/// `window.ps` would silently stop re-injecting the advanced script after every
/// navigation.
pub async fn reinject_runtime(
    page: &Page,
    advanced_script: Option<&str>,
    bridge_token: &str,
) -> Result<(), anyhow::Error> {
    let has_ps: bool = page
        .evaluate("typeof window.ps !== 'undefined' && !!window.ps", None::<&()>)
        .await
        .unwrap_or(false);

    if !has_ps {
        tracing::info!("Page lost window.ps — re-injecting runtime");
        // Re-substitute the SAME per-session secrets (the expose_function bindings
        // persist across navigation and still expect this token + these names).
        let runtime_js = render_runtime_js_for_token(bridge_token);
        page.evaluate_expression(&runtime_js)
            .await
            .map_err(|e| anyhow::anyhow!("Runtime re-injection failed: {}", e))?;
    }

    if let Some(code) = advanced_script {
        if !code.is_empty() {
            let has_adv: bool = page
                .evaluate("!!(window.ps && window.ps._advInjected)", None::<&()>)
                .await
                .unwrap_or(false);
            if !has_adv {
                if let Err(e) = page.evaluate_expression(code).await {
                    tracing::warn!(error = %e, "Advanced script re-injection failed");
                } else {
                    // Mark THIS document as carrying the advanced script. The init
                    // script resets the flag to false on every new document.
                    mark_advanced_injected(page).await;
                    tracing::debug!("Advanced script (re-)injected");
                }
            }
        }
    }

    Ok(())
}

/// Register page event listeners that automatically re-inject the runtime +
/// advanced script after navigations/reloads.
///
/// playwright_rs has no `domcontentloaded` page event, so we use `on_load`
/// plus `on_framenavigated` (covers SPA route changes and early navigation). The
/// guards inside `reinject_runtime` make both idempotent.
pub async fn setup_reinject_listeners(
    page: &Page,
    advanced_script: Option<String>,
    bridge_token: String,
) {
    use std::sync::atomic::{AtomicBool, Ordering};
    // Coalescing guard: on a reload BOTH on_load and the main-frame on_framenavigated
    // fire (near-simultaneously), and a SPA can fire several in a burst. playwright_rs
    // tokio::spawns every page-event handler, and each re-inject does page I/O — so
    // overlapping re-injections pile up worker tasks and can starve the runtime, which
    // is what makes a manual hard-reload lag/freeze the headed browser. swap(true) lets
    // exactly one run at a time; the rest no-op (reinject_runtime's guards make
    // a slightly-late one harmless anyway).
    let reinjecting = std::sync::Arc::new(AtomicBool::new(false));

    // on_load — fires when the page finishes loading after a navigation/reload.
    {
        let p = page.clone();
        let adv = advanced_script.clone();
        let tok = bridge_token.clone();
        let guard = reinjecting.clone();
        let _ = page.on_load(move || {
            let p = p.clone();
            let adv = adv.clone();
            let tok = tok.clone();
            let guard = guard.clone();
            async move {
                if guard.swap(true, Ordering::SeqCst) {
                    return Ok(());
                }
                let _ = reinject_runtime(&p, adv.as_deref(), &tok).await;
                guard.store(false, Ordering::SeqCst);
                Ok(())
            }
        }).await;
    }

    // on_framenavigated — fires when a frame navigates. CRITICAL: only re-inject for the
    // MAIN frame. A heavy site (chatgpt.com) has many iframes/subframes; re-injecting on
    // every subframe navigation triggers a storm of page.evaluate calls (each spawned as
    // its own task) that starves the runtime and freezes the browser on a hard reload.
    // The runtime lives in the main frame's main world, so subframe navs are irrelevant.
    {
        let p = page.clone();
        let adv = advanced_script.clone();
        let tok = bridge_token.clone();
        let guard = reinjecting.clone();
        let _ = page.on_framenavigated(move |frame: playwright_rs::protocol::Frame| {
            let p = p.clone();
            let adv = adv.clone();
            let tok = tok.clone();
            let guard = guard.clone();
            async move {
                // parent_frame() == None  ⇒  this IS the main frame; skip all subframes.
                if frame.parent_frame().is_some() {
                    return Ok(());
                }
                if guard.swap(true, Ordering::SeqCst) {
                    return Ok(());
                }
                let _ = reinject_runtime(&p, adv.as_deref(), &tok).await;
                guard.store(false, Ordering::SeqCst);
                Ok(())
            }
        }).await;
    }

    tracing::info!("Streaming re-inject listeners registered (on_load + main-frame on_framenavigated)");
}

fn ok_str() -> serde_json::Value {
    serde_json::Value::String(r#"{"ok":true}"#.to_string())
}

fn err_str(msg: &str) -> serde_json::Value {
    // Build via serde_json so control chars / unicode in `msg` are escaped
    // correctly — hand-rolling only \ and " produces invalid JSON the page
    // can't parse. The bridge returns a JSON document as its (string) value.
    serde_json::Value::String(serde_json::json!({ "ok": false, "error": msg }).to_string())
}

/// Extract a string from args at index. Handles both Value::String and other types.
fn value_to_string(args: &[serde_json::Value], index: usize) -> String {
    match args.get(index) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// Extract a JSON value from args at index.
/// If it's a string, try to parse as JSON. If already an object/array, use directly.
fn value_to_json(args: &[serde_json::Value], index: usize) -> serde_json::Value {
    match args.get(index) {
        Some(serde_json::Value::String(s)) => {
            serde_json::from_str(s).unwrap_or(serde_json::Value::String(s.clone()))
        }
        Some(val) => val.clone(),
        None => serde_json::json!({}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn secret() -> BridgeSecret {
        BridgeSecret {
            namespace: "abc123".into(),
            token: "s3cr3t".into(),
        }
    }

    // ── Item 1: every bridge is token-gated ──────────────────────────────────

    #[test]
    fn check_token_accepts_only_the_exact_token_and_strips_it() {
        let args = vec![json!("s3cr3t"), json!("input[type=password]")];
        let rest = check_token(&args, "s3cr3t").expect("valid token");
        assert_eq!(rest.len(), 1, "token must be stripped from the arg list");
        assert_eq!(value_to_string(rest, 0), "input[type=password]");
    }

    #[test]
    fn check_token_rejects_missing_wrong_and_non_string_tokens() {
        // An iframe / page script that never saw the runtime closure looks like this.
        assert!(check_token(&[], "s3cr3t").is_none(), "no args");
        assert!(
            check_token(&[json!("input[type=password]")], "s3cr3t").is_none(),
            "caller passed the selector where the token belongs"
        );
        assert!(check_token(&[json!("s3cr3tx")], "s3cr3t").is_none(), "prefix/suffix");
        assert!(check_token(&[json!("s3cr3")], "s3cr3t").is_none(), "truncated");
        assert!(check_token(&[json!(null)], "s3cr3t").is_none(), "null");
        assert!(check_token(&[json!(1)], "s3cr3t").is_none(), "number");
        assert!(check_token(&[json!({"t": "s3cr3t"})], "s3cr3t").is_none(), "object");
    }

    #[test]
    fn check_token_fails_closed_when_no_token_was_configured() {
        // A blank expected token must NEVER authorise anything — otherwise the
        // "inert runtime" fallback paths would become a wide-open bridge.
        assert!(check_token(&[json!("")], "").is_none());
        assert!(check_token(&[json!("anything")], "").is_none());
    }

    #[test]
    fn every_binding_base_name_is_covered_by_the_registration_list() {
        // Guards the invariant the fix rests on: 15 bridges, one list, one gate.
        assert_eq!(BRIDGE_BASE_NAMES.len(), 15, "15 bridges are exposed");
        let mut sorted = BRIDGE_BASE_NAMES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), BRIDGE_BASE_NAMES.len(), "no duplicate base names");
    }

    #[test]
    fn js_runtime_lists_every_binding_base_name() {
        // The JS side derives window['__ps_' + ns + '_' + base] from its own list.
        // A base name present on only one side is a dead capability, so assert the
        // JS source mentions each one as a quoted list entry.
        for base in BRIDGE_BASE_NAMES {
            assert!(
                STREAMING_RUNTIME_JS.contains(&format!("'{base}'")),
                "js/streaming_runtime.js is missing bridge base name {base}"
            );
        }
    }

    #[test]
    fn js_runtime_never_hardcodes_the_old_guessable_globals() {
        // The old fixed names were callable by any script/frame that knew the docs.
        for legacy in [
            "window.__ps_pw_",
            "__ps_emit_bridge",
            "__ps_respond_bridge",
            "__ps_stream_bridge",
            "__ps_log_bridge",
        ] {
            assert!(
                !STREAMING_RUNTIME_JS.contains(legacy),
                "js/streaming_runtime.js still references the guessable global {legacy}"
            );
        }
    }

    #[test]
    fn js_runtime_gates_on_the_main_frame_and_forwards_the_token() {
        // The frame check the vendored playwright crate cannot give us on the Rust
        // side (no source/frame info on a binding call) lives here instead.
        assert!(
            STREAMING_RUNTIME_JS.contains("window.top !== window"),
            "runtime must refuse to install (and to learn the token) in a subframe"
        );
        assert!(
            STREAMING_RUNTIME_JS.contains(BRIDGE_TOKEN_PLACEHOLDER),
            "runtime must carry the capability-token placeholder"
        );
        assert!(
            STREAMING_RUNTIME_JS.contains(BRIDGE_NS_PLACEHOLDER),
            "runtime must carry the binding-namespace placeholder"
        );
    }

    #[test]
    fn js_runtime_exposes_a_per_document_advanced_script_marker() {
        // `add_init_script` means window.ps is present on every fresh document, so the
        // old `!window.ps` guard would never re-inject the caller's advanced script
        // again after a navigation. reinject_runtime tracks it separately.
        assert!(
            STREAMING_RUNTIME_JS.contains("_advInjected: false"),
            "the runtime must reset the advanced-script marker on each document"
        );
    }

    #[test]
    fn js_runtime_captures_and_locks_the_bindings_before_page_script_runs() {
        // Playwright installs bindings as writable properties; capturing them into the
        // closure (and locking the property) is what stops page script wrapping one to
        // read the capability token off a legitimate call.
        assert!(STREAMING_RUNTIME_JS.contains("_bound[base] = fn"));
        assert!(STREAMING_RUNTIME_JS.contains("writable: false"));
        assert!(STREAMING_RUNTIME_JS.contains("enumerable: false"));
        // Calls must go through the captured map, never a live window lookup.
        assert!(
            !STREAMING_RUNTIME_JS.contains("await window[fn]"),
            "a call-time window lookup would honour a page-installed wrapper"
        );
    }

    // ── Bridge secret encoding ───────────────────────────────────────────────

    #[test]
    fn bridge_secret_round_trips_and_keeps_the_halves_distinct() {
        let s = BridgeSecret::generate();
        assert_ne!(
            s.namespace, s.token,
            "leaking a binding name (enumerable on window) must not leak the token"
        );
        let decoded = BridgeSecret::decode(&s.encode()).expect("round trip");
        assert_eq!(decoded, s);
    }

    #[test]
    fn bridge_secret_generates_unique_pairs() {
        let a = BridgeSecret::generate();
        let b = BridgeSecret::generate();
        assert_ne!(a.namespace, b.namespace);
        assert_ne!(a.token, b.token);
    }

    #[test]
    fn bridge_secret_decode_rejects_non_identifier_input() {
        // The namespace is interpolated into JS as an identifier fragment.
        for bad in [
            "",
            "abc",                 // no separator
            ".tok",                // empty namespace
            "ns.",                 // empty token
            "n s.tok",             // space
            "ns'.tok",             // quote — would break out of the JS literal
            "ns\\.tok",            // backslash
            "ns\".tok",
            "ns.tok\n",
            "ns.<script>",
        ] {
            assert!(
                BridgeSecret::decode(bad).is_none(),
                "decode must reject {bad:?}"
            );
        }
    }

    #[test]
    fn binding_names_are_namespaced_per_session() {
        let s = secret();
        assert_eq!(s.binding("pw_click"), "__ps_abc123_pw_click");
        let other = BridgeSecret::generate();
        assert_ne!(
            s.binding("pw_click"),
            other.binding("pw_click"),
            "two sessions must not share a binding name"
        );
    }

    #[test]
    fn rendered_runtime_substitutes_both_secrets_and_leaves_no_placeholder() {
        let js = render_runtime_js(Some(&secret()));
        assert!(!js.contains(BRIDGE_TOKEN_PLACEHOLDER));
        assert!(!js.contains(BRIDGE_NS_PLACEHOLDER));
        assert!(js.contains("\"s3cr3t\""));
        assert!(js.contains("\"abc123\""));
    }

    #[test]
    fn rendered_runtime_for_missing_secret_is_inert() {
        // The fallback paths expose no bridges; the runtime must render with blank
        // secrets (and check_token then refuses everything — see the test above).
        for js in [render_runtime_js(None), render_runtime_js_for_token("")] {
            assert!(!js.contains(BRIDGE_TOKEN_PLACEHOLDER));
            assert!(!js.contains(BRIDGE_NS_PLACEHOLDER));
            assert!(js.contains("const _bridgeToken = \"\""));
        }
    }

    #[test]
    fn rendered_runtime_for_token_matches_the_decoded_secret() {
        let s = BridgeSecret::generate();
        assert_eq!(render_runtime_js_for_token(&s.encode()), render_runtime_js(Some(&s)));
    }

    // ── Item 4b: page-chosen upload filenames ────────────────────────────────

    #[test]
    fn safe_temp_path_keeps_the_basename_inside_the_private_dir() {
        let dir = Path::new("/tmp/writ-bridge-xyz");
        assert_eq!(
            safe_temp_path(dir, "report.pdf").unwrap(),
            dir.join("report.pdf")
        );
    }

    #[test]
    fn safe_temp_path_blocks_traversal_and_absolute_paths() {
        let dir = Path::new("/tmp/writ-bridge-xyz");
        for name in [
            "../../../etc/cron.d/pwn",
            "/etc/passwd",
            "..",
            ".",
            "",
            "a/b",
        ] {
            match safe_temp_path(dir, name) {
                None => {}
                Some(p) => assert!(
                    p.starts_with(dir) && p.parent() == Some(dir),
                    "{name:?} escaped the private dir as {p:?}"
                ),
            }
        }
    }

    #[test]
    fn upload_dirs_are_unique_and_unpredictable() {
        // Two calls must never collide on a shared path — the old code wrote the
        // page-chosen basename straight into $TMPDIR, which any local process (or
        // the page, repeatedly) could target.
        let a = new_upload_dir().expect("temp dir");
        let b = new_upload_dir().expect("temp dir");
        assert_ne!(a, b);
        assert!(a.starts_with(std::env::temp_dir()));
        assert!(
            a.file_name().unwrap().to_str().unwrap().starts_with("writ-bridge-"),
            "upload dirs should be identifiable for cleanup"
        );
        // Both live directly under $TMPDIR, and the page-chosen name lands inside.
        let inner = safe_temp_path(&a, "../escape.sh");
        assert!(inner.is_none() || inner.unwrap().parent() == Some(a.as_path()));
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }

    // ── Bridge plumbing regression cover ─────────────────────────────────────

    #[test]
    fn value_helpers_tolerate_missing_and_non_string_args() {
        let args = vec![json!("a"), json!({"k": 1}), json!(7)];
        assert_eq!(value_to_string(&args, 0), "a");
        assert_eq!(value_to_string(&args, 2), "7");
        assert_eq!(value_to_string(&args, 9), "");
        assert_eq!(value_to_json(&args, 1), json!({"k": 1}));
        assert_eq!(value_to_json(&args, 9), json!({}));
    }

    #[test]
    fn err_str_is_valid_json_even_for_hostile_messages() {
        let v = err_str("boom \"quoted\" \\ and \n newline");
        let s = v.as_str().expect("string value");
        let parsed: serde_json::Value = serde_json::from_str(s).expect("bridge error must be JSON");
        assert_eq!(parsed["ok"], json!(false));
        assert!(parsed["error"].as_str().unwrap().contains("newline"));
    }
}
