//! Tracing redaction + subscriber init — a last-line-of-defense scrub at the log SINK.
//!
//! House rule (`MEMORY` / ENGINEERING_GUIDELINES): the agent must NEVER log secrets, tokens,
//! persona credentials, extracted values, or `~/.writ` filesystem paths. The stores/handlers already
//! avoid logging those by construction; this layer is defense-in-depth so an accidental `?value` or a
//! third-party crate's log line can't leak material to a sink.
//!
//! ## Why this lives in `util` (ungated) and not in `local`
//! The scrubber was originally written for the desktop daemon (`local::logging`) and was therefore
//! compiled out of the managed-cloud `writ-agent` build — whose ROLLING FILE APPENDER (see [`init`])
//! consequently wrote every log line to disk unredacted. The engine is shared, so the scrub must be
//! too: it now lives here (no feature gate) and `local::logging` re-exports it for the desktop call
//! sites. There is exactly ONE set of patterns and ONE writer implementation for every binary.
//!
//! ## Approach — scrub the rendered line, not the fields
//! Rather than a field-visitor `Layer` (which only sees the events WE emit, and can't catch a
//! dependency's formatting), we wrap the `fmt` subscriber's WRITER. Every fully-rendered log line
//! passes through [`redact_line`] before it reaches its sink, so the scrub applies uniformly across
//! our events, spans, and any dependency that logs through `tracing`. The patterns are conservative
//! (token PREFIXES, the sealed-blob magic, the home-dir path) so ordinary diagnostic text is intact.
//!
//! ## What gets redacted
//!   * `wlt_…` (local runtime token), `wlk_…` (local API key), `wto_…`/`wtr_…` (cloud account
//!     access/refresh), `wrt_…` (local OAuth refresh), `wac_…` (authorization code),
//!     `pso_…`/`pst_…` (agent registration tokens) — replaced with `<token:redacted>`.
//!   * `WF1:…` sealed field blobs (vault Layer-B ciphertext) — replaced with `<sealed>`.
//!   * `~/.writ/…` and the resolved home path (`/Users/<u>/.writ/…`, `/home/<u>/.writ/…`,
//!     `C:\Users\…\.writ\…`) — replaced with `~/.writ/<redacted>` so a path can't reveal the layout
//!     or username.
//!   * Third-party AI provider keys (`sk-…`, `sk-ant-…`, `AIza…`) and secret URL query values
//!     (`?key=…`, `&api_key=…`, `access_token=…`, every SESSION-token param name the navigate step
//!     carries forward, …) — masked so a BYO key or a live session id can't leak via an error line.
//!   * `scheme://user:pass@host` URL userinfo — masked, because users routinely paste a proxy URL in
//!     that shape and the value is a live credential pair.
//!
//! NOTE: this remains a PREFIX/shape-based backstop, not a value scrubber — the primary defense is
//! still "don't log secrets by construction". A raw password with no recognizable shape is not caught.
//!
//! Net-new Rust — not ported from the legacy Python `desktop-agent`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use lazy_static::lazy_static;
use regex::Regex;
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::fmt::{self, MakeWriter};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

use crate::config::env::AppConfig;

lazy_static! {
    /// Any of our token prefixes followed by a run of token-shaped chars (base64url / hex / `_`).
    /// Matched case-sensitively — the prefixes are lowercase by construction.
    ///
    /// `wrt_` (local OAuth REFRESH token) and `wac_` (authorization code) are distinct prefixes from
    /// `wtr_` (cloud account refresh) — an easy pair to misread as already covered. All are listed.
    static ref TOKEN_RE: Regex =
        Regex::new(r"\b(?:wlt|wlk|wlo|wtk|wto|wtr|wrt|wac|pso|pst)_[A-Za-z0-9_\-]{6,}")
            .expect("valid token regex");
    /// Sealed Layer-B field blob: the `WF1:` magic + its base64 body.
    static ref SEALED_RE: Regex = Regex::new(r"WF1:[A-Za-z0-9+/=]+").expect("valid sealed regex");
    /// A `~/.writ/...` path, or an absolute path ending in `/.writ/...` (unix) or `\.writ\...`
    /// (windows). Captures the leading path up to and including the `.writ` segment so we can replace
    /// the whole prefix with a neutral marker.
    static ref WRIT_PATH_RE: Regex =
        Regex::new(r"(?:~|[A-Za-z]:\\[^\s]*|/[^\s]*)?[\\/]?\.writ[\\/][^\s]*")
            .expect("valid writ-path regex");
    /// Third-party AI provider API keys: OpenAI/OpenRouter `sk-…` (incl. `sk-ant-…`, `sk-or-…`) and
    /// Google `AIza…`. These are NOT writ tokens, so the prefix regex above misses them — a BYO key
    /// that lands in a log line (e.g. via an error) must still be masked.
    static ref PROVIDER_KEY_RE: Regex =
        Regex::new(r"\b(?:sk-(?:ant-|or-)?[A-Za-z0-9_\-]{16,}|AIza[A-Za-z0-9_\-]{20,})")
            .expect("valid provider-key regex");
    /// Secret-bearing URL query values (`?key=…`, `&api_key=…`, `access_token=…`, …). Masks the VALUE
    /// while keeping the param name, so a leaked URL doesn't expose the credential it carries.
    ///
    /// The SESSION-token names are the exact set `automation::step_navigate::SESSION_TOKEN_PARAMS`
    /// carries forward from the live page — by construction those hold a LIVE session id / CSRF token,
    /// so every one of them must be here (only `token` used to be, which let `sid`, `session_id`,
    /// `ssid`, `sessionid`, `PHPSESSID`, `jsessionid`, `csrf`, `csrftoken` and bare `auth` through).
    /// Longer names are listed before their prefixes purely for readability.
    static ref QUERY_SECRET_RE: Regex = Regex::new(
        r#"(?i)([?&](?:api[_-]?key|access_token|refresh_token|id_token|auth_token|authtoken|token|ticket|key|secret|password|passwd|signature|session_id|sessionid|phpsessid|jsessionid|csrftoken|csrf|ssid|sid|auth)=)[^&\s'"]+"#
    ).expect("valid query-secret regex");
    /// `scheme://user:pass@host` URL userinfo. Users paste proxy URLs in exactly this shape
    /// (`http://user:pass@proxy.host:8080`), and the credential has no recognizable token shape, so
    /// nothing else here would catch it. Requires the `://` so ordinary `user@host` email text and
    /// `git@github.com` style strings are left alone.
    static ref URL_USERINFO_RE: Regex =
        Regex::new(r"(?i)\b([a-z][a-z0-9+.\-]*://)[^/\s:@]+(?::[^/\s@]*)?@")
            .expect("valid url-userinfo regex");
}

/// Scrub a single rendered log line. Order matters: paths first (they may contain a token-shaped
/// segment we'd rather mask as a path), then sealed blobs, then bare tokens, then URL-shaped secrets.
pub fn redact_line(line: &str) -> String {
    let s = WRIT_PATH_RE.replace_all(line, "~/.writ/<redacted>");
    let s = SEALED_RE.replace_all(&s, "<sealed>");
    let s = TOKEN_RE.replace_all(&s, "<token:redacted>");
    let s = QUERY_SECRET_RE.replace_all(&s, "${1}<redacted>");
    let s = URL_USERINFO_RE.replace_all(&s, "${1}<redacted>@");
    let s = PROVIDER_KEY_RE.replace_all(&s, "<token:redacted>");
    s.into_owned()
}

/// Reduce a resolved URL to the part that is safe to log or to embed in an error message:
/// `scheme://host[:port]/path`, with the QUERY, the FRAGMENT and any `user:pass@` userinfo removed.
///
/// This is the ONE helper every URL-bearing log line / error string in the engine goes through.
/// It matters because a step URL is *post*-`value_resolver`: `{{vault:vendor_key}}` has already
/// become the live secret by the time we hold the string, and an error built from it fans out to the
/// daemon log, the run row's `error` column, the local `GET /v1/runs` response, the cloud
/// `task_result` frame AND an AI-repair prompt. Falls back to everything before the first `?`/`#`
/// when the string doesn't parse as a URL, so nothing after those separators is ever emitted.
pub fn redact_url_for_log(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) => {
            u.set_query(None);
            u.set_fragment(None);
            // `set_username`/`set_password` return Err for cannot-be-a-base URLs (mailto:, data:);
            // ignore that — such URLs have no userinfo to strip.
            let _ = u.set_username("");
            let _ = u.set_password(None);
            u.to_string()
        }
        Err(_) => url.split(['?', '#']).next().unwrap_or("").to_string(),
    }
}

/// A `Write` that redacts each buffer before forwarding it to `inner`. `tracing-subscriber`'s `fmt`
/// layer writes one fully-formatted event per `write_all`, so redacting per-write scrubs whole lines.
///
/// Generic over the inner writer so the SAME scrub can front stdout, stderr and the rolling file
/// appender (it used to hardcode `io::stdout()`, which is why three of the five tracing initializers
/// in this crate had no redaction at all).
pub struct RedactingWriter<W: Write> {
    inner: W,
}

impl<W: Write> RedactingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: Write> Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Render to text (lossily — log lines are UTF-8), redact, then emit. We always report the
        // ORIGINAL length as consumed so the caller doesn't retry on the (shorter) redacted output.
        let text = String::from_utf8_lossy(buf);
        let redacted = redact_line(&text);
        self.inner.write_all(redacted.as_bytes())?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// `MakeWriter` decorator: wraps ANY `MakeWriter` so every rendered line is scrubbed on its way to
/// that sink. Use it on every `fmt` layer — `Redacting(io::stderr)`, `Redacting(file_appender)`, …
#[derive(Clone, Copy, Default)]
pub struct Redacting<M>(pub M);

impl<'a, M> MakeWriter<'a> for Redacting<M>
where
    M: MakeWriter<'a>,
{
    type Writer = RedactingWriter<M::Writer>;
    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter::new(self.0.make_writer())
    }
}

/// `MakeWriter` factory yielding a redacting STDOUT writer. Kept as a distinct unit struct (rather
/// than folding into [`Redacting`]) because the daemon binaries name it directly.
#[derive(Clone, Copy, Default)]
pub struct RedactingMakeWriter;

impl<'a> MakeWriter<'a> for RedactingMakeWriter {
    type Writer = RedactingWriter<io::Stdout>;
    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriter::new(io::stdout())
    }
}

// -------------------------------------------------------------------------------------------------
// Subscriber init (managed-cloud `writ-agent` binary)
// -------------------------------------------------------------------------------------------------

/// Resolve where the rolling log file lives.
///
/// A BARE filename (the `RECORDER_LOG_FILE` default, `recorder.log`) used to be interpreted relative
/// to the process CWD — so the agent dropped a log wherever it happened to be launched from, in a
/// directory whose permissions we know nothing about. A bare name is now resolved under the agent's
/// own data home (`$WRIT_HOME`, else `~/.writ`) in a `logs/` subdirectory. An explicit path (anything
/// with a directory component) is still honored verbatim, and `RECORDER_LOG_FILE` remains the escape
/// hatch for container deployments that want a specific location.
fn resolve_log_path(configured: &str) -> PathBuf {
    let configured = configured.trim();
    let name = if configured.is_empty() { "recorder.log" } else { configured };
    let as_path = Path::new(name);
    // Any directory component at all (absolute or relative) means the operator chose a location.
    if as_path.parent().map(|p| !p.as_os_str().is_empty()).unwrap_or(false) {
        return as_path.to_path_buf();
    }
    let home = std::env::var_os("WRIT_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".writ")));
    match home {
        Some(h) => h.join("logs").join(name),
        // No resolvable home (a locked-down container user): keep the historical CWD behavior rather
        // than losing logs entirely.
        None => as_path.to_path_buf(),
    }
}

/// chmod a directory to `0700` (unix only, best-effort).
///
/// The rolling appender creates a NEW file at every daily rotation, at the process umask (typically
/// `0644`), and we cannot inject a mode into its `OpenOptions`. Locking the containing DIRECTORY down
/// is therefore the durable protection: no other local user can traverse into it to read a rotated
/// log, whatever mode that file was born with.
fn lock_down_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Create the log file the appender is about to open, at mode `0600` set AT CREATION
/// (`O_CREAT|O_EXCL` + `.mode()`), mirroring `local::vault::write_secret_file`.
///
/// Log lines are redacted but not secret-free by proof, so the file must not be world-readable — and
/// a create-then-chmod would leave a window where it is. `Rotation::DAILY` names the file
/// `<prefix>.<YYYY-MM-DD>` in UTC, which is what we pre-create; any already-existing sibling is
/// chmod'ed instead (best-effort). Combined with [`lock_down_dir`] a rotated file is unreachable by
/// other users even if the name guess ever drifts.
fn precreate_owner_only(dir: &Path, prefix: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.join(format!("{prefix}.{today}"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // O_EXCL: never adopt a file someone else planted
            .mode(0o600) // perms at creation → no world-readable window
            .open(&path)
        {
            Ok(_) => {}
            // Already there (restart / same-day rotation): tighten what we find.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            Err(_) => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, prefix);
    }
}

pub fn init(config: &AppConfig) {
    // Quiet two noisy playwright-rs internal targets. The bundled Playwright
    // 1.60 driver returns a `Disposable` channel object from addInitScript (and
    // friends) that playwright-rs 0.13's object_factory doesn't model, so every
    // init-script injection — stealth + the streaming runtime bridge re-inject on
    // each navigation — spams three benign lines:
    //   WARN  object_factory: Unknown protocol type: Disposable
    //   ERROR connection:     Failed to create object type=Disposable ...
    //   ERROR connection:     Error dispatching message: ... Disposable
    // It's purely cosmetic: add_init_script uses send_no_result(), so the handle
    // is ignored and the script still runs. Real operation failures surface as
    // Result::Err on the agent's own targets, not here — so silencing these two
    // library-internal targets loses nothing. Override with RUST_LOG to debug the
    // protocol layer (e.g. RUST_LOG=playwright_rs::server::connection=error).
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"))
        .add_directive(
            "playwright_rs::server::object_factory=off"
                .parse()
                .expect("static directive"),
        )
        .add_directive(
            "playwright_rs::server::connection=off"
                .parse()
                .expect("static directive"),
        );

    let log_path = resolve_log_path(&config.log_file);
    let log_dir = log_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let log_filename = log_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("recorder.log");

    // The appender itself only `create_dir_all`s lazily on first write, and never chmods. Create the
    // tree ourselves so we can lock it down BEFORE any line is written.
    let _ = std::fs::create_dir_all(log_dir);
    lock_down_dir(log_dir);
    precreate_owner_only(log_dir, log_filename);

    let file_appender = RollingFileAppender::builder()
        .rotation(Rotation::DAILY)
        .filename_prefix(log_filename)
        .max_log_files(5)
        .build(log_dir)
        .expect("Failed to create log file appender");

    // BOTH sinks go through the redactor. The file appender in particular used to be unprotected,
    // so anything an event leaked landed verbatim on disk (and then in a support bundle).
    let file_layer = fmt::layer()
        .with_writer(Redacting(file_appender))
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(false);

    // ANSI is disabled on the console too: the redactor matches on the RENDERED text, and SGR escape
    // sequences interleaved with a field value could split a token from its prefix and defeat a
    // pattern. Reliable scrubbing outranks colored output.
    let console_layer = fmt::layer()
        .with_writer(Redacting(io::stdout))
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(false);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_tokens() {
        let line = "registered with token wlt_abcdEF12_34-xyz and wto_SECRETvalue123";
        let out = redact_line(line);
        assert!(!out.contains("wlt_abcdEF12"), "local token masked: {out}");
        assert!(!out.contains("wto_SECRETvalue123"), "cloud token masked: {out}");
        assert!(out.contains("<token:redacted>"));
        // A normal word that merely starts with letters is untouched.
        assert!(out.contains("registered with token"));
    }

    /// `wrt_` (local OAuth refresh) and `wac_` (authorization code) are their OWN prefixes — `wtr_`
    /// being present did not cover them, which is exactly how they were missed.
    #[test]
    fn redacts_oauth_refresh_and_code_prefixes() {
        for (line, needle) in [
            ("stored refresh wrt_AbCd1234_refreshVALUE ok", "wrt_AbCd1234"),
            ("callback code wac_ZZ99xx_authCODEvalue used", "wac_ZZ99xx"),
        ] {
            let out = redact_line(line);
            assert!(!out.contains(needle), "prefix masked: {out}");
            assert!(out.contains("<token:redacted>"), "{out}");
        }
    }

    #[test]
    fn redacts_ws_ticket_and_query() {
        // The `wtk_` WS-ticket prefix is masked wherever it appears...
        let line = "issued ticket wtk_abcDEF123_ghi-jkl for /ws/record";
        let out = redact_line(line);
        assert!(!out.contains("wtk_abcDEF123"), "ws-ticket masked: {out}");
        assert!(out.contains("<token:redacted>"), "{out}");
        // ...including as a `?ticket=` query value in any logged URL.
        let url = "upgrade GET /ws/record?ticket=wtk_SECRETticketVALUE99 from webview";
        let out = redact_line(url);
        assert!(!out.contains("wtk_SECRETticketVALUE99"), "ticket query value masked: {out}");
        assert!(out.contains("ticket=<redacted>") || out.contains("<token:redacted>"), "{out}");
    }

    /// Every name in `step_navigate::SESSION_TOKEN_PARAMS` must have its VALUE masked — those params
    /// hold a live session id / CSRF token by construction.
    #[test]
    fn redacts_every_session_token_param() {
        for name in [
            "sid", "session_id", "token", "auth", "ssid", "sessionid", "PHPSESSID", "jsessionid",
            "csrf", "csrftoken",
        ] {
            let line = format!("GET https://app.example.com/x?{name}=LIVEsessionVALUE99&page=2 ok");
            let out = redact_line(&line);
            assert!(
                !out.contains("LIVEsessionVALUE99"),
                "session param `{name}` value must be masked: {out}"
            );
            assert!(out.contains("<redacted>"), "{out}");
            // The non-secret param survives, so the line is still useful.
            assert!(out.contains("page=2"), "{out}");
        }
    }

    /// `http://user:pass@host` userinfo is masked — the shape users paste for a proxy, and one no
    /// token-prefix or provider-key pattern would ever catch.
    #[test]
    fn redacts_url_userinfo() {
        let line = "Per-run proxy applied server=http://bob:s3cr3tPASS@proxy.example.com:8080 ok";
        let out = redact_line(line);
        assert!(!out.contains("s3cr3tPASS"), "proxy password masked: {out}");
        assert!(!out.contains("bob:"), "proxy username masked: {out}");
        assert!(out.contains("<redacted>@proxy.example.com:8080"), "host kept: {out}");
        // A userinfo-less URL is untouched, and an email address is not a URL.
        let ok = "fetching https://proxy.example.com:8080/health for bob@example.com";
        assert_eq!(redact_line(ok), ok);
    }

    #[test]
    fn redacts_sealed_blobs() {
        let line = "credentials_encrypted=WF1:AAAABBBBCCCCdddd/eee+fff= loaded";
        let out = redact_line(line);
        assert!(!out.contains("WF1:AAAABBBB"), "sealed blob masked: {out}");
        assert!(out.contains("<sealed>"));
    }

    #[test]
    fn redacts_writ_paths() {
        for line in [
            "opening db at /Users/jane/.writ/writ.db now",
            "home tree /home/bob/.writ/files/x ready",
            "config ~/.writ/config.toml loaded",
        ] {
            let out = redact_line(line);
            assert!(!out.contains(".writ/writ.db"), "{out}");
            assert!(!out.contains("jane"), "username not leaked via path: {out}");
            assert!(!out.contains("/bob/"), "username not leaked via path: {out}");
            assert!(out.contains("~/.writ/<redacted>"), "{out}");
        }
    }

    #[test]
    fn redacts_provider_keys() {
        for (line, needle) in [
            ("openai key sk-abcdEFGH1234567890xyz used", "sk-abcdEFGH"),
            ("anthropic sk-ant-api03-AAbbCCddEEffGG112233 set", "sk-ant-api03"),
            ("google key AIzaSyA0bCd3fGhIjKlMnOpQrStUvWx here", "AIzaSyA0"),
        ] {
            let out = redact_line(line);
            assert!(!out.contains(needle), "provider key masked: {out}");
            assert!(out.contains("<token:redacted>"), "{out}");
        }
    }

    #[test]
    fn redacts_secret_query_values() {
        let line = "GET https://generativelanguage.googleapis.com/v1beta/x?key=AIzaSyLEAKED12345 failed";
        let out = redact_line(line);
        assert!(!out.contains("AIzaSyLEAKED12345"), "query key masked: {out}");
        assert!(out.contains("key=<redacted>"), "param name kept, value masked: {out}");
        // A non-secret query stays intact.
        let ok = "GET https://api.example.com/v1/items?page=2&limit=50 ok";
        assert_eq!(redact_line(ok), ok);
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        let line = "monitor tick complete considered=3 changed=1 errored=0";
        assert_eq!(redact_line(line), line);
    }

    /// The URL helper every engine error/log line uses: query, fragment and userinfo gone, the part
    /// an operator actually needs (host + path) kept.
    #[test]
    fn url_redaction_drops_query_fragment_and_userinfo() {
        let out = redact_url_for_log(
            "https://api.vendor.com/export?api_token=LIVEvendorKEY99&format=csv#frag",
        );
        assert!(!out.contains("LIVEvendorKEY99"), "secret query value dropped: {out}");
        assert!(!out.contains("frag"), "fragment dropped: {out}");
        assert_eq!(out, "https://api.vendor.com/export");

        let out = redact_url_for_log("http://bob:s3cr3t@proxy.host:8080/path");
        assert!(!out.contains("s3cr3t"), "userinfo dropped: {out}");
        assert!(out.contains("proxy.host:8080/path"), "{out}");

        // Unparseable input still never emits anything after `?`/`#`.
        let out = redact_url_for_log("not a url?token=LIVEtoken");
        assert!(!out.contains("LIVEtoken"), "{out}");
        assert_eq!(out, "not a url");
    }

    #[test]
    fn writer_redacts_through_write() {
        // The generic writer forwards to ANY inner sink; a Vec<u8> lets us assert on real bytes
        // (which the old stdout-only writer could not).
        let mut sink: Vec<u8> = Vec::new();
        {
            let mut w = RedactingWriter::new(&mut sink);
            let buf = b"token wlt_deadBEEF12_secret end";
            assert_eq!(w.write(buf).unwrap(), buf.len(), "reports the ORIGINAL length consumed");
            w.flush().unwrap();
        }
        let out = String::from_utf8(sink).unwrap();
        assert!(out.contains("<token:redacted>"), "{out}");
        assert!(!out.contains("wlt_deadBEEF12"), "{out}");
    }

    /// A bare filename resolves under the data home (not the CWD); an explicit path is honored.
    #[test]
    fn log_path_defaults_under_data_home() {
        // This test MUTATES `WRIT_HOME`, which other tests' `Paths::resolve()` reads. Serialize on the
        // crate-wide guard (same pattern as `browser::install`'s trusted-root test) so a concurrent
        // test can't observe our temporary home. The guard only exists in the `local` build; the tests
        // it serializes with only exist there too.
        #[cfg(feature = "local")]
        let _g = crate::local::config::test_env_guard();

        let dir = tempfile::tempdir().unwrap();
        let prev = std::env::var_os("WRIT_HOME");
        std::env::set_var("WRIT_HOME", dir.path());

        let p = resolve_log_path("recorder.log");
        assert_eq!(p, dir.path().join("logs").join("recorder.log"));
        assert!(p.is_absolute(), "never CWD-relative: {}", p.display());

        // An operator-chosen path (RECORDER_LOG_FILE=/var/log/x.log) is untouched.
        assert_eq!(resolve_log_path("/var/log/writ/x.log"), PathBuf::from("/var/log/writ/x.log"));
        // Empty falls back to the default NAME, still under the home.
        assert_eq!(resolve_log_path("  "), dir.path().join("logs").join("recorder.log"));

        match prev {
            Some(v) => std::env::set_var("WRIT_HOME", v),
            None => std::env::remove_var("WRIT_HOME"),
        }
    }

    /// The pre-created log file is owner-only from birth (no create-then-chmod window).
    #[cfg(unix)]
    #[test]
    fn precreated_log_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        lock_down_dir(dir.path());
        precreate_owner_only(dir.path(), "recorder.log");

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = dir.path().join(format!("recorder.log.{today}"));
        assert!(path.exists(), "pre-created the file the appender will open");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "log file is owner-only");
        let dmode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(dmode & 0o777, 0o700, "log dir is owner-only (protects rotated files)");

        // Idempotent: a second call on an existing file tightens rather than failing.
        precreate_owner_only(dir.path(), "recorder.log");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
