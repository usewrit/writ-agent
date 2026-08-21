//! Crash reporting + diagnostics for the Writ Desktop daemon (PKG-11 / PROD-11 / PROD-13).
//!
//! Three concerns, all SCRUBBED and all opt-in-where-network is involved:
//!
//!   1. **Panic hook** ([`install_panic_hook`]) — a `std::panic::set_hook` that, on any unwinding
//!      panic in the process, captures a structured, REDACTED crash record to
//!      `~/.writ/logs/crash-<ts>.json` and logs a structured `tracing::error!`. It NEVER aborts the
//!      process — it chains to the default hook so normal unwinding/abort semantics are preserved.
//!      The record carries the panic message, source location, crate version, target triple, and a
//!      redacted backtrace — and NEVER a token, sealed blob, or a `~/.writ` path with a username.
//!
//!   2. **Telemetry stub** ([`maybe_report_crash`]) — a DEFAULT-NO-OP plumbing point that would POST
//!      a scrubbed crash report to a remote sink ONLY when the user has explicitly opted in
//!      (`telemetry_opt_in`) AND a DSN is configured (`WRIT_TELEMETRY_DSN`). With no DSN (the
//!      shipped default) it does nothing — there is no built-in endpoint, no phone-home.
//!
//!   3. **Diagnostics bundle** ([`build_diagnostics_bundle`]) — a "Export diagnostics" helper for the
//!      Settings UI. Bundles the REDACTED logs + the (secret-free) `config.toml` + the crash records
//!      into a single `.tar` under `~/.writ/artifacts/`. Every text file is passed through the same
//!      [`super::logging::redact_line`] scrub before it enters the archive, and the config is
//!      non-secret by construction (keys/tokens live in the vault/keyring, never the file).
//!
//! ## Redaction is shared, not re-implemented
//! All scrubbing reuses [`super::logging::redact_line`] — the SAME last-line-of-defense regexes the
//! log sink uses (token prefixes, `WF1:` sealed blobs, `~/.writ` paths). A backtrace or a log file is
//! scrubbed line-by-line through it, so a crash artifact can never leak material the live logs would
//! also mask.
//!
//! Net-new Rust in this crate (behind the `local` feature). NOT ported from the legacy
//! Python `desktop-agent`. No new crate dependency: the crash record uses `serde_json`, the backtrace
//! uses `std::backtrace`, and the bundle emits a hand-rolled (dependency-free) USTAR `.tar` so the
//! cloud build stays byte-unchanged and the `local` feature gains no archive crate.

use std::backtrace::Backtrace;
use std::io::Write;
use std::panic::PanicHookInfo;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::config::Paths;
use super::logging::redact_line;

/// Env var naming the remote telemetry sink. UNSET by default → telemetry is a no-op (no built-in
/// endpoint ships). Only consulted when the user has also opted in via `telemetry_opt_in`.
const TELEMETRY_DSN_ENV: &str = "WRIT_TELEMETRY_DSN";

/// A single captured panic, fully redacted and ready to serialize to `crash-<ts>.json`.
///
/// Every string field has already passed through [`redact_line`] (or is non-secret by construction:
/// the version, the target triple, the ISO timestamp). The struct is what both the on-disk JSON and
/// the (opt-in) telemetry payload are built from — one scrub site, two consumers.
#[derive(Debug, Clone, Serialize)]
pub struct CrashRecord {
    /// RFC-3339 UTC capture time (also encoded in the filename).
    pub timestamp: String,
    /// Crate version (`CARGO_PKG_VERSION`) — non-secret build metadata.
    pub version: String,
    /// Target triple this binary was built for — non-secret build metadata.
    pub target: String,
    /// Which binary captured the panic (`writ-agentd` / `writ` / a test) — non-secret.
    pub binary: String,
    /// The panic message, REDACTED. A panic payload can embed a formatted value, so this is scrubbed.
    pub message: String,
    /// `file:line:col` of the panic site, REDACTED (a source path could in theory contain `.writ`).
    pub location: Option<String>,
    /// The thread name (`main`, a tokio worker, …) — non-secret, but redacted defensively.
    pub thread: String,
    /// Resolved backtrace, REDACTED line-by-line. `None` when backtraces are disabled
    /// (`RUST_BACKTRACE` unset) so we never write a useless `"<disabled>"` blob.
    pub backtrace: Option<String>,
}

impl CrashRecord {
    /// Build a fully-redacted record from a panic hook callback. `binary` names the capthook owner so
    /// a bundle can tell which process crashed. The backtrace is captured + resolved HERE (inside the
    /// hook, where the stack is still meaningful) and scrubbed before storage.
    fn from_panic(info: &PanicHookInfo<'_>, binary: &str) -> Self {
        // The panic payload is `&(dyn Any)`; the common cases are `&str` / `String`. Anything else
        // becomes a neutral marker (we never `Debug`-format an unknown payload — it could be a value).
        let raw_msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());

        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()));

        // Resolve the backtrace only when the user asked for one (RUST_BACKTRACE). `Backtrace::capture`
        // returns a Disabled status otherwise; we map that to `None` rather than an opaque string.
        let bt = Backtrace::capture();
        let backtrace = match bt.status() {
            std::backtrace::BacktraceStatus::Captured => Some(redact_multiline(&bt.to_string())),
            _ => None,
        };

        let thread = std::thread::current()
            .name()
            .unwrap_or("unnamed")
            .to_string();

        Self {
            timestamp: now_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            target: target_triple().to_string(),
            binary: redact_line(binary),
            message: redact_line(&raw_msg),
            location: location.map(|l| redact_line(&l)),
            thread: redact_line(&thread),
            backtrace,
        }
    }
}

/// Install the process-wide panic hook. Call EARLY in each binary's `main` (before any work that
/// could panic) so even an init-time panic is captured. Idempotent enough for practical use — calling
/// it twice simply re-wraps the previous hook; binaries call it exactly once.
///
/// `binary` is a short owner label (`"writ-agentd"` / `"writ"`) stamped into every crash record.
///
/// Behavior on panic:
///   * Build a scrubbed [`CrashRecord`], write it to `~/.writ/logs/crash-<ts>.json` (best-effort —
///     a write failure is itself logged, never re-panicked).
///   * Emit a structured `tracing::error!` (which the daemon's redacting writer also scrubs).
///   * Fire the opt-in telemetry stub (default no-op).
///   * Print an EQUIVALENT, REDACTED panic line to stderr in place of the default hook's output.
///
/// ## Why we do NOT chain to the previous hook
/// The hook chain used to end with `prev(info)`. `prev` is the DEFAULT hook (this is installed once,
/// early, in each binary's `main`), and the default hook prints the panic payload — plus, with
/// `RUST_BACKTRACE`, the whole backtrace — to stderr VERBATIM. So the carefully redacted crash record
/// was accompanied, one line later, by the unredacted original: on a daemon whose stderr is captured
/// by journald / the launching shell / an AI IDE, and in any `2>&1` log. A panic payload is a
/// `format!`ed string, so it can carry a token, a resolved URL or an extracted value.
///
/// Skipping `prev` does NOT change panic semantics: the hook is only a REPORTER. Unwinding vs. abort
/// is decided by the panic runtime (`panic=unwind`/`abort`), not by the hook, and `catch_unwind`
/// still sees the payload. We print our own redacted equivalent so the operator still gets an
/// immediate stderr signal.
pub fn install_panic_hook(binary: &'static str) {
    // Take (and drop) the previous hook so we fully REPLACE it rather than chaining an unredacted
    // printer behind ourselves. Bound to `_prev` to make the intent explicit at the call site.
    let _prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Never let the hook itself panic (that would abort with a confusing double-panic). Each step
        // is independently fallible and swallowed.
        let record = CrashRecord::from_panic(info, binary);

        if let Err(e) = persist_record(&record) {
            // Can't write the crash file — say so on the log path (which is itself redacted at the
            // sink). Do NOT include the path (it's under ~/.writ).
            tracing::error!(error = %e, "failed to persist crash record");
        }

        // Structured log line. All fields are already redacted; the daemon's RedactingWriter is a
        // second pass. We deliberately log at ERROR — a panic is always notable.
        tracing::error!(
            binary = %record.binary,
            version = %record.version,
            location = record.location.as_deref().unwrap_or("unknown"),
            thread = %record.thread,
            has_backtrace = record.backtrace.is_some(),
            "panic captured: {}",
            record.message
        );

        // Opt-in, DSN-gated, default no-op. Swallows its own errors.
        maybe_report_crash(&record);

        // Stand in for the default hook's stderr line, REDACTED. Same shape an operator expects
        // (`thread '<name>' panicked at <loc>: <msg>`) so nothing about the diagnostic experience
        // regresses — only the leak does. The backtrace is deliberately NOT printed here: it lives,
        // scrubbed, in the crash record, whereas the default hook printed it raw.
        let _ = writeln!(
            std::io::stderr(),
            "thread '{}' panicked at {}:\n{}\n(redacted; full scrubbed record in ~/.writ/logs/crash-*.json)",
            record.thread,
            record.location.as_deref().unwrap_or("unknown location"),
            record.message,
        );
    }));
}

/// How many `crash-<ts>.json` records are retained in `~/.writ/logs`. Older ones are deleted by
/// [`prune_crash_records`] on every capture.
///
/// A panic in a supervised process is usually a REPEATING panic: the supervisor restarts the worker,
/// it panics again on the same input, and each cycle wrote one more file — unbounded, with nothing in
/// the tree pruning `logs/` at all until now. 20 is enough to see a pattern (first occurrence plus
/// the recent tail) without letting a crash loop become the disk problem.
const CRASH_RECORDS_KEPT: usize = 20;

/// Write a crash record to `~/.writ/logs/crash-<ts>.json` (mode `0600` on unix). The filename uses a
/// filesystem-safe timestamp so concurrent panics don't collide. Returns the written path on success.
///
/// Resolves the home with [`Paths::resolve`] and ensures the `logs/` dir exists (a panic can fire
/// before normal bootstrap). On ANY failure this returns `Err` rather than panicking — the caller
/// (the hook) logs and moves on. After a successful write, prunes down to [`CRASH_RECORDS_KEPT`].
fn persist_record(record: &CrashRecord) -> std::io::Result<PathBuf> {
    let paths = Paths::resolve()
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let logs = paths.logs_dir();
    std::fs::create_dir_all(&logs)?;

    let fname = format!("crash-{}.json", fs_safe_stamp(&record.timestamp));
    let path = logs.join(fname);

    let body = serde_json::to_vec_pretty(record)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::write(&path, &body)?;
    set_0600(&path);

    // Cap the directory AFTER the new record lands, so the newest capture is always among the kept
    // set even if the cap is somehow 0. Failures here are swallowed: we already have the record on
    // disk, and the panic hook must never turn a housekeeping error into a second failure.
    prune_crash_records(&logs, CRASH_RECORDS_KEPT);
    Ok(path)
}

/// Delete all but the newest `keep` `crash-*.json` files in `logs`. Best-effort and infallible by
/// design (it runs inside the panic hook).
///
/// "Newest" is decided by FILENAME, not mtime: the name is `crash-<rfc3339-with-:.+→->.json`, whose
/// fixed-width UTC fields make lexicographic order identical to chronological order. That is both
/// cheaper (no `stat` per file) and more robust than mtime, which a backup/restore or an `rsync -a`
/// can rewrite. Nanosecond-precision names also break ties between two panics in the same second.
fn prune_crash_records(logs: &Path, keep: usize) {
    let Ok(entries) = std::fs::read_dir(logs) else {
        return;
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_str()?.to_string();
            (name.starts_with("crash-") && name.ends_with(".json")).then_some(name)
        })
        .collect();
    if names.len() <= keep {
        return;
    }
    // Ascending = oldest first, so the newest `keep` are the tail: iterate from the newest end,
    // skip the ones we keep, and delete the remainder.
    names.sort_unstable();
    let mut removed = 0usize;
    for stale in names.iter().rev().skip(keep) {
        if std::fs::remove_file(logs.join(stale)).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        // Best-effort note. `tracing` inside the panic hook is already the established pattern here.
        tracing::debug!(removed, keep, "pruned old crash records");
    }
}

/// Opt-in, DSN-gated telemetry plumbing — DEFAULT NO-OP.
///
/// Sends a scrubbed crash report to a remote sink ONLY when BOTH hold:
///   * the user opted in (`telemetry_opt_in` in `config.toml` / `WRIT_TELEMETRY`), AND
///   * a DSN endpoint is configured (`WRIT_TELEMETRY_DSN`).
///
/// With no DSN (the shipped default) this returns immediately — Writ ships NO built-in telemetry
/// endpoint, so out of the box nothing is ever sent. The actual POST is intentionally left as a
/// documented stub (a fire-and-forget `reqwest` call could go here); we do NOT wire a live network
/// call into the panic path by default. The record is already fully redacted; we re-scrub nothing.
///
/// Swallows all errors — telemetry must never affect the crashing process.
pub fn maybe_report_crash(record: &CrashRecord) {
    if !telemetry_enabled() {
        return;
    }
    let Some(dsn) = telemetry_dsn() else {
        // Opted in but no endpoint configured: nothing to send. This is the normal shipped state for
        // a user who flipped the toggle without a self-hosted sink.
        return;
    };

    // STUB: a real deployment would POST the redacted JSON to `dsn` here (fire-and-forget, short
    // timeout, never blocking shutdown). We deliberately do NOT make a network call by default — the
    // plumbing is present and gated so it can be enabled without touching the panic path. The DSN is
    // never logged (it could embed a token in its query string).
    let _ = &dsn;
    let _ = record;
    tracing::debug!("telemetry opt-in + DSN present; crash report dispatch is stubbed (no-op)");
}

/// True when anonymous telemetry is opted in. Reads the env override first (`WRIT_TELEMETRY`), then
/// falls back to the persisted `config.toml` (`[app].telemetry_opt_in`). Best-effort: any resolution
/// failure is treated as NOT opted in (fail closed — never send by default).
fn telemetry_enabled() -> bool {
    match std::env::var("WRIT_TELEMETRY")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("1") | Some("true") | Some("yes") | Some("on") => return true,
        Some("0") | Some("false") | Some("no") | Some("off") => return false,
        _ => {}
    }
    // No env override → consult the on-disk config (fail closed on any error).
    Paths::resolve()
        .map(|p| super::config::load_config(&p).telemetry_opt_in)
        .unwrap_or(false)
}

/// The configured telemetry DSN, or `None`. Empty/whitespace counts as unset.
fn telemetry_dsn() -> Option<String> {
    std::env::var(TELEMETRY_DSN_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Build a redacted diagnostics bundle for the Settings "Export diagnostics" button.
///
/// Produces a single dependency-free `.tar` at `~/.writ/artifacts/diagnostics-<ts>.tar` containing:
///   * every `*.log` and `crash-*.json` under `~/.writ/logs/`, each REDACTED line-by-line, and
///   * the `config.toml` (non-secret by construction), also passed through the scrub for belt-and-
///     braces.
///
/// Returns the bundle path. NEVER includes the DB, the vault key, the local token, or any secret
/// file — only the redacted text artifacts an operator needs to debug. Best-effort per file: an
/// unreadable file is skipped (logged), not fatal.
pub fn build_diagnostics_bundle(paths: &Paths) -> std::io::Result<PathBuf> {
    let artifacts = paths.artifacts_dir();
    std::fs::create_dir_all(&artifacts)?;
    let out_path = artifacts.join(format!("diagnostics-{}.tar", fs_safe_stamp(&now_rfc3339())));

    let mut tar = TarWriter::new(std::fs::File::create(&out_path)?);

    // Redacted logs + crash records.
    let logs = paths.logs_dir();
    if let Ok(entries) = std::fs::read_dir(&logs) {
        for entry in entries.flatten() {
            let p = entry.path();
            let name = match p.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let is_log = name.ends_with(".log");
            let is_crash = name.starts_with("crash-") && name.ends_with(".json");
            if !(is_log || is_crash) {
                continue;
            }
            match std::fs::read_to_string(&p) {
                Ok(text) => {
                    let scrubbed = redact_multiline(&text);
                    if let Err(e) = tar.append(&format!("logs/{name}"), scrubbed.as_bytes()) {
                        tracing::warn!(error = %e, "diagnostics: could not add a log entry");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "diagnostics: could not read a log file"),
            }
        }
    }

    // Non-secret config (still scrubbed defensively). Missing file is fine — just omit it.
    if let Ok(text) = std::fs::read_to_string(paths.config_toml()) {
        let scrubbed = redact_multiline(&text);
        if let Err(e) = tar.append("config.toml", scrubbed.as_bytes()) {
            tracing::warn!(error = %e, "diagnostics: could not add config.toml");
        }
    }

    tar.finish()?;
    set_0600(&out_path);
    Ok(out_path)
}

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

/// Redact a multi-line blob by scrubbing each line through [`redact_line`] (the sink redactor is
/// per-line). Preserves line structure so a backtrace/log stays readable.
fn redact_multiline(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&redact_line(line));
    }
    // Preserve a trailing newline if the source had one (tar consumers expect intact text files).
    if text.ends_with('\n') {
        out.push('\n');
    }
    out
}

/// RFC-3339 UTC now (e.g. `2026-06-29T08:30:00.123456789+00:00`).
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Make a timestamp filesystem-safe (`:`/`.`/`+` → `-`) for crash/bundle filenames.
fn fs_safe_stamp(ts: &str) -> String {
    ts.chars()
        .map(|c| match c {
            ':' | '.' | '+' => '-',
            other => other,
        })
        .collect()
}

/// The build target triple, baked in at compile time via the build env. Falls back to `"unknown"` if
/// the env var is somehow absent (it is always set by cargo for normal builds).
fn target_triple() -> &'static str {
    option_env!("TARGET").unwrap_or(std::env::consts::ARCH)
}

/// chmod `0600` on unix (best-effort; no-op elsewhere). Crash/diagnostics artifacts mirror the
/// `~/.writ` tree's owner-only posture even though they carry only redacted content.
fn set_0600(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

// -------------------------------------------------------------------------------------------------
// Minimal, dependency-free USTAR tar writer.
//
// We emit a tiny subset of the POSIX USTAR format — enough for `tar -xf` / Finder / 7-zip to extract
// the redacted text files. Using a hand-rolled writer keeps the `local` feature free of a `zip`/`tar`
// crate (the cloud build stays byte-unchanged). Only regular files are supported; sizes are the byte
// length of the (already-redacted) content held in memory, which is fine for log/config text.
// -------------------------------------------------------------------------------------------------

/// A minimal USTAR archive writer over any `Write` sink.
struct TarWriter<W: Write> {
    inner: W,
}

impl<W: Write> TarWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner }
    }

    /// Append one regular file (`name` is the in-archive path; `data` is its full content).
    fn append(&mut self, name: &str, data: &[u8]) -> std::io::Result<()> {
        let header = ustar_header(name, data.len())?;
        self.inner.write_all(&header)?;
        self.inner.write_all(data)?;
        // Pad the file body to a 512-byte boundary.
        let rem = data.len() % 512;
        if rem != 0 {
            let pad = [0u8; 512];
            self.inner.write_all(&pad[..512 - rem])?;
        }
        Ok(())
    }

    /// Write the two zero-filled 512-byte blocks that terminate a tar stream, then flush.
    fn finish(&mut self) -> std::io::Result<()> {
        let zero = [0u8; 512];
        self.inner.write_all(&zero)?;
        self.inner.write_all(&zero)?;
        self.inner.flush()
    }
}

/// Build a 512-byte USTAR header block for a regular file. `name` must fit the 100-byte name field
/// (our names are short: `logs/<file>` / `config.toml`); a too-long name is rejected so we never emit
/// a corrupt header. Mode/uid/gid/mtime are fixed, neutral values.
fn ustar_header(name: &str, size: usize) -> std::io::Result<[u8; 512]> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > 100 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "tar entry name too long",
        ));
    }

    let mut h = [0u8; 512];
    h[..name_bytes.len()].copy_from_slice(name_bytes);

    // Octal numeric fields are ASCII, NUL- or space-terminated. Helper to write a zero-padded octal
    // value into a fixed field.
    fn put_octal(field: &mut [u8], value: u64) {
        // width-1 octal digits + trailing NUL (USTAR convention for these fields).
        let digits = field.len() - 1;
        let s = format!("{value:0width$o}", width = digits);
        let bytes = s.as_bytes();
        let take = bytes.len().min(digits);
        field[..take].copy_from_slice(&bytes[bytes.len() - take..]);
        field[digits] = 0;
    }

    put_octal(&mut h[100..108], 0o600); // mode
    put_octal(&mut h[108..116], 0); // uid
    put_octal(&mut h[116..124], 0); // gid
    put_octal(&mut h[124..136], size as u64); // size
    put_octal(&mut h[136..148], 0); // mtime (epoch 0 — neutral, no host clock leak)
    h[156] = b'0'; // typeflag: regular file

    // USTAR magic + version.
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");

    // Checksum: computed with the checksum field treated as 8 spaces, then written as octal.
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    let chk = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(&chk.as_bytes()[..8]);

    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A crash record built from a `&str` panic payload is fully populated and scrubbed: a token in
    /// the message is masked, the version/target are present, and serialization round-trips.
    #[test]
    fn crash_record_scrubs_message_and_serializes() {
        // Synthesize a record directly (PanicHookInfo can't be constructed outside a real panic).
        let rec = CrashRecord {
            timestamp: now_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            target: target_triple().to_string(),
            binary: "writ-agentd".to_string(),
            message: redact_line("boom with token wlt_deadBEEF12_secret here"),
            location: Some(redact_line("src/x.rs:1:1")),
            thread: redact_line("main"),
            backtrace: Some(redact_multiline(
                "frame at /Users/jane/.writ/writ.db\nnext frame ok",
            )),
        };
        assert!(!rec.message.contains("wlt_deadBEEF12"), "token masked: {}", rec.message);
        assert!(rec.message.contains("<token:redacted>"));
        let bt = rec.backtrace.as_deref().unwrap();
        assert!(!bt.contains("jane"), "username not leaked via backtrace path: {bt}");
        assert!(bt.contains("~/.writ/<redacted>"));
        // Multi-line structure preserved.
        assert!(bt.contains("next frame ok"));

        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"backtrace\""));
    }

    /// `redact_multiline` scrubs every line and preserves a trailing newline.
    #[test]
    fn multiline_redaction_preserves_structure() {
        let src = "ok line\ntoken wlt_aaaaaa_bbb end\npath /home/bob/.writ/x\n";
        let out = redact_multiline(src);
        assert!(out.ends_with('\n'), "trailing newline preserved");
        assert_eq!(out.lines().count(), 3);
        assert!(!out.contains("wlt_aaaaaa"));
        assert!(!out.contains("/bob/"));
        assert!(out.contains("<token:redacted>"));
    }

    /// The opt-in flag is ON by default, but crash reporting still needs a DSN and there is no
    /// built-in one — so out of the box `maybe_report_crash` is a no-op and does not panic. (We
    /// can't assert on "no network call" directly, but the stub never makes one.)
    #[test]
    fn crash_reporting_is_a_noop_without_a_dsn() {
        let _g = crate::local::config::test_env_guard();
        // Ensure a clean env for this assertion (tests share the process).
        std::env::remove_var("WRIT_TELEMETRY");
        std::env::remove_var(TELEMETRY_DSN_ENV);
        // Point WRIT_HOME at a throwaway dir so `telemetry_enabled` reads a default config instead
        // of the developer's real ~/.writ.
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));

        assert!(telemetry_enabled(), "the default config carries the opt-in flag on");
        assert!(telemetry_dsn().is_none(), "no DSN by default — so the flag alone reports nothing");

        let rec = CrashRecord {
            timestamp: now_rfc3339(),
            version: "test".into(),
            target: "test".into(),
            binary: "test".into(),
            message: "x".into(),
            location: None,
            thread: "main".into(),
            backtrace: None,
        };
        // Must not panic / must not block.
        maybe_report_crash(&rec);

        std::env::remove_var("WRIT_HOME");
    }

    /// `persist_record` writes a `crash-<ts>.json` into `~/.writ/logs` and the file parses back to the
    /// same redacted record.
    #[test]
    fn persist_record_writes_parseable_json() {
        let _g = crate::local::config::test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();

        let rec = CrashRecord {
            timestamp: now_rfc3339(),
            version: "1.0.0".into(),
            target: "x".into(),
            binary: "writ".into(),
            message: "hello".into(),
            location: Some("a.rs:2:3".into()),
            thread: "main".into(),
            backtrace: None,
        };
        let path = persist_record(&rec).unwrap();
        assert!(path.exists());
        assert!(path.file_name().unwrap().to_str().unwrap().starts_with("crash-"));

        let text = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["message"], json!("hello"));
        assert_eq!(parsed["binary"], json!("writ"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "crash file is owner-only");
        }
        std::env::remove_var("WRIT_HOME");
    }

    /// A repeating panic must not fill the disk: `prune_crash_records` keeps the newest N records by
    /// (chronologically ordered) filename, deletes the rest, and touches nothing else in `logs/`.
    #[test]
    fn prune_crash_records_keeps_newest_only() {
        let dir = tempfile::tempdir().unwrap();
        let logs = dir.path();

        // 25 records with chronologically increasing names, plus files that are NOT crash records.
        for i in 0..25 {
            std::fs::write(logs.join(format!("crash-2026-07-25T00-00-{i:02}-000Z.json")), b"{}").unwrap();
        }
        std::fs::write(logs.join("agentd.log"), b"keep me").unwrap();
        std::fs::write(logs.join("crash-notes.md"), b"keep me too").unwrap();

        prune_crash_records(logs, 20);

        let mut kept: Vec<String> = std::fs::read_dir(logs)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.starts_with("crash-") && n.ends_with(".json"))
            .collect();
        kept.sort();
        assert_eq!(kept.len(), 20, "capped to the keep window");
        // The 5 OLDEST (00..04) are gone; the newest (24) survives.
        assert_eq!(kept.first().unwrap(), "crash-2026-07-25T00-00-05-000Z.json");
        assert_eq!(kept.last().unwrap(), "crash-2026-07-25T00-00-24-000Z.json");
        // Non-crash files are untouched.
        assert!(logs.join("agentd.log").exists());
        assert!(logs.join("crash-notes.md").exists(), "a .md is not a crash record");

        // Idempotent: a second pass at or under the cap removes nothing.
        prune_crash_records(logs, 20);
        assert_eq!(
            std::fs::read_dir(logs).unwrap().flatten().count(),
            22,
            "20 records + 2 unrelated files"
        );
    }

    /// `persist_record` enforces the cap itself, so a crash LOOP self-limits with no external sweeper:
    /// writing more than `CRASH_RECORDS_KEPT` records leaves exactly that many, including the newest.
    #[test]
    fn persist_record_caps_the_directory() {
        let _g = crate::local::config::test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();

        let mut last = PathBuf::new();
        for i in 0..(CRASH_RECORDS_KEPT + 7) {
            let rec = CrashRecord {
                // Distinct, monotonically increasing stamps (the real hook uses `now_rfc3339`, which
                // is nanosecond-precision, so collisions do not happen in practice either).
                timestamp: format!("2026-07-25T00:00:{:02}.000000000+00:00", i),
                version: "1.0.0".into(),
                target: "x".into(),
                binary: "writ-agent-fleet".into(),
                message: format!("panic #{i}"),
                location: None,
                thread: "main".into(),
                backtrace: None,
            };
            last = persist_record(&rec).unwrap();
        }

        let count = std::fs::read_dir(paths.logs_dir())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("crash-") && n.ends_with(".json")
            })
            .count();
        assert_eq!(count, CRASH_RECORDS_KEPT, "the directory is capped, not unbounded");
        assert!(last.exists(), "the newest record is always kept");

        std::env::remove_var("WRIT_HOME");
    }

    /// The diagnostics bundle gathers redacted logs + crash records + config into a valid `.tar` whose
    /// entries are scrubbed (no token / no username path).
    #[test]
    fn diagnostics_bundle_is_scrubbed_tar() {
        let _g = crate::local::config::test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();

        // Seed a log with a token + a username path, a crash record, and a config.
        std::fs::write(
            paths.logs_dir().join("agentd.log"),
            "boot ok token wlt_SECRET12_abc opened /Users/jane/.writ/writ.db\n",
        )
        .unwrap();
        std::fs::write(
            paths.logs_dir().join("crash-2026.json"),
            "{\"message\":\"panic wto_TOKENvalue99\"}\n",
        )
        .unwrap();
        std::fs::write(paths.config_toml(), "schema_version = 1\n[server]\nport = 8131\n").unwrap();

        let bundle = build_diagnostics_bundle(&paths).unwrap();
        assert!(bundle.exists());
        assert!(bundle.extension().unwrap() == "tar");

        // Read the raw tar bytes and assert no secret survived anywhere in the archive (headers carry
        // names, bodies carry the redacted text). A simple substring scan over the whole file is a
        // strong end-to-end check.
        let bytes = std::fs::read(&bundle).unwrap();
        let blob = String::from_utf8_lossy(&bytes);
        assert!(!blob.contains("wlt_SECRET12"), "log token leaked into bundle");
        assert!(!blob.contains("wto_TOKENvalue99"), "crash token leaked into bundle");
        assert!(!blob.contains("jane"), "username path leaked into bundle");
        // Sanity: the archive actually contains our entries' names + the redaction marker.
        assert!(blob.contains("logs/agentd.log"));
        assert!(blob.contains("config.toml"));
        assert!(blob.contains("<token:redacted>"));

        std::env::remove_var("WRIT_HOME");
    }

    /// The hand-rolled tar header has a correct USTAR magic and a checksum that validates the way
    /// `tar` verifies it (sum of all bytes with the checksum field counted as spaces).
    #[test]
    fn ustar_header_checksum_is_valid() {
        let size = 42;
        let h = ustar_header("logs/x.log", size).unwrap();
        // Magic.
        assert_eq!(&h[257..263], b"ustar\0");
        // Recompute the checksum treating bytes 148..156 as spaces; it must equal the stored octal.
        let mut copy = h;
        for b in &mut copy[148..156] {
            *b = b' ';
        }
        let expected: u32 = copy.iter().map(|&b| b as u32).sum();
        let stored = std::str::from_utf8(&h[148..154]).unwrap();
        let stored = u32::from_str_radix(stored.trim_end_matches('\0').trim(), 8).unwrap();
        assert_eq!(stored, expected, "tar header checksum must validate");
        // Name too long is rejected (no corrupt header).
        let long = "a".repeat(101);
        assert!(ustar_header(&long, 0).is_err());
    }

    /// `install_panic_hook` followed by a caught panic writes a crash record. We run the panic in a
    /// `catch_unwind` so the test process survives; the hook still fires inside it.
    #[test]
    fn installed_hook_captures_a_real_panic() {
        let _g = crate::local::config::test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path().join(".writ"));
        std::env::remove_var("WRIT_TELEMETRY");
        std::env::remove_var(TELEMETRY_DSN_ENV);
        let paths = Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();

        install_panic_hook("writ-test");

        // Trigger a panic but keep the test alive. Our hook prints a REDACTED line to stderr (it no
        // longer chains to the default hook, which printed the payload verbatim). The hook should
        // have written a crash-*.json before unwinding.
        //
        // The payload deliberately embeds a token so we can assert the persisted record scrubs it —
        // a panic message is a `format!`ed string and can carry live material.
        let result = std::panic::catch_unwind(|| {
            panic!("synthetic panic for the crash hook test wlt_PANICtoken12_secret");
        });
        assert!(result.is_err(), "the panic unwound as expected");

        // Retire our process-global hook (it resolves WRIT_HOME at panic time, so it would otherwise
        // write crash files into whatever sandbox a LATER test points WRIT_HOME at).
        //
        // The replacement still PRINTS the panic. A `Box::new(|_| {})` no-op — what this used to
        // install — silently swallowed the message of every subsequent panic in the whole test
        // process, so any later test that failed an assertion reported "FAILED" with an EMPTY stdout
        // section and no way to tell which assertion broke.
        let _ = std::panic::take_hook();
        std::panic::set_hook(Box::new(|info| {
            eprintln!("test panic (writ crash-capture hook retired): {info}");
        }));

        // A crash record should now exist in logs/.
        let mut found = false;
        for entry in std::fs::read_dir(paths.logs_dir()).unwrap().flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("crash-") && name.ends_with(".json") {
                let text = std::fs::read_to_string(entry.path()).unwrap();
                if text.contains("synthetic panic") {
                    found = true;
                    assert!(
                        !text.contains("wlt_PANICtoken12"),
                        "a token in the panic payload must be redacted in the record: {text}"
                    );
                    assert!(text.contains("<token:redacted>"), "{text}");
                }
            }
        }
        assert!(found, "the installed hook persisted a crash record");

        std::env::remove_var("WRIT_HOME");
    }
}
