//! Authenticator import — turn EXISTING TOTP secrets into personas without re-enrolling 2FA.
//!
//! TOTP is stateless and seed-derived: the secret the user's phone already holds mints the same
//! codes on-device (see `Vault::mint_totp`), so reading the seeds an authenticator exports lets a
//! persona 2FA-login with no per-site re-enrollment. Faithful port of the cloud
//! the cloud backend's `authenticator_import` service — two ingest formats, no protobuf dependency:
//!
//!   1. `otpauth://` URIs        — one account each (QR scan decoded client-side, hand-paste, and
//!                                 the JSON exports of 2FAS / Aegis / Bitwarden / Raivo).
//!   2. `otpauth-migration://`   — Google Authenticator "Export accounts": base64 protobuf holding
//!                                 EVERY enrolled account (secret/name/issuer/algo/digits).
//!
//! ## Security
//! - Parsing returns a PREVIEW WITHOUT secrets. The full entries (incl. seeds) are staged in a
//!   process-local, short-TTL, single-use token store (the desktop analog of the cloud's Redis
//!   staging) and only the user-selected entries are committed to personas (vault-sealed).
//! - A Google export contains ALL of the user's authenticator accounts, many unrelated to Writ —
//!   we never auto-import; the user picks which to keep at commit.
//! - Seeds NEVER appear in any log, preview, or serialized surface of this module.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

/// Staged imports expire after this long — the preview→commit hop is seconds.
const STAGE_TTL: Duration = Duration::from_secs(600);
/// Sanity cap on a single import payload (mirrors the cloud `_MAX_ENTRIES`).
const MAX_ENTRIES: usize = 200;
/// Cap on concurrently staged imports so an abusive loop can't grow the map unbounded.
const MAX_STAGED: usize = 16;

/// Light issuer→domain hints so the preview can pre-fill a sensible target_domain.
/// Intentionally tiny — anything unknown stays `None` and the user fills it in.
const ISSUER_DOMAIN_HINTS: &[(&str, &str)] = &[
    ("google", "google.com"),
    ("github", "github.com"),
    ("gitlab", "gitlab.com"),
    ("amazon", "amazon.com"),
    ("amazon web services", "aws.amazon.com"),
    ("aws", "aws.amazon.com"),
    ("microsoft", "microsoft.com"),
    ("facebook", "facebook.com"),
    ("instagram", "instagram.com"),
    ("twitter", "twitter.com"),
    ("x", "x.com"),
    ("dropbox", "dropbox.com"),
    ("slack", "slack.com"),
    ("discord", "discord.com"),
    ("cloudflare", "cloudflare.com"),
    ("digitalocean", "digitalocean.com"),
    ("stripe", "stripe.com"),
    ("paypal", "paypal.com"),
    ("coinbase", "coinbase.com"),
    ("linkedin", "linkedin.com"),
    ("shopify", "shopify.com"),
    ("namecheap", "namecheap.com"),
];

/// One parsed TOTP account. `secret` is the raw base32 seed — NEVER serialized into a preview; it
/// lives only in the in-memory staging map until commit/expiry. Deliberately NOT `Serialize`.
#[derive(Debug, Clone)]
pub struct ImportEntry {
    /// Base32, unpadded, uppercase. SECRET — never logged.
    pub secret: String,
    pub issuer: Option<String>,
    /// Account name, e.g. `user@example.com`.
    pub label: Option<String>,
    pub algorithm: String,
    pub digits: i64,
    pub period: i64,
}

impl ImportEntry {
    /// Secret-free view shown to the user before they pick what to import.
    pub fn preview(&self, idx: usize) -> Value {
        json!({
            "idx": idx,
            "issuer": self.issuer,
            "label": self.label,
            "suggested_name": suggested_name(self.issuer.as_deref(), self.label.as_deref()),
            "suggested_domain": guess_domain(self.issuer.as_deref(), self.label.as_deref()),
            "algorithm": self.algorithm,
            "digits": self.digits,
            "period": self.period,
        })
    }
}

// ---------------------------------------------------------------------------
// Public parse entry point
// ---------------------------------------------------------------------------

/// Parse any mix of single `otpauth://` URIs and a Google migration blob into a deduped list of
/// TOTP entries. Non-TOTP (HOTP) and malformed entries are skipped. Errors only if NOTHING usable
/// was found (or the import is absurdly large). The error string is user-facing and secret-free.
pub fn parse_payloads(
    otpauth_uris: &[String],
    migration_payload: Option<&str>,
) -> Result<Vec<ImportEntry>, String> {
    let mut entries: Vec<ImportEntry> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    for uri in otpauth_uris {
        let uri = uri.trim();
        if uri.is_empty() {
            continue;
        }
        if uri.to_ascii_lowercase().starts_with("otpauth-migration://") {
            // Someone pasted a migration URI into the per-account box — handle it.
            match parse_migration_payload(uri) {
                Ok(mut batch) => entries.append(&mut batch),
                Err(e) => errors.push(e),
            }
            continue;
        }
        match parse_otpauth_uri(uri) {
            Ok(Some(entry)) => entries.push(entry),
            Ok(None) => {} // HOTP — counter-based, can't be time-minted
            Err(e) => errors.push(e),
        }
    }

    if let Some(payload) = migration_payload.map(str::trim).filter(|s| !s.is_empty()) {
        match parse_migration_payload(payload) {
            Ok(mut batch) => entries.append(&mut batch),
            Err(e) => errors.push(e),
        }
    }

    let deduped = dedupe(entries);
    if deduped.is_empty() {
        let detail = if errors.is_empty() {
            "no TOTP accounts found in the import".to_string()
        } else {
            errors.into_iter().take(3).collect::<Vec<_>>().join("; ")
        };
        return Err(detail);
    }
    if deduped.len() > MAX_ENTRIES {
        return Err(format!("import has too many accounts ({} > {MAX_ENTRIES})", deduped.len()));
    }
    Ok(deduped)
}

// ---------------------------------------------------------------------------
// otpauth:// URI  (single account)
// ---------------------------------------------------------------------------

/// Parse `otpauth://totp/Label?secret=...&issuer=...&...`.
///
/// Returns `Ok(None)` for HOTP (counter-based — we mint time-based codes, so HOTP can't be
/// mirrored). Errors on a malformed TOTP URI.
pub fn parse_otpauth_uri(uri: &str) -> Result<Option<ImportEntry>, String> {
    let parsed = url::Url::parse(uri).map_err(|_| "not an otpauth:// URI".to_string())?;
    if parsed.scheme() != "otpauth" {
        return Err("not an otpauth:// URI".to_string());
    }
    let otp_type = parsed.host_str().unwrap_or("").to_ascii_lowercase();
    if otp_type == "hotp" {
        return Ok(None);
    }
    if otp_type != "totp" {
        return Err(format!("unsupported otpauth type '{otp_type}'"));
    }

    let q: HashMap<String, String> = parsed
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    let secret_raw = q.get("secret").map(|s| s.trim()).unwrap_or("");
    if secret_raw.is_empty() {
        return Err("otpauth URI missing secret".to_string());
    }
    let secret =
        normalize_base32(secret_raw).ok_or_else(|| "otpauth secret is not valid base32".to_string())?;

    // Label is the path: "/Issuer:account" or "/account". Issuer query param wins.
    let label_raw = percent_decode(parsed.path().trim_start_matches('/'));
    let label_raw = if label_raw.is_empty() { None } else { Some(label_raw) };
    let mut issuer = q.get("issuer").map(|s| s.trim()).filter(|s| !s.is_empty()).map(str::to_string);
    let mut label = label_raw.clone();
    if let Some(raw) = &label_raw {
        if let Some((prefix, rest)) = raw.split_once(':') {
            if issuer.is_none() && !prefix.trim().is_empty() {
                issuer = Some(prefix.trim().to_string());
            }
            let rest = rest.trim();
            label = if rest.is_empty() { label_raw.clone() } else { Some(rest.to_string()) };
        }
    }

    let algorithm = match q.get("algorithm").map(|a| a.to_ascii_uppercase()) {
        Some(a) if a == "SHA256" || a == "SHA512" => a,
        _ => "SHA1".to_string(),
    };
    let digits = match q.get("digits").and_then(|d| d.parse::<i64>().ok()) {
        Some(d) if d == 6 || d == 8 => d,
        _ => 6,
    };
    let period = match q.get("period").and_then(|p| p.parse::<i64>().ok()) {
        Some(p) if p > 0 => p,
        _ => 30,
    };

    Ok(Some(ImportEntry { secret, issuer, label, algorithm, digits, period }))
}

// ---------------------------------------------------------------------------
// otpauth-migration://  (Google Authenticator "Export accounts")
// ---------------------------------------------------------------------------

/// Parse a Google Authenticator export.
///
/// Accepts the full `otpauth-migration://offline?data=<urlencoded-base64>` URI OR just the raw
/// (url/base64) data blob. The blob is a protobuf:
///
/// ```text
/// MigrationPayload { repeated OtpParameters otp_parameters = 1; ... }
/// OtpParameters { bytes secret=1; string name=2; string issuer=3;
///                 Algorithm algorithm=4; DigitCount digits=5;
///                 OtpType type=6; int64 counter=7; }
/// ```
pub fn parse_migration_payload(payload: &str) -> Result<Vec<ImportEntry>, String> {
    let payload = payload.trim();
    let data_b64 = if payload.to_ascii_lowercase().contains("otpauth-migration://") || payload.contains("data=") {
        let parsed = url::Url::parse(payload)
            .map_err(|_| "migration URI is not a valid URI".to_string())?;
        let data = parsed
            .query_pairs()
            .find(|(k, _)| k == "data")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        if data.trim().is_empty() {
            return Err("migration URI missing data= parameter".to_string());
        }
        data.trim().to_string()
    } else {
        payload.to_string()
    };
    // query_pairs already url-decoded; be tolerant if a raw %-encoded blob was passed.
    let data_b64 = percent_decode(&data_b64);
    let raw = b64_decode_loose(&data_b64).ok_or_else(|| "migration data is not valid base64".to_string())?;

    let mut entries: Vec<ImportEntry> = Vec::new();
    for (field_num, wire_type, value) in iter_protobuf_fields(&raw)? {
        if field_num == 1 && wire_type == 2 {
            if let ProtoValue::Bytes(buf) = value {
                if let Some(entry) = parse_otp_parameters(&buf) {
                    entries.push(entry);
                }
            }
        }
    }
    if entries.is_empty() {
        return Err("no TOTP accounts in the Google Authenticator export".to_string());
    }
    Ok(entries)
}

fn parse_otp_parameters(buf: &[u8]) -> Option<ImportEntry> {
    let mut secret_bytes: Option<Vec<u8>> = None;
    let mut name: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut algorithm = "SHA1".to_string();
    let mut digits: i64 = 6;
    let mut otp_type: u64 = 2; // default totp

    // One bad sub-message shouldn't kill the whole import.
    let fields = match iter_protobuf_fields(buf) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "skipping unparseable migration OTP entry");
            return None;
        }
    };
    for (field_num, wire_type, value) in fields {
        match (field_num, wire_type, value) {
            (1, 2, ProtoValue::Bytes(b)) => secret_bytes = Some(b),
            (2, 2, ProtoValue::Bytes(b)) => name = decode_utf8(&b),
            (3, 2, ProtoValue::Bytes(b)) => issuer = decode_utf8(&b),
            (4, 0, ProtoValue::Varint(v)) => {
                algorithm = match v {
                    2 => "SHA256",
                    3 => "SHA512",
                    _ => "SHA1", // 0/1 = SHA1 default; 4 = MD5 unsupported → SHA1
                }
                .to_string()
            }
            (5, 0, ProtoValue::Varint(v)) => digits = if v == 2 { 8 } else { 6 },
            (6, 0, ProtoValue::Varint(v)) => otp_type = v,
            _ => {}
        }
    }

    if otp_type != 2 {
        return None; // 1 = HOTP (counter-based) — can't be time-minted
    }
    let secret_bytes = secret_bytes?;
    if secret_bytes.is_empty() {
        return None;
    }
    let secret = data_encoding::BASE32_NOPAD.encode(&secret_bytes);
    // Google Authenticator's migration export is always 30s period.
    Some(ImportEntry { secret, issuer, label: name, algorithm, digits, period: 30 })
}

// ---------------------------------------------------------------------------
// In-memory staging (preview → commit) — the desktop analog of the cloud's Redis staging
// ---------------------------------------------------------------------------

struct Staged {
    entries: Vec<ImportEntry>,
    expires_at: Instant,
}

fn stage_map() -> &'static Mutex<HashMap<String, Staged>> {
    static STAGE: OnceLock<Mutex<HashMap<String, Staged>>> = OnceLock::new();
    STAGE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Stash the full entries (incl. secrets) under a single-use token, return the token.
/// The loopback API is single-user, so the token scopes only against replay/expiry (the cloud's
/// tenant-namespacing has no local analog).
pub fn stage_entries(entries: Vec<ImportEntry>) -> String {
    let token = uuid::Uuid::new_v4().simple().to_string();
    let mut map = stage_map().lock().expect("authimport stage lock poisoned");
    let now = Instant::now();
    map.retain(|_, s| s.expires_at > now);
    // Bounded: evict the oldest staged import rather than growing without limit.
    while map.len() >= MAX_STAGED {
        if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, s)| s.expires_at)
            .map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        } else {
            break;
        }
    }
    map.insert(token.clone(), Staged { entries, expires_at: now + STAGE_TTL });
    token
}

/// Load a staged import (non-consuming — commit burns it explicitly on success).
pub fn load_staged(token: &str) -> Option<Vec<ImportEntry>> {
    if token.is_empty() {
        return None;
    }
    let mut map = stage_map().lock().expect("authimport stage lock poisoned");
    let now = Instant::now();
    map.retain(|_, s| s.expires_at > now);
    map.get(token).map(|s| s.entries.clone())
}

/// Burn the staging token so an import payload can't be committed twice.
pub fn consume_staged(token: &str) {
    let mut map = stage_map().lock().expect("authimport stage lock poisoned");
    map.remove(token);
}

// ---------------------------------------------------------------------------
// Minimal protobuf wire reader (varint + length-delimited only)
// ---------------------------------------------------------------------------

enum ProtoValue {
    Varint(u64),
    Bytes(Vec<u8>),
    #[allow(dead_code)]
    Fixed(u64),
}

/// Yield `(field_number, wire_type, value)` for a protobuf message. Only the wire types the
/// migration schema uses are decoded in full; fixed32/64 are skipped-with-value so we stay
/// forward-compatible with new fields.
fn iter_protobuf_fields(buf: &[u8]) -> Result<Vec<(u64, u8, ProtoValue)>, String> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let n = buf.len();
    while i < n {
        let (tag, next) = read_varint(buf, i)?;
        i = next;
        let field_num = tag >> 3;
        let wire_type = (tag & 0x07) as u8;
        match wire_type {
            0 => {
                let (val, next) = read_varint(buf, i)?;
                i = next;
                out.push((field_num, 0, ProtoValue::Varint(val)));
            }
            2 => {
                let (len, next) = read_varint(buf, i)?;
                i = next;
                let len = len as usize;
                if i + len > n {
                    return Err("truncated protobuf field".to_string());
                }
                out.push((field_num, 2, ProtoValue::Bytes(buf[i..i + len].to_vec())));
                i += len;
            }
            5 => {
                if i + 4 > n {
                    return Err("truncated protobuf field".to_string());
                }
                let v = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as u64;
                out.push((field_num, 5, ProtoValue::Fixed(v)));
                i += 4;
            }
            1 => {
                if i + 8 > n {
                    return Err("truncated protobuf field".to_string());
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&buf[i..i + 8]);
                out.push((field_num, 1, ProtoValue::Fixed(u64::from_le_bytes(b))));
                i += 8;
            }
            other => return Err(format!("unsupported protobuf wire type {other}")),
        }
    }
    Ok(out)
}

fn read_varint(buf: &[u8], mut i: usize) -> Result<(u64, usize), String> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        let Some(&b) = buf.get(i) else {
            return Err("truncated varint".to_string());
        };
        i += 1;
        result |= u64::from(b & 0x7F) << shift;
        if b & 0x80 == 0 {
            return Ok((result, i));
        }
        shift += 7;
        if shift > 63 {
            return Err("varint too long".to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Strip spaces/dashes/padding, upper-case, and verify the result decodes as base32.
pub fn normalize_base32(secret: &str) -> Option<String> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .trim_end_matches('=')
        .to_ascii_uppercase();
    if cleaned.is_empty() {
        return None;
    }
    data_encoding::BASE32_NOPAD.decode(cleaned.as_bytes()).ok()?;
    Some(cleaned)
}

/// Decode standard or url-safe base64, tolerating missing padding.
fn b64_decode_loose(data: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let s: String = data.chars().filter(|c| *c != '\n' && *c != '\r').collect();
    let s = s.trim();
    let padded = format!("{s}{}", "=".repeat((4 - s.len() % 4) % 4));
    base64::engine::general_purpose::STANDARD
        .decode(padded.as_bytes())
        .ok()
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(padded.as_bytes()).ok())
}

/// Minimal `%XX` decoder for otpauth label paths (the `url` crate leaves path segments encoded).
/// Invalid escapes pass through literally — parity with Python's tolerant `unquote`.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(b) = hex {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn decode_utf8(b: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(b).into_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Drop exact duplicate seeds (same secret+issuer+label) — common when a user pastes URIs and also
/// uploads a migration blob that overlaps.
fn dedupe(entries: Vec<ImportEntry>) -> Vec<ImportEntry> {
    let mut seen: std::collections::HashSet<(String, String, String)> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        let key = (
            e.secret.clone(),
            e.issuer.clone().unwrap_or_default().to_lowercase(),
            e.label.clone().unwrap_or_default().to_lowercase(),
        );
        if seen.insert(key) {
            out.push(e);
        }
    }
    out
}

pub fn suggested_name(issuer: Option<&str>, label: Option<&str>) -> String {
    let issuer = issuer.map(str::trim).unwrap_or("");
    let label = label.map(str::trim).unwrap_or("");
    if !issuer.is_empty() && !label.is_empty() {
        return format!("{issuer} — {label}");
    }
    if !issuer.is_empty() {
        return issuer.to_string();
    }
    if !label.is_empty() {
        return label.to_string();
    }
    "Imported account".to_string()
}

/// Best-effort target_domain for the preview; `None` when we can't tell.
pub fn guess_domain(issuer: Option<&str>, label: Option<&str>) -> Option<String> {
    for candidate in [issuer, label] {
        let c = candidate.map(str::trim).unwrap_or("").to_lowercase();
        if c.is_empty() {
            continue;
        }
        if c.contains('.') && !c.contains(' ') {
            // Already looks like a domain / email host.
            let host = c.rsplit('@').next().unwrap_or(&c);
            return Some(host.split('/').next().unwrap_or(host).to_string());
        }
        if let Some((_, hint)) = ISSUER_DOMAIN_HINTS.iter().find(|(k, _)| *k == c) {
            return Some((*hint).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plain_totp_uri() {
        let e = parse_otpauth_uri(
            "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&digits=6&period=30",
        )
        .unwrap()
        .unwrap();
        assert_eq!(e.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(e.issuer.as_deref(), Some("GitHub"));
        assert_eq!(e.label.as_deref(), Some("octocat"));
        assert_eq!(e.algorithm, "SHA1");
        assert_eq!((e.digits, e.period), (6, 30));
    }

    #[test]
    fn label_prefix_supplies_issuer_when_param_absent() {
        let e = parse_otpauth_uri("otpauth://totp/Shopify:me%40shop.com?secret=JBSWY3DPEHPK3PXP")
            .unwrap()
            .unwrap();
        assert_eq!(e.issuer.as_deref(), Some("Shopify"));
        assert_eq!(e.label.as_deref(), Some("me@shop.com"));
    }

    #[test]
    fn hotp_is_skipped_and_bad_uris_error() {
        assert!(parse_otpauth_uri("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1")
            .unwrap()
            .is_none());
        assert!(parse_otpauth_uri("https://example.com").is_err());
        assert!(parse_otpauth_uri("otpauth://totp/x?secret=notbase32!!").is_err());
    }

    /// A migration payload built by hand: MigrationPayload{ otp_parameters { secret "Hello!\xDE\xAD\xBE\xEF",
    /// name "acct", issuer "Iss", algorithm 1, digits 1, type 2 } } — mirrors the cloud test vector.
    #[test]
    fn parses_a_google_migration_blob() {
        use base64::Engine as _;
        // Inner OtpParameters message.
        let secret = b"Hello!\xde\xad\xbe\xef";
        let mut inner: Vec<u8> = Vec::new();
        inner.extend([0x0A, secret.len() as u8]); // field 1 (secret), wire 2
        inner.extend(secret);
        inner.extend([0x12, 4]); // field 2 (name), wire 2
        inner.extend(b"acct");
        inner.extend([0x1A, 3]); // field 3 (issuer), wire 2
        inner.extend(b"Iss");
        inner.extend([0x20, 1]); // field 4 (algorithm) = 1 (SHA1)
        inner.extend([0x28, 1]); // field 5 (digits) = 1 (six)
        inner.extend([0x30, 2]); // field 6 (type) = 2 (totp)
        // Outer MigrationPayload: field 1, wire 2.
        let mut outer: Vec<u8> = vec![0x0A, inner.len() as u8];
        outer.extend(&inner);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&outer);

        let entries = parse_migration_payload(&b64).unwrap();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.label.as_deref(), Some("acct"));
        assert_eq!(e.issuer.as_deref(), Some("Iss"));
        assert_eq!(e.algorithm, "SHA1");
        assert_eq!((e.digits, e.period), (6, 30));
        assert_eq!(e.secret, data_encoding::BASE32_NOPAD.encode(secret));

        // The full URI form parses identically (data= is url-encoded base64).
        let uri = format!(
            "otpauth-migration://offline?data={}",
            b64.replace('+', "%2B").replace('/', "%2F").replace('=', "%3D")
        );
        let entries2 = parse_migration_payload(&uri).unwrap();
        assert_eq!(entries2[0].secret, e.secret);
    }

    #[test]
    fn staging_is_single_use_and_expires() {
        let entries = vec![ImportEntry {
            secret: "JBSWY3DPEHPK3PXP".into(),
            issuer: None,
            label: Some("a".into()),
            algorithm: "SHA1".into(),
            digits: 6,
            period: 30,
        }];
        let token = stage_entries(entries);
        assert_eq!(load_staged(&token).unwrap().len(), 1);
        consume_staged(&token);
        assert!(load_staged(&token).is_none(), "consumed token must not load again");
        assert!(load_staged("nope").is_none());
    }

    #[test]
    fn dedupe_and_payload_mix() {
        let uri = "otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub".to_string();
        let entries = parse_payloads(&[uri.clone(), uri], None).unwrap();
        assert_eq!(entries.len(), 1, "duplicate URIs collapse to one entry");
        assert!(parse_payloads(&[], None).is_err(), "an empty import errors");
    }

    #[test]
    fn domain_guessing_and_names() {
        assert_eq!(guess_domain(Some("GitHub"), None).as_deref(), Some("github.com"));
        assert_eq!(guess_domain(None, Some("me@corp.io")).as_deref(), Some("corp.io"));
        assert_eq!(guess_domain(Some("Unknown Co"), None), None);
        assert_eq!(suggested_name(Some("Iss"), Some("acct")), "Iss — acct");
        assert_eq!(suggested_name(None, None), "Imported account");
    }
}
