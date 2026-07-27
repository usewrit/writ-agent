//! Desktop credential seam for cloud-dispatched work (A2).
//!
//! This is the DESKTOP mirror of `bridge/saas_bridge::resolve_credentials`. The cloud agent decrypts
//! per-run credentials with the channel key it stashed in the cloud-BUILD credentials file
//! (`auth::load_credentials()`); the desktop daemon has NO such file — its per-agent Fernet channel
//! key lives ONLY in the OS keyring (`super::super::channel::get()`), captured at device-link. So this
//! module reads the key from the keyring (exactly like `marketplace::unseal_recipe`) and reuses the
//! shared Fernet decrypt.
//!
//! SECURITY (the never-trust-a-BYO-agent rule + marketplace invariant 4):
//!  * Fail CLOSED: no channel key → [`LocalError::Unauthorized`] (re-link required); no partial creds.
//!  * The plaintext credential map lives only in memory (returned to the caller for the run) and is
//!    NEVER persisted / logged. The reserved `__proxy__` object is stripped from the string map and
//!    returned separately as a [`ProxyOverride`] so a non-string value can't collapse the whole map.
//!  * The decrypt uses the keyring channel key ONLY — never a value carried in the wire frame.

use std::collections::HashMap;

use serde_json::Value;

use super::super::super::error::{LocalError, LocalResult};

/// A per-run BYO proxy override carried as the reserved `__proxy__` key inside the sealed credentials
/// (`{server, username, password, bypass}`). Mirrors the shape `saas_bridge::extract_proxy_override`
/// maps to `playwright_rs::protocol::ProxySettings`; kept as a plain struct here so `creds.rs` is
/// independent of the browser protocol crate and trivially testable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyOverride {
    pub server: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub bypass: Option<String>,
}

impl ProxyOverride {
    /// Map to the browser-context proxy settings the run pipeline applies.
    pub fn to_proxy_settings(&self) -> playwright_rs::protocol::ProxySettings {
        playwright_rs::protocol::ProxySettings {
            server: self.server.clone(),
            bypass: self.bypass.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
        }
    }
}

/// Resolve the credential map + optional proxy override for a cloud-dispatched run.
///
/// `config` is the run frame's `config` object (the same shape the cloud agent's
/// `resolve_credentials` reads). Reads the keyring channel key, Fernet-decrypts the
/// `credentials_encrypted` blob, keeps only string-valued entries as the credential map, and strips
/// `__proxy__` out as a [`ProxyOverride`]. When no `credentials_encrypted` blob is present it falls
/// back to a pre-decrypted `credentials_decrypted` object (the daemon may inject one in-memory).
///
/// Fail-closed: a `credentials_encrypted` blob with NO channel key in the keyring →
/// [`LocalError::Unauthorized`] (never returns partial/plaintext creds). A frame with no credentials
/// at all → an empty map + `None` proxy (a BYO-clean supply-pool recipe legitimately carries none).
pub fn resolve_credentials(
    config: &Value,
) -> LocalResult<(HashMap<String, String>, Option<ProxyOverride>)> {
    // 1) Prefer the channel_key-sealed blob (the normal cloud-dispatch path).
    if let Some(encrypted) = config
        .get("credentials_encrypted")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        // No channel key → fail closed (re-link required). We do NOT fall through to any other path
        // for a SEALED blob: an encrypted blob we can't open must never silently yield empty creds.
        let key = super::super::channel::get()?.ok_or(LocalError::Unauthorized)?;
        let map = decrypt_object_with_key(encrypted, key.expose())?;
        return Ok(split_object(map));
    }

    // 2) Fallback: a pre-decrypted `credentials_decrypted` object (string or object), injected
    //    in-memory by the daemon for a reused handler. Never persisted.
    if let Some(creds_val) = config.get("credentials_decrypted") {
        let map = match creds_val {
            Value::String(s) => serde_json::from_str::<serde_json::Map<String, Value>>(s).ok(),
            Value::Object(m) => Some(m.clone()),
            _ => None,
        };
        if let Some(map) = map {
            return Ok(split_object(map));
        }
    }

    // 3) No credentials on the frame — a BYO-clean recipe legitimately carries none.
    Ok((HashMap::new(), None))
}

/// Fernet-decrypt an encrypted credentials blob to a JSON object WITHOUT collapsing values to strings
/// (so the reserved `__proxy__` object survives). Mirrors `saas_bridge::decrypt_credentials_object`,
/// keyed on the passed channel key. Fails closed on a bad key / decrypt / non-object payload.
fn decrypt_object_with_key(
    encrypted: &str,
    channel_key: &str,
) -> LocalResult<serde_json::Map<String, Value>> {
    let fernet = fernet::Fernet::new(channel_key)
        .ok_or_else(|| LocalError::Internal("invalid channel key (not a Fernet key)".into()))?;
    let plaintext = fernet
        .decrypt(encrypted)
        .map_err(|_| LocalError::Unauthorized)?; // key mismatch/tamper → unauthorized, not a 500
    let json_str = String::from_utf8(plaintext)
        .map_err(|_| LocalError::Internal("decrypted credentials are not valid UTF-8".into()))?;
    match serde_json::from_str::<Value>(&json_str) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(LocalError::Internal("decrypted credentials are not a JSON object".into())),
    }
}

/// Split a decrypted credentials object into (string-valued credential map, optional `__proxy__`
/// override). `__proxy__` is stripped from the map and parsed separately; a proxy is accepted ONLY
/// when it is an object with a non-empty `server` (mirrors the cloud agent's guard). Any other
/// non-string entry is dropped so a stray value can't collapse the whole map.
fn split_object(
    mut map: serde_json::Map<String, Value>,
) -> (HashMap<String, String>, Option<ProxyOverride>) {
    let proxy = map.remove("__proxy__").and_then(|v| parse_proxy(&v));
    let creds: HashMap<String, String> = map
        .into_iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
        .collect();
    (creds, proxy)
}

/// Parse a `__proxy__` value into a [`ProxyOverride`]. Requires an object with a non-empty `server`
/// (mirrors `saas_bridge::extract_proxy_override`); returns `None` otherwise → the run falls back to
/// env proxy / direct egress.
fn parse_proxy(v: &Value) -> Option<ProxyOverride> {
    let obj = v.as_object()?;
    let server = obj
        .get("server")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())?
        .to_string();
    let str_field = |k: &str| {
        obj.get(k)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };
    Some(ProxyOverride {
        server,
        username: str_field("username"),
        password: str_field("password"),
        bypass: str_field("bypass"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Encrypt a JSON object with a fresh Fernet key → the wire `credentials_encrypted` string.
    fn seal(key: &str, obj: &Value) -> String {
        let fernet = fernet::Fernet::new(key).unwrap();
        fernet.encrypt(serde_json::to_string(obj).unwrap().as_bytes())
    }

    #[test]
    fn split_object_strips_proxy_and_keeps_strings() {
        let map = serde_json::from_value::<serde_json::Map<String, Value>>(json!({
            "username": "alice",
            "password": "s3cret",
            "port": 8080, // non-string, non-proxy → dropped (must not collapse the map)
            "__proxy__": { "server": "http://proxy:3128", "username": "pu", "bypass": "*.local" }
        }))
        .unwrap();
        let (creds, proxy) = split_object(map);
        assert_eq!(creds.get("username").map(String::as_str), Some("alice"));
        assert_eq!(creds.get("password").map(String::as_str), Some("s3cret"));
        assert!(!creds.contains_key("__proxy__"), "proxy must be stripped from the cred map");
        assert!(!creds.contains_key("port"), "non-string entries dropped");
        let proxy = proxy.expect("proxy override parsed");
        assert_eq!(proxy.server, "http://proxy:3128");
        assert_eq!(proxy.username.as_deref(), Some("pu"));
        assert_eq!(proxy.bypass.as_deref(), Some("*.local"));
        assert_eq!(proxy.password, None);
    }

    #[test]
    fn parse_proxy_requires_non_empty_server() {
        assert!(parse_proxy(&json!({ "username": "u" })).is_none(), "no server → None");
        assert!(parse_proxy(&json!({ "server": "" })).is_none(), "empty server → None");
        assert!(parse_proxy(&json!("not-an-object")).is_none());
        assert_eq!(
            parse_proxy(&json!({ "server": "http://p:1" })).unwrap().server,
            "http://p:1"
        );
    }

    #[test]
    fn decrypt_object_round_trips_via_channel_key() {
        // Fernet round-trip through the SAME key path the resolve uses (no keyring needed for the
        // core decrypt — the keyring read is exercised by the live link).
        let key = fernet::Fernet::generate_key();
        let sealed = seal(&key, &json!({ "username": "bob", "__proxy__": { "server": "http://x:9" } }));
        let map = decrypt_object_with_key(&sealed, &key).unwrap();
        let (creds, proxy) = split_object(map);
        assert_eq!(creds.get("username").map(String::as_str), Some("bob"));
        assert_eq!(proxy.unwrap().server, "http://x:9");
    }

    #[test]
    fn decrypt_object_fails_closed_on_wrong_key() {
        let key = fernet::Fernet::generate_key();
        let other = fernet::Fernet::generate_key();
        let sealed = seal(&key, &json!({ "username": "bob" }));
        // Wrong key → Unauthorized (never a partial/plaintext leak).
        let err = decrypt_object_with_key(&sealed, &other).unwrap_err();
        assert!(matches!(err, LocalError::Unauthorized), "wrong key → Unauthorized, got {err:?}");
    }

    #[test]
    fn decrypt_object_rejects_non_fernet_key() {
        let err = decrypt_object_with_key("whatever", "not-a-fernet-key").unwrap_err();
        assert!(matches!(err, LocalError::Internal(_)), "bad key → Internal");
    }

    #[test]
    fn resolve_credentials_no_blob_yields_empty() {
        // A BYO-clean frame with no credentials at all → empty map, no proxy, no error (no keyring
        // touch since there is no sealed blob to open).
        let (creds, proxy) = resolve_credentials(&json!({})).unwrap();
        assert!(creds.is_empty());
        assert!(proxy.is_none());
    }

    #[test]
    fn resolve_credentials_reads_predecrypted_object() {
        // In-memory `credentials_decrypted` object path (daemon-injected) → parsed without a keyring
        // read; `__proxy__` split out.
        let cfg = json!({
            "credentials_decrypted": { "api_token": "t0k", "__proxy__": { "server": "http://p:2" } }
        });
        let (creds, proxy) = resolve_credentials(&cfg).unwrap();
        assert_eq!(creds.get("api_token").map(String::as_str), Some("t0k"));
        assert_eq!(proxy.unwrap().server, "http://p:2");
    }

    #[test]
    fn resolve_credentials_reads_predecrypted_string() {
        let cfg = json!({ "credentials_decrypted": "{\"k\":\"v\"}" });
        let (creds, proxy) = resolve_credentials(&cfg).unwrap();
        assert_eq!(creds.get("k").map(String::as_str), Some("v"));
        assert!(proxy.is_none());
    }
}
