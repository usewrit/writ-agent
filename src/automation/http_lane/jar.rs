//! A small, serializable cookie jar for the browserless HTTP lane.
//!
//! reqwest's own cookie store is not enabled (and can't be enumerated to round-trip a persisted
//! session), and the lane drives redirects manually anyway (per-hop SSRF re-vet + Set-Cookie capture),
//! so we keep our own RFC 6265-subset jar. It round-trips the exact Playwright cookie JSON shape used
//! by `SessionState.cookies` so a session captured by a browser run restores into the HTTP lane and
//! vice versa.

use serde_json::Value;
use url::Url;

/// A stored cookie in Playwright's field vocabulary.
#[derive(Debug, Clone)]
struct StoredCookie {
    name: String,
    value: String,
    /// Verbatim Playwright form: a leading `.` (".example.com") = domain cookie; no dot = host-only.
    domain: String,
    path: String,
    /// Seconds since epoch; `-1` = session cookie (Playwright convention).
    expires: f64,
    http_only: bool,
    secure: bool,
    /// "Strict" | "Lax" | "None" — preserved for round-trip fidelity; never enforced by the lane.
    same_site: Option<String>,
    /// RFC 6265 §5.4 ordering tiebreaker (lower = created earlier).
    creation_index: u64,
}

/// Hard cap on stored cookies.
///
/// WHY: the jar never evicted and is PERSISTED into `SessionState` by `export_session_state`, so a
/// hostile (or merely chatty) login endpoint that sets a new `Set-Cookie` name on every request grew
/// the stored session without bound — across runs, since the session is reloaded next time. It is also
/// scanned linearly on every request. Browsers apply the same kind of limit (Chrome: 180 per domain,
/// ~3 300 total); this is deliberately generous relative to any real site.
const MAX_COOKIES: usize = 512;

#[derive(Debug, Default)]
pub struct CookieJar {
    cookies: Vec<StoredCookie>,
    next_creation_index: u64,
}

impl CookieJar {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make room for one more cookie, evicting only if the jar is full.
    ///
    /// Eviction policy, in order: (1) an already-EXPIRED cookie — it would never be sent again anyway;
    /// (2) otherwise the OLDEST-created cookie (lowest `creation_index`), i.e. least-recently-set.
    /// Session/auth cookies are set at login and then refreshed, so their creation index keeps moving
    /// forward while filler cookies age out — the policy therefore protects exactly the cookies a
    /// warm run depends on.
    fn make_room(&mut self, now: f64) {
        if self.cookies.len() < MAX_COOKIES {
            return;
        }
        if let Some(pos) = self
            .cookies
            .iter()
            .position(|c| c.expires != -1.0 && c.expires <= now)
        {
            self.cookies.remove(pos);
            return;
        }
        if let Some((pos, _)) = self
            .cookies
            .iter()
            .enumerate()
            .min_by_key(|(_, c)| c.creation_index)
        {
            self.cookies.remove(pos);
        }
    }

    /// Seed the jar from persisted `SessionState.cookies` (Playwright JSON objects).
    pub fn from_session_cookies(cookies: &[Value]) -> Self {
        let mut jar = Self::new();
        for c in cookies {
            let (Some(name), Some(value)) = (
                c.get("name").and_then(Value::as_str),
                c.get("value").and_then(Value::as_str),
            ) else {
                continue; // same as inject_session_state: skip a cookie missing name/value
            };
            let domain = c.get("domain").and_then(Value::as_str).unwrap_or("").to_string();
            let path = c.get("path").and_then(Value::as_str).unwrap_or("/").to_string();
            let expires = c.get("expires").and_then(Value::as_f64).unwrap_or(-1.0);
            let http_only = c.get("httpOnly").and_then(Value::as_bool).unwrap_or(false);
            let secure = c.get("secure").and_then(Value::as_bool).unwrap_or(false);
            let same_site = c
                .get("sameSite")
                .and_then(Value::as_str)
                .map(normalize_same_site);
            // A persisted session can already be over the cap (written before this limit existed, or
            // by a browser run). Keep the FIRST MAX_COOKIES so seeding is deterministic.
            if jar.cookies.len() >= MAX_COOKIES {
                break;
            }
            let idx = jar.next_creation_index;
            jar.next_creation_index += 1;
            jar.cookies.push(StoredCookie {
                name: name.to_string(),
                value: value.to_string(),
                domain,
                path,
                expires,
                http_only,
                secure,
                same_site,
                creation_index: idx,
            });
        }
        jar
    }

    /// Export to the exact 8-key Playwright JSON shape `extract_session_state` emits (so a byte-for-byte
    /// round-trip with a browser-captured session holds). `sameSite` serializes to JSON `null` when
    /// unknown so the key set always matches.
    pub fn to_session_cookies(&self) -> Vec<Value> {
        self.cookies
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "value": c.value,
                    "domain": c.domain,
                    "path": c.path,
                    // Emit -1 as an integer to match Playwright's own output for session cookies.
                    "expires": if c.expires == -1.0 { serde_json::json!(-1) } else { serde_json::json!(c.expires) },
                    "httpOnly": c.http_only,
                    "secure": c.secure,
                    "sameSite": c.same_site,
                })
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.cookies.is_empty()
    }

    /// The value of the most-recently-set cookie with `name` (any domain/path). Used by an AuthRecipe
    /// `from: "cookie"` extraction, which reads a session/csrf cookie the login set.
    pub fn value_of(&self, name: &str) -> Option<String> {
        self.cookies
            .iter()
            .filter(|c| c.name == name)
            .max_by_key(|c| c.creation_index)
            .map(|c| c.value.clone())
    }

    /// Inject a cookie directly (AuthRecipe `store: {as: "cookie"}`). Stored host-only for `domain`.
    pub fn set_cookie(&mut self, name: &str, value: &str, domain: &str, path: &str) {
        self.cookies.retain(|c| !(c.name == name && c.domain == domain && c.path == path));
        self.make_room(now_epoch_wall());
        let idx = self.next_creation_index;
        self.next_creation_index += 1;
        self.cookies.push(StoredCookie {
            name: name.to_string(),
            value: value.to_string(),
            domain: domain.to_string(),
            path: path.to_string(),
            expires: -1.0,
            http_only: false,
            secure: false,
            same_site: None,
            creation_index: idx,
        });
    }

    pub fn clear(&mut self) {
        self.cookies.clear();
    }

    /// The `Cookie:` header value to send with a request to `url` at time `now_epoch` (seconds), or
    /// `None` when no cookie matches. Applies RFC 6265 domain/path/secure/expiry matching; ordering is
    /// longest-path-first then creation order.
    pub fn cookie_header_for(&self, url: &Url, now_epoch: f64) -> Option<String> {
        let host = url.host_str()?.to_ascii_lowercase();
        let is_https = url.scheme() == "https";
        let req_path = if url.path().is_empty() { "/" } else { url.path() };

        let mut matches: Vec<&StoredCookie> = self
            .cookies
            .iter()
            .filter(|c| {
                if c.expires != -1.0 && c.expires <= now_epoch {
                    return false; // expired
                }
                if c.secure && !is_https {
                    return false;
                }
                if !domain_matches(&host, &c.domain) {
                    return false;
                }
                path_matches(req_path, &c.path)
            })
            .collect();

        // RFC 6265 §5.4: cookies with longer paths first; ties broken by earlier creation.
        matches.sort_by(|a, b| {
            b.path
                .len()
                .cmp(&a.path.len())
                .then(a.creation_index.cmp(&b.creation_index))
        });

        if matches.is_empty() {
            return None;
        }
        Some(
            matches
                .iter()
                .map(|c| format!("{}={}", c.name, c.value))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    /// Store a `Set-Cookie` header value received from `request_url`. Ignores unparseable headers and
    /// rejects a `Domain=` attribute that doesn't domain-match the request host (RFC 6265 §5.3).
    pub fn store_set_cookie(&mut self, request_url: &Url, set_cookie: &str) {
        let Some(host) = request_url.host_str().map(|h| h.to_ascii_lowercase()) else {
            return;
        };
        let mut parts = set_cookie.split(';');
        let Some(nv) = parts.next() else { return };
        let Some(eq) = nv.find('=') else { return };
        let name = nv[..eq].trim().to_string();
        let value = nv[eq + 1..].trim().to_string();
        if name.is_empty() {
            return;
        }

        let mut domain_attr: Option<String> = None;
        let mut path_attr: Option<String> = None;
        let mut expires_attr: Option<f64> = None;
        let mut max_age_attr: Option<f64> = None;
        let mut http_only = false;
        let mut secure = false;
        let mut same_site: Option<String> = None;

        for attr in parts {
            let attr = attr.trim();
            let (k, v) = match attr.find('=') {
                Some(i) => (attr[..i].trim(), attr[i + 1..].trim()),
                None => (attr, ""),
            };
            match k.to_ascii_lowercase().as_str() {
                "domain"
                    if !v.is_empty() => {
                        domain_attr = Some(v.trim_start_matches('.').to_ascii_lowercase());
                    }
                "path"
                    if v.starts_with('/') => {
                        path_attr = Some(v.to_string());
                    }
                "expires" => {
                    if let Ok(dt) = chrono::DateTime::parse_from_rfc2822(v) {
                        expires_attr = Some(dt.timestamp() as f64);
                    } else if let Ok(dt) = chrono::DateTime::parse_from_str(v, "%a, %d-%b-%Y %H:%M:%S GMT") {
                        expires_attr = Some(dt.timestamp() as f64);
                    }
                }
                "max-age" => {
                    if let Ok(secs) = v.parse::<i64>() {
                        // Interpreted relative to "now" by the caller's clock is not available here;
                        // store as an absolute using chrono::Utc::now would break resume determinism in
                        // tests, so we encode Max-Age as (now-agnostic) by resolving against a passed
                        // clock is not possible — use a large sentinel handled below.
                        max_age_attr = Some(secs as f64);
                    }
                }
                "httponly" => http_only = true,
                "secure" => secure = true,
                "samesite"
                    if !v.is_empty() => {
                        same_site = Some(normalize_same_site(v));
                    }
                _ => {}
            }
        }

        // Domain: an explicit attribute must domain-match the request host (no cross-site set).
        let domain = match domain_attr {
            Some(d) => {
                if host == d || host.ends_with(&format!(".{d}")) {
                    format!(".{d}") // store as a dotted domain cookie
                } else {
                    return; // reject cross-domain cookie
                }
            }
            None => host.clone(), // host-only
        };

        // Path default (RFC 6265 §5.1.4): the request path up to the last '/'.
        let path = path_attr.unwrap_or_else(|| default_path(request_url));

        // Expiry: Max-Age wins over Expires. Max-Age is relative; the caller resolves "now" via
        // `cookie_header_for`, but we need an absolute here — resolve against the wall clock.
        let expires = if let Some(ma) = max_age_attr {
            now_epoch_wall() + ma
        } else {
            expires_attr.unwrap_or(-1.0)
        };

        // Replace an existing cookie with the same (name, domain, path) — RFC 6265 §5.3 step 11.
        self.cookies
            .retain(|c| !(c.name == name && c.domain == domain && c.path == path));
        // Bound the jar (it is persisted into SessionState, so unbounded growth outlives the run).
        self.make_room(now_epoch_wall());
        let idx = self.next_creation_index;
        self.next_creation_index += 1;
        self.cookies.push(StoredCookie {
            name,
            value,
            domain,
            path,
            expires,
            http_only,
            secure,
            same_site,
            creation_index: idx,
        });
    }
}

/// Wall-clock epoch seconds. Isolated in one place so tests that need determinism can avoid the
/// Max-Age path (they use absolute `expires` instead).
fn now_epoch_wall() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn normalize_same_site(v: &str) -> String {
    match v.trim().to_ascii_lowercase().as_str() {
        "strict" => "Strict".to_string(),
        "lax" => "Lax".to_string(),
        "none" => "None".to_string(),
        other => {
            // Preserve an unexpected value capitalized, best-effort.
            let mut c = other.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        }
    }
}

/// RFC 6265 §5.1.3 domain match. `cookie_domain` is the stored form (leading `.` = domain cookie).
fn domain_matches(host: &str, cookie_domain: &str) -> bool {
    if cookie_domain.is_empty() {
        return false;
    }
    if let Some(bare) = cookie_domain.strip_prefix('.') {
        host == bare || host.ends_with(&format!(".{bare}"))
    } else {
        host == cookie_domain // host-only
    }
}

/// RFC 6265 §5.1.4 path match.
fn path_matches(req_path: &str, cookie_path: &str) -> bool {
    if cookie_path == req_path {
        return true;
    }
    if let Some(rest) = req_path.strip_prefix(cookie_path) {
        return cookie_path.ends_with('/') || rest.starts_with('/');
    }
    false
}

/// RFC 6265 §5.1.4 default-path: the request URI path up to (not including) the rightmost '/'.
fn default_path(url: &Url) -> String {
    let p = url.path();
    if !p.starts_with('/') {
        return "/".to_string();
    }
    match p.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => p[..i].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn u(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn roundtrip_session_cookie_and_flags() {
        let cookies = vec![json!({
            "name": "sid", "value": "abc", "domain": ".example.com", "path": "/",
            "expires": -1, "httpOnly": true, "secure": true, "sameSite": "Lax"
        })];
        let jar = CookieJar::from_session_cookies(&cookies);
        let out = jar.to_session_cookies();
        assert_eq!(out.len(), 1);
        let c = &out[0];
        assert_eq!(c["name"], json!("sid"));
        assert_eq!(c["domain"], json!(".example.com"));
        assert_eq!(c["expires"], json!(-1)); // stays an integer -1 (session cookie)
        assert_eq!(c["httpOnly"], json!(true));
        assert_eq!(c["secure"], json!(true));
        assert_eq!(c["sameSite"], json!("Lax"));
    }

    #[test]
    fn unknown_same_site_serializes_null() {
        let cookies = vec![json!({"name":"a","value":"b","domain":"x.com","path":"/","expires":-1})];
        let jar = CookieJar::from_session_cookies(&cookies);
        assert_eq!(jar.to_session_cookies()[0]["sameSite"], Value::Null);
    }

    #[test]
    fn host_only_vs_domain_cookie_matching() {
        let jar = CookieJar::from_session_cookies(&[
            json!({"name":"h","value":"1","domain":"example.com","path":"/","expires":-1}),
            json!({"name":"d","value":"2","domain":".example.com","path":"/","expires":-1}),
        ]);
        // host-only "example.com" matches example.com but NOT sub.example.com
        let hdr = jar.cookie_header_for(&u("https://example.com/x"), 0.0).unwrap();
        assert!(hdr.contains("h=1") && hdr.contains("d=2"));
        let sub = jar.cookie_header_for(&u("https://sub.example.com/x"), 0.0).unwrap();
        assert!(!sub.contains("h=1") && sub.contains("d=2"));
    }

    #[test]
    fn secure_cookie_not_sent_over_http() {
        let jar = CookieJar::from_session_cookies(&[
            json!({"name":"s","value":"1","domain":"example.com","path":"/","expires":-1,"secure":true}),
        ]);
        assert!(jar.cookie_header_for(&u("http://example.com/"), 0.0).is_none());
        assert!(jar.cookie_header_for(&u("https://example.com/"), 0.0).is_some());
    }

    #[test]
    fn expired_cookie_dropped() {
        let jar = CookieJar::from_session_cookies(&[
            json!({"name":"e","value":"1","domain":"example.com","path":"/","expires":100.0}),
        ]);
        assert!(jar.cookie_header_for(&u("https://example.com/"), 200.0).is_none());
        assert!(jar.cookie_header_for(&u("https://example.com/"), 50.0).is_some());
    }

    #[test]
    fn path_match_and_ordering() {
        let jar = CookieJar::from_session_cookies(&[
            json!({"name":"root","value":"1","domain":"example.com","path":"/","expires":-1}),
            json!({"name":"deep","value":"2","domain":"example.com","path":"/api","expires":-1}),
        ]);
        // /api request gets both, longest path first
        let hdr = jar.cookie_header_for(&u("https://example.com/api/x"), 0.0).unwrap();
        assert_eq!(hdr, "deep=2; root=1");
        // / request gets only root
        let hdr2 = jar.cookie_header_for(&u("https://example.com/"), 0.0).unwrap();
        assert_eq!(hdr2, "root=1");
    }

    #[test]
    fn store_set_cookie_host_only_and_replace() {
        let mut jar = CookieJar::new();
        jar.store_set_cookie(&u("https://example.com/login"), "sid=abc; Path=/; HttpOnly");
        let hdr = jar.cookie_header_for(&u("https://example.com/x"), 0.0).unwrap();
        assert_eq!(hdr, "sid=abc");
        // Replace same name/domain/path
        jar.store_set_cookie(&u("https://example.com/login"), "sid=def; Path=/");
        let hdr = jar.cookie_header_for(&u("https://example.com/x"), 0.0).unwrap();
        assert_eq!(hdr, "sid=def");
        // Host-only: not sent to a subdomain
        assert!(jar.cookie_header_for(&u("https://sub.example.com/"), 0.0).is_none());
    }

    #[test]
    fn store_set_cookie_rejects_cross_domain() {
        let mut jar = CookieJar::new();
        jar.store_set_cookie(&u("https://example.com/"), "x=1; Domain=evil.com");
        assert!(jar.is_empty());
        // A valid parent-domain attribute is accepted and becomes a domain cookie.
        jar.store_set_cookie(&u("https://sub.example.com/"), "y=1; Domain=example.com");
        assert!(jar.cookie_header_for(&u("https://other.example.com/"), 0.0).is_some());
    }

    /// A hostile login endpoint that sets a fresh cookie NAME on every request must not grow the jar
    /// without bound — the jar is persisted into `SessionState`, so the growth would outlive the run.
    #[test]
    fn jar_is_bounded_and_evicts_oldest() {
        let mut jar = CookieJar::new();
        for i in 0..(MAX_COOKIES * 3) {
            jar.store_set_cookie(&u("https://example.com/"), &format!("k{i}=v; Path=/"));
        }
        assert_eq!(jar.cookies.len(), MAX_COOKIES, "jar not bounded");
        // The most recent cookies survive; the earliest were evicted.
        assert!(jar.value_of(&format!("k{}", MAX_COOKIES * 3 - 1)).is_some(), "newest evicted");
        assert!(jar.value_of("k0").is_none(), "oldest not evicted");
    }

    /// Eviction prefers an ALREADY-EXPIRED cookie over a live one, so filling the jar cannot knock out
    /// the session cookie a warm run needs while dead entries are still sitting there.
    #[test]
    fn eviction_prefers_expired_over_live_cookies() {
        let mut jar = CookieJar::new();
        // A live session cookie set FIRST (lowest creation index — the plain LRU victim).
        jar.store_set_cookie(&u("https://example.com/"), "sid=secret; Path=/");
        // An already-expired filler cookie.
        jar.store_set_cookie(
            &u("https://example.com/"),
            "dead=x; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        );
        for i in 0..(MAX_COOKIES - 2) {
            jar.store_set_cookie(&u("https://example.com/"), &format!("f{i}=v; Path=/"));
        }
        assert_eq!(jar.cookies.len(), MAX_COOKIES);
        // One more insert must reclaim the expired cookie, not the session one.
        jar.store_set_cookie(&u("https://example.com/"), "extra=1; Path=/");
        assert_eq!(jar.value_of("sid").as_deref(), Some("secret"), "session cookie evicted");
        assert!(jar.value_of("dead").is_none(), "expired cookie not reclaimed");
    }

    /// A persisted session that is ALREADY over the cap (written before the limit existed) is
    /// truncated on seed rather than restored unbounded.
    #[test]
    fn seeding_from_a_bloated_session_is_capped() {
        let cookies: Vec<Value> = (0..(MAX_COOKIES * 2))
            .map(|i| {
                json!({"name": format!("k{i}"), "value":"v", "domain":"example.com", "path":"/", "expires": -1})
            })
            .collect();
        let jar = CookieJar::from_session_cookies(&cookies);
        assert_eq!(jar.cookies.len(), MAX_COOKIES);
        assert_eq!(jar.to_session_cookies().len(), MAX_COOKIES, "export stays bounded too");
    }

    #[test]
    fn default_path_from_request() {
        let mut jar = CookieJar::new();
        jar.store_set_cookie(&u("https://example.com/a/b/c"), "p=1");
        // default-path = /a/b ; so /a/b/x matches, /a does not
        assert!(jar.cookie_header_for(&u("https://example.com/a/b/x"), 0.0).is_some());
        assert!(jar.cookie_header_for(&u("https://example.com/a"), 0.0).is_none());
    }
}
