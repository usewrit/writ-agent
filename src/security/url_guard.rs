use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use url::Url;

const BLOCKED_HOSTS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "[::]",
    "[::1]",
    "metadata.google.internal",
    "metadata.goog",
    "kubernetes.default.svc",
    "kubernetes.default",
    "kubernetes",
];

struct CidrBlock {
    addr: IpAddr,
    prefix_len: u8,
}

impl CidrBlock {
    const fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
            prefix_len: prefix,
        }
    }

    const fn v6(segments: [u16; 8], prefix: u8) -> Self {
        Self {
            addr: IpAddr::V6(Ipv6Addr::new(
                segments[0], segments[1], segments[2], segments[3],
                segments[4], segments[5], segments[6], segments[7],
            )),
            prefix_len: prefix,
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let net_bits = u32::from(net);
                let addr_bits = u32::from(addr);
                let mask = if self.prefix_len >= 32 {
                    u32::MAX
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (net_bits & mask) == (addr_bits & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let net_bits = u128::from(net);
                let addr_bits = u128::from(addr);
                let mask = if self.prefix_len >= 128 {
                    u128::MAX
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (net_bits & mask) == (addr_bits & mask)
            }
            _ => false,
        }
    }
}

const CLOUD_METADATA_CIDRS: &[CidrBlock] = &[
    CidrBlock::v4(169, 254, 169, 254, 32), // AWS / GCP / Azure
    CidrBlock::v4(100, 100, 100, 200, 32),  // Alibaba Cloud
    CidrBlock::v6([0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254], 128), // AWS IPv6 metadata
    // NAT64 well-known prefix (RFC 6052). A NAT64 gateway translates `64:ff9b::<v4>` to that IPv4
    // address, so `64:ff9b::a9fe:a9fe` reaches 169.254.169.254 — the embedded IPv4 is NOT in a
    // `::ffff:` mapped form, so `to_ipv4_mapped()` does not see it and the fc00::/7 + fe80::/10
    // checks do not cover it either. Block the whole /96 rather than trying to translate each one.
    CidrBlock::v6([0x0064, 0xff9b, 0, 0, 0, 0, 0, 0], 96),
    // 6to4 (RFC 3056): `2002:<v4>::/48` is an automatic tunnel to the embedded IPv4 address, so the
    // same smuggling applies. The prefix is deprecated (RFC 7526) and carries no legitimate traffic.
    CidrBlock::v6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
];

const SAFE_INTERNAL_PREFIXES: &[&str] = &["about:"];

/// Extract the embedded IPv4 of a deprecated IPv4-compatible IPv6 address
/// (`::a.b.c.d`, high 96 bits zero) — but NOT `::`, `::1`, or other special
/// low addresses, which carry their own IPv6 semantics handled elsewhere. Used
/// alongside [`Ipv6Addr::to_ipv4_mapped`] to fold these legacy forms back to V4
/// before the SSRF range checks, closing the IPv4-in-IPv6 bypass.
fn ipv4_compatible(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    let segs = v6.segments();
    // High 96 bits must be zero (`::a.b.c.d`).
    if segs[0..6].iter().any(|&s| s != 0) {
        return None;
    }
    let v4 = Ipv4Addr::new(
        (segs[6] >> 8) as u8,
        (segs[6] & 0xff) as u8,
        (segs[7] >> 8) as u8,
        (segs[7] & 0xff) as u8,
    );
    // Skip `::`, `::1` and the very low addresses — they are not a real embedded
    // IPv4 host and are already covered by is_loopback()/is_unspecified().
    if u32::from(v4) <= 1 {
        return None;
    }
    Some(v4)
}

/// True if `ip` is in an internal/blocked range (loopback / RFC1918 / link-local / metadata / ULA).
/// `pub(crate)` so the IP-relay data plane can vet a RESOLVED destination address before dialing it
/// (DNS-rebinding defense — connect only to a vetted IP, never re-resolve the host).
pub(crate) fn is_blocked_ip(ip: IpAddr) -> bool {
    // Normalize IPv4-mapped (`::ffff:a.b.c.d`) and IPv4-compatible (`::a.b.c.d`)
    // IPv6 forms down to their embedded IPv4 address FIRST, so an attacker cannot
    // smuggle a loopback/RFC1918/metadata target past the V4 checks by wrapping it
    // in IPv6 (e.g. `[::ffff:169.254.169.254]` or `[::ffff:127.0.0.1]`). Without
    // this, `Ipv6Addr::is_loopback()` is false for `::ffff:127.0.0.1` and the V6
    // branch below only covers fe80::/10 + fc00::/7, so the mapped address would
    // slip through and connect to an internal host.
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped().or_else(|| ipv4_compatible(v6)) {
            return is_blocked_ip(IpAddr::V4(v4));
        }
    }

    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return true;
    }

    match ip {
        IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_link_local() {
                return true;
            }
            // Shared address space 100.64.0.0/10 (RFC 6598, "CGNAT"). Also the range Tailscale hands
            // out, so a tailnet peer's private service was reachable: only the single Alibaba
            // metadata address 100.100.100.200 inside it was listed before. Written out by octet
            // because `Ipv4Addr::is_shared()` is still unstable (`feature(ip)`) and this crate pins
            // rust-version 1.75.
            let o = v4.octets();
            if o[0] == 100 && (64..=127).contains(&o[1]) {
                return true;
            }
            // Reserved: 240.0.0.0/4 (future use)
            if o[0] >= 240 {
                return true;
            }
        }
        IpAddr::V6(v6) => {
            // Link-local fe80::/10
            let segs = v6.segments();
            if segs[0] & 0xffc0 == 0xfe80 {
                return true;
            }
            // Unique local fc00::/7
            if segs[0] & 0xfe00 == 0xfc00 {
                return true;
            }
            // Deprecated site-local fec0::/10 (RFC 3879). Neither check above catches it:
            // `0xfec0 & 0xfe00 == 0xfe00` (not 0xfc00) and `0xfec0 & 0xffc0 == 0xfec0` (not 0xfe80).
            // Still routable on plenty of older internal networks.
            if segs[0] & 0xffc0 == 0xfec0 {
                return true;
            }
        }
    }

    for cidr in CLOUD_METADATA_CIDRS {
        if cidr.contains(ip) {
            return true;
        }
    }

    false
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    let stripped = s.trim_matches(|c| c == '[' || c == ']');
    stripped.parse::<IpAddr>().ok()
}

/// SSRF check used by the per-request route blocker. Fails OPEN on DNS
/// resolution failure (a transient DNS hiccup mid-request shouldn't abort an
/// already-vetted navigation's subresources). For NAVIGATION/entry targets use
/// `is_navigation_url_safe`, which fails CLOSED.
pub fn is_url_safe(url_str: &str) -> bool {
    is_url_safe_inner(url_str, false)
}

/// SSRF check for NAVIGATION / entry-point targets (the URL the agent is about
/// to `goto`). Fails CLOSED: an unresolvable hostname is treated as unsafe so an
/// attacker cannot smuggle an internal target past us via DNS that only the
/// agent's network can resolve (or via DNS-rebinding timing).
pub fn is_navigation_url_safe(url_str: &str) -> bool {
    is_url_safe_inner(url_str, true)
}

/// Synchronous, DNS-FREE SSRF check for a REDIRECT-hop target — safe to call from a
/// `reqwest::redirect::Policy::custom` callback, which runs on the connection task and must NOT block
/// on async DNS. Blocks non-http(s) schemes, the [`BLOCKED_HOSTS`] list, and blocked IP LITERALS
/// (loopback / RFC1918 / link-local / cloud-metadata, incl. IPv4-in-IPv6 forms). Returns `true` =
/// allow the redirect, `false` = block it.
///
/// It deliberately does NOT resolve hostnames, so a redirect whose `Location` host only resolves to
/// an internal IP via DNS is NOT caught here. That narrow DNS-rebind-on-redirect residual is accepted:
/// the ENTRY url is fully vetted (DNS-resolving, fail-closed) by [`is_navigation_url_safe_async`], and
/// this stops the common `Location: http://169.254.169.254/…` / `http://localhost` redirect pivots
/// without stalling the reactor.
pub fn is_redirect_target_safe(url_str: &str) -> bool {
    let parsed = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return false,
    };
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return false;
    }
    let hostname = match parsed.host_str() {
        Some(h) => h,
        None => return false,
    };
    let hostname_lower = hostname.to_lowercase();
    let hostname_clean = hostname_lower.trim_matches(|c| c == '[' || c == ']');
    let hostname_no_dot = hostname_clean.trim_end_matches('.');
    for blocked in BLOCKED_HOSTS {
        if hostname_clean == *blocked || hostname_no_dot == *blocked {
            return false;
        }
    }
    if let Some(ip) = parse_ip(hostname_clean) {
        if is_blocked_ip(ip) {
            return false;
        }
    }
    true
}

fn is_url_safe_inner(url_str: &str, fail_closed_on_dns_error: bool) -> bool {
    if url_str.is_empty() {
        return false;
    }

    for prefix in SAFE_INTERNAL_PREFIXES {
        if url_str.starts_with(prefix) {
            return true;
        }
    }

    // A single-leading-slash path ("/foo") is same-origin relative and safe — it resolves against the
    // current page origin. A PROTOCOL-RELATIVE url ("//evil.host/…") ALSO starts with '/' but swaps in
    // an arbitrary host, so it must NOT take this shortcut; it falls through to the full host/IP/DNS
    // SSRF checks below (where `Url::parse` rejects the schemeless form → treated as unsafe).
    if url_str.starts_with('/') && !url_str.starts_with("//") {
        return true;
    }

    let parsed = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return false,
    };

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        tracing::warn!(scheme = scheme, "SSRF blocked: scheme not allowed");
        return false;
    }

    let hostname = match parsed.host_str() {
        Some(h) => h,
        None => return false,
    };

    let hostname_lower = hostname.to_lowercase();
    let hostname_clean = hostname_lower.trim_matches(|c| c == '[' || c == ']');
    let hostname_no_dot = hostname_clean.trim_end_matches('.');

    for blocked in BLOCKED_HOSTS {
        if hostname_clean == *blocked || hostname_no_dot == *blocked {
            tracing::warn!(hostname = hostname_clean, "SSRF blocked: hostname is blocked");
            return false;
        }
    }

    // Check if hostname is an IP literal
    if let Some(ip) = parse_ip(hostname_clean) {
        if is_blocked_ip(ip) {
            tracing::warn!(
                hostname = hostname,
                "SSRF blocked: private/internal IP"
            );
            return false;
        }
    }

    // DNS resolution check — resolve and verify all IPs
    match dns_resolve(hostname) {
        Ok(addrs) => {
            for ip in addrs {
                if is_blocked_ip(ip) {
                    tracing::warn!(
                        hostname = hostname,
                        resolved_ip = %ip,
                        "SSRF blocked: resolves to internal IP"
                    );
                    return false;
                }
            }
        }
        Err(_) => {
            // For navigation/entry targets, fail CLOSED — an unresolvable host is
            // treated as unsafe. For the per-request route blocker, pass through
            // (a literal-IP host already passed the checks above; a transient DNS
            // failure shouldn't tear down vetted navigation subresources).
            if fail_closed_on_dns_error {
                tracing::warn!(hostname = hostname, "SSRF blocked: DNS resolution failed (fail-closed)");
                return false;
            }
        }
    }

    true
}

fn dns_resolve(hostname: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    use std::net::ToSocketAddrs;
    let addr_str = format!("{}:0", hostname);
    let addrs: Vec<IpAddr> = addr_str
        .to_socket_addrs()?
        .map(|sa| sa.ip())
        .collect();
    Ok(addrs)
}

pub async fn is_url_safe_async(url_str: &str) -> bool {
    refusal_reason_inner(url_str, false).await.is_none()
}

/// Async, fail-closed-on-DNS-error variant for navigation/entry targets.
pub async fn is_navigation_url_safe_async(url_str: &str) -> bool {
    refusal_reason_inner(url_str, true).await.is_none()
}

/// Why a navigation/entry URL was refused, in words meant for the person who
/// typed it — or `None` when the URL is fine.
///
/// The bool guards above collapse every refusal into `false`, which the recorder
/// then reported as "Refused unsafe start URL". For an actual SSRF attempt that
/// vagueness is fine; for the far more common case — a typo'd domain that simply
/// doesn't resolve — it reads as a security refusal (or a broken engine) instead
/// of "check the address". The guard KNOWS which case it hit; this variant is how
/// a caller keeps that distinction instead of throwing it away.
pub async fn navigation_refusal(url_str: &str) -> Option<&'static str> {
    refusal_reason_inner(url_str, true).await
}

async fn refusal_reason_inner(
    url_str: &str,
    fail_closed_on_dns_error: bool,
) -> Option<&'static str> {
    if url_str.is_empty() {
        return Some("the URL is empty");
    }

    for prefix in SAFE_INTERNAL_PREFIXES {
        if url_str.starts_with(prefix) {
            return None;
        }
    }

    // Same-origin relative path is safe; a protocol-relative "//host/…" is NOT (see the sync variant).
    if url_str.starts_with('/') && !url_str.starts_with("//") {
        return None;
    }

    let parsed = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return Some("this is not a valid URL"),
    };

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        tracing::warn!(scheme = scheme, "SSRF blocked: scheme not allowed");
        return Some("only http(s) addresses can be opened");
    }

    let hostname = match parsed.host_str() {
        Some(h) => h.to_string(),
        None => return Some("the URL has no hostname"),
    };

    let hostname_lower = hostname.to_lowercase();
    let hostname_clean = hostname_lower.trim_matches(|c| c == '[' || c == ']');
    let hostname_no_dot = hostname_clean.trim_end_matches('.');

    for blocked in BLOCKED_HOSTS {
        if hostname_clean == *blocked || hostname_no_dot == *blocked {
            tracing::warn!(hostname = hostname_clean, "SSRF blocked: hostname is blocked");
            return Some("this hostname is blocked (internal/metadata address)");
        }
    }

    if let Some(ip) = parse_ip(hostname_clean) {
        if is_blocked_ip(ip) {
            tracing::warn!(hostname = %hostname, "SSRF blocked: private/internal IP");
            return Some("this address points at a private/internal network");
        }
    }

    // DNS. Cached and bounded — see `resolve_host_verdict` for why both matter.
    let timeout = if fail_closed_on_dns_error {
        NAV_DNS_TIMEOUT
    } else {
        ROUTE_DNS_TIMEOUT
    };
    match resolve_host_verdict(hostname_no_dot, &hostname, timeout).await {
        HostVerdict::Safe => None,
        HostVerdict::Internal => {
            Some("this hostname resolves to a private/internal address")
        }
        HostVerdict::Unresolved => {
            // Navigation targets fail CLOSED; the per-request route blocker passes
            // through (it is a defence-in-depth layer, not the only one, and
            // blocking every subresource on a flaky resolver would break pages).
            if fail_closed_on_dns_error {
                tracing::warn!(hostname = %hostname, "SSRF blocked: DNS resolution failed or timed out (fail-closed)");
                return Some(
                    "this domain could not be resolved — check the address for a \
                     typo, or check your network's DNS",
                );
            }
            None
        }
    }
}

/// How long a hostname's verdict stays cached.
///
/// This is the knob that trades SSRF-via-DNS-rebinding exposure against the
/// resolution storm below. 60s is short enough that a rebind is caught on the
/// next page load, and it does not weaken the guard much in absolute terms: the
/// browser does its OWN resolution for the actual connection, so this check has
/// never been able to pin the address the request ultimately reaches. It is a
/// screen against obviously-internal targets, not a TOCTOU-proof gate.
const DNS_VERDICT_TTL: Duration = Duration::from_secs(60);

/// Per-request cap. A subresource must never hold the browser's route handler
/// open on a slow resolver — it fails open on timeout, exactly as it already did
/// on a DNS error.
const ROUTE_DNS_TIMEOUT: Duration = Duration::from_secs(2);

/// Navigation/entry targets get longer: this one fails CLOSED, so a premature
/// timeout on a cold resolver would refuse a perfectly good URL.
const NAV_DNS_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum HostVerdict {
    /// Resolved, and no address is in a blocked range.
    Safe,
    /// Resolved to at least one internal/private address.
    Internal,
    /// Could not be resolved in time. Caller decides open/closed.
    Unresolved,
}

/// hostname → (verdict, decided_at). Only DEFINITIVE verdicts are stored;
/// a timeout is never cached, or one slow moment would pin a host for a minute.
static DNS_VERDICT_CACHE: OnceLock<DashMap<String, (HostVerdict, Instant)>> = OnceLock::new();

fn dns_cache() -> &'static DashMap<String, (HostVerdict, Instant)> {
    DNS_VERDICT_CACHE.get_or_init(DashMap::new)
}

/// Resolve `hostname` and decide whether it points anywhere internal.
///
/// **Why this is cached and bounded.** Every context installs
/// `context.route("**/*")` as an SSRF screen (browser/manager.rs), and the
/// browser is BLOCKED on `route.continue_()` for each intercepted request until
/// this returns. Uncached, that meant one `getaddrinfo` per request — including
/// repeats of the same host — so a page like google.fr (100+ requests over a
/// dozen hostnames, plus a consent redirect) paid hundreds of resolutions before
/// it could finish loading. The document's own request is in that queue, so
/// `page.goto` blew past its 30s budget and surfaced as
/// `Protocol error: Timeout 30000ms exceeded` — the recorder simply never opened
/// on request-heavy sites, while light ones worked fine.
///
/// With the cache a page pays one lookup per distinct host per minute; with the
/// timeout, a single unresponsive resolver can no longer stall a page at all.
async fn resolve_host_verdict(cache_key: &str, hostname: &str, timeout: Duration) -> HostVerdict {
    let cache = dns_cache();

    if let Some(entry) = cache.get(cache_key) {
        let (verdict, decided_at) = *entry;
        if decided_at.elapsed() < DNS_VERDICT_TTL {
            return verdict;
        }
    }

    let lookup_host = format!("{}:0", hostname);
    let resolved = tokio::time::timeout(timeout, tokio::net::lookup_host(&lookup_host)).await;

    let verdict = match resolved {
        Ok(Ok(addrs)) => {
            let mut v = HostVerdict::Safe;
            for addr in addrs {
                if is_blocked_ip(addr.ip()) {
                    tracing::warn!(
                        hostname = %hostname,
                        resolved_ip = %addr.ip(),
                        "SSRF blocked: resolves to internal IP"
                    );
                    v = HostVerdict::Internal;
                    break;
                }
            }
            v
        }
        // Resolver said no, or took too long. Not cached — see the field note.
        Ok(Err(_)) | Err(_) => return HostVerdict::Unresolved,
    };

    // Bound the cache. A recording session touches tens of hosts; a crawl can
    // touch thousands, and an unbounded map here would be a slow leak for the
    // life of the process. Clearing wholesale (rather than evicting LRU) keeps
    // this lock-free and cheap — the cost of a rebuild is one lookup per live
    // host, which is exactly what the steady state already pays every TTL.
    if cache.len() >= DNS_CACHE_MAX_ENTRIES {
        cache.clear();
    }
    cache.insert(cache_key.to_string(), (verdict, Instant::now()));
    verdict
}

const DNS_CACHE_MAX_ENTRIES: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_url() {
        assert!(!is_url_safe(""));
    }

    #[test]
    fn test_about_blank() {
        assert!(is_url_safe("about:blank"));
        assert!(is_url_safe("about:srcdoc"));
    }

    #[test]
    fn test_relative_url() {
        assert!(is_url_safe("/path/to/page"));
    }

    #[test]
    fn test_protocol_relative_url_not_treated_as_safe_relative() {
        // "//host/…" starts with '/' but is protocol-relative (arbitrary host) — it must NOT slip
        // through the same-origin relative-path shortcut. Schemeless → Url::parse fails → unsafe.
        assert!(!is_url_safe("//169.254.169.254/latest/meta-data/"));
        assert!(!is_url_safe("//metadata.google.internal/"));
        assert!(!is_url_safe("//evil.example/"));
        assert!(!is_navigation_url_safe("//169.254.169.254/latest/meta-data/"));
        // A genuine same-origin path is still allowed.
        assert!(is_url_safe("/path/to/page"));
        assert!(is_navigation_url_safe("/path/to/page"));
    }

    #[test]
    fn test_blocked_schemes() {
        assert!(!is_url_safe("file:///etc/passwd"));
        assert!(!is_url_safe("data:text/html,<h1>hi</h1>"));
        assert!(!is_url_safe("javascript:alert(1)"));
        assert!(!is_url_safe("ftp://example.com"));
    }

    #[test]
    fn test_localhost_blocked() {
        assert!(!is_url_safe("http://localhost"));
        assert!(!is_url_safe("http://localhost:8080"));
        assert!(!is_url_safe("http://127.0.0.1"));
        assert!(!is_url_safe("http://127.0.0.1:3000"));
        assert!(!is_url_safe("http://0.0.0.0"));
    }

    #[test]
    fn test_private_ips_blocked() {
        assert!(!is_url_safe("http://10.0.0.1"));
        assert!(!is_url_safe("http://172.16.0.1"));
        assert!(!is_url_safe("http://192.168.1.1"));
    }

    #[test]
    fn test_cloud_metadata_blocked() {
        assert!(!is_url_safe("http://169.254.169.254"));
        assert!(!is_url_safe("http://169.254.169.254/latest/meta-data/"));
        assert!(!is_url_safe("http://100.100.100.200"));
        assert!(!is_url_safe("http://metadata.google.internal"));
    }

    #[test]
    fn test_public_urls_allowed() {
        assert!(is_url_safe("https://example.com"));
        assert!(is_url_safe("https://google.com"));
        assert!(is_url_safe("http://8.8.8.8"));
    }

    #[test]
    fn test_link_local_blocked() {
        assert!(!is_url_safe("http://169.254.1.1"));
    }

    #[test]
    fn test_ipv6_loopback_blocked() {
        assert!(!is_url_safe("http://[::1]"));
    }

    #[test]
    fn test_kubernetes_blocked() {
        assert!(!is_url_safe("http://kubernetes.default.svc"));
        assert!(!is_url_safe("http://kubernetes.default"));
        assert!(!is_url_safe("http://kubernetes"));
    }

    #[test]
    fn test_blocked_ip_function() {
        assert!(is_blocked_ip("127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("172.16.0.1".parse().unwrap()));
        assert!(is_blocked_ip("192.168.0.1".parse().unwrap()));
        assert!(is_blocked_ip("169.254.169.254".parse().unwrap()));
        assert!(is_blocked_ip("0.0.0.0".parse().unwrap()));
        assert!(is_blocked_ip("::1".parse().unwrap()));

        assert!(!is_blocked_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_blocked_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_redirect_target_safe() {
        // Public http(s) targets are allowed.
        assert!(is_redirect_target_safe("https://example.com/final"));
        assert!(is_redirect_target_safe("http://8.8.8.8/"));
        // Internal / metadata / loopback redirect targets (IP literals) are blocked.
        assert!(!is_redirect_target_safe("http://169.254.169.254/latest/meta-data/"));
        assert!(!is_redirect_target_safe("http://127.0.0.1:6379/"));
        assert!(!is_redirect_target_safe("http://10.0.0.5/"));
        assert!(!is_redirect_target_safe("http://[::1]/"));
        assert!(!is_redirect_target_safe("http://[::ffff:169.254.169.254]/"));
        // Blocked-hostname list + non-http schemes are blocked.
        assert!(!is_redirect_target_safe("http://localhost/"));
        assert!(!is_redirect_target_safe("http://metadata.google.internal/"));
        assert!(!is_redirect_target_safe("file:///etc/passwd"));
        assert!(!is_redirect_target_safe("gopher://evil/"));
        // Malformed → blocked.
        assert!(!is_redirect_target_safe("not a url"));
    }

    /// 100.64.0.0/10 (RFC 6598 CGNAT — and the range Tailscale allocates from). Only the single
    /// Alibaba metadata address inside it was blocked before, leaving every tailnet peer reachable.
    #[test]
    fn test_cgnat_shared_range_blocked() {
        assert!(is_blocked_ip("100.64.0.1".parse().unwrap()));
        assert!(is_blocked_ip("100.100.100.200".parse().unwrap()));
        assert!(is_blocked_ip("100.127.255.254".parse().unwrap()));
        assert!(is_blocked_ip("100.101.102.103".parse().unwrap()), "tailnet peer");
        // Boundaries: 100.63.x and 100.128.x are OUTSIDE the /10 and stay allowed.
        assert!(!is_blocked_ip("100.63.255.255".parse().unwrap()));
        assert!(!is_blocked_ip("100.128.0.1".parse().unwrap()));
        assert!(!is_blocked_ip("99.64.0.1".parse().unwrap()));
        // End-to-end through the URL guards (incl. the sync redirect check).
        assert!(!is_url_safe("http://100.100.100.200/"));
        assert!(!is_url_safe("http://100.64.1.2:8080/x"));
        assert!(!is_redirect_target_safe("http://100.90.1.2/"));
    }

    /// Deprecated IPv6 site-local `fec0::/10` (RFC 3879). Neither existing V6 check covers it:
    /// `0xfec0 & 0xfe00 == 0xfe00` (not `0xfc00`) and `0xfec0 & 0xffc0 == 0xfec0` (not `0xfe80`).
    #[test]
    fn test_ipv6_site_local_blocked() {
        assert!(is_blocked_ip("fec0::1".parse().unwrap()));
        assert!(is_blocked_ip("feff:ffff::1".parse().unwrap()));
        assert!(is_blocked_ip("fed0::abcd".parse().unwrap()));
        // fe80::/10 and fc00::/7 still blocked; a public 2001: address still allowed.
        assert!(is_blocked_ip("fe80::1".parse().unwrap()));
        assert!(is_blocked_ip("fd00::1".parse().unwrap()));
        assert!(!is_blocked_ip("2001:4860:4860::8888".parse().unwrap()));
        assert!(!is_redirect_target_safe("http://[fec0::1]/"));
    }

    /// NAT64 (`64:ff9b::/96`, RFC 6052) and 6to4 (`2002::/16`, RFC 3056) embed an IPv4 destination in
    /// a form `to_ipv4_mapped()` cannot see, so `64:ff9b::a9fe:a9fe` translated straight to the cloud
    /// metadata address 169.254.169.254.
    #[test]
    fn test_nat64_and_6to4_prefixes_blocked() {
        assert!(is_blocked_ip("64:ff9b::a9fe:a9fe".parse().unwrap()), "NAT64 → metadata");
        assert!(is_blocked_ip("64:ff9b::7f00:1".parse().unwrap()), "NAT64 → loopback");
        assert!(is_blocked_ip("64:ff9b::0808:0808".parse().unwrap()), "whole /96 blocked");
        assert!(is_blocked_ip("2002:a9fe:a9fe::1".parse().unwrap()), "6to4 → metadata");
        assert!(is_blocked_ip("2002:0a00:0001::1".parse().unwrap()), "6to4 → RFC1918");
        // Neighbouring prefixes are untouched.
        assert!(!is_blocked_ip("64:ff9c::1".parse().unwrap()));
        assert!(!is_blocked_ip("2003::1".parse().unwrap()));
        // End-to-end.
        assert!(!is_url_safe("http://[64:ff9b::a9fe:a9fe]/latest/meta-data/"));
        assert!(!is_redirect_target_safe("http://[2002:a9fe:a9fe::1]/"));
    }

    #[test]
    fn test_ipv4_mapped_and_compatible_ipv6_blocked() {
        // IPv4-mapped (::ffff:a.b.c.d) must inherit the V4 blocklist — otherwise an
        // attacker reaches loopback/RFC1918/metadata by wrapping the address in IPv6.
        assert!(is_blocked_ip("::ffff:127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:192.168.1.1".parse().unwrap()));
        assert!(is_blocked_ip("::ffff:169.254.169.254".parse().unwrap()));
        // Deprecated IPv4-compatible (::a.b.c.d) form too.
        assert!(is_blocked_ip("::127.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::10.0.0.1".parse().unwrap()));
        assert!(is_blocked_ip("::169.254.169.254".parse().unwrap()));
        // A mapped PUBLIC address stays allowed (no false positives).
        assert!(!is_blocked_ip("::ffff:8.8.8.8".parse().unwrap()));
        // The bracketed URL form is rejected end-to-end.
        assert!(!is_url_safe("http://[::ffff:169.254.169.254]"));
        assert!(!is_url_safe("http://[::ffff:127.0.0.1]:8080"));
        assert!(!is_navigation_url_safe("http://[::ffff:10.0.0.1]"));
    }

    // ── DNS verdict cache ────────────────────────────────────────────────
    //
    // THE BUG this exists for: every browser context installs
    // `context.route("**/*")` as an SSRF screen, and the browser is blocked on
    // `route.continue_()` until the check returns. Uncached, that was one
    // `getaddrinfo` per request — repeats of the same host included — so a page
    // firing 100+ requests across a dozen hostnames (google.fr, with its consent
    // redirect) spent its whole 30s navigation budget resolving. The recorder
    // never opened, and reported `Protocol error: Timeout 30000ms exceeded`.

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    /// A blocked hostname must be decided WITHOUT touching the resolver at all —
    /// it is caught by the literal/IP screens well before DNS.
    #[test]
    fn blocked_literals_never_reach_the_resolver() {
        rt().block_on(async {
            assert!(!is_url_safe_async("http://127.0.0.1/x").await);
            assert!(!is_url_safe_async("http://169.254.169.254/latest/meta-data").await);
            assert!(!is_navigation_url_safe_async("http://metadata.google.internal/").await);
            // Nothing above is a hostname lookup, so nothing should be cached.
            assert!(dns_cache().get("127.0.0.1").is_none());
        });
    }

    /// The second call for the same host must be served from cache. Without this
    /// the route handler pays a resolution per request, which is the stall.
    #[test]
    fn a_decided_verdict_is_reused_within_the_ttl() {
        rt().block_on(async {
            let host = "cache-probe.invalid.test";
            dns_cache().insert(host.to_string(), (HostVerdict::Safe, Instant::now()));
            // `.invalid` never resolves, so a cache MISS would return Unresolved.
            // Getting Safe back proves the cached verdict was used.
            let v = resolve_host_verdict(host, host, Duration::from_millis(50)).await;
            assert_eq!(v, HostVerdict::Safe);
            dns_cache().remove(host);
        });
    }

    /// A stale entry must be re-resolved rather than trusted forever — that TTL is
    /// what keeps the cache from becoming a DNS-rebinding hole.
    #[test]
    fn an_expired_verdict_is_not_reused() {
        rt().block_on(async {
            let host = "expired-probe.invalid.test";
            let stale = Instant::now() - (DNS_VERDICT_TTL + Duration::from_secs(1));
            dns_cache().insert(host.to_string(), (HostVerdict::Safe, stale));
            // Past the TTL we must go back to the resolver, which cannot resolve
            // `.invalid` → Unresolved, NOT the stale Safe.
            let v = resolve_host_verdict(host, host, Duration::from_secs(2)).await;
            assert_eq!(v, HostVerdict::Unresolved);
            dns_cache().remove(host);
        });
    }

    /// An unresolvable host must NOT be cached: one bad moment would otherwise
    /// pin the verdict for a whole TTL.
    #[test]
    fn unresolved_is_never_cached() {
        rt().block_on(async {
            let host = "never-cached.invalid.test";
            dns_cache().remove(host);
            let v = resolve_host_verdict(host, host, Duration::from_secs(2)).await;
            assert_eq!(v, HostVerdict::Unresolved);
            assert!(dns_cache().get(host).is_none(), "a timeout/error must not be cached");
        });
    }

    /// The two callers must keep their opposite postures on an unresolvable host:
    /// a navigation target fails CLOSED, a subresource passes through.
    #[test]
    fn unresolvable_host_fails_closed_for_navigation_and_open_for_subresources() {
        rt().block_on(async {
            let url = "https://posture-probe.invalid.test/asset.js";
            assert!(!is_navigation_url_safe_async(url).await, "navigation must fail closed");
            assert!(is_url_safe_async(url).await, "a subresource must pass through");
        });
    }

    /// The refusal REASON tells a typo'd domain apart from a policy block.
    ///
    /// Both refuse the navigation, but the person reading the error needs opposite
    /// advice: "check the address" vs "this address is off-limits". Collapsing them
    /// into one message is what sent a user with a misspelled hostname hunting for
    /// an engine bug — three retries of the same typo, each "SSRF blocked".
    #[test]
    fn refusal_reasons_distinguish_typo_from_policy() {
        rt().block_on(async {
            let nxdomain = navigation_refusal("https://quotes.toscape-probe.invalid.test/")
                .await
                .expect("an unresolvable host must be refused");
            assert!(nxdomain.contains("could not be resolved"), "got: {nxdomain}");
            assert!(nxdomain.contains("typo"), "must point at the likely fix: {nxdomain}");

            let metadata = navigation_refusal("http://169.254.169.254/latest/meta-data")
                .await
                .expect("cloud metadata must be refused");
            assert!(metadata.contains("private/internal"), "got: {metadata}");

            let scheme = navigation_refusal("file:///etc/passwd")
                .await
                .expect("non-http schemes must be refused");
            assert!(scheme.contains("http"), "got: {scheme}");

            assert!(navigation_refusal("https://example.com/").await.is_none(),
                    "a resolvable public host is not refused");
        });
    }
}
