//! Single-use, short-lived WebSocket connect tickets.
//!
//! ## Why
//! A browser cannot set an `Authorization` header on a WebSocket, so the loopback recorder /
//! live-preview sockets historically carried the long-lived `wlt_` bearer as a `?token=` query
//! param. A query string leaks far more readily than a header — it lands in the webview's own
//! history/referrer, in any proxy or crash log that captures the URL, and in `Performance`/devtools
//! resource lists — so putting the DAEMON'S MASTER BEARER there is a standing exposure.
//!
//! This module replaces that with a **ticket handshake**:
//!   1. The webview `POST`s the authenticated `/v1/ws-ticket` endpoint (bearer in the header) asking
//!      for a ticket scoped to a specific route (`record` / `ai-preview`) and, for preview, a
//!      specific channel key.
//!   2. The daemon mints a cryptographically-random `wtk_` ticket, stores only its SHA-256, and
//!      returns the raw value with a short TTL.
//!   3. The webview opens the WebSocket with `?ticket=<wtk_…>`. The WS handler CONSUMES the ticket
//!      (atomic remove) and upgrades only if it is unexpired and scoped to that exact route+channel.
//!
//! ## Security properties
//!   * **No master bearer on the wire.** A leaked WS URL exposes at most a single-use ticket that is
//!     already spent (or expires in seconds), never the `wlt_` token.
//!   * **Single-use.** [`consume`] atomically removes the entry, so a replayed URL fails.
//!   * **Expiring.** Entries carry a [`TICKET_TTL`] deadline; a stale ticket never authorizes.
//!   * **Route/channel scoped.** A ticket minted for `ai-preview:concierge-1` cannot open `/ws/record`
//!     nor spy on `ai-preview:ai-2`.
//!   * **Rate-limited + capped.** Issuance is bounded per window and the live set is capped, so a
//!     compromised webview can't exhaust memory by minting endlessly.
//!   * **Never logged.** Only the SHA-256 is stored; the raw ticket is returned once and dropped. The
//!     `wtk_` prefix + `?ticket=` query param are both scrubbed by the logging redactor.
//!
//! The ticket only ever grants what the `wlt_` holder could already do (open a loopback recorder/
//! preview socket); it is a transport hardening, not a new capability.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

use base64::Engine as _;
use dashmap::DashMap;
use rand::RngCore as _;
use sha2::{Digest, Sha256};

/// Ticket lifetime. Long enough for the webview to open the socket immediately after minting,
/// short enough that a leaked URL is worthless within seconds.
pub const TICKET_TTL: Duration = Duration::from_secs(30);

/// Ticket string prefix (mirrors the daemon's other `w*_` token shapes; scrubbed by `logging`).
const TICKET_PREFIX: &str = "wtk_";

/// Hard cap on live (unconsumed, unexpired) tickets. A well-behaved webview holds ≤ a handful at a
/// time; this bounds memory against a misbehaving/compromised caller.
const MAX_OUTSTANDING: usize = 128;

/// Sliding-window issuance limit: at most this many tickets may be minted per [`RATE_WINDOW`].
const MAX_ISSUE_PER_WINDOW: u32 = 120;
const RATE_WINDOW: Duration = Duration::from_secs(60);

/// The routes a ticket may be scoped to. A ticket is valid ONLY for the route it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsRoute {
    /// `GET /ws/record` — the local recorder socket.
    Record,
    /// `GET /ws/ai-preview/:key` — the live AI/concierge spectator socket.
    AiPreview,
}

impl WsRoute {
    /// Parse the wire string the webview sends in the mint request body.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "record" => Some(WsRoute::Record),
            "ai-preview" => Some(WsRoute::AiPreview),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            WsRoute::Record => "record",
            WsRoute::AiPreview => "ai-preview",
        }
    }
}

/// Why a ticket could not be issued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueError {
    /// The per-window issuance limit was hit, or the live set is at capacity.
    RateLimited,
}

struct TicketEntry {
    route: WsRoute,
    /// The channel key the ticket is scoped to (`None` for routes without one, e.g. `record`).
    channel: Option<String>,
    expires_at: Instant,
}

struct RateWindow {
    window_start: Instant,
    count: u32,
}

/// The process-global ticket store. One instance per daemon process (mirrors the `live_preview`
/// global registry pattern); shared by the HTTP mint handler and the WS consume handlers.
pub struct TicketStore {
    tickets: DashMap<String, TicketEntry>,
    rate: std::sync::Mutex<RateWindow>,
}

impl TicketStore {
    fn new() -> Self {
        Self {
            tickets: DashMap::new(),
            rate: std::sync::Mutex::new(RateWindow { window_start: Instant::now(), count: 0 }),
        }
    }

    /// Drop expired entries. Cheap: called on every issue so the live set stays bounded by TTL.
    fn prune(&self, now: Instant) {
        self.tickets.retain(|_, e| e.expires_at > now);
    }

    /// Sliding-window rate check. Returns `Ok(())` if a mint is allowed and records it.
    fn check_rate(&self, now: Instant) -> Result<(), IssueError> {
        let mut w = self.rate.lock().unwrap_or_else(|e| e.into_inner());
        if now.duration_since(w.window_start) >= RATE_WINDOW {
            w.window_start = now;
            w.count = 0;
        }
        if w.count >= MAX_ISSUE_PER_WINDOW {
            return Err(IssueError::RateLimited);
        }
        w.count += 1;
        Ok(())
    }

    /// Mint a ticket scoped to `route` (+ optional `channel`). Returns the RAW `wtk_` ticket (store
    /// only its hash) and the TTL. Fails closed on rate-limit / capacity.
    pub fn issue(&self, route: WsRoute, channel: Option<String>) -> Result<(String, Duration), IssueError> {
        let now = Instant::now();
        self.prune(now);
        if self.tickets.len() >= MAX_OUTSTANDING {
            tracing::warn!(route = route.as_str(), "ws-ticket: outstanding cap reached — refusing to mint");
            return Err(IssueError::RateLimited);
        }
        self.check_rate(now)?;

        let mut raw = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let ticket = format!(
            "{TICKET_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
        );
        let hash = hash_ticket(&ticket);
        self.tickets.insert(
            hash,
            TicketEntry { route, channel, expires_at: now + TICKET_TTL },
        );
        tracing::debug!(route = route.as_str(), "ws-ticket: issued"); // never logs the ticket
        Ok((ticket, TICKET_TTL))
    }

    /// Atomically consume a presented ticket. Returns true ONLY when it exists, is unexpired, and is
    /// scoped to exactly `route` + `channel`. The entry is removed regardless of the scope-match
    /// outcome, so even a wrong-scope use burns the single-use ticket (no oracle, no replay).
    pub fn consume(&self, presented: &str, route: WsRoute, channel: Option<&str>) -> bool {
        if presented.is_empty() {
            return false;
        }
        let hash = hash_ticket(presented);
        let Some((_, entry)) = self.tickets.remove(&hash) else {
            return false;
        };
        if entry.expires_at <= Instant::now() {
            return false;
        }
        if entry.route != route {
            return false;
        }
        entry.channel.as_deref() == channel
    }

    /// Live (pre-prune) ticket count — for tests/metrics only.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.tickets.len()
    }
}

/// SHA-256 hex of a ticket string. We store only this so a memory image never yields a usable
/// ticket, and equality is a plain map lookup (the ticket's 256-bit entropy makes guessing infeasible;
/// there is no secret to leak via lookup timing).
fn hash_ticket(ticket: &str) -> String {
    let mut h = Sha256::new();
    h.update(ticket.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The process-global store.
static STORE: OnceLock<TicketStore> = OnceLock::new();

/// The global ticket store, created on first use.
pub fn store() -> &'static TicketStore {
    STORE.get_or_init(TicketStore::new)
}

/// Convenience: mint a ticket on the global store.
pub fn issue(route: WsRoute, channel: Option<String>) -> Result<(String, Duration), IssueError> {
    store().issue(route, channel)
}

/// Convenience: consume a ticket on the global store.
pub fn consume(presented: &str, route: WsRoute, channel: Option<&str>) -> bool {
    store().consume(presented, route, channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_ticket_has_shape_and_is_single_use() {
        let s = TicketStore::new();
        let (t, ttl) = s.issue(WsRoute::Record, None).unwrap();
        assert!(t.starts_with("wtk_"));
        assert!(t.len() > 40);
        assert_eq!(ttl, TICKET_TTL);
        // First consume succeeds; the second (replay) fails — single use.
        assert!(s.consume(&t, WsRoute::Record, None));
        assert!(!s.consume(&t, WsRoute::Record, None));
    }

    #[test]
    fn wrong_route_or_channel_is_rejected_and_burns_the_ticket() {
        let s = TicketStore::new();
        let (t, _) = s.issue(WsRoute::AiPreview, Some("concierge-1".into())).unwrap();
        // Wrong route.
        assert!(!s.consume(&t, WsRoute::Record, None));
        // The mismatched attempt still consumed it — a correct retry now fails (no scope oracle).
        assert!(!s.consume(&t, WsRoute::AiPreview, Some("concierge-1")));

        // Fresh ticket: wrong channel is rejected, right channel accepted.
        let (t2, _) = s.issue(WsRoute::AiPreview, Some("concierge-1".into())).unwrap();
        assert!(!s.consume(&t2, WsRoute::AiPreview, Some("ai-2")));
        let (t3, _) = s.issue(WsRoute::AiPreview, Some("concierge-1".into())).unwrap();
        assert!(s.consume(&t3, WsRoute::AiPreview, Some("concierge-1")));
    }

    #[test]
    fn unknown_and_empty_tickets_are_rejected() {
        let s = TicketStore::new();
        assert!(!s.consume("", WsRoute::Record, None));
        assert!(!s.consume("wtk_never_issued", WsRoute::Record, None));
    }

    #[test]
    fn expired_ticket_is_rejected() {
        let s = TicketStore::new();
        let (t, _) = s.issue(WsRoute::Record, None).unwrap();
        // Force-expire the stored entry.
        let hash = hash_ticket(&t);
        if let Some(mut e) = s.tickets.get_mut(&hash) {
            e.expires_at = Instant::now() - Duration::from_secs(1);
        }
        assert!(!s.consume(&t, WsRoute::Record, None));
    }

    #[test]
    fn prune_drops_only_expired_entries() {
        let s = TicketStore::new();
        let (_live, _) = s.issue(WsRoute::Record, None).unwrap();
        let (dead, _) = s.issue(WsRoute::Record, None).unwrap();
        if let Some(mut e) = s.tickets.get_mut(&hash_ticket(&dead)) {
            e.expires_at = Instant::now() - Duration::from_secs(1);
        }
        s.prune(Instant::now());
        assert_eq!(s.len(), 1, "only the live ticket survives prune");
    }

    #[test]
    fn tickets_are_unique() {
        let s = TicketStore::new();
        let a = s.issue(WsRoute::Record, None).unwrap().0;
        let b = s.issue(WsRoute::Record, None).unwrap().0;
        assert_ne!(a, b);
    }

    #[test]
    fn issuance_is_rate_limited() {
        let s = TicketStore::new();
        // Consume tickets as we go so the outstanding cap isn't what stops us — we want to prove the
        // per-window RATE limit specifically.
        let mut minted = 0u32;
        // The only `Err` this can return is `RateLimited`, which is the loop's exit condition.
        while let Ok((t, _)) = s.issue(WsRoute::Record, None) {
            minted += 1;
            let _ = s.consume(&t, WsRoute::Record, None);
            assert!(minted <= MAX_ISSUE_PER_WINDOW + 5, "rate limit never tripped");
        }
        assert_eq!(minted, MAX_ISSUE_PER_WINDOW, "exactly the window budget is mintable");
    }

    #[test]
    fn route_parse_roundtrips() {
        assert_eq!(WsRoute::parse("record"), Some(WsRoute::Record));
        assert_eq!(WsRoute::parse("ai-preview"), Some(WsRoute::AiPreview));
        assert_eq!(WsRoute::parse("bogus"), None);
        assert_eq!(WsRoute::Record.as_str(), "record");
    }
}
