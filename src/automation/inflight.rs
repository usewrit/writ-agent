//! In-flight document/XHR/fetch counter, keyed by browser-context guid.
//!
//! WHY THIS EXISTS. A click returns as soon as the page's own handler runs — the
//! request that handler triggers leaves AFTER. Anything that reads the page (or the
//! cookie jar) at that instant sees the PRE-action document: a sign-in whose POST is
//! still on the wire looks like a page that never submitted. That is how a recorded
//! login banks the ANONYMOUS session, and how its POST goes missing from a captured
//! trace, leaving the optimizer with no backend call to fold the login steps into.
//! Sites that hand anonymous visitors a session cookie (Laravel/Symfony and friends)
//! make that jar look authentic, so nothing downstream catches it.
//!
//! A plain sleep cannot tell "nothing happened" from "still waiting", so it has to be
//! long enough for the slow case and wastes that time on every action that starts no
//! traffic. Counting requests gives the honest signal.
//!
//! Twin of the Python agent's `InFlightRequests` / `_settle_after_action`
//! (playwright-recorder/automation_engine.py). Keyed by context guid rather than
//! stashed on the page object because the step functions take only a `Page`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use playwright_rs::protocol::BrowserContext;
use playwright_rs::server::channel_owner::ChannelOwner as _;
use playwright_rs::Page;

/// Resource types worth waiting for. A stylesheet or image still loading says nothing
/// about whether the action landed; a document/XHR/fetch does.
const WATCHED: &[&str] = &["document", "xhr", "fetch"];

#[derive(Debug)]
struct State {
    pending: i64,
    /// When the count last moved. A counter that stops moving means a request whose
    /// completion we will never observe (aborted mid-navigation, socket kept open);
    /// without this the settle would sit out its whole budget on every such page.
    last_change: Instant,
}

#[derive(Clone, Debug)]
pub struct InFlight(Arc<Mutex<State>>);

impl InFlight {
    fn new() -> Self {
        InFlight(Arc::new(Mutex::new(State { pending: 0, last_change: Instant::now() })))
    }

    fn bump(&self, delta: i64) {
        if let Ok(mut s) = self.0.lock() {
            // Never below zero: a request that started before the handlers were
            // attached still reports finished.
            s.pending = (s.pending + delta).max(0);
            s.last_change = Instant::now();
        }
    }

    fn snapshot(&self) -> (i64, Duration) {
        match self.0.lock() {
            Ok(s) => (s.pending, s.last_change.elapsed()),
            // A poisoned lock must not wedge a run — report "nothing pending".
            Err(_) => (0, Duration::ZERO),
        }
    }
}

fn registry() -> &'static Mutex<HashMap<String, InFlight>> {
    static REG: OnceLock<Mutex<HashMap<String, InFlight>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Start counting on `context`. Idempotent per guid — a second call is a no-op, so a
/// caller that also arms its own capture cannot double-count.
///
/// Passive listeners only: they observe, never intercept, so they do not conflict with
/// the SSRF route blocker or the network capture that share this context.
pub async fn attach(context: &BrowserContext) {
    let guid = context.guid().to_string();
    {
        let Ok(mut reg) = registry().lock() else { return };
        if reg.contains_key(&guid) {
            return;
        }
        reg.insert(guid, InFlight::new());
    }
    let started = lookup_by_guid(context.guid());
    let Some(counter) = started else { return };

    let c = counter.clone();
    let _ = context
        .on_request(move |request: playwright_rs::Request| {
            let c = c.clone();
            async move {
                if WATCHED.contains(&request.resource_type()) {
                    c.bump(1);
                }
                Ok(())
            }
        })
        .await;
    let c = counter.clone();
    let _ = context
        .on_request_finished(move |request: playwright_rs::Request| {
            let c = c.clone();
            async move {
                if WATCHED.contains(&request.resource_type()) {
                    c.bump(-1);
                }
                Ok(())
            }
        })
        .await;
    let c = counter;
    let _ = context
        .on_request_failed(move |request: playwright_rs::Request| {
            let c = c.clone();
            async move {
                if WATCHED.contains(&request.resource_type()) {
                    c.bump(-1);
                }
                Ok(())
            }
        })
        .await;
}

/// Drop a closed context's counter, so the registry tracks LIVE contexts and cannot
/// grow without bound on a long-lived agent.
pub fn forget(context_guid: &str) {
    if let Ok(mut reg) = registry().lock() {
        reg.remove(context_guid);
    }
}

fn lookup_by_guid(guid: &str) -> Option<InFlight> {
    registry().lock().ok()?.get(guid).cloned()
}

fn lookup(page: &Page) -> Option<InFlight> {
    let context = page.context().ok()?;
    lookup_by_guid(context.guid())
}

/// Wait for the request an action just triggered to leave and land.
///
/// Returns after `probe` when the action started no traffic — the common case (a click
/// that toggles a tab), so this costs no more than the fixed pause it replaces. When
/// traffic IS in flight it keeps waiting, bounded by `max`, then lets the document
/// finish loading.
///
/// Best-effort by construction: a page whose context was never attached falls back to
/// the plain pause, and the load wait swallows its timeout — a run that already did its
/// work must never fail because a page kept a socket open.
pub async fn settle_after_action(page: &Page, probe: Duration, max: Duration) {
    let Some(counter) = lookup(page) else {
        tokio::time::sleep(probe).await;
        return;
    };
    // Give the action's own request a beat to be issued: the click returns before the
    // browser puts anything on the wire.
    let deadline = Instant::now() + probe;
    while Instant::now() < deadline && counter.snapshot().0 == 0 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if counter.snapshot().0 == 0 {
        return;
    }
    let deadline = Instant::now() + max;
    while Instant::now() < deadline {
        let (pending, quiet_for) = counter.snapshot();
        if pending == 0 || quiet_for > Duration::from_millis(1500) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The navigation this triggered may still be parsing — wait for the new document,
    // not the one the action was performed on.
    let _ = crate::browser::navigation::wait_for_load_state(
        page,
        "load",
        Duration::from_secs(5),
    )
    .await;
}
