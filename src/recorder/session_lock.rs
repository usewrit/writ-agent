//! Non-blocking access to the recording-session table.
//!
//! # Why this exists
//!
//! The session table is a `DashMap`, whose guards are **synchronous** `RwLock`s.
//! Calling `sessions.get(id)` from an async task does not yield — it *parks the
//! tokio worker thread* until the shard is free. That is the ingredient in a
//! deadlock that froze the recorder solid on any page whose navigation raced a
//! user action:
//!
//! 1. `local::record::session::handle_action` takes a **write** guard
//!    (`get_session_mut`) and holds it across every `await` of the action —
//!    keyboard input, `page.evaluate`, the lot.
//! 2. The action navigates the page (Enter in a search box, a click on a submit
//!    button). Chrome fires `frameNavigated`; playwright-rs spawns a task for it.
//! 3. That task calls `sessions.get(id)` and **blocks its worker thread**.
//! 4. The blocked worker is one of `num_cpus` — and on a small VPS or a
//!    CPU-limited container that can be 1 or 2. With the workers parked, nothing
//!    is left to pump the Playwright driver pipe.
//! 5. The driver pipe is exactly what step 1 is awaiting. It never gets a
//!    response, never releases the write guard, and step 3 never unblocks.
//!
//! Circular wait, permanently wedged. The user sees the screencast freeze
//! mid-navigation, no further action reaches the browser, and the agent's own
//! health check eventually reports `read_loop_wedged`.
//!
//! Two comments in this crate already describe the same hazard from the other
//! side — `page_listeners` dropped its network listeners over it, and the
//! `framenavigated` handler is carefully written to never hold the lock across an
//! await. Both mitigations address the *holder*. This module addresses the
//! *waiter*, which is the half that actually parks threads: acquire with
//! `try_get`, and `yield_now()` on contention so the worker stays free to run the
//! very task that will release the guard.
//!
//! # Rule
//!
//! **Never call `sessions.get`/`get_mut`/`iter` from an async context.** Use
//! [`session_ref`] / [`session_mut`] instead. A blocking guard is fine only on a
//! thread that is allowed to block — i.e. inside `spawn_blocking`.

use std::time::Duration;

use dashmap::mapref::one::{Ref, RefMut};
use dashmap::try_result::TryResult;
use dashmap::DashMap;

use crate::models::session::RecordingSession;

/// Give up after this long rather than spinning forever. A caller that cannot get
/// the session within this window is an event handler whose work is optional
/// (record a step, re-inject a helper); dropping it is strictly better than
/// holding a task hostage. Comfortably longer than any single page action.
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(15);

/// Spin hot (pure yields) for this many attempts before falling back to a short
/// sleep. Contention is normally over in microseconds — the fast path should not
/// pay for a timer — but an action doing real page I/O can hold the guard for
/// hundreds of milliseconds, and busy-yielding through that would burn a core.
const HOT_SPINS: u32 = 32;
const BACKOFF: Duration = Duration::from_millis(2);

/// Acquire a shared reference to a session without ever blocking the worker.
///
/// Returns `None` if the session does not exist, or if the guard could not be
/// acquired within [`ACQUIRE_TIMEOUT`].
pub async fn session_ref<'a>(
    sessions: &'a DashMap<String, RecordingSession>,
    session_id: &str,
) -> Option<Ref<'a, String, RecordingSession>> {
    let mut spins: u32 = 0;
    let deadline = tokio::time::Instant::now() + ACQUIRE_TIMEOUT;
    loop {
        match sessions.try_get(session_id) {
            TryResult::Present(r) => return Some(r),
            TryResult::Absent => return None,
            TryResult::Locked => {
                if tokio::time::Instant::now() >= deadline {
                    tracing::warn!(
                        session_id = %session_id,
                        "Timed out waiting for the session lock (read); skipping this event"
                    );
                    return None;
                }
                yield_once(&mut spins).await;
            }
        }
    }
}

/// Acquire an exclusive reference to a session without ever blocking the worker.
///
/// Returns `None` if the session does not exist, or if the guard could not be
/// acquired within [`ACQUIRE_TIMEOUT`].
pub async fn session_mut<'a>(
    sessions: &'a DashMap<String, RecordingSession>,
    session_id: &str,
) -> Option<RefMut<'a, String, RecordingSession>> {
    let mut spins: u32 = 0;
    let deadline = tokio::time::Instant::now() + ACQUIRE_TIMEOUT;
    loop {
        match sessions.try_get_mut(session_id) {
            TryResult::Present(r) => return Some(r),
            TryResult::Absent => return None,
            TryResult::Locked => {
                if tokio::time::Instant::now() >= deadline {
                    tracing::warn!(
                        session_id = %session_id,
                        "Timed out waiting for the session lock (write); skipping this event"
                    );
                    return None;
                }
                yield_once(&mut spins).await;
            }
        }
    }
}

async fn yield_once(spins: &mut u32) {
    if *spins < HOT_SPINS {
        *spins += 1;
        tokio::task::yield_now().await;
    } else {
        tokio::time::sleep(BACKOFF).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property that matters: a contended acquire must YIELD, so the task
    /// holding the guard can still be polled to completion on the same worker.
    /// A blocking `get()` here would park the thread and hang the test on a
    /// single-worker runtime — which is exactly the production deadlock.
    #[test]
    fn contended_acquire_yields_instead_of_blocking_the_worker() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let map: DashMap<String, u32> = DashMap::new();
            map.insert("s".to_string(), 1);

            // Hold a write guard, then let another task try to read it. On a
            // current-thread runtime the reader MUST yield or nothing else can
            // ever run — including the code that drops the guard.
            let mut spins = 0u32;
            let guard = map.get_mut("s").unwrap();
            assert!(matches!(map.try_get("s"), TryResult::Locked));
            yield_once(&mut spins).await;
            assert_eq!(spins, 1, "first contention should be a cheap yield");
            drop(guard);
            assert!(matches!(map.try_get("s"), TryResult::Present(_)));
        });
    }

    #[test]
    fn backs_off_to_sleeping_after_the_hot_window() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut spins = HOT_SPINS;
            let started = std::time::Instant::now();
            yield_once(&mut spins).await;
            // Past the hot window we sleep rather than burn the core.
            assert!(started.elapsed() >= BACKOFF / 2);
            assert_eq!(spins, HOT_SPINS, "sleeping path must not keep incrementing");
        });
    }
}
