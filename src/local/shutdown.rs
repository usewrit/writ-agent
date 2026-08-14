//! Process-global GRACEFUL SHUTDOWN request.
//!
//! The daemon's clean stop — drain the scheduler, stop the cloud agent / relay supervisors, remove
//! `agentd.json`, release the singleton lock and `runtime.json` — hangs off one `tokio::select!` in
//! `writ-agentd`'s `async_main`. Until now the ONLY things that could enter it were Ctrl-C and (on
//! unix) SIGTERM.
//!
//! ## Why that was not enough
//! Windows has no SIGTERM. The desktop shell's "Quit" therefore reached for `taskkill`, and
//! `taskkill /PID <pid> /T` **cannot** stop `writ-agentd`: it asks politely by posting to the
//! target's console/windows, and the daemon — spawned by a GUI-subsystem shell with piped stdio —
//! has neither. So Quit left the daemon running, and the only alternative, `/F`, is a hard
//! `TerminateProcess`: no unwinding, no cleanup, so `runtime.json` and the singleton lock file are
//! left behind for the next boot to detect and sweep ("removing stale singleton lock").
//!
//! A request-driven shutdown fixes both: the daemon stops ITSELF, through exactly the same code path
//! a SIGTERM takes, on every platform.
//!
//! ## Contract
//! * [`request`] is idempotent and never blocks — the first call wins and later ones are no-ops.
//! * [`requested`] resolves once a request has been made, INCLUDING one made before it was first
//!   awaited (the flag is checked before and after arming the waiter, so a request that lands in the
//!   gap cannot be lost).
//! * Nothing here terminates anything. It only resolves a future; the shutdown itself remains the
//!   ordinary fall-out-of-`select!` path, so there is exactly one teardown sequence to reason about.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use tokio::sync::Notify;

static REQUESTED: AtomicBool = AtomicBool::new(false);

fn notify() -> &'static Notify {
    static CELL: OnceLock<Notify> = OnceLock::new();
    CELL.get_or_init(Notify::new)
}

/// Ask the daemon to stop. Idempotent, non-blocking, safe from any task or thread.
///
/// `reason` is logged once (on the first call) so a shutdown is always attributable — an operator
/// looking at a stopped daemon can tell "the desktop app asked" from "someone hit Ctrl-C".
pub fn request(reason: &str) {
    if !REQUESTED.swap(true, Ordering::SeqCst) {
        tracing::info!(reason, "graceful shutdown requested");
    }
    notify().notify_waiters();
}

/// Has a shutdown been requested? Lets long-running work bail out early instead of being cut off.
pub fn is_requested() -> bool {
    REQUESTED.load(Ordering::SeqCst)
}

/// Resolve when [`request`] has been called — immediately if it already has.
pub async fn requested() {
    loop {
        if is_requested() {
            return;
        }
        // Arm the waiter BEFORE re-checking: `Notify::notify_waiters` only wakes waiters that
        // already exist, so a request landing between the check and the await would otherwise be
        // lost and this future would hang forever.
        let waiting = notify().notified();
        if is_requested() {
            return;
        }
        waiting.await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request made BEFORE anyone awaits must still resolve — the desktop shell fires this
    /// milliseconds after boot in the "quit immediately" case, and a lost request means a daemon
    /// that never exits, which is the exact bug this module exists to fix.
    #[tokio::test]
    async fn request_before_await_still_resolves() {
        // Not using the shared statics' initial state: this test and the one below both mutate the
        // process-global flag, so they must agree on ordering. `request` is idempotent and only ever
        // moves false → true, so asserting "resolves" is order-independent.
        request("test");
        assert!(is_requested());
        // Must return immediately rather than hang.
        tokio::time::timeout(std::time::Duration::from_secs(5), requested())
            .await
            .expect("a prior request must resolve immediately");
    }

    /// And it stays resolved for every later waiter (the teardown path may await it more than once).
    #[tokio::test]
    async fn requested_is_level_triggered_not_edge_triggered() {
        request("test");
        for _ in 0..3 {
            tokio::time::timeout(std::time::Duration::from_secs(5), requested())
                .await
                .expect("every subsequent waiter must also resolve");
        }
    }
}
