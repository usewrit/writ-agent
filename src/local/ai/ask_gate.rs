//! In-process handoff that lets a RUNNING explorer session PARK on an ask-the-user pause without
//! closing its browser. The session registers a one-shot waiter keyed by the concierge session id
//! and awaits; `/respond` (same process) resolves it with the user's answers — the plaintext of a
//! just-sealed secret travels ONLY through this channel (memory-to-memory, never persisted raw) so
//! the resumed session can keep filling on the SAME live page. If no waiter is registered (the
//! session timed out and closed, or the daemon restarted), `/respond` falls back to the classic
//! stop→ask→re-run path — this gate is an optimization, never a correctness dependency.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tokio::sync::oneshot;

/// The user's answers, shaped for a parked explorer to CONTINUE with:
/// - `fill`: key → plaintext (execution only — a sealed secret's opened value, or a typed literal),
/// - `record`: key → the REPLAY spelling for recorded steps ({{secret:VAULT_KEY}} ref / literal),
/// - `text`: key → displayable answer (secrets already replaced by their refs) for the model turn.
#[derive(Debug)]
pub struct AskAnswers {
    pub fill: HashMap<String, String>,
    pub record: HashMap<String, String>,
    pub text: HashMap<String, String>,
}

fn waiters() -> &'static Mutex<HashMap<i64, oneshot::Sender<AskAnswers>>> {
    static WAITERS: OnceLock<Mutex<HashMap<i64, oneshot::Sender<AskAnswers>>>> = OnceLock::new();
    WAITERS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Register a waiter for a concierge session's pending ask. Replaces any stale waiter for the id.
pub fn register(session_id: i64) -> oneshot::Receiver<AskAnswers> {
    let (tx, rx) = oneshot::channel();
    waiters().lock().unwrap().insert(session_id, tx);
    rx
}

/// Drop a waiter (timeout/cancel/finish) so a later `/respond` takes the classic re-run path.
pub fn unregister(session_id: i64) {
    waiters().lock().unwrap().remove(&session_id);
}

/// Is a live session currently parked on this concierge id?
pub fn has_waiter(session_id: i64) -> bool {
    waiters().lock().unwrap().contains_key(&session_id)
}

/// Hand the answers to the parked session. `false` when no waiter is (still) there — the caller
/// must fall back to re-spawning the mission loop.
pub fn resolve(session_id: i64, answers: AskAnswers) -> bool {
    let tx = waiters().lock().unwrap().remove(&session_id);
    match tx {
        Some(tx) => tx.send(answers).is_ok(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_delivers_to_registered_waiter_once() {
        let rx = register(9001);
        assert!(has_waiter(9001));
        let ok = resolve(
            9001,
            AskAnswers { fill: HashMap::new(), record: HashMap::new(), text: HashMap::new() },
        );
        assert!(ok);
        assert!(!has_waiter(9001));
        assert!(rx.await.is_ok());
        // Second resolve has nobody to deliver to.
        assert!(!resolve(
            9001,
            AskAnswers { fill: HashMap::new(), record: HashMap::new(), text: HashMap::new() },
        ));
    }

    #[tokio::test]
    async fn unregister_makes_respond_fall_back() {
        let _rx = register(9002);
        unregister(9002);
        assert!(!has_waiter(9002));
    }
}
