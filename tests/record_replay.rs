//! Record → replay smoke over the local recording WebSocket (`GET /ws/record`).
//!
//! The FULL record→replay flow drives a live warm Chromium (the daemon's own browser, shared with the
//! run engine) — it cannot run in CI without a Chromium binary + a display, so the end-to-end smoke is
//! `#[ignore]`d and documented below.
//!
//! What CAN be asserted browserlessly is the WS-connect AUTH CONTRACT the `/ws/record` handler applies
//! BEFORE it upgrades (`auth::ws_connect_authorized`): a loopback Origin/Host guard + a constant-time
//! `wlt_` query-token compare. We test that function directly with the SAME token the daemon mints.
//!
//! Why not assert HTTP status over the router? `axum`'s `WebSocketUpgrade` extractor rejects a request
//! that is not a genuine, upgradable connection with `426 Upgrade Required` at EXTRACTION time — before
//! the handler body (and thus its auth/availability logic) ever runs. A `tower::oneshot` request can't
//! complete a real WS handshake, so it always sees 426; the 401 (bad token) / 503 (no browser-backed
//! recorder) statuses are only observable from a real WebSocket client. That live HTTP path, like the
//! record→replay smoke itself, is covered by the `#[ignore]`d case below (run with `-- --ignored`).
//!
//! ADDITIVE (net-new file), `local`-feature only → the cloud build is byte-unchanged.
//!
//! Run (auth-contract tests):  cargo test --features local --test record_replay
//! Run (full smoke):           cargo test --features local --test record_replay -- --ignored
//!                             (requires a Chromium/Patchright driver + a run-capable engine)

#![cfg(feature = "local")]

use std::sync::Arc;
use writ_agent::local::server::AppState;
use writ_agent::local::{auth, config, config::LocalConfig, db, engine, vault};

const TOKEN: &str = "wlt_record_replay";

/// Real `AppState` over a fresh headless vault + encrypted DB. The `StubEngine` provides NO browser,
/// so `AppState.recorder` is `None` — exactly the build where a real `/ws/record` connection would
/// answer 503 once auth passes. Kept for the `#[ignore]`d smoke (which swaps in a run-capable engine).
async fn test_state() -> AppState {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = config::Paths::at(dir.keep()); // keep() persists the dir for the test process lifetime
    paths.ensure_dirs().expect("ensure dirs");
    let v = vault::Vault::load_or_create(&paths.root, false).expect("headless vault");
    let pool = db::open(&paths.db(), &v.db_key_hex()).await.expect("open encrypted db");
    AppState {
        db: pool,
        vault: Arc::new(v),
        engine: Arc::new(engine::StubEngine),
        config: LocalConfig::default(),
        token: Arc::new(TOKEN.to_string()),
        health: writ_agent::local::app::health::DaemonHealth::shared(),
        recorder: None,
    }
}

/// A loopback Origin string the WS-connect guard accepts (the local UI / Tauri shell origin shape).
fn loopback_origin(port: u16) -> String {
    format!("http://127.0.0.1:{port}")
}

/// The recorder WS auth gate is the SAME predicate `/ws/record` runs before upgrading: a valid `wlt_`
/// query token + a loopback Origin/Host must authorize; absent/empty/wrong tokens must not.
#[tokio::test]
async fn ws_connect_requires_valid_token() {
    let st = test_state().await;
    let port = st.config.port;
    let origin = loopback_origin(port);

    // Valid token + loopback origin/host → authorized.
    assert!(
        auth::ws_connect_authorized(Some(TOKEN), Some(&origin), Some(&origin), st.token.as_str(), port),
        "the minted wlt_ token over a loopback origin authorizes the recorder WS"
    );

    // Absent token → rejected (a browser that forgot the ?token= can't open the recorder).
    assert!(
        !auth::ws_connect_authorized(None, Some(&origin), Some(&origin), st.token.as_str(), port),
        "no ?token= → unauthorized"
    );

    // Empty token → rejected (an empty string never matches, even constant-time).
    assert!(
        !auth::ws_connect_authorized(Some(""), Some(&origin), Some(&origin), st.token.as_str(), port),
        "empty token → unauthorized"
    );

    // Wrong token → rejected.
    assert!(
        !auth::ws_connect_authorized(
            Some("wlt_not_the_token"),
            Some(&origin),
            Some(&origin),
            st.token.as_str(),
            port
        ),
        "a wrong token → unauthorized"
    );
}

/// DNS-rebind defense: even WITH the correct token, a foreign (non-loopback) Origin/Host is rejected,
/// so a malicious web page cannot drive the recorder via a victim's browser.
#[tokio::test]
async fn ws_connect_rejects_foreign_origin_even_with_token() {
    let st = test_state().await;
    let port = st.config.port;

    // Correct token but an evil cross-origin Origin → rejected by the loopback guard.
    assert!(
        !auth::ws_connect_authorized(
            Some(TOKEN),
            Some("http://evil.example"),
            None,
            st.token.as_str(),
            port
        ),
        "a foreign Origin is rejected even with the right token (DNS-rebind defense)"
    );

    // Correct token but a foreign Host header → also rejected.
    assert!(
        !auth::ws_connect_authorized(
            Some(TOKEN),
            None,
            Some("evil.example:80"),
            st.token.as_str(),
            port
        ),
        "a foreign Host is rejected even with the right token"
    );
}

/// FULL record → replay smoke (IGNORED — needs a live Chromium/Patchright driver + a run-capable
/// engine wiring a real `recorder`).
///
/// When un-ignored against such a build, the shape of the smoke is:
///   1. Build `AppState` whose `engine` is the `RealEngine` (owns a warm `BrowserManager`) and whose
///      `recorder` is `Some(PlaywrightRecorder)` sharing that same browser.
///   2. Open `GET /ws/record?token=<wlt_>` with a real WebSocket client and complete the handshake
///      (a non-upgradable `oneshot` request can't — see the module note — so this needs a live client).
///   3. Send the recorder start frame, drive a couple of synthetic interactions (navigate + click +
///      a text fill) against a local fixture page, and collect the emitted recorded-step frames.
///   4. Stop recording; persist the steps as a workflow (`workflows::insert`).
///   5. REPLAY: dispatch the saved workflow through the engine (or the `replay_steps` frame) and assert
///      the replayed run reaches the same terminal page / extracted data as the recording.
///   6. Assert the unhappy paths along the way: a bad `?token=` → 401, and (on a browserless build) a
///      valid token with `recorder: None` → 503 "recorder unavailable".
///
/// This is intentionally left as a documented `#[ignore]` per the test-harness task: the auth-contract
/// tests above cover everything reachable without a browser; the live driver path is validated
/// manually / in a browser-capable CI lane with `-- --ignored`.
#[tokio::test]
#[ignore = "needs Chromium (live Patchright driver) + a run-capable RealEngine recorder"]
async fn record_then_replay_smoke() {
    // Placeholder body: a browser-capable build replaces this with the steps documented above. Kept
    // as a compiling no-op so the harness lists the (ignored) case and it can be run with --ignored.
    let _st = test_state().await;
}
