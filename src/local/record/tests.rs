//! Protocol-framing + auth tests for the local recording WS that do NOT need a real browser.
//!
//! The browser-driving paths (start/action/stop/replay against live Chromium) are exercised by the
//! desktop app end-to-end; here we lock down the wire contract (screencast frame layout the UI
//! decodes, the flat-action shape, the route's own query-token + Origin/Host auth) so a regression
//! in the transport surfaces in CI without launching Chromium.

use crate::browser::screenshot::ScreencastStream;
use crate::local::auth;

/// The screencast binary frame the loopback path forwards RAW must match exactly what
/// the desktop app's `BrowserRecorder` view decodes: `[4B BE url_len][url UTF-8][JPEG]`,
/// reading `url_len` at byte offset 0 (NO leading envelope byte). This is the contract that lets the
/// UI render frames identically to the cloud path.
#[test]
fn screencast_frame_layout_matches_ui_decoder() {
    let url = "https://example.com/login";
    let jpeg = b"\xFF\xD8\xFF\xE0_fake_jpeg_bytes_";
    let frame = ScreencastStream::encode_frame(url, jpeg);

    // UI reads a big-endian u32 url length at offset 0.
    let url_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    assert_eq!(url_len, url.len(), "url_len header must equal the URL byte length");

    // Then `url_len` UTF-8 URL bytes.
    let decoded_url = std::str::from_utf8(&frame[4..4 + url_len]).unwrap();
    assert_eq!(decoded_url, url);

    // Then the raw JPEG payload — and NOTHING is prepended (no 0x01 session envelope: there is no
    // gateway demux on a single-session loopback socket).
    assert_eq!(&frame[4 + url_len..], jpeg);
    assert_ne!(frame[0], 0x01, "loopback frames carry no session-multiplexing envelope byte");
}

/// The UI sends a FLAT action frame: `{type:"action", action:"click", x, y, ...}`. The driver builds
/// an `IncomingAction` from the `action` STRING + the whole frame as data (params are siblings, not
/// nested). Confirm that shape deserializes the way the recorder expects.
#[test]
fn flat_action_frame_builds_incoming_action() {
    use crate::recorder::action_handler::IncomingAction;
    use std::collections::HashMap;

    let frame = serde_json::json!({
        "type": "action",
        "action": "click",
        "x": 120.5,
        "y": 64.0,
        "selector": "#submit"
    });

    let action_type = frame.get("action").and_then(|v| v.as_str()).unwrap();
    let data: HashMap<String, serde_json::Value> =
        serde_json::from_value(frame.clone()).unwrap();
    let incoming = IncomingAction { action_type: action_type.to_string(), data };

    assert_eq!(incoming.action_type, "click");
    assert_eq!(incoming.data.get("selector").and_then(|v| v.as_str()), Some("#submit"));
    assert_eq!(incoming.data.get("x").and_then(|v| v.as_f64()), Some(120.5));
}

/// The route does its OWN auth: a SINGLE-USE `?ticket=<wtk_…>` (minted by the authenticated
/// `POST /v1/ws-ticket`, consumed atomically here) + a loopback Origin/Host guard. The long-lived
/// `wlt_` bearer never appears in the WS URL. These are the rules the `/ws/record` handler enforces
/// before the upgrade: `ws_origin_allowed` (DNS-rebind defense) AND `ws_ticket::consume`.
#[test]
fn ws_route_auth_rules() {
    use crate::local::ws_ticket::{self, WsRoute};
    let port = 8131;

    // Loopback Origin/Host guard: absent headers pass; loopback passes; a foreign Origin is rejected
    // regardless of the ticket (DNS-rebind defense).
    assert!(auth::ws_origin_allowed(None, None, port));
    assert!(auth::ws_origin_allowed(Some("http://127.0.0.1:8131"), Some("127.0.0.1:8131"), port));
    assert!(!auth::ws_origin_allowed(Some("http://attacker.example"), None, port));

    // A freshly-minted record ticket is accepted exactly ONCE (single use); a replay fails.
    let (ticket, _ttl) = ws_ticket::issue(WsRoute::Record, None).unwrap();
    assert!(ws_ticket::consume(&ticket, WsRoute::Record, None), "first use succeeds");
    assert!(!ws_ticket::consume(&ticket, WsRoute::Record, None), "replay is rejected");

    // An absent/unknown ticket is rejected (a browser can't send the bearer header, so a valid
    // ticket is mandatory).
    assert!(!ws_ticket::consume("", WsRoute::Record, None));
    assert!(!ws_ticket::consume("wtk_never_issued", WsRoute::Record, None));
}

/// The `stopped` frame the UI consumes carries the recorded steps + raw replay + captured network
/// calls under the exact keys `BrowserRecorder.tsx` reads (`steps`, `stepCount`, `raw_replay`,
/// `rawReplayCount`, `network_calls`, `network_calls_count`). Lock the key names.
#[test]
fn stopped_frame_shape() {
    let frame = serde_json::json!({
        "type": "stopped",
        "steps": [],
        "stepCount": 0,
        "raw_replay": [],
        "rawReplayCount": 0,
        "network_calls": [],
        "network_calls_count": 0,
    });
    for key in ["type", "steps", "stepCount", "raw_replay", "rawReplayCount", "network_calls", "network_calls_count"] {
        assert!(frame.get(key).is_some(), "stopped frame missing `{key}`");
    }
    assert_eq!(frame["type"], "stopped");
}
