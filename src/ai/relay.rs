use std::sync::Arc;

use futures_util::SinkExt;
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

use super::client::WsSink;

/// WebSocket adapter that routes data through the gateway's persistent WS
/// using session envelopes.
///
/// The recorder's session stores this as its websocket handle -- all code that
/// calls `send_json()` / `send_bytes()` works unchanged regardless of whether
/// the connection is a direct WS or a gateway relay.
#[derive(Clone)]
pub struct GatewaySessionRelay {
    ws_tx: Arc<Mutex<WsSink>>,
    session_id: String,
}

impl GatewaySessionRelay {
    pub fn new(ws_tx: Arc<Mutex<WsSink>>, session_id: String) -> Self {
        Self { ws_tx, session_id }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Send a JSON message wrapped in a session envelope:
    /// `{"channel": "session", "session_id": "...", "msg": <data>}`
    pub async fn send_json(&self, data: serde_json::Value) -> anyhow::Result<()> {
        let envelope = serde_json::json!({
            "channel": "session",
            "session_id": self.session_id,
            "msg": data,
        });
        let text = serde_json::to_string(&envelope)?;
        let mut sink = self.ws_tx.lock().await;
        sink.send(Message::Text(text)).await?;
        Ok(())
    }

    /// Send binary data with session envelope prefix.
    ///
    /// Wire format: `[0x01][4-byte BE u32 = sid_len][session_id UTF-8][payload]`
    pub async fn send_bytes(&self, data: &[u8]) -> anyhow::Result<()> {
        let sid_bytes = self.session_id.as_bytes();
        let sid_len = sid_bytes.len() as u32;

        let mut frame = Vec::with_capacity(1 + 4 + sid_bytes.len() + data.len());
        frame.push(0x01);
        frame.extend_from_slice(&sid_len.to_be_bytes());
        frame.extend_from_slice(sid_bytes);
        frame.extend_from_slice(data);

        let mut sink = self.ws_tx.lock().await;
        sink.send(Message::Binary(frame)).await?;
        Ok(())
    }
}
