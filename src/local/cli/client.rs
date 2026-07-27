//! A tiny blocking HTTP client the `writ` CLI uses to talk to a running `writ-agentd` over the
//! loopback API.
//!
//! Discovery + auth come straight from `~/.writ/runtime.json` (the `0600` descriptor the daemon
//! publishes on bootstrap): it carries the loopback `port` and the `wlt_` runtime bearer. The CLI is
//! a short-lived, synchronous process, so this uses `reqwest::blocking` (already a crate feature) —
//! no tokio runtime needed for the REST calls.
//!
//! SECURITY: the `wlt_` token is loopback-only and is NEVER printed by this module (it is read from
//! the `0600` descriptor and sent as a `Bearer` header). The base url is always `127.0.0.1:<port>`.
//!
//! House style: `tracing` only, NEVER log the token; errors fold into the crate-local
//! [`crate::local::error::LocalError`] so the CLI has one error type.

use crate::local::app::runtime_file::{self, RuntimeInfo};
use crate::local::config::Paths;
use crate::local::error::{LocalError, LocalResult};
use serde_json::Value;
use std::time::Duration;

/// Per-request timeout for the (local, fast) loopback calls. Generous enough that a cold first run
/// (which may warm a browser) doesn't trip it for status-style reads.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A connected handle to the local daemon: the resolved base url + the `wlt_` bearer + a blocking
/// HTTP client. Build with [`DaemonClient::connect`].
pub struct DaemonClient {
    http: reqwest::blocking::Client,
    base_url: String,
    token: String,
}

impl DaemonClient {
    /// Discover a running daemon from `~/.writ/runtime.json` and build a client.
    ///
    /// Returns [`LocalError::NotFound`] (mapped to a friendly "is the daemon running?" message by the
    /// CLI) when the descriptor is absent — i.e. no daemon is up. Other IO/parse errors propagate.
    pub fn connect(paths: &Paths) -> LocalResult<Self> {
        let info = runtime_file::read(paths)?
            .ok_or_else(|| LocalError::NotFound("no running daemon (runtime.json not found)".into()))?;
        Self::from_runtime(&info)
    }

    /// Build a client from an already-read [`RuntimeInfo`] descriptor.
    pub fn from_runtime(info: &RuntimeInfo) -> LocalResult<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("writ-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| LocalError::Internal(format!("cli http client build: {e}")))?;
        Ok(Self {
            http,
            base_url: format!("http://127.0.0.1:{}", info.port),
            token: info.token.clone(),
        })
    }

    /// `GET <path>` → parsed JSON. `path` is absolute (e.g. `/v1/agent`).
    pub fn get(&self, path: &str) -> LocalResult<Value> {
        let resp = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .send()
            .map_err(|e| LocalError::Internal(format!("local request failed: {e}")))?;
        Self::parse(resp)
    }

    /// `POST <path>` with an empty body → parsed JSON. The daemon's cloud routes take no body.
    pub fn post_empty(&self, path: &str) -> LocalResult<Value> {
        let resp = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .send()
            .map_err(|e| LocalError::Internal(format!("local request failed: {e}")))?;
        Self::parse(resp)
    }

    /// `POST <path>` with a JSON body → parsed JSON.
    pub fn post_json(&self, path: &str, body: &Value) -> LocalResult<Value> {
        let resp = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .map_err(|e| LocalError::Internal(format!("local request failed: {e}")))?;
        Self::parse(resp)
    }

    /// `PUT <path>` with a JSON body → parsed JSON.
    pub fn put_json(&self, path: &str, body: &Value) -> LocalResult<Value> {
        let resp = self
            .http
            .put(format!("{}{}", self.base_url, path))
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .map_err(|e| LocalError::Internal(format!("local request failed: {e}")))?;
        Self::parse(resp)
    }

    /// Map a loopback HTTP response onto `LocalResult<Value>`, surfacing the daemon's
    /// `{error, code}` body on a non-2xx so the CLI can print a useful message.
    fn parse(resp: reqwest::blocking::Response) -> LocalResult<Value> {
        let status = resp.status();
        let body: Value = resp.json().unwrap_or(Value::Null);
        if status.is_success() {
            return Ok(body);
        }
        let msg = body
            .get("error")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| format!("daemon returned HTTP {}", status.as_u16()));
        Err(match status.as_u16() {
            401 => LocalError::Unauthorized,
            404 => LocalError::NotFound(msg),
            _ => LocalError::Internal(msg),
        })
    }
}
