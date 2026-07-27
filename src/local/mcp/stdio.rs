//! MCP-over-stdio transport — line-delimited JSON-RPC on stdin/stdout for a future `writ-agent mcp`
//! CLI subcommand.
//!
//! This is the PROCESS-TRUST surface: the runner is spawned as a child of a local MCP client (e.g.
//! an IDE or desktop agent), so trust is established by process ownership — there is NO bearer token
//! and NO Origin/Host guard (those guard the loopback HTTP surface in `server.rs`). It reads one
//! JSON-RPC frame per line from stdin and writes exactly one line of JSON per reply to stdout;
//! notifications produce no output line. Diagnostics go to `tracing` (stderr), never stdout — stdout
//! is reserved for the JSON-RPC stream.
//!
//! House style: no `async-trait`; `tracing` only; NORMAL multiline strings. Tokio's `io` (the `full`
//! feature is enabled crate-wide) provides the buffered stdin reader + stdout writer.

use super::protocol;
use crate::local::auth::Caller;
use crate::local::error::LocalResult;
use crate::local::server::AppState;
use serde_json::Value;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Run the stdio MCP loop until stdin reaches EOF. Each non-empty line is parsed as a JSON-RPC frame
/// and dispatched through `mcp::protocol`; the reply (if any) is written as a single line to stdout.
/// A line that is not valid JSON yields a JSON-RPC parse error reply (id `null`). Returns once stdin
/// closes.
pub async fn run_stdio(state: AppState) -> LocalResult<()> {
    tracing::info!("mcp stdio runner started (process-trust; no token)");
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin).lines();
    let mut stdout = io::stdout();

    while let Some(line) = reader.next_line().await? {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(trimmed) {
            // PROCESS TRUST: the runner is a child of the MCP client the user launched, so the caller
            // already has this user's privileges (it could read `runtime.json` and use the master
            // bearer directly). There is no credential to scope, hence `FullAccess` — the per-tool
            // scope gate in `tool_executor` is for the HTTP surface, where a scoped `wlk_`/`wlo_`
            // credential exists to be honored.
            Ok(frame) => protocol::handle_value(&state, &Caller::FullAccess, frame).await,
            Err(e) => {
                tracing::debug!(error = %e, "mcp stdio: parse error");
                Some(protocol::JsonRpcResponse::err(
                    Value::Null,
                    protocol::PARSE_ERROR,
                    "Parse error",
                ))
            }
        };
        // Notifications (None) produce no output line.
        if let Some(resp) = reply {
            let mut buf = serde_json::to_string(&resp)?;
            buf.push('\n');
            stdout.write_all(buf.as_bytes()).await?;
            stdout.flush().await?;
        }
    }

    tracing::info!("mcp stdio runner: stdin closed, exiting");
    Ok(())
}
