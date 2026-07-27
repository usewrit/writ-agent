//! Local MCP server for the Writ desktop backend — exposes the user's enabled workflows as MCP
//! tools over two transports backed by ONE protocol core.
//!
//! Layout:
//! - [`protocol`] — JSON-RPC 2.0 wire types + method dispatch (`initialize`/`ping`/`tools/list`/
//!   `tools/call`/`notifications/*`). Transport-agnostic; both surfaces call `protocol::handle_value`.
//! - [`tools`] — builds the `tools/list` catalog from enabled workflows (name = sanitized workflow
//!   name or `workflow_<id>`; `inputSchema` derived by scanning steps for `{{input.NAME}}`; secret
//!   placeholders excluded).
//! - [`tool_executor`] — `tools/call` → resolve the tool to a workflow → `RunRequest{source:Mcp}` →
//!   `state.engine.run(..)` → MCP content result.
//! - [`http`] — loopback `POST /mcp` (bearer + Origin/Host guard applied by `server.rs`).
//! - [`stdio`] — line-delimited JSON-RPC on stdin/stdout for a future `writ-agent mcp` CLI
//!   (process-trust; no token).
//!
//! Wiring: `api::v1::router()` merges `mcp::http::router()` (so `server.rs` mounts it inside the
//! bearer + Origin/Host guard); the stdio runner is invoked as `writ mcp stdio` (`cli::mcp_stdio`).

pub mod http;
pub mod protocol;
pub mod static_tools;
pub mod stdio;
pub mod tool_executor;
pub mod tools;

/// The stdio MCP runner, re-exported for the CLI entrypoint: `local::mcp::run_stdio(state).await`.
pub use stdio::run_stdio;
