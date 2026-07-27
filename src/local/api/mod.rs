//! Local backend HTTP API surface. Versioned namespaces live under here; `v1` is the REST API
//! mounted onto the loopback router by `server::build_router`. Future phases (OpenAI-compat,
//! MCP-over-HTTP) add sibling modules alongside `v1`.

pub mod v1;
