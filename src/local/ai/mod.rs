//! Local-daemon AI gateway: multi-provider completions + the ported agent-assist brain.
//!
//! - [`provider`] — config resolution (vault-sealed key) + a unified `complete()` over OpenAI
//!   (chat + Responses), Anthropic, Google Gemini, and any OpenAI-compatible endpoint.
//! - [`prompts`] — verbatim prompts ported from the cloud `agent_brain.py` / `ai_assist.py`.
//! - [`brain`] — agent-turn assembly (system + user message), lenient parse, decision coercion.
//!
//! The REST surface lives in `api::v1::ai_config` (`/v1/ai/config`) and `api::v1::ai_assist`
//! (`/v1/ai-assist/*`), wired into the loopback router by `server.rs` like every other resource.

pub mod action_executor;
pub mod ask_gate;
pub mod autonomous_prompts;
pub mod brain;
pub mod concierge;
pub mod concierge_docs;
pub mod context_clean;
pub mod explorer;
pub mod live_preview;
pub mod observation;
pub mod optimize_live;
pub mod prompts;
pub mod provider;
pub mod run;
pub mod session;
