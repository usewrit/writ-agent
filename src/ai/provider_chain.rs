use std::future::Future;
use std::sync::Arc;

use crate::models::ai::AiMessage;

use super::client::GatewayAIClient;

// ── Trait ──────────────────────────────────────────────────────

/// Abstraction over AI completion providers.
///
/// The primary implementation is [`GatewayProvider`] which routes through the
/// backend AI gateway.  Future implementations can call OpenAI / Anthropic
/// SDKs directly as fallback paths.
///
/// Methods return `impl Future` so the trait is object-safe enough for generic
/// bounds while staying zero-cost.
pub trait AiProvider: Send + Sync {
    /// Text completion -> parsed JSON (returns `None` on failure).
    fn complete_json(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        tenant_id: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> impl Future<Output = Option<serde_json::Value>> + Send;

    /// Vision completion (screenshot + prompt) -> parsed JSON.
    fn complete_vision(
        &self,
        screenshot_b64: &str,
        prompt: &str,
        tenant_id: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> impl Future<Output = Option<serde_json::Value>> + Send;

    /// Raw completion -> text string.
    fn complete_raw(
        &self,
        messages: Vec<AiMessage>,
        tenant_id: &str,
        system: Option<&str>,
        max_tokens: u32,
        purpose: &str,
    ) -> impl Future<Output = anyhow::Result<String>> + Send;
}

// ── Gateway provider ───────────────────────────────────────────

/// Routes AI calls through the backend WebSocket gateway.
pub struct GatewayProvider {
    client: Arc<GatewayAIClient>,
}

impl GatewayProvider {
    pub fn new(client: Arc<GatewayAIClient>) -> Self {
        Self { client }
    }
}

impl AiProvider for GatewayProvider {
    async fn complete_json(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        tenant_id: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> Option<serde_json::Value> {
        self.client
            .complete_json(system_prompt, user_prompt, tenant_id, max_tokens, purpose)
            .await
    }

    async fn complete_vision(
        &self,
        screenshot_b64: &str,
        prompt: &str,
        tenant_id: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> Option<serde_json::Value> {
        self.client
            .complete_vision(screenshot_b64, prompt, tenant_id, max_tokens, purpose)
            .await
    }

    async fn complete_raw(
        &self,
        messages: Vec<AiMessage>,
        tenant_id: &str,
        system: Option<&str>,
        max_tokens: u32,
        purpose: &str,
    ) -> anyhow::Result<String> {
        self.client
            .complete_raw(messages, tenant_id, system, max_tokens, purpose)
            .await
    }
}
