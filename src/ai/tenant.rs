use std::sync::Arc;

use crate::models::ai::AiMessage;

use super::client::GatewayAIClient;

/// Thin wrapper that binds a `tenant_id` to a shared [`GatewayAIClient`].
///
/// Created per AI session so callers don't have to pass `tenant_id` on every call.
pub struct TenantScopedAIClient {
    client: Arc<GatewayAIClient>,
    tenant_id: String,
}

impl TenantScopedAIClient {
    pub fn new(client: Arc<GatewayAIClient>, tenant_id: String) -> Self {
        Self { client, tenant_id }
    }

    pub fn is_connected(&self) -> bool {
        self.client.is_connected()
    }

    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    /// Text-only completion -> parsed JSON.
    pub async fn complete_json(
        &self,
        system_prompt: &str,
        user_prompt: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> Option<serde_json::Value> {
        self.client
            .complete_json(system_prompt, user_prompt, &self.tenant_id, max_tokens, purpose)
            .await
    }

    /// Vision completion (screenshot + prompt) -> parsed JSON.
    pub async fn complete_vision(
        &self,
        screenshot_b64: &str,
        prompt: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> Option<serde_json::Value> {
        self.client
            .complete_vision(screenshot_b64, prompt, &self.tenant_id, max_tokens, purpose)
            .await
    }

    /// Vision + system prompt -> parsed JSON.
    pub async fn complete_vision_with_system(
        &self,
        system_prompt: &str,
        screenshot_b64: &str,
        prompt: &str,
        max_tokens: u32,
        purpose: &str,
    ) -> Option<serde_json::Value> {
        self.client
            .complete_vision_with_system(
                system_prompt,
                screenshot_b64,
                prompt,
                &self.tenant_id,
                max_tokens,
                purpose,
            )
            .await
    }

    /// Raw completion -> text string.
    pub async fn complete_raw(
        &self,
        messages: Vec<AiMessage>,
        system: Option<&str>,
        max_tokens: u32,
        purpose: &str,
    ) -> anyhow::Result<String> {
        self.client
            .complete_raw(messages, &self.tenant_id, system, max_tokens, purpose)
            .await
    }
}
