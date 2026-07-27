//! `LocalAiClient` — the desktop's local AI gateway behind the object-safe [`crate::ai::client::AiClient`]
//! trait (A5).
//!
//! The cloud agent's `BridgeAIClient` routes AI completions back over the gateway WS to CLOUD AI. The
//! desktop must NOT do that — its AI runs on the user's OWN vault-sealed BYO provider key
//! (`src/local/ai`). This client implements the SAME `AiClient` trait the transport-agnostic AI mode
//! drivers (`ai::standard_mode` / `intelligent` / `api_discovery`) consume, so a cloud-dispatched AI
//! task can be driven purely by dependency injection — no cloud round-trip.
//!
//! When no provider is configured (`provider::resolve_config` → `None`), every completion returns
//! `None`, which the mode drivers already treat exactly like a failed cloud completion (graceful
//! degrade). `tenant_id`/`purpose` are ignored locally — identity/billing stay server-side
//! (the never-trust-a-BYO-agent rule); there is no cross-tenant billing on-device.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;
use sqlx::sqlite::SqlitePool;

use crate::local::ai::{brain, provider};
use crate::local::vault::Vault;
use crate::models::ai::{AiContentPart, AiMessage, AiMessageContent, ImageSource};

/// An [`crate::ai::client::AiClient`] backed by the desktop's local provider gateway.
pub struct LocalAiClient {
    db: SqlitePool,
    vault: Arc<Vault>,
}

impl LocalAiClient {
    pub fn new(db: SqlitePool, vault: Arc<Vault>) -> Self {
        Self { db, vault }
    }

    /// Resolve the configured provider, run one completion, and JSON-parse the answer via
    /// `brain::parse_decision`. `None` at any stage (no provider, provider error, unparseable text)
    /// degrades exactly like a failed cloud completion.
    async fn complete_parsed(
        &self,
        messages: Vec<AiMessage>,
        system: Option<&str>,
        max_tokens: u32,
    ) -> Option<Value> {
        let cfg = provider::resolve_config(&self.db, &self.vault).await.ok()??;
        let completion = provider::complete(&cfg, &messages, system, max_tokens).await.ok()?;
        brain::parse_decision(&completion.text)
    }

    /// Build a single user message carrying an optional base64 screenshot + a text prompt (the
    /// vision shape the local provider fans out per-provider). Mirrors `brain`'s vision assembly.
    fn vision_message(screenshot_b64: &str, prompt: &str) -> Vec<AiMessage> {
        let mut parts: Vec<AiContentPart> = Vec::new();
        if !screenshot_b64.is_empty() {
            parts.push(AiContentPart::Image {
                source: ImageSource {
                    source_type: "base64".into(),
                    media_type: "image/jpeg".into(),
                    data: screenshot_b64.to_string(),
                },
            });
        }
        parts.push(AiContentPart::Text { text: prompt.to_string() });
        vec![AiMessage { role: "user".into(), content: AiMessageContent::Parts(parts) }]
    }
}

impl crate::ai::client::AiClient for LocalAiClient {
    fn complete_json<'a>(
        &'a self,
        system_prompt: &'a str,
        user_prompt: &'a str,
        _tenant_id: &'a str,
        max_tokens: u32,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<Value>> + Send + 'a>> {
        let system = system_prompt.to_string();
        let user = user_prompt.to_string();
        Box::pin(async move {
            let messages = vec![AiMessage {
                role: "user".into(),
                content: AiMessageContent::Text(user),
            }];
            let system = if system.is_empty() { None } else { Some(system.as_str()) };
            self.complete_parsed(messages, system, max_tokens).await
        })
    }

    fn complete_vision<'a>(
        &'a self,
        screenshot_b64: &'a str,
        prompt: &'a str,
        _tenant_id: &'a str,
        max_tokens: u32,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<Value>> + Send + 'a>> {
        Box::pin(async move {
            let messages = Self::vision_message(screenshot_b64, prompt);
            self.complete_parsed(messages, None, max_tokens).await
        })
    }

    fn complete_vision_with_system<'a>(
        &'a self,
        system_prompt: &'a str,
        screenshot_b64: &'a str,
        prompt: &'a str,
        _tenant_id: &'a str,
        max_tokens: u32,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<Value>> + Send + 'a>> {
        let system = system_prompt.to_string();
        Box::pin(async move {
            let messages = Self::vision_message(screenshot_b64, prompt);
            let system = if system.is_empty() { None } else { Some(system.as_str()) };
            self.complete_parsed(messages, system, max_tokens).await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::client::AiClient;
    use crate::local::{db, vault};

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-ai").await.unwrap()
    }

    fn vault_at() -> (tempfile::TempDir, Arc<Vault>) {
        let dir = tempfile::tempdir().unwrap();
        let v = Arc::new(vault::Vault::load_or_create(dir.path(), false).unwrap());
        (dir, v)
    }

    /// No provider configured AND no env keys → every completion returns `None` (graceful degrade,
    /// exactly like a failed cloud completion). Guard env-key interference by clearing them.
    #[tokio::test]
    async fn no_provider_configured_returns_none() {
        // A stray env key on the CI box would make `resolve_config` return a real config; clear the
        // ones the detector reads so this asserts the true no-provider path.
        for k in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"] {
            std::env::remove_var(k);
        }
        let pool = pool().await;
        let (_dir, vault) = vault_at();
        let client = LocalAiClient::new(pool, vault);
        assert!(
            client.complete_json("sys", "hello", "t", 256, "test").await.is_none(),
            "no provider → complete_json None"
        );
        assert!(
            client.complete_vision("", "look", "t", 256, "test").await.is_none(),
            "no provider → complete_vision None"
        );
        assert!(
            client
                .complete_vision_with_system("sys", "", "look", "t", 256, "test")
                .await
                .is_none(),
            "no provider → complete_vision_with_system None"
        );
    }
}
