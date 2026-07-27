//! Typed sqlx store layer (runtime-checked CRUD per table). Generated P1; integrated + verified.
//!
//! ## `Debug` and secret material
//!
//! Several row structs here carry credentials: persona login secrets and TOTP seeds, vault secret
//! ciphertext, a webhook's plaintext bearer token, a chat bot token, credential HASHES, and the
//! concierge transcript (which contains whatever the user typed, up to and including an OTP). A
//! `#[derive(Debug)]` on those prints all of it, and these structs DO reach `tracing` — every
//! `tracing::warn!(error = ?e)` on a code path holding one, every `.expect()` message, every
//! `#[instrument]`. So they get hand-written `Debug` impls that show the identifying fields and report
//! secret fields only as present/absent, via [`redacted`]. Same pattern as `local::vault`,
//! `local::cloud::token::TokenPair`, `local::cloud::link` and `local::ai::provider::AiConfig`.
//!
//! This is about `Debug` only — `Serialize` is a separate, deliberate decision per struct (the API
//! surfaces these rows, and the routes that do choose which fields go out).

/// `Debug` placeholder for a field that must never be printed: reports PRESENCE, never content.
///
/// Presence still matters for diagnostics ("is a TOTP seed stored for this persona?") and leaks
/// nothing — not even a length, which for a short secret is itself a hint.
pub(crate) fn redacted<T>(v: &Option<T>) -> &'static str {
    match v {
        Some(_) => "<redacted>",
        None => "None",
    }
}

/// [`redacted`] for a NON-optional secret field — always present, never printable.
pub(crate) const REDACTED: &str = "<redacted>";

pub mod ai_preview_steps;
pub mod ai_sessions;
pub mod automation_executions;
pub mod automations;
pub mod changes;
pub mod cloud_sync_map;
pub mod concierge_sessions;
pub mod config_kv;
pub mod crawl_jobs;
pub mod installed_workflows;
pub mod local_api_keys;
pub mod monitor_state;
pub mod notification_connectors;
pub mod oauth;
pub mod personas;
pub mod repair_history;
pub mod run_artifacts;
pub mod runs;
pub mod selector_extractors;
pub mod stored_files;
pub mod target_selectors;
pub mod targets;
pub mod uptime_checks;
pub mod vault_secrets;
pub mod webhook_triggers;
pub mod workflow_sessions;
pub mod workflows;

#[cfg(test)]
mod redaction_tests {
    //! One test per secret-bearing row struct: `format!("{:?}")` must never contain the secret.
    //!
    //! These are the regression guard for the hand-written `Debug` impls. A future contributor who
    //! "tidies up" one of them back into `#[derive(Debug)]` fails here rather than in production logs.

    const SECRET: &str = "SUPERSECRETVALUE";

    /// Assert a `Debug` rendering carries no secret and does say something was withheld.
    fn assert_redacted(what: &str, rendered: String) {
        assert!(!rendered.contains(SECRET), "{what} leaked a secret into Debug: {rendered}");
        assert!(rendered.contains("<redacted>"), "{what} did not mark the withheld field: {rendered}");
    }

    #[test]
    fn vault_secret_debug_hides_the_value() {
        let row = super::vault_secrets::NewVaultSecret {
            key: "STRIPE_KEY".into(),
            value_encrypted: SECRET.into(),
            ..Default::default()
        };
        assert_redacted("NewVaultSecret", format!("{row:?}"));
        // The identifying field is still there — a redacting Debug must stay useful.
        assert!(format!("{row:?}").contains("STRIPE_KEY"));
    }

    #[test]
    fn persona_debug_hides_credentials_and_totp_seed() {
        let row = super::personas::NewPersona {
            name: "payroll".into(),
            login_username: Some("alice".into()),
            credentials_encrypted: Some(SECRET.into()),
            totp_seed_encrypted: Some(SECRET.into()),
            session_state_encrypted: Some(SECRET.into()),
            proxy_config_encrypted: Some(SECRET.into()),
            ..Default::default()
        };
        assert_redacted("NewPersona", format!("{row:?}"));
        assert!(format!("{row:?}").contains("payroll"));

        let patch = super::personas::PersonaUpdate {
            credentials_encrypted: Some(SECRET.into()),
            ..Default::default()
        };
        assert_redacted("PersonaUpdate", format!("{patch:?}"));
    }

    #[test]
    fn webhook_trigger_debug_hides_the_bearer_token_and_signing_secret() {
        let row = super::webhook_triggers::NewWebhookTrigger {
            name: "deploy hook".into(),
            token: SECRET.into(),
            secret_encrypted: Some(SECRET.into()),
            ..Default::default()
        };
        assert_redacted("NewWebhookTrigger", format!("{row:?}"));
        assert!(format!("{row:?}").contains("deploy hook"));

        let patch = super::webhook_triggers::WebhookTriggerPatch {
            secret_encrypted: Some(SECRET.into()),
            ..Default::default()
        };
        assert_redacted("WebhookTriggerPatch", format!("{patch:?}"));
    }

    #[test]
    fn notification_connector_debug_hides_the_webhook_url_and_bot_token() {
        let row = super::notification_connectors::NewNotificationConnector {
            provider: "slack".into(),
            name: "alerts".into(),
            webhook_url: Some(format!("https://hooks.slack.com/services/{SECRET}")),
            bot_token: Some(format!("xoxb-{SECRET}")),
            ..Default::default()
        };
        assert_redacted("NewNotificationConnector", format!("{row:?}"));
        assert!(format!("{row:?}").contains("slack"));
    }

    #[test]
    fn local_api_key_debug_hides_the_hash_but_keeps_the_prefix() {
        let row = super::local_api_keys::NewLocalApiKey {
            name: "mcp".into(),
            prefix: "wlk_abcd".into(),
            key_hash: SECRET.into(),
            ..Default::default()
        };
        assert_redacted("NewLocalApiKey", format!("{row:?}"));
        // The prefix is a deliberate non-secret display fragment; it must survive.
        assert!(format!("{row:?}").contains("wlk_abcd"));
    }

    #[test]
    fn redacted_helper_reports_presence_only() {
        assert_eq!(super::redacted(&Some(SECRET)), "<redacted>");
        assert_eq!(super::redacted(&None::<&str>), "None");
        // Never the length — for a short secret that is itself a hint.
        assert!(!super::redacted(&Some("abc")).contains('3'));
    }
}
