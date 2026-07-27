//! Full-capability cloud execution agent (`golden-stargazing-gadget` Workstream A).
//!
//! When the desktop is cloud-linked it can act as a BYO execution agent the cloud dispatches work TO
//! — driving the desktop's OWN warm browser, local AI gateway, and local scheduler over the existing
//! [`super::gateway::LinkedAgentBridge`] WS. This submodule holds the desktop-side seams the bridge
//! router uses so `gateway.rs` stays a thin router:
//!   * [`creds`] — the channel_key credential seam (keyring, NOT the cloud creds file).
//!   * [`ai_client`] — [`ai_client::LocalAiClient`], local AI behind the shared `AiClient` trait.
//!
//!   * [`manager`] — [`manager::LinkedAgentManager`], the supervised enable/disable lifecycle holder.
//!
//! The capability handlers (ad-hoc recipe execution / AI tasks / streaming) live in [`workflow`] /
//! [`ai_task`]; the `/v1/cloud/agent/*` REST surface lives in `crate::local::api::v1::cloud_agent`.
//! All net-new Rust lives under `src/local/**` (behind the `local` cargo feature); security/identity/
//! billing stay server-side (the never-trust-a-BYO-agent rule).

// `ai_browsing` + `record` were relocated to `local`-gated homes (`crate::local::browse` /
// `crate::local::record::bridge`) so the OSS fleet worker can compose the SAME recording +
// interactive-browse handlers. Re-exported here at their historical paths so `gateway.rs`
// (`super::agent::ai_browsing::*` / `super::agent::record::*`) keeps resolving unchanged. Safe
// across feature combos: this module only compiles under `local,cloud`, where both targets exist.
pub use crate::local::browse as ai_browsing;
pub use crate::local::record::bridge as record;
pub mod ai_client;
pub mod ai_task;
pub mod creds;
pub mod manager;
pub mod monitoring;
pub mod runs;
pub mod streaming;
pub mod streaming_map;
pub mod workflow;

use serde_json::Value;
use sqlx::sqlite::SqlitePool;

use super::state::LinkState;
use crate::local::config;

/// Defense-in-depth supply-pool gate (`golden-stargazing-gadget` §8, invariant 6).
///
/// The server is the AUTHORITY on whether other-tenant (shared supply-pool) work is routed to this
/// agent (the never-trust-a-BYO-agent rule) — it MUST NOT dispatch other-tenant work to an agent that
/// did not advertise `supply_pool_opt_in`. This is the AGENT-SIDE second line: if a dispatched
/// capability frame is stamped with an owner/tenant id that differs from THIS desktop's linked account,
/// AND the user has NOT opted this device into the shared supply pool, the agent REFUSES the work.
///
/// Returns `true` when the frame must be REFUSED. The check is fail-OPEN on the "own work" side (an
/// unstamped frame, or one whose tenant matches the owner, is always allowed) and only ever *adds* a
/// refusal when the two signals — a foreign tenant stamp AND opt-in-off — both hold, so it can never
/// block the owner's own cloud-dispatched runs. Identity is the gateway's stamp; the agent authorizes
/// nothing beyond this local self-protection.
///
/// A config read error fails SAFE for the OWNER (treats opt-in as OFF): with opt-in unknown we only
/// ever refuse a frame that is ALREADY stamped foreign, never the owner's own work.
pub async fn should_refuse_foreign_tenant(msg: &Value, db: &SqlitePool) -> bool {
    // The gateway stamps the dispatching tenant/owner id on the frame (or nests it under `config`).
    // Read the first non-empty of the known stamp keys; an absent stamp ⇒ treat as the owner's own
    // work (nothing to refuse).
    let stamped = frame_tenant_id(msg);
    let stamped = match stamped {
        Some(s) if !s.is_empty() => s,
        _ => return false, // no foreign stamp ⇒ owner's own work ⇒ allow
    };

    // The owner's tenant is the linked account id.
    let owner = LinkState::load_or_default(db).await.map(|l| l.account_id).unwrap_or_default();
    if !owner.is_empty() && stamped == owner {
        return false; // frame is the owner's own work ⇒ allow regardless of opt-in
    }

    // Foreign (or owner-unknown) stamp: allow ONLY if this device opted into the shared supply pool.
    let opted_in = match config::Paths::resolve() {
        Ok(paths) => config::load_config(&paths).supply_pool_opt_in,
        Err(_) => false, // fail safe: opt-in unknown ⇒ treated as OFF ⇒ refuse foreign work
    };
    !opted_in
}

/// Extract the gateway-stamped dispatching tenant/owner id from a capability frame, checking the known
/// stamp keys at the top level then under `config` (the backend may nest it with the recipe). Returns
/// the first non-null string value; `None` when the frame carries no tenant stamp.
fn frame_tenant_id(msg: &Value) -> Option<String> {
    const KEYS: [&str; 4] = ["owner_tenant_id", "tenant_id", "owner_account_id", "account_id"];
    for key in KEYS {
        if let Some(s) = msg.get(key).and_then(Value::as_str) {
            return Some(s.to_string());
        }
    }
    let config = msg.get("config")?;
    for key in KEYS {
        if let Some(s) = config.get(key).and_then(Value::as_str) {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod supply_gate_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frame_tenant_id_reads_top_level_then_config() {
        assert_eq!(frame_tenant_id(&json!({"tenant_id": "t1"})).as_deref(), Some("t1"));
        assert_eq!(
            frame_tenant_id(&json!({"config": {"owner_tenant_id": "t2"}})).as_deref(),
            Some("t2")
        );
        // Top-level wins over a nested stamp.
        assert_eq!(
            frame_tenant_id(&json!({"owner_tenant_id": "top", "config": {"tenant_id": "nested"}}))
                .as_deref(),
            Some("top")
        );
        // No stamp anywhere ⇒ None (owner's own work).
        assert!(frame_tenant_id(&json!({"config": {"steps": []}})).is_none());
        assert!(frame_tenant_id(&json!({})).is_none());
    }

    /// Open an encrypted in-memory-ish store rooted at a fresh temp dir, seeded with the given owner
    /// account id as the linked tenant (empty ⇒ unlinked).
    async fn store_linked_as(owner: &str) -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::local::config::Paths::at(dir.path().join(".writ"));
        paths.ensure_dirs().unwrap();
        let vault = crate::local::vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = crate::local::db::open(&paths.db(), &vault.db_key_hex()).await.unwrap();
        if !owner.is_empty() {
            LinkState { account_id: owner.into(), ..Default::default() }
                .save(&pool)
                .await
                .unwrap();
        }
        (dir, pool)
    }

    #[tokio::test]
    async fn owner_own_work_is_always_allowed() {
        // A frame stamped with the OWNER's tenant is allowed regardless of the (process-global)
        // supply-pool config — the gate only ever refuses FOREIGN work.
        let (_dir, pool) = store_linked_as("acct_owner").await;
        let frame = json!({"tenant_id": "acct_owner", "config": {"steps": []}});
        assert!(!should_refuse_foreign_tenant(&frame, &pool).await, "owner's own work is allowed");
        // An unstamped frame (no tenant) is treated as the owner's own work.
        let bare = json!({"config": {"steps": []}});
        assert!(!should_refuse_foreign_tenant(&bare, &pool).await, "unstamped ⇒ own work ⇒ allowed");
    }

    #[tokio::test]
    async fn foreign_work_is_refused_when_not_opted_in() {
        // A frame stamped with a DIFFERENT tenant is refused when this device has NOT opted into the
        // shared pool. `should_refuse_foreign_tenant` reads the opt-in from the config under the
        // resolved home (`WRIT_HOME`); point that at an isolated dir with a default (opt-in-off) config
        // so the assertion is deterministic regardless of the developer's real `~/.writ`.
        let _g = crate::local::config::test_env_guard();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("WRIT_HOME", dir.path());
        std::env::remove_var("WRIT_SUPPLY_POOL"); // ensure the env override can't force opt-in on
        let paths = crate::local::config::Paths::resolve().unwrap();
        paths.ensure_dirs().unwrap();
        crate::local::config::write_config(&paths, &crate::local::config::LocalConfig::default())
            .unwrap();

        // Reuse the same home so LinkState + the config-load agree on the store.
        let vault = crate::local::vault::Vault::load_or_create(&paths.root, false).unwrap();
        let pool = crate::local::db::open(&paths.db(), &vault.db_key_hex()).await.unwrap();
        LinkState { account_id: "acct_owner".into(), ..Default::default() }
            .save(&pool)
            .await
            .unwrap();

        let frame = json!({"owner_tenant_id": "acct_stranger", "config": {"steps": []}});
        assert!(
            should_refuse_foreign_tenant(&frame, &pool).await,
            "foreign tenant + opt-in off ⇒ refused"
        );

        // With the SAME frame but opt-in ON, the foreign work is allowed (server still authoritative).
        crate::local::config::set_cloud_agent(&paths, true, true).unwrap();
        assert!(
            !should_refuse_foreign_tenant(&frame, &pool).await,
            "foreign tenant + opt-in on ⇒ allowed (server-authoritative dispatch)"
        );

        std::env::remove_var("WRIT_HOME");
    }
}
