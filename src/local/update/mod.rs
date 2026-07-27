//! Desktop auto-update — manifest verify/apply state machine (AUTO_UPDATE.md, PROD-6/7/8).
//!
//! This module is the Rust client half of the signed auto-update contract in
//! [`docs/desktop/AUTO_UPDATE.md`]. It implements ONLY the offline-safe, cryptographic decision
//! layer — "given a fetched manifest and the running app, is this update trustworthy, applicable,
//! and in-cohort, and which artifact do I fetch + sha256-check?" — plus the post-update self-check /
//! rollback bookkeeping. It does NOT download bytes, drive the OS installer, or read MDM policy
//! files: those are the Tauri-updater / `writ-agent update --from` wiring tracked separately (§8).
//!
//! Layout (each file owns one concern; nothing here touches the network):
//!   * [`manifest`] — the wire schema (`schema_version`/`kid`/`signature`/`signed`), RFC 8785 JCS
//!     canonicalization of `signed` (byte-identical to the signing script's `jq -Scj`), and the
//!     pinned-`kid` Ed25519 detached-signature verify.
//!   * [`policy`] — the normative §3 gate chain, IN ORDER: schema → kid → signature → channel →
//!     expiry/staleness → downgrade → min-supported → rollout-bucket → artifact-select → (sha256 is
//!     verified by the caller after download, but the expected digest is surfaced here).
//!   * [`version_record`] — the monotonic installed/prior version + release-date + health-fail
//!     counter, persisted in the SQLCipher DB (`app_meta`). This is the downgrade anchor (§3 step 6)
//!     and the rollback source of truth.
//!   * [`rollback`] — post-update self-check (reuses the daemon health probe + `PRAGMA cipher_version`
//!     + a DB open) and the auto-rollback-after-N-consecutive-fails decision.
//!
//! SECURITY invariants (AUTO_UPDATE.md §1): the verification key is COMPILED IN + `kid`-indexed
//! (never fetched); the algorithm is FIXED to Ed25519 in code (there is no trusted `alg` field);
//! downgrade is refused against the DB-recorded installed version (not the manifest's self-claim);
//! every artifact is sha256-checked before apply; rollout bucketing is a pure local hash (air-gapped
//! safe). No secret material is ever logged.

pub mod manifest;
pub mod policy;
pub mod rollback;
pub mod version_record;

/// Test-only signing helpers + the deterministic test keypair whose PUBLIC half is pinned in
/// [`manifest`] under the same cfg. Public so `tests/update_verify.rs` (which enables the
/// `update-test-keys` feature) can mint signed manifests; compiled OUT of every shipped build.
#[cfg(any(test, feature = "update-test-keys"))]
pub mod test_support;

pub use manifest::{Artifact, Manifest, ManifestError, Signed, SCHEMA_VERSION};
pub use policy::{current_platform_key, evaluate, Channel, PolicyInput, UpdateDecision, UpdateReject};
pub use rollback::{
    post_update_self_check, run_post_update_gate, RollbackAction, SelfCheckReport,
    HEALTH_FAIL_ROLLBACK_THRESHOLD,
};
pub use version_record::VersionRecord;
