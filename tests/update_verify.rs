//! Auto-update verify/apply state-machine gate (TASK 3.2/3.3, AUTO_UPDATE.md §3).
//!
//! End-to-end proof of the CLIENT verification + apply algorithm: sign a manifest with the
//! deterministic TEST Ed25519 key (whose public half is pinned under the `update-test-keys` feature),
//! then drive [`writ_agent::local::update::evaluate`] and assert:
//!
//!   REJECT for  — tampered payload, downgrade, unknown-kid, wrong-channel, stale/expired manifest,
//!                 sha256-mismatch (the last via the decision's artifact-digest check);
//!   APPLY for   — the happy path (a fresh, in-channel, in-cohort, newer, correctly-signed manifest).
//!
//! This is ADDITIVE (net-new file). It compiles ONLY when `update-test-keys` (⇒ `local`) is enabled,
//! so no test key is ever in a shipped build. The signing helper `test_support::sign_manifest`
//! reproduces `scripts/desktop/sign-update-manifest.sh` exactly (JCS canonicalize `signed` →
//! Ed25519 sign → base64url signature), so a signature that verifies here would verify in production.
//!
//! Run: cargo test --features local,update-test-keys --test update_verify

#![cfg(feature = "update-test-keys")]

use std::collections::BTreeMap;
use writ_agent::local::update::manifest::{Artifact, Manifest, Rollout, Signed};
use writ_agent::local::update::policy::{evaluate, Channel, PolicyInput, UpdateReject};
use writ_agent::local::update::test_support;

/// A known-good artifact whose sha256 is the digest of the fixed payload bytes below.
const PAYLOAD: &[u8] = b"pretend-this-is-the-installer-dmg-bytes";

/// Lowercase-hex SHA-256 of [`PAYLOAD`] (computed at test time so it can never drift).
fn payload_sha256() -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(PAYLOAD);
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a well-formed `signed` payload for the running platform, newer than the installed 1.0.0,
/// stable channel, generous expiry, 100% rollout (no rollout block).
fn good_signed(platform_key: &str) -> Signed {
    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        platform_key.to_string(),
        Artifact {
            url: "https://downloads.writ.example/desktop/stable/1.4.2/app.dmg".into(),
            size_bytes: PAYLOAD.len() as u64,
            sha256: payload_sha256(),
            format: "dmg".into(),
            installer: Some("app.dmg".into()),
        },
    );
    Signed {
        manifest_id: "8f1c0e2a-3b4d-4e5f-9a0b-1c2d3e4f5a6b".into(),
        channel: "stable".into(),
        version: "1.4.2".into(),
        min_supported_version: "1.0.0".into(),
        released_at: "2026-06-28T17:00:00Z".into(),
        manifest_expires_at: "2099-01-01T00:00:00Z".into(),
        notes_url: None,
        changelog: Some("test build".into()),
        security_advisory: false,
        rollout: None,
        chromium_revision: None,
        artifacts,
    }
}

/// The runtime policy input: installed 1.0.0, released 2026-01-01, "now" mid-2026 (before expiry,
/// after both release dates). `platform_key` matches the artifact so the happy path selects it.
fn input<'a>(platform_key: &'a str) -> PolicyInput<'a> {
    PolicyInput {
        channel: Channel::Stable,
        installed_version: "1.0.0",
        installed_build_released_at: Some("2026-01-01T00:00:00Z"),
        install_id: "test-install-id-fixed",
        platform_key,
        now: chrono::DateTime::parse_from_rfc3339("2026-07-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    }
}

/// Sign `signed`, parse, and evaluate against `input` — the common test driver.
fn eval(signed: &Signed, input: &PolicyInput<'_>) -> Result<writ_agent::local::update::policy::UpdateDecision, UpdateReject> {
    let bytes = test_support::sign_manifest(signed);
    let manifest = Manifest::parse(&bytes).expect("parse signed manifest");
    evaluate(&manifest, &bytes, input)
}

// ============================================================================ APPLY (happy path)

#[test]
fn happy_path_applies_and_selects_the_platform_artifact() {
    let plat = current_platform();
    let signed = good_signed(plat);
    let inp = input(plat);
    let decision = eval(&signed, &inp).expect("well-formed newer in-channel manifest must APPLY");
    assert_eq!(decision.version, "1.4.2");
    assert_eq!(decision.released_at, "2026-06-28T17:00:00Z");
    assert_eq!(decision.artifact.format, "dmg");
    // The surfaced sha256 matches the payload, and the byte-check passes for the real bytes.
    assert_eq!(decision.expected_sha256(), payload_sha256());
    assert!(decision.verify_artifact_bytes(PAYLOAD), "correct bytes must pass the sha256 check");
}

// ============================================================================ REJECT: tampered payload

#[test]
fn tampered_payload_is_rejected_bad_signature() {
    let plat = current_platform();
    let signed = good_signed(plat);
    let bytes = test_support::sign_manifest(&signed);

    // Tamper: flip the version INSIDE `signed` after signing, keeping the original signature. The
    // canonical bytes change, so the Ed25519 verify must fail.
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["signed"]["version"] = serde_json::json!("9.9.9");
    let tampered = serde_json::to_vec(&v).unwrap();

    let manifest = Manifest::parse(&tampered).expect("parse (structure still valid)");
    let err = evaluate(&manifest, &tampered, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "bad_signature", "tampered signed payload must REJECT: {err:?}");
    assert!(!err.is_skip(), "a tamper is a hard REJECT, not a SKIP");
}

// ============================================================================ REJECT: unknown kid

#[test]
fn unknown_kid_is_rejected() {
    let plat = current_platform();
    let signed = good_signed(plat);
    // Sign with the pinned test seed but stamp a kid that is NOT in the pinned map.
    let bytes = test_support::sign_manifest_with(&test_support::TEST_SEED, "wtu-not-pinned", &signed);
    let manifest = Manifest::parse(&bytes).expect("parse");
    let err = evaluate(&manifest, &bytes, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "unknown_kid", "unknown kid must REJECT: {err:?}");
}

// ============================================================================ REJECT: wrong signing key

#[test]
fn wrong_signing_key_is_rejected_bad_signature() {
    let plat = current_platform();
    let signed = good_signed(plat);
    // Sign with an UNPINNED private seed but stamp the PINNED kid — the pinned key won't verify it.
    let bytes = test_support::sign_manifest_with(&test_support::WRONG_SEED, test_support::TEST_KID, &signed);
    let manifest = Manifest::parse(&bytes).expect("parse");
    let err = evaluate(&manifest, &bytes, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "bad_signature", "wrong key must REJECT: {err:?}");
}

// ============================================================================ SKIP: wrong channel

#[test]
fn wrong_channel_is_skipped() {
    let plat = current_platform();
    let mut signed = good_signed(plat);
    signed.channel = "beta".into(); // client is Stable
    let err = eval(&signed, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "wrong_channel");
    assert!(err.is_skip(), "a channel mismatch is a SKIP, not a REJECT");
}

// ============================================================================ SKIP: downgrade

#[test]
fn downgrade_is_skipped() {
    let plat = current_platform();
    let mut signed = good_signed(plat);
    signed.version = "0.9.0".into(); // older than installed 1.0.0
    let err = eval(&signed, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "not_newer", "a downgrade must be refused (against the INSTALLED version)");
    assert!(err.is_skip());
}

#[test]
fn equal_version_is_skipped_not_applied() {
    let plat = current_platform();
    let mut signed = good_signed(plat);
    signed.version = "1.0.0".into(); // == installed
    let err = eval(&signed, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "not_newer");
}

// ============================================================================ REJECT: expired

#[test]
fn expired_manifest_is_rejected() {
    let plat = current_platform();
    let mut signed = good_signed(plat);
    signed.manifest_expires_at = "2026-06-30T00:00:00Z".into(); // before now (2026-07-01)
    let err = eval(&signed, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "expired", "a past-expiry manifest must REJECT: {err:?}");
    assert!(!err.is_skip());
}

// ============================================================================ REJECT: stale/replay

#[test]
fn replay_older_than_installed_is_rejected() {
    let plat = current_platform();
    let mut signed = good_signed(plat);
    // released_at BEFORE the installed build's release date (2026-01-01) → a replayed older manifest.
    signed.released_at = "2025-12-01T00:00:00Z".into();
    let err = eval(&signed, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "replay_older_than_installed", "a replayed older manifest must REJECT: {err:?}");
    assert!(!err.is_skip());
}

// ============================================================================ REJECT: sha256 mismatch

#[test]
fn sha256_mismatch_is_detected_by_the_artifact_check() {
    let plat = current_platform();
    let mut signed = good_signed(plat);
    // A correctly-signed manifest whose artifact sha256 does NOT match the real payload bytes. The
    // policy chain APPLIES (the digest is checked by the downloader AFTER fetch, per §3 step 10), then
    // the downloader's byte-check — surfaced here via `verify_artifact_bytes` — must REJECT the bytes.
    let wrong_digest = "0000000000000000000000000000000000000000000000000000000000000000";
    signed.artifacts.get_mut(plat).unwrap().sha256 = wrong_digest.into();
    let decision = eval(&signed, &input(plat)).expect("policy applies; sha256 is a post-download check");
    assert_eq!(decision.expected_sha256(), wrong_digest);
    assert!(
        !decision.verify_artifact_bytes(PAYLOAD),
        "bytes that don't match the manifest sha256 MUST fail the pre-apply integrity check"
    );
}

// ============================================================================ SKIP: forward gate + rollout + platform

#[test]
fn below_min_supported_is_skipped_forward_gate() {
    let plat = current_platform();
    let mut signed = good_signed(plat);
    signed.min_supported_version = "1.3.0".into(); // installed 1.0.0 < floor → apply the floor first
    let err = eval(&signed, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "below_min_supported");
    assert!(err.is_skip());
}

#[test]
fn out_of_rollout_cohort_is_skipped_but_security_advisory_bypasses() {
    let plat = current_platform();

    // A 0% rollout puts EVERY client out of the cohort (bucket is always >= 0 is false; >= 0 percent
    // means no one qualifies since bucket < percentage is required and bucket>=0 always).
    let mut signed = good_signed(plat);
    signed.rollout = Some(Rollout { percentage: 0, cohort_seed: "seed".into() });
    let err = eval(&signed, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "not_in_rollout", "0% rollout excludes everyone");
    assert!(err.is_skip());

    // A security advisory bypasses the rollout gate entirely and applies.
    let mut adv = good_signed(plat);
    adv.rollout = Some(Rollout { percentage: 0, cohort_seed: "seed".into() });
    adv.security_advisory = true;
    let decision = eval(&adv, &input(plat)).expect("security advisory bypasses rollout");
    assert_eq!(decision.version, "1.4.2");
}

#[test]
fn missing_artifact_for_platform_is_skipped() {
    let plat = current_platform();
    // Build the manifest for a DIFFERENT platform key, then evaluate as the current platform.
    let other = if plat == "macos-aarch64" { "windows-x86_64" } else { "macos-aarch64" };
    let signed = good_signed(other);
    let err = eval(&signed, &input(plat)).unwrap_err();
    assert_eq!(err.code(), "no_artifact_for_platform");
    assert!(err.is_skip());
}

// ============================================================================ helpers

/// The running platform key, or a fixed fallback so the test is deterministic on unusual targets
/// (the test builds the manifest for THIS key, so an empty/unknown key would otherwise never match).
fn current_platform() -> &'static str {
    let k = writ_agent::local::update::policy::current_platform_key();
    if k.is_empty() {
        "linux-x86_64"
    } else {
        k
    }
}
