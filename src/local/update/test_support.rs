//! Test-only manifest signing — the deterministic Ed25519 test keypair (its public half is pinned in
//! [`super::manifest`] under the same cfg) plus a [`sign_manifest`] helper that reproduces exactly
//! what `scripts/desktop/sign-update-manifest.sh` does: canonicalize `signed` (JCS), Ed25519-sign the
//! canonical bytes, and stamp `kid` + base64url(unpadded) `signature`.
//!
//! This is compiled ONLY under `#[cfg(any(test, feature = "update-test-keys"))]` — it is NEVER in a
//! shipped feature set, so no test key ever reaches production and no signing capability ships.

use super::manifest::{canonicalize_signed, Manifest, Signed};

/// The `kid` stamped by [`sign_manifest`] and pinned (test-only) in `manifest.rs`.
pub const TEST_KID: &str = "wtu-test-2026";

/// Raw 32-byte Ed25519 PRIVATE seed (deterministic: bytes `01..=20`). The matching public key is
/// [`TEST_PUBKEY_HEX`]. Test-only; deliberately fixed so signatures are reproducible.
pub const TEST_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Raw 32-byte Ed25519 PUBLIC key (hex) derived from [`TEST_SEED`] via RFC 8032. Pinned in
/// `manifest.rs`'s test key table so a manifest signed by [`sign_manifest`] verifies.
pub const TEST_PUBKEY_HEX: &str =
    "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";

/// A SECOND, UNPINNED Ed25519 seed — used to forge a wrong-key signature (the wrong-key reject test).
pub const WRONG_SEED: [u8; 32] = [
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
    0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
];

/// Sign a `signed` payload with the given raw seed under `kid`, returning the full manifest JSON
/// bytes (schema_version 1 + kid + base64url signature + the pretty-serialized `signed`). Reproduces
/// the signing script: the signature covers the JCS-canonical bytes of `signed`, and the emitted
/// `signed` bytes are the caller's `serde_json` serialization (the verifier re-canonicalizes from the
/// raw wire, so the emitted formatting is irrelevant to verification).
pub fn sign_manifest_with(seed: &[u8; 32], kid: &str, signed: &Signed) -> Vec<u8> {
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    let canonical = canonicalize_signed(signed).expect("canonicalize test signed payload");
    let sk = SigningKey::from_bytes(seed);
    let sig = sk.sign(canonical.as_bytes());
    let sig_b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig.to_bytes());

    let manifest = serde_json::json!({
        "schema_version": super::manifest::SCHEMA_VERSION,
        "kid": kid,
        "signature": sig_b64url,
        "signed": signed,
    });
    serde_json::to_vec(&manifest).expect("serialize test manifest")
}

/// Convenience: sign with the PINNED test seed + kid (the happy path).
pub fn sign_manifest(signed: &Signed) -> Vec<u8> {
    sign_manifest_with(&TEST_SEED, TEST_KID, signed)
}

/// Parse a manifest that [`sign_manifest`] produced (for tests that then run the policy chain).
pub fn parse(bytes: &[u8]) -> Manifest {
    Manifest::parse(bytes).expect("parse test manifest")
}
