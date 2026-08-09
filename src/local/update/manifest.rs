//! Auto-update manifest — wire schema, JCS canonicalization, and pinned-`kid` Ed25519 verify.
//!
//! The manifest is a JSON object with exactly four top-level fields (AUTO_UPDATE.md §2):
//! `schema_version`, `kid`, `signature`, and `signed`. ONLY `signed` is covered by the signature.
//! The signature is a detached (raw, one-shot) Ed25519 signature over the **RFC 8785 JCS**
//! canonical bytes of the `signed` object — the same bytes `scripts/desktop/sign-update-manifest.sh`
//! produces with `jq -Scj .signed`. This module's [`canonicalize_signed`] MUST be byte-identical to
//! that, or every real manifest fails verification.
//!
//! ## Trust model (mirrors the CLOUD-6 entitlement key map — SECURITY §2.3, a SEPARATE key set)
//! The Ed25519 verification key(s) are COMPILED IN as a `kid`-indexed table ([`PINNED_KEYS`]) and
//! never fetched. The manifest's `kid` selects the key; an unknown `kid` is rejected before the
//! signature is even checked. The algorithm is FIXED to Ed25519 in code — there is no `alg` field
//! the client trusts (avoids the classic "alg: none" downgrade). Ship at least two keys at all times
//! (current + next) for zero-downtime rotation.
//!
//! ## What this module does NOT do
//! It does not apply the §3 policy gates (channel/expiry/downgrade/rollout/artifact) — that is
//! [`super::policy`] — and it does not touch the network. It parses, canonicalizes, and verifies the
//! signature; a caller with a verified manifest then runs the policy chain.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The only manifest `schema_version` this build understands. A manifest carrying any other value is
/// rejected (AUTO_UPDATE.md §3 step 1) — forward format evolution ships a new supported version here.
pub const SCHEMA_VERSION: u32 = 1;

// ============================================================================ pinned keys

/// A `kid` → compiled-in Ed25519 **public** verification key (raw 32-byte EdDSA public key, hex).
///
/// Trust is pinned to these keys: the manifest's `kid` MUST match one of these or verification is
/// rejected (AUTO_UPDATE.md §1.1). The raw 32-byte form matches the signing script's
/// `openssl pkey ... -pubout -outform DER | tail -c 32 | xxd -p` output — the last 32 bytes of the
/// Ed25519 SPKI DER are the raw public key.
struct PinnedKey {
    kid: &'static str,
    /// Lowercase hex of the raw 32-byte Ed25519 public key.
    pubkey_hex: &'static str,
}

/// Pinned update-verification keys — the raw-32-byte-hex PUBLIC halves of the real Ed25519
/// update-signing keypairs. The PRIVATE halves live ONLY in the release secret store (GitHub Actions
/// secret `WRIT_UPDATE_SIGNING_KEY_B64`); this binary carries nothing but the public keys.
///
/// This is the updater's OWN key set — a different trust domain from the CLOUD-6 entitlement key map.
///
/// N / N+1 rotation (AUTO_UPDATE.md §1.3): `wtu-2026-1` signs today; `wtu-2026-2` is trusted but not
/// yet signing, so rotating to it never bricks an installed build. When `-1` is retired, start signing
/// with `-2` and add a `-3` row — never remove a row the field still depends on.
///
/// These rows MUST stay byte-identical to the SPKI constants in the Tauri shell's
/// `src/updater/keys.rs` (each hex below is the last 32 bytes of the corresponding SPKI DER). The two
/// are the same trust decision made in two processes; a divergence means one approves a manifest the
/// other rejects.
const PINNED_KEYS: &[PinnedKey] = &[
    PinnedKey {
        kid: "wtu-2026-1",
        pubkey_hex: "4cc68c37093d0c5fe64e3f8558c7cb7758caf43a7cdb76ff7067c237b58cd75d",
    },
    PinnedKey {
        kid: "wtu-2026-2",
        pubkey_hex: "1d6e66be1c1545c8de0daa4d54f5f19209a42fcfb599efc85e7a31e062e9737f",
    },
];

/// A test-only pinned key. Its private half is the deterministic seed in [`super::test_support`].
/// Gated behind `#[cfg(any(test, feature = "update-test-keys"))]` so it is consulted by in-crate
/// unit tests AND by the `tests/update_verify.rs` integration test (which enables `update-test-keys`)
/// but is COMPILED OUT of every shipped build — `update-test-keys` is never in a release feature set.
#[cfg(any(test, feature = "update-test-keys"))]
const TEST_PINNED_KEYS: &[PinnedKey] = &[PinnedKey {
    kid: super::test_support::TEST_KID,
    pubkey_hex: super::test_support::TEST_PUBKEY_HEX,
}];

/// PRODUCTION BUILD GUARD (AUTO_UPDATE.md §1 / PROD-6). Returns `Err(reason)` when the SHIPPED pinned
/// key set is not fit for release — i.e. the real-key `PINNED_KEYS` table is EMPTY. Every shipped
/// build MUST pin at least the active + next real keys; until the release owner provisions them the
/// table is empty ON PURPOSE and the updater fails closed (every manifest is `unknown_kid`). The
/// release pipeline calls this (see `scripts/desktop/check-updater-keys.sh` +
/// `production_guard_flags_empty_pinned_keys`) so a build that forgot to add keys cannot ship an
/// updater that would silently reject every legitimate update.
///
/// NOTE: the test key table is deliberately EXCLUDED — this checks only the real shipped `PINNED_KEYS`.
pub fn pinned_keys_production_ready() -> Result<(), String> {
    if PINNED_KEYS.is_empty() {
        return Err(
            "daemon update PINNED_KEYS is EMPTY — provision real Ed25519 update keys before release".into(),
        );
    }
    // Every pinned row must be a valid Ed25519 public key.
    for k in PINNED_KEYS {
        if verifying_key_from_hex(k.pubkey_hex).is_none() {
            return Err(format!("pinned update key {:?} is not a valid Ed25519 public key", k.kid));
        }
    }
    Ok(())
}

/// Look up a pinned verification key by `kid`. `None` ⇒ unknown `kid` ⇒ reject. Under test (or the
/// `update-test-keys` feature) the test table is ALSO consulted — never in a shipped build.
fn pinned_pubkey(kid: &str) -> Option<&'static str> {
    if let Some(k) = PINNED_KEYS.iter().find(|k| k.kid == kid) {
        return Some(k.pubkey_hex);
    }
    #[cfg(any(test, feature = "update-test-keys"))]
    if let Some(k) = TEST_PINNED_KEYS.iter().find(|k| k.kid == kid) {
        return Some(k.pubkey_hex);
    }
    None
}

// ============================================================================ schema

/// The full auto-update manifest (AUTO_UPDATE.md §2). Only [`Manifest::signed`] is signature-covered.
///
/// `signed` is captured BOTH as the typed [`Signed`] and (via a second deserialize of the raw bytes)
/// as a `serde_json::Value` at verify time, so the canonicalization is computed from the on-wire JSON
/// — never from a re-serialization of the typed struct, which could drop or reorder fields.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    /// Format version. Unknown ⇒ reject (not signed).
    pub schema_version: u32,
    /// Key id selecting the pinned verification key. Unknown ⇒ reject (not signed).
    pub kid: String,
    /// base64url (unpadded) Ed25519 signature over the canonical bytes of `signed` (it IS the sig,
    /// so it is not itself signed).
    pub signature: String,
    /// The signed payload — everything trusted lives here.
    pub signed: Signed,
}

/// The signed payload (AUTO_UPDATE.md §2.1). `#[serde(default)]` on the optional fields so a sparse
/// manifest loads forward; `deny_unknown_fields` is intentionally NOT set (a newer manifest may carry
/// fields an older client ignores — but note the SIGNATURE still covers those bytes, so an older
/// client canonicalizes them faithfully via the raw-Value path even if it doesn't model them).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Signed {
    /// Unique per manifest (uuid) — logging/audit + replay dedup.
    pub manifest_id: String,
    /// `stable` | `beta` | `managed`. Must match the client channel to apply.
    pub channel: String,
    /// The release version (semver). Monotonic — must be `>` installed to apply.
    pub version: String,
    /// Client must be `>=` this to apply this manifest directly (forward gate).
    pub min_supported_version: String,
    /// RFC3339 UTC signed release timestamp. Staleness/replay anchor.
    pub released_at: String,
    /// RFC3339 UTC hard expiry; client rejects after this instant.
    pub manifest_expires_at: String,
    /// Human release notes (display only).
    #[serde(default)]
    pub notes_url: Option<String>,
    /// Short inline summary (display only).
    #[serde(default)]
    pub changelog: Option<String>,
    /// If true, surface more prominently and (per policy) bypass the rollout gate.
    #[serde(default)]
    pub security_advisory: bool,
    /// Staged-rollout descriptor. Absent ⇒ 100%.
    #[serde(default)]
    pub rollout: Option<Rollout>,
    /// Bundled Chromium/patchright revision (informational + SBOM cross-ref).
    #[serde(default)]
    pub chromium_revision: Option<String>,
    /// `platform-key → artifact`. Must contain the running platform's key to be applicable.
    pub artifacts: BTreeMap<String, Artifact>,
}

/// Staged-rollout descriptor (AUTO_UPDATE.md §2.1). Bucketing is computed CLIENT-SIDE from a stable
/// install-id hash against `percentage` + `cohort_seed` — no server call (offline-safe).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rollout {
    /// 0..=100. A client whose local bucket is `>=` this is not yet in the cohort.
    pub percentage: u32,
    /// Seed mixed into the install-id hash so successive releases shuffle the cohort ordering.
    pub cohort_seed: String,
}

/// A per-platform downloadable artifact (AUTO_UPDATE.md §2.3).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Artifact {
    /// Download URL (overridable by a managed feed base — not handled here).
    pub url: String,
    /// Expected size; the downloader aborts if the bytes exceed this (DoS guard).
    pub size_bytes: u64,
    /// Lowercase hex SHA-256 of the artifact bytes. Verified before apply.
    pub sha256: String,
    /// `dmg` | `msi` | `appimage` | `pkg` | `nsis`.
    pub format: String,
    /// Bare filename (for offline `update --from` matching).
    #[serde(default)]
    pub installer: Option<String>,
}

// ============================================================================ errors

/// Why a manifest could not be parsed or its signature verified. These are the CRYPTO/STRUCTURE
/// rejects (schema/kid/signature) — the applicability SKIP/REJECTs (channel/expiry/downgrade/…) live
/// in [`super::policy::UpdateReject`], which wraps these for the schema/kid/signature steps.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    /// Top-level JSON did not parse into the manifest shape.
    #[error("update manifest is malformed: {0}")]
    Malformed(String),
    /// `schema_version` is not one this build understands (AUTO_UPDATE.md §3 step 1).
    #[error("update manifest schema_version {found} is unsupported (this build supports {supported})")]
    UnsupportedSchema { found: u32, supported: u32 },
    /// The `kid` matches no compiled-in pinned key (AUTO_UPDATE.md §3 step 2).
    #[error("update manifest signed by an unknown kid {0:?} (not in the pinned key map)")]
    UnknownKid(String),
    /// A pinned key exists for the `kid` but its bytes are not a valid Ed25519 public key. This is a
    /// BUILD error (a bad compiled-in constant), not attacker input — surfaced distinctly.
    #[error("pinned update key {0:?} is not a valid Ed25519 public key (build misconfiguration)")]
    BadPinnedKey(String),
    /// The base64url `signature` is not decodable to a 64-byte Ed25519 signature.
    #[error("update manifest signature is malformed")]
    MalformedSignature,
    /// The signature did not verify against the pinned key over the canonical `signed` bytes
    /// (tampered payload or wrong key). AUTO_UPDATE.md §3 step 3.
    #[error("update manifest signature verification failed (tampered payload or wrong key)")]
    BadSignature,
}

// ============================================================================ parse + verify

impl Manifest {
    /// Parse the manifest JSON WITHOUT verifying anything. The result is untrusted until
    /// [`Manifest::verify_signature`] passes; callers should treat the fields as attacker-controlled.
    pub fn parse(bytes: &[u8]) -> Result<Self, ManifestError> {
        serde_json::from_slice::<Manifest>(bytes).map_err(|e| ManifestError::Malformed(e.to_string()))
    }

    /// Run steps 1–3 of AUTO_UPDATE.md §3 IN ORDER against the ORIGINAL bytes:
    ///   1. schema_version supported,
    ///   2. `kid` resolves to a compiled-in pinned key,
    ///   3. Ed25519 signature verifies over the JCS-canonical bytes of `signed`.
    ///
    /// The canonical bytes are recomputed from the RAW on-wire `signed` object (re-parsed from
    /// `bytes` as a `serde_json::Value`), NOT from a re-serialization of the typed [`Signed`] — so a
    /// field this build doesn't model is still faithfully canonicalized and thus signature-covered.
    /// Returns `()` on success; the caller already holds the parsed `self`.
    pub fn verify_signature(&self, bytes: &[u8]) -> Result<(), ManifestError> {
        // Step 1 — schema.
        if self.schema_version != SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedSchema {
                found: self.schema_version,
                supported: SCHEMA_VERSION,
            });
        }
        // Step 2 — pinned kid (before touching the signature).
        let pubkey_hex = pinned_pubkey(&self.kid).ok_or_else(|| ManifestError::UnknownKid(self.kid.clone()))?;
        let verifying_key = verifying_key_from_hex(pubkey_hex)
            .ok_or_else(|| ManifestError::BadPinnedKey(self.kid.clone()))?;

        // Recompute the canonical bytes from the raw wire `signed` (never the typed struct).
        let raw: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|e| ManifestError::Malformed(e.to_string()))?;
        let signed = raw
            .get("signed")
            .ok_or_else(|| ManifestError::Malformed("manifest has no top-level \"signed\" object".into()))?;
        let canonical = canonicalize_value(signed);

        // Step 3 — signature (algorithm fixed to Ed25519 in code).
        let sig = decode_signature(&self.signature).ok_or(ManifestError::MalformedSignature)?;
        use ed25519_dalek::Verifier;
        verifying_key
            .verify(canonical.as_bytes(), &sig)
            .map_err(|_| ManifestError::BadSignature)
    }
}

/// Build an `ed25519_dalek::VerifyingKey` from a 64-char (32-byte) lowercase-hex public key.
/// `None` on a malformed hex string or a non-canonical key point.
fn verifying_key_from_hex(hex: &str) -> Option<ed25519_dalek::VerifyingKey> {
    let bytes = decode_hex_32(hex)?;
    ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
}

/// Decode a 64-char lowercase-hex string into a `[u8; 32]`. `None` on any non-hex char or wrong len.
fn decode_hex_32(hex: &str) -> Option<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for (i, chunk) in bytes.chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// Decode the manifest's base64url (unpadded, per the signing script's `b64url`) `signature` into a
/// 64-byte Ed25519 signature. Tolerant of padding if a re-padded variant is ever supplied.
fn decode_signature(sig_b64url: &str) -> Option<ed25519_dalek::Signature> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sig_b64url.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(sig_b64url.trim()))
        .ok()?;
    let arr: [u8; 64] = raw.try_into().ok()?;
    Some(ed25519_dalek::Signature::from_bytes(&arr))
}

// ============================================================================ JCS canonicalization

/// RFC 8785 (JCS) canonicalization of the `signed` object, byte-identical to the signing script's
/// `jq -Scj .signed`: keys sorted lexicographically at every level, compact separators (`,`/`:`), no
/// insignificant whitespace, no trailing newline, integers emitted without a decimal point.
///
/// Public so the tests (and any offline `update --from` verifier) can assert the exact bytes.
pub fn canonicalize_signed(signed: &Signed) -> Result<String, ManifestError> {
    let v = serde_json::to_value(signed).map_err(|e| ManifestError::Malformed(e.to_string()))?;
    Ok(canonicalize_value(&v))
}

/// Recursively emit the JCS canonical form of a `serde_json::Value`.
///
/// The manifest only ever contains strings, integers, bools, null, arrays, and objects — no
/// floating-point numbers — so the JCS number rule reduces to "print the integer with no decimal
/// point and no exponent", which is exactly `serde_json`'s integer formatting. Object keys are sorted
/// by their UTF-16 code units per RFC 8785; for the ASCII keys in this schema that is identical to a
/// byte/`str` ordering, which is what `BTreeMap<String, _>` and `str::cmp` give us. Strings are
/// emitted with `serde_json`'s string escaping (RFC 8785 mandates the same minimal `\uXXXX`/`\"`/`\\`
/// escaping that `serde_json` produces).
fn canonicalize_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => encode_json_string(s),
        serde_json::Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&canonicalize_value(item));
            }
            out.push(']');
            out
        }
        serde_json::Value::Object(map) => {
            // Sort keys lexicographically (UTF-16 code units per RFC 8785). `serde_json::Map` iterates
            // insertion order by default, so collect + sort explicitly.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| jcs_key_cmp(a, b));
            let mut out = String::from("{");
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&encode_json_string(k));
                out.push(':');
                out.push_str(&canonicalize_value(&map[*k]));
            }
            out.push('}');
            out
        }
    }
}

/// Compare two object keys by UTF-16 code units (RFC 8785 §3.2.3). For the all-ASCII keys in the
/// manifest schema this is identical to `str::cmp`, but we implement the code-unit rule faithfully so
/// a future non-ASCII key still canonicalizes byte-identically to a JCS signer.
fn jcs_key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Serialize a Rust string as a JSON string literal with JCS/`serde_json`-compatible escaping. We
/// delegate to `serde_json` so the escape set (`\"`, `\\`, `\n`, `\uXXXX` for control chars, etc.)
/// matches exactly what the `jq`-based signer emits.
fn encode_json_string(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signer emits `jq -Scj .signed`. Our canonicalizer must produce the SAME bytes for a nested
    /// object with keys deliberately out of order and mixed value types.
    #[test]
    fn canonicalize_matches_jcs_sort_and_compact() {
        let v = serde_json::json!({
            "b": 1,
            "a": {
                "z": [3, 2, 1],
                "y": "hi",
                "x": true
            },
            "c": "str"
        });
        // Keys sorted at every level, compact separators, integers with no decimal, no whitespace.
        let expected = r#"{"a":{"x":true,"y":"hi","z":[3,2,1]},"b":1,"c":"str"}"#;
        assert_eq!(canonicalize_value(&v), expected);
    }

    /// Integers must not gain a decimal point (`1`, not `1.0`) and strings must be minimally escaped.
    #[test]
    fn canonicalize_integer_and_string_forms() {
        let v = serde_json::json!({ "n": 192847362u64, "s": "a\"b\\c", "neg": -5 });
        assert_eq!(canonicalize_value(&v), r#"{"n":192847362,"neg":-5,"s":"a\"b\\c"}"#);
    }

    #[test]
    fn unknown_kid_has_no_pinned_key() {
        assert!(pinned_pubkey("definitely-not-a-real-kid").is_none());
    }

    /// PRODUCTION BUILD GUARD: real keys are provisioned, so `pinned_keys_production_ready()` MUST
    /// report the build as shippable. This is the gate the release pipeline / CI check relies on; it
    /// asserted `is_err()` while the table was still empty.
    #[test]
    fn production_guard_accepts_provisioned_pinned_keys() {
        assert!(!PINNED_KEYS.is_empty(), "the shipped pinned-key table must not be empty");
        let verdict = pinned_keys_production_ready();
        assert!(verdict.is_ok(), "provisioned pinned keys must pass the guard; got {verdict:?}");
    }

    /// The N / N+1 rotation invariant (§1.3): BOTH the active and next kids must resolve. Shipping
    /// only the active key means the first rotation strands every installed build on a manifest it
    /// cannot verify — a failure that surfaces only at the next release, on users' machines.
    #[test]
    fn active_and_next_kids_are_both_pinned() {
        for kid in ["wtu-2026-1", "wtu-2026-2"] {
            let hex = pinned_pubkey(kid).unwrap_or_else(|| panic!("{kid} must be pinned"));
            assert_eq!(hex.len(), 64, "{kid} pubkey must be 32 raw bytes as hex");
            assert!(
                verifying_key_from_hex(hex).is_some(),
                "{kid} must decode to a valid Ed25519 public key"
            );
        }
    }

    /// The shell (`src/updater/keys.rs`) pins the SAME keys as base64 SPKI DER. The last 32 bytes of
    /// an Ed25519 SPKI DER are the raw public key, so each shell constant must end with the daemon's
    /// hex row. Asserting it here is what keeps the two processes from drifting into a state where the
    /// shell downloads an update the daemon then refuses to approve.
    #[test]
    fn daemon_rows_match_the_shell_spki_constants() {
        // (kid, base64 SPKI DER as pinned in frontend-desktop/src-tauri/src/updater/keys.rs)
        const SHELL_SPKI_B64: &[(&str, &str)] = &[
            ("wtu-2026-1", "MCowBQYDK2VwAyEATMaMNwk9DF/mTj+FWMfLd1jK9Dp823b/cGfCN7WM110="),
            ("wtu-2026-2", "MCowBQYDK2VwAyEAHW5mvhwVRcjeDapNVPXxkgmkL8+1me/IXnox4GLpc38="),
        ];
        use base64::Engine as _;
        for (kid, spki_b64) in SHELL_SPKI_B64 {
            let der = base64::engine::general_purpose::STANDARD
                .decode(spki_b64)
                .unwrap_or_else(|e| panic!("{kid} shell SPKI is not valid base64: {e}"));
            assert!(der.len() >= 32, "{kid} shell SPKI is too short to hold a key");
            let from_shell = &der[der.len() - 32..];

            let expected_hex = pinned_pubkey(kid).unwrap_or_else(|| panic!("{kid} must be pinned"));
            let from_daemon = decode_hex_32(expected_hex)
                .unwrap_or_else(|| panic!("{kid} daemon row is not 32 bytes of hex"));

            assert_eq!(
                from_shell,
                &from_daemon[..],
                "{kid}: the shell's SPKI constant and the daemon's pinned hex are different keys"
            );
        }
    }
}
