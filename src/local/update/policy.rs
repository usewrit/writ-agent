//! Update policy — the normative AUTO_UPDATE.md §3 verify/apply gate chain, IN ORDER.
//!
//! [`evaluate`] takes a parsed [`Manifest`], the ORIGINAL manifest bytes (needed to re-canonicalize
//! `signed` for the signature check), and the runtime [`PolicyInput`] (the client's channel, the
//! recorded installed version + its release date, and a stable install-id for rollout bucketing), and
//! runs the gates in the exact §3 order:
//!
//! ```text
//!   1. schema_version supported            ┐
//!   2. kid resolves to a pinned key        ├─ manifest.rs (verify_signature): REJECT
//!   3. Ed25519 signature verifies          ┘
//!   4. channel matches                     → SKIP (wrong-channel)
//!   5. expiry / staleness                  → REJECT (expired) / REJECT (replay: older than installed)
//!   6. downgrade gate (version <= installed)→ SKIP (not newer)
//!   7. forward gate (installed < min_supported) → SKIP (needs the floor version first)
//!   8. rollout bucket (unless security_advisory) → SKIP (not in cohort yet)  [offline-safe]
//!   9. artifact select (current platform)  → SKIP (no artifact for this platform)
//!  10. sha256 is verified by the DOWNLOADER after fetch; the expected digest is surfaced here.
//! ```
//!
//! A `SKIP` is a normal not-applicable outcome (the app silently stays put + surfaces a passive
//! "update available/none" state); a `REJECT` is an integrity/trust failure that is logged loudly.
//! Both distinctions and their reason codes match §3. This function is PURE and offline — no network,
//! no clock except the injected `now`, no filesystem.

use super::manifest::{Artifact, Manifest, ManifestError};
use sha2::{Digest, Sha256};

/// The client's update channel (AUTO_UPDATE.md §2.1 / §6). A client only applies a manifest whose
/// `channel` equals its own — it never implicitly widens (a `stable` client never auto-pulls `beta`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Stable,
    Beta,
    Managed,
}

impl Channel {
    /// The wire string form (matches the manifest's `channel` enum).
    pub fn as_str(self) -> &'static str {
        match self {
            Channel::Stable => "stable",
            Channel::Beta => "beta",
            Channel::Managed => "managed",
        }
    }

    /// Parse a channel string; unknown values are treated as `None` (the caller decides — an unknown
    /// configured channel means nothing matches, which fails closed).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "stable" => Some(Channel::Stable),
            "beta" => Some(Channel::Beta),
            "managed" => Some(Channel::Managed),
            _ => None,
        }
    }
}

/// Runtime inputs to the policy chain. All offline-derived: no field requires a network call.
#[derive(Debug, Clone)]
pub struct PolicyInput<'a> {
    /// The client's configured/managed channel. A manifest on a different channel is SKIPPED.
    pub channel: Channel,
    /// The MONOTONIC installed version, read from the `app_meta` version record (NOT the manifest's
    /// self-claim). The downgrade anchor (§3 step 6).
    pub installed_version: &'a str,
    /// RFC3339 UTC release date of the installed build (the version record's
    /// `installed_build_released_at`), if known. Used for the replay/staleness gate (§3 step 5): a
    /// manifest whose `released_at` predates this is a replayed-older manifest and is REJECTED. When
    /// `None` (never stamped), the replay-vs-installed check is skipped (the expiry check still runs).
    pub installed_build_released_at: Option<&'a str>,
    /// A STABLE per-install identifier (e.g. a random id minted once and persisted). Mixed with the
    /// rollout `cohort_seed` to compute the local rollout bucket. Must be stable across runs so a
    /// client's cohort membership doesn't flap.
    pub install_id: &'a str,
    /// The platform key of the running build (`macos-aarch64`, `windows-x86_64`, …). Usually
    /// [`current_platform_key`]; injectable for tests/cross-checks.
    pub platform_key: &'a str,
    /// "Now", injected so the expiry/staleness gate is deterministic + testable.
    pub now: chrono::DateTime<chrono::Utc>,
}

/// The APPLY decision: the manifest passed every gate and this artifact should be downloaded and
/// (after its sha256 verifies against [`expected_sha256`]) handed to the OS updater.
///
/// [`expected_sha256`]: UpdateDecision::expected_sha256
#[derive(Debug, Clone)]
pub struct UpdateDecision {
    /// The version being applied (the manifest's `signed.version`).
    pub version: String,
    /// The signed release timestamp (RFC3339) — recorded as the new build's release date on success.
    pub released_at: String,
    /// The selected per-platform artifact (url/size/sha256/format/installer).
    pub artifact: Artifact,
}

impl UpdateDecision {
    /// The expected lowercase-hex SHA-256 the downloader must match the fetched bytes against BEFORE
    /// applying (AUTO_UPDATE.md §3 step 10). A mismatch is a tamper REJECT.
    pub fn expected_sha256(&self) -> &str {
        &self.artifact.sha256
    }

    /// Convenience for the downloader: does `bytes` match the expected sha256? (The download path
    /// normally streams + hashes, but this covers the buffered/offline `update --from` case.)
    pub fn verify_artifact_bytes(&self, bytes: &[u8]) -> bool {
        let digest = Sha256::digest(bytes);
        let got = hex_lower(&digest);
        // Constant-time-ish compare is unnecessary here (public digest), a plain eq is fine.
        got.eq_ignore_ascii_case(self.artifact.sha256.trim())
    }
}

/// Every not-applicable / rejected outcome of the policy chain, with a stable reason code matching
/// AUTO_UPDATE.md §3. `Skip*` are normal "stay put" outcomes; `Reject*` are integrity/trust failures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UpdateReject {
    // ---- steps 1–3: crypto/structure (wraps manifest.rs). REJECT. ----
    #[error("update rejected (signature/kid/schema): {0}")]
    Signature(#[from] ManifestError),

    // ---- step 4: channel. SKIP. ----
    #[error("update skipped: manifest channel {manifest:?} != client channel {client:?}")]
    WrongChannel { manifest: String, client: String },

    // ---- step 5: expiry / staleness. REJECT. ----
    #[error("update rejected: manifest expired (expires_at {0})")]
    Expired(String),
    #[error("update rejected: manifest released_at {0} predates the installed build (replay/older)")]
    ReplayOlderThanInstalled(String),
    #[error("update rejected: manifest timestamp is unparseable ({0})")]
    BadTimestamp(String),

    // ---- step 6: downgrade. SKIP. ----
    #[error("update skipped: version {version} is not newer than installed {installed}")]
    NotNewer { version: String, installed: String },

    // ---- step 7: forward gate. SKIP (must apply the floor version first). ----
    #[error("update skipped: installed {installed} < min_supported_version {min_supported} (apply the floor version first)")]
    BelowMinSupported { installed: String, min_supported: String },

    // ---- semver parse failures on the manifest's own version fields. REJECT. ----
    #[error("update rejected: unparseable semver in manifest ({0})")]
    BadVersion(String),

    // ---- step 8: rollout. SKIP (not in the cohort yet). ----
    #[error("update skipped: not in rollout cohort (bucket {bucket} >= percentage {percentage})")]
    NotInRollout { bucket: u32, percentage: u32 },

    // ---- step 9: artifact select. SKIP (no artifact for this platform). ----
    #[error("update skipped: no artifact for platform {0}")]
    NoArtifactForPlatform(String),
}

impl UpdateReject {
    /// `true` for the normal not-applicable outcomes (channel/downgrade/forward/rollout/no-artifact):
    /// the app silently stays put. `false` for the integrity/trust REJECTs (signature/expiry/replay),
    /// which are logged loudly and never applied.
    pub fn is_skip(&self) -> bool {
        matches!(
            self,
            UpdateReject::WrongChannel { .. }
                | UpdateReject::NotNewer { .. }
                | UpdateReject::BelowMinSupported { .. }
                | UpdateReject::NotInRollout { .. }
                | UpdateReject::NoArtifactForPlatform(_)
        )
    }

    /// A stable machine reason code for the structured logger (AUTO_UPDATE.md §3: "every REJECT/SKIP
    /// reason is logged with the manifest_id and reason code").
    pub fn code(&self) -> &'static str {
        match self {
            UpdateReject::Signature(e) => match e {
                ManifestError::UnsupportedSchema { .. } => "unsupported_schema",
                ManifestError::UnknownKid(_) => "unknown_kid",
                ManifestError::BadPinnedKey(_) => "bad_pinned_key",
                ManifestError::MalformedSignature => "malformed_signature",
                ManifestError::BadSignature => "bad_signature",
                ManifestError::Malformed(_) => "malformed_manifest",
            },
            UpdateReject::WrongChannel { .. } => "wrong_channel",
            UpdateReject::Expired(_) => "expired",
            UpdateReject::ReplayOlderThanInstalled(_) => "replay_older_than_installed",
            UpdateReject::BadTimestamp(_) => "bad_timestamp",
            UpdateReject::NotNewer { .. } => "not_newer",
            UpdateReject::BelowMinSupported { .. } => "below_min_supported",
            UpdateReject::BadVersion(_) => "bad_version",
            UpdateReject::NotInRollout { .. } => "not_in_rollout",
            UpdateReject::NoArtifactForPlatform(_) => "no_artifact_for_platform",
        }
    }
}

/// Run the full §3 gate chain. `Ok(UpdateDecision)` ⇒ apply this artifact (after its sha256 verifies
/// post-download). `Err(UpdateReject)` ⇒ SKIP or REJECT per [`UpdateReject::is_skip`]; the reason
/// code is logged by the caller with the manifest_id.
///
/// `manifest_bytes` MUST be the original on-wire bytes the [`Manifest`] was parsed from — the
/// signature is re-verified over the JCS canonicalization of the raw `signed` object, so a
/// re-serialized manifest would not verify.
pub fn evaluate(
    manifest: &Manifest,
    manifest_bytes: &[u8],
    input: &PolicyInput<'_>,
) -> Result<UpdateDecision, UpdateReject> {
    let s = &manifest.signed;

    // Steps 1–3: schema + pinned kid + signature (over the raw canonical `signed` bytes).
    manifest.verify_signature(manifest_bytes)?;

    // Step 4: channel must match (never implicitly widens).
    if s.channel != input.channel.as_str() {
        return Err(UpdateReject::WrongChannel {
            manifest: s.channel.clone(),
            client: input.channel.as_str().to_string(),
        });
    }

    // Step 5: expiry (hard) then staleness/replay (older than the installed build's release date).
    let expires_at = parse_rfc3339(&s.manifest_expires_at)
        .map_err(|_| UpdateReject::BadTimestamp(s.manifest_expires_at.clone()))?;
    if input.now > expires_at {
        return Err(UpdateReject::Expired(s.manifest_expires_at.clone()));
    }
    let released_at = parse_rfc3339(&s.released_at)
        .map_err(|_| UpdateReject::BadTimestamp(s.released_at.clone()))?;
    if let Some(installed_rel) = input.installed_build_released_at {
        // Only enforce when we can parse BOTH; an unparseable/absent installed date conservatively
        // skips the replay-vs-installed check (the expiry gate already ran).
        if let Ok(installed_at) = parse_rfc3339(installed_rel) {
            if released_at < installed_at {
                return Err(UpdateReject::ReplayOlderThanInstalled(s.released_at.clone()));
            }
        }
    }

    // Parse the two semver fields once (reject unparseable — a malformed signed field is a trust
    // problem even though the signature verified).
    let cand = semver::Version::parse(s.version.trim())
        .map_err(|e| UpdateReject::BadVersion(format!("version {:?}: {e}", s.version)))?;
    let installed = semver::Version::parse(input.installed_version.trim())
        .map_err(|e| UpdateReject::BadVersion(format!("installed {:?}: {e}", input.installed_version)))?;
    let min_supported = semver::Version::parse(s.min_supported_version.trim()).map_err(|e| {
        UpdateReject::BadVersion(format!("min_supported_version {:?}: {e}", s.min_supported_version))
    })?;

    // Step 6: downgrade gate — must be strictly newer than the INSTALLED version (the DB anchor).
    if cand <= installed {
        return Err(UpdateReject::NotNewer {
            version: s.version.clone(),
            installed: input.installed_version.to_string(),
        });
    }

    // Step 7: forward gate — the client must be at/above the manifest's min_supported floor to apply
    // directly; otherwise it must fetch/apply the floor version first.
    if installed < min_supported {
        return Err(UpdateReject::BelowMinSupported {
            installed: input.installed_version.to_string(),
            min_supported: s.min_supported_version.clone(),
        });
    }

    // Step 8: rollout bucket (client-side, offline). Skipped for security advisories (they roll to
    // everyone immediately) and when no rollout block is present (⇒ 100%).
    if !s.security_advisory {
        if let Some(rollout) = &s.rollout {
            let pct = rollout.percentage.min(100);
            let bucket = rollout_bucket(input.install_id, &rollout.cohort_seed);
            if bucket >= pct {
                return Err(UpdateReject::NotInRollout { bucket, percentage: pct });
            }
        }
    }

    // Step 9: artifact select for the running platform.
    let artifact = s
        .artifacts
        .get(input.platform_key)
        .cloned()
        .ok_or_else(|| UpdateReject::NoArtifactForPlatform(input.platform_key.to_string()))?;

    // Step 10 (sha256) is performed by the downloader against `artifact.sha256`; we surface it via
    // `UpdateDecision::expected_sha256`.
    Ok(UpdateDecision { version: s.version.clone(), released_at: s.released_at.clone(), artifact })
}

/// The offline rollout bucket (AUTO_UPDATE.md §3 step 8): the first 4 bytes of
/// `SHA256(install_id || ":" || cohort_seed)` as a big-endian u32, mod 100. A client whose bucket is
/// `< percentage` is in the cohort. Pure + deterministic (no server call).
pub fn rollout_bucket(install_id: &str, cohort_seed: &str) -> u32 {
    let mut h = Sha256::new();
    h.update(install_id.as_bytes());
    h.update(b":");
    h.update(cohort_seed.as_bytes());
    let digest = h.finalize();
    let n = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    n % 100
}

/// The compiled-in platform key for the running build (`macos-aarch64`, `macos-x86_64`,
/// `windows-x86_64`, `linux-x86_64`). Unknown target triples map to an empty string, which no
/// manifest artifact key matches ⇒ the update SKIPs with `no_artifact_for_platform` (fail-safe).
pub fn current_platform_key() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "macos-aarch64"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "macos-x86_64"
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "windows-x86_64"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux-x86_64"
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
    )))]
    {
        ""
    }
}

/// Parse an RFC3339 timestamp into a UTC datetime.
fn parse_rfc3339(s: &str) -> Result<chrono::DateTime<chrono::Utc>, chrono::ParseError> {
    chrono::DateTime::parse_from_rfc3339(s.trim()).map(|dt| dt.with_timezone(&chrono::Utc))
}

/// Lowercase-hex of a byte slice.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_roundtrips() {
        assert_eq!(Channel::parse("stable"), Some(Channel::Stable));
        assert_eq!(Channel::parse("BETA"), Some(Channel::Beta));
        assert_eq!(Channel::parse("managed").unwrap().as_str(), "managed");
        assert_eq!(Channel::parse("nightly"), None);
    }

    #[test]
    fn rollout_bucket_is_deterministic_and_ranged() {
        let b1 = rollout_bucket("install-abc", "v1.4.2-stable");
        let b2 = rollout_bucket("install-abc", "v1.4.2-stable");
        assert_eq!(b1, b2, "same inputs → same bucket");
        assert!(b1 < 100);
        // A different install id generally lands in a different bucket (not guaranteed, but assert the
        // range for a spread of ids).
        for i in 0..50 {
            assert!(rollout_bucket(&format!("id-{i}"), "seed") < 100);
        }
    }

    #[test]
    fn skip_vs_reject_classification() {
        assert!(UpdateReject::WrongChannel { manifest: "beta".into(), client: "stable".into() }.is_skip());
        assert!(UpdateReject::NotNewer { version: "1".into(), installed: "2".into() }.is_skip());
        assert!(!UpdateReject::Expired("x".into()).is_skip());
        assert!(!UpdateReject::Signature(ManifestError::BadSignature).is_skip());
        assert_eq!(UpdateReject::Signature(ManifestError::BadSignature).code(), "bad_signature");
    }
}
