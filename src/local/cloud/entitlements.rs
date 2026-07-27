//! Account entitlements — **REFLECTION-ONLY** (Stage B-2).
//!
//! ## What this is, and what it is emphatically NOT
//!
//! This module fetches, signature-verifies, and caches the account *entitlements document*: the
//! cloud's signed assertion of the linked account's `plan`, enabled `features`, and numeric `limits`.
//! The verified document drives **UI and upsell reflection** ("Pro" badges, "upgrade to enable
//! CAPTCHA solving" prompts, greying-out of paid affordances) and provides an **offline grace
//! window** so the desktop UI doesn't flap when the network is briefly unavailable.
//!
//! It is **NEVER an authorization gate.** Nothing in this module decides whether a paid or metered
//! action is *allowed* to run. Every paid/metered/cloud-mediated capability is re-resolved and
//! re-enforced **server-side, per call** — the desktop only ever *reflects* what it last saw.
//! See the never-trust-a-BYO-agent rule: security, billing, metering, and "success" truth live in
//! the cloud (ws-gateway + backend), never in the agent. A tampered, forged, stale, or simply
//! absent entitlements document must, at worst, make the LOCAL UI *under*-report entitlements
//! (fail-closed reflection) — it can never *grant* a capability, because the server gates the
//! capability independently and ignores anything the client claims to be entitled to.
//!
//! Concretely:
//! - [`feature_enabled`] / [`limit`] / [`plan`] read the last verified+fresh document. They are
//!   advisory. A caller using them to *skip* a server round-trip for a paid feature would be a bug.
//! - When verification fails (unknown/wrong `kid`, bad signature, tampered claims), or the cached
//!   copy is past its grace window, the document **fails closed**: every feature reflects OFF and
//!   every limit reflects absent. The UI degrades to the free/unlinked presentation; the server
//!   still owns the real decision.
//!
//! [`feature_enabled`]: Entitlements::feature_enabled
//! [`limit`]: Entitlements::limit
//! [`plan`]: Entitlements::plan
//!
//! ## Trust model
//!
//! The document is an **EdDSA (Ed25519) compact JWS**. We verify it with `jsonwebtoken` using
//! [`Algorithm::EdDSA`] and a **`kid`-pinned** public key: the header's `kid` must match an entry in
//! a small baked-in table ([`PINNED_KEYS`]); an unknown `kid` is rejected outright. This pins trust
//! to keys shipped *in the binary*, not to whatever the network hands us. The signing private key
//! lives only in the cloud; the desktop holds public keys only.
//!
//! ## Freshness & grace
//!
//! The JWS carries a short `exp` (the cloud issues these with ~1h validity). Within `exp` the cached
//! copy is authoritative. Past `exp` we still honor the cached copy for up to [`GRACE`] (7 days) so a
//! brief outage doesn't strip the UI's paid affordances — but only if the signature & `kid` still
//! verify. Past the grace window the document is considered stale and fails closed locally.
//!
//! ## Storage
//!
//! The verified compact JWS is cached at `~/.writ/cloud/entitlements.json` (`0600`). We persist the
//! *raw signed token* (not the decoded claims) so every load re-verifies the signature from scratch —
//! the on-disk file is untrusted input, exactly like the network response. No secret material is
//! stored here: the document is a public, signed assertion about the account. The cloud *account
//! token* never touches this file (it lives in the OS keyring, `writ-cloud/account`).
//!
//! House style: no `async-trait`; runtime-resolved paths; `tracing` only and NEVER token/claim
//! secrets (there are none here, but we still avoid dumping raw JWS at info level).
//!
//! Net-new Rust in this crate (Stage B-2 — entitlements reflection).

use super::super::error::{LocalError, LocalResult};
use super::client::CloudClient;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Cloud path of the signed entitlements document (authenticated GET via [`CloudClient`]).
const ENTITLEMENTS_PATH: &str = "/api/v1/account/entitlements";

/// Offline grace window: how long past the JWS `exp` we keep honoring a still-signature-valid cached
/// document before failing closed. 7 days.
pub const GRACE: chrono::Duration = chrono::Duration::days(7);

/// A `kid` → baked-in Ed25519 **public** key (PKCS#8 SubjectPublicKeyInfo PEM).
///
/// Trust is pinned to these keys: the JWS header `kid` MUST match one of these, or verification is
/// rejected. Rotating the signing key = ship a new `(kid, pem)` row here in a desktop release (keep
/// the old row until all issued tokens expire, then drop it).
struct PinnedKey {
    kid: &'static str,
    /// SPKI PEM (`-----BEGIN PUBLIC KEY-----`). Ed25519.
    pem: &'static str,
}

/// Pinned verification keys — **EMPTY in a shipped build** (SB-3).
///
/// This table MUST NOT contain any key whose private half is public. It ships empty on purpose: an
/// unknown `kid` is already rejected (see [`pinned_key`] / [`verify_jws_with_grace`]), so with no
/// pinned key EVERY entitlement JWS fails verification and the reflection fails CLOSED — which is the
/// correct default (the cloud independently re-enforces every capability server-side; this table only
/// drives desktop nav/upsell REFLECTION).
///
/// DEPLOYERS: to enable entitlement reflection, add your production signing key here as a
/// `PinnedKey { kid, pem }` row (Ed25519 SPKI PEM). On rotation, keep the old row until all issued
/// tokens have expired, then drop it. Do NOT add a key whose private half is committed anywhere.
const PINNED_KEYS: &[PinnedKey] = &[
    // Intentionally empty. Add production key(s) here, e.g.:
    // PinnedKey { kid: "writ-ent-2026-01", pem: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n" },
];

/// The dev/test pinned key. Its PRIVATE half is committed in this very file (`tests::TEST_PRIV_PEM`),
/// so anyone can mint an entitlements document this key verifies.
///
/// Gated on `#[cfg(any(test, feature = "update-test-keys"))]` — a real, opt-in FEATURE that is never
/// in a release feature set (see Cargo.toml; only `tests/update_verify.rs` enables it). It was
/// previously gated on `#[cfg(any(test, debug_assertions))]`, which is a much weaker promise than it
/// reads as: `debug_assertions` is ON for a plain `cargo build` / `cargo run`, so every debug binary —
/// including anything a contributor or a distro packager hands someone — trusted a keypair published
/// in the repository. `local::update::manifest` already had this right; this matches it.
///
/// (The feature is named for the auto-update keys because it is the crate's single "compile the
/// publicly-known test keys in" switch and adding a second one would need a Cargo.toml change. What
/// matters is the property: it is absent from `default` and from every shipped build.)
#[cfg(any(test, feature = "update-test-keys"))]
const TEST_PINNED_KEYS: &[PinnedKey] = &[PinnedKey {
    kid: "writ-ent-test-2026",
    pem: "-----BEGIN PUBLIC KEY-----\n\
          MCowBQYDK2VwAyEAKb5L6VMorfmlsZUiVV/3Xe8GHwd/kj1LoSYd7LXR36w=\n\
          -----END PUBLIC KEY-----\n",
}];

/// Look up a pinned key by `kid`. `None` ⇒ unknown `kid` ⇒ reject. Under `cfg(test)` and with the
/// `update-test-keys` feature the dev/test key table is also consulted — never in any shipped build,
/// debug or release.
fn pinned_key(kid: &str) -> Option<&'static PinnedKey> {
    if let Some(k) = PINNED_KEYS.iter().find(|k| k.kid == kid) {
        return Some(k);
    }
    #[cfg(any(test, feature = "update-test-keys"))]
    if let Some(k) = TEST_PINNED_KEYS.iter().find(|k| k.kid == kid) {
        #[cfg(not(test))]
        {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(
                    kid = k.kid,
                    "entitlements: trusting the DEV/TEST signing key (debug build only — release builds reject this kid)"
                );
            });
        }
        return Some(k);
    }
    None
}

/// Verified claims carried by the entitlements JWS.
///
/// `#[serde(default)]` so a sparse/older document loads forward. Unknown fields are ignored.
/// `exp` is the standard JWT numeric-date (seconds since the Unix epoch).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EntitlementClaims {
    /// Plan slug, e.g. `"free"`, `"pro"`, `"team"`. Empty ⇒ treat as free/unlinked.
    pub plan: String,
    /// Feature flags. A feature is "on" iff present AND truthy. We accept a map for forward-compat
    /// (a feature may carry a sub-config), but [`feature_enabled`] only inspects truthiness.
    ///
    /// [`feature_enabled`]: Entitlements::feature_enabled
    pub features: HashMap<String, serde_json::Value>,
    /// Numeric limits, e.g. `{"max_workflows": 50}`. Absent ⇒ no reflected limit.
    pub limits: HashMap<String, i64>,
    /// Whether the linked plan may monetize (sell/earn) on the cloud. REFLECTION-ONLY: gates the
    /// "Earnings"/"Sell" upsell affordances in the desktop nav; the cloud independently re-enforces.
    pub can_monetize: bool,
    /// Per-section nav reflection, e.g. `{"marketplace": true, "earnings": false, ...}`. Mirrors the
    /// same gating the web uses. A map for forward-compat; truthiness drives whether a nav item shows.
    pub nav: HashMap<String, serde_json::Value>,
    /// The cloud WEBAPP base URL (`settings.frontend_url`) for desktop deep-links (open marketplace /
    /// earnings / billing / sell in the browser). Empty ⇒ no deep-links surfaced.
    pub web_url: String,
    /// Standard JWT expiry (Unix seconds). The cloud issues ~1h-lived documents.
    pub exp: i64,
    /// Standard JWT issued-at (Unix seconds), if present. Informational.
    pub iat: i64,
}

impl EntitlementClaims {
    /// `exp` as a UTC datetime, if set (`exp > 0`).
    fn expires_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        (self.exp > 0).then(|| chrono::DateTime::from_timestamp(self.exp, 0)).flatten()
    }
}

/// A verified, possibly-cached entitlements reflection.
///
/// Construct via [`Entitlements::refresh`] (fetch+verify+cache) or [`Entitlements::load_cached`]
/// (verify the on-disk copy). All accessors are reflection-only (see module docs). When the
/// underlying document is stale-past-grace or could not be verified, the value fails closed:
/// [`feature_enabled`] returns `false`, [`limit`] returns `None`, [`plan`] returns `"free"`.
///
/// [`feature_enabled`]: Entitlements::feature_enabled
/// [`limit`]: Entitlements::limit
/// [`plan`]: Entitlements::plan
#[derive(Debug, Clone)]
pub struct Entitlements {
    claims: EntitlementClaims,
    /// `true` once the document is stale beyond [`GRACE`] (or was constructed fail-closed). When set,
    /// all reflection accessors report the free/empty state regardless of `claims`.
    failed_closed: bool,
}

impl Entitlements {
    /// A fully fail-closed reflection (no entitlements). Used when nothing is cached, or when the
    /// cached document is unverifiable / stale-past-grace. Every feature reflects OFF.
    pub fn empty() -> Self {
        Self { claims: EntitlementClaims::default(), failed_closed: true }
    }

    /// Reflection-only: is `name` enabled? `false` when failed-closed, absent, or falsy.
    ///
    /// NOT an authorization gate — the server independently gates the capability (see module docs).
    pub fn feature_enabled(&self, name: &str) -> bool {
        if self.failed_closed {
            return false;
        }
        match self.claims.features.get(name) {
            Some(v) => is_truthy(v),
            None => false,
        }
    }

    /// Reflection-only: numeric limit `name`, or `None` when failed-closed / absent.
    pub fn limit(&self, name: &str) -> Option<i64> {
        if self.failed_closed {
            return None;
        }
        self.claims.limits.get(name).copied()
    }

    /// Reflection-only: the plan slug, or `"free"` when failed-closed / unset.
    pub fn plan(&self) -> &str {
        if self.failed_closed || self.claims.plan.is_empty() {
            "free"
        } else {
            &self.claims.plan
        }
    }

    /// Reflection-only: the full feature map (for surfacing to the desktop UI). Empty when
    /// failed-closed. Clones so callers can serialize freely without borrowing the reflection.
    ///
    /// NOT an authorization gate — see [`feature_enabled`] and the module docs.
    ///
    /// [`feature_enabled`]: Entitlements::feature_enabled
    pub fn features(&self) -> HashMap<String, serde_json::Value> {
        if self.failed_closed {
            HashMap::new()
        } else {
            self.claims.features.clone()
        }
    }

    /// Reflection-only: the full numeric-limits map. Empty when failed-closed.
    pub fn limits(&self) -> HashMap<String, i64> {
        if self.failed_closed {
            HashMap::new()
        } else {
            self.claims.limits.clone()
        }
    }

    /// Reflection-only: may the linked plan monetize (sell/earn)? `false` when failed-closed.
    ///
    /// NOT an authorization gate — the cloud independently re-enforces every paid/monetized action.
    pub fn can_monetize(&self) -> bool {
        !self.failed_closed && self.claims.can_monetize
    }

    /// Reflection-only: the per-section nav map as JSON (`{}` when failed-closed). Drives which
    /// cloud nav items the desktop renders; the cloud still gates the underlying capability.
    pub fn nav(&self) -> serde_json::Value {
        if self.failed_closed {
            json!({})
        } else {
            serde_json::to_value(&self.claims.nav).unwrap_or_else(|_| json!({}))
        }
    }

    /// Reflection-only: the cloud WEBAPP base URL for desktop deep-links, or `""` when failed-closed
    /// / unset.
    pub fn web_url(&self) -> &str {
        if self.failed_closed {
            ""
        } else {
            &self.claims.web_url
        }
    }

    /// `true` if this reflection is failing closed (stale-past-grace / unverifiable / empty).
    pub fn is_failed_closed(&self) -> bool {
        self.failed_closed
    }

    /// Fetch the signed document from the cloud, verify it, cache the raw JWS to
    /// `~/.writ/cloud/entitlements.json` (`0600`), and return the reflection.
    ///
    /// On a network/auth error the cloud copy can't be fetched; callers that want resilience should
    /// fall back to [`Entitlements::load_cached`] (which applies the grace window). This method does
    /// NOT silently swallow fetch errors — it surfaces them so the caller can decide.
    pub async fn refresh(client: &mut CloudClient) -> LocalResult<Self> {
        let resp: EntitlementsResponse = client.get_json(ENTITLEMENTS_PATH).await?;
        let jws = resp.token.trim().to_string();
        let claims = verify_jws(&jws, chrono::Utc::now())?;
        cache_write(&entitlements_cache_path()?, &jws)?;
        tracing::debug!(plan = %claims.plan, "entitlements refreshed and cached");
        Ok(Self { claims, failed_closed: false })
    }

    /// Load + verify the cached JWS, applying the grace window. Returns a fail-closed
    /// [`Entitlements::empty`] when there is no cache, the cache is unverifiable, or it is stale past
    /// [`GRACE`]. Never errors on "absent/stale" — those are normal fail-closed states.
    pub fn load_cached() -> Self {
        Self::load_cached_at(&entitlements_cache_path_or_default(), chrono::Utc::now())
    }

    /// Testable core of [`load_cached`]: explicit path + injected `now`.
    ///
    /// [`load_cached`]: Entitlements::load_cached
    fn load_cached_at(path: &Path, now: chrono::DateTime<chrono::Utc>) -> Self {
        let jws = match cache_read(path) {
            Ok(Some(s)) => s,
            Ok(None) => return Self::empty(),
            Err(e) => {
                tracing::warn!(error = %e, "entitlements cache read failed — reflecting empty");
                return Self::empty();
            }
        };
        match verify_jws_with_grace(&jws, now) {
            Ok(claims) => Self { claims, failed_closed: false },
            Err(e) => {
                // Stale-past-grace, tampered, wrong/unknown kid, bad signature → fail closed.
                tracing::warn!(error = %e, "cached entitlements failed verification — reflecting empty");
                Self::empty()
            }
        }
    }
}

/// Truthiness for a feature flag value: explicit `true`, a non-zero number, a non-empty string
/// other than `"false"`/`"off"`/`"0"`, or any present object/array (a feature sub-config implies on).
/// `null`/`false`/`0`/`""` are off.
fn is_truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(false),
        serde_json::Value::String(s) => {
            let s = s.trim().to_ascii_lowercase();
            !matches!(s.as_str(), "" | "false" | "off" | "0" | "no")
        }
        serde_json::Value::Null => false,
        // A present object/array (feature carries sub-config) ⇒ enabled.
        serde_json::Value::Object(_) | serde_json::Value::Array(_) => true,
    }
}

/// Verify the JWS strictly: `exp` must be in the future (standard validation). Used on fresh fetch.
///
/// Rejects: unknown/missing `kid`, wrong key, bad signature, expired `exp`, malformed claims.
fn verify_jws(jws: &str, now: chrono::DateTime<chrono::Utc>) -> LocalResult<EntitlementClaims> {
    verify_inner(jws, now, /* allow_grace = */ false)
}

/// Verify the JWS allowing the offline grace window: signature/`kid` must still pass, but an `exp`
/// in the past is tolerated up to [`GRACE`]. Used on cached load.
fn verify_jws_with_grace(jws: &str, now: chrono::DateTime<chrono::Utc>) -> LocalResult<EntitlementClaims> {
    verify_inner(jws, now, /* allow_grace = */ true)
}

/// Shared verification. We disable `jsonwebtoken`'s own `exp` check and enforce freshness ourselves so
/// the grace window is explicit and unit-testable with an injected clock. Signature + `kid` pinning +
/// algorithm pinning are always enforced by `jsonwebtoken`.
fn verify_inner(
    jws: &str,
    now: chrono::DateTime<chrono::Utc>,
    allow_grace: bool,
) -> LocalResult<EntitlementClaims> {
    // 1) Pin the algorithm and the key by `kid` BEFORE touching the signature.
    let header = decode_header(jws)
        .map_err(|e| LocalError::BadRequest(format!("entitlements: malformed JWS header ({e})")))?;
    if header.alg != Algorithm::EdDSA {
        return Err(LocalError::BadRequest(format!(
            "entitlements: unexpected JWS alg {:?} (require EdDSA)",
            header.alg
        )));
    }
    let kid = header
        .kid
        .as_deref()
        .ok_or_else(|| LocalError::BadRequest("entitlements: JWS missing kid".into()))?;
    let pinned = pinned_key(kid)
        .ok_or_else(|| LocalError::BadRequest(format!("entitlements: unknown signing kid {kid:?}")))?;
    let key = DecodingKey::from_ed_pem(pinned.pem.as_bytes())
        .map_err(|e| LocalError::Internal(format!("entitlements: bad pinned key {kid:?} ({e})")))?;

    // 2) Verify the signature (and pin EdDSA again at the validator). We do our own `exp` handling.
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.algorithms = vec![Algorithm::EdDSA];
    validation.validate_exp = false; // freshness enforced below (grace-aware)
    validation.validate_nbf = false;
    // NO AUDIENCE / SUBJECT BINDING — deliberate, and the reason is worth stating because the shape
    // ("verify a signature, ignore who it was issued to") is normally a bug.
    //
    // The document the cloud issues today carries neither `aud` nor `sub` (see `EntitlementClaims`):
    // there is no account identifier in it to bind against, so enabling `validate_aud` would only
    // reject every real token. The consequence is that a JWS issued for account A verifies on account
    // B's install — a Pro user's cached `entitlements.json`, copied to a Free install, reflects Pro.
    //
    // That is bounded to REFLECTION and cannot escalate: this module never authorizes anything (see
    // the module docs — the cloud re-resolves and re-enforces every paid/metered capability per call,
    // and ignores what the client believes it is entitled to), and `PINNED_KEYS` ships EMPTY, so a
    // stock build rejects every document outright and reflects the free state regardless.
    //
    // Closing it properly is an ISSUER change, not a verifier one: the cloud must stamp the account id
    // into the document, and this function must then compare it against the locally linked account
    // (`cloud::state::LinkState::account_id`, which needs the DB pool that neither
    // `Entitlements::load_cached` nor `refresh` currently has). Until the claim exists there is nothing
    // to check, so we do not pretend to check it.
    validation.validate_aud = false;
    validation.required_spec_claims.clear(); // we require `exp` explicitly, our own way

    let data = decode::<EntitlementClaims>(jws, &key, &validation)
        .map_err(|e| LocalError::BadRequest(format!("entitlements: signature/claims invalid ({e})")))?;
    let claims = data.claims;

    // 3) Freshness: `exp` is mandatory; within `exp` ⇒ fresh; past `exp` ⇒ only OK within grace.
    let exp = claims
        .expires_at()
        .ok_or_else(|| LocalError::BadRequest("entitlements: JWS missing/zero exp".into()))?;
    if now <= exp {
        return Ok(claims);
    }
    let overdue = now - exp;
    if allow_grace && overdue <= GRACE {
        tracing::debug!(grace_secs = overdue.num_seconds(), "entitlements past exp but within grace");
        return Ok(claims);
    }
    Err(LocalError::Unauthorized) // stale-past-grace (or grace not allowed) ⇒ caller fails closed
}

/// Cloud response envelope: `{ "token": "<compact-jws>" }`.
#[derive(Debug, Deserialize)]
struct EntitlementsResponse {
    /// The EdDSA compact JWS string.
    token: String,
}

/// Resolved cache path `~/.writ/cloud/entitlements.json`.
fn entitlements_cache_path() -> LocalResult<PathBuf> {
    let paths = super::super::config::Paths::resolve()?;
    paths.ensure_dirs()?;
    Ok(paths.cloud_dir().join("entitlements.json"))
}

/// Best-effort path for fallible-free callers; never errors (used by [`Entitlements::load_cached`]).
/// If the home dir can't be resolved, points at a non-existent path so the read yields `None`.
fn entitlements_cache_path_or_default() -> PathBuf {
    match super::super::config::Paths::resolve() {
        Ok(p) => p.cloud_dir().join("entitlements.json"),
        Err(_) => PathBuf::from("/nonexistent/.writ/cloud/entitlements.json"),
    }
}

/// Read the cached compact JWS, or `None` if the file is absent. Empty file ⇒ `None`.
fn cache_read(path: &Path) -> LocalResult<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(s) => {
            let t = s.trim().to_string();
            Ok((!t.is_empty()).then_some(t))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(LocalError::Io(e)),
    }
}

/// Write the compact JWS to `path` with `0600` perms (parent dir is created by the caller path
/// resolver). The JWS is a public signed assertion (no secret material), but we keep it `0600` to
/// match the rest of the `~/.writ` tree.
fn cache_write(path: &Path, jws: &str) -> LocalResult<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, jws.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    /// PLACEHOLDER/TEST signing key — its public half is the pinned `writ-ent-test-2026` entry.
    /// (PKCS#8 Ed25519 private key; published deliberately for tests only.)
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIBMEPOENF9Y3zw6g6zdoVAOl5Q038xOdz7ehDN5rOc7r\n\
        -----END PRIVATE KEY-----\n";

    /// A DIFFERENT Ed25519 private key, NOT pinned — used to forge a wrong-signature token.
    const WRONG_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIFX1E58aiUvuNvrj37al8UfjJxaQw++dYUKSyZnOPzx8\n\
        -----END PRIVATE KEY-----\n";

    const TEST_KID: &str = "writ-ent-test-2026";

    fn sample_claims(exp: chrono::DateTime<chrono::Utc>) -> EntitlementClaims {
        let mut features = HashMap::new();
        features.insert("captcha_solving".to_string(), serde_json::json!(true));
        features.insert("export_csv".to_string(), serde_json::json!(false));
        let mut limits = HashMap::new();
        limits.insert("max_workflows".to_string(), 50);
        let mut nav = HashMap::new();
        nav.insert("marketplace".to_string(), serde_json::json!(true));
        nav.insert("earnings".to_string(), serde_json::json!(true));
        nav.insert("sell".to_string(), serde_json::json!(true));
        nav.insert("billing".to_string(), serde_json::json!(true));
        EntitlementClaims {
            plan: "pro".into(),
            features,
            limits,
            can_monetize: true,
            nav,
            web_url: "https://app.writ.example".into(),
            exp: exp.timestamp(),
            iat: (exp - chrono::Duration::hours(1)).timestamp(),
        }
    }

    /// Sign `claims` with the given private key PEM under header `(EdDSA, kid)`.
    fn sign(priv_pem: &str, kid: &str, claims: &EntitlementClaims) -> String {
        let key = EncodingKey::from_ed_pem(priv_pem.as_bytes()).expect("encoding key");
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        encode(&header, claims, &key).expect("sign")
    }

    #[test]
    fn valid_token_verifies_and_reflects() {
        let exp = chrono::Utc::now() + chrono::Duration::hours(1);
        let jws = sign(TEST_PRIV_PEM, TEST_KID, &sample_claims(exp));
        let claims = verify_jws(&jws, chrono::Utc::now()).expect("valid token verifies");
        let ent = Entitlements { claims, failed_closed: false };
        assert!(ent.feature_enabled("captcha_solving"));
        assert!(!ent.feature_enabled("export_csv"), "false flag reflects off");
        assert!(!ent.feature_enabled("nonexistent"), "absent flag reflects off");
        assert_eq!(ent.limit("max_workflows"), Some(50));
        assert_eq!(ent.limit("nope"), None);
        assert_eq!(ent.plan(), "pro");
        // New reflection accessors surface the full maps + monetize/nav/web_url.
        assert_eq!(ent.features().get("captcha_solving"), Some(&serde_json::json!(true)));
        assert_eq!(ent.limits().get("max_workflows"), Some(&50));
        assert!(ent.can_monetize());
        assert_eq!(ent.nav()["earnings"], serde_json::json!(true));
        assert_eq!(ent.web_url(), "https://app.writ.example");
    }

    #[test]
    fn wrong_key_fails_closed() {
        // Signed with a non-pinned key but advertising the pinned kid → signature mismatch.
        let exp = chrono::Utc::now() + chrono::Duration::hours(1);
        let jws = sign(WRONG_PRIV_PEM, TEST_KID, &sample_claims(exp));
        let err = verify_jws(&jws, chrono::Utc::now());
        assert!(err.is_err(), "wrong-key token must not verify");
        // And the public reflection path fails closed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entitlements.json");
        cache_write(&path, &jws).unwrap();
        let ent = Entitlements::load_cached_at(&path, chrono::Utc::now());
        assert!(ent.is_failed_closed());
        assert!(!ent.feature_enabled("captcha_solving"));
        assert_eq!(ent.plan(), "free");
        assert_eq!(ent.limit("max_workflows"), None);
        // The new accessors must also fail closed: empty maps, no monetize, no deep-links.
        assert!(ent.features().is_empty());
        assert!(ent.limits().is_empty());
        assert!(!ent.can_monetize());
        assert_eq!(ent.nav(), serde_json::json!({}));
        assert_eq!(ent.web_url(), "");
    }

    #[test]
    fn unknown_kid_rejected() {
        let exp = chrono::Utc::now() + chrono::Duration::hours(1);
        let jws = sign(TEST_PRIV_PEM, "some-rotated-kid-not-pinned", &sample_claims(exp));
        assert!(verify_jws(&jws, chrono::Utc::now()).is_err(), "unknown kid must be rejected");
    }

    #[test]
    fn shipped_pinned_table_is_empty() {
        // SB-3: the PRODUCTION pinned table must ship empty (no key whose private half is public). The
        // test key that lets the fixtures above verify lives ONLY in the cfg(test) TEST_PINNED_KEYS.
        assert!(
            PINNED_KEYS.is_empty(),
            "PINNED_KEYS must be empty in a shipped build — deployers add their prod key at deploy time"
        );
        // With an empty prod table, the test kid is reachable ONLY via the test-gated table.
        assert!(PINNED_KEYS.iter().all(|k| k.kid != TEST_KID));
    }

    #[test]
    fn tampered_claims_fail_closed() {
        let exp = chrono::Utc::now() + chrono::Duration::hours(1);
        let jws = sign(TEST_PRIV_PEM, TEST_KID, &sample_claims(exp));
        // Flip a byte in the payload segment (middle of the 3 dot-separated parts).
        let mut parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3);
        let payload = parts[1];
        // Mutate the last char of the payload to a different base64url char.
        let mut bytes = payload.as_bytes().to_vec();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        let tampered_payload = String::from_utf8(bytes).unwrap();
        parts[1] = &tampered_payload;
        let tampered = parts.join(".");
        assert!(verify_jws(&tampered, chrono::Utc::now()).is_err(), "tampered payload must fail");
    }

    #[test]
    fn expired_within_grace_ok_past_grace_fails() {
        // exp 1 day in the past: strict verify fails, grace verify passes.
        let exp = chrono::Utc::now() - chrono::Duration::days(1);
        let jws = sign(TEST_PRIV_PEM, TEST_KID, &sample_claims(exp));
        let now = chrono::Utc::now();

        assert!(verify_jws(&jws, now).is_err(), "strict verify rejects an expired token");
        let claims = verify_jws_with_grace(&jws, now).expect("within 7-day grace");
        assert_eq!(claims.plan, "pro");

        // Now move the clock to 8 days after exp → past the 7-day grace → fail closed.
        let past_grace = exp + GRACE + chrono::Duration::hours(1);
        assert!(
            verify_jws_with_grace(&jws, past_grace).is_err(),
            "past grace must fail closed even with a valid signature"
        );
    }

    #[test]
    fn cache_roundtrip_and_grace_reflection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entitlements.json");

        // Fresh token, cached, loaded within validity → reflects.
        let exp = chrono::Utc::now() + chrono::Duration::minutes(30);
        let jws = sign(TEST_PRIV_PEM, TEST_KID, &sample_claims(exp));
        cache_write(&path, &jws).unwrap();
        assert_eq!(cache_read(&path).unwrap().as_deref(), Some(jws.as_str()), "roundtrip");

        let ent = Entitlements::load_cached_at(&path, chrono::Utc::now());
        assert!(!ent.is_failed_closed());
        assert!(ent.feature_enabled("captcha_solving"));
        assert_eq!(ent.plan(), "pro");

        // Same cache, but clock is 3 days past exp → within grace → still reflects.
        let within_grace = exp + chrono::Duration::days(3);
        let ent = Entitlements::load_cached_at(&path, within_grace);
        assert!(!ent.is_failed_closed(), "within grace still reflects");
        assert!(ent.feature_enabled("captcha_solving"));

        // Clock 10 days past exp → past grace → fails closed.
        let past_grace = exp + chrono::Duration::days(10);
        let ent = Entitlements::load_cached_at(&path, past_grace);
        assert!(ent.is_failed_closed(), "past grace fails closed");
        assert!(!ent.feature_enabled("captcha_solving"));
        assert_eq!(ent.plan(), "free");
        assert_eq!(ent.limit("max_workflows"), None);
    }

    #[test]
    fn absent_cache_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does_not_exist.json");
        let ent = Entitlements::load_cached_at(&path, chrono::Utc::now());
        assert!(ent.is_failed_closed());
        assert!(!ent.feature_enabled("anything"));
        assert_eq!(ent.plan(), "free");
    }

    #[test]
    fn empty_is_failed_closed() {
        let ent = Entitlements::empty();
        assert!(ent.is_failed_closed());
        assert!(!ent.feature_enabled("captcha_solving"));
        assert_eq!(ent.plan(), "free");
        assert_eq!(ent.limit("max_workflows"), None);
    }

    #[test]
    fn truthiness_table() {
        assert!(is_truthy(&serde_json::json!(true)));
        assert!(!is_truthy(&serde_json::json!(false)));
        assert!(is_truthy(&serde_json::json!(1)));
        assert!(!is_truthy(&serde_json::json!(0)));
        assert!(is_truthy(&serde_json::json!("enabled")));
        assert!(!is_truthy(&serde_json::json!("")));
        assert!(!is_truthy(&serde_json::json!("false")));
        assert!(!is_truthy(&serde_json::json!("off")));
        assert!(!is_truthy(&serde_json::json!(null)));
        assert!(is_truthy(&serde_json::json!({"tier": "gold"})), "sub-config ⇒ on");
    }

    #[cfg(unix)]
    #[test]
    fn cache_write_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("entitlements.json");
        cache_write(&path, "header.payload.sig").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "cache file must be 0600");
    }

    // The live fetch path requires a linked account + a reachable backend.
    #[tokio::test]
    #[ignore = "network: requires a live Writ Cloud backend + a linked account token"]
    async fn refresh_against_live_backend() {
        let mut client = CloudClient::connect(None).expect("a linked token");
        let ent = Entitlements::refresh(&mut client).await.expect("refresh");
        tracing::info!(plan = ent.plan(), "fetched entitlements");
    }
}
