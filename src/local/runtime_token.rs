//! Live rotation overlay for the `wlt_` runtime bearer.
//!
//! The daemon mints its `wlt_` token at boot and seeds it into `AppState.token` (an `Arc<String>`
//! shared by every handler). That seed is FIXED for the process, so a naive rotate could only change
//! the on-disk `local_token` / `runtime.json` — leaving the LIVE server still honoring the old token
//! until a restart. That desync is exactly what the shell's transactional rotation guards against by
//! refusing to touch the file unless the daemon CONFIRMS the new token is active.
//!
//! This module is the daemon half that makes the confirmation real: a tiny process-global overlay
//! mapping `seed → rotated`. The auth middleware verifies a presented bearer against the CURRENT
//! effective token ([`verify`]); the rotate endpoint swaps it ([`set`]) after atomically rewriting the
//! files. Because the daemon is a singleton process there is exactly one seed in production; the map is
//! KEYED BY SEED purely so the crate's many per-test `AppState`s (each with its own token) stay
//! isolated when tests run in parallel — one test's rotation never affects another's auth.
//!
//! Security: constant-time compare (delegates to [`crate::local::auth::verify_local_bearer`]); the raw
//! token is never logged (only whether a rotation happened).

use std::sync::OnceLock;

use dashmap::DashMap;

/// `seed → current rotated token`. Absent seed ⇒ the seed itself is still the effective token.
static OVERLAY: OnceLock<DashMap<String, String>> = OnceLock::new();

fn overlay() -> &'static DashMap<String, String> {
    OVERLAY.get_or_init(DashMap::new)
}

/// Verify a presented bearer against the EFFECTIVE runtime token for `seed` — the rotated value if one
/// has been set, else the boot seed. Constant-time. This is what the auth middleware calls instead of
/// comparing directly against `AppState.token`.
pub fn verify(presented: &str, seed: &str) -> bool {
    let effective = overlay().get(seed).map(|v| v.clone());
    let effective = effective.as_deref().unwrap_or(seed);
    crate::local::auth::verify_local_bearer(presented, effective)
}

/// The current effective token for `seed` (for republishing `runtime.json` after a rotation).
pub fn current(seed: &str) -> String {
    overlay().get(seed).map(|v| v.clone()).unwrap_or_else(|| seed.to_string())
}

/// Swap the live token for `seed` to `new`. After this call, `new` authenticates and the previous
/// value does not. Never logs the token value.
pub fn set(seed: &str, new: &str) {
    overlay().insert(seed.to_string(), new.to_string());
    tracing::info!("runtime token rotated (live in-memory swap)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_is_effective_until_rotated_then_swaps() {
        let seed = "wlt_seed_alpha";
        // Before any rotation, the seed authenticates and a random value does not.
        assert!(verify(seed, seed));
        assert!(!verify("wlt_other", seed));
        assert_eq!(current(seed), seed);

        // Rotate: the new token authenticates, the OLD seed no longer does.
        set(seed, "wlt_new_alpha");
        assert!(verify("wlt_new_alpha", seed));
        assert!(!verify(seed, seed), "old token must stop working after rotation");
        assert_eq!(current(seed), "wlt_new_alpha");
    }

    #[test]
    fn overlays_are_isolated_per_seed() {
        let a = "wlt_seed_iso_a";
        let b = "wlt_seed_iso_b";
        set(a, "wlt_rot_a");
        // Rotating `a` must not affect `b` (per-seed isolation → per-test isolation).
        assert!(verify("wlt_rot_a", a));
        assert!(verify(b, b));
        assert!(!verify("wlt_rot_a", b));
    }
}
