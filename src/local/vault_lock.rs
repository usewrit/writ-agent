//! Vault app-lock — an opt-in, desktop-only passphrase gate layered OVER the keyring-rooted vault.
//!
//! SECURITY_AND_ENTITLEMENTS_SPEC §1.3: `unlock_secret = root XOR Argon2id(passphrase, salt)`
//! (Argon2id m=256 MiB / t=3 / p=1, with a low-RAM capability probe + a downgrade tier). The
//! keyring root AND the passphrase are BOTH required — the passphrase only ever *strengthens* the
//! at-rest protection; it never replaces the keyring root and it NEVER re-keys the SQLCipher DB
//! (that is rotation's job, see `vault_rotate`). When the lock is engaged and currently LOCKED, the
//! secret-touching routes (`/v1/secrets`, runs that resolve secrets, `/v1/cloud`) return
//! `423 Locked`.
//!
//! ## How the wrap authenticates a passphrase (no plaintext verifier)
//! Enabling the lock stores `wrap = root XOR Argon2id(pp, salt)` plus the random `salt` and the cost
//! tier in the `config` KV table (none of these reveal the root: the wrap is the root XORed with a
//! 256-bit derived key, the salt is public). `unlock(pp)` re-derives `Argon2id(pp, salt)`, XORs it
//! back into the wrap to recover a CANDIDATE root, and constant-time compares it to the live keyring
//! root. A correct passphrase reproduces the root exactly → unlock; a wrong one yields garbage →
//! reject. The candidate root is never logged and is dropped (zeroized) immediately.
//!
//! ## State machine
//! `Disabled` (no passphrase set — the default; "lose the keyring = lose the data"), or enabled and
//! either `Unlocked { last_activity }` or `Locked`. A relock is driven by an idle timeout (no
//! secret-touching activity for N seconds) or an explicit `lock()` (sleep / screen-lock hooks call
//! it). `touch()` bumps `last_activity` on every authenticated secret access so an active session
//! stays open. **Headless `writ-agentd` never engages the passphrase** — the daemon process keeps
//! the lock `Disabled`/`Unlocked` so launchd/systemd auto-restart is never blocked.
//!
//! Net-new Rust in this crate (behind the `local` feature). NEVER ported from Python.

use std::sync::Arc;
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};

use base64::Engine;
use rand::RngCore;
use sqlx::SqlitePool;
use zeroize::Zeroize;

use crate::local::error::{LocalError, LocalResult};
use crate::local::store::config_kv;
use crate::local::vault::{RootKey, Vault};

/// `config` KV keys for the persisted (non-secret) app-lock material. The wrap is the root XORed
/// with a 256-bit Argon2id key (does not reveal the root); the salt is public; the tier records the
/// Argon2id cost so unlock re-derives identically even after a low-RAM downgrade.
const CFG_WRAP: &str = "vault_lock.wrap_b64";
const CFG_SALT: &str = "vault_lock.salt_b64";
const CFG_M_COST: &str = "vault_lock.m_cost_kib";
const CFG_T_COST: &str = "vault_lock.t_cost";
const CFG_P_COST: &str = "vault_lock.p_cost";

/// Argon2id cost tiers (SECURITY_AND_ENTITLEMENTS_SPEC §1.3). The default targets 256 MiB / t=3 /
/// p=1; a machine that cannot allocate that much falls back to the downgrade tier (64 MiB) so the
/// lock still functions on constrained hardware. The chosen tier is persisted so unlock matches.
pub const ARGON2_M_COST_FULL: u32 = 256 * 1024; // 256 MiB, in KiB
pub const ARGON2_M_COST_LOW: u32 = 64 * 1024; //  64 MiB, in KiB
pub const ARGON2_T_COST: u32 = 3;
pub const ARGON2_P_COST: u32 = 1;

/// Default idle relock window (seconds) when the lock is engaged. The setter clamps to a sane range.
pub const DEFAULT_IDLE_SECS: u64 = 15 * 60;

/// The runtime lock state. `Disabled` is the at-rest default (no passphrase configured).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockMode {
    /// No app-lock passphrase is configured — secret routes are always allowed.
    Disabled,
    /// Passphrase configured and the session is unlocked (carries the last-activity instant).
    Unlocked,
    /// Passphrase configured and the session is locked — secret routes return 423.
    Locked,
}

#[derive(Debug)]
struct Machine {
    mode: LockMode,
    /// Wall-clock-free monotonic marker for idle relock; only meaningful when `Unlocked`.
    last_activity: Instant,
    /// Idle relock window. A relock fires once `last_activity` is older than this.
    idle: Duration,
}

/// Cheaply-clonable shared handle to the app-lock state.
pub type SharedVaultLock = Arc<VaultLock>;

/// Process-global app-lock handle. The runtime lock state (Unlocked/Locked + idle timer) must
/// persist across HTTP requests within a daemon process, but threading a new field through
/// `AppState` would ripple across every construction site (and conflict with parallel work). Instead
/// the lock lives in a single process-global slot — the SAME pattern `cloud::link` uses for its
/// in-flight device-flow slot. `lifecycle::bootstrap` initializes it once at startup; the
/// secret-route guard and the `/v1/vault/*` handlers read it via [`global`].
static GLOBAL_LOCK: OnceLock<SharedVaultLock> = OnceLock::new();

/// Install the process-global app-lock (idempotent: the FIRST install wins; later calls are no-ops
/// and return the already-installed handle). Called once from `lifecycle::bootstrap`.
pub fn install_global(lock: SharedVaultLock) -> SharedVaultLock {
    let _ = GLOBAL_LOCK.set(lock);
    GLOBAL_LOCK.get().expect("vault lock global set above").clone()
}

/// The process-global app-lock, defaulting to a permanently-disabled lock when none was installed
/// (tests, headless paths, and any code path that runs before `bootstrap`). This guarantees the
/// secret-route guard is fail-OPEN ONLY when no lock was ever configured — a configured lock is
/// always installed at bootstrap and starts Locked.
pub fn global() -> SharedVaultLock {
    GLOBAL_LOCK.get_or_init(VaultLock::disabled).clone()
}

/// The app-lock guard. Holds the runtime state machine; the durable wrap/salt/tier live in `config`.
pub struct VaultLock {
    inner: RwLock<Machine>,
}

/// A non-secret snapshot of the lock for the `/v1/vault/status` route and the UI.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LockStatus {
    /// Is an app-lock passphrase configured at all?
    pub enabled: bool,
    /// Is the vault currently locked (only meaningful when `enabled`)?
    pub locked: bool,
    /// The idle relock window, in seconds (0 when disabled).
    pub idle_timeout_secs: u64,
}

impl VaultLock {
    /// Build the runtime lock from the persisted `config` state. If a wrap is present the daemon
    /// starts `Locked` (a fresh process must re-authenticate); otherwise the lock is `Disabled`.
    /// Headless callers that must never block can ignore this and use [`VaultLock::disabled`].
    pub async fn load(db: &SqlitePool) -> LocalResult<SharedVaultLock> {
        let configured = config_kv::get(db, CFG_WRAP).await?.is_some();
        let mode = if configured { LockMode::Locked } else { LockMode::Disabled };
        Ok(Arc::new(Self {
            inner: RwLock::new(Machine { mode, last_activity: Instant::now(), idle: Duration::from_secs(DEFAULT_IDLE_SECS) }),
        }))
    }

    /// A lock that is permanently disabled (no passphrase) — for tests and headless `writ-agentd`,
    /// which must never block launchd/systemd auto-restart on a human passphrase prompt.
    pub fn disabled() -> SharedVaultLock {
        Arc::new(Self {
            inner: RwLock::new(Machine { mode: LockMode::Disabled, last_activity: Instant::now(), idle: Duration::from_secs(DEFAULT_IDLE_SECS) }),
        })
    }

    /// True iff secret-touching routes must be refused right now. Disabled ⇒ never; enabled ⇒ true
    /// when explicitly locked OR when the idle window has elapsed since the last activity (lazy
    /// relock — checked on read so we need no background timer thread).
    pub fn is_locked(&self) -> bool {
        let relock = {
            let g = self.inner.read().expect("vault lock poisoned");
            match g.mode {
                LockMode::Disabled => return false,
                LockMode::Locked => return true,
                LockMode::Unlocked => g.last_activity.elapsed() >= g.idle,
            }
        };
        if relock {
            // Idle elapsed → flip to Locked (write lock) and report locked.
            let mut g = self.inner.write().expect("vault lock poisoned");
            if g.mode == LockMode::Unlocked && g.last_activity.elapsed() >= g.idle {
                g.mode = LockMode::Locked;
            }
            return g.mode == LockMode::Locked;
        }
        false
    }

    /// The guard the secret-route seam calls: `Ok(())` when access is allowed, `Err(Locked)` (423)
    /// when the vault is locked. Does NOT bump activity (call [`VaultLock::touch`] after a successful
    /// secret access so the idle timer reflects real use).
    pub fn guard(&self) -> LocalResult<()> {
        if self.is_locked() {
            Err(LocalError::Locked)
        } else {
            Ok(())
        }
    }

    /// Bump the idle timer after a successful authenticated secret access (keeps an active session
    /// open). No-op when disabled/locked.
    pub fn touch(&self) {
        let mut g = self.inner.write().expect("vault lock poisoned");
        if g.mode == LockMode::Unlocked {
            g.last_activity = Instant::now();
        }
    }

    /// Explicitly relock now (sleep / screen-lock / manual "Lock" button). No-op when disabled.
    pub fn lock(&self) {
        let mut g = self.inner.write().expect("vault lock poisoned");
        if g.mode != LockMode::Disabled {
            g.mode = LockMode::Locked;
        }
    }

    /// A non-secret status snapshot for the API/UI.
    pub fn status(&self) -> LockStatus {
        // Reading via is_locked() so a lazily-elapsed idle window is reflected.
        let locked = self.is_locked();
        let g = self.inner.read().expect("vault lock poisoned");
        LockStatus {
            enabled: g.mode != LockMode::Disabled,
            locked,
            idle_timeout_secs: if g.mode == LockMode::Disabled { 0 } else { g.idle.as_secs() },
        }
    }

    /// Set the idle relock window (clamped to 1 minute .. 24 hours). Persisted only in-process; the
    /// caller may surface it via config if it should survive a restart.
    pub fn set_idle_secs(&self, secs: u64) {
        let clamped = secs.clamp(60, 24 * 3600);
        let mut g = self.inner.write().expect("vault lock poisoned");
        g.idle = Duration::from_secs(clamped);
    }

    /// Probe how much Argon2id memory this machine can sustain and return the cost tier to use.
    /// Tries the full 256 MiB tier with a throwaway derivation; on failure (allocation refused on a
    /// constrained box) it downgrades to 64 MiB. Returns `(m_cost_kib, t_cost, p_cost)`.
    pub fn probe_cost_tier() -> (u32, u32, u32) {
        // A one-shot derivation over a dummy salt; success means the allocation is sustainable.
        let probe = |m: u32| Vault::argon2id_key(b"probe", &[0u8; 16], m, ARGON2_T_COST, ARGON2_P_COST).is_ok();
        if probe(ARGON2_M_COST_FULL) {
            (ARGON2_M_COST_FULL, ARGON2_T_COST, ARGON2_P_COST)
        } else {
            (ARGON2_M_COST_LOW, ARGON2_T_COST, ARGON2_P_COST)
        }
    }

    /// Whether an app-lock passphrase is already persisted (a wrap exists in `config`). Used by the
    /// enable path to distinguish first-time setup (allowed) from OVERWRITING an existing lock (which
    /// must first prove control of the current lock — see the `/v1/vault/enable` handler).
    pub async fn is_configured(db: &SqlitePool) -> LocalResult<bool> {
        Ok(config_kv::get(db, CFG_WRAP).await?.is_some())
    }

    /// Enable the app-lock with `passphrase`: derive the Argon2id key over a fresh random salt, store
    /// `wrap = root XOR key` + the salt + the chosen cost tier in `config`, and flip the runtime
    /// state to `Unlocked` (the enabling caller is, by definition, authenticated). Refuses a too-short
    /// passphrase. NEVER logs the passphrase, the key, or the wrap.
    ///
    /// The cost tier is chosen via [`VaultLock::probe_cost_tier`] so a low-RAM machine still works.
    pub async fn enable(&self, db: &SqlitePool, vault: &Vault, passphrase: &str) -> LocalResult<()> {
        if passphrase.chars().count() < 6 {
            return Err(LocalError::BadRequest("passphrase must be at least 6 characters".into()));
        }
        let (m, t, p) = Self::probe_cost_tier();
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let key = Vault::argon2id_key(passphrase.as_bytes(), &salt, m, t, p)?;
        let root = vault.root_copy();
        let wrap = root.xor(key.as_bytes()); // root XOR Argon2id(pp, salt)

        config_kv::set(db, CFG_WRAP, &b64(wrap.as_bytes())).await?;
        config_kv::set(db, CFG_SALT, &b64(&salt)).await?;
        config_kv::set(db, CFG_M_COST, &m.to_string()).await?;
        config_kv::set(db, CFG_T_COST, &t.to_string()).await?;
        config_kv::set(db, CFG_P_COST, &p.to_string()).await?;
        salt.zeroize();

        let mut g = self.inner.write().expect("vault lock poisoned");
        g.mode = LockMode::Unlocked;
        g.last_activity = Instant::now();
        tracing::info!(m_cost_kib = m, t_cost = t, p_cost = p, "vault app-lock enabled");
        Ok(())
    }

    /// Disable the app-lock entirely (clears the persisted wrap/salt/tier and flips to `Disabled`).
    /// The caller must already be unlocked/authenticated; this is the "turn off the PIN" path.
    pub async fn disable(&self, db: &SqlitePool) -> LocalResult<()> {
        for k in [CFG_WRAP, CFG_SALT, CFG_M_COST, CFG_T_COST, CFG_P_COST] {
            let _ = config_kv::delete(db, k).await;
        }
        let mut g = self.inner.write().expect("vault lock poisoned");
        g.mode = LockMode::Disabled;
        tracing::info!("vault app-lock disabled");
        Ok(())
    }

    /// Attempt to unlock with `passphrase`. Re-derives the Argon2id key over the stored salt+tier,
    /// recovers the candidate root from the wrap, and constant-time compares it to the live keyring
    /// root. On match the state flips to `Unlocked`; on mismatch it returns `Unauthorized` and stays
    /// locked. A no-op `Ok(())` when the lock is `Disabled`. NEVER logs the passphrase or any key.
    pub async fn unlock(&self, db: &SqlitePool, vault: &Vault, passphrase: &str) -> LocalResult<()> {
        // Disabled → nothing to unlock.
        {
            let g = self.inner.read().expect("vault lock poisoned");
            if g.mode == LockMode::Disabled {
                return Ok(());
            }
        }
        let wrap_b64 = config_kv::get(db, CFG_WRAP)
            .await?
            .ok_or_else(|| LocalError::Internal("vault lock: missing wrap".into()))?;
        let salt_b64 = config_kv::get(db, CFG_SALT)
            .await?
            .ok_or_else(|| LocalError::Internal("vault lock: missing salt".into()))?;
        let m = config_kv::get(db, CFG_M_COST).await?.and_then(|s| s.parse().ok()).unwrap_or(ARGON2_M_COST_FULL);
        let t = config_kv::get(db, CFG_T_COST).await?.and_then(|s| s.parse().ok()).unwrap_or(ARGON2_T_COST);
        let p = config_kv::get(db, CFG_P_COST).await?.and_then(|s| s.parse().ok()).unwrap_or(ARGON2_P_COST);

        let wrap = unb64_32(&wrap_b64)?;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt_b64.as_bytes())
            .map_err(|_| LocalError::Internal("vault lock: bad salt".into()))?;

        let key = Vault::argon2id_key(passphrase.as_bytes(), &salt, m, t, p)?;
        let candidate = RootKey::from_bytes(wrap).xor(key.as_bytes()); // wrap XOR key = candidate root
        let live = vault.root_copy();
        if !candidate.ct_eq(&live) {
            tracing::warn!("vault unlock failed (bad passphrase)");
            return Err(LocalError::Unauthorized);
        }

        let mut g = self.inner.write().expect("vault lock poisoned");
        g.mode = LockMode::Unlocked;
        g.last_activity = Instant::now();
        tracing::info!("vault unlocked");
        Ok(())
    }
}

/// base64-encode raw bytes (standard alphabet).
fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Decode a base64 string into a fixed 32-byte array (the wrap is always 32 bytes).
fn unb64_32(s: &str) -> LocalResult<[u8; 32]> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|_| LocalError::Internal("vault lock: bad wrap base64".into()))?;
    if raw.len() != 32 {
        return Err(LocalError::Internal("vault lock: wrap is not 32 bytes".into()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    /// A fresh encrypted DB + headless vault for lock tests.
    async fn fixture() -> (tempfile::TempDir, SqlitePool, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::load_or_create(dir.path(), false).unwrap();
        let pool = db::open(&dir.path().join("t.db"), &vault.db_key_hex()).await.unwrap();
        (dir, pool, vault)
    }

    // Use the cheapest Argon2id tier in tests so they stay fast (the probe would pick 256 MiB).
    async fn enable_fast(lock: &VaultLock, db: &SqlitePool, vault: &Vault, pp: &str) {
        // Mirror `enable` but force the low tier for speed; production uses `enable`.
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let m = 8 * 1024; // 8 MiB — fast, still a valid Argon2id tier
        let key = Vault::argon2id_key(pp.as_bytes(), &salt, m, ARGON2_T_COST, ARGON2_P_COST).unwrap();
        let wrap = vault.root_copy().xor(key.as_bytes());
        config_kv::set(db, CFG_WRAP, &b64(wrap.as_bytes())).await.unwrap();
        config_kv::set(db, CFG_SALT, &b64(&salt)).await.unwrap();
        config_kv::set(db, CFG_M_COST, &m.to_string()).await.unwrap();
        config_kv::set(db, CFG_T_COST, &ARGON2_T_COST.to_string()).await.unwrap();
        config_kv::set(db, CFG_P_COST, &ARGON2_P_COST.to_string()).await.unwrap();
        let mut g = lock.inner.write().unwrap();
        g.mode = LockMode::Unlocked;
    }

    #[tokio::test]
    async fn disabled_lock_never_blocks() {
        let lock = VaultLock::disabled();
        assert!(!lock.is_locked());
        assert!(lock.guard().is_ok());
        assert!(!lock.status().enabled);
        // lock()/touch() are no-ops on a disabled lock.
        lock.lock();
        assert!(!lock.is_locked());
    }

    #[tokio::test]
    async fn enable_lock_unlock_roundtrip() {
        let (_dir, pool, vault) = fixture().await;
        let lock = VaultLock::load(&pool).await.unwrap(); // Disabled (no wrap yet)
        assert!(!lock.status().enabled);

        enable_fast(&lock, &pool, &vault, "correct horse").await;
        assert!(lock.status().enabled);
        assert!(!lock.is_locked(), "enabling leaves the session unlocked");

        // Explicit lock → guard refuses with 423.
        lock.lock();
        assert!(lock.is_locked());
        assert!(matches!(lock.guard(), Err(LocalError::Locked)));

        // Wrong passphrase stays locked (Unauthorized, NOT a panic).
        let err = lock.unlock(&pool, &vault, "wrong passphrase").await.unwrap_err();
        assert!(matches!(err, LocalError::Unauthorized));
        assert!(lock.is_locked());

        // Correct passphrase unlocks.
        lock.unlock(&pool, &vault, "correct horse").await.unwrap();
        assert!(!lock.is_locked());
        assert!(lock.guard().is_ok());
    }

    #[tokio::test]
    async fn fresh_process_starts_locked_when_configured() {
        let (_dir, pool, vault) = fixture().await;
        // Configure a lock, then simulate a daemon restart by loading a fresh VaultLock.
        let lock = VaultLock::load(&pool).await.unwrap();
        enable_fast(&lock, &pool, &vault, "pw-123456").await;

        let reloaded = VaultLock::load(&pool).await.unwrap();
        assert!(reloaded.status().enabled);
        assert!(reloaded.is_locked(), "a fresh process must re-authenticate");

        // And it can be unlocked with the same passphrase across the "restart".
        reloaded.unlock(&pool, &vault, "pw-123456").await.unwrap();
        assert!(!reloaded.is_locked());
    }

    #[tokio::test]
    async fn idle_window_relocks_lazily() {
        let (_dir, pool, vault) = fixture().await;
        let lock = VaultLock::load(&pool).await.unwrap();
        enable_fast(&lock, &pool, &vault, "idle-pass").await;
        // Force an immediate idle window so the lazy relock fires on the next read.
        lock.set_idle_secs(60);
        {
            let mut g = lock.inner.write().unwrap();
            g.idle = Duration::from_millis(0);
            g.last_activity = Instant::now() - Duration::from_secs(1);
        }
        assert!(lock.is_locked(), "an elapsed idle window relocks on read");
    }

    #[tokio::test]
    async fn locked_lock_refuses_management_guard() {
        // AC-1: the /v1/vault/{disable,recovery/generate,enable-overwrite} handlers gate on
        // `guard()?`. When the vault is enabled+locked that guard MUST refuse (423 Locked) so a
        // loopback-bearer caller cannot turn the lock off — or overwrite it — without the PIN.
        let (_dir, pool, vault) = fixture().await;
        let lock = VaultLock::load(&pool).await.unwrap();
        enable_fast(&lock, &pool, &vault, "pin-123456").await;
        assert!(VaultLock::is_configured(&pool).await.unwrap(), "a wrap is persisted");

        lock.lock();
        assert!(lock.is_locked());
        assert!(matches!(lock.guard(), Err(LocalError::Locked)), "locked → management refused");

        // Once unlocked, the same guard admits the management operation.
        lock.unlock(&pool, &vault, "pin-123456").await.unwrap();
        assert!(lock.guard().is_ok(), "unlocked → management allowed");
    }

    #[tokio::test]
    async fn is_configured_tracks_persisted_wrap() {
        let (_dir, pool, vault) = fixture().await;
        let lock = VaultLock::load(&pool).await.unwrap();
        assert!(!VaultLock::is_configured(&pool).await.unwrap(), "no wrap yet → first-time enable allowed");
        enable_fast(&lock, &pool, &vault, "pin-123456").await;
        assert!(VaultLock::is_configured(&pool).await.unwrap(), "wrap present → overwrite is gated");
    }

    #[tokio::test]
    async fn disable_clears_persisted_state() {
        let (_dir, pool, vault) = fixture().await;
        let lock = VaultLock::load(&pool).await.unwrap();
        enable_fast(&lock, &pool, &vault, "to-remove").await;
        assert!(config_kv::get(&pool, CFG_WRAP).await.unwrap().is_some());

        lock.disable(&pool).await.unwrap();
        assert!(config_kv::get(&pool, CFG_WRAP).await.unwrap().is_none());
        assert!(!lock.status().enabled);
        assert!(!lock.is_locked());
    }
}
