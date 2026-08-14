//! The single seam through which this crate opens an OS-keyring entry.
//!
//! Every secret this daemon keeps outside the encrypted DB — the vault root ([`super::vault`]), the
//! cloud account token ([`super::cloud::token`]), the per-agent channel key
//! ([`super::cloud::channel`]), the IP-relay tunnel credential (`super::relay::secret`) — opens its
//! entry here instead of calling [`keyring::Entry::new`] directly. Callers keep their own error
//! mapping (the four modules word their `LocalError`s differently), so this returns the raw
//! [`keyring::Result`].
//!
//! PRODUCTION: a pass-through to `keyring::Entry::new` — the real OS store (macOS Keychain, Windows
//! Credential Manager, Secret Service). Behaviour is exactly what it was before this seam existed;
//! there is NO env var or runtime switch that can divert a real secret away from the OS keyring.
//!
//! TESTS (`cfg(test)` — this crate's own unit tests only): the first entry opened installs a
//! process-global, in-MEMORY credential store as keyring-rs's default builder. Two reasons, both
//! load-bearing:
//!
//! 1. **Isolation.** Unit tests exercise real code paths that WRITE and DELETE keyring entries
//!    (`POST /v1/cloud/unlink` → `token::clear()` + `channel::clear()`; vault rotation dropping its
//!    in-flight root). Against the real Keychain those operate on the *developer's own* live
//!    `writ-cloud` entries — a `cargo test` run would silently unlink their desktop app.
//! 2. **Determinism.** `cargo test --lib` runs ~1.4k tests in one process across many threads. The
//!    macOS Keychain access-controls per item, and a burst of concurrent reads/deletes from an
//!    ad-hoc-signed test binary is answered with `errSecAuthFailed` ("Unable to obtain
//!    authorization for this operation") — which surfaced as a 500 from the unlink route ONLY
//!    under the full parallel run. Several tests here had grown `if matches!(.., Ok(None))` guards
//!    to dodge that; with an in-memory store they no longer have to skip.
//!
//! The store is process-global (not per-test) on purpose: that is what a real keyring is. A test
//! that needs its own slot addresses a distinct profile/account name, exactly as it must against
//! the OS store.
//!
//! SCOPE: `cfg(test)` covers this crate's unit tests. Integration tests (`tests/*.rs`) link the lib
//! without it and still see the real keyring — they only ever READ it (an unlinked
//! `GET /v1/cloud/status`), and that path already treats a keyring error as "assume present" rather
//! than failing, so it neither mutates the developer's Keychain nor flakes on it.

/// Open the keyring entry for `service`/`account`.
///
/// Thin wrapper over [`keyring::Entry::new`]; the only added behaviour is installing the in-memory
/// test store (`cfg(test)` builds only) before the first entry is created.
pub fn new_entry(service: &str, account: &str) -> keyring::Result<keyring::Entry> {
    #[cfg(test)]
    test_store::install();
    keyring::Entry::new(service, account)
}

#[cfg(test)]
pub use test_store::{fail_deletes, stop_failing_deletes};

/// In-memory credential store used in place of the OS keyring for this crate's unit tests.
#[cfg(test)]
mod test_store {
    use keyring::credential::{
        Credential, CredentialApi, CredentialBuilderApi, CredentialPersistence,
    };
    use std::any::Any;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Mutex, MutexGuard, Once, OnceLock};

    /// A credential's identity: `(target, service, account)` — the same triple keyring-rs uses to
    /// address an OS entry, so two `new_entry` calls with equal arguments see the same secret.
    type Key = (Option<String>, String, String);

    #[derive(Default)]
    struct Store {
        secrets: HashMap<Key, Vec<u8>>,
        /// Entries whose `delete_credential` is forced to fail — see [`fail_deletes`].
        deletes_fail: HashSet<Key>,
    }

    fn store() -> MutexGuard<'static, Store> {
        static STORE: OnceLock<Mutex<Store>> = OnceLock::new();
        STORE
            .get_or_init(|| Mutex::new(Store::default()))
            .lock()
            // A panicking test must not poison the store for every later test.
            .unwrap_or_else(|e| e.into_inner())
    }

    /// Make every `delete_credential` on `(service, account)` fail with the exact platform error
    /// macOS raises when the Keychain refuses an ACL-gated delete — so tests can drive the
    /// "the OS refused" branch of `cloud::link::unlink` without a locked keychain.
    ///
    /// STICKY until [`stop_failing_deletes`], deliberately: a one-shot injection would be racy,
    /// because this store is process-global and any concurrently running test that deletes the
    /// same entry could consume the injected failure first. Address an entry no other test
    /// touches (a unique `WRIT_PROFILE`) and clear it when done.
    pub fn fail_deletes(service: &str, account: &str) {
        install(); // the caller may inject before anything has opened an entry
        store().deletes_fail.insert((None, service.to_string(), account.to_string()));
    }

    /// Undo [`fail_deletes`] for `(service, account)`. Idempotent.
    pub fn stop_failing_deletes(service: &str, account: &str) {
        store().deletes_fail.remove(&(None, service.to_string(), account.to_string()));
    }

    /// Install the in-memory builder as keyring-rs's default, exactly once per process.
    ///
    /// [`keyring::set_default_credential_builder`] takes the crate's builder write lock, so it must
    /// land before any entry is created; [`Once`] blocks every other thread until it has. Since all
    /// entries in this crate come from [`super::new_entry`], no thread can race past it.
    pub fn install() {
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            keyring::set_default_credential_builder(Box::new(MemBuilder));
        });
    }

    #[derive(Debug)]
    struct MemBuilder;

    impl CredentialBuilderApi for MemBuilder {
        fn build(
            &self,
            target: Option<&str>,
            service: &str,
            user: &str,
        ) -> keyring::Result<Box<Credential>> {
            Ok(Box::new(MemCredential {
                key: (target.map(str::to_string), service.to_string(), user.to_string()),
            }))
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn persistence(&self) -> CredentialPersistence {
            CredentialPersistence::ProcessOnly
        }
    }

    #[derive(Debug)]
    struct MemCredential {
        key: Key,
    }

    impl CredentialApi for MemCredential {
        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            store().secrets.insert(self.key.clone(), secret.to_vec());
            Ok(())
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            store().secrets.get(&self.key).cloned().ok_or(keyring::Error::NoEntry)
        }

        /// Matches the OS stores (and the trait contract): deleting a credential that is not there
        /// is `NoEntry`, not success — the `clear()` helpers rely on that to report whether
        /// anything was actually removed.
        fn delete_credential(&self) -> keyring::Result<()> {
            let mut store = store();
            if store.deletes_fail.contains(&self.key) {
                // The wording is verbatim what macOS returns for an ACL-refused delete, so the
                // test exercises the exact string the production symptom carried.
                return Err(keyring::Error::PlatformFailure(Box::new(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Unable to obtain authorization for this operation.",
                ))));
            }
            if store.secrets.remove(&self.key).is_some() {
                Ok(())
            } else {
                Err(keyring::Error::NoEntry)
            }
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The store behaves like a keyring: absent → `NoEntry`, set → readable from a SEPARATE entry
    /// handle for the same (service, account), delete → gone, second delete → `NoEntry`.
    #[test]
    fn in_memory_store_round_trips_and_deletes_like_a_keyring() {
        let account = "keyring-store-round-trip";
        let e = new_entry("writ-test", account).unwrap();
        assert!(matches!(e.get_password(), Err(keyring::Error::NoEntry)), "absent entry → NoEntry");

        e.set_password("s3cret").unwrap();
        // A fresh handle must see the same value (a real keyring is a store, not per-entry state).
        let again = new_entry("writ-test", account).unwrap();
        assert_eq!(again.get_password().unwrap(), "s3cret");

        assert!(again.delete_credential().is_ok(), "first delete removes it");
        assert!(
            matches!(again.delete_credential(), Err(keyring::Error::NoEntry)),
            "second delete reports NoEntry so clear() can report 'nothing removed'"
        );
        assert!(matches!(e.get_password(), Err(keyring::Error::NoEntry)));
    }

    /// Distinct services/accounts address distinct secrets — the property the per-profile token and
    /// channel-key slots depend on for cross-account isolation.
    #[test]
    fn entries_are_scoped_by_service_and_account() {
        new_entry("writ-test-a", "same-account").unwrap().set_password("a").unwrap();
        new_entry("writ-test-b", "same-account").unwrap().set_password("b").unwrap();
        new_entry("writ-test-a", "other-account").unwrap().set_password("c").unwrap();

        assert_eq!(new_entry("writ-test-a", "same-account").unwrap().get_password().unwrap(), "a");
        assert_eq!(new_entry("writ-test-b", "same-account").unwrap().get_password().unwrap(), "b");
        assert_eq!(new_entry("writ-test-a", "other-account").unwrap().get_password().unwrap(), "c");
    }

    /// The injected delete failure is sticky, scoped to its own entry, and reversible — the three
    /// properties the unlink tests rely on to drive the "the OS refused" branch without racing
    /// other tests that share this process-global store.
    #[test]
    fn injected_delete_failure_is_sticky_scoped_and_reversible() {
        let e = new_entry("writ-test-fail", "victim").unwrap();
        let bystander = new_entry("writ-test-fail", "bystander").unwrap();
        e.set_password("x").unwrap();
        bystander.set_password("y").unwrap();

        fail_deletes("writ-test-fail", "victim");
        // Sticky: it does not get consumed by the first attempt.
        for _ in 0..3 {
            let err = e.delete_credential().expect_err("delete must be refused");
            assert!(
                err.to_string().contains("Unable to obtain authorization"),
                "carries the macOS refusal wording: {err}"
            );
        }
        // Reads and writes are untouched — only deletes are refused.
        assert_eq!(e.get_password().unwrap(), "x", "the secret survives a refused delete");
        // Scoped: a neighbouring account is unaffected.
        assert!(bystander.delete_credential().is_ok());

        stop_failing_deletes("writ-test-fail", "victim");
        assert!(e.delete_credential().is_ok(), "reversible");
    }

    /// Byte secrets (the vault's 32-byte root) round-trip unchanged, not just UTF-8 passwords.
    #[test]
    fn binary_secrets_round_trip() {
        let raw: [u8; 32] = [0xA5; 32];
        let e = new_entry("writ-test-binary", "root").unwrap();
        e.set_secret(&raw).unwrap();
        let back = new_entry("writ-test-binary", "root").unwrap().get_secret().unwrap();
        assert_eq!(back, raw.to_vec());
    }
}
