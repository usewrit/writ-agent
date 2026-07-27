//! SQLCipher cipher-gate — the CI proof that the encrypted local DB layer is genuinely linked.
//!
//! This is the integration-test counterpart to `crate::local::db`'s in-file unit tests. It is
//! ADDITIVE (net-new file) and only compiles under the `local` cargo feature, so the default
//! (cloud) `writ-agent` build is byte-unchanged and never sees it.
//!
//! Ground truth (PRODUCTION_READINESS.md + SECURITY_AND_ENTITLEMENTS_SPEC.md §1.5):
//!   The whole DB is SQLCipher-encrypted at rest and `crate::local::db::open` carries a LOAD-BEARING
//!   fail-closed assert: an empty `PRAGMA cipher_version` means sqlx linked PLAIN SQLite and
//!   `PRAGMA key` silently no-op'd, leaving the DB plaintext while appearing encrypted. If the
//!   `libsqlite3-sys` `bundled-sqlcipher-*` feature ever stops unifying onto sqlx's sqlite driver,
//!   the binary would happily write secrets in the clear. This gate FAILS the build before that ships.
//!
//! Two independent assertions, each sufficient on its own to catch a de-linked cipher:
//!   1. cipher_version is non-empty  — `db::assert_cipher_active` returns Err(CipherUnavailable)
//!      when `PRAGMA cipher_version` is empty (plain SQLite linked).
//!   2. wrong key errors             — re-opening an existing encrypted DB with the WRONG key must
//!      fail (the encrypted header won't decrypt). With plain SQLite linked, `PRAGMA key` is a
//!      no-op and the wrong-key open would SUCCEED — so a success here is a cipher regression.
//!   3. (belt) encrypted at rest     — the file must NOT start with the plaintext SQLite magic.
//!
//! Run locally:  cargo test --features local --test cipher_gate
//! Run in CI:    cargo test --features local local::            (the in-file db::tests)
//!               cargo test --features local --test cipher_gate (this file)

#![cfg(feature = "local")]

use writ_agent::local::db;

const GOOD_KEY: &str = "correct-horse-battery-staple-42";
const WRONG_KEY: &str = "this-is-not-the-key-totally-different";

/// (1) cipher_version non-empty AND (3) encrypted-at-rest header check.
#[tokio::test]
async fn cipher_version_is_non_empty_and_file_is_encrypted_at_rest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("cipher_gate.db");

    // `open` internally calls `assert_cipher_active`, so a successful open already proves a
    // non-empty cipher_version. We ALSO assert it explicitly here as the documented gate.
    let pool = db::open(&path, GOOD_KEY)
        .await
        .expect("open encrypted DB with correct key");

    db::assert_cipher_active(&pool)
        .await
        .expect("PRAGMA cipher_version must be non-empty (SQLCipher must be linked)");

    pool.close().await;

    // The on-disk file must be SQLCipher-encrypted: a plaintext SQLite DB begins with the
    // 16-byte magic "SQLite format 3\0". Its presence means the cipher silently no-op'd.
    let bytes = std::fs::read(&path).expect("read db file");
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "DB MUST be SQLCipher-encrypted at rest — found plaintext SQLite header (cipher de-linked)"
    );
}

/// (2) Opening an existing encrypted DB with the WRONG key must error.
#[tokio::test]
async fn wrong_key_fails_to_open_encrypted_db() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("wrong_key.db");

    // Create + key + migrate with the correct key, then close so the file exists encrypted.
    let pool = db::open(&path, GOOD_KEY)
        .await
        .expect("create encrypted DB with correct key");
    pool.close().await;

    // Re-open the SAME file with the WRONG key. SQLCipher cannot decrypt the header, so the
    // first access (cipher assert / integrity check / migrate) fails and `open` returns Err.
    // If plain SQLite were linked, `PRAGMA key` would be a no-op and this would WRONGLY succeed.
    let result = db::open(&path, WRONG_KEY).await;
    assert!(
        result.is_err(),
        "opening an encrypted DB with the WRONG key MUST fail — it succeeded, so SQLCipher is not \
         actually enforcing encryption (cipher de-linked)"
    );
}
