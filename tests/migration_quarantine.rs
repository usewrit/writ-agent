//! Migration + boot-policy quarantine conformance for the encrypted local DB.
//!
//! Integration counterpart to `crate::local::db`'s in-file unit tests. ADDITIVE (net-new file),
//! `local`-feature only, so the default (cloud) `writ-agent` build is byte-unchanged and never sees it.
//!
//! What this proves (LOCAL_BACKEND_SPEC.md §2 + SECURITY_AND_ENTITLEMENTS_SPEC.md §1.5):
//!   1. `db::open` on a fresh path KEYS + asserts the cipher is active + runs the forward-only
//!      migrations, leaving the schema present and queryable.
//!   2. The migrator records what it applied in `_sqlx_migrations`, and every table the
//!      `0001_init.sql` migration declares is present and selectable.
//!   3. The same encrypted DB re-opens cleanly (migrations are idempotent on a second `open`).
//!   4. BOOT POLICY — a foreign/corrupt file is handled per `db::open`'s fail-closed contract:
//!      a plaintext (foreign) SQLite file fails to open because the wrong key cannot decrypt the
//!      header (the cipher gate / integrity check trips before any plaintext is read).
//!
//! FOLLOW-UP: a dedicated `schema_version` column + an explicit quarantine/sidelining of a
//! corrupt-or-foreign DB (move-aside + fresh re-create, with an operator-visible marker) is the
//! data-lifecycle agent's task and is NOT present yet. Until it lands, the boot policy under test is
//! the CURRENT `db::open` behavior: fail closed (return `Err`) rather than open a non-decryptable or
//! integrity-failing file. The `foreign_db_is_rejected_by_boot_policy` test is written to assert that
//! current contract; when quarantine lands it should be tightened to assert the move-aside instead.
//!
//! Run:  cargo test --features local --test migration_quarantine

#![cfg(feature = "local")]

use sqlx::Row as _;
use writ_agent::local::db;

const KEY: &str = "migration-quarantine-test-key-9000";

/// Every table the `0001_init.sql` migration declares. Each must exist + be selectable after `open`.
/// (Kept in sync with `migrations/0001_init.sql`'s `CREATE TABLE` list.)
const EXPECTED_TABLES: &[&str] = &[
    "workflows",
    "runs",
    "run_artifacts",
    "targets",
    "target_selectors",
    "selector_extractors",
    "monitor_state",
    "changes",
    "uptime_checks",
    "automations",
    "automation_executions",
    "webhook_triggers",
    "personas",
    "vault_secrets",
    "stored_files",
    "local_api_keys",
    "config",
    "workflow_sessions",
];

/// (1)+(2) A fresh `open` keys + asserts cipher + migrates; the migrator records the applied
/// migration and every declared table is present and queryable.
#[tokio::test]
async fn open_applies_migrations_and_schema_is_present() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("migrate.db");

    let pool = db::open(&path, KEY).await.expect("open + migrate fresh encrypted DB");

    // The cipher must be genuinely active (open already asserts this; re-assert as the documented gate).
    db::assert_cipher_active(&pool)
        .await
        .expect("PRAGMA cipher_version must be non-empty");

    // The migrator records what it applied in `_sqlx_migrations`. At least the `0001_init` migration
    // must be present (this is how we prove migrations actually RAN, not just that tables happen to exist).
    let applied: i64 = sqlx::query("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .expect("the sqlx migrations bookkeeping table exists after open")
        .try_get(0)
        .expect("count column");
    assert!(applied >= 1, "at least the 0001_init migration must be recorded as applied");

    // Every declared table must exist in sqlite_master AND be selectable (catches a half-applied schema).
    for table in EXPECTED_TABLES {
        let in_master: i64 = sqlx::query(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        )
        .bind(table)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("query sqlite_master for {table}: {e}"))
        .try_get(0)
        .expect("count column");
        assert_eq!(in_master, 1, "table `{table}` must exist after migration");

        // A trivial count proves the table is actually queryable (not a stale/foreign object).
        sqlx::query(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("table `{table}` must be selectable: {e}"));
    }

    pool.close().await;

    // Belt-and-braces: the file is SQLCipher-encrypted at rest (no plaintext SQLite magic header).
    let bytes = std::fs::read(&path).expect("read db file");
    assert!(
        !bytes.starts_with(b"SQLite format 3\0"),
        "migrated DB must be SQLCipher-encrypted at rest"
    );
}

/// (3) Re-opening the SAME encrypted DB with the SAME key succeeds and the migrations are idempotent
/// (the migrator must not re-run or error on an already-migrated schema). This is the daemon-restart path.
#[tokio::test]
async fn reopen_is_idempotent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("reopen.db");

    // First open: create + migrate. Seed one row so we can confirm it survives the reopen.
    let pool = db::open(&path, KEY).await.expect("first open");
    sqlx::query("INSERT INTO config (key, value) VALUES ('boot_probe', 'v1')")
        .execute(&pool)
        .await
        .expect("seed a config row");
    let applied_first: i64 = sqlx::query("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    pool.close().await;

    // Second open: must succeed, NOT re-apply migrations, and the seeded row must still be there.
    let pool2 = db::open(&path, KEY).await.expect("reopen migrated encrypted DB");
    let applied_second: i64 = sqlx::query("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&pool2)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_eq!(
        applied_first, applied_second,
        "reopen must be idempotent — no extra migrations applied on the second open"
    );
    let probe: String = sqlx::query("SELECT value FROM config WHERE key = 'boot_probe'")
        .fetch_one(&pool2)
        .await
        .expect("seeded row survives reopen")
        .try_get(0)
        .unwrap();
    assert_eq!(probe, "v1", "data persists across reopen");
    pool2.close().await;
}

/// (4) BOOT POLICY — a foreign/plaintext (non-SQLCipher) file is REJECTED by `db::open`.
///
/// We write a real plaintext SQLite DB to a path, then ask `db::open` to open it WITH A KEY. Because
/// the file is not SQLCipher-encrypted, keying it makes the header undecryptable, so the cipher
/// gate / integrity check trips and `open` returns `Err` (fail-closed) rather than reading foreign
/// data as if it were ours. This is the current boot contract; when an explicit move-aside quarantine
/// lands (data-lifecycle agent), tighten this to assert the sidelined-file + fresh-DB behavior.
#[tokio::test]
async fn foreign_db_is_rejected_by_boot_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let foreign = dir.path().join("foreign.db");

    // Create a genuine PLAINTEXT SQLite DB (no key) at `foreign` with some unrelated content. Opening
    // it WITHOUT a key links plain sqlite via sqlx; we write a row then close so a real file exists.
    {
        use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
        let opts = SqliteConnectOptions::new()
            .filename(&foreign)
            .create_if_missing(true);
        let plain = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("create a plaintext foreign sqlite db");
        sqlx::query("CREATE TABLE not_ours (x INTEGER)")
            .execute(&plain)
            .await
            .expect("write to the foreign db");
        plain.close().await;
    }

    // Sanity: the foreign file really IS a plaintext SQLite DB (has the magic header). If this ever
    // fails, the "foreign" precondition is wrong and the rejection below would be meaningless.
    let bytes = std::fs::read(&foreign).expect("read foreign db");
    assert!(
        bytes.starts_with(b"SQLite format 3\0"),
        "precondition: the foreign file must be a plaintext SQLite DB"
    );

    // Boot policy: opening this foreign/plaintext file WITH OUR KEY must FAIL closed — keying a
    // plaintext header makes it undecryptable, so the cipher/integrity gate trips before any foreign
    // data is trusted. With plain SQLite mistakenly linked, `PRAGMA key` would no-op and this would
    // WRONGLY succeed — so a success here is also a cipher-de-link regression.
    let result = db::open(&foreign, KEY).await;
    assert!(
        result.is_err(),
        "boot policy MUST reject a foreign/plaintext DB when opened with our key (fail-closed)"
    );
}
