-- APP_META — the auto-update version record (AUTO_UPDATE.md §3 steps 6/12/13). A single-row
-- (`id=1`) table holding the MONOTONIC installed-version state the update policy reads on every
-- verify pass and advances after a successful apply. Kept OUT of the `config` KV so the typed
-- version fields (installed/prior version, release date, post-update health-fail counter) can't be
-- stomped by an unrelated string cursor and so `version_record.rs` owns a well-typed row.
--
-- SECURITY: no secret material here — versions, an RFC3339 release timestamp, and a health-fail
-- count only. The row lives in the SQLCipher-encrypted DB like everything else, so it inherits
-- encryption at rest, but it is a plain integrity/rollback record, not a credential.
--
-- Downgrade protection anchor: `installed_version` is the value AUTO_UPDATE.md §3 step 6 compares a
-- candidate manifest's `version` against (NOT whatever the manifest claims). `prior_version` retains
-- EXACTLY ONE previous version for the client-local rollback (§3 step 12, PROD-7).
CREATE TABLE app_meta (
    id INTEGER PRIMARY KEY CHECK (id = 1),               -- singleton row
    -- The version the running app was installed as. Seeded to the compiled-in CARGO_PKG_VERSION on
    -- first boot; advanced ONLY after a verified update applies + passes its post-update self-check.
    installed_version TEXT,
    -- The single retained prior version (for one-step client-local rollback). NULL until the first
    -- update. Never keep more than one — rollback restores exactly the last-good build.
    prior_version TEXT,
    -- RFC3339 UTC release timestamp of the installed build (the manifest's signed `released_at`).
    -- Replay/staleness anchor: §3 step 5 rejects a manifest whose `released_at` predates THIS.
    installed_build_released_at TEXT,
    -- Consecutive post-update self-check failures since the last success. Reset to 0 on a healthy
    -- boot; auto-rollback fires once it reaches the configured ceiling (rollback.rs).
    health_fail_count INTEGER NOT NULL DEFAULT 0,
    -- Bookkeeping for logging/audit (never trusted for gating).
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Materialize the singleton row so `version_record.rs` can UPDATE it unconditionally (it also
-- upserts defensively, but seeding here keeps the first read simple). Versions start NULL so the
-- first boot stamps them from the compiled-in CARGO_PKG_VERSION.
INSERT INTO app_meta (id, installed_version, prior_version, installed_build_released_at, health_fail_count)
VALUES (1, NULL, NULL, NULL, 0);
