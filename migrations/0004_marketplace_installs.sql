-- Marketplace installs (consumer-owned, local-first protected executor).
--
-- One row per installed marketplace listing. The `sealed_recipe` column holds the listing's FROZEN
-- recipe snapshot, encrypted with THIS agent's per-agent Fernet channel key (the cloud seals it for
-- us at `/api/marketplace/installs/{slug}/sealed-recipe`). The PLAINTEXT recipe is NEVER stored: the
-- executor decrypts the sealed blob IN MEMORY at run time and discards it. The blob is additionally
-- protected at rest by the SQLCipher-encrypted DB (Layer A) and may be vault-field-wrapped (Layer B)
-- before storage. We persist listing METADATA (title/creator/price/free flag/input schema) for the
-- UI, but NEVER the steps.
--
-- Conventions match 0001/0002/0003: timestamps TEXT RFC3339 UTC; JSON fields TEXT; booleans INTEGER
-- 0/1; additive only.
CREATE TABLE installed_workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,              -- marketplace listing slug (natural key)
    listing_title TEXT,                     -- display title (metadata only)
    creator TEXT,                           -- creator display name/handle (metadata only)
    is_free INTEGER NOT NULL,               -- 1 = free listing (run locally, no charge) | 0 = paid (metered)
    price_micros INTEGER,                   -- creator price-per-run in micro-USD (paid listings; reflection only)
    proxy_cloud_id TEXT,                    -- cloud proxy workflow id created by the install endpoint
    sealed_recipe TEXT NOT NULL,            -- channel_key-Fernet-sealed (then optionally vault-sealed) recipe blob
    input_schema TEXT,                      -- JSON: BYO input/secret slots the consumer must attach
    installed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_run_at TEXT                        -- RFC3339 UTC of the most recent local run (NULL until first run)
);
