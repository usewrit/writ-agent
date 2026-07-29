-- SAVED CRAWLS — a re-runnable crawl configuration with a stable handle.
--
-- A `crawl_jobs` row is one RUN: its settings live on the row and its id dies with that run. That
-- left a crawl with no stable identity, so it could not be exposed as a callable API the way a
-- workflow can — the id would change on every re-crawl — and "re-crawl with the same settings"
-- meant refilling a form.
--
-- `crawl_definitions` is that handle. It owns the saved settings as ONE JSON-TEXT blob (the same
-- shape the local `POST /v1/crawl` body takes, so a new crawl option cannot silently fall out of a
-- hand-maintained column mirror), plus a slug. `crawl_jobs.definition_id` points every run back at
-- the config that launched it, so runs become the definition's history — which is what makes
-- `max_age` answerable: "has this saved crawl completed recently enough to just hand over the data?"
--
-- Local scope, same as crawl_jobs: no tenant/user columns. JSON columns are TEXT (callers serde
-- them); timestamps are TEXT RFC3339 UTC (matches 0008_concierge_sessions.sql).
CREATE TABLE crawl_definitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,                                  -- human label, e.g. 'Docs — example.com'
    slug TEXT NOT NULL UNIQUE,                           -- URL-safe stable ref used by the callable endpoint
    description TEXT,

    config TEXT NOT NULL,                                -- JSON: the saved StartCrawlRequest body
    seed_url TEXT NOT NULL,                              -- mirrored from config so listing needs no JSON parse

    -- Freshness applied when a caller omits max_age. NULL = no default, i.e. an unqualified call
    -- always re-crawls — the safe behavior for a caller who never opted into reuse.
    default_max_age_seconds INTEGER,

    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT,
    last_run_at TEXT                                     -- last dispatch from this definition (any outcome)
);

CREATE INDEX ix_crawl_definitions_created ON crawl_definitions(created_at DESC);

-- Lineage on the run table. NULL for every pre-existing (ad-hoc) crawl, so the column is additive
-- and needs no backfill. No FK: SQLite cannot attach one to an existing table without a full
-- rebuild, and a dangling id here only ever fails to match a freshness lookup — which falls through
-- to a normal crawl.
ALTER TABLE crawl_jobs ADD COLUMN definition_id INTEGER;

-- The freshness lookup: newest completed run for a definition. Without it every max_age-qualified
-- call scans that definition's whole run history.
CREATE INDEX ix_crawl_jobs_definition_completed
    ON crawl_jobs(definition_id, status, completed_at DESC);
