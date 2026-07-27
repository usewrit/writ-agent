-- DRAGNET LOCAL CRAWL — one row per whole-site crawl run on THIS machine.
--
-- The desktop twin of the cloud `crawl_jobs` model (backend/models/crawl_job.py), stripped to the
-- LOCAL scope: there is no cloud fleet / Redis frontier / tenant. One crawl maps a site (sitemap +
-- robots + link graph) and fetches every in-scope page with a bounded local worker pool (HTTP-first,
-- browser fallback), extracting clean markdown per page (or replaying a prebuilt extractor). The
-- live URL frontier + visited-set live in-process (services/crawl); this durable row is the
-- control-plane record the UI + the "Scribe" concierge poll. Each page's extracted data lands under
-- the synthetic per-crawl workflow (`workflow_id`) so it aggregates through the normal Workflow Data
-- API + lineage dedup — one queryable dataset. JSON columns are TEXT (callers serde them); timestamps
-- are TEXT RFC3339 UTC (matches 0008_concierge_sessions.sql). No tenant/user columns locally.
CREATE TABLE crawl_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,                                  -- human label, e.g. 'Dragnet: docs.example.com'
    seed_url TEXT NOT NULL,                              -- entry URL the crawl starts from

    -- Scope --------------------------------------------------------------------
    include_paths TEXT NOT NULL DEFAULT '[]',            -- JSON array: regex allowlist for URL paths (empty = all)
    exclude_paths TEXT NOT NULL DEFAULT '[]',            -- JSON array: regex denylist for URL paths
    max_depth INTEGER NOT NULL DEFAULT 3,                -- link-discovery depth; seed + sitemap pages are depth 0
    same_domain INTEGER NOT NULL DEFAULT 1,              -- 0/1: only follow links on the seed's registrable domain
    allow_subdomains INTEGER NOT NULL DEFAULT 1,         -- 0/1: follow links on subdomains of the seed domain

    -- Extraction ---------------------------------------------------------------
    extract_mode TEXT NOT NULL DEFAULT 'markdown',       -- markdown | schema
    extract_schema TEXT,                                 -- JSON: schema-mode extractor spec (row_selector + fields)

    -- Authenticated crawl ------------------------------------------------------
    persona_id INTEGER REFERENCES personas(id) ON DELETE SET NULL,

    -- Politeness / budget ------------------------------------------------------
    respect_robots INTEGER NOT NULL DEFAULT 1,           -- 0/1: honor robots.txt per discovered URL
    delay_ms INTEGER NOT NULL DEFAULT 250,               -- politeness delay between page fetches
    max_concurrent INTEGER NOT NULL DEFAULT 4,           -- ceiling on pages fetched at once (local worker cap)
    page_budget INTEGER NOT NULL DEFAULT 500,            -- hard ceiling on total pages fetched

    -- Aggregation --------------------------------------------------------------
    workflow_id INTEGER REFERENCES workflows(id) ON DELETE SET NULL,   -- synthetic per-crawl workflow (Data API)
    concierge_session_id INTEGER,                        -- ConciergeSession (Scribe) that launched this crawl, if any

    -- Lifecycle + live counters -----------------------------------------------
    status TEXT NOT NULL DEFAULT 'queued',               -- queued|mapping|crawling|completed|failed|cancelled|stopping
    pages_discovered INTEGER NOT NULL DEFAULT 0,
    pages_done INTEGER NOT NULL DEFAULT 0,
    pages_failed INTEGER NOT NULL DEFAULT 0,
    pages_skipped INTEGER NOT NULL DEFAULT 0,            -- admitted then dropped (robots/scope/dupe at fetch time)
    workers_active INTEGER NOT NULL DEFAULT 0,           -- live worker count (for the UI meter)
    current_depth INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,         -- boolean 0/1; the crawl loop observes it and drains

    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT,
    started_at TEXT,
    completed_at TEXT
);
CREATE INDEX ix_crawl_jobs_status_created ON crawl_jobs(status, created_at);
