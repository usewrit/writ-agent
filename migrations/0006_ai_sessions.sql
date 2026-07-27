-- AI SESSIONS — the server-side autonomous AI browser-agent runs (form-filler loop; the Rust port
-- of the Python recorder's `ai_generate_workflow`). One row per session: an ai_session can run
-- standalone (via /v1/ai-sessions/start) or inside an automation flow. Optionally linked to the run
-- and/or workflow that spawned it. JSON fields are TEXT; timestamps TEXT RFC3339 UTC; statuses mirror
-- the loop's `SessionStatus` (running|complete|blocked|max_steps|stuck|error).
CREATE TABLE ai_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    workflow_id INTEGER REFERENCES workflows(id) ON DELETE SET NULL,
    name TEXT,
    goal TEXT NOT NULL,
    entry_url TEXT,
    status TEXT NOT NULL DEFAULT 'running',              -- running|complete|blocked|max_steps|stuck|error
    step_count INTEGER NOT NULL DEFAULT 0,
    max_steps INTEGER NOT NULL DEFAULT 20,
    available_data TEXT DEFAULT '{}',                    -- JSON: keys/values shown to the model
    fill_data TEXT DEFAULT '{}',                         -- JSON: actual values to fill (secrets decrypted)
    filled_fields TEXT DEFAULT '[]',                     -- JSON: data keys already filled
    clicked_indices TEXT DEFAULT '[]',                   -- JSON: field indices already clicked
    last_url TEXT,
    result_data TEXT,                                    -- JSON: structured SessionResult payload
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    started_at TEXT,
    completed_at TEXT
);
CREATE INDEX ix_ai_sessions_status_created ON ai_sessions(status, created_at);
CREATE INDEX ix_ai_sessions_workflow ON ai_sessions(workflow_id);
