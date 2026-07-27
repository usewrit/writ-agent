-- AI CONCIERGE SESSIONS — one row per concierge mission (natural-language goal -> live watch+notify
-- automation). The LOCAL mirror of the cloud `concierge_sessions` model (backend/models/
-- concierge_session.py), stripped to the desktop scope: NO autobuy, so `platform` defaults to
-- 'desktop' and the mission ends at 'done' (never 'armed'). A single AI call per planner turn picks
-- ONE tool (find_page / propose_selectors / create_monitor / ask_user / wire_automation / finish);
-- the transport is POLLING (`GET /v1/ai-concierge/{id}`), a pause is status='awaiting_input' +
-- pending_request, and the FE POSTs answers to `/respond`. JSON fields are TEXT (callers serde them);
-- timestamps are TEXT RFC3339 UTC (matches 0006_ai_sessions.sql). No tenant/user columns locally.
CREATE TABLE concierge_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    goal TEXT NOT NULL,
    platform TEXT NOT NULL DEFAULT 'desktop',            -- always 'desktop' locally (autobuy is cloud-only)
    status TEXT NOT NULL DEFAULT 'planning',             -- planning|browsing|proposing|awaiting_input|building|armed|done|error|cancelled
    phase TEXT,                                          -- last tool/phase label, for FE narration
    progress_message TEXT,                               -- human line the FE shows while polling
    transcript TEXT DEFAULT '[]',                        -- JSON: [{role, content, ts}] human-visible chat (never secrets)
    brain_history TEXT DEFAULT '[]',                     -- JSON: [{thought, tool, result, ts}] planner turns
    plan TEXT DEFAULT '{}',                              -- JSON: evolving mission plan (resolved_url, price_selector, baseline_price, threshold, ...)
    pending_request TEXT,                                -- JSON: {requests:[{field,kind,question,options?,multi?,default?}], resume_status?}
    answers TEXT DEFAULT '{}',                           -- JSON: merged answers keyed by request field (non-secret)
    resources TEXT DEFAULT '{}',                         -- JSON: {target_id, target_selector_id, extractor_id, trigger_rule_id, browse_session_id}
    browse_session_id INTEGER REFERENCES ai_sessions(id) ON DELETE SET NULL,
    input_tokens INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    total_tokens INTEGER NOT NULL DEFAULT 0,
    ai_calls_count INTEGER NOT NULL DEFAULT 0,
    turn_seq INTEGER NOT NULL DEFAULT 0,                 -- monotone planner-turn counter; optimistic-lock/idempotency key for /respond
    cancel_requested INTEGER NOT NULL DEFAULT 0,         -- boolean 0/1
    error_message TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    updated_at TEXT,
    completed_at TEXT
);
CREATE INDEX ix_concierge_sessions_status_created ON concierge_sessions(status, created_at);
