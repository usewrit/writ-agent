-- AI-PREVIEW REPLAY STEPS — disk-cheap per-step replay for "watch the AI". One row per loop step of
-- an AI session (kind='ai') or concierge mission (kind='concierge'), holding the model's short
-- `thought`, a human `action` summary, the page `url`, the run `status`, and a DOWNSCALED + DEDUPED
-- keyframe (`screenshot`: raw JPEG BLOB, nullable — NULL means "same frame as the previous step", so
-- the FE reuses the last non-null one). Keyframes are stored as RAW BYTES (never base64: base64 is
-- +33% on disk; the API base64-encodes only at read) at a small size (≤720px, low quality), so an
-- entire long run replays in a few hundred KB.
--
-- Generic (kind, ref_id) rather than a hard FK, so ONE table serves both surfaces. The owning DELETE
-- handlers clear rows explicitly, and each writer trims to the most recent N steps — this is a
-- bounded, self-pruning cache of frames, not durable history.
CREATE TABLE ai_preview_steps (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT    NOT NULL,               -- 'ai' | 'concierge'
    ref_id       INTEGER NOT NULL,               -- ai_sessions.id / concierge_sessions.id
    step_num     INTEGER NOT NULL,
    thought      TEXT,
    action       TEXT,
    url          TEXT,
    status       TEXT,
    screenshot   BLOB,                            -- downscaled JPEG bytes; NULL = unchanged from prev
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE INDEX idx_ai_preview_steps_ref ON ai_preview_steps(kind, ref_id, step_num);
