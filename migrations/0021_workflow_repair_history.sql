-- AI auto-repair history: a snapshot per recipe-level repair (whole-workflow rewrite or autonomous
-- re-record) so a user can inspect or revert what the AI changed. Selector-only in-place fixes are
-- NOT logged here (they are minor and already reflected in the steps). Rows cascade with the workflow.
CREATE TABLE IF NOT EXISTS workflow_repair_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id  INTEGER NOT NULL,
    repaired_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    kind         TEXT NOT NULL,           -- 'recipe' (whole-workflow rewrite) | 're_record' (autonomous)
    old_steps    TEXT NOT NULL,           -- JSON snapshot of the pre-repair steps array
    new_steps    TEXT,                    -- JSON snapshot of the repaired steps array
    note         TEXT,                    -- short human note (what triggered it)
    FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_workflow_repair_history_workflow
    ON workflow_repair_history(workflow_id, id DESC);
