-- Per-workflow run VENUE pin. NULL/'' = Auto (follow the app default — local on the desktop app);
-- 'local' or 'cloud' hard-route the workflow to a specific agent regardless of which app runs it.
-- Read by the desktop split "Run" button to resolve the default venue; overrides the app default.
ALTER TABLE workflows ADD COLUMN execution_target TEXT;
