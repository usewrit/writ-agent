-- Inline "setup steps" manifest for a monitor target: the recorded steps
-- (navigate/login/click) replayed in the browser BEFORE the content read, so a
-- check can run behind a login or after navigation. Stored as the JSON the shared
-- checker's `pre_check_workflow` hook expects: { "steps": [...], "credentials": {...} }.
-- NULL/absent = a plain check with no setup (the fast HTTP path stays unchanged).
ALTER TABLE targets ADD COLUMN setup_steps TEXT;
