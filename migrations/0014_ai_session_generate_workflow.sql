-- AI SESSIONS — opt out of "record a reusable workflow at the end".
--
-- The autonomous AI session (form-filler loop) now captures the concrete actions it executes and, on a
-- successful (`complete`) finish, assembles + persists a `workflows` row and links it back
-- (`ai_sessions.workflow_id`). This flag lets a caller disable that (e.g. an automation-internal AI
-- step that should not spawn a workflow). DEFAULT 1 → every existing/absent row keeps the new
-- record-a-workflow behavior; a caller passes `generate_workflow: false` to skip it.
ALTER TABLE ai_sessions ADD COLUMN generate_workflow INTEGER NOT NULL DEFAULT 1;
