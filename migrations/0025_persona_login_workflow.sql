-- PERSONA LOGIN WORKFLOW — how a persona SIGNS ITSELF IN.
--
-- A persona's warm session (`session_state_encrypted`) could previously only arrive by
-- CAPTURE from something that had already signed in. Nothing could make a persona sign
-- IN, so a persona created from credentials alone never had a session, and every
-- authenticated crawl using it was refused ("no live login session") with no route out
-- of the error. Worse, locally the capture path didn't even exist: a successful run
-- harvested its session into `workflow_sessions` (workflow-keyed) and never onto the
-- persona at all.
--
-- `login_workflow_id` names the workflow that performs the login. Running it with the
-- persona resolved (credentials + 2FA folded in) and writing the harvested session back
-- onto the persona is what makes sign-in re-runnable — on demand (POST
-- /v1/personas/{id}/sign-in) and automatically when a crawl finds the session stale.
--
-- `last_login_error` records why the most recent sign-in attempt failed (cleared on
-- success) so the UI can explain without digging through run history.
--
-- ON DELETE SET NULL: deleting the login workflow must never delete the identity — it
-- only leaves the persona unable to re-login until another workflow is attached.
ALTER TABLE personas ADD COLUMN login_workflow_id INTEGER REFERENCES workflows(id) ON DELETE SET NULL;
ALTER TABLE personas ADD COLUMN last_login_error TEXT;
CREATE INDEX ix_personas_login_workflow ON personas(login_workflow_id);
