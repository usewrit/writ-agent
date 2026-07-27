-- BROWSERLESS HTTP EXECUTION LANE — per-workflow persisted auth session + lane metadata.
--
-- Workflows whose steps are pure HTTP (api_call / login_post, the concierge API-builder shape) can run
-- without launching a browser. This migration adds:
--   * workflow_sessions — a per-workflow vault-sealed SessionState (cookies/headers/storage/tokens) so a
--     browserless run reuses the last login instead of re-authenticating every time. A dedicated table
--     (not a `workflows` column) keeps the hot catalog row small and lets a session be cleared without
--     bumping the workflow's own updated_at / sync state.
--   * workflows.http_capable — a sticky lane hint: -1 unknown (probe), 0 proven browser-only (the HTTP
--     lane failed and the browser succeeded), 1 proven HTTP-capable. Reset to -1 when steps/auth_config
--     change (the store update path).
--   * workflows.auth_config — the declarative AuthRecipe JSON (login/refresh/probe/challenge steps +
--     token map). NULL = none / degenerate recipe synthesized from a leading login_post step.

CREATE TABLE workflow_sessions (
    workflow_id INTEGER PRIMARY KEY REFERENCES workflows(id) ON DELETE CASCADE,
    -- Vault Layer-B sealed SessionState JSON. AAD: 'workflow_sessions|session_state_encrypted|<workflow_id>'.
    session_state_encrypted TEXT,
    -- RFC3339; duplicated outside the sealed blob so a TTL check never has to decrypt.
    extracted_at TEXT,
    -- Which lane captured it: 'http' | 'browser'.
    engine TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

ALTER TABLE workflows ADD COLUMN http_capable INTEGER NOT NULL DEFAULT -1;
ALTER TABLE workflows ADD COLUMN auth_config TEXT;
