-- Marketplace installs become CALLABLE PROXY workflows (cloud parity: the cloud install mints a
-- consumer-tenant proxy AutomationWorkflow; the desktop now mints a local proxy `workflows` row).
--
-- `workflows.marketplace_slug`: set (to the listing slug) when the row is a PROXY for an installed
-- marketplace listing. The row's own `steps` stay '[]' — the PLAINTEXT recipe is NEVER persisted
-- (protected-executor invariant 1). At run time the engine detects the marker, authorizes a metered
-- run cloud-side when paid, unseals the recipe IN MEMORY, executes it, and finalizes the charge —
-- while the `runs` row + rollup stay bound to the proxy row, so run history / extracted data /
-- schedules / derived MCP tools all work like a regular workflow.
ALTER TABLE workflows ADD COLUMN marketplace_slug TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_workflows_marketplace_slug
    ON workflows(marketplace_slug) WHERE marketplace_slug IS NOT NULL;

-- `installed_workflows.bindings`: the CONSUMER's saved attachment choices for the listing's BYO
-- slots, as JSON — `{"secrets":{slot->local vault KEY NAME},"persona_id":N,"persona_none":bool,
-- "inputs":{non-secret input defaults}}`. NAMES/IDS ONLY for secrets/personas — secret VALUES live
-- exclusively in `vault_secrets`/`personas` ciphertext columns. Lets scheduled/background proxy
-- runs resolve without re-asking.
ALTER TABLE installed_workflows ADD COLUMN bindings TEXT;
