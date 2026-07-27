-- Per-workflow AI auto-repair opt-in. When set (and the daemon is cloud-linked), a LOCAL run that
-- breaks a step calls the MANAGED cloud AI gateway to re-derive the failing step, applies the fix in
-- place, retries, and persists the repaired recipe. Runs stay on this device; only the repair call
-- crosses to the cloud (metered on the linked account, used even when a BYO AI key is configured).
-- NULL/0 = off (the default for every existing row); 1 = on.
ALTER TABLE workflows ADD COLUMN ai_repair_enabled INTEGER NOT NULL DEFAULT 0;
