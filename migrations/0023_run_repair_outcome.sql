-- AI auto-repair OUTCOME per run, plus the per-workflow last-repair stamp. The desktop mirror of the
-- cloud's AutomationTask.ai_repair_result.success / AutomationWorkflow.last_repaired_at.
--
-- Until now a local repair left NO trace on the run. `status='repairing'` is transient: it is flipped
-- back to 'running' the moment the repair resolves (engine/real.rs), so once a run terminated you
-- could not tell whether AI had fixed it, tried and given up, or never run at all. Home's "Needs
-- attention" therefore showed every failure identically — including ones AI had already repaired,
-- which sat there forever, and ones AI had already given up on, which looked untriaged.
--
-- Tri-state, mirroring the existing `runs.success` idiom on this same table:
--   NULL = no verdict (the default for every existing row: repair off, never triggered, or the
--          daemon died mid-repair)
--   1    = the AI's fix worked                 -> "Repaired"
--   0    = the AI tried and could not fix it   -> "Repair failed" (this one needs a human)
-- One tri-state column rather than the cloud's attempted+result pair: `attempted` is exactly
-- `ai_repair_succeeded IS NOT NULL` here, so a second column would only add a way to disagree.
-- LAST verdict wins — the smart-repair self-heal restart re-enters `execute` with the SAME run id, so
-- a fix that is later followed by a give-up must read as "repair failed" (the run is still broken).
ALTER TABLE runs ADD COLUMN ai_repair_succeeded INTEGER;

-- When AI last PERSISTED a repair to this workflow. Same ISO-8601 UTC strftime format as every other
-- timestamp here, so a plain string compare against `runs.completed_at` is chronological. A failed run
-- OLDER than this has since been fixed -> Home drops it from "Needs attention" (`repaired_since`).
-- Stamped for BOTH selector-level writeback and recipe-level repairs, which is why it can't just be
-- derived from workflow_repair_history (0021) — that table deliberately records only the latter.
-- NULL = never repaired.
ALTER TABLE workflows ADD COLUMN last_repaired_at TEXT;
