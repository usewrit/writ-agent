-- Structured schedule recurrence (SCHEDULE_RECURRENCE_SPEC.md §1a).
--
-- Adds precise recurring schedules to WORKFLOWS and TARGETS (monitors) alongside the existing
-- interval columns (`workflows.schedule_interval_ms` / `targets.check_period_ms`). Three kinds:
--   * interval — the pre-existing "every N ms" behavior. The interval still comes from the existing
--     column; the new columns are ignored. This is the DEFAULT so every pre-existing row keeps its
--     exact behavior (fully backward compatible).
--   * daily    — fires every day at `schedule_time` (local wall-clock) in `schedule_tz`.
--   * weekly   — fires on each ISO weekday in `schedule_days` at `schedule_time` in `schedule_tz`.
--
-- Column meanings (identical on both tables):
--   schedule_kind  — 'interval' | 'daily' | 'weekly'. NOT NULL, defaults to 'interval'.
--   schedule_time  — "HH:MM" 24-hour local wall-clock (daily/weekly). NULL for interval.
--   schedule_days  — JSON array string of ISO weekday ints, 1=Mon … 7=Sun (weekly only). NULL otherwise.
--   schedule_tz    — IANA tz name (e.g. 'America/New_York'). NULL ⇒ treated as UTC.
--
-- Automations need NO column: their recurrence rides inside the `scheduled` event block's config JSON
-- (mode/time/days/tz), read at tick time — see scheduled_automations.rs.

ALTER TABLE workflows ADD COLUMN schedule_kind TEXT NOT NULL DEFAULT 'interval';
ALTER TABLE workflows ADD COLUMN schedule_time TEXT;
ALTER TABLE workflows ADD COLUMN schedule_days TEXT;
ALTER TABLE workflows ADD COLUMN schedule_tz TEXT;

ALTER TABLE targets ADD COLUMN schedule_kind TEXT NOT NULL DEFAULT 'interval';
ALTER TABLE targets ADD COLUMN schedule_time TEXT;
ALTER TABLE targets ADD COLUMN schedule_days TEXT;
ALTER TABLE targets ADD COLUMN schedule_tz TEXT;
