//! Structured schedule recurrence — pure helpers for the local scheduler.
//!
//! Adds precise recurring schedules (the schedule-recurrence spec §4) on top of the pre-existing
//! "every N ms" interval cadence. Three kinds:
//!   * `Interval` — the existing behavior: fire `interval_ms` after `now`. Byte-identical to before.
//!   * `Daily`    — fire every day at `time` ("HH:MM") wall-clock in `tz`.
//!   * `Weekly`   — fire on each ISO weekday in `days` (1=Mon … 7=Sun) at `time` in `tz`.
//!
//! Timezones are resolved via the IANA database (`chrono-tz`), so the wall-clock time is DST-correct:
//! a "09:00 daily" schedule stays at local 09:00 across spring-forward / fall-back. The result of
//! [`next_run`] / [`prev_occurrence`] is always UTC (matching the `next_scheduled_at` / `next_run_at`
//! columns, which store UTC RFC3339).
//!
//! This module is the SINGLE definition the workflow lane ([`super::scheduled`]), the monitor lane
//! ([`crate::local::monitor::runner`]), and the automation lane ([`super::scheduled_automations`])
//! all call, so the next-run algorithm can never drift between the three subsystems. It mirrors the
//! cloud `services/schedule_recurrence.py` helper.

use chrono::{DateTime, Datelike, Duration, TimeZone, Utc};
use chrono_tz::Tz;
use serde_json::Value;

/// A structured schedule read from DB columns (workflows/targets) or block config (automations).
#[derive(Debug, Clone)]
pub struct Recurrence {
    pub kind: Kind,
    /// Interval cadence (ms) for [`Kind::Interval`] — the existing `schedule_interval_ms` /
    /// `check_period_ms`. For daily/weekly it is only a last-resort fallback interval.
    pub interval_ms: i64,
    /// Local wall-clock fire time "HH:MM" (daily/weekly). Unparseable/absent ⇒ treated as "00:00".
    pub time: Option<String>,
    /// ISO weekdays 1..=7 (1=Mon) the schedule may fire on (weekly only).
    pub days: Vec<u32>,
    /// IANA tz name; empty/invalid ⇒ UTC.
    pub tz: String,
}

/// The three recurrence kinds. Anything unrecognized parses to [`Kind::Interval`] (back-compat).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Interval,
    Daily,
    Weekly,
}

impl Kind {
    /// Parse a stored `schedule_kind` / block `mode` string. Absent or unknown ⇒ `Interval`.
    pub fn parse(s: Option<&str>) -> Kind {
        match s {
            Some("daily") => Kind::Daily,
            Some("weekly") => Kind::Weekly,
            _ => Kind::Interval,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Interval => "interval",
            Kind::Daily => "daily",
            Kind::Weekly => "weekly",
        }
    }
}

impl Recurrence {
    /// Build a recurrence from the four persisted schedule columns of a workflow/target row plus the
    /// row's interval column (`schedule_interval_ms` / `check_period_ms`). `schedule_days` is the JSON
    /// array string stored in the TEXT column (e.g. `"[3,5]"`); a malformed/absent value ⇒ no days.
    pub fn from_columns(
        kind: Option<&str>,
        interval_ms: i64,
        time: Option<&str>,
        days_json: Option<&str>,
        tz: Option<&str>,
    ) -> Recurrence {
        Recurrence {
            kind: Kind::parse(kind),
            interval_ms,
            time: time.map(str::to_string),
            days: parse_days_json(days_json),
            tz: tz.unwrap_or("").to_string(),
        }
    }

    /// Build a recurrence from a `scheduled` automation event block's `config` object. Reads
    /// `mode` (interval|daily|weekly; absent ⇒ interval), the interval from `interval_ms` or the
    /// `interval_minutes` compatibility shim (×60000), and `time`/`days`/`tz` for daily/weekly.
    /// `days` accepts a JSON array of ints. The interval is NOT clamped here — the caller keeps the
    /// clamp floor for the interval path exactly as before.
    pub fn from_block_config(config: &Value) -> Recurrence {
        let kind = Kind::parse(config.get("mode").and_then(Value::as_str));
        let interval_ms = config
            .get("interval_ms")
            .and_then(Value::as_i64)
            .or_else(|| {
                config
                    .get("interval_minutes")
                    .and_then(Value::as_i64)
                    .map(|m| m * 60_000)
            })
            .unwrap_or(0);
        let time = config.get("time").and_then(Value::as_str).map(str::to_string);
        let days = config
            .get("days")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(|v| v.as_u64().map(|n| n as u32)).collect())
            .unwrap_or_default();
        let tz = config
            .get("tz")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Recurrence { kind, interval_ms, time, days, tz }
    }
}

/// Parse a `schedule_days` TEXT column (JSON array of ints, e.g. `"[3,5]"`) into ISO weekday ints.
/// A `None`, empty, or malformed value yields an empty vec (no matching weekday → weekly falls back).
fn parse_days_json(days_json: Option<&str>) -> Vec<u32> {
    let Some(s) = days_json else { return Vec::new() };
    let s = s.trim();
    if s.is_empty() {
        return Vec::new();
    }
    serde_json::from_str::<Vec<i64>>(s)
        .map(|v| v.into_iter().filter(|d| (1..=7).contains(d)).map(|d| d as u32).collect())
        .unwrap_or_default()
}

fn load_tz(tz: &str) -> Tz {
    tz.parse::<Tz>().unwrap_or(chrono_tz::UTC)
}

fn parse_hhmm(t: Option<&str>) -> (u32, u32) {
    if let Some(s) = t {
        let mut it = s.splitn(2, ':');
        if let (Some(h), Some(m)) = (it.next(), it.next()) {
            if let (Ok(h), Ok(m)) = (h.trim().parse::<u32>(), m.trim().parse::<u32>()) {
                if h < 24 && m < 60 {
                    return (h, m);
                }
            }
        }
    }
    (0, 0)
}

/// Build wall-clock `date @ hh:mm` in tz, converted to UTC (earliest on DST ambiguity, +1h on gap).
fn local_at_utc(tz: Tz, y: i32, mo: u32, d: u32, hh: u32, mm: u32) -> DateTime<Utc> {
    use chrono::LocalResult;
    match tz.with_ymd_and_hms(y, mo, d, hh, mm, 0) {
        LocalResult::Single(dt) => dt.with_timezone(&Utc),
        LocalResult::Ambiguous(a, _) => a.with_timezone(&Utc),
        LocalResult::None => {
            // Spring-forward gap: nudge forward an hour until valid.
            match tz.with_ymd_and_hms(y, mo, d, (hh + 1).min(23), mm, 0) {
                LocalResult::Single(dt) => dt.with_timezone(&Utc),
                LocalResult::Ambiguous(a, _) => a.with_timezone(&Utc),
                LocalResult::None => {
                    Utc.with_ymd_and_hms(y, mo, d, hh, mm, 0).single().unwrap_or_else(Utc::now)
                }
            }
        }
    }
}

/// Shift a LOCAL calendar date by whole days.
///
/// This exists because `DateTime<Tz> + Duration::days(1)` adds **24 hours of absolute time**, not
/// one calendar day: chrono applies the offset to the underlying UTC instant. On a DST-transition
/// day that is wrong in both directions —
///   * **fall back** (a 25-hour local day): +24 h can leave you on the SAME calendar date, so a
///     "roll to tomorrow" produced a candidate still in the past. `list_due` then re-selected the
///     row on every 15-second tick and the job re-ran for the whole hour-long window.
///   * **spring forward** (a 23-hour local day): +24 h can cross TWO local midnights, silently
///     SKIPPING a day for a late-evening schedule.
/// Calendar arithmetic on the naive local date has neither problem.
fn shift_local_date(date: chrono::NaiveDate, days: i64) -> Option<chrono::NaiveDate> {
    if days >= 0 {
        date.checked_add_days(chrono::Days::new(days as u64))
    } else {
        date.checked_sub_days(chrono::Days::new(days.unsigned_abs()))
    }
}

/// How many calendar days forward/back we are willing to search for a matching occurrence.
/// A week covers every weekly pattern; the extra days absorb DST edges and month boundaries.
const RECURRENCE_SEARCH_DAYS: i64 = 8;

/// Next fire strictly after `now` (SPEC §4). For [`Kind::Interval`] this is `now + interval_ms`
/// (the existing behavior); the caller applies the anti-detection clamp floor to the interval.
pub fn next_run(r: &Recurrence, now: DateTime<Utc>) -> DateTime<Utc> {
    match r.kind {
        Kind::Interval => now + Duration::milliseconds(r.interval_ms.max(0)),
        Kind::Daily => {
            let tz = load_tz(&r.tz);
            let (hh, mm) = parse_hhmm(r.time.as_deref());
            let today = now.with_timezone(&tz).date_naive();
            // Walk forward by CALENDAR day until the candidate is strictly in the future. The loop
            // (rather than a single roll) is the post-condition: every branch is guaranteed to
            // return a future instant, even across a DST transition or a spring-forward gap that
            // `local_at_utc` nudges forward by an hour.
            for off in 0..=RECURRENCE_SEARCH_DAYS {
                if let Some(d) = shift_local_date(today, off) {
                    let cand = local_at_utc(tz, d.year(), d.month(), d.day(), hh, mm);
                    if cand > now {
                        return cand;
                    }
                }
            }
            // Unreachable in practice (a daily schedule always matches within a day or two);
            // degrade to a bounded future instant rather than returning something in the past.
            now + Duration::days(1)
        }
        Kind::Weekly => {
            let tz = load_tz(&r.tz);
            let (hh, mm) = parse_hhmm(r.time.as_deref());
            let today = now.with_timezone(&tz).date_naive();
            for off in 0..=RECURRENCE_SEARCH_DAYS {
                let Some(d) = shift_local_date(today, off) else { continue };
                if r.days.contains(&d.weekday().number_from_monday()) {
                    let cand = local_at_utc(tz, d.year(), d.month(), d.day(), hh, mm);
                    if cand > now {
                        return cand;
                    }
                }
            }
            // days empty or none matched in a week ⇒ safety fallback (never sooner than a day).
            now + Duration::milliseconds(r.interval_ms.max(86_400_000))
        }
    }
}

/// Latest scheduled occurrence <= now, or None ([`Kind::Interval`] ⇒ None). For automation due checks
/// (SPEC §4 "Due semantics"): an automation is due when its `last_triggered_at` predates this.
pub fn prev_occurrence(r: &Recurrence, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    match r.kind {
        Kind::Interval => None,
        Kind::Daily => {
            let tz = load_tz(&r.tz);
            let (hh, mm) = parse_hhmm(r.time.as_deref());
            let today = now.with_timezone(&tz).date_naive();
            // Walk BACK by calendar day until the candidate is at or before `now`. The old code did
            // a single `- Duration::days(1)` with no post-condition (unlike the Weekly branch,
            // which did check), so on a DST day it could return an occurrence in the FUTURE — and
            // `is_due` comparing against a future occurrence fires the automation early and then
            // again on every tick.
            for off in 0..=RECURRENCE_SEARCH_DAYS {
                if let Some(d) = shift_local_date(today, -off) {
                    let cand = local_at_utc(tz, d.year(), d.month(), d.day(), hh, mm);
                    if cand <= now {
                        return Some(cand);
                    }
                }
            }
            None
        }
        Kind::Weekly => {
            let tz = load_tz(&r.tz);
            let (hh, mm) = parse_hhmm(r.time.as_deref());
            let today = now.with_timezone(&tz).date_naive();
            for off in 0..=RECURRENCE_SEARCH_DAYS {
                let Some(d) = shift_local_date(today, -off) else { continue };
                if r.days.contains(&d.weekday().number_from_monday()) {
                    let cand = local_at_utc(tz, d.year(), d.month(), d.day(), hh, mm);
                    if cand <= now {
                        return Some(cand);
                    }
                }
            }
            None
        }
    }
}

/// Recurrence-aware "is this automation due?" — for [`Kind::Interval`] this is the existing
/// elapsed-since-last check (the caller floors `interval_ms` to the clamp minimum before calling).
/// For daily/weekly it is due when a scheduled occurrence has passed since it last fired.
pub fn is_due(r: &Recurrence, last_triggered_at: Option<&str>, now: DateTime<Utc>) -> bool {
    if r.kind == Kind::Interval {
        return match last_triggered_at {
            None => true,
            Some(s) => match DateTime::parse_from_rfc3339(s) {
                Ok(prev) => {
                    now.signed_duration_since(prev.with_timezone(&Utc))
                        >= Duration::milliseconds(r.interval_ms)
                }
                Err(_) => true,
            },
        };
    }
    match prev_occurrence(r, now) {
        None => false,
        Some(prev) => match last_triggered_at {
            None => true,
            Some(s) => match DateTime::parse_from_rfc3339(s) {
                Ok(last) => last.with_timezone(&Utc) < prev,
                Err(_) => true,
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    fn utc(y: i32, mo: u32, d: u32, hh: u32, mm: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(y, mo, d, hh, mm, 0).single().unwrap()
    }

    fn interval(ms: i64) -> Recurrence {
        Recurrence { kind: Kind::Interval, interval_ms: ms, time: None, days: vec![], tz: String::new() }
    }

    fn daily(time: &str, tz: &str) -> Recurrence {
        Recurrence {
            kind: Kind::Daily,
            interval_ms: 0,
            time: Some(time.into()),
            days: vec![],
            tz: tz.into(),
        }
    }

    fn weekly(time: &str, days: Vec<u32>, tz: &str) -> Recurrence {
        Recurrence { kind: Kind::Weekly, interval_ms: 0, time: Some(time.into()), days, tz: tz.into() }
    }

    #[test]
    fn kind_parse_defaults_to_interval() {
        assert_eq!(Kind::parse(Some("daily")), Kind::Daily);
        assert_eq!(Kind::parse(Some("weekly")), Kind::Weekly);
        assert_eq!(Kind::parse(Some("interval")), Kind::Interval);
        assert_eq!(Kind::parse(None), Kind::Interval);
        assert_eq!(Kind::parse(Some("garbage")), Kind::Interval, "unknown ⇒ interval (back-compat)");
    }

    #[test]
    fn interval_is_now_plus_interval() {
        let now = utc(2026, 7, 5, 12, 0);
        let next = next_run(&interval(3_600_000), now);
        assert_eq!(next, now + Duration::milliseconds(3_600_000));
        // Interval has no prev-occurrence concept.
        assert!(prev_occurrence(&interval(3_600_000), now).is_none());
    }

    #[test]
    fn daily_fires_today_if_time_still_ahead() {
        // now = 08:00 UTC, schedule 12:00 UTC ⇒ today at 12:00.
        let now = utc(2026, 7, 5, 8, 0);
        let next = next_run(&daily("12:00", "UTC"), now);
        assert_eq!(next, utc(2026, 7, 5, 12, 0));
    }

    #[test]
    fn daily_rolls_to_tomorrow_when_time_passed() {
        // now = 13:00 UTC, schedule 12:00 UTC ⇒ tomorrow at 12:00 (strictly after now).
        let now = utc(2026, 7, 5, 13, 0);
        let next = next_run(&daily("12:00", "UTC"), now);
        assert_eq!(next, utc(2026, 7, 6, 12, 0), "past today's time rolls to tomorrow");
    }

    #[test]
    fn daily_non_utc_tz_is_dst_correct() {
        // America/New_York in July is EDT (UTC-4). 09:00 local == 13:00 UTC.
        // now = 05:00 UTC (01:00 EDT), so today's 09:00 EDT (13:00 UTC) is still ahead.
        let now = utc(2026, 7, 5, 5, 0);
        let next = next_run(&daily("09:00", "America/New_York"), now);
        assert_eq!(next, utc(2026, 7, 5, 13, 0), "09:00 EDT == 13:00 UTC");
        // The wall-clock local hour is 9 in the target tz.
        assert_eq!(next.with_timezone(&load_tz("America/New_York")).hour(), 9);
    }

    #[test]
    fn daily_winter_tz_shifts_by_an_hour_vs_summer() {
        // In January New York is EST (UTC-5), so 09:00 local == 14:00 UTC (vs 13:00 in summer) —
        // proving the tz math is DST-aware, not a fixed offset.
        let now = utc(2026, 1, 5, 5, 0);
        let next = next_run(&daily("09:00", "America/New_York"), now);
        assert_eq!(next, utc(2026, 1, 5, 14, 0), "09:00 EST == 14:00 UTC");
    }

    #[test]
    fn invalid_tz_falls_back_to_utc() {
        let now = utc(2026, 7, 5, 8, 0);
        let next = next_run(&daily("12:00", "Not/AZone"), now);
        assert_eq!(next, utc(2026, 7, 5, 12, 0), "unparseable tz ⇒ UTC");
    }

    #[test]
    fn weekly_picks_the_next_allowed_weekday() {
        // 2026-07-05 is a Sunday (ISO weekday 7). Schedule Wed(3) & Fri(5) at 09:00 UTC.
        // Next allowed day at/after Sunday is Wednesday 2026-07-08.
        let now = utc(2026, 7, 5, 10, 0);
        let next = next_run(&weekly("09:00", vec![3, 5], "UTC"), now);
        assert_eq!(next, utc(2026, 7, 8, 9, 0), "next Wed at 09:00");
    }

    #[test]
    fn weekly_same_day_before_time_fires_today() {
        // 2026-07-08 is a Wednesday (ISO 3). now = 08:00, schedule Wed 09:00 ⇒ today 09:00.
        let now = utc(2026, 7, 8, 8, 0);
        let next = next_run(&weekly("09:00", vec![3], "UTC"), now);
        assert_eq!(next, utc(2026, 7, 8, 9, 0), "today Wed 09:00 is still ahead");
    }

    #[test]
    fn weekly_same_day_after_time_rolls_a_week() {
        // Wednesday 10:00, schedule only Wed 09:00 ⇒ next Wednesday.
        let now = utc(2026, 7, 8, 10, 0);
        let next = next_run(&weekly("09:00", vec![3], "UTC"), now);
        assert_eq!(next, utc(2026, 7, 15, 9, 0), "past today's Wed time ⇒ next Wed");
    }

    #[test]
    fn weekly_empty_days_uses_daily_fallback() {
        let now = utc(2026, 7, 5, 12, 0);
        let r = weekly("09:00", vec![], "UTC");
        let next = next_run(&r, now);
        // Fallback is at least a day out.
        assert!(next >= now + Duration::milliseconds(86_400_000));
    }

    #[test]
    fn is_due_daily_vs_last_triggered() {
        // now = 12:30 UTC; a daily 12:00 schedule's prev occurrence is today 12:00.
        let now = utc(2026, 7, 5, 12, 30);
        let r = daily("12:00", "UTC");

        // Never fired ⇒ due.
        assert!(is_due(&r, None, now), "never fired is due");
        // Fired before today's 12:00 (e.g. yesterday) ⇒ due.
        let yesterday = utc(2026, 7, 4, 12, 0).to_rfc3339();
        assert!(is_due(&r, Some(&yesterday), now), "fired before prev occurrence ⇒ due");
        // Already fired at today's 12:00 ⇒ NOT due.
        let today = utc(2026, 7, 5, 12, 0).to_rfc3339();
        assert!(!is_due(&r, Some(&today), now), "already fired this occurrence ⇒ not due");
    }

    #[test]
    fn is_due_weekly_vs_last_triggered() {
        // 2026-07-08 is Wednesday. now = Wed 10:00, schedule Wed 09:00 ⇒ prev = Wed 09:00.
        let now = utc(2026, 7, 8, 10, 0);
        let r = weekly("09:00", vec![3], "UTC");

        assert!(is_due(&r, None, now), "never fired is due");
        // Fired last week ⇒ due (before this Wednesday's occurrence).
        let last_week = utc(2026, 7, 1, 9, 0).to_rfc3339();
        assert!(is_due(&r, Some(&last_week), now), "last week's fire ⇒ due");
        // Fired at this Wed 09:00 already ⇒ not due.
        let this_occ = utc(2026, 7, 8, 9, 0).to_rfc3339();
        assert!(!is_due(&r, Some(&this_occ), now), "already fired this occurrence ⇒ not due");
    }

    #[test]
    fn is_due_interval_matches_elapsed_since_last() {
        let now = utc(2026, 7, 5, 12, 0);
        let r = interval(60_000); // 60s

        assert!(is_due(&r, None, now), "never fired is due");
        let recent = (now - Duration::seconds(10)).to_rfc3339();
        assert!(!is_due(&r, Some(&recent), now), "10s ago with 60s interval ⇒ not due");
        let old = (now - Duration::seconds(120)).to_rfc3339();
        assert!(is_due(&r, Some(&old), now), "120s ago with 60s interval ⇒ due");
    }

    #[test]
    fn from_columns_reads_days_json() {
        let r = Recurrence::from_columns(
            Some("weekly"),
            0,
            Some("13:00"),
            Some("[3,5]"),
            Some("America/New_York"),
        );
        assert_eq!(r.kind, Kind::Weekly);
        assert_eq!(r.days, vec![3, 5]);
        assert_eq!(r.time.as_deref(), Some("13:00"));
        assert_eq!(r.tz, "America/New_York");

        // Malformed days JSON ⇒ empty (safe fallback, no panic).
        let bad = Recurrence::from_columns(Some("weekly"), 0, Some("13:00"), Some("not-json"), None);
        assert!(bad.days.is_empty());
        // Out-of-range weekday ints are filtered out.
        let filt = Recurrence::from_columns(Some("weekly"), 0, None, Some("[0,3,8]"), None);
        assert_eq!(filt.days, vec![3]);
    }

    #[test]
    fn from_block_config_reads_mode_and_minutes_shim() {
        // interval_ms path.
        let c = serde_json::json!({ "mode": "interval", "interval_ms": 600000 });
        let r = Recurrence::from_block_config(&c);
        assert_eq!(r.kind, Kind::Interval);
        assert_eq!(r.interval_ms, 600_000);

        // interval_minutes compatibility shim (×60000).
        let c = serde_json::json!({ "interval_minutes": 10 });
        let r = Recurrence::from_block_config(&c);
        assert_eq!(r.kind, Kind::Interval, "absent mode ⇒ interval");
        assert_eq!(r.interval_ms, 600_000);

        // weekly config.
        let c = serde_json::json!({ "mode": "weekly", "time": "09:00", "days": [3, 5], "tz": "America/New_York" });
        let r = Recurrence::from_block_config(&c);
        assert_eq!(r.kind, Kind::Weekly);
        assert_eq!(r.time.as_deref(), Some("09:00"));
        assert_eq!(r.days, vec![3, 5]);
        assert_eq!(r.tz, "America/New_York");
    }

    // ----------------------------------------------------------------------- //
    // DST regressions.                                                        //
    //                                                                         //
    // `DateTime<Tz> + Duration::days(1)` adds 24 h of ABSOLUTE time, so on a   //
    // 25-hour fall-back day the "roll to tomorrow" stayed on the same local    //
    // calendar date and returned an instant in the PAST — which `list_due`     //
    // re-selected every 15 s, re-running the job for the whole window. The     //
    // mirror bug skipped a day on a 23-hour spring-forward day. Both branches  //
    // now walk calendar dates instead.                                        //
    //                                                                         //
    // US fall back 2026: 2026-11-01, local 02:00 EDT → 01:00 EST.              //
    // US spring forward 2026: 2026-03-08, local 02:00 EST → 03:00 EDT.         //
    // ----------------------------------------------------------------------- //

    #[test]
    fn daily_next_run_is_always_in_the_future_across_fall_back() {
        let r = daily("00:30", "America/New_York");
        // 04:35Z on the fall-back day is 00:35 EDT — just past the 00:30 fire time, so the next
        // run must roll to the FOLLOWING calendar day. The old code returned 04:30Z (in the past).
        let now = utc(2026, 11, 1, 4, 35);
        let next = next_run(&r, now);
        assert!(next > now, "next_run must be strictly in the future, got {next} for now={now}");
        // And it must be the next day's 00:30 local, not merely "now + epsilon".
        let local = next.with_timezone(&load_tz("America/New_York"));
        assert_eq!((local.hour(), local.minute()), (0, 30), "wall-clock time drifted: {local}");
        assert_eq!(local.day(), 2, "should be the next calendar day: {local}");
    }

    #[test]
    fn daily_next_run_never_regresses_scanning_the_whole_fall_back_day() {
        // Sweep every 5 minutes across the DST-transition day; next_run must never be <= now.
        let r = daily("00:30", "America/New_York");
        let mut t = utc(2026, 11, 1, 0, 0);
        let end = utc(2026, 11, 2, 12, 0);
        while t < end {
            let next = next_run(&r, t);
            assert!(next > t, "regressed at now={t}: next={next}");
            t += Duration::minutes(5);
        }
    }

    #[test]
    fn daily_prev_occurrence_is_never_in_the_future_across_fall_back() {
        // The Daily branch of `prev_occurrence` had no `cand <= now` post-condition (unlike Weekly),
        // so it could hand back a FUTURE occurrence — firing the automation early, then every tick.
        let r = daily("00:30", "America/New_York");
        let mut t = utc(2026, 11, 1, 0, 0);
        let end = utc(2026, 11, 2, 12, 0);
        while t < end {
            let prev = prev_occurrence(&r, t).expect("daily always has a previous occurrence");
            assert!(prev <= t, "prev_occurrence in the future at now={t}: prev={prev}");
            t += Duration::minutes(5);
        }
    }

    #[test]
    fn daily_late_evening_schedule_does_not_skip_spring_forward_day() {
        // A 23-hour local day + 24 h absolute could cross two local midnights, skipping a fire.
        // From 2026-03-07 23:35 local, the next 23:30 must be 2026-03-08, not 2026-03-09.
        let r = daily("23:30", "America/New_York");
        let tz = load_tz("America/New_York");
        let now = tz.with_ymd_and_hms(2026, 3, 7, 23, 35, 0).unwrap().with_timezone(&Utc);
        let next = next_run(&r, now);
        let local = next.with_timezone(&tz);
        assert_eq!(local.day(), 8, "spring-forward day was skipped: {local}");
        assert_eq!((local.hour(), local.minute()), (23, 30));
    }

    #[test]
    fn weekly_next_and_prev_bracket_now_across_dst() {
        // days = [Sun(7)] so the fall-back Sunday (2026-11-01) is a fire day.
        let r = weekly("00:30", vec![7], "America/New_York");
        let now = utc(2026, 11, 1, 4, 35); // 00:35 EDT, just past the fire time
        let next = next_run(&r, now);
        assert!(next > now, "weekly next_run regressed: {next}");
        if let Some(prev) = prev_occurrence(&r, now) {
            assert!(prev <= now, "weekly prev_occurrence in the future: {prev}");
        }
    }

    #[test]
    fn shift_local_date_walks_calendar_days_not_absolute_hours() {
        let d = chrono::NaiveDate::from_ymd_opt(2026, 11, 1).unwrap();
        assert_eq!(shift_local_date(d, 1).unwrap(), chrono::NaiveDate::from_ymd_opt(2026, 11, 2).unwrap());
        assert_eq!(shift_local_date(d, -1).unwrap(), chrono::NaiveDate::from_ymd_opt(2026, 10, 31).unwrap());
        assert_eq!(shift_local_date(d, 0).unwrap(), d);
        // Month/year boundaries.
        let dec31 = chrono::NaiveDate::from_ymd_opt(2026, 12, 31).unwrap();
        assert_eq!(shift_local_date(dec31, 1).unwrap(), chrono::NaiveDate::from_ymd_opt(2027, 1, 1).unwrap());
    }
}
