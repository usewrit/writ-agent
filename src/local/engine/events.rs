//! Run lifecycle events (STAGE E2) — the wire vocabulary streamed over `GET /v1/runs/:id/events`
//! and fanned out per-run by the [`super::registry::RunRegistry`].
//!
//! A live run emits, in order: one [`RunEvent::Started`], then a [`RunEvent::Step`] per executed
//! step (with a coarse `status`), interleaved with optional [`RunEvent::Progress`] hints, and
//! finally exactly one terminal [`RunEvent::Finished`] (or a [`RunEvent::Error`] when the
//! orchestration itself failed before/around the step loop). Subscribers MUST treat `Finished`
//! and `Error` as stream-closing.
//!
//! ## Secret hygiene
//! Events carry only structural metadata — run id, step index, step *type*, a status enum, counts.
//! They NEVER carry extracted values, credentials, form data, URLs with query strings, or error
//! bodies that could embed a secret. The `Error`/`Step` messages are operator-facing classifications
//! (e.g. "navigation failed"), the same surface already written to the `runs` row, never a raw value.

use super::RunStatus;
use serde::Serialize;

/// Coarse per-step lifecycle marker. A step emits `Running` as it starts and exactly one terminal
/// (`Succeeded` / `Failed` / `Skipped`) as it resolves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// The step has begun executing.
    Running,
    /// The step finished without error.
    Succeeded,
    /// The step errored (the run will terminate after this).
    Failed,
    /// The step was disabled / unparseable / had no type — not executed.
    Skipped,
}

/// A single run-lifecycle event. `Clone` because it is broadcast to N subscribers; small + cheap.
///
/// Serializes to a tagged JSON object (`{"event":"step", ...}`) so an SSE client can branch on the
/// `event` discriminant without positional parsing.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RunEvent {
    /// The run has been registered and is about to drive its steps. `total_steps` is the count of
    /// raw steps the engine will iterate (including ones it may skip).
    Started { run_id: i64, total_steps: usize },
    /// A step transitioned. `index` is 0-based into the raw step list; `step_type` is the recorded
    /// step kind (e.g. `click`, `wait`, `extract`) — never a value.
    Step {
        run_id: i64,
        index: usize,
        step_type: String,
        status: StepStatus,
    },
    /// A coarse progress hint: `completed` of `total` steps done. Cheap heartbeat for a progress bar.
    Progress {
        run_id: i64,
        completed: usize,
        total: usize,
    },
    /// The run's current step FAILED and AI auto-repair is now running (the run is NOT finished — it
    /// will resume once repair completes). Non-terminal. `slow` distinguishes the heavy re-record /
    /// whole-recipe rebuild (which can take 1–2 min → the UI should notify) from the fast per-step
    /// selector fix (a badge is enough). Surfaces as a `repairing` run state everywhere run state is
    /// shown; the engine also flips the persisted row to `status="repairing"` so a refetch sees it.
    Repairing { run_id: i64, slow: bool },
    /// Terminal: the run reached a final status. Stream-closing.
    Finished { run_id: i64, status: RunStatus },
    /// Terminal: the run failed around the step loop (resolution/launch/panic). `message` is an
    /// operator-facing classification, never a raw secret/value. Stream-closing.
    Error { run_id: i64, message: String },
    /// A CLOUD-REFLECTED run (a linked account's run executing on Writ Cloud, not on this device)
    /// changed state — injected into the GLOBAL stream by the cloud run-events forwarder, NOT by a
    /// local run. It is a pure NUDGE: the desktop shell forwards it as a Tauri `run:event`, and the
    /// webview refetches its cloud reflection. Carries only the cloud task id (no value/secret) and
    /// never appears on a per-run stream. Non-terminal (it never closes a stream).
    CloudReflected { task_id: i64 },
    /// A cloud RECORD (workflow / monitor / change / crawl / dataset / trigger) was created, updated
    /// or deleted — injected into the GLOBAL stream by the cloud run-events forwarder when the cloud
    /// frame carries the backend's `event: "entity"` discriminant (see
    /// the cloud backend's `run_events` service::emit_entity_event`). Unlike the run variants this describes a
    /// record, not an execution, so it lets a cloud-reflected LIST refresh after an edit made in the
    /// web app instead of waiting for a hard reload.
    ///
    /// Carries only control metadata — the record TYPE, the action, and row ids. Never a name, URL,
    /// extracted value or any other payload field, per this module's secret-hygiene rule.
    ///
    /// Serializes with the tag `entity` (not `cloud_entity`) so the frame the webview receives over
    /// the Tauri `run:event` IPC is shape-identical to the cloud's own SSE frame, and one client-side
    /// handler covers both transports. Never appears on a per-run stream; non-terminal.
    #[serde(rename = "entity")]
    CloudEntity {
        entity: String,
        action: String,
        id: Option<i64>,
        target_id: Option<i64>,
    },
}

impl RunEvent {
    /// The run id this event belongs to (every variant carries one).
    pub fn run_id(&self) -> i64 {
        match self {
            RunEvent::Started { run_id, .. }
            | RunEvent::Step { run_id, .. }
            | RunEvent::Progress { run_id, .. }
            | RunEvent::Repairing { run_id, .. }
            | RunEvent::Finished { run_id, .. }
            | RunEvent::Error { run_id, .. } => *run_id,
            // A cloud-reflected nudge carries the cloud task id (never routed to a per-run stream).
            RunEvent::CloudReflected { task_id } => *task_id,
            // Not a run at all — it describes a record. Global-stream only, so this id is never used
            // for routing; 0 keeps the accessor total.
            RunEvent::CloudEntity { .. } => 0,
        }
    }

    /// True for the two stream-closing variants (`Finished` / `Error`). An SSE writer uses this to
    /// end the stream after delivering the event.
    pub fn is_terminal(&self) -> bool {
        matches!(self, RunEvent::Finished { .. } | RunEvent::Error { .. })
    }

    /// The SSE `event:` field name (matches the serde tag), so a client can register typed listeners.
    pub fn name(&self) -> &'static str {
        match self {
            RunEvent::Started { .. } => "started",
            RunEvent::Step { .. } => "step",
            RunEvent::Progress { .. } => "progress",
            RunEvent::Repairing { .. } => "repairing",
            RunEvent::Finished { .. } => "finished",
            RunEvent::Error { .. } => "error",
            RunEvent::CloudReflected { .. } => "cloud_reflected",
            RunEvent::CloudEntity { .. } => "entity",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_classification() {
        assert!(RunEvent::Finished { run_id: 1, status: RunStatus::Success }.is_terminal());
        assert!(RunEvent::Error { run_id: 1, message: "x".into() }.is_terminal());
        assert!(!RunEvent::Started { run_id: 1, total_steps: 3 }.is_terminal());
        assert!(!RunEvent::Progress { run_id: 1, completed: 1, total: 3 }.is_terminal());
    }

    #[test]
    fn run_id_and_name_are_consistent() {
        let e = RunEvent::Step {
            run_id: 7,
            index: 2,
            step_type: "click".into(),
            status: StepStatus::Running,
        };
        assert_eq!(e.run_id(), 7);
        assert_eq!(e.name(), "step");
    }

    /// The JSON shape is tagged on `event` and never leaks a value field.
    #[test]
    fn serializes_tagged() {
        let v = serde_json::to_value(RunEvent::Finished {
            run_id: 9,
            status: RunStatus::Success,
        })
        .unwrap();
        assert_eq!(v["event"], "finished");
        assert_eq!(v["run_id"], 9);
        assert_eq!(v["status"], "success");
    }

    #[test]
    fn step_status_serializes_snake_case() {
        assert_eq!(serde_json::to_value(StepStatus::Succeeded).unwrap(), "succeeded");
        assert_eq!(serde_json::to_value(StepStatus::Skipped).unwrap(), "skipped");
    }
}
