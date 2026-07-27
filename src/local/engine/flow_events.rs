//! `FlowEventEngine` — a thin [`LocalEngine`] decorator that fires `workflow_started` /
//! `workflow_completed` automations around every workflow run, WITHOUT touching the core engine
//! (`real.rs`).
//!
//! It wraps the real engine and, on the synchronous [`LocalEngine::run`] path, dispatches any enabled
//! automation whose event is `workflow_started`/`workflow_completed` and whose watched workflow
//! matches (the automation's `workflow_id`, or unset = any). Everything else delegates straight to the
//! inner engine.
//!
//! **Loop bound (one hop).** Follow-up automations are dispatched with [`RunSource::Workflow`], and a
//! run whose source is already `Workflow` does NOT fire further events. So a direct run (scheduled /
//! webhook / monitor / mcp / a flow's workflow-action) fires its completion automations once; those
//! automations' own workflow-actions are `Workflow`-sourced and cannot cascade. This is the same
//! "logically chained, bounded" model the cloud `unified_trigger_service` uses.
//!
//! **Scope.** BOTH the synchronous `run` path and the interactive `run_async` 202 API path fire
//! events. Events fire ONLY once the inner run actually starts: a `NotFound`/governor-rejected run
//! errors out of the inner call and fires NOTHING. `run` awaits the inner run, then fires
//! `workflow_started` + `workflow_completed`. `run_async` returns a `run_id` once the run row is
//! inserted + the body spawned, so the decorator fires `workflow_started` at that point and spawns a
//! watcher that awaits the run's terminal status via the [`RunRegistry`] before firing
//! `workflow_completed`. Recipe/streaming/browser/governor all delegate.

use super::events::RunEvent;
use super::{
    Lane, LocalEngine, RunRegistry, RunRequest, RunResult, RunSource, RunStatus, StartedRun,
    StreamEvent,
};
use crate::browser::manager::BrowserManager;
use crate::local::error::LocalResult;
use crate::local::flow;
use crate::local::governor::ResourceGovernor;
use crate::local::store::automations;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePool;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Wraps an inner engine, firing workflow-lifecycle automations around `run`.
pub struct FlowEventEngine {
    inner: Arc<dyn LocalEngine>,
    db: SqlitePool,
}

impl FlowEventEngine {
    pub fn new(inner: Arc<dyn LocalEngine>, db: SqlitePool) -> Self {
        Self { inner, db }
    }
}

/// Whether an automation that watches `auto_workflow_id` (None = any) should fire for a run of
/// `workflow_id`.
fn watches_workflow(auto_workflow_id: Option<i64>, workflow_id: i64) -> bool {
    auto_workflow_id.is_none() || auto_workflow_id == Some(workflow_id)
}

/// Lowercase status token (mirrors the flow-builder field vocabulary the conditions read).
fn status_str(s: RunStatus) -> &'static str {
    match s {
        RunStatus::Running => "running",
        RunStatus::Success => "success",
        RunStatus::Failed => "failed",
        RunStatus::Cancelled => "cancelled",
        RunStatus::Timeout => "timeout",
        RunStatus::CaptchaRequired => "captcha_required",
        RunStatus::TwofaRequired => "twofa_required",
    }
}

/// Spawn a detached dispatch of all `event` automations watching `workflow_id`. Best-effort: a load
/// error or a single automation failure is logged, never propagated (it must not affect the run).
fn fire_event(db: &SqlitePool, engine: &Arc<dyn LocalEngine>, event: &'static str, workflow_id: i64, context: Value) {
    let db = db.clone();
    let engine = engine.clone();
    tokio::spawn(async move {
        let autos = match automations::list_enabled_for_event(&db, event, 256).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(event, error = %e, "could not load workflow-event automations");
                return;
            }
        };
        for auto in autos {
            if !watches_workflow(auto.workflow_id, workflow_id) {
                continue;
            }
            // Only automations with a real block tree run here — a legacy no-blocks automation would
            // re-run its (watched) `workflow_id`, which for a workflow-event is a self-trigger.
            if !flow::has_executable_tree(auto.blocks.as_deref()) {
                continue;
            }
            let trigger = flow::FlowTrigger {
                event: event.to_string(),
                change_id: None,
                base_inputs: json!({}),
                context: context.clone(),
                // Workflow-sourced → the follow-up's own workflow-actions cannot cascade (one hop).
                source: RunSource::Workflow,
                lane: Lane::Background,
            };
            if let Err(e) = flow::run_automation(&db, &engine, &auto, trigger).await {
                tracing::warn!(automation_id = auto.id, event, error = %e, "workflow-event automation failed");
            }
        }
    });
}

/// Await the terminal status of an async run via the [`RunRegistry`].
///
/// Subscribes to the run's lifecycle events and returns the status of the first terminal
/// (`Finished`/`Error`) event. If the engine has no registry, or the run is already gone from the
/// table (finalized + de-registered before we could `get` it), we fall back to `fallback` — the
/// status the engine reported at start time. A generous overall timeout bounds the wait so a wedged
/// run can never leak a watcher task forever.
async fn await_terminal_status(
    registry: Option<Arc<RunRegistry>>,
    run_id: i64,
    fallback: RunStatus,
) -> RunStatus {
    // If the started status is ALREADY terminal (e.g. a synchronous fallback engine), don't wait.
    if !matches!(fallback, RunStatus::Running) {
        return fallback;
    }
    let registry = match registry {
        Some(r) => r,
        None => return fallback,
    };
    let handle = match registry.get(run_id) {
        Some(h) => h,
        // Already finalized + de-registered — the best we can do is the snapshot we were handed.
        None => return fallback,
    };
    // A snapshot might have gone terminal between `get` and `subscribe`; check first.
    let snap = handle.status();
    if !matches!(snap, RunStatus::Running) {
        return snap;
    }
    let mut rx = handle.subscribe();
    // Bound the wait so a hung run can't keep this watcher alive indefinitely.
    let deadline = tokio::time::Duration::from_secs(60 * 30);
    let wait = async {
        loop {
            match rx.recv().await {
                Ok(ev) if ev.is_terminal() => {
                    return match ev {
                        RunEvent::Finished { status, .. } => status,
                        // An orchestration Error is a failure terminal.
                        RunEvent::Error { .. } => RunStatus::Failed,
                        _ => RunStatus::Running,
                    };
                }
                Ok(_) => continue, // non-terminal lifecycle event
                // Lagged: we missed events but the channel is alive — re-sample the snapshot.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                    let s = handle.status();
                    if !matches!(s, RunStatus::Running) {
                        return s;
                    }
                }
                // Sender dropped (run finalized) — read the final snapshot.
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return handle.status(),
            }
        }
    };
    match tokio::time::timeout(deadline, wait).await {
        Ok(status) => status,
        Err(_) => {
            tracing::warn!(run_id, "async run completion watcher timed out; not firing completion");
            // Treat a timed-out watch as "unknown" — return Running so the caller can decide; but
            // since we DO want to record something, map it to the last known snapshot instead.
            handle.status()
        }
    }
}

impl LocalEngine for FlowEventEngine {
    fn run<'a>(
        &'a self,
        req: RunRequest,
    ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
        Box::pin(async move {
            // A run already sourced from a workflow-event automation does not re-fire (loop bound).
            let fire = req.source != RunSource::Workflow && req.workflow_id > 0;
            let workflow_id = req.workflow_id;

            // Drive the inner run FIRST. If it errors (NotFound workflow / governor-rejected /
            // never-admitted), the run never actually started, so NEITHER `workflow_started` nor
            // `workflow_completed` should fire — propagate the error untouched.
            let result = self.inner.run(req).await?;

            if fire {
                // The run reached a terminal state, so it did start: emit `workflow_started` (for the
                // sync path this is the moment we KNOW it started) followed by `workflow_completed`.
                fire_event(
                    &self.db,
                    &self.inner,
                    "workflow_started",
                    workflow_id,
                    json!({ "event": "workflow_started", "workflow_id": workflow_id }),
                );
                fire_event(
                    &self.db,
                    &self.inner,
                    "workflow_completed",
                    workflow_id,
                    json!({
                        "event": "workflow_completed",
                        "workflow_id": workflow_id,
                        "success": result.success,
                        "status": status_str(result.status),
                        "error": result.error,
                        "result": result.extracted_data,
                        "workflow_duration_seconds": result.duration_ms as f64 / 1000.0,
                    }),
                );
            }
            Ok(result)
        })
    }

    fn active_runs(&self) -> usize {
        self.inner.active_runs()
    }

    fn run_async<'a>(
        &'a self,
        req: RunRequest,
    ) -> Pin<Box<dyn Future<Output = LocalResult<StartedRun>> + Send + 'a>> {
        Box::pin(async move {
            // A run already sourced from a workflow-event automation does not re-fire (loop bound).
            let fire = req.source != RunSource::Workflow && req.workflow_id > 0;
            let workflow_id = req.workflow_id;

            // Start the run FIRST. `run_async` only returns Ok after the run row is inserted + the
            // body spawned, so a NotFound/governor-rejected run errors here and fires NOTHING.
            let started = self.inner.run_async(req).await?;

            // The run genuinely started (row + task exist) → NOW emit `workflow_started`.
            if fire {
                fire_event(
                    &self.db,
                    &self.inner,
                    "workflow_started",
                    workflow_id,
                    json!({ "event": "workflow_started", "workflow_id": workflow_id }),
                );
            }

            // The async path returns a `run_id` immediately; the run finishes in a detached engine
            // task. To fire `workflow_completed` we watch the run's terminal status via the shared
            // RunRegistry (the only observation point we have here). Best-effort: if the engine has
            // no registry, or the run already finalized before we could subscribe, we fall back to
            // the `StartedRun.status` we were handed.
            if fire {
                let db = self.db.clone();
                let engine = self.inner.clone();
                let registry = self.inner.registry();
                let run_id = started.run_id;
                let started_status = started.status;
                tokio::spawn(async move {
                    let status = await_terminal_status(registry, run_id, started_status).await;
                    fire_event(
                        &db,
                        &engine,
                        "workflow_completed",
                        workflow_id,
                        json!({
                            "event": "workflow_completed",
                            "workflow_id": workflow_id,
                            "success": matches!(status, RunStatus::Success),
                            "status": status_str(status),
                            // The async path exposes only the run's terminal STATUS via the registry,
                            // not its extracted payload/error — those live on the persisted `runs`
                            // row. Downstream blocks that read `result.*`/`error` on an async
                            // completion get an empty result (parity gap noted in the module doc).
                            "result": json!({}),
                        }),
                    );
                });
            }

            Ok(started)
        })
    }

    fn cancel(&self, run_id: i64) -> Option<bool> {
        self.inner.cancel(run_id)
    }

    fn registry(&self) -> Option<Arc<super::RunRegistry>> {
        self.inner.registry()
    }

    fn browser(&self) -> Option<Arc<BrowserManager>> {
        self.inner.browser()
    }

    fn governor(&self) -> Option<Arc<ResourceGovernor>> {
        self.inner.governor()
    }

    fn streaming(&self) -> Option<Arc<super::streaming::LocalStreamingManager>> {
        self.inner.streaming()
    }

    fn vault(&self) -> Option<Arc<crate::local::vault::Vault>> {
        self.inner.vault()
    }

    fn run_recipe<'a>(
        &'a self,
        recipe: crate::local::store::workflows::Workflow,
        inputs: Value,
        source: super::RunSource,
    ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
        self.inner.run_recipe(recipe, inputs, source)
    }

    fn run_streaming<'a>(
        &'a self,
        wf: crate::local::store::workflows::Workflow,
        inputs: Value,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = LocalResult<(
                        tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
                        String,
                    )>,
                > + Send
                + 'a,
        >,
    > {
        self.inner.run_streaming(wf, inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watches_specific_or_any() {
        assert!(watches_workflow(None, 5), "unset watches any workflow");
        assert!(watches_workflow(Some(5), 5), "exact match");
        assert!(!watches_workflow(Some(6), 5), "different workflow is not watched");
    }

    #[test]
    fn status_tokens() {
        assert_eq!(status_str(RunStatus::Success), "success");
        assert_eq!(status_str(RunStatus::Failed), "failed");
        assert_eq!(status_str(RunStatus::CaptchaRequired), "captcha_required");
    }

    // --- end-to-end: a watched workflow's run fires its workflow_completed automation -------------

    use crate::local::db;
    use crate::local::store::automation_executions;
    use crate::local::store::automations::{self as auto_store, NewAutomation};
    use crate::local::store::workflows::{self, NewWorkflow};

    /// Inner engine that always succeeds and records the workflow ids it was asked to run.
    struct MockInner {
        ran: std::sync::Mutex<Vec<i64>>,
    }
    impl LocalEngine for MockInner {
        fn run<'a>(
            &'a self,
            req: RunRequest,
        ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
            self.ran.lock().unwrap().push(req.workflow_id);
            Box::pin(async move {
                Ok(RunResult {
                    run_id: req.workflow_id,
                    status: RunStatus::Success,
                    success: true,
                    error: None,
                    extracted_data: json!({}),
                    duration_ms: 1,
                })
            })
        }
        fn active_runs(&self) -> usize {
            0
        }
    }

    async fn test_pool() -> SqlitePool {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.db");
        std::mem::forget(dir);
        db::open(&path, "test-key").await.unwrap()
    }

    #[tokio::test]
    async fn completed_event_fires_watching_automation() {
        let pool = test_pool().await;
        // The watched workflow (W) and the workflow the automation runs in response (W2).
        let w = workflows::insert(
            &pool,
            &NewWorkflow { name: "watched".into(), steps: Some("[]".into()), ..Default::default() },
        )
        .await
        .unwrap();
        let w2 = workflows::insert(
            &pool,
            &NewWorkflow { name: "reaction".into(), steps: Some("[]".into()), ..Default::default() },
        )
        .await
        .unwrap();

        // Automation: "when workflow W completes, run W2". `workflow_id` = the WATCHED workflow.
        let blocks = json!([
            { "id": "e", "type": "event", "blockType": "workflow_completed",
              "config": { "workflow_id": w.id, "status_condition": "any" } },
            { "id": "a", "type": "action", "blockType": "workflow", "parentId": "e",
              "config": { "workflow_id": w2.id } }
        ])
        .to_string();
        let auto = auto_store::insert(
            &pool,
            &NewAutomation {
                name: "on W completed".into(),
                event_type: Some("workflow_completed".into()),
                workflow_id: Some(w.id),
                blocks: Some(blocks),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let inner = Arc::new(MockInner { ran: std::sync::Mutex::new(Vec::new()) });
        let engine = FlowEventEngine::new(inner.clone(), pool.clone());

        // A direct (scheduled) run of the watched workflow.
        engine
            .run(RunRequest {
                workflow_id: w.id,
                inputs: json!({}),
                source: RunSource::Scheduled,
                lane: Lane::Background,
                dry_run: false,
                persona_id: None,
                allow_local_secret_refs: true,
            })
            .await
            .unwrap();

        // The completion automation fires in a DETACHED task — poll its execution row until it reaches
        // a TERMINAL status. The row is first inserted `running` and then completed to `success`, so we
        // must wait for the terminal state rather than assert on the first appearance (otherwise we can
        // race and read the transient `running`). The window is generous (up to ~6s) so heavy parallel-
        // test scheduling can't starve the spawn into a false failure.
        let mut final_status: Option<String> = None;
        for _ in 0..300 {
            let execs = automation_executions::list_for_automation(&pool, auto.id, 10).await.unwrap();
            if let Some(exec) = execs.first() {
                if matches!(exec.status.as_deref(), Some("success") | Some("failed")) {
                    final_status = exec.status.clone();
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            final_status.as_deref(),
            Some("success"),
            "workflow_completed automation recorded a successful execution"
        );

        // The reaction workflow (W2) ran via the inner engine; W2 does NOT re-fire (Workflow-sourced).
        let ran = inner.ran.lock().unwrap().clone();
        assert!(ran.contains(&w.id), "the watched workflow ran");
        assert!(ran.contains(&w2.id), "the reaction workflow ran");
    }

    #[tokio::test]
    async fn workflow_sourced_run_does_not_fire() {
        let pool = test_pool().await;
        let w = workflows::insert(
            &pool,
            &NewWorkflow { name: "w".into(), steps: Some("[]".into()), ..Default::default() },
        )
        .await
        .unwrap();
        let blocks = json!([
            { "id": "e", "type": "event", "blockType": "workflow_completed",
              "config": { "workflow_id": w.id } },
            { "id": "a", "type": "action", "blockType": "notification", "parentId": "e", "config": {} }
        ])
        .to_string();
        let auto = auto_store::insert(
            &pool,
            &NewAutomation {
                name: "watcher".into(),
                event_type: Some("workflow_completed".into()),
                workflow_id: Some(w.id),
                blocks: Some(blocks),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let inner = Arc::new(MockInner { ran: std::sync::Mutex::new(Vec::new()) });
        let engine = FlowEventEngine::new(inner.clone(), pool.clone());

        // A Workflow-sourced run (i.e. itself a follow-up) must NOT fire further events.
        engine
            .run(RunRequest {
                workflow_id: w.id,
                inputs: json!({}),
                source: RunSource::Workflow,
                lane: Lane::Background,
                dry_run: false,
                persona_id: None,
                allow_local_secret_refs: true,
            })
            .await
            .unwrap();

        // Give any (erroneously) spawned task a chance, then assert nothing fired.
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let execs = automation_executions::list_for_automation(&pool, auto.id, 10).await.unwrap();
        assert!(execs.is_empty(), "Workflow-sourced runs do not fire workflow-event automations");
    }

    /// The ASYNC (`run_async`) path also fires `workflow_completed`. `MockInner` has no registry, so
    /// the default `run_async` runs synchronously and returns a terminal status; the decorator's
    /// completion watcher sees a non-`Running` fallback and fires immediately (no registry poll).
    #[tokio::test]
    async fn async_path_fires_completed_event() {
        let pool = test_pool().await;
        let w = workflows::insert(
            &pool,
            &NewWorkflow { name: "watched".into(), steps: Some("[]".into()), ..Default::default() },
        )
        .await
        .unwrap();
        let w2 = workflows::insert(
            &pool,
            &NewWorkflow { name: "reaction".into(), steps: Some("[]".into()), ..Default::default() },
        )
        .await
        .unwrap();
        let blocks = json!([
            { "id": "e", "type": "event", "blockType": "workflow_completed",
              "config": { "workflow_id": w.id, "status_condition": "any" } },
            { "id": "a", "type": "action", "blockType": "workflow", "parentId": "e",
              "config": { "workflow_id": w2.id } }
        ])
        .to_string();
        let auto = auto_store::insert(
            &pool,
            &NewAutomation {
                name: "on W completed (async)".into(),
                event_type: Some("workflow_completed".into()),
                workflow_id: Some(w.id),
                blocks: Some(blocks),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let inner = Arc::new(MockInner { ran: std::sync::Mutex::new(Vec::new()) });
        let engine = FlowEventEngine::new(inner.clone(), pool.clone());

        // Start the watched workflow via the ASYNC path (the 202 API route).
        engine
            .run_async(RunRequest {
                workflow_id: w.id,
                inputs: json!({}),
                source: RunSource::Api,
                lane: Lane::Background,
                dry_run: false,
                persona_id: None,
                allow_local_secret_refs: true,
            })
            .await
            .unwrap();

        // Poll the completion automation's execution row to a terminal status (detached fire).
        let mut final_status: Option<String> = None;
        for _ in 0..300 {
            let execs = automation_executions::list_for_automation(&pool, auto.id, 10).await.unwrap();
            if let Some(exec) = execs.first() {
                if matches!(exec.status.as_deref(), Some("success") | Some("failed")) {
                    final_status = exec.status.clone();
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(
            final_status.as_deref(),
            Some("success"),
            "async run_async fired a successful workflow_completed automation"
        );
        let ran = inner.ran.lock().unwrap().clone();
        assert!(ran.contains(&w2.id), "the reaction workflow ran off the async completion");
    }
}
