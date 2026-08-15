//! `RealEngine` — the ENG-6 keystone. Executes a RECORDED workflow end-to-end on the user's
//! machine and returns a [`RunResult`], persisting a `runs` row.
//!
//! ## Why a separate path (not a refactor of the cloud bridge)
//! The cloud run pipeline ([`crate::bridge::saas_bridge::handle_execute_workflow`]) is a
//! frame-SENDER: it is driven by a ws-gateway dispatch message, decrypts credentials with the
//! per-agent channel key, and emits `task_result` WS frames. Its orchestration is welded to that
//! transport. Rather than risk changing cloud behavior by extracting a shared orchestrator, this
//! engine reuses the genuine common core — the per-step executor
//! [`crate::automation::step_executor::execute_step`] plus the public [`BrowserManager`] /
//! navigation / url-guard helpers — and owns its own DB-rooted orchestration (load workflow row →
//! insert `runs` row → drive steps on a warm context → finalize the row + return a value). The
//! cloud path is untouched.
//!
//! ## CAPTCHA
//! Local/OSS runs are unattended and have no captcha-solving capability (that is the paid cloud
//! feature). When a step reports a CAPTCHA ([`StepError::CaptchaNotSolved`] /
//! [`StepError::CaptchaBotDetected`]) the run finalizes as `captcha_required` and returns
//! [`RunStatus::CaptchaRequired`] — it never attempts to solve.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sqlx::SqlitePool;

use super::events::{RunEvent, StepStatus};
use super::registry::{CancelToken, EmitGuard, RunRegistry, StepEmitter};
use super::streaming::{LocalStreamingManager, StreamEvent};
use super::{
    persona, resolve, twofa, Lane, RunIdSink, RunRequest, RunResult, RunSource, RunStatus, StartedRun,
};
use crate::automation::files::RunFiles;
use crate::automation::step_executor::{execute_step_ctx, is_dispatchable, StepError, StepRunContext};
use crate::browser::manager::BrowserManager;
use crate::config::env::AppConfig;
use crate::local::error::{LocalError, LocalResult};
use crate::local::governor::{GovernorConfig, ResourceGovernor, RunPermit};
use crate::local::store::{runs, workflows};
use crate::local::vault::Vault;
use crate::models::workflow::WorkflowStepConfig;

/// Per-action element wait for selector-driven steps (fill/click/select/check/…): how long a step
/// waits for its target element before failing. Deliberately SHORT so a moved/removed selector on a
/// changed site hands off to AI auto-repair in seconds instead of stalling ~30s per action (and up
/// to ~60s when a fill stacks its fallback tiers). Navigation keeps the full workflow budget
/// (`timeout_ms`) via a separate Playwright timeout, so slow page loads are unaffected.
const STEP_ACTION_TIMEOUT_MS: u64 = 8_000;

/// The real, browser-backed local execution engine.
///
/// Holds a shared warm-browser manager (lazily launched on first run), the encrypted-store pool,
/// and the vault (for decrypting a workflow's sealed `credentials_encrypted` Layer-B blob).
/// Cheaply cloneable internals are `Arc`-wrapped so the engine lives behind `Arc<dyn LocalEngine>`.
pub struct RealEngine {
    db: SqlitePool,
    vault: Arc<Vault>,
    browser: Arc<BrowserManager>,
    active: Arc<AtomicUsize>,
    /// Live-run table (STAGE E2): event fan-out + cancel tokens, keyed by `run_id`. Shared with the
    /// API layer via [`super::LocalEngine::registry`] so `/v1/runs/:id/events` + `cancel` route here.
    registry: Arc<RunRegistry>,
    /// Find-or-lazily-start manager for long-lived STREAMING sessions (the OpenAI-compat
    /// `stream:true` path). Shares the SAME warm `BrowserManager` so a chat tab reuses the one
    /// Chromium runs + recording already hold.
    streaming: Arc<LocalStreamingManager>,
    /// Process-wide resource governor (PROD-14): bounds concurrent runs by lane (interactive priority,
    /// background sub-ceiling) and sheds background work over a soft RSS watermark. Every run acquires
    /// a permit by lane BEFORE launching a browser context; the scheduler shares the SAME `Arc` to
    /// consult the watermark before heavy ticks (see [`Self::governor`]).
    governor: Arc<ResourceGovernor>,
    /// Per-workflow AI-repair lock. While one run repairs a workflow, other runs of it wait at their
    /// start until the repair finishes, then run the repaired recipe (no duplicate/racing repairs).
    repair_gate: super::repair_gate::RepairGate,
}

impl RealEngine {
    /// Build an engine over an existing browser manager (shared with the recorder, so runs reuse
    /// the one warm Chromium). Uses the DEFAULT governor ceilings; prefer [`Self::with_governor`] to
    /// honor the user's `[engine]` config.
    pub fn new(db: SqlitePool, vault: Arc<Vault>, browser: Arc<BrowserManager>) -> Self {
        Self::with_governor(db, vault, browser, GovernorConfig::default())
    }

    /// Build an engine over an existing browser manager with explicit governor ceilings (folded from
    /// the user's `[engine]` config via [`GovernorConfig::from_local`]).
    pub fn with_governor(
        db: SqlitePool,
        vault: Arc<Vault>,
        browser: Arc<BrowserManager>,
        gov_cfg: GovernorConfig,
    ) -> Self {
        // PROD-14 (second half): the governor bounds RUNS, but every other user of this same warm
        // browser — recording, crawl-shard browser fallbacks, streaming, concierge/browse, monitor
        // checks — reaches `BrowserManager` directly with no ceiling at all. Push a derived ceiling
        // into the manager so total LIVE contexts are bounded no matter which entry point asked. This
        // is the single funnel every `RealEngine` constructor goes through, so it is the one place
        // that has both the governor config and the manager.
        browser.set_context_limit(gov_cfg.max_browser_contexts());

        let streaming = Arc::new(LocalStreamingManager::new(
            browser.clone(),
            db.clone(),
            vault.clone(),
        ));
        Self {
            db,
            vault,
            browser,
            active: Arc::new(AtomicUsize::new(0)),
            registry: Arc::new(RunRegistry::new()),
            streaming,
            governor: Arc::new(ResourceGovernor::new(gov_cfg)),
            repair_gate: super::repair_gate::RepairGate::default(),
        }
    }

    /// Build an engine that owns a fresh `BrowserManager` derived from process env. Convenience for
    /// the single-process desktop binary where there is no separate recorder to share with. Uses the
    /// DEFAULT governor ceilings.
    pub fn with_env_browser(db: SqlitePool, vault: Arc<Vault>) -> Self {
        let browser = Arc::new(BrowserManager::new(Arc::new(AppConfig::from_env())));
        Self::new(db, vault, browser)
    }

    /// Like [`Self::with_env_browser`] but honors explicit governor ceilings (folded from the user's
    /// `[engine]` config). The single-process daemon (`app::lifecycle::bootstrap`) uses this so the
    /// configured resource ceilings take effect.
    pub fn with_env_browser_governed(db: SqlitePool, vault: Arc<Vault>, gov_cfg: GovernorConfig) -> Self {
        let browser = Arc::new(BrowserManager::new(Arc::new(AppConfig::from_env())));
        Self::with_governor(db, vault, browser, gov_cfg)
    }

    /// Like [`Self::with_env_browser_governed`] but takes an EXPLICIT browser [`AppConfig`] instead of
    /// deriving it purely from process env. The single-process daemon (`app::lifecycle::bootstrap`)
    /// uses this to seed the browser config from the user's `config.toml` `[browser]` section (e.g. the
    /// global `headless` default) on top of the env-derived base, so a UI-set browser knob actually
    /// takes effect on the warm browser. Governor ceilings are honored via `gov_cfg`.
    pub fn with_app_config_governed(
        db: SqlitePool,
        vault: Arc<Vault>,
        app_config: AppConfig,
        gov_cfg: GovernorConfig,
    ) -> Self {
        let browser = Arc::new(BrowserManager::new(Arc::new(app_config)));
        Self::with_governor(db, vault, browser, gov_cfg)
    }

    /// The shared resource governor. The daemon hands this SAME `Arc` to the scheduler so its tick can
    /// consult [`ResourceGovernor::should_shed_background`] before dispatching heavy background work.
    pub fn governor(&self) -> Arc<ResourceGovernor> {
        self.governor.clone()
    }

    /// The synchronous run (load workflow → open run row → drive steps → finalize), owning all
    /// `&self` borrows so the boxed future in the trait impl is `'a`. STAGE E2: registers a live
    /// [`EmitGuard`] for the run's lifetime so events stream + cancel routes even on the blocking
    /// path, then runs the shared body.
    ///
    /// MARKETPLACE PROXY (0017): a row with `marketplace_slug` set never executes its own (empty)
    /// steps — [`Self::prepare_marketplace_exec`] swaps in the unsealed sealed-recipe (after the
    /// paid authorize gate, BEFORE any `runs` row exists), the run/rollup stays bound to the proxy
    /// row, and the metered charge is finalized after the body returns.
    ///
    /// `on_start` (when present) is invoked with the freshly allocated `run_id` the moment the `runs`
    /// row exists and BEFORE the body executes, so a caller that dispatched this run under an
    /// EXTERNAL id (a fleet `task_id`) can record the mapping and later cancel it by run id. See
    /// [`super::LocalEngine::run_tracked`].
    // `req` is only mutated by the cloud-gated marketplace-proxy swap below.
    #[cfg_attr(not(feature = "cloud"), allow(unused_mut))]
    async fn run_inner(
        &self,
        mut req: RunRequest,
        on_start: Option<RunIdSink<'_>>,
    ) -> LocalResult<RunResult> {
        // PROD-14: acquire a governor permit by lane BEFORE opening the run row. Interactive runs wait
        // for a slot (priority); background runs that hit the ceiling/watermark fail fast with a busy
        // error — and we never insert a `runs` row for a run we refuse to start.
        let permit = self
            .governor
            .admit(req.lane)
            .await
            .map_err(|reject| LocalError::Internal(format!("run rejected: {}", reject.as_str())))?;
        let mut wf = self.load_workflow(&req).await?;
        // REPAIR LOCK (entry barrier): if another run is currently repairing this workflow, wait for
        // that repair to finish, then reload so THIS run uses the freshly repaired recipe instead of
        // racing it / re-failing on the stale one. Best-effort here; the in-loop `try_begin` below is
        // the actual guarantee against duplicate concurrent repairs.
        if self.repair_gate.is_repairing(wf.id) {
            self.repair_gate.wait_if_repairing(wf.id).await;
            wf = self.load_workflow(&req).await?;
        }
        #[cfg(feature = "cloud")]
        let mp_exec = self.prepare_marketplace_exec(&wf, &mut req).await?;
        let run_id = self.insert_run_row(&req, wf.id).await?;
        // Publish the run id to the dispatcher BEFORE the body starts, so a cancel that arrives one
        // millisecond after dispatch already has something to cancel.
        if let Some(sink) = on_start {
            sink(run_id);
        }
        let guard = self.registry.register(run_id);
        // A persisted workflow has a rollup row to record the outcome against (its id).
        let rollup_id = Some(wf.id);
        #[cfg(feature = "cloud")]
        let (exec_wf, mp_settle) = match mp_exec {
            Some(m) => (m.exec_wf, Some((m.slug, m.metered_id))),
            None => (wf, None),
        };
        #[cfg(not(feature = "cloud"))]
        let exec_wf = wf;
        let result = Self::run_body(
            self.db.clone(),
            self.vault.clone(),
            self.browser.clone(),
            self.active.clone(),
            exec_wf,
            rollup_id,
            req,
            guard,
            permit,
            self.repair_gate.clone(),
        )
        .await;
        #[cfg(feature = "cloud")]
        Self::settle_marketplace_run(&self.db, mp_settle, &result).await;
        Ok(result)
    }

    /// Run an EPHEMERAL in-memory recipe (marketplace protected executor) to completion and return its
    /// terminal [`RunResult`]. The recipe is NEVER persisted as a workflow row: we insert a `runs` row
    /// with `workflow_id = NULL` so it shows in `/v1/runs` (read-only over the `runs` table) without a
    /// workflow rollup, register a live [`EmitGuard`] (so `/v1/runs/:id/events` + cancel work), and
    /// drive the SAME `run_body` the normal path uses. The caller (the marketplace executor) gets the
    /// real `status` + `duration_ms` to finalize a metered charge.
    ///
    /// The passed `recipe` MUST be BYO-clean (`credentials_encrypted = None`, `default_persona_id =
    /// None`); resolution then pulls only the CONSUMER's own vault secrets + inputs. The recipe is held
    /// only in memory here and dropped when this returns.
    async fn run_recipe_inner(
        &self,
        recipe: workflows::Workflow,
        inputs: serde_json::Value,
        source: RunSource,
    ) -> LocalResult<RunResult> {
        let permit = self
            .governor
            .admit(Lane::Interactive)
            .await
            .map_err(|reject| LocalError::Internal(format!("run rejected: {}", reject.as_str())))?;

        // Insert a runs row with NO workflow_id (the recipe has no persisted workflow row). The
        // `runs.workflow_id` column is nullable, so this surfaces in /v1/runs without a rollup. The
        // trigger_context `source` tag lets the UI distinguish where the ephemeral run came from
        // (the marketplace protected executor vs. a cloud-account dispatch).
        let context_source = match source {
            RunSource::CloudAgent => "cloud_agent",
            _ => "marketplace",
        };
        // `recipe_name` is the ONLY record of what an ephemeral run is running: the recipe has no
        // persisted `workflows` row, so `runs.workflow_id` is NULL and there is nothing to join a
        // display name from. Without it every ad-hoc run is an anonymous row. It's a name, not a
        // value — no secret/credential material (the recipe's creds live in its sealed blob).
        let trigger_context = serde_json::to_string(&serde_json::json!({
            "inputs": inputs,
            "lane": "interactive",
            "dry_run": false,
            "source": context_source,
            "recipe_name": recipe.name,
        }))
        .ok();
        let run = runs::insert(
            &self.db,
            &runs::NewRun {
                workflow_id: None,
                trigger_type: Some(trigger_type_for(source).to_string()),
                trigger_context,
                ..Default::default()
            },
        )
        .await?;

        let req = RunRequest {
            workflow_id: 0,
            inputs,
            source,
            lane: Lane::Interactive,
            dry_run: false,
            // BYO-clean recipe: persona/creds come from the consumer's own data, never a pinned id.
            persona_id: None,
            // TB-2: an AD-HOC recipe whose STEPS are authored cloud-side (`CloudAgent`) must NOT read
            // the local vault/file store — it resolves secrets only from its own sealed creds blob.
            // A marketplace recipe (`Api`) is BYO-clean and legitimately resolves the CONSUMER's own
            // local vault secrets, so it keeps full local resolution.
            allow_local_secret_refs: source != RunSource::CloudAgent,
        };
        let guard = self.registry.register(run.id);
        // No rollup row for an ephemeral recipe → None skips `record_run_outcome`.
        Ok(Self::run_body(
            self.db.clone(),
            self.vault.clone(),
            self.browser.clone(),
            self.active.clone(),
            recipe,
            None,
            req,
            guard,
            permit,
            self.repair_gate.clone(),
        )
        .await)
    }

    /// Load the workflow a [`RunRequest`] targets. A missing workflow is a clean `NotFound` —
    /// nothing has been inserted yet.
    async fn load_workflow(&self, req: &RunRequest) -> LocalResult<workflows::Workflow> {
        workflows::get_by_id(&self.db, req.workflow_id)
            .await?
            .ok_or_else(|| LocalError::NotFound(format!("workflow {}", req.workflow_id)))
    }

    /// Open the `runs` row (status='running') for a loaded workflow. The run id anchors everything
    /// that follows; if later steps blow up we still finalize THIS row. Kept separate from
    /// [`Self::load_workflow`] so fallible pre-run gates (the marketplace authorize step) can run
    /// in between WITHOUT ever leaving an orphaned row.
    async fn insert_run_row(&self, req: &RunRequest, workflow_id: i64) -> LocalResult<i64> {
        let trigger_context = serde_json::to_string(&serde_json::json!({
            "inputs": req.inputs,
            "lane": match req.lane { Lane::Interactive => "interactive", Lane::Background => "background" },
            "dry_run": req.dry_run,
        }))
        .ok();
        let run = runs::insert(
            &self.db,
            &runs::NewRun {
                workflow_id: Some(workflow_id),
                trigger_type: Some(trigger_type_for(req.source).to_string()),
                trigger_context,
                ..Default::default()
            },
        )
        .await?;
        Ok(run.id)
    }

    /// MARKETPLACE PROXY prep (0017): when the loaded row is a PROXY for an installed listing
    /// (`marketplace_slug` set), do the protected-executor front half BEFORE the `runs` row exists:
    ///   * load the install (sealed blob + the consumer's saved bindings),
    ///   * PAID gate — authorize a metered run cloud-side (a denial aborts with the cloud's reason;
    ///     no row, no charge),
    ///   * unseal the recipe IN MEMORY and build the BYO-clean EXEC workflow,
    ///   * apply the consumer's bindings: secret-slot → vault-key TOKEN RENAMES (names only, never
    ///     values), saved input DEFAULTS under the caller's per-run inputs, and the saved persona
    ///     when the caller didn't pick one.
    ///
    /// Returns `None` for a normal (non-proxy) workflow. The plaintext recipe lives only in the
    /// returned exec workflow and is dropped when the run ends.
    #[cfg(feature = "cloud")]
    async fn prepare_marketplace_exec(
        &self,
        wf: &workflows::Workflow,
        req: &mut RunRequest,
    ) -> LocalResult<Option<MarketplaceExec>> {
        use crate::local::cloud::marketplace as mp;
        use crate::local::store::installed_workflows;

        let Some(slug) = wf.marketplace_slug.as_deref().filter(|s| !s.is_empty()) else {
            return Ok(None);
        };
        let install = installed_workflows::get_by_slug(&self.db, slug).await?.ok_or_else(|| {
            LocalError::NotFound(format!("marketplace install '{slug}' — reinstall the listing"))
        })?;
        let bindings = mp::InstallBindings::parse(install.bindings.as_deref());

        let metered_id = mp::authorize_metered_run(&self.db, slug, install.is_free).await?;
        // SELF-HEALING unseal: a re-link mints a new channel key — a stale seal is refreshed from
        // the cloud (current key) and retried once, so old installs survive a fresh link.
        let recipe_json =
            mp::unseal_recipe_healing(&self.db, &self.vault, slug, &install.sealed_recipe).await?;
        let mut exec_wf = mp::build_recipe_workflow(slug, install.listing_title.as_deref(), &recipe_json);

        if !bindings.secrets.is_empty() {
            exec_wf.steps = mp::rename_secret_refs(&exec_wf.steps, &bindings.secrets);
            if let Some(raw) = exec_wf.raw_replay.take() {
                exec_wf.raw_replay = Some(mp::rename_secret_refs(&raw, &bindings.secrets));
            }
        }
        if !bindings.inputs.is_empty() {
            if req.inputs.is_null() {
                req.inputs = serde_json::Value::Object(serde_json::Map::new());
            }
            if let Some(obj) = req.inputs.as_object_mut() {
                for (k, v) in &bindings.inputs {
                    obj.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
        }
        if req.persona_id.is_none() && !bindings.persona_none {
            req.persona_id = bindings.persona_id;
        }
        Ok(Some(MarketplaceExec { exec_wf, slug: slug.to_string(), metered_id }))
    }

    /// MARKETPLACE settle (0017): after the body returns, finalize the metered charge (best-effort;
    /// the cloud reconciles the hold on its own timeout) and stamp the install's `last_run_at`.
    #[cfg(feature = "cloud")]
    async fn settle_marketplace_run(
        db: &SqlitePool,
        settle: Option<(String, Option<String>)>,
        result: &RunResult,
    ) {
        let Some((slug, metered_id)) = settle else { return };
        if let Some(mid) = metered_id {
            crate::local::cloud::marketplace::finalize_metered_run(
                db,
                &slug,
                &mid,
                result.success,
                result.duration_ms,
            )
            .await;
        }
        let _ = crate::local::store::installed_workflows::set_last_run(db, &slug).await;
    }

    /// The shared run body, on OWNED clones so both the synchronous path (`run_inner`) and the
    /// spawned path (`run_async`) can drive it. Emits lifecycle events through `guard`, isolates a
    /// step panic into a terminal failed [`RunResult`] (never a process abort), finalizes the `runs`
    /// row + workflow rollup, de-registers the run, and returns the mapped result.
    ///
    /// This NEVER returns `Err`: every outcome (success, classified failure, cancellation, panic) is
    /// a finalized `RunResult`. The only fallible step — opening the run row — happened in
    /// [`Self::insert_run_row`] before this is called.
    async fn run_body(
        db: SqlitePool,
        vault: Arc<Vault>,
        browser: Arc<BrowserManager>,
        active: Arc<AtomicUsize>,
        wf: workflows::Workflow,
        rollup_workflow_id: Option<i64>,
        req: RunRequest,
        guard: EmitGuard,
        permit: RunPermit,
        repair_gate: super::repair_gate::RepairGate,
    ) -> RunResult {
        // Hold the governor permit for the ENTIRE run body so the slot stays reserved until the run
        // finalizes; it releases on drop at the end of this function (success, failure, or panic
        // isolation all flow through here). Bound to `_permit` so it isn't dropped early.
        let _permit = permit;
        let started = Instant::now();
        let run_id = guard.run_id();
        // The rollup workflow row to record the outcome against, when this is a PERSISTED workflow run.
        // `None` for an ephemeral marketplace recipe (no workflow row to roll up).
        let workflow_id = rollup_workflow_id;
        let cancel = guard.cancel_token();

        // The overall budget for this run, derived from the workflow's OWN per-step budget. The permit
        // above is held for the whole body by design, so a run that never returns permanently consumes
        // a slot: with a background sub-ceiling of 2, two wedged runs reject every subsequent dispatch
        // forever. `wf.timeout_ms` was only ever applied per-step and per-navigation, and a step that
        // neither completes nor times out (a driver that stops answering, a page that never settles) is
        // outside that. This is the whole-run backstop that guarantees the permit is eventually freed.
        let budget = overall_run_budget(wf.timeout_ms, step_count_hint(&wf));

        // RAII, not fetch_add/fetch_sub. The manual pair leaked the counter whenever the body did not
        // reach its `fetch_sub` — a cancelled/aborted `run_body` future permanently inflated
        // `active_runs()`, which is exactly the number the fleet heartbeat advertises as "busy", so a
        // few cancellations made the worker look permanently full. The guard mirrors `_permit`.
        let _active = ActiveRunGuard::new(active);

        // Emit Started up front (total raw step count is computed inside `execute` after resolution;
        // here we publish a Started with the step count parsed from the workflow row so subscribers
        // who attach immediately see a structural frame). The authoritative per-step frames follow.
        let total_steps = step_count_hint(&wf);
        guard.emit(RunEvent::Started { run_id, total_steps });

        // Panic isolation: drive the step loop inside a spawned task whose JoinHandle surfaces a
        // panic as `Err(JoinError)` rather than unwinding into (and aborting) the daemon. The body
        // is fully owned (clones), so it is trivially Send + 'static.
        let exec = {
            let db = db.clone();
            let vault = vault.clone();
            let browser = browser.clone();
            let cancel = cancel.clone();
            // The spawned task publishes per-step events through a detached emitter (the guard's
            // broadcast sender), so it can emit without owning the `EmitGuard` — which we keep here
            // to write the terminal frame + de-register after the task joins.
            let emitter = guard.step_emitter();
            let repair_gate = repair_gate.clone();
            tokio::spawn(async move {
                // One recipe-level repair-restart is permitted per run (the self-heal budget).
                Self::execute(&db, &vault, &browser, &wf, &req, run_id, &cancel, &emitter, 1, &repair_gate, None).await
            })
        };

        // WHOLE-RUN TIMEOUT. `&mut exec` (a `JoinHandle` is `Unpin`) so the handle survives the
        // timeout and can be ABORTED — otherwise `timeout` would consume it and the wedged task would
        // keep running, still holding its browser context, after we declared the run dead.
        let mut exec = exec;
        let joined = match tokio::time::timeout(budget, &mut exec).await {
            Ok(joined) => joined,
            Err(_) => {
                tracing::error!(
                    run_id,
                    budget_s = budget.as_secs(),
                    "run exceeded its overall budget — aborting the step task and releasing the slot"
                );
                // Cooperative first: flip the token so a step loop between steps bails cleanly (and
                // its context close runs). Then abort, so a task wedged INSIDE a step still goes away
                // — the `ContextCloseGuard` in `execute` closes its context on that unwind.
                cancel.cancel();
                exec.abort();
                let duration_ms = started.elapsed().as_millis() as u64;
                let result = Self::finalize(
                    &db,
                    run_id,
                    workflow_id,
                    Err(RunFailure::Timeout {
                        message: format!(
                            "Run exceeded its overall time budget of {}s and was stopped.",
                            budget.as_secs()
                        ),
                    }),
                    duration_ms,
                )
                .await;
                guard.finish(result.status);
                return result;
            }
        };

        let outcome: Result<HashMap<String, serde_json::Value>, RunFailure> = match joined {
            Ok(result) => result,
            Err(join_err) => {
                // A panic inside a step (or the executor) — log a generic note (NEVER the payload,
                // which could embed a value) and treat it as a terminal infra failure.
                if join_err.is_panic() {
                    tracing::error!(run_id, "run task panicked — isolated to a failed run");
                    Err(RunFailure::step(
                        "Internal error: a workflow step panicked".into(),
                        "infra",
                    ))
                } else {
                    // The JoinHandle was cancelled (only the timeout path above aborts it, and that
                    // path returns early) — defensively treat as cancelled.
                    tracing::warn!(run_id, "run task ended abnormally (join cancelled)");
                    Err(RunFailure::Cancelled)
                }
            }
        };

        let duration_ms = started.elapsed().as_millis() as u64;

        let result = Self::finalize(&db, run_id, workflow_id, outcome, duration_ms).await;

        // Emit the terminal event + de-register. `Cancelled` and the others all map cleanly.
        guard.finish(result.status);
        result
    }

    /// Finalize the `runs` row + workflow rollup from a step outcome and map to a `RunResult`. Pure
    /// DB + mapping; emits no events (the caller does that after this returns).
    async fn finalize(
        db: &SqlitePool,
        run_id: i64,
        workflow_id: Option<i64>,
        outcome: Result<HashMap<String, serde_json::Value>, RunFailure>,
        duration_ms: u64,
    ) -> RunResult {
        // Record the workflow rollup ONLY for a persisted workflow run; an ephemeral marketplace
        // recipe has no workflow row (`workflow_id = None`) so its outcome lives in the `runs` row
        // alone. Each branch below calls this with the branch's success flag + optional error.
        async fn record_rollup(
            db: &SqlitePool,
            workflow_id: Option<i64>,
            success: bool,
            error: Option<&str>,
        ) {
            if let Some(wid) = workflow_id {
                let _ = workflows::record_run_outcome(db, wid, success, error).await;
            }
        }
        match outcome {
            Ok(mut extracted) => {
                // Lift captured downloads to `result_data.output_files` (cloud parity + the FE reads
                // them there), leaving `extracted_data` to the workflow's own extraction keys.
                let output_files = extracted.remove("output_files");
                // Which lane produced this run: `execute` stamps `_engine` ("http" when the browserless
                // HTTP lane handled it) into the extracted map; strip it out so it isn't a data field.
                let engine = extracted
                    .remove("_engine")
                    .and_then(|v| v.as_str().map(String::from))
                    .unwrap_or_else(|| "browser".into());
                let engine_fallback = extracted.remove("_engine_fallback");
                let mut rd = serde_json::Map::new();
                rd.insert("success".into(), serde_json::json!(true));
                rd.insert("extracted_data".into(), serde_json::json!(extracted));
                rd.insert("engine".into(), serde_json::json!(engine));
                if let Some(fb) = engine_fallback {
                    rd.insert("engine_fallback".into(), fb);
                }
                if let Some(of) = output_files {
                    rd.insert("output_files".into(), of);
                }
                let result_data = serde_json::to_string(&serde_json::Value::Object(rd)).ok();
                let _ = runs::complete(db, run_id, result_data.as_deref(), Some(duration_ms as i64)).await;
                record_rollup(db, workflow_id, true, None).await;
                RunResult {
                    run_id,
                    status: RunStatus::Success,
                    success: true,
                    error: None,
                    extracted_data: serde_json::to_value(extracted).unwrap_or(serde_json::json!({})),
                    duration_ms,
                }
            }
            Err(RunFailure::Captcha { message, url }) => {
                // Unattended: DO NOT solve. Finalize as captcha_required (a non-success terminal
                // state) and surface RunStatus::CaptchaRequired so the caller can upsell cloud.
                tracing::warn!(run_id, %url, "run blocked on CAPTCHA (local runs cannot solve)");
                let _ = runs::fail(db, run_id, "captcha_required", Some(&message), Some("captcha"), Some(duration_ms as i64)).await;
                // A captcha is not a recipe failure — count the run but don't poison the streak.
                record_rollup(db, workflow_id, true, None).await;
                RunResult {
                    run_id,
                    status: RunStatus::CaptchaRequired,
                    success: false,
                    error: Some(message),
                    extracted_data: serde_json::json!({}),
                    duration_ms,
                }
            }
            Err(RunFailure::Twofa { method, message, url }) => {
                // Unattended 2FA gate, finalized as twofa_required (a non-success terminal state,
                // the CAPTCHA gate's twin). Two distinct shapes share the status, told apart by
                // failure_category so the UI can offer the RIGHT fix:
                //   • "twofa" (email/SMS persona) → the code can only be read in the cloud → upsell.
                //   • "twofa_persona" (no persona / method 'none' / TOTP without a seed) → attach a
                //     persona or import its 2FA secret; the cloud won't help.
                tracing::warn!(run_id, %url, method, "run blocked on 2FA");
                let category = if matches!(method.as_str(), "persona_missing" | "persona_no_method" | "totp_seed_missing") {
                    "twofa_persona"
                } else {
                    "twofa"
                };
                let _ = runs::fail(db, run_id, "twofa_required", Some(&message), Some(category), Some(duration_ms as i64)).await;
                // Like a captcha, a cloud-only 2FA method is not a recipe failure — count the run but
                // don't poison the streak (the recipe isn't broken; it just needs the cloud to sign in).
                record_rollup(db, workflow_id, true, None).await;
                RunResult {
                    run_id,
                    status: RunStatus::TwofaRequired,
                    success: false,
                    error: Some(message),
                    extracted_data: serde_json::json!({}),
                    duration_ms,
                }
            }
            Err(RunFailure::Timeout { message }) => {
                // The whole-run backstop fired. Like a cancellation this is not proof the recipe is
                // broken (the machine or the site stalled), so count the run without poisoning the
                // streak — but persist a DISTINCT `timeout` status so an operator can tell a wedged
                // run apart from a step that failed.
                tracing::error!(run_id, "run timed out (overall budget)");
                let _ = runs::fail(db, run_id, "timeout", Some(&message), Some("infra"), Some(duration_ms as i64)).await;
                record_rollup(db, workflow_id, true, None).await;
                RunResult {
                    run_id,
                    status: RunStatus::Timeout,
                    success: false,
                    error: Some(message),
                    extracted_data: serde_json::json!({}),
                    duration_ms,
                }
            }
            Err(RunFailure::Cancelled) => {
                // Cancellation is a terminal non-success state, not a recipe failure: count the run
                // but do NOT poison the streak (the recipe wasn't proven broken).
                tracing::info!(run_id, "run cancelled");
                let _ = runs::fail(db, run_id, "cancelled", Some("run cancelled"), Some("cancelled"), Some(duration_ms as i64)).await;
                record_rollup(db, workflow_id, true, None).await;
                RunResult {
                    run_id,
                    status: RunStatus::Cancelled,
                    success: false,
                    error: Some("run cancelled".into()),
                    extracted_data: serde_json::json!({}),
                    duration_ms,
                }
            }
            Err(RunFailure::Step { message, category }) => {
                let _ = runs::fail(db, run_id, "failed", Some(&message), Some(category), Some(duration_ms as i64)).await;
                record_rollup(db, workflow_id, false, Some(&message)).await;
                RunResult {
                    run_id,
                    status: RunStatus::Failed,
                    success: false,
                    error: Some(message),
                    extracted_data: serde_json::json!({}),
                    duration_ms,
                }
            }
        }
    }

    /// Drive the workflow's recorded steps on a warm browser context. Returns the merged extracted
    /// data on success, or a classified [`RunFailure`].
    ///
    /// STAGE E2: a static method on OWNED clones (so the caller can spawn it for panic isolation),
    /// emitting per-step lifecycle events through `emitter` and checking `cancel` BETWEEN steps so a
    /// `POST /v1/runs/:id/cancel` aborts promptly (the run finalizes [`RunFailure::Cancelled`]). The
    /// cancel check is between steps (the executor's own step is not preemptible mid-flight).
    ///
    /// Resolution order (STAGE E1):
    ///   1. [`resolve::resolve_run_refs`] builds the `credentials` (SECRET) + `form_data` (non-secret)
    ///      maps and normalizes `{{vault:KEY}}` → `{{secret:KEY}}` in the steps text.
    ///   2. [`persona::resolve_persona`] (when the workflow pins a `default_persona_id`) decrypts the
    ///      persona's login creds / fingerprint / session_state / proxy / TOTP. Persona creds are
    ///      merged UNDER the resolved run creds (an explicit workflow/vault value wins).
    ///   3. The context is built with the persona fingerprint + proxy; the persona session_state is
    ///      restored before navigation so the run starts authenticated.
    #[allow(clippy::too_many_arguments)]
    async fn execute(
        db: &SqlitePool,
        vault: &Arc<Vault>,
        browser: &Arc<BrowserManager>,
        wf: &workflows::Workflow,
        req: &RunRequest,
        run_id: i64,
        cancel: &CancelToken,
        emitter: &StepEmitter,
        // AI auto-repair SELF-HEAL budget: how many times a recipe-level repair (whole-workflow
        // rewrite / autonomous re-record) may persist a new recipe and restart THIS run with it.
        // Starts at 1 and decrements on each restart so a run can never repair-loop. Ignored on the
        // OSS build (no gateway). The per-step selector repair does NOT consume this budget.
        #[cfg_attr(not(feature = "cloud"), allow(unused_variables))] repair_restarts_left: u8,
        // Per-workflow repair lock: acquired the first time THIS run repairs, held (threaded through
        // the self-heal restart) until it settles, so concurrent runs of the workflow serialize behind
        // one repair instead of each launching their own. `None` on entry; carried forward on restart.
        #[cfg_attr(not(feature = "cloud"), allow(unused_variables))]
        repair_gate: &super::repair_gate::RepairGate,
        #[cfg_attr(not(feature = "cloud"), allow(unused_variables, unused_mut))]
        mut repair_guard: Option<super::repair_gate::RepairGuard>,
    ) -> Result<HashMap<String, serde_json::Value>, RunFailure> {
        // A cancel requested before we even resolve: short-circuit (no browser launch).
        if cancel.is_cancelled() {
            return Err(RunFailure::Cancelled);
        }

        // 1) Combined ref-resolution: credentials (secret), form_data (inputs over stored), and the
        //    steps TEXT with {{vault:KEY}} folded to {{secret:KEY}}. SECRET VALUES NEVER LOGGED.
        // TB-2: `allow_local_secret_refs` gates the LOCAL vault/file lookup. It is `false` ONLY for an
        // ad-hoc cloud-authored recipe (`RunSource::CloudAgent` `execute_workflow`), which then resolves
        // secrets solely from its own channel-key-sealed `credentials_encrypted` blob.
        let refs = resolve::resolve_run_refs(db, vault, wf, &req.inputs, req.allow_local_secret_refs)
            .await
            .map_err(|e| RunFailure::step(format!("Run resolution failed: {e}"), "creator"))?;
        let mut credentials = refs.credentials;
        let form_data = refs.form_data;

        // Parse steps from the NORMALIZED text so the executor resolves both secret spellings. An
        // EMPTY step array is a trivially successful zero-step run (parity with cloud); but a NON-empty
        // yet UNPARSEABLE `steps` blob is a CREATOR error, not a silent empty success — otherwise a
        // corrupt workflow would report "success" having done nothing.
        let trimmed = refs.steps_text.trim();
        // `mut` so AI auto-repair can rewrite a re-derived selector back into the steps array after the
        // loop (and persist it) — see the repair block below. Only the `cloud` build mutates it.
        #[cfg_attr(not(feature = "cloud"), allow(unused_mut))]
        let mut raw_steps: Vec<serde_json::Value> = if trimmed.is_empty() || trimmed == "[]" {
            Vec::new()
        } else {
            serde_json::from_str(&refs.steps_text).map_err(|e| {
                RunFailure::step(format!("Workflow steps are not valid JSON: {e}"), "creator")
            })?
        };

        // 2) Persona resolution (optional). A run-body persona override (the desktop Run modal) wins
        //    over the workflow's pinned `default_persona_id`. A dangling id is non-fatal; a hard
        //    decrypt error (e.g. an unparseable TOTP seed for a 2FA persona) fails the run loudly.
        let persona_pick = req.persona_id.or(wf.default_persona_id);
        let resolved_persona = match persona_pick {
            Some(pid) => persona::resolve_persona(db, vault, pid)
                .await
                .map_err(|e| RunFailure::step(format!("Persona resolution failed: {e}"), "creator"))?,
            None => None,
        };
        // Merge persona login creds + minted TOTP UNDER the run creds (workflow/vault values win).
        if let Some(p) = &resolved_persona {
            p.merge_into_credentials(&mut credentials);
        }
        // Persona BYO proxy egress. The identity itself is resolved after the browser
        // launch below, so a synthesized UA can carry the REAL Chrome major.
        let proxy_override = resolved_persona.as_ref().and_then(|p| p.proxy.clone());

        let timeout_ms = if wf.timeout_ms > 0 { wf.timeout_ms as u64 } else { 60_000 };
        let fast_mode = wf.fast_mode != 0;
        let headless = wf.headless != 0;
        let entry_url = wf.entry_url.as_deref().filter(|s| !s.is_empty()).unwrap_or("about:blank");

        // PRE-FLIGHT 2FA gate: fail fast as `twofa_required` BEFORE launching a browser — no wasted
        // Chromium, no half-finished login left on the site. Two doomed shapes are caught here:
        //   • NO persona at all (also covers a dangling default_persona_id): without a persona there
        //     is no warm session either, so the challenge WILL appear and the twofa step has no OTP
        //     source — previously this silently reported the step as Succeeded on a logged-out page.
        //   • email-OTP / SMS persona: those codes can only be read in the cloud.
        // A persona whose method is 'none' passes (its warm session may legitimately skip the
        // challenge — the per-step branch below is challenge-aware), and TOTP mints on-device so it
        // never trips this. Mirrors the cloud dispatch + engine pre-flights at the local seam.
        let has_twofa_step = raw_steps
            .iter()
            .any(|s| s.get("type").and_then(|v| v.as_str()) == Some("twofa"));
        if has_twofa_step {
            match resolved_persona.as_ref() {
                None => {
                    tracing::info!(run_id, "pre-flight: twofa step but no persona attached — not launching a browser");
                    return Err(RunFailure::Twofa {
                        message: "This workflow enters a 2FA code when signing in, but no persona \
                                  is attached. Attach a persona with a 2FA method — or import its \
                                  2FA secret — so runs can enter codes automatically."
                            .to_string(),
                        method: "persona_missing".to_string(),
                        url: entry_url.to_string(),
                    });
                }
                Some(p) if matches!(p.twofa_method.as_str(), "email_otp" | "sms") => {
                    let method = p.twofa_method.clone();
                    tracing::info!(run_id, method, "pre-flight: 2FA needs the cloud (email/SMS) — not launching a browser");
                    return Err(RunFailure::Twofa {
                        message: format!(
                            "This workflow signs in with a 2FA code sent by {}. Reading that code \
                             requires running in the cloud.",
                            if method == "sms" { "SMS" } else { "email" }
                        ),
                        method,
                        url: entry_url.to_string(),
                    });
                }
                Some(_) => {}
            }
        }

        // File assets (local): materialize any files the caller bound to this run's upload slots
        // (`inputs.files = { file_id -> { file_id, slots } }`) from the ON-DEVICE encrypted vault to
        // temp paths, so `upload` steps resolve `{{file:slot}}` / `file_slot` at replay. The guards
        // keep the temps alive for the run and delete them on drop. No bound files → inert (upload
        // fails closed as before). Downloads (`wait_for_download`) still need the separate capture path.
        let mut _file_guards: Vec<crate::local::storage::files::TempGuard> = Vec::new();
        let run_files = {
            let mut entries: Vec<(crate::automation::files::ResolvedFile, std::path::PathBuf)> = Vec::new();

            // The caller's bindings are only HALF the story. A recorded upload step usually PINS a
            // file (`config.file_id`, or `options.file_id` when the recorder wrote it), and the
            // cloud resolves those server-side alongside the request map (`_resolve_run_files_map`
            // unions step ids + slot bindings). Locally nothing did, so a pinned upload only ever
            // worked when something happened to pass the file explicitly — true for the Run modal
            // (it submits the pinned file as the slot's default) but NOT for a scheduled run, an
            // automation, a monitor, or an MCP call with no `files` argument. Those failed closed
            // with "no file resolved" on a workflow that runs fine in the cloud.
            //
            // Bound with NO slot, deliberately: `resolve_step_files` checks the slot first, so a
            // run-time binding for the same step still wins and this stays a pure fallback.
            let mut pinned: Vec<String> = Vec::new();
            for step in &raw_steps {
                if step.get("type").and_then(|v| v.as_str()) != Some("upload") {
                    continue;
                }
                let pick = |obj: Option<&serde_json::Value>| -> Option<String> {
                    obj.and_then(|o| o.get("file_id"))
                        .and_then(|v| v.as_str())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                };
                // `config` wins over `options` — it is the explicit later edit.
                if let Some(fid) = pick(step.get("config")).or_else(|| pick(step.get("options"))) {
                    if !pinned.contains(&fid) {
                        pinned.push(fid);
                    }
                }
            }
            if !pinned.is_empty() {
                if let Ok(paths) = crate::local::config::Paths::resolve() {
                    // A file the caller bound explicitly is materialized below; skip it here so it
                    // isn't fetched twice (and so its slots aren't dropped).
                    let bound: std::collections::BTreeSet<String> = req
                        .inputs
                        .get("files")
                        .and_then(|v| v.as_object())
                        .map(|o| {
                            o.iter()
                                .map(|(k, v)| {
                                    v.get("file_id")
                                        .and_then(|x| x.as_str())
                                        .unwrap_or(k)
                                        .to_string()
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    for file_id in pinned.into_iter().filter(|f| !bound.contains(f)) {
                        match crate::local::storage::files::materialize_for_run(db, vault, &paths, &file_id).await {
                            Ok((path, guard)) => {
                                let meta = crate::local::store::stored_files::get_active(db, &file_id).await.ok().flatten();
                                entries.push((
                                    crate::automation::files::ResolvedFile {
                                        file_id: file_id.clone(),
                                        url: String::new(),
                                        filename: meta.as_ref().map(|m| m.filename.clone()),
                                        content_type: meta.as_ref().map(|m| m.content_type.clone()),
                                        size: meta.as_ref().map(|m| m.size_bytes as u64),
                                        slots: Vec::new(),
                                    },
                                    path,
                                ));
                                _file_guards.push(guard);
                            }
                            Err(e) => tracing::warn!(
                                file_id = %file_id, error = %e,
                                "could not materialize the file pinned on an upload step — that step will fail closed"
                            ),
                        }
                    }
                }
            }

            if let (Some(files_obj), Some(paths)) = (
                req.inputs.get("files").and_then(|v| v.as_object()),
                crate::local::config::Paths::resolve().ok(),
            ) {
                for (fid, binding) in files_obj {
                    let file_id = binding.get("file_id").and_then(|v| v.as_str()).unwrap_or(fid).to_string();
                    let slots: Vec<String> = binding
                        .get("slots")
                        .and_then(|v| v.as_array())
                        .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                        .unwrap_or_default();
                    match crate::local::storage::files::materialize_for_run(db, vault, &paths, &file_id).await {
                        Ok((path, guard)) => {
                            let meta = crate::local::store::stored_files::get_active(db, &file_id).await.ok().flatten();
                            entries.push((
                                crate::automation::files::ResolvedFile {
                                    file_id: file_id.clone(),
                                    url: String::new(),
                                    filename: meta.as_ref().map(|m| m.filename.clone()),
                                    content_type: meta.as_ref().map(|m| m.content_type.clone()),
                                    size: meta.as_ref().map(|m| m.size_bytes as u64),
                                    slots,
                                },
                                path,
                            ));
                            _file_guards.push(guard);
                        }
                        Err(e) => tracing::warn!(file_id = %file_id, error = %e, "could not materialize bound file for run — upload will fail closed"),
                    }
                }
            }
            if entries.is_empty() {
                RunFiles::from_config(&serde_json::json!({}), None)
            } else {
                RunFiles::from_prefetched(entries)
            }
        };

        tracing::info!(
            run_id,
            workflow_id = wf.id,
            steps = raw_steps.len(),
            entry_url,
            persona = resolved_persona.as_ref().map(|p| p.persona_id),
            has_session = resolved_persona.as_ref().map(|p| p.session_state.is_some()).unwrap_or(false),
            proxied = proxy_override.is_some(),
            "local run starting"
        );

        // Cancel requested during resolution → bail before launching the browser.
        if cancel.is_cancelled() {
            return Err(RunFailure::Cancelled);
        }

        // --- Browserless HTTP lane gate ---
        // When every enabled step is pure HTTP (api_call / login_post / wait / return) and this
        // workflow isn't pinned browser-only (http_capable == 0), try the lane FIRST — no Chromium. A
        // fallback drops through to the browser path below in the SAME run; a park/fatal is terminal.
        //
        // HYBRID (auth_config.kind == "browser"): the sign-in is a recorded DOM login (browser.step_range)
        // but the DATA steps are pure HTTP. Once a browser run has harvested a session, run just the data
        // steps over HTTP and skip Chromium; otherwise fall through so the browser signs in + harvests.
        let mut http_fallback_reason: Option<&'static str> = None;
        let hybrid_range = super::http::hybrid_browser_range(wf);
        if wf.http_capable != 0 {
            if let Some(range) = hybrid_range {
                let data_steps = super::http::hybrid_data_steps(&raw_steps, range);
                if crate::automation::http_lane::http_lane_eligible(&data_steps).eligible
                    && super::http::has_fresh_workflow_session(db, wf).await
                {
                    match super::http::try_http_run(
                        db, vault, wf, &data_steps, &credentials, &form_data,
                        resolved_persona.as_ref(), run_id, cancel, emitter, timeout_ms,
                    )
                    .await
                    {
                        super::http::HttpRunOutcome::Done(extracted) => return Ok(extracted),
                        super::http::HttpRunOutcome::Failed(f) => return Err(f),
                        super::http::HttpRunOutcome::Fallback { reason } => {
                            tracing::warn!(run_id, workflow_id = wf.id, reason, "hybrid HTTP data phase fell back to browser sign-in");
                            http_fallback_reason = Some(reason);
                        }
                    }
                }
            } else if crate::automation::http_lane::http_lane_eligible(&raw_steps).eligible {
                match super::http::try_http_run(
                    db, vault, wf, &raw_steps, &credentials, &form_data,
                    resolved_persona.as_ref(), run_id, cancel, emitter, timeout_ms,
                )
                .await
                {
                    super::http::HttpRunOutcome::Done(extracted) => return Ok(extracted),
                    super::http::HttpRunOutcome::Failed(f) => return Err(f),
                    super::http::HttpRunOutcome::Fallback { reason } => {
                        tracing::warn!(run_id, workflow_id = wf.id, reason, "HTTP lane fell back to browser");
                        http_fallback_reason = Some(reason);
                    }
                }
            }
        }

        // Warm the shared browser in the requested headless mode, then a stealth context pinned to
        // the persona fingerprint + proxy (both None → fresh fingerprint + env/direct egress).
        browser
            .ensure_warm_browser_with(headless)
            .await
            .map_err(|e| RunFailure::step(format!("Browser launch failed: {e}"), "infra"))?;
        // Pin the persona's captured fingerprint (returning-user warmth), or — when it has
        // none — a DETERMINISTIC identity seeded on the persona id, so a persona without
        // saved warmth still presents one stable machine across runs instead of a fresh
        // random UA/locale/timezone each time. A HEADED run keeps the real machine's
        // hardware (only a headless run synthesizes a device); no persona → unchanged
        // fresh-fingerprint behaviour.
        // `match` rather than `.map()`: the closure `.map()` takes is not async, so awaiting
        // `chrome_major()` inside it does not compile. Matching also keeps the probe lazy — with no
        // persona there is no fingerprint to build, so we never pay for it.
        let fingerprint = match resolved_persona.as_ref() {
            Some(p) => {
                let chrome_major = browser.chrome_major().await;
                Some(p.identity(&chrome_major, None, headless))
            }
            None => None,
        };
        let (context, page, fp_used) = browser
            .create_stealth_context_with_fingerprint_proxy(fingerprint, proxy_override)
            .await
            .map_err(|e| RunFailure::step(format!("Browser context failed: {e}"), "infra"))?;

        // Element-action vs navigation timeouts. A selector-driven step waits at most
        // STEP_ACTION_TIMEOUT_MS for its target (short → fast hand-off to AI repair on a changed
        // site); navigation keeps the full workflow budget so slow page loads aren't cut short.
        page.set_default_timeout(STEP_ACTION_TIMEOUT_MS as f64).await;
        page.set_default_navigation_timeout(timeout_ms as f64).await;

        // CR-11: guarantee the context is closed even if the step loop PANICS **or this future is
        // CANCELLED** (the whole-run timeout aborts the step task; a `monitor_handle.abort()` on the
        // fleet path drops it mid-flight). The normal exits below close it explicitly (awaited, for
        // prompt cleanup) and DISARM this guard. `BrowserContext` has no `Drop` of its own, so without
        // this every such interruption strands a live context + its renderer inside Chromium. Shared
        // with the wire executor so both paths converge on one guard.
        let mut ctx_guard = crate::browser::context::ContextCloseGuard::new(context.clone());

        // Hybrid support: when this workflow persists its session, capture auth headers during the run
        // so a browser sign-in's session (cookies + bearer/api-key headers) can be harvested and reused
        // over the HTTP lane on the NEXT run — the browser cost is then paid only when the session goes
        // stale. Attached only when persistence is on (cheap no-op listener otherwise).
        // Persona runs capture too: the harvested session is written back onto the
        // PERSONA after a successful run (cloud parity), which is what lets a login
        // workflow establish the session an authenticated crawl replays.
        let captured_headers = if wf.session_persistence != 0 || resolved_persona.is_some() {
            Some(crate::automation::session_state::attach_auth_header_capture(&context).await)
        } else {
            None
        };

        // SECURITY: vet the entry URL before navigating (rejects file:/internal/metadata hosts).
        // about:blank — the default — is allowed. Anything else flows through the same guard the
        // cloud path uses.
        if !crate::security::url_guard::is_navigation_url_safe_async(entry_url).await {
            ctx_guard.disarm();
            let _ = context.close().await;
            return Err(RunFailure::step(
                format!("Refused unsafe entry URL: {entry_url}"),
                "buyer",
            ));
        }

        // Restore the persona's saved session state (cookies + storage added BEFORE navigation) so
        // the run starts authenticated; otherwise a plain navigation. 1:1 with the cloud restore.
        let nav_result = match resolved_persona.as_ref().and_then(|p| p.session_state.as_ref()) {
            Some(state) => {
                crate::automation::session_state::inject_session_state(
                    &page,
                    &context,
                    state,
                    Some(entry_url),
                    30_000,
                )
                .await
            }
            None => crate::browser::navigation::goto(
                &page,
                entry_url,
                "domcontentloaded",
                Duration::from_secs(30),
            )
            .await,
        };
        if let Err(e) = nav_result {
            ctx_guard.disarm();
            let _ = context.close().await;
            return Err(RunFailure::step(format!("Navigation failed: {e}"), "infra"));
        }

        // The count of steps we will actually run (enabled, typed) — drives Progress denominators.
        let total = raw_steps.len();

        // Execute each enabled step via the SHARED executor.
        let mut extracted: HashMap<String, serde_json::Value> = HashMap::new();
        let mut step_failure: Option<RunFailure> = None;
        let mut completed: usize = 0;
        // (step index, re-derived selector) for any steps AI auto-repair fixed mid-run — applied back
        // to `raw_steps` and persisted after the loop so the next run starts from the repaired recipe.
        #[cfg(feature = "cloud")]
        let mut repairs: Vec<(usize, String)> = Vec::new();
        // A whole-recipe repair (Tier A) or autonomous re-record (Tier B) produced a REPLACEMENT steps
        // array. Set when the fast per-step selector repair can't handle the failure; handled after the
        // loop (persist + self-heal restart). Supersedes `repairs` (a full replacement).
        #[cfg(feature = "cloud")]
        let mut pending_recipe: Option<Vec<serde_json::Value>> = None;
        // Set when we lost the repair-lock race to a concurrent run: it is repairing this workflow, so
        // we waited it out and will restart from the top with its repaired recipe (see after the loop).
        #[cfg(feature = "cloud")]
        let mut restart_from_concurrent_repair = false;

        for (i, raw_step) in raw_steps.iter().enumerate() {
            // COOPERATIVE CANCELLATION: between steps, honor a cancel request and abort cleanly.
            if cancel.is_cancelled() {
                tracing::info!(run_id, step = i, "cancellation observed — aborting run between steps");
                step_failure = Some(RunFailure::Cancelled);
                break;
            }

            let step_type = raw_step["type"].as_str().unwrap_or("");
            if step_type.is_empty() {
                emitter.emit(RunEvent::Step {
                    run_id,
                    index: i,
                    step_type: String::new(),
                    status: StepStatus::Skipped,
                });
                continue;
            }
            let enabled = raw_step.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            if !enabled {
                emitter.emit(RunEvent::Step {
                    run_id,
                    index: i,
                    step_type: step_type.to_string(),
                    status: StepStatus::Skipped,
                });
                continue;
            }

            // LOCAL download capture: `wait_for_download` is handled HERE, not by the shared executor
            // (whose path uploads to cloud object storage via presigned URLs). The engine owns the vault,
            // so it saves the captured file straight into the on-device encrypted vault and exposes its
            // id under `{{output_key}}` for downstream steps.
            if step_type == "wait_for_download" {
                emitter.emit(RunEvent::Step { run_id, index: i, step_type: step_type.to_string(), status: StepStatus::Running });
                let cfg: WorkflowStepConfig = match serde_json::from_value(
                    raw_step.get("config").cloned().unwrap_or_else(|| raw_step.clone()),
                ) {
                    Ok(c) => c,
                    Err(e) => {
                        emitter.emit(RunEvent::Step { run_id, index: i, step_type: step_type.to_string(), status: StepStatus::Failed });
                        step_failure = Some(RunFailure::step(format!("bad wait_for_download config: {e}"), "creator"));
                        break;
                    }
                };
                match capture_download_local(&page, &cfg, db, vault, timeout_ms).await {
                    Ok((handle, output_key)) => {
                        if let Some(k) = output_key {
                            if !handle.file_id.is_empty() {
                                extracted.insert(k, serde_json::json!(handle.file_id));
                            }
                        }
                        // Accumulate for result_data.output_files (parity with the cloud capture path).
                        run_files.push_output_file(handle);
                        completed += 1;
                        emitter.emit(RunEvent::Step { run_id, index: i, step_type: step_type.to_string(), status: StepStatus::Succeeded });
                        emitter.emit(RunEvent::Progress { run_id, completed, total });
                        continue;
                    }
                    Err(e) => {
                        tracing::error!(run_id, step = i, error = %e, "local download capture failed");
                        emitter.emit(RunEvent::Step { run_id, index: i, step_type: step_type.to_string(), status: StepStatus::Failed });
                        step_failure = Some(RunFailure::step(e, "creator"));
                        break;
                    }
                }
            }

            // LOCAL 2FA (persona-driven): a `twofa` step is handled HERE, not by the generic step
            // executor, because the engine owns the vault (to mint a FRESH in-window TOTP at step
            // time) and the resolved persona (to branch by method). TOTP mints on-device for free;
            // email/SMS codes can only be read in the cloud → finalize `twofa_required` (the twin of
            // the CAPTCHA gate). The minted code is SECRET — never logged.
            if step_type == "twofa" {
                emitter.emit(RunEvent::Step {
                    run_id,
                    index: i,
                    step_type: step_type.to_string(),
                    status: StepStatus::Running,
                });
                let method = resolved_persona
                    .as_ref()
                    .map(|p| p.twofa_method.as_str())
                    .unwrap_or("none");
                match method {
                    // Persona attached but no 2FA method. Its warm session may legitimately have
                    // skipped the challenge — so skip ONLY when the page isn't showing one. A visible
                    // challenge with nothing to answer it is a config gap → fail actionably as
                    // twofa_required instead of reporting a Succeeded step on the challenge page
                    // (the no-persona case never reaches here; the pre-flight gate catches it).
                    "none" => {
                        if twofa::challenge_present(&page).await {
                            tracing::warn!(run_id, step = i, "twofa step: challenge on the page but the persona has no 2FA method");
                            emitter.emit(RunEvent::Step {
                                run_id,
                                index: i,
                                step_type: step_type.to_string(),
                                status: StepStatus::Failed,
                            });
                            step_failure = Some(RunFailure::Twofa {
                                method: "persona_no_method".to_string(),
                                message: "This sign-in is asking for a 2FA code, but the attached \
                                          persona has no 2FA method configured. Add a 2FA method to \
                                          the persona — or import its 2FA secret — so runs can enter \
                                          codes automatically."
                                    .to_string(),
                                url: page.url(),
                            });
                            break;
                        }
                        tracing::info!(run_id, step = i, "twofa step: no 2FA method and no challenge on the page — skipping");
                        completed += 1;
                        emitter.emit(RunEvent::Step {
                            run_id,
                            index: i,
                            step_type: step_type.to_string(),
                            status: StepStatus::Succeeded,
                        });
                        emitter.emit(RunEvent::Progress { run_id, completed, total });
                        continue;
                    }
                    // Authenticator app: mint a FRESH in-window code on-device, then enter + submit it.
                    "totp" => {
                        let pid = resolved_persona.as_ref().map(|p| p.persona_id).unwrap_or(0);
                        // Warm-session guard: when the persona's saved session skipped the challenge
                        // entirely (no OTP field detected AND the recorded selector resolves to
                        // nothing), entering a code would type it into whatever input the fallback
                        // chain lands on. Skip the step instead — nothing is asking for a code.
                        if !twofa::challenge_present(&page).await
                            && !twofa::recorded_selector_present(&page, raw_step).await
                        {
                            tracing::info!(run_id, step = i, "twofa step: no challenge on the page (warm session) — skipping");
                            completed += 1;
                            emitter.emit(RunEvent::Step {
                                run_id,
                                index: i,
                                step_type: step_type.to_string(),
                                status: StepStatus::Succeeded,
                            });
                            emitter.emit(RunEvent::Progress { run_id, completed, total });
                            continue;
                        }
                        let outcome = match persona::mint_current_totp(db, vault, pid).await {
                            Ok(Some(code)) => twofa::enter_code(&page, raw_step, &code).await.map(Some),
                            Ok(None) => Ok(None),
                            Err(e) => Err(e),
                        };
                        match outcome {
                            Ok(Some(())) => {
                                completed += 1;
                                emitter.emit(RunEvent::Step {
                                    run_id,
                                    index: i,
                                    step_type: step_type.to_string(),
                                    status: StepStatus::Succeeded,
                                });
                                emitter.emit(RunEvent::Progress { run_id, completed, total });
                                continue;
                            }
                            // Method is TOTP but the persona holds no seed — a config gap, not a
                            // broken recipe: fail as twofa_required with the import-the-secret fix.
                            Ok(None) => {
                                tracing::warn!(run_id, step = i, "twofa step: persona method is TOTP but no seed is configured");
                                emitter.emit(RunEvent::Step {
                                    run_id,
                                    index: i,
                                    step_type: step_type.to_string(),
                                    status: StepStatus::Failed,
                                });
                                step_failure = Some(RunFailure::Twofa {
                                    method: "totp_seed_missing".to_string(),
                                    message: "The attached persona's 2FA method is TOTP, but no \
                                              secret is configured. Import the persona's 2FA secret \
                                              (QR / setup key) so runs can enter codes automatically."
                                        .to_string(),
                                    url: page.url(),
                                });
                                break;
                            }
                            Err(e) => {
                                tracing::error!(run_id, step = i, error = %e, "local TOTP 2FA failed");
                                emitter.emit(RunEvent::Step {
                                    run_id,
                                    index: i,
                                    step_type: step_type.to_string(),
                                    status: StepStatus::Failed,
                                });
                                step_failure = Some(RunFailure::step(e.to_string(), "creator"));
                                break;
                            }
                        }
                    }
                    // Email/SMS codes can only be read in the cloud → gate the run there.
                    "email_otp" | "sms" => {
                        tracing::warn!(run_id, step = i, method, "2FA via email/SMS requires the cloud");
                        emitter.emit(RunEvent::Step {
                            run_id,
                            index: i,
                            step_type: step_type.to_string(),
                            status: StepStatus::Failed,
                        });
                        step_failure = Some(RunFailure::Twofa {
                            method: method.to_string(),
                            message: format!(
                                "This workflow signs in with a 2FA code sent by {}. Reading that code \
                                 requires running in the cloud.",
                                if method == "sms" { "SMS" } else { "email" }
                            ),
                            url: page.url(),
                        });
                        break;
                    }
                    // Unknown method — non-fatal skip (don't wedge a run on a config we don't grok).
                    other => {
                        tracing::warn!(run_id, step = i, method = other, "unknown 2FA method — skipping twofa step");
                        completed += 1;
                        emitter.emit(RunEvent::Step {
                            run_id,
                            index: i,
                            step_type: step_type.to_string(),
                            status: StepStatus::Succeeded,
                        });
                        emitter.emit(RunEvent::Progress { run_id, completed, total });
                        continue;
                    }
                }
            }

            // A step type the executor has no handler for does NOTHING. Report it as skipped
            // rather than dispatching it and recording the resulting `Ok(None)` as a success —
            // a no-op that reads as "succeeded" is how a workflow can claim to verify something
            // it never checked. Types this loop resolves itself (twofa, above) never get here.
            if !is_dispatchable(step_type) {
                tracing::warn!(
                    run_id, step = i, step_type,
                    "unsupported step type — nothing to execute, step skipped"
                );
                emitter.emit(RunEvent::Step {
                    run_id,
                    index: i,
                    step_type: step_type.to_string(),
                    status: StepStatus::Skipped,
                });
                continue;
            }

            let step_config: WorkflowStepConfig = match serde_json::from_value(
                raw_step.get("config").cloned().unwrap_or_else(|| raw_step.clone()),
            ) {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(run_id, step = i, error = %e, "skipping unparseable step config");
                    emitter.emit(RunEvent::Step {
                        run_id,
                        index: i,
                        step_type: step_type.to_string(),
                        status: StepStatus::Skipped,
                    });
                    continue;
                }
            };

            emitter.emit(RunEvent::Step {
                run_id,
                index: i,
                step_type: step_type.to_string(),
                status: StepStatus::Running,
            });

            let step_ctx = StepRunContext {
                credentials: &credentials,
                form_data: &form_data,
                run_files: &run_files,
                timeout_ms,
                fast_mode,
                // Prior steps' response_extractions so `{{extracted:key}}` resolves in api_call bodies/headers.
                extracted: &extracted,
                // An upload step with no declared file_slot is bound as `step:<id>` in the
                // run's files map, so a caller-supplied file can be matched to it.
                step_id: raw_step.get("id").and_then(|v| v.as_str()),
            };
            let result = execute_step_ctx(&page, step_type, &step_config, &step_ctx).await;

            match result {
                Ok(maybe_data) => {
                    if let Some(data) = maybe_data {
                        extracted.extend(data);
                    }
                    completed += 1;
                    emitter.emit(RunEvent::Step {
                        run_id,
                        index: i,
                        step_type: step_type.to_string(),
                        status: StepStatus::Succeeded,
                    });
                    emitter.emit(RunEvent::Progress { run_id, completed, total });
                }
                Err(e @ (StepError::CaptchaNotSolved(_) | StepError::CaptchaBotDetected(_))) => {
                    tracing::warn!(run_id, step = i, "captcha encountered — local runs cannot solve");
                    emitter.emit(RunEvent::Step {
                        run_id,
                        index: i,
                        step_type: step_type.to_string(),
                        status: StepStatus::Failed,
                    });
                    step_failure = Some(RunFailure::Captcha {
                        message: e.to_string(),
                        url: page.url(),
                    });
                    break;
                }
                Err(e) => {
                    let category = classify_step_error(&e);
                    tracing::error!(run_id, step = i, step_type, error = %e, "workflow step failed");

                    // AI AUTO-REPAIR (cloud-linked only): the workflow opted in, so before failing,
                    // ask the MANAGED cloud AI gateway to re-derive the broken selector, retry the step
                    // in place, and remember the fix for post-loop persistence. The run stays on this
                    // device; only the repair call crosses to the cloud (metered on the linked account).
                    // Out-of-credit ends the run with the gateway's upgrade message (no thrash).
                    #[cfg(feature = "cloud")]
                    if wf.ai_repair_enabled == 1 {
                        use super::repair::{repair_step_selector, RepairOutcome};
                        // REPAIR LOCK: the first time this run repairs, grab the per-workflow lock so
                        // concurrent runs don't each launch their own repair. If another run already
                        // holds it, don't repair in parallel — wait for it to finish, then restart THIS
                        // run from the top with its repaired recipe (handled after the loop).
                        if repair_guard.is_none() {
                            match repair_gate.try_begin(wf.id) {
                                Some(g) => repair_guard = Some(g),
                                None => {
                                    tracing::info!(
                                        run_id, workflow_id = wf.id, step = i,
                                        "AI auto-repair: workflow already being repaired by another run — waiting, then restarting with its result"
                                    );
                                    repair_gate.wait_if_repairing(wf.id).await;
                                    restart_from_concurrent_repair = true;
                                    break;
                                }
                            }
                        }
                        // Announce the repair attempt BEFORE the gateway round-trip. Without this the
                        // logs go silent between "workflow step failed" and the eventual outcome,
                        // which reads as a hang while repair is actually in flight.
                        tracing::info!(
                            run_id, step = i, step_type,
                            "AI auto-repair: step failed — re-deriving selector via cloud gateway"
                        );
                        // Surface a live "repairing" state: push the event (nudge) AND flip the
                        // persisted row so every run-state surface (Live Activity / Runs / Home)
                        // shows "Repairing" on its next refetch, not just live listeners. The fast
                        // per-step fix is `slow: false` (badge only — no notification).
                        emitter.emit(RunEvent::Repairing { run_id, slow: false });
                        let _ = runs::set_status(db, run_id, "repairing").await;
                        match repair_step_selector(db, &page, step_type, &step_config, &e.to_string()).await {
                            RepairOutcome::Repaired { selector } => {
                                let mut fixed = step_config.clone();
                                fixed.selector = Some(selector.clone());
                                // Signal the retry, then run the step again with the re-derived selector.
                                emitter.emit(RunEvent::Step {
                                    run_id,
                                    index: i,
                                    step_type: step_type.to_string(),
                                    status: StepStatus::Running,
                                });
                                match execute_step_ctx(&page, step_type, &fixed, &step_ctx).await {
                                    Ok(maybe_data) => {
                                        if let Some(data) = maybe_data {
                                            extracted.extend(data);
                                        }
                                        repairs.push((i, selector));
                                        completed += 1;
                                        tracing::info!(run_id, step = i, "AI repair succeeded — step retried and passed");
                                        // Durable verdict (0023): `status='repairing'` is about to be
                                        // flipped back to 'running' and leaves no trace, so record
                                        // that the fix WORKED. A later give-up in this same run
                                        // overwrites it — last verdict wins.
                                        let _ = runs::set_repair_outcome(db, run_id, true).await;
                                        emitter.emit(RunEvent::Step {
                                            run_id,
                                            index: i,
                                            step_type: step_type.to_string(),
                                            status: StepStatus::Succeeded,
                                        });
                                        emitter.emit(RunEvent::Progress { run_id, completed, total });
                                        // Repair resolved — clear the transient "repairing" row state.
                                        let _ = runs::set_status(db, run_id, "running").await;
                                        continue;
                                    }
                                    Err(retry_err) => {
                                        tracing::warn!(run_id, step = i, error = %retry_err, "AI repair retry still failed — reporting the original failure");
                                        // The AI re-derived a selector and it STILL didn't work: it
                                        // had its go and the run is dead. Record the give-up so the
                                        // feed shows "Repair failed" rather than a bare failure.
                                        let _ = runs::set_repair_outcome(db, run_id, false).await;
                                        // Fall through to the ordinary failure below.
                                    }
                                }
                            }
                            RepairOutcome::CreditRequired(message) => {
                                emitter.emit(RunEvent::Step {
                                    run_id,
                                    index: i,
                                    step_type: step_type.to_string(),
                                    status: StepStatus::Failed,
                                });
                                // Not a recipe fault — tag `infra` so it doesn't poison the workflow's
                                // reliability streak; the message tells the user to upgrade/add credit.
                                step_failure = Some(RunFailure::step(message, "infra"));
                                break;
                            }
                            RepairOutcome::Unavailable => {
                                // The fast per-step selector fix can't help (a script/navigation step,
                                // or the model couldn't re-derive one). ESCALATE to smart repair: hand
                                // the WHOLE workflow + data/secret placeholders + entry URL + error +
                                // DOM to the gateway and get back a repaired recipe (Tier A); if that
                                // can't produce one, autonomously re-record from the entry point (Tier
                                // B). A produced recipe is persisted + retried once (self-heal) below.
                                use super::repair::{repair_or_rerecord, SmartRepairInputs, RecipeOutcome};
                                // Per-step selector repair couldn't help — announce the heavier
                                // escalation (whole-recipe repair / autonomous re-record). Tier B can
                                // take a while, so this line is what tells the operator it's working.
                                tracing::info!(
                                    run_id, step = i, step_type,
                                    allow_rerecord = repair_restarts_left > 0,
                                    "AI auto-repair: escalating to smart repair (whole-recipe repair / autonomous re-record)"
                                );
                                // The heavy re-record / rebuild can take 1–2 min: emit `slow: true`
                                // so the UI fires a notification ("this may take a minute") in
                                // addition to the badge. Row stays `repairing` from the per-step flip.
                                emitter.emit(RunEvent::Repairing { run_id, slow: true });
                                let _ = runs::set_status(db, run_id, "repairing").await;
                                let secret_keys: Vec<String> =
                                    resolve::scan_secret_keys(&refs.steps_text).into_iter().collect();
                                let form_keys: Vec<String> = form_data.keys().cloned().collect();
                                let err_string = e.to_string();
                                let inputs = SmartRepairInputs {
                                    raw_steps: &raw_steps,
                                    form_keys: &form_keys,
                                    secret_keys: &secret_keys,
                                    entry_url: wf.entry_url.as_deref(),
                                    goal: wf.description.as_deref(),
                                    error: &err_string,
                                    // Only spend the expensive autonomous re-record when a restart can
                                    // actually apply it this run.
                                    allow_rerecord: repair_restarts_left > 0,
                                    // Seed the re-record with the workflow's data so a credentialed
                                    // flow (login, etc.) can be reproduced autonomously.
                                    credentials: &credentials,
                                    form_data: &form_data,
                                };
                                match repair_or_rerecord(db, vault, &page, cancel, inputs).await {
                                    RecipeOutcome::Recipe(steps) => {
                                        tracing::info!(run_id, step = i, "AI smart repair produced a repaired recipe — will restart the run");
                                        pending_recipe = Some(steps);
                                        break;
                                    }
                                    RecipeOutcome::CreditRequired(message) => {
                                        emitter.emit(RunEvent::Step {
                                            run_id,
                                            index: i,
                                            step_type: step_type.to_string(),
                                            status: StepStatus::Failed,
                                        });
                                        step_failure = Some(RunFailure::step(message, "infra"));
                                        break;
                                    }
                                    RecipeOutcome::Unavailable => {
                                        // Every tier is exhausted — the per-step fix, the whole-recipe
                                        // rewrite AND the autonomous re-record all came back empty.
                                        // This is the definitive give-up: record it so the run carries
                                        // a "Repair failed" badge instead of looking untriaged.
                                        let _ = runs::set_repair_outcome(db, run_id, false).await;
                                        // Nothing worked — fall through to the ordinary failure below.
                                    }
                                }
                            }
                        }
                    }

                    emitter.emit(RunEvent::Step {
                        run_id,
                        index: i,
                        step_type: step_type.to_string(),
                        status: StepStatus::Failed,
                    });
                    step_failure = Some(RunFailure::step(e.to_string(), category));
                    break;
                }
            }
        }

        // CONCURRENT-REPAIR WAIT: we hit a broken step but ANOTHER run held the repair lock, so we
        // waited it out above. That run has now repaired + persisted the recipe — restart from the top
        // with the fresh recipe (no repair of our own; the other run already did it).
        #[cfg(feature = "cloud")]
        if restart_from_concurrent_repair {
            ctx_guard.disarm();
            let _ = context.close().await;
            if repair_restarts_left > 0 {
                if let Ok(Some(fresh)) = workflows::get_by_id(db, wf.id).await {
                    tracing::info!(run_id, workflow_id = wf.id, "AI auto-repair: restarting with the recipe repaired by a concurrent run");
                    return Box::pin(Self::execute(
                        db, vault, browser, &fresh, req, run_id, cancel, emitter,
                        repair_restarts_left - 1, repair_gate, repair_guard.take(),
                    ))
                    .await;
                }
            }
            return Err(RunFailure::step(
                "This workflow is being repaired by another run — retry shortly to use the repaired recipe.".into(),
                "infra",
            ));
        }

        // AI SMART-REPAIR SELF-HEAL: a whole-recipe repair (Tier A) or autonomous re-record (Tier B)
        // produced a REPLACEMENT recipe. Persist it (snapshotting the old recipe into repair history),
        // then restart THIS run ONCE from the top with the repaired recipe so it self-heals now. The
        // `repair_restarts_left` budget guarantees this happens at most once per run (no repair loop).
        #[cfg(feature = "cloud")]
        if let Some(new_steps) = pending_recipe.take() {
            // Release the browser context before restarting — the recursive run opens its own.
            ctx_guard.disarm();
            let _ = context.close().await;

            super::repair::persist_repaired_recipe(
                db,
                wf.id,
                &raw_steps,
                &new_steps,
                "recipe",
                "AI auto-repair replaced the recipe after a step broke",
            )
            .await;
            // The recipe IS saved now, whether or not this run gets to retry it below — so the
            // verdict is "repaired" either way, and the workflow is stamped as fixed (which retires
            // this workflow's OLDER failures from "Needs attention"). If the retry below breaks
            // again unrepairably, that pass overwrites the run verdict with a give-up.
            let _ = runs::set_repair_outcome(db, run_id, true).await;

            if repair_restarts_left > 0 {
                if let Ok(Some(fresh)) = workflows::get_by_id(db, wf.id).await {
                    tracing::info!(run_id, workflow_id = wf.id, "AI smart repair: restarting run with the repaired recipe");
                    // Repair produced a recipe — clear the transient "repairing" row state; the
                    // restart re-drives the run as normal "running".
                    let _ = runs::set_status(db, run_id, "running").await;
                    return Box::pin(Self::execute(
                        db,
                        vault,
                        browser,
                        &fresh,
                        req,
                        run_id,
                        cancel,
                        emitter,
                        repair_restarts_left - 1,
                        repair_gate,
                        repair_guard.take(),
                    ))
                    .await;
                }
                tracing::warn!(run_id, workflow_id = wf.id, "AI smart repair: could not reload workflow to restart");
            }
            // Budget exhausted or reload failed — the repaired recipe IS saved, so the next run uses
            // it. Report a clear terminal message for THIS run.
            return Err(RunFailure::step(
                "This workflow was auto-repaired, but couldn't be retried this run — the next run will use the repaired recipe.".into(),
                "infra",
            ));
        }

        // AI AUTO-REPAIR WRITEBACK: fold any mid-run selector fixes back into the recipe and persist,
        // so the NEXT run starts clean instead of re-repairing (and re-spending credit) every time.
        // The `.iter()` borrow from the step loop is released here, so `raw_steps` is free to mutate.
        // Best-effort — a persist failure never fails the run (the fix was already applied this run).
        #[cfg(feature = "cloud")]
        if !repairs.is_empty() {
            for (idx, selector) in &repairs {
                let Some(step) = raw_steps.get_mut(*idx) else { continue };
                // The selector lives under `config` when present, else at the step's top level
                // (mirrors how the step config is parsed: `raw_step["config"]` ?? `raw_step`).
                let target = match step.get("config") {
                    Some(c) if c.is_object() => step.get_mut("config").unwrap(),
                    _ => step,
                };
                if let Some(obj) = target.as_object_mut() {
                    obj.insert("selector".into(), serde_json::Value::String(selector.clone()));
                }
            }
            match serde_json::to_string(&raw_steps) {
                Ok(steps_json) => {
                    let patch = workflows::WorkflowUpdate { steps: Some(steps_json), ..Default::default() };
                    match workflows::update(db, wf.id, &patch).await {
                        Ok(_) => {
                            // Stamp the workflow as repaired only now that the fixed selectors are
                            // actually saved (0023) — selector fixes are deliberately NOT written to
                            // workflow_repair_history, so this stamp is the only record that they
                            // happened, and it's what retires this workflow's older failures from
                            // Home's "Needs attention".
                            if let Err(e) = workflows::mark_repaired(db, wf.id).await {
                                tracing::warn!(run_id, workflow_id = wf.id, error = %e, "AI repair: failed to stamp last_repaired_at");
                            }
                            tracing::info!(run_id, workflow_id = wf.id, repaired = repairs.len(), "AI repair: persisted repaired selectors");
                        }
                        Err(e) => tracing::warn!(run_id, workflow_id = wf.id, error = %e, "AI repair: failed to persist repaired steps"),
                    }
                }
                Err(e) => tracing::warn!(run_id, error = %e, "AI repair: could not serialize repaired steps"),
            }
        }

        // Hybrid: on a SUCCESSFUL browser run that persists its session, harvest the session (cookies +
        // storage + captured auth headers) and store it for the HTTP lane to reuse next run. Done while
        // the context is still open. Only for a hybrid workflow (browser sign-in → HTTP data) or after
        // an HTTP-lane fallback (so the retry can go HTTP next time) — a pure-DOM workflow would never
        // reuse it. Best-effort — never fails the run.
        if step_failure.is_none() && (hybrid_range.is_some() || http_fallback_reason.is_some()) {
            if let Some(cap) = &captured_headers {
                let headers = cap.lock().map(|m| m.clone()).unwrap_or_default();
                let mut state = crate::automation::session_state::extract_session_state(
                    &page, &context, &headers,
                )
                .await;
                state.fingerprint = serde_json::to_value(&fp_used).ok();
                super::http::persist_browser_session(db, vault, wf.id, &state).await;
            }
        }

        // PERSONA WRITE-BACK. On a successful run that resolved a persona, harvest the
        // live session (cookies + storage + captured auth headers) onto the PERSONA row
        // — not just workflow_sessions. This is the capture half of persona sign-in:
        // without it a login workflow can run perfectly and the persona still ends up
        // sessionless, so an authenticated crawl can never start. Done while the
        // context is still open; best-effort (never fails the run).
        if step_failure.is_none() {
            if let Some(pid) = resolved_persona.as_ref().map(|p| p.persona_id) {
                if let Some(cap) = &captured_headers {
                    let headers = cap.lock().map(|m| m.clone()).unwrap_or_default();
                    let mut state = crate::automation::session_state::extract_session_state(
                        &page, &context, &headers,
                    )
                    .await;
                    state.fingerprint = serde_json::to_value(&fp_used).ok();
                    super::persona::save_session_state(db, vault, pid, &state).await;
                }
            }
        }

        // Always release the browser context (success or failure). Disarm the panic-safety guard
        // first so we don't double-close (this awaited close is the deterministic cleanup path).
        ctx_guard.disarm();
        let _ = context.close().await;

        // Carry any captured downloads out via the extracted map (the caller lifts `output_files` to
        // the top level of result_data). Only on success — a failed run reports its failure, not files.
        let mut extracted = extracted;
        let captured = run_files.output_files_json();
        if !captured.is_empty() {
            extracted.insert("output_files".into(), serde_json::json!(captured));
        }
        // If we reached the browser path via an HTTP-lane fallback, tag the result so the run detail
        // shows it, and mark the workflow browser-only (a proven fallback) so the next run skips the
        // wasted HTTP probe. Only when the browser run itself succeeded.
        if let Some(reason) = http_fallback_reason {
            extracted.insert("_engine".into(), serde_json::json!("browser"));
            extracted.insert(
                "_engine_fallback".into(),
                serde_json::json!({ "from": "http", "reason": reason }),
            );
            if step_failure.is_none() {
                let _ = workflows::set_http_capable(db, wf.id, 0).await;
            }
        }
        match step_failure {
            Some(f) => Err(f),
            None => Ok(extracted),
        }
    }
}

/// The prepared EXEC half of a marketplace-proxy run (0017): the in-memory recipe workflow to
/// drive, plus what [`RealEngine::settle_marketplace_run`] needs afterwards. The recipe is dropped
/// with this struct — never persisted or logged.
#[cfg(feature = "cloud")]
struct MarketplaceExec {
    exec_wf: workflows::Workflow,
    slug: String,
    metered_id: Option<String>,
}

impl super::LocalEngine for RealEngine {
    fn run<'a>(
        &'a self,
        req: RunRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LocalResult<RunResult>> + Send + 'a>> {
        Box::pin(self.run_inner(req, None))
    }

    /// Same as [`Self::run`], but publishes the allocated `run_id` to `on_start` before the body
    /// starts so a remote dispatcher can map its own task id onto it and cancel by id later.
    fn run_tracked<'a>(
        &'a self,
        req: RunRequest,
        on_start: RunIdSink<'a>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LocalResult<RunResult>> + Send + 'a>> {
        Box::pin(self.run_inner(req, Some(on_start)))
    }

    fn active_runs(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    /// STAGE E2 fire-and-forget: open the run row, register the live handle, SPAWN the body on owned
    /// clones, and return the new run id immediately (status `Running`). The spawned task finalizes
    /// the `runs` row + de-registers itself; the caller streams `/v1/runs/:id/events` to observe it.
    fn run_async<'a>(
        &'a self,
        req: RunRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LocalResult<StartedRun>> + Send + 'a>> {
        Box::pin(async move {
            // `mut` is only exercised by the cloud-gated marketplace-proxy swap below.
            #[cfg_attr(not(feature = "cloud"), allow(unused_mut))]
            let mut req = req;
            // PROD-14: admit by lane BEFORE opening the row (no row for a refused run). The permit is
            // moved into the spawned body and held for the run's lifetime.
            let permit = self
                .governor
                .admit(req.lane)
                .await
                .map_err(|reject| LocalError::Internal(format!("run rejected: {}", reject.as_str())))?;
            let mut wf = self.load_workflow(&req).await?;
            // REPAIR LOCK (entry barrier): wait out any in-flight repair of this workflow, then reload
            // so this run uses the repaired recipe. Mirrors the synchronous `run_inner` path.
            if self.repair_gate.is_repairing(wf.id) {
                self.repair_gate.wait_if_repairing(wf.id).await;
                wf = self.load_workflow(&req).await?;
            }
            // MARKETPLACE PROXY (0017): the fallible front half (authorize + unseal) runs BEFORE the
            // row exists, so a payment denial is a clean Err to the caller — no orphaned run.
            #[cfg(feature = "cloud")]
            let mp_exec = self.prepare_marketplace_exec(&wf, &mut req).await?;
            let run_id = self.insert_run_row(&req, wf.id).await?;
            let guard = self.registry.register(run_id);
            let db = self.db.clone();
            let vault = self.vault.clone();
            let browser = self.browser.clone();
            let active = self.active.clone();
            let rollup_id = Some(wf.id);
            #[cfg(feature = "cloud")]
            let (exec_wf, mp_settle) = match mp_exec {
                Some(m) => (m.exec_wf, Some((m.slug, m.metered_id))),
                None => (wf, None),
            };
            #[cfg(not(feature = "cloud"))]
            let exec_wf = wf;
            let repair_gate = self.repair_gate.clone();
            tokio::spawn(async move {
                let result =
                    Self::run_body(db.clone(), vault, browser, active, exec_wf, rollup_id, req, guard, permit, repair_gate)
                        .await;
                #[cfg(feature = "cloud")]
                Self::settle_marketplace_run(&db, mp_settle, &result).await;
                let _ = result;
            });
            Ok(StartedRun { run_id, status: RunStatus::Running })
        })
    }

    /// Run an EPHEMERAL marketplace recipe to completion (SYNCHRONOUS) and return the terminal
    /// [`RunResult`]. The recipe lives only in memory (never persisted as a workflow row); the run
    /// surfaces in `/v1/runs` via a `workflow_id = NULL` `runs` row. See [`super::LocalEngine::run_recipe`].
    fn run_recipe<'a>(
        &'a self,
        recipe: workflows::Workflow,
        inputs: serde_json::Value,
        source: RunSource,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = LocalResult<RunResult>> + Send + 'a>> {
        Box::pin(self.run_recipe_inner(recipe, inputs, source))
    }

    /// Route a cancel request to the live-run registry. See [`super::LocalEngine::cancel`].
    fn cancel(&self, run_id: i64) -> Option<bool> {
        self.registry.cancel(run_id)
    }

    /// Expose the shared live-run registry to the API layer (SSE + cancel).
    fn registry(&self) -> Option<Arc<RunRegistry>> {
        Some(self.registry.clone())
    }

    /// Expose the warm `BrowserManager` so the local recording WS reuses the SAME Chromium the run
    /// engine drives (one warm browser shared across runs + recording).
    fn browser(&self) -> Option<Arc<BrowserManager>> {
        Some(self.browser.clone())
    }

    /// Expose the shared resource governor (PROD-14) so the scheduler can consult the memory watermark
    /// before dispatching heavy background work.
    fn governor(&self) -> Option<Arc<ResourceGovernor>> {
        Some(self.governor.clone())
    }

    /// Expose the shared streaming-session manager so the `/v1/streaming/sessions*` routes can
    /// LAUNCH / LIST / END the long-lived sessions a streaming workflow holds.
    fn streaming(&self) -> Option<Arc<LocalStreamingManager>> {
        Some(self.streaming.clone())
    }

    /// Expose the at-rest vault so the automation flow interpreter can persist a data-export
    /// StoredFile (`save_data_to_file` / `query_and_export`) without threading a vault handle
    /// through every trigger site.
    fn vault(&self) -> Option<Arc<Vault>> {
        Some(self.vault.clone())
    }

    /// Drive ONE streamed chat turn against the workflow's find-or-lazily-started streaming session.
    /// Delegates to the shared [`LocalStreamingManager`] (over the SAME warm browser). See the trait
    /// docs for the returned `(receiver, response_field)` contract.
    fn run_streaming<'a>(
        &'a self,
        wf: workflows::Workflow,
        inputs: serde_json::Value,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = LocalResult<(
                        tokio::sync::mpsc::UnboundedReceiver<StreamEvent>,
                        String,
                    )>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { self.streaming.run_turn(&wf, inputs).await })
    }
}

/// Cheap up-front step-count for the `Started` event: parse the workflow's stored `steps` JSON-TEXT
/// and count array entries. Best-effort (0 on a non-array / parse failure); the authoritative
/// per-step frames come from the resolved+normalized step list inside `execute`.
/// Capture a page download straight into the on-device encrypted vault (the local twin of the shared
/// executor's cloud upload). Arms the waiter BEFORE the trigger, clicks the trigger (or relies on the
/// prior step), saves the download to a temp file, reads it, stores it via [`storage::files::create_file`]
/// (source `workflow_output`), and returns `(file_id, output_key)`. The temp is always deleted.
async fn capture_download_local(
    page: &playwright_rs::Page,
    config: &WorkflowStepConfig,
    db: &SqlitePool,
    vault: &Arc<Vault>,
    timeout_ms: u64,
) -> Result<(crate::automation::files::OutputFile, Option<String>), String> {
    let paths = crate::local::config::Paths::resolve().map_err(|e| format!("resolve paths: {e}"))?;
    let trigger = config.trigger_selector.as_deref().filter(|s| !s.is_empty());
    let output_key = config.output_key.clone().filter(|s| !s.is_empty());

    let waiter = page
        .expect_download(Some(timeout_ms as f64))
        .await
        .map_err(|e| format!("arm download waiter: {e}"))?;
    if let Some(sel) = trigger {
        let locator = page.locator(sel).await;
        locator
            .first()
            .click(None)
            .await
            .map_err(|e| format!("trigger click: {e}"))?;
    }
    let download = waiter.wait().await.map_err(|e| format!("no download captured: {e}"))?;

    let suggested = download.suggested_filename().to_string();
    let suffix = crate::automation::files::filename_suffix(Some(&suggested));
    let tmp = crate::automation::files::unique_temp_path("psdl_", &suffix);
    if let Err(e) = download.save_as(&tmp).await {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("save download: {e}"));
    }
    let read = tokio::fs::read(&tmp).await;
    let _ = std::fs::remove_file(&tmp);
    let bytes = read.map_err(|e| format!("read download: {e}"))?;

    let filename = if suggested.trim().is_empty() { "download".to_string() } else { suggested };
    let stored = crate::local::storage::files::create_file(
        db, vault, &paths, &bytes, &filename, None, "workflow_output",
    )
    .await
    .map_err(|e| format!("save to vault: {e}"))?;
    tracing::info!(file_id = %stored.id, filename = %stored.filename, "captured download into local vault");
    let handle = crate::automation::files::OutputFile {
        file_id: stored.id,
        filename: stored.filename,
        size: stored.size_bytes.max(0) as u64,
        content_type: stored.content_type,
        output_key: output_key.clone(),
    };
    Ok((handle, output_key))
}

fn step_count_hint(wf: &workflows::Workflow) -> usize {
    serde_json::from_str::<Vec<serde_json::Value>>(&wf.steps)
        .map(|v| v.len())
        .unwrap_or(0)
}

/// A classified terminal failure of a single run.
pub(crate) enum RunFailure {
    /// A CAPTCHA was encountered on an unattended run — solving is a paid cloud feature.
    Captcha { message: String, url: String },
    /// A 2FA challenge whose code can only be obtained in the cloud (email-OTP / SMS). TOTP is
    /// minted on-device and never reaches here — this is the email/SMS cloud-gate, mirroring
    /// [`RunFailure::Captcha`]: a terminal non-success state that does NOT poison the recipe streak.
    Twofa { method: String, message: String, url: String },
    /// The run was cancelled (cooperatively, between steps) via the registry token. A terminal
    /// non-success state that does NOT poison the recipe streak.
    Cancelled,
    /// The run blew its WHOLE-RUN budget (see [`overall_run_budget`]) and was stopped so its governor
    /// permit could be released. A terminal non-success state that does NOT poison the recipe streak —
    /// a stalled driver/site is not proof the recipe is broken.
    Timeout { message: String },
    /// Any other step/setup failure, tagged with a coarse fault category for the `runs` row.
    Step { message: String, category: &'static str },
}

impl RunFailure {
    pub(crate) fn step(message: String, category: &'static str) -> Self {
        RunFailure::Step { message, category }
    }
}

/// Floor on the whole-run budget. A workflow with one quick step still gets a couple of minutes:
/// browser warm-up, a stealth context, session restore and the first navigation all happen before the
/// first step's own timeout even starts counting.
const MIN_RUN_BUDGET: Duration = Duration::from_secs(120);

/// Ceiling on the whole-run budget. A recorded workflow long enough to legitimately need more than
/// this is not something an unattended worker should hold a concurrency slot for; past here the
/// operator wants a report, not a run that keeps going.
const MAX_RUN_BUDGET: Duration = Duration::from_secs(2 * 3600);

/// Extra multiplier on the per-step budget when computing the whole-run budget, covering the
/// serialized non-step work (warm-up, context creation, entry navigation, session restore/harvest,
/// and — on the cloud build — one AI repair round-trip plus a single self-heal restart).
const RUN_BUDGET_OVERHEAD_STEPS: u64 = 4;

/// Derive a whole-run time budget from the workflow's OWN per-step budget and step count.
///
/// `timeout_ms` is what the workflow already declares for a single step / navigation (0 → the engine's
/// 60s default), so `(steps + overhead) × timeout_ms` is the workflow's own stated worst case rather
/// than an invented number: every step burning its full allowance, plus headroom for the serialized
/// setup/teardown around the loop. Clamped into [`MIN_RUN_BUDGET`]..=[`MAX_RUN_BUDGET`] so neither a
/// zero-step workflow nor a 5000-step one produces a nonsense budget, and saturating throughout so a
/// hostile/corrupt `timeout_ms` cannot overflow into a tiny budget.
fn overall_run_budget(timeout_ms: i64, steps: usize) -> Duration {
    let per_step_ms = if timeout_ms > 0 { timeout_ms as u64 } else { 60_000 };
    let units = (steps as u64).saturating_add(RUN_BUDGET_OVERHEAD_STEPS);
    let total_ms = per_step_ms.saturating_mul(units);
    Duration::from_millis(total_ms).clamp(MIN_RUN_BUDGET, MAX_RUN_BUDGET)
}

/// RAII counter for `RealEngine::active_runs()`.
///
/// The count was a bare `fetch_add` / `fetch_sub` pair around the run body. Every path that skipped
/// the `fetch_sub` — a cancelled or aborted `run_body` future, the new whole-run timeout's early
/// return — leaked one from the gauge permanently. That gauge is what the fleet heartbeat advertises
/// as `active_sessions`, so a handful of cancellations made an idle worker look permanently busy and
/// the coordinator stopped scheduling it. A guard cannot be skipped.
struct ActiveRunGuard {
    counter: Arc<AtomicUsize>,
}

impl ActiveRunGuard {
    fn new(counter: Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self { counter }
    }
}

impl Drop for ActiveRunGuard {
    fn drop(&mut self) {
        // Saturating: never wrap below zero even under a logic bug (a wrapped `usize` gauge would
        // advertise ~1.8e19 active sessions and permanently exclude the worker from dispatch).
        let _ = self
            .counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| Some(v.saturating_sub(1)));
    }
}

/// Map a `RunSource` to the `runs.trigger_type` vocabulary
/// (`manual|on_change|scheduled|webhook|api|workflow`).
fn trigger_type_for(source: RunSource) -> &'static str {
    match source {
        RunSource::Manual => "manual",
        RunSource::Api | RunSource::Mcp => "api",
        RunSource::Scheduled => "scheduled",
        RunSource::Webhook => "webhook",
        RunSource::Workflow => "workflow",
        RunSource::Monitor => "on_change",
        RunSource::CloudAgent => "cloud",
    }
}

/// Coarse fault category for a non-captcha step error (stored in `runs.failure_category`).
fn classify_step_error(e: &StepError) -> &'static str {
    match e {
        StepError::ElementNotFound(_) | StepError::Timeout(_) => "creator",
        StepError::NavigationFailed(_) => "infra",
        StepError::SessionExpired => "buyer",
        StepError::Execution(_) => "creator",
        // Captcha variants are handled before this is reached, but be exhaustive.
        StepError::CaptchaNotSolved(_) | StepError::CaptchaBotDetected(_) => "captcha",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::engine::LocalEngine;
    use crate::local::store::workflows::NewWorkflow;
    use crate::local::{db, vault};

    /// Build a `RealEngine` over a fresh encrypted DB + file-backed vault (no keyring prompt).
    async fn engine() -> RealEngine {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        let v = vault::Vault::load_or_create(dir.path(), false).unwrap();
        let pool = db::open(&dir.path().join("t.db"), &v.db_key_hex()).await.unwrap();
        RealEngine::with_env_browser(pool, Arc::new(v))
    }

    /// A missing workflow id is a clean NotFound (and persists no run row).
    #[tokio::test]
    async fn run_missing_workflow_is_not_found() {
        let eng = engine().await;
        let err = eng
            .run(RunRequest {
                workflow_id: 999_999,
                inputs: serde_json::json!({}),
                source: RunSource::Api,
                lane: Lane::Interactive,
                dry_run: false,
                persona_id: None,
                allow_local_secret_refs: true,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, LocalError::NotFound(_)), "expected NotFound, got {err:?}");
        assert_eq!(eng.active_runs(), 0);
    }

    /// Result-mapping + run-row persistence WITHOUT a browser: a step failure (here a context
    /// build with no warm browser — but we exercise the full mapping by inserting a workflow whose
    /// only step is unparseable, so zero steps run) finalizes the row and returns a value.
    ///
    /// This is the no-network/no-browser proof: the browser-backed happy path is in
    /// [`run_trivial_workflow_browser`] (ignored — needs a launchable Chromium).
    #[tokio::test]
    async fn engine_persists_run_row_on_browser_failure() {
        let eng = engine().await;
        let wf = workflows::insert(
            &eng.db,
            &NewWorkflow { name: "no-steps".into(), steps: Some("[]".into()), ..Default::default() },
        )
        .await
        .unwrap();

        let res = eng
            .run(RunRequest {
                workflow_id: wf.id,
                inputs: serde_json::json!({}),
                source: RunSource::Manual,
                lane: Lane::Interactive,
                dry_run: false,
                persona_id: None,
                allow_local_secret_refs: true,
            })
            .await
            .expect("engine returns a RunResult (browser launch may fail in CI)");

        // A `runs` row was persisted and terminal-finalized either way.
        let row = runs::get_by_id(&eng.db, res.run_id).await.unwrap().expect("run row exists");
        assert_ne!(row.status, "running", "run must be finalized, not left running");
        assert!(row.duration_ms.is_some(), "duration recorded");
        assert_eq!(res.duration_ms, row.duration_ms.unwrap() as u64);
        // The workflow rollup was touched.
        let after = workflows::get_by_id(&eng.db, wf.id).await.unwrap().unwrap();
        assert_eq!(after.total_run_count, 1, "run counted against workflow rollup");
        assert_eq!(eng.active_runs(), 0, "active count released");

        // If a Chromium WAS launchable in this environment, an empty-steps workflow is a success;
        // if not, it's a classified infra failure. Either way the mapping is internally consistent.
        match res.status {
            RunStatus::Success => {
                assert!(res.success);
                assert_eq!(row.success, Some(1));
            }
            RunStatus::Failed => {
                assert!(!res.success);
                assert_eq!(row.success, Some(0));
                assert!(res.error.is_some());
            }
            other => panic!("unexpected terminal status for empty-steps run: {other:?}"),
        }
    }

    /// LOW (real.rs:496): a NON-empty but UNPARSEABLE `steps` blob must FAIL (creator category), not
    /// silently "succeed" as an empty run. Deterministic without a browser: resolution parses the
    /// steps text before any Chromium launch, so the run finalizes `failed` immediately.
    #[tokio::test]
    async fn unparseable_steps_fail_not_empty_success() {
        let eng = engine().await;
        let wf = workflows::insert(
            &eng.db,
            &NewWorkflow {
                name: "corrupt-steps".into(),
                steps: Some("{ this is not valid json".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let res = eng
            .run(RunRequest {
                workflow_id: wf.id,
                inputs: serde_json::json!({}),
                source: RunSource::Manual,
                lane: Lane::Interactive,
                dry_run: false,
                persona_id: None,
                allow_local_secret_refs: true,
            })
            .await
            .expect("engine returns a RunResult");

        assert_eq!(res.status, RunStatus::Failed, "corrupt steps must fail, not succeed");
        assert!(!res.success);
        let row = runs::get_by_id(&eng.db, res.run_id).await.unwrap().expect("run row exists");
        assert_eq!(row.status, "failed");
        assert_eq!(row.failure_category.as_deref(), Some("creator"), "creator-category fault");
        assert_eq!(eng.active_runs(), 0, "active count released");
    }

    /// PRE-FLIGHT 2FA gate (no browser): a workflow with a `twofa` step run as an email-OTP persona
    /// finalizes `twofa_required` WITHOUT launching Chromium — proving the cloud-gate short-circuits
    /// before the browser warm (so it's deterministic in headless CI). TOTP would NOT gate here.
    #[tokio::test]
    async fn email_2fa_run_gates_to_cloud_without_a_browser() {
        use crate::local::store::personas::{self, NewPersona};
        let eng = engine().await;
        // An email-OTP persona — its code can only be read in the cloud (no on-device mint).
        let p = personas::insert(
            &eng.db,
            &NewPersona {
                name: "mail2fa".into(),
                twofa_method: Some("email_otp".into()),
                relay_address: Some("otp@example.com".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // A workflow whose only step is a 2FA challenge.
        let wf = workflows::insert(
            &eng.db,
            &NewWorkflow {
                name: "needs-cloud-2fa".into(),
                steps: Some(r#"[{"type":"twofa","enabled":true,"config":{}}]"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let res = eng
            .run(RunRequest {
                workflow_id: wf.id,
                inputs: serde_json::json!({}),
                source: RunSource::Manual,
                lane: Lane::Interactive,
                dry_run: false,
                persona_id: Some(p.id),
                allow_local_secret_refs: true,
            })
            .await
            .expect("engine returns a RunResult");

        assert_eq!(res.status, RunStatus::TwofaRequired, "email 2FA must gate to cloud");
        assert!(!res.success);
        assert!(
            res.error.as_deref().unwrap_or("").to_lowercase().contains("cloud"),
            "error explains the cloud requirement, got {:?}",
            res.error
        );
        let row = runs::get_by_id(&eng.db, res.run_id).await.unwrap().expect("run row exists");
        assert_eq!(row.status, "twofa_required", "persisted status string");
        assert_eq!(row.failure_category.as_deref(), Some("twofa"), "fault category stamped");
        assert_eq!(eng.active_runs(), 0, "active count released");
    }

    /// A `twofa` workflow with NO persona at all must fail fast BEFORE a browser launches —
    /// previously the step silently reported Succeeded on the challenge page. The distinct
    /// `twofa_persona` category is what tells the UI "attach a persona" apart from the
    /// email/SMS "run it in the cloud" upsell (both share the `twofa_required` status).
    #[tokio::test]
    async fn no_persona_twofa_run_gates_without_a_browser() {
        let eng = engine().await;
        let wf = workflows::insert(
            &eng.db,
            &NewWorkflow {
                name: "needs-persona-2fa".into(),
                steps: Some(r#"[{"type":"twofa","enabled":true,"config":{}}]"#.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let res = eng
            .run(RunRequest {
                workflow_id: wf.id,
                inputs: serde_json::json!({}),
                source: RunSource::Manual,
                lane: Lane::Interactive,
                dry_run: false,
                persona_id: None,
                allow_local_secret_refs: true,
            })
            .await
            .expect("engine returns a RunResult");

        assert_eq!(res.status, RunStatus::TwofaRequired, "no-persona 2FA must gate, not no-op");
        assert!(!res.success);
        assert!(
            res.error.as_deref().unwrap_or("").to_lowercase().contains("persona"),
            "error tells the operator to attach a persona, got {:?}",
            res.error
        );
        let row = runs::get_by_id(&eng.db, res.run_id).await.unwrap().expect("run row exists");
        assert_eq!(row.status, "twofa_required", "persisted status string");
        assert_eq!(
            row.failure_category.as_deref(),
            Some("twofa_persona"),
            "persona-gap category (drives the attach-a-persona card, not the cloud upsell)"
        );
        assert_eq!(eng.active_runs(), 0, "active count released");
    }

    /// Full browser-backed run of a TRIVIAL recorded workflow (a single no-network `wait` step on
    /// about:blank). Ignored by default: launching Chromium isn't guaranteed in CI. Run locally
    /// with `cargo test --features local -- --ignored run_trivial_workflow_browser`.
    #[tokio::test]
    #[ignore = "requires a launchable Chromium (not available in headless CI)"]
    async fn run_trivial_workflow_browser() {
        let eng = engine().await;
        // A missing Chromium / driver is an ENVIRONMENTAL condition, not a defect in the code under
        // test — report and skip rather than panic, so running the ignored suite on a machine without
        // a browser produces a clear message instead of a bogus failure.
        if let Err(e) = eng.browser.initialize().await {
            eprintln!("skipping run_trivial_workflow_browser — no launchable Chromium/driver: {e}");
            return;
        }

        let steps = serde_json::json!([
            { "type": "wait", "enabled": true, "config": { "duration": 50 } }
        ])
        .to_string();
        let wf = workflows::insert(
            &eng.db,
            &NewWorkflow {
                name: "trivial".into(),
                steps: Some(steps),
                entry_url: Some("about:blank".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let res = eng
            .run(RunRequest {
                workflow_id: wf.id,
                inputs: serde_json::json!({}),
                source: RunSource::Manual,
                lane: Lane::Interactive,
                dry_run: false,
                persona_id: None,
                allow_local_secret_refs: true,
            })
            .await
            .expect("run");

        assert_eq!(res.status, RunStatus::Success, "trivial wait run should succeed: {:?}", res.error);
        assert!(res.success);
        let row = runs::get_by_id(&eng.db, res.run_id).await.unwrap().unwrap();
        assert_eq!(row.status, "success");

        let _ = eng.browser.shutdown().await;
    }

    /// `run_async` (STAGE E2) returns a `run_id` immediately with status Running and persists the
    /// `runs` row. It then drives to a terminal state in the background (a browser launch failure in
    /// a browserless CI is the expected terminal here); we poll the row until it is finalized.
    #[tokio::test]
    async fn run_async_starts_then_finalizes_in_background() {
        let eng = engine().await;
        let wf = workflows::insert(
            &eng.db,
            &NewWorkflow { name: "async".into(), steps: Some("[]".into()), ..Default::default() },
        )
        .await
        .unwrap();

        let started = eng
            .run_async(RunRequest {
                workflow_id: wf.id,
                inputs: serde_json::json!({}),
                source: RunSource::Api,
                lane: Lane::Interactive,
                dry_run: false,
                persona_id: None,
                allow_local_secret_refs: true,
            })
            .await
            .expect("run_async returns a StartedRun");
        assert_eq!(started.status, RunStatus::Running);

        // The row exists immediately (status running, since the body is still spawning/launching).
        let row0 = runs::get_by_id(&eng.db, started.run_id).await.unwrap().expect("row exists");
        assert_eq!(row0.workflow_id, Some(wf.id));

        // Poll for the background task to finalize the row (bounded so the test never hangs).
        //
        // The budget is 60s, not the 5s it used to be. Reaching a terminal state here means actually
        // launching Chromium (or failing to), and under `cargo test`'s full-suite parallelism that
        // regularly took longer than 5s on a loaded machine — the test passed in isolation and failed
        // in the suite. A generous ceiling costs nothing: the loop breaks on the first terminal read,
        // so a healthy run still finishes in a couple of seconds.
        let mut terminal = None;
        for _ in 0..2_400 {
            let row = runs::get_by_id(&eng.db, started.run_id).await.unwrap().unwrap();
            if row.status != "running" {
                terminal = Some(row.status);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let status = terminal.expect("run finalized within the poll budget");
        assert_ne!(status, "running", "run reached a terminal state");

        // A terminal row does NOT imply a quiesced registry. `run_body` writes the terminal status in
        // `finalize`, and only THEN emits the terminal frame + de-registers (`guard.finish()`) and
        // drops its `ActiveRunGuard` on scope exit. That order is deliberate — releasing the slot
        // before the row is terminal would under-report "busy" and let the coordinator dispatch onto a
        // run that is still finalizing — so the window between the two is real, and asserting the
        // counters the instant the row flipped raced the spawned task (~1 failure in 10, even alone).
        // Wait for the release with the same bounded loop the status poll uses, so the test still
        // never hangs; the asserts below stay as the verdict and name which half did not release.
        for _ in 0..2_400 {
            if !eng.registry.is_live(started.run_id) && eng.active_runs() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(!eng.registry.is_live(started.run_id), "finalized run de-registered");
        assert_eq!(eng.active_runs(), 0, "active count released");
    }

    /// `cancel` on a non-live run id reports `None` (nothing live to signal); the registry plumbing
    /// is exposed through the trait.
    #[tokio::test]
    async fn cancel_unknown_run_is_none() {
        let eng = engine().await;
        assert_eq!(LocalEngine::cancel(&eng, 424_242), None);
        assert!(eng.registry().is_some(), "RealEngine exposes a registry");
    }

    /// `run_tracked` publishes the allocated `run_id` BEFORE the body finishes, and the id it reports
    /// is the id the terminal `RunResult` carries — the property the fleet bridge's
    /// `task_id → run_id` cancel map depends on.
    #[tokio::test]
    async fn run_tracked_publishes_the_run_id_it_then_returns() {
        let eng = engine().await;
        let wf = workflows::insert(
            &eng.db,
            &NewWorkflow { name: "tracked".into(), steps: Some("[]".into()), ..Default::default() },
        )
        .await
        .unwrap();

        let seen = Arc::new(std::sync::Mutex::new(Vec::<i64>::new()));
        let sink = {
            let seen = seen.clone();
            Box::new(move |run_id: i64| seen.lock().unwrap().push(run_id))
        };
        let res = eng
            .run_tracked(
                RunRequest { workflow_id: wf.id, ..Default::default() },
                sink,
            )
            .await
            .expect("engine returns a RunResult");

        let ids = seen.lock().unwrap().clone();
        assert_eq!(ids.len(), 1, "the sink fires exactly once per run");
        assert_eq!(ids[0], res.run_id, "the published id is the run's real id");
        assert_eq!(eng.active_runs(), 0, "active count released");
    }

    /// A REJECTED run (missing workflow) must never publish an id — there is no run to cancel, and a
    /// stale mapping would let a later cancel hit an unrelated run.
    #[tokio::test]
    async fn run_tracked_publishes_nothing_when_the_run_is_refused() {
        let eng = engine().await;
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink = {
            let fired = fired.clone();
            Box::new(move |_run_id: i64| fired.store(true, Ordering::SeqCst))
        };
        let err = eng
            .run_tracked(RunRequest { workflow_id: 987_654, ..Default::default() }, sink)
            .await
            .unwrap_err();
        assert!(matches!(err, LocalError::NotFound(_)), "expected NotFound, got {err:?}");
        assert!(!fired.load(Ordering::SeqCst), "no row ⇒ no id published");
    }

    /// The default trait impl is a pass-through: an engine with no registry runs normally and simply
    /// never reports an id (there is nothing cancellable to map).
    #[tokio::test]
    async fn run_tracked_default_impl_runs_without_publishing() {
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sink = {
            let fired = fired.clone();
            Box::new(move |_run_id: i64| fired.store(true, Ordering::SeqCst))
        };
        let err = super::super::StubEngine
            .run_tracked(RunRequest::default(), sink)
            .await
            .unwrap_err();
        assert!(matches!(err, LocalError::Internal(_)), "stub still runs, got {err:?}");
        assert!(!fired.load(Ordering::SeqCst), "the default impl publishes no id");
    }

    /// The whole-run budget is derived from the workflow's OWN declared per-step timeout, clamped into
    /// a sane band. This is the number that guarantees a governor permit is eventually released.
    #[test]
    fn overall_run_budget_derives_from_the_workflow_budget() {
        // 20 steps × 30s + 4 overhead units = 720s.
        assert_eq!(overall_run_budget(30_000, 20), Duration::from_secs(720));

        // Zero/negative `timeout_ms` falls back to the engine's own 60s default:
        // (10 + 4) × 60s = 840s.
        assert_eq!(overall_run_budget(0, 10), Duration::from_secs(840));
        assert_eq!(overall_run_budget(-5, 10), Duration::from_secs(840));

        // FLOOR: a tiny workflow still gets time to warm a browser + navigate.
        assert_eq!(overall_run_budget(1, 0), MIN_RUN_BUDGET);
        assert_eq!(overall_run_budget(1_000, 1), MIN_RUN_BUDGET, "5s of steps clamps up to the floor");

        // CEILING: a huge recipe cannot hold a concurrency slot indefinitely.
        assert_eq!(overall_run_budget(60_000, 100_000), MAX_RUN_BUDGET);

        // No overflow → no accidentally-tiny budget from a corrupt/hostile value.
        assert_eq!(overall_run_budget(i64::MAX, 5), MAX_RUN_BUDGET);
        assert!(overall_run_budget(i64::MAX, usize::MAX) >= MIN_RUN_BUDGET);
    }

    /// The active-run gauge is RAII: it releases on drop (the path a cancelled/aborted run body takes)
    /// and never wraps below zero.
    #[test]
    fn active_run_guard_releases_on_drop_and_never_wraps() {
        let counter = Arc::new(AtomicUsize::new(0));
        {
            let _a = ActiveRunGuard::new(counter.clone());
            assert_eq!(counter.load(Ordering::SeqCst), 1);
            {
                let _b = ActiveRunGuard::new(counter.clone());
                assert_eq!(counter.load(Ordering::SeqCst), 2);
            }
            assert_eq!(counter.load(Ordering::SeqCst), 1, "inner guard released");
        }
        assert_eq!(counter.load(Ordering::SeqCst), 0, "outer guard released");

        // A stray drop against an already-zero gauge saturates instead of wrapping to usize::MAX
        // (which the fleet heartbeat would advertise as ~1.8e19 active sessions).
        drop(ActiveRunGuard { counter: counter.clone() });
        assert_eq!(counter.load(Ordering::SeqCst), 0, "saturating, not wrapping");
    }

    /// A run whose future is DROPPED mid-flight must not leak the active gauge. This is the shape the
    /// old `fetch_add`/`fetch_sub` pair got wrong: the `fetch_sub` simply never ran, and the worker
    /// then advertised itself as permanently busy.
    #[tokio::test]
    async fn dropped_run_future_does_not_leak_the_active_gauge() {
        let eng = engine().await;
        let wf = workflows::insert(
            &eng.db,
            &NewWorkflow {
                name: "dropped".into(),
                // A `wait` step keeps the body alive long enough to drop the future mid-run.
                steps: Some(r#"[{"type":"wait","enabled":true,"config":{"duration":5000}}]"#.into()),
                entry_url: Some("about:blank".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        {
            let fut = eng.run(RunRequest { workflow_id: wf.id, ..Default::default() });
            tokio::pin!(fut);
            // Poll it a few times so the body starts, then drop it (cancellation).
            for _ in 0..8 {
                if futures_util::poll!(&mut fut).is_ready() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        }
        // Give the spawned body a moment to unwind.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            eng.active_runs(),
            0,
            "a cancelled run body must not leave the active gauge inflated"
        );
    }
}
