//! `LocalEngine` seam — the single in-process interface REST/MCP/OpenAI/scheduler call to run a
//! workflow. House style: boxed-future (NO `async-trait`), object-safe so the server/scheduler/
//! cloud-link can hold `Arc<dyn LocalEngine>`.
//!
//! The real run pipeline ([`RealEngine`], in `real.rs`) is the P1 keystone (ENG-6): it loads a
//! recorded workflow from the encrypted store, drives its steps on a warm Chromium context using
//! the SAME public step executor the cloud bridge uses (`automation::step_executor::execute_step`),
//! and persists a `runs` row. It is a SEPARATE path from the cloud `bridge/saas_bridge`
//! `handle_execute_workflow` (which sends WS `task_result` frames) — they share the per-step
//! executor as the common core, not the orchestration. The [`StubEngine`] stays as a fallback.

use super::error::{LocalError, LocalResult};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub mod events;
pub mod flow_events;
pub(crate) mod http;
pub(crate) mod persona;
mod real;
/// AI auto-repair via the managed cloud gateway (cloud build only).
#[cfg(feature = "cloud")]
pub(crate) mod repair;
pub(crate) mod repair_gate;
pub mod registry;

pub(crate) use real::RunFailure;
pub(crate) mod resolve;
pub mod streaming;
pub(crate) mod twofa;
pub use flow_events::FlowEventEngine;
pub use real::RealEngine;
pub use registry::RunRegistry;
// Steps-text helpers reused by the API dry-run preview (CR-4): normalize `{{vault:}}`→`{{secret:}}`
// and enumerate the referenced secret KEY NAMES (names only — never values).
pub use resolve::{normalize_vault_aliases, scan_secret_keys};
pub use streaming::StreamEvent;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunSource {
    Manual,
    Api,
    Mcp,
    Scheduled,
    Webhook,
    Workflow,
    Monitor,
    /// A run dispatched to this machine BY the linked cloud account (the desktop acting as a BYO
    /// execution agent — `LinkedAgentBridge` `run_local_workflow` / ad-hoc `execute_workflow`). Maps
    /// to the `runs.trigger_type` value `"cloud"` so the UI can distinguish cloud-initiated runs from
    /// local ones. Identity/billing/isolation stay server-side (the never-trust-a-BYO-agent rule) —
    /// this tag is purely local-run provenance.
    CloudAgent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    /// User/API/MCP runs — priority on the shared warm-browser pool.
    Interactive,
    /// Scheduler/monitor runs.
    Background,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Running,
    Success,
    Failed,
    Cancelled,
    Timeout,
    CaptchaRequired,
    /// The run hit a 2FA challenge whose code can only be obtained in the cloud (email-OTP / SMS).
    /// TOTP is minted on-device and never reaches here; this is the email/SMS cloud-gate, mirroring
    /// [`RunStatus::CaptchaRequired`] — a non-success terminal state the caller upsells cloud on.
    TwofaRequired,
}

#[derive(Debug, Clone)]
pub struct RunRequest {
    pub workflow_id: i64,
    pub inputs: serde_json::Value,
    pub source: RunSource,
    pub lane: Lane,
    pub dry_run: bool,
    /// Optional persona override for this run. When `Some`, it takes PRECEDENCE over the workflow's
    /// pinned `default_persona_id` (the desktop Run modal sets this so a user can pick a different
    /// login identity per run). `None` → fall back to the workflow default. Marketplace recipes stay
    /// BYO-clean (`None`); persona/creds resolve from the consumer's own data only.
    pub persona_id: Option<i64>,
    /// Whether this run may resolve `{{secret:KEY}}`/`{{vault:KEY}}`/`{{file:slot}}` placeholders
    /// against the user's LOCAL vault + file store (TB-2).
    ///
    /// `true` (the [`Default`]) for every run the user or the user's own saved workflow authored —
    /// local runs, MCP/API/scheduler runs, and cloud-dispatched runs of the user's OWN saved
    /// `cloud_callable` workflows. Set to `false` ONLY for an AD-HOC recipe whose STEPS are authored
    /// cloud-side (`RunSource::CloudAgent` `execute_workflow`): such a recipe must resolve secrets
    /// ONLY from its own channel-key-sealed `credentials_encrypted` blob, never by guessing local
    /// vault key names. When `false`, [`super::resolve::resolve_run_refs`] skips the local
    /// `vault_secrets` lookup and the engine strips `{{file:slot}}` markers so a cloud recipe cannot
    /// exfiltrate a local secret/file.
    pub allow_local_secret_refs: bool,
}

impl Default for RunRequest {
    fn default() -> Self {
        Self {
            workflow_id: 0,
            inputs: serde_json::Value::Null,
            source: RunSource::Api,
            lane: Lane::Interactive,
            dry_run: false,
            persona_id: None,
            // Preserve historical behavior: a run resolves local vault/file refs unless a caller
            // explicitly opts out (the cloud ad-hoc recipe path).
            allow_local_secret_refs: true,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RunResult {
    pub run_id: i64,
    pub status: RunStatus,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub extracted_data: serde_json::Value,
    pub duration_ms: u64,
}

/// A run started asynchronously: the run id + the SSE-observable broadcast handle. Returned by
/// [`LocalEngine::run_async`] so a 202 caller can subscribe to lifecycle events / cancel by id.
pub struct StartedRun {
    pub run_id: i64,
    pub status: RunStatus,
}

/// One-shot callback handed the `run_id` of a run the instant its `runs` row exists — before the run
/// body executes. See [`LocalEngine::run_tracked`].
pub type RunIdSink<'a> = Box<dyn FnOnce(i64) + Send + 'a>;

/// In-process execution contract. No loopback hop, no WS, no tenant_id (single-user).
pub trait LocalEngine: Send + Sync {
    fn run<'a>(
        &'a self,
        req: RunRequest,
    ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>>;

    /// Like [`Self::run`] — same synchronous await-to-completion contract, same [`RunResult`] — but
    /// reports the allocated `run_id` through `on_start` as soon as the run row exists and BEFORE the
    /// body runs.
    ///
    /// WHY this exists: a remote dispatcher (the fleet coordinator) addresses work by its OWN
    /// `task_id` and has no way to learn the local `run_id`, so a `cancel_task` frame had nothing to
    /// cancel — it was logged and dropped while the worker kept driving the browser and holding its
    /// governor permit. With the id published at dispatch time the bridge can keep a
    /// `task_id → run_id` map and route a cancel into [`Self::cancel`], which the step loop already
    /// polls cooperatively.
    ///
    /// Default: fall back to [`Self::run`] WITHOUT reporting an id — an engine with no registry has
    /// nothing cancellable, so there is no id worth publishing.
    fn run_tracked<'a>(
        &'a self,
        req: RunRequest,
        on_start: RunIdSink<'a>,
    ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
        drop(on_start);
        self.run(req)
    }

    fn active_runs(&self) -> usize;

    /// Start a run WITHOUT awaiting its completion (STAGE E2). The engine inserts the `runs` row,
    /// registers a live [`registry::RunHandle`], spawns the execute body, and returns the new
    /// `run_id` so the caller can 202 + stream `/v1/runs/:id/events` or `cancel` it.
    ///
    /// Default: fall back to the synchronous `run` (await to completion, then report the terminal
    /// status). Engines that own a [`RunRegistry`] (the `RealEngine`) override this to truly spawn.
    fn run_async<'a>(
        &'a self,
        req: RunRequest,
    ) -> Pin<Box<dyn Future<Output = LocalResult<StartedRun>> + Send + 'a>> {
        Box::pin(async move {
            let res = self.run(req).await?;
            Ok(StartedRun { run_id: res.run_id, status: res.status })
        })
    }

    /// Request cancellation of a LIVE run by id (STAGE E2). Returns:
    ///   - `Some(true)`  — the run was live and this call signalled cancellation,
    ///   - `Some(false)` — the run was live but already cancelling,
    ///   - `None`        — no live run with this id (already finished / never started here).
    ///
    /// Default: `None` (an engine with no registry has nothing live to cancel).
    fn cancel(&self, _run_id: i64) -> Option<bool> {
        None
    }

    /// The engine's live-run registry, when it has one (the `RealEngine` does). The API layer uses
    /// it to subscribe to `/v1/runs/:id/events` and to route `cancel`. Default: `None`.
    fn registry(&self) -> Option<Arc<RunRegistry>> {
        None
    }

    /// The engine's warm `BrowserManager`, when it owns one (the `RealEngine` does). The local
    /// recording WS (`local::record`) reuses this SAME manager so recording shares the one warm
    /// Chromium the run engine already holds — no second browser launch. Default: `None` (the
    /// `StubEngine` has no browser, so recording is simply unavailable in that build).
    fn browser(&self) -> Option<Arc<crate::browser::manager::BrowserManager>> {
        None
    }

    /// The engine's process-wide resource governor (PROD-14), when it owns one (the `RealEngine`
    /// does). The scheduler reads it to consult [`ResourceGovernor::should_shed_background`] before
    /// dispatching heavy background work, so it backs off while memory is high. Default: `None` — a
    /// governorless engine (the `StubEngine`) is never throttled by the scheduler.
    fn governor(&self) -> Option<Arc<crate::local::governor::ResourceGovernor>> {
        None
    }

    /// The engine's local streaming-session manager, when it owns one (the `RealEngine` does). The
    /// API layer uses it to LAUNCH / LIST / END the long-lived streaming sessions behind the
    /// `/v1/streaming/sessions*` routes (the desktop "Run a streaming workflow" path). Default:
    /// `None` — a streamless engine (the `StubEngine`) has no sessions to manage.
    fn streaming(&self) -> Option<Arc<streaming::LocalStreamingManager>> {
        None
    }

    /// The engine's at-rest vault, when it owns one (the `RealEngine` does). The automation flow
    /// interpreter (`flow.rs`) uses it — with `db` + `Paths::resolve()` — to write a data-export
    /// StoredFile from a `save_data_to_file` / `query_and_export` action WITHOUT threading a vault
    /// handle through every trigger site. Default: `None` — a vaultless engine (the `StubEngine`)
    /// cannot persist an encrypted file, so those actions degrade to a recorded skip.
    fn vault(&self) -> Option<Arc<crate::local::vault::Vault>> {
        None
    }

    /// Run an EPHEMERAL recipe (marketplace protected executor) end-to-end, returning the terminal
    /// [`RunResult`] synchronously so the caller has the real `status` + `duration_ms` to FINALIZE a
    /// metered charge before responding.
    ///
    /// Unlike [`run`] (which loads a PERSISTED workflow row by id), the recipe is an in-memory
    /// [`workflows::Workflow`] the daemon decrypted from a channel_key-sealed marketplace blob — it is
    /// NEVER persisted as plaintext. The engine inserts a `runs` row with `workflow_id = NULL` (so it
    /// surfaces in `/v1/runs` without a workflow rollup), drives the recipe's steps on the warm
    /// browser via the SAME executor as a normal run, and discards the recipe.
    ///
    /// BYO (the never-trust-a-BYO-agent rule / marketplace invariant 4): the recipe carries NO
    /// credential VALUES (`credentials_encrypted = None`, `default_persona_id = None`); resolution
    /// pulls the CONSUMER's own vault secrets / inputs only.
    ///
    /// `source` tags the `runs.trigger_type` for the ephemeral run (marketplace callers pass
    /// [`RunSource::Api`]; the cloud-agent bridge passes [`RunSource::CloudAgent`] so the run surfaces
    /// as `"cloud"`).
    ///
    /// Default: unsupported (a browserless engine cannot run a recipe).
    fn run_recipe<'a>(
        &'a self,
        _recipe: crate::local::store::workflows::Workflow,
        _inputs: serde_json::Value,
        _source: RunSource,
    ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
        Box::pin(async {
            Err(LocalError::BadRequest(
                "recipe execution is not supported by this engine".into(),
            ))
        })
    }

    /// Run ONE streamed chat turn of a STREAMING workflow (one driven by an in-page `advanced_script`
    /// + handlers), returning a receiver of [`StreamEvent`]s the OpenAI-compat `stream:true` path
    /// proxies into `chat.completion.chunk` SSE. The receiver yields incremental
    /// [`StreamEvent::Chunk`]s and one terminal [`StreamEvent::Done`]/[`StreamEvent::Error`].
    ///
    /// `wf` is the (already loaded) workflow row; `inputs` is the resolved run-input object. The
    /// engine finds-or-lazily-starts a long-lived streaming session for the workflow. The second
    /// tuple element is the resolved `response_field` (default `content`) so the caller can pull the
    /// final content out of the `Done` payload.
    ///
    /// Default: unsupported (a streamless engine has no warm browser to drive a chat tab).
    fn run_streaming<'a>(
        &'a self,
        _wf: crate::local::store::workflows::Workflow,
        _inputs: serde_json::Value,
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
        Box::pin(async {
            Err(LocalError::BadRequest(
                "streaming is not supported by this engine".into(),
            ))
        })
    }
}

/// Placeholder engine until the ENG-6 keystone refactor lands; lets the base wire
/// `Arc<dyn LocalEngine>` into the server/scheduler.
pub struct StubEngine;

impl LocalEngine for StubEngine {
    fn run<'a>(
        &'a self,
        _req: RunRequest,
    ) -> Pin<Box<dyn Future<Output = LocalResult<RunResult>> + Send + 'a>> {
        Box::pin(async { Err(LocalError::Internal("engine run not yet implemented (ENG-6)".into())) })
    }
    fn active_runs(&self) -> usize {
        0
    }
}
