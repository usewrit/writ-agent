// `otp_entry` is transport-neutral (shared OTP-entry JS invocations): used by the recorder, the
// local 2FA engine, and the extracted `automation::agent_actions`. It carries no cloud coupling, so
// it stays UNGATED and ships in the cloud-free `fleet` build.
pub mod otp_entry;

// Cloud recorder-agent connection machinery (managed product). Gated behind `cloud` and physically
// OMITTED from the OSS self-host export. `speed_profile` is used only by `saas_bridge`.
#[cfg(feature = "cloud")]
pub mod auth;
#[cfg(feature = "cloud")]
pub mod saas_bridge;
// `session_relay` (AgentSessionRelay) is a self-contained mpsc/JSON adapter with NO cloud coupling
// (its comment always intended the fleet build's streaming to use it). Shared so the fleet worker
// can serve live streaming sessions too.
#[cfg(any(feature = "cloud", all(feature = "fleet", feature = "local")))]
pub mod session_relay;
#[cfg(feature = "cloud")]
pub mod speed_profile;

// Shared streaming-session orchestration (open browser → navigate → StreamingSessionManager +
// command loop). BOTH the cloud `saas_bridge` and the OSS `fleet_bridge` call it; each passes its
// own resolved credentials/proxy so the two keep their distinct credential-decrypt paths. Every
// helper it drives lives in feature-ungated modules (streaming/*, automation/*, browser/*,
// wire_exec, otp_entry, url_guard).
#[cfg(any(feature = "cloud", all(feature = "fleet", feature = "local")))]
pub mod streaming_session;

// Self-host FLEET worker bridge (the OSS product). A cloud-free twin of `saas_bridge`: it connects
// to a self-host coordinator over the same `/api/recorder/connect` → `/ws/ai-gateway` two-step, but
// carries NO cloud auth/token machinery and drives the `local` engine directly. It hosts a
// coordinator-deployable LOCAL workflow catalog (`save_local_workflow`/`save_local_secret`/
// `save_local_persona` + `run_local_workflow` + `request_local_catalog`). Gated on BOTH `fleet`
// (never compiled in the managed cloud build, which is mutually exclusive with `fleet`) AND `local`
// (the engine/store/vault it reuses). A `fleet`-only build with no `local` engine compiles the
// module out — there would be nothing to run.
#[cfg(all(feature = "fleet", feature = "local"))]
pub mod fleet_bridge;

// Shared wire-dispatched `execute_workflow` executor — the full-definition run (steps/credentials/
// session_state in the message config) that BOTH the cloud `saas_bridge` and the OSS `fleet_bridge`
// serve. Transport (outgoing frame sink) and channel-key source are parameterized; everything it
// drives (automation step executor, HTTP lane, url guard, session state) is feature-ungated.
#[cfg(any(feature = "cloud", all(feature = "fleet", feature = "local")))]
pub mod wire_exec;
