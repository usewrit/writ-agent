pub mod engine;
pub mod agent_actions;
pub mod step_executor;
pub mod inflight;
pub mod step_navigate;
pub mod step_click;
pub mod step_fill;
pub mod step_select;
pub mod step_check;
pub mod step_captcha;
// Automated CAPTCHA solver — MANAGED CLOUD BUILD ONLY. Compiled only when `captcha_solver` is on and
// this is not the `local` desktop build. The open-source and desktop builds fall back to the
// detection-only path in `step_captcha`.
#[cfg(all(feature = "captcha_solver", not(feature = "local")))]
pub mod captcha_solver;
pub mod step_wait;
pub mod step_eval;
pub mod response_extract;
pub mod http_lane;
pub mod step_change;
pub mod step_ai;
pub mod step_misc;
pub mod step_upload;
pub mod step_download;
pub mod files;
pub mod recognition;
pub mod raw_replay;
pub mod session_state;
pub mod human_behavior;
pub mod coordinates;
pub mod selectors;
pub mod iframes;
pub mod network_capture;

pub use agent_actions::run_agent_actions;
