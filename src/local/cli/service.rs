//! Thin presentation wrappers over [`crate::local::app::supervisor`] for the service
//! install/uninstall subcommands.
//!
//! The actual unit generation + service-manager calls live in `supervisor`; this layer just maps a
//! [`ServiceReport`]/[`SupervisorError`] onto stdout + a [`LocalResult`] so the binaries
//! (`writ-agentd install-service`/`uninstall-service`) have a one-line call site. The daemon binary
//! is the natural owner of "install ME as a service" because it resolves its OWN path via
//! `current_exe()`.
//!
//! NEVER logs a secret (there are none here — only paths + the binary location).

use crate::local::app::supervisor::{self, SupervisorError};
use crate::local::error::{LocalError, LocalResult};

/// Install the current binary as a user-level service and print a friendly confirmation.
pub fn install() -> LocalResult<()> {
    match supervisor::install_service() {
        Ok(report) => {
            println!("Service installed via {}.", report.manager);
            println!("{}", report.note);
            Ok(())
        }
        Err(e) => Err(map_err(e)),
    }
}

/// Uninstall the user-level service and print a friendly confirmation.
pub fn uninstall() -> LocalResult<()> {
    match supervisor::uninstall_service() {
        Ok(report) => {
            println!("Service uninstall via {}: done.", report.manager);
            println!("{}", report.note);
            Ok(())
        }
        Err(e) => Err(map_err(e)),
    }
}

/// Fold a [`SupervisorError`] into the crate boundary error so the binaries share one error type.
fn map_err(e: SupervisorError) -> LocalError {
    match e {
        SupervisorError::Unsupported => {
            LocalError::BadRequest("service install is not supported on this platform".into())
        }
        other => LocalError::Internal(other.to_string()),
    }
}
