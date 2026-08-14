// Playwright server management
//
// Handles downloading, launching, and managing the lifecycle of the Playwright
// Node.js server process.

use crate::server::driver::get_driver_executable;
use crate::{Error, Result};
use tokio::process::{Child, Command};
use tracing::Instrument;

/// Manages the Playwright server process lifecycle
///
/// The PlaywrightServer wraps a Node.js child process that runs the Playwright
/// driver. It communicates with the server via stdio pipes using JSON-RPC protocol.
///
/// # Example
///
/// ```ignore
/// # use playwright_rs::server::playwright_server::PlaywrightServer;
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let server = PlaywrightServer::launch().await?;
/// // Use the server...
/// server.shutdown().await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct PlaywrightServer {
    /// The Playwright server child process
    ///
    /// This is public to allow integration tests to access stdin/stdout pipes.
    /// In production code, you should use the Connection layer instead of
    /// accessing the process directly.
    pub process: Child,

    /// writ-agent patch: the last few lines the driver wrote to STDERR.
    ///
    /// The driver's stderr was drained into `tracing::debug!` and otherwise discarded. When the
    /// handshake then failed, the caller reported only "Playwright initialization timeout after 30
    /// seconds" — while node had usually already explained itself on stderr (bad architecture,
    /// missing DLL, unreadable bundle) at a log level nobody runs in production. Keep a bounded tail
    /// so the failure can carry the reason. Bounded, so a chatty driver cannot grow it without limit.
    pub stderr_tail: std::sync::Arc<std::sync::Mutex<std::collections::VecDeque<String>>>,
}

/// How many trailing stderr lines to keep for diagnostics.
const STDERR_TAIL_LINES: usize = 20;

impl PlaywrightServer {
    /// writ-agent patch: a one-line summary of why the driver may have failed — its exit status (if
    /// it has already died) plus the tail of its stderr. Empty string when there is nothing to add.
    pub fn failure_context(&mut self) -> String {
        let mut parts: Vec<String> = Vec::new();
        match self.process.try_wait() {
            Ok(Some(status)) => parts.push(format!("driver process exited with {status}")),
            Ok(None) => parts.push("driver process still running".to_string()),
            Err(e) => parts.push(format!("could not query driver process: {e}")),
        }
        let tail = self.stderr_tail.lock().unwrap_or_else(|e| e.into_inner());
        if !tail.is_empty() {
            parts.push(format!(
                "driver stderr: {}",
                tail.iter().cloned().collect::<Vec<_>>().join(" | ")
            ));
        }
        parts.join("; ")
    }
}

impl PlaywrightServer {
    /// Launch the Playwright server process
    ///
    /// This will:
    /// 1. Check if the Playwright driver exists (download if needed)
    /// 2. Launch the server using `node <driver>/cli.js run-driver`
    /// 3. Set environment variable `PW_LANG_NAME=rust`
    ///
    /// # Errors
    ///
    /// Returns `Error::ServerNotFound` if the driver cannot be located.
    /// Returns `Error::LaunchFailed` if the process fails to start.
    ///
    /// See: <https://playwright.dev/docs/api>
    pub async fn launch() -> Result<Self> {
        // Get the driver executable paths
        // The driver should already be downloaded by build.rs
        let (node_exe, cli_js) = get_driver_executable()?;

        // writ-agent patch: name the driver being spawned. Every "Playwright timed out" report so
        // far had to be debugged by hand because nothing in a shipped build said WHICH `node` ran.
        tracing::info!(
            node = %node_exe.display(),
            cli = %cli_js.display(),
            "spawning the Playwright driver"
        );

        // Launch the server process. Stderr is piped (not inherited)
        // because the Node driver writes terminal-capability queries
        // and other escape sequences to its stderr while alive. With
        // stderr inherited, those bytes clobber the user's tty and
        // break shell line-editing after a Ctrl-C while the driver is
        // still gracefully shutting down chromium (see #59). We drain
        // the piped stderr in a background task and forward each line
        // via `tracing::debug!` so users with tracing enabled can
        // still see driver diagnostics.
        let mut cmd = Command::new(&node_exe);
        cmd.arg(&cli_js)
            .arg("run-driver")
            .env("PW_LANG_NAME", "rust")
            .env("PW_LANG_NAME_VERSION", env!("CARGO_PKG_RUST_VERSION"))
            .env("PW_CLI_DISPLAY_VERSION", env!("CARGO_PKG_VERSION"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Put the Node driver in its own process group so a Ctrl-C in
        // the user's shell (which sends SIGINT to the foreground process
        // group) doesn't reach Node. When our process dies, Node's stdin
        // pipe closes and the driver runs `gracefullyProcessExitDoNotHang`
        // — a quiet, browser-aware shutdown. Without this isolation, Node
        // gets SIGINT'd alongside us and races a noisy EPIPE error path
        // that writes terminal-capability queries to stderr; the
        // terminal's responses then pollute bash's stdin buffer and
        // disrupt readline. See issue #59.
        // process_group is on tokio::process::Command directly (Unix
        // only). Pgid 0 means "make the child its own group leader"
        // (PGID == child PID).
        #[cfg(unix)]
        {
            cmd.process_group(0);
        }

        // writ-agent patch: CREATE_NO_WINDOW on Windows.
        //
        // `node.exe` is a CONSOLE-subsystem program. When the parent has no console of its own —
        // which is exactly the case for the daemon spawned as a Tauri SIDECAR from a
        // `windows_subsystem = "windows"` GUI shell — Windows ALLOCATES a fresh console (and a
        // conhost.exe) for the child unless a creation flag says otherwise. That is both a visible
        // console flash and real startup work that the same binary does not do when it is launched
        // from a PowerShell window, where a console already exists to inherit. It matches the
        // reported behaviour precisely: running the sidecar by hand in a terminal works, the same
        // build spawned by the desktop app hangs in the driver handshake.
        //
        // CREATE_NO_WINDOW keeps the child console-less and windowless. Playwright's own Node
        // implementation does the same thing (`windowsHide: true`), so this matches upstream rather
        // than diverging from it. stdio is piped either way, so nothing about the protocol changes.
        #[cfg(windows)]
        {
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| Error::LaunchFailed(format!("Failed to spawn process: {}", e)))?;

        // Drain Node's stderr in a background task. Without an active
        // reader the kernel pipe buffer would eventually fill and
        // block the driver's writes; we don't want that. Bytes are
        // forwarded line-by-line via `tracing::debug!` so they're
        // accessible when needed without polluting the terminal.
        // writ-agent patch: ALSO retain a bounded tail, so a failed handshake can report what the
        // driver said instead of only that it timed out.
        let stderr_tail = std::sync::Arc::new(std::sync::Mutex::new(
            std::collections::VecDeque::<String>::with_capacity(STDERR_TAIL_LINES),
        ));
        if let Some(stderr) = child.stderr.take() {
            let tail = std::sync::Arc::clone(&stderr_tail);
            tokio::spawn(
                async move {
                    use tokio::io::{AsyncBufReadExt, BufReader};
                    let mut lines = BufReader::new(stderr).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        tracing::debug!(target: "playwright_rs::driver_stderr", "{}", line);
                        let mut t = tail.lock().unwrap_or_else(|e| e.into_inner());
                        if t.len() == STDERR_TAIL_LINES {
                            t.pop_front();
                        }
                        t.push_back(line);
                    }
                }
                .in_current_span(),
            );
        }

        // Check if process started successfully
        // Give it a moment to potentially fail
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(Error::LaunchFailed(format!(
                    "Server process exited immediately with status: {}",
                    status
                )));
            }
            Ok(None) => {
                // Process is still running, good!
            }
            Err(e) => {
                return Err(Error::LaunchFailed(format!(
                    "Failed to check process status: {}",
                    e
                )));
            }
        }

        Ok(Self { process: child, stderr_tail })
    }

    /// Shut down the server gracefully
    ///
    /// Sends a shutdown signal to the server and waits for it to exit.
    ///
    /// # Platform-Specific Behavior
    ///
    /// **Windows**: Explicitly closes stdio pipes before killing the process to avoid
    /// hangs. On Windows, tokio uses a blocking threadpool for child process stdio,
    /// and failing to close pipes before terminating can cause the cleanup to hang
    /// indefinitely. Uses a timeout to prevent permanent hangs.
    ///
    /// **Unix**: Uses standard process termination with graceful wait.
    ///
    /// # Errors
    ///
    /// Returns an error if the shutdown fails or times out.
    pub async fn shutdown(mut self) -> Result<()> {
        #[cfg(windows)]
        {
            // Windows-specific cleanup: Close stdio pipes BEFORE killing process
            // This prevents hanging due to Windows' blocking threadpool for stdio
            drop(self.process.stdin.take());
            drop(self.process.stdout.take());
            drop(self.process.stderr.take());

            // Kill the process
            self.process
                .kill()
                .await
                .map_err(|e| Error::LaunchFailed(format!("Failed to kill process: {}", e)))?;

            // Wait for process to exit with timeout (Windows can hang without this)
            match tokio::time::timeout(std::time::Duration::from_secs(5), self.process.wait()).await
            {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) => Err(Error::LaunchFailed(format!(
                    "Failed to wait for process: {}",
                    e
                ))),
                Err(_) => {
                    // Timeout - try one more kill
                    let _ = self.process.start_kill();
                    Err(Error::LaunchFailed(
                        "Process shutdown timeout after 5 seconds".to_string(),
                    ))
                }
            }
        }

        #[cfg(not(windows))]
        {
            // Unix: Standard graceful shutdown
            self.process
                .kill()
                .await
                .map_err(|e| Error::LaunchFailed(format!("Failed to kill process: {}", e)))?;

            // Wait for process to exit
            let _ = self.process.wait().await;

            Ok(())
        }
    }

    /// Force kill the server process
    ///
    /// This should only be used if graceful shutdown fails.
    ///
    /// # Platform-Specific Behavior
    ///
    /// **Windows**: Closes stdio pipes before killing to prevent hangs.
    ///
    /// **Unix**: Standard force kill operation.
    ///
    /// # Errors
    ///
    /// Returns an error if the kill operation fails.
    pub async fn kill(mut self) -> Result<()> {
        #[cfg(windows)]
        {
            // Windows: Close pipes before killing
            drop(self.process.stdin.take());
            drop(self.process.stdout.take());
            drop(self.process.stderr.take());
        }

        self.process
            .kill()
            .await
            .map_err(|e| Error::LaunchFailed(format!("Failed to kill process: {}", e)))?;

        #[cfg(windows)]
        {
            // On Windows, wait with timeout
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(2), self.process.wait()).await;
        }

        #[cfg(not(windows))]
        {
            // On Unix, optionally wait (don't block)
            let _ =
                tokio::time::timeout(std::time::Duration::from_millis(500), self.process.wait())
                    .await;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_launch_and_shutdown() {
        // This test will attempt to launch the Playwright server
        // If Playwright is not installed, it will try to download it
        let result = PlaywrightServer::launch().await;

        match result {
            Ok(server) => {
                tracing::info!("Server launched successfully!");
                // Clean shutdown
                let shutdown_result = server.shutdown().await;
                assert!(
                    shutdown_result.is_ok(),
                    "Shutdown failed: {:?}",
                    shutdown_result
                );
            }
            Err(Error::ServerNotFound) => {
                // This can happen if npm is not installed or download fails
                tracing::warn!(
                    "Could not launch server: Playwright not found and download may have failed"
                );
                tracing::warn!(
                    "To run this test, install Playwright manually: npm install playwright"
                );
                // Don't fail the test - this is expected in CI without Node.js
            }
            Err(Error::LaunchFailed(msg)) => {
                tracing::warn!("Launch failed: {}", msg);
                tracing::warn!("This may be expected if Node.js or npm is not installed");
                // Don't fail - expected in environments without Node.js
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_server_can_be_killed() {
        // Test that we can force-kill a server
        let result = PlaywrightServer::launch().await;

        if let Ok(server) = result {
            tracing::info!("Server launched, testing kill...");
            let kill_result = server.kill().await;
            assert!(kill_result.is_ok(), "Kill failed: {:?}", kill_result);
        } else {
            // Server didn't launch, that's okay for this test
            tracing::warn!("Server didn't launch (expected without Node.js/Playwright)");
        }
    }
}
