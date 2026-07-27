use std::sync::Arc;
use std::time::Instant;

use axum::http::Method;
use axum::routing::{get, post};
use axum::Router;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use super::middleware::{self, RateLimiter};
use crate::api::{ai_tasks, convert, health, sessions, ws_ai_tasks, ws_record, ws_spectate};
use crate::browser::manager::BrowserManager;
use crate::config::constants;
use crate::config::env::AppConfig;
use crate::recorder::core::PlaywrightRecorder;

pub struct AppState {
    pub config: AppConfig,
    pub start_time: Instant,
    pub rate_limiter: RateLimiter,
    pub recorder: Arc<PlaywrightRecorder>,
    pub browser_manager: Arc<BrowserManager>,
}

/// SECURITY / STATUS: this axum HTTP+WS server is **NOT used in production**.
/// The live agent path is the outbound `saas_bridge` (see `cli::commands::run_start`),
/// which dials the gateway and never opens a listening socket. `run()` here is
/// dead code retained for local development/testing only and is gated behind an
/// explicit `RECORDER_ENABLE_LOCAL_SERVER=1` opt-in so it can never be started by
/// accident. It binds to loopback (127.0.0.1) — never 0.0.0.0 — and the WS
/// handlers authenticate via `authenticate_ws_token` as defense-in-depth.
pub async fn run(config: AppConfig) {
    if std::env::var("RECORDER_ENABLE_LOCAL_SERVER")
        .map(|v| {
            let v = v.to_lowercase();
            v != "1" && v != "true" && v != "yes"
        })
        .unwrap_or(true)
    {
        tracing::error!(
            "server::app::run() is disabled. Set RECORDER_ENABLE_LOCAL_SERVER=1 to enable the \
             local dev server. Production uses the outbound saas_bridge, not this listener."
        );
        return;
    }

    // Bind to loopback only — this dev server must never be exposed on a public
    // interface (it has no production auth model beyond the WS token check).
    let addr = format!("127.0.0.1:{}", config.port);

    let shared_config = Arc::new(config.clone());

    // Initialize browser manager
    let browser_manager = Arc::new(BrowserManager::new(shared_config.clone()));
    if let Err(e) = browser_manager.initialize().await {
        tracing::error!(error = %e, "Failed to initialize Playwright");
        std::process::exit(1);
    }
    if let Err(e) = browser_manager.ensure_warm_browser().await {
        tracing::error!(error = %e, "Failed to launch warm browser");
        std::process::exit(1);
    }

    // Create recorder
    let recorder = Arc::new(PlaywrightRecorder::new(browser_manager.clone()));

    let state = Arc::new(AppState {
        config,
        start_time: Instant::now(),
        rate_limiter: RateLimiter::new(constants::RATE_LIMIT_ACTIONS_PER_SEC),
        recorder,
        browser_manager,
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any);

    // Authenticated routes
    let authed_routes = Router::new()
        .route("/status", get(health::status))
        .route("/sessions/active", get(sessions::list_active))
        .route("/sessions/{id}/stop", post(sessions::stop_session))
        .route("/convert/display", post(convert::to_display))
        .route("/convert/python", post(convert::to_python))
        .route("/convert/javascript", post(convert::to_javascript))
        .route("/convert/workflow", post(convert::to_workflow))
        .route("/ai-tasks/execute", post(ai_tasks::execute))
        .layer(axum::middleware::from_fn(middleware::auth_middleware))
        .layer(axum::Extension(shared_config));

    // Public routes (no auth required)
    let public_routes = Router::new()
        .route("/health", get(health::health));

    // WebSocket routes (auth handled inside the handler)
    let ws_routes = Router::new()
        .route("/ws/record", get(ws_record::handler))
        .route("/ws/ai-tasks", get(ws_ai_tasks::handler))
        .route("/ws/spectate/{id}", get(ws_spectate::handler));

    let app = Router::new()
        .merge(public_routes)
        .merge(authed_routes)
        .merge(ws_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let listener = TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        tracing::error!(error = %e, addr = %addr, "Failed to bind");
        std::process::exit(1);
    });

    tracing::info!(addr = %addr, "Listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "Server error");
        });

    tracing::info!("Shutting down");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C"),
        _ = terminate => tracing::info!("Received SIGTERM"),
    }
}
