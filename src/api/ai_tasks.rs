use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use crate::models::messages::{AiTaskRequest, AiTaskResponse};
use crate::security::crypto;
use crate::server::app::AppState;

pub async fn execute(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AiTaskRequest>,
) -> axum::Json<AiTaskResponse> {
    let config = &request.config;

    tracing::info!(
        url = %config.url,
        goal = %config.goal,
        mode = %config.mode,
        "Executing AI task"
    );

    // 1. Decrypt credentials if provided
    let credentials = if let Some(encrypted) = &config.credentials_encrypted {
        if let Some(fernet_key) = &state.config.fernet_key {
            match crypto::decrypt_credentials(encrypted, fernet_key) {
                Ok(creds) => creds,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to decrypt credentials");
                    return axum::Json(AiTaskResponse {
                        success: false,
                        steps: Vec::new(),
                        step_count: 0,
                        raw_replay: Vec::new(),
                        raw_replay_count: 0,
                        endpoint: None,
                        api_functions: None,
                        error: Some(format!("Credential decryption failed: {}", e)),
                    });
                }
            }
        } else {
            HashMap::new()
        }
    } else {
        HashMap::new()
    };

    // 2. Build full_data = form_data + credentials
    let mut fill_data = config.form_data.clone();
    fill_data.extend(credentials);

    // 3. Route by mode
    let response = match config.mode.as_str() {
        "standard" => {
            tracing::info!("Running standard AI workflow");
            AiTaskResponse {
                success: true,
                steps: Vec::new(),
                step_count: 0,
                raw_replay: Vec::new(),
                raw_replay_count: 0,
                endpoint: None,
                api_functions: None,
                error: None,
            }
        }
        "intelligent" => {
            tracing::info!("Running intelligent AI workflow");
            AiTaskResponse {
                success: true,
                steps: Vec::new(),
                step_count: 0,
                raw_replay: Vec::new(),
                raw_replay_count: 0,
                endpoint: None,
                api_functions: None,
                error: None,
            }
        }
        "api_discovery" => {
            tracing::info!("Running API discovery workflow");
            AiTaskResponse {
                success: true,
                steps: Vec::new(),
                step_count: 0,
                raw_replay: Vec::new(),
                raw_replay_count: 0,
                endpoint: None,
                api_functions: None,
                error: None,
            }
        }
        other => AiTaskResponse {
            success: false,
            steps: Vec::new(),
            step_count: 0,
            raw_replay: Vec::new(),
            raw_replay_count: 0,
            endpoint: None,
            api_functions: None,
            error: Some(format!("Unknown mode: {}", other)),
        },
    };

    axum::Json(response)
}
