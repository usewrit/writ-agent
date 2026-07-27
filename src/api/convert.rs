use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::codegen;
use crate::models::step::StepsInput;
use crate::server::app::AppState;

pub async fn to_display(
    State(_state): State<Arc<AppState>>,
    Json(input): Json<StepsInput>,
) -> axum::Json<serde_json::Value> {
    let display_steps = codegen::display::steps_to_display(&input.steps);
    axum::Json(json!({ "steps": display_steps }))
}

pub async fn to_python(
    State(_state): State<Arc<AppState>>,
    Json(input): Json<StepsInput>,
) -> axum::Json<serde_json::Value> {
    let code = codegen::python::steps_to_playwright_python(&input.steps, true);
    axum::Json(json!({ "code": code }))
}

pub async fn to_javascript(
    State(_state): State<Arc<AppState>>,
    Json(input): Json<StepsInput>,
) -> axum::Json<serde_json::Value> {
    let code = codegen::javascript::steps_to_playwright_js(&input.steps);
    axum::Json(json!({ "code": code }))
}

pub async fn to_workflow(
    State(_state): State<Arc<AppState>>,
    Json(input): Json<StepsInput>,
) -> axum::Json<serde_json::Value> {
    let workflow = codegen::workflow_json::steps_to_workflow_json(
        &input.steps,
        &input.name,
        &input.description,
        None,
    );
    axum::Json(workflow)
}
