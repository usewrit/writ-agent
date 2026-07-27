use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Authentication required")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Session limit reached (max {0})")]
    SessionLimit(usize),

    #[error("Browser error: {0}")]
    Browser(String),

    #[error("AI error: {0}")]
    Ai(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden(_) => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::SessionLimit(_) => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            AppError::Browser(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Ai(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Timeout(_) => (StatusCode::GATEWAY_TIMEOUT, self.to_string()),
            AppError::BadRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };

        let body = json!({
            "error": message,
            "status": status.as_u16(),
        });

        (status, axum::Json(body)).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::BadRequest(err.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}
