//! Boundary error for the local backend (mirrors the crate's `server/error.rs::AppError`
//! pattern). Module-local typed sub-errors (e.g. vault, db) convert into this at the API edge.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub type LocalResult<T> = Result<T, LocalError>;

#[derive(Debug, thiserror::Error)]
pub enum LocalError {
    #[error("database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("migration error: {0}")]
    Migrate(String),
    /// Empty `PRAGMA cipher_version` => sqlx linked plain SQLite => the DB would be PLAINTEXT
    /// while appearing encrypted. Fail closed (SECURITY_AND_ENTITLEMENTS_SPEC §1.5).
    #[error("SQLCipher unavailable: PRAGMA cipher_version is empty (refusing to open a plaintext DB)")]
    CipherUnavailable,
    #[error("database integrity check failed: {0}")]
    Corrupt(String),
    /// The DB on disk was written by a NEWER app version (its `schema_version` exceeds the one this
    /// binary understands). Refuse to open it — a silent downgrade would corrupt or drop data.
    #[error("database schema is from a newer app version ({found} > {supported}); upgrade Writ to open it")]
    SchemaVersionFuture { found: u32, supported: u32 },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    /// The request conflicts with existing state: a uniqueness collision (this monitor already
    /// watches that selector), or a lost optimistic-lock race (`concierge_sessions.turn_seq`).
    /// Maps to 409 — the caller can fix it (pick another value) or retry (re-read, re-apply).
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("unauthorized")]
    Unauthorized,
    /// Authenticated but the credential lacks the scope/capability for this route (403).
    #[error("forbidden")]
    Forbidden,
    /// Per-account data-isolation boundary violated: either the active profile home holds a DB
    /// stamped for a DIFFERENT account (owner-stamp mismatch, caught at boot) or a request's
    /// `X-Writ-Account` header names a different account than the profile the daemon is serving
    /// (caught by the account-binding middleware). Fail CLOSED — never risk serving one account's
    /// data as another's. Maps to 403.
    #[error("account isolation violation: {0}")]
    IsolationViolation(String),
    /// Vault is locked (app-lock engaged) — secret-touching routes return 423.
    #[error("vault locked")]
    Locked,
    /// A rate-limited surface (e.g. WS-ticket minting) hit its per-window budget → 429. Transient:
    /// the caller retries after the window. Carries no secret.
    #[error("too many requests")]
    TooManyRequests,
    /// Automated CAPTCHA solving is a paid cloud feature — not present in the OSS binary.
    #[error("captcha required: automated solving needs a connected Writ Cloud account")]
    CaptchaRequired { captcha_type: Option<String>, url: String },
    /// The linked account is out of AI credit (or over a plan limit) for a metered cloud-AI call —
    /// e.g. AI auto-repair via the managed gateway. Maps to 402 so the UI shows an upgrade prompt.
    /// Carries the server's user-facing message ("… upgrade / add credit").
    #[error("{0}")]
    PaymentRequired(String),
    /// The aggregate local-monitor cadence would exceed what THIS machine can sustainably run
    /// (see `scheduler::capacity`). NOT a plan limit — pure device protection, so it maps to 409
    /// (a conflict with device state), never 402: there is nothing to pay for locally.
    #[error("this machine is at its monitor capacity: this change needs {would_use:.1} of {budget:.0} checks/min — slow a check interval, disable a monitor, or run heavy monitors in the cloud")]
    DeviceCapacity { would_use: f64, budget: f64 },
    /// The Writ Cloud backend could not be reached (offline / DNS / connect-or-read timeout).
    /// This is an EXPECTED, transient condition — not a fault — so it maps to 503 and lets the
    /// desktop UI degrade gracefully (retry affordance, last-known reflection) instead of treating
    /// it as an internal error. Distinct from `Unauthorized` (linked-but-token-rejected).
    #[error("cloud unreachable: {0}")]
    CloudUnreachable(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Internal(String),
}

/// Which integrity constraint a driver error violated, or `None` when it is not a constraint error.
///
/// Goes through `sqlx`'s driver-agnostic [`sqlx::error::ErrorKind`] rather than matching SQLite
/// result codes or message text: the codes differ per backend and the message is exactly the string
/// we must NOT put in a response.
fn constraint_kind(e: &sqlx::Error) -> Option<sqlx::error::ErrorKind> {
    match e {
        sqlx::Error::Database(db) => match db.kind() {
            k @ (sqlx::error::ErrorKind::UniqueViolation
            | sqlx::error::ErrorKind::ForeignKeyViolation
            | sqlx::error::ErrorKind::NotNullViolation
            | sqlx::error::ErrorKind::CheckViolation) => Some(k),
            _ => None,
        },
        _ => None,
    }
}

impl LocalError {
    pub fn status(&self) -> StatusCode {
        match self {
            LocalError::NotFound(_) => StatusCode::NOT_FOUND,
            LocalError::BadRequest(_) => StatusCode::BAD_REQUEST,
            LocalError::Conflict(_) => StatusCode::CONFLICT,
            // A constraint violation is a CLIENT problem, not an internal fault: adding the same CSS
            // selector to a monitor twice trips `UNIQUE(target_id, selector)` and used to surface as a
            // 500 with raw SQLite text ("UNIQUE constraint failed: target_selectors.selector"), which
            // both misled the client into retrying and leaked the schema. Uniqueness → 409 (fix the
            // value or accept the existing row); the reference/shape violations → 400.
            LocalError::Db(e) => match constraint_kind(e) {
                Some(sqlx::error::ErrorKind::UniqueViolation) => StatusCode::CONFLICT,
                Some(_) => StatusCode::BAD_REQUEST,
                None => StatusCode::INTERNAL_SERVER_ERROR,
            },
            LocalError::Unauthorized => StatusCode::UNAUTHORIZED,
            LocalError::Forbidden => StatusCode::FORBIDDEN,
            LocalError::IsolationViolation(_) => StatusCode::FORBIDDEN, // 403 → fail-closed account boundary
            LocalError::Locked => StatusCode::LOCKED, // 423
            LocalError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS, // 429 → retry after the window
            LocalError::CaptchaRequired { .. } => StatusCode::PAYMENT_REQUIRED, // 402 → CaptchaGate upsell
            LocalError::PaymentRequired(_) => StatusCode::PAYMENT_REQUIRED, // 402 → out of AI credit, upgrade upsell
            LocalError::DeviceCapacity { .. } => StatusCode::CONFLICT, // 409 → device, not billing
            LocalError::CloudUnreachable(_) => StatusCode::SERVICE_UNAVAILABLE, // 503 → offline, retryable
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Stable machine code for clients (UI/MCP) to branch on.
    pub fn code(&self) -> &'static str {
        match self {
            LocalError::Db(e) => match constraint_kind(e) {
                Some(sqlx::error::ErrorKind::UniqueViolation) => "conflict",
                Some(sqlx::error::ErrorKind::ForeignKeyViolation) => "invalid_reference",
                Some(_) => "invalid_field",
                None => "db_error",
            },
            LocalError::Conflict(_) => "conflict",
            LocalError::Migrate(_) => "db_error",
            LocalError::CipherUnavailable => "cipher_unavailable",
            LocalError::Corrupt(_) => "db_corrupt",
            LocalError::SchemaVersionFuture { .. } => "schema_version_future",
            LocalError::NotFound(_) => "not_found",
            LocalError::BadRequest(_) => "bad_request",
            LocalError::Unauthorized => "unauthorized",
            LocalError::Forbidden => "forbidden",
            LocalError::IsolationViolation(_) => "isolation_violation",
            LocalError::Locked => "vault_locked",
            LocalError::TooManyRequests => "too_many_requests",
            LocalError::CaptchaRequired { .. } => "captcha_required",
            LocalError::PaymentRequired(_) => "payment_required",
            LocalError::DeviceCapacity { .. } => "device_capacity",
            LocalError::CloudUnreachable(_) => "cloud_unreachable",
            LocalError::Io(_) => "io_error",
            LocalError::Json(_) => "json_error",
            LocalError::Internal(_) => "internal",
        }
    }

    /// The message that goes to the CLIENT.
    ///
    /// Identical to `Display` for every variant except [`LocalError::Db`]: a driver error's text
    /// names tables, columns and index names ("UNIQUE constraint failed: target_selectors.target_id,
    /// target_selectors.selector"). That is schema disclosure and it is useless to the caller, so the
    /// raw text stays server-side (logged in `into_response`) and the client gets an actionable
    /// summary instead.
    pub fn public_message(&self) -> String {
        match self {
            LocalError::Db(e) => match constraint_kind(e) {
                Some(sqlx::error::ErrorKind::UniqueViolation) => {
                    "already exists: one of these values must be unique and is already in use".into()
                }
                Some(sqlx::error::ErrorKind::ForeignKeyViolation) => {
                    "invalid reference: a record this request points at does not exist".into()
                }
                Some(sqlx::error::ErrorKind::NotNullViolation) => {
                    "a required field is missing".into()
                }
                Some(_) => "a field value is not allowed".into(),
                None => "database error".into(),
            },
            other => other.to_string(),
        }
    }
}

impl IntoResponse for LocalError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "local backend error");
        } else if matches!(self, LocalError::Db(_)) {
            // A constraint violation is a 4xx, so the branch above never logs it — but the raw driver
            // text is deliberately withheld from the response, so log it here or it is lost entirely.
            tracing::warn!(error = %self, "local backend constraint violation");
        }
        let mut body = json!({ "error": self.public_message(), "code": self.code() });
        if let LocalError::CaptchaRequired { captcha_type, url } = &self {
            body["captcha_type"] = json!(captcha_type);
            body["url"] = json!(url);
        }
        if let LocalError::DeviceCapacity { would_use, budget } = &self {
            body["would_use_units_per_min"] = json!(would_use);
            body["budget_units_per_min"] = json!(budget);
        }
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePool;

    /// A bare in-memory SQLite pool (no SQLCipher key needed — nothing here is persisted). Used only
    /// to make the driver produce a REAL constraint error rather than a hand-built fake.
    async fn mem_pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE parent (id INTEGER PRIMARY KEY);
             CREATE TABLE t (
                 id INTEGER PRIMARY KEY,
                 a TEXT NOT NULL,
                 b TEXT,
                 parent_id INTEGER REFERENCES parent(id),
                 UNIQUE(a, b)
             );",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON").execute(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn unique_violation_is_409_with_no_driver_text() {
        let pool = mem_pool().await;
        sqlx::query("INSERT INTO t (a, b) VALUES ('x', 'y')").execute(&pool).await.unwrap();
        let err: LocalError = sqlx::query("INSERT INTO t (a, b) VALUES ('x', 'y')")
            .execute(&pool)
            .await
            .expect_err("second insert must violate UNIQUE(a, b)")
            .into();

        assert_eq!(err.status(), StatusCode::CONFLICT, "duplicate must be 409, not 500");
        assert_eq!(err.code(), "conflict");
        let msg = err.public_message();
        // The response text must not name the table, the columns, or the driver phrasing.
        assert!(!msg.contains("UNIQUE"), "leaked driver text: {msg}");
        assert!(!msg.contains("constraint"), "leaked driver text: {msg}");
        assert!(msg.contains("already exists"), "unhelpful message: {msg}");
        // Display (log side) still carries the full driver text.
        assert!(err.to_string().to_uppercase().contains("UNIQUE"));
    }

    #[tokio::test]
    async fn fk_and_not_null_violations_are_400() {
        let pool = mem_pool().await;

        let fk: LocalError = sqlx::query("INSERT INTO t (a, parent_id) VALUES ('x', 999)")
            .execute(&pool)
            .await
            .expect_err("parent 999 does not exist")
            .into();
        assert_eq!(fk.status(), StatusCode::BAD_REQUEST);
        assert_eq!(fk.code(), "invalid_reference");
        assert!(fk.public_message().contains("invalid reference"));

        let nn: LocalError = sqlx::query("INSERT INTO t (a) VALUES (NULL)")
            .execute(&pool)
            .await
            .expect_err("a is NOT NULL")
            .into();
        assert_eq!(nn.status(), StatusCode::BAD_REQUEST);
        assert_eq!(nn.code(), "invalid_field");
    }

    #[tokio::test]
    async fn non_constraint_db_error_stays_500_and_generic() {
        let pool = mem_pool().await;
        let err: LocalError = sqlx::query("SELECT * FROM no_such_table")
            .execute(&pool)
            .await
            .expect_err("table does not exist")
            .into();
        assert_eq!(err.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.code(), "db_error");
        assert_eq!(err.public_message(), "database error");
        assert!(!err.public_message().contains("no_such_table"));
    }

    #[test]
    fn conflict_variant_is_409_and_keeps_its_message() {
        let e = LocalError::Conflict("this monitor already watches that selector".into());
        assert_eq!(e.status(), StatusCode::CONFLICT);
        assert_eq!(e.code(), "conflict");
        assert!(e.public_message().contains("already watches"));
    }
}
