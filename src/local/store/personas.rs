//! Store layer for the `personas` table (§6 of 0001_init.sql).
//!
//! Personas hold login identities + 2FA config. All sensitive fields are ciphertext-only
//! (`*_encrypted`); the encryption key lives in the OS keyring (never in this DB). This store
//! treats every `*_encrypted` / `*_seed_encrypted` column as an opaque String and NEVER logs it.
//!
//! Runtime-checked sqlx only (no compile-time macros). Errors map into `LocalError` via `?`.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;

/// Max rows returned by an unbounded `list`.
const LIST_CAP: i64 = 500;

/// One row of the `personas` table. Column order/names mirror 0001_init.sql exactly.
///
/// `Debug` is hand-written — see the module docs on `store`. The four ciphertext columns are the
/// persona's login credentials, its TOTP seed, its proxy config (which carries proxy credentials) and
/// its saved browser session (cookies = a live logged-in session). A derived `Debug` put all of that
/// in any log line that formatted a `Persona`, and ciphertext is still material an attacker should
/// never be handed for free.
#[derive(Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct Persona {
    #[serde(default)]
    pub id: i64,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub target_domain: Option<String>,
    #[serde(default)]
    pub login_username: Option<String>,
    /// Ciphertext — never logged.
    #[serde(default)]
    pub credentials_encrypted: Option<String>,
    pub twofa_method: String,
    /// Ciphertext — never logged.
    #[serde(default)]
    pub totp_seed_encrypted: Option<String>,
    pub totp_digits: i64,
    pub totp_period_seconds: i64,
    pub totp_algorithm: String,
    #[serde(default)]
    pub email_otp_mode: Option<String>,
    #[serde(default)]
    pub relay_address: Option<String>,
    /// JSON-TEXT — callers serde it.
    #[serde(default)]
    pub otp_extract_config: Option<String>,
    /// JSON-TEXT — callers serde it.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Ciphertext — never logged.
    #[serde(default)]
    pub proxy_config_encrypted: Option<String>,
    /// Ciphertext — never logged.
    #[serde(default)]
    pub session_state_encrypted: Option<String>,
    #[serde(default)]
    pub earliest_cookie_expiry: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    pub validation_status: String,
    #[serde(default)]
    pub last_login_at: Option<String>,
    pub is_active: i64,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub last_used_at: Option<String>,
}

impl std::fmt::Debug for Persona {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Persona")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("target_domain", &self.target_domain)
            .field("login_username", &self.login_username)
            .field("twofa_method", &self.twofa_method)
            .field("validation_status", &self.validation_status)
            .field("is_active", &self.is_active)
            .field("expires_at", &self.expires_at)
            // Secret material: presence only, never content.
            .field("credentials_encrypted", &super::redacted(&self.credentials_encrypted))
            .field("totp_seed_encrypted", &super::redacted(&self.totp_seed_encrypted))
            .field("proxy_config_encrypted", &super::redacted(&self.proxy_config_encrypted))
            .field("session_state_encrypted", &super::redacted(&self.session_state_encrypted))
            .finish_non_exhaustive()
    }
}

/// Fields accepted on insert. Optional ciphertext/JSON columns may be omitted (`None`).
/// `Debug` redacts the same four ciphertext columns as [`Persona`].
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct NewPersona {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub target_domain: Option<String>,
    #[serde(default)]
    pub login_username: Option<String>,
    #[serde(default)]
    pub credentials_encrypted: Option<String>,
    /// Defaults to `"none"` when empty.
    #[serde(default)]
    pub twofa_method: Option<String>,
    #[serde(default)]
    pub totp_seed_encrypted: Option<String>,
    /// Defaults to 6 when `None`.
    #[serde(default)]
    pub totp_digits: Option<i64>,
    /// Defaults to 30 when `None`.
    #[serde(default)]
    pub totp_period_seconds: Option<i64>,
    /// Defaults to `"SHA1"` when empty.
    #[serde(default)]
    pub totp_algorithm: Option<String>,
    #[serde(default)]
    pub email_otp_mode: Option<String>,
    #[serde(default)]
    pub relay_address: Option<String>,
    #[serde(default)]
    pub otp_extract_config: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub proxy_config_encrypted: Option<String>,
    #[serde(default)]
    pub session_state_encrypted: Option<String>,
    #[serde(default)]
    pub earliest_cookie_expiry: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl std::fmt::Debug for NewPersona {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewPersona")
            .field("name", &self.name)
            .field("target_domain", &self.target_domain)
            .field("login_username", &self.login_username)
            .field("twofa_method", &self.twofa_method)
            .field("credentials_encrypted", &super::redacted(&self.credentials_encrypted))
            .field("totp_seed_encrypted", &super::redacted(&self.totp_seed_encrypted))
            .field("proxy_config_encrypted", &super::redacted(&self.proxy_config_encrypted))
            .field("session_state_encrypted", &super::redacted(&self.session_state_encrypted))
            .finish_non_exhaustive()
    }
}

/// Mutable fields on `update`. `None` leaves the column untouched (COALESCE semantics).
/// `Debug` redacts the same four ciphertext columns as [`Persona`].
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct PersonaUpdate {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub target_domain: Option<String>,
    #[serde(default)]
    pub login_username: Option<String>,
    #[serde(default)]
    pub credentials_encrypted: Option<String>,
    #[serde(default)]
    pub twofa_method: Option<String>,
    #[serde(default)]
    pub totp_seed_encrypted: Option<String>,
    #[serde(default)]
    pub totp_digits: Option<i64>,
    #[serde(default)]
    pub totp_period_seconds: Option<i64>,
    #[serde(default)]
    pub totp_algorithm: Option<String>,
    #[serde(default)]
    pub email_otp_mode: Option<String>,
    #[serde(default)]
    pub relay_address: Option<String>,
    #[serde(default)]
    pub otp_extract_config: Option<String>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub proxy_config_encrypted: Option<String>,
    #[serde(default)]
    pub session_state_encrypted: Option<String>,
    #[serde(default)]
    pub earliest_cookie_expiry: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub validation_status: Option<String>,
    /// 0/1.
    #[serde(default)]
    pub is_active: Option<i64>,
}

impl std::fmt::Debug for PersonaUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersonaUpdate")
            .field("name", &self.name)
            .field("target_domain", &self.target_domain)
            .field("login_username", &self.login_username)
            .field("twofa_method", &self.twofa_method)
            .field("validation_status", &self.validation_status)
            .field("is_active", &self.is_active)
            .field("credentials_encrypted", &super::redacted(&self.credentials_encrypted))
            .field("totp_seed_encrypted", &super::redacted(&self.totp_seed_encrypted))
            .field("proxy_config_encrypted", &super::redacted(&self.proxy_config_encrypted))
            .field("session_state_encrypted", &super::redacted(&self.session_state_encrypted))
            .finish_non_exhaustive()
    }
}

/// Insert a persona, returning the full row (so callers see DB-applied defaults/id/timestamps).
pub async fn insert(pool: &SqlitePool, p: &NewPersona) -> LocalResult<Persona> {
    let row = sqlx::query_as::<_, Persona>(
        r#"
        INSERT INTO personas (
            name, description, target_domain, login_username, credentials_encrypted,
            twofa_method, totp_seed_encrypted, totp_digits, totp_period_seconds, totp_algorithm,
            email_otp_mode, relay_address, otp_extract_config, fingerprint,
            proxy_config_encrypted, session_state_encrypted, earliest_cookie_expiry, expires_at
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            COALESCE(?6, 'none'), ?7, COALESCE(?8, 6), COALESCE(?9, 30), COALESCE(?10, 'SHA1'),
            ?11, ?12, ?13, ?14,
            ?15, ?16, ?17, ?18
        )
        RETURNING *
        "#,
    )
    .bind(&p.name)
    .bind(&p.description)
    .bind(&p.target_domain)
    .bind(&p.login_username)
    .bind(&p.credentials_encrypted)
    .bind(&p.twofa_method)
    .bind(&p.totp_seed_encrypted)
    .bind(p.totp_digits)
    .bind(p.totp_period_seconds)
    .bind(&p.totp_algorithm)
    .bind(&p.email_otp_mode)
    .bind(&p.relay_address)
    .bind(&p.otp_extract_config)
    .bind(&p.fingerprint)
    .bind(&p.proxy_config_encrypted)
    .bind(&p.session_state_encrypted)
    .bind(&p.earliest_cookie_expiry)
    .bind(&p.expires_at)
    .fetch_one(pool)
    .await?;
    tracing::info!(persona_id = row.id, name = %row.name, "persona inserted");
    Ok(row)
}

/// Fetch one persona by id, or `None` if absent.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<Persona>> {
    let row = sqlx::query_as::<_, Persona>("SELECT * FROM personas WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Fetch one persona by its unique name.
pub async fn get_by_name(pool: &SqlitePool, name: &str) -> LocalResult<Option<Persona>> {
    let row = sqlx::query_as::<_, Persona>("SELECT * FROM personas WHERE name = ?1")
        .bind(name)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// List personas, newest-first, capped at `limit` (default/cap `LIST_CAP`).
pub async fn list(pool: &SqlitePool, limit: Option<i64>) -> LocalResult<Vec<Persona>> {
    let lim = limit.unwrap_or(LIST_CAP).clamp(1, LIST_CAP);
    let rows = sqlx::query_as::<_, Persona>(
        "SELECT * FROM personas ORDER BY created_at DESC, id DESC LIMIT ?1",
    )
    .bind(lim)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List personas scoped to a target domain, newest-first.
pub async fn list_by_domain(pool: &SqlitePool, domain: &str) -> LocalResult<Vec<Persona>> {
    let rows = sqlx::query_as::<_, Persona>(
        "SELECT * FROM personas WHERE target_domain = ?1 ORDER BY created_at DESC, id DESC",
    )
    .bind(domain)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Partially update a persona (COALESCE: `None` fields are left as-is). Bumps `updated_at`.
/// Returns the updated row, or `None` if no such id.
pub async fn update(pool: &SqlitePool, id: i64, u: &PersonaUpdate) -> LocalResult<Option<Persona>> {
    let row = sqlx::query_as::<_, Persona>(
        r#"
        UPDATE personas SET
            name                   = COALESCE(?2, name),
            description            = COALESCE(?3, description),
            target_domain          = COALESCE(?4, target_domain),
            login_username         = COALESCE(?5, login_username),
            credentials_encrypted  = COALESCE(?6, credentials_encrypted),
            twofa_method           = COALESCE(?7, twofa_method),
            totp_seed_encrypted    = COALESCE(?8, totp_seed_encrypted),
            totp_digits            = COALESCE(?9, totp_digits),
            totp_period_seconds    = COALESCE(?10, totp_period_seconds),
            totp_algorithm         = COALESCE(?11, totp_algorithm),
            email_otp_mode         = COALESCE(?12, email_otp_mode),
            relay_address          = COALESCE(?13, relay_address),
            otp_extract_config     = COALESCE(?14, otp_extract_config),
            fingerprint            = COALESCE(?15, fingerprint),
            proxy_config_encrypted = COALESCE(?16, proxy_config_encrypted),
            session_state_encrypted= COALESCE(?17, session_state_encrypted),
            earliest_cookie_expiry = COALESCE(?18, earliest_cookie_expiry),
            expires_at             = COALESCE(?19, expires_at),
            validation_status      = COALESCE(?20, validation_status),
            is_active              = COALESCE(?21, is_active),
            updated_at             = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id = ?1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(&u.name)
    .bind(&u.description)
    .bind(&u.target_domain)
    .bind(&u.login_username)
    .bind(&u.credentials_encrypted)
    .bind(&u.twofa_method)
    .bind(&u.totp_seed_encrypted)
    .bind(u.totp_digits)
    .bind(u.totp_period_seconds)
    .bind(&u.totp_algorithm)
    .bind(&u.email_otp_mode)
    .bind(&u.relay_address)
    .bind(&u.otp_extract_config)
    .bind(&u.fingerprint)
    .bind(&u.proxy_config_encrypted)
    .bind(&u.session_state_encrypted)
    .bind(&u.earliest_cookie_expiry)
    .bind(&u.expires_at)
    .bind(&u.validation_status)
    .bind(u.is_active)
    .fetch_optional(pool)
    .await?;
    if row.is_some() {
        tracing::info!(persona_id = id, "persona updated");
    }
    Ok(row)
}

/// Stamp `last_login_at` (+ `last_used_at`) to now and set validation_status.
pub async fn mark_login(pool: &SqlitePool, id: i64, status: &str) -> LocalResult<()> {
    sqlx::query(
        r#"
        UPDATE personas SET
            last_login_at     = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
            last_used_at      = strftime('%Y-%m-%dT%H:%M:%fZ','now'),
            validation_status = ?2,
            updated_at        = strftime('%Y-%m-%dT%H:%M:%fZ','now')
        WHERE id = ?1
        "#,
    )
    .bind(id)
    .bind(status)
    .execute(pool)
    .await?;
    Ok(())
}

/// Bump `last_used_at` to now (lightweight touch on use). No-op if id absent.
pub async fn touch_used(pool: &SqlitePool, id: i64) -> LocalResult<()> {
    sqlx::query("UPDATE personas SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Hard-delete a persona. Returns `true` if a row was removed.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM personas WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    let removed = res.rows_affected() > 0;
    if removed {
        tracing::info!(persona_id = id, "persona deleted");
    }
    Ok(removed)
}
