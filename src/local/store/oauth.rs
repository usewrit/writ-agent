//! Store layer for the local OAuth 2.1 authorization server (`oauth_clients` / `oauth_codes` /
//! `oauth_tokens`, migration 0016).
//!
//! Public clients + PKCE only — there are no client secrets anywhere. Codes and tokens are stored
//! as sha256 hex of the raw value (same idiom as `local_api_keys.key_hash`); the raw strings exist
//! only in the HTTP responses that mint them. NEVER log a hash or a raw credential.
//!
//! Runtime-checked sqlx only (no compile-time macros). Errors map into `LocalError` via `?`.

use super::super::error::LocalResult;
use sqlx::sqlite::SqlitePool;

/// One registered OAuth client (RFC 7591 dynamic registration).
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct OauthClient {
    #[serde(default)]
    pub id: i64,
    pub client_id: String,
    pub client_name: Option<String>,
    /// JSON array of exact-match redirect URIs.
    pub redirect_uris: String,
    pub created_at: String,
}

/// One single-use authorization code (hash-addressed).
///
/// `Debug` is hand-written (see the `store` module docs): `code_hash` and `code_challenge` are
/// credential verifiers for an in-flight authorization and never belong in a log line.
#[derive(Clone, sqlx::FromRow)]
pub struct OauthCode {
    pub id: i64,
    pub code_hash: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub expires_at: i64,
    pub used: i64,
}

/// One issued access(+refresh) pair (hash-addressed). `access_hash`/`refresh_hash` are sensitive —
/// never serialized to clients.
#[derive(Clone, sqlx::FromRow)]
pub struct OauthToken {
    pub id: i64,
    pub access_hash: String,
    pub refresh_hash: Option<String>,
    pub client_id: String,
    pub scope: String,
    pub access_expires_at: i64,
    pub refresh_expires_at: Option<i64>,
    pub revoked: i64,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// Register a client. `redirect_uris` is a pre-validated JSON array string.
pub async fn insert_client(
    pool: &SqlitePool,
    client_id: &str,
    client_name: Option<&str>,
    redirect_uris_json: &str,
) -> LocalResult<OauthClient> {
    let row = sqlx::query_as::<_, OauthClient>(
        r#"
        INSERT INTO oauth_clients (client_id, client_name, redirect_uris)
        VALUES (?1, ?2, ?3)
        RETURNING *
        "#,
    )
    .bind(client_id)
    .bind(client_name)
    .bind(redirect_uris_json)
    .fetch_one(pool)
    .await?;
    tracing::info!(client_id = %row.client_id, name = row.client_name.as_deref().unwrap_or("-"), "oauth client registered");
    Ok(row)
}

/// Fetch a client by its public id.
pub async fn get_client(pool: &SqlitePool, client_id: &str) -> LocalResult<Option<OauthClient>> {
    let row = sqlx::query_as::<_, OauthClient>("SELECT * FROM oauth_clients WHERE client_id = ?1")
        .bind(client_id)
        .fetch_optional(pool)
        .await?;
    Ok(row)
}

/// Persist a freshly minted (hashed) authorization code.
pub async fn insert_code(
    pool: &SqlitePool,
    code_hash: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    scope: &str,
    expires_at: i64,
) -> LocalResult<()> {
    sqlx::query(
        r#"
        INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, scope, expires_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
    )
    .bind(code_hash)
    .bind(client_id)
    .bind(redirect_uri)
    .bind(code_challenge)
    .bind(scope)
    .bind(expires_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// SINGLE-USE claim of an authorization code: atomically flips `used` 0→1 and returns the row —
/// a second redemption (replay) finds `used=1` and gets `None`. Expiry is enforced here too.
pub async fn take_code(pool: &SqlitePool, code_hash: &str, now: i64) -> LocalResult<Option<OauthCode>> {
    take_code_with(pool, code_hash, now).await
}

/// [`take_code`] over any executor, so the claim and the token it mints share ONE transaction.
/// See [`take_refresh_with`] for why that matters.
pub async fn take_code_with<'e, E>(
    exec: E,
    code_hash: &str,
    now: i64,
) -> LocalResult<Option<OauthCode>>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query_as::<_, OauthCode>(
        r#"
        UPDATE oauth_codes SET used = 1
        WHERE code_hash = ?1 AND used = 0 AND expires_at > ?2
        RETURNING *
        "#,
    )
    .bind(code_hash)
    .bind(now)
    .fetch_optional(exec)
    .await?;
    Ok(row)
}

/// Persist a freshly minted (hashed) access(+refresh) pair.
#[allow(clippy::too_many_arguments)]
pub async fn insert_token(
    pool: &SqlitePool,
    access_hash: &str,
    refresh_hash: Option<&str>,
    client_id: &str,
    scope: &str,
    access_expires_at: i64,
    refresh_expires_at: Option<i64>,
) -> LocalResult<()> {
    insert_token_with(
        pool,
        access_hash,
        refresh_hash,
        client_id,
        scope,
        access_expires_at,
        refresh_expires_at,
    )
    .await
}

/// [`insert_token`] over any executor, so the mint can join the claim's transaction.
#[allow(clippy::too_many_arguments)]
pub async fn insert_token_with<'e, E>(
    exec: E,
    access_hash: &str,
    refresh_hash: Option<&str>,
    client_id: &str,
    scope: &str,
    access_expires_at: i64,
    refresh_expires_at: Option<i64>,
) -> LocalResult<()>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    sqlx::query(
        r#"
        INSERT INTO oauth_tokens (access_hash, refresh_hash, client_id, scope, access_expires_at, refresh_expires_at)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
    )
    .bind(access_hash)
    .bind(refresh_hash)
    .bind(client_id)
    .bind(scope)
    .bind(access_expires_at)
    .bind(refresh_expires_at)
    .execute(exec)
    .await?;
    Ok(())
}

/// AUTH lookup: live (non-revoked, non-expired) token by access hash.
pub async fn get_active_by_access_hash(
    pool: &SqlitePool,
    access_hash: &str,
    now: i64,
) -> LocalResult<Option<OauthToken>> {
    let row = sqlx::query_as::<_, OauthToken>(
        "SELECT * FROM oauth_tokens WHERE access_hash = ?1 AND revoked = 0 AND access_expires_at > ?2",
    )
    .bind(access_hash)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// REFRESH rotation claim: atomically revoke the pair addressed by this refresh hash and return it
/// (so the caller can mint a replacement). A replayed refresh token finds `revoked=1` → `None`.
pub async fn take_refresh(
    pool: &SqlitePool,
    refresh_hash: &str,
    now: i64,
) -> LocalResult<Option<OauthToken>> {
    take_refresh_with(pool, refresh_hash, now).await
}

/// [`take_refresh`] over any executor.
///
/// Rotation is only safe if the revoke and the replacement mint are ONE atomic unit. As two
/// autocommit statements, a failure (or a crash) between them left the client holding a refresh token
/// the server had already revoked, with no replacement issued and no way to recover short of
/// re-running the whole authorization flow — a permanent lockout from a transient error. The token
/// endpoint therefore drives this and [`insert_token_with`] inside a single transaction.
pub async fn take_refresh_with<'e, E>(
    exec: E,
    refresh_hash: &str,
    now: i64,
) -> LocalResult<Option<OauthToken>>
where
    E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
{
    let row = sqlx::query_as::<_, OauthToken>(
        r#"
        UPDATE oauth_tokens SET revoked = 1
        WHERE refresh_hash = ?1 AND revoked = 0
          AND refresh_expires_at IS NOT NULL AND refresh_expires_at > ?2
        RETURNING *
        "#,
    )
    .bind(refresh_hash)
    .bind(now)
    .fetch_optional(exec)
    .await?;
    Ok(row)
}

/// Best-effort usage stamp (mirrors `local_api_keys::touch_used`).
pub async fn touch_used(pool: &SqlitePool, id: i64) -> LocalResult<()> {
    sqlx::query("UPDATE oauth_tokens SET last_used_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Housekeeping: drop expired/used codes and long-dead tokens. Called opportunistically from the
/// token endpoint (no scheduler wiring needed for correctness — expiry is enforced at read time).
pub async fn purge_expired(pool: &SqlitePool, now: i64) -> LocalResult<()> {
    sqlx::query("DELETE FROM oauth_codes WHERE expires_at <= ?1 OR used = 1")
        .bind(now)
        .execute(pool)
        .await?;
    // Keep revoked rows for 30 days (debug/audit), then drop.
    sqlx::query(
        r#"
        DELETE FROM oauth_tokens
        WHERE (revoked = 1 OR access_expires_at <= ?1)
          AND COALESCE(refresh_expires_at, 0) <= ?1
          AND access_expires_at <= ?1 - 2592000
        "#,
    )
    .bind(now)
    .execute(pool)
    .await?;
    Ok(())
}

impl std::fmt::Debug for OauthCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthCode")
            .field("id", &self.id)
            .field("client_id", &self.client_id)
            .field("redirect_uri", &self.redirect_uri)
            .field("scope", &self.scope)
            .field("expires_at", &self.expires_at)
            .field("used", &self.used)
            .field("code_hash", &super::REDACTED)
            .field("code_challenge", &super::REDACTED)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OauthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthToken")
            .field("id", &self.id)
            .field("client_id", &self.client_id)
            .field("scope", &self.scope)
            .field("access_expires_at", &self.access_expires_at)
            .field("refresh_expires_at", &self.refresh_expires_at)
            .field("revoked", &self.revoked)
            .field("access_hash", &super::REDACTED)
            .field("refresh_hash", &super::redacted(&self.refresh_hash))
            .finish_non_exhaustive()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::db;

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-oauth-store").await.unwrap()
    }

    fn now() -> i64 {
        chrono::Utc::now().timestamp()
    }

    /// THE REGRESSION: refresh rotation revokes the old pair and mints the replacement. Done as two
    /// autocommit statements, a failed mint left the client with a revoked refresh token and NO
    /// replacement — a permanent lockout requiring the whole authorization flow to be re-run. In one
    /// transaction, a failed mint rolls the revoke back and the old token stays usable, so the client
    /// simply retries.
    #[tokio::test]
    async fn a_failed_mint_rolls_the_refresh_revoke_back() {
        let pool = pool().await;
        insert_client(&pool, "wcl_x", Some("Host"), r#"["http://127.0.0.1/cb"]"#).await.unwrap();
        insert_token(&pool, "acc1", Some("ref1"), "wcl_x", "run", now() + 3600, Some(now() + 7200))
            .await
            .unwrap();

        // Force the mint to fail: a temporary unique index over `scope` collides with the row above.
        sqlx::query("CREATE UNIQUE INDEX tmp_unique_scope ON oauth_tokens(scope)")
            .execute(&pool)
            .await
            .unwrap();

        let mut tx = pool.begin().await.unwrap();
        let claimed = take_refresh_with(&mut *tx, "ref1", now()).await.unwrap();
        assert!(claimed.is_some(), "the refresh token was claimable");
        let minted = insert_token_with(
            &mut *tx,
            "acc2",
            Some("ref2"),
            "wcl_x",
            "run",
            now() + 3600,
            Some(now() + 7200),
        )
        .await;
        assert!(minted.is_err(), "the mint must have failed for this test to mean anything");
        drop(tx); // no commit ⇒ rollback

        sqlx::query("DROP INDEX tmp_unique_scope").execute(&pool).await.unwrap();

        // The client is NOT locked out: its refresh token is still live and its access token still works.
        assert!(
            take_refresh(&pool, "ref1", now()).await.unwrap().is_some(),
            "the revoke must have rolled back with the failed mint"
        );
        // (that claim consumed it, which is the normal single-use behaviour)
        assert!(take_refresh(&pool, "ref1", now()).await.unwrap().is_none());
    }

    /// The happy path still rotates atomically: after a committed transaction the old refresh token is
    /// dead and the new pair is live.
    #[tokio::test]
    async fn a_committed_rotation_kills_the_old_pair_and_installs_the_new_one() {
        let pool = pool().await;
        insert_client(&pool, "wcl_x", None, r#"["http://127.0.0.1/cb"]"#).await.unwrap();
        insert_token(&pool, "acc1", Some("ref1"), "wcl_x", "run", now() + 3600, Some(now() + 7200))
            .await
            .unwrap();

        let mut tx = pool.begin().await.unwrap();
        let row = take_refresh_with(&mut *tx, "ref1", now()).await.unwrap().unwrap();
        assert_eq!(row.client_id, "wcl_x");
        insert_token_with(&mut *tx, "acc2", Some("ref2"), "wcl_x", "run", now() + 3600, Some(now() + 7200))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        assert!(get_active_by_access_hash(&pool, "acc1", now()).await.unwrap().is_none());
        assert!(get_active_by_access_hash(&pool, "acc2", now()).await.unwrap().is_some());
        assert!(take_refresh(&pool, "ref1", now()).await.unwrap().is_none(), "replay is dead");
    }

    /// The authorization-code claim shares the same shape.
    #[tokio::test]
    async fn a_failed_mint_rolls_the_code_claim_back() {
        let pool = pool().await;
        insert_client(&pool, "wcl_x", None, r#"["http://127.0.0.1/cb"]"#).await.unwrap();
        insert_code(&pool, "codehash", "wcl_x", "http://127.0.0.1/cb", "chal", "run", now() + 300)
            .await
            .unwrap();
        insert_token(&pool, "acc1", None, "wcl_x", "run", now() + 3600, None).await.unwrap();
        sqlx::query("CREATE UNIQUE INDEX tmp_unique_scope ON oauth_tokens(scope)")
            .execute(&pool)
            .await
            .unwrap();

        let mut tx = pool.begin().await.unwrap();
        assert!(take_code_with(&mut *tx, "codehash", now()).await.unwrap().is_some());
        assert!(
            insert_token_with(&mut *tx, "acc2", None, "wcl_x", "run", now() + 3600, None)
                .await
                .is_err()
        );
        drop(tx);
        sqlx::query("DROP INDEX tmp_unique_scope").execute(&pool).await.unwrap();

        // The code was not burned, so the client can retry the exchange instead of restarting consent.
        assert!(take_code(&pool, "codehash", now()).await.unwrap().is_some());
    }
}
