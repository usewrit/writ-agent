//! Store layer for the `crawl_definitions` table (0024_crawl_definitions.sql) — a SAVED,
//! re-runnable crawl configuration with a stable handle.
//!
//! A [`super::crawl_jobs::CrawlJob`] is one RUN: its settings live on the row and its id dies with
//! that run, so a crawl had no stable identity to expose as a callable API and "re-crawl with the
//! same settings" meant refilling a form. A definition owns the settings, carries a slug, and every
//! run it launches points back at it (`crawl_jobs.definition_id`) — so runs become its history.
//!
//! That history is what makes `max_age` answerable: [`find_fresh_run`] asks "has this saved crawl
//! completed recently enough that the caller can just have the data?"
//!
//! Runtime-checked sqlx only. `config` is JSON-TEXT (callers serde it); timestamps are TEXT RFC3339
//! UTC (matches 0008_concierge_sessions.sql). No tenant/user columns — local scope.

use super::super::error::{LocalError, LocalResult};
use super::crawl_jobs::CrawlJob;
use sqlx::sqlite::SqlitePool;
use sqlx::Row as _;

/// Cap an echoed freshness window at 30 days: beyond that "reuse" stops meaning "recent" and starts
/// meaning "never crawl again", which is a footgun dressed as an optimization.
pub const MAX_FRESHNESS_SECONDS: i64 = 30 * 24 * 3600;

/// A full `crawl_definitions` row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct CrawlDefinition {
    pub id: i64,
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub description: Option<String>,
    /// JSON-TEXT: the saved crawl-start body.
    pub config: String,
    pub seed_url: String,
    #[serde(default)]
    pub default_max_age_seconds: Option<i64>,
    pub created_at: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub last_run_at: Option<String>,
}

/// Caller-supplied fields to save a crawl.
#[derive(Debug, Clone, Default)]
pub struct NewCrawlDefinition {
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    /// JSON-TEXT, already serialized by the caller.
    pub config: String,
    pub seed_url: String,
    pub default_max_age_seconds: Option<i64>,
}

const SELECT_COLS: &str = "id, name, slug, description, config, seed_url,
    default_max_age_seconds, created_at, updated_at, last_run_at";

/// URL-safe slug body. Empty input yields an empty string so callers can fall back.
pub fn slugify(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = true;
    for ch in value.trim().to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out.chars().take(100).collect()
}

/// A slug not already taken. Collisions get a numeric suffix rather than an error: two saved crawls
/// of the same site is a reasonable thing to want, and failing the save over a name clash would be
/// hostile.
pub async fn mint_slug(pool: &SqlitePool, desired: &str) -> LocalResult<String> {
    let base = {
        let s = slugify(desired);
        if s.is_empty() {
            "crawl".to_string()
        } else {
            s
        }
    };
    let mut candidate = base.clone();
    for attempt in 2..200 {
        let taken: Option<i64> = sqlx::query("SELECT id FROM crawl_definitions WHERE slug = ?1")
            .bind(&candidate)
            .fetch_optional(pool)
            .await?
            .map(|r| r.try_get(0))
            .transpose()?;
        if taken.is_none() {
            return Ok(candidate);
        }
        candidate = format!("{base}-{attempt}");
    }
    Err(LocalError::Internal(
        "could not mint a unique crawl slug after 200 attempts".into(),
    ))
}

/// Save a crawl configuration. Returns the full row.
pub async fn insert(
    pool: &SqlitePool,
    new: &NewCrawlDefinition,
) -> LocalResult<CrawlDefinition> {
    let id: i64 = sqlx::query(
        r#"
        INSERT INTO crawl_definitions
            (name, slug, description, config, seed_url, default_max_age_seconds)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        RETURNING id
        "#,
    )
    .bind(&new.name)
    .bind(&new.slug)
    .bind(new.description.as_deref())
    .bind(&new.config)
    .bind(&new.seed_url)
    .bind(new.default_max_age_seconds)
    .fetch_one(pool)
    .await?
    .try_get(0)?;

    tracing::info!(definition_id = id, slug = %new.slug, "saved crawl created");
    get_by_id(pool, id)
        .await?
        .ok_or_else(|| LocalError::Internal("crawl_definition vanished after insert".into()))
}

/// Fetch one saved crawl by id.
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> LocalResult<Option<CrawlDefinition>> {
    Ok(
        sqlx::query_as::<_, CrawlDefinition>(&format!(
            "SELECT {SELECT_COLS} FROM crawl_definitions WHERE id = ?1"
        ))
        .bind(id)
        .fetch_optional(pool)
        .await?,
    )
}

/// Fetch one saved crawl by slug.
pub async fn get_by_slug(pool: &SqlitePool, slug: &str) -> LocalResult<Option<CrawlDefinition>> {
    Ok(
        sqlx::query_as::<_, CrawlDefinition>(&format!(
            "SELECT {SELECT_COLS} FROM crawl_definitions WHERE slug = ?1"
        ))
        .bind(slug)
        .fetch_optional(pool)
        .await?,
    )
}

/// Resolve a caller-supplied ref: a numeric id, a slug, or an exact name.
///
/// Accepting all three is what lets an AI agent pass whatever it has on hand — it usually knows the
/// human name, not the slug — without a lookup round-trip.
pub async fn resolve(pool: &SqlitePool, reference: &str) -> LocalResult<Option<CrawlDefinition>> {
    if let Ok(id) = reference.parse::<i64>() {
        if let Some(found) = get_by_id(pool, id).await? {
            return Ok(Some(found));
        }
    }
    if let Some(found) = get_by_slug(pool, reference).await? {
        return Ok(Some(found));
    }
    Ok(
        sqlx::query_as::<_, CrawlDefinition>(&format!(
            "SELECT {SELECT_COLS} FROM crawl_definitions WHERE name = ?1 ORDER BY id LIMIT 1"
        ))
        .bind(reference)
        .fetch_optional(pool)
        .await?,
    )
}

/// List saved crawls newest-first, capped at `limit`.
pub async fn list(pool: &SqlitePool, limit: i64) -> LocalResult<Vec<CrawlDefinition>> {
    let limit = limit.clamp(1, 1000);
    Ok(
        sqlx::query_as::<_, CrawlDefinition>(&format!(
            "SELECT {SELECT_COLS} FROM crawl_definitions ORDER BY created_at DESC, id DESC LIMIT ?1"
        ))
        .bind(limit)
        .fetch_all(pool)
        .await?,
    )
}

/// Replace the saved settings (and the mirrored seed url).
pub async fn update_config(
    pool: &SqlitePool,
    id: i64,
    config: &str,
    seed_url: &str,
) -> LocalResult<()> {
    sqlx::query(
        "UPDATE crawl_definitions SET config = ?2, seed_url = ?3,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
    )
    .bind(id)
    .bind(config)
    .bind(seed_url)
    .execute(pool)
    .await?;
    Ok(())
}

/// Patch the presentation/freshness fields. `None` leaves a field untouched.
pub async fn update_meta(
    pool: &SqlitePool,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
    default_max_age_seconds: Option<i64>,
) -> LocalResult<()> {
    sqlx::query(
        "UPDATE crawl_definitions SET
            name = COALESCE(?2, name),
            description = COALESCE(?3, description),
            default_max_age_seconds = COALESCE(?4, default_max_age_seconds),
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ?1",
    )
    .bind(id)
    .bind(name)
    .bind(description)
    .bind(default_max_age_seconds)
    .execute(pool)
    .await?;
    Ok(())
}

/// Stamp the last dispatch time.
pub async fn touch_last_run(pool: &SqlitePool, id: i64) -> LocalResult<()> {
    sqlx::query(
        "UPDATE crawl_definitions SET last_run_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?1",
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Delete a saved crawl. Returns true if a row was removed.
///
/// The runs it launched are deliberately left in place — their collected data outlives the config.
/// `crawl_jobs.definition_id` simply stops resolving, which reads as "ad-hoc", exactly like every
/// crawl started straight from the wizard.
pub async fn delete(pool: &SqlitePool, id: i64) -> LocalResult<bool> {
    let res = sqlx::query("DELETE FROM crawl_definitions WHERE id = ?1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Bind a run to the definition that launched it.
pub async fn attach_run(pool: &SqlitePool, crawl_id: i64, definition_id: i64) -> LocalResult<()> {
    sqlx::query("UPDATE crawl_jobs SET definition_id = ?2 WHERE id = ?1")
        .bind(crawl_id)
        .bind(definition_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// The newest REUSABLE run for a definition, or `None`.
///
/// Reusable means all of:
///
/// * `status = 'completed'` — a failed or cancelled crawl is not data you already have.
/// * finished within `max_age_seconds`.
/// * `pages_done > 0` — a crawl that converged having fetched nothing is not a result worth serving
///   for the next N hours. That is exactly the shape a fully-blocked host produces (every page 403s,
///   the crawl still completes), and pinning that empty answer behind a long `max_age` would turn one
///   bad crawl into a day of silently empty responses.
///
/// `max_age_seconds <= 0` always returns `None` — that is the caller saying "run it fresh".
pub async fn find_fresh_run(
    pool: &SqlitePool,
    definition_id: i64,
    max_age_seconds: i64,
) -> LocalResult<Option<CrawlJob>> {
    if max_age_seconds <= 0 {
        return Ok(None);
    }
    // Compared in SQL against SQLite's own clock so this does not depend on the host's timezone
    // handling: completed_at is TEXT RFC3339 UTC and julianday() parses it directly.
    let row = sqlx::query_as::<_, CrawlJob>(&format!(
        "SELECT {cols} FROM crawl_jobs
          WHERE definition_id = ?1
            AND status = 'completed'
            AND completed_at IS NOT NULL
            AND pages_done > 0
            AND (julianday('now') - julianday(completed_at)) * 86400.0 <= ?2
          ORDER BY completed_at DESC, id DESC
          LIMIT 1",
        cols = super::crawl_jobs::select_cols(),
    ))
    .bind(definition_id)
    .bind(max_age_seconds as f64)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Seconds since a crawl finished, or `None` when it has no completion stamp.
pub async fn run_age_seconds(pool: &SqlitePool, crawl_id: i64) -> LocalResult<Option<f64>> {
    let age: Option<f64> = sqlx::query(
        "SELECT (julianday('now') - julianday(completed_at)) * 86400.0
           FROM crawl_jobs WHERE id = ?1 AND completed_at IS NOT NULL",
    )
    .bind(crawl_id)
    .fetch_optional(pool)
    .await?
    .map(|r| r.try_get(0))
    .transpose()?;
    Ok(age.map(|a| a.max(0.0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugify_produces_url_safe_refs() {
        assert_eq!(slugify("Docs — example.com"), "docs-example-com");
        assert_eq!(slugify("  Multiple   Spaces  "), "multiple-spaces");
        assert_eq!(slugify("!!!"), "");
        assert_eq!(slugify("Already-slugged"), "already-slugged");
    }

    #[test]
    fn slugify_caps_length() {
        assert!(slugify(&"a".repeat(300)).len() <= 100);
    }
}
