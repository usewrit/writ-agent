//! Native marketplace — DAEMON Stage 2 (the protected local executor).
//!
//! Makes the cloud Marketplace fully NATIVE in the desktop app when an account is linked:
//!   * **BROWSE** — thin authenticated passthroughs to the cloud `/api/marketplace/*` listing /
//!     detail / category / collection / creator / reviews surfaces, carried by [`CloudClient`] (the
//!     `wto_` account token, auto-refreshing on 401). The webview never sees the token.
//!   * **INSTALL** — calls the cloud install endpoint (which creates the consumer-owned PROXY
//!     workflow exactly as today), then fetches the install's FROZEN recipe SEALED with THIS agent's
//!     per-agent Fernet channel key, and persists ONLY the sealed blob (vault-wrapped on top) in the
//!     encrypted `installed_workflows` table. The PLAINTEXT recipe is NEVER persisted / returned /
//!     logged.
//!   * **RUN** — the PROTECTED EXECUTOR. For a PAID listing it MUST first authorize a metered run
//!     cloud-side (wallet held); if not authorized it does NOT run. It then unseals the recipe IN
//!     MEMORY (vault → channel_key Fernet), runs it on the LOCAL engine with the CONSUMER's own data
//!     (BYO: their personas/secrets/inputs), and — for a paid listing — reports the actual duration
//!     back to FINALIZE the charge. The plaintext recipe is discarded when the run returns.
//!
//! SECURITY (the never-trust-a-BYO-agent rule + marketplace protected-executor invariants):
//!  1. Only the SEALED blob is persisted (`installed_workflows.sealed_recipe`); the plaintext recipe
//!     lives only in the in-memory [`workflows::Workflow`] the executor builds, and is never written
//!     to the DB / returned over any local API / logged.
//!  2. `channel_key` + `wto_` stay daemon-side: the webview hits the loopback `/v1/cloud/marketplace/*`
//!     routes with the `wlt_` bearer only; this module attaches the `wto_` via [`CloudClient`] and
//!     unseals with the keyring channel key.
//!  3. BILLING AUTHORITY IS THE CLOUD. A paid run is gated by `authorize-run` BEFORE execution and
//!     reconciled by `finalize` AFTER — the agent never decides what is owed (the agent is untrusted).
//!  4. BYO: the executed recipe carries NO credential VALUES (`credentials_encrypted = None`,
//!     `default_persona_id = None`); resolution pulls the CONSUMER's own vault secrets / inputs only.
//!
//! Net-new Rust in this crate, behind the `local` cargo feature.

use serde_json::{json, Value};
use sqlx::sqlite::SqlitePool;
use std::collections::{HashMap, HashSet};

use super::super::error::{LocalError, LocalResult};
use super::super::store::installed_workflows::{self, NewInstall};
use super::super::store::workflows;
use super::super::vault::Vault;
use super::channel;
use super::client::CloudClient;
use super::state::LinkState;

// --------------------------------------------------------------------------------------------
// Cloud marketplace paths (backend `marketplace_router` is mounted under `/api/marketplace`).
// CloudClient joins these onto the resolved cloud base url (no trailing slash).
// --------------------------------------------------------------------------------------------

const MP_LISTINGS: &str = "/api/marketplace/listings";
const MP_CATEGORIES: &str = "/api/marketplace/categories";
const MP_COLLECTIONS: &str = "/api/marketplace/collections";
const MP_CREATORS: &str = "/api/marketplace/creators";

/// Build the cloud install path for a listing slug.
fn install_path(slug: &str) -> String {
    format!("{MP_LISTINGS}/{slug}/install")
}

/// Build the cloud sealed-recipe path for an installed listing slug.
fn sealed_recipe_path(slug: &str) -> String {
    format!("/api/marketplace/installs/{slug}/sealed-recipe")
}

/// Build the cloud uninstall path for a listing slug (`DELETE` releases the install grant).
fn uninstall_path(slug: &str) -> String {
    format!("{MP_LISTINGS}/{}/install", encode_segment(slug))
}

/// Build the cloud authorize-run path for an installed listing slug.
fn authorize_run_path(slug: &str) -> String {
    format!("/api/marketplace/installs/{slug}/authorize-run")
}

/// Build the cloud finalize path for an installed listing slug + run id.
fn finalize_path(slug: &str, run_id: &str) -> String {
    format!("/api/marketplace/installs/{slug}/runs/{run_id}/finalize")
}

/// AAD binding the locally-stored sealed recipe to its install row (Layer-B vault field wrap on top
/// of the channel_key Fernet seal). Mirrors the `table|column|row_key` convention used elsewhere
/// (`workflows::credentials_aad`, `vault.rs` tests). Keyed on the natural key (slug) since the row id
/// isn't known until after insert and an upsert keeps the same slug.
fn sealed_recipe_aad(slug: &str) -> String {
    format!("installed_workflows|sealed_recipe|{slug}")
}

// --------------------------------------------------------------------------------------------
// BROWSE — authenticated passthroughs
// --------------------------------------------------------------------------------------------

/// Open an authenticated cloud client for the current link, or a clean `Unauthorized` when the
/// desktop is not linked (no panic, no partial work). Every marketplace call funnels through here so
/// the `wto_` token is loaded once from the keyring and never leaves the daemon.
async fn client(db: &SqlitePool) -> LocalResult<CloudClient> {
    let link = LinkState::load_or_default(db).await?;
    CloudClient::connect(Some(&link))
}

/// `GET /api/marketplace/listings` (browse grid). `query` is the raw query string the UI passed
/// (search / category / collection / sort / pagination) WITHOUT a leading `?`; it is appended
/// verbatim so the cloud owns the filter semantics. Empty → no query string.
pub async fn list_listings(db: &SqlitePool, query: &str) -> LocalResult<Value> {
    let path = append_query(MP_LISTINGS, query);
    client(db).await?.get_json(&path).await
}

/// `GET /api/marketplace/listings/{slug}` (listing detail). `slug` is path-segment-encoded so a
/// hostile slug can't escape the path.
pub async fn get_listing(db: &SqlitePool, slug: &str) -> LocalResult<Value> {
    let path = format!("{MP_LISTINGS}/{}", encode_segment(slug));
    client(db).await?.get_json(&path).await
}

/// `GET /api/marketplace/listings/{slug}/reviews` (read-only reviews).
pub async fn get_reviews(db: &SqlitePool, slug: &str, query: &str) -> LocalResult<Value> {
    let base = format!("{MP_LISTINGS}/{}/reviews", encode_segment(slug));
    let path = append_query(&base, query);
    client(db).await?.get_json(&path).await
}

/// `GET /api/marketplace/categories`.
pub async fn list_categories(db: &SqlitePool) -> LocalResult<Value> {
    client(db).await?.get_json(MP_CATEGORIES).await
}

/// `GET /api/marketplace/collections`.
pub async fn list_collections(db: &SqlitePool) -> LocalResult<Value> {
    client(db).await?.get_json(MP_COLLECTIONS).await
}

/// `GET /api/marketplace/creators`.
pub async fn list_creators(db: &SqlitePool) -> LocalResult<Value> {
    client(db).await?.get_json(MP_CREATORS).await
}

// --------------------------------------------------------------------------------------------
// SEARCH — advanced multi-query candidate search (backs the MCP `writ_search_api` tool)
// --------------------------------------------------------------------------------------------

/// Advanced "find me an API that does X" search over the cloud marketplace.
///
/// The cloud's `/api/marketplace/listings?q=` text search is a plain title/summary/keywords match,
/// so a multi-word natural-language need can miss listings that match only one distinctive term.
/// This fans out SEVERAL targeted queries concurrently — the full text, each distinctive keyword,
/// and the target site when one is given or detected in the query — merges the returned cards by
/// slug, re-scores every candidate locally against the whole query (relevance + marketplace quality
/// signals), marks the ones already installed on this machine, and returns the top `limit`
/// candidates best-first.
///
/// Per-query failures are tolerated (a partial sweep is better than none); only a fully-failed
/// sweep surfaces an error, and it is the FIRST error so an expired session reads as Unauthorized
/// rather than a generic failure. Result is metadata-only card fields — never recipes/steps.
pub async fn search_api(
    db: &SqlitePool,
    query: &str,
    site: Option<&str>,
    category: Option<&str>,
    limit: usize,
) -> LocalResult<Value> {
    let terms = tokenize_query(query);
    let site_owned = site.map(str::to_string).or_else(|| detect_site(query));
    let site = site_owned.as_deref();

    // Fan-out query strings. sort=rank is the marketplace's competitive default; the category
    // filter (when given) applies to every sub-query since it narrows, never redirects.
    let mut suffix = String::from("&sort=rank&limit=25");
    if let Some(c) = category.map(str::trim).filter(|c| !c.is_empty()) {
        suffix.push_str(&format!("&category={}", encode_segment(c)));
    }
    let mut queries: Vec<String> = vec![format!("q={}{suffix}", encode_segment(query))];
    for term in terms.iter().take(3) {
        if !term.eq_ignore_ascii_case(query.trim()) {
            queries.push(format!("q={}{suffix}", encode_segment(term)));
        }
    }
    if let Some(s) = site {
        queries.push(format!("target_site={}{suffix}", encode_segment(s)));
    }

    // Run every sub-query concurrently, each on its own authenticated client (the verbs take
    // `&mut self` for the 401-refresh path, so clients aren't shared across futures).
    let futs = queries.iter().map(|qs| {
        let db = db.clone();
        let path = append_query(MP_LISTINGS, qs);
        async move { client(&db).await?.get_json::<Value>(&path).await }
    });
    let results = futures_util::future::join_all(futs).await;
    let mut responses: Vec<Value> = Vec::new();
    let mut first_err: Option<LocalError> = None;
    for r in results {
        match r {
            Ok(v) => responses.push(v),
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    if responses.is_empty() {
        return Err(first_err
            .unwrap_or_else(|| LocalError::Internal("marketplace search returned nothing".into())));
    }

    // Merge cards by slug, keeping each candidate's best score across the sub-queries.
    let mut merged: HashMap<String, (f64, Vec<String>, Value)> = HashMap::new();
    for resp in &responses {
        for card in extract_listings(resp) {
            let Some(slug) = card.get("slug").and_then(Value::as_str) else {
                continue;
            };
            let (score, matched) = score_listing(&card, &terms, site);
            let better = merged.get(slug).map_or(true, |(best, _, _)| score > *best);
            if better {
                merged.insert(slug.to_string(), (score, matched, card));
            }
        }
    }

    // Mark listings already installed on this machine (local metadata only).
    let installed: HashSet<String> = installed_workflows::list(db)
        .await?
        .into_iter()
        .map(|m| m.slug)
        .collect();

    let mut scored: Vec<(f64, Vec<String>, Value)> = merged.into_values().collect();
    scored.sort_by(|a, b| {
        b.0.partial_cmp(&a.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                i64_field(&b.2, &["install_count"])
                    .unwrap_or(0)
                    .cmp(&i64_field(&a.2, &["install_count"]).unwrap_or(0))
            })
    });
    let total_considered = scored.len();
    let candidates: Vec<Value> = scored
        .into_iter()
        .take(limit.clamp(1, 10))
        .map(|(score, matched, card)| candidate_json(&card, score, &matched, &installed))
        .collect();

    Ok(json!({
        "query": query,
        "terms": terms,
        "site": site,
        "total_considered": total_considered,
        "candidates": candidates,
    }))
}

/// The listings array of a browse response (`{"listings":[...]}` today; array/`items`/`results`
/// tolerated so a cloud reshape degrades to "fewer results", never a parse failure).
fn extract_listings(resp: &Value) -> Vec<Value> {
    if let Some(arr) = resp.as_array() {
        return arr.clone();
    }
    for k in ["listings", "items", "results"] {
        if let Some(arr) = resp.get(k).and_then(Value::as_array) {
            return arr.clone();
        }
    }
    Vec::new()
}

/// Distinctive lowercase search terms of a natural-language query: alnum/dot/hyphen tokens, ≥3
/// chars, minus common EN/FR stopwords (and "api" itself — every listing is one), capped at 6,
/// first-seen order. Dots are kept inside tokens so a domain stays one term.
fn tokenize_query(query: &str) -> Vec<String> {
    const STOPWORDS: [&str; 34] = [
        "the", "and", "for", "that", "this", "with", "from", "into", "need", "want", "find",
        "get", "search", "any", "all", "api", "apis", "web", "site", "website", "les", "des",
        "une", "qui", "que", "avec", "pour", "dans", "sur", "est", "veux", "donne", "cherche",
        "trouve",
    ];
    let mut out: Vec<String> = Vec::new();
    for raw in query.split(|c: char| !(c.is_alphanumeric() || c == '.' || c == '-')) {
        let t = raw.trim_matches(|c| c == '.' || c == '-').to_lowercase();
        if t.len() < 3 || STOPWORDS.contains(&t.as_str()) || out.contains(&t) {
            continue;
        }
        out.push(t);
        if out.len() == 6 {
            break;
        }
    }
    out
}

/// Best-effort target-site detection inside a free-text query: a URL's host, or a bare
/// `name.tld`-looking token. Lowercased, `www.` stripped. `None` when nothing domain-shaped.
fn detect_site(query: &str) -> Option<String> {
    for raw in query.split_whitespace() {
        let t = raw.trim_matches(|c: char| !(c.is_alphanumeric() || c == '.' || c == '-' || c == '/' || c == ':'));
        let host = if let Some((_, rest)) = t.split_once("://") {
            rest.split('/').next().unwrap_or("")
        } else if t.contains('.')
            && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            t
        } else {
            continue;
        };
        let host = host.trim_start_matches("www.").trim_matches('.').to_lowercase();
        if let Some((name, tld)) = host.rsplit_once('.') {
            if !name.is_empty() && tld.len() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic()) {
                return Some(host);
            }
        }
    }
    None
}

/// Score one listing card against the query terms: term coverage over the card's text fields
/// dominates; a target-site match is a strong boost; marketplace quality signals (rating, installs,
/// attested success rate) are small nudges so relevance always wins. Returns the score plus which
/// terms matched (the "why" shown to the user).
fn score_listing(card: &Value, terms: &[String], site: Option<&str>) -> (f64, Vec<String>) {
    let title = lower_field(card, "title");
    let haystacks: [String; 8] = [
        title.clone(),
        lower_field(card, "summary"),
        lower_field(card, "category"),
        lower_field(card, "capability_key"),
        lower_field(card, "intent"),
        lower_field(card, "target_domain"),
        lower_array(card, "keywords"),
        lower_array(card, "tags"),
    ];
    let mut matched: Vec<String> = Vec::new();
    let mut title_hits = 0usize;
    for term in terms {
        if haystacks.iter().any(|h| h.contains(term.as_str())) {
            matched.push(term.clone());
            if title.contains(term.as_str()) {
                title_hits += 1;
            }
        }
    }
    let coverage = if terms.is_empty() {
        0.0
    } else {
        matched.len() as f64 / terms.len() as f64
    };
    let mut score = coverage * 3.0 + (title_hits as f64 * 0.5).min(1.5);
    if let Some(site) = site.map(str::to_lowercase).filter(|s| !s.is_empty()) {
        let dom = lower_field(card, "target_domain");
        if !dom.is_empty() && (dom.contains(&site) || site.contains(&dom)) {
            score += 2.0;
        }
    }
    if let Some(r) = card.get("rating_avg").and_then(Value::as_f64) {
        score += (r / 5.0).clamp(0.0, 1.0) * 0.5;
    }
    if let Some(n) = i64_field(card, &["install_count"]) {
        score += ((1.0 + n.max(0) as f64).ln() * 0.15).min(0.75);
    }
    if let Some(sr) = card.pointer("/metrics/success_rate").and_then(Value::as_f64) {
        score += sr.clamp(0.0, 1.0) * 0.5;
    }
    (score, matched)
}

/// Project one merged card into the candidate shape the MCP tool returns to the model. Metadata
/// only — pricing/rating/creator so the user can choose, never recipe internals.
fn candidate_json(card: &Value, score: f64, matched: &[String], installed: &HashSet<String>) -> Value {
    let slug = card.get("slug").and_then(Value::as_str).unwrap_or_default();
    let pricing_model = card
        .get("pricing_model")
        .and_then(Value::as_str)
        .unwrap_or("free");
    let price = i64_field(
        card,
        &["price_per_success_micros", "price_micros", "price_run_micros"],
    );
    let is_free = pricing_model.eq_ignore_ascii_case("free") || price.map_or(false, |p| p <= 0);
    let summary = card
        .get("summary")
        .and_then(Value::as_str)
        .map(|s| {
            if s.chars().count() > 240 {
                let cut: String = s.chars().take(240).collect();
                format!("{cut}…")
            } else {
                s.to_string()
            }
        });
    json!({
        "slug": slug,
        "title": card.get("title").cloned().unwrap_or(Value::Null),
        "summary": summary,
        "category": card.get("category").cloned().unwrap_or(Value::Null),
        "target_site": card.get("target_domain").cloned().unwrap_or(Value::Null),
        "intent": card.get("intent").cloned().unwrap_or(Value::Null),
        "asset_type": card.get("asset_type").cloned().unwrap_or(Value::Null),
        "pricing": {
            "model": pricing_model,
            "is_free": is_free,
            "price_per_success_micros": price,
            "estimated_price_micros": card.get("estimated_price_micros").cloned().unwrap_or(Value::Null),
        },
        "rating": {
            "avg": card.get("rating_avg").cloned().unwrap_or(Value::Null),
            "count": card.get("rating_count").cloned().unwrap_or(Value::Null),
        },
        "installs": card.get("install_count").cloned().unwrap_or(Value::Null),
        "success_rate": card.pointer("/metrics/success_rate").cloned().unwrap_or(Value::Null),
        "creator": creator_name(card).map(Value::String).unwrap_or(Value::Null),
        "installed": installed.contains(slug),
        "score": (score * 100.0).round() / 100.0,
        "matched_terms": matched,
    })
}

/// Lowercased string field, or empty when absent/non-string.
fn lower_field(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .map(str::to_lowercase)
        .unwrap_or_default()
}

/// Lowercased space-joined string array field, or empty when absent.
fn lower_array(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_lowercase)
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

// --------------------------------------------------------------------------------------------
// CONSUMER BINDINGS (0017) — the buyer's saved attachment choices for a listing's BYO slots
// --------------------------------------------------------------------------------------------

/// The consumer's persisted attachment choices for an install, stored as JSON in
/// `installed_workflows.bindings`. NAMES/IDS ONLY for secrets/personas — the secret VALUES stay in
/// the `vault_secrets`/`personas` ciphertext stores; `inputs` holds NON-secret run-input defaults so
/// scheduled/background proxy runs resolve without re-asking.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct InstallBindings {
    /// Manifest secret-slot key → LOCAL vault secret KEY NAME the consumer picked for it.
    pub secrets: HashMap<String, String>,
    /// The consumer's own persona to use for the listing's persona slot(s).
    pub persona_id: Option<i64>,
    /// The consumer explicitly chose to run WITHOUT a persona (don't re-ask).
    pub persona_none: bool,
    /// Saved NON-secret input defaults; per-run caller inputs override key-by-key.
    pub inputs: serde_json::Map<String, Value>,
}

impl InstallBindings {
    /// Parse the stored JSON, degrading to defaults on absent/corrupt text (never blocks a run).
    pub fn parse(raw: Option<&str>) -> Self {
        raw.and_then(|s| serde_json::from_str(s).ok()).unwrap_or_default()
    }

    /// Serialize for [`installed_workflows::set_bindings`].
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".into())
    }
}

/// Rename `{{secret:SLOT}}` / `{{vault:SLOT}}` references (incl. the dotted `SLOT.field` form) to
/// the consumer's chosen vault KEY, in the recipe's steps TEXT. A NAMES-ONLY token rename — no
/// secret value is ever substituted (mirrors the engine's `vault:`→`secret:` normalization).
pub(crate) fn rename_secret_refs(text: &str, bindings: &HashMap<String, String>) -> String {
    let mut out = text.to_string();
    for (slot, key) in bindings {
        if slot == key || slot.is_empty() || key.is_empty() {
            continue;
        }
        for ns in ["secret", "vault"] {
            out = out.replace(&format!("{{{{{ns}:{slot}}}}}"), &format!("{{{{secret:{key}}}}}"));
            out = out.replace(&format!("{{{{{ns}:{slot}."), &format!("{{{{secret:{key}."));
        }
    }
    out
}

/// Normalize a manifest slot array (`input_slots` / `secret_slots` / `persona_slots`) into the
/// stable `{key, label, ...}` objects the desktop Run modal renders. Manifests from different
/// backend versions key the slot name as `key`, `name`, or (persona) `slot` — collapse them here so
/// the UI never re-implements the tolerance. NAMES/TYPES ONLY — a manifest is data-less by
/// construction, and nothing else is copied through except the listed presentation extras.
fn normalized_slots(manifest: &Value, field: &str) -> Vec<Value> {
    manifest
        .get(field)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|slot| {
            let key = ["key", "name", "slot"].iter().find_map(|k| {
                slot.get(*k)
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            })?;
            let label = slot
                .get("label")
                .and_then(Value::as_str)
                .filter(|l| !l.is_empty())
                .unwrap_or(key);
            let mut out = json!({ "key": key, "label": label });
            for extra in ["required", "target_domain", "twofa", "type", "field_type"] {
                if let Some(v) = slot.get(extra).filter(|v| !v.is_null()) {
                    out[extra] = v.clone();
                }
            }
            Some(out)
        })
        .collect()
}

/// The NAMES-ONLY "attach" projection for an install: the listing's BYO manifest slots + the
/// consumer's current bindings. This is what the desktop Run modal renders for a PROXY workflow row
/// (its own `steps` are `[]`, so the regular placeholder scan finds nothing) — the loopback twin of
/// the MCP `marketplace_needs_input` elicitation. Secret VALUES never appear (the bindings carry
/// vault KEY NAMES; the pickable key/persona options come from the UI's own `/v1/secrets` /
/// `/v1/personas` surfaces). `None` = no install row (the proxy is orphaned — reinstall).
pub async fn attach_state(db: &SqlitePool, slug: &str) -> LocalResult<Option<Value>> {
    let Some(install) = installed_workflows::get_by_slug(db, slug).await? else {
        return Ok(None);
    };
    let manifest = install
        .input_schema
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| json!({}));
    let bindings = InstallBindings::parse(install.bindings.as_deref());
    let persona_slots = normalized_slots(&manifest, "persona_slots");
    Ok(Some(json!({
        "slug": install.slug,
        "listing_title": install.listing_title,
        "is_free": install.is_free,
        "manifest": {
            "input_slots": normalized_slots(&manifest, "input_slots"),
            "secret_slots": normalized_slots(&manifest, "secret_slots"),
            "persona_slots": persona_slots,
            "has_login": manifest
                .get("has_login")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        },
        "bindings": {
            "secrets": bindings.secrets,
            "persona_id": bindings.persona_id,
            "persona_none": bindings.persona_none,
            "inputs": bindings.inputs,
        },
    })))
}

/// Persist binding PICKS from the loopback UI (the desktop Run modal's attach section) — the HTTP
/// twin of the MCP elicitation's selection args, with the SAME validation rules:
///   * `secrets: {slot: key}` — `slot` must be a manifest secret slot; `key` must be an existing
///     LOCAL vault secret KEY NAME (values never transit); `null` unbinds the slot;
///   * `persona: <id> | "none" | null` — an existing persona's id, an explicit "run without", or
///     `null` to clear the choice (re-ask);
///   * `inputs: {key: value}` — NON-secret run-input defaults; `null` removes a saved default.
/// Merge semantics over the stored bindings; scheduled/background proxy runs resolve them via the
/// engine intercept exactly like MCP-made picks. Returns the updated bindings.
pub async fn apply_bindings(
    db: &SqlitePool,
    slug: &str,
    picks: &Value,
) -> LocalResult<InstallBindings> {
    use crate::local::store::{personas, vault_secrets};

    let install = installed_workflows::get_by_slug(db, slug)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("installed workflow {slug}")))?;
    let manifest = install
        .input_schema
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok())
        .unwrap_or_else(|| json!({}));
    let mut bindings = InstallBindings::parse(install.bindings.as_deref());

    if let Some(Value::Object(secret_picks)) = picks.get("secrets") {
        let slots: HashSet<String> = normalized_slots(&manifest, "secret_slots")
            .iter()
            .filter_map(|s| s.get("key").and_then(Value::as_str).map(str::to_string))
            .collect();
        for (slot, key) in secret_picks {
            if !slots.contains(slot) {
                return Err(LocalError::BadRequest(format!(
                    "'{slot}' is not a secret slot of this listing"
                )));
            }
            match key {
                Value::Null => {
                    bindings.secrets.remove(slot);
                }
                Value::String(key) if !key.trim().is_empty() => {
                    let key = key.trim();
                    if vault_secrets::get_by_key(db, key).await?.is_none() {
                        return Err(LocalError::BadRequest(format!(
                            "no vault secret named '{key}' — add it in the Vault first"
                        )));
                    }
                    bindings.secrets.insert(slot.clone(), key.to_string());
                }
                _ => {
                    return Err(LocalError::BadRequest(
                        "secret picks must map slot -> vault key name (or null to unbind)".into(),
                    ))
                }
            }
        }
    }

    match picks.get("persona") {
        None => {}
        Some(Value::Null) => {
            bindings.persona_id = None;
            bindings.persona_none = false;
        }
        Some(Value::String(s)) if s.eq_ignore_ascii_case("none") => {
            bindings.persona_id = None;
            bindings.persona_none = true;
        }
        Some(p) => {
            let id = p
                .as_i64()
                .ok_or_else(|| {
                    LocalError::BadRequest("'persona' must be a persona id, \"none\", or null".into())
                })?;
            if personas::get_by_id(db, id).await?.is_none() {
                return Err(LocalError::BadRequest(format!("no persona with id {id}")));
            }
            bindings.persona_id = Some(id);
            bindings.persona_none = false;
        }
    }

    if let Some(Value::Object(inputs)) = picks.get("inputs") {
        for (k, v) in inputs {
            if v.is_null() {
                bindings.inputs.remove(k);
            } else {
                bindings.inputs.insert(k.clone(), v.clone());
            }
        }
    }

    installed_workflows::set_bindings(db, slug, Some(&bindings.to_json())).await?;
    Ok(bindings)
}

// --------------------------------------------------------------------------------------------
// PROXY WORKFLOW (0017) — the install's callable face in the regular workflow surface
// --------------------------------------------------------------------------------------------

/// Ensure the installed listing has a local PROXY `workflows` row (cloud parity with the cloud's
/// consumer-tenant proxy AutomationWorkflow): callable right after install via the regular run
/// paths — derived MCP tool, `writ_run_workflow`, REST run, schedules, automations. The row's own
/// `steps` stay `[]`; the ENGINE swaps in the unsealed sealed-recipe at run time. Idempotent —
/// an existing proxy row is returned as-is (also lazily heals pre-0017 installs on first run).
pub async fn ensure_proxy_workflow(
    db: &SqlitePool,
    slug: &str,
    title: Option<&str>,
) -> LocalResult<workflows::Workflow> {
    if let Some(existing) = workflows::get_by_marketplace_slug(db, slug).await? {
        return Ok(existing);
    }
    let wf = workflows::insert(
        db,
        &workflows::NewWorkflow {
            name: title.filter(|t| !t.trim().is_empty()).unwrap_or(slug).to_string(),
            description: Some(format!(
                "Installed marketplace API '{slug}'. Runs locally on the protected executor — the \
                 recipe stays sealed; paid runs are authorized and settled cloud-side."
            )),
            steps: Some("[]".into()),
            // EXPLICIT Connect surfaces (not the absent-key defaults): an installed marketplace
            // API is an API — exposed over MCP, local REST, and the OpenAI-compat endpoint from
            // the moment it lands, exactly like an api-recorded save. Explicit so a future
            // default flip can never silently hide an MCP-born workflow.
            streaming_config: Some(
                json!({"connect": {"rest": true, "openai": true, "mcp": true}}).to_string(),
            ),
            marketplace_slug: Some(slug.to_string()),
            ..Default::default()
        },
    )
    .await?;
    tracing::info!(slug, workflow_id = wf.id, "marketplace proxy workflow minted");
    Ok(wf)
}

// --------------------------------------------------------------------------------------------
// INSTALL
// --------------------------------------------------------------------------------------------

/// Result of [`install`] — the install SUMMARY the loopback API returns. NEVER carries the recipe /
/// sealed blob / steps; only metadata the UI needs to render the installed-item row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct InstallSummary {
    pub slug: String,
    pub is_free: bool,
    pub listing_title: Option<String>,
    pub creator: Option<String>,
    pub price_micros: Option<i64>,
    pub proxy_cloud_id: Option<String>,
    /// The LOCAL proxy `workflows` row minted for this install (0017) — the id the regular run
    /// surfaces (derived MCP tool, `writ_run_workflow`, schedules) dispatch on.
    pub local_workflow_id: Option<i64>,
}

/// INSTALL a marketplace listing natively:
///   1. POST the cloud install endpoint (creates the consumer-owned proxy workflow as today).
///   2. GET the install's FROZEN recipe SEALED with this agent's channel key.
///   3. Vault-wrap the sealed blob (Layer-B at rest) and UPSERT it into `installed_workflows`.
///
/// Returns the install SUMMARY (no recipe). The sealed blob is the ONLY representation of the recipe
/// persisted, and it is never returned to the caller.
///
/// SECURITY: the cloud `sealed-recipe` body MUST already be channel_key-Fernet ciphertext (the cloud
/// encrypts the frozen recipe for THIS agent). We never decrypt it at install time — we only wrap it
/// in the local vault field cipher and store it. The plaintext recipe is never present here.
pub async fn install(db: &SqlitePool, vault: &Vault, slug: &str) -> LocalResult<InstallSummary> {
    let mut client = client(db).await?;

    // 1) Cloud install — creates the proxy workflow + install grant for this tenant.
    let install_resp: Value = client.post_json(&install_path(slug), &json!({})).await?;
    let proxy_cloud_id = install_resp
        .get("proxy_workflow_id")
        .and_then(value_id_string)
        .or_else(|| install_resp.get("workflow_id").and_then(value_id_string));

    // 2) Fetch the channel_key-sealed frozen recipe for this install.
    let sealed_resp: Value = client.get_json(&sealed_recipe_path(slug)).await?;
    let sealed = sealed_resp
        .get("sealed")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| LocalError::Internal("sealed-recipe response missing 'sealed'".into()))?;

    // 3) Vault-wrap the (already channel_key-sealed) blob for a second layer at rest, then upsert.
    //    The blob is opaque ciphertext either way — we never decode it here.
    let wrapped = vault.seal_field(sealed.as_bytes(), &sealed_recipe_aad(slug))?;

    // Listing metadata for the UI comes from the listing detail (best-effort — an install must still
    // succeed if the detail fetch hiccups, so we degrade to the slug + the install response).
    let detail = client.get_json::<Value>(&format!("{MP_LISTINGS}/{}", encode_segment(slug))).await.ok();
    let is_free = resolve_is_free(detail.as_ref(), &install_resp);
    let listing_title = detail
        .as_ref()
        .and_then(|d| string_field(d, &["title", "name", "listing_title"]));
    let creator = detail
        .as_ref()
        .and_then(|d| creator_name(d));
    let price_micros = if is_free {
        None
    } else {
        detail.as_ref().and_then(|d| i64_field(d, &["price_per_run_micros", "price_micros"]))
    };
    let input_schema = detail.as_ref().and_then(input_schema_json);

    installed_workflows::upsert(
        db,
        &NewInstall {
            slug: slug.to_string(),
            listing_title: listing_title.clone(),
            creator: creator.clone(),
            is_free,
            price_micros,
            proxy_cloud_id: proxy_cloud_id.clone(),
            sealed_recipe: wrapped,
            input_schema,
        },
    )
    .await?;

    // 4) Mint the local PROXY workflow row (0017) so the install is immediately callable through the
    //    regular run surfaces, exactly like the cloud's consumer-tenant proxy.
    let proxy = ensure_proxy_workflow(db, slug, listing_title.as_deref()).await?;

    tracing::info!(slug, is_free, proxy_workflow_id = proxy.id, "marketplace listing installed natively");
    Ok(InstallSummary {
        slug: slug.to_string(),
        is_free,
        listing_title,
        creator,
        price_micros,
        proxy_cloud_id,
        local_workflow_id: Some(proxy.id),
    })
}

// --------------------------------------------------------------------------------------------
// LIST installed (metadata only)
// --------------------------------------------------------------------------------------------

/// List the locally installed marketplace workflows as METADATA ONLY (never the sealed blob/steps).
/// Thin passthrough to the store's safe projection.
pub async fn list_installed(db: &SqlitePool) -> LocalResult<Vec<installed_workflows::InstalledMeta>> {
    installed_workflows::list(db).await
}

// --------------------------------------------------------------------------------------------
// UNINSTALL
// --------------------------------------------------------------------------------------------

/// Result of [`uninstall`] — what was actually removed, for the UI/tool to report.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UninstallSummary {
    pub slug: String,
    /// The `installed_workflows` row (sealed recipe + bindings) was removed.
    pub removed_install: bool,
    /// The local PROXY `workflows` row deleted with the install (`None` = none existed).
    pub removed_workflow_id: Option<i64>,
    /// The cloud released the install grant. Best-effort — `false` means the cloud call failed
    /// (offline / unlinked) but the LOCAL rows are gone regardless; the cloud reconciles later.
    pub cloud_released: bool,
}

/// UNINSTALL a marketplace listing: release the cloud install grant, then remove BOTH local rows —
/// the `installed_workflows` row (sealed recipe + bindings) AND the PROXY `workflows` row minted by
/// [`ensure_proxy_workflow`]. Removing only one of the two is exactly the bug this closes: a
/// leftover proxy row runs into the engine's "reinstall the listing" NotFound, and a leftover
/// install row is an orphaned sealed recipe with no callable face.
///
/// The cloud call is BEST-EFFORT: an unlinked/offline daemon (or an install the cloud already
/// dropped) must not wedge local cleanup — the user is deleting THEIR local state. Deleting the
/// proxy row also retires every surface derived from it (derived MCP tool, schedules, REST id);
/// its `runs` history cascades away exactly like any other workflow delete.
pub async fn uninstall(db: &SqlitePool, slug: &str) -> LocalResult<UninstallSummary> {
    let cloud_released = match client(db).await {
        Ok(mut c) => match c.delete(&uninstall_path(slug)).await {
            Ok(()) => true,
            // Already gone cloud-side (never installed there / reconciled earlier) — that IS released.
            Err(LocalError::NotFound(_)) => true,
            Err(e) => {
                tracing::warn!(slug, error = %e, "cloud uninstall failed — removing local install anyway");
                false
            }
        },
        Err(e) => {
            tracing::warn!(slug, error = %e, "not linked — removing local install only");
            false
        }
    };

    let removed_install = installed_workflows::delete(db, slug).await?;
    let mut removed_workflow_id = None;
    if let Some(proxy) = workflows::get_by_marketplace_slug(db, slug).await? {
        if workflows::delete(db, proxy.id).await? {
            removed_workflow_id = Some(proxy.id);
        }
    }
    if !removed_install && removed_workflow_id.is_none() {
        return Err(LocalError::NotFound(format!("installed workflow {slug}")));
    }
    tracing::info!(
        slug,
        removed_install,
        removed_workflow_id,
        cloud_released,
        "marketplace listing uninstalled"
    );
    Ok(UninstallSummary {
        slug: slug.to_string(),
        removed_install,
        removed_workflow_id,
        cloud_released,
    })
}

// --------------------------------------------------------------------------------------------
// RUN — the PROTECTED EXECUTOR
// --------------------------------------------------------------------------------------------

/// Result of [`run`] — the TERMINAL outcome of the synchronous protected-executor run. `run_id`
/// keeps the historical `{ run_id }` loopback contract (the run also surfaces in `/v1/runs`); the
/// added fields let a caller (the MCP `writ_install_api` tool, or the UI) consume the result without
/// a second poll. `extracted_data` is the CONSUMER's own run output — never recipe internals.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RunOutcome {
    pub run_id: i64,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
    pub extracted_data: Value,
}

/// RUN an installed marketplace workflow. Since 0017 this is a thin adapter over the REGULAR run
/// path: it resolves (lazily minting for pre-0017 installs) the install's local PROXY workflow row
/// and dispatches `engine.run` on its id. The ENGINE's marketplace intercept then does the
/// protected-executor law — authorize (paid) → unseal IN MEMORY → execute → finalize — with the
/// `runs` row + rollup bound to the proxy row, so this lane and the derived-tool/schedule/REST
/// lanes are ONE lane.
///
/// `inputs` are the CONSUMER's own run values for the recipe's `{{input.*}}` placeholders (BYO —
/// same shape as a normal workflow run). Callers with no values pass `json!({})`.
pub async fn run(
    db: &SqlitePool,
    engine: &std::sync::Arc<dyn crate::local::engine::LocalEngine>,
    slug: &str,
    inputs: Value,
) -> LocalResult<RunOutcome> {
    if !inputs.is_object() {
        return Err(LocalError::BadRequest("run inputs must be a JSON object".into()));
    }
    let install = installed_workflows::get_by_slug(db, slug)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("installed workflow {slug}")))?;
    let proxy = ensure_proxy_workflow(db, slug, install.listing_title.as_deref()).await?;

    let result = engine
        .run(crate::local::engine::RunRequest {
            workflow_id: proxy.id,
            inputs,
            source: crate::local::engine::RunSource::Api,
            lane: crate::local::engine::Lane::Interactive,
            dry_run: false,
            persona_id: None,
            allow_local_secret_refs: true,
        })
        .await?;
    Ok(RunOutcome {
        run_id: result.run_id,
        success: result.success,
        error: result.error,
        duration_ms: result.duration_ms,
        extracted_data: result.extracted_data,
    })
}

// --------------------------------------------------------------------------------------------
// PROTECTED-EXECUTOR primitives — shared by the ENGINE's marketplace intercept
// --------------------------------------------------------------------------------------------

/// PAID gate: authorize a metered run cloud-side BEFORE any execution. The agent is untrusted —
/// billing authority is the cloud (the never-trust-a-BYO-agent rule). Returns the metered cloud run
/// id to finalize against (`None` for free/defensively-free authorizations). A denial is a
/// `BadRequest` carrying the cloud's reason (e.g. "insufficient balance") — no run, no charge.
pub(crate) async fn authorize_metered_run(
    db: &SqlitePool,
    slug: &str,
    is_free: bool,
) -> LocalResult<Option<String>> {
    if is_free {
        return Ok(None);
    }
    let mut cloud = client(db).await?;
    let auth: Value = cloud.post_json(&authorize_run_path(slug), &json!({})).await?;
    let authorized = auth.get("authorized").and_then(|v| v.as_bool()).unwrap_or(false);
    if !authorized {
        let reason = auth
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("run not authorized")
            .to_string();
        tracing::warn!(slug, "marketplace run NOT authorized — aborting before execution");
        return Err(LocalError::BadRequest(format!("run not authorized: {reason}")));
    }
    // A defensively-free authorization (cloud reclassified the listing as free) carries no run id.
    let now_free = auth.get("is_free").and_then(|v| v.as_bool()).unwrap_or(false);
    if now_free {
        return Ok(None);
    }
    Ok(auth.get("run_id").and_then(value_id_string).or_else(|| {
        // Authorized==true but no run_id is a cloud contract violation; treat as un-finalizable
        // (we still run, but there's nothing to reconcile). Log and proceed without a hold ref.
        tracing::warn!(slug, "authorize-run authorized without a run_id — finalize will be skipped");
        None
    }))
}

/// Finalize a metered charge with the run's real status + duration. Best-effort: a finalize network
/// blip must NOT mask a completed run from the user (the cloud reconciles holds on its own timeout
/// too) — we log and continue. The run already happened locally.
pub(crate) async fn finalize_metered_run(
    db: &SqlitePool,
    slug: &str,
    metered_id: &str,
    success: bool,
    duration_ms: u64,
) {
    let status = if success { "success" } else { "failed" };
    let body = json!({ "status": status, "duration_ms": duration_ms });
    let outcome = async {
        client(db)
            .await?
            .post_json::<Value, Value>(&finalize_path(slug, metered_id), &body)
            .await
    }
    .await;
    if let Err(e) = outcome {
        tracing::warn!(slug, error = %e, "marketplace finalize failed (cloud reconciles the hold on timeout)");
    }
}

/// Terminal (non-`running`) run states the engine can finalize a run into.
fn is_terminal_run_status(status: &str) -> bool {
    !matches!(status, "running" | "pending" | "queued")
}

/// Read a finished/in-flight marketplace run's status from the runs store, projected to the
/// `MarketplaceRunStatus` UI contract (the desktop page polls this to drive the run badge). We
/// deliberately do NOT serialize the raw run row: the UI keys on a `done` flag + an end-user-safe
/// `error`, and the raw row uses different field names (`completed_at`, `error_message`) with no
/// `done`. The recipe/steps are never part of either shape — only run-lifecycle metadata + the
/// consumer's own extracted output live on a run row.
pub async fn run_status(db: &SqlitePool, run_id: i64) -> LocalResult<Value> {
    let run = super::super::store::runs::get_by_id(db, run_id)
        .await?
        .ok_or_else(|| LocalError::NotFound(format!("run {run_id}")))?;
    let done = is_terminal_run_status(&run.status);
    Ok(json!({
        "run_id": run.id.to_string(),
        "status": run.status,
        "done": done,
        "duration_ms": run.duration_ms,
        "started_at": run.started_at,
        "finished_at": run.completed_at,
        // End-user-safe error detail only (the engine already keeps this generic); never recipe
        // internals — a run row carries no step/selector text.
        "error": run.error_message,
    }))
}

// --------------------------------------------------------------------------------------------
// Unseal + recipe → in-memory Workflow
// --------------------------------------------------------------------------------------------

/// Unseal a stored sealed recipe IN MEMORY: open the Layer-B vault field wrap, then Fernet-decrypt
/// the Layer-A channel_key blob, then parse the recipe JSON. The returned `Value` is the plaintext
/// recipe — it must stay in memory (never persisted/logged) and is dropped by the caller after the
/// run. A missing channel key (older link) is a clean error prompting a re-link.
/// [`unseal_recipe`] with SELF-HEALING for a stale seal: a fresh re-link mints a NEW per-agent
/// channel key, so recipes sealed under an OLDER link stop decrypting ("channel key
/// mismatch/tamper"). The install grant still stands cloud-side and the sealed-recipe endpoint
/// always seals for the CURRENT key — so on a decrypt failure we re-fetch, persist the fresh
/// seal, and retry ONCE. A still-failing decrypt (or an unreachable/unauthorized cloud) surfaces
/// an ACTIONABLE error instead of a generic one. A missing channel key is `Unauthorized` from the
/// inner unseal and is not retried here (only a re-link can mint one).
pub(crate) async fn unseal_recipe_healing(
    db: &SqlitePool,
    vault: &Vault,
    slug: &str,
    sealed: &str,
) -> LocalResult<Value> {
    let first = match unseal_recipe(vault, slug, sealed) {
        Ok(v) => return Ok(v),
        Err(e @ LocalError::Unauthorized) => return Err(e), // no channel key at all → re-link
        Err(e) => e,
    };
    tracing::warn!(slug, error = %first, "sealed recipe unseal failed — refreshing the seal from the cloud");
    let refreshed = refresh_sealed_recipe(db, vault, slug).await?;
    unseal_recipe(vault, slug, &refreshed).map_err(|_| {
        LocalError::BadRequest(format!(
            "the sealed recipe for '{slug}' cannot be decrypted on this device even after \
             refreshing it from the cloud. Re-link the Writ Cloud account in the Writ app \
             (Settings → Account), or uninstall and reinstall the listing."
        ))
    })
}

/// Re-fetch an install's sealed recipe from the cloud (sealed for THIS agent's CURRENT channel
/// key), vault-wrap it, persist it on the install row, and return the wrapped blob. The plaintext
/// recipe is never present here — this moves ciphertext only.
async fn refresh_sealed_recipe(db: &SqlitePool, vault: &Vault, slug: &str) -> LocalResult<String> {
    let mut client = client(db).await?;
    let sealed_resp: Value = client.get_json(&sealed_recipe_path(slug)).await?;
    let sealed = sealed_resp
        .get("sealed")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| LocalError::Internal("sealed-recipe response missing 'sealed'".into()))?;
    let wrapped = vault.seal_field(sealed.as_bytes(), &sealed_recipe_aad(slug))?;
    installed_workflows::set_sealed_recipe(db, slug, &wrapped).await?;
    tracing::info!(slug, "sealed recipe refreshed for the current channel key");
    Ok(wrapped)
}

pub(crate) fn unseal_recipe(vault: &Vault, slug: &str, sealed: &str) -> LocalResult<Value> {
    // Layer B: vault field decrypt (XChaCha20-Poly1305, AAD-bound to the install row).
    let channel_sealed = vault.open_field(sealed, &sealed_recipe_aad(slug))?;
    let channel_sealed = String::from_utf8(channel_sealed)
        .map_err(|_| LocalError::Internal("sealed recipe blob is not valid UTF-8".into()))?;

    // Layer A: channel_key Fernet decrypt — mirrors the backend `cryptography.fernet.Fernet` seal and
    // the bridge's `saas_bridge::decrypt_credentials_object` read path.
    let key = channel::get()?
        .ok_or_else(|| LocalError::Unauthorized)?; // no channel key → re-link required
    let fernet = fernet::Fernet::new(key.expose())
        .ok_or_else(|| LocalError::Internal("invalid channel key (not a Fernet key)".into()))?;
    let plaintext = fernet
        .decrypt(&channel_sealed)
        .map_err(|_| LocalError::Internal("sealed recipe decrypt failed (channel key mismatch/tamper)".into()))?;

    // Parse the recipe JSON. NEVER log the plaintext.
    serde_json::from_slice::<Value>(&plaintext)
        .map_err(|_| LocalError::Internal("sealed recipe is not valid JSON".into()))
}

/// Build a BYO-CLEAN in-memory [`workflows::Workflow`] from a decrypted recipe object.
///
/// The recipe is the cloud `serve_recipe` projection: `steps`, `raw_replay`, `entry_url`,
/// `exit_condition`, `timeout_ms`, `retry_count`, `functions`, optional `streaming_config`. It carries
/// NO creator data by construction. We set `id = 0` (the engine inserts a `runs` row with NULL
/// workflow_id), `credentials_encrypted = None` + `default_persona_id = None` (BYO — the consumer's
/// own vault secrets / inputs / persona resolve at run time), and the rollup/bookkeeping columns to
/// their inert defaults (this workflow has no persisted rollup row).
pub(crate) fn build_recipe_workflow(
    slug: &str,
    listing_title: Option<&str>,
    recipe: &Value,
) -> crate::local::store::workflows::Workflow {
    use crate::local::store::workflows::Workflow;

    // JSON-TEXT columns: re-serialize a recipe sub-value to compact text, or `None` when absent/null.
    let text = |key: &str| -> Option<String> {
        match recipe.get(key) {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(other) => Some(other.to_string()),
        }
    };
    // `steps` is the only NON-optional recipe column on the row; default to an empty array (a trivially
    // successful zero-step run) rather than failing — parity with the engine's tolerant parse.
    let steps = text("steps").unwrap_or_else(|| "[]".to_string());
    let workflow_type = recipe
        .get("workflow_type")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("recorded")
        .to_string();

    Workflow {
        id: 0,
        name: listing_title.unwrap_or(slug).to_string(),
        description: None,
        workflow_type,
        steps,
        raw_replay: text("raw_replay"),
        form_data: None, // BYO: the consumer's inputs resolve from the run path, not the recipe.
        exit_condition: text("exit_condition"),
        input_rules: text("input_rules"),
        api_functions: text("api_functions"),
        streaming_config: text("streaming_config"),
        functions: text("functions"),
        // BYO INVARIANT: no creator credential values, no creator persona binding.
        credentials_encrypted: None,
        entry_url: recipe.get("entry_url").and_then(|v| v.as_str()).map(str::to_string),
        timeout_ms: recipe.get("timeout_ms").and_then(Value::as_i64).unwrap_or(0),
        retry_count: recipe.get("retry_count").and_then(Value::as_i64).unwrap_or(0),
        // Honor the recipe's headless/fast hints if present; otherwise the engine's run defaults apply.
        headless: recipe.get("headless").and_then(Value::as_bool).map(|b| b as i64).unwrap_or(1),
        fast_mode: recipe.get("fast_mode").and_then(Value::as_bool).map(|b| b as i64).unwrap_or(1),
        is_active: 1,
        is_verified: 0,
        schedule_enabled: 0,
        schedule_interval_ms: None,
        schedule_kind: None,
        schedule_time: None,
        schedule_days: None,
        schedule_tz: None,
        last_scheduled_at: None,
        next_scheduled_at: None,
        session_persistence: 0,
        session_ttl_seconds: None,
        login_url_patterns: None,
        relogin_max_retries: 0,
        http_capable: -1,
        auth_config: None,
        default_persona_id: None,
        estimated_duration_ms: None,
        usage_count: 0,
        total_run_count: 0,
        total_failure_count: 0,
        consecutive_failures: 0,
        last_run_at: None,
        // Ephemeral recipe-derived workflow (never persisted): no run history.
        last_run_status: None,
        last_run_duration_ms: None,
        last_run_has_extracted_data: None,
        last_failure_at: None,
        last_failure_error: None,
        cloud_callable: 0,
        execution_target: None,
        ai_repair_enabled: 0,
        // Ephemeral: this row is never persisted, so it has no repair history to stamp.
        last_repaired_at: None,
        // The EXEC recipe is not itself a proxy row (the proxy row stays in `workflows`; this
        // in-memory workflow is what it executes).
        marketplace_slug: None,
        created_at: String::new(),
        updated_at: None,
    }
}

// --------------------------------------------------------------------------------------------
// Small helpers (path/query encoding + tolerant cloud-JSON field reads)
// --------------------------------------------------------------------------------------------

/// Append a raw query string (without `?`) to a path, tolerating an empty/`?`-prefixed value.
fn append_query(path: &str, query: &str) -> String {
    let q = query.trim().trim_start_matches('?');
    if q.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{q}")
    }
}

/// Percent-encode a single path SEGMENT (a marketplace slug) so a hostile value can't traverse the
/// path or inject a query. Slugs are normally `[a-z0-9-]`, but we encode defensively.
fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Stringify a JSON `id`-like field (cloud ids may be ints or strings). Empty string → `None`.
fn value_id_string(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Resolve `is_free` for an install: prefer the install response's explicit flag, then the listing
/// detail (price 0 / explicit `is_free`), defaulting to PAID (safer — never silently skip a charge).
fn resolve_is_free(detail: Option<&Value>, install_resp: &Value) -> bool {
    if let Some(b) = install_resp.get("is_free").and_then(|v| v.as_bool()) {
        return b;
    }
    if let Some(d) = detail {
        if let Some(b) = d.get("is_free").and_then(|v| v.as_bool()) {
            return b;
        }
        // A zero / absent price-per-run is treated as free.
        match i64_field(d, &["price_per_run_micros", "price_micros"]) {
            Some(p) => return p <= 0,
            None => return true,
        }
    }
    // No signal at all → default to PAID so we never skip an authorize-run on a paid listing.
    false
}

/// First present non-empty string among the candidate keys.
fn string_field(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
    }
    None
}

/// First present integer among the candidate keys.
fn i64_field(v: &Value, keys: &[&str]) -> Option<i64> {
    for k in keys {
        if let Some(n) = v.get(*k).and_then(Value::as_i64) {
            return Some(n);
        }
    }
    None
}

/// Best-effort creator display name from a listing detail (`creator.name`/`creator.handle` object,
/// or a flat `creator`/`creator_name` string).
fn creator_name(detail: &Value) -> Option<String> {
    if let Some(obj) = detail.get("creator").and_then(|c| c.as_object()) {
        for k in ["name", "display_name", "handle", "username"] {
            if let Some(s) = obj.get(k).and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                return Some(s.to_string());
            }
        }
    }
    string_field(detail, &["creator", "creator_name"])
}

/// Best-effort input-schema JSON-TEXT from a listing detail. The marketplace exposes the BYO slots
/// the consumer must attach under `data_manifest`/`input_schema`/`inputs`; we store whichever is
/// present as compact JSON-TEXT (metadata only — the UI renders it; the executor doesn't read it).
fn input_schema_json(detail: &Value) -> Option<String> {
    for k in ["input_schema", "data_manifest", "inputs"] {
        match detail.get(k) {
            Some(Value::Null) | None => continue,
            Some(v) => return Some(v.to_string()),
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::{db, vault};

    async fn pool() -> SqlitePool {
        let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
        db::open(&dir.path().join("t.db"), "test-key-mp").await.unwrap()
    }

    fn vault_at() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let v = vault::Vault::load_or_create(dir.path(), false).unwrap();
        (dir, v)
    }

    #[test]
    fn append_query_tolerates_shapes() {
        assert_eq!(append_query("/x", ""), "/x");
        assert_eq!(append_query("/x", "  "), "/x");
        assert_eq!(append_query("/x", "?a=1"), "/x?a=1");
        assert_eq!(append_query("/x", "a=1&b=2"), "/x?a=1&b=2");
    }

    #[test]
    fn encode_segment_blocks_traversal() {
        assert_eq!(encode_segment("cool-wf_1.0~x"), "cool-wf_1.0~x");
        assert_eq!(encode_segment("../etc"), "..%2Fetc");
        assert_eq!(encode_segment("a/b?c=1"), "a%2Fb%3Fc%3D1");
        assert_eq!(encode_segment("a b"), "a%20b");
    }

    #[test]
    fn resolve_is_free_defaults_to_paid_without_signal() {
        // No signal anywhere → PAID (never skip a charge).
        assert!(!resolve_is_free(None, &json!({})));
        // Explicit install flag wins.
        assert!(resolve_is_free(None, &json!({ "is_free": true })));
        // Listing detail price 0 → free; positive → paid.
        assert!(resolve_is_free(Some(&json!({ "price_per_run_micros": 0 })), &json!({})));
        assert!(!resolve_is_free(Some(&json!({ "price_per_run_micros": 50000 })), &json!({})));
        // Absent price on a detail → free (a listing with no price-per-run).
        assert!(resolve_is_free(Some(&json!({ "title": "x" })), &json!({})));
    }

    #[test]
    fn rename_secret_refs_is_names_only() {
        let bindings: HashMap<String, String> = [
            ("shop_password".to_string(), "my_amazon_pass".to_string()),
            ("same".to_string(), "same".to_string()),
        ]
        .into_iter()
        .collect();
        let steps = r#"[{"v":"{{secret:shop_password}}"},{"v":"{{vault:shop_password}}"},
                        {"v":"{{secret:shop_password.user}}"},{"v":"{{secret:same}}"},
                        {"v":"{{secret:untouched}}"},{"v":"{{input.shop_password}}"}]"#;
        let out = rename_secret_refs(steps, &bindings);
        assert!(out.contains("{{secret:my_amazon_pass}}"), "{out}");
        assert!(out.contains("{{secret:my_amazon_pass.user}}"), "dotted form renamed: {out}");
        assert!(!out.contains("secret:shop_password"), "old slot gone: {out}");
        assert!(!out.contains("vault:shop_password"), "vault spelling renamed too: {out}");
        assert!(out.contains("{{secret:same}}"), "identity binding untouched");
        assert!(out.contains("{{secret:untouched}}"), "unbound slots untouched");
        assert!(out.contains("{{input.shop_password}}"), "input namespace never touched");
    }

    #[test]
    fn install_bindings_parse_roundtrip_and_defaults() {
        assert_eq!(InstallBindings::parse(None), InstallBindings::default());
        assert_eq!(InstallBindings::parse(Some("not json")), InstallBindings::default());
        let mut b = InstallBindings::default();
        b.secrets.insert("slot".into(), "key".into());
        b.persona_id = Some(7);
        b.inputs.insert("product_url".into(), json!("https://x"));
        let parsed = InstallBindings::parse(Some(&b.to_json()));
        assert_eq!(parsed, b);
        // Older/partial blobs load forward.
        let sparse = InstallBindings::parse(Some(r#"{"persona_none":true}"#));
        assert!(sparse.persona_none && sparse.secrets.is_empty());
    }

    #[tokio::test]
    async fn ensure_proxy_workflow_mints_once_and_stays_sealed() {
        let pool = pool().await;
        let a = ensure_proxy_workflow(&pool, "price-watch", Some("Price Watch")).await.unwrap();
        assert_eq!(a.name, "Price Watch");
        assert_eq!(a.marketplace_slug.as_deref(), Some("price-watch"));
        assert_eq!(a.steps, "[]", "proxy row NEVER carries recipe steps");
        assert_eq!(a.is_active, 1);
        // MCP-born workflows are automatically MCP-exposed — EXPLICITLY (all API surfaces on).
        let s = a.connect_surfaces();
        assert!(s.mcp && s.rest && s.openai, "installed API exposed on every Connect surface");
        assert!(a.streaming_config.as_deref().unwrap_or("").contains("\"mcp\":true"), "explicit, not default");
        // Idempotent — a second ensure returns the SAME row (no duplicate).
        let b = ensure_proxy_workflow(&pool, "price-watch", Some("Renamed")).await.unwrap();
        assert_eq!(b.id, a.id);
        // Title fallback = slug.
        let c = ensure_proxy_workflow(&pool, "other", None).await.unwrap();
        assert_eq!(c.name, "other");
    }

    /// A minimal install row (opaque sealed blob, no cloud) for uninstall/attach tests.
    async fn seed_install(pool: &SqlitePool, slug: &str, input_schema: Option<&str>) {
        installed_workflows::upsert(
            pool,
            &NewInstall {
                slug: slug.to_string(),
                listing_title: Some("Price Watch".into()),
                creator: None,
                is_free: true,
                price_micros: None,
                proxy_cloud_id: None,
                sealed_recipe: "OPAQUE".into(),
                input_schema: input_schema.map(str::to_string),
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn uninstall_removes_install_and_proxy_even_unlinked() {
        let pool = pool().await;
        seed_install(&pool, "price-watch", None).await;
        let proxy = ensure_proxy_workflow(&pool, "price-watch", Some("Price Watch")).await.unwrap();

        // Unlinked daemon: the cloud release is best-effort (false) but BOTH local rows go.
        let s = uninstall(&pool, "price-watch").await.unwrap();
        assert!(s.removed_install);
        assert_eq!(s.removed_workflow_id, Some(proxy.id));
        assert!(!s.cloud_released, "no cloud link in tests");
        assert!(installed_workflows::get_by_slug(&pool, "price-watch").await.unwrap().is_none());
        assert!(workflows::get_by_id(&pool, proxy.id).await.unwrap().is_none());

        // Second uninstall of the same slug: nothing left → NotFound.
        assert!(matches!(
            uninstall(&pool, "price-watch").await,
            Err(LocalError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn uninstall_sweeps_a_leftover_proxy_without_install_row() {
        // The historical bad state: install row gone, proxy row stranded ("reinstall the
        // listing" on every run). Uninstall must clean it rather than 404.
        let pool = pool().await;
        let proxy = ensure_proxy_workflow(&pool, "stranded", None).await.unwrap();
        let s = uninstall(&pool, "stranded").await.unwrap();
        assert!(!s.removed_install);
        assert_eq!(s.removed_workflow_id, Some(proxy.id));
    }

    #[tokio::test]
    async fn attach_state_projects_manifest_and_bindings_names_only() {
        let pool = pool().await;
        let manifest = r#"{
            "input_slots": [{"key": "product_url", "label": "Product URL", "required": true}],
            "secret_slots": [{"name": "shop_password"}],
            "persona_slots": [{"slot": "login", "target_domain": "shop.example.com", "twofa": "totp"}],
            "has_login": true
        }"#;
        seed_install(&pool, "price-watch", Some(manifest)).await;

        let st = attach_state(&pool, "price-watch").await.unwrap().unwrap();
        assert_eq!(st["slug"], "price-watch");
        assert_eq!(st["manifest"]["has_login"], true);
        assert_eq!(st["manifest"]["input_slots"][0]["key"], "product_url");
        assert_eq!(st["manifest"]["input_slots"][0]["required"], true);
        // key/name/slot spellings all normalize to `key`.
        assert_eq!(st["manifest"]["secret_slots"][0]["key"], "shop_password");
        assert_eq!(st["manifest"]["persona_slots"][0]["key"], "login");
        assert_eq!(st["manifest"]["persona_slots"][0]["target_domain"], "shop.example.com");
        // Fresh install: empty bindings, and NEVER any secret value anywhere.
        assert_eq!(st["bindings"]["secrets"], json!({}));
        assert_eq!(st["bindings"]["persona_id"], Value::Null);
        assert!(attach_state(&pool, "missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn apply_bindings_validates_and_persists() {
        let pool = pool().await;
        let manifest = r#"{"secret_slots": [{"key": "shop_password"}],
                           "input_slots": [{"key": "product_url"}]}"#;
        seed_install(&pool, "price-watch", Some(manifest)).await;
        crate::local::store::vault_secrets::insert(
            &pool,
            &crate::local::store::vault_secrets::NewVaultSecret {
                key: "my_pass".into(),
                value_encrypted: "WF1:opaque".into(),
                description: None,
                category: None,
            },
        )
        .await
        .unwrap();

        // Unknown slot / unknown vault key / unknown persona are all rejected.
        assert!(apply_bindings(&pool, "price-watch", &json!({"secrets": {"nope": "my_pass"}}))
            .await
            .is_err());
        assert!(apply_bindings(&pool, "price-watch", &json!({"secrets": {"shop_password": "ghost"}}))
            .await
            .is_err());
        assert!(apply_bindings(&pool, "price-watch", &json!({"persona": 12345})).await.is_err());

        // Valid picks persist (names only) and merge across calls.
        let b = apply_bindings(
            &pool,
            "price-watch",
            &json!({"secrets": {"shop_password": "my_pass"},
                    "persona": "none",
                    "inputs": {"product_url": "https://x"}}),
        )
        .await
        .unwrap();
        assert_eq!(b.secrets.get("shop_password").map(String::as_str), Some("my_pass"));
        assert!(b.persona_none && b.persona_id.is_none());
        let saved = InstallBindings::parse(
            installed_workflows::get_by_slug(&pool, "price-watch")
                .await
                .unwrap()
                .unwrap()
                .bindings
                .as_deref(),
        );
        assert_eq!(saved, b);

        // Null unbinds a secret slot / removes an input default; persona null clears the decline.
        let b2 = apply_bindings(
            &pool,
            "price-watch",
            &json!({"secrets": {"shop_password": null},
                    "persona": null,
                    "inputs": {"product_url": null}}),
        )
        .await
        .unwrap();
        assert!(b2.secrets.is_empty() && b2.inputs.is_empty());
        assert!(!b2.persona_none && b2.persona_id.is_none());
    }

    #[test]
    fn tokenize_query_keeps_distinctive_terms_only() {
        assert_eq!(
            tokenize_query("Find the price of a product on amazon.com API"),
            vec!["price".to_string(), "product".to_string(), "amazon.com".to_string()]
        );
        // Stopwords (EN/FR) + short tokens drop; dedupe; cap at 6.
        assert_eq!(
            tokenize_query("je veux une api pour suivre le prix prix"),
            vec!["suivre".to_string(), "prix".to_string()]
        );
        assert_eq!(tokenize_query("to of in"), Vec::<String>::new());
    }

    #[test]
    fn detect_site_finds_hosts_and_ignores_prose() {
        assert_eq!(detect_site("track prices on amazon.com daily").as_deref(), Some("amazon.com"));
        assert_eq!(
            detect_site("scrape https://www.leboncoin.fr/annonces please").as_deref(),
            Some("leboncoin.fr")
        );
        assert_eq!(detect_site("just plain words here"), None);
        // A trailing sentence dot never fabricates a domain.
        assert_eq!(detect_site("I need this fast."), None);
    }

    #[test]
    fn score_listing_ranks_relevance_over_popularity() {
        let terms = vec!["price".to_string(), "amazon".to_string()];
        let relevant = json!({
            "slug": "amz-price", "title": "Amazon price tracker", "summary": "Track any product price",
            "target_domain": "amazon.com", "keywords": ["price", "watch"], "install_count": 3,
        });
        let popular_offtopic = json!({
            "slug": "news", "title": "News digest", "summary": "Daily headlines",
            "target_domain": "news.com", "install_count": 100000, "rating_avg": 5.0,
        });
        let (s1, matched) = score_listing(&relevant, &terms, Some("amazon.com"));
        let (s2, _) = score_listing(&popular_offtopic, &terms, Some("amazon.com"));
        assert!(s1 > s2, "relevance must beat popularity: {s1} vs {s2}");
        assert_eq!(matched, terms, "both terms matched");
    }

    #[test]
    fn extract_listings_tolerates_shapes() {
        assert_eq!(extract_listings(&json!({"listings": [{"slug": "a"}]})).len(), 1);
        assert_eq!(extract_listings(&json!([{"slug": "a"}, {"slug": "b"}])).len(), 2);
        assert_eq!(extract_listings(&json!({"items": [{"slug": "a"}]})).len(), 1);
        assert!(extract_listings(&json!({"total": 0})).is_empty());
    }

    #[test]
    fn candidate_json_is_metadata_only_and_marks_installed() {
        let card = json!({
            "slug": "amz-price", "title": "Amazon price tracker", "summary": "Track prices",
            "pricing_model": "per_success", "price_per_success_micros": 50000,
            "rating_avg": 4.5, "rating_count": 12, "install_count": 40,
            "creator": {"name": "Acme"}, "target_domain": "amazon.com",
        });
        let installed: HashSet<String> = ["amz-price".to_string()].into_iter().collect();
        let c = candidate_json(&card, 4.257, &["price".to_string()], &installed);
        assert_eq!(c["slug"], "amz-price");
        assert_eq!(c["installed"], true);
        assert_eq!(c["pricing"]["is_free"], false);
        assert_eq!(c["pricing"]["price_per_success_micros"], 50000);
        assert_eq!(c["creator"], "Acme");
        assert_eq!(c["score"], 4.26);
        // Never any recipe-ish fields.
        let s = c.to_string();
        assert!(!s.contains("steps") && !s.contains("sealed") && !s.contains("recipe"), "{s}");
    }

    #[test]
    fn creator_and_fields_tolerate_shapes() {
        let d = json!({ "creator": { "name": "Acme Co" }, "title": "Cool" });
        assert_eq!(creator_name(&d).as_deref(), Some("Acme Co"));
        assert_eq!(string_field(&d, &["title", "name"]).as_deref(), Some("Cool"));
        let flat = json!({ "creator": "solo-dev" });
        assert_eq!(creator_name(&flat).as_deref(), Some("solo-dev"));
        assert_eq!(creator_name(&json!({})), None);
    }

    #[test]
    fn build_recipe_workflow_is_byo_clean() {
        let recipe = json!({
            "steps": [ { "type": "wait", "config": { "duration": 10 } } ],
            "entry_url": "https://example.com",
            "timeout_ms": 45000,
            "retry_count": 1,
            "functions": [ { "name": "f" } ],
        });
        let wf = build_recipe_workflow("cool-wf", Some("Cool WF"), &recipe);
        // BYO INVARIANTS: no creds, no persona, ephemeral id.
        assert_eq!(wf.id, 0);
        assert!(wf.credentials_encrypted.is_none(), "no creator credential values");
        assert!(wf.default_persona_id.is_none(), "no creator persona binding");
        assert!(wf.form_data.is_none(), "BYO inputs resolve from the run path, not the recipe");
        // Recipe fields mapped through.
        assert_eq!(wf.name, "Cool WF");
        assert_eq!(wf.entry_url.as_deref(), Some("https://example.com"));
        assert_eq!(wf.timeout_ms, 45000);
        assert_eq!(wf.retry_count, 1);
        assert!(wf.steps.contains("wait"));
        assert!(wf.functions.as_deref().unwrap().contains("\"name\":\"f\""));
        // Empty steps default.
        let empty = build_recipe_workflow("x", None, &json!({}));
        assert_eq!(empty.steps, "[]");
        assert_eq!(empty.name, "x", "falls back to the slug when no title");
    }

    /// Round-trip the LOCAL Layer-B vault wrap (the channel_key Fernet inner layer is exercised by
    /// the bridge tests + a live link). `unseal_recipe` requires the keyring channel key, which a
    /// throwaway test box may not have — so here we prove only that a wrong/missing vault wrap fails
    /// closed (never returns a partial/plaintext recipe). The full unseal is covered by the live link
    /// path; this guards the at-rest layer.
    #[tokio::test]
    async fn vault_wrap_round_trips_opaque_blob() {
        let (_dir, v) = vault_at();
        let inner = "gAAAAA_pretend_channel_key_fernet_blob";
        let wrapped = v.seal_field(inner.as_bytes(), &sealed_recipe_aad("cool-wf")).unwrap();
        // The wrapped blob is opaque (no plaintext leak) and not the inner value verbatim.
        assert!(wrapped.starts_with("WF1:"));
        assert_ne!(wrapped, inner);
        // Opening with the SAME aad yields the inner channel-sealed blob back.
        let opened = v.open_field(&wrapped, &sealed_recipe_aad("cool-wf")).unwrap();
        assert_eq!(String::from_utf8(opened).unwrap(), inner);
        // A WRONG aad (different slug) fails closed — never returns the blob.
        assert!(v.open_field(&wrapped, &sealed_recipe_aad("other")).is_err());
    }

    /// The installed-metadata projection the loopback API returns NEVER contains the sealed blob, even
    /// after an install upsert that stored one. Defense-in-depth for invariant 1.
    #[tokio::test]
    async fn list_installed_never_leaks_sealed_blob() {
        let pool = pool().await;
        installed_workflows::upsert(
            &pool,
            &NewInstall {
                slug: "wf".into(),
                listing_title: Some("WF".into()),
                creator: Some("acme".into()),
                is_free: false,
                price_micros: Some(50_000),
                proxy_cloud_id: Some("wf_proxy".into()),
                sealed_recipe: "WF1:opaque_sealed_blob_value".into(),
                input_schema: None,
            },
        )
        .await
        .unwrap();
        let metas = list_installed(&pool).await.unwrap();
        let json = serde_json::to_string(&metas).unwrap();
        assert!(!json.contains("sealed"), "metadata JSON must not leak the sealed recipe: {json}");
        assert!(!json.contains("opaque_sealed_blob_value"), "no sealed value: {json}");
        assert!(json.contains("\"slug\":\"wf\""));
    }
}
