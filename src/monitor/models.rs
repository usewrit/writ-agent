//! Data models for the monitoring subsystem.
//!
//! `Target` / `Selector` deserialize from the `assign_targets` frame; `ReportItem`
//! serializes into the `target_check_batch` frame and matches the backend's
//! `SingleReportData` schema (the cloud backend's `batch_reports` router) exactly.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

fn default_check_type() -> String {
    "content".to_string()
}
fn default_content_type() -> String {
    "text".to_string()
}
fn default_true() -> bool {
    true
}

/// Parse an optional i64 that may arrive as a JSON number OR a string — the
/// backend sends the target id as `str(target.id)` (a string) while selector ids
/// come as numbers, so be lenient. Missing/null/unparseable → None.
fn de_opt_i64_flex<'de, D>(d: D) -> Result<Option<i64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Option::<serde_json::Value>::deserialize(d)?;
    Ok(match v {
        Some(serde_json::Value::Number(n)) => n.as_i64(),
        Some(serde_json::Value::String(s)) => s.trim().parse::<i64>().ok(),
        _ => None,
    })
}

/// One monitored selector within a content target.
#[derive(Debug, Clone, Deserialize)]
pub struct Selector {
    #[serde(default)]
    pub id: Option<i64>,
    #[serde(default)]
    pub name: Option<String>,
    pub selector: String,
    #[serde(default = "default_content_type")]
    pub content_type: String, // text | html | visual
    #[serde(default)]
    pub ignore_regex: Option<String>,
    #[serde(default)]
    pub baseline_hash: Option<String>,
    #[serde(default)]
    pub baseline_content: Option<String>,
    /// For content_type == "visual": the screenshot region {x,y,width,height}
    /// to clip and pixel-hash. Absent for text/html selectors.
    #[serde(default)]
    pub visual_region: Option<serde_json::Value>,
}

/// A monitoring target as handed down by the coordinator. Mirrors the
/// desktop-agent target dict.
#[derive(Debug, Clone, Deserialize)]
pub struct Target {
    #[serde(default, deserialize_with = "de_opt_i64_flex")]
    pub id: Option<i64>,
    pub url: String,
    #[serde(default = "default_check_type")]
    pub check_type: String, // content | uptime
    #[serde(default)]
    pub check_period_ms: Option<i64>,
    #[serde(default)]
    pub requires_playwright: bool,
    /// Optional auth/login workflow to run (in the browser) before checking.
    #[serde(default)]
    pub pre_check_workflow: Option<serde_json::Value>,
    /// Saved auth session ({cookies,headers,localStorage,sessionStorage,fingerprint}).
    #[serde(default)]
    pub auth_session: Option<serde_json::Value>,
    #[serde(default)]
    pub timeout_ms: Option<i64>,
    #[serde(default)]
    pub expected_status_code: Option<i64>,
    #[serde(default = "default_true")]
    pub check_ssl: bool,
    #[serde(default)]
    pub selectors: Vec<Selector>,
}

impl Target {
    /// Tiered routing: a target goes through the browser when it needs JS
    /// rendering, an auth session, or a pre-check workflow. Otherwise the fast
    /// HTTP path handles it. (Uptime is always HTTP.)
    pub fn needs_browser(&self) -> bool {
        if self.check_type == "uptime" {
            return false;
        }
        self.requires_playwright
            || self.pre_check_workflow.is_some()
            || self.auth_session.is_some()
            // A visual (screenshot-region) selector can ONLY be captured in the
            // browser — the HTTP path has no page to clip. Force the browser path
            // whenever any selector is visual, regardless of requires_playwright.
            || self
                .selectors
                .iter()
                .any(|s| s.content_type == "visual" && s.visual_region.is_some())
    }
}

/// One report item — matches `SingleReportData` in the backend batch endpoint.
/// `None` fields are omitted so the payload stays identical to the Python agent.
#[derive(Debug, Clone, Serialize, Default)]
pub struct ReportItem {
    pub target_url: String,
    pub check_type: String,

    /// Id of the target checked (the coalesced group's representative). Lets the
    /// backend fan an uptime result out to the exact fetch_key group.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<i64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_name: Option<String>,

    // Content fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_snippet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_content: Option<String>,
    /// Base64 PNG of a visual zone's region (first run + on change) for the
    /// before/after image diff. Omitted for text/html and steady-state visual.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub screenshot: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,

    // Uptime fields
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_up: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_time_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_time_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_time_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_cert_valid: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_cert_expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_cert_days_until_expiry: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_cert_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_cert_subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_error: Option<String>,

    // Common
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

/// The result of checking a single target: the report items to batch up, plus an
/// optional refreshed auth session (when a browser/pre-check ran) to persist via
/// `precheck_complete`, and whether any selector changed (for adaptive scheduling).
#[derive(Debug, Clone, Default)]
pub struct CheckOutcome {
    pub reports: Vec<ReportItem>,
    pub auth_session: Option<serde_json::Value>,
    pub changed: bool,
}
