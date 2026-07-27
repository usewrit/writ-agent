//! Scripted-server tests for the HTTP lane request driver + probe ladder.
//!
//! These run in-module (not under `tests/`) because they need the crate-internal `skip_url_vetting`
//! flag: the SSRF guard has no loopback escape, so a `127.0.0.1` fake server would otherwise be
//! blocked. A tiny axum app on an ephemeral port scripts each auth flow.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use serde_json::json;

use super::ladder::{run_workflow_http, LadderConfig, NullObserver};
use super::recipe::{AuthRecipe, ChallengeResolver, RecipeRunner};
use super::{HttpLaneError, HttpLaneExecutor, HttpLaneOptions};

#[derive(Clone, Default)]
struct SrvState {
    login_hits: Arc<AtomicUsize>,
}

fn has_good_cookie(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.contains("sid=good"))
        .unwrap_or(false)
}

async fn login(State(st): State<SrvState>) -> impl IntoResponse {
    st.login_hits.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::OK,
        [(axum::http::header::SET_COOKIE, "sid=good; Path=/; HttpOnly")],
        "ok",
    )
}

async fn data(State(_st): State<SrvState>, headers: HeaderMap) -> impl IntoResponse {
    if has_good_cookie(&headers) {
        (StatusCode::OK, axum::Json(json!({"items": [1, 2, 3]}))).into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "no session").into_response()
    }
}

async fn login_reject() -> impl IntoResponse {
    (StatusCode::UNAUTHORIZED, "bad creds")
}

async fn challenge() -> impl IntoResponse {
    (
        StatusCode::FORBIDDEN,
        [(axum::http::header::SERVER, "cloudflare")],
        "<html>Just a moment... cf-chl</html>",
    )
}

/// Spawn an axum app on an ephemeral port; returns the base URL (http://127.0.0.1:PORT).
async fn spawn(app: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://127.0.0.1:{}", addr.port())
}

fn exec_for(base: &str) -> HttpLaneExecutor {
    let mut e = HttpLaneExecutor::new(HttpLaneOptions {
        fingerprint: None,
        proxy: None,
        session: None,
        entry_url: Some(base),
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    e.skip_url_vetting = true;
    e
}

fn ladder_cfg() -> LadderConfig {
    LadderConfig { login_url_patterns: vec![], relogin_max_retries: 1 }
}

fn creds() -> HashMap<String, String> {
    HashMap::new()
}

#[tokio::test]
async fn fresh_login_then_data() {
    let st = SrvState::default();
    let app = Router::new()
        .route("/login", post(login))
        .route("/data", get(data))
        .with_state(st.clone());
    let base = spawn(app).await;
    let mut exec = exec_for(&base);

    let steps = vec![
        json!({"type": "login_post", "config": {"url": format!("{base}/login"), "method": "POST"}}),
        json!({"type": "api_call", "config": {"url": format!("{base}/data"), "method": "GET", "variable": "rows"}}),
    ];
    let out = run_workflow_http(&mut exec, &steps, &creds(), &creds(), &ladder_cfg(), &NullObserver, None)
        .await
        .expect("http run ok");
    assert_eq!(st.login_hits.load(Ordering::SeqCst), 1);
    assert_eq!(out.extracted.get("rows"), Some(&json!({"items": [1, 2, 3]})));
}

#[tokio::test]
async fn warm_session_skips_login() {
    let st = SrvState::default();
    let app = Router::new()
        .route("/login", post(login))
        .route("/data", get(data))
        .with_state(st.clone());
    let base = spawn(app).await;

    // Seed a warm session with the good cookie.
    let session = crate::models::session::SessionState {
        cookies: vec![json!({
            "name": "sid", "value": "good", "domain": "127.0.0.1", "path": "/", "expires": -1
        })],
        headers: HashMap::new(),
        local_storage: HashMap::new(),
        session_storage: HashMap::new(),
        extracted_at: None,
        fingerprint: None,
        tokens: None,
    };
    let mut exec = HttpLaneExecutor::new(HttpLaneOptions {
        fingerprint: None,
        proxy: None,
        session: Some(&session),
        entry_url: Some(&base),
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    exec.skip_url_vetting = true;

    let steps = vec![
        json!({"type": "login_post", "config": {"url": format!("{base}/login"), "method": "POST"}}),
        json!({"type": "api_call", "config": {"url": format!("{base}/data"), "method": "GET", "variable": "rows"}}),
    ];
    let out = run_workflow_http(&mut exec, &steps, &creds(), &creds(), &ladder_cfg(), &NullObserver, None)
        .await
        .expect("http run ok");
    // Login was skipped (lazy) — the warm cookie carried the data call.
    assert_eq!(st.login_hits.load(Ordering::SeqCst), 0);
    assert_eq!(out.extracted.get("rows"), Some(&json!({"items": [1, 2, 3]})));
}

#[tokio::test]
async fn stale_session_triggers_relogin() {
    let st = SrvState::default();
    let app = Router::new()
        .route("/login", post(login))
        .route("/data", get(data))
        .with_state(st.clone());
    let base = spawn(app).await;

    // Seed a STALE cookie (not "good") so /data 401s until re-login.
    let session = crate::models::session::SessionState {
        cookies: vec![json!({
            "name": "sid", "value": "stale", "domain": "127.0.0.1", "path": "/", "expires": -1
        })],
        headers: HashMap::new(),
        local_storage: HashMap::new(),
        session_storage: HashMap::new(),
        extracted_at: None,
        fingerprint: None,
        tokens: None,
    };
    let mut exec = HttpLaneExecutor::new(HttpLaneOptions {
        fingerprint: None,
        proxy: None,
        session: Some(&session),
        entry_url: Some(&base),
        timeout: Duration::from_secs(5),
    })
    .unwrap();
    exec.skip_url_vetting = true;

    let steps = vec![
        json!({"type": "login_post", "config": {"url": format!("{base}/login"), "method": "POST"}}),
        json!({"type": "api_call", "config": {"url": format!("{base}/data"), "method": "GET", "variable": "rows"}}),
    ];
    let out = run_workflow_http(&mut exec, &steps, &creds(), &creds(), &ladder_cfg(), &NullObserver, None)
        .await
        .expect("http run ok");
    // Stale detected on /data → re-login executed once → retry succeeded.
    assert_eq!(st.login_hits.load(Ordering::SeqCst), 1);
    assert_eq!(out.extracted.get("rows"), Some(&json!({"items": [1, 2, 3]})));
}

#[tokio::test]
async fn login_rejected_falls_back() {
    let app = Router::new().route("/login", post(login_reject));
    let base = spawn(app).await;
    let mut exec = exec_for(&base);
    let steps = vec![
        json!({"type": "login_post", "config": {"url": format!("{base}/login"), "method": "POST"}}),
    ];
    let err = run_workflow_http(&mut exec, &steps, &creds(), &creds(), &ladder_cfg(), &NullObserver, None)
        .await
        .unwrap_err();
    assert!(matches!(err, HttpLaneError::Fallback(super::FallbackReason::AuthFailed)));
}

#[tokio::test]
async fn challenge_page_falls_back() {
    let app = Router::new().route("/data", get(challenge));
    let base = spawn(app).await;
    let mut exec = exec_for(&base);
    let steps = vec![
        json!({"type": "api_call", "config": {"url": format!("{base}/data"), "method": "GET", "variable": "rows"}}),
    ];
    let err = run_workflow_http(&mut exec, &steps, &creds(), &creds(), &ladder_cfg(), &NullObserver, None)
        .await
        .unwrap_err();
    assert!(matches!(err, HttpLaneError::Fallback(super::FallbackReason::ChallengePage)));
}

#[tokio::test]
async fn response_extractions_chain_into_headers() {
    // /token returns a JSON token; /secure requires Authorization: Bearer <token>.
    async fn token() -> impl IntoResponse {
        (StatusCode::OK, axum::Json(json!({"access": "T0P"}))).into_response()
    }
    async fn secure(headers: HeaderMap) -> impl IntoResponse {
        let ok = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|a| a == "Bearer T0P")
            .unwrap_or(false);
        if ok {
            (StatusCode::OK, axum::Json(json!({"secret": 42}))).into_response()
        } else {
            (StatusCode::UNAUTHORIZED, "no bearer").into_response()
        }
    }
    let app = Router::new().route("/token", post(token)).route("/secure", get(secure));
    let base = spawn(app).await;
    let mut exec = exec_for(&base);
    let steps = vec![
        json!({"type": "api_call", "config": {
            "url": format!("{base}/token"), "method": "POST", "body": "{}",
            "response_extractions": {"tok": "$.access"}, "variable": "tokresp"
        }}),
        json!({"type": "api_call", "config": {
            "url": format!("{base}/secure"), "method": "GET",
            "headers": {"Authorization": "Bearer {{extracted:tok}}"}, "variable": "sec"
        }}),
    ];
    let out = run_workflow_http(&mut exec, &steps, &creds(), &creds(), &ladder_cfg(), &NullObserver, None)
        .await
        .expect("http run ok");
    assert_eq!(out.extracted.get("tok"), Some(&json!("T0P")));
    assert_eq!(out.extracted.get("sec"), Some(&json!({"secret": 42})));
}

#[tokio::test]
async fn session_export_roundtrips_cookie() {
    let st = SrvState::default();
    let app = Router::new().route("/login", post(login)).with_state(st);
    let base = spawn(app).await;
    let mut exec = exec_for(&base);
    let steps = vec![
        json!({"type": "login_post", "config": {"url": format!("{base}/login"), "method": "POST"}}),
    ];
    let _ = run_workflow_http(&mut exec, &steps, &creds(), &creds(), &ladder_cfg(), &NullObserver, None)
        .await
        .unwrap();
    let state = exec.export_session_state();
    // The Set-Cookie from /login was captured into the jar and exported.
    assert!(state.cookies.iter().any(|c| c["name"] == json!("sid") && c["value"] == json!("good")));
    assert!(state.extracted_at.is_some());
}

// ---- AuthRecipe interpreter: CSRF prefetch -> credentials -> TOTP challenge -> data -----------

async fn recipe_login_page() -> impl IntoResponse {
    (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "text/html")],
     r#"<form><input name="_csrf" value="CSRF123"></form>"#)
}

async fn recipe_session(body: String) -> impl IntoResponse {
    // Requires the csrf; then demands a 2FA code (401 with a verification-code signal).
    if body.contains("_csrf=CSRF123") {
        (StatusCode::UNAUTHORIZED, "verification code required").into_response()
    } else {
        (StatusCode::BAD_REQUEST, "missing csrf").into_response()
    }
}

async fn recipe_2fa(body: String) -> impl IntoResponse {
    if body.contains("\"code\":\"999111\"") {
        (
            StatusCode::OK,
            [(axum::http::header::SET_COOKIE, "sid=good; Path=/; HttpOnly")],
            axum::Json(json!({"ok": true})),
        )
            .into_response()
    } else {
        (StatusCode::UNAUTHORIZED, "bad code").into_response()
    }
}

#[tokio::test]
async fn recipe_csrf_totp_flow() {
    let st = SrvState::default();
    let app = Router::new()
        .route("/login", get(recipe_login_page))
        .route("/session", post(recipe_session))
        .route("/2fa", post(recipe_2fa))
        .route("/data", get(data))
        .with_state(st);
    let base = spawn(app).await;
    let mut exec = exec_for(&base);

    let recipe_json = json!({
        "version": 1, "kind": "http",
        "login": {"steps": [
            {"request": {"method": "GET", "url": format!("{base}/login")},
             "extract": {"csrf": {"from": "html_css", "selector": "input[name=_csrf]", "attribute": "value"}}},
            {"request": {"method": "POST", "url": format!("{base}/session"),
                         "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                         "body": "_csrf={{extracted:csrf}}"},
             "expect": {"status": [200]},
             "challenges": [{
                 "type": "totp",
                 "detect": {"status": [401]},
                 "submit": {"method": "POST", "url": format!("{base}/2fa"),
                            "headers": {"Content-Type": "application/json"},
                            "body": "{\"code\":\"{{challenge:code}}\"}"},
                 "expect": {"status": [200]}
             }]}
        ]}
    });
    let recipe: AuthRecipe = serde_json::from_value(recipe_json).unwrap();
    let creds = HashMap::new();
    let mut runner = RecipeRunner::new(
        &recipe, &creds, &creds, None,
        ChallengeResolver::LocalPersona { totp_code: Some("999111".into()) },
        1,
    );
    let steps = vec![
        json!({"type": "api_call", "config": {"url": format!("{base}/data"), "method": "GET", "variable": "rows"}}),
    ];
    let out = run_workflow_http(&mut exec, &steps, &creds, &creds, &ladder_cfg(), &NullObserver, Some(&mut runner))
        .await
        .expect("recipe run ok");
    // The CSRF+TOTP login established the session cookie, so the data call succeeded.
    assert_eq!(out.extracted.get("rows"), Some(&json!({"items": [1, 2, 3]})));
}

#[tokio::test]
async fn recipe_totp_missing_parks() {
    let st = SrvState::default();
    let app = Router::new()
        .route("/login", get(recipe_login_page))
        .route("/session", post(recipe_session))
        .route("/2fa", post(recipe_2fa))
        .with_state(st);
    let base = spawn(app).await;
    let mut exec = exec_for(&base);
    let recipe_json = json!({
        "version": 1, "kind": "http",
        "login": {"steps": [
            {"request": {"method": "GET", "url": format!("{base}/login")},
             "extract": {"csrf": {"from": "html_css", "selector": "input[name=_csrf]", "attribute": "value"}}},
            {"request": {"method": "POST", "url": format!("{base}/session"),
                         "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                         "body": "_csrf={{extracted:csrf}}"},
             "expect": {"status": [200]},
             "challenges": [{"type": "totp", "detect": {"status": [401]},
                 "submit": {"method": "POST", "url": format!("{base}/2fa"), "body": "{}"},
                 "expect": {"status": [200]}}]}
        ]}
    });
    let recipe: AuthRecipe = serde_json::from_value(recipe_json).unwrap();
    let creds = HashMap::new();
    // No TOTP code available → the challenge parks (typed "needs a code").
    let mut runner = RecipeRunner::new(
        &recipe, &creds, &creds, None,
        ChallengeResolver::LocalPersona { totp_code: None },
        1,
    );
    let steps = vec![json!({"type": "api_call", "config": {"url": format!("{base}/data"), "variable": "rows"}})];
    let err = run_workflow_http(&mut exec, &steps, &creds, &creds, &ladder_cfg(), &NullObserver, Some(&mut runner))
        .await
        .unwrap_err();
    assert!(matches!(err, HttpLaneError::Parked(_)));
}
