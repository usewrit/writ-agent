//! The declarative AuthRecipe (v1) and its interpreter.
//!
//! A recipe describes how to authenticate a workflow over HTTP as a small program: a `probe` (is the
//! session still good?), a `login` chain (GET a CSRF token, POST credentials, answer a 2FA challenge),
//! a `refresh` rung (mint a fresh access token from a refresh token), and `stale` detection knobs. The
//! interpreter runs the cheapest rung that works — reuse, then refresh, then full login — and exports
//! the resulting cookies + token store for persistence.
//!
//! The JSON shape is the cross-surface contract mirrored by the Python agent and pinned by
//! `tests/fixtures/auth_recipe_v1.json`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::monitor::extract::{json_value_path, run_extractor};
use crate::util::value_resolver::resolve_value_full;

use super::{FallbackReason, HttpLaneError, HttpLaneExecutor, HttpResponse, ParkKind};

// ---- Schema (v1) -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRecipe {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default = "default_kind")]
    pub kind: String, // "http" | "browser" | "none"
    #[serde(default = "default_true")]
    pub http: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<RecipeStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<LoginBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<RecipeStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserBlock>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<StaleSpec>,
}

fn default_version() -> u32 {
    1
}
fn default_kind() -> String {
    "http".to_string()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginBlock {
    #[serde(default)]
    pub steps: Vec<RecipeStep>,
    /// Named token declarations resolved after login (value templated from an extracted var), applied
    /// as request headers and persisted in the token store.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tokens: HashMap<String, TokenDecl>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeStep {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub request: RequestSpec,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extract: HashMap<String, ExtractSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<ExpectSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestSpec {
    #[serde(default = "default_get")]
    pub method: String,
    pub url: String,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub headers: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

fn default_get() -> String {
    "GET".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractSpec {
    pub from: String, // json | html_css | regex | header | cookie | redirect_param | jwt_claim
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default)]
    pub optional: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<StoreSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreSpec {
    #[serde(rename = "as", default = "default_store_as")]
    pub as_: String, // header | cookie | var
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_claim: Option<String>,
}

fn default_store_as() -> String {
    "var".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExpectSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_url_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_body_regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_path_present: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub kind: String, // totp | email_otp | user_prompt
    #[serde(default)]
    pub detect: ExpectSpec,
    pub submit: RequestSpec,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extract: HashMap<String, ExtractSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<ExpectSpec>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wait_seconds: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserBlock {
    /// `[start, end)` — the contiguous prefix of enabled workflow steps that make up the DOM login.
    pub step_range: [usize; 2],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub success: Option<ExpectSpec>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StaleSpec {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub url_patterns: Vec<String>,
    #[serde(default)]
    pub html_when_json_expected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenDecl {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    pub value: String,
}

impl AuthRecipe {
    /// Synthesize a degenerate recipe from a workflow's leading `login_post` steps (no `auth_config`).
    pub fn degenerate(login_steps: Vec<RequestSpec>, login_url_patterns: Vec<String>) -> Self {
        AuthRecipe {
            version: 1,
            kind: "http".to_string(),
            http: true,
            probe: None,
            login: Some(LoginBlock {
                steps: login_steps
                    .into_iter()
                    .map(|request| RecipeStep {
                        id: None,
                        request,
                        extract: HashMap::new(),
                        expect: None,
                        challenges: Vec::new(),
                    })
                    .collect(),
                tokens: HashMap::new(),
            }),
            refresh: None,
            browser: None,
            stale: Some(StaleSpec {
                status: vec![401, 403],
                url_patterns: login_url_patterns,
                html_when_json_expected: true,
            }),
        }
    }
}

// ---- Challenge resolution --------------------------------------------------------------------

/// How this surface obtains a challenge code. The local engine mints TOTP on-device; the cloud/self-host
/// bridge polls the persona OTP endpoint (wired in the bridge, not here).
pub enum ChallengeResolver {
    /// A TOTP code minted on-device (persona seed). `None` for a persona without a seed.
    LocalPersona { totp_code: Option<String> },
    /// No persona / can't resolve any challenge on this surface.
    None,
}

impl ChallengeResolver {
    /// Resolve a code for a challenge of `kind`, or a park reason when this surface can't.
    fn resolve(&self, kind: &str) -> Result<String, ParkKind> {
        match (self, kind) {
            (ChallengeResolver::LocalPersona { totp_code: Some(code) }, "totp") => Ok(code.clone()),
            (_, "totp") => Err(ParkKind::Attention(
                "This sign-in needs an authenticator (TOTP) code and no persona provided one.".into(),
            )),
            (_, "email_otp") => Err(ParkKind::Twofa(
                "This sign-in needs an emailed code — run in the cloud or link a persona with an OTP relay.".into(),
            )),
            (_, _) => Err(ParkKind::Attention(
                "This sign-in needs a one-time code you must supply — run it in the browser or attach a 2FA persona.".into(),
            )),
        }
    }
}

// ---- Interpreter -----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthOutcome {
    Reused,
    Refreshed,
    LoggedIn,
    NoAuthNeeded,
}

pub struct RecipeRunner<'a> {
    recipe: &'a AuthRecipe,
    credentials: &'a HashMap<String, String>,
    form_data: &'a HashMap<String, String>,
    /// Recipe-extracted vars — ALSO exposed to data steps as `{{extracted:name}}`.
    pub vars: HashMap<String, Value>,
    /// Token store: name -> {value, header, prefix, expires_at?} (persisted as SessionState.tokens).
    tokens: HashMap<String, Value>,
    challenge: ChallengeResolver,
    relogin_max_retries: u32,
}

impl<'a> RecipeRunner<'a> {
    pub fn new(
        recipe: &'a AuthRecipe,
        credentials: &'a HashMap<String, String>,
        form_data: &'a HashMap<String, String>,
        seeded_tokens: Option<&Value>,
        challenge: ChallengeResolver,
        relogin_max_retries: u32,
    ) -> Self {
        let mut tokens = HashMap::new();
        if let Some(map) = seeded_tokens.and_then(|v| v.as_object()) {
            for (k, v) in map {
                tokens.insert(k.clone(), v.clone());
            }
        }
        RecipeRunner {
            recipe,
            credentials,
            form_data,
            vars: HashMap::new(),
            tokens,
            challenge,
            relogin_max_retries,
        }
    }

    pub fn export_tokens(&self) -> Option<Value> {
        if self.tokens.is_empty() {
            None
        } else {
            Some(Value::Object(self.tokens.clone().into_iter().collect()))
        }
    }

    /// The full ladder for the start of a run: probe (if a session is warm) → refresh → login.
    pub async fn ensure_session(&mut self, exec: &mut HttpLaneExecutor) -> Result<AuthOutcome, HttpLaneError> {
        // Seed sticky headers from any persisted token store first.
        if let Some(tokens) = self.export_tokens() {
            exec.seed_tokens(&tokens);
        }

        // If a session is warm and the probe passes, reuse it.
        if exec.has_session() {
            if let Some(probe) = &self.recipe.probe {
                let resp = self.run_recipe_request(exec, &probe.request).await?;
                if self.expect_ok(probe.expect.as_ref(), &resp) {
                    return Ok(AuthOutcome::Reused);
                }
            } else {
                // No probe declared: assume the warm session is good; the first data step is the probe.
                return Ok(AuthOutcome::Reused);
            }
            // Probe failed → try refresh before a full login.
            if self.try_refresh(exec).await? {
                return Ok(AuthOutcome::Refreshed);
            }
        }

        self.do_login(exec).await?;
        Ok(AuthOutcome::LoggedIn)
    }

    /// Re-entry when a DATA step reported stale mid-run: refresh then re-login (bounded).
    pub async fn reauthenticate(&mut self, exec: &mut HttpLaneExecutor) -> Result<AuthOutcome, HttpLaneError> {
        if self.try_refresh(exec).await? {
            return Ok(AuthOutcome::Refreshed);
        }
        exec.jar_mut().clear();
        self.do_login(exec).await?;
        Ok(AuthOutcome::LoggedIn)
    }

    async fn try_refresh(&mut self, exec: &mut HttpLaneExecutor) -> Result<bool, HttpLaneError> {
        let Some(refresh) = &self.recipe.refresh else {
            return Ok(false);
        };
        let resp = self.run_recipe_request(exec, &refresh.request).await?;
        if !self.expect_ok(refresh.expect.as_ref(), &resp) {
            return Ok(false);
        }
        self.apply_extractions(exec, &refresh.extract, &resp)?;
        Ok(true)
    }

    async fn do_login(&mut self, exec: &mut HttpLaneExecutor) -> Result<(), HttpLaneError> {
        let Some(login) = &self.recipe.login else {
            return Err(HttpLaneError::Fallback(FallbackReason::Unsupported));
        };
        let mut attempts = 0u32;
        loop {
            match self.run_login_once(exec, login).await {
                Ok(()) => {
                    self.apply_login_tokens(exec, login)?;
                    return Ok(());
                }
                Err(HttpLaneError::Fallback(FallbackReason::AuthFailed)) if attempts < self.relogin_max_retries => {
                    attempts += 1;
                    exec.jar_mut().clear();
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn run_login_once(&mut self, exec: &mut HttpLaneExecutor, login: &LoginBlock) -> Result<(), HttpLaneError> {
        for step in &login.steps {
            let resp = self.run_recipe_request(exec, &step.request).await?;
            if looks_like_challenge(&resp) {
                return Err(HttpLaneError::Fallback(FallbackReason::ChallengePage));
            }
            self.apply_extractions(exec, &step.extract, &resp)?;

            // If the step's expect fails, try its challenges (2FA) before giving up.
            let mut ok = self.expect_ok(step.expect.as_ref(), &resp);
            if !ok && !step.challenges.is_empty() {
                ok = self.run_challenges(exec, step, &resp).await?;
            }
            if !ok {
                return Err(HttpLaneError::Fallback(FallbackReason::AuthFailed));
            }
        }
        Ok(())
    }

    async fn run_challenges(
        &mut self,
        exec: &mut HttpLaneExecutor,
        step: &RecipeStep,
        parent_resp: &HttpResponse,
    ) -> Result<bool, HttpLaneError> {
        for ch in &step.challenges {
            if !detect_matches(&ch.detect, parent_resp) {
                continue;
            }
            let code = match self.challenge.resolve(&ch.kind) {
                Ok(c) => c,
                Err(park) => return Err(HttpLaneError::Parked(park)),
            };
            let resp = self.run_recipe_request_with(exec, &ch.submit, Some(&code)).await?;
            self.apply_extractions(exec, &ch.extract, &resp)?;
            let expect = ch.expect.as_ref().or(step.expect.as_ref());
            if self.expect_ok(expect, &resp) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn apply_login_tokens(&mut self, exec: &mut HttpLaneExecutor, login: &LoginBlock) -> Result<(), HttpLaneError> {
        for (name, decl) in &login.tokens {
            let value = self.resolve(&decl.value);
            if value.trim().is_empty() || value.contains("{{") {
                continue;
            }
            let mut entry = serde_json::Map::new();
            entry.insert("value".into(), Value::String(value.clone()));
            if let Some(h) = &decl.header {
                entry.insert("header".into(), Value::String(h.clone()));
                let prefix = decl.prefix.clone().unwrap_or_default();
                exec.set_sticky_header(h, format!("{prefix}{value}"));
            }
            if let Some(p) = &decl.prefix {
                entry.insert("prefix".into(), Value::String(p.clone()));
            }
            self.tokens.insert(name.clone(), Value::Object(entry));
        }
        Ok(())
    }

    // ---- request + extraction helpers ----

    async fn run_recipe_request(&self, exec: &mut HttpLaneExecutor, spec: &RequestSpec) -> Result<HttpResponse, HttpLaneError> {
        self.run_recipe_request_with(exec, spec, None).await
    }

    async fn run_recipe_request_with(
        &self,
        exec: &mut HttpLaneExecutor,
        spec: &RequestSpec,
        challenge_code: Option<&str>,
    ) -> Result<HttpResponse, HttpLaneError> {
        let url = self.resolve_with_challenge(&spec.url, challenge_code);
        let mut headers = Vec::new();
        for (k, v) in &spec.headers {
            let val = self.resolve_with_challenge(v, challenge_code);
            if val.trim().is_empty() || val.contains("{{") || val.contains('\r') || val.contains('\n') {
                continue;
            }
            headers.push((k.clone(), val));
        }
        let body = spec.body.as_ref().map(|b| self.resolve_with_challenge(b, challenge_code));
        exec.request(&spec.method, &url, &headers, body).await
    }

    fn resolve(&self, s: &str) -> String {
        resolve_value_full(s, self.credentials, Some(self.form_data), None, Some(&self.vars))
    }

    /// Like [`resolve`] but also substitutes `{{challenge:code}}` with the resolved challenge code.
    fn resolve_with_challenge(&self, s: &str, challenge_code: Option<&str>) -> String {
        let out = self.resolve(s);
        match challenge_code {
            Some(code) => out.replace("{{challenge:code}}", code),
            None => out,
        }
    }

    fn apply_extractions(
        &mut self,
        exec: &mut HttpLaneExecutor,
        specs: &HashMap<String, ExtractSpec>,
        resp: &HttpResponse,
    ) -> Result<(), HttpLaneError> {
        for (name, spec) in specs {
            let value = extract_value(spec, resp, exec, &self.vars);
            match value {
                Some(v) => {
                    // store side-effects
                    if let Some(store) = &spec.store {
                        self.apply_store(exec, store, &v);
                    }
                    self.vars.insert(name.clone(), v);
                }
                None if spec.optional => {}
                None => {
                    return Err(HttpLaneError::Fallback(FallbackReason::AuthFailed));
                }
            }
        }
        Ok(())
    }

    fn apply_store(&mut self, exec: &mut HttpLaneExecutor, store: &StoreSpec, value: &Value) {
        let sval = value_to_string(value);
        match store.as_.as_str() {
            "header" => {
                if let Some(h) = &store.header {
                    let prefix = store.prefix.clone().unwrap_or_default();
                    exec.set_sticky_header(h, format!("{prefix}{sval}"));
                    let mut entry = serde_json::Map::new();
                    entry.insert("value".into(), Value::String(sval.clone()));
                    entry.insert("header".into(), Value::String(h.clone()));
                    if !prefix.is_empty() {
                        entry.insert("prefix".into(), Value::String(prefix));
                    }
                    self.tokens.insert(h.clone(), Value::Object(entry));
                }
            }
            "cookie" => {
                if let Some(name) = &store.cookie_name {
                    if let Some(dom) = exec.entry_registrable().map(|s| s.to_string()) {
                        exec.jar_mut().set_cookie(name, &sval, &dom, "/");
                    }
                }
            }
            _ => {} // "var" — already stored in vars by the caller
        }
    }

    fn expect_ok(&self, expect: Option<&ExpectSpec>, resp: &HttpResponse) -> bool {
        let Some(e) = expect else {
            return resp.status < 400; // default: any <400 is success
        };
        expect_matches(e, resp)
    }
}

// ---- free helpers ----------------------------------------------------------------------------

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// Whether a response satisfies an ExpectSpec (all present conditions must hold).
fn expect_matches(e: &ExpectSpec, resp: &HttpResponse) -> bool {
    if !e.status.is_empty() && !e.status.contains(&resp.status) {
        return false;
    }
    let final_url = resp.final_url.as_str().to_ascii_lowercase();
    for p in &e.url_patterns {
        if !final_url.contains(&p.to_ascii_lowercase()) {
            return false;
        }
    }
    for p in &e.not_url_patterns {
        if final_url.contains(&p.to_ascii_lowercase()) {
            return false;
        }
    }
    if let Some(re) = &e.body_regex {
        if let Ok(re) = regex::Regex::new(re) {
            if !re.is_match(&resp.body) {
                return false;
            }
        }
    }
    if let Some(re) = &e.not_body_regex {
        if let Ok(re) = regex::Regex::new(re) {
            if re.is_match(&resp.body) {
                return false;
            }
        }
    }
    if let Some(path) = &e.json_path_present {
        let data = resp.json.clone().unwrap_or(Value::Null);
        if json_value_path(&data, path).is_none() {
            return false;
        }
    }
    true
}

/// A challenge's `detect` matches when its (looser) conditions hold — status in the set OR body/json
/// signal. Unlike `expect`, an EMPTY detect never matches (avoid firing on every response).
fn detect_matches(detect: &ExpectSpec, resp: &HttpResponse) -> bool {
    let empty = detect.status.is_empty()
        && detect.url_patterns.is_empty()
        && detect.body_regex.is_none()
        && detect.json_path_present.is_none();
    if empty {
        return false;
    }
    expect_matches(detect, resp)
}

fn looks_like_challenge(resp: &HttpResponse) -> bool {
    let low = resp.body.to_ascii_lowercase();
    low.contains("cf-chl") || low.contains("cf-turnstile") || low.contains("just a moment")
        || low.contains("challenge-platform")
}

/// Resolve one extraction spec against a response / the jar / prior vars.
fn extract_value(
    spec: &ExtractSpec,
    resp: &HttpResponse,
    exec: &HttpLaneExecutor,
    vars: &HashMap<String, Value>,
) -> Option<Value> {
    match spec.from.as_str() {
        "json" => {
            let path = spec.path.as_deref()?;
            let data = resp.json.clone().unwrap_or(Value::Null);
            json_value_path(&data, path)
        }
        "html_css" => {
            let selector = spec.selector.as_deref()?;
            let mut cfg = serde_json::Map::new();
            cfg.insert("selector".into(), Value::String(selector.to_string()));
            if let Some(a) = &spec.attribute {
                cfg.insert("attribute".into(), Value::String(a.clone()));
            }
            let v = run_extractor(&resp.body, "css", &Value::Object(cfg), false, None);
            non_null(v)
        }
        "regex" => {
            let pattern = spec.pattern.as_deref()?;
            let cfg = serde_json::json!({ "pattern": pattern });
            let v = run_extractor(&resp.body, "regex", &cfg, false, None);
            non_null(v)
        }
        "header" => {
            let name = spec.name.as_deref()?.to_ascii_lowercase();
            resp.headers
                .iter()
                .find(|(k, _)| k.to_ascii_lowercase() == name)
                .map(|(_, v)| Value::String(v.clone()))
        }
        "cookie" => {
            let name = spec.name.as_deref()?;
            exec.cookie_value(name).map(Value::String)
        }
        "redirect_param" => {
            let param = spec.param.as_deref()?;
            for url in resp.redirect_chain.iter().chain(std::iter::once(&resp.final_url)) {
                if let Some((_, v)) = url.query_pairs().find(|(k, _)| k == param) {
                    return Some(Value::String(v.into_owned()));
                }
            }
            None
        }
        "jwt_claim" => {
            let source = spec.source.as_deref()?;
            let claim = spec.path.as_deref().or(spec.name.as_deref())?;
            let jwt = vars.get(source).and_then(|v| v.as_str())?;
            decode_jwt_claim(jwt, claim)
        }
        _ => None,
    }
}

fn non_null(v: Value) -> Option<Value> {
    if v.is_null() {
        None
    } else {
        Some(v)
    }
}

/// Decode a JWT payload claim (base64url middle segment; no signature verification).
fn decode_jwt_claim(jwt: &str, claim: &str) -> Option<Value> {
    use base64::Engine;
    let payload = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload).ok()?;
    let json: Value = serde_json::from_slice(&bytes).ok()?;
    json.get(claim).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipe_v1_fixture_roundtrips() {
        let raw = include_str!("../../../tests/fixtures/auth_recipe_v1.json");
        let recipe: AuthRecipe = serde_json::from_str(raw).expect("fixture parses");
        assert_eq!(recipe.version, 1);
        assert_eq!(recipe.kind, "http");
        let login = recipe.login.as_ref().expect("login block");
        assert_eq!(login.steps.len(), 2);
        // Second step posts credentials with a {{extracted:csrf}} and has a totp challenge.
        assert!(login.steps[1].request.body.as_ref().unwrap().contains("{{extracted:csrf}}"));
        assert_eq!(login.steps[1].challenges[0].kind, "totp");
        // Round-trip serialize → parse is stable.
        let out = serde_json::to_string(&recipe).unwrap();
        let _again: AuthRecipe = serde_json::from_str(&out).unwrap();
    }

    #[test]
    fn degenerate_from_login_post() {
        let r = AuthRecipe::degenerate(
            vec![RequestSpec {
                method: "POST".into(),
                url: "https://x/login".into(),
                headers: HashMap::new(),
                body: Some("u={{secret:user}}".into()),
            }],
            vec!["/login".into()],
        );
        assert_eq!(r.login.as_ref().unwrap().steps.len(), 1);
        assert_eq!(r.stale.as_ref().unwrap().status, vec![401, 403]);
    }

    #[test]
    fn jwt_claim_decode() {
        // {"exp":123,"sub":"abc"} base64url
        let jwt = "h.eyJleHAiOjEyMywic3ViIjoiYWJjIn0.s";
        assert_eq!(decode_jwt_claim(jwt, "sub"), Some(Value::String("abc".into())));
        assert_eq!(decode_jwt_claim(jwt, "exp"), Some(serde_json::json!(123)));
    }
}
