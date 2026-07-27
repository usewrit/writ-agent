use std::collections::HashMap;

use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub role: String,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub auth: Option<String>,
    #[serde(default)]
    pub bypassed: Option<bool>,
    #[serde(default)]
    pub exp: Option<u64>,
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

pub fn verify_push_jwt(token: &str, secret: &str) -> Option<Claims> {
    if secret.is_empty() {
        return None;
    }

    let key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.required_spec_claims.insert("exp".to_string());
    validation.validate_exp = true;

    let token_data = decode::<Claims>(token, &key, &validation).ok()?;

    if token_data.claims.role != "coordinator" {
        return None;
    }

    Some(token_data.claims)
}

pub fn verify_bearer(token: &str, secret: &str) -> bool {
    if secret.is_empty() {
        return false;
    }
    constant_time_eq(token.as_bytes(), secret.as_bytes())
}

pub fn authenticate_request(auth_header: &str, secret: &str) -> Option<Claims> {
    let token = auth_header.strip_prefix("Bearer ")?;

    if let Some(claims) = verify_push_jwt(token, secret) {
        return Some(claims);
    }

    if verify_bearer(token, secret) {
        return Some(Claims {
            role: "coordinator".to_string(),
            tenant_id: None,
            auth: Some("shared_secret".to_string()),
            bypassed: None,
            exp: None,
            extra: HashMap::new(),
        });
    }

    None
}

pub fn authenticate_ws_token(
    query_token: Option<&str>,
    auth_header: Option<&str>,
    secret: &str,
    is_dev_bypass: bool,
) -> Option<Claims> {
    if let Some(token) = query_token {
        if !token.is_empty() {
            let header = format!("Bearer {}", token);
            if let Some(claims) = authenticate_request(&header, secret) {
                return Some(claims);
            }
        }
    }

    if let Some(header) = auth_header {
        if let Some(claims) = authenticate_request(header, secret) {
            return Some(claims);
        }
    }

    if is_dev_bypass {
        return Some(Claims {
            role: "coordinator".to_string(),
            tenant_id: None,
            auth: None,
            bypassed: Some(true),
            exp: None,
            extra: HashMap::new(),
        });
    }

    None
}

/// Defense-in-depth WS auth for the (dev-only) local axum server. Pulls a
/// `?token=` query param and the `Authorization` header out of an axum request
/// and validates them with `authenticate_ws_token`. Returns true if authorized.
/// `auth_bypass` should come from `AppConfig::auth_bypass_enabled()` (explicit
/// opt-in only — see config::env).
pub fn ws_request_authorized(
    query: &std::collections::HashMap<String, String>,
    headers: &axum::http::HeaderMap,
    secret: &str,
    auth_bypass: bool,
) -> bool {
    let query_token = query.get("token").map(|s| s.as_str());
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    authenticate_ws_token(query_token, auth_header, secret, auth_bypass).is_some()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn make_jwt(role: &str, secret: &str, exp_offset_secs: i64) -> String {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = serde_json::json!({
            "role": role,
            "exp": (now as i64 + exp_offset_secs) as u64,
            "tenant_id": "test-tenant",
        });

        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn test_valid_jwt() {
        let secret = "test-secret-key";
        let token = make_jwt("coordinator", secret, 3600);
        let claims = verify_push_jwt(&token, secret);
        assert!(claims.is_some());
        assert_eq!(claims.unwrap().role, "coordinator");
    }

    #[test]
    fn test_wrong_role_jwt() {
        let secret = "test-secret-key";
        let token = make_jwt("user", secret, 3600);
        assert!(verify_push_jwt(&token, secret).is_none());
    }

    #[test]
    fn test_expired_jwt() {
        let secret = "test-secret-key";
        let token = make_jwt("coordinator", secret, -3600);
        assert!(verify_push_jwt(&token, secret).is_none());
    }

    #[test]
    fn test_wrong_secret_jwt() {
        let token = make_jwt("coordinator", "secret-1", 3600);
        assert!(verify_push_jwt(&token, "secret-2").is_none());
    }

    #[test]
    fn test_empty_secret_jwt() {
        let token = make_jwt("coordinator", "some-secret", 3600);
        assert!(verify_push_jwt(&token, "").is_none());
    }

    #[test]
    fn test_bearer_valid() {
        assert!(verify_bearer("my-secret", "my-secret"));
    }

    #[test]
    fn test_bearer_invalid() {
        assert!(!verify_bearer("wrong", "my-secret"));
    }

    #[test]
    fn test_bearer_empty_secret() {
        assert!(!verify_bearer("any", ""));
    }

    #[test]
    fn test_authenticate_request_jwt() {
        let secret = "test-secret";
        let token = make_jwt("coordinator", secret, 3600);
        let header = format!("Bearer {}", token);
        let claims = authenticate_request(&header, secret);
        assert!(claims.is_some());
        assert_eq!(claims.unwrap().role, "coordinator");
    }

    #[test]
    fn test_authenticate_request_bearer() {
        let secret = "shared-secret-123";
        let header = format!("Bearer {}", secret);
        let claims = authenticate_request(&header, secret);
        assert!(claims.is_some());
        assert_eq!(claims.unwrap().auth.as_deref(), Some("shared_secret"));
    }

    #[test]
    fn test_authenticate_request_no_bearer_prefix() {
        assert!(authenticate_request("Basic xyz", "secret").is_none());
    }

    #[test]
    fn test_ws_token_from_query() {
        let secret = "ws-secret";
        let claims = authenticate_ws_token(Some(secret), None, secret, false);
        assert!(claims.is_some());
    }

    #[test]
    fn test_ws_token_from_header() {
        let secret = "ws-secret";
        let header = format!("Bearer {}", secret);
        let claims = authenticate_ws_token(None, Some(&header), secret, false);
        assert!(claims.is_some());
    }

    #[test]
    fn test_ws_token_dev_bypass() {
        let claims = authenticate_ws_token(None, None, "", true);
        assert!(claims.is_some());
        assert_eq!(claims.unwrap().bypassed, Some(true));
    }

    #[test]
    fn test_ws_token_no_auth() {
        assert!(authenticate_ws_token(None, None, "secret", false).is_none());
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }
}
