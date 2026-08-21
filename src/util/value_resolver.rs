use std::collections::HashMap;
use regex::Regex;

/// Resolves template placeholders in a value string.
///
/// Replacement order:
/// 1. `{{secret:key}}` — looked up from `credentials`
/// 2. `{{key}}` — looked up from `form_data` (if provided)
///
/// Unmatched placeholders are left as-is.
pub fn resolve_value(
    value: &str,
    credentials: &HashMap<String, String>,
    form_data: Option<&HashMap<String, String>>,
) -> String {
    resolve_value_with_files(value, credentials, form_data, None)
}

/// Like [`resolve_value`] but with an additional FIRST pass for `{{file:slot}}`
/// (File assets §6.3): a file slot resolves to the local temp path of the file
/// fetched for that slot in this run. The `files` map is `slot -> local path`,
/// populated by the upload/value-resolution path as it fetches stored files.
///
/// Replacement order (so a more specific prefix wins before the generic `{{key}}`):
/// 1. `{{file:slot}}` — looked up from `files`
/// 2. `{{secret:key}}` — looked up from `credentials`
/// 3. `{{key}}` — looked up from `form_data` (if provided)
///
/// Unmatched placeholders are left as-is.
pub fn resolve_value_with_files(
    value: &str,
    credentials: &HashMap<String, String>,
    form_data: Option<&HashMap<String, String>>,
    files: Option<&HashMap<String, String>>,
) -> String {
    resolve_value_full(value, credentials, form_data, files, None)
}

/// Renders a JSON value into the string form used when substituting `{{extracted:key}}`
/// into a request URL / header / body:
/// - a JSON string → its contents (no surrounding quotes)
/// - a number / bool → its literal text
/// - an object / array → compact JSON (`{"a":1}`)
/// - null → the caller treats "no value", so this returns `None`
///
/// Mirrors the Python agent's stringification so extracted values chain identically
/// across engines.
fn extracted_to_string(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        other => serde_json::to_string(other).ok(),
    }
}

/// The full resolver used by the request lanes (api_call / login_post, both the
/// browser in-page fetch and the browserless HTTP lane).
///
/// Replacement order (prefixed forms before the generic `{{key}}` so a specific
/// prefix never falls through to a form-data lookup):
/// 1. `{{file:slot}}`      — from `files`
/// 2. `{{extracted:key}}`  — from a prior step's extractions / recipe vars (`extracted`)
/// 3. `{{secret:key}}`     — from `credentials`
/// 4. `{{key}}`            — from `form_data`
///
/// Unmatched placeholders (and `{{extracted:key}}` whose value is JSON null) are
/// left verbatim, matching the other passes.
pub fn resolve_value_full(
    value: &str,
    credentials: &HashMap<String, String>,
    form_data: Option<&HashMap<String, String>>,
    files: Option<&HashMap<String, String>>,
    extracted: Option<&HashMap<String, serde_json::Value>>,
) -> String {
    let mut result = value.to_string();

    // Pass 1: replace {{file:slot}} from the run-level fetched-file paths. Done
    // BEFORE the generic {{key}} pass so `file:` is never mis-resolved as a form key.
    if let Some(fm) = files {
        let file_re = Regex::new(r"\{\{file:([^}]+)\}\}").expect("invalid file regex");
        result = file_re
            .replace_all(&result, |caps: &regex::Captures| {
                let slot = caps[1].trim();
                fm.get(slot)
                    .cloned()
                    .unwrap_or_else(|| caps[0].to_string())
            })
            .into_owned();
    }

    // Pass 2: replace {{extracted:key}} from prior-step extractions / recipe vars.
    if let Some(ex) = extracted {
        let ex_re = Regex::new(r"\{\{extracted:([^}]+)\}\}").expect("invalid extracted regex");
        result = ex_re
            .replace_all(&result, |caps: &regex::Captures| {
                let key = caps[1].trim();
                ex.get(key)
                    .and_then(extracted_to_string)
                    .unwrap_or_else(|| caps[0].to_string())
            })
            .into_owned();
    }

    // Pass 3: replace {{secret:key}} from credentials
    let secret_re = Regex::new(r"\{\{secret:([^}]+)\}\}").expect("invalid secret regex");
    result = secret_re
        .replace_all(&result, |caps: &regex::Captures| {
            let key = &caps[1];
            match credentials.get(key) {
                Some(v) => v.clone(),
                None => {
                    // Leave the placeholder VERBATIM (never an empty string): a login step
                    // that types "" looks like a wrong password and the run still reports
                    // success, banking an anonymous session. The literal is at least
                    // diagnosable on the page. Names only, never values.
                    tracing::warn!(
                        secret_key = %key,
                        available = ?{
                            let mut k: Vec<&str> = credentials.keys().map(|s| s.as_str()).collect();
                            k.sort_unstable();
                            k
                        },
                        "unresolved {{secret:…}} placeholder — left verbatim"
                    );
                    caps[0].to_string()
                }
            }
        })
        .into_owned();

    // Pass 4: replace {{key}} from form_data
    if let Some(fd) = form_data {
        let form_re = Regex::new(r"\{\{([^}]+)\}\}").expect("invalid form regex");
        result = form_re
            .replace_all(&result, |caps: &regex::Captures| {
                let key = &caps[1];
                fd.get(key)
                    .cloned()
                    .unwrap_or_else(|| caps[0].to_string())
            })
            .into_owned();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_secrets() {
        let mut creds = HashMap::new();
        creds.insert("password".to_string(), "s3cret".to_string());

        let out = resolve_value("my pass is {{secret:password}}", &creds, None);
        assert_eq!(out, "my pass is s3cret");
    }

    #[test]
    fn test_resolve_form_data() {
        let creds = HashMap::new();
        let mut fd = HashMap::new();
        fd.insert("name".to_string(), "Alice".to_string());

        let out = resolve_value("Hello {{name}}", &creds, Some(&fd));
        assert_eq!(out, "Hello Alice");
    }

    #[test]
    fn test_secrets_before_form_data() {
        let mut creds = HashMap::new();
        creds.insert("token".to_string(), "abc123".to_string());
        let mut fd = HashMap::new();
        fd.insert("greeting".to_string(), "Hi".to_string());

        let out = resolve_value("{{greeting}} {{secret:token}}", &creds, Some(&fd));
        assert_eq!(out, "Hi abc123");
    }

    #[test]
    fn test_unresolved_placeholders_kept() {
        let creds = HashMap::new();
        let out = resolve_value("{{secret:missing}} and {{also_missing}}", &creds, None);
        assert_eq!(out, "{{secret:missing}} and {{also_missing}}");
    }

    #[test]
    fn test_no_placeholders() {
        let creds = HashMap::new();
        let out = resolve_value("plain text", &creds, None);
        assert_eq!(out, "plain text");
    }

    #[test]
    fn test_resolve_file_slot_to_path() {
        let creds = HashMap::new();
        let mut files = HashMap::new();
        files.insert("resume".to_string(), "/tmp/psfile_abc.pdf".to_string());

        let out = resolve_value_with_files(
            "open {{file:resume}}",
            &creds,
            None,
            Some(&files),
        );
        assert_eq!(out, "open /tmp/psfile_abc.pdf");
    }

    #[test]
    fn test_file_slot_resolved_before_form_data() {
        // {{file:resume}} must NOT be mis-resolved as a form key "file:resume".
        let creds = HashMap::new();
        let mut fd = HashMap::new();
        fd.insert("file:resume".to_string(), "WRONG".to_string());
        let mut files = HashMap::new();
        files.insert("resume".to_string(), "/tmp/p.pdf".to_string());

        let out = resolve_value_with_files(
            "{{file:resume}}",
            &creds,
            Some(&fd),
            Some(&files),
        );
        assert_eq!(out, "/tmp/p.pdf");
    }

    #[test]
    fn test_unresolved_file_slot_kept() {
        let creds = HashMap::new();
        let files = HashMap::new();
        let out = resolve_value_with_files("{{file:missing}}", &creds, None, Some(&files));
        assert_eq!(out, "{{file:missing}}");
    }

    #[test]
    fn test_resolve_extracted_string() {
        let creds = HashMap::new();
        let mut ex = HashMap::new();
        ex.insert("token".to_string(), serde_json::json!("abc123"));
        let out = resolve_value_full(
            "Bearer {{extracted:token}}",
            &creds,
            None,
            None,
            Some(&ex),
        );
        assert_eq!(out, "Bearer abc123");
    }

    #[test]
    fn test_resolve_extracted_number_bool_object() {
        let creds = HashMap::new();
        let mut ex = HashMap::new();
        ex.insert("n".to_string(), serde_json::json!(42));
        ex.insert("b".to_string(), serde_json::json!(true));
        ex.insert("o".to_string(), serde_json::json!({"a": 1}));
        let out = resolve_value_full(
            "{{extracted:n}}|{{extracted:b}}|{{extracted:o}}",
            &creds,
            None,
            None,
            Some(&ex),
        );
        assert_eq!(out, r#"42|true|{"a":1}"#);
    }

    #[test]
    fn test_extracted_before_form_and_secret() {
        // {{extracted:x}} must NOT be mis-resolved as a form/secret key.
        let mut creds = HashMap::new();
        creds.insert("extracted:x".to_string(), "WRONG".to_string());
        let mut fd = HashMap::new();
        fd.insert("extracted:x".to_string(), "ALSO_WRONG".to_string());
        let mut ex = HashMap::new();
        ex.insert("x".to_string(), serde_json::json!("right"));
        let out = resolve_value_full("{{extracted:x}}", &creds, Some(&fd), None, Some(&ex));
        assert_eq!(out, "right");
    }

    #[test]
    fn test_extracted_null_kept() {
        let creds = HashMap::new();
        let mut ex = HashMap::new();
        ex.insert("nope".to_string(), serde_json::Value::Null);
        let out = resolve_value_full("{{extracted:nope}}", &creds, None, None, Some(&ex));
        assert_eq!(out, "{{extracted:nope}}");
    }

    #[test]
    fn test_extracted_missing_kept() {
        let creds = HashMap::new();
        let ex: HashMap<String, serde_json::Value> = HashMap::new();
        let out = resolve_value_full("{{extracted:gone}}", &creds, None, None, Some(&ex));
        assert_eq!(out, "{{extracted:gone}}");
    }
}
