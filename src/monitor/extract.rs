//! Field-extractor engine for `selector_extractors`.
//!
//! A monitor selector captures a blob of content (text / html / a visual hash). A *field extractor*
//! turns that blob into a typed value — a price, a SKU, an array of titles — via one of five
//! `extract_type`s. This module is the single, transport-agnostic implementation of that step, used
//! by the `/v1/extractors/.../test` routes (and ready to wire into the live check pipeline).
//!
//! All extractors are total: a miss (no match, bad selector, unparseable JSON) yields the extractor's
//! `default_value` (or JSON `null`), never an error — a check must never fail because one optional
//! field didn't resolve.
//!
//! `config` is the extractor's stored JSON object; the keys each type reads:
//!   * `text`      — none. Returns the content trimmed (array: non-empty lines).
//!   * `regex`     — `pattern` (required), `group` (optional capture index; default 1 if the pattern
//!                   has a capture group, else 0). Array: every match of that group.
//!   * `css`       — `selector` (required), `attribute` (optional; text when absent). Array: every node.
//!   * `attribute` — `attribute` (required), `selector` (optional; first element when absent).
//!   * `json_path` — `path` (required); a minimal `$.a.b[0]`-style path. Array: a resolved array as-is.

use serde_json::Value;

/// Run one extractor over `content`. Never panics; a miss returns `default` (as a string value) or
/// `Value::Null`. `is_array` selects the multi-match shape where the type supports it.
pub fn run_extractor(
    content: &str,
    extract_type: &str,
    config: &Value,
    is_array: bool,
    default: Option<&str>,
) -> Value {
    let resolved = match extract_type {
        "text" => extract_text(content, is_array),
        "regex" => extract_regex(content, config, is_array),
        "css" => extract_css(content, config, is_array),
        "attribute" => extract_attribute(content, config, is_array),
        "json_path" | "json" => extract_json_path(content, config, is_array),
        _ => None,
    };
    resolved.unwrap_or_else(|| default_value(default, is_array))
}

/// The fallback when an extractor misses: the configured default as a string (or an empty array when
/// `is_array`), else `null`.
fn default_value(default: Option<&str>, is_array: bool) -> Value {
    match default {
        Some(d) => {
            if is_array {
                Value::Array(vec![Value::String(d.to_string())])
            } else {
                Value::String(d.to_string())
            }
        }
        None => {
            if is_array {
                Value::Array(Vec::new())
            } else {
                Value::Null
            }
        }
    }
}

fn extract_text(content: &str, is_array: bool) -> Option<Value> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    if is_array {
        let lines: Vec<Value> = trimmed
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|l| Value::String(l.to_string()))
            .collect();
        Some(Value::Array(lines))
    } else {
        Some(Value::String(trimmed.to_string()))
    }
}

fn extract_regex(content: &str, config: &Value, is_array: bool) -> Option<Value> {
    let pattern = config.get("pattern").and_then(Value::as_str)?;
    // Bounded compile so a pathological pattern can't blow up memory (single-user local, but cheap).
    let re = regex::RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .ok()?;
    // Which capture to return: explicit `group`, else group 1 when the pattern has one, else whole.
    let group = config
        .get("group")
        .and_then(Value::as_u64)
        .map(|g| g as usize)
        .unwrap_or(if re.captures_len() > 1 { 1 } else { 0 });

    let pick = |caps: regex::Captures| caps.get(group).map(|m| m.as_str().to_string());

    if is_array {
        let all: Vec<Value> = re
            .captures_iter(content)
            .filter_map(pick)
            .map(Value::String)
            .collect();
        if all.is_empty() {
            None
        } else {
            Some(Value::Array(all))
        }
    } else {
        re.captures(content).and_then(pick).map(Value::String)
    }
}

fn extract_css(content: &str, config: &Value, is_array: bool) -> Option<Value> {
    let selector = config.get("selector").and_then(Value::as_str)?;
    let attribute = config.get("attribute").and_then(Value::as_str);
    select_nodes(content, selector, attribute, is_array)
}

fn extract_attribute(content: &str, config: &Value, is_array: bool) -> Option<Value> {
    let attribute = config.get("attribute").and_then(Value::as_str)?;
    // `selector` is optional: with none, read the attribute off the fragment's first element.
    let selector = config.get("selector").and_then(Value::as_str).unwrap_or("*");
    select_nodes(content, selector, Some(attribute), is_array)
}

/// Parse `content` as an HTML fragment, run `selector`, and collect each node's `attribute` value (or
/// its text when `attribute` is None). `None` if the selector is invalid or nothing matched.
fn select_nodes(content: &str, selector: &str, attribute: Option<&str>, is_array: bool) -> Option<Value> {
    let frag = scraper::Html::parse_fragment(content);
    let css = scraper::Selector::parse(selector).ok()?;
    let mut out: Vec<String> = Vec::new();
    for el in frag.select(&css) {
        let val = match attribute {
            Some(attr) => el.value().attr(attr).map(str::to_string),
            None => {
                let t = el.text().collect::<Vec<_>>().join("").trim().to_string();
                if t.is_empty() {
                    None
                } else {
                    Some(t)
                }
            }
        };
        if let Some(v) = val {
            out.push(v);
            if !is_array {
                break;
            }
        }
    }
    if out.is_empty() {
        return None;
    }
    if is_array {
        Some(Value::Array(out.into_iter().map(Value::String).collect()))
    } else {
        Some(Value::String(out.into_iter().next().unwrap()))
    }
}

fn extract_json_path(content: &str, config: &Value, is_array: bool) -> Option<Value> {
    let path = config.get("path").and_then(Value::as_str)?;
    let root: Value = serde_json::from_str(content).ok()?;
    let found = json_path_get(&root, path)?;
    if is_array {
        match found {
            Value::Array(_) => Some(found),
            other => Some(Value::Array(vec![other])),
        }
    } else {
        Some(found)
    }
}

/// Resolve a minimal JSONPath-ish expression against an already-parsed JSON value. This is the shared
/// entry point used by `response_extractions` (api_call / the HTTP lane), where the response body is
/// already a `serde_json::Value` rather than a string. Same minimal dialect as [`json_path_get`].
pub fn json_value_path(root: &Value, path: &str) -> Option<Value> {
    json_path_get(root, path)
}

/// Resolve a minimal JSONPath-ish expression against `root`. Supports dotted keys and bracket indices:
/// `$.a.b[0].c`, `a.b`, `[0].name`. Returns `None` on any miss. Not a full JSONPath (no wildcards or
/// filters) — deliberately small and dependency-free; covers the shapes the extractor UI emits.
fn json_path_get(root: &Value, path: &str) -> Option<Value> {
    let mut cur = root;
    let trimmed = path.trim().trim_start_matches('$');
    for raw in trimmed.split('.') {
        let seg = raw.trim();
        if seg.is_empty() {
            continue;
        }
        // A segment may be `key`, `key[2]`, `key[2][3]`, or a bare `[2]`.
        let (key, indices) = split_key_indices(seg);
        if !key.is_empty() {
            cur = cur.get(key)?;
        }
        for idx in indices {
            cur = cur.get(idx)?;
        }
    }
    Some(cur.clone())
}

/// Split `key[1][2]` → ("key", [1, 2]); `[0]` → ("", [0]); `key` → ("key", []).
fn split_key_indices(seg: &str) -> (&str, Vec<usize>) {
    let bracket = seg.find('[');
    let key = match bracket {
        Some(b) => &seg[..b],
        None => seg,
    };
    let mut indices = Vec::new();
    if let Some(b) = bracket {
        for part in seg[b..].split(']') {
            let p = part.trim_start_matches('[').trim();
            if p.is_empty() {
                continue;
            }
            if let Ok(n) = p.parse::<usize>() {
                indices.push(n);
            }
        }
    }
    (key, indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_scalar_and_array() {
        assert_eq!(run_extractor("  hello  ", "text", &json!({}), false, None), json!("hello"));
        assert_eq!(
            run_extractor("a\n\n b \nc", "text", &json!({}), true, None),
            json!(["a", "b", "c"])
        );
    }

    #[test]
    fn regex_group_and_default_group() {
        // Explicit capture group 1.
        assert_eq!(
            run_extractor("Price: $19.99", "regex", &json!({"pattern": r"\$([0-9.]+)"}), false, None),
            json!("19.99")
        );
        // No capture group → whole match.
        assert_eq!(
            run_extractor("abc123", "regex", &json!({"pattern": r"[0-9]+"}), false, None),
            json!("123")
        );
        // Array: every match of the group.
        assert_eq!(
            run_extractor("a1 b2 c3", "regex", &json!({"pattern": r"([a-z])[0-9]"}), true, None),
            json!(["a", "b", "c"])
        );
    }

    #[test]
    fn css_text_and_attribute() {
        let html = r#"<ul><li class="t">One</li><li class="t">Two</li></ul>"#;
        assert_eq!(
            run_extractor(html, "css", &json!({"selector": "li.t"}), false, None),
            json!("One")
        );
        assert_eq!(
            run_extractor(html, "css", &json!({"selector": "li.t"}), true, None),
            json!(["One", "Two"])
        );
        let a = r#"<a href="/x" data-id="42">go</a>"#;
        assert_eq!(
            run_extractor(a, "css", &json!({"selector": "a", "attribute": "data-id"}), false, None),
            json!("42")
        );
    }

    #[test]
    fn attribute_with_and_without_selector() {
        let html = r#"<img src="/p.png" alt="pic">"#;
        assert_eq!(
            run_extractor(html, "attribute", &json!({"attribute": "src"}), false, None),
            json!("/p.png")
        );
        assert_eq!(
            run_extractor(html, "attribute", &json!({"selector": "img", "attribute": "alt"}), false, None),
            json!("pic")
        );
    }

    #[test]
    fn json_path_nested_and_indexed() {
        let body = r#"{"data":{"items":[{"price":10},{"price":20}]}}"#;
        assert_eq!(
            run_extractor(body, "json_path", &json!({"path": "$.data.items[0].price"}), false, None),
            json!(10)
        );
        assert_eq!(
            run_extractor(body, "json_path", &json!({"path": "data.items[1].price"}), false, None),
            json!(20)
        );
        // Resolving an array with is_array returns it as-is.
        assert_eq!(
            run_extractor(body, "json_path", &json!({"path": "data.items"}), true, None),
            json!([{"price": 10}, {"price": 20}])
        );
    }

    #[test]
    fn miss_falls_back_to_default() {
        // No regex match → default string.
        assert_eq!(
            run_extractor("nothing", "regex", &json!({"pattern": r"\d+"}), false, Some("0")),
            json!("0")
        );
        // No default, scalar → null; array → [].
        assert_eq!(run_extractor("nothing", "regex", &json!({"pattern": r"\d+"}), false, None), Value::Null);
        assert_eq!(
            run_extractor("nothing", "css", &json!({"selector": ".missing"}), true, None),
            json!([])
        );
        // Unknown extract_type → default.
        assert_eq!(run_extractor("x", "bogus", &json!({}), false, Some("d")), json!("d"));
    }
}
