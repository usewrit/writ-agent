//! Minimal robots.txt admission for the Dragnet crawl — per-origin fetch + parse, cached in-process
//! for the crawl's lifetime. Fail-OPEN by design (matching the cloud `robots_guard`): a fetch error,
//! a non-200, or an unparsable file all yield "allowed", so a missing/broken robots.txt never stalls
//! a crawl. Only the `User-agent: *` group is honored (longest-match Allow/Disallow, Allow wins ties)
//! — enough for the politeness contract without a full RFC 9309 engine.

use std::collections::HashMap;
use url::Url;

/// Ceiling on the number of Allow/Disallow directives kept from ONE origin's robots.txt.
///
/// WHY: the rules are cached per origin for the WHOLE crawl and re-scanned LINEARLY for every
/// admitted URL ([`RobotsRules::allowed`]), so an unbounded rule list is a CPU bomb as much as a heap
/// one — a 20 MB robots.txt with ~1 M directives means ~1 M string comparisons per URL admitted.
/// Real robots.txt files carry tens of rules; the largest in the wild are in the low thousands.
/// Directives past the cap are ignored, which is the same fail-OPEN direction the rest of this module
/// already takes for a broken/missing file.
const MAX_RULES: usize = 4_000;

/// The Allow/Disallow rules distilled from one origin's robots.txt `User-agent: *` group.
#[derive(Debug, Clone, Default)]
pub struct RobotsRules {
    allow: Vec<String>,
    disallow: Vec<String>,
}

impl RobotsRules {
    /// Is `path` (the URL path, e.g. `/docs/x`) fetchable? Longest-matching directive wins; an Allow
    /// beats a Disallow of equal specificity. No matching rule → allowed.
    pub fn allowed(&self, path: &str) -> bool {
        let path = if path.is_empty() { "/" } else { path };
        let mut best_len: i64 = -1;
        let mut decision = true;
        for a in &self.allow {
            if path_matches(path, a) && a.len() as i64 >= best_len {
                best_len = a.len() as i64;
                decision = true;
            }
        }
        for d in &self.disallow {
            // An empty Disallow ("Disallow:") means "allow everything" — never blocks.
            if d.is_empty() {
                continue;
            }
            if path_matches(path, d) && d.len() as i64 > best_len {
                best_len = d.len() as i64;
                decision = false;
            }
        }
        decision
    }
}

/// Prefix match with a trailing-`*` wildcard tolerance (`/api/*` behaves like the prefix `/api/`).
fn path_matches(path: &str, rule: &str) -> bool {
    let rule = rule.strip_suffix('*').unwrap_or(rule);
    path.starts_with(rule)
}

/// Parse a robots.txt body into the `User-agent: *` group's rules. Groups are delimited by
/// `User-agent:` lines; a directive belongs to the star group iff a `User-agent: *` preceded it in
/// the current contiguous group of agent lines.
pub fn parse(body: &str) -> RobotsRules {
    let mut rules = RobotsRules::default();
    let mut group_is_star = false;
    let mut in_agent_block = false; // consecutive `User-agent:` lines form one group header
    for raw in body.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((field, value)) = line.split_once(':') else { continue };
        let field = field.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        match field.as_str() {
            "user-agent" => {
                if !in_agent_block {
                    // Starting a NEW group header — reset applicability.
                    group_is_star = false;
                }
                in_agent_block = true;
                if value == "*" {
                    group_is_star = true;
                }
            }
            "disallow" => {
                in_agent_block = false;
                if group_is_star && rules.allow.len() + rules.disallow.len() < MAX_RULES {
                    rules.disallow.push(value);
                }
            }
            "allow" => {
                in_agent_block = false;
                if group_is_star && rules.allow.len() + rules.disallow.len() < MAX_RULES {
                    rules.allow.push(value);
                }
            }
            _ => {
                in_agent_block = false;
            }
        }
    }
    rules
}

/// Per-origin robots cache for one crawl. `None` cached value = "fetched, none applicable / fail-open".
#[derive(Default)]
pub struct RobotsCache {
    by_origin: HashMap<String, RobotsRules>,
}

impl RobotsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Is `url` allowed for the star agent? Fetches + caches the origin's robots.txt on first sight.
    /// Fail-open on any error. `client` is the crawl's shared reqwest client.
    pub async fn allowed(&mut self, client: &reqwest::Client, url: &str) -> bool {
        let Ok(parsed) = Url::parse(url) else { return true };
        let origin = match (parsed.scheme(), parsed.host_str()) {
            (scheme, Some(host)) => {
                let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
                format!("{scheme}://{host}{port}")
            }
            _ => return true,
        };
        if !self.by_origin.contains_key(&origin) {
            let rules = fetch_rules(client, &origin).await;
            self.by_origin.insert(origin.clone(), rules);
        }
        let path = parsed.path();
        self.by_origin.get(&origin).map(|r| r.allowed(path)).unwrap_or(true)
    }
}

/// Fetch + parse one origin's robots.txt. Any failure → empty (allow-all) rules.
async fn fetch_rules(client: &reqwest::Client, origin: &str) -> RobotsRules {
    let url = format!("{origin}/robots.txt");
    match client.get(&url).send().await {
        // BOUNDED read (512 KiB, the de-facto robots.txt limit). reqwest transparently gunzips, so an
        // uncapped `text()` here let a gzipped robots.txt inflate ~1000x into the heap; an oversized
        // file now fails open (allow-all) exactly like an unreachable one.
        Ok(resp) if resp.status().is_success() => {
            match crate::crawl_shard::body_limit::read_text_capped(
                resp,
                crate::crawl_shard::body_limit::ROBOTS_MAX,
            )
            .await
            {
                Ok(body) => parse(&body),
                Err(e) => {
                    tracing::debug!(%url, error = %e, "robots.txt not usable; failing open");
                    RobotsRules::default()
                }
            }
        }
        _ => RobotsRules::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn star_group_disallow_blocks_prefix() {
        let r = parse("User-agent: *\nDisallow: /private\nAllow: /private/ok\n");
        assert!(!r.allowed("/private"), "disallowed prefix");
        assert!(!r.allowed("/private/secret"));
        assert!(r.allowed("/private/ok"), "longer Allow wins");
        assert!(r.allowed("/public"));
        assert!(r.allowed("/"));
    }

    #[test]
    fn non_star_group_is_ignored() {
        // Rules under a specific agent don't apply to the star crawler.
        let r = parse("User-agent: BadBot\nDisallow: /\n\nUser-agent: *\nDisallow: /admin\n");
        assert!(r.allowed("/anything"));
        assert!(!r.allowed("/admin/panel"));
    }

    #[test]
    fn empty_disallow_allows_all() {
        let r = parse("User-agent: *\nDisallow:\n");
        assert!(r.allowed("/whatever"));
    }

    #[test]
    fn wildcard_suffix_is_prefix() {
        let r = parse("User-agent: *\nDisallow: /search/*\n");
        assert!(!r.allowed("/search/results"));
        assert!(r.allowed("/other"));
    }

    #[test]
    fn no_robots_content_allows_all() {
        let r = parse("");
        assert!(r.allowed("/x"));
    }

    /// A hostile robots.txt must not mint an unbounded rule list: the rules are cached for the whole
    /// crawl and rescanned linearly for EVERY admitted URL, so 1 M directives = 1 M compares per URL.
    #[test]
    fn rule_count_is_capped() {
        let mut body = String::from("User-agent: *\n");
        // Fill the budget with one namespace, then keep going in a DIFFERENT namespace so the
        // over-cap rules cannot be satisfied by prefix-matching one of the kept ones.
        for i in 0..MAX_RULES {
            body.push_str(&format!("Disallow: /kept/{i}\n"));
        }
        for i in 0..500 {
            body.push_str(&format!("Disallow: /dropped/{i}\n"));
        }
        let r = parse(&body);
        assert_eq!(r.allow.len() + r.disallow.len(), MAX_RULES, "rule list not capped");
        // Rules kept are the FIRST ones, and they still work.
        assert!(!r.allowed("/kept/0"));
        // A directive past the cap is ignored — fail-open, the same direction as a missing file.
        assert!(r.allowed("/dropped/0"));
    }
}
