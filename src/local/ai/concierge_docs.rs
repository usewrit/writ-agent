//! Concierge knowledge base (desktop) — the docs the AI concierge reads on demand.
//!
//! When the user asks "how do I call this workflow?", the concierge retrieves the most
//! relevant entries here and answers grounded in BOTH these docs and the session's REAL
//! resource (workflow id + the endpoints it enabled). Endpoints use the DAEMON paths and
//! the local `wlk_` key prefix. Mirrors the cloud KB (the cloud backend's `concierge_docs` service).

/// One doc entry: (id, tags, title, body). `tags` are space-separated keywords for retrieval.
pub struct Doc {
    pub id: &'static str,
    pub tags: &'static str,
    pub title: &'static str,
    pub body: &'static str,
}

pub const DOCS: &[Doc] = &[
    Doc {
        id: "call_workflow_rest",
        tags: "call run invoke rest api endpoint curl http trigger execute how to use workflow",
        title: "Call a workflow over REST",
        body: "Run a workflow with a POST to its run endpoint:\n  POST /v1/workflows/{id}/run\nBody (optional inputs): {\"inputs\": {\"key\": \"value\"}} — injected at run time via {{key}} placeholders. Returns {task_id|run_id, status}.\nAuth: header `Authorization: Bearer wlk_YOUR_KEY`.\ncurl -X POST {ORIGIN}/v1/workflows/{id}/run -H \"Authorization: Bearer wlk_YOUR_KEY\" -H \"Content-Type: application/json\" -d '{\"inputs\": {}}'",
    },
    Doc {
        id: "call_workflow_openai",
        tags: "openai compatible chat completions sdk model responses base_url gpt llm call workflow",
        title: "Call a workflow as an OpenAI-compatible endpoint",
        body: "Each workflow exposes an OpenAI-compatible base at /v1/workflows/{id}/v1 — point any OpenAI SDK at it.\n  POST /v1/workflows/{id}/v1/chat/completions\n  GET  /v1/workflows/{id}/v1/models\nUse model name \"default\". Auth header `Authorization: Bearer wlk_YOUR_KEY`.\nfrom openai import OpenAI\nclient = OpenAI(base_url=\"{ORIGIN}/v1/workflows/{id}/v1\", api_key=\"wlk_YOUR_KEY\")\nclient.chat.completions.create(model=\"default\", messages=[{\"role\":\"user\",\"content\":\"run\"}])",
    },
    Doc {
        id: "call_workflow_mcp",
        tags: "mcp tool model context protocol claude connect agent",
        title: "Use a workflow as an MCP tool",
        body: "Enable the MCP surface on the workflow's Connect tab; the workflow (and its callable functions) then appear as MCP tools an AI agent can call. Authentication uses the same `wlk_` API key as a Bearer token.",
    },
    Doc {
        id: "api_keys",
        tags: "api key create token authorization bearer scope permission secret wlk_ access how to authenticate",
        title: "Create and use an API key",
        body: "Create a local key: POST /v1/keys with {\"name\": \"...\", \"scopes\": \"read|run\"} — it returns the plaintext `key` ONCE (copy it now; never shown again). scopes is a coarse CSV: read|run|admin (admin includes run includes read).\nUse it on every call: header `Authorization: Bearer wlk_YOUR_KEY`.\nManage keys in Settings → API Keys.",
    },
    Doc {
        id: "schedule",
        tags: "schedule cron interval automatic recurring every hour daily timer run",
        title: "Schedule a workflow to run automatically",
        body: "Turn on a schedule so the workflow runs on its own at a fixed interval (set it from the workflow's Connect tab, or ask the assistant). The local scheduler fires the run and reschedules the next one automatically.",
    },
    Doc {
        id: "callable_functions",
        tags: "function callable script steps extraction typed reusable named tool sub",
        title: "Callable functions on a workflow",
        body: "A workflow can expose named callable functions: a script (JS run at run time), an extraction (a CSS/JSONPath query), or a step-group (a named range of the workflow's steps). Once added they are callable over the same REST/OpenAI/MCP surfaces as the workflow.",
    },
    Doc {
        id: "connect_surfaces",
        tags: "connect expose enable surface rest openai mcp api openapi callable",
        title: "Expose a workflow (REST / OpenAI / MCP)",
        body: "A workflow is callable only on the surfaces you enable on its Connect tab: REST, OpenAI-compatible, and MCP. An enabled surface accepts a `wlk_` API key as a Bearer token. After enabling a surface, create an API key to call it.",
    },
    Doc {
        id: "monitors",
        tags: "monitor watch check selector price change detect target notify alert",
        title: "Monitors (watch a page for changes)",
        body: "A monitor watches a URL + a selector and detects when its content changes. A price extractor turns the watched text into extracted.price, which an automation condition can compare (e.g. price lt 300). Monitors run on their own check interval (min 60s HTTP / 300s browser).",
    },
];

fn tokens(text: &str) -> Vec<String> {
    text.chars()
        .map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .filter(|w| w.len() > 1)
        .map(|w| w.to_string())
        .collect()
}

/// Top-k most relevant doc entries for a free-text query (keyword overlap over tags +
/// title, lightly weighting the body). Deterministic; falls back to the first k.
pub fn search(query: &str, k: usize) -> Vec<&'static Doc> {
    let q: std::collections::HashSet<String> = tokens(query).into_iter().collect();
    if q.is_empty() {
        return DOCS.iter().take(k).collect();
    }
    let mut scored: Vec<(i32, &'static Doc)> = Vec::new();
    for d in DOCS {
        let tag_hits = tokens(d.tags).iter().filter(|w| q.contains(*w)).count() as i32;
        let title_hits = tokens(d.title).iter().filter(|w| q.contains(*w)).count() as i32;
        let body_set: std::collections::HashSet<String> = tokens(d.body).into_iter().collect();
        let body_hits = body_set.iter().filter(|w| q.contains(*w)).count() as i32;
        let score = tag_hits * 3 + title_hits * 4 + body_hits;
        if score > 0 {
            scored.push((score, d));
        }
    }
    scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
    if scored.is_empty() {
        return DOCS.iter().take(k).collect();
    }
    scored.into_iter().take(k).map(|(_, d)| d).collect()
}

/// Compact text block of doc entries for injection into the answer prompt.
pub fn render_snippets(entries: &[&Doc]) -> String {
    entries
        .iter()
        .map(|e| format!("### {}\n{}", e.title, e.body))
        .collect::<Vec<_>>()
        .join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn how_do_i_call_returns_calling_docs() {
        let hits: Vec<&str> = search("how do I call this workflow with the api", 3)
            .iter()
            .map(|d| d.id)
            .collect();
        assert!(hits.contains(&"call_workflow_rest"), "{hits:?}");
        assert!(hits.iter().any(|id| *id == "call_workflow_openai" || *id == "api_keys"), "{hits:?}");
    }

    #[test]
    fn key_query_returns_api_keys() {
        let hits: Vec<&str> = search("create an api key token", 2).iter().map(|d| d.id).collect();
        assert!(hits.contains(&"api_keys"), "{hits:?}");
    }

    #[test]
    fn empty_query_falls_back() {
        assert_eq!(search("", 3).len(), 3);
    }
}
