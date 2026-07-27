//! Offline-first runtime proof for the Writ desktop local backend.
//!
//! The product promise (DESKTOP_APP_PLAN / LOCAL_BACKEND_SPEC — local-first wedge: "record → run →
//! callable, creds stay local") is that the app is FULLY FUNCTIONAL with NO account and NO cloud
//! reachable. This is the runtime complement to PROD-15: it drives the REAL loopback router
//! (`local::server::build_router`) end-to-end via `tower::ServiceExt::oneshot` (same recipe as
//! `tests/cipher_gate.rs` + the `*_conformance` tests — headless `Vault{use_keyring:false}` + an
//! encrypted `db::open`, `StubEngine`, the minted `wlt_` bearer), and asserts the CORE LOCAL surfaces
//! all answer with NO cloud configured and ZERO outbound network.
//!
//! ZERO-NETWORK INVARIANT (the whole point):
//!   - `WRIT_CLOUD_URL` is NEVER set by this test, so the daemon resolves only its built-in default
//!     base url (a STRING — `CloudClient::resolve_base_url` does no I/O).
//!   - The DB is a throwaway tempdir, the vault is headless (no OS keyring), and the engine is the
//!     browserless `StubEngine`. Nothing here opens a socket to anywhere off-box.
//!   - Every asserted surface is a pure local read/write or a protocol/validation path. The ONLY
//!     route that could ever touch the network is `GET /v1/cloud/entitlements` (a verified fetch) —
//!     which we deliberately DO NOT call here; we call `GET /v1/cloud/status`, which is a pure DB
//!     reflection (`LinkState::load_or_default` + the string `resolve_base_url`) and is guaranteed to
//!     report `linked:false` for a fresh DB WITHOUT any network.
//!
//! What this proves works with no account, fully offline (each via the loopback router + bearer):
//!   1. `GET  /v1/agent`                          → 200 health (status:ok, encrypted:true).
//!   2. `POST /v1/workflows` + `GET /v1/workflows` → CRUD round-trips through the encrypted store.
//!   3. `POST /mcp` initialize + tools/list       → JSON-RPC 2.0 over HTTP, 200, the seeded workflow
//!                                                   surfaces as exactly one MCP tool.
//!   4. `GET  /v1/models` (OpenAI-compat)          → 200, lists the `writ:workflow:<id>` model.
//!   5. `GET  /v1/data`                            → 200 (the extracted-data explorer index).
//!   6. `GET  /v1/cloud/status`                    → 200 `linked:false` (unlinked, NO network — it
//!                                                   must REFLECT not-linked, never error).
//!
//! Anything that needs a real Chromium (an actual record or run) is OUT of scope here and lives as a
//! documented `#[ignore]`d case below (the network-cut record→run→MCP gate), mirroring
//! `tests/record_replay.rs`. The browserless `StubEngine` is correct for this file: every assertion
//! is a local read/write/validation/protocol path that needs no browser.
//!
//! ADDITIVE (net-new file), `local`-feature only → the cloud `writ-agent` build is byte-unchanged.
//!
//! Run:  cargo test --features local --test offline_first
//! Check: cargo check --features local

#![cfg(feature = "local")]

use axum::body::{to_bytes, Body};
use axum::http::Request;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt as _;
use writ_agent::local::server::{build_router, AppState};
use writ_agent::local::store::workflows::{self, NewWorkflow};
use writ_agent::local::{config, config::LocalConfig, db, engine, vault};

const TOKEN: &str = "wlt_offline_first";

/// Build a real `AppState` over a fresh headless vault + encrypted DB — the SAME recipe the
/// conformance tests use: `vault::load_or_create(.., false)` touches NO OS keyring, `db::open` keys +
/// migrates the SQLCipher DB. The `StubEngine` has no browser (so `recorder: None`); every assertion
/// in this file is a local read/write/validation/protocol path that needs none.
///
/// Critically, this builds the app with NO cloud configured: a throwaway DB has no persisted
/// `LinkState`, and the test process never sets `WRIT_CLOUD_URL`, so the app is genuinely unlinked
/// and offline.
async fn offline_state() -> AppState {
    let dir = tempfile::tempdir().expect("tempdir");
    let paths = config::Paths::at(dir.keep()); // keep() persists the dir for the test process lifetime
    paths.ensure_dirs().expect("ensure dirs");
    let v = vault::Vault::load_or_create(&paths.root, false).expect("headless vault (no keyring)");
    let pool = db::open(&paths.db(), &v.db_key_hex()).await.expect("open encrypted db");
    AppState {
        db: pool,
        vault: Arc::new(v),
        engine: Arc::new(engine::StubEngine),
        config: LocalConfig::default(),
        token: Arc::new(TOKEN.to_string()),
        health: writ_agent::local::app::health::DaemonHealth::shared(),
        recorder: None,
    }
}

/// GET a path with the loopback bearer; return `(status, body_bytes)`.
async fn get(state: &AppState, uri: &str) -> (u16, Vec<u8>) {
    let resp = build_router(state.clone())
        .oneshot(
            Request::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    (status, bytes.to_vec())
}

/// POST a JSON body with the loopback bearer; return `(status, body_bytes)`.
async fn post(state: &AppState, uri: &str, body: &Value) -> (u16, Vec<u8>) {
    let resp = build_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    (status, bytes.to_vec())
}

/// GET + decode a 200 JSON body (fails loudly with the body on a non-200).
async fn get_json(state: &AppState, uri: &str) -> Value {
    let (status, bytes) = get(state, uri).await;
    assert_eq!(status, 200, "GET {uri} expected 200, body={}", String::from_utf8_lossy(&bytes));
    serde_json::from_slice(&bytes).expect("response body is JSON")
}

/// Seed one enabled workflow that reads an `{{input.*}}` placeholder (so it surfaces as an MCP tool
/// with a derived inputSchema and as an OpenAI model). Returns its id.
async fn seed_workflow(state: &AppState, name: &str) -> i64 {
    let wf = workflows::insert(
        &state.db,
        &NewWorkflow {
            name: name.into(),
            description: Some(format!("offline {name}")),
            steps: Some(r#"[{"type":"goto","config":{"url":"{{input.target_url}}"}}]"#.into()),
            ..Default::default()
        },
    )
    .await
    .expect("seed workflow");
    wf.id
}

// ── 1. Local health: GET /v1/agent answers offline ────────────────────────────────────────────────

#[tokio::test]
async fn agent_health_works_offline() {
    let st = offline_state().await;
    let v = get_json(&st, "/v1/agent").await;
    assert_eq!(v["status"], "ok", "the local daemon reports healthy with no cloud");
    // The encrypted-store invariant is surfaced as a flag; offline never degrades it.
    assert_eq!(v["encrypted"], json!(true), "store is encrypted at rest, offline or not");
    assert!(v["version"].is_string(), "version is reported");
    assert_eq!(v["active_runs"], json!(0), "no runs in flight on a fresh daemon");
}

// ── 2. Workflows CRUD: create + read back through the encrypted store ──────────────────────────────

#[tokio::test]
async fn workflows_crud_works_offline() {
    let st = offline_state().await;

    // CREATE.
    let (status, bytes) = post(&st, "/v1/workflows", &json!({ "name": "Offline WF" })).await;
    assert_eq!(status, 200, "create succeeds offline, body={}", String::from_utf8_lossy(&bytes));
    let created: Value = serde_json::from_slice(&bytes).unwrap();
    let id = created["id"].as_i64().expect("created workflow has an id");
    assert_eq!(created["name"], "Offline WF");
    // Secret hygiene holds offline too: the sealed blob is never echoed.
    assert!(created.get("credentials_encrypted").is_none(), "sealed blob is redacted");

    // LIST reflects the create (no cloud round-trip — it's a pure local store read).
    let list = get_json(&st, "/v1/workflows").await;
    let items = list["data"].as_array().expect("data is an array");
    assert_eq!(list["count"], json!(1), "the one created workflow is listed");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["id"], json!(id));

    // GET one by id round-trips.
    let one = get_json(&st, &format!("/v1/workflows/{id}")).await;
    assert_eq!(one["id"], json!(id));
    assert_eq!(one["name"], "Offline WF");
}

// ── 3. MCP-over-HTTP: initialize + tools/list answer offline ───────────────────────────────────────

#[tokio::test]
async fn mcp_initialize_and_tools_list_work_offline() {
    let st = offline_state().await;
    let id = seed_workflow(&st, "Mcp Offline").await;

    // initialize → JSON-RPC 2.0, 200, advertises the protocol + tool capability.
    let (status, bytes) =
        post(&st, "/mcp", &json!({"jsonrpc":"2.0","id":1,"method":"initialize"})).await;
    assert_eq!(status, 200, "MCP initialize is 200 offline, body={}", String::from_utf8_lossy(&bytes));
    let init: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(init["jsonrpc"], "2.0");
    assert_eq!(init["id"], json!(1), "id echoed");
    assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
    assert_eq!(init["result"]["serverInfo"]["name"], "writ-local");
    assert!(init["result"]["capabilities"]["tools"].is_object(), "tools capability advertised");
    assert!(init.get("error").is_none(), "initialize is a success — no error member");

    // tools/list → static writ_* tools (fixed catalog, offline) + the seeded workflow as the one
    // DERIVED tool (a local catalog read).
    let (status, bytes) =
        post(&st, "/mcp", &json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).await;
    assert_eq!(status, 200, "MCP tools/list is 200 offline, body={}", String::from_utf8_lossy(&bytes));
    let listed: Value = serde_json::from_slice(&bytes).unwrap();
    let tools = listed["result"]["tools"].as_array().expect("tools is an array");
    assert!(tools.iter().any(|t| t["name"] == "writ_build"), "static tools present offline");
    let derived: Vec<&Value> = tools
        .iter()
        .filter(|t| !t["name"].as_str().unwrap_or("").starts_with("writ_"))
        .collect();
    assert_eq!(derived.len(), 1, "the seeded workflow is exposed as one derived tool");
    let tool = derived[0];
    assert!(tool["name"].as_str().map(|n| !n.is_empty()).unwrap_or(false), "tool has a non-empty name");
    assert_eq!(tool["inputSchema"]["type"], "object", "tool carries a JSON-Schema inputSchema");
    // The `{{input.*}}` scan derived the placeholder as a required property — fully local derivation.
    assert_eq!(tool["inputSchema"]["properties"]["target_url"]["type"], "string");
    assert!(id > 0, "the seeded workflow id is real");
}

// ── 4. OpenAI-compat: GET /v1/models lists writ:workflow:* offline ─────────────────────────────────

#[tokio::test]
async fn openai_models_list_works_offline() {
    let st = offline_state().await;
    let id = seed_workflow(&st, "Openai Offline").await;

    let v = get_json(&st, "/v1/models").await;
    assert_eq!(v["object"], "list", "OpenAI models-list envelope");
    let data = v["data"].as_array().expect("data is an array");
    assert_eq!(data.len(), 1, "the one enabled workflow is the one model");
    let model = &data[0];
    assert_eq!(model["object"], "model");
    assert_eq!(
        model["id"], format!("writ:workflow:{id}"),
        "model id is the writ:workflow:<id> contract — workflows ARE the offline models"
    );
    assert_eq!(model["owned_by"], "writ");
}

// ── 5. Data explorer: GET /v1/data answers offline ────────────────────────────────────────────────

#[tokio::test]
async fn data_index_works_offline() {
    let st = offline_state().await;
    // A fresh daemon with a workflow but no runs yet → the data index is a well-formed (empty) list.
    seed_workflow(&st, "Data Offline").await;
    let v = get_json(&st, "/v1/data").await;
    let wfs = v["workflows"].as_array().expect("workflows is an array");
    // No runs have produced extracted data, so the index is empty — but the surface WORKS (200).
    assert!(wfs.is_empty(), "no data-bearing runs yet → empty index, still well-formed");
}

// ── 6. Cloud status: GET /v1/cloud/status reflects linked:false offline (does NOT error) ───────────

// `/v1/cloud/status` (cloud-link reflection) exists only when the cloud-link surface is compiled in
// (`feature = "cloud"`, on for the managed desktop build). The cloud-free OSS coordinator build
// (`local,fleet`) omits the whole cloud-link module by design, so this reflection route is absent
// there and this assertion does not apply.
#[cfg(feature = "cloud")]
#[tokio::test]
async fn cloud_status_reports_unlinked_offline_without_erroring() {
    let st = offline_state().await;
    // CRITICAL offline-first assertion: with no account and no network, the cloud-status surface must
    // REFLECT not-linked — not 500, not hang. `status` reads `LinkState` from the DB and resolves the
    // base url as a STRING; it makes ZERO outbound calls. (We deliberately avoid `/v1/cloud/entitlements`,
    // which would attempt a verified fetch.)
    let v = get_json(&st, "/v1/cloud/status").await;
    assert_eq!(v["linked"], json!(false), "fresh, networkless daemon is unlinked");
    assert_eq!(v["account"], Value::Null, "no account metadata when unlinked");
    // base_url is always a resolved STRING (built-in default, since WRIT_CLOUD_URL is unset) — proving
    // resolution is pure string work with no I/O.
    assert!(v["base_url"].is_string(), "base_url resolves to a string with no network: {v}");
}

// ── Cross-cutting: every core surface is reachable in ONE offline session ──────────────────────────

/// One headless daemon, one session, every core surface exercised back-to-back with NO cloud and NO
/// network — the end-to-end "fully functional offline with no account" proof in a single test.
#[tokio::test]
async fn full_offline_surface_is_functional_end_to_end() {
    let st = offline_state().await;

    // Health.
    assert_eq!(get_json(&st, "/v1/agent").await["status"], "ok");

    // Create a workflow, then confirm it propagates to EVERY callable surface — all locally.
    let (status, bytes) = post(&st, "/v1/workflows", &json!({
        "name": "End To End",
        "steps": "[{\"type\":\"goto\",\"config\":{\"url\":\"{{input.url}}\"}}]"
    }))
    .await;
    assert_eq!(status, 200, "create, body={}", String::from_utf8_lossy(&bytes));
    let id = serde_json::from_slice::<Value>(&bytes).unwrap()["id"].as_i64().unwrap();

    // REST list sees it.
    assert_eq!(get_json(&st, "/v1/workflows").await["count"], json!(1));

    // MCP exposes it as a derived tool (alongside the fixed static writ_* catalog).
    let (_s, b) = post(&st, "/mcp", &json!({"jsonrpc":"2.0","id":9,"method":"tools/list"})).await;
    let tools = serde_json::from_slice::<Value>(&b).unwrap();
    let derived = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| !t["name"].as_str().unwrap_or("").starts_with("writ_"))
        .count();
    assert_eq!(derived, 1, "MCP sees the workflow");

    // OpenAI exposes it as a model.
    let models = get_json(&st, "/v1/models").await;
    let ids: Vec<String> = models["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["id"].as_str().map(String::from))
        .collect();
    assert!(ids.contains(&format!("writ:workflow:{id}")), "OpenAI sees the workflow: {ids:?}");

    // Data surface answers.
    assert!(get_json(&st, "/v1/data").await["workflows"].is_array());
    // Cloud-status reflection is present only in the cloud-link-capable (managed) build; the OSS
    // cloud-free coordinator build omits it entirely.
    #[cfg(feature = "cloud")]
    assert_eq!(get_json(&st, "/v1/cloud/status").await["linked"], json!(false));
}

// ── Auth still applies offline: no bearer → 401 (the loopback gate is unconditional) ───────────────

#[tokio::test]
async fn offline_surfaces_still_require_the_bearer() {
    let st = offline_state().await;
    // Offline does NOT mean unauthenticated — the loopback bearer gate is always on, so a missing
    // Authorization header is a 401 from the server layer before any handler runs.
    // `mut` because the cloud build pushes onto this below — without it the test file does not
    // compile at all under `--features cloud`, which is how this went unnoticed.
    #[allow(unused_mut)]
    let mut surfaces = vec![("GET", "/v1/agent"), ("GET", "/v1/models"), ("GET", "/v1/data")];
    // The cloud-link reflection route exists only in the cloud-link-capable build; include it in the
    // bearer-gate sweep only there (the OSS cloud-free build omits the route entirely).
    #[cfg(feature = "cloud")]
    surfaces.push(("GET", "/v1/cloud/status"));
    for (method, uri) in surfaces {
        let resp = build_router(st.clone())
            .oneshot(Request::builder().method(method).uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), 401, "{method} {uri} requires the loopback bearer even offline");
    }
}

// ── Run-dependent (needs a real Chromium): the network-cut record → run → MCP gate ────────────────
//
// The CORE offline proof above needs no browser. The ONE thing it cannot cover browserlessly is an
// actual RECORD or RUN, which drives a live warm Chromium (the daemon's own browser, shared by the
// run engine + recording WS) — that cannot run in CI without a Chromium binary + a display. So the
// end-to-end "record a flow, run it, then call it over MCP — all with the network physically cut" gate
// is left as a documented `#[ignore]`d case (mirrors `tests/record_replay.rs`).
//
// When un-ignored against a browser-capable build (wired to the `RealEngine` + `recorder: Some(..)`),
// the shape of this gate is:
//   0. Build `offline_state()`-style `AppState` BUT with the `RealEngine` (owns a warm `BrowserManager`)
//      and `recorder: Some(PlaywrightRecorder)` sharing that browser. Still: NO `WRIT_CLOUD_URL`, NO
//      keyring, NO outbound network permitted (run under a network namespace / firewall that drops all
//      egress, to PROVE no cloud call is required for the happy path).
//   1. RECORD: open `GET /ws/record?token=<wlt_>` with a real WS client, drive a couple of synthetic
//      interactions against a LOCAL fixture page (a `file://` or a loopback test server), collect the
//      emitted recorded-step frames, stop, and persist them as a workflow (`workflows::insert`).
//   2. RUN: `POST /v1/workflows/:id/run` → 202; stream `GET /v1/runs/:id/events` to completion and
//      assert the run reaches a terminal SUCCESS with extracted data — all locally, egress still cut.
//   3. CALL: `POST /mcp` `tools/call` (and/or `POST /v1/chat/completions`) naming that workflow → a
//      200 result whose content reflects the run — proving the record→run→callable loop is closed
//      with ZERO cloud dependency.
//   4. Throughout, assert `GET /v1/cloud/status` stays `linked:false` and nothing 5xx's for lack of a
//      reachable cloud.
//
// Run (full offline gate):  cargo test --features local --test offline_first -- --ignored
//                           (requires a Chromium/Patchright driver + a run-capable RealEngine recorder,
//                            ideally under an egress-blocking sandbox to literally prove the network cut)
#[tokio::test]
#[ignore = "needs Chromium (live Patchright driver) + a run-capable RealEngine recorder; documents the network-cut record→run→MCP gate"]
async fn network_cut_record_run_mcp_gate() {
    // Placeholder body: a browser-capable build replaces this with the steps documented above. Kept as
    // a compiling no-op so the harness lists the (ignored) case and it can be run with --ignored.
    let _st = offline_state().await;
}
