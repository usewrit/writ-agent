-- Writ Desktop — local SQLite schema (single-user). Runs inside a SQLCipher-encrypted DB (Layer A).
-- Conventions: timestamps TEXT RFC3339 UTC; JSON fields TEXT; booleans INTEGER 0/1.
-- All tenant_id / billing / marketplace / earnings / queue / agent-dispatch columns are dropped.
-- Authoritative: LOCAL_BACKEND_SPEC.md §2 (+ §9 local_api_keys). PKs INTEGER AUTOINCREMENT except stored_files (TEXT handle).

PRAGMA foreign_keys = ON;

-- 1. workflows
CREATE TABLE workflows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, description TEXT,
    workflow_type TEXT NOT NULL DEFAULT 'recorded',     -- recorded|pre_check|on_change|api_recorded
    steps TEXT NOT NULL DEFAULT '[]', raw_replay TEXT DEFAULT '[]', form_data TEXT DEFAULT '{}',
    exit_condition TEXT, input_rules TEXT, api_functions TEXT, streaming_config TEXT, functions TEXT,
    credentials_encrypted TEXT,                          -- XChaCha20-Poly1305 (WF1) Layer-B
    entry_url TEXT, timeout_ms INTEGER NOT NULL DEFAULT 30000, retry_count INTEGER NOT NULL DEFAULT 2,
    headless INTEGER NOT NULL DEFAULT 1, fast_mode INTEGER NOT NULL DEFAULT 1,
    is_active INTEGER NOT NULL DEFAULT 1, is_verified INTEGER NOT NULL DEFAULT 0,
    schedule_enabled INTEGER NOT NULL DEFAULT 0, schedule_interval_ms INTEGER,
    last_scheduled_at TEXT, next_scheduled_at TEXT,
    session_persistence INTEGER NOT NULL DEFAULT 0, session_ttl_seconds INTEGER,
    login_url_patterns TEXT DEFAULT '[]', relogin_max_retries INTEGER NOT NULL DEFAULT 1,
    default_persona_id INTEGER REFERENCES personas(id) ON DELETE SET NULL,
    estimated_duration_ms INTEGER, usage_count INTEGER NOT NULL DEFAULT 0,
    total_run_count INTEGER NOT NULL DEFAULT 0, total_failure_count INTEGER NOT NULL DEFAULT 0,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_run_at TEXT, last_failure_at TEXT, last_failure_error TEXT,
    cloud_callable INTEGER NOT NULL DEFAULT 0,           -- opt-in: callable through Writ Cloud (catalog metadata only)
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT
);
CREATE INDEX ix_workflows_type_name ON workflows(workflow_type, name);
CREATE INDEX ix_workflows_active ON workflows(is_active);
CREATE INDEX ix_workflows_due_schedule ON workflows(next_scheduled_at)
    WHERE schedule_enabled=1 AND is_active=1 AND schedule_interval_ms IS NOT NULL;

-- 2. runs (collapsed AutomationTask)
CREATE TABLE runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    workflow_id INTEGER REFERENCES workflows(id) ON DELETE CASCADE,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    change_id INTEGER REFERENCES changes(id) ON DELETE SET NULL,
    automation_id INTEGER REFERENCES automations(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'running',              -- running|success|failed|cancelled|timeout|interrupted|captcha_required
    trigger_type TEXT NOT NULL DEFAULT 'manual',        -- manual|on_change|scheduled|webhook|api|workflow
    success INTEGER, started_at TEXT, completed_at TEXT, duration_ms INTEGER,
    trigger_context TEXT, result_data TEXT, error_message TEXT, failure_category TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL DEFAULT 3,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX ix_runs_workflow_created ON runs(workflow_id, created_at);
CREATE INDEX ix_runs_status_created ON runs(status, created_at);

CREATE TABLE run_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,                                  -- screenshot|download|extracted_file|diff
    step_index INTEGER, file_id TEXT REFERENCES stored_files(id) ON DELETE SET NULL,
    path TEXT, content_type TEXT, meta TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX ix_run_artifacts_run ON run_artifacts(run_id);

-- 3. targets (monitors) + selectors
CREATE TABLE targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL,
    check_type TEXT NOT NULL DEFAULT 'content',          -- content|uptime
    selector TEXT, ignore_regex TEXT, check_period_ms INTEGER,
    expected_status_code INTEGER DEFAULT 200, timeout_ms INTEGER DEFAULT 10000,
    max_response_time_ms INTEGER DEFAULT 5000, check_ssl INTEGER DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1, requires_playwright INTEGER NOT NULL DEFAULT 0,
    baseline_hash TEXT, baseline_content TEXT, baseline_fetched_at TEXT,
    pre_check_workflow_id INTEGER REFERENCES workflows(id) ON DELETE SET NULL,
    on_change_workflow_id INTEGER REFERENCES workflows(id) ON DELETE SET NULL,
    on_change_enabled INTEGER NOT NULL DEFAULT 0, on_change_conditions TEXT, on_change_in_session INTEGER NOT NULL DEFAULT 0,
    persona_id INTEGER REFERENCES personas(id) ON DELETE SET NULL, auth_session_encrypted TEXT,
    notification_providers TEXT DEFAULT '{}', provider_notification_settings TEXT DEFAULT '{}',
    notification_title TEXT, notification_message TEXT, notification_priority INTEGER,
    next_run_at TEXT,                                    -- scheduler due-key
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT
);
CREATE INDEX ix_targets_enabled_created ON targets(enabled, created_at);
CREATE INDEX ix_targets_due ON targets(next_run_at) WHERE enabled=1;

CREATE TABLE target_selectors (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    name TEXT NOT NULL, selector TEXT NOT NULL, description TEXT, enabled INTEGER NOT NULL DEFAULT 1,
    content_type TEXT DEFAULT 'text', visual_region TEXT, ignore_regex TEXT, priority INTEGER DEFAULT 0,
    baseline_hash TEXT, baseline_content TEXT, baseline_screenshot TEXT, baseline_fetched_at TEXT,
    last_content_hash TEXT, last_checked_at TEXT, change_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT,
    UNIQUE(target_id, selector)
);
CREATE INDEX ix_target_selectors_target_enabled ON target_selectors(target_id, enabled);

CREATE TABLE selector_extractors (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_selector_id INTEGER NOT NULL REFERENCES target_selectors(id) ON DELETE CASCADE,
    name TEXT NOT NULL, output_name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
    extract_type TEXT NOT NULL DEFAULT 'text', config TEXT DEFAULT '{}', is_array INTEGER NOT NULL DEFAULT 0, default_value TEXT
);
CREATE INDEX ix_selector_extractors_selector ON selector_extractors(target_selector_id);

-- 4. monitor live-state + change-only history
CREATE TABLE monitor_state (
    target_id INTEGER PRIMARY KEY REFERENCES targets(id) ON DELETE CASCADE,
    checked_at TEXT NOT NULL, state TEXT, is_up INTEGER, status_code INTEGER, last_change_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE TABLE changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    target_selector_id INTEGER REFERENCES target_selectors(id) ON DELETE SET NULL,
    content_hash TEXT NOT NULL, previous_hash TEXT, diff_snippet TEXT, content_before TEXT, content_after TEXT,
    screenshot_before TEXT, screenshot_after TEXT, screenshot_diff TEXT,
    first_detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_detected_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX ix_changes_target_first ON changes(target_id, first_detected_at);
CREATE TABLE uptime_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    checked_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    is_up INTEGER NOT NULL, status_code INTEGER, response_time_ms INTEGER, error_message TEXT,
    ssl_cert_valid INTEGER, ssl_cert_expires_at TEXT, ssl_cert_days_until_expiry INTEGER, ssl_cert_issuer TEXT, ssl_error TEXT
);
CREATE INDEX ix_uptime_target_checked ON uptime_checks(target_id, checked_at);

-- 5. automations + executions + webhook triggers
CREATE TABLE automations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL DEFAULT 'change_detected',  -- change_detected|webhook_received|workflow_started|workflow_completed
    target_selector_id INTEGER REFERENCES target_selectors(id) ON DELETE SET NULL,
    workflow_id INTEGER REFERENCES workflows(id) ON DELETE SET NULL,
    webhook_trigger_id INTEGER REFERENCES webhook_triggers(id) ON DELETE SET NULL,
    name TEXT NOT NULL, description TEXT, enabled INTEGER NOT NULL DEFAULT 1, priority INTEGER DEFAULT 0,
    conditions TEXT DEFAULT '{}', actions TEXT NOT NULL DEFAULT '[]',  -- notify|workflow|return_data
    blocks TEXT, last_triggered_at TEXT, trigger_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT
);
CREATE INDEX ix_automations_target_enabled ON automations(target_id, enabled);
CREATE INDEX ix_automations_event_type ON automations(event_type);

CREATE TABLE automation_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, automation_id INTEGER NOT NULL REFERENCES automations(id) ON DELETE CASCADE,
    change_id INTEGER REFERENCES changes(id) ON DELETE SET NULL, status TEXT DEFAULT 'pending',
    trigger_context TEXT, action_results TEXT DEFAULT '[]',
    triggered_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), completed_at TEXT, error_message TEXT
);
CREATE INDEX ix_automation_executions_automation ON automation_executions(automation_id);

CREATE TABLE webhook_triggers (
    id INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1, secret_encrypted TEXT,  -- XChaCha (WF1) Layer-B
    workflow_id INTEGER REFERENCES workflows(id) ON DELETE SET NULL,
    target_id INTEGER REFERENCES targets(id) ON DELETE SET NULL, action TEXT NOT NULL DEFAULT 'run_workflow',
    payload_mapping TEXT, conditions TEXT, wait_for_result INTEGER NOT NULL DEFAULT 0, wait_timeout INTEGER NOT NULL DEFAULT 120,
    custom_path TEXT UNIQUE, function_name TEXT, last_triggered_at TEXT, trigger_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT
);
CREATE INDEX ix_webhook_triggers_workflow ON webhook_triggers(workflow_id);

-- 6. personas (ciphertext only; key in keyring)
CREATE TABLE personas (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, description TEXT, target_domain TEXT,
    login_username TEXT, credentials_encrypted TEXT, twofa_method TEXT NOT NULL DEFAULT 'none',
    totp_seed_encrypted TEXT, totp_digits INTEGER NOT NULL DEFAULT 6, totp_period_seconds INTEGER NOT NULL DEFAULT 30,
    totp_algorithm TEXT NOT NULL DEFAULT 'SHA1', email_otp_mode TEXT, relay_address TEXT, otp_extract_config TEXT,
    fingerprint TEXT, proxy_config_encrypted TEXT, session_state_encrypted TEXT,
    earliest_cookie_expiry TEXT, expires_at TEXT, validation_status TEXT NOT NULL DEFAULT 'unknown',
    last_login_at TEXT, is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT, last_used_at TEXT
);
CREATE INDEX ix_personas_domain ON personas(target_domain);

-- 7. vault_secrets (ciphertext only)
CREATE TABLE vault_secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE, value_encrypted TEXT NOT NULL,
    description TEXT, category TEXT,                      -- credentials|api_keys|tokens|ai_provider
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_at TEXT, last_used_at TEXT, use_count INTEGER DEFAULT 0
);

-- 8. stored_files (OpenAI-style TEXT handle; bytes under ~/.writ/files, age-encrypted)
CREATE TABLE stored_files (
    id TEXT PRIMARY KEY, storage_key TEXT NOT NULL, filename TEXT NOT NULL,
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream', size_bytes INTEGER NOT NULL DEFAULT 0, sha256 TEXT,
    source TEXT NOT NULL DEFAULT 'upload',               -- upload|api|workflow_output
    source_run_id INTEGER REFERENCES runs(id) ON DELETE SET NULL, purpose TEXT,
    status TEXT NOT NULL DEFAULT 'ready', expires_at TEXT, deleted_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), meta TEXT
);
CREATE INDEX ix_stored_files_sha256 ON stored_files(sha256);
CREATE INDEX ix_stored_files_deleted ON stored_files(deleted_at);
CREATE INDEX ix_stored_files_source ON stored_files(source);

-- 9. local_api_keys (external clients/agents call the local API; hashed, scoped)
CREATE TABLE local_api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,                                  -- "Claude Desktop", "n8n", ...
    prefix TEXT NOT NULL,                               -- 'wlk_' + first 6 chars (shown in UI)
    key_hash TEXT NOT NULL,                             -- sha256 of the full key (full key shown once)
    scopes TEXT NOT NULL DEFAULT 'run',                 -- read|run|admin (CSV)
    enabled INTEGER NOT NULL DEFAULT 1,
    last_used_at TEXT, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), revoked_at TEXT
);
CREATE INDEX ix_local_api_keys_enabled ON local_api_keys(enabled);

-- 10. config kv (scheduler cursors, onboarding flags, migration markers). Secrets/keys NEVER here.
CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT NOT NULL);
