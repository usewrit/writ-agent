-- LOCAL OAUTH 2.1 AUTHORIZATION SERVER — state for `api/v1/oauth.rs`.
--
-- Some MCP-capable AI apps only speak OAuth (no API-key field). The daemon therefore acts as a
-- tiny, spec-shaped authorization server for its OWN resources: RFC 7591 dynamic client
-- registration, authorization-code + PKCE (S256 only, public clients — NO client secrets), and
-- refresh-token rotation. Everything stays on the machine.
--
-- Token/code VALUES are never stored — sha256 hex only (same idiom as local_api_keys.key_hash).

CREATE TABLE oauth_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Public identifier handed out at registration ("wcl_" + random). No secret: PKCE carries proof.
    client_id TEXT NOT NULL UNIQUE,
    client_name TEXT,
    -- JSON array of registered redirect URIs; authorize matches EXACTLY against these.
    redirect_uris TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

-- Short-lived authorization codes (one per approved consent; single-use).
CREATE TABLE oauth_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    -- PKCE S256 challenge (base64url(sha256(verifier))) — verified at the token endpoint.
    code_challenge TEXT NOT NULL,
    -- CSV scope granted at consent (auth.rs scope tokens; default the execute capability).
    scope TEXT NOT NULL DEFAULT 'run',
    expires_at INTEGER NOT NULL,          -- unix seconds
    used INTEGER NOT NULL DEFAULT 0
);

-- Issued bearer pairs. `access_hash` is the hot auth-lookup column.
CREATE TABLE oauth_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    access_hash TEXT NOT NULL UNIQUE,
    refresh_hash TEXT UNIQUE,
    client_id TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT 'run',
    access_expires_at INTEGER NOT NULL,   -- unix seconds
    refresh_expires_at INTEGER,           -- unix seconds; NULL = no refresh issued
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    last_used_at TEXT
);

CREATE INDEX idx_oauth_tokens_client ON oauth_tokens(client_id);
CREATE INDEX idx_oauth_codes_expiry ON oauth_codes(expires_at);
