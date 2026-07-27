-- NOTIFICATION CONNECTORS — reusable "fast connector" notification destinations (Slack / Discord /
-- Telegram) the user configures once and references from automation notification blocks via the
-- unified `provider:id` recipient format. The LOCAL mirror of the cloud slack/discord/telegram
-- recipient models (backend/models/{slack,discord,telegram}_recipient.py), collapsed into ONE table
-- keyed by `provider` (no tenant/user columns locally — every row is this install's).
--
-- All three channels are plain outbound HTTP (Slack/Discord incoming-webhook URL; Telegram
-- bot API), so they deliver on desktop with no cloud relay. `run_notification_action`
-- (src/local/flow.rs) reads these rows and POSTs the per-provider payload through the SSRF url_guard.
--
-- SECURITY: `webhook_url` and `bot_token` are credential-bearing. They are NOT logged and NOT
-- returned by the list API (which projects only {id, provider, name, enabled}); the whole DB is
-- SQLCipher-encrypted at rest, so these columns inherit encryption at rest like every other table
-- (matching the Track-B column spec, which lists them as plain TEXT). `chat_id` is a non-secret
-- Telegram channel identifier.
CREATE TABLE notification_connectors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,                              -- 'slack' | 'discord' | 'telegram'
    name TEXT NOT NULL,                                 -- user-facing label
    webhook_url TEXT,                                   -- slack/discord incoming-webhook URL (secret, nullable)
    bot_token TEXT,                                     -- telegram bot token (secret, nullable)
    chat_id TEXT,                                       -- telegram chat id (non-secret, nullable)
    enabled INTEGER NOT NULL DEFAULT 1,                 -- boolean 0/1
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX ix_notification_connectors_provider_enabled ON notification_connectors(provider, enabled);
