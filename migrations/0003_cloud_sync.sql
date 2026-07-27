-- Cloud↔app sync map: links a LOCAL row (workflow|persona|monitor) to the cloud row it was
-- pulled from (origin='cloud') or pushed up to (origin='local'). The `content_hash` snapshots the
-- normalized recipe at last sync so a later PULL can detect local divergence and report (never
-- silently overwrite) a cloud-origin row whose local content drifted.
-- Conventions match 0001/0002: timestamps TEXT RFC3339 UTC; additive only.
CREATE TABLE cloud_sync_map (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,         -- 'workflow'|'persona'|'monitor'
    local_id INTEGER NOT NULL,
    cloud_id TEXT NOT NULL,
    content_hash TEXT,                 -- hash of normalized recipe at last sync (divergence detection)
    origin TEXT NOT NULL DEFAULT 'cloud', -- 'cloud' (pulled) | 'local' (pushed up)
    synced_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE UNIQUE INDEX ux_cloud_sync_entity_cloud ON cloud_sync_map(entity_type, cloud_id);
CREATE UNIQUE INDEX ux_cloud_sync_entity_local ON cloud_sync_map(entity_type, local_id);
