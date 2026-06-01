CREATE TABLE tenants (
    id              TEXT PRIMARY KEY,
    name            TEXT UNIQUE NOT NULL,
    created_at      TEXT NOT NULL,
    notify_enabled  INTEGER NOT NULL DEFAULT 1,
    recipients      TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE api_keys (
    id         TEXT PRIMARY KEY,
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    hash       TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
);

ALTER TABLE endpoints ADD COLUMN tenant_id TEXT REFERENCES tenants(id);

INSERT INTO meta (key, value) VALUES ('session_secret', '')
    ON CONFLICT(key) DO NOTHING;
