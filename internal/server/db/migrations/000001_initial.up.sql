CREATE TABLE endpoints (
    id          TEXT PRIMARY KEY,
    hostname    TEXT NOT NULL,
    os          TEXT NOT NULL,
    arch        TEXT NOT NULL,
    user        TEXT NOT NULL,
    tags        TEXT NOT NULL DEFAULT '[]',
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL
);

CREATE TABLE inventories (
    endpoint_id  TEXT PRIMARY KEY REFERENCES endpoints(id) ON DELETE CASCADE,
    scan_id      TEXT NOT NULL,
    received_at  TEXT NOT NULL,
    raw          TEXT NOT NULL
);

CREATE TABLE vulnerabilities (
    id            TEXT PRIMARY KEY,
    canonical_id  TEXT NOT NULL,
    aliases       TEXT NOT NULL DEFAULT '[]',
    upstream      TEXT NOT NULL DEFAULT '[]',
    summary       TEXT,
    details       TEXT,
    published_at  TEXT,
    modified_at   TEXT,
    source        TEXT NOT NULL,
    raw           TEXT NOT NULL
);
CREATE INDEX idx_vuln_canonical ON vulnerabilities(canonical_id);

CREATE TABLE endpoint_vulnerabilities (
    endpoint_id       TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    purl              TEXT NOT NULL,
    vulnerability_id  TEXT NOT NULL REFERENCES vulnerabilities(id),
    package_name      TEXT NOT NULL,
    package_version   TEXT NOT NULL,
    package_ecosystem TEXT NOT NULL,
    dirs              TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (endpoint_id, purl, vulnerability_id)
);
CREATE INDEX idx_ev_endpoint ON endpoint_vulnerabilities(endpoint_id);
CREATE INDEX idx_ev_vuln ON endpoint_vulnerabilities(vulnerability_id);

CREATE TABLE endpoint_history (
    endpoint_id   TEXT NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
    date          TEXT NOT NULL,
    status        TEXT NOT NULL,
    vuln_count    INTEGER NOT NULL DEFAULT 0,
    canonical_ids TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (endpoint_id, date)
);
CREATE INDEX idx_history_date ON endpoint_history(date);

CREATE TABLE meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO meta (key, value) VALUES ('schema_version', '0.1.0');
