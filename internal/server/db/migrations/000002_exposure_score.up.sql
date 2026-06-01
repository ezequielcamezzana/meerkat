ALTER TABLE vulnerabilities
    ADD COLUMN severity_score  REAL NOT NULL DEFAULT 0.0;
ALTER TABLE vulnerabilities
    ADD COLUMN severity_source TEXT NOT NULL DEFAULT 'unknown';

ALTER TABLE endpoint_vulnerabilities
    ADD COLUMN exposure_score REAL NOT NULL DEFAULT 0.0;
ALTER TABLE endpoint_vulnerabilities
    ADD COLUMN package_scope  TEXT NOT NULL DEFAULT 'runtime';
ALTER TABLE endpoint_vulnerabilities
    ADD COLUMN package_kind   TEXT NOT NULL DEFAULT 'project-dependency';

CREATE INDEX idx_ev_exposure_score
    ON endpoint_vulnerabilities(endpoint_id, exposure_score DESC);
