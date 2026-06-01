ALTER TABLE endpoint_vulnerabilities
    ADD COLUMN discovered_at TEXT NOT NULL DEFAULT '';
