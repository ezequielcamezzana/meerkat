ALTER TABLE endpoint_vulnerabilities
    ADD COLUMN fixed_version TEXT NOT NULL DEFAULT '';
