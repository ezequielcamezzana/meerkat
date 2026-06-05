-- API keys gain a role: 'complete' (read+write, the existing behavior) or
-- 'guest' (read-only). Existing keys backfill to 'complete' via the default.
ALTER TABLE api_keys ADD COLUMN role TEXT NOT NULL DEFAULT 'complete';
