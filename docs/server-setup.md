# Setting up a meerkat server

The server (the "mob") receives inventories from clients, matches them against OSV, stores everything in SQLite, serves the dashboard + JSON API, sends email alerts, and runs passive re-matching. One install = one organization.

## 1. Install & run

The server is the same `meerkat` binary, run in server mode. It reads configuration from **environment variables only** (no config file) and auto-applies DB migrations on startup.

```sh
MEERKAT_DB_PATH=/var/lib/meerkat/meerkat.db \
MEERKAT_BASE_URL=https://meerkat.example.com \
meerkat server
```

It listens on `:8080` by default and serves the dashboard at `/app`.

### Configuration (environment variables)

| Var | Default | Description |
|---|---|---|
| `MEERKAT_LISTEN` | `:8080` | HTTP listen address |
| `MEERKAT_DB_PATH` | `~/.meerkat/server.db` | SQLite file path |
| `MEERKAT_BASE_URL` | derived | Public URL, used in email links + dashboard assets |
| `MEERKAT_LOG_FORMAT` / `MEERKAT_LOG_LEVEL` | `text` / `info` | Logging |
| `MEERKAT_CORS_ALLOWED_ORIGINS` | `*` | Comma-separated; **restrict in production** |
| `MEERKAT_OSV_BASE_URL` / `MEERKAT_OSV_TIMEOUT` | `https://api.osv.dev` / `30s` | OSV matcher |
| `MEERKAT_REMATCH_INTERVAL` | `1h` | Passive re-match tick (`0` disables) |
| `MEERKAT_REMATCH_BATCH` | `100` | Max stale endpoints re-matched per tick |
| `MEERKAT_HISTORY_RETENTION_DAYS` | `30` | History horizon |

**Email alerts** (optional) — two transports, Brevo takes precedence:

| Var | Description |
|---|---|
| `MEERKAT_BREVO_API_KEY` | Brevo v3 API key (`xkeysib-…`). If set, email goes via Brevo's HTTP API |
| `MEERKAT_NOTIFY_FROM` | Sender address (must be a **Brevo-verified** sender) |
| `MEERKAT_NOTIFY_FROM_NAME` | Sender display name (default `meerkat`) |
| `MEERKAT_SMTP_HOST` / `_PORT` / `_USER` / `_PASS` | SMTP fallback (used only when Brevo isn't configured) |

Recipients and the on/off toggle are configured **per-tenant** in the dashboard under **Settings**, not via env. If no transport is configured, notifications are silently disabled.

## 2. Create an API key

Clients authenticate with an **API key**, scoped to a **tenant** (a team/org boundary). Creating a key creates the tenant if it doesn't exist.

```sh
meerkat key create --tenant eng
# Tenant "eng" created (id: ...)
# API key created (...). Store this key securely — it will not be shown again:
# mk_2yKx9mQp7vN3rL5fW8jH4dG6sB1cZ0aE
```

The plaintext token is printed **once** (only its hash is stored). Distribute it to that tenant's clients out-of-band.

```sh
meerkat key list                 # all keys (id, tenant, name, created)
meerkat key revoke <key-id>      # disable a key
```

Use `--db <path>` on `key`/`migrate` commands if your DB isn't at the default path.

## 3. Access model

There is **no built-in TLS or login wall** beyond the API key — put the server behind a reverse proxy (nginx/Caddy) for HTTPS, and gate it by network (intranet/VPN/proxy auth) if needed.

The same API key serves two purposes:

- **Scanner ingestion** — `POST /v1/inventories` requires `Authorization: Bearer mk_…`.
- **Dashboard** — a human signs in at `/app/login` by pasting the API key; the server exchanges it for a **session cookie**. All UI + read endpoints are then gated by that session.

Routes at a glance:

| Route | Auth |
|---|---|
| `GET /v1/healthz` | none (liveness probe) |
| `GET /app/login`, assets | none |
| `POST /v1/inventories` | API key (Bearer) |
| `/app`, `GET /v1/endpoints…`, `/v1/settings` | session cookie |

Keys are per-tenant, so each tenant only sees its own endpoints and vulnerabilities.

## 4. How matching & passive scanning work

- On each upload, the server matches the inventory against OSV, resolves canonical CVE IDs, computes an exposure score, diffs against the endpoint's previous vulns, and emails on anything **new**.
- The `vulnerabilities` table doubles as a cache: a vuln fetched within 24h is reused instead of re-hitting OSV.
- **Passive re-matching** re-evaluates *stale* endpoints (`last_seen` > 24h) whose vuln data is overdue (`last_matched_at` > 24h) against current OSV data, in batches. It catches new CVEs for **offline** machines and emails on them — without a fresh client scan. It bumps `last_matched_at`, never `last_seen`, so the endpoint stays marked stale.

## 5. Deployment

### systemd

```ini
# /etc/systemd/system/meerkat.service
[Unit]
Description=meerkat server
After=network.target

[Service]
ExecStart=/usr/local/bin/meerkat server
EnvironmentFile=/opt/meerkat/.env
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
systemctl enable --now meerkat
journalctl -u meerkat -f
```

> **`.env` gotcha:** systemd `EnvironmentFile` does not want surrounding quotes, `export`, or Windows line endings. A value like `KEY="xkeysib-…"` or a trailing `\r` will be passed literally and rejected (e.g. Brevo `401 Key not found`). Keep lines as bare `KEY=value`.

### Docker

```dockerfile
FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY meerkat /usr/local/bin/meerkat
EXPOSE 8080
VOLUME ["/data"]
ENV MEERKAT_DB_PATH=/data/meerkat.db
ENTRYPOINT ["meerkat", "server"]
```

## Health & migrations

- `GET /v1/healthz` → `{"status":"ok"}` when the DB is reachable (no auth) — use it for load balancers / uptime checks.
- Migrations apply automatically on `meerkat server`. Run them manually with `meerkat migrate` if you prefer.
