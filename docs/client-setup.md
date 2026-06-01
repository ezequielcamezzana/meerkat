# Setting up a meerkat client

A client (the "scout") scans one machine and uploads its dependency inventory to the server. This guide assumes you **already have an API key** and the server URL — if you need to create a key, see [server-setup.md](server-setup.md).

## 1. Install the binary

```sh
curl -fsSL https://raw.githubusercontent.com/ezequielcamezzana/meerkat/main/install.sh | sh
meerkat version
```

The installer detects your OS/arch (macOS/Linux, amd64/arm64) and drops the binary in `/usr/local/bin` (override with `INSTALL_DIR`). Or grab a binary manually from the [Releases](https://github.com/ezequielcamezzana/meerkat/releases) page.

## 2. Configure

### Interactive

```sh
meerkat config init
```

You'll be prompted for:

- **Tags** — comma-separated labels for this machine (e.g. `eng,laptop`). Used to filter in the dashboard.
- **Server URL** — e.g. `https://meerkat.example.com`. Leave empty to run **offline** (writes inventories locally, never uploads).
- **Server token** — your API key (`mk_…`). Can be left blank and set later.
- **Scan interval** — e.g. `1h`, `30m`, `1d`.

This writes `~/.meerkat/config.yaml` (mode `0600` — it holds your token).

### Non-interactive (CI, headless, provisioning)

```sh
meerkat config init --non-interactive \
  --tags eng,ci \
  --server-url https://meerkat.example.com \
  --token mk_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx \
  --interval 1h
```

Values can also come from env vars: `MEERKAT_TAGS`, `MEERKAT_SERVER`, `MEERKAT_TOKEN`, `MEERKAT_INTERVAL`.

## 3. Run a scan

```sh
meerkat scan
```

This walks the scan root, detects projects via lock files, builds the inventory, and uploads it. Useful flags:

| Flag | Effect |
|---|---|
| `--root <path>` | Override the scan root (default `/`) |
| `--output <path>` | Write the inventory to a file **instead of** uploading |
| `--no-upload` | Skip the upload step |
| `--no-cache` | Bypass cache reads (still writes cache) |
| `--workers <n>` | Parallel scan workers (default: CPU count) |
| `-v` | Verbose logging |

A scan exits non-zero only on fatal errors. Per-project scan failures are collected and reported but don't fail the run; a failed upload is queued and retried on the next scan.

## 4. Schedule automatic scans

```sh
meerkat service start    # installs a crontab entry at your configured interval
meerkat service status   # active (interval: 1h)
meerkat service stop     # remove it
```

> The scheduler only runs while the machine is on. If a machine is off (e.g. over a weekend), the server's **passive re-matching** keeps its last inventory checked against new CVEs — but a fresh scan still needs the machine online.

## Managing configuration

```sh
meerkat config show                 # full config (token redacted)
meerkat config get server.url
meerkat config set server.token mk_...
meerkat config set tags eng,prod
meerkat config set interval 6h      # reinstalls the service if running
meerkat config set excludes-add vendor
meerkat config reset                # remove config + service (add --all to wipe cache/logs)
```

Supported `set`/`get` keys: `tags`, `interval`, `server.url`, `server.token`, `scan.root`, `scan.excludes` (plus `excludes-add` / `excludes-remove`), `notifications.local`.

## Filesystem layout

```
~/.meerkat/
├── config.yaml      # your config (0600)
├── cache/           # content-addressed scan cache
├── pending/         # inventories awaiting upload (retried next scan)
└── meerkat.log      # service-mode log
```

- `meerkat cache info` / `meerkat cache clear` manage the cache.
- meerkat is **read-only**: it never runs package managers and never writes outside `~/.meerkat/`.

## Troubleshooting

- **"meerkat is not configured"** — run `meerkat config init`.
- **Uploads failing (5xx / network)** — inventories queue in `~/.meerkat/pending/` and drain on the next scan. A `4xx` (bad token / schema) is not queued; check `server.token`.
- **Nothing detected** — meerkat only detects projects with a supported lock file. A directory with no lock files produces an empty inventory.
