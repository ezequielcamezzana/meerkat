<p align="center">
  <img src="internal/server/ui/assets/meerkat-icon.png" alt="meerkat" width="80" height="80" />
</p>

<h1 align="center">meerkat</h1>

<p align="center"><em>the colony watches its own</em></p>

<p align="center">SBOM-as-fingerprint: scan your fleet's dependencies, match them against known vulnerabilities, and answer <em>"which machines have this CVE?"</em> in seconds.</p>

<p align="center">
  <a href="https://cafecito.app/ezequielcamezzana"><img src="https://cdn.cafecito.app/imgs/buttons/button_5.svg" alt="Invitame un café en cafecito.app" /></a>
</p>

---

> [!WARNING]
> **meerkat is alpha and built for research purposes.** It works and is useful today, but the scope is intentionally narrow and the data model still moves. Expect rough edges. Right now it scans **project dependencies only** (resolved from lock files) — system packages, global installs, and richer vulnerability matching are on the way. It does **not** yet cover everything you'd expect from a production-grade security tool.

> [!CAUTION]
> meerkat builds and centralizes a **software inventory (SBOM) of every machine** that reports to it — package names and versions. That data is sensitive: it's effectively a map of each machine's attack surface. Run the server on a trusted, access-controlled network, protect the API keys, and use this with care.

## What it does

A small CLI runs on each machine, inventories the software dependencies it finds, and ships that inventory to a central server. The server matches every package against [OSV](https://osv.dev), records which machines are affected, and exposes a dashboard. When a new CVE drops, you already know who's exposed.

Inspired by how meerkat colonies work: every member scouts its surroundings and alerts the group, while a sentinel keeps the collective view.

### What it scans (alpha)

- **Project-tier dependencies only**, resolved from lock files:
  | Ecosystem | Detected from |
  |---|---|
  | npm | `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` |
  | PyPI | `poetry.lock`, `Pipfile.lock`, `uv.lock` |
  | Cargo | `Cargo.lock` |
  | Go | `go.sum` |
  | Conan (C/C++) | `conan.lock`, `conanfile.txt/.py` |
- Uses [Syft](https://github.com/anchore/syft) as a library, with caching so repeated scans are fast.
- Vulnerability matching via OSV, with canonical-CVE grouping and a CVSS-derived **exposure score**.

**Not yet** (planned): system packages (dpkg/rpm/apk), global installs (brew, npm -g), Windows, and deeper matching. The C/C++ + Conan coverage and daily-cadence full-machine scanning are the differentiators we're building toward.

## The two actors

meerkat is a **single binary** that runs in one of two modes:

- **Client (scout)** — `meerkat scan` on a developer machine or server. Walks the filesystem, detects projects, builds an `inventory.json` of dependencies, and uploads it. Configured per-machine via `~/.meerkat/config.yaml`. Can run on a schedule.
- **Server (mob)** — `meerkat server` on one host. Receives inventories, matches against OSV, stores everything in SQLite, serves the dashboard + JSON API, emails alerts when an endpoint gains a *new* vulnerability, and runs **passive re-matching** (re-evaluates offline machines against fresh OSV data so they're flagged even when powered off).

The server never reads filesystems and never runs Syft; the client never matches vulnerabilities. They talk over one HTTP endpoint with a bearer **API key**.

## Quickstart

**On the server host:**

```sh
# 1. Run the server (auto-applies DB migrations; DB at ~/.meerkat/server.db)
meerkat server

# 2. Create an API key for a team/tenant (prints the token once)
meerkat key create --tenant eng
# > mk_2yKx9mQp7vN3rL5fW8jH4dG6sB1cZ0aE
```

> If you set a custom `MEERKAT_DB_PATH`, pass the same path to `meerkat key create --db <path>` so they share one database.

**On each client machine:**

```sh
# install (macOS / Linux)
curl -fsSL https://raw.githubusercontent.com/ezequielcamezzana/meerkat/main/install.sh | sh

meerkat config init          # paste the server URL + API key, pick an interval
meerkat scan                 # run once now
meerkat service start        # scan automatically on a schedule
```

Open the dashboard at `http://<server>/app` and sign in with the API key.

Full walkthroughs:
- [docs/client-setup.md](docs/client-setup.md) — set up a scanning client
- [docs/server-setup.md](docs/server-setup.md) — run the server, manage keys, access

## Commands

| Command | Mode | Purpose |
|---|---|---|
| `meerkat scan` | client | Scan this machine and upload its inventory |
| `meerkat config init` | client | First-time setup → `~/.meerkat/config.yaml` |
| `meerkat config show \| get \| set \| reset` | client | Inspect / edit / wipe the config |
| `meerkat service start \| stop \| status` | client | Schedule automatic scans (crontab) |
| `meerkat cache info \| clear` | client | Inspect / clear the scan cache |
| `meerkat server` | server | Run the HTTP server (foreground) |
| `meerkat key create \| guest \| list \| revoke` | server | Manage API keys & tenants (`guest` = read-only key) |
| `meerkat migrate` | server | Apply DB migrations manually (idempotent) |
| `meerkat version` | both | Print version, commit, build date |

Add `-v` / `--verbose` to any command for debug logging.

## Platforms

macOS and Linux, `amd64` and `arm64`. No Windows yet.

## Live demo

A hosted instance with **synthetic data** — a fake fleet built from sample lock files — is up so you can try the dashboard without installing anything:

**[https://meerkat.camecorp.lat/](https://meerkat.camecorp.lat/)**

Sign in with this read-only key:

```
mk_XduLgOubsKHYZMfQy0ERYAri8P2jl54u
```

1. Open the URL — you'll land on the sign-in screen.
2. Paste the key and click **Sign in**.

You get the full read experience: the fleet grid colored by exposure, per-endpoint vulnerability pages with canonical-CVE grouping and **exposure scores**, the projects/severity donuts, the 30-day activity timeline, and the audit/fix report exports.

> [!NOTE]
> This is a **guest (read-only)** key. You can browse everything, but you can't upload inventories or change settings — writes are blocked server-side and hidden in the UI (look for the **guest · read-only** badge in the nav). All data is synthetic, so nothing here is a real machine.

## Contact

Questions, feedback, or issues — email **ezequielcamezzana@gmail.com**.

## License

[Apache License 2.0](LICENSE).
