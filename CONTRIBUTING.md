# Contributing to meerkat

Thanks for your interest! meerkat is alpha, so things move — issues and PRs are welcome.

## Prerequisites

- **Go 1.25+** (see `go.mod`)
- git

No CGO is required — the SQLite driver (`modernc.org/sqlite`) and Syft are pure Go, so everything cross-compiles cleanly.

## Build & test

```sh
go build ./...            # build everything
go build -o meerkat ./cmd/meerkat   # build the binary
go test ./...             # run tests
go vet ./...              # static checks
gofmt -l .                # formatting (should print nothing)
```

CI runs `build` + `vet` + `test` on every push and PR — keep them green.

## Run it locally

```sh
# Server (in-memory or local DB, no email)
MEERKAT_DB_PATH=./dev.db MEERKAT_BASE_URL=http://localhost:8080 go run ./cmd/meerkat server

# In another shell: create a key for a tenant, then point a client at it
go run ./cmd/meerkat key create --tenant dev --db ./dev.db
go run ./cmd/meerkat config init   # paste http://localhost:8080 + the key
go run ./cmd/meerkat scan
```

Dashboard at http://localhost:8080/app (sign in with the API key).

## Project layout

```
cmd/meerkat/            # CLI entry point + command definitions
internal/cli/           # client mode: walker, scanner, cataloger, grouper, cache, uploader, config
internal/server/        # server mode: api, db, ingest, matcher, scoring, notifier, rematch, ui
pkg/api/                # types shared between client and server
internal/server/db/migrations/   # numbered SQL migrations
docs/                   # setup guides
ai/                     # design docs (dd.md is the full design document)
```

## Conventions

- **Match the surrounding style.** Run `gofmt`; keep changes small and focused.
- **Tests** for new packages and behavior. Server packages use an in-memory SQLite DB (`db.Open(":memory:")` + `Migrate`).
- **Migrations are append-only.** Add a new numbered file under `internal/server/db/migrations/` (e.g. `000007_xxx.up.sql`) — never edit an applied migration. They auto-apply on `meerkat server` / `meerkat migrate`.
- **Commit messages**: short and descriptive. Prefixes like `docs:`, `test:`, `chore:` are filtered out of the release changelog, so use them for non-feature work.
- The frontend is a single embedded `internal/server/ui/index.html`; it follows the design system in `ai/DESIGN.md` (flat, black/white/grays, pills, no brand colors).

## Pull requests

1. Branch off `main`.
2. Make the change + tests; ensure `go build/vet/test` and `gofmt` pass.
3. Open a PR describing what and why. CI must pass before merge.

For security issues, **do not** open a public issue — see [SECURITY.md](SECURITY.md).
