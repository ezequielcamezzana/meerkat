# Security Policy

> [!NOTE]
> meerkat is **alpha** and built for research purposes. Treat it accordingly: it has not had a formal security audit, and the threat model below describes the *current* state, not a hardened product.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public GitHub issue.

Email **ezequielcamezzana@gmail.com** with:

- a description of the issue and its impact,
- steps to reproduce (a proof of concept if possible),
- affected version / commit.

You'll get a best-effort acknowledgement. Given the alpha status, fixes are handled on a best-effort basis with no formal SLA. Please allow reasonable time for a fix before any public disclosure.

## Supported versions

Only the **latest release** is supported. Fixes land on `main` and ship in the next tag.

## Security model & operator responsibilities

meerkat centralizes sensitive data and ships with deliberately minimal built-in protections. Operators are responsible for the surrounding controls:

- **The data is sensitive.** The server stores a software inventory (SBOM) of every reporting machine — package names and versions. That is effectively a map of each machine's attack surface. Protect the database and restrict who can read the dashboard/API.
- **No built-in TLS.** Terminate TLS at a reverse proxy (nginx/Caddy). Don't expose the server over plaintext HTTP on untrusted networks.
- **Network gating.** There is no user-account system; access is gated by the API key and by the network. Run the server on a trusted/internal network (intranet, VPN, or proxy auth).
- **API keys are secrets.** A key both authenticates a scanning client (`POST /v1/inventories`) and grants dashboard access (via session). Store keys securely, scope them per tenant, and revoke (`meerkat key revoke <id>`) when rotating or offboarding.
- **Keep config out of version control.** Server secrets live in environment variables / `.env`, which is git-ignored. Never commit `.env`, API keys, or the database.
- **CORS.** Defaults to `*` for dev convenience — set `MEERKAT_CORS_ALLOWED_ORIGINS` in production.

## What meerkat does *not* do

- It is **read-only** on clients: it never runs package managers and never writes outside `~/.meerkat/`.
- The server never reads filesystems and never executes scanners.
- It does not (yet) cover everything you'd expect from a production-grade security tool — see the scope notes in the [README](README.md).
