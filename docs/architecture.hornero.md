# meerkat

description: SBOM-as-fingerprint — a single binary that scouts a machine's dependencies (client) and matches a fleet against OSV (server).
notes: One binary, two modes. Client and server share the wire types and talk over one HTTP endpoint with a bearer API key.

## Bucket: Wire
position: -228, -163
description: Shared inventory/package types exchanged between client and server (pkg/api). Pure data, referenced by both sides, depends on nothing.

## Bucket: Scout
position: -238, 881
description: Client mode. Walks the filesystem, scans projects with syft (cached), groups packages, uploads the inventory.

## Bucket: Matching
position: 699, -147
description: Server-side vulnerability matching against OSV, with canonical-CVE grouping and CVSS-derived exposure scoring.

## Bucket: Mob
position: 1047, -181
description: Server core. Persists inventories, drives matching, alerts on new vulns, and re-matches offline machines.

## Bucket: Gateway
position: 2007, 33
description: HTTP surface. Bearer-key / session auth, the JSON API and dashboard router.

## Capability: Notifier
bucket: Mob
position: 1358, 451
description: Emits an alert when an endpoint gains a new vulnerability.
methods:
- Notify(v: NewVuln)

## Capability: Scanner
bucket: Scout
position: 320, 900
description: Extracts the resolved package list for one project.
methods:
- Scan(p: Project): Package

## Capability: VulnMatcher
bucket: Matching
position: 696, 80
description: Queries a vuln source per PURL and fetches full vuln records.
methods:
- QueryBatch(packages: Package): string
- FetchVulns(ids: string): Vulnerability

## Capability: Walker
bucket: Scout
position: 40, 900
description: Walks a root and emits detected projects from lock files.
methods:
- Walk(root: string, excludes: array): Project

## Block: Auth
bucket: Gateway
position: 2002, 245
description: Signs/verifies dashboard sessions and hashes API keys.

## Block: BrevoNotifier
bucket: Mob
implements: Notifier
position: 1080, 880
description: Sends alerts through the Brevo transactional email API.
props:
- apiKey: string
- from: string
- baseURL: string

## Block: Cache
bucket: Scout
position: 600, 1340
description: On-disk store of scan results keyed by lock-file content hash.
props:
- dir: string

## Block: CachedScanner
bucket: Scout
implements: Scanner
position: 320, 1340
description: Content-hash cache in front of an inner scanner.
props:
- inner: struct(Scanner)
- cache: struct(Cache)

## Block: Cataloger
bucket: Scout
position: 35, 1342
description: Fans projects out across workers, producing packages.
props:
- scanner: struct(Scanner)
- workers: number

## Block: DB
bucket: Mob
position: 1665, 84
description: SQLite store for endpoints, inventories, vulns and sessions.
props:
- path: string

## Block: EmailNotifier
bucket: Mob
implements: Notifier
position: 1080, 1080
description: Sends alerts over SMTP.
props:
- host: string
- from: string

## Block: Endpoint
bucket: Wire
position: 40, 280
description: The reporting machine's identity.
props:
- id: string
- hostname: string
- os: string
- arch: string
- user: string
- tags: array

## Block: FSWalker
bucket: Scout
implements: Walker
position: 40, 1120
description: Filesystem walker that detects projects from lock files.

## Block: Grouper
bucket: Scout
position: 40, 1560
description: Dedupes packages across directories into the final list.

## Block: Ingest
bucket: Mob
position: 1400, 280
description: Persists an inventory, runs matching, scores it, and fires alerts.
props:
- db: struct(DB)
- matcher: struct(VulnMatcher)
- notifier: struct(Notifier)
- baseURL: string

## Block: Inventory
bucket: Wire
position: 40, 60
description: The full upload payload: who scanned, which machine, the run, and the packages.
props:
- schemaVersion: string
- scanner: struct(ScannerInfo)
- endpoint: struct(Endpoint)
- scan: struct(ScanMeta)
- packages: array(Package)

## Block: LocalNotifier
bucket: Scout
position: 600, 1560
description: Desktop notification after a local scan finishes.
props:
- enabled: bool

## Block: Match
bucket: Matching
position: 980, 280
description: A (purl, vuln) pairing with its exposure score and fix version.
props:
- purl: string
- vulnerability: struct(Vulnerability)
- exposureScore: number
- fixedVersion: string

## Block: NewVuln
bucket: Mob
position: 1080, 480
description: Payload describing a newly exposed endpoint for alerting.
props:
- canonicalID: string
- summary: string
- endpointHostname: string

## Block: NewVulnRef
bucket: Wire
position: 325, 689
description: Canonical-CVE summary returned to the client for newly found vulns.
props:
- canonicalID: string
- summary: string

## Block: NoopMatcher
bucket: Matching
implements: VulnMatcher
position: 701, 502
description: No-op matcher for tests and offline runs.

## Block: NoopNotifier
bucket: Mob
implements: Notifier
position: 1080, 680
description: Discards alerts; used when no mailer is configured.

## Block: OSVMatcher
bucket: Matching
implements: VulnMatcher
position: 700, 280
description: Matches PURLs against osv.dev with batching.
props:
- endpoint: string

## Block: Package
bucket: Wire
position: 331, 14
description: One resolved dependency with its PURL, scope and provenance dirs.
props:
- name: string
- version: string
- ecosystem: string
- purl: string
- scope: string
- direct: bool
- kind: string
- dirs: array

## Block: Project
bucket: Scout
position: 600, 900
description: A directory with lock files for one ecosystem, found by the walker.
props:
- ecosystem: string
- packageManager: string
- dir: string
- lockFiles: array

## Block: Rematcher
bucket: Mob
position: 1661, 332
description: Periodically re-evaluates offline endpoints against fresh OSV data.
props:
- db: struct(DB)
- ingest: struct(Ingest)
- batch: number

## Block: Result
bucket: Mob
position: 1400, 60
description: Outcome of ingesting one inventory.
props:
- scanID: string
- endpointID: string
- vulnCount: number
- newVulnerabilities: array(NewVulnRef)

## Block: Router
bucket: Gateway
position: 2003, 146
description: HTTP handler: auth middleware, JSON API and dashboard.
props:
- db: struct(DB)
- ingest: struct(Ingest)

## Block: ScanError
bucket: Wire
position: 320, 500
description: A project that failed to catalog.
props:
- projectDir: string
- ecosystem: string
- message: string

## Block: ScanMeta
bucket: Wire
position: 309, 298
description: Run metadata and timings for one scan (api.Scan).
props:
- id: string
- root: string
- projectsScanned: number
- cacheHits: number
- errors: array(ScanError)

## Block: ScannerInfo
bucket: Wire
position: 40, 500
description: Name and version of the scanning agent (api.Scanner).
props:
- name: string
- version: string

## Block: SyftScanner
bucket: Scout
implements: Scanner
position: 320, 1120
description: Wraps the syft library to extract packages from a project.

## Block: Uploader
bucket: Scout
position: 320, 1560
description: POSTs the inventory with the bearer key; queues to disk on failure.
props:
- serverURL: string
- token: string
- pendingDir: string

## Block: Vulnerability
bucket: Matching
position: 991, 60
description: A resolved vuln record from OSV.
props:
- id: string
- aliases: array
- summary: string
- details: string
- source: string

## Flow: Scan & upload (client)
color: #9fbbe0
description: meerkat scan — from filesystem walk to inventory upload.
steps:
- 1 @ FSWalker [Walker.Walk]: walk the root, detect projects from lock files
- 2 < 1 @ CachedScanner [Scanner.Scan]: cache lookup; run syft on miss
> Key is the lock-file content hash, so repeated scans are fast.
- 3 < 2 @ Cataloger: fan projects across workers, emit packages
- 4 < 3 @ Grouper: dedupe packages across directories
- 5 < 4 @ Uploader: POST the inventory with the bearer API key
> On network failure the inventory is queued to the pending dir and drained later.
- 6 < 5 @ LocalNotifier: desktop notification with the result

## Flow: Ingest & match (server)
color: #a8c8a0
description: Inventory upload — persisted, matched against OSV, scored, alerted.
steps:
- 1 @ Router: bearer-key auth, decode the inventory
- 2 < 1 @ Ingest: upsert endpoint, insert inventory
- 3 < 2 @ OSVMatcher [VulnMatcher.QueryBatch, VulnMatcher.FetchVulns]: query OSV per PURL, fetch full records
- 4 < 3 @ Ingest: assemble matches, compute exposure score, write vulns
- 5a < 4 @ BrevoNotifier [Notifier.Notify]: new vuln: email the affected fleet
- 5b < 4 @ Router: respond with the new-vuln refs

## Flow: Passive rematch (server)
color: #d8b48c
description: Re-evaluates powered-off machines against fresh OSV data on a timer.
steps:
- 1 @ Rematcher: on tick, pick a batch of offline endpoints
- 2 < 1 @ OSVMatcher [VulnMatcher.QueryBatch]: re-match stored packages against current OSV
- 3 < 2 @ Ingest: store new matches and fire alerts
- 4 < 3 @ EmailNotifier [Notifier.Notify]: flag machines newly exposed while offline
