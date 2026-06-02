package ingest

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ezequielcamezzana/meerkat/internal/server/db"
	"github.com/ezequielcamezzana/meerkat/internal/server/matcher"
	"github.com/ezequielcamezzana/meerkat/internal/server/notifier"
	"github.com/ezequielcamezzana/meerkat/internal/server/scoring"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

const supportedSchema = "0.1.0"

type Result struct {
	ScanID             string
	EndpointID         string
	VulnCount          int
	NewVulnerabilities []api.NewVulnRef
	EndpointURL        string
}

type Ingest struct {
	db       *db.DB
	matcher  matcher.VulnMatcher
	notifier notifier.Notifier
	baseURL  string
}

func New(database *db.DB, m matcher.VulnMatcher, n notifier.Notifier, baseURL string) *Ingest {
	return &Ingest{db: database, matcher: m, notifier: n, baseURL: baseURL}
}

const vulnMaxAge = 24 * time.Hour

func (i *Ingest) Process(ctx context.Context, inv api.Inventory, tenantID string) (Result, error) {
	if inv.SchemaVersion != supportedSchema {
		return Result{}, fmt.Errorf("unsupported schema version %q (want %q)", inv.SchemaVersion, supportedSchema)
	}

	now := time.Now().UTC()

	if err := i.db.UpsertEndpoint(ctx, inv.Endpoint, tenantID, now); err != nil {
		return Result{}, fmt.Errorf("upserting endpoint: %w", err)
	}
	if err := i.db.InsertInventory(ctx, inv); err != nil {
		return Result{}, fmt.Errorf("inserting inventory: %w", err)
	}

	// WHY: history date uses the scan's StartedAt (scanner's local timezone),
	// not server UTC. A scan at 23:00 UTC-3 is still "yesterday" locally.
	scanTime := inv.Scan.StartedAt
	if scanTime.IsZero() {
		scanTime = now
	}
	res, err := i.evaluate(ctx, inv.Endpoint, inv.Packages, tenantID, now, scanTime.Format("2006-01-02"))
	if err != nil {
		return Result{}, err
	}
	res.ScanID = inv.Scan.ID
	return res, nil
}

// Rematch re-evaluates an endpoint's stored packages against current OSV data
// (passive scanning) without a fresh client scan. It updates last_matched_at,
// not last_seen — the endpoint stays "stale", but its vuln data is current.
func (i *Ingest) Rematch(ctx context.Context, endpoint api.Endpoint, packages []api.Package, tenantID string) (Result, error) {
	now := time.Now().UTC()
	return i.evaluate(ctx, endpoint, packages, tenantID, now, now.Format("2006-01-02"))
}

// evaluate is the shared tail of active ingest and passive re-match: resolve
// vulns (DB cache + OSV for the misses), persist matches + exposure, update
// history + last_matched_at, and notify on newly-appeared vulns.
func (i *Ingest) evaluate(ctx context.Context, endpoint api.Endpoint, packages []api.Package, tenantID string, now time.Time, historyDate string) (Result, error) {
	// Previous canonical IDs, captured before we overwrite them (for the diff).
	prevIDs, err := i.db.GetPreviousCanonicalIDs(ctx, endpoint.ID)
	if err != nil {
		return Result{}, fmt.Errorf("getting previous vulns: %w", err)
	}

	// Which vuln IDs hit which packages.
	idsByPurl, err := i.matcher.QueryBatch(ctx, packages)
	if err != nil {
		return Result{}, fmt.Errorf("vuln querybatch: %w", err)
	}
	idSet := make(map[string]struct{})
	for _, ids := range idsByPurl {
		for _, id := range ids {
			idSet[id] = struct{}{}
		}
	}
	ids := make([]string, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}

	// The vulnerabilities table is the cache: reuse records fetched within
	// vulnMaxAge, only hit OSV for the stale/missing ones.
	cached, staleIDs, err := i.db.GetFreshVulns(ctx, ids, vulnMaxAge)
	if err != nil {
		return Result{}, fmt.Errorf("reading cached vulns: %w", err)
	}
	fetched, err := i.matcher.FetchVulns(ctx, staleIDs)
	if err != nil {
		return Result{}, fmt.Errorf("fetching vulns: %w", err)
	}

	vulnByID := make(map[string]matcher.Vulnerability, len(cached)+len(fetched))
	for id, v := range cached {
		vulnByID[id] = v
	}
	// Only freshly-fetched vulns are written (stamps fetched_at = now). Cached
	// rows are already correct — rewriting them would reset their age.
	for _, v := range fetched {
		vulnByID[v.ID] = v
		canonicalID := matcher.Canonical(v)
		sevScore, sevSource := scoring.SeverityScore(v.Raw)
		if err := i.db.UpsertVulnerability(ctx, v, canonicalID, sevScore, sevSource, now); err != nil {
			return Result{}, fmt.Errorf("upserting vuln %s: %w", v.ID, err)
		}
	}

	// Canonical set + strongest severity per canonical, over all resolved vulns.
	newCanonicalSet := make(map[string]struct{})
	severityByCanonical := make(map[string]float64)
	for _, v := range vulnByID {
		canonicalID := matcher.Canonical(v)
		newCanonicalSet[canonicalID] = struct{}{}
		sevScore, _ := scoring.SeverityScore(v.Raw)
		if sevScore > severityByCanonical[canonicalID] {
			severityByCanonical[canonicalID] = sevScore
		}
	}

	// Assemble per-(purl,vuln) matches, enrich with package metadata + exposure.
	enriched := enrichMatches(matcher.AssembleMatches(packages, idsByPurl, vulnByID), packages)
	for idx := range enriched {
		canonicalID := matcher.Canonical(enriched[idx].Vulnerability)
		enriched[idx].ExposureScore = scoring.ExposureScore(
			severityByCanonical[canonicalID],
			scoring.ScopeWeight(enriched[idx].PackageScope),
			scoring.KindWeight(enriched[idx].PackageKind),
		)
		enriched[idx].FixedVersion = matcher.FixedVersion(
			enriched[idx].Vulnerability.Raw, enriched[idx].PackageName)
	}

	if err := i.db.ReplaceEndpointVulnerabilities(ctx, endpoint.ID, enriched, now); err != nil {
		return Result{}, fmt.Errorf("replacing endpoint vulns: %w", err)
	}

	// History
	newCanonicalIDs := setToSlice(newCanonicalSet)
	var maxExposure float64
	for _, m := range enriched {
		if m.ExposureScore > maxExposure {
			maxExposure = m.ExposureScore
		}
	}
	status := scoring.Bucket(maxExposure)
	if err := i.db.UpsertHistory(ctx, endpoint.ID, historyDate, status, len(newCanonicalIDs), newCanonicalIDs); err != nil {
		return Result{}, fmt.Errorf("upserting history: %w", err)
	}
	if _, err := i.db.CleanupHistory(ctx, 30); err != nil {
		slog.Warn("history cleanup failed", "err", err)
	}
	if err := i.db.SetLastMatched(ctx, endpoint.ID, now); err != nil {
		slog.Warn("setting last_matched_at failed", "err", err)
	}

	// Notify on newly-appeared canonical vulns (outside any transaction).
	diffIDs := diff(newCanonicalSet, prevIDs)
	summaryByCanonical := make(map[string]string, len(vulnByID))
	for _, v := range vulnByID {
		summaryByCanonical[matcher.Canonical(v)] = v.Summary
	}
	newRefs := make([]api.NewVulnRef, 0, len(diffIDs))
	for _, id := range diffIDs {
		newRefs = append(newRefs, api.NewVulnRef{CanonicalID: id, Summary: summaryByCanonical[id]})
	}

	endpointURL := ""
	if i.baseURL != "" {
		endpointURL = i.baseURL + "/app/endpoint/" + endpoint.ID
	}

	if len(diffIDs) > 0 && i.notifier != nil && tenantID != "" {
		ep := endpoint
		url := endpointURL
		go func() {
			tenant, err := i.db.GetTenantByID(context.Background(), tenantID)
			if err != nil {
				slog.Warn("email notification: could not read tenant", "err", err)
				return
			}
			if !tenant.NotifyEnabled {
				slog.Debug("email notification: disabled for tenant", "tenant", tenantID)
				return
			}
			if len(tenant.Recipients) == 0 {
				slog.Debug("email notification: no recipients configured", "tenant", tenantID)
				return
			}
			slog.Info("dispatching email notification", "new_vulns", len(diffIDs), "recipients", len(tenant.Recipients))
			vulns := buildNewVulns(diffIDs, enriched)
			if err := i.notifier.SendNew(context.Background(), ep, vulns, tenant.Recipients, url); err != nil {
				slog.Warn("email notification failed", "err", err)
			} else {
				slog.Info("email notification sent", "recipients", tenant.Recipients)
			}
		}()
	}

	return Result{
		EndpointID:         endpoint.ID,
		VulnCount:          len(newCanonicalIDs),
		NewVulnerabilities: newRefs,
		EndpointURL:        endpointURL,
	}, nil
}

// enrichMatches adds package metadata (name, version, ecosystem, dirs) to each match.
func enrichMatches(matches []matcher.Match, packages []api.Package) []matcher.Match {
	byPurl := make(map[string]api.Package, len(packages))
	for _, p := range packages {
		byPurl[p.Purl] = p
	}
	enriched := make([]matcher.Match, len(matches))
	copy(enriched, matches)
	for idx := range enriched {
		if p, ok := byPurl[enriched[idx].Purl]; ok {
			enriched[idx].PackageName = p.Name
			enriched[idx].PackageVersion = p.Version
			enriched[idx].PackageEcosystem = p.Ecosystem
			enriched[idx].Dirs = p.Dirs
		}
	}
	return enriched
}

func diff(newSet map[string]struct{}, prev []string) []string {
	prevSet := make(map[string]struct{}, len(prev))
	for _, id := range prev {
		prevSet[id] = struct{}{}
	}
	var added []string
	for id := range newSet {
		if _, exists := prevSet[id]; !exists {
			added = append(added, id)
		}
	}
	return added
}

func setToSlice(s map[string]struct{}) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

func buildNewVulns(canonicalIDs []string, matches []matcher.Match) []notifier.NewVuln {
	byCanonical := make(map[string]matcher.Match)
	for _, m := range matches {
		c := matcher.Canonical(m.Vulnerability)
		byCanonical[c] = m
	}
	var vulns []notifier.NewVuln
	for _, id := range canonicalIDs {
		if m, ok := byCanonical[id]; ok {
			vulns = append(vulns, notifier.NewVuln{
				CanonicalID: id,
				Summary:     m.Vulnerability.Summary,
				PackageName: m.PackageName,
				PackageVer:  m.PackageVersion,
				Purl:        m.Purl,
			})
		}
	}
	return vulns
}
