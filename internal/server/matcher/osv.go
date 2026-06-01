package matcher

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
	"golang.org/x/sync/semaphore"
)

type OSVConfig struct {
	BaseURL       string
	Timeout       time.Duration
	MaxConcurrent int
	HTTPClient    *http.Client
}

type OSVMatcher struct {
	cfg    OSVConfig
	client *http.Client
}

func NewOSVMatcher(cfg OSVConfig) *OSVMatcher {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.osv.dev"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.MaxConcurrent == 0 {
		cfg.MaxConcurrent = 10
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: cfg.Timeout}
	}
	return &OSVMatcher{cfg: cfg, client: client}
}

// OSV request/response types

type osvQuery struct {
	Package struct {
		PURL string `json:"purl"`
	} `json:"package"`
}

type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvVuln struct {
	ID        string          `json:"id"`
	Aliases   []string        `json:"aliases"`
	Upstream  []string        `json:"upstream"`
	Summary   string          `json:"summary"`
	Details   string          `json:"details"`
	Published string          `json:"published"`
	Modified  string          `json:"modified"`
	Raw       json.RawMessage `json:"-"`
}

const batchChunkSize = 1000

// QueryBatch asks OSV which vuln IDs hit each package PURL. It does NOT fetch
// vuln details — that's FetchVulns. Returns a map of purl -> []vulnID.
func (m *OSVMatcher) QueryBatch(ctx context.Context, packages []api.Package) (map[string][]string, error) {
	idsByPurl := make(map[string][]string)
	if len(packages) == 0 {
		return idsByPurl, nil
	}

	// OSV batch API limits queries per request; chunk to stay under the limit.
	for start := 0; start < len(packages); start += batchChunkSize {
		end := start + batchChunkSize
		if end > len(packages) {
			end = len(packages)
		}
		chunk := packages[start:end]

		req := osvBatchRequest{Queries: make([]osvQuery, len(chunk))}
		for i, p := range chunk {
			req.Queries[i].Package.PURL = p.Purl
		}

		batchResp, err := m.queryBatch(ctx, req)
		if err != nil {
			return nil, err
		}

		for i, result := range batchResp.Results {
			if i >= len(chunk) {
				break
			}
			purl := chunk[i].Purl
			for _, v := range result.Vulns {
				idsByPurl[purl] = append(idsByPurl[purl], v.ID)
			}
		}
	}
	return idsByPurl, nil
}

// Match runs the full pipeline (querybatch + fetch all + assemble) with no
// caching. Kept as a convenience for tests and the uncached path.
func (m *OSVMatcher) Match(ctx context.Context, packages []api.Package) ([]Match, error) {
	idsByPurl, err := m.QueryBatch(ctx, packages)
	if err != nil {
		return nil, err
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
	vulns, err := m.FetchVulns(ctx, ids)
	if err != nil {
		return nil, err
	}
	vulnByID := make(map[string]Vulnerability, len(vulns))
	for _, v := range vulns {
		vulnByID[v.ID] = v
	}
	return AssembleMatches(packages, idsByPurl, vulnByID), nil
}

func (m *OSVMatcher) queryBatch(ctx context.Context, req osvBatchRequest) (*osvBatchResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling batch query: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.BaseURL+"/v1/querybatch", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building batch request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("osv querybatch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusBadRequest {
			// WARNING: OSV rejects the whole batch when any single PURL is malformed
			// or from an unsupported ecosystem. Treat as no matches so ingest succeeds.
			slog.Warn("osv querybatch rejected (unsupported PURL?)", "body", string(body))
			return &osvBatchResponse{}, nil
		}
		return nil, fmt.Errorf("osv querybatch returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var result osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding batch response: %w", err)
	}
	return &result, nil
}

// FetchVulns fetches full vuln records by ID (GET /v1/vulns/{id}), in parallel.
func (m *OSVMatcher) FetchVulns(ctx context.Context, ids []string) ([]Vulnerability, error) {
	sem := semaphore.NewWeighted(int64(m.cfg.MaxConcurrent))
	results := make([]Vulnerability, len(ids))
	errs := make([]error, len(ids))
	var wg sync.WaitGroup

	for i, id := range ids {
		wg.Add(1)
		go func(idx int, vulnID string) {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				errs[idx] = err
				return
			}
			defer sem.Release(1)

			v, err := m.fetchVuln(ctx, vulnID)
			if err != nil {
				errs[idx] = err
				return
			}
			results[idx] = *v
		}(i, id)
	}

	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

func (m *OSVMatcher) fetchVuln(ctx context.Context, id string) (*Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.BaseURL+"/v1/vulns/"+id, nil)
	if err != nil {
		return nil, fmt.Errorf("building vuln request: %w", err)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching vuln %s: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv vuln %s returned HTTP %d", id, resp.StatusCode)
	}

	var raw json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding vuln %s: %w", id, err)
	}

	var v osvVuln
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parsing vuln %s: %w", id, err)
	}

	vuln := &Vulnerability{
		ID:       v.ID,
		Aliases:  v.Aliases,
		Upstream: v.Upstream,
		Summary:  v.Summary,
		Details:  v.Details,
		Source:   "osv",
		Raw:      raw,
	}
	if v.Published != "" {
		vuln.PublishedAt, _ = time.Parse(time.RFC3339, v.Published)
	}
	if v.Modified != "" {
		vuln.ModifiedAt, _ = time.Parse(time.RFC3339, v.Modified)
	}
	return vuln, nil
}
