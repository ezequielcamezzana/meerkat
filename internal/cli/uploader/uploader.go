// Package uploader sends the generated inventory to the meerkat server.
package uploader

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

const (
	pendingCap = 50
	uploadPath = "/v1/inventories"
	timeout    = 3 * time.Minute
)

type UploadResult struct {
	NewVulnerabilities []api.NewVulnRef
	EndpointURL        string
}

type Uploader struct {
	serverURL  string
	token      string
	pendingDir string
	client     *http.Client
}

func New(serverURL, token, pendingDir string) *Uploader {
	return &Uploader{
		serverURL:  serverURL,
		token:      token,
		pendingDir: pendingDir,
		client:     &http.Client{Timeout: timeout},
	}
}

func (u *Uploader) Upload(ctx context.Context, inv api.Inventory) (UploadResult, error) {
	if u.serverURL == "" {
		return UploadResult{}, u.writePending(inv)
	}

	body, err := json.Marshal(inv)
	if err != nil {
		return UploadResult{}, fmt.Errorf("marshaling inventory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.serverURL+uploadPath, bytes.NewReader(body))
	if err != nil {
		return UploadResult{}, fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if u.token != "" {
		req.Header.Set("Authorization", "Bearer "+u.token)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		if qErr := u.writePending(inv); qErr != nil {
			return UploadResult{}, fmt.Errorf("upload failed (%w); also failed to queue: %v", err, qErr)
		}
		return UploadResult{}, fmt.Errorf("upload failed, queued for retry: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var parsed struct {
			NewVulnerabilities []api.NewVulnRef `json:"new_vulnerabilities"`
			EndpointURL        string           `json:"endpoint_url"`
		}
		json.NewDecoder(resp.Body).Decode(&parsed)
		return UploadResult{
			NewVulnerabilities: parsed.NewVulnerabilities,
			EndpointURL:        parsed.EndpointURL,
		}, nil
	}

	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return UploadResult{}, fmt.Errorf("upload rejected by server: HTTP %d", resp.StatusCode)
	}

	// 5xx — transient, queue for retry
	if qErr := u.writePending(inv); qErr != nil {
		return UploadResult{}, fmt.Errorf("server error HTTP %d; also failed to queue: %v", resp.StatusCode, qErr)
	}
	return UploadResult{}, fmt.Errorf("server error HTTP %d, queued for retry", resp.StatusCode)
}

func (u *Uploader) DrainPending(ctx context.Context) (int, error) {
	entries, err := u.listPending()
	if err != nil {
		return 0, err
	}

	drained := 0
	for _, path := range entries {
		data, err := os.ReadFile(path)
		if err != nil {
			return drained, fmt.Errorf("reading pending file: %w", err)
		}

		var inv api.Inventory
		if err := json.Unmarshal(data, &inv); err != nil {
			return drained, fmt.Errorf("parsing pending file: %w", err)
		}

		// Upload directly to avoid re-queuing on failure
		if err := u.uploadDirect(ctx, inv); err != nil {
			return drained, err
		}

		os.Remove(path)
		drained++
	}
	return drained, nil
}

func (u *Uploader) writePending(inv api.Inventory) error {
	if err := os.MkdirAll(u.pendingDir, 0700); err != nil {
		return fmt.Errorf("creating pending dir: %w", err)
	}

	// Enforce cap: remove oldest if at limit
	if entries, err := u.listPending(); err == nil && len(entries) >= pendingCap {
		os.Remove(entries[0])
	}

	path := filepath.Join(u.pendingDir, inv.Scan.ID+".json")
	data, err := json.Marshal(inv)
	if err != nil {
		return fmt.Errorf("marshaling inventory: %w", err)
	}
	return os.WriteFile(path, data, 0600)
}

// uploadDirect sends to server without falling back to pending queue.
func (u *Uploader) uploadDirect(ctx context.Context, inv api.Inventory) error {
	body, err := json.Marshal(inv)
	if err != nil {
		return fmt.Errorf("marshaling inventory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.serverURL+uploadPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if u.token != "" {
		req.Header.Set("Authorization", "Bearer "+u.token)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("server returned HTTP %d", resp.StatusCode)
}

func (u *Uploader) listPending() ([]string, error) {
	entries, err := os.ReadDir(u.pendingDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing pending dir: %w", err)
	}

	var paths []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			paths = append(paths, filepath.Join(u.pendingDir, e.Name()))
		}
	}
	sort.Strings(paths)
	return paths, nil
}
