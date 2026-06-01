package uploader_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ezequielcamezzana/meerkat/internal/cli/uploader"
	"github.com/ezequielcamezzana/meerkat/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testInventory(id string) api.Inventory {
	return api.Inventory{
		SchemaVersion: "0.1.0",
		Scan:          api.Scan{ID: id},
	}
}

func TestUpload_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/inventories", r.URL.Path)
		assert.Equal(t, "Bearer testtoken", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	dir := t.TempDir()
	u := uploader.New(srv.URL, "testtoken", dir)
	_, err := u.Upload(context.Background(), testInventory("scan-001"))
	require.NoError(t, err)

	entries, _ := os.ReadDir(dir)
	assert.Empty(t, entries, "no pending file should be written on success")
}

func TestUpload_4xx_NoPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	dir := t.TempDir()
	u := uploader.New(srv.URL, "bad", dir)
	_, err := u.Upload(context.Background(), testInventory("scan-002"))
	require.Error(t, err)

	entries, _ := os.ReadDir(dir)
	assert.Empty(t, entries, "4xx should not create a pending file")
}

func TestUpload_5xx_WritesPending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	dir := t.TempDir()
	u := uploader.New(srv.URL, "tok", dir)
	_, err := u.Upload(context.Background(), testInventory("scan-003"))
	require.Error(t, err)

	entries, _ := os.ReadDir(dir)
	require.Len(t, entries, 1)
	assert.Equal(t, "scan-003.json", entries[0].Name())
}

func TestUpload_NetworkError_WritesPending(t *testing.T) {
	dir := t.TempDir()
	u := uploader.New("http://localhost:19999", "tok", dir)
	_, err := u.Upload(context.Background(), testInventory("scan-004"))
	require.Error(t, err)

	entries, _ := os.ReadDir(dir)
	require.Len(t, entries, 1)
}

func TestUpload_NoServerURL_WritesPending(t *testing.T) {
	dir := t.TempDir()
	u := uploader.New("", "", dir)
	_, err := u.Upload(context.Background(), testInventory("scan-005"))
	require.NoError(t, err, "offline mode should not return an error")

	entries, _ := os.ReadDir(dir)
	require.Len(t, entries, 1)
	assert.Equal(t, "scan-005.json", entries[0].Name())
}

func TestDrainPending(t *testing.T) {
	drained := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		drained++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	u := uploader.New(srv.URL, "", dir)

	// Pre-populate two pending files
	for _, id := range []string{"a-001", "b-002"} {
		inv := testInventory(id)
		data, _ := json.Marshal(inv)
		require.NoError(t, os.WriteFile(filepath.Join(dir, id+".json"), data, 0600))
	}

	n, err := u.DrainPending(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, 2, drained)

	entries, _ := os.ReadDir(dir)
	assert.Empty(t, entries, "pending files should be deleted after drain")
}
