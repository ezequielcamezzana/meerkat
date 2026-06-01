package notifier

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

func TestNewBrevoNotifier_missingConfig_returnsNoop(t *testing.T) {
	if _, ok := NewBrevoNotifier("", "from@x.com", "", "", nil).(*NoopNotifier); !ok {
		t.Fatal("expected NoopNotifier when API key is empty")
	}
	if _, ok := NewBrevoNotifier("xkeysib-abc", "", "", "", nil).(*NoopNotifier); !ok {
		t.Fatal("expected NoopNotifier when From is empty")
	}
}

func TestBrevoNotifier_SendNew_postsExpectedRequest(t *testing.T) {
	var gotKey, gotPath string
	var payload brevoEmail

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("api-key")
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &payload)
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"messageId":"<1@brevo>"}`))
	}))
	defer srv.Close()

	n := NewBrevoNotifier("xkeysib-secret", "alerts@example.com", "meerkat", srv.URL, srv.Client())
	endpoint := api.Endpoint{Hostname: "web-01", Tags: []string{"prod"}}
	vulns := []NewVuln{{CanonicalID: "CVE-2024-0001", Summary: "bug", PackageName: "foo", PackageVer: "1.0"}}

	err := n.SendNew(context.Background(), endpoint, vulns, []string{"a@x.com", "b@x.com"}, "http://meerkat/endpoint/1")
	if err != nil {
		t.Fatalf("SendNew error: %v", err)
	}

	if gotPath != "/v3/smtp/email" {
		t.Errorf("path = %q, want /v3/smtp/email", gotPath)
	}
	if gotKey != "xkeysib-secret" {
		t.Errorf("api-key header = %q", gotKey)
	}
	if payload.Sender.Email != "alerts@example.com" {
		t.Errorf("sender = %q", payload.Sender.Email)
	}
	if len(payload.To) != 2 || payload.To[0].Email != "a@x.com" {
		t.Errorf("recipients = %+v", payload.To)
	}
	if payload.Subject == "" || payload.TextContent == "" {
		t.Error("subject/textContent should not be empty")
	}
	if payload.HTMLContent == "" {
		t.Error("htmlContent should not be empty")
	}
	if !strings.Contains(payload.HTMLContent, "CVE-2024-0001") ||
		!strings.Contains(payload.HTMLContent, "View endpoint") {
		t.Error("htmlContent missing CVE or CTA")
	}
}

func TestBrevoNotifier_SendNew_noRecipients_returnsNil(t *testing.T) {
	n := NewBrevoNotifier("xkeysib-secret", "alerts@example.com", "meerkat", "http://unused.local", http.DefaultClient)
	if err := n.SendNew(context.Background(), api.Endpoint{}, nil, nil, ""); err != nil {
		t.Fatalf("expected nil for no recipients, got %v", err)
	}
}

func TestBrevoNotifier_SendNew_apiError_returnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"code":"invalid_parameter","message":"sender not verified"}`))
	}))
	defer srv.Close()

	n := NewBrevoNotifier("xkeysib-secret", "alerts@example.com", "meerkat", srv.URL, srv.Client())
	err := n.SendNew(context.Background(), api.Endpoint{Hostname: "h"}, []NewVuln{{CanonicalID: "CVE-1"}}, []string{"a@x.com"}, "")
	if err == nil {
		t.Fatal("expected error on HTTP 400, got nil")
	}
}
