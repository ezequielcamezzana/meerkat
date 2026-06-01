package notifier

import (
	"context"
	"strings"
	"testing"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

func TestNewEmailNotifier_noSMTP_returnsNoop(t *testing.T) {
	n := NewEmailNotifier(SMTPConfig{})
	if _, ok := n.(*EmailNotifier); ok {
		t.Fatal("expected NoopNotifier when SMTP not configured, got *EmailNotifier")
	}
	if _, ok := n.(*NoopNotifier); !ok {
		t.Fatal("expected *NoopNotifier when SMTP not configured")
	}
}

func TestNewEmailNotifier_noFrom_returnsNoop(t *testing.T) {
	n := NewEmailNotifier(SMTPConfig{Host: "localhost", Port: 1025})
	if _, ok := n.(*EmailNotifier); ok {
		t.Fatal("expected NoopNotifier when From is empty, got *EmailNotifier")
	}
}

func TestNewEmailNotifier_withSMTP_returnsEmailNotifier(t *testing.T) {
	n := NewEmailNotifier(SMTPConfig{Host: "localhost", Port: 1025, From: "alerts@example.com"})
	if _, ok := n.(*EmailNotifier); !ok {
		t.Fatalf("expected *EmailNotifier, got %T", n)
	}
}

func TestRenderBody_containsCanonicalIDsAndURL(t *testing.T) {
	endpoint := api.Endpoint{
		Hostname: "web-01",
		Tags:     []string{"prod", "web"},
	}
	vulns := []NewVuln{
		{CanonicalID: "CVE-2024-0001", Summary: "A bad bug", PackageName: "foo", PackageVer: "1.0.0"},
		{CanonicalID: "CVE-2024-0002", Summary: "Another bug", PackageName: "bar", PackageVer: "2.0.0"},
	}
	endpointURL := "http://meerkat.local/endpoints/abc123"

	body := renderBody(endpoint, vulns, endpointURL)

	if !strings.Contains(body, "CVE-2024-0001") {
		t.Error("body missing CVE-2024-0001")
	}
	if !strings.Contains(body, "CVE-2024-0002") {
		t.Error("body missing CVE-2024-0002")
	}
	if !strings.Contains(body, endpointURL) {
		t.Error("body missing endpointURL")
	}
	if !strings.Contains(body, "web-01") {
		t.Error("body missing hostname")
	}
}

func TestNoopNotifier_SendNew_newSignature(t *testing.T) {
	n := &NoopNotifier{}
	err := n.SendNew(context.Background(), api.Endpoint{}, nil, []string{"a@b.com"}, "http://x")
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestEmailNotifier_SendNew_invalidHost_returnsError(t *testing.T) {
	n := &EmailNotifier{
		smtp: SMTPConfig{
			Host: "invalid.host.local",
			Port: 9999,
			From: "alerts@example.com",
		},
	}
	endpoint := api.Endpoint{Hostname: "web-01"}
	vulns := []NewVuln{
		{CanonicalID: "CVE-2024-0001", Summary: "bug", PackageName: "pkg", PackageVer: "1.0"},
	}
	err := n.SendNew(context.Background(), endpoint, vulns, []string{"user@example.com"}, "http://meerkat/endpoints/1")
	if err == nil {
		t.Fatal("expected error with invalid SMTP host, got nil")
	}
}

func TestEmailNotifier_SendNew_noRecipients_returnsNil(t *testing.T) {
	n := &EmailNotifier{
		smtp: SMTPConfig{
			Host: "invalid.host.local",
			Port: 9999,
			From: "alerts@example.com",
		},
	}
	err := n.SendNew(context.Background(), api.Endpoint{}, nil, nil, "")
	if err != nil {
		t.Fatalf("expected nil for empty recipients, got %v", err)
	}
}
