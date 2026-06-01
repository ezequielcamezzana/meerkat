package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

// BrevoNotifier sends mail through Brevo's transactional email HTTP API
// (POST /v3/smtp/email), authenticated with an `api-key` header.
type BrevoNotifier struct {
	apiKey   string
	from     string
	fromName string
	baseURL  string
	client   *http.Client
}

// NewBrevoNotifier returns a NoopNotifier when the API key or sender is unset,
// so the server runs fine without email configured.
func NewBrevoNotifier(apiKey, from, fromName, baseURL string, client *http.Client) Notifier {
	if apiKey == "" || from == "" {
		return &NoopNotifier{}
	}
	if baseURL == "" {
		baseURL = "https://api.brevo.com"
	}
	if fromName == "" {
		fromName = "meerkat"
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &BrevoNotifier{apiKey: apiKey, from: from, fromName: fromName, baseURL: baseURL, client: client}
}

type brevoSender struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type brevoRecipient struct {
	Email string `json:"email"`
}

type brevoEmail struct {
	Sender      brevoSender      `json:"sender"`
	To          []brevoRecipient `json:"to"`
	Subject     string           `json:"subject"`
	HTMLContent string           `json:"htmlContent,omitempty"`
	TextContent string           `json:"textContent"`
}

// logoURLFrom derives the hosted icon URL from the endpoint link's origin, so
// the email can reference the same asset the dashboard serves.
func logoURLFrom(endpointURL string) string {
	if endpointURL == "" {
		return ""
	}
	u, err := url.Parse(endpointURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/app/assets/meerkat-icon.png"
}

func (b *BrevoNotifier) SendNew(ctx context.Context, endpoint api.Endpoint, vulns []NewVuln, recipients []string, endpointURL string) error {
	if len(recipients) == 0 {
		return nil
	}

	to := make([]brevoRecipient, len(recipients))
	for i, r := range recipients {
		to[i] = brevoRecipient{Email: r}
	}
	payload := brevoEmail{
		Sender:      brevoSender{Email: b.from, Name: b.fromName},
		To:          to,
		Subject:     fmt.Sprintf("[meerkat] %d new vulnerability(ies) on %s", len(vulns), endpoint.Hostname),
		HTMLContent: renderHTMLBody(endpoint, vulns, endpointURL, logoURLFrom(endpointURL)),
		TextContent: renderBody(endpoint, vulns, endpointURL),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling brevo email: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+"/v3/smtp/email", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building brevo request: %w", err)
	}
	req.Header.Set("api-key", b.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("brevo send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("brevo returned HTTP %d: %s", resp.StatusCode, string(msg))
	}
	return nil
}
