package notifier

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

type SMTPConfig struct {
	Host string
	Port int
	User string
	Pass string
	From string
}

type EmailNotifier struct {
	smtp SMTPConfig
}

func NewEmailNotifier(cfg SMTPConfig) Notifier {
	if cfg.Host == "" || cfg.From == "" {
		return &NoopNotifier{}
	}
	return &EmailNotifier{smtp: cfg}
}

func (e *EmailNotifier) SendNew(_ context.Context, endpoint api.Endpoint, vulns []NewVuln, recipients []string, endpointURL string) error {
	if len(recipients) == 0 {
		return nil
	}

	body := renderBody(endpoint, vulns, endpointURL)
	subject := fmt.Sprintf("[meerkat] %d new vulnerability(ies) on %s", len(vulns), endpoint.Hostname)
	msg := []byte("From: " + e.smtp.From + "\r\n" +
		"To: " + strings.Join(recipients, ", ") + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		body)

	addr := fmt.Sprintf("%s:%d", e.smtp.Host, e.smtp.Port)

	var auth smtp.Auth
	if e.smtp.User != "" {
		auth = smtp.PlainAuth("", e.smtp.User, e.smtp.Pass, e.smtp.Host)
	}

	return smtp.SendMail(addr, auth, e.smtp.From, recipients, msg)
}
