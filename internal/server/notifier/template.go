package notifier

import (
	"bytes"
	"fmt"
	htmltemplate "html/template"
	"strings"
	"text/template"

	"github.com/ezequielcamezzana/meerkat/pkg/api"
)

var emailTmpl = template.Must(template.New("email").Parse(`{{.Hostname}} (tags: {{.Tags}}) has {{.Count}} new vulnerability(ies):
{{range .Vulns}}
- {{.CanonicalID}}
  {{.Summary}}
  Package: {{.PackageName}} {{.PackageVer}}
{{end}}
View endpoint: {{.EndpointURL}}
`))

// All styles are inline because email clients ignore <style> blocks. Palette
// follows DESIGN.md: white canvas, neutral grays, one black CTA, orange accent.
var emailHTMLTmpl = htmltemplate.Must(htmltemplate.New("emailHTML").Parse(`<div style="background:#ffffff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;color:#000000;padding:24px;">
  <div style="max-width:520px;margin:0 auto;">
    <div style="margin-bottom:24px;">
      {{if .LogoURL}}<img src="{{.LogoURL}}" alt="meerkat" width="28" height="28" style="vertical-align:middle;border-radius:9999px;margin-right:8px;">{{end}}<span style="font-size:18px;font-weight:600;vertical-align:middle;">meerkat</span>
    </div>
    <h1 style="font-size:20px;font-weight:600;margin:0 0 4px;">{{.Count}} new vulnerabilit{{if eq .Count 1}}y{{else}}ies{{end}} found</h1>
    <p style="font-size:14px;color:#737373;margin:0 0 20px;">on <strong style="color:#000000;">{{.Hostname}}</strong>{{if .Tags}} · {{.Tags}}{{end}}</p>
    <a href="{{.EndpointURL}}" style="display:inline-block;background:#000000;color:#ffffff;text-decoration:none;font-size:14px;font-weight:500;padding:10px 20px;border-radius:9999px;margin-bottom:24px;">View endpoint &rarr;</a>
    <div style="border:1px solid #e5e5e5;border-radius:12px;overflow:hidden;">
      {{range .Vulns}}<div style="padding:14px 16px;border-top:1px solid #e5e5e5;">
        <div style="font-family:ui-monospace,Menlo,monospace;font-size:13px;font-weight:600;color:#000000;">{{.CanonicalID}}</div>
        {{if .Summary}}<div style="font-size:13px;color:#737373;margin-top:3px;">{{.Summary}}</div>{{end}}
        {{if .PackageName}}<div style="font-size:12px;color:#a3a3a3;margin-top:4px;">{{.PackageName}} {{.PackageVer}}</div>{{end}}
      </div>{{end}}
    </div>
    <p style="font-size:12px;color:#a3a3a3;margin-top:20px;">You're receiving this because email alerts are enabled in meerkat.</p>
  </div>
</div>`))

// renderHTMLBody builds the HTML email. logoURL may be empty (the brand then
// falls back to the wordmark only).
func renderHTMLBody(endpoint api.Endpoint, vulns []NewVuln, endpointURL, logoURL string) string {
	data := struct {
		Hostname    string
		Tags        string
		Count       int
		Vulns       []NewVuln
		EndpointURL string
		LogoURL     string
	}{
		Hostname:    endpoint.Hostname,
		Tags:        strings.Join(endpoint.Tags, ", "),
		Count:       len(vulns),
		Vulns:       vulns,
		EndpointURL: endpointURL,
		LogoURL:     logoURL,
	}
	var buf bytes.Buffer
	if err := emailHTMLTmpl.Execute(&buf, data); err != nil {
		return ""
	}
	return buf.String()
}

func renderBody(endpoint api.Endpoint, vulns []NewVuln, endpointURL string) string {
	data := struct {
		Hostname    string
		Tags        string
		Count       int
		Vulns       []NewVuln
		EndpointURL string
	}{
		Hostname:    endpoint.Hostname,
		Tags:        strings.Join(endpoint.Tags, ", "),
		Count:       len(vulns),
		Vulns:       vulns,
		EndpointURL: endpointURL,
	}
	var buf bytes.Buffer
	if err := emailTmpl.Execute(&buf, data); err != nil {
		return fmt.Sprintf("render error: %v", err)
	}
	return buf.String()
}
