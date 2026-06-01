//go:build darwin || linux

package service

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const marker = "# meerkat-managed"

type crontabInstaller struct{}

func NewInstaller() Installer { return &crontabInstaller{} }

func (c *crontabInstaller) Install(binaryPath string, interval time.Duration, logPath string) error {
	existing := readCrontab()
	lines := filterMeerkat(existing) // remove any existing entry first
	lines = append(lines, buildCronLine(binaryPath, interval, logPath))
	return writeCrontab(lines)
}

func (c *crontabInstaller) Uninstall() error {
	existing := readCrontab()
	filtered := filterMeerkat(existing)
	if len(filtered) == len(existing) {
		return nil // nothing to remove
	}
	return writeCrontab(filtered)
}

func (c *crontabInstaller) IsInstalled() bool {
	return strings.Contains(readCrontab(), marker)
}

func buildCronLine(binaryPath string, interval time.Duration, logPath string) string {
	expr := durationToCron(interval)
	return fmt.Sprintf("%s %s scan >> %s 2>&1 %s", expr, binaryPath, logPath, marker)
}

// durationToCron converts a duration to a cron expression.
// Minimum granularity is 1 minute.
func durationToCron(d time.Duration) string {
	mins := int(d.Minutes())
	if mins < 1 {
		mins = 1
	}

	if mins < 60 {
		return fmt.Sprintf("*/%d * * * *", mins)
	}

	hours := mins / 60
	if hours == 1 {
		return "0 * * * *"
	}
	if hours < 24 {
		return fmt.Sprintf("0 */%d * * *", hours)
	}
	return "0 0 * * *"
}

func readCrontab() string {
	out, _ := exec.Command("crontab", "-l").Output()
	return string(out)
}

func filterMeerkat(crontab string) []string {
	var out []string
	for _, line := range strings.Split(crontab, "\n") {
		if !strings.Contains(line, marker) {
			out = append(out, line)
		}
	}
	// trim trailing empty lines
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return out
}

func writeCrontab(lines []string) error {
	input := strings.Join(lines, "\n") + "\n"
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = bytes.NewBufferString(input)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("writing crontab: %w\n%s", err, out)
	}
	return nil
}
