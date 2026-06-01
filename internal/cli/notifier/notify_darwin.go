//go:build darwin

package notifier

import (
	"fmt"
	"os/exec"
)

func defaultAlertFn(title, body string, _ any) error {
	if path, err := exec.LookPath("terminal-notifier"); err == nil {
		return exec.Command(path, "-title", title, "-message", body).Run()
	}
	osa, err := exec.LookPath("osascript")
	if err != nil {
		return err
	}
	return exec.Command(osa, "-e", fmt.Sprintf("display notification %q with title %q", body, title)).Run()
}
