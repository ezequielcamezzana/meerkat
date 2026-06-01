//go:build !darwin

package notifier

import "github.com/gen2brain/beeep"

func defaultAlertFn(title, body string, icon any) error {
	return beeep.Alert(title, body, icon)
}
