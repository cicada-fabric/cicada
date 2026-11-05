//go:build !linux

package componentinstall

import "errors"

func prepareShellIntegration(string, string, string) (shellIntegrationChange, error) {
	return nil, errors.New("shell integration requires Linux Bash")
}
