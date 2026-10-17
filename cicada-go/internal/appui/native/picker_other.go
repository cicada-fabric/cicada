//go:build !windows

package native

import "errors"

const ownerFilePickerAvailable = false

func choosePEMFile(string) (string, error) {
	return "", errors.New("native Owner PEM selection is supported on Windows only")
}

func chooseOwnerPublicDestination(string) (string, error) {
	return "", errors.New("native public key export is supported on Windows only")
}
