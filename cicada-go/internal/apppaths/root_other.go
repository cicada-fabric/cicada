//go:build !linux && !darwin && !windows

package apppaths

func validatePlatformRoot(string) error { return ErrInvalidRoot }
