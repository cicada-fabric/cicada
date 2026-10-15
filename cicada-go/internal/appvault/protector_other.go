//go:build !windows

package appvault

func NewPlatformProtector() (Protector, error) { return nil, ErrUnsupportedOS }
