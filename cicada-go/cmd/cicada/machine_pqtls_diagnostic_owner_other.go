//go:build !linux

package main

import "os"

// On platforms without the Linux UID metadata used by this opt-in sink, the
// directory mode and exclusive owner-created file remain the available checks.
func machinePQOwnedByCurrentUser(os.FileInfo) bool { return true }
