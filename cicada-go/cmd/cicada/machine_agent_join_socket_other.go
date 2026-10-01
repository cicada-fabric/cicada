//go:build !unix

package main

import (
	"errors"
	"os"
)

var errLocalJoinUnixSocketUnsupported = errors.New("local Node Join Unix sockets are unsupported on this platform")

func machineAgentJoinSocketPlatformPathMaxBytes() int   { return 0 }
func machineAgentJoinSocketCurrentUID() (uint32, error) { return 0, errLocalJoinUnixSocketUnsupported }
func machineAgentJoinSocketRuntimeDirectory() (string, error) {
	return "", errLocalJoinUnixSocketUnsupported
}
func machineAgentJoinSocketOwner(os.FileInfo) (uint32, bool) { return 0, false }
func prepareMachineAgentJoinSocketRuntimeDirectory(string) error {
	return errLocalJoinUnixSocketUnsupported
}
func prepareMachineAgentJoinSocketDirectory(string) error { return errLocalJoinUnixSocketUnsupported }
func validateMachineAgentJoinSocketForDial(string) error  { return errLocalJoinUnixSocketUnsupported }
func validateMachineAgentJoinSocketForDialAs(string, uint32) error {
	return errLocalJoinUnixSocketUnsupported
}
func machineAgentJoinSocketEntry(string, uint32, bool) (os.FileInfo, error) {
	return nil, errLocalJoinUnixSocketUnsupported
}
func removeStaleMachineAgentJoinSocket(string) error { return errLocalJoinUnixSocketUnsupported }
func removeStaleMachineAgentJoinSocketAs(string, uint32) error {
	return errLocalJoinUnixSocketUnsupported
}
func removeOwnedMachineAgentJoinSocket(string, os.FileInfo) error {
	return errLocalJoinUnixSocketUnsupported
}
