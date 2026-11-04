//go:build !linux

package main

import (
	"context"
	"errors"
	"io"
)

var errNodeHubUnsupported = errors.New("NODE_HUB_UNAVAILABLE: Linux user service required")

func ListLocalNodeHubConnections(context.Context, string) (LocalNodeHubList, error) {
	return LocalNodeHubList{}, errNodeHubUnsupported
}
func AddLocalNodeHubConnection(context.Context, LocalNodeHubAddInput) (LocalNodeHubView, error) {
	return LocalNodeHubView{}, errNodeHubUnsupported
}
func RemoveLocalNodeHubConnection(context.Context, LocalNodeHubSelection) (LocalNodeHubRemoval, error) {
	return LocalNodeHubRemoval{}, errNodeHubUnsupported
}

func nodeHubsCommand([]string, io.Writer) error  { return errNodeHubUnsupported }
func nodeHubManagerDaemonCommand([]string) error { return errNodeHubUnsupported }
func checkManagedMachineHubFence(ctx context.Context) error {
	h, _ := machineHubFrom(ctx)
	if h.ManagedConnectionID != "" {
		return errNodeHubUnsupported
	}
	return nil
}
func checkManagedLocalNodePin(ctx context.Context, p LocalNodeConnectionPin) error {
	if p.ConnectionID != "" {
		return errNodeHubUnsupported
	}
	return nil
}
func installNodeHubStateReference(context.Context, *machineHubContext) error { return nil }
func ResolveAdoptedLocalNodeConnection(context.Context, LocalNodeConnectionPin) (LocalNodeConnection, error) {
	return LocalNodeConnection{}, errNodeHubUnsupported
}
func ValidateRetainedLocalNodeArtifacts(context.Context, LocalNodeConnectionPin, LocalNodeConnectionPin) error {
	return errNodeHubUnsupported
}
func beginManagedNativeAdmission(ctx context.Context) (func(), error) {
	if err := checkManagedMachineHubFence(ctx); err != nil {
		return nil, err
	}
	return func() {}, nil
}
