package main

import (
	"context"
	"errors"

	"github.com/cicada-ai/cicada/internal/store"
)

func downloadBoundNodeSnapshot(ctx context.Context, base, nodeID, token string,
	job machineJob, workspace string) error {
	if job.WorkspaceSnapshotDigest == "" {
		return nil
	}
	client, err := machineNodeControlClientFromContext(ctx, nodeWorkerJobsEndpoint(base, nodeID), token)
	if err != nil {
		return err
	}
	if !client.bindingReady() {
		return store.ErrNodeControlMigrationBlocked
	}
	return client.downloadWorkspaceSnapshot(ctx, token, job, workspace)
}

func uploadBoundNodeSnapshot(ctx context.Context, base, nodeID, token string,
	job machineJob, workspace string) (string, error) {
	if job.WorkspaceID == "" {
		return "", errors.New("encrypted workspace snapshot upload requires an authenticated Workspace ID")
	}
	client, err := machineNodeControlClientFromContext(ctx, nodeWorkerJobsEndpoint(base, nodeID), token)
	if err != nil {
		return "", err
	}
	if !client.bindingReady() {
		return "", store.ErrNodeControlMigrationBlocked
	}
	return client.uploadWorkspaceSnapshot(ctx, token, job, workspace)
}
