package main

import (
	"context"
	"errors"
	"os"
	"sync"
	"syscall"
	"time"
)

// The gate follows original state, not its alias or generation. Shared
// admission covers epoch verification through Start. Remove/adoption commit
// their durable fence on the exclusive side, before cancelling any worker.
func acquireNodeHubAdmission(ctx context.Context, state, node string, exclusive bool) (func(), error) {
	root, err := openLocalNodeDirectory(ctx, machineNodeStateDir(state, node), false)
	if err != nil {
		return nil, ErrLocalNodeHubConfig
	}
	defer root.Close()
	const name = "node-hub-admission.lock"
	f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, e := root.Lstat(name)
		if e != nil || !localNodePrivate(info, false) {
			return nil, ErrLocalNodeHubConfig
		}
		f, err = root.OpenFile(name, os.O_RDWR, 0)
	}
	if err != nil {
		return nil, ErrLocalNodeHubConfig
	}
	info, e := root.Lstat(name)
	opened, se := f.Stat()
	if e != nil || se != nil || !localNodePrivate(info, false) || !os.SameFile(info, opened) {
		f.Close()
		return nil, ErrLocalNodeHubConfig
	}
	mode := syscall.LOCK_SH | syscall.LOCK_NB
	if exclusive {
		mode = syscall.LOCK_EX | syscall.LOCK_NB
	}
	for {
		err = syscall.Flock(int(f.Fd()), mode)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			f.Close()
			return nil, errNodeHubConflict
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, errNodeHubPending
		case <-time.After(5 * time.Millisecond):
		}
	}
	after, e := root.Lstat(name)
	if e != nil || !os.SameFile(after, opened) {
		f.Close()
		return nil, ErrLocalNodeHubConfig
	}
	var once sync.Once
	return func() { once.Do(func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }) }, nil
}

func beginManagedNativeAdmission(ctx context.Context) (func(), error) {
	h, ok := machineHubFrom(ctx)
	if !ok || h.StateDir == "" {
		if ok && h.ManagedConnectionID != "" {
			return nil, ErrLocalNodeHubConfig
		}
		return func() {}, nil
	}
	if _, err := os.Lstat(machineNodeStateDir(h.StateDir, h.NodeID)); errors.Is(err, os.ErrNotExist) && h.ManagedConnectionID == "" {
		return func() {}, nil
	}
	release, err := acquireNodeHubAdmission(ctx, h.StateDir, h.NodeID, false)
	if err != nil {
		return nil, err
	}
	ref, err := readNodeHubStateReference(ctx, h.StateDir, h.NodeID)
	if err != nil || ref != nil && (h.ManagedConnectionID != ref.ConnectionID || h.ManagedUserRoot != ref.UserRoot) {
		release()
		return nil, errNodeHubNotReady
	}
	if err = checkManagedMachineHubFence(ctx); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
