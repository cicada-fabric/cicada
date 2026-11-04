//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func TestNativeThreadHubAliasUsesExactEnabledDTOAndRejectsUnknownOrRemoved(t *testing.T) {
	a, b := syntheticNodeHubView(0), syntheticNodeHubView(1)
	a.Alias, b.Alias = "原 Hub", "Aliyun"
	view := LocalNodeHubList{Format: LocalNodeHubsFormat, Revision: 3, ManagerState: "RUNNING", Connections: []LocalNodeHubView{a, b}}
	root := privateLocalNodeRoot(t)
	list := func(_ context.Context, selected string) (LocalNodeHubList, error) {
		if selected != root {
			t.Fatal("alias inspected another installation")
		}
		return view, nil
	}
	got, err := nativeThreadHubAlias(context.Background(), root, b.Alias, b.NodeID, list)
	if err != nil || got != b {
		t.Fatal("explicit alias did not select its exact DTO", err)
	}
	if _, err := nativeThreadHubAlias(context.Background(), root, "Ali", b.NodeID, list); !errors.Is(err, ErrLocalNodeNotRunning) {
		t.Fatal("prefix alias guessed a Hub", err)
	}
	if _, err := nativeThreadHubAlias(context.Background(), root, b.Alias, "SYNTHETIC-other-node", list); !errors.Is(err, ErrLocalNodeNotReady) {
		t.Fatal("alias changed explicit Node", err)
	}
	view.Connections[1].DesiredState, view.Connections[1].RuntimeState = "REMOVING", "STOPPING"
	if _, err := nativeThreadHubAlias(context.Background(), root, b.Alias, "", list); !errors.Is(err, ErrLocalNodeNotReady) {
		t.Fatal("removed selected alias fell back to A", err)
	}
	view.Connections[1] = b
	view.Connections[1].Alias = a.Alias
	if _, err := nativeThreadHubAlias(context.Background(), root, a.Alias, "", list); !errors.Is(err, ErrLocalNodeHubConfig) {
		t.Fatal("ambiguous alias bypassed closed DTO", err)
	}
}

func TestNativeThreadHubAliasAndHubIDFlagsAreMutuallyExclusiveBeforeRecordAccess(t *testing.T) {
	var out bytes.Buffer
	err := nativeThreadOperatorWithManager("join", []string{"--thread", "SYNTHETIC-selector-never-opened", "--name", "Synthetic", "--hub", "Aliyun", "--hub-id", "SYNTHETIC-hub"}, &out, nil, nil)
	if !errors.Is(err, ErrLocalNodeHubConfig) || out.Len() != 0 {
		t.Fatal("mutually exclusive selection reached native record or command", err)
	}
}
