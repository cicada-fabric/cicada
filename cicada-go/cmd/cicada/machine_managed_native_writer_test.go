package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestManagedCodexWriterSerializesSameNativeIDAcrossHubContexts(t *testing.T) {
	root := t.TempDir()
	job := machineJob{MachineID: "node-a", ThreadID: "native-thread-shared"}
	firstContext := withMachineHubContext(context.Background(), machineHubContext{
		HubID: "hub-a", NodeID: "node-a", WriterRoot: root, WriterScope: "account:synthetic"})
	first, err := acquireManagedMachineCodexWriter(firstContext, job, job.ThreadID)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.CheckCurrent(); err != nil {
		t.Fatalf("first lease is not current: %v", err)
	}

	secondContext, cancel := context.WithTimeout(withMachineHubContext(context.Background(), machineHubContext{
		HubID: "hub-b", NodeID: "node-a", WriterRoot: root, WriterScope: "account:synthetic"}), 50*time.Millisecond)
	defer cancel()
	if _, err := acquireManagedMachineCodexWriter(secondContext, job, job.ThreadID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Hub entered the same native Thread before lease release: %v", err)
	}
	firstEpoch := first.Epoch
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	secondContext = withMachineHubContext(context.Background(), machineHubContext{
		HubID: "hub-b", NodeID: "node-a", WriterRoot: root, WriterScope: "account:synthetic"})
	second, err := acquireManagedMachineCodexWriter(secondContext, job, job.ThreadID)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.Epoch != firstEpoch+1 {
		t.Fatalf("native writer owner epoch=%d want=%d", second.Epoch, firstEpoch+1)
	}
	if err := first.CheckCurrent(); err == nil {
		t.Fatal("released prior writer remained eligible to publish a result")
	}
	if err := second.CheckCurrent(); err != nil {
		t.Fatalf("second lease failed current-owner check: %v", err)
	}
	wrongNodeContext := withMachineHubContext(context.Background(), machineHubContext{
		HubID: "hub-b", NodeID: "node-a", WriterRoot: root, WriterScope: "account:synthetic"})
	if _, err := acquireManagedMachineCodexWriter(wrongNodeContext,
		machineJob{MachineID: "node-b"}, "native-thread-shared"); err == nil {
		t.Fatal("managed writer accepted a Worker assigned to a different pinned Node")
	}
}
