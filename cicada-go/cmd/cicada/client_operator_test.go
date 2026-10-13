package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/clientoperator"
)

func TestClientOperatorRejectsArbitraryRPCAndSecretFlags(t *testing.T) {
	for _, args := range [][]string{{"rpc", "--operation", "intent.submit"}, {"nodes", "preview", "--profile", "unused", "--code", "SENSITIVE"}, {"enroll", "--profile", "unused", "--grant", "SENSITIVE"}, {"prepare", "--profile", "unused", "--owner-private", "SENSITIVE"}} {
		var output bytes.Buffer
		if err := clientOperatorCommand(args, strings.NewReader("approve\n"), &output); err == nil {
			t.Fatal("accepted unbounded or secret command")
		}
		if strings.Contains(output.String(), "SENSITIVE") {
			t.Fatal("secret entered output")
		}
	}
}

func TestClientOperatorApprovalRejectsPipesAndNonTerminalDevices(t *testing.T) {
	var output bytes.Buffer
	if err := clientOperatorApproval(strings.NewReader("approve\n"), &output, clientoperator.NodeCandidate{}); err == nil {
		t.Fatal("accepted scripted approval")
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = clientOperatorApproval(f, &output, clientoperator.NodeCandidate{}); err == nil {
		t.Fatal("accepted character device as terminal")
	}
	if output.Len() != 0 {
		t.Fatal("prompted without real interactive terminal")
	}
}

func TestClientOperatorReviewIncludesUpgradeScopeAndEscapesName(t *testing.T) {
	text := clientOperatorReviewText(clientoperator.NodeCandidate{NodeName: "synthetic\nname", Mode: "UPGRADE", NodeKeyEpoch: 7, BindingID: "synthetic-binding", BindingVersion: 3, HubNodeControlKeyID: "synthetic-hub-key", HubNodeControlKeyVersion: 5})
	for _, field := range []string{"synthetic\\nname", "Mode: UPGRADE", "Node key epoch: 7", "Target binding: synthetic-binding version 3", "synthetic-hub-key version 5"} {
		if !strings.Contains(text, field) {
			t.Fatalf("review omitted %s", field)
		}
	}
}
