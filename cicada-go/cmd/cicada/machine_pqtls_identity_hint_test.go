package main

import (
	"os"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func machinePQIdentityHintFixture(t *testing.T) (*machineHubContext, *machineNodeControlClient) {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0700)
	nodeID, origin := "synthetic-hint-node", "https://192.0.2.1:8443"
	if _, _, err := loadOrCreateMachineNodeIdentity(root, nodeID); err != nil {
		t.Fatal(err)
	}
	client, err := openMachineNodeControlClient(root, origin, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	hubKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	s := &client.state
	s.HubID = "synthetic-hint-hub"
	s.HubKeyID = hubKey.Public().ID
	s.HubFingerprint = nodewire.IdentityFingerprint(hubKey.Public())
	s.HubKeyVersion = 1
	s.HubPublicIdentity = hubKey.Public()
	s.NodeKeyID = client.identity.Public().ID
	s.NodeKeyFingerprint = nodewire.IdentityFingerprint(client.identity.Public())
	s.NodeKeyVersion = 1
	s.NodeKeyEpoch = 1
	s.BindingID = "synthetic-hint-binding"
	s.BindingVersion = 1
	s.ApprovedRequestID = "synthetic-hint-request"
	s.ApprovedRequestVersion = 1
	s.ApprovedCandidateDigest = strings.Repeat("a", 64)
	if err := client.persistLocked(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { machineNodeControlClients.Delete(client.statePath) })
	return &machineHubContext{StateDir: root, WriterRoot: root, NodeID: nodeID, Origin: origin}, client
}
func TestMachinePQIdentityHintUsesExistingApprovedStateOnly(t *testing.T) {
	for _, name := range []string{"approved", "pending", "missing-state", "wrong-node", "wrong-origin", "missing-approved-metadata", "explicit-wrong-hub"} {
		t.Run(name, func(t *testing.T) {
			hub, client := machinePQIdentityHintFixture(t)
			wantSuccess := name == "approved" || name == "explicit-wrong-hub"
			switch name {
			case "pending":
				client.state.BindingID = ""
				client.persistLocked()
			case "missing-state":
				os.Remove(client.statePath)
			case "wrong-node":
				hub.NodeID = "foreign-node"
			case "wrong-origin":
				hub.Origin = "https://192.0.2.2:8443"
			case "missing-approved-metadata":
				client.state.ApprovedRequestID = ""
				client.persistLocked()
			case "explicit-wrong-hub":
				hub.HubID = "explicit-foreign-hub"
			}
			err := recoverMachinePQHubIdentityHint(hub, "unused-config-must-never-be-read")
			if (err == nil) != wantSuccess {
				t.Fatal("unexpected identity hint result", err)
			}
			if name == "approved" && (hub.HubID != client.state.HubID || hub.approvedHubID == nil || *hub.approvedHubID.Load() != hub.HubID) {
				t.Fatal("existing approved pin not restored")
			}
			if name == "explicit-wrong-hub" && hub.HubID != "explicit-foreign-hub" {
				t.Fatal("explicit foreign Hub pin overwritten")
			}
			if !wantSuccess && hub.HubID != "" {
				t.Fatal("refused state promoted to identity hint")
			}
		})
	}
}
