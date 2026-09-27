package control

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestClientControlIdentityIsSeparateAndDurable(t *testing.T) {
	root := t.TempDir()
	config := Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")}
	first, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	hubPublic := first.ClientControlPublicIdentity()
	if err := e2ee.ValidatePublicIdentity(hubPublic); err != nil {
		t.Fatal(err)
	}
	if hubPublic.ID == first.Identity().ID {
		t.Fatal("Client Control key reused peer Contact identity")
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	binding := clientwire.Binding{HubID: "hub-test", OwnerID: first.Identity().ID,
		DeviceID: "android-test", SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest,
		HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID,
		SessionEpoch: binding.SessionEpoch, Sequence: 1, OperationID: "op-test", Operation: "status.snapshot",
		SenderKeyID: device.Public().ID, SenderKeyVersion: 1, ReceiverKeyID: hubPublic.ID, ReceiverKeyVersion: 1}
	wire, err := clientwire.SealRequest(device, hubPublic, binding, route, []byte(`{"cursor":""}`))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := first.OpenClientControlPacket(device.Public(), binding, wire)
	if err != nil || string(opened.Plaintext) != `{"cursor":""}` {
		t.Fatalf("open Client packet: %v", err)
	}
	if err := first.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Shutdown(context.Background())
	if second.ClientControlPublicIdentity().ID != hubPublic.ID {
		t.Fatal("Client Control key changed on Hub restart")
	}
	if _, err := second.OpenClientControlPacket(device.Public(), binding, wire); err != nil {
		t.Fatalf("reopened Hub cannot decrypt: %v", err)
	}
	info, err := os.Stat(filepath.Join(config.StateDir, "e2ee", "client-control-identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("Client Control private key mode = %o", info.Mode().Perm())
	}
}

func TestClientApprovalReadsExcludeUnownedLegacyGoals(t *testing.T) {
	c := newTestControl(t, "success")
	ownerID := c.Identity().ID
	if _, err := c.store.CreateGoal("legacy-goal", "Legacy request", "Done", "", 1,
		"control-local", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.store.CreateOwnedGoal(ownerID, store.Goal{ID: "client-goal", Objective: "Client request",
		SuccessCriteria: "Done", Priority: 1, MachineID: "control-local"}); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][3]string{{"legacy-approval", "legacy-goal", "legacy-worker"}, {"client-approval", "client-goal", "client-worker"}} {
		if _, err := c.store.CreateWorker(pair[2], pair[1], "control-local", filepath.Join(t.TempDir(), "result")); err != nil {
			t.Fatal(err)
		}
		if _, err := c.store.CreateApproval(pair[0], pair[1], pair[2], "review", map[string]string{"action": "inspect"}); err != nil {
			t.Fatal(err)
		}
	}
	approvals, err := c.ClientApprovals(ownerID, true)
	if err != nil || len(approvals) != 1 || approvals[0].ID != "client-approval" {
		t.Fatalf("Client approval projection leaked ownerless legacy row: approvals=%#v err=%v", approvals, err)
	}
	if legacy, err := c.ClientApproval(ownerID, "legacy-approval"); err == nil || legacy != nil {
		t.Fatalf("Client approval lookup exposed ownerless legacy row: approval=%#v err=%v", legacy, err)
	}
}
