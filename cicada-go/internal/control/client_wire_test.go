package control

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
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
