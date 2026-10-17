package store

import (
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3StoreBoundHeartbeatAfterSameSecondApprovalKeepsPrecision(t *testing.T) {
	f := n3Fixture(t, true)
	f.now = f.now.Truncate(time.Second).Add(123456789 * time.Nanosecond)
	g := f.activate(t)
	original := f.client(t, g, 1, f.now.Add(2*time.Second))
	packet, err := f.db.ProcessHubAppNodeClient(original)
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := wire.OpenAppNodeConfirmationResponse(f.device, f.hub, g, original.Packet, packet, 1)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := time.Parse(time.RFC3339Nano, confirmed.Binding.ApprovedAt)
	if err != nil {
		t.Fatal(err)
	}
	heartbeat := approved.Add(10 * time.Nanosecond)
	if heartbeat.Unix() != approved.Unix() {
		t.Fatal("synthetic same-second fixture changed")
	}
	var credential string
	if err = f.db.db.QueryRow(`SELECT node_credential_digest FROM node_owner_bindings_v2 WHERE id=?`, confirmed.Binding.OwnerBindingID).Scan(&credential); err != nil {
		t.Fatal(err)
	}
	if err = f.db.recordBoundNodeMachineHeartbeat(credential, "", nil, nil, func() time.Time { return heartbeat }); err != nil {
		t.Fatal(err)
	}
	status, _ := wire.NewAppNodeStatus(f.session, g.GrantID, heartbeat.Add(time.Nanosecond))
	_, observed, _ := f.call(t, status, heartbeat.Add(time.Nanosecond))
	if observed.Result.Node == nil || observed.Result.Node.Connectivity != "CONNECTED" || observed.Result.Node.LastHeartbeatAt != appNodeStamp(heartbeat) {
		t.Fatal("accepted heartbeat was truncated before its exact same-second approval")
	}
	// The other existing bound Fabric heartbeat writer must not overwrite a
	// precise accepted timestamp with whole-second time either.
	heartbeat = heartbeat.Add(10 * time.Nanosecond)
	if err = f.db.recordBoundNodeHeartbeat(credential, func() time.Time { return heartbeat }); err != nil {
		t.Fatal(err)
	}
	status, _ = wire.NewAppNodeStatus(f.session, g.GrantID, heartbeat.Add(time.Nanosecond))
	_, observed, _ = f.call(t, status, heartbeat.Add(time.Nanosecond))
	if observed.Result.Node == nil || observed.Result.Node.Connectivity != "CONNECTED" || observed.Result.Node.LastHeartbeatAt != appNodeStamp(heartbeat) {
		t.Fatal("secondary bound heartbeat writer truncated accepted time")
	}
	machine, err := f.db.GetMachine(g.Candidate.NodeID)
	if err != nil || machine.Status != "offline" {
		t.Fatal("heartbeat made a Worker available", err)
	}
}
