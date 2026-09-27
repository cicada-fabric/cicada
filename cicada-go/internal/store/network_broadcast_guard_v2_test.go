package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

// These rows are synthetic test enrollments. Production enrollment is issued
// through the signed Owner Network Join flow.
func mapBroadcastFixtureNetwork(t *testing.T, f *sameGroupBroadcastV2Fixture) string {
	t.Helper()
	hubID, err := f.sealed.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	network, err := f.sealed.store.CreateNetwork(Network{ID: NewID("net"), HubID: hubID,
		Name: "synthetic broadcast scope", OwnerID: f.sealed.ownerID})
	if err != nil {
		t.Fatal(err)
	}
	group, err := f.sealed.store.GetGroup(f.sealed.groupID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.PrepareGroupNetworkMapping(group.ID, network.ID, "synthetic test mapping", group.Version); err != nil {
		t.Fatal(err)
	}
	if err := f.sealed.store.ApproveGroupNetworkMapping(group.ID, network.ID, group.Version); err != nil {
		t.Fatal(err)
	}
	return network.ID
}

func enrollBroadcastFixtureEndpoint(t *testing.T, f *sameGroupBroadcastV2Fixture, networkID string, endpoint sameGroupSealedV1EndpointFixture) {
	t.Helper()
	stamp := now()
	if _, err := f.sealed.store.db.Exec(`INSERT INTO network_memberships_v2
(id,network_id,principal_id,status,created_at,updated_at) VALUES(?,?,?,'active',?,?)`, NewID("nm"), networkID, endpoint.principal, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.sealed.store.db.Exec(`INSERT INTO endpoint_network_memberships_v2
(network_id,endpoint_id,status,nickname,created_at,updated_at) VALUES(?,?,'active',?,?,?)`, networkID, endpoint.id, endpoint.id, stamp, stamp); err != nil {
		t.Fatal(err)
	}
}

func revokeBroadcastFixtureEndpoint(t *testing.T, f *sameGroupBroadcastV2Fixture, networkID string, endpoint sameGroupSealedV1EndpointFixture) {
	t.Helper()
	membership, err := f.sealed.store.GetNetworkMembership(networkID, endpoint.principal)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.sealed.store.RevokeNetworkMembership(networkID, endpoint.principal, membership.Revision); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkGuardSameGroupBroadcastSnapshotAndRetry(t *testing.T) {
	f := newSameGroupBroadcastV2Fixture(t)
	if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_legacy_unmapped")); err != nil {
		t.Fatalf("unmapped PREPARING group lost legacy behavior: %v", err)
	}
	networkID := mapBroadcastFixtureNetwork(t, f)
	if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_no_source_network")); !errors.Is(err, ErrSameGroupBroadcastV2Denied) {
		t.Fatalf("mapped source without Network enrollment: %v", err)
	}
	enrollBroadcastFixtureEndpoint(t, f, networkID, f.sealed.source)
	if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_no_recipient_network")); !errors.Is(err, ErrSameGroupBroadcastV2NotReady) {
		t.Fatalf("mapped recipient without Network enrollment: %v", err)
	}
	enrollBroadcastFixtureEndpoint(t, f, networkID, f.sealed.target)
	enrollBroadcastFixtureEndpoint(t, f, networkID, f.sealed.sameNode)
	f.snapshot(t, "bc_mapped_network")
	revokeBroadcastFixtureEndpoint(t, f, networkID, f.sealed.target)
	if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_mapped_network")); !errors.Is(err, ErrSameGroupBroadcastV2Denied) {
		t.Fatalf("snapshot retry exposed revoked Network recipient: %v", err)
	}
	if _, err := f.sealed.store.CreateSameGroupBroadcastV2Snapshot(f.input("bc_new_after_revoke")); !errors.Is(err, ErrSameGroupBroadcastV2NotReady) {
		t.Fatalf("new snapshot included revoked Network recipient: %v", err)
	}
}

func TestNetworkGuardMonitorBroadcastPreviewAndDispatch(t *testing.T) {
	for _, stage := range []string{"prepare", "preview", "dispatch"} {
		t.Run(stage, func(t *testing.T) {
			f := newUserMonitorBroadcastFixture(t)
			networkID := mapBroadcastFixtureNetwork(t, f.sameGroupBroadcastV2Fixture)
			for _, endpoint := range []sameGroupSealedV1EndpointFixture{f.sealed.source, f.sealed.target, f.sealed.sameNode} {
				enrollBroadcastFixtureEndpoint(t, f.sameGroupBroadcastV2Fixture, networkID, endpoint)
			}
			if stage == "prepare" {
				revokeBroadcastFixtureEndpoint(t, f.sameGroupBroadcastV2Fixture, networkID, f.sealed.source)
				digest := sha256.Sum256([]byte("synthetic prepare body"))
				if _, err := f.sealed.store.PrepareUserMonitorBroadcastV2(PrepareUserMonitorBroadcastV2Input{
					ClientRequestID: f.acceptedRequest(t), GroupID: f.sealed.groupID,
					MonitorEndpointID: f.sealed.source.id, BodyDigest: hex.EncodeToString(digest[:]),
				}); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
					t.Fatalf("revoked source prepared Monitor preview: %v", err)
				}
				return
			}
			body := []byte("synthetic Network guarded Monitor body")
			preview, _ := f.prepare(t, body)
			approved, _ := f.confirm(t, preview, body, 1)
			input := f.consumeInput(approved)
			revokeBroadcastFixtureEndpoint(t, f.sameGroupBroadcastV2Fixture, networkID, f.sealed.target)
			if stage == "preview" {
				if _, err := f.sealed.store.PreviewUserMonitorBroadcastV2Delivery(previewUserMonitorBroadcastInput(input)); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
					t.Fatalf("review exposed revoked recipient: %v", err)
				}
				return
			}
			if _, err := f.sealed.store.AuthorizeUserMonitorBroadcastV2Delivery(input); !errors.Is(err, ErrUserMonitorBroadcastV2Denied) {
				t.Fatalf("dispatch accepted revoked recipient: %v", err)
			}
		})
	}
}
