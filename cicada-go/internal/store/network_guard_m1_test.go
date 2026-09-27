package store

import (
	"errors"
	"testing"
	"time"
)

// The fixture enrolls the two existing Group endpoints through trusted test
// setup. Runtime authorization still uses the same central Network guard as a
// signed Join, including the persistent membership and endpoint revisions.
func TestMappedNetworkNativeWakeRejectsRevocationAndOldAttemptAfterRejoin(t *testing.T) {
	f := newLocalDeliveryAuthorizationFixture(t)
	hubID, err := f.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	network, err := f.store.CreateNetwork(Network{ID: "synthetic-wake-network", HubID: hubID, Name: "wake", OwnerID: "owner_local"})
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []*Endpoint{f.source, f.target} {
		stamp := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
		if _, err := f.store.db.Exec(`INSERT INTO network_memberships_v2
			(id,network_id,principal_id,grants_json,status,expires_at,revision,created_at,updated_at)
			VALUES(?,?,?,'[]','active','',1,?,?)`, NewID("netmem"), network.ID, endpoint.PrincipalID, stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := f.store.db.Exec(`INSERT INTO endpoint_network_memberships_v2
			(network_id,endpoint_id,status,revision,nickname,discoverable,created_at,updated_at)
			VALUES(?,?,'active',1,?,0,?,?)`, network.ID, endpoint.ID, endpoint.Name, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.store.PrepareGroupNetworkMapping(f.group.ID, network.ID, "synthetic explicit mapping", f.group.Version); err != nil {
		t.Fatal(err)
	}
	if err := f.store.ApproveGroupNetworkMapping(f.group.ID, network.ID, f.group.Version); err != nil {
		t.Fatal(err)
	}
	attempt := enqueueAndClaimNativeWakeTest(t, f)
	input := RelayNativeWakeAuthorizationInput{MessageID: attempt.MessageID, AttemptID: attempt.AttemptID}
	if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID, input); err != nil {
		t.Fatalf("current mapped delivery denied: %v", err)
	}
	if err := f.store.RevokeNetworkMembership(network.ID, f.target.PrincipalID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID, input); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
		t.Fatalf("revoked receiver could inject old attempt: %v", err)
	}
	// A fresh signed Join can re-enable this identity, but never an attempt
	// created under the previous Network enrollment revision.
	// Pin the new revision to the exact same timestamp as the queued message.
	// Timestamp-only fencing would accept this stale attempt.
	var stamp string
	if err := f.store.db.QueryRow(`SELECT created_at FROM fabric_messages WHERE id=?`, attempt.MessageID).Scan(&stamp); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE network_memberships_v2 SET status='active',revision=revision+1,updated_at=? WHERE network_id=? AND principal_id=?`, stamp, network.ID, f.target.PrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.db.Exec(`UPDATE endpoint_network_memberships_v2 SET status='active',revision=revision+1,updated_at=? WHERE network_id=? AND endpoint_id=?`, stamp, network.ID, f.target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID, input); !errors.Is(err, ErrRelayNativeWakeAuthorizationUnavailable) {
		t.Fatalf("rejoined receiver revived old attempt: %v", err)
	}
	// The same rejoined registration must accept a newly queued envelope.
	const freshID = "msg-native-wake-new-revision"
	if _, err := f.store.EnqueueRelayMessage(RelayMessageInput{
		Message: FabricMessage{ID: freshID, FromEndpointID: f.source.ID, ToEndpointID: f.target.ID, Kind: "send", Body: "synthetic new revision"},
		Security: RelayMessageSecurity{
			SenderEndpointID: f.source.ID, SenderPrincipalID: f.source.PrincipalID,
			SenderGroupID: f.group.ID, SenderBindingID: f.sourceBinding.ID,
			SenderBindingEpoch: f.sourceBinding.Epoch, ReceiverEndpointID: f.target.ID,
			ReceiverPrincipalID: f.target.PrincipalID, ReceiverGroupID: f.group.ID,
			ReceiverBindingID: f.targetBinding.ID, ReceiverBindingEpoch: f.targetBinding.Epoch,
		},
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := f.store.ClaimRelayInbox(RelayClaimInput{
		RecipientEndpointID: f.target.ID, ConsumerID: "new-network-revision",
		BindingID: f.targetBinding.ID, BindingEpoch: f.targetBinding.Epoch, Limit: 1,
	})
	if err != nil || len(claimed) != 1 || claimed[0].MessageID != freshID {
		t.Fatalf("new message under rejoined Network denied: %#v %v", claimed, err)
	}
	freshAttempt := claimed[0]
	if _, err := f.store.RecordRelayReceipt(RelayReceipt{
		AttemptID: freshAttempt.AttemptID, MessageID: freshAttempt.MessageID, Digest: freshAttempt.Digest,
		TargetEndpointID: freshAttempt.RecipientEndpointID, BindingID: freshAttempt.BindingID,
		BindingEpoch: freshAttempt.BindingEpoch, Layer: RelayReceiptNodeReceived,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AuthorizeRelayNativeWakeForNodeCredential(f.nodeDigest, f.nodeID,
		RelayNativeWakeAuthorizationInput{MessageID: freshID, AttemptID: freshAttempt.AttemptID}); err != nil {
		t.Fatalf("fresh message under rejoined Network denied at native wake: %v", err)
	}
}
