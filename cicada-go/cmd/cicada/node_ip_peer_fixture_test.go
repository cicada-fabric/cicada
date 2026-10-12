//go:build linux && amd64 && cgo && cicada_pqtls

package main

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

type firstInstallPeerFixture struct {
	groupID        string
	source, target *fabric.JoinResult
	sourceKey      *e2ee.Identity
	unjoinedID     string
}

// Reuse actual Join/Owner key guards on the newly enrolled Hub. Only synthetic
// native-session metadata comes from this fixture; no legacy Node enrollment
// seed, raw table insert, Runtime, provider or model participates.
func firstInstallPreparePeer(t *testing.T, dbPath, ownerID string, owner *e2ee.Identity, states map[string]string) firstInstallPeerFixture {
	t.Helper()
	db, err := store.NewForOfflineMaintenance(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	principal, err := db.GetPrincipal(ownerID)
	if err != nil {
		t.Fatal(err)
	}
	group, err := db.CreateGroup(store.Group{ID: "SYNTHETIC-IP-PEER-GROUP", Name: "SYNTHETIC IP PEER TEST ONLY", OwnerPrincipalID: ownerID, TrustDomainID: principal.TrustDomainID, State: store.GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(db, ownerID, principal.TrustDomainID)
	if err != nil {
		t.Fatal(err)
	}
	f := firstInstallPeerFixture{groupID: group.ID}
	for _, nodeID := range []string{"synthetic-node-a", "synthetic-node-b"} {
		_, token, err := loadMachineRecoveryClient(states[nodeID], nodeID)
		if err != nil {
			t.Fatal(err)
		}
		join, err := service.JoinForNodeCredential(token, fabric.JoinInput{GroupID: group.ID, PrincipalName: "SYNTHETIC-IP-PRINCIPAL-" + nodeID, EndpointName: "SYNTHETIC-IP-ENDPOINT-" + nodeID, Harness: "codex", NativeSessionID: "SYNTHETIC-NATIVE-METADATA-ONLY-" + nodeID, NodeID: nodeID, LeaseSeconds: 3600})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := db.GetActiveSessionBinding(join.Endpoint.ID)
		if err != nil {
			t.Fatal(err)
		}
		key, err := nodekeys.LoadOrCreate(machineNodeStateDir(states[nodeID], nodeID), join.Endpoint.ID)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := key.SignEndpointKeyAttestation(join.Endpoint.ID, join.Endpoint.PrincipalID, nodeID, binding.ID, binding.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.RegisterEndpointKeyCandidate(join.Endpoint.ID, join.Endpoint.PrincipalID, binding.ID, binding.Epoch, proof); err != nil {
			t.Fatal(err)
		}
		manifest, err := db.PreviewGroupEndpointKeyGrant(ownerID, group.ID, join.Endpoint.ID, owner.Public().ID, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		issued, _ := time.Parse(time.RFC3339Nano, manifest.IssuedAt)
		expires, _ := time.Parse(time.RFC3339Nano, manifest.ExpiresAt)
		grant, err := owner.SignOwnerLinkKeyGrant(ownerID, store.GroupEndpointKeyGrantOperation, manifest.Digest, manifest.CandidateBindingDigest, uint64(manifest.CandidateVersion), e2ee.OwnerLinkGrantSideSource, issued, expires)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.AcceptGroupEndpointKeyGrant(ownerID, group.ID, join.Endpoint.ID, owner.Public().ID, grant); err != nil {
			t.Fatal(err)
		}
		if nodeID == "synthetic-node-a" {
			f.source = join
			f.sourceKey = key
		} else {
			f.target = join
		}
	}
	unjoinedPrincipal, err := db.CreatePrincipal(store.Principal{ID: "SYNTHETIC-IP-UNJOINED-PRINCIPAL", Kind: store.PrincipalKindAgent, OwnerID: ownerID, TrustDomainID: principal.TrustDomainID, Name: "SYNTHETIC UNJOINED ONLY", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	unjoined, err := db.CreateEndpointV2(store.Endpoint{ID: "SYNTHETIC-IP-UNJOINED-ENDPOINT", Name: "SYNTHETIC UNJOINED ONLY", Harness: "codex", NativeSessionID: "SYNTHETIC-UNJOINED-NATIVE-METADATA", MachineID: "synthetic-node-b", Owner: ownerID, PrincipalID: unjoinedPrincipal.ID, Status: "online"})
	if err != nil || unjoined.MigrationState != store.EndpointMigrationPendingGroup {
		t.Fatal("unjoined fixture unexpectedly joined", err)
	}
	f.unjoinedID = unjoined.ID
	return f
}

func firstInstallPeerContext(t *testing.T, state, nodeID, hubID, origin string) (context.Context, func()) {
	t.Helper()
	_, token, err := loadMachineRecoveryClient(state, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	h := machineHubContext{StateDir: state, WriterRoot: state, NodeID: nodeID, HubID: hubID, Origin: origin, Token: token}
	active := filepath.Join(state, ".node-tls", e2ee.NodeTLSAuthorityDigest([]byte(hubID+"\x00"+nodeID)), "active.json")
	if err := configureMachinePQTransport(&h, active); err != nil {
		t.Fatal(err)
	}
	return withMachineHubContext(context.Background(), h), func() { h.TLSRuntime.Close() }
}

func firstInstallPeerSend(t *testing.T, f firstInstallPeerFixture, ctx context.Context, origin, nodeID string) []byte {
	t.Helper()
	path := origin + "/v2/relay/nodes/" + nodeID + "/group/sealed/peer-key?"
	query := url.Values{"group_id": {f.groupID}, "source_endpoint_id": {f.source.Endpoint.ID}, "target_endpoint_id": {f.target.Endpoint.ID}}
	var peer store.SameGroupSealedV1PeerKey
	if err := machineAPIJSON(ctx, path+query.Encode(), http.MethodGet, nil, &peer); err != nil {
		t.Fatal(err)
	}
	query.Set("target_endpoint_id", f.unjoinedID)
	if err := machineAPIJSON(ctx, path+query.Encode(), http.MethodGet, nil, &peer); !machineAPIHasStatus(err, http.StatusNotFound) {
		t.Fatal("unjoined Endpoint key route admitted", err)
	}
	sender, receiver := peer.Sender, peer.Receiver
	message := e2ee.EndpointMessageContext{MessageID: "SYNTHETIC-IP-PQ-OPAQUE-MESSAGE", Kind: "SEND", SenderEndpointID: sender.EndpointID, SenderPrincipalID: sender.PrincipalID, SenderOwnerID: sender.OwnerID, SenderGroupID: f.groupID, SenderMembershipRevision: sender.MembershipRevision, SenderBindingEpoch: sender.BindingEpoch, SenderKeyID: sender.Candidate.KeyID, ReceiverEndpointID: receiver.EndpointID, ReceiverPrincipalID: receiver.PrincipalID, ReceiverOwnerID: receiver.OwnerID, ReceiverGroupID: f.groupID, ReceiverMembershipRevision: receiver.MembershipRevision, ReceiverBindingEpoch: receiver.BindingEpoch, ReceiverKeyID: receiver.Candidate.KeyID, TransportHubID: peer.HubID}
	ciphertext, err := e2ee.SealEndpointMessage(f.sourceKey, receiver.Candidate.Public, message, []byte("SYNTHETIC PRIVATE IP PQ PAYLOAD TEST ONLY"), 1)
	if err != nil {
		t.Fatal(err)
	}
	input := fabric.NodeSameGroupSealedV1SendInput{GroupID: f.groupID, SourceEndpointID: f.source.Endpoint.ID, TargetEndpointID: f.target.Endpoint.ID, MessageID: message.MessageID, IdempotencyKey: "SYNTHETIC-IP-PQ-EXACT-RETRY", DataScope: store.SameGroupSealedV1DataScope, Ciphertext: ciphertext}
	for i := 0; i < 2; i++ {
		if err := machineAPIJSON(ctx, origin+"/v2/relay/nodes/"+nodeID+"/group/sealed/send", http.MethodPost, input, nil); err != nil {
			t.Fatal(err)
		}
	}
	return ciphertext
}

func firstInstallPeerEvidence(t *testing.T, dbPath, targetState string, wantReceived bool, ciphertext []byte) *fabric.NodeReceiptInput {
	t.Helper()
	db, err := store.NewForOfflineMaintenance(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const messageID = "SYNTHETIC-IP-PQ-OPAQUE-MESSAGE"
	row, err := db.GetRelaySealedV1(messageID)
	if err != nil || !bytes.Equal(row.Ciphertext, ciphertext) {
		t.Fatal("actual Hub lost exact ciphertext", err)
	}
	receipts, err := db.ListRelayReceipts(messageID, 100)
	if err != nil {
		t.Fatal(err)
	}
	accepted, received := 0, 0
	var ack *fabric.NodeReceiptInput
	for _, r := range receipts {
		switch r.Layer {
		case store.RelayReceiptAccepted:
			accepted++
		case store.RelayReceiptNodeReceived:
			received++
			ack = &fabric.NodeReceiptInput{AttemptID: r.AttemptID, MessageID: r.MessageID, Digest: r.Digest, EndpointID: r.TargetEndpointID, BindingID: r.BindingID, BindingEpoch: r.BindingEpoch, Layer: r.Layer}
		case store.RelayReceiptCodexQueueAccepted, store.RelayReceiptNativeThreadResumed:
			t.Fatal("missing Native Runtime acquired consumption/queue claim")
		}
	}
	if accepted != 1 || received != map[bool]int{false: 0, true: 1}[wantReceived] {
		t.Fatalf("persisted retry/ACK counts accepted=%d received=%d", accepted, received)
	}
	if err := nativeE2EAssertDatabasePrivateTextAbsent(dbPath, "SYNTHETIC PRIVATE IP PQ PAYLOAD TEST ONLY"); err != nil {
		t.Fatal(err)
	}
	if wantReceived {
		inbox, err := nodeinbox.Open(machineNodeInboxPath(targetState, "synthetic-node-b"))
		if err != nil {
			t.Fatal(err)
		}
		defer inbox.Close()
		delivery, err := inbox.Get(context.Background(), messageID)
		if err != nil || !bytes.Equal(delivery.Payload, []byte("SYNTHETIC PRIVATE IP PQ PAYLOAD TEST ONLY")) {
			t.Fatal("product Node did not persist decrypted inbox payload", err)
		}
	}
	return ack
}
