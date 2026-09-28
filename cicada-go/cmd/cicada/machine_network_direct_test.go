package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestMachineNetworkDirectNodeCredentialDoesNotFollowRedirect(t *testing.T) {
	t.Setenv("CICADA_NODE_TOKEN", "synthetic-direct-node-token")
	var received atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Store(true)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "CicadaNode synthetic-direct-node-token" {
			t.Errorf("Network direct claim used wrong Node credential")
		}
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	var result struct {
		Deliveries []fabric.NetworkDirectDelivery
	}
	if err := machineAPIJSON(context.Background(), source.URL+"/v2/fabric/node/networks/direct/claim",
		http.MethodPost, map[string]any{"node_id": "node_test"}, &result); err == nil || received.Load() {
		t.Fatalf("redirected destination received Network Node credential: err=%v received=%t", err, received.Load())
	}
}

func TestMachineNetworkDirectSocketSealsExactSendAndReusesEnvelope(t *testing.T) {
	const hubID, networkID, sourceNode, targetNode = "hub_synthetic_direct", "net_synthetic_direct", "node_direct_a", "node_direct_b"
	const sourceEndpoint, targetEndpoint, nativeID = "ep_direct_a", "ep_direct_b", "native_direct_a"
	workspace := prepareLocalSealedRPCNode(t, nativeID, sourceNode)
	t.Setenv("CICADA_HUB_ID", hubID)
	stateDir, err := os.MkdirTemp("", "cicada-nd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })
	sourceKey, err := nodekeys.LoadOrCreate(machineNodeStateDir(stateDir, sourceNode), sourceEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	targetKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	sourceOwner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	targetOwner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	trustLocalSealedRPCTestOwners(t, stateDir, sourceNode, map[string]*e2ee.Identity{
		"owner_direct_a": sourceOwner, "owner_direct_b": targetOwner})
	nodeToken, _, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	makeSide := func(endpoint, principal, owner, node, binding, native string, key, ownerKey *e2ee.Identity) store.NetworkDirectPeerKeyEvidence {
		t.Helper()
		attestation, err := key.SignNetworkDirectKeyAttestation(hubID, networkID, endpoint, principal, node, binding, 1)
		if err != nil {
			t.Fatal(err)
		}
		fingerprint, err := nodekeys.PeerKeyFingerprint(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		manifest := store.NetworkDirectKeyManifest{Version: 1, HubID: hubID, NetworkID: networkID, EndpointID: endpoint,
			PrincipalID: principal, OwnerID: owner, NodeID: node,
			NativeSessionDigest: e2ee.NetworkDirectNativeSessionDigest(native),
			BindingID:           binding, BindingEpoch: 1, MembershipRevision: 1, EndpointEnrollmentRevision: 1,
			Candidate: store.NetworkDirectKeyCandidate{NetworkID: networkID, EndpointID: endpoint, PrincipalID: principal,
				OwnerID: owner, NodeID: node, BindingID: binding, BindingEpoch: 1, Public: key.Public(),
				Fingerprint: fingerprint, Attestation: attestation, Version: 1}}
		manifest.Digest, err = manifest.CanonicalDigest()
		if err != nil {
			t.Fatal(err)
		}
		proof, err := ownerKey.SignOwnerNetworkDirectKeyGrant(hubID, networkID, endpoint, owner, manifest.Digest,
			now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		return store.NetworkDirectPeerKeyEvidence{Manifest: manifest, Grant: store.OwnerNetworkDirectKeyGrant{
			NetworkID: networkID, EndpointID: endpoint, OwnerID: owner, OwnerKeyID: ownerKey.Public().ID,
			ManifestDigest: manifest.Digest, State: "active", AcceptedAt: now.Format(time.RFC3339Nano), Revision: 1},
			GrantProof: proof, OwnerPublic: ownerKey.Public()}
	}
	bundle := store.NetworkDirectPeerBundle{HubID: hubID, NetworkID: networkID,
		Sender:   makeSide(sourceEndpoint, "pr_direct_a", "owner_direct_a", sourceNode, "native_binding_a", nativeID, sourceKey, sourceOwner),
		Receiver: makeSide(targetEndpoint, "pr_direct_b", "owner_direct_b", targetNode, "native_binding_b", "native_direct_b", targetKey, targetOwner)}
	var mu sync.Mutex
	var envelopes [][]byte
	var askEnvelopes [][]byte
	var askDeadlines []string
	serverHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v2/fabric/networks/" + networkID + "/whoami":
			if r.Header.Get("Authorization") != "Cicada-Network-Session private-network-token" {
				t.Errorf("whoami credential mismatch")
				http.Error(w, "denied", 401)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"network_id": networkID, "endpoint_id": sourceEndpoint, "principal_id": "pr_direct_a"})
		case "/v2/fabric/networks/" + networkID + "/direct/native-binding":
			_ = json.NewEncoder(w).Encode(store.NetworkDirectNativeBinding{ID: "native_binding_a", EndpointID: sourceEndpoint,
				PrincipalID: "pr_direct_a", NodeID: sourceNode, NativeSessionID: nativeID, Epoch: 1, Status: "active"})
		case "/v2/fabric/networks/" + networkID + "/direct/peer-key":
			_ = json.NewEncoder(w).Encode(bundle)
		case "/v2/fabric/node/networks/direct/send":
			if r.Header.Get("Authorization") != "CicadaNode "+nodeToken {
				t.Errorf("send lacked Node credential")
				http.Error(w, "denied", 401)
				return
			}
			var input struct {
				MessageID        string `json:"message_id"`
				TargetEndpointID string `json:"target_endpoint_id"`
				Ciphertext       []byte `json:"ciphertext"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.TargetEndpointID != targetEndpoint {
				t.Errorf("bad sealed SEND: %#v %v", input, err)
				http.Error(w, "bad", 400)
				return
			}
			mu.Lock()
			envelopes = append(envelopes, append([]byte(nil), input.Ciphertext...))
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(store.RelaySealedV1Record{Route: store.RelaySealedV1Route{MessageID: input.MessageID}})
		case "/v2/fabric/node/networks/direct/ask":
			if r.Header.Get("Authorization") != "CicadaNode "+nodeToken {
				http.Error(w, "denied", http.StatusUnauthorized)
				return
			}
			var input fabric.NetworkDirectAskInput
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				http.Error(w, "bad", http.StatusBadRequest)
				return
			}
			mu.Lock()
			askEnvelopes = append(askEnvelopes, append([]byte(nil), input.Ciphertext...))
			askDeadlines = append(askDeadlines, input.ExpiresAt)
			count := len(askEnvelopes)
			mu.Unlock()
			if count == 1 {
				// The Hub committed the request but its response was lost.
				connection, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Errorf("lose accepted ASK response: %v", err)
					return
				}
				_ = connection.Close()
				return
			}
			_ = json.NewEncoder(w).Encode(store.FabricRequest{RequestID: input.RequestID, State: "OPEN"})
		default:
			http.NotFound(w, r)
		}
	})
	_, server := startLocalSealedRPCBridge(t, stateDir, sourceNode, nodeToken, serverHandler)
	_ = server
	request := localNetworkDirectRequest{Version: localJoinProtocolVersion, Operation: "network_direct_send",
		NetworkID: networkID, EndpointID: sourceEndpoint, SessionToken: "private-network-token", Harness: "codex",
		NativeSessionID: nativeID, Workspace: workspace, NodeID: sourceNode,
		OperationID: "op_0123456789abcdef0123456789abcdef", IdempotencyKey: "same-send",
		TargetEndpointID: targetEndpoint, Body: "synthetic private body"}
	socket := machineAgentJoinSocketPath(stateDir, sourceNode)
	for i := 0; i < 2; i++ {
		result, err := requestMachineAgentNetworkDirect(socket, request)
		if err != nil || result.State != "RELAY_PERSISTED" {
			t.Fatalf("sealed socket SEND %d: %#v %v", i, result, err)
		}
	}
	mu.Lock()
	if len(envelopes) != 2 || !bytes.Equal(envelopes[0], envelopes[1]) || bytes.Contains(envelopes[0], []byte(request.Body)) {
		mu.Unlock()
		t.Fatal("retry changed ciphertext or leaked plaintext to Hub")
	}
	ciphertext := append([]byte(nil), envelopes[0]...)
	mu.Unlock()
	messageID, _, err := localSealedRPCIDs(request.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	route := store.NetworkDirectContext(&bundle, messageID, "SEND", "", "")
	opened, _, err := e2ee.OpenNetworkDirectMessage(targetKey, sourceKey.Public(), route, ciphertext)
	if err != nil || string(opened) != request.Body {
		t.Fatalf("receiver could not open exact Network direct envelope: %v", err)
	}
	// A Hub may return another valid, Owner-signed manifest. The local Node
	// still must bind its own signed source to the verified original Thread.
	for _, mismatch := range []struct{ node, native string }{
		{sourceNode, "native_other_thread"}, {"node_other", nativeID},
	} {
		bundle.Sender = makeSide(sourceEndpoint, "pr_direct_a", "owner_direct_a", mismatch.node,
			"native_binding_a", mismatch.native, sourceKey, sourceOwner)
		if _, err := requestMachineAgentNetworkDirect(socket, request); err == nil {
			t.Fatalf("Owner-signed source mismatch was accepted: %+v", mismatch)
		}
	}
	mu.Lock()
	count := len(envelopes)
	mu.Unlock()
	if count != 2 {
		t.Fatal("invalid source reached Hub enqueue")
	}
	bundle.Sender = makeSide(sourceEndpoint, "pr_direct_a", "owner_direct_a", sourceNode,
		"native_binding_a", nativeID, sourceKey, sourceOwner)
	ask := request
	ask.Operation = "network_direct_ask"
	ask.OperationID = "op_abcdef0123456789abcdef0123456789"
	ask.IdempotencyKey = "same-ask"
	ask.ExpiresAt = now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	if _, err := requestMachineAgentNetworkDirect(socket, ask); err == nil {
		t.Fatal("simulated lost ASK response was reported as accepted")
	}
	if result, err := requestMachineAgentNetworkDirect(socket, ask); err != nil || result.State != "OPEN" {
		t.Fatalf("exact ASK retry failed: %#v %v", result, err)
	}
	mu.Lock()
	if len(askEnvelopes) != 2 || !bytes.Equal(askEnvelopes[0], askEnvelopes[1]) ||
		askDeadlines[0] != ask.ExpiresAt || askDeadlines[1] != ask.ExpiresAt {
		mu.Unlock()
		t.Fatal("lost-response ASK retry changed ciphertext or deadline")
	}
	mu.Unlock()
	digest := machineSealedCiphertextDigest(ciphertext)
	delivery := fabric.NetworkDirectDelivery{NetworkID: networkID, NodeID: targetNode, NativeSessionID: "native_direct_b",
		RelaySealedV1DeliveryAttempt: store.RelaySealedV1DeliveryAttempt{MessageID: messageID, AttemptID: "attempt_direct_b",
			RecipientEndpointID: targetEndpoint, BindingID: "native_binding_b", BindingEpoch: 1,
			Digest: digest, Ciphertext: ciphertext, PayloadMode: store.RelayPayloadModeSealedV1,
			Route: store.RelaySealedV1Route{MessageID: messageID, SenderEndpointID: sourceEndpoint,
				ReceiverEndpointID: targetEndpoint, Kind: "send"}}}
	auth := store.NetworkDirectDeliveryAuthorization{NetworkID: networkID, EndpointID: targetEndpoint,
		NativeSessionID: delivery.NativeSessionID, BindingID: delivery.BindingID, BindingEpoch: 1,
		MessageID: messageID, AttemptID: delivery.AttemptID, Digest: digest,
		Context: route, Bundle: bundle}
	if err := verifyMachineNetworkDirectAuthorization(targetNode, delivery, auth); err != nil {
		t.Fatalf("valid signed native target was rejected: %v", err)
	}
	for _, mismatch := range []struct{ node, native string }{
		{targetNode, "native_wrong_thread"}, {"node_wrong", "native_direct_b"},
	} {
		auth.Bundle.Receiver = makeSide(targetEndpoint, "pr_direct_b", "owner_direct_b", mismatch.node,
			"native_binding_b", mismatch.native, targetKey, targetOwner)
		auth.Context = store.NetworkDirectContext(&auth.Bundle, messageID, "SEND", "", "")
		if err := verifyMachineNetworkDirectAuthorization(targetNode, delivery, auth); err == nil {
			t.Fatalf("Owner-signed recipient mismatch was accepted: %+v", mismatch)
		}
	}
}

func TestNetworkDirectDeniedRetiresLocalAttemptWithoutHubAck(t *testing.T) {
	ctx := context.Background()
	privateDir := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	inbox, err := nodeinbox.Open(filepath.Join(privateDir, "inbox.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	journal := &machineRelayJournal{path: filepath.Join(t.TempDir(), "journal.json"), deliveries: []machineRelayJournalEntry{}}
	for _, messageID := range []string{"msg_denied", "msg_allowed"} {
		payload := []byte(messageID)
		hash := sha256.Sum256(payload)
		if _, _, err := inbox.Save(ctx, nodeinbox.Message{MessageID: messageID, Digest: hex.EncodeToString(hash[:]),
			EndpointID: "ep_current", SessionID: "native_current", BindingEpoch: 1, Payload: payload}); err != nil {
			t.Fatal(err)
		}
	}
	claim, err := inbox.Claim(ctx, "synthetic-consumer")
	if err != nil || claim.MessageID != "msg_denied" {
		t.Fatalf("first local claim: %#v %v", claim, err)
	}
	entry := machineRelayJournalEntry{NetworkID: "net_denied", MessageID: claim.MessageID, Digest: claim.Digest,
		EndpointID: claim.EndpointID, SessionID: claim.SessionID, BindingEpoch: claim.BindingEpoch,
		AttemptID: claim.AttemptID, AuthorizationKind: "network-direct", PayloadMode: store.RelayPayloadModeSealedV1}
	journal.deliveries = append(journal.deliveries, entry)
	if err := journal.persist(); err != nil {
		t.Fatal(err)
	}
	if err := retireMachineNetworkDirectDenied(ctx, inbox, journal, *claim, entry); err != nil {
		t.Fatal(err)
	}
	failed, err := inbox.Get(ctx, claim.MessageID)
	if err != nil || failed.State != nodeinbox.FAILED || journal.index(claim.MessageID) >= 0 {
		t.Fatalf("denied item did not preserve local FAILED evidence and retire journal: %#v %v", failed, err)
	}
	next, err := inbox.Claim(ctx, "synthetic-consumer")
	if err != nil || next.MessageID != "msg_allowed" {
		t.Fatalf("denied item starved later delivery: %#v %v", next, err)
	}
}
