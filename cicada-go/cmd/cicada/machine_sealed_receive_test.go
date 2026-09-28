package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

type machineSealedReceiveFixture struct {
	store               *store.Store
	service             *fabric.Service
	databasePath        string
	stateDir            string
	sourceNodeID        string
	sourceToken         string
	sourceOwnerKeyID    string
	sourceOwnerIdentity *e2ee.Identity
	sourceEndpoint      string
	sourceKey           *e2ee.Identity
	targetNodeID        string
	targetToken         string
	targetOwnerKeyID    string
	targetOwnerIdentity *e2ee.Identity
	targetKey           *e2ee.Identity
	link                *store.CommunicationLink
	manifest            *store.CommunicationLinkKeyManifest
	dataScope           string
	ciphertext          []byte
	messageID           string
	requestID           string
	targetEndpoint      string
	claimed             []fabric.NodeSealedDelivery
}

func newMachineSealedReceiveFixture(t *testing.T) *machineSealedReceiveFixture {
	return newMachineSealedReceiveFixtureWithSeed(t, true)
}

func newMachineSealedReceiveRequestFixture(t *testing.T) *machineSealedReceiveFixture {
	return newMachineSealedReceiveFixtureWithSeedAndRouteKind(t, true, "ask")
}

func newMachineSealedReceiveReplyFixture(t *testing.T) *machineSealedReceiveFixture {
	return newMachineSealedReceiveFixtureWithActions(t, true, "ask", []string{"ask", "reply"})
}

func newMachineSealedReceiveFixtureWithSeed(t *testing.T, seedMessage bool) *machineSealedReceiveFixture {
	return newMachineSealedReceiveFixtureWithSeedAndRouteKind(t, seedMessage, "send")
}

func newMachineSealedReceiveFixtureWithSeedAndRouteKind(t *testing.T, seedMessage bool, routeKind string) *machineSealedReceiveFixture {
	return newMachineSealedReceiveFixtureWithActions(t, seedMessage, routeKind, []string{routeKind})
}

func newMachineSealedReceiveFixtureWithActions(t *testing.T, seedMessage bool,
	routeKind string, actions []string) *machineSealedReceiveFixture {
	return newMachineSealedReceiveFixtureWithActionsForNativeSessions(t, seedMessage,
		routeKind, actions, "", "")
}

func newMachineSealedReceiveFixtureWithActionsForNativeSessions(t *testing.T, seedMessage bool,
	routeKind string, actions []string, sourceNativeSessionID, targetNativeSessionID string) *machineSealedReceiveFixture {
	return newMachineSealedReceiveFixtureWithEndpointGrantsForNativeSessions(t, seedMessage,
		routeKind, actions, []string{"message.ask"}, sourceNativeSessionID, targetNativeSessionID)
}

func newMachineSealedReceiveFixtureWithEndpointGrantsForNativeSessions(t *testing.T, seedMessage bool,
	routeKind string, actions, endpointGrants []string, sourceNativeSessionID, targetNativeSessionID string) *machineSealedReceiveFixture {
	return newMachineSealedReceiveFixtureWithOwnerGrantTimingForNativeSessions(t, seedMessage,
		routeKind, actions, endpointGrants, sourceNativeSessionID, targetNativeSessionID, false)
}

func newMachineSealedReceiveFixtureWithDeferredOwnerGrantsForNativeSessions(t *testing.T, seedMessage bool,
	routeKind string, actions, endpointGrants []string, sourceNativeSessionID, targetNativeSessionID string) *machineSealedReceiveFixture {
	return newMachineSealedReceiveFixtureWithOwnerGrantTimingForNativeSessions(t, seedMessage,
		routeKind, actions, endpointGrants, sourceNativeSessionID, targetNativeSessionID, true)
}

func newMachineSealedReceiveFixtureWithOwnerGrantTimingForNativeSessions(t *testing.T, seedMessage bool,
	routeKind string, actions, endpointGrants []string, sourceNativeSessionID, targetNativeSessionID string,
	deferOwnerGrants bool) *machineSealedReceiveFixture {
	t.Helper()
	databasePath := filepath.Join(t.TempDir(), "hub.sqlite3")
	state, err := store.New(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })

	type ownerSetup struct {
		identity  *e2ee.Identity
		keyID     string
		deviceID  string
		nodeToken string
	}
	newBoundNode := func(ownerID, nodeID string) ownerSetup {
		t.Helper()
		ownerIdentity, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		ownerKey, err := state.RegisterOwnerApprovalKeyLocal(ownerID, ownerIdentity.Public())
		if err != nil {
			t.Fatal(err)
		}
		clientIdentity, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		deviceID := "client_" + nodeID
		hubID, err := state.GetClientHubID()
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		deviceGrant, err := ownerIdentity.SignOwnerDeviceGrant(ownerID, deviceID,
			clientIdentity.Public(), hubID, e2ee.OwnerDevicePurposeControl,
			now.Add(-time.Minute), now.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
			OwnerID: ownerID, OwnerKeyID: ownerKey.KeyID, DeviceID: deviceID,
			DevicePublic: clientIdentity.Public(), OwnerDeviceGrant: deviceGrant,
		}); err != nil {
			t.Fatal(err)
		}
		nodeToken, _, err := fabric.NewNodeCredential()
		if err != nil {
			t.Fatal(err)
		}
		codeSum := sha256.Sum256([]byte("device-code-" + nodeID))
		codeDigest := hex.EncodeToString(codeSum[:])
		if _, err := state.CreatePendingNodeDeviceBinding(nodeID, nodeID,
			fabric.HashSessionCredential(nodeToken), codeDigest, now.Add(10*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if _, err := state.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
			t.Fatal(err)
		}
		return ownerSetup{identity: ownerIdentity, keyID: ownerKey.KeyID,
			deviceID: deviceID, nodeToken: nodeToken}
	}

	type endpointSetup struct {
		ownerID    string
		groupID    string
		endpointID string
		nodeID     string
		principal  string
		bindingID  string
	}
	makeEndpoint := func(ownerID, groupID, endpointID, nodeID, nativeSessionID string) endpointSetup {
		t.Helper()
		if strings.TrimSpace(nativeSessionID) == "" {
			nativeSessionID = "native_" + endpointID
		}
		owner, err := state.CreatePrincipal(store.Principal{ID: ownerID,
			Kind: store.PrincipalKindHuman, OwnerID: ownerID, TrustDomainID: ownerID, Name: ownerID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.CreateGroup(store.Group{ID: groupID, Name: "Group " + ownerID,
			OwnerPrincipalID: owner.ID, TrustDomainID: ownerID, State: store.GroupStateActive}); err != nil {
			t.Fatal(err)
		}
		principal, err := state.CreatePrincipal(store.Principal{ID: "pr_" + endpointID,
			Kind: store.PrincipalKindAgent, OwnerID: ownerID, TrustDomainID: ownerID, Name: endpointID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.CreateMembership(store.Membership{PrincipalID: principal.ID,
			GroupID: groupID, Role: "member", Grants: append([]string(nil), endpointGrants...)}); err != nil {
			t.Fatal(err)
		}
		endpoint, err := state.UpsertEndpoint(store.Endpoint{ID: endpointID, Name: endpointID,
			Harness: "codex", NativeSessionID: nativeSessionID, MachineID: nodeID,
			Owner: ownerID, Status: "online"})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := state.CreateSessionBinding(store.SessionBinding{EndpointID: endpoint.ID,
			PrincipalID: principal.ID, GroupID: groupID, NativeSessionID: nativeSessionID, NodeID: nodeID})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.AcquireSessionBindingLease(binding.ID, "lease_"+endpointID,
			binding.Epoch, time.Now().UTC().Add(2*time.Hour).Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		return endpointSetup{ownerID: ownerID, groupID: groupID, endpointID: endpointID,
			nodeID: nodeID, principal: principal.ID, bindingID: binding.ID}
	}

	sourceOwner := newBoundNode("owner_source", "node_source")
	targetOwner := newBoundNode("owner_target", "node_target")
	source := makeEndpoint("owner_source", "group_source", "ep_source", "node_source", sourceNativeSessionID)
	target := makeEndpoint("owner_target", "group_target", "ep_target", "node_target", targetNativeSessionID)
	hubID, err := state.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	invite, err := state.CreateExternalThreadInvite(store.ExternalThreadInviteInput{
		OwnerID: source.ownerID, SourceEndpointID: source.endpointID,
		SourceGroupID: source.groupID, HubID: hubID,
		Actions: actions, DataScopes: []string{"thread.message"},
		ExpiresAt: time.Now().UTC().Add(30 * time.Minute).Truncate(time.Second).Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := state.AcceptExternalThreadInvite(invite.Token, target.ownerID, target.endpointID, target.groupID)
	if err != nil {
		t.Fatal(err)
	}
	link, err := state.GetCommunicationLinkForOwner(accepted.LinkID, source.ownerID)
	if err != nil {
		t.Fatal(err)
	}

	stateDir := shortLocalJoinStateDir(t)
	sourceKey, err := nodekeys.LoadOrCreate(machineNodeStateDir(stateDir, source.nodeID), source.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	targetKey, err := nodekeys.LoadOrCreate(machineNodeStateDir(stateDir, target.nodeID), target.endpointID)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []struct {
		info endpointSetup
		key  *e2ee.Identity
	}{{source, sourceKey}, {target, targetKey}} {
		binding, err := state.GetSessionBindingForEndpoint(endpoint.info.endpointID)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := endpoint.key.SignEndpointKeyAttestation(endpoint.info.endpointID,
			binding.PrincipalID, binding.NodeID, binding.ID, binding.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.RegisterEndpointKeyCandidate(endpoint.info.endpointID,
			binding.PrincipalID, binding.ID, binding.Epoch, proof); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := state.GetCommunicationLinkKeyManifest(link.ID, source.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	linkExpiry, err := time.Parse(time.RFC3339, link.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct {
		ownerID  string
		keyID    string
		identity *e2ee.Identity
		side     e2ee.OwnerLinkGrantSide
	}{
		{link.SourceOwnerID, sourceOwner.keyID, sourceOwner.identity, e2ee.OwnerLinkGrantSideSource},
		{link.TargetOwnerID, targetOwner.keyID, targetOwner.identity, e2ee.OwnerLinkGrantSideTarget},
	} {
		if deferOwnerGrants {
			continue
		}
		proof, err := grant.identity.SignOwnerLinkKeyGrant(grant.ownerID, link.ID,
			link.ContractDigest, manifest.Digest, uint64(link.Version), grant.side,
			time.Now().UTC().Add(-time.Minute), linkExpiry)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := state.RecordCommunicationLinkKeyGrant(grant.ownerID, link.ID,
			string(grant.side), grant.keyID, proof); err != nil {
			t.Fatal(err)
		}
	}

	for _, nodeID := range []string{source.nodeID, target.nodeID} {
		cryptoState, err := nodekeys.OpenCryptoState(machineNodeStateDir(stateDir, nodeID))
		if err != nil {
			t.Fatal(err)
		}
		for _, owner := range []struct {
			id       string
			keyID    string
			identity *e2ee.Identity
		}{{source.ownerID, sourceOwner.keyID, sourceOwner.identity}, {target.ownerID, targetOwner.keyID, targetOwner.identity}} {
			fingerprint, err := nodekeys.PeerKeyFingerprint(owner.identity.Public())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cryptoState.TrustOwnerApprovalKeyLocal(owner.id, owner.keyID,
				owner.identity.Public(), fingerprint); err != nil {
				t.Fatal(err)
			}
		}
		if err := cryptoState.Close(); err != nil {
			t.Fatal(err)
		}
	}

	messageID := "msg_machine_sealed"
	requestID := ""
	envelopeKind := "SEND"
	if routeKind == "ask" {
		messageID = "msg_machine_sealed_ask"
		requestID = "rq_machine_sealed_ask"
		envelopeKind = "REQUEST"
	}
	context := e2ee.EndpointMessageContext{
		MessageID: messageID, Kind: envelopeKind, RequestID: requestID,
		SenderEndpointID: link.SourceEndpointID, SenderPrincipalID: link.SourcePrincipalID,
		SenderOwnerID: link.SourceOwnerID, SenderGroupID: link.SourceGroupID,
		SenderMembershipRevision: link.ScopeSnapshot.SourceMembershipRevision,
		SenderBindingEpoch:       manifest.Source.BindingEpoch, SenderKeyID: manifest.Source.KeyID,
		ReceiverEndpointID: link.TargetEndpointID, ReceiverPrincipalID: link.TargetPrincipalID,
		ReceiverOwnerID: link.TargetOwnerID, ReceiverGroupID: link.TargetGroupID,
		ReceiverMembershipRevision: link.ScopeSnapshot.TargetMembershipRevision,
		ReceiverBindingEpoch:       manifest.Target.BindingEpoch, ReceiverKeyID: manifest.Target.KeyID,
		LinkID: link.ID, LinkRevision: link.Version, TransportHubID: link.TransportHubID,
	}
	const plaintext = "private message for the original session"
	ciphertext, err := e2ee.SealEndpointMessage(sourceKey, manifest.Target.PublicIdentity,
		context, []byte(plaintext), 1)
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(state, source.ownerID, source.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	if seedMessage {
		if routeKind == "ask" {
			if _, err := state.EnqueueCommunicationLinkSealedAsk(store.CommunicationLinkSealedAsk{
				NodeCredentialDigest: fabric.HashSessionCredential(sourceOwner.nodeToken),
				LinkID:               link.ID, MessageID: context.MessageID, RequestID: context.RequestID,
				DataScope: "thread.message", ExpiresAt: link.ExpiresAt, Ciphertext: ciphertext,
			}); err != nil {
				t.Fatal(err)
			}
		} else {
			if _, err := service.SendNodeSealedLinkMessage(sourceOwner.nodeToken, fabric.NodeSealedLinkSendInput{
				LinkID: link.ID, MessageID: context.MessageID, DataScope: "thread.message", Ciphertext: ciphertext,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	return &machineSealedReceiveFixture{store: state, service: service, databasePath: databasePath, stateDir: stateDir,
		sourceNodeID: source.nodeID, sourceToken: sourceOwner.nodeToken,
		sourceOwnerKeyID: sourceOwner.keyID, sourceOwnerIdentity: sourceOwner.identity,
		sourceEndpoint: source.endpointID, sourceKey: sourceKey,
		targetNodeID: target.nodeID, targetToken: targetOwner.nodeToken,
		targetOwnerKeyID: targetOwner.keyID, targetOwnerIdentity: targetOwner.identity,
		targetKey: targetKey,
		link:      link, manifest: manifest, dataScope: "thread.message", ciphertext: ciphertext,
		messageID: context.MessageID, requestID: context.RequestID, targetEndpoint: target.endpointID}
}

func (f *machineSealedReceiveFixture) server(t *testing.T, receipts *[]string) *httptest.Server {
	return f.serverForNode(t, f.targetNodeID, f.targetToken, receipts)
}

func (f *machineSealedReceiveFixture) serverForNode(t *testing.T, nodeID, nodeToken string,
	receipts *[]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "CicadaNode "+nodeToken {
			t.Errorf("Node authorization=%q", got)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case request.URL.Path == "/v2/relay/nodes/"+nodeID+"/sealed/claim":
			var input fabric.NodeClaimInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode sealed claim: %v", err)
			}
			deliveries, err := f.service.ClaimNodeSealedDeliveries(nodeToken, nodeID, input)
			if err != nil {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			f.claimed = append(f.claimed, deliveries...)
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": deliveries})
		case request.URL.Path == "/v2/relay/nodes/"+nodeID+"/group/sealed/claim":
			if request.Method != http.MethodPost {
				t.Errorf("same-Group sealed claim method=%s", request.Method)
			}
			var input fabric.NodeClaimInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode same-Group sealed claim: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			deliveries, err := f.service.ClaimNodeSameGroupSealedV1Deliveries(nodeToken, nodeID, input)
			if err != nil {
				response.WriteHeader(http.StatusForbidden)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{"deliveries": deliveries})
		case strings.HasPrefix(request.URL.Path, "/v2/relay/nodes/"+nodeID+"/sealed/") && strings.HasSuffix(request.URL.Path, "/authorization"):
			parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
			messageID := parts[len(parts)-2]
			authorization, err := f.service.AuthorizeNodeSealedDelivery(nodeToken,
				messageID, request.URL.Query().Get("attempt_id"))
			if err != nil {
				response.WriteHeader(http.StatusNotFound)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(authorization)
		case request.URL.Path == "/v2/relay/nodes/"+nodeID+"/claim":
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case request.URL.Path == "/v2/fabric/node/networks/direct/claim":
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case request.URL.Path == "/v2/relay/nodes/"+nodeID+"/receipts":
			var input fabric.NodeReceiptInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode Node receipt: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			if receipts != nil {
				*receipts = append(*receipts, input.Layer)
			}
			if _, err := f.service.RecordNodeReceipt(nodeID, input); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			response.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(response).Encode(map[string]any{"status": input.Layer})
		default:
			t.Errorf("unexpected Node API route: %s %s", request.Method, request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
		}
	}))
}

func enqueueMachineSealedReply(t *testing.T, fixture *machineSealedReceiveFixture,
	replyMessageID, plaintext string) []byte {
	t.Helper()
	link, manifest := fixture.link, fixture.manifest
	context := e2ee.EndpointMessageContext{
		MessageID: replyMessageID, Kind: "REPLY",
		RequestID: fixture.requestID, ReplyTo: fixture.messageID,
		SenderEndpointID: link.TargetEndpointID, SenderPrincipalID: link.TargetPrincipalID,
		SenderOwnerID: link.TargetOwnerID, SenderGroupID: link.TargetGroupID,
		SenderMembershipRevision: link.ScopeSnapshot.TargetMembershipRevision,
		SenderBindingEpoch:       manifest.Target.BindingEpoch, SenderKeyID: manifest.Target.KeyID,
		ReceiverEndpointID: link.SourceEndpointID, ReceiverPrincipalID: link.SourcePrincipalID,
		ReceiverOwnerID: link.SourceOwnerID, ReceiverGroupID: link.SourceGroupID,
		ReceiverMembershipRevision: link.ScopeSnapshot.SourceMembershipRevision,
		ReceiverBindingEpoch:       manifest.Source.BindingEpoch, ReceiverKeyID: manifest.Source.KeyID,
		LinkID: link.ID, LinkRevision: link.Version, TransportHubID: link.TransportHubID,
	}
	ciphertext, err := e2ee.SealEndpointMessage(fixture.targetKey,
		manifest.Source.PublicIdentity, context, []byte(plaintext), 1)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := fixture.store.EnqueueCommunicationLinkSealedReply(store.CommunicationLinkSealedReply{
		NodeCredentialDigest: fabric.HashSessionCredential(fixture.targetToken),
		RequestID:            fixture.requestID, MessageID: replyMessageID,
		DataScope: fixture.dataScope, Ciphertext: ciphertext,
	})
	if err != nil || accepted.State != store.FabricRequestReplied || accepted.ReplyMessageID != replyMessageID {
		t.Fatalf("store did not accept correlated sealed REPLY: request=%#v error=%v", accepted, err)
	}
	return ciphertext
}

func installMachineSealedFakeCodex(t *testing.T, fail bool, nodeToken string) (argumentsPath, countPath string) {
	t.Helper()
	root := t.TempDir()
	argumentsPath = filepath.Join(root, "arguments")
	countPath = filepath.Join(root, "count")
	binary := filepath.Join(root, "codex")
	exit := "0"
	if fail {
		exit = "2"
	}
	script := "#!/bin/sh\nif [ -n \"$CICADA_NODE_TOKEN\" ] || [ -n \"$CICADA_NODE_TOKEN_FILE\" ]; then exit 91; fi\nprintf x >> " + countPath + "\nprintf '%s\\n' \"$@\" >> " + argumentsPath + "\nexit " + exit + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_CODEX_BIN", binary)
	t.Setenv("CICADA_API_TOKEN", "management-token-must-not-reach-codex")
	t.Setenv("CICADA_NODE_TOKEN", nodeToken)
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	return argumentsPath, countPath
}

func TestMachineSealedReceivePersistsInjectsExactThreadAndDedupes(t *testing.T) {
	fixture := newMachineSealedReceiveFixture(t)
	argumentsPath, countPath := installMachineSealedFakeCodex(t, false, fixture.targetToken)
	var receipts []string
	server := fixture.server(t, &receipts)
	defer server.Close()
	inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()

	for attempt := 0; attempt < 2; attempt++ {
		if err := processMachineFabricDeliveriesV2(context.Background(), server.URL,
			fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
			t.Fatalf("process sealed delivery attempt %d: %v", attempt, err)
		}
	}
	data, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := string(data)
	for _, expected := range []string{"queue\n", "--thread\n", "native_" + fixture.targetEndpoint + "\n", "--message\n", "private message for the original session"} {
		if !strings.Contains(argv, expected) {
			t.Fatalf("native queue arguments omitted %q: %q", expected, argv)
		}
	}
	if bytes.Contains([]byte(argv), fixture.ciphertext) {
		t.Fatal("native queue prompt contained the sealed ciphertext envelope")
	}
	count, err := os.ReadFile(countPath)
	if err != nil || string(count) != "x" {
		t.Fatalf("sealed message queue count=%q error=%v", count, err)
	}
	if strings.Join(receipts, ",") != "NODE_RECEIVED,CODEX_QUEUE_ACCEPTED,CONSUMPTION_UNCONFIRMED" {
		t.Fatalf("sealed receipt layers=%v", receipts)
	}
	stored, err := inbox.Get(context.Background(), fixture.messageID)
	if err != nil || string(stored.Payload) != "private message for the original session" ||
		stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED {
		t.Fatalf("durable decrypted inbox=%#v error=%v", stored, err)
	}
	journal, err := openMachineRelayJournal(fixture.stateDir, fixture.targetNodeID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := os.ReadFile(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, fixture.ciphertext) || bytes.Contains(encoded, []byte("ciphertext")) {
		t.Fatal("sealed recovery journal duplicated ciphertext instead of using the Node crypto inbox")
	}
}

func TestMachineSealedRequestDecryptsAndQueuesExactNativeSession(t *testing.T) {
	fixture := newMachineSealedReceiveRequestFixture(t)
	argumentsPath, countPath := installMachineSealedFakeCodex(t, false, fixture.targetToken)
	var receipts []string
	server := fixture.server(t, &receipts)
	defer server.Close()
	inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()

	for attempt := 0; attempt < 2; attempt++ {
		if err := processMachineFabricDeliveriesV2(context.Background(), server.URL,
			fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
			t.Fatalf("process sealed REQUEST attempt %d: %v", attempt, err)
		}
	}
	data, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatal(err)
	}
	argv := string(data)
	for _, expected := range []string{"queue\n", "--thread\n", "native_" + fixture.targetEndpoint + "\n",
		"--message\n", fixture.requestID, `"request_id":"` + fixture.requestID + `"`,
		"Cicada SEALED_V1 REQUEST", "call cicada_reply", `"link_id":"` + fixture.link.ID + `"`,
		"private message for the original session"} {
		if !strings.Contains(argv, expected) {
			t.Fatalf("native REQUEST queue omitted %q: %q", expected, argv)
		}
	}
	if strings.Contains(argv, "cicada_receive") || strings.Contains(argv, "cicada_send") {
		t.Fatalf("sealed REQUEST prompt directed the runtime through a legacy plaintext path: %q", argv)
	}
	if bytes.Contains([]byte(argv), fixture.ciphertext) {
		t.Fatal("native REQUEST prompt contained the sealed ciphertext envelope")
	}
	count, err := os.ReadFile(countPath)
	if err != nil || string(count) != "x" {
		t.Fatalf("sealed REQUEST queue count=%q error=%v", count, err)
	}
	if strings.Join(receipts, ",") != "NODE_RECEIVED,CODEX_QUEUE_ACCEPTED,CONSUMPTION_UNCONFIRMED" {
		t.Fatalf("sealed REQUEST receipt layers=%v", receipts)
	}
	stored, err := inbox.Get(context.Background(), fixture.messageID)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED ||
		string(stored.Payload) != "private message for the original session" {
		t.Fatalf("durable decrypted REQUEST=%#v error=%v", stored, err)
	}
	visible, err := inbox.ListInjectedForSession(context.Background(), fixture.targetEndpoint,
		"native_"+fixture.targetEndpoint, fixture.manifest.Target.BindingEpoch,
		fixture.link.TargetGroupID, 0, 8)
	if err != nil || len(visible) != 1 || visible[0].Kind != "REQUEST" ||
		visible[0].RequestID != fixture.requestID || visible[0].ReplyTo != "" ||
		visible[0].SenderEndpointID != fixture.sourceEndpoint {
		t.Fatalf("sealed receive omitted its verified REQUEST route: %#v error=%v", visible, err)
	}
}

func TestMachineSealedRequestRejectsInvalidCorrelation(t *testing.T) {
	fixture := newMachineSealedReceiveRequestFixture(t)
	deliveries, err := fixture.service.ClaimNodeSealedDeliveries(fixture.targetToken,
		fixture.targetNodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(fixture.targetNodeID), Limit: 50})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim setup deliveries=%d error=%v", len(deliveries), err)
	}
	delivery := deliveries[0]
	authorization, err := fixture.service.AuthorizeNodeSealedDelivery(fixture.targetToken,
		delivery.MessageID, delivery.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMachineSealedClaimAuthorization(fixture.targetNodeID, delivery, *authorization); err != nil {
		t.Fatalf("valid sealed REQUEST correlation rejected: %v", err)
	}

	missingRequestID := delivery
	missingRequestID.RequestID = ""
	if err := validateMachineSealedClaimAuthorization(fixture.targetNodeID, missingRequestID, *authorization); err == nil {
		t.Fatal("sealed REQUEST without request_id was accepted")
	}

	replyRoute := delivery
	replyAuthorization := *authorization
	replyRoute.Route.ReplyTo = "msg_parent"
	replyAuthorization.Route.ReplyTo = "msg_parent"
	if err := validateMachineSealedClaimAuthorization(fixture.targetNodeID, replyRoute, replyAuthorization); err == nil {
		t.Fatal("sealed REPLY-shaped route was accepted as REQUEST")
	}

	wrongCorrelation := delivery
	wrongAuthorization := *authorization
	wrongRequestID := fixture.requestID + "_wrong"
	wrongCorrelation.RequestID = wrongRequestID
	wrongCorrelation.Route.RequestID = wrongRequestID
	wrongAuthorization.Route.RequestID = wrongRequestID
	if err := validateMachineSealedClaimAuthorization(fixture.targetNodeID, wrongCorrelation, wrongAuthorization); err != nil {
		t.Fatalf("wrongly paired route should reach envelope correlation check: %v", err)
	}
	if _, err := openMachineSealedDelivery(context.Background(), fixture.stateDir,
		fixture.targetNodeID, wrongCorrelation, wrongAuthorization); err == nil {
		t.Fatal("Endpoint envelope with a different request_id was accepted")
	}
}

func TestMachineSealedReplyReturnsToOriginalRequesterSession(t *testing.T) {
	fixture := newMachineSealedReceiveReplyFixture(t)
	const replyMessageID = "msg_machine_sealed_reply"
	const replyPlaintext = "the sealed answer for the original requester"
	replyCiphertext := enqueueMachineSealedReply(t, fixture, replyMessageID, replyPlaintext)

	for _, messageID := range []string{fixture.messageID, replyMessageID} {
		if legacy, err := fixture.store.GetFabricMessage(messageID); err != nil || legacy != nil {
			t.Fatalf("legacy Hub read exposed sealed message %s: %#v error=%v", messageID, legacy, err)
		}
	}
	askRecord, err := fixture.store.GetRelaySealedV1(fixture.messageID)
	if err != nil || askRecord.Route.Kind != "ask" || askRecord.Route.RequestID != fixture.requestID ||
		bytes.Contains(askRecord.Ciphertext, []byte("private message for the original session")) {
		t.Fatalf("Hub did not retain only the opaque original REQUEST: %#v error=%v", askRecord, err)
	}
	replyRecord, err := fixture.store.GetRelaySealedV1(replyMessageID)
	if err != nil || replyRecord.Route.Kind != "reply" ||
		replyRecord.Route.RequestID != fixture.requestID || replyRecord.Route.ReplyTo != fixture.messageID ||
		!bytes.Equal(replyRecord.Ciphertext, replyCiphertext) || bytes.Contains(replyRecord.Ciphertext, []byte(replyPlaintext)) {
		t.Fatalf("Hub did not retain only the exactly correlated encrypted REPLY: %#v error=%v", replyRecord, err)
	}

	argumentsPath, countPath := installMachineSealedFakeCodex(t, false, fixture.sourceToken)
	var receipts []string
	server := fixture.serverForNode(t, fixture.sourceNodeID, fixture.sourceToken, &receipts)
	defer server.Close()
	inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.sourceNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	for attempt := 0; attempt < 2; attempt++ {
		if err := processMachineFabricDeliveriesV2(context.Background(), server.URL,
			fixture.sourceNodeID, inbox, fixture.stateDir); err != nil {
			t.Fatalf("process sealed REPLY attempt %d: %v", attempt, err)
		}
	}
	if len(fixture.claimed) == 0 {
		t.Fatal("source Node did not claim the correlated REPLY")
	}
	for _, claimedReply := range fixture.claimed {
		if claimedReply.MessageID != replyMessageID || claimedReply.RequestID != fixture.requestID ||
			claimedReply.Route.Kind != "reply" || claimedReply.Route.ReplyTo != fixture.messageID ||
			!bytes.Equal(claimedReply.Ciphertext, replyCiphertext) {
			t.Fatalf("source Node claim correlation/ciphertext mismatch: message=%q request=%q route=%#v cipher_match=%t",
				claimedReply.MessageID, claimedReply.RequestID, claimedReply.Route,
				bytes.Equal(claimedReply.Ciphertext, replyCiphertext))
		}
	}
	claimWire, err := json.Marshal(fixture.claimed[0])
	if err != nil || bytes.Contains(claimWire, []byte(replyPlaintext)) || !bytes.Contains(claimWire, []byte(`"ciphertext"`)) {
		t.Fatalf("Relay claim exposed reply plaintext instead of ciphertext: %s error=%v", claimWire, err)
	}

	args, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatalf("source Node did not queue sealed REPLY: claimed=%d receipts=%v: %v",
			len(fixture.claimed), receipts, err)
	}
	argv := string(args)
	for _, expected := range []string{"queue\n", "--thread\n", "native_" + fixture.sourceEndpoint + "\n",
		"--message\n", "Cicada SEALED_V1 REPLY", replyMessageID, fixture.requestID,
		fixture.messageID, `"request_id":"` + fixture.requestID + `"`,
		`"reply_to":"` + fixture.messageID + `"`, replyPlaintext} {
		if !strings.Contains(argv, expected) {
			t.Fatalf("original requester queue omitted correlated REPLY field %q: %q", expected, argv)
		}
	}
	if bytes.Contains(args, replyCiphertext) {
		t.Fatal("source native queue prompt contained the sealed ciphertext envelope")
	}
	count, err := os.ReadFile(countPath)
	if err != nil || string(count) != "x" {
		t.Fatalf("sealed REPLY queue count=%q error=%v", count, err)
	}
	if strings.Join(receipts, ",") != "NODE_RECEIVED,CODEX_QUEUE_ACCEPTED,CONSUMPTION_UNCONFIRMED" {
		t.Fatalf("sealed REPLY receipt layers=%v", receipts)
	}
	stored, err := inbox.Get(context.Background(), replyMessageID)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || string(stored.Payload) != replyPlaintext {
		t.Fatalf("original requester durable REPLY=%#v error=%v", stored, err)
	}
}

func TestMachineSealedReplyRejectsInvalidCorrelation(t *testing.T) {
	fixture := newMachineSealedReceiveReplyFixture(t)
	const replyMessageID = "msg_machine_sealed_reply_invalid_correlation"
	_ = enqueueMachineSealedReply(t, fixture, replyMessageID, "correlated sealed answer")
	deliveries, err := fixture.service.ClaimNodeSealedDeliveries(fixture.sourceToken,
		fixture.sourceNodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(fixture.sourceNodeID), Limit: 50})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim setup deliveries=%d error=%v", len(deliveries), err)
	}
	delivery := deliveries[0]
	authorization, err := fixture.service.AuthorizeNodeSealedDelivery(fixture.sourceToken,
		delivery.MessageID, delivery.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateMachineSealedClaimAuthorization(fixture.sourceNodeID, delivery, *authorization); err != nil {
		t.Fatalf("valid sealed REPLY correlation rejected: %v", err)
	}

	missingReplyTo := delivery
	missingAuthorization := *authorization
	missingReplyTo.Route.ReplyTo = ""
	missingAuthorization.Route.ReplyTo = ""
	if err := validateMachineSealedClaimAuthorization(fixture.sourceNodeID, missingReplyTo, missingAuthorization); err == nil {
		t.Fatal("sealed REPLY without reply_to was accepted")
	}

	wrongRequestID := fixture.requestID + "_wrong"
	wrongRequest := delivery
	wrongRequestAuthorization := *authorization
	wrongRequest.RequestID = wrongRequestID
	wrongRequest.Route.RequestID = wrongRequestID
	wrongRequestAuthorization.Route.RequestID = wrongRequestID
	if err := validateMachineSealedClaimAuthorization(fixture.sourceNodeID, wrongRequest, wrongRequestAuthorization); err != nil {
		t.Fatalf("malformed correlation should reach envelope verification: %v", err)
	}
	if _, err := openMachineSealedDelivery(context.Background(), fixture.stateDir,
		fixture.sourceNodeID, wrongRequest, wrongRequestAuthorization); err == nil {
		t.Fatal("Endpoint envelope with a different request_id was accepted as REPLY")
	}

	wrongReplyTo := delivery
	wrongReplyAuthorization := *authorization
	wrongReplyTo.Route.ReplyTo = "msg_other_request"
	wrongReplyAuthorization.Route.ReplyTo = "msg_other_request"
	if err := validateMachineSealedClaimAuthorization(fixture.sourceNodeID, wrongReplyTo, wrongReplyAuthorization); err != nil {
		t.Fatalf("malformed reply_to should reach envelope verification: %v", err)
	}
	if _, err := openMachineSealedDelivery(context.Background(), fixture.stateDir,
		fixture.sourceNodeID, wrongReplyTo, wrongReplyAuthorization); err == nil {
		t.Fatal("Endpoint envelope with a different reply_to was accepted")
	}
}

func TestMachineSealedReplyRecoversCrashBeforeInboxSave(t *testing.T) {
	fixture := newMachineSealedReceiveReplyFixture(t)
	const replyMessageID = "msg_machine_sealed_reply_recovery"
	const replyPlaintext = "sealed answer recovered from Node crypto inbox"
	replyCiphertext := enqueueMachineSealedReply(t, fixture, replyMessageID, replyPlaintext)
	deliveries, err := fixture.service.ClaimNodeSealedDeliveries(fixture.sourceToken,
		fixture.sourceNodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(fixture.sourceNodeID), Limit: 50})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim setup deliveries=%d error=%v", len(deliveries), err)
	}
	delivery := deliveries[0]
	authorization, err := fixture.service.AuthorizeNodeSealedDelivery(fixture.sourceToken,
		delivery.MessageID, delivery.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openMachineSealedDelivery(context.Background(), fixture.stateDir,
		fixture.sourceNodeID, delivery, *authorization)
	if err != nil || opened.Duplicate || string(opened.Plaintext) != replyPlaintext {
		t.Fatalf("pre-crash sealed REPLY open=%#v error=%v", opened, err)
	}
	journal, err := openMachineRelayJournal(fixture.stateDir, fixture.sourceNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.putSealed(delivery, authorization.DataScope); err != nil {
		t.Fatal(err)
	}
	inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.sourceNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	if _, err := inbox.Get(context.Background(), replyMessageID); !errors.Is(err, nodeinbox.ErrNotFound) {
		t.Fatalf("crash fixture unexpectedly has local plaintext inbox row: %v", err)
	}
	argumentsPath, countPath := installMachineSealedFakeCodex(t, false, fixture.sourceToken)
	var receipts []string
	server := fixture.serverForNode(t, fixture.sourceNodeID, fixture.sourceToken, &receipts)
	defer server.Close()
	// Reconcile exercises the journal→Node crypto inbox recovery path before
	// any later remote claim could recreate the plaintext inbox row.
	if err := reconcileMachineRelayJournal(context.Background(), server.URL,
		fixture.sourceNodeID, fixture.stateDir, inbox, journal); err != nil {
		t.Fatalf("recover sealed REPLY inbox after crash: %v", err)
	}
	if err := drainMachineRelayInbox(context.Background(), server.URL,
		fixture.sourceNodeID, fixture.stateDir, inbox, journal); err != nil {
		t.Fatalf("drain recovered sealed REPLY: %v", err)
	}
	stored, err := inbox.Get(context.Background(), replyMessageID)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || string(stored.Payload) != replyPlaintext {
		t.Fatalf("recovered sealed REPLY inbox=%#v error=%v", stored, err)
	}
	args, err := os.ReadFile(argumentsPath)
	if err != nil {
		t.Fatalf("recovered REPLY was not queued to its native session: %v", err)
	}
	argv := string(args)
	for _, expected := range []string{"--thread\nnative_" + fixture.sourceEndpoint + "\n",
		"Cicada SEALED_V1 REPLY", replyMessageID, fixture.requestID, fixture.messageID,
		`"request_id":"` + fixture.requestID + `"`, `"reply_to":"` + fixture.messageID + `"`, replyPlaintext} {
		if !strings.Contains(argv, expected) {
			t.Fatalf("recovered REPLY omitted exact session/correlation field %q: %q", expected, argv)
		}
	}
	if bytes.Contains(args, replyCiphertext) {
		t.Fatal("recovered native REPLY prompt contained the ciphertext envelope")
	}
	count, err := os.ReadFile(countPath)
	if err != nil || string(count) != "x" {
		t.Fatalf("recovered REPLY queue count=%q error=%v", count, err)
	}
	if strings.Join(receipts, ",") != "NODE_RECEIVED,CODEX_QUEUE_ACCEPTED,CONSUMPTION_UNCONFIRMED" {
		t.Fatalf("recovered REPLY receipt layers=%v", receipts)
	}
}

func TestMachineSealedReceiveRecoversCrashBetweenJournalAndInbox(t *testing.T) {
	fixture := newMachineSealedReceiveFixture(t)
	argumentsPath, countPath := installMachineSealedFakeCodex(t, false, fixture.targetToken)
	deliveries, err := fixture.service.ClaimNodeSealedDeliveries(fixture.targetToken,
		fixture.targetNodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(fixture.targetNodeID), Limit: 50})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim setup deliveries=%d error=%v", len(deliveries), err)
	}
	delivery := deliveries[0]
	authorization, err := fixture.service.AuthorizeNodeSealedDelivery(fixture.targetToken,
		delivery.MessageID, delivery.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openMachineSealedDelivery(context.Background(), fixture.stateDir,
		fixture.targetNodeID, delivery, *authorization)
	if err != nil || opened.Duplicate || string(opened.Plaintext) != "private message for the original session" {
		t.Fatalf("pre-crash endpoint open=%#v error=%v", opened, err)
	}
	journal, err := openMachineRelayJournal(fixture.stateDir, fixture.targetNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.putSealed(delivery, authorization.DataScope); err != nil {
		t.Fatal(err)
	}
	// This is the crash point: ciphertext and route journal are durable; the
	// decrypted local inbox row and NODE_RECEIVED receipt do not yet exist.
	inboxPath := machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID)
	first, err := nodeinbox.Open(inboxPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	inbox, err := nodeinbox.Open(inboxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	var receipts []string
	server := fixture.server(t, &receipts)
	defer server.Close()
	if err := processMachineFabricDeliveriesV2(context.Background(), server.URL,
		fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
		t.Fatal(err)
	}
	stored, err := inbox.Get(context.Background(), fixture.messageID)
	if err != nil || string(stored.Payload) != "private message for the original session" ||
		stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED {
		t.Fatalf("recovered sealed inbox=%#v error=%v", stored, err)
	}
	count, err := os.ReadFile(countPath)
	if err != nil || string(count) != "x" {
		t.Fatalf("recovered delivery queue count=%q error=%v", count, err)
	}
	argv, err := os.ReadFile(argumentsPath)
	if err != nil || !bytes.Contains(argv, []byte("native_"+fixture.targetEndpoint)) {
		t.Fatalf("recovered delivery did not use exact native thread: args=%q error=%v", argv, err)
	}
	if len(receipts) == 0 || receipts[0] != fabric.ReceiptNodeReceived {
		t.Fatalf("recovered durable receipt layers=%v", receipts)
	}
}

func TestMachineSealedRequestRecoversCrashBetweenJournalAndInbox(t *testing.T) {
	fixture := newMachineSealedReceiveRequestFixture(t)
	argumentsPath, countPath := installMachineSealedFakeCodex(t, false, fixture.targetToken)
	deliveries, err := fixture.service.ClaimNodeSealedDeliveries(fixture.targetToken,
		fixture.targetNodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(fixture.targetNodeID), Limit: 50})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim setup deliveries=%d error=%v", len(deliveries), err)
	}
	delivery := deliveries[0]
	authorization, err := fixture.service.AuthorizeNodeSealedDelivery(fixture.targetToken,
		delivery.MessageID, delivery.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openMachineSealedDelivery(context.Background(), fixture.stateDir,
		fixture.targetNodeID, delivery, *authorization)
	if err != nil || opened.Duplicate || string(opened.Plaintext) != "private message for the original session" {
		t.Fatalf("pre-crash sealed REQUEST open=%#v error=%v", opened, err)
	}
	journal, err := openMachineRelayJournal(fixture.stateDir, fixture.targetNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.putSealed(delivery, authorization.DataScope); err != nil {
		t.Fatal(err)
	}
	inboxPath := machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID)
	first, err := nodeinbox.Open(inboxPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	inbox, err := nodeinbox.Open(inboxPath)
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	var receipts []string
	server := fixture.server(t, &receipts)
	defer server.Close()
	if err := processMachineFabricDeliveriesV2(context.Background(), server.URL,
		fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
		t.Fatalf("recover sealed REQUEST: %v", err)
	}
	stored, err := inbox.Get(context.Background(), fixture.messageID)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED ||
		string(stored.Payload) != "private message for the original session" {
		t.Fatalf("recovered sealed REQUEST inbox=%#v error=%v", stored, err)
	}
	argv, err := os.ReadFile(argumentsPath)
	if err != nil || !bytes.Contains(argv, []byte("native_"+fixture.targetEndpoint)) ||
		!bytes.Contains(argv, []byte(fixture.requestID)) {
		t.Fatalf("recovered REQUEST omitted exact session or correlation: args=%q error=%v", argv, err)
	}
	count, err := os.ReadFile(countPath)
	if err != nil || string(count) != "x" {
		t.Fatalf("recovered REQUEST queue count=%q error=%v", count, err)
	}
	if len(receipts) == 0 || receipts[0] != fabric.ReceiptNodeReceived {
		t.Fatalf("recovered REQUEST receipt layers=%v", receipts)
	}
	entry := journal.entry(fixture.messageID)
	if entry != nil && (entry.Kind != "ask" || entry.RequestID != fixture.requestID) {
		t.Fatalf("recovery journal lost REQUEST correlation: %#v", entry)
	}
}

func TestMachineSealedReceiveRechecksRevocationBeforeNativeQueue(t *testing.T) {
	fixture := newMachineSealedReceiveFixture(t)
	argumentsPath, countPath := installMachineSealedFakeCodex(t, false, fixture.targetToken)
	deliveries, err := fixture.service.ClaimNodeSealedDeliveries(fixture.targetToken,
		fixture.targetNodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(fixture.targetNodeID), Limit: 50})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim setup deliveries=%d error=%v", len(deliveries), err)
	}
	delivery := deliveries[0]
	authorization, err := fixture.service.AuthorizeNodeSealedDelivery(fixture.targetToken,
		delivery.MessageID, delivery.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openMachineSealedDelivery(context.Background(), fixture.stateDir,
		fixture.targetNodeID, delivery, *authorization)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := openMachineRelayJournal(fixture.stateDir, fixture.targetNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.putSealed(delivery, authorization.DataScope); err != nil {
		t.Fatal(err)
	}
	inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	if _, _, err := inbox.Save(context.Background(), nodeinbox.Message{MessageID: delivery.MessageID,
		Digest: delivery.Digest, EndpointID: authorization.EndpointID,
		SessionID: authorization.NativeSessionID, BindingEpoch: authorization.BindingEpoch,
		Payload: opened.Plaintext}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.RecordNodeReceipt(fixture.targetNodeID, fabric.NodeReceiptInput{
		AttemptID: delivery.AttemptID, MessageID: delivery.MessageID, Digest: delivery.Digest,
		EndpointID: authorization.EndpointID, BindingID: authorization.BindingID,
		BindingEpoch: authorization.BindingEpoch, Layer: fabric.ReceiptNodeReceived,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.store.RevokeCommunicationLink(fixture.link.ID,
		fixture.link.SourceOwnerID, fixture.link.Version, "sealed receive revoke test"); err != nil {
		t.Fatal(err)
	}
	var receipts []string
	server := fixture.server(t, &receipts)
	defer server.Close()
	if err := processMachineFabricDeliveriesV2(context.Background(), server.URL,
		fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
		t.Fatalf("process revoked sealed delivery: %v", err)
	}
	if _, err := os.Stat(argumentsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoked sealed message reached native Codex queue: stat=%v", err)
	}
	if _, err := os.Stat(countPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoked sealed message ran native queue: stat=%v", err)
	}
	stored, err := inbox.Get(context.Background(), fixture.messageID)
	if err != nil || stored.State != nodeinbox.FAILED {
		t.Fatalf("revoked sealed message state=%#v error=%v", stored, err)
	}
	if strings.Join(receipts, ",") != "NODE_RECEIVED,FAILED" {
		t.Fatalf("revoked sealed receipt layers=%v", receipts)
	}
}

func TestMachineSealedReceiveRejectsStaleAttemptBeforeNativeQueue(t *testing.T) {
	fixture := newMachineSealedReceiveFixture(t)
	argumentsPath, countPath := installMachineSealedFakeCodex(t, false, fixture.targetToken)
	deliveries, err := fixture.service.ClaimNodeSealedDeliveries(fixture.targetToken,
		fixture.targetNodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(fixture.targetNodeID), Limit: 50})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("claim setup deliveries=%d error=%v", len(deliveries), err)
	}
	delivery := deliveries[0]
	authorization, err := fixture.service.AuthorizeNodeSealedDelivery(fixture.targetToken,
		delivery.MessageID, delivery.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openMachineSealedDelivery(context.Background(), fixture.stateDir,
		fixture.targetNodeID, delivery, *authorization)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := openMachineRelayJournal(fixture.stateDir, fixture.targetNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.putSealed(delivery, authorization.DataScope); err != nil {
		t.Fatal(err)
	}
	inbox, err := nodeinbox.Open(machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	if _, _, err := inbox.Save(context.Background(), nodeinbox.Message{MessageID: delivery.MessageID,
		Digest: delivery.Digest, EndpointID: authorization.EndpointID,
		SessionID: authorization.NativeSessionID, BindingEpoch: authorization.BindingEpoch,
		Payload: opened.Plaintext}); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.RecordNodeReceipt(fixture.targetNodeID, fabric.NodeReceiptInput{
		AttemptID: delivery.AttemptID, MessageID: delivery.MessageID, Digest: delivery.Digest,
		EndpointID: authorization.EndpointID, BindingID: authorization.BindingID,
		BindingEpoch: authorization.BindingEpoch, Layer: fabric.ReceiptNodeReceived,
	}); err != nil {
		t.Fatal(err)
	}
	if err := journal.update(delivery.MessageID, func(entry *machineRelayJournalEntry) { entry.NodeReceived = true }); err != nil {
		t.Fatal(err)
	}
	var receipts []string
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "CicadaNode "+fixture.targetToken {
			t.Errorf("Node authorization=%q", got)
			response.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case request.URL.Path == "/v2/relay/nodes/"+fixture.targetNodeID+"/sealed/claim":
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case request.URL.Path == "/v2/relay/nodes/"+fixture.targetNodeID+"/group/sealed/claim":
			var input fabric.NodeClaimInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode same-Group sealed claim: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			if input.ConsumerID != machineRelayConsumerID(fixture.targetNodeID) || input.Limit != 50 {
				t.Errorf("same-Group sealed claim=%#v", input)
			}
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case strings.HasSuffix(request.URL.Path, "/authorization"):
			if request.URL.Query().Get("attempt_id") != delivery.AttemptID {
				t.Errorf("preflight attempt=%q, want exact stale attempt %q", request.URL.Query().Get("attempt_id"), delivery.AttemptID)
			}
			response.WriteHeader(http.StatusNotFound)
		case request.URL.Path == "/v2/relay/nodes/"+fixture.targetNodeID+"/claim":
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case request.URL.Path == "/v2/fabric/node/networks/direct/claim":
			_, _ = response.Write([]byte(`{"deliveries":[]}`))
		case request.URL.Path == "/v2/relay/nodes/"+fixture.targetNodeID+"/receipts":
			var input fabric.NodeReceiptInput
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Errorf("decode Node receipt: %v", err)
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			receipts = append(receipts, input.Layer)
			if _, err := fixture.service.RecordNodeReceipt(fixture.targetNodeID, input); err != nil {
				response.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"status": input.Layer})
		default:
			t.Errorf("unexpected stale-attempt Node API route: %s", request.URL.Path)
			response.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	if err := processMachineFabricDeliveriesV2(context.Background(), server.URL,
		fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
		t.Fatalf("process stale sealed attempt: %v", err)
	}
	if _, err := os.Stat(argumentsPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale sealed attempt reached native Codex queue: stat=%v", err)
	}
	if _, err := os.Stat(countPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale sealed attempt ran native queue: stat=%v", err)
	}
	stored, err := inbox.Get(context.Background(), fixture.messageID)
	if err != nil || stored.State != nodeinbox.FAILED {
		t.Fatalf("stale sealed attempt state=%#v error=%v", stored, err)
	}
	if strings.Join(receipts, ",") != "FAILED" {
		t.Fatalf("stale-attempt receipt layers=%v", receipts)
	}
}

func TestMachineSealedReceiveNativeQueueFailureIsUncertainAndNeverRetried(t *testing.T) {
	fixture := newMachineSealedReceiveFixture(t)
	argumentsPath, countPath := installMachineSealedFakeCodex(t, true, fixture.targetToken)
	var receipts []string
	server := fixture.server(t, &receipts)
	defer server.Close()
	inboxPath := machineNodeInboxPath(fixture.stateDir, fixture.targetNodeID)
	for attempt := 0; attempt < 2; attempt++ {
		inbox, err := nodeinbox.Open(inboxPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := processMachineFabricDeliveriesV2(context.Background(), server.URL,
			fixture.targetNodeID, inbox, fixture.stateDir); err != nil {
			inbox.Close()
			t.Fatalf("uncertain process attempt %d: %v", attempt, err)
		}
		stored, err := inbox.Get(context.Background(), fixture.messageID)
		if err != nil || stored.State != nodeinbox.INJECTION_UNCERTAIN {
			inbox.Close()
			t.Fatalf("uncertain local state=%#v error=%v", stored, err)
		}
		if err := inbox.Close(); err != nil {
			t.Fatal(err)
		}
	}
	count, err := os.ReadFile(countPath)
	if err != nil || string(count) != "x" {
		t.Fatalf("uncertain native queue count=%q error=%v", count, err)
	}
	argv, err := os.ReadFile(argumentsPath)
	if err != nil || !bytes.Contains(argv, []byte("native_"+fixture.targetEndpoint)) {
		t.Fatalf("uncertain delivery did not target exact native thread: args=%q error=%v", argv, err)
	}
	if strings.Join(receipts, ",") != "NODE_RECEIVED,INJECTION_UNCERTAIN" {
		t.Fatalf("uncertain sealed receipt layers=%v", receipts)
	}
}

func TestMachineSealedJournalDoesNotPersistCiphertextAndRetainsAttemptFlagsCorrectly(t *testing.T) {
	root := t.TempDir()
	delivery := fabric.NodeSealedDelivery{
		RelaySealedV1DeliveryAttempt: store.RelaySealedV1DeliveryAttempt{
			AttemptID: "attempt_sealed", MessageID: "msg_sealed_journal", Digest: "digest_sealed",
			RecipientEndpointID: "ep_target", ReceiverGroupID: "group_target",
			BindingID: "binding_target", BindingEpoch: 7, State: store.RelayAttemptClaimed,
			PayloadMode: store.RelayPayloadModeSealedV1,
			Route:       store.RelaySealedV1Route{MessageID: "msg_sealed_journal", SenderEndpointID: "ep_source", ReceiverEndpointID: "ep_target", Kind: "send"},
			Security: store.RelayMessageSecurity{MessageID: "msg_sealed_journal", Digest: "digest_sealed",
				SenderEndpointID: "ep_source", SenderPrincipalID: "pr_source", SenderGroupID: "group_source",
				SenderBindingID: "binding_source", SenderBindingEpoch: 4,
				ReceiverEndpointID: "ep_target", ReceiverPrincipalID: "pr_target", ReceiverGroupID: "group_target",
				ReceiverBindingID: "binding_target", ReceiverBindingEpoch: 7,
				VisibilityPolicyRef: "thread.message", AuthorizationRef: machineCommunicationLinkAuthorizationRefPrefix + "link_sealed"},
			Ciphertext: []byte("ciphertext-marker-must-stay-in-crypto-inbox"),
		},
		Harness: "codex", NativeSessionID: "native_target", NodeID: "node_target",
	}
	journal, err := openMachineRelayJournal(root, "node_target")
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.putSealed(delivery, "thread.message"); err != nil {
		t.Fatal(err)
	}
	if err := journal.update(delivery.MessageID, func(entry *machineRelayJournalEntry) { entry.NodeReceived = true }); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("ciphertext-marker-must-stay-in-crypto-inbox")) || bytes.Contains(data, []byte("ciphertext")) {
		t.Fatalf("journal contains sealed ciphertext: %s", data)
	}
	if entry := journal.entry(delivery.MessageID); entry == nil || !entry.NodeReceived {
		t.Fatalf("journal lost same-attempt receipt state: %#v", entry)
	}
	delivery.AttemptID = "attempt_sealed_retry"
	if err := journal.putSealed(delivery, "thread.message"); err != nil {
		t.Fatal(err)
	}
	if entry := journal.entry(delivery.MessageID); entry == nil || entry.NodeReceived || entry.AttemptID != delivery.AttemptID {
		t.Fatalf("new attempt reused old receipt state: %#v", entry)
	}
}

func TestMachineSealedAuthorizationRequiresExactCurrentAttemptAndBinding(t *testing.T) {
	delivery, authorization := machineSealedValidationFixture()
	if err := validateMachineSealedClaimAuthorization("node_target", delivery, authorization); err != nil {
		t.Fatalf("valid sealed assignment rejected: %v", err)
	}
	mutations := []struct {
		name   string
		mutate func(*fabric.NodeSealedDelivery, *store.CommunicationLinkSealedDeliveryAuthorization)
	}{
		{"attempt", func(_ *fabric.NodeSealedDelivery, auth *store.CommunicationLinkSealedDeliveryAuthorization) {
			auth.AttemptID += "_stale"
		}},
		{"digest", func(claim *fabric.NodeSealedDelivery, _ *store.CommunicationLinkSealedDeliveryAuthorization) {
			claim.Digest += "_changed"
		}},
		{"binding", func(claim *fabric.NodeSealedDelivery, _ *store.CommunicationLinkSealedDeliveryAuthorization) {
			claim.BindingEpoch++
		}},
		{"session", func(claim *fabric.NodeSealedDelivery, auth *store.CommunicationLinkSealedDeliveryAuthorization) {
			auth.NativeSessionID = "native_other"
			_ = claim
		}},
		{"route", func(claim *fabric.NodeSealedDelivery, _ *store.CommunicationLinkSealedDeliveryAuthorization) {
			claim.Route.ReceiverEndpointID = "ep_other"
		}},
		{"node", func(claim *fabric.NodeSealedDelivery, _ *store.CommunicationLinkSealedDeliveryAuthorization) {
			claim.NodeID = "node_other"
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			claim := delivery
			auth := authorization
			test.mutate(&claim, &auth)
			if err := validateMachineSealedClaimAuthorization("node_target", claim, auth); err == nil {
				t.Fatal("mismatched current authorization was accepted")
			}
		})
	}
}

func TestMachineSealedRecoveryKeepsJournalWhenOldAttemptAuthorizationIsGone(t *testing.T) {
	root := t.TempDir()
	const nodeID = "node_target"
	inbox, err := nodeinbox.Open(machineNodeInboxPath(root, nodeID))
	if err != nil {
		t.Fatal(err)
	}
	defer inbox.Close()
	delivery, _ := machineSealedValidationFixture()
	journal, err := openMachineRelayJournal(root, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.putSealed(delivery, "thread.message"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_NODE_TOKEN", "node-token")
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !strings.HasSuffix(request.URL.Path, "/authorization") || request.URL.Query().Get("attempt_id") != delivery.AttemptID {
			t.Errorf("unexpected recovery authorization request %s?%s", request.URL.Path, request.URL.RawQuery)
		}
		response.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	if err := reconcileMachineRelayJournal(context.Background(), server.URL, nodeID, root, inbox, journal); err != nil {
		t.Fatal(err)
	}
	if journal.entry(delivery.MessageID) == nil {
		t.Fatal("reconciliation discarded sealed journal while the old attempt awaits recovery")
	}
	if _, err := inbox.Get(context.Background(), delivery.MessageID); !errors.Is(err, nodeinbox.ErrNotFound) {
		t.Fatalf("unauthorized recovery wrote a local inbox row: %v", err)
	}
}

func machineSealedValidationFixture() (fabric.NodeSealedDelivery, store.CommunicationLinkSealedDeliveryAuthorization) {
	route := store.RelaySealedV1Route{MessageID: "msg_exact", SenderEndpointID: "ep_source",
		ReceiverEndpointID: "ep_target", Kind: "send"}
	security := store.RelayMessageSecurity{
		MessageID: "msg_exact", Digest: "digest_exact", SenderEndpointID: "ep_source",
		SenderPrincipalID: "pr_source", SenderGroupID: "group_source",
		SenderBindingID: "binding_source", SenderBindingEpoch: 4,
		ReceiverEndpointID: "ep_target", ReceiverPrincipalID: "pr_target", ReceiverGroupID: "group_target",
		ReceiverBindingID: "binding_target", ReceiverBindingEpoch: 7,
		VisibilityPolicyRef: "thread.message", AuthorizationRef: machineCommunicationLinkAuthorizationRefPrefix + "link_exact",
	}
	manifest := store.CommunicationLinkKeyManifest{
		LinkID: "link_exact", LinkVersion: 9,
		Source: store.CommunicationLinkKeySide{EndpointID: "ep_source", PrincipalID: "pr_source",
			GroupID: "group_source", BindingID: "binding_source", BindingEpoch: 4},
		Target: store.CommunicationLinkKeySide{EndpointID: "ep_target", PrincipalID: "pr_target",
			GroupID: "group_target", BindingID: "binding_target", BindingEpoch: 7, NodeID: "node_target"},
	}
	delivery := fabric.NodeSealedDelivery{
		RelaySealedV1DeliveryAttempt: store.RelaySealedV1DeliveryAttempt{
			AttemptID: "attempt_exact", MessageID: "msg_exact", Digest: "digest_exact",
			RecipientEndpointID: "ep_target", ReceiverGroupID: "group_target", BindingID: "binding_target",
			BindingEpoch: 7, State: store.RelayAttemptClaimed, PayloadMode: store.RelayPayloadModeSealedV1,
			Route: route, Security: security,
		},
		Harness: "codex", NativeSessionID: "native_target", NodeID: "node_target",
	}
	authorization := store.CommunicationLinkSealedDeliveryAuthorization{
		AttemptID: "attempt_exact", MessageID: "msg_exact", Digest: "digest_exact",
		EndpointID: "ep_target", BindingID: "binding_target", BindingEpoch: 7,
		NativeSessionID: "native_target", DataScope: "thread.message", Route: route,
		Bundle: store.CommunicationLinkAuthorizationBundle{Manifest: manifest, LinkState: "PROPOSED"},
	}
	return delivery, authorization
}
