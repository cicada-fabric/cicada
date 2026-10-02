package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
	serverpkg "github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// These fixtures use current signed Link/Network grants and the production TCP
// handler. The only runtime substitute is this executable's literal queue helper.
type n2TransportReceiptAudit struct {
	Status int      `json:"http_status"`
	Body   string   `json:"synthetic_raw_receipt_bytes"`
	SHA256 string   `json:"sha256"`
	Keys   []string `json:"keys"`
}

type n2RouteFixture struct {
	link          *machineSealedReceiveFixture
	network       bool
	hub           *httptest.Server
	ctx           context.Context
	inbox         *nodeinbox.Inbox
	journal       *machineRelayJournal
	process       nativeDeliveryProcessFixture
	messageID     string
	guardCalls    atomic.Int64
	deny          atomic.Bool
	sourceScope   store.NetworkAccessScope
	targetScope   store.NetworkAccessScope
	laterDelivery func(*testing.T) fabric.NetworkDirectDelivery
	receiptMu     sync.Mutex
	receipts      []n2TransportReceiptAudit
}

func newN2RouteFixture(t *testing.T, network bool) *n2RouteFixture {
	return newN2RouteFixtureMode(t, network, false)
}
func newN2RouteFixtureMode(t *testing.T, network, ingress bool) *n2RouteFixture {
	t.Helper()
	link := newMachineSealedReceiveFixtureWithSeed(t, !network && !ingress)
	f := &n2RouteFixture{link: link, network: network, messageID: link.messageID}
	handler := serverpkg.NewFabricHandler(link.service, "") // no Control business service
	f.hub = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/authorization") || strings.HasSuffix(r.URL.Path, "/authorize") {
			f.guardCalls.Add(1)
			if f.deny.Load() {
				http.Error(w, "synthetic revoked current authorization", http.StatusForbidden)
				return
			}
		}
		if strings.HasSuffix(r.URL.Path, "/sealed/send") {
			// Passive receipt tap: the original production handler authenticates,
			// commits and encodes the response. Forward every byte/header/status
			// unchanged; record only this bounded synthetic receipt, never requests.
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, r)
			data := recorder.Body.Bytes()
			var object map[string]json.RawMessage
			safe := len(data) <= 4096 && json.Unmarshal(data, &object) == nil
			keys := []string{}
			for key := range object {
				switch key {
				case "message_id", "payload_mode", "outbox_state", "sequence", "error":
					keys = append(keys, key)
				default:
					safe = false
				}
			}
			if safe {
				sort.Strings(keys)
				hash := sha256.Sum256(data)
				f.receiptMu.Lock()
				f.receipts = append(f.receipts, n2TransportReceiptAudit{Status: recorder.Code, Body: string(data), SHA256: hex.EncodeToString(hash[:]), Keys: keys})
				f.receiptMu.Unlock()
			} else {
				t.Error("production receipt was not a bounded safe synthetic receipt")
			}
			for key, values := range recorder.Header() {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(recorder.Code)
			_, _ = w.Write(data)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	t.Cleanup(f.hub.Close)
	hubID, err := link.store.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	nativeID := "native_" + link.targetEndpoint
	if network {
		nativeID = "synthetic-n2-network-target"
	}
	dir := t.TempDir()
	f.process = nativeDeliveryProcessFixture{Root: link.stateDir, HubID: hubID, NodeID: link.targetNodeID, Origin: f.hub.URL, Token: link.targetToken, WriterScope: machineNativeWriterScope(), NativeID: nativeID, ConfigPath: filepath.Join(dir, "queue-fixture.json"), CounterPath: filepath.Join(dir, "queue-count"), ArgsPath: filepath.Join(dir, "queue-argv.json"), WitnessPath: filepath.Join(dir, "witness")}
	nativeDeliverySaveConfig(t, f.process)
	f.ctx = nativeDeliveryChildContext(t, f.process)
	f.ctx = context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(f.process.ConfigPath)})
	f.inbox, err = nodeinbox.Open(machineNodeInboxPath(link.stateDir, link.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.inbox.Close() })
	f.journal, err = openMachineRelayJournal(link.stateDir, link.targetNodeID)
	if err != nil {
		t.Fatal(err)
	}
	if network {
		f.prepareNetwork(t, hubID)
	} else if !ingress {
		deliveries, err := link.service.ClaimNodeSealedDeliveries(link.targetToken, link.targetNodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(link.targetNodeID), Limit: 1})
		if err != nil || len(deliveries) != 1 {
			t.Fatalf("real Link claim: %v %#v", err, deliveries)
		}
		if err = acceptMachineSealedRelayDelivery(f.ctx, f.hub.URL, link.targetNodeID, link.stateDir, f.inbox, f.journal, deliveries[0]); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { n2RouteExport(t, f) })
	return f
}

func (f *n2RouteFixture) prepareNetwork(t *testing.T, hubID string) {
	t.Helper()
	s := f.link.store
	const networkID = "net_n2_actual_direct_synthetic"
	if _, err := s.CreateNetwork(store.Network{ID: networkID, HubID: hubID, Name: "Synthetic direct traffic Network", OwnerID: "owner_source"}); err != nil {
		t.Fatal(err)
	}
	// This shared fixture has legacy Link Groups. Review each as explicitly
	// pending/quarantined before the one-way Network activation; direct traffic
	// uses newly signed Network enrollment, never the quarantined Group route.
	groups, err := s.ListGroups(store.GroupFilter{})
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		if _, err := s.PrepareGroupNetworkMapping(group.ID, networkID,
			"synthetic N2 reviewed pending legacy Group quarantine", group.Version); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ActivateNetworkMode(); err != nil {
		t.Fatal(err)
	}
	join := func(ownerID, nodeID, nativeID, token string, owner *e2ee.Identity) (store.NetworkAccessScope, *e2ee.Identity, string) {
		invitation := "synthetic-n2-direct-invitation-" + nativeID + "-aaaaaaaaaaaaaaaa"
		// Invitation persistence and join admission require the same canonical
		// grant ordering; IssueNetworkInvitation sorts its independent copy.
		grants := []string{"direct.receive", "direct.send"}
		if err := s.IssueNetworkInvitation(networkID, ownerID, "owner_source", invitation, time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), grants); err != nil {
			t.Fatal(err)
		}
		proof, err := owner.SignOwnerNetworkJoinGrant(ownerID, hubID, networkID, nodeID, nativeID, store.NetworkInvitationDigest(invitation), owner.Public().ID, grants, false, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Nonce     string `json:"nonce"`
			ExpiresAt string `json:"expires_at"`
		}
		if err = json.Unmarshal(proof, &claims); err != nil {
			t.Fatal(err)
		}
		if _, err := e2ee.VerifyOwnerNetworkJoinGrant(proof, owner.Public(), e2ee.OwnerNetworkJoinGrant{
			HubID: hubID, NetworkID: networkID, OwnerID: ownerID, NodeID: nodeID, NativeSessionID: nativeID,
			InvitationDigest: store.NetworkInvitationDigest(invitation), Grants: grants, Discoverable: false}, time.Now().UTC()); err != nil {
			t.Fatalf("synthetic real Owner consent verification before join: %v", err)
		}
		accessToken := "synthetic-n2-network-access-" + nativeID + "-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		leaseOwner := "synthetic-n2-access-lease-" + nativeID
		ownerPrincipal, err := s.GetPrincipal(ownerID)
		if err != nil {
			t.Fatal(err)
		}
		joined, err := s.AcceptNetworkJoin(store.AcceptNetworkJoinInput{NetworkID: networkID, OwnerID: ownerID, TrustDomainID: ownerPrincipal.TrustDomainID, NodeID: nodeID, NativeSessionID: nativeID, Harness: "codex", EndpointName: "Synthetic actual direct agent", InvitationToken: invitation, ProofNonce: claims.Nonce, ProofDigest: store.NetworkInvitationDigest(string(proof)), ProofExpiresAt: claims.ExpiresAt, OwnerKeyID: owner.Public().ID, OwnerJoinProof: string(proof), NodeCredentialHash: fabric.HashSessionCredential(token), Grants: grants, CredentialHash: fabric.HashSessionCredential(accessToken), LeaseOwner: leaseOwner, LeaseExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
		if err != nil {
			t.Fatal(err)
		}
		scope := store.NetworkAccessScope{NetworkID: networkID, PrincipalID: joined.PrincipalID, EndpointID: joined.EndpointID, AccessSessionID: joined.AccessSessionID, AccessEpoch: joined.AccessSessionEpoch, LeaseOwner: leaseOwner, MembershipID: joined.MembershipID, MembershipRevision: joined.MembershipRevision, EndpointMembershipRevision: joined.EndpointRevision}
		binding, err := s.EnsureNetworkDirectNativeBinding(scope)
		if err != nil {
			t.Fatal(err)
		}
		key, err := nodekeys.LoadOrCreate(machineNodeStateDir(f.link.stateDir, nodeID), joined.EndpointID)
		if err != nil {
			t.Fatal(err)
		}
		attestation, err := key.SignNetworkDirectKeyAttestation(hubID, networkID, joined.EndpointID, joined.PrincipalID, nodeID, binding.ID, binding.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.RegisterNetworkDirectKeyCandidate(scope, attestation); err != nil {
			t.Fatal(err)
		}
		manifest, err := s.PreviewNetworkDirectKeyGrant(ownerID, networkID, joined.EndpointID, owner.Public().ID)
		if err != nil {
			t.Fatal(err)
		}
		grant, err := owner.SignOwnerNetworkDirectKeyGrant(hubID, networkID, joined.EndpointID, ownerID, manifest.Digest, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.AcceptNetworkDirectKeyGrant(ownerID, networkID, joined.EndpointID, grant); err != nil {
			t.Fatal(err)
		}
		return scope, key, accessToken
	}
	source, key, accessToken := join("owner_source", f.link.sourceNodeID, "synthetic-n2-network-source", f.link.sourceToken, f.link.sourceOwnerIdentity)
	target, _, _ := join("owner_target", f.link.targetNodeID, f.process.NativeID, f.link.targetToken, f.link.targetOwnerIdentity)
	f.sourceScope, f.targetScope = source, target
	trustLocalSealedRPCTestOwners(t, f.link.stateDir, f.link.targetNodeID, map[string]*e2ee.Identity{"owner_source": f.link.sourceOwnerIdentity, "owner_target": f.link.targetOwnerIdentity})
	bundle, err := s.NetworkDirectPeerKey(source, target.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	f.messageID = "synthetic-n2-network-message"
	ciphertext, err := e2ee.SealNetworkDirectMessage(key, bundle.Receiver.Manifest.Candidate.Public, store.NetworkDirectContext(bundle, f.messageID, "SEND", "", ""), []byte("SYNTHETIC_N2_DIRECT /resume 'literal' `no-shell`\nsecond line"), 1)
	if err != nil {
		t.Fatal(err)
	}
	sourceCtx := withMachineHubContext(context.Background(), machineHubContext{HubID: hubID, NodeID: f.link.sourceNodeID, Origin: f.hub.URL, Token: f.link.sourceToken})
	var record store.RelaySealedV1Record
	if err = machineAPIJSON(sourceCtx, f.hub.URL+"/v2/fabric/node/networks/direct/send", http.MethodPost, fabric.NetworkDirectSendInput{NetworkID: networkID, NetworkSessionToken: accessToken, TargetEndpointID: target.EndpointID, MessageID: f.messageID, IdempotencyKey: f.messageID, Ciphertext: ciphertext}, &record); err != nil {
		t.Fatal(err)
	}
	deliveries, err := f.link.service.ClaimNetworkDirectSealed(f.link.targetToken, f.link.targetNodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(f.link.targetNodeID), Limit: 1})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("real ND claim: %v %#v", err, deliveries)
	}
	if err = acceptMachineNetworkDirectDelivery(f.ctx, f.hub.URL, f.link.targetNodeID, f.link.stateDir, f.inbox, f.journal, deliveries[0]); err != nil {
		t.Fatal(err)
	}
	f.laterDelivery = func(t *testing.T) fabric.NetworkDirectDelivery {
		t.Helper()
		later, _, _ := join("owner_target", f.link.targetNodeID, "synthetic-n2-network-later", f.link.targetToken, f.link.targetOwnerIdentity)
		bundle, err := s.NetworkDirectPeerKey(source, later.EndpointID)
		if err != nil {
			t.Fatal(err)
		}
		const messageID = "synthetic-n2-network-later-message"
		sealed, err := e2ee.SealNetworkDirectMessage(key, bundle.Receiver.Manifest.Candidate.Public,
			store.NetworkDirectContext(bundle, messageID, "SEND", "", ""), []byte("SYNTHETIC_N2_LATER_AUTHORIZED_BODY"), 2)
		if err != nil {
			t.Fatal(err)
		}
		var record store.RelaySealedV1Record
		if err = machineAPIJSON(sourceCtx, f.hub.URL+"/v2/fabric/node/networks/direct/send", http.MethodPost,
			fabric.NetworkDirectSendInput{NetworkID: networkID, NetworkSessionToken: accessToken, TargetEndpointID: later.EndpointID,
				MessageID: messageID, IdempotencyKey: messageID, Ciphertext: sealed}, &record); err != nil {
			t.Fatal(err)
		}
		deliveries, err := f.link.service.ClaimNetworkDirectSealed(f.link.targetToken, f.link.targetNodeID,
			fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(f.link.targetNodeID), Limit: 1})
		if err != nil || len(deliveries) != 1 {
			t.Fatalf("later real ND claim: %#v %v", deliveries, err)
		}
		return deliveries[0]
	}
}

func (f *n2RouteFixture) claim(t *testing.T) (nodeinbox.Claim, machineRelayJournalEntry) {
	t.Helper()
	claim, err := f.inbox.Claim(f.ctx, machineRelayConsumerID(f.link.targetNodeID))
	if err != nil {
		t.Fatal(err)
	}
	entry := f.journal.entry(claim.MessageID)
	if entry == nil {
		t.Fatal("missing immutable journal")
	}
	return *claim, *entry
}
func (f *n2RouteFixture) drain(ctx context.Context, claim nodeinbox.Claim, entry machineRelayJournalEntry) error {
	if f.network {
		return drainMachineNetworkDirectClaim(ctx, f.hub.URL, f.link.targetNodeID, f.link.stateDir, f.inbox, f.journal, claim, entry)
	}
	return drainMachineSealedRelayClaim(ctx, f.hub.URL, f.link.targetNodeID, f.link.stateDir, f.inbox, f.journal, claim, entry)
}
func n2EachRoute(t *testing.T, run func(*testing.T, *n2RouteFixture)) {
	for _, network := range []bool{false, true} {
		name := "Link"
		if network {
			name = "NetworkDirect"
		}
		t.Run(name, func(t *testing.T) { run(t, newN2RouteFixture(t, network)) })
	}
}
func TestNativeDeliveryN2LinkNetworkBusyPreservesPreIntent(t *testing.T) {
	n2EachRoute(t, func(t *testing.T, f *n2RouteFixture) {
		claim, entry := f.claim(t)
		before := *f.journal.entry(f.messageID)
		holder := nativeDeliveryStartProcess(t, "n1-hold", f.process)
		holder.ready(t, "writer_held")
		ctx, cancel := context.WithTimeout(f.ctx, 120*time.Millisecond)
		defer cancel()
		if err := f.drain(ctx, claim, entry); err == nil {
			t.Fatal("busy writer unexpectedly admitted")
		}
		stored, err := f.inbox.Get(f.ctx, f.messageID)
		if err != nil || stored.State != nodeinbox.NODE_RECEIVED {
			t.Fatalf("preintent state: %#v %v", stored, err)
		}
		if !reflect.DeepEqual(before, *f.journal.entry(f.messageID)) {
			t.Fatal("busy changed original journal")
		}
		if _, err = os.Stat(f.process.CounterPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("busy queue side effect: %v", err)
		}
		n2ReleaseHolder(t, holder)
		retry, next := f.claim(t)
		if retry.AttemptID == claim.AttemptID {
			t.Fatal("cleanup did not abandon CLAIMED")
		}
		if err = f.drain(f.ctx, retry, next); err != nil {
			t.Fatal(err)
		}
		if nativeDeliveryCount(t, f.process.CounterPath) != 1 {
			t.Fatal("retry queue count")
		}
	})
}
func TestNativeDeliveryN2LinkNetworkCurrentGuardAfterWriterWait(t *testing.T) {
	n2EachRoute(t, func(t *testing.T, f *n2RouteFixture) {
		claim, entry := f.claim(t)
		holder := nativeDeliveryStartProcess(t, "n1-hold", f.process)
		holder.ready(t, "writer_held")
		reached := make(chan struct{})
		ctx := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(f.process.ConfigPath), observe: func(phase string) {
			if phase == "writer_wait" {
				close(reached)
			}
		}})
		done := make(chan error, 1)
		go func() { done <- f.drain(ctx, claim, entry) }()
		select {
		case <-reached:
		case <-time.After(5 * time.Second):
			t.Fatal("writer wait not reached")
		}
		before := f.guardCalls.Load()
		f.revoke(t)
		n2ReleaseHolder(t, holder)
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Fatal("held Guard denial stuck")
		}
		stored, err := f.inbox.Get(f.ctx, f.messageID)
		if err != nil || stored.State != nodeinbox.FAILED {
			t.Fatalf("denial not durably fenced: %#v %v", stored, err)
		}
		if len(nativeDeliveryRawOutcomes(t, f.process.Root)) != 0 {
			t.Fatal("revoked authority wrote native intent")
		}
		if f.journal.entry(f.messageID) != nil {
			t.Fatal("durably rejected journal not retired")
		}
		if f.guardCalls.Load() <= before {
			t.Fatal("no fresh HTTP Guard after writer wait")
		}
		if _, err := os.Stat(f.process.CounterPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("revoked queue side effect")
		}
	})
}
func TestNativeDeliveryN2LinkNetworkReleasedWriterAllowsReceipt(t *testing.T) {
	n2EachRoute(t, func(t *testing.T, f *n2RouteFixture) {
		claim, entry := f.claim(t)
		closed := false
		ctx := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(f.process.ConfigPath), observe: func(phase string) {
			if phase == "accepted_writer_closed" {
				closed = true
			}
		}})
		if err := f.drain(ctx, claim, entry); err != nil {
			t.Fatal(err)
		}
		stored, err := f.inbox.Get(f.ctx, f.messageID)
		if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || !closed {
			t.Fatalf("completion: %#v closed=%v %v", stored, closed, err)
		}
		if nativeDeliveryCount(t, f.process.CounterPath) != 1 {
			t.Fatal("actual subprocess count")
		}
		if f.journal.entry(f.messageID) != nil {
			t.Fatal("successful current receipts did not retire journal")
		}
		data, err := os.ReadFile(f.process.ArgsPath)
		if err != nil {
			t.Fatal(err)
		}
		var argv []string
		if err = json.Unmarshal(data, &argv); err != nil {
			t.Fatal(err)
		}
		if len(argv) != 5 || argv[0] != "queue" || argv[1] != "--thread" || argv[2] != claim.SessionID || argv[3] != "--message" {
			t.Fatalf("literal argv: %q", argv)
		}
		if f.network {
			_, encoded, found := strings.Cut(argv[4], "\n")
			var envelope struct {
				NetworkID          string `json:"network_id"`
				MessageID          string `json:"message_id"`
				SenderEndpointID   string `json:"sender_endpoint_id"`
				ReceiverEndpointID string `json:"receiver_endpoint_id"`
				Body               string `json:"body"`
			}
			if !found || json.Unmarshal([]byte(encoded), &envelope) != nil ||
				envelope.Body != string(claim.Payload) || envelope.NetworkID != entry.NetworkID ||
				envelope.MessageID != claim.MessageID || envelope.SenderEndpointID != entry.SenderEndpointID ||
				envelope.ReceiverEndpointID != claim.EndpointID {
				t.Fatalf("actual ND prompt lost exact body or authenticated route: %#v", envelope)
			}
		} else if !strings.Contains(argv[4], string(claim.Payload)) {
			t.Fatalf("actual Link prompt lost body: %q", argv[4])
		}
	})
}

func n2ReleaseHolder(t *testing.T, holder *nativeDeliveryProcess) {
	t.Helper()
	if _, err := fmt.Fprintln(holder.stdin, "release"); err != nil {
		t.Fatal(err)
	}
	holder.wait(t, false)
}
func (f *n2RouteFixture) revoke(t *testing.T) {
	t.Helper()
	if f.network {
		if err := f.link.store.RevokeNetworkMembership(f.targetScope.NetworkID, f.targetScope.PrincipalID, f.targetScope.MembershipRevision); err != nil {
			t.Fatal(err)
		}
	} else {
		if _, err := f.link.store.RevokeCommunicationLink(f.link.link.ID, f.link.link.SourceOwnerID, f.link.link.Version, "synthetic revoke while physical writer held"); err != nil {
			t.Fatal(err)
		}
	}
}
func TestNativeDeliveryN2LinkNetworkStartedCancellationRemainsUnknown(t *testing.T) {
	n2EachRoute(t, func(t *testing.T, f *n2RouteFixture) {
		f.process.QueueBlock = true
		nativeDeliverySaveConfig(t, f.process)
		readyReader, readyWriter, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		blockReader, blockWriter, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = readyReader.Close()
			_ = readyWriter.Close()
			_ = blockReader.Close()
			_ = blockWriter.Close()
		})
		command := nativeDeliveryQueueCommand(f.process.ConfigPath)
		lifecycle := machineNativeDeliveryLifecycle{command: func(ctx context.Context, binary string, args ...string) *exec.Cmd {
			child := command(ctx, binary, args...)
			child.ExtraFiles = []*os.File{readyWriter, blockReader}
			return child
		}}
		ctx, cancel := context.WithCancel(context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, lifecycle))
		defer cancel()
		claim, entry := f.claim(t)
		done := make(chan error, 1)
		go func() { done <- f.drain(ctx, claim, entry) }()
		ready := make(chan string, 1)
		go func() { line, _ := bufio.NewReader(readyReader).ReadString('\n'); ready <- line }()
		select {
		case line := <-ready:
			if line != "accepted\n" {
				t.Fatalf("queue witness: %q", line)
			}
		case <-time.After(8 * time.Second):
			t.Fatal("queue did not start")
		}
		cancel()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("started cancellation returned success")
			}
		case <-time.After(8 * time.Second):
			t.Fatal("started cancellation stuck")
		}
		stored, err := f.inbox.Get(f.ctx, f.messageID)
		if err != nil || stored.State != nodeinbox.INJECTING {
			t.Fatalf("cancelled inbox: %#v %v", stored, err)
		}
		if outcomes := nativeDeliveryRawOutcomes(t, f.process.Root); !reflect.DeepEqual(outcomes, []nodelock.NativeOutcomeState{nodelock.NativeUncertain}) {
			t.Fatalf("native witness: %v", outcomes)
		}
		if err = f.inbox.Close(); err != nil {
			t.Fatal(err)
		}
		f.inbox, err = nodeinbox.Open(machineNodeInboxPath(f.link.stateDir, f.link.targetNodeID))
		if err != nil {
			t.Fatal(err)
		}
		if err = reconcileMachineRelayJournal(f.ctx, f.hub.URL, f.link.targetNodeID, f.link.stateDir, f.inbox, f.journal); err != nil {
			t.Fatal(err)
		}
		stored, err = f.inbox.Get(f.ctx, f.messageID)
		if err != nil || stored.State != nodeinbox.INJECTION_UNCERTAIN || f.journal.entry(f.messageID) == nil || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
			t.Fatalf("unknown recovery: %#v %v", stored, err)
		}
		if err = reconcileMachineRelayJournal(f.ctx, f.hub.URL, f.link.targetNodeID, f.link.stateDir, f.inbox, f.journal); err != nil {
			t.Fatal(err)
		}
		if f.journal.entry(f.messageID) == nil || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
			t.Fatal("terminal authorization denial erased unknown evidence")
		}
	})
}
func TestNativeDeliveryN2NetworkDeniedAfterStartRetainsRecoveryCoordinates(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		name := "Unknown"
		if accepted {
			name = "QueueAccepted"
		}
		t.Run(name, func(t *testing.T) {
			f := newN2RouteFixture(t, true)
			claim, entry := f.claim(t)
			if !accepted {
				f.process.QueueExit = 7
				nativeDeliverySaveConfig(t, f.process)
			}
			command := nativeDeliveryQueueCommand(f.process.ConfigPath)
			ctx := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: command, observe: func(phase string) {
				if (!accepted && phase == "queue_wait_succeeded") || (accepted && phase == "accepted_writer_closed") {
					f.revoke(t)
				}
			}})
			err := f.drain(ctx, claim, entry)
			if accepted && err == nil {
				t.Fatal("revoked accepted receipt unexpectedly succeeded")
			}
			if !accepted {
				f.revoke(t)
			}
			before := *f.journal.entry(f.messageID)
			if err = reconcileMachineRelayJournal(f.ctx, f.hub.URL, f.link.targetNodeID, f.link.stateDir, f.inbox, f.journal); err != nil {
				t.Fatal(err)
			}
			if f.journal.entry(f.messageID) == nil || !reflect.DeepEqual(before, *f.journal.entry(f.messageID)) || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
				t.Fatal("denial changed post-start journal or injected twice")
			}
			// A later independently enrolled ND Endpoint must progress past the
			// denied outcome, without reusing quarantined legacy Group authority.
			later := f.laterDelivery(t)
			if err = acceptMachineNetworkDirectDelivery(f.ctx, f.hub.URL, f.link.targetNodeID, f.link.stateDir, f.inbox, f.journal, later); err != nil {
				t.Fatal(err)
			}
			nextProcess := f.process
			nextProcess.QueueExit = 0
			nextProcess.NativeID = later.NativeSessionID
			nextProcess.ConfigPath = filepath.Join(filepath.Dir(f.process.ConfigPath), "later-queue-fixture.json")
			nativeDeliverySaveConfig(t, nextProcess)
			nextCtx := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, machineNativeDeliveryLifecycle{command: nativeDeliveryQueueCommand(nextProcess.ConfigPath)})
			if err = reconcileMachineRelayJournal(nextCtx, f.hub.URL, f.link.targetNodeID, f.link.stateDir, f.inbox, f.journal); err != nil {
				t.Fatal(err)
			}
			if err = drainMachineRelayInbox(nextCtx, f.hub.URL, f.link.targetNodeID, f.link.stateDir, f.inbox, f.journal); err != nil {
				t.Fatal(err)
			}
			progressed, err := f.inbox.Get(f.ctx, later.MessageID)
			if err != nil || progressed.State != nodeinbox.CONSUMPTION_UNCONFIRMED || nativeDeliveryCount(t, f.process.CounterPath) != 2 {
				t.Fatalf("later Network direct starved: %#v %v", progressed, err)
			}
			if f.journal.entry(f.messageID) == nil {
				t.Fatal("later progress erased denied Network journal")
			}
			stored, err := f.inbox.Get(f.ctx, f.messageID)
			if err != nil {
				t.Fatal(err)
			}
			want := nodeinbox.INJECTION_UNCERTAIN
			if accepted {
				want = nodeinbox.CONSUMPTION_UNCONFIRMED
			}
			if stored.State != want {
				t.Fatalf("retained state %s want %s", stored.State, want)
			}
		})
	}
}

// Optional test-only evidence retains bounded synthetic bytes, not fixture
// credentials, private endpoint keys, crypto databases, or production payloads.
func n2RouteExport(t *testing.T, f *n2RouteFixture) {
	t.Helper()
	root := os.Getenv("CICADA_N2_TEST_EVIDENCE_DIR")
	if root == "" {
		return
	}
	name := strings.NewReplacer("/", "_", "\\", "_").Replace(t.Name())
	directory := filepath.Join(root, name)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Error(err)
		return
	}
	type raw struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
		Bytes  string `json:"synthetic_raw_bytes"`
	}
	files := []string{f.process.CounterPath, f.process.ArgsPath, f.process.WitnessPath}
	outcomes, err := filepath.Glob(filepath.Join(f.process.Root, ".native-writers", "*.operations", "*.json"))
	if err != nil {
		t.Error(err)
		return
	}
	files = append(files, outcomes...)
	records := []raw{}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Error(err)
			return
		}
		if len(data) > 128*1024 {
			t.Error("synthetic evidence exceeds bounded record limit")
			return
		}
		hash := sha256.Sum256(data)
		records = append(records, raw{Path: filepath.Base(path), SHA256: hex.EncodeToString(hash[:]), Bytes: string(data)})
	}
	state := "unavailable"
	attemptID := ""
	if delivery, err := f.inbox.Get(context.Background(), f.messageID); err == nil {
		state = string(delivery.State)
		attemptID = delivery.AttemptID
	}
	journal := f.journal.entry(f.messageID)
	record := struct {
		Route      string                    `json:"route"`
		MessageID  string                    `json:"message_id"`
		AttemptID  string                    `json:"local_attempt_id"`
		InboxState string                    `json:"inbox_state"`
		Journal    *machineRelayJournalEntry `json:"synthetic_journal"`
		Files      []raw                     `json:"synthetic_files"`
		Receipts   []n2TransportReceiptAudit `json:"synthetic_production_receipts"`
	}{Route: "Link", MessageID: f.messageID, AttemptID: attemptID, InboxState: state, Journal: journal, Files: records}
	f.receiptMu.Lock()
	record.Receipts = append([]n2TransportReceiptAudit(nil), f.receipts...)
	f.receiptMu.Unlock()
	if f.network {
		record.Route = "Network-direct"
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		t.Error(err)
		return
	}
	data = append(data, '\n')
	if err = os.WriteFile(filepath.Join(directory, "synthetic-route-audit.json"), data, 0600); err != nil {
		t.Error(err)
	}
	t.Logf("actual synthetic route audit: route=%s inbox=%s local_attempt=%s retained_journal=%v raw_records=%d", record.Route, state, attemptID, journal != nil, len(records))
}

// Separate once-only transport gate: real MCP method, owner Unix socket and
// production Fabric TCP handler, two logical Nodes and a synthetic subprocess.
// It does not claim a real native Runtime, public HTTPS or physical topology.
func TestNativeDeliveryN2LinkTransport(t *testing.T) {
	f := newN2RouteFixtureMode(t, false, true)
	token, credentialDigest, err := fabric.NewSessionCredential()
	if err != nil {
		t.Fatal(err)
	}
	const body = "SYNTHETIC_N2_UNIX_TCP_BODY /resume 'literal' `no-shell`\nsecond line"
	workspace := prepareLocalSealedBridgeSession(t, "native_ep_source")
	t.Setenv("CICADA_MACHINE_ID", f.link.sourceNodeID)
	t.Setenv("CICADA_NODE_STATE_DIR", f.link.stateDir)
	// The original crypto fixture has no workspace. Register the verified
	// synthetic native-record workspace through the real Endpoint primitive,
	// preserving its existing identity, owner, memberships and signed binding.
	endpoint, err := f.link.store.GetEndpointV2(f.link.link.SourceEndpointID)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Workspace = workspace
	if _, err = f.link.store.UpsertEndpoint(*endpoint); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", f.link.databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Fixture-only installs a synthetic credential on the already signed/leased
	// original binding. Identity, lease, membership and keys remain authoritative.
	changed, err := db.Exec(`UPDATE session_bindings SET credential_hash=? WHERE id=?`, credentialDigest, f.link.manifest.Source.BindingID)
	if err != nil {
		t.Fatal(err)
	}
	n, err := changed.RowsAffected()
	if err != nil || n != 1 {
		t.Fatalf("synthetic source credential: %d %v", n, err)
	}
	// Production-issued credentials still pass the real current Session Guard.
	// The fixture bootstrap above changes only its hash, preserving the already
	// authenticated binding epoch, lease, memberships and bilateral key grants.
	actor, err := f.link.service.AuthenticateForGroup(token, f.link.link.SourceGroupID)
	if err != nil || actor.EndpointID != f.link.link.SourceEndpointID ||
		actor.BindingID != f.link.manifest.Source.BindingID || actor.BindingEpoch != f.link.manifest.Source.BindingEpoch {
		t.Fatalf("production source Session Guard before MCP: actor=%#v error=%v", actor, err)
	}
	sourceProcess := f.process
	sourceProcess.NodeID = f.link.sourceNodeID
	sourceProcess.Token = f.link.sourceToken
	sourceProcess.NativeID = "native_ep_source"
	sourceCtx := nativeDeliveryChildContext(t, sourceProcess)
	bridge, err := startMachineAgentJoinBridge(sourceCtx, f.link.stateDir, f.hub.URL, f.link.sourceNodeID, f.link.sourceToken)
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	origin, err := normalizeMCPAPIOrigin(f.hub.URL)
	if err != nil {
		t.Fatal(err)
	}
	current := mcpTestContext("codex", "native_ep_source", f.link.sourceNodeID, workspace)
	scope, trusted, err := mcpSessionScope(origin, current)
	if err != nil {
		t.Fatal(err)
	}
	actualCard, err := f.link.service.WhoAmI(actor)
	if err != nil || actualCard == nil {
		t.Fatalf("production current source card: %v", err)
	}
	card := *actualCard
	if card.Workspace != workspace || card.NativeSessionID != "native_ep_source" ||
		card.NodeID != f.link.sourceNodeID || card.EndpointID != f.link.link.SourceEndpointID ||
		card.BindingID != f.link.manifest.Source.BindingID || card.BindingEpoch != f.link.manifest.Source.BindingEpoch {
		t.Fatalf("production current card differs from verified synthetic native record: %#v", card)
	}
	mcp := newMCPServer(f.hub.URL, card.EndpointID, filepath.Join(t.TempDir(), "mcp", "sessions.json"))
	mcp.setSession(token, card.EndpointID, card.GroupID, trusted, scope, mcpPublicJoinResult{Endpoint: store.Endpoint{ID: card.EndpointID, GroupID: card.GroupID, Owner: f.link.link.SourceOwnerID}, NetworkCard: card, BindingID: card.BindingID, BindingEpoch: card.BindingEpoch})
	defer func() {
		if mcp.outbox != nil {
			_ = mcp.outbox.close()
		}
		close(mcp.stop)
	}()
	sent, err := mcp.callTool("cicada_send", map[string]any{"link_id": f.link.link.ID, "data_scope": f.link.dataScope, "body": body, "idempotency_key": "synthetic-n2-transport-send"})
	if err != nil {
		t.Fatal(err)
	}
	result := sent.(map[string]any)
	if result["status"] != mcpOutboxStatusSent {
		t.Fatalf("actual sealed send: %#v", result)
	}
	f.messageID = result["operation_id"].(string)
	f.receiptMu.Lock()
	receipts := append([]n2TransportReceiptAudit(nil), f.receipts...)
	f.receiptMu.Unlock()
	if len(receipts) != 1 || receipts[0].Status != http.StatusAccepted {
		t.Fatalf("actual production SEND receipt count/status: %#v", receipts)
	}
	var accepted struct {
		MessageID   string `json:"message_id"`
		PayloadMode string `json:"payload_mode"`
		Sequence    int64  `json:"sequence"`
	}
	if json.Unmarshal([]byte(receipts[0].Body), &accepted) != nil || accepted.MessageID != f.messageID || accepted.PayloadMode != store.RelayPayloadModeSealedV1 || accepted.Sequence < 1 {
		t.Fatalf("actual production SEND receipt lost exact ID/mode/positive sequence: %#v", accepted)
	}
	record, err := f.link.store.GetRelaySealedV1(f.messageID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(record.Ciphertext), body) {
		t.Fatal("Hub persisted clear synthetic body")
	}
	deliveries, err := f.link.service.ClaimNodeSealedDeliveries(f.link.targetToken, f.link.targetNodeID, fabric.NodeClaimInput{ConsumerID: machineRelayConsumerID(f.link.targetNodeID), Limit: 1})
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("real transport claim: %#v %v", deliveries, err)
	}
	if err = acceptMachineSealedRelayDelivery(f.ctx, f.hub.URL, f.link.targetNodeID, f.link.stateDir, f.inbox, f.journal, deliveries[0]); err != nil {
		t.Fatal(err)
	}
	claim, entry := f.claim(t)
	if string(claim.Payload) != body {
		t.Fatal("receiver did not decrypt exact synthetic body")
	}
	if err = f.drain(f.ctx, claim, entry); err != nil {
		t.Fatal(err)
	}
	stored, err := f.inbox.Get(f.ctx, f.messageID)
	if err != nil || stored.State != nodeinbox.CONSUMPTION_UNCONFIRMED || f.journal.entry(f.messageID) != nil || nativeDeliveryCount(t, f.process.CounterPath) != 1 {
		t.Fatalf("real TCP receipt completion: %#v %v", stored, err)
	}
	t.Log("production MCP -> owner Unix socket -> Fabric TCP sealed Relay -> exact receiver Guard/decrypt/inbox -> synthetic subprocess -> HTTP queue accepted/consumption unconfirmed; Control nil; real native NOT_RUN")
}

// Protocol-parser fixture only: this bounded HTTP response exercises the actual
// Node receipt decoder. It does not represent a Hub authorization or admission
// proof; TestNativeDeliveryN2LinkTransport supplies that production evidence.
func TestNativeDeliveryN2LinkSendReceiptStrictDecoder(t *testing.T) {
	for _, unknown := range []bool{false, true} {
		name := "ExistingHubSequence"
		if unknown {
			name = "UnknownFieldDenied"
		}
		t.Run(name, func(t *testing.T) {
			nodeToken, _, err := fabric.NewNodeCredential()
			if err != nil {
				t.Fatal(err)
			}
			payload := map[string]any{"message_id": "synthetic-n2-parser-message", "payload_mode": store.RelayPayloadModeSealedV1, "outbox_state": "READY", "sequence": int64(27)}
			if unknown {
				payload["synthetic_unknown_authority_field"] = "not-authority"
			}
			hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v2/relay/nodes/synthetic-parser-node/sealed/send" || r.Header.Get("Authorization") != "CicadaNode "+nodeToken {
					t.Error("unexpected parser-fixture request")
					http.Error(w, "synthetic parser request mismatch", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusAccepted)
				_ = json.NewEncoder(w).Encode(payload)
			}))
			defer hub.Close()
			ctx := withMachineHubContext(context.Background(), machineHubContext{HubID: "synthetic-parser-hub", NodeID: "synthetic-parser-node", Origin: hub.URL, Token: nodeToken})
			bridge := &machineAgentJoinBridge{ctx: ctx, baseURL: hub.URL, nodeID: "synthetic-parser-node", nodeToken: nodeToken}
			receipt, err := bridge.postSealedLinkMessage(fabric.NodeSealedLinkSendInput{LinkID: "synthetic-parser-link", MessageID: "synthetic-n2-parser-message", DataScope: "thread.message", Ciphertext: []byte("synthetic-parser-opaque-placeholder")})
			if unknown {
				if err == nil || err.Error() != "Hub returned an invalid sealed-send receipt" {
					t.Fatalf("unknown receipt field accepted: %#v %v", receipt, err)
				}
				return
			}
			if err != nil || receipt.MessageID != "synthetic-n2-parser-message" || receipt.PayloadMode != store.RelayPayloadModeSealedV1 || receipt.OutboxState != "READY" || receipt.Sequence != 27 {
				t.Fatalf("actual decoder lost existing Hub receipt: %#v %v", receipt, err)
			}
		})
	}
}
