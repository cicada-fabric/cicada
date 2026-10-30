package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/store"
)

// This is a producer isolation test: one real HTTP Hub, the existing legacy
// enrollment fixture, one Node and two synthetic original native records. Only
// the queue executable is fake. It does not qualify two scoped Nodes or Runtime.
func TestEndpointGroupsColdOriginalASKReachesExactQueue(t *testing.T) {
	f, registrations, group, unlock := newEndpointGroupsReplyFixture(t)
	argumentsPath, countPath := installMachineSealedFakeCodex(t, false, f.token)
	hash := func(v any) string {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal("closed witness encoding failed")
		}
		sum := sha256.Sum256(raw)
		return hex.EncodeToString(sum[:])
	}
	identity := func() string {
		t.Helper()
		var anchors [2]wire.EndpointGroupsRegistrationAnchor
		var publics [2]e2ee.PublicIdentity
		for i := range anchors {
			r, enrolled, err := f.client.endpointGroupsRegistrationCandidate(f.native[i], f.workspace)
			if err != nil || !enrolled {
				t.Fatal("original registration unavailable")
			}
			anchors[i] = r.Anchor
			anchors[i].LeaseExpiresAt, anchors[i].State = "", ""
			key, err := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), r.Anchor.Registration.EndpointID)
			if err != nil {
				t.Fatal("original key unavailable")
			}
			publics[i] = key.Public()
		}
		state, err := nodekeys.OpenExistingCryptoState(f.ctx, machineNodeStateDir(f.nodeRoot, f.nodeID))
		if err != nil {
			t.Fatal("original crypto state unavailable")
		}
		trust, trustErr := state.GetNodeOwnerKeyTrustLocalContext(f.ctx, f.setup.OwnerID, f.owner.Public().ID)
		closeErr := state.Close()
		if trustErr != nil || closeErr != nil || trust.State != nodekeys.NodeOwnerKeyTrustActive {
			t.Fatal("original Owner pin unavailable")
		}
		return hash(struct {
			Node, Owner e2ee.PublicIdentity
			Anchors     [2]wire.EndpointGroupsRegistrationAnchor
			Keys        [2]e2ee.PublicIdentity
		}{f.client.publicIdentity(), trust.PublicIdentity, anchors, publics})
	}
	originalIdentity := identity()
	f.client.mu.Lock()
	originalState := cloneMachineNodeControlState(f.client.state)
	f.client.mu.Unlock()
	peer, err := f.bridge.fetchCrossNodeGroupPeerKey(group, registrations[0].Anchor.Registration.EndpointID, registrations[1].Anchor.Registration.EndpointID)
	if err != nil || peer.EndpointGroupCurrent == nil || peer.Sender.EndpointGroupGrant == nil || peer.Receiver.EndpointGroupGrant == nil {
		t.Fatal("original manual grants unavailable")
	}
	requestID, err := wire.NewRequestID()
	if err != nil {
		t.Fatal("synthetic request identity unavailable")
	}
	askID, err := wire.NewRequestID()
	if err != nil {
		t.Fatal("synthetic message identity unavailable")
	}
	const question = "synthetic cold original ASK question"
	key, err := nodekeys.LoadExisting(machineNodeStateDir(f.nodeRoot, f.nodeID), peer.Sender.EndpointID)
	if err != nil {
		t.Fatal("original sender key unavailable")
	}
	messageContext := crossNodeGroupEndpointContext(peer, peer.Sender, peer.Receiver, askID, requestID, "", "", "REQUEST")
	ciphertext, err := e2ee.SealEndpointMessage(key, crossNodeGroupManifest(peer.Receiver).CandidatePublicIdentity, messageContext, []byte(question), 1)
	if err != nil {
		t.Fatal("original ASK sealing failed")
	}
	key = nil // Recovery must load its own existing key from the retained root.
	base := "/v2/relay/nodes/" + url.PathEscape(f.nodeID)
	ask := fabric.NodeSameGroupSealedV1AskInput{GroupID: group, SourceEndpointID: peer.Sender.EndpointID, TargetEndpointID: peer.Receiver.EndpointID, MessageID: askID, RequestID: requestID, DataScope: store.SameGroupSealedV1DataScope, ExpiresAt: time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano), Ciphertext: ciphertext}
	originalASK := hash(ask)
	// Generic ListRelayInbox intentionally exposes only PLAINTEXT rows. Read
	// this exact sealed item's metadata through a separate read-only handle;
	// never change the production visibility filter to satisfy this oracle.
	uri := (&url.URL{Scheme: "file", Path: filepath.Join(f.root, "hub", "synthetic.sqlite3"), RawQuery: "mode=ro"}).String()
	readOnly, err := sql.Open("sqlite", uri)
	if err != nil {
		t.Fatal("closed Hub metadata reader unavailable")
	}
	defer readOnly.Close()
	type hubInboxMetadata struct {
		store.RelayInboxItem
		AttemptState string
	}
	readHubInbox := func() (*hubInboxMetadata, error) {
		var item hubInboxMetadata
		err := readOnly.QueryRowContext(context.Background(), `SELECT i.message_id,COALESCE(f.request_id,''),i.digest,i.recipient_endpoint_id,i.binding_id,i.binding_epoch,i.attempt_id,i.state,COALESCE(a.state,'')
FROM relay_v2_inbox i JOIN fabric_messages f ON f.id=i.message_id
LEFT JOIN relay_v2_delivery_attempts a ON a.attempt_id=i.attempt_id AND a.message_id=i.message_id
WHERE i.message_id=? AND i.recipient_endpoint_id=?`, askID, peer.Receiver.EndpointID).Scan(&item.MessageID, &item.RequestID, &item.Digest, &item.RecipientEndpointID, &item.BindingID, &item.BindingEpoch, &item.AttemptID, &item.State, &item.AttemptState)
		return &item, err
	}
	if _, err := readHubInbox(); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("closed Hub metadata reader preflight failed")
	}

	// Retain only closed route/status and lifecycle observations. The real
	// handler still receives each original request and response without edits.
	var observationMu sync.Mutex
	type httpFact struct {
		Route  string `json:"route"`
		Status int    `json:"status"`
	}
	var httpFacts []httpFact
	var lifecycle []string
	f.mu.Lock()
	actual := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		route := ""
		switch r.URL.Path {
		case base + "/sealed/claim":
			route = "SEALED_CLAIM"
		case base + "/group/sealed/claim":
			route = "GROUP_CLAIM"
		case "/v2/fabric/node/networks/direct/claim":
			route = "NETWORK_CLAIM"
		case base + "/claim":
			route = "PLAIN_CLAIM"
		default:
			if strings.HasPrefix(r.URL.Path, base+"/group/sealed/deliveries/") && strings.HasSuffix(r.URL.Path, "/authorization") {
				route = "GROUP_AUTHORIZATION"
			} else if strings.HasPrefix(r.URL.Path, base+"/") {
				route = "OTHER_RELAY"
			}
		}
		if route == "" {
			actual.ServeHTTP(w, r)
			return
		}
		recorder := httptest.NewRecorder()
		actual.ServeHTTP(recorder, r)
		observationMu.Lock()
		if len(httpFacts) < 32 {
			httpFacts = append(httpFacts, httpFact{route, recorder.Code})
		}
		observationMu.Unlock()
		for k, values := range recorder.Header() {
			w.Header()[k] = values
		}
		w.WriteHeader(recorder.Code)
		_, _ = w.Write(recorder.Body.Bytes())
	})
	f.mu.Unlock()
	var inbox *nodeinbox.Inbox
	var writerOutcome nodelock.NativeOutcomeState
	retiredChallenges := 0
	phase := "ORIGINAL_GRANTS"
	witness := func(err error) {
		t.Helper()
		fact := map[string]any{"phase": phase, "error_class": machineSealedPhaseError(err), "test_failed": t.Failed(), "request_sha256": hash(requestID), "message_sha256": hash(askID), "ask_sha256": originalASK, "identity_sha256": originalIdentity, "queue_calls": 0, "writer_outcome": writerOutcome, "retired_completed_challenges": retiredChallenges}
		if count, readErr := os.ReadFile(countPath); readErr == nil {
			fact["queue_calls"] = len(count)
		} else if !errors.Is(readErr, os.ErrNotExist) {
			fact["queue_calls"] = -1
		}
		if request, readErr := f.db.GetSameGroupSealedV1RequestStatus(fabric.HashSessionCredential(f.token), requestID); readErr == nil && request != nil {
			fact["hub_request"] = request.State
		}
		if item, readErr := readHubInbox(); readErr == nil {
			fact["hub_metadata_read"] = "AVAILABLE"
			fact["hub_inbox"] = item.State
			fact["hub_attempt"] = item.AttemptState
		} else if errors.Is(readErr, sql.ErrNoRows) {
			fact["hub_metadata_read"] = "NOT_FOUND"
		} else {
			fact["hub_metadata_read"] = "READ_ERROR"
		}
		if inbox != nil {
			if delivery, readErr := inbox.Get(context.Background(), askID); readErr == nil {
				fact["node_inbox"] = delivery.State
			}
		}
		if journal, readErr := openMachineRelayJournal(f.nodeRoot, f.nodeID); readErr == nil {
			fact["journal_present"] = journal.entry(askID) != nil
		}
		observationMu.Lock()
		fact["http"] = append([]httpFact(nil), httpFacts...)
		fact["lifecycle"] = append([]string(nil), lifecycle...)
		observationMu.Unlock()
		raw, _ := json.Marshal(fact)
		t.Log("COLD_ORIGINAL_ASK " + string(raw))
	}
	defer func() {
		witness(nil)
		if inbox != nil {
			_ = inbox.Close()
		}
	}()
	fail := func(err error) {
		t.Helper()
		witness(err)
		t.Fatalf("cold original ASK failed phase=%s error_class=%s", phase, machineSealedPhaseError(err))
	}
	witness(nil)

	phase = "OFFLINE_ASK"
	unlock()
	if err := f.bridge.Close(); err != nil {
		fail(err)
	}
	f.bridge = nil
	hubContext, _ := machineHubFrom(f.ctx)
	f.cancel()
	f.cancel = nil
	if err := f.history.Close(); err != nil {
		fail(err)
	}
	f.history = nil
	machineNodeControlClients.Delete(f.client.statePath)
	f.client = nil
	raw, err := json.Marshal(ask)
	if err != nil {
		fail(err)
	}
	f.http(t, http.MethodPost, base+"/group/sealed/ask", "CicadaNode "+f.token, "", raw, http.StatusAccepted)
	stored, err := f.db.GetRelaySealedV1(askID)
	if err != nil || stored == nil || !bytes.Equal(stored.Ciphertext, ciphertext) {
		fail(errors.New("offline original ciphertext not retained"))
	}
	if _, err := os.Stat(countPath); !errors.Is(err, os.ErrNotExist) {
		fail(errors.New("offline queue unexpectedly invoked"))
	}
	witness(nil)

	phase = "COLD_OPEN"
	if _, err := os.Stat(filepath.Join(f.nodeRoot, "native-context-history.sqlite3")); err != nil {
		fail(err)
	}
	f.history, err = nodeinbox.OpenNativeContextRegistry(filepath.Join(f.nodeRoot, "native-context-history.sqlite3"))
	if err != nil {
		fail(err)
	}
	hubContext.NativeContexts = f.history
	f.ctx, f.cancel = context.WithCancel(withMachineHubContext(context.Background(), hubContext))
	f.client, err = openMachineNodeControlClientMode(f.nodeRoot, f.server.URL, f.nodeID, true)
	if err != nil {
		fail(err)
	}
	f.bridge, err = startMachineAgentJoinBridge(f.ctx, f.nodeRoot, f.server.URL, f.nodeID, f.token)
	if err != nil {
		fail(err)
	}
	if identity() != originalIdentity {
		fail(errors.New("cold open changed original identity"))
	}
	witness(nil)

	phase = "FABRIC"
	inbox, err = nodeinbox.Open(machineNodeInboxPath(f.nodeRoot, f.nodeID))
	if err != nil {
		fail(err)
	}
	dependencies := machineNativeDeliveryDependencies(f.ctx)
	dependencies.observe = func(event string) {
		observationMu.Lock()
		defer observationMu.Unlock()
		if len(lifecycle) < 16 {
			lifecycle = append(lifecycle, event)
		}
	}
	ctx := context.WithValue(f.ctx, machineNativeDeliveryLifecycleKey{}, dependencies)
	if err := processPinnedTestMachineFabricDeliveries(ctx, f.server.URL, f.nodeID, inbox, f.nodeRoot); err != nil {
		fail(err)
	}
	witness(nil)

	phase = "EXACT_QUEUE"
	count, err := os.ReadFile(countPath)
	arguments, argsErr := os.ReadFile(argumentsPath)
	if err != nil || argsErr != nil || string(count) != "x" || !bytes.Contains(arguments, []byte("queue\n--thread\n"+f.native[1]+"\n--message\n")) || !bytes.Contains(arguments, []byte(question)) {
		fail(errors.New("exact original queue did not run once"))
	}
	delivery, err := inbox.Get(f.ctx, askID)
	if err != nil || delivery.State != nodeinbox.CONSUMPTION_UNCONFIRMED || delivery.Digest != stored.Security.Digest || delivery.SessionID != f.native[1] || delivery.BindingEpoch != registrations[1].Anchor.BindingEpoch {
		fail(errors.New("queued inbox changed original coordinates"))
	}
	item, err := readHubInbox()
	if err != nil || item.MessageID != askID || item.RequestID != requestID || item.Digest != delivery.Digest {
		fail(errors.New("Hub lost original correlation"))
	}
	op := nodelock.NativeOperation{HubID: f.hub.HubID, NodeID: f.nodeID, EndpointID: peer.Receiver.EndpointID, BindingID: item.BindingID, BindingEpoch: item.BindingEpoch, MessageID: askID, Digest: delivery.Digest, AttemptID: item.AttemptID}
	writerOutcome, err = machineNativeQueueOutcome(f.ctx, f.native[1], op)
	if err != nil || writerOutcome != nodelock.NativeQueueAccepted {
		fail(errors.New("original writer lacks durable acceptance"))
	}
	if identity() != originalIdentity || hash(ask) != originalASK {
		fail(errors.New("recovery replaced original identity or ASK"))
	}
	witness(nil)
	phase = "PROTECTED_ORIGINALS"
	f.client.mu.Lock()
	for id, intent := range originalState.LocalEndpointIntents {
		for stepID, step := range intent.Steps {
			recovered, present := f.client.state.LocalEndpointIntents[id].Steps[stepID]
			responseUnchanged := bytes.Equal(step.ResponsePacket, recovered.ResponsePacket)
			// Production may retire only the completed historical Prepare's
			// challenge response. Its original request and successful Complete
			// remain exact. This is not permission to replace any write receipt.
			retired := !responseUnchanged && len(recovered.ResponsePacket) == 0 && endpointGroupsRetirementMetadata(intent, step)
			if !present || step.Settled != recovered.Settled || !bytes.Equal(step.RequestPacket, recovered.RequestPacket) || (!responseUnchanged && !retired) {
				f.client.mu.Unlock()
				fail(errors.New("recovery replaced an original grant or registration receipt"))
			}
			if retired {
				retiredChallenges++
			}
		}
	}
	f.client.mu.Unlock()
	witness(nil)

	phase = "EXACT_RECHECK"
	if err := processPinnedTestMachineFabricDeliveries(ctx, f.server.URL, f.nodeID, inbox, f.nodeRoot); err != nil {
		fail(err)
	}
	count, err = os.ReadFile(countPath)
	if err != nil || string(count) != "x" {
		fail(errors.New("original delivery recheck duplicated queue"))
	}
	f.mu.Lock()
	askPosts := f.posts[base+"/group/sealed/ask"]
	f.mu.Unlock()
	if askPosts != 1 {
		fail(errors.New("original ASK was submitted more than once"))
	}
}
