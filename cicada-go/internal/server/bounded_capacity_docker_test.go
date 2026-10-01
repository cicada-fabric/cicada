package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

const (
	capacityEndpointCount = 64
	capacityConcurrent    = 16
	capacityDirectoryGets = 46
	capacityAsks          = store.DefaultRelayPendingAsksPerSenderEndpoint + 1
	capacityWorkloadSize  = capacityDirectoryGets + capacityAsks + 1 // plus one sealed SEND
)

type boundedCapacityJoin struct {
	Endpoint     store.Endpoint `json:"endpoint"`
	SessionToken string         `json:"session_token"`
}

type boundedCapacitySample struct {
	Operation  string        `json:"operation"`
	Status     int           `json:"status"`
	Elapsed    time.Duration `json:"-"`
	ElapsedMS  float64       `json:"elapsed_ms"`
	RetryAfter string        `json:"retry_after,omitempty"`
	Body       []byte        `json:"-"`
	Err        error         `json:"-"`
	RequestID  string        `json:"-"`
	MessageID  string        `json:"-"`
}

// TestHubBoundedCapacityDocker drives the real isolated Hub listener and its
// SQLite file. It is a small bounded contention sample, not a capacity claim.
func TestHubBoundedCapacityDocker(t *testing.T) {
	baseURL := strings.TrimRight(os.Getenv("CICADA_TEST_HUB_URL"), "/")
	dbPath := os.Getenv("CICADA_TEST_HUB_DB")
	managerToken := os.Getenv("CICADA_TEST_HUB_TOKEN")
	resultPath := os.Getenv("CICADA_CAPACITY_RESULT_PATH")
	if baseURL == "" || dbPath == "" || managerToken == "" || resultPath == "" {
		t.Skip("requires the isolated bounded-capacity Docker Hub fixture")
	}

	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		MaxIdleConns: capacityConcurrent, MaxIdleConnsPerHost: capacityConcurrent,
		MaxConnsPerHost: capacityConcurrent,
	}}
	defer client.CloseIdleConnections()

	call := func(ctx context.Context, method, path, authorization, groupScope string,
		body []byte) (int, http.Header, []byte, time.Duration, error) {
		started := time.Now()
		request, err := http.NewRequestWithContext(ctx, method, baseURL+path, bytes.NewReader(body))
		if err != nil {
			return 0, nil, nil, time.Since(started), err
		}
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		if groupScope != "" {
			request.Header.Set("Cicada-Group-Scope", groupScope)
		}
		if body != nil {
			request.Header.Set("Content-Type", "application/json")
		}
		response, err := client.Do(request)
		elapsed := time.Since(started)
		if err != nil {
			return 0, nil, nil, elapsed, err
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 512*1024+1))
		if err != nil || len(data) > 512*1024 {
			return response.StatusCode, response.Header.Clone(), nil, elapsed, fmt.Errorf("bounded response read failed")
		}
		return response.StatusCode, response.Header.Clone(), data, elapsed, nil
	}
	callJSON := func(method, path, authorization, groupScope string, value any) (int, http.Header, []byte) {
		t.Helper()
		var body []byte
		if value != nil {
			var err error
			body, err = json.Marshal(value)
			if err != nil {
				t.Fatal("encode synthetic capacity request")
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		status, headers, responseBody, _, err := call(ctx, method, path, authorization, groupScope, body)
		if err != nil {
			t.Fatal("synthetic setup HTTP request failed")
		}
		return status, headers, responseBody
	}
	managerAuth := "Bearer " + managerToken

	var owner e2ee.PublicIdentity
	status, _, body := callJSON(http.MethodGet, "/v1/identity", managerAuth, "", nil)
	if status != http.StatusOK || json.Unmarshal(body, &owner) != nil || owner.ID == "" {
		t.Fatal("could not establish synthetic Hub Owner identity")
	}
	status, _, body = callJSON(http.MethodGet, "/v2/client/identity", "", "", nil)
	var hubIdentity struct {
		HubID string `json:"hub_id"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &hubIdentity) != nil || hubIdentity.HubID == "" {
		t.Fatal("could not establish synthetic Hub identity")
	}
	status, _, body = callJSON(http.MethodPost, "/v1/groups", managerAuth, "",
		map[string]string{"name": "synthetic bounded capacity fixture"})
	var group store.Group
	if status != http.StatusCreated || json.Unmarshal(body, &group) != nil || group.ID == "" {
		t.Fatal("could not create synthetic Group through Hub API")
	}

	persistence, err := store.New(dbPath)
	if err != nil {
		t.Fatal("could not open only the disposable Hub SQLite state")
	}
	storeOpen := true
	defer func() {
		if storeOpen {
			_ = persistence.Close()
		}
	}()
	if err := persistence.EnsureLocalOwnerPrincipal(owner.ID); err != nil {
		t.Fatal("could not bind synthetic Owner identity to fixture state")
	}
	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("could not create synthetic Owner approval key")
	}
	ownerKey, err := persistence.RegisterOwnerApprovalKeyLocal(owner.ID, ownerIdentity.Public())
	if err != nil {
		t.Fatal("could not register synthetic Owner approval key")
	}
	deviceIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal("could not create synthetic Owner device key")
	}
	const deviceID = "synthetic-bounded-capacity-device"
	issuedAt := time.Now().UTC().Add(-time.Minute)
	deviceGrant, err := ownerIdentity.SignOwnerDeviceGrant(owner.ID, deviceID,
		deviceIdentity.Public(), hubIdentity.HubID, e2ee.OwnerDevicePurposeControl,
		issuedAt, issuedAt.Add(2*time.Hour))
	if err != nil {
		t.Fatal("could not sign synthetic Owner device grant")
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: owner.ID, OwnerKeyID: ownerKey.KeyID, DeviceID: deviceID,
		DevicePublic: deviceIdentity.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		t.Fatal("could not register synthetic Owner device")
	}
	limits, err := persistence.GetRelayAdmissionLimits()
	if err != nil || limits != store.DefaultRelayAdmissionLimits() {
		t.Fatal("fresh disposable Hub did not use its documented Relay admission defaults")
	}

	bindNode := func(nodeID string) string {
		t.Helper()
		nodeToken, digest, err := fabricpkg.NewNodeCredential()
		if err != nil {
			t.Fatal("could not create synthetic Node credential")
		}
		codeSum := sha256.Sum256([]byte("SYNTHETIC-TEST-ONLY:" + nodeID))
		codeDigest := hex.EncodeToString(codeSum[:])
		if _, err := persistence.CreatePendingNodeDeviceBinding(nodeID, nodeID,
			digest, codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
			t.Fatal("could not create synthetic Node binding")
		}
		if _, err := persistence.ConfirmPendingNodeDeviceBinding(owner.ID, deviceID, codeDigest); err != nil {
			t.Fatal("could not confirm synthetic Node binding")
		}
		return nodeToken
	}
	const sourceNodeID = "capacity_synthetic_source"
	const targetNodeID = "capacity_synthetic_target"
	sourceNodeToken := bindNode(sourceNodeID)
	targetNodeToken := bindNode(targetNodeID)

	joinEndpoint := func(nodeID, nodeToken string, ordinal int) boundedCapacityJoin {
		t.Helper()
		requestBody := map[string]any{
			"group_id": group.ID, "endpoint_name": fmt.Sprintf("synthetic-capacity-%03d", ordinal),
			"harness": "codex", "native_session_id": fmt.Sprintf("synthetic-capacity-native-%03d", ordinal),
			"workspace": "/tmp/cicada-synthetic-capacity",
		}
		status, _, body := callJSON(http.MethodPost, "/v2/fabric/node/join",
			"CicadaNode "+nodeToken, "", requestBody)
		var joined boundedCapacityJoin
		if status != http.StatusCreated || json.Unmarshal(body, &joined) != nil ||
			joined.Endpoint.ID == "" || joined.Endpoint.MachineID != nodeID || joined.SessionToken == "" {
			t.Fatalf("synthetic endpoint %d did not join through the Hub", ordinal)
		}
		return joined
	}
	var source, target boundedCapacityJoin
	for ordinal := 0; ordinal < capacityEndpointCount; ordinal++ {
		if ordinal%2 == 0 {
			joined := joinEndpoint(sourceNodeID, sourceNodeToken, ordinal)
			if ordinal == 0 {
				source = joined
			}
		} else {
			joined := joinEndpoint(targetNodeID, targetNodeToken, ordinal)
			if ordinal == 1 {
				target = joined
			}
		}
	}
	if source.Endpoint.ID == "" || target.Endpoint.ID == "" {
		t.Fatal("synthetic source/target Endpoint setup was incomplete")
	}
	sourceKey := addAndGrantSameGroupSealedTestEndpointKey(t, persistence,
		owner.ID, group.ID, ownerKey.KeyID, ownerIdentity, source.Endpoint)
	targetKey := addAndGrantSameGroupSealedTestEndpointKey(t, persistence,
		owner.ID, group.ID, ownerKey.KeyID, ownerIdentity, target.Endpoint)
	if err := persistence.Close(); err != nil {
		t.Fatal("could not close synthetic fixture Store before load")
	}
	storeOpen = false

	groupBase := "/v2/relay/nodes/" + sourceNodeID + "/group/sealed/"
	targetBase := "/v2/relay/nodes/" + targetNodeID + "/group/sealed/"
	peerQuery := func(sourceEndpoint, targetEndpoint string) string {
		values := url.Values{"group_id": {group.ID}, "source_endpoint_id": {sourceEndpoint},
			"target_endpoint_id": {targetEndpoint}}
		return "peer-key?" + values.Encode()
	}
	loadPeer := func(nodeToken, nodeID, sourceEndpoint, targetEndpoint string) store.SameGroupSealedV1PeerKey {
		t.Helper()
		path := "/v2/relay/nodes/" + nodeID + "/group/sealed/" + peerQuery(sourceEndpoint, targetEndpoint)
		status, _, responseBody := callJSON(http.MethodGet, path, "CicadaNode "+nodeToken, "", nil)
		var peer store.SameGroupSealedV1PeerKey
		if status != http.StatusOK || json.Unmarshal(responseBody, &peer) != nil ||
			peer.Sender.EndpointID != sourceEndpoint || peer.Receiver.EndpointID != targetEndpoint {
			t.Fatal("current synthetic sealed peer key route was unavailable")
		}
		return peer
	}
	peer := loadPeer(sourceNodeToken, sourceNodeID, source.Endpoint.ID, target.Endpoint.ID)
	makeCiphertext := func(sourceIdentity *e2ee.Identity, route store.SameGroupSealedV1PeerKey,
		messageID, kind, requestID, replyTo string) []byte {
		t.Helper()
		context := e2ee.EndpointMessageContext{
			MessageID: messageID, Kind: kind, RequestID: requestID, ReplyTo: replyTo,
			SenderEndpointID: route.Sender.EndpointID, SenderPrincipalID: route.Sender.PrincipalID,
			SenderOwnerID: route.Sender.OwnerID, SenderGroupID: route.Sender.GroupID,
			SenderMembershipRevision: route.Sender.MembershipRevision,
			SenderBindingEpoch:       route.Sender.BindingEpoch, SenderKeyID: route.Sender.Candidate.KeyID,
			ReceiverEndpointID: route.Receiver.EndpointID, ReceiverPrincipalID: route.Receiver.PrincipalID,
			ReceiverOwnerID: route.Receiver.OwnerID, ReceiverGroupID: route.Receiver.GroupID,
			ReceiverMembershipRevision: route.Receiver.MembershipRevision,
			ReceiverBindingEpoch:       route.Receiver.BindingEpoch, ReceiverKeyID: route.Receiver.Candidate.KeyID,
			TransportHubID: route.HubID,
		}
		wire, err := e2ee.SealEndpointMessage(sourceIdentity, route.Receiver.Candidate.Public,
			context, []byte("SYNTHETIC TEST ONLY: bounded Hub transport workload"), 1)
		if err != nil {
			t.Fatal("could not seal synthetic capacity traffic")
		}
		return wire
	}

	type askWork struct {
		requestID, messageID, idempotency string
		body                              []byte
	}
	type capacityTask struct {
		operation, method, path, auth, scope string
		body                                 []byte
		requestID, messageID                 string
	}
	tasks := make([]capacityTask, 0, capacityWorkloadSize)
	for index := 0; index < capacityDirectoryGets; index++ {
		tasks = append(tasks, capacityTask{operation: "directory_read", method: http.MethodGet,
			path: "/v2/fabric/members?limit=100",
			auth: "CicadaSession " + source.SessionToken, scope: group.ID})
	}
	askBodies := make([]askWork, capacityAsks)
	for index := 0; index < capacityAsks; index++ {
		messageID, requestID, idempotency := store.NewID("capacity_message"),
			store.NewID("capacity_request"), store.NewID("capacity_idem")
		ciphertext := makeCiphertext(sourceKey, peer, messageID, "REQUEST", requestID, "")
		encoded, err := json.Marshal(fabricpkg.NodeSameGroupSealedV1AskInput{
			GroupID: group.ID, SourceEndpointID: source.Endpoint.ID, TargetEndpointID: target.Endpoint.ID,
			MessageID: messageID, RequestID: requestID, IdempotencyKey: idempotency,
			DataScope: store.SameGroupSealedV1DataScope,
			ExpiresAt: time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano), Ciphertext: ciphertext,
		})
		if err != nil {
			t.Fatal("could not encode synthetic sealed ASK")
		}
		askBodies[index] = askWork{requestID: requestID, messageID: messageID,
			idempotency: idempotency, body: encoded}
		tasks = append(tasks, capacityTask{operation: "sealed_ask", method: http.MethodPost, path: groupBase + "ask",
			auth: "CicadaNode " + sourceNodeToken, body: encoded,
			requestID: requestID, messageID: messageID})
	}
	sendMessageID := store.NewID("capacity_send")
	sendCiphertext := makeCiphertext(sourceKey, peer, sendMessageID, "SEND", "", "")
	sendBody, err := json.Marshal(fabricpkg.NodeSameGroupSealedV1SendInput{
		GroupID: group.ID, SourceEndpointID: source.Endpoint.ID, TargetEndpointID: target.Endpoint.ID,
		MessageID: sendMessageID, IdempotencyKey: store.NewID("capacity_send_idem"),
		DataScope: store.SameGroupSealedV1DataScope, Ciphertext: sendCiphertext,
	})
	if err != nil {
		t.Fatal("could not encode synthetic sealed SEND")
	}
	tasks = append(tasks, capacityTask{operation: "sealed_send", method: http.MethodPost, path: groupBase + "send",
		auth: "CicadaNode " + sourceNodeToken, body: sendBody, messageID: sendMessageID})
	if len(tasks) != capacityWorkloadSize {
		t.Fatalf("bounded workload has %d requests, want %d", len(tasks), capacityWorkloadSize)
	}

	samples := make([]boundedCapacitySample, len(tasks))
	work := make(chan int, len(tasks))
	var current, observedMax int32
	var workers sync.WaitGroup
	for worker := 0; worker < capacityConcurrent; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range work {
				now := atomic.AddInt32(&current, 1)
				for max := atomic.LoadInt32(&observedMax); now > max &&
					!atomic.CompareAndSwapInt32(&observedMax, max, now); max = atomic.LoadInt32(&observedMax) {
				}
				task := tasks[index]
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				status, headers, responseBody, elapsed, callErr := call(ctx,
					task.method, task.path, task.auth, task.scope, task.body)
				cancel()
				samples[index] = boundedCapacitySample{
					Operation: task.operation, Status: status, Elapsed: elapsed,
					ElapsedMS:  float64(elapsed.Microseconds()) / 1000,
					RetryAfter: headers.Get("Retry-After"), Body: responseBody,
					Err: callErr, RequestID: task.requestID, MessageID: task.messageID,
				}
				atomic.AddInt32(&current, -1)
			}
		}()
	}
	for index := range tasks {
		work <- index
	}
	close(work)
	workers.Wait()

	statusCounts := map[string]int{}
	operationCounts := map[string]int{}
	latencies := make([]float64, 0, len(samples))
	acceptedAsks := make([]askWork, 0, store.DefaultRelayPendingAsksPerSenderEndpoint)
	var rejectedAsk *askWork
	rejectedAsks := 0
	var retryAfterSeconds int
	var errorsObserved int
	for index, sample := range samples {
		operationCounts[sample.Operation]++
		latencies = append(latencies, sample.ElapsedMS)
		if sample.Err != nil {
			errorsObserved++
			continue
		}
		statusCounts[strconv.Itoa(sample.Status)]++
		switch sample.Operation {
		case "directory_read":
			if sample.Status != http.StatusOK {
				continue
			}
			var listing struct {
				Endpoints []json.RawMessage `json:"endpoints"`
			}
			if json.Unmarshal(sample.Body, &listing) != nil || len(listing.Endpoints) != capacityEndpointCount {
				errorsObserved++
			}
		case "sealed_ask":
			if sample.Status == http.StatusAccepted {
				acceptedAsks = append(acceptedAsks, askBodies[index-capacityDirectoryGets])
			} else if sample.Status == http.StatusTooManyRequests {
				rejectedAsks++
				candidate := askBodies[index-capacityDirectoryGets]
				rejectedAsk = &candidate
				seconds, parseErr := strconv.Atoi(sample.RetryAfter)
				if parseErr != nil || seconds < 1 {
					errorsObserved++
				} else {
					retryAfterSeconds = seconds
				}
			} else {
				errorsObserved++
			}
		case "sealed_send":
			if sample.Status != http.StatusAccepted {
				errorsObserved++
			}
		}
	}
	sort.Float64s(latencies)
	percentile := func(p float64) float64 {
		if len(latencies) == 0 {
			return 0
		}
		index := int(math.Ceil(p*float64(len(latencies)))) - 1
		if index < 0 {
			index = 0
		}
		if index >= len(latencies) {
			index = len(latencies) - 1
		}
		return latencies[index]
	}
	loadResult := map[string]any{
		"scope": "REAL_TCP_DISPOSABLE_HUB", "synthetic": true,
		"native_runtime": "NATIVE_NOT_RUN", "endpoint_count": capacityEndpointCount,
		"logical_node_callers": 2, "planned_http_requests": capacityWorkloadSize,
		"configured_concurrency": capacityConcurrent, "observed_max_inflight": atomic.LoadInt32(&observedMax),
		"sample_count": len(samples), "status_distribution": statusCounts,
		"operation_counts":               operationCounts,
		"latency_ms":                     map[string]any{"p50": percentile(0.50), "p95": percentile(0.95)},
		"errors_or_bad_directory_counts": errorsObserved,
		"ask_admission": map[string]any{
			"default_sender_endpoint_limit": store.DefaultRelayPendingAsksPerSenderEndpoint,
			"accepted":                      len(acceptedAsks), "resource_exhausted": rejectedAsks,
			"retry_after_seconds": retryAfterSeconds,
		},
	}
	encodedResult, err := json.MarshalIndent(loadResult, "", "  ")
	if err != nil {
		t.Fatal("could not encode bounded capacity result")
	}
	if err := os.WriteFile(resultPath, append(encodedResult, '\n'), 0600); err != nil {
		t.Fatal("could not persist bounded capacity result")
	}
	if errorsObserved != 0 || len(acceptedAsks) != store.DefaultRelayPendingAsksPerSenderEndpoint ||
		rejectedAsk == nil || retryAfterSeconds < 1 || atomic.LoadInt32(&observedMax) < 2 ||
		atomic.LoadInt32(&observedMax) > capacityConcurrent {
		t.Fatalf("bounded load did not meet expected admission/HTTP envelope: errors=%d accepts=%d max_inflight=%d",
			errorsObserved, len(acceptedAsks), atomic.LoadInt32(&observedMax))
	}
	if statusCounts["200"] != capacityDirectoryGets || statusCounts["202"] != store.DefaultRelayPendingAsksPerSenderEndpoint+1 || statusCounts["429"] != 1 {
		t.Fatal("bounded load returned an unexpected HTTP status distribution")
	}

	// A cancellation request remains pending until the executor reports stop;
	// a completed reply frees one slot, after which the exact rejected Ask can
	// be retried. No peer body is stored in this report.
	cancelledAsk := acceptedAsks[0]
	status, _, body = callJSON(http.MethodPost, groupBase+"requests/"+cancelledAsk.requestID+"/cancel",
		"CicadaNode "+sourceNodeToken, "", map[string]any{})
	var cancelState struct {
		State string `json:"state"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &cancelState) != nil || cancelState.State != store.FabricRequestCancelRequested {
		t.Fatal("sealed Ask cancellation did not persist its pending state")
	}
	repliedAsk := acceptedAsks[1]
	reversePeer := loadPeer(targetNodeToken, targetNodeID, target.Endpoint.ID, source.Endpoint.ID)
	replyMessageID := store.NewID("capacity_reply")
	replyCiphertext := makeCiphertext(targetKey, reversePeer, replyMessageID,
		"REPLY", repliedAsk.requestID, repliedAsk.messageID)
	replyBody, err := json.Marshal(fabricpkg.NodeSameGroupSealedV1ReplyInput{
		RequestID: repliedAsk.requestID, MessageID: replyMessageID, Ciphertext: replyCiphertext,
	})
	if err != nil {
		t.Fatal("could not encode synthetic sealed REPLY")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	status, _, body, _, err = call(ctx, http.MethodPost, targetBase+"reply",
		"CicadaNode "+targetNodeToken, "", replyBody)
	cancel()
	var replyState struct {
		State string `json:"state"`
	}
	if err != nil || status != http.StatusAccepted || json.Unmarshal(body, &replyState) != nil || replyState.State != store.FabricRequestReplied {
		t.Fatal("sealed REPLY did not progress while the bounded Ask quota was full")
	}
	retry := *rejectedAsk
	ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
	status, _, body, _, err = call(ctx, http.MethodPost, groupBase+"ask",
		"CicadaNode "+sourceNodeToken, "", retry.body)
	cancel()
	var retriedState struct {
		State string `json:"state"`
	}
	if err != nil || status != http.StatusAccepted || json.Unmarshal(body, &retriedState) != nil || retriedState.State != store.FabricRequestOpen {
		t.Fatal("exact previously rejected ASK did not progress after REPLIED freed one slot")
	}

	recovery := map[string]any{
		"cancel_state": cancelState.State, "reply_state": replyState.State,
		"released_slot_exact_retry_state": retriedState.State,
		"http_calls_after_sample":         4, "model_or_native_calls": "NOT_RUN",
	}
	recoveryJSON, err := json.MarshalIndent(recovery, "", "  ")
	if err != nil {
		t.Fatal("could not encode bounded capacity recovery state")
	}
	if err := os.WriteFile(resultPath+".recovery.json", append(recoveryJSON, '\n'), 0600); err != nil {
		t.Fatal("could not persist bounded capacity recovery result")
	}
}
