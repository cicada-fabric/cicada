package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fabricpkg "github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestCausalBudgetIsPermanentHTTPConflictAcrossSealedRoutes(t *testing.T) {
	for name, write := range map[string]func(http.ResponseWriter, error){
		"Network Fabric":     networkV2Error,
		"same-Group":         relayNodeSameGroupSealedWriteError,
		"Communication Link": relayNodeSealedWriteError,
	} {
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			write(response, store.ErrRelayCausalBudget)
			if response.Code != http.StatusConflict {
				t.Fatalf("permanent ancestry budget status=%d, want 409", response.Code)
			}
			if response.Header().Get("Retry-After") != "" {
				t.Fatalf("permanent ancestry budget carried Retry-After: %q", response.Header().Get("Retry-After"))
			}
		})
	}
	response := httptest.NewRecorder()
	networkV2Error(response, fabricpkg.ErrConflict)
	if response.Code != http.StatusConflict {
		t.Fatalf("Fabric-mapped permanent conflict status=%d, want 409", response.Code)
	}
}

func TestCausalTemporaryAdmissionRemainsRetryable429(t *testing.T) {
	response := httptest.NewRecorder()
	networkV2Error(response, &store.RelayAdmissionError{Scope: "synthetic", Limit: 4,
		Pending: 4, RetryAfterSeconds: 9})
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "9" {
		t.Fatalf("temporary Relay capacity status=%d Retry-After=%q, want 429/9",
			response.Code, response.Header().Get("Retry-After"))
	}
	response = httptest.NewRecorder()
	networkV2Error(response, store.ErrNetworkBroadcastPending)
	if response.Code != http.StatusTooEarly || response.Header().Get("Retry-After") != "" {
		t.Fatalf("uncommitted metadata status=%d Retry-After=%q, want 425 without Retry-After",
			response.Code, response.Header().Get("Retry-After"))
	}
}

func TestSealedCausalParentAndCycleArePermanentHTTPConflict(t *testing.T) {
	for name, write := range map[string]func(http.ResponseWriter, error){"same-Group": relayNodeSameGroupSealedWriteError, "Communication Link": relayNodeSealedWriteError} {
		for label, err := range map[string]error{"parent": store.ErrRelayCausalParentInvalid, "cycle": store.ErrRelayCausalCycle, "budget": store.ErrRelayCausalBudget} {
			t.Run(name+"/"+label, func(t *testing.T) {
				response := httptest.NewRecorder()
				write(response, fmt.Errorf("wrapped: %w", err))
				if response.Code != http.StatusConflict || response.Header().Get("Retry-After") != "" {
					t.Fatalf("permanent failure mapped to %d/%q", response.Code, response.Header().Get("Retry-After"))
				}
			})
		}
	}
}

func TestSealedCausalTemporaryAdmissionRetainsRetryAfter(t *testing.T) {
	for name, write := range map[string]func(http.ResponseWriter, error){"same-Group": relayNodeSameGroupSealedWriteError, "Communication Link": relayNodeSealedWriteError} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRecorder()
			write(r, &store.RelayAdmissionError{Scope: "synthetic", Limit: 4, Pending: 4, RetryAfterSeconds: 9})
			if r.Code != http.StatusTooManyRequests || r.Header().Get("Retry-After") != "9" {
				t.Fatalf("temporary failure mapped to %d/%q", r.Code, r.Header().Get("Retry-After"))
			}
		})
	}
}

func TestSameGroupCausalProductionHTTP409WithoutAdmittedChild(t *testing.T) {
	f := newSameGroupSealedHTTPFixture(t)
	base := "/v2/relay/nodes/" + f.sourceNodeID + "/group/sealed/"
	reverseBase := "/v2/relay/nodes/" + f.targetNodeID + "/group/sealed/"
	peerFor := func(source, target, base, auth string) store.SameGroupSealedV1PeerKey {
		t.Helper()
		q := url.Values{"group_id": {f.groupID}, "source_endpoint_id": {source}, "target_endpoint_id": {target}}
		r := f.call(t, http.MethodGet, base+"peer-key?"+q.Encode(), auth, nil)
		if r.Code != http.StatusOK {
			t.Fatalf("peer %d %s", r.Code, r.Body.String())
		}
		var peer store.SameGroupSealedV1PeerKey
		if err := json.Unmarshal(r.Body.Bytes(), &peer); err != nil {
			t.Fatal(err)
		}
		return peer
	}
	peer := peerFor(f.sourceEndpoint.ID, f.targetEndpoint.ID, base, f.sourceNodeAuth)
	requestID, messageID := "http-causal-root", "http-causal-root-message"
	expires := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano)
	root := f.call(t, http.MethodPost, base+"ask", f.sourceNodeAuth, map[string]any{"group_id": f.groupID, "source_endpoint_id": f.sourceEndpoint.ID, "target_endpoint_id": f.targetEndpoint.ID, "message_id": messageID, "request_id": requestID, "idempotency_key": "http-causal-root-idem", "data_scope": store.SameGroupSealedV1DataScope, "expires_at": expires, "ciphertext": f.seal(t, peer, f.sourceKey, messageID, "REQUEST", requestID, "")})
	if root.Code != http.StatusAccepted {
		t.Fatalf("root %d %s", root.Code, root.Body.String())
	}
	reverse := peerFor(f.targetEndpoint.ID, f.sourceEndpoint.ID, reverseBase, f.targetNodeAuth)
	checkDenied := func(label, expectedError string) {
		t.Helper()
		childMessage, childRequest := "http-child-"+label, "http-request-"+label
		route := e2ee.EndpointMessageContext{MessageID: childMessage, Kind: "REQUEST", RequestID: childRequest, ParentRequestID: requestID, SenderEndpointID: reverse.Sender.EndpointID, SenderPrincipalID: reverse.Sender.PrincipalID, SenderOwnerID: reverse.Sender.OwnerID, SenderGroupID: reverse.Sender.GroupID, SenderMembershipRevision: reverse.Sender.MembershipRevision, SenderBindingEpoch: reverse.Sender.BindingEpoch, SenderKeyID: reverse.Sender.Candidate.KeyID, ReceiverEndpointID: reverse.Receiver.EndpointID, ReceiverPrincipalID: reverse.Receiver.PrincipalID, ReceiverOwnerID: reverse.Receiver.OwnerID, ReceiverGroupID: reverse.Receiver.GroupID, ReceiverMembershipRevision: reverse.Receiver.MembershipRevision, ReceiverBindingEpoch: reverse.Receiver.BindingEpoch, ReceiverKeyID: reverse.Receiver.Candidate.KeyID, TransportHubID: reverse.HubID}
		wire, err := e2ee.SealEndpointMessage(f.targetKey, reverse.Receiver.Candidate.Public, route, []byte("synthetic rejected causal body"), 1)
		if err != nil {
			t.Fatal(err)
		}
		statusBefore := f.call(t, http.MethodGet, base+"requests/"+requestID, f.sourceNodeAuth, nil).Body.String()
		response := f.call(t, http.MethodPost, reverseBase+"ask", f.targetNodeAuth, map[string]any{"group_id": f.groupID, "source_endpoint_id": f.targetEndpoint.ID, "target_endpoint_id": f.sourceEndpoint.ID, "message_id": childMessage, "request_id": childRequest, "parent_request_id": requestID, "idempotency_key": "http-child-idem-" + label, "data_scope": store.SameGroupSealedV1DataScope, "expires_at": expires, "ciphertext": wire})
		if response.Code != http.StatusConflict || response.Header().Get("Retry-After") != "" || !strings.Contains(response.Body.String(), expectedError) {
			t.Fatalf("causal %s mapped to %d/%q %s", label, response.Code, response.Header().Get("Retry-After"), response.Body.String())
		}
		statusAfter := f.call(t, http.MethodGet, base+"requests/"+requestID, f.sourceNodeAuth, nil).Body.String()
		if statusBefore != statusAfter {
			t.Fatal("denied child changed parent")
		}
		if record, err := f.persistence.GetRelayMessage(childMessage); record != nil || !errors.Is(err, store.ErrRelayMessageNotFound) {
			t.Fatalf("denied child persisted ciphertext: %#v %v", record, err)
		}
	}
	checkDenied("unreceived-parent", store.ErrRelayCausalParentInvalid.Error())
	claim := f.call(t, http.MethodPost, reverseBase+"claim", f.targetNodeAuth, map[string]any{"consumer_id": "causal-http-receiver", "limit": 1})
	var claimed struct {
		Deliveries []store.RelaySealedV1DeliveryAttempt `json:"deliveries"`
	}
	if claim.Code != http.StatusOK || json.Unmarshal(claim.Body.Bytes(), &claimed) != nil || len(claimed.Deliveries) != 1 {
		t.Fatalf("claim %d %s", claim.Code, claim.Body.String())
	}
	a := claimed.Deliveries[0]
	receipt := f.call(t, http.MethodPost, "/v2/relay/nodes/"+f.targetNodeID+"/receipts", f.targetNodeAuth, fabricpkg.NodeReceiptInput{AttemptID: a.AttemptID, MessageID: a.MessageID, Digest: a.Digest, EndpointID: a.RecipientEndpointID, BindingID: a.BindingID, BindingEpoch: a.BindingEpoch, Layer: store.RelayReceiptNodeReceived})
	if receipt.Code != http.StatusOK {
		t.Fatalf("receipt %d %s", receipt.Code, receipt.Body.String())
	}
	checkDenied("endpoint-cycle", store.ErrRelayCausalCycle.Error())
}
