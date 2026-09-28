package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

type networkDirectCurrentActor struct {
	NetworkID   string `json:"network_id"`
	EndpointID  string `json:"endpoint_id"`
	PrincipalID string `json:"principal_id"`
}

func (b *machineAgentJoinBridge) networkDirect(request localNetworkDirectRequest) (*localNetworkDirectResult, error) {
	if request.Version != localJoinProtocolVersion || request.NetworkID == "" || request.EndpointID == "" ||
		request.SessionToken == "" || request.NativeSessionID == "" || request.NodeID != b.nodeID ||
		request.Harness != "codex" || harness.Canonical(request.Harness) != "codex" ||
		!filepath.IsAbs(request.Workspace) || len(request.Workspace) > 4096 {
		return nil, errors.New("invalid Network direct native context")
	}
	if err := verifyCodexSessionRecord(request.NativeSessionID, request.Workspace); err != nil {
		return nil, err
	}
	actor, binding, err := b.verifyNetworkDirectSource(request)
	if err != nil {
		return nil, err
	}
	if request.Operation == "network_direct_publish_key" {
		return b.publishNetworkDirectKey(request, actor, binding)
	}
	if request.Operation != "network_direct_send" && request.Operation != "network_direct_ask" && request.Operation != "network_direct_reply" {
		return nil, errors.New("unsupported Network direct operation")
	}
	if request.OperationID == "" || request.IdempotencyKey == "" || request.Body == "" || len(request.Body) > 64*1024 {
		return nil, errors.New("incomplete Network direct operation")
	}
	messageID, generatedRequestID, err := localSealedRPCIDs(request.OperationID)
	if err != nil {
		return nil, err
	}
	if request.Operation == "network_direct_ask" && request.RequestID == "" {
		request.RequestID = generatedRequestID
	}
	var bundle *store.NetworkDirectPeerBundle
	var originalMessageID string
	if request.Operation == "network_direct_reply" {
		if request.RequestID == "" || request.TargetEndpointID != "" {
			return nil, errors.New("Network direct reply requires only the original request ID")
		}
		encoded, _ := json.Marshal(map[string]string{"network_id": request.NetworkID, "network_session_token": request.SessionToken, "request_id": request.RequestID})
		data, err := b.nodeHTTP(http.MethodPost, "/v2/fabric/node/networks/direct/reply-route", encoded)
		if err != nil {
			return nil, err
		}
		var route store.NetworkDirectReplyRoute
		if err := decodeStrictBridgeJSON(data, &route); err != nil || route.RequestID != request.RequestID || route.Bundle == nil {
			return nil, errors.New("Hub returned invalid Network direct reply route")
		}
		bundle = route.Bundle
		originalMessageID = route.RequestMessageID
		request.TargetEndpointID = bundle.Receiver.Manifest.EndpointID
	} else {
		if request.TargetEndpointID == "" || request.TargetEndpointID == request.EndpointID {
			return nil, errors.New("Network direct target is invalid")
		}
		bundle, err = b.fetchNetworkDirectPeerBundle(request, request.TargetEndpointID)
		if err != nil {
			return nil, err
		}
	}
	if bundle.NetworkID != request.NetworkID || bundle.HubID != strings.TrimSpace(os.Getenv("CICADA_HUB_ID")) ||
		bundle.Sender.Manifest.EndpointID != request.EndpointID || bundle.Receiver.Manifest.EndpointID != request.TargetEndpointID ||
		bundle.Sender.Manifest.BindingID != binding.ID || bundle.Sender.Manifest.BindingEpoch != binding.Epoch {
		return nil, errors.New("Network direct route does not match this native source")
	}
	kind := "SEND"
	if request.Operation == "network_direct_ask" {
		kind = "REQUEST"
	}
	if request.Operation == "network_direct_reply" {
		kind = "REPLY"
	}
	route := store.NetworkDirectContext(bundle, messageID, kind, request.RequestID, originalMessageID)
	ciphertext, err := b.sealNetworkDirect(request, bundle, route)
	if err != nil {
		return nil, err
	}
	switch request.Operation {
	case "network_direct_send":
		encoded, _ := json.Marshal(fabric.NetworkDirectSendInput{NetworkID: request.NetworkID, NetworkSessionToken: request.SessionToken,
			TargetEndpointID: request.TargetEndpointID, MessageID: messageID, IdempotencyKey: request.IdempotencyKey, Ciphertext: ciphertext})
		data, err := b.nodeHTTP(http.MethodPost, "/v2/fabric/node/networks/direct/send", encoded)
		if err != nil {
			return nil, err
		}
		var record store.RelaySealedV1Record
		if err := decodeStrictBridgeJSON(data, &record); err != nil || record.Route.MessageID != messageID {
			return nil, errors.New("Hub returned invalid Network direct SEND receipt")
		}
		return &localNetworkDirectResult{NetworkID: request.NetworkID, MessageID: messageID, TargetEndpointID: request.TargetEndpointID,
			State: "RELAY_PERSISTED", PayloadMode: store.RelayPayloadModeSealedV1}, nil
	case "network_direct_ask":
		if request.ExpiresAt == "" {
			return nil, errors.New("Network direct ASK requires its persisted deadline")
		}
		encoded, _ := json.Marshal(fabric.NetworkDirectAskInput{NetworkID: request.NetworkID, NetworkSessionToken: request.SessionToken,
			TargetEndpointID: request.TargetEndpointID, MessageID: messageID, RequestID: request.RequestID,
			IdempotencyKey: request.IdempotencyKey, ExpiresAt: request.ExpiresAt, Ciphertext: ciphertext})
		data, err := b.nodeHTTP(http.MethodPost, "/v2/fabric/node/networks/direct/ask", encoded)
		if err != nil {
			return nil, err
		}
		var status store.FabricRequest
		if err := decodeStrictBridgeJSON(data, &status); err != nil || status.RequestID != request.RequestID {
			return nil, errors.New("Hub returned invalid Network direct ASK receipt")
		}
		return &localNetworkDirectResult{NetworkID: request.NetworkID, MessageID: messageID, RequestID: request.RequestID,
			TargetEndpointID: request.TargetEndpointID, State: status.State, PayloadMode: store.RelayPayloadModeSealedV1}, nil
	default:
		encoded, _ := json.Marshal(fabric.NetworkDirectReplyInput{NetworkID: request.NetworkID, NetworkSessionToken: request.SessionToken,
			RequestID: request.RequestID, MessageID: messageID, IdempotencyKey: request.IdempotencyKey, Ciphertext: ciphertext})
		data, err := b.nodeHTTP(http.MethodPost, "/v2/fabric/node/networks/direct/reply", encoded)
		if err != nil {
			return nil, err
		}
		var status store.FabricRequest
		if err := decodeStrictBridgeJSON(data, &status); err != nil || status.ReplyMessageID != messageID {
			return nil, errors.New("Hub returned invalid Network direct REPLY receipt")
		}
		return &localNetworkDirectResult{NetworkID: request.NetworkID, MessageID: messageID, RequestID: request.RequestID,
			TargetEndpointID: request.TargetEndpointID, State: status.State, PayloadMode: store.RelayPayloadModeSealedV1}, nil
	}
}

func (b *machineAgentJoinBridge) verifyNetworkDirectSource(request localNetworkDirectRequest) (networkDirectCurrentActor, *store.NetworkDirectNativeBinding, error) {
	path := "/v2/fabric/networks/" + urlPath(request.NetworkID)
	data, err := b.httpWithAuthorization(http.MethodGet, path+"/whoami", nil, "Cicada-Network-Session "+request.SessionToken, "")
	if err != nil {
		return networkDirectCurrentActor{}, nil, err
	}
	var actor networkDirectCurrentActor
	if err := decodeStrictBridgeJSON(data, &actor); err != nil || actor.NetworkID != request.NetworkID || actor.EndpointID != request.EndpointID || actor.PrincipalID == "" {
		return networkDirectCurrentActor{}, nil, errors.New("Network session does not match its trusted Endpoint")
	}
	data, err = b.httpWithAuthorization(http.MethodPost, path+"/direct/native-binding", []byte(`{}`), "Cicada-Network-Session "+request.SessionToken, "")
	if err != nil {
		return networkDirectCurrentActor{}, nil, err
	}
	var binding store.NetworkDirectNativeBinding
	if err := decodeStrictBridgeJSON(data, &binding); err != nil || binding.EndpointID != request.EndpointID ||
		binding.PrincipalID != actor.PrincipalID || binding.NodeID != b.nodeID ||
		binding.NativeSessionID != request.NativeSessionID || binding.Status != "active" || binding.Epoch == 0 {
		return networkDirectCurrentActor{}, nil, errors.New("Network direct native binding does not match this original Thread")
	}
	return actor, &binding, nil
}

func (b *machineAgentJoinBridge) publishNetworkDirectKey(request localNetworkDirectRequest,
	actor networkDirectCurrentActor, binding *store.NetworkDirectNativeBinding) (*localNetworkDirectResult, error) {
	hubID := strings.TrimSpace(os.Getenv("CICADA_HUB_ID"))
	if hubID == "" {
		return nil, errors.New("CICADA_HUB_ID must be pinned before Network direct key publication")
	}
	identity, err := nodekeys.LoadOrCreate(machineNodeStateDir(b.stateDir, b.nodeID), request.EndpointID)
	if err != nil {
		return nil, err
	}
	attestation, err := identity.SignNetworkDirectKeyAttestation(hubID, request.NetworkID, request.EndpointID,
		actor.PrincipalID, b.nodeID, binding.ID, binding.Epoch)
	if err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(map[string][]byte{"attestation": attestation})
	data, err := b.httpWithAuthorization(http.MethodPost, "/v2/fabric/networks/"+urlPath(request.NetworkID)+"/direct/key-candidate",
		encoded, "Cicada-Network-Session "+request.SessionToken, "")
	if err != nil {
		return nil, err
	}
	var candidate store.NetworkDirectKeyCandidate
	if err := decodeStrictBridgeJSON(data, &candidate); err != nil || candidate.EndpointID != request.EndpointID ||
		candidate.NetworkID != request.NetworkID || candidate.Public.ID != identity.Public().ID {
		return nil, errors.New("Hub returned invalid Network direct key candidate")
	}
	return &localNetworkDirectResult{NetworkID: request.NetworkID, State: "CANDIDATE_PUBLISHED",
		KeyFingerprint: candidate.Fingerprint}, nil
}

func (b *machineAgentJoinBridge) fetchNetworkDirectPeerBundle(request localNetworkDirectRequest,
	targetEndpointID string) (*store.NetworkDirectPeerBundle, error) {
	encoded, _ := json.Marshal(map[string]string{"target_endpoint_id": targetEndpointID})
	data, err := b.httpWithAuthorization(http.MethodPost, "/v2/fabric/networks/"+urlPath(request.NetworkID)+"/direct/peer-key",
		encoded, "Cicada-Network-Session "+request.SessionToken, "")
	if err != nil {
		return nil, err
	}
	var bundle store.NetworkDirectPeerBundle
	if err := decodeStrictBridgeJSON(data, &bundle); err != nil || bundle.NetworkID != request.NetworkID ||
		bundle.HubID != strings.TrimSpace(os.Getenv("CICADA_HUB_ID")) ||
		bundle.Sender.Manifest.EndpointID != request.EndpointID || bundle.Receiver.Manifest.EndpointID != targetEndpointID {
		return nil, errors.New("Hub returned invalid Network direct peer evidence")
	}
	return &bundle, nil
}

func networkDirectEvidence(side store.NetworkDirectPeerKeyEvidence) (nodekeys.NetworkDirectEvidence, error) {
	manifest := side.Manifest
	digest, err := manifest.CanonicalDigest()
	if err != nil || digest != manifest.Digest || side.Grant.ManifestDigest != digest || side.Grant.State != "active" {
		return nodekeys.NetworkDirectEvidence{}, errors.New("Network direct manifest digest or grant is invalid")
	}
	canonical, err := manifest.CanonicalClaims()
	if err != nil {
		return nodekeys.NetworkDirectEvidence{}, err
	}
	acceptedAt, err := time.Parse(time.RFC3339Nano, side.Grant.AcceptedAt)
	if err != nil {
		return nodekeys.NetworkDirectEvidence{}, err
	}
	return nodekeys.NetworkDirectEvidence{ManifestCanonical: canonical,
		ExpectedAttestation: e2ee.NetworkDirectKeyAttestation{Version: 1, HubID: manifest.HubID,
			NetworkID: manifest.NetworkID, EndpointID: manifest.EndpointID, PrincipalID: manifest.PrincipalID,
			NodeID: manifest.NodeID, BindingID: manifest.BindingID, BindingEpoch: manifest.BindingEpoch,
			Public: manifest.Candidate.Public}, Attestation: manifest.Candidate.Attestation,
		ExpectedGrant: e2ee.OwnerNetworkDirectKeyGrant{Version: 1, HubID: manifest.HubID, NetworkID: manifest.NetworkID,
			EndpointID: manifest.EndpointID, OwnerID: manifest.OwnerID, OwnerKeyID: side.Grant.OwnerKeyID,
			ManifestDigest: digest}, GrantProof: side.GrantProof, AcceptedAt: acceptedAt, OwnerPublic: side.OwnerPublic}, nil
}

func (b *machineAgentJoinBridge) sealNetworkDirect(request localNetworkDirectRequest,
	bundle *store.NetworkDirectPeerBundle, route e2ee.NetworkDirectContext) ([]byte, error) {
	identity, err := nodekeys.LoadOrCreate(machineNodeStateDir(b.stateDir, b.nodeID), request.EndpointID)
	if err != nil {
		return nil, err
	}
	if identity.Public().ID != bundle.Sender.Manifest.Candidate.Public.ID {
		return nil, errors.New("Network direct local key differs from Owner-approved candidate")
	}
	if bundle.Sender.Manifest.NodeID != b.nodeID ||
		bundle.Sender.Manifest.NativeSessionDigest != e2ee.NetworkDirectNativeSessionDigest(request.NativeSessionID) {
		return nil, errors.New("Owner-approved Network direct source differs from this verified native Thread")
	}
	state, err := nodekeys.OpenCryptoState(machineNodeStateDir(b.stateDir, b.nodeID))
	if err != nil {
		return nil, err
	}
	defer state.Close()
	sender, err := networkDirectEvidence(bundle.Sender)
	if err != nil {
		return nil, err
	}
	receiver, err := networkDirectEvidence(bundle.Receiver)
	if err != nil {
		return nil, err
	}
	opID, err := nodekeys.NetworkDirectOperationID(route, []byte(request.Body))
	if err != nil {
		return nil, err
	}
	sealed, err := state.SealOutboundNetworkDirectMessage(b.ctx, identity, route, sender, receiver, opID, []byte(request.Body))
	if err != nil {
		return nil, fmt.Errorf("seal Network direct message: %w", err)
	}
	if len(sealed.Envelope) == 0 || bytes.Equal(sealed.Envelope, []byte(request.Body)) {
		return nil, errors.New("Network direct ciphertext is unavailable")
	}
	return sealed.Envelope, nil
}
