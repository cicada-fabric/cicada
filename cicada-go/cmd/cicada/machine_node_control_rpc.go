package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

const (
	machineNodeControlStateVersion  = 1
	maxMachineNodeControlStateBytes = 8 << 20
)

type machineNodeControlHubIdentity struct {
	Version        int                 `json:"version"`
	Algorithm      string              `json:"algorithm"`
	HubID          string              `json:"hub_id"`
	KeyID          string              `json:"key_id"`
	KeyVersion     uint64              `json:"key_version"`
	Fingerprint    string              `json:"fingerprint"`
	PublicIdentity e2ee.PublicIdentity `json:"public_identity"`
}

type machineNodeControlCandidate struct {
	RequestID                 string `json:"request_id"`
	Version                   int64  `json:"version"`
	Mode                      string `json:"mode"`
	HubID                     string `json:"hub_id"`
	NodeID                    string `json:"node_id"`
	NodeName                  string `json:"node_name"`
	NodeKeyID                 string `json:"node_key_id"`
	NodeKeyFingerprint        string `json:"node_key_fingerprint"`
	HubNodeControlKeyID       string `json:"hub_node_control_key_id"`
	HubNodeControlKeyVersion  uint64 `json:"hub_node_control_key_version"`
	HubNodeControlFingerprint string `json:"hub_node_control_fingerprint"`
	NodeKeyEpoch              uint64 `json:"node_key_epoch"`
	CandidateDigest           string `json:"candidate_digest"`
	State                     string `json:"state"`
	ExpiresAt                 string `json:"expires_at"`
	BindingID                 string `json:"binding_id,omitempty"`
	BindingVersion            uint64 `json:"binding_version,omitempty"`
}

type machineNodeControlPairingReply struct {
	UserCode        string                      `json:"user_code"`
	VerificationURI string                      `json:"verification_uri"`
	Candidate       machineNodeControlCandidate `json:"candidate"`
}

type machineNodeControlPairingStatus struct {
	RequestID                 string `json:"request_id"`
	Version                   int64  `json:"version"`
	Mode                      string `json:"mode"`
	HubID                     string `json:"hub_id"`
	NodeID                    string `json:"node_id"`
	NodeName                  string `json:"node_name"`
	NodeKeyID                 string `json:"node_key_id"`
	NodeKeyFingerprint        string `json:"node_key_fingerprint"`
	HubNodeControlKeyID       string `json:"hub_node_control_key_id"`
	HubNodeControlKeyVersion  uint64 `json:"hub_node_control_key_version"`
	HubNodeControlFingerprint string `json:"hub_node_control_fingerprint"`
	NodeKeyEpoch              uint64 `json:"node_key_epoch"`
	CandidateDigest           string `json:"candidate_digest"`
	State                     string `json:"state"`
	ExpiresAt                 string `json:"expires_at"`
	BindingID                 string `json:"binding_id"`
	BindingVersion            uint64 `json:"binding_version"`
}

type machineNodeControlPairingInput struct {
	NodeID             string              `json:"node_id"`
	NodeName           string              `json:"node_name"`
	CredentialDigest   string              `json:"credential_digest,omitempty"`
	RequestNonce       []byte              `json:"request_nonce"`
	NodePublicIdentity e2ee.PublicIdentity `json:"node_public_identity"`
	NodeFingerprint    string              `json:"node_fingerprint"`
	ProofPacket        []byte              `json:"proof_packet"`
	HubID              string              `json:"hub_id"`
	HubPublicIdentity  e2ee.PublicIdentity `json:"hub_public_identity"`
	HubKeyVersion      uint64              `json:"hub_key_version"`
	HubFingerprint     string              `json:"hub_fingerprint"`
}

type machineNodeControlState struct {
	Version                 int                            `json:"version"`
	NodeID                  string                         `json:"node_id"`
	HubOrigin               string                         `json:"hub_origin"`
	HubCandidateID          string                         `json:"hub_candidate_id,omitempty"`
	HubCandidateFingerprint string                         `json:"hub_candidate_fingerprint,omitempty"`
	HubCandidateVersion     uint64                         `json:"hub_candidate_version,omitempty"`
	HubCandidateIdentity    e2ee.PublicIdentity            `json:"hub_candidate_identity,omitempty"`
	PendingPairingUserCode  string                         `json:"pending_pairing_user_code,omitempty"`
	PendingPairingURI       string                         `json:"pending_pairing_uri,omitempty"`
	HubID                   string                         `json:"hub_id,omitempty"`
	HubKeyID                string                         `json:"hub_key_id,omitempty"`
	HubFingerprint          string                         `json:"hub_fingerprint,omitempty"`
	HubKeyVersion           uint64                         `json:"hub_key_version,omitempty"`
	HubPublicIdentity       e2ee.PublicIdentity            `json:"hub_public_identity,omitempty"`
	NodeKeyID               string                         `json:"node_key_id,omitempty"`
	NodeKeyFingerprint      string                         `json:"node_key_fingerprint,omitempty"`
	NodeKeyVersion          uint64                         `json:"node_key_version,omitempty"`
	BindingID               string                         `json:"binding_id,omitempty"`
	BindingVersion          uint64                         `json:"binding_version,omitempty"`
	NodeKeyEpoch            uint64                         `json:"node_key_epoch,omitempty"`
	ApprovedRequestID       string                         `json:"approved_request_id,omitempty"`
	ApprovedRequestVersion  int64                          `json:"approved_request_version,omitempty"`
	ApprovedCandidateDigest string                         `json:"approved_candidate_digest,omitempty"`
	PendingPairing          *machineNodeControlCandidate   `json:"pending_pairing,omitempty"`
	Sequence                uint64                         `json:"sequence"`
	PendingOperationID      string                         `json:"pending_operation_id,omitempty"`
	PendingOperation        string                         `json:"pending_operation,omitempty"`
	PendingSequence         uint64                         `json:"pending_sequence,omitempty"`
	PendingPlaintextDigest  string                         `json:"pending_plaintext_digest,omitempty"`
	PendingPacket           []byte                         `json:"pending_packet,omitempty"`
	PendingResponsePacket   []byte                         `json:"pending_response_packet,omitempty"`
	PendingWorkerID         string                         `json:"pending_worker_id,omitempty"`
	PendingWorkerAttempt    int                            `json:"pending_worker_attempt,omitempty"`
	PendingSnapshotPath     string                         `json:"pending_snapshot_path,omitempty"`
	PendingSnapshotManifest *nodewire.SnapshotManifest     `json:"pending_snapshot_manifest,omitempty"`
	ClaimTicket             *machineNodeControlClaimTicket `json:"claim_ticket,omitempty"`
}

// ClaimTicket retains only the Hub's sealed response. The plaintext job is
// decoded in memory after restart; an EXECUTING ticket is never redispatched.
type machineNodeControlClaimTicket struct {
	Version                 int    `json:"version"`
	ResponsePacket          []byte `json:"response_packet"`
	WorkerID                string `json:"worker_id"`
	Attempt                 int    `json:"attempt"`
	Phase                   string `json:"phase"`
	ClaimOperationID        string `json:"claim_operation_id"`
	ClaimSequence           uint64 `json:"claim_sequence"`
	BindingID               string `json:"binding_id"`
	BindingVersion          uint64 `json:"binding_version"`
	NodeKeyEpoch            uint64 `json:"node_key_epoch"`
	ExecutionID             string `json:"execution_id"`
	ProviderID              string `json:"provider_id"`
	ProviderAttempt         int    `json:"provider_attempt,omitempty"`
	ProviderAdmissionIntent string `json:"provider_admission_intent,omitempty"`
	ResourceID              string `json:"resource_id,omitempty"`
	LeaseID                 string `json:"lease_id"`
	FencingEpoch            int64  `json:"fencing_epoch,omitempty"`
}

const (
	machineNodeControlLegacyClaimTicketVersion = 1
	machineNodeControlClaimTicketVersion       = 2
)

type machineNodeControlClient struct {
	mu                 sync.Mutex
	stateDir           string
	statePath          string
	base               string
	nodeID             string
	identity           *e2ee.Identity
	state              machineNodeControlState
	snapshotTransferMu sync.Mutex
}

var machineNodeControlClients sync.Map // map[statePath]*machineNodeControlClient

func machineNodeControlPaths(stateDir, nodeID string) (string, string) {
	directory := machineNodeStateDir(stateDir, nodeID)
	return filepath.Join(directory, "node-control-identity.bin"), filepath.Join(directory, "node-control-state.json")
}

func openMachineNodeControlClient(stateDir, base, nodeID string) (*machineNodeControlClient, error) {
	identityPath, statePath := machineNodeControlPaths(stateDir, nodeID)
	if cached, ok := machineNodeControlClients.Load(statePath); ok {
		client := cached.(*machineNodeControlClient)
		if client.base != strings.TrimRight(base, "/") || client.nodeID != nodeID {
			return nil, errors.New("Node-Control state is already bound to another Hub context")
		}
		return client, nil
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(filepath.Dir(statePath), 0o700); err != nil {
		return nil, err
	}
	identityData, err := os.ReadFile(identityPath)
	var identity *e2ee.Identity
	if err == nil {
		if err := protectNodeControlLocalFile(identityPath); err != nil {
			return nil, err
		}
		identity, err = e2ee.UnmarshalIdentity(identityData)
		if err != nil {
			return nil, fmt.Errorf("load Node-Control private identity: %w", err)
		}
	} else if errors.Is(err, os.ErrNotExist) {
		identity, err = e2ee.NewIdentity()
		if err != nil {
			return nil, err
		}
		identityData, err = identity.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if err := persistNodeSecretFile(identityPath, identityData, ".node-control-key-*"); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("read Node-Control private identity: %w", err)
	}
	client := &machineNodeControlClient{stateDir: stateDir, statePath: statePath,
		base: strings.TrimRight(base, "/"), nodeID: nodeID, identity: identity,
		state: machineNodeControlState{Version: machineNodeControlStateVersion,
			NodeID: nodeID, HubOrigin: strings.TrimRight(base, "/")}}
	data, err := os.ReadFile(statePath)
	if err == nil {
		if err := protectNodeControlLocalFile(statePath); err != nil {
			return nil, err
		}
		if len(data) == 0 || len(data) > maxMachineNodeControlStateBytes {
			return nil, errors.New("Node-Control local state exceeds its bounded size")
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&client.state); err != nil {
			return nil, fmt.Errorf("decode Node-Control local state: %w", err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, errors.New("Node-Control local state contains trailing data")
		}
		if client.state.Version != machineNodeControlStateVersion || client.state.NodeID != nodeID ||
			client.state.HubOrigin != strings.TrimRight(base, "/") {
			return nil, errors.New("Node-Control local state does not match this Node and Hub")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read Node-Control local state: %w", err)
	} else if err := client.persistLocked(); err != nil {
		return nil, err
	}
	public := identity.Public()
	if client.state.NodeKeyID != "" && (client.state.NodeKeyID != public.ID ||
		client.state.NodeKeyFingerprint != nodewire.IdentityFingerprint(public)) {
		return nil, errors.New("Node-Control private key does not match the approved local key pin")
	}
	actual, loaded := machineNodeControlClients.LoadOrStore(statePath, client)
	if loaded {
		other := actual.(*machineNodeControlClient)
		if other.base != client.base || other.nodeID != nodeID {
			return nil, errors.New("Node-Control state is already bound to another Hub context")
		}
		return other, nil
	}
	return client, nil
}

func protectNodeControlLocalFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("Node-Control state file must be a regular non-symlink")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	return nil
}

func (client *machineNodeControlClient) persistLocked() error {
	data, err := json.Marshal(client.state)
	if err != nil {
		return err
	}
	if len(data)+1 > maxMachineNodeControlStateBytes {
		return errors.New("Node-Control local state exceeds its bounded size")
	}
	return persistNodeSecretFile(client.statePath, append(data, '\n'), ".node-control-state-*")
}

func (client *machineNodeControlClient) publicIdentity() e2ee.PublicIdentity {
	return client.identity.Public()
}

func (client *machineNodeControlClient) bindingReady() bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	return client.state.BindingID != "" && client.state.BindingVersion > 0 &&
		client.state.NodeKeyEpoch > 0 && client.state.HubKeyID != "" && client.state.HubKeyVersion > 0
}

func (client *machineNodeControlClient) approvedBinding() nodewire.Binding {
	client.mu.Lock()
	defer client.mu.Unlock()
	return nodewire.Binding{HubID: client.state.HubID, NodeID: client.nodeID,
		BindingID: client.state.BindingID, BindingVersion: client.state.BindingVersion,
		NodeKeyEpoch: client.state.NodeKeyEpoch, NodeKeyVersion: client.state.NodeKeyVersion,
		HubKeyVersion: client.state.HubKeyVersion, NodeKey: client.identity.Public(),
		HubKey: client.state.HubPublicIdentity}
}

func (client *machineNodeControlClient) pinHubCandidate(hub machineNodeControlHubIdentity) error {
	if hub.Version != nodewire.Version || hub.Algorithm != e2ee.Algorithm || hub.HubID == "" ||
		hub.KeyID != hub.PublicIdentity.ID || hub.KeyVersion == 0 ||
		e2ee.ValidatePublicIdentity(hub.PublicIdentity) != nil ||
		hub.Fingerprint != nodewire.IdentityFingerprint(hub.PublicIdentity) {
		return errors.New("Hub returned an invalid Node-Control identity candidate")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state.HubID != "" && (client.state.HubID != hub.HubID || client.state.HubKeyID != hub.KeyID ||
		client.state.HubFingerprint != hub.Fingerprint || client.state.HubKeyVersion != hub.KeyVersion ||
		!sameMachineNodeControlPublicIdentity(client.state.HubPublicIdentity, hub.PublicIdentity)) {
		return errors.New("Hub Node-Control key changed; refusing an unapproved pin replacement")
	}
	if client.state.HubCandidateID != "" && (client.state.HubCandidateID != hub.KeyID ||
		client.state.HubCandidateFingerprint != hub.Fingerprint || client.state.HubCandidateVersion != hub.KeyVersion ||
		!sameMachineNodeControlPublicIdentity(client.state.HubCandidateIdentity, hub.PublicIdentity)) {
		return errors.New("pending Hub Node-Control key candidate changed; refusing silent trust-on-first-use")
	}
	previous := cloneMachineNodeControlState(client.state)
	client.state.HubCandidateID, client.state.HubCandidateFingerprint = hub.KeyID, hub.Fingerprint
	client.state.HubCandidateVersion, client.state.HubCandidateIdentity = hub.KeyVersion, hub.PublicIdentity
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

// cloneMachineNodeControlState gives persistence rollbacks an independent
// snapshot of pointer- and slice-backed fields, including the sealed claim
// ticket. A shallow copy can retain the same ClaimTicket pointer and leak a
// fence mutation through a failed durable write.
func cloneMachineNodeControlState(state machineNodeControlState) machineNodeControlState {
	clonePublicIdentity := func(identity e2ee.PublicIdentity) e2ee.PublicIdentity {
		identity.KEMPublic = append([]byte(nil), identity.KEMPublic...)
		identity.SigningPublic = append([]byte(nil), identity.SigningPublic...)
		return identity
	}
	cloneBytes := func(value []byte) []byte {
		if value == nil {
			return nil
		}
		return append([]byte(nil), value...)
	}
	state.HubCandidateIdentity = clonePublicIdentity(state.HubCandidateIdentity)
	state.HubPublicIdentity = clonePublicIdentity(state.HubPublicIdentity)
	state.PendingPacket = cloneBytes(state.PendingPacket)
	state.PendingResponsePacket = cloneBytes(state.PendingResponsePacket)
	if state.PendingSnapshotManifest != nil {
		manifest := *state.PendingSnapshotManifest
		state.PendingSnapshotManifest = &manifest
	}
	if state.PendingPairing != nil {
		candidate := *state.PendingPairing
		state.PendingPairing = &candidate
	}
	if state.ClaimTicket != nil {
		ticket := *state.ClaimTicket
		ticket.ResponsePacket = cloneBytes(ticket.ResponsePacket)
		state.ClaimTicket = &ticket
	}
	return state
}

func sameMachineNodeControlPublicIdentity(left, right e2ee.PublicIdentity) bool {
	return left.ID == right.ID && bytes.Equal(left.KEMPublic, right.KEMPublic) &&
		bytes.Equal(left.SigningPublic, right.SigningPublic)
}

func (client *machineNodeControlClient) installApprovedBinding(status machineNodeControlPairingStatus,
	requestID string, candidate machineNodeControlCandidate, hub machineNodeControlHubIdentity) error {
	public := client.identity.Public()
	if status.State != "CONFIRMED" || status.RequestID != requestID ||
		status.NodeID != client.nodeID || status.NodeName != candidate.NodeName || status.HubID != hub.HubID ||
		status.NodeKeyID != public.ID || status.NodeKeyFingerprint != nodewire.IdentityFingerprint(public) ||
		status.HubNodeControlKeyID != hub.KeyID || status.HubNodeControlFingerprint != hub.Fingerprint ||
		status.HubNodeControlKeyVersion != hub.KeyVersion || status.NodeKeyEpoch == 0 ||
		status.BindingID == "" || status.BindingVersion == 0 ||
		status.CandidateDigest != candidate.CandidateDigest || status.Version != candidate.Version ||
		status.Mode != candidate.Mode || status.ExpiresAt != candidate.ExpiresAt {
		return errors.New("Owner approval does not match the immutable Node/Hub key candidate")
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state.HubID != "" && (client.state.HubID != hub.HubID || client.state.HubKeyID != hub.KeyID ||
		client.state.HubFingerprint != hub.Fingerprint || client.state.HubKeyVersion != hub.KeyVersion ||
		!sameMachineNodeControlPublicIdentity(client.state.HubPublicIdentity, hub.PublicIdentity)) {
		return errors.New("Owner-approved Hub key conflicts with the existing local pin")
	}
	if candidate.RequestID != requestID || candidate.NodeID != client.nodeID ||
		candidate.NodeKeyID != public.ID || candidate.NodeKeyFingerprint != nodewire.IdentityFingerprint(public) ||
		candidate.HubID != hub.HubID || candidate.HubNodeControlKeyID != hub.KeyID ||
		candidate.HubNodeControlFingerprint != hub.Fingerprint || candidate.HubNodeControlKeyVersion != hub.KeyVersion ||
		candidate.CandidateDigest != status.CandidateDigest || candidate.Version != status.Version ||
		candidate.NodeName != status.NodeName || candidate.ExpiresAt != status.ExpiresAt ||
		candidate.NodeKeyEpoch != status.NodeKeyEpoch {
		return errors.New("confirmed Node-Control state differs from the displayed pairing candidate")
	}
	previous := cloneMachineNodeControlState(client.state)
	client.state.HubID, client.state.HubKeyID = hub.HubID, hub.KeyID
	client.state.HubFingerprint, client.state.HubKeyVersion = hub.Fingerprint, hub.KeyVersion
	client.state.HubPublicIdentity = hub.PublicIdentity
	client.state.NodeKeyID, client.state.NodeKeyFingerprint = public.ID, nodewire.IdentityFingerprint(public)
	client.state.NodeKeyVersion, client.state.BindingID = 1, status.BindingID
	client.state.BindingVersion, client.state.NodeKeyEpoch = status.BindingVersion, status.NodeKeyEpoch
	client.state.ApprovedRequestID = status.RequestID
	client.state.ApprovedRequestVersion = status.Version
	client.state.ApprovedCandidateDigest = status.CandidateDigest
	client.state.HubCandidateID, client.state.HubCandidateFingerprint = "", ""
	client.state.HubCandidateVersion, client.state.HubCandidateIdentity = 0, e2ee.PublicIdentity{}
	client.state.PendingPairing = nil
	client.state.PendingPairingUserCode, client.state.PendingPairingURI = "", ""
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

func (client *machineNodeControlClient) call(ctx context.Context, token, operation string,
	requestBody any, target any) error {
	plain, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	if len(plain) == 0 || len(plain) > nodewire.MaxRequestPlaintextBytes {
		return errors.New("Node-Control request exceeds the 64KiB management limit")
	}
	plainSum := sha256.Sum256(plain)
	plainDigest := hex.EncodeToString(plainSum[:])
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state.BindingID == "" || client.state.BindingVersion == 0 || client.state.NodeKeyEpoch == 0 ||
		client.state.NodeKeyID != client.identity.Public().ID || client.state.HubKeyID != client.state.HubPublicIdentity.ID {
		return errors.New("Node-Control key binding is not Owner-approved")
	}
	if len(client.state.PendingPacket) == 0 {
		if client.state.Sequence >= uint64(^uint64(0)>>1) {
			return errors.New("Node-Control sequence exhausted; require Owner-approved epoch upgrade")
		}
		sequence := client.state.Sequence + 1
		operationID, err := newMachineNodeControlOperationID()
		if err != nil {
			return err
		}
		binding := machineNodeControlBindingFromState(client)
		public := client.identity.Public()
		route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest,
			HubID: binding.HubID, NodeID: binding.NodeID, BindingID: binding.BindingID,
			BindingVersion: binding.BindingVersion, NodeKeyEpoch: binding.NodeKeyEpoch,
			Sequence: sequence, OperationID: operationID, Operation: operation,
			SenderKeyID: public.ID, SenderKeyVersion: binding.NodeKeyVersion,
			ReceiverKeyID: binding.HubKey.ID, ReceiverKeyVersion: binding.HubKeyVersion}
		packet, err := nodewire.SealRequest(client.identity, binding.HubKey, binding, route, plain)
		if err != nil {
			return err
		}
		if len(packet) > nodewire.MaxRequestPacketBytes {
			return errors.New("Node-Control request packet exceeds the 256KiB transport limit")
		}
		previous := cloneMachineNodeControlState(client.state)
		client.state.Sequence, client.state.PendingOperationID = sequence, operationID
		client.state.PendingOperation, client.state.PendingSequence = operation, sequence
		client.state.PendingPlaintextDigest = plainDigest
		client.state.PendingPacket = packet
		client.state.PendingResponsePacket = nil
		client.state.PendingWorkerID, client.state.PendingWorkerAttempt = machineNodeControlPendingWorker(operation, requestBody)
		if err := client.persistLocked(); err != nil {
			client.state = previous
			return err
		}
	} else if client.state.PendingOperation != operation || client.state.PendingPlaintextDigest != plainDigest {
		return fmt.Errorf("Node-Control operation %q is still awaiting its exact retry; refusing replacement operation %q",
			client.state.PendingOperation, operation)
	}
	var responsePacket []byte
	fromCache := len(client.state.PendingResponsePacket) > 0
	if len(client.state.PendingResponsePacket) > 0 {
		responsePacket = append([]byte(nil), client.state.PendingResponsePacket...)
	} else {
		responsePacket, err = client.postPacket(ctx, token, client.state.PendingPacket)
		if err != nil {
			return err
		}
	}
	invalidateCachedResponse := func() error {
		if !fromCache {
			return nil
		}
		previous := cloneMachineNodeControlState(client.state)
		client.state.PendingResponsePacket = nil
		if err := client.persistLocked(); err != nil {
			client.state = previous
			return err
		}
		return nil
	}
	binding := machineNodeControlBindingFromState(client)
	opened, err := nodewire.OpenResponse(client.identity, binding.HubKey, binding, responsePacket)
	if err != nil {
		if persistErr := invalidateCachedResponse(); persistErr != nil {
			return persistErr
		}
		return errors.New("Hub response did not authenticate under the Owner-approved Node-Control pin")
	}
	if opened.Route.Direction != nodewire.DirectionResponse ||
		opened.Route.Sequence != client.state.PendingSequence ||
		opened.Route.OperationID != client.state.PendingOperationID ||
		opened.Route.Operation != client.state.PendingOperation {
		if persistErr := invalidateCachedResponse(); persistErr != nil {
			return persistErr
		}
		return errors.New("Hub response is for a different Node-Control request")
	}
	var envelope struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   string          `json:"error_code,omitempty"`
		OperationID string          `json:"operation_id"`
		Sequence    uint64          `json:"sequence"`
	}
	if err := decodeMachineNodeControlJSON(opened.Plaintext, &envelope); err != nil ||
		envelope.OperationID != client.state.PendingOperationID || envelope.Sequence != client.state.PendingSequence ||
		(envelope.OK && (len(envelope.Result) == 0 || envelope.ErrorCode != "")) ||
		(!envelope.OK && (len(envelope.Result) != 0 || !machineNodeControlResponseCodeAllowed(envelope.ErrorCode))) {
		if persistErr := invalidateCachedResponse(); persistErr != nil {
			return persistErr
		}
		return errors.New("Hub returned an invalid Node-Control response body")
	}
	if !envelope.OK {
		switch envelope.ErrorCode {
		case "IN_PROGRESS":
			return errMachineNodeControlInProgress
		case "OUTCOME_UNCERTAIN":
			return errMachineNodeControlOutcomeUncertain
		case "RESULT_EXPIRED":
			if client.state.PendingOperation == "node.jobs.claim" || client.state.PendingOperation == "node.approvals.create" {
				if !fromCache {
					previous := cloneMachineNodeControlState(client.state)
					client.state.PendingResponsePacket = append([]byte(nil), responsePacket...)
					if err := client.persistLocked(); err != nil {
						client.state = previous
						return err
					}
				}
				return errMachineNodeControlResultExpired
			}
		}
	}
	var claimed machineJob
	if envelope.OK && client.state.PendingOperation == "node.jobs.claim" {
		if err := decodeMachineNodeControlJSON(envelope.Result, &claimed); err != nil ||
			claimed.WorkerID == "" || claimed.WorkerID != client.state.PendingWorkerID || claimed.Attempt <= 0 {
			if persistErr := invalidateCachedResponse(); persistErr != nil {
				return persistErr
			}
			return errors.New("Hub returned a claim for a different Worker attempt")
		}
	}
	if target != nil {
		if envelope.OK {
			if err := decodeMachineNodeControlJSON(envelope.Result, target); err != nil {
				if persistErr := invalidateCachedResponse(); persistErr != nil {
					return persistErr
				}
				return fmt.Errorf("decode Node-Control result: %w", err)
			}
		}
	}
	if !fromCache {
		previous := cloneMachineNodeControlState(client.state)
		client.state.PendingResponsePacket = append([]byte(nil), responsePacket...)
		if err := client.persistLocked(); err != nil {
			client.state = previous
			return err
		}
	}
	previous := cloneMachineNodeControlState(client.state)
	completedOperation := client.state.PendingOperation
	if completedOperation == "node.jobs.claim" {
		requestPacket, packetErr := nodewire.DecodePacket(client.state.PendingPacket)
		if packetErr != nil || requestPacket.Route.Operation != completedOperation ||
			requestPacket.Route.Direction != nodewire.DirectionRequest ||
			requestPacket.Route.BindingID != client.state.BindingID ||
			requestPacket.Route.BindingVersion != client.state.BindingVersion ||
			requestPacket.Route.NodeKeyEpoch != client.state.NodeKeyEpoch {
			return errors.New("durable Node-Control claim packet lost its trusted binding route")
		}
		ticket, ticketErr := newMachineNodeControlClaimTicket(ctx, client.state, requestPacket.Route,
			claimed, responsePacket)
		if ticketErr != nil {
			return ticketErr
		}
		client.state.ClaimTicket = &ticket
		applyMachineNodeControlClaimTicket(&claimed, ticket)
		if jobTarget, ok := target.(*machineJob); ok {
			applyMachineNodeControlClaimTicket(jobTarget, ticket)
		}
	}
	client.clearPendingLocked()
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	if !envelope.OK {
		switch envelope.ErrorCode {
		case "RESULT_TOO_LARGE":
			return errors.New("Node-Control rejected the queued Worker task because it exceeds the 2MiB response limit")
		case "RESULT_EXPIRED":
			if completedOperation == "node.jobs.result" {
				return nil // Signed RESULT_EXPIRED proves the result operation already completed.
			}
			return errMachineNodeControlResultExpired
		}
	}
	return nil
}

var (
	errMachineNodeControlInProgress       = errors.New("Node-Control operation is still processing; exact packet retained")
	errMachineNodeControlOutcomeUncertain = errors.New("Node-Control operation outcome is uncertain; exact packet retained and no action will be redispatched")
	errMachineNodeControlResultExpired    = errors.New("Node-Control operation completed but its bounded result expired; exact action remains fenced")
)

func machineNodeControlResponseCodeAllowed(code string) bool {
	switch code {
	case "RESULT_TOO_LARGE", "RESULT_EXPIRED", "IN_PROGRESS", "OUTCOME_UNCERTAIN":
		return true
	default:
		return false
	}
}

func machineNodeControlPendingWorker(operation string, payload any) (string, int) {
	if operation != "node.jobs.claim" && operation != "node.jobs.result" {
		return "", 0
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", 0
	}
	var fields struct {
		WorkerID string `json:"worker_id"`
		Attempt  int    `json:"attempt"`
	}
	if json.Unmarshal(encoded, &fields) != nil {
		return "", 0
	}
	return fields.WorkerID, fields.Attempt
}

func decodeMachineNodeControlJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Node-Control JSON contains trailing data")
	}
	return nil
}

// recoverPending retries the durable byte-identical outbox before any new
// management operation. A signed terminal result is accepted only after the
// route and envelope validate. A claimed job is retained as its sealed Hub
// response until execution begins, so restart never needs durable plaintext.
func (client *machineNodeControlClient) recoverPending(ctx context.Context, token string) error {
	client.mu.Lock()
	snapshotPending := len(client.state.PendingPacket) > 0 &&
		(client.state.PendingOperation == nodewire.SnapshotUploadOperation ||
			client.state.PendingOperation == nodewire.SnapshotDownloadOperation)
	client.mu.Unlock()
	if snapshotPending {
		_, _, err := client.resumeNodeControlSnapshot(ctx, token, false)
		return err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.state.PendingPacket) == 0 {
		return nil
	}
	if client.state.BindingID == "" || client.state.PendingSequence == 0 ||
		client.state.PendingOperationID == "" || client.state.PendingOperation == "" {
		return errors.New("Node-Control outbox is incomplete; refusing to replace it")
	}
	responsePacket := append([]byte(nil), client.state.PendingResponsePacket...)
	fromCache := len(responsePacket) > 0
	var err error
	if !fromCache {
		responsePacket, err = client.postPacket(ctx, token, client.state.PendingPacket)
		if err != nil {
			return err
		}
	}
	binding := machineNodeControlBindingFromState(client)
	opened, err := nodewire.OpenResponse(client.identity, binding.HubKey, binding, responsePacket)
	if err != nil || opened.Route.Direction != nodewire.DirectionResponse ||
		opened.Route.Sequence != client.state.PendingSequence ||
		opened.Route.OperationID != client.state.PendingOperationID ||
		opened.Route.Operation != client.state.PendingOperation {
		if fromCache {
			previous := cloneMachineNodeControlState(client.state)
			client.state.PendingResponsePacket = nil
			if persistErr := client.persistLocked(); persistErr != nil {
				client.state = previous
				return persistErr
			}
		}
		return errors.New("recovered Node-Control response did not authenticate for the exact outbox")
	}
	var envelope struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		ErrorCode   string          `json:"error_code,omitempty"`
		OperationID string          `json:"operation_id"`
		Sequence    uint64          `json:"sequence"`
	}
	if err := decodeMachineNodeControlJSON(opened.Plaintext, &envelope); err != nil ||
		envelope.OperationID != client.state.PendingOperationID || envelope.Sequence != client.state.PendingSequence ||
		(envelope.OK && (len(envelope.Result) == 0 || envelope.ErrorCode != "")) ||
		(!envelope.OK && (len(envelope.Result) != 0 || !machineNodeControlResponseCodeAllowed(envelope.ErrorCode))) {
		return errors.New("recovered Node-Control response body is invalid")
	}
	if !envelope.OK {
		switch envelope.ErrorCode {
		case "IN_PROGRESS":
			return errMachineNodeControlInProgress
		case "OUTCOME_UNCERTAIN":
			return errMachineNodeControlOutcomeUncertain
		case "RESULT_EXPIRED":
			if client.state.PendingOperation == "node.jobs.claim" || client.state.PendingOperation == "node.approvals.create" {
				return errMachineNodeControlResultExpired
			}
		case "RESULT_TOO_LARGE":
		}
	}
	var claimed machineJob
	if envelope.OK && client.state.PendingOperation == "node.jobs.claim" {
		if err := decodeMachineNodeControlJSON(envelope.Result, &claimed); err != nil ||
			claimed.WorkerID == "" || claimed.WorkerID != client.state.PendingWorkerID || claimed.Attempt <= 0 {
			return errors.New("recovered claim does not match the persisted Worker identity")
		}
	}
	if !fromCache {
		previous := cloneMachineNodeControlState(client.state)
		client.state.PendingResponsePacket = append([]byte(nil), responsePacket...)
		if err := client.persistLocked(); err != nil {
			client.state = previous
			return err
		}
	}
	previous := cloneMachineNodeControlState(client.state)
	operation := client.state.PendingOperation
	workerID, attempt := client.state.PendingWorkerID, client.state.PendingWorkerAttempt
	if operation == "node.jobs.claim" && envelope.OK {
		requestPacket, packetErr := nodewire.DecodePacket(client.state.PendingPacket)
		if packetErr != nil || requestPacket.Route.Operation != operation ||
			requestPacket.Route.Direction != nodewire.DirectionRequest {
			return errors.New("recovered claim request lost its exact sealed route")
		}
		ticket, ticketErr := newMachineNodeControlClaimTicket(ctx, client.state,
			requestPacket.Route, claimed, responsePacket)
		if ticketErr != nil {
			return ticketErr
		}
		client.state.ClaimTicket = &ticket
	}
	if operation == "node.jobs.result" && client.state.ClaimTicket != nil &&
		client.state.ClaimTicket.WorkerID == workerID && client.state.ClaimTicket.Attempt == attempt &&
		(client.state.ClaimTicket.Phase == "EXECUTING" ||
			client.state.ClaimTicket.Phase == "RESOURCE_STOP_UNVERIFIED") {
		client.state.ClaimTicket = nil
	}
	client.clearPendingLocked()
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	if !envelope.OK {
		switch envelope.ErrorCode {
		case "RESULT_TOO_LARGE":
			return errors.New("Node-Control rejected an oversized queued Worker response")
		case "RESULT_EXPIRED":
			if operation == "node.jobs.result" {
				return nil
			}
			return errMachineNodeControlResultExpired
		}
	}
	return nil
}

func (client *machineNodeControlClient) claimTicketJob() (*machineJob, error) {
	client.mu.Lock()
	if client.state.ClaimTicket == nil {
		client.mu.Unlock()
		return nil, nil
	}
	ticket := *client.state.ClaimTicket
	binding := machineNodeControlBindingFromState(client)
	client.mu.Unlock()
	if ticket.Phase != "READY" {
		return nil, errors.New("a prior claimed Worker outcome is uncertain; refusing to execute or claim another job")
	}
	opened, err := nodewire.OpenResponse(client.identity, binding.HubKey, binding, ticket.ResponsePacket)
	if err != nil || opened.Route.Direction != nodewire.DirectionResponse || opened.Route.Operation != "node.jobs.claim" {
		return nil, errors.New("durable claim ticket failed Node-Control response authentication")
	}
	if ticket.Version != machineNodeControlClaimTicketVersion ||
		!validMachineNodeProviderAdmissionIntent(ticket.ProviderAdmissionIntent) ||
		ticket.ClaimOperationID == "" || ticket.ClaimSequence == 0 ||
		opened.Route.OperationID != ticket.ClaimOperationID || opened.Route.Sequence != ticket.ClaimSequence ||
		ticket.BindingID != client.state.BindingID || ticket.BindingVersion != client.state.BindingVersion ||
		ticket.NodeKeyEpoch != client.state.NodeKeyEpoch || ticket.ExecutionID == "" ||
		ticket.ProviderID == "" || ticket.LeaseID == "" {
		return nil, errors.New("durable claim lacks its exact Node-Control execution identity; explicit reconciliation is required")
	}
	var envelope struct {
		OK          bool            `json:"ok"`
		Result      json.RawMessage `json:"result"`
		OperationID string          `json:"operation_id"`
		Sequence    uint64          `json:"sequence"`
	}
	if err := decodeMachineNodeControlJSON(opened.Plaintext, &envelope); err != nil || !envelope.OK ||
		envelope.OperationID != opened.Route.OperationID || envelope.Sequence != opened.Route.Sequence {
		return nil, errors.New("durable claim ticket has an invalid authenticated response")
	}
	var job machineJob
	if err := decodeMachineNodeControlJSON(envelope.Result, &job); err != nil ||
		job.WorkerID != ticket.WorkerID || job.Attempt != ticket.Attempt || job.Attempt <= 0 {
		return nil, errors.New("durable claim ticket identifies a different Worker attempt")
	}
	applyMachineNodeControlClaimTicket(&job, ticket)
	return &job, nil
}

func (client *machineNodeControlClient) beginClaimExecution(job machineJob) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state.ClaimTicket == nil || client.state.ClaimTicket.Version != machineNodeControlClaimTicketVersion ||
		!validMachineNodeProviderAdmissionIntent(client.state.ClaimTicket.ProviderAdmissionIntent) ||
		client.state.ClaimTicket.Phase != "READY" ||
		client.state.ClaimTicket.WorkerID != job.WorkerID || client.state.ClaimTicket.Attempt != job.Attempt ||
		client.state.ClaimTicket.ExecutionID != job.executionID ||
		client.state.ClaimTicket.ProviderID != job.providerID ||
		job.providerAttempt <= 0 || client.state.ClaimTicket.ProviderAttempt != job.providerAttempt ||
		client.state.ClaimTicket.ResourceID != job.resourceID ||
		client.state.ClaimTicket.LeaseID != job.leaseID ||
		client.state.ClaimTicket.FencingEpoch != job.fencingEpoch ||
		(job.resourceID == "" && job.fencingEpoch != 0) ||
		(job.resourceID != "" && job.fencingEpoch <= 0) {
		return errors.New("Worker execution lacks its durable Node-Control claim ticket")
	}
	previous := cloneMachineNodeControlState(client.state)
	client.state.ClaimTicket.Phase = "EXECUTING"
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

func (client *machineNodeControlClient) finishClaimExecution(job machineJob) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.state.ClaimTicket == nil || client.state.ClaimTicket.Version != machineNodeControlClaimTicketVersion ||
		!validMachineNodeProviderAdmissionIntent(client.state.ClaimTicket.ProviderAdmissionIntent) ||
		(client.state.ClaimTicket.Phase != "EXECUTING" &&
			client.state.ClaimTicket.Phase != "RESOURCE_STOP_UNVERIFIED") ||
		client.state.ClaimTicket.WorkerID != job.WorkerID || client.state.ClaimTicket.Attempt != job.Attempt ||
		client.state.ClaimTicket.ExecutionID != job.executionID || client.state.ClaimTicket.ProviderID != job.providerID ||
		job.providerAttempt <= 0 || client.state.ClaimTicket.ProviderAttempt != job.providerAttempt ||
		client.state.ClaimTicket.ResourceID != job.resourceID || client.state.ClaimTicket.LeaseID != job.leaseID ||
		client.state.ClaimTicket.FencingEpoch != job.fencingEpoch {
		return errors.New("completed Worker does not match its durable Node-Control claim ticket")
	}
	previous := cloneMachineNodeControlState(client.state)
	client.state.ClaimTicket = nil
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

func (client *machineNodeControlClient) markClaimResourceStopUnverified(job machineJob) error {
	client.mu.Lock()
	defer client.mu.Unlock()
	ticket := client.state.ClaimTicket
	if ticket == nil || ticket.Version != machineNodeControlClaimTicketVersion ||
		!validMachineNodeProviderAdmissionIntent(ticket.ProviderAdmissionIntent) ||
		ticket.Phase != "EXECUTING" || ticket.WorkerID != job.WorkerID ||
		ticket.Attempt != job.Attempt || ticket.ExecutionID != job.executionID ||
		ticket.ProviderAttempt != job.providerAttempt || job.providerAttempt <= 0 ||
		ticket.ResourceID != job.resourceID || ticket.LeaseID != job.leaseID ||
		ticket.FencingEpoch != job.fencingEpoch || ticket.FencingEpoch <= 0 {
		return errors.New("resource stop warning does not match the exact executing claim ticket")
	}
	previous := cloneMachineNodeControlState(client.state)
	ticket.Phase = "RESOURCE_STOP_UNVERIFIED"
	if err := client.persistLocked(); err != nil {
		client.state = previous
		return err
	}
	return nil
}

func recoverMachineNodeControlOutbox(ctx context.Context, base, nodeID, token string) error {
	endpoint := nodeWorkerJobsEndpoint(base, nodeID)
	client, err := machineNodeControlClientFromContext(ctx, endpoint, token)
	if err != nil {
		return err
	}
	return client.recoverPending(ctx, token)
}

func (client *machineNodeControlClient) postPacket(ctx context.Context, token string, packet []byte) ([]byte, error) {
	if !machineHubOriginMatches(ctx, strings.TrimRight(client.base, "/")+"/v2/node/control/rpc") {
		return nil, errors.New("Node-Control request escaped its pinned Hub origin")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(client.base, "/")+"/v2/node/control/rpc", bytes.NewReader(packet))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "CicadaNode "+strings.TrimSpace(token))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	clientHTTP, err := machineNodeHTTPClient(ctx, 30*time.Second)
	if err != nil {
		return nil, err
	}
	response, err := clientHTTP.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(nodewire.MaxPacketBytes)+1))
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, &machineAPIError{StatusCode: response.StatusCode, Status: response.Status,
			Body: strings.TrimSpace(string(truncateMachineAPIError(data)))}
	}
	if len(data) == 0 || len(data) > nodewire.MaxPacketBytes {
		return nil, errors.New("Hub returned an invalid Node-Control response packet size")
	}
	if _, err := nodewire.DecodePacket(data); err != nil {
		return nil, errors.New("Hub returned an invalid Node-Control response packet")
	}
	return data, nil
}

func truncateMachineAPIError(data []byte) []byte {
	if len(data) > 1024 {
		return data[:1024]
	}
	return data
}

func (client *machineNodeControlClient) clearPendingLocked() {
	client.state.PendingOperationID = ""
	client.state.PendingOperation = ""
	client.state.PendingSequence = 0
	client.state.PendingPlaintextDigest = ""
	client.state.PendingPacket = nil
	client.state.PendingResponsePacket = nil
	client.state.PendingWorkerID = ""
	client.state.PendingWorkerAttempt = 0
	client.state.PendingSnapshotPath = ""
	client.state.PendingSnapshotManifest = nil
}

func machineNodeControlBindingFromState(client *machineNodeControlClient) nodewire.Binding {
	return nodewire.Binding{HubID: client.state.HubID, NodeID: client.nodeID,
		BindingID: client.state.BindingID, BindingVersion: client.state.BindingVersion,
		NodeKeyEpoch: client.state.NodeKeyEpoch, NodeKeyVersion: client.state.NodeKeyVersion,
		HubKeyVersion: client.state.HubKeyVersion, NodeKey: client.identity.Public(),
		HubKey: client.state.HubPublicIdentity}
}

func newMachineNodeControlOperationID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "ncrpc_" + hex.EncodeToString(random[:]), nil
}

func machineNodeControlRequestForEndpoint(parsed *url.URL, method string, payload any) (string, any, error) {
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 4 || parts[0] != "v2" || parts[1] != "relay" || parts[2] != "nodes" || parts[3] == "" {
		return "", nil, errors.New("invalid Node-scoped API route")
	}
	rest := parts[4:]
	decodePayload := func(target any) error {
		if payload == nil {
			return nil
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, target)
	}
	switch {
	case len(rest) == 1 && rest[0] == "heartbeat" && method == http.MethodPost:
		input := struct {
			Status       string         `json:"status,omitempty"`
			Capabilities map[string]any `json:"capabilities,omitempty"`
		}{}
		if err := decodePayload(&input); err != nil {
			return "", nil, err
		}
		return "node.heartbeat", input, nil
	case len(rest) == 1 && rest[0] == "jobs" && method == http.MethodGet:
		return "node.jobs.list", struct{}{}, nil
	case len(rest) == 3 && rest[0] == "jobs" && rest[1] != "" && rest[2] == "claim" && method == http.MethodPost:
		return "node.jobs.claim", map[string]string{"worker_id": rest[1]}, nil
	case len(rest) == 3 && rest[0] == "jobs" && rest[1] != "" && rest[2] == "result" && method == http.MethodPost:
		var input map[string]any
		if err := decodePayload(&input); err != nil {
			return "", nil, err
		}
		input["worker_id"] = rest[1]
		return "node.jobs.result", input, nil
	case len(rest) == 3 && rest[0] == "jobs" && rest[1] != "" && rest[2] == "approvals" && method == http.MethodPost:
		var input map[string]any
		if err := decodePayload(&input); err != nil {
			return "", nil, err
		}
		input["worker_id"] = rest[1]
		return "node.approvals.create", input, nil
	case len(rest) == 4 && rest[0] == "jobs" && rest[1] != "" && rest[2] == "approvals" && method == http.MethodGet:
		attempt, err := parseMachineNodeControlAttempt(parsed.Query().Get("attempt"))
		if err != nil {
			return "", nil, err
		}
		return "node.approvals.status", map[string]any{"worker_id": rest[1],
			"attempt": attempt, "approval_id": rest[3]}, nil
	default:
		return "", nil, errors.New("Node bearer management request is not in the encrypted Node-Control operation whitelist")
	}
}

func parseMachineNodeControlAttempt(raw string) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, errors.New("Node approval attempt is invalid")
	}
	return value, nil
}

func machineNodeControlClientFromContext(ctx context.Context, endpoint, nodeToken string) (*machineNodeControlClient, error) {
	hub, ok := machineHubFrom(ctx)
	if !ok || hub.StateDir == "" || hub.NodeID == "" || hub.Token == "" ||
		hub.Token != strings.TrimSpace(nodeToken) {
		return nil, errors.New("Node-Control requires the current private Hub/Node context")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
	if len(parts) < 4 || parts[3] != hub.NodeID {
		return nil, errors.New("Node-Control route does not match the pinned Node ID")
	}
	if !machineHubOriginMatches(ctx, endpoint) {
		return nil, errors.New("Node-Control route escaped its pinned Hub origin")
	}
	return openMachineNodeControlClient(hub.StateDir, hub.Origin, hub.NodeID)
}

func machineNodeControlGetHubIdentity(ctx context.Context, client *machineNodeControlClient) (machineNodeControlHubIdentity, error) {
	var identity machineNodeControlHubIdentity
	endpoint := strings.TrimRight(client.base, "/") + "/v2/node/identity"
	if err := requestMachineNodeControlJSON(ctx, endpoint, http.MethodGet, "", nil, &identity); err != nil {
		return identity, err
	}
	if err := client.pinHubCandidate(identity); err != nil {
		return identity, err
	}
	return identity, nil
}

func requestMachineNodeControlJSON(ctx context.Context, endpoint, method, token string, payload, target any) error {
	if !machineHubOriginMatches(ctx, endpoint) {
		return errors.New("Node-Control pairing request escaped its pinned Hub origin")
	}
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "CicadaNode "+token)
	}
	client, err := machineNodeHTTPClient(ctx, 15*time.Second)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (128<<10)+1))
	if err != nil {
		return err
	}
	if len(data) > 128<<10 {
		return errors.New("Node-Control pairing response exceeds its bounded size")
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return &machineAPIError{StatusCode: response.StatusCode, Status: response.Status,
			Body: strings.TrimSpace(string(truncateMachineAPIError(data)))}
	}
	if target != nil {
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(target); err != nil {
			return err
		}
	}
	return nil
}

func buildMachineNodeControlPairingInput(client *machineNodeControlClient, hub machineNodeControlHubIdentity,
	nodeName, credentialDigest string) (machineNodeControlPairingInput, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return machineNodeControlPairingInput{}, err
	}
	nodePublic := client.publicIdentity()
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{
		HubID: hub.HubID, NodeID: client.nodeID, RequestNonce: nonce[:],
		CredentialDigest: credentialDigest, NodePublicIdentity: nodePublic,
		HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion,
	})
	if err != nil {
		return machineNodeControlPairingInput{}, err
	}
	proof, err := e2ee.Seal(client.identity, hub.PublicIdentity, transcript,
		nodewire.PairingProofAAD(), 1)
	if err != nil {
		return machineNodeControlPairingInput{}, err
	}
	return machineNodeControlPairingInput{NodeID: client.nodeID, NodeName: nodeName,
		CredentialDigest: credentialDigest, RequestNonce: nonce[:],
		NodePublicIdentity: nodePublic, NodeFingerprint: nodewire.IdentityFingerprint(nodePublic),
		ProofPacket: proof, HubID: hub.HubID, HubPublicIdentity: hub.PublicIdentity,
		HubKeyVersion: hub.KeyVersion, HubFingerprint: hub.Fingerprint}, nil
}

func startMachineNodeControlPairing(ctx context.Context, client *machineNodeControlClient,
	hub machineNodeControlHubIdentity, nodeName, token, credentialDigest string, upgrade bool) (*machineNodeControlPairingReply, error) {
	input, err := buildMachineNodeControlPairingInput(client, hub, nodeName, credentialDigest)
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(client.base, "/") + "/v2/nodes/device-code"
	if upgrade {
		endpoint = strings.TrimRight(client.base, "/") + "/v2/node/control/key-upgrade"
		input.CredentialDigest = ""
	}
	var reply machineNodeControlPairingReply
	requestToken := ""
	if upgrade {
		requestToken = token
	}
	if err := requestMachineNodeControlJSON(ctx, endpoint, http.MethodPost,
		requestToken, input, &reply); err != nil {
		return nil, err
	}
	if !validFormattedNodeDeviceCode(reply.UserCode) || reply.Candidate.RequestID == "" ||
		reply.Candidate.NodeID != client.nodeID || reply.Candidate.NodeName != strings.TrimSpace(nodeName) ||
		reply.Candidate.NodeKeyID != input.NodePublicIdentity.ID ||
		reply.Candidate.NodeKeyFingerprint != input.NodeFingerprint || reply.Candidate.HubID != hub.HubID ||
		reply.Candidate.HubNodeControlKeyID != hub.KeyID ||
		reply.Candidate.HubNodeControlFingerprint != hub.Fingerprint ||
		reply.Candidate.HubNodeControlKeyVersion != hub.KeyVersion || reply.Candidate.CandidateDigest == "" {
		return nil, errors.New("Hub returned a pairing candidate that differs from the displayed keys")
	}
	client.mu.Lock()
	copyCandidate := reply.Candidate
	previous := cloneMachineNodeControlState(client.state)
	client.state.PendingPairing = &copyCandidate
	client.state.PendingPairingUserCode, client.state.PendingPairingURI = reply.UserCode, reply.VerificationURI
	if err := client.persistLocked(); err != nil {
		client.state = previous
		client.mu.Unlock()
		return nil, err
	}
	client.mu.Unlock()
	return &reply, nil
}

func pollMachineNodeControlPairingStatus(ctx context.Context, client *machineNodeControlClient,
	token, requestID string) (machineNodeControlPairingStatus, error) {
	var status machineNodeControlPairingStatus
	endpoint := strings.TrimRight(client.base, "/") + "/v2/node/device-code/" + url.PathEscape(requestID) +
		"/status?node_id=" + url.QueryEscape(client.nodeID)
	err := requestMachineNodeControlJSON(ctx, endpoint, http.MethodGet, token, nil, &status)
	return status, err
}

func nodeControlCandidateFromReply(reply machineNodeControlPairingReply) machineNodeControlCandidate {
	return reply.Candidate
}

func machineNodeControlStatusError(err error) bool {
	var apiErr *machineAPIError
	return errors.As(err, &apiErr) && (apiErr.StatusCode == http.StatusNotFound || apiErr.StatusCode == http.StatusConflict)
}

func hashNodeCredential(token string) string { return fabric.HashSessionCredential(token) }

type machineNodeControlBindingStatus struct {
	RequestID          string `json:"request_id"`
	CandidateVersion   int64  `json:"candidate_version"`
	CandidateDigest    string `json:"candidate_digest"`
	NodeID             string `json:"node_id"`
	HubID              string `json:"hub_id"`
	BindingID          string `json:"binding_id"`
	BindingVersion     uint64 `json:"binding_version"`
	NodeKeyID          string `json:"node_key_id"`
	NodeKeyFingerprint string `json:"node_key_fingerprint"`
	NodeKeyEpoch       uint64 `json:"node_key_epoch"`
	HubKeyID           string `json:"hub_key_id"`
	HubKeyVersion      uint64 `json:"hub_key_version"`
	HubKeyFingerprint  string `json:"hub_key_fingerprint"`
}

func (client *machineNodeControlClient) verifyBindingRPC(ctx context.Context, token string) error {
	var status machineNodeControlBindingStatus
	if err := client.call(ctx, token, "node.binding.status", struct{}{}, &status); err != nil {
		return err
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if status.RequestID != client.state.ApprovedRequestID ||
		status.CandidateVersion != client.state.ApprovedRequestVersion ||
		status.CandidateDigest != client.state.ApprovedCandidateDigest ||
		status.NodeID != client.state.NodeID || status.HubID != client.state.HubID ||
		status.BindingID != client.state.BindingID || status.BindingVersion != client.state.BindingVersion ||
		status.NodeKeyID != client.state.NodeKeyID || status.NodeKeyFingerprint != client.state.NodeKeyFingerprint ||
		status.NodeKeyEpoch != client.state.NodeKeyEpoch || status.HubKeyID != client.state.HubKeyID ||
		status.HubKeyVersion != client.state.HubKeyVersion || status.HubKeyFingerprint != client.state.HubFingerprint {
		return errors.New("encrypted Node-Control status differs from the locally Owner-approved binding")
	}
	return nil
}

// awaitMachineNodeControlBinding is the only entry into Control management.
// It requires a Hub pin and exact Owner-approved candidate, then proves the
// newly approved key with a sealed status RPC before jobs or approvals run.
func awaitMachineNodeControlBinding(ctx context.Context, stateDir, base, nodeID, nodeName, token,
	credentialDigest string, once, verifyRPC bool, output io.Writer) error {
	if output == nil {
		output = io.Discard
	}
	client, err := openMachineNodeControlClient(stateDir, base, nodeID)
	if err != nil {
		return err
	}
	if client.bindingReady() {
		if err := client.recoverPending(ctx, token); err != nil {
			return fmt.Errorf("recover durable Node-Control outbox: %w", err)
		}
		if verifyRPC {
			if err := client.verifyBindingRPC(ctx, token); err != nil {
				return fmt.Errorf("verify Owner-approved Node-Control binding: %w", err)
			}
		}
		return nil
	}
	hub, err := machineNodeControlGetHubIdentity(ctx, client)
	if err != nil {
		return fmt.Errorf("fetch Node-Control Hub key candidate: %w", err)
	}
	if expectedHubID := machinePinnedHubID(ctx); expectedHubID != "" && expectedHubID != hub.HubID {
		return errors.New("Hub Node-Control identity does not match the locally pinned Hub ID")
	}
	client.mu.Lock()
	pending := client.state.PendingPairing
	pendingCode, pendingURI := client.state.PendingPairingUserCode, client.state.PendingPairingURI
	client.mu.Unlock()
	if pending != nil {
		expiresAt, parseErr := time.Parse(time.RFC3339Nano, pending.ExpiresAt)
		if parseErr != nil {
			return errors.New("stored Node-Control pairing candidate has an invalid expiry")
		}
		if !time.Now().Before(expiresAt) {
			client.mu.Lock()
			previous := cloneMachineNodeControlState(client.state)
			client.state.PendingPairing = nil
			client.state.PendingPairingUserCode, client.state.PendingPairingURI = "", ""
			if err := client.persistLocked(); err != nil {
				client.state = previous
				client.mu.Unlock()
				return err
			}
			client.mu.Unlock()
			pending, pendingCode, pendingURI = nil, "", ""
		}
	}
	var challenge *machineNodeControlPairingReply
	if pending != nil {
		challenge = &machineNodeControlPairingReply{Candidate: *pending,
			UserCode: pendingCode, VerificationURI: pendingURI}
	} else {
		active, probeErr := probeMachineNodeBinding(ctx, base, nodeID, token)
		if probeErr != nil {
			return fmt.Errorf("check legacy Node credential before PQ upgrade: %w", probeErr)
		}
		challenge, err = startMachineNodeControlPairing(ctx, client, hub, nodeName, token, credentialDigest, active)
		if err != nil {
			return fmt.Errorf("start Owner-approved Node-Control pairing: %w", err)
		}
	}
	if once {
		status, pollErr := pollMachineNodeControlPairingStatus(ctx, client, token, challenge.Candidate.RequestID)
		if pollErr == nil && status.State == "CONFIRMED" {
			if err := client.installApprovedBinding(status, challenge.Candidate.RequestID,
				nodeControlCandidateFromReply(*challenge), hub); err != nil {
				return err
			}
			if verifyRPC {
				if err := client.verifyBindingRPC(ctx, token); err != nil {
					return fmt.Errorf("prove the approved Node-Control key over encrypted RPC: %w", err)
				}
			}
			return nil
		}
		if pollErr == nil && status.State != "PENDING" {
			return fmt.Errorf("Node-Control pairing is not active (state %q)", status.State)
		}
	}
	verificationURL, err := resolveNodeDeviceVerificationURL(base, challenge.VerificationURI)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Owner approval required at %s. Compare Node key %s (%s) and Hub Node-Control key %s (%s) before approving. Device code: %s (valid for %s).\n",
		verificationURL, challenge.Candidate.NodeKeyID, challenge.Candidate.NodeKeyFingerprint,
		challenge.Candidate.HubNodeControlKeyID, challenge.Candidate.HubNodeControlFingerprint,
		challenge.UserCode, control.NodeDeviceCodeLifetime)
	if once {
		return errors.New("Node-Control binding is waiting for explicit Owner approval")
	}
	expires := time.Now().Add(control.NodeDeviceCodeLifetime - time.Minute)
	for {
		if err := waitMachineNodeBindingPoll(ctx); err != nil {
			return err
		}
		status, pollErr := pollMachineNodeControlPairingStatus(ctx, client, token, challenge.Candidate.RequestID)
		if pollErr != nil {
			if !machineNodeControlStatusError(pollErr) {
				fmt.Fprintln(output, "Node-Control approval status:", pollErr)
			}
			if time.Now().After(expires) {
				return errors.New("Node-Control pairing code expired; restart the Agent to create a new Owner-approved candidate")
			}
			continue
		}
		if err := client.installApprovedBinding(status, challenge.Candidate.RequestID,
			nodeControlCandidateFromReply(*challenge), hub); err != nil {
			return err
		}
		if verifyRPC {
			if err := client.verifyBindingRPC(ctx, token); err != nil {
				return fmt.Errorf("prove the approved Node-Control key over encrypted RPC: %w", err)
			}
		}
		return nil
	}
}
