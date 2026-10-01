package control

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

const nodeControlHubKeyVersion uint64 = 1

type NodeControlHubIdentity struct {
	Version        int                 `json:"version"`
	Algorithm      string              `json:"algorithm"`
	HubID          string              `json:"hub_id"`
	KeyID          string              `json:"key_id"`
	KeyVersion     uint64              `json:"key_version"`
	Fingerprint    string              `json:"fingerprint"`
	PublicIdentity e2ee.PublicIdentity `json:"public_identity"`
}

type NodeControlDeviceCodeInput struct {
	Mode               string
	NodeID             string
	NodeName           string
	CredentialDigest   string
	RequestNonce       []byte
	NodePublicIdentity e2ee.PublicIdentity
	NodeFingerprint    string
	ProofPacket        []byte
	HubID              string
	HubPublicIdentity  e2ee.PublicIdentity
	HubKeyVersion      uint64
	HubFingerprint     string
	TargetBindingID    string
}

type NodeControlDeviceCode struct {
	UserCode        string                         `json:"user_code"`
	VerificationURI string                         `json:"verification_uri"`
	Candidate       *store.NodeControlKeyCandidate `json:"candidate"`
}

func (c *Control) NodeControlPublicIdentity() (NodeControlHubIdentity, error) {
	if c == nil || c.store == nil || c.nodeControlIdentity == nil {
		return NodeControlHubIdentity{}, errors.New("Node-Control identity is unavailable")
	}
	hubID, err := c.store.GetClientHubID()
	if err != nil {
		return NodeControlHubIdentity{}, err
	}
	public := c.nodeControlIdentity.Public()
	if e2ee.ValidatePublicIdentity(public) != nil {
		return NodeControlHubIdentity{}, errors.New("Node-Control public identity is invalid")
	}
	return NodeControlHubIdentity{Version: nodewire.Version, Algorithm: e2ee.Algorithm,
		HubID: hubID, KeyID: public.ID, KeyVersion: nodeControlHubKeyVersion,
		Fingerprint: nodewire.IdentityFingerprint(public), PublicIdentity: public}, nil
}

// StartNodeControlDeviceBinding stages a public Node key and a short-lived
// code. The caller has already generated the Node bearer locally and sends
// only its case-sensitive base64url SHA-256 digest.
func (c *Control) StartNodeControlDeviceBinding(input NodeControlDeviceCodeInput) (*NodeControlDeviceCode, error) {
	return c.startNodeControlDeviceBinding(input, "")
}

// StartNodeControlKeyUpgrade stages an Owner-confirmed application-key
// rotation for a currently active Node bearer. It never replaces that bearer.
func (c *Control) StartNodeControlKeyUpgrade(token string, input NodeControlDeviceCodeInput) (*NodeControlDeviceCode, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Node-Control binding registry is unavailable")
	}
	token = strings.TrimSpace(token)
	if _, err := fabric.NodeCredentialFromAuthorization("CicadaNode " + token); err != nil {
		return nil, store.ErrNodeControlKeyUnauthorized
	}
	digest := fabric.HashSessionCredential(token)
	_, binding, err := c.store.GetOwnerBoundNodeCredentialByHash(digest)
	if err != nil || binding == nil || binding.NodeID != strings.TrimSpace(input.NodeID) {
		return nil, store.ErrNodeControlKeyUnauthorized
	}
	input.Mode = store.NodeControlPairingUpgrade
	input.TargetBindingID = binding.ID
	input.CredentialDigest = digest
	return c.startNodeControlDeviceBinding(input, store.NodeControlPairingUpgrade)
}

func (c *Control) startNodeControlDeviceBinding(input NodeControlDeviceCodeInput, requiredMode string) (*NodeControlDeviceCode, error) {
	if c == nil || c.store == nil || c.nodeControlIdentity == nil {
		return nil, errors.New("Node-Control binding registry is unavailable")
	}
	input.NodeID = strings.TrimSpace(input.NodeID)
	input.NodeName = strings.TrimSpace(input.NodeName)
	input.CredentialDigest = strings.TrimSpace(input.CredentialDigest)
	input.Mode = strings.ToUpper(strings.TrimSpace(input.Mode))
	input.HubID = strings.TrimSpace(input.HubID)
	input.NodeFingerprint = strings.ToLower(strings.TrimSpace(input.NodeFingerprint))
	input.HubFingerprint = strings.ToLower(strings.TrimSpace(input.HubFingerprint))
	if input.Mode == "" {
		input.Mode = store.NodeControlPairingInitial
	}
	if requiredMode != "" && input.Mode != requiredMode {
		return nil, errors.New("Node-Control key-upgrade mode is required")
	}
	if input.Mode != store.NodeControlPairingInitial && input.Mode != store.NodeControlPairingUpgrade {
		return nil, errors.New("unsupported Node-Control pairing mode")
	}
	hub, err := c.NodeControlPublicIdentity()
	if err != nil {
		return nil, err
	}
	if input.HubID != hub.HubID || input.HubKeyVersion != hub.KeyVersion ||
		input.HubPublicIdentity.ID != hub.KeyID || input.HubFingerprint != hub.Fingerprint ||
		!sameNodeControlPublicIdentity(input.HubPublicIdentity, hub.PublicIdentity) {
		return nil, errors.New("Node-Control Hub key candidate does not match the current Control key")
	}
	if input.NodeFingerprint != nodewire.IdentityFingerprint(input.NodePublicIdentity) {
		return nil, errors.New("Node-Control public key fingerprint mismatch")
	}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{
		HubID: hub.HubID, NodeID: input.NodeID, RequestNonce: input.RequestNonce,
		CredentialDigest: input.CredentialDigest, NodePublicIdentity: input.NodePublicIdentity,
		HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion,
	})
	if err != nil {
		return nil, errors.New("invalid Node-Control key proof context")
	}
	opened, sequence, err := e2ee.Open(c.nodeControlIdentity, input.NodePublicIdentity,
		input.ProofPacket, nodewire.PairingProofAAD())
	if err != nil || sequence != 1 || !bytes.Equal(opened, transcript) {
		return nil, errors.New("Node-Control key proof verification failed")
	}
	code, err := newNodeDeviceCode()
	if err != nil {
		return nil, err
	}
	codeDigest := nodeDeviceCodeDigest(hub.HubID, code)
	candidate, err := c.store.StartNodeControlKeyRequest(store.NodeControlKeyRequestInput{
		Mode: input.Mode, NodeID: input.NodeID, NodeName: input.NodeName,
		CredentialDigest: input.CredentialDigest, CodeDigest: codeDigest,
		NodePublicIdentity: input.NodePublicIdentity, NodeFingerprint: input.NodeFingerprint,
		ProofPacket: input.ProofPacket, HubPublicIdentity: hub.PublicIdentity,
		HubKeyVersion: hub.KeyVersion, HubFingerprint: hub.Fingerprint,
		TargetBindingID: input.TargetBindingID, ExpiresAt: time.Now().UTC().Add(NodeDeviceCodeLifetime),
	})
	if err != nil {
		return nil, err
	}
	return &NodeControlDeviceCode{UserCode: formatNodeDeviceCode(code),
		VerificationURI: NodeDeviceVerificationURI, Candidate: candidate}, nil
}

func sameNodeControlPublicIdentity(left, right e2ee.PublicIdentity) bool {
	return left.ID == right.ID && bytes.Equal(left.KEMPublic, right.KEMPublic) &&
		bytes.Equal(left.SigningPublic, right.SigningPublic)
}

func (c *Control) PreviewNodeControlDeviceCode(ownerID, clientDeviceID, userCode string) (*store.NodeControlKeyCandidate, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Node-Control binding registry is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	code, err := normalizeNodeDeviceCode(userCode)
	if err != nil {
		return nil, err
	}
	hubID, err := c.store.GetClientHubID()
	if err != nil {
		return nil, err
	}
	return c.store.PreviewNodeControlKeyRequest(ownerID, clientDeviceID,
		nodeDeviceCodeDigest(hubID, code))
}

func (c *Control) ConfirmNodeControlDeviceCode(ownerID, clientDeviceID, userCode,
	candidateDigest string, candidateVersion int64) (*store.NodeControlKeyBinding, error) {
	if c == nil || c.store == nil || c.nodeControlIdentity == nil {
		return nil, errors.New("Node-Control binding registry is unavailable")
	}
	if err := c.ValidateClientSessionOwner(ownerID); err != nil {
		return nil, err
	}
	code, err := normalizeNodeDeviceCode(userCode)
	if err != nil {
		return nil, err
	}
	hub, err := c.NodeControlPublicIdentity()
	if err != nil {
		return nil, err
	}
	return c.store.ConfirmNodeControlKeyRequest(ownerID, clientDeviceID,
		nodeDeviceCodeDigest(hub.HubID, code), candidateVersion, candidateDigest,
		hub.KeyID, hub.Fingerprint)
}

func (c *Control) NodeControlPairingStatus(token, nodeID, requestID string) (*store.NodeControlKeyCandidate, error) {
	token = strings.TrimSpace(token)
	if _, err := fabric.NodeCredentialFromAuthorization("CicadaNode " + token); err != nil {
		return nil, store.ErrNodeControlKeyUnauthorized
	}
	return c.store.NodeControlPairingStatus(fabric.HashSessionCredential(token), nodeID, requestID)
}

func (c *Control) NodeControlKeyForCredential(credentialDigest, nodeID string) (*store.NodeControlKeyBinding, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Node-Control key registry is unavailable")
	}
	return c.store.NodeControlKeyForCredential(credentialDigest, nodeID)
}

func (c *Control) OpenNodeControlRequest(binding *store.NodeControlKeyBinding, packet []byte) (nodewire.Opened, error) {
	if c == nil || c.nodeControlIdentity == nil || binding == nil {
		return nodewire.Opened{}, errors.New("Node-Control identity or binding is unavailable")
	}
	return nodewire.OpenRequest(c.nodeControlIdentity, binding.NodePublicIdentity,
		nodeControlWireBinding(binding), packet)
}

func (c *Control) OpenNodeControlResponse(binding *store.NodeControlKeyBinding, packet []byte) (nodewire.Opened, error) {
	if c == nil || c.nodeControlIdentity == nil || binding == nil {
		return nodewire.Opened{}, errors.New("Node-Control identity or binding is unavailable")
	}
	return nodewire.OpenResponse(c.nodeControlIdentity, binding.NodePublicIdentity,
		nodeControlWireBinding(binding), packet)
}

func (c *Control) SealNodeControlResponse(binding *store.NodeControlKeyBinding,
	route nodewire.Route, body []byte) ([]byte, error) {
	if c == nil || c.nodeControlIdentity == nil || binding == nil {
		return nil, errors.New("Node-Control identity or binding is unavailable")
	}
	return nodewire.SealResponse(c.nodeControlIdentity, binding.NodePublicIdentity,
		nodeControlWireBinding(binding), route, body)
}

func (c *Control) SealNodeControlSnapshotChunk(binding *store.NodeControlKeyBinding,
	route nodewire.Route, manifest nodewire.SnapshotManifest, index int, plaintext []byte) ([]byte, error) {
	if c == nil || c.nodeControlIdentity == nil || binding == nil {
		return nil, errors.New("Node-Control identity or binding is unavailable")
	}
	return nodewire.SealSnapshotChunk(c.nodeControlIdentity, binding.NodePublicIdentity,
		route, manifest, index, plaintext)
}

func (c *Control) OpenNodeControlSnapshotChunk(binding *store.NodeControlKeyBinding,
	route nodewire.Route, manifest nodewire.SnapshotManifest, index int, envelope []byte) ([]byte, error) {
	if c == nil || c.nodeControlIdentity == nil || binding == nil {
		return nil, errors.New("Node-Control identity or binding is unavailable")
	}
	return nodewire.OpenSnapshotChunk(c.nodeControlIdentity, binding.NodePublicIdentity,
		route, manifest, index, envelope)
}

func nodeControlWireBinding(binding *store.NodeControlKeyBinding) nodewire.Binding {
	return nodewire.Binding{HubID: binding.HubID, NodeID: binding.NodeID,
		BindingID: binding.OwnerBindingID, BindingVersion: binding.BindingVersion,
		NodeKeyEpoch: binding.NodeKeyEpoch, HubKeyVersion: binding.HubKeyVersion,
		NodeKeyVersion: binding.NodeKeyVersion, NodeKey: binding.NodePublicIdentity,
		HubKey: binding.HubPublicIdentity}
}

func (c *Control) NodeControlRPCBegin(input store.NodeControlRPCInput) (*store.NodeControlRPCRecord, bool, error) {
	if c == nil || c.store == nil {
		return nil, false, errors.New("Node-Control request registry is unavailable")
	}
	return c.store.BeginNodeControlRPC(input)
}

func (c *Control) NodeControlRPCComplete(input store.NodeControlRPCCompletion) error {
	if c == nil || c.store == nil {
		return errors.New("Node-Control request registry is unavailable")
	}
	return c.store.CompleteNodeControlRPC(input)
}

func (c *Control) NodeControlSnapshotRPCResponseProjection(input store.NodeControlRPCInput,
	requestRoute nodewire.Route) (*store.NodeControlSnapshotRPCResponseProjection, error) {
	if c == nil || c.store == nil {
		return nil, errors.New("Node-Control snapshot replay projection is unavailable")
	}
	return c.store.NodeControlSnapshotRPCResponseProjection(input, requestRoute)
}

func (c *Control) NodeControlRPCUncertain(input store.NodeControlRPCInput) error {
	if c == nil || c.store == nil {
		return errors.New("Node-Control request registry is unavailable")
	}
	return c.store.MarkNodeControlRPCUncertain(input)
}

// RecordNodeControlHeartbeat routes the trusted Node-Control guard all the way
// to the Store mutation transaction; token hashing preserves the existing
// case-sensitive base64url credential digest.
func (c *Control) RecordNodeControlHeartbeat(token string, input store.NodeControlRPCInput,
	status string, capabilities map[string]any) error {
	token = strings.TrimSpace(token)
	if _, err := fabric.NodeCredentialFromAuthorization("CicadaNode " + token); err != nil ||
		fabric.HashSessionCredential(token) != input.CredentialDigest {
		return store.ErrNodeControlKeyUnauthorized
	}
	if c == nil || c.store == nil {
		return errors.New("Node-Control heartbeat store is unavailable")
	}
	return c.store.RecordBoundNodeMachineHeartbeatNodeControl(input, status, capabilities)
}

func validateNodeControlHubIdentity(identity NodeControlHubIdentity, configuredHubID string) error {
	if identity.Version != nodewire.Version || identity.Algorithm != e2ee.Algorithm ||
		identity.HubID == "" || configuredHubID != "" && identity.HubID != configuredHubID ||
		identity.KeyID != identity.PublicIdentity.ID || identity.KeyVersion == 0 ||
		identity.Fingerprint != nodewire.IdentityFingerprint(identity.PublicIdentity) ||
		e2ee.ValidatePublicIdentity(identity.PublicIdentity) != nil {
		return fmt.Errorf("invalid Node-Control Hub identity")
	}
	return nil
}

func ValidateNodeControlHubIdentity(identity NodeControlHubIdentity, configuredHubID string) error {
	return validateNodeControlHubIdentity(identity, configuredHubID)
}
