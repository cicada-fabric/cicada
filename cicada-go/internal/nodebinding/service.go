// Package nodebinding owns existing Node pairing proof validation without a
// Control business instance. Control and explicit Hub Nodes composition reuse
// this same implementation and frozen public DTOs/identifiers.
package nodebinding

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

const KeyVersion uint64 = 1
const CodeLifetime = 10 * time.Minute
const VerificationURI = "/client/device"

type HubIdentity struct {
	Version        int                 `json:"version"`
	Algorithm      string              `json:"algorithm"`
	HubID          string              `json:"hub_id"`
	KeyID          string              `json:"key_id"`
	KeyVersion     uint64              `json:"key_version"`
	Fingerprint    string              `json:"fingerprint"`
	PublicIdentity e2ee.PublicIdentity `json:"public_identity"`
}
type Input struct {
	Mode, NodeID, NodeName, CredentialDigest string
	RequestNonce                             []byte
	NodePublicIdentity                       e2ee.PublicIdentity
	NodeFingerprint                          string
	ProofPacket                              []byte
	HubID                                    string
	HubPublicIdentity                        e2ee.PublicIdentity
	HubKeyVersion                            uint64
	HubFingerprint, TargetBindingID          string
}
type DeviceCode struct {
	UserCode        string                         `json:"user_code"`
	VerificationURI string                         `json:"verification_uri"`
	Candidate       *store.NodeControlKeyCandidate `json:"candidate"`
}
type Service struct {
	db       *store.Store
	identity *e2ee.Identity
}

func NewService(db *store.Store, identity *e2ee.Identity) (*Service, error) {
	if db == nil || identity == nil || e2ee.ValidatePublicIdentity(identity.Public()) != nil {
		return nil, errors.New("Node-Control identity unavailable")
	}
	return &Service{db: db, identity: identity}, nil
}
func (s *Service) PublicIdentity() (HubIdentity, error) {
	hub, err := s.db.GetClientHubID()
	if err != nil {
		return HubIdentity{}, err
	}
	pub := s.identity.Public()
	return HubIdentity{Version: nodewire.Version, Algorithm: e2ee.Algorithm, HubID: hub, KeyID: pub.ID, KeyVersion: KeyVersion, Fingerprint: nodewire.IdentityFingerprint(pub), PublicIdentity: pub}, nil
}
func (s *Service) Start(input Input, requiredMode string) (*DeviceCode, error) {
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
		return nil, errors.New("required Node pairing mode does not match")
	}
	if input.Mode != store.NodeControlPairingInitial && input.Mode != store.NodeControlPairingUpgrade {
		return nil, errors.New("unsupported Node pairing mode")
	}
	hub, err := s.PublicIdentity()
	if err != nil {
		return nil, err
	}
	if input.HubID != hub.HubID || input.HubKeyVersion != hub.KeyVersion || input.HubFingerprint != hub.Fingerprint || !reflect.DeepEqual(input.HubPublicIdentity, hub.PublicIdentity) || input.NodeFingerprint != nodewire.IdentityFingerprint(input.NodePublicIdentity) {
		return nil, errors.New("Node pairing key candidate does not match current Hub keys")
	}
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: hub.HubID, NodeID: input.NodeID, RequestNonce: input.RequestNonce, CredentialDigest: input.CredentialDigest, NodePublicIdentity: input.NodePublicIdentity, HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion})
	if err != nil || len(input.ProofPacket) == 0 || len(input.ProofPacket) > 64*1024 {
		return nil, errors.New("invalid Node pairing proof context")
	}
	opened, sequence, err := e2ee.Open(s.identity, input.NodePublicIdentity, input.ProofPacket, nodewire.PairingProofAAD())
	if err != nil || sequence != 1 || !bytes.Equal(opened, transcript) {
		return nil, errors.New("Node pairing proof verification failed")
	}
	const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	random := make([]byte, 12)
	if _, err = rand.Read(random); err != nil {
		return nil, err
	}
	code := make([]byte, 12)
	for i, b := range random {
		code[i] = alphabet[int(b)%len(alphabet)]
	}
	// Keep the existing code digest/expiry and complete public candidate tuple.
	digest := CodeDigest(hub.HubID, string(code))
	candidate, err := s.db.StartNodeControlKeyRequest(store.NodeControlKeyRequestInput{Mode: input.Mode, NodeID: input.NodeID, NodeName: input.NodeName, CredentialDigest: input.CredentialDigest, CodeDigest: digest, NodePublicIdentity: input.NodePublicIdentity, NodeFingerprint: input.NodeFingerprint, ProofPacket: input.ProofPacket, HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion, HubFingerprint: hub.Fingerprint, TargetBindingID: input.TargetBindingID, ExpiresAt: time.Now().UTC().Add(CodeLifetime)})
	if err != nil {
		return nil, err
	}
	return &DeviceCode{UserCode: string(code[:4]) + "-" + string(code[4:8]) + "-" + string(code[8:]), VerificationURI: VerificationURI, Candidate: candidate}, nil
}

func CodeDigest(hubID, code string) string {
	hash := sha256.Sum256([]byte("cicada-node-device-code-v1\x00" + strings.TrimSpace(hubID) + "\x00" + code))
	return hex.EncodeToString(hash[:])
}
