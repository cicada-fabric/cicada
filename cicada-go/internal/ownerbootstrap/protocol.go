// Package ownerbootstrap frames finite, locally issued first-Owner authority.
// It does not issue authority, create accounts, or store Owner private keys.
package ownerbootstrap

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	Format      = "cicada.owner-bootstrap.v1"
	Purpose     = "ROOT_SIGNER_BOOTSTRAP"
	Operation   = "owner.bootstrap.complete"
	MaxLifetime = 10 * time.Minute
	Suite       = "ML-KEM-768+ML-DSA-65+AES-256-GCM"
)

var ErrInvalid = errors.New("invalid Owner bootstrap material")

type Manifest struct {
	Version              int                 `json:"version"`
	Purpose              string              `json:"purpose"`
	AccountID            string              `json:"account_id"`
	OwnerID              string              `json:"owner_id"`
	HubID                string              `json:"hub_id"`
	AuthorityID          string              `json:"authority_id"`
	OperationID          string              `json:"operation_id"`
	CandidatePublic      e2ee.PublicIdentity `json:"candidate_public_identity"`
	CandidateFingerprint string              `json:"candidate_fingerprint"`
	ExpiresAt            string              `json:"expires_at"`
}

type PairingFile struct {
	Format            string      `json:"format"`
	Origin            string      `json:"origin"`
	AllowLoopbackHTTP bool        `json:"allow_loopback_http"`
	Hub               HubIdentity `json:"hub"`
	Manifest          Manifest    `json:"manifest"`
	Challenge         []byte      `json:"challenge"`
}

// HubIdentity uses the unchanged /v2/client/identity public JSON shape. It is
// kept below the Client operator to avoid any management dependency or cycle.
type HubIdentity struct {
	Contract   string              `json:"contract"`
	HubID      string              `json:"hub_id"`
	Public     e2ee.PublicIdentity `json:"control_public_identity"`
	KeyVersion uint64              `json:"control_key_version"`
	Suite      string              `json:"suite"`
}

type Possession struct {
	Format   string   `json:"format"`
	Manifest Manifest `json:"manifest"`
	Nonce    []byte   `json:"nonce"`
}

type Receipt struct {
	Format         string `json:"format"`
	ManifestDigest string `json:"manifest_digest"`
	AuthorityID    string `json:"authority_id"`
	AccountID      string `json:"account_id"`
	OwnerID        string `json:"owner_id"`
	KeyID          string `json:"key_id"`
	State          string `json:"state"`
	Version        int64  `json:"version"`
}

// Fingerprint fixes the complete public candidate JSON and a dedicated domain.
func Fingerprint(public e2ee.PublicIdentity) string {
	fingerprint, _ := e2ee.OwnerDevicePublicKeyFingerprint(public)
	return fingerprint
}

func (m Manifest) Digest() string {
	b, _ := json.Marshal(m)
	h := sha256.Sum256(append([]byte("cicada/owner-bootstrap/manifest/v1\x00"), b...))
	return hex.EncodeToString(h[:])
}

func (m Manifest) Binding() clientwire.Binding {
	return clientwire.Binding{HubID: m.HubID, OwnerID: m.OwnerID, DeviceID: "bootstrap_" + m.AuthorityID, SessionEpoch: 1, HubKeyVersion: 1, DeviceKeyVersion: 1}
}

func (p PairingFile) Route(direction string, sequence uint64) clientwire.Route {
	m := p.Manifest
	sender, receiver := p.Hub.Public.ID, m.CandidatePublic.ID
	if direction == clientwire.DirectionRequest {
		sender, receiver = receiver, sender
	}
	return clientwire.Route{Version: 1, Direction: direction, HubID: m.HubID, OwnerID: m.OwnerID, DeviceID: m.Binding().DeviceID, SessionEpoch: 1, Sequence: sequence, OperationID: m.OperationID, Operation: Operation, SenderKeyID: sender, ReceiverKeyID: receiver, SenderKeyVersion: 1, ReceiverKeyVersion: 1}
}

func CanonicalOrigin(raw string, allowHTTP bool) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", ErrInvalid
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !allowHTTP || ip == nil || !ip.IsLoopback() {
			return "", ErrInvalid
		}
	}
	u.Path = ""
	return u.String(), nil
}

func (p PairingFile) Validate(at time.Time) error {
	m := p.Manifest
	if p.Format != Format || m.Version != 1 || m.Purpose != Purpose || p.Hub.Contract != "android-hub-v1" || p.Hub.Suite != Suite || p.Hub.KeyVersion != 1 || p.Hub.HubID != m.HubID || e2ee.ValidatePublicIdentity(p.Hub.Public) != nil || e2ee.ValidatePublicIdentity(m.CandidatePublic) != nil || p.Hub.Public.ID == m.CandidatePublic.ID || m.CandidateFingerprint != Fingerprint(m.CandidatePublic) {
		return ErrInvalid
	}
	for _, v := range []string{m.AccountID, m.OwnerID, m.HubID, m.AuthorityID, m.OperationID} {
		if v == "" || len(v) > 128 || strings.TrimSpace(v) != v || strings.ContainsAny(v, "/\\ \t\r\n") {
			return ErrInvalid
		}
	}
	origin, e := CanonicalOrigin(p.Origin, p.AllowLoopbackHTTP)
	if e != nil || origin != p.Origin {
		return ErrInvalid
	}
	expiry, e := time.Parse(time.RFC3339Nano, m.ExpiresAt)
	if e != nil || (!at.IsZero() && !expiry.After(at)) {
		return ErrInvalid
	}
	return nil
}

func nonceDigest(p PairingFile, nonce []byte) string {
	h := sha256.Sum256(append([]byte("cicada/owner-bootstrap/possession/v1\x00"+p.Manifest.Digest()+"\x00"), nonce...))
	return hex.EncodeToString(h[:])
}

func CreateChallenge(hub *e2ee.Identity, p PairingFile, at time.Time) (PairingFile, string, error) {
	if p.Validate(at) != nil || hub == nil || !reflect.DeepEqual(hub.Public(), p.Hub.Public) {
		return PairingFile{}, "", ErrInvalid
	}
	nonce := make([]byte, 32)
	if _, e := rand.Read(nonce); e != nil {
		return PairingFile{}, "", e
	}
	body, _ := json.Marshal(Possession{Format: Format, Manifest: p.Manifest, Nonce: nonce})
	packet, e := clientwire.SealResponse(hub, p.Manifest.CandidatePublic, p.Manifest.Binding(), p.Route(clientwire.DirectionResponse, 1), body)
	if e != nil {
		return PairingFile{}, "", e
	}
	p.Challenge = packet
	return p, nonceDigest(p, nonce), nil
}

func CreateProof(owner *e2ee.Identity, p PairingFile, at time.Time) ([]byte, error) {
	if owner == nil {
		return nil, ErrInvalid
	}
	return CreateProofWithPrivateOperations(owner.Public(), owner, p, at)
}

// CreateProofWithPrivateOperations keeps Owner private-key custody with the
// local provider. Exact route and Hub signature checks precede decapsulation.
func CreateProofWithPrivateOperations(owner e2ee.PublicIdentity, operations e2ee.PrivateOperations, p PairingFile, at time.Time) ([]byte, error) {
	possession, e := OpenChallengeWithPrivateOperations(owner, operations, p, at)
	if e != nil {
		return nil, e
	}
	defer clear(possession)
	return CreateProofFromPossessionWithPrivateOperations(owner, operations, p, possession, at)
}

// OpenChallengeWithPrivateOperations authenticates the exact Hub challenge
// before local review. The returned nonce-bearing bytes are transient secrets:
// callers must keep them only in RAM and clear them when review/signing ends.
func OpenChallengeWithPrivateOperations(owner e2ee.PublicIdentity, operations e2ee.PrivateOperations, p PairingFile, at time.Time) ([]byte, error) {
	if p.Validate(at) != nil || operations == nil || !reflect.DeepEqual(owner, p.Manifest.CandidatePublic) {
		return nil, ErrInvalid
	}
	opened, e := clientwire.OpenResponseWithPrivateOperations(owner, operations, p.Hub.Public, p.Manifest.Binding(), p.Route(clientwire.DirectionResponse, 1), p.Challenge)
	if e != nil || !reflect.DeepEqual(opened.Route, p.Route(clientwire.DirectionResponse, 1)) {
		return nil, ErrInvalid
	}
	if !validPossession(opened.Plaintext, p.Manifest) {
		clear(opened.Plaintext)
		return nil, ErrInvalid
	}
	return opened.Plaintext, nil
}

// CreateProofFromPossessionWithPrivateOperations signs only the canonical
// possession bytes for this reviewed manifest. It invokes no decapsulation.
// The Hub still verifies its secret nonce and current finite authority.
func CreateProofFromPossessionWithPrivateOperations(owner e2ee.PublicIdentity, operations e2ee.PrivateOperations, p PairingFile, possession []byte, at time.Time) ([]byte, error) {
	if p.Validate(at) != nil || operations == nil || !reflect.DeepEqual(owner, p.Manifest.CandidatePublic) {
		return nil, ErrInvalid
	}
	if !validPossession(possession, p.Manifest) {
		return nil, ErrInvalid
	}
	return clientwire.SealRequestWithPrivateOperations(owner, operations, p.Hub.Public, p.Manifest.Binding(), p.Route(clientwire.DirectionRequest, 1), possession)
}

func validPossession(data []byte, manifest Manifest) bool {
	var body Possession
	e := json.Unmarshal(data, &body)
	defer clear(body.Nonce)
	if e != nil || body.Format != Format || !reflect.DeepEqual(body.Manifest, manifest) || len(body.Nonce) != 32 {
		return false
	}
	canonical, _ := json.Marshal(body)
	defer clear(canonical)
	return bytes.Equal(canonical, data)
}

func VerifyProof(hub *e2ee.Identity, p PairingFile, packet []byte, at time.Time) (string, error) {
	if p.Validate(at) != nil || hub == nil || !reflect.DeepEqual(hub.Public(), p.Hub.Public) {
		return "", ErrInvalid
	}
	opened, e := clientwire.OpenRequest(hub, p.Manifest.CandidatePublic, p.Manifest.Binding(), packet)
	if e != nil || !reflect.DeepEqual(opened.Route, p.Route(clientwire.DirectionRequest, 1)) {
		return "", ErrInvalid
	}
	var body Possession
	if json.Unmarshal(opened.Plaintext, &body) != nil || body.Format != Format || !reflect.DeepEqual(body.Manifest, p.Manifest) || len(body.Nonce) != 32 {
		return "", ErrInvalid
	}
	canonical, _ := json.Marshal(body)
	if !bytes.Equal(canonical, opened.Plaintext) {
		return "", ErrInvalid
	}
	return nonceDigest(p, body.Nonce), nil
}

func CreateReceipt(hub *e2ee.Identity, p PairingFile, r Receipt) ([]byte, error) {
	body, e := json.Marshal(r)
	if e != nil {
		return nil, e
	}
	return clientwire.SealResponse(hub, p.Manifest.CandidatePublic, p.Manifest.Binding(), p.Route(clientwire.DirectionResponse, 2), body)
}

func VerifyReceipt(owner *e2ee.Identity, p PairingFile, packet []byte) (*Receipt, error) {
	if owner == nil {
		return nil, ErrInvalid
	}
	return VerifyReceiptWithPrivateOperations(owner.Public(), owner, p, packet)
}

// VerifyReceiptWithPrivateOperations authenticates an exact Hub receipt while
// retaining the same public identity, algorithms and owner-bootstrap v1 scope.
func VerifyReceiptWithPrivateOperations(owner e2ee.PublicIdentity, operations e2ee.PrivateOperations, p PairingFile, packet []byte) (*Receipt, error) {
	if p.Validate(time.Time{}) != nil || operations == nil || !reflect.DeepEqual(owner, p.Manifest.CandidatePublic) {
		return nil, ErrInvalid
	}
	opened, e := clientwire.OpenResponseWithPrivateOperations(owner, operations, p.Hub.Public, p.Manifest.Binding(), p.Route(clientwire.DirectionResponse, 2), packet)
	if e != nil || !reflect.DeepEqual(opened.Route, p.Route(clientwire.DirectionResponse, 2)) {
		return nil, ErrInvalid
	}
	var r Receipt
	m := p.Manifest
	if json.Unmarshal(opened.Plaintext, &r) != nil || r.Format != Format || r.ManifestDigest != m.Digest() || r.AuthorityID != m.AuthorityID || r.AccountID != m.AccountID || r.OwnerID != m.OwnerID || r.KeyID != m.CandidatePublic.ID || r.State != "ACTIVE" || r.Version != 1 {
		return nil, ErrInvalid
	}
	return &r, nil
}
