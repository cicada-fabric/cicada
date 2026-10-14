// Package hubowner provides Hub-owned finite Owner bootstrap independently
// of Control business. It owns no Owner private keys or account login service.
package hubowner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/store"
)

type Service struct {
	store      *store.Store
	identities hubidentity.Set
}

func NewService(persistence *store.Store, identities hubidentity.Set) (*Service, error) {
	if persistence == nil || identities.Peer == nil || identities.ClientControl == nil || identities.NodeControl == nil {
		return nil, store.ErrHubOwnerSetupConflict
	}
	return &Service{store: persistence, identities: identities}, nil
}

func (s *Service) HubOwnerSetup() (*store.HubOwnerSetup, error) {
	if s == nil || s.store == nil {
		return nil, store.ErrHubOwnerSetupConflict
	}
	return s.store.GetHubOwnerSetup()
}
func (s *Service) ClientHubID() (string, error) {
	if s == nil || s.store == nil {
		return "", store.ErrHubOwnerSetupConflict
	}
	return s.store.GetClientHubID()
}
func (s *Service) ClientControlPublicIdentity() e2ee.PublicIdentity {
	if s == nil || s.identities.ClientControl == nil {
		return e2ee.PublicIdentity{}
	}
	return s.identities.ClientControl.Public()
}

// IssueOwnerBootstrapLocal is only for the independently controlled local
// deployment CLI. No public, bearer, Node or model route exposes this method.
func (s *Service) IssueOwnerBootstrapLocal(candidate e2ee.PublicIdentity, expectedFingerprint string) (*ownerbootstrap.PairingFile, error) {
	if s == nil || s.store == nil || s.identities.ClientControl == nil || e2ee.ValidatePublicIdentity(candidate) != nil || expectedFingerprint != ownerbootstrap.Fingerprint(candidate) {
		return nil, store.ErrOwnerBootstrapRejected
	}
	for _, identity := range []*e2ee.Identity{s.identities.Peer, s.identities.ClientControl, s.identities.NodeControl} {
		if identity != nil && identity.Public().ID == candidate.ID {
			return nil, store.ErrOwnerBootstrapRejected
		}
	}
	setup, e := s.store.CheckOwnerBootstrapIssueLocal()
	if e != nil {
		return nil, e
	}
	if setup == nil || setup.State != store.HubOwnerReady || setup.RootEverEstablished {
		return nil, store.ErrOwnerBootstrapRejected
	}
	current, e := s.store.CurrentOwnerBootstrapPairing()
	if e != nil {
		return nil, e
	}
	if current != nil {
		if !reflect.DeepEqual(current.Manifest.CandidatePublic, candidate) {
			return nil, store.ErrOwnerBootstrapRejected
		}
		return current, nil
	}
	at := time.Now().UTC()
	p := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: setup.Origin, AllowLoopbackHTTP: setup.AllowLoopbackHTTP,
		Hub:      ownerbootstrap.HubIdentity{Contract: "android-hub-v1", HubID: setup.HubID, Public: s.identities.ClientControl.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite},
		Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: setup.AccountID, OwnerID: setup.OwnerID, HubID: setup.HubID, AuthorityID: store.NewID("root"), OperationID: store.NewID("bootstrap"), CandidatePublic: candidate, CandidateFingerprint: expectedFingerprint, ExpiresAt: at.Add(ownerbootstrap.MaxLifetime).Format(time.RFC3339Nano)}}
	p, nonce, e := ownerbootstrap.CreateChallenge(s.identities.ClientControl, p, at)
	if e != nil {
		return nil, e
	}
	return s.store.IssueOwnerBootstrapLocal(p, nonce)
}

// AcceptOwnerBootstrap verifies only an already stored finite authority. It
// neither enrolls a Client nor dispatches management business operations.
func (s *Service) AcceptOwnerBootstrap(packet []byte) ([]byte, error) {
	if s == nil || s.store == nil || s.identities.ClientControl == nil || len(packet) == 0 || len(packet) > 256*1024 {
		return nil, store.ErrOwnerBootstrapRejected
	}
	var public struct {
		Route clientwire.Route `json:"route"`
	}
	if json.Unmarshal(packet, &public) != nil || public.Route.Operation != ownerbootstrap.Operation || public.Route.Direction != clientwire.DirectionRequest || public.Route.Sequence != 1 || !strings.HasPrefix(public.Route.DeviceID, "bootstrap_") {
		return nil, store.ErrOwnerBootstrapRejected
	}
	// Cheap exact durable lookup precedes all PQ verification.
	identity := strings.TrimPrefix(public.Route.DeviceID, "bootstrap_")
	if len(identity) > 128 {
		return nil, store.ErrOwnerBootstrapRejected
	}
	digest := sha256.Sum256(packet)
	proofDigest := hex.EncodeToString(digest[:])
	preflight, e := s.store.PreflightOwnerBootstrap(public.Route, proofDigest)
	if e != nil {
		return nil, e
	}
	p := preflight.Pairing
	if !reflect.DeepEqual(p.Hub.Public, s.identities.ClientControl.Public()) {
		return nil, store.ErrOwnerBootstrapRejected
	}
	if len(preflight.CachedReceipt) > 0 {
		return preflight.CachedReceipt, nil
	}
	// Preflight is only an early rejection. Completion below checks the
	// current account, expiry and permanent root fence in its transaction.
	nonce, e := ownerbootstrap.VerifyProof(s.identities.ClientControl, *p, packet, time.Time{})
	if e != nil {
		return nil, store.ErrOwnerBootstrapRejected
	}
	m := p.Manifest
	r := ownerbootstrap.Receipt{Format: ownerbootstrap.Format, ManifestDigest: m.Digest(), AuthorityID: m.AuthorityID, AccountID: m.AccountID, OwnerID: m.OwnerID, KeyID: m.CandidatePublic.ID, State: store.OwnerApprovalKeyActive, Version: 1}
	receipt, e := ownerbootstrap.CreateReceipt(s.identities.ClientControl, *p, r)
	if e != nil {
		return nil, errors.New("Owner bootstrap receipt is unavailable")
	}
	return s.store.CompleteOwnerBootstrap(identity, nonce, proofDigest, receipt)
}
