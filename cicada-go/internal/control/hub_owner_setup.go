package control

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
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/store"
)

// ManagerOwnerID is the persisted human association, never a crypto key ID
// comparison. Legacy installations may retain their old human ID unchanged.
func (c *Control) ManagerOwnerID() string {
	if c == nil {
		return ""
	}
	return c.managerOwnerID
}

func (c *Control) HubOwnerSetup() (*store.HubOwnerSetup, error) {
	if c == nil || c.store == nil {
		return nil, store.ErrHubOwnerSetupConflict
	}
	return c.store.GetHubOwnerSetup()
}

// IssueOwnerBootstrapLocal is only for the independently controlled local
// deployment CLI. No public, bearer, Node or model route exposes this method.
func (c *Control) IssueOwnerBootstrapLocal(candidate e2ee.PublicIdentity, expectedFingerprint string) (*ownerbootstrap.PairingFile, error) {
	if c == nil || c.store == nil || c.clientIdentity == nil || e2ee.ValidatePublicIdentity(candidate) != nil || expectedFingerprint != ownerbootstrap.Fingerprint(candidate) {
		return nil, store.ErrOwnerBootstrapRejected
	}
	for _, identity := range []*e2ee.Identity{c.identity, c.clientIdentity, c.nodeControlIdentity} {
		if identity != nil && identity.Public().ID == candidate.ID {
			return nil, store.ErrOwnerBootstrapRejected
		}
	}
	setup, e := c.store.GetHubOwnerSetup()
	if e != nil {
		return nil, e
	}
	if setup == nil || setup.State != store.HubOwnerReady || setup.RootEverEstablished || c.ValidateClientOwnerScope(setup.OwnerID) != nil {
		return nil, store.ErrOwnerBootstrapRejected
	}
	current, e := c.store.CurrentOwnerBootstrapPairing()
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
		Hub:      ownerbootstrap.HubIdentity{Contract: "android-hub-v1", HubID: setup.HubID, Public: c.clientIdentity.Public(), KeyVersion: 1, Suite: ownerbootstrap.Suite},
		Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: setup.AccountID, OwnerID: setup.OwnerID, HubID: setup.HubID, AuthorityID: store.NewID("root"), OperationID: store.NewID("bootstrap"), CandidatePublic: candidate, CandidateFingerprint: expectedFingerprint, ExpiresAt: at.Add(ownerbootstrap.MaxLifetime).Format(time.RFC3339Nano)}}
	p, nonce, e := ownerbootstrap.CreateChallenge(c.clientIdentity, p, at)
	if e != nil {
		return nil, e
	}
	return c.store.IssueOwnerBootstrapLocal(p, nonce)
}

// AcceptOwnerBootstrap verifies only an already stored finite authority. It
// neither enrolls a Client nor dispatches management business operations.
func (c *Control) AcceptOwnerBootstrap(packet []byte) ([]byte, error) {
	if c == nil || c.store == nil || c.clientIdentity == nil || len(packet) == 0 || len(packet) > 256*1024 {
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
	preflight, e := c.store.PreflightOwnerBootstrap(public.Route, proofDigest)
	if e != nil {
		return nil, e
	}
	p := preflight.Pairing
	if !reflect.DeepEqual(p.Hub.Public, c.clientIdentity.Public()) {
		return nil, store.ErrOwnerBootstrapRejected
	}
	if len(preflight.CachedReceipt) > 0 {
		return preflight.CachedReceipt, nil
	}
	// Preflight is only an early rejection. Completion below checks the
	// current account, expiry and permanent root fence in its transaction.
	nonce, e := ownerbootstrap.VerifyProof(c.clientIdentity, *p, packet, time.Time{})
	if e != nil {
		return nil, store.ErrOwnerBootstrapRejected
	}
	m := p.Manifest
	r := ownerbootstrap.Receipt{Format: ownerbootstrap.Format, ManifestDigest: m.Digest(), AuthorityID: m.AuthorityID, AccountID: m.AccountID, OwnerID: m.OwnerID, KeyID: m.CandidatePublic.ID, State: store.OwnerApprovalKeyActive, Version: 1}
	receipt, e := ownerbootstrap.CreateReceipt(c.clientIdentity, *p, r)
	if e != nil {
		return nil, errors.New("Owner bootstrap receipt is unavailable")
	}
	return c.store.CompleteOwnerBootstrap(identity, nonce, proofDigest, receipt)
}
