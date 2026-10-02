package control

import (
	"bytes"
	"encoding/hex"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

// ActivateNodeTLSAuthorityLocal is a trusted local maintenance coordinator,
// never an unattended renewal right or a general RPC. The exact Owner grant
// and independently signed Node install ACK must already be persisted in D1.
// It signs with Control's actual independent application identity, performs
// Store's current-fenced CAS, and returns only independently reread committed
// current material. No private identity or uncommitted proof is returned.
func (c *Control) ActivateNodeTLSAuthorityLocal(input store.NodeTLSAuthorityActionInput, nonce string) (*store.NodeTLSAuthoritySnapshot, error) {
	if c == nil || c.store == nil || c.nodeControlIdentity == nil || input.ExpectedVersion == 0 || input.ExpectedVersion >= math.MaxInt64 || !nodeTLSActivationNonce(nonce) {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	b, err := c.store.NodeControlKeyForCredential(input.CredentialDigest, input.NodeID)
	if err != nil {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	hub, err := c.NodeControlPublicIdentity()
	if err != nil || hub.HubID != b.HubID || hub.KeyID != b.HubKeyID || hub.KeyVersion != b.HubKeyVersion || !sameNodeControlPublicIdentity(hub.PublicIdentity, b.HubPublicIdentity) {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	r, err := c.store.GetNodeTLSAuthorityReservationLocal(input.RequestID)
	if err != nil {
		return nil, err
	}
	if r.State == store.NodeTLSActive {
		return c.nodeTLSCommittedActivation(input, nonce)
	}
	claims, err := c.store.PrepareNodeTLSActivation(input, nonce)
	if err != nil {
		if errors.Is(err, store.ErrNodeTLSAuthorityConflict) {
			return c.nodeTLSCommittedActivation(input, nonce)
		}
		return nil, err
	}
	if claims.InstallAckClaims.GrantClaims.HubID != hub.HubID || claims.InstallAckClaims.GrantClaims.HubControlKeyID != hub.KeyID || claims.InstallAckClaims.GrantClaims.HubControlKeyVersion != hub.KeyVersion {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	proof, err := e2ee.SignNodeTLSActivation(c.nodeControlIdentity, claims)
	if err != nil {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	_, err = c.store.ActivateNodeTLSGrant(store.NodeTLSActivationInput{NodeTLSAuthorityActionInput: input, Activation: proof})
	if err != nil && !errors.Is(err, store.ErrNodeTLSAuthorityConflict) {
		return nil, err
	}
	// A same-intent CAS competitor may have committed first. Only the original
	// nonce+version+current tuple may recover that immutable winner's proof.
	return c.nodeTLSCommittedActivation(input, nonce)
}

func nodeTLSActivationNonce(nonce string) bool {
	raw, err := hex.DecodeString(nonce)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == nonce && nonce != strings.Repeat("0", 64)
}

func (c *Control) nodeTLSCommittedActivation(input store.NodeTLSAuthorityActionInput, nonce string) (*store.NodeTLSAuthoritySnapshot, error) {
	status, err := c.store.ReadNodeTLSAuthorityRecoveryLocal(store.NodeTLSAuthorityStatusInput{NodeID: input.NodeID, CredentialDigest: input.CredentialDigest})
	if err != nil {
		return nil, err
	}
	r := status.CurrentActive
	if status.CurrentActiveState != store.NodeTLSAuthorityCurrentVerified || r == nil || r.Claims.RequestID != input.RequestID || r.RowVersion != input.ExpectedVersion+1 {
		return nil, store.ErrNodeTLSAuthorityConflict
	}
	hub, err := c.NodeControlPublicIdentity()
	b := status.CurrentBinding
	if err != nil || b == nil || hub.HubID != b.HubID || hub.KeyVersion != b.HubKeyVersion || !sameNodeControlPublicIdentity(hub.PublicIdentity, b.HubPublicIdentity) {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	proof, err := e2ee.VerifyNodeTLSActivation(hub.PublicIdentity, time.Now().UTC(), r.Activation)
	if err != nil || proof.Nonce != nonce || proof.ActivationVersion != r.RowVersion || proof.InstallAckClaims.GrantClaims != r.Claims || proof.InstallAckDigest != e2ee.NodeTLSAuthorityDigest(r.InstallAck) {
		return nil, store.ErrNodeTLSAuthorityConflict
	}
	// Read again rather than authorize from a previously cached snapshot.
	current, err := c.store.CurrentNodeTransportBinding(input.NodeID)
	if err != nil || current.TLSAuthority == nil {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	a := current.TLSAuthority
	if a.State != store.NodeTLSActive || a.RowVersion != r.RowVersion || a.ReservationVersion != r.ReservationVersion || a.Claims != r.Claims || a.LeafDERHash != r.LeafDERHash || !bytes.Equal(a.Activation, r.Activation) || !bytes.Equal(a.InstallAck, r.InstallAck) || !bytes.Equal(a.Grant, r.Grant) || !bytes.Equal(a.CSRPEM, r.CSRPEM) || !bytes.Equal(a.IssuerChainPEM, r.IssuerChainPEM) || !bytes.Equal(a.TrustAnchorPEM, r.TrustAnchorPEM) || !bytes.Equal(a.LeafCertificatePEM, r.LeafCertificatePEM) {
		return nil, store.ErrNodeTLSAuthorityDenied
	}
	return a, nil
}
