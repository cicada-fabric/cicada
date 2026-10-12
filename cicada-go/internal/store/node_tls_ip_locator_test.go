package store

import (
	"errors"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestNodeTLSIPLocatorNativeCurrentAuthorityAndReplacement(t *testing.T) {
	if !nodeTLSNativeRequired(t) {
		return
	}
	f := newNodeTLSNativeFixture(t)
	f.input.HubDialAddress = "192.0.2.1:7443"
	r, err := f.s.ReserveNodeTLSCandidate(f.input)
	if err != nil {
		t.Fatal(err)
	}
	if r.Claims.Version != 2 || r.Claims.HubDialAddress != f.input.HubDialAddress {
		t.Fatal("locator absent from reserved approval")
	}
	bad := f.input
	bad.HubDialAddress = "192.0.2.2:7443"
	if _, err := f.s.ReserveNodeTLSCandidate(bad); !errors.Is(err, ErrNodeTLSAuthorityConflict) {
		t.Fatal("reserved locator substituted", err)
	}
	altered := r.Claims
	altered.HubDialAddress = bad.HubDialAddress
	badGrant, err := e2ee.SignOwnerTLSLeafGrant(f.owner, altered)
	if err != nil {
		t.Fatal(err)
	}
	action := NodeTLSAuthorityActionInput{RequestID: r.Claims.RequestID, NodeID: r.Claims.NodeID, CredentialDigest: f.digest, ExpectedVersion: r.RowVersion}
	if _, err := f.s.BeginNodeTLSLeafIssue(NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: badGrant}); !errors.Is(err, ErrNodeTLSAuthorityDenied) {
		t.Fatal("different signed candidate admitted", err)
	}
	active := nodeTLSActivateFixture(t, f, r)
	if current, err := f.s.CurrentNodeTransportBinding(f.input.NodeID); err != nil || current.TLSAuthority == nil || current.TLSAuthority.Claims.HubDialAddress != f.input.HubDialAddress {
		t.Fatal("current authority lost locator", err)
	}
	// Locator changes consume a fresh epoch, nonce and serial with fresh Owner
	// approval. Reserving the replacement preserves the previous ACTIVE row.
	next := f.input
	next.RequestID = "synthetic_ip_replacement"
	next.ExpectedTLSEpochFloor = active.Claims.TLSEpoch
	next.GrantNonce = nodeTLSTestHash("ip-replacement-nonce")
	next.HubDialAddress = "[2001:db8::1]:7443"
	replacement, err := f.s.ReserveNodeTLSCandidate(next)
	if err != nil {
		t.Fatal(err)
	}
	if current, err := f.s.CurrentNodeTransportBinding(f.input.NodeID); err != nil || current.TLSAuthority == nil || current.TLSAuthority.Claims != active.Claims {
		t.Fatal("unactivated locator replaced ACTIVE", err)
	}
	if replacement.Claims.TLSEpoch != 2 || replacement.Claims.Serial == active.Claims.Serial {
		t.Fatal("locator replacement reused burned identity")
	}
	activated := nodeTLSActivateFixture(t, f, replacement)
	if activated.Claims.HubDialAddress != next.HubDialAddress {
		t.Fatal("activation lost replacement locator")
	}
	old, err := f.s.GetNodeTLSAuthorityReservationLocal(active.Claims.RequestID)
	if err != nil || old.State != NodeTLSRevoked || old.Claims != active.Claims {
		t.Fatal("old locator authority/history not retained", err)
	}
}
