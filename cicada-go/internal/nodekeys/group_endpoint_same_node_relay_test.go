package nodekeys

import (
	"context"
	"testing"
	"time"
)

func TestGroupEndpointPinSameNodeRelayRetainsGuards(t *testing.T) {
	f := newGroupEndpointKeyPinFixture(t, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	trustGroupEndpointKeyPinFixtureOwner(t, f)
	f.evidence.Local.NodeID = f.evidence.Grant.Manifest.NodeID
	if _, err := f.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), f.evidence); err != nil {
		t.Fatal(err)
	}
	self := f.evidence
	self.Local.EndpointID = self.Peer.EndpointID
	if _, err := f.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), self); err == nil {
		t.Fatal("self Endpoint pin accepted")
	}
	bad := f.evidence
	bad.Local.OwnerID = "foreign-owner"
	if _, err := f.state.PinOwnerGrantedGroupEndpointPeerKey(context.Background(), bad); err == nil {
		t.Fatal("foreign Owner pin accepted")
	}
}
