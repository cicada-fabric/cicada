package ownerbootstrap

import (
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

func syntheticPair(t *testing.T) (*e2ee.Identity, *e2ee.Identity, PairingFile) {
	t.Helper()
	hub, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	owner, e := e2ee.NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	p := PairingFile{Format: Format, Origin: "https://synthetic.invalid", Hub: HubIdentity{Contract: "android-hub-v1", HubID: "synthetic-hub", Public: hub.Public(), KeyVersion: 1, Suite: Suite}, Manifest: Manifest{Version: 1, Purpose: Purpose, AccountID: "synthetic-account", OwnerID: "synthetic-owner", HubID: "synthetic-hub", AuthorityID: "synthetic-authority", OperationID: "synthetic-operation", CandidatePublic: owner.Public(), CandidateFingerprint: Fingerprint(owner.Public()), ExpiresAt: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)}}
	p, _, e = CreateChallenge(hub, p, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	return hub, owner, p
}

func TestOwnerBootstrapProtocolFullScopeAndPossession(t *testing.T) {
	hub, owner, p := syntheticPair(t)
	proof, e := CreateProof(owner, p, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyProof(hub, p, proof, time.Now()); e != nil {
		t.Fatal(e)
	}
	for _, mutate := range []func(*PairingFile){
		func(p *PairingFile) { p.Manifest.Purpose = "CLIENT_ENROLL" },
		func(p *PairingFile) { p.Manifest.AccountID = "another-account" },
		func(p *PairingFile) { p.Manifest.OwnerID = "another-owner" },
		func(p *PairingFile) { p.Manifest.AuthorityID = "another-authority" },
		func(p *PairingFile) { p.Manifest.OperationID = "another-operation" },
		func(p *PairingFile) { p.Manifest.HubID = "another-hub" },
		func(p *PairingFile) {
			p.Manifest.ExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
		},
		func(p *PairingFile) { p.Manifest.CandidateFingerprint = "synthetic-wrong-fingerprint" },
	} {
		changed := p
		mutate(&changed)
		if _, e = CreateProof(owner, changed, time.Now()); e == nil {
			t.Fatal("changed pairing scope accepted")
		}
		if _, e = VerifyProof(hub, changed, proof, time.Now()); e == nil {
			t.Fatal("changed proof scope accepted")
		}
	}
	opened, e := clientwire.OpenResponse(owner, p.Hub.Public, p.Manifest.Binding(), p.Challenge)
	if e != nil {
		t.Fatal(e)
	}
	noncanonical := append([]byte(" "), opened.Plaintext...)
	noncanonicalProof, e := clientwire.SealRequest(owner, p.Hub.Public, p.Manifest.Binding(), p.Route(clientwire.DirectionRequest, 1), noncanonical)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyProof(hub, p, noncanonicalProof, time.Now()); e == nil {
		t.Fatal("different possession bytes accepted")
	}
}
