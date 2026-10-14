package ownerbootstrap

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

type bootstrapPrivateOperations struct {
	identity            *e2ee.Identity
	signs, decapsulates int
}

func (o *bootstrapPrivateOperations) Sign(message []byte) ([]byte, error) {
	o.signs++
	return o.identity.Sign(message)
}
func (o *bootstrapPrivateOperations) MLKEMDecapsulate(ciphertext []byte) ([]byte, error) {
	o.decapsulates++
	return o.identity.MLKEMDecapsulate(ciphertext)
}

func TestOwnerBootstrapExternalPrivateOperationsUsePublishedVector(t *testing.T) {
	raw, e := os.ReadFile(publishedVectorPath)
	if e != nil {
		t.Fatal(e)
	}
	var v publishedBootstrapVector
	if json.Unmarshal(raw, &v) != nil {
		t.Fatal("decode public synthetic vector")
	}
	hub, e := e2ee.UnmarshalIdentity(v.Hub.Private)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := e2ee.UnmarshalIdentity(v.Owner.Private)
	if e != nil {
		t.Fatal(e)
	}
	at, e := time.Parse(time.RFC3339Nano, v.At)
	if e != nil {
		t.Fatal(e)
	}
	ops := &bootstrapPrivateOperations{identity: owner}
	proof, e := CreateProofWithPrivateOperations(owner.Public(), ops, v.Pairing, at)
	if e != nil || ops.decapsulates != 1 || ops.signs != 1 {
		t.Fatalf("external proof failed: %v", e)
	}
	nonce, e := VerifyProof(hub, v.Pairing, proof, at)
	if e != nil || nonce != v.NonceDigest {
		t.Fatal("external proof changed canonical possession scope")
	}
	var receipt *Receipt
	receipt, e = VerifyReceiptWithPrivateOperations(owner.Public(), ops, v.Pairing, []byte(v.Receipt))
	if e != nil || !reflect.DeepEqual(*receipt, v.ExpectedReceipt) || ops.decapsulates != 2 || ops.signs != 1 {
		t.Fatalf("external receipt failed: %v", e)
	}
}

func TestOwnerBootstrapExternalOperationsRejectScopeBeforePrivateUse(t *testing.T) {
	hub, owner, p := syntheticPair(t)
	route := p.Route(clientwire.DirectionResponse, 1)
	for _, change := range []func(*PairingFile){
		func(p *PairingFile) { p.Manifest.Purpose = "CLIENT_ENROLL" },
		func(p *PairingFile) { p.Manifest.OwnerID = "synthetic-other" },
		func(p *PairingFile) { p.Manifest.HubID = "synthetic-other" },
		func(p *PairingFile) { p.Manifest.AuthorityID = "synthetic-other" },
		func(p *PairingFile) { p.Manifest.OperationID = "synthetic-other" },
		func(p *PairingFile) {
			p.Manifest.ExpiresAt = time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
		},
	} {
		changed := p
		change(&changed)
		ops := &bootstrapPrivateOperations{identity: owner}
		if _, e := CreateProofWithPrivateOperations(owner.Public(), ops, changed, time.Now()); e == nil || ops.signs != 0 || ops.decapsulates != 0 {
			t.Fatal("changed bootstrap scope invoked private provider")
		}
	}
	// AccountID exists inside the authenticated encrypted possession. Its
	// mismatch is rejected after opening, before invoking the signer.
	wrongAccount := p
	wrongAccount.Manifest.AccountID = "synthetic-other"
	accountOps := &bootstrapPrivateOperations{identity: owner}
	if _, e := CreateProofWithPrivateOperations(owner.Public(), accountOps, wrongAccount, time.Now()); e == nil || accountOps.decapsulates != 1 || accountOps.signs != 0 {
		t.Fatal("encrypted account mismatch reached the signer")
	}
	wrong := route
	wrong.Sequence = 2
	packet, e := clientwire.SealResponse(hub, owner.Public(), p.Manifest.Binding(), wrong, []byte(`{}`))
	if e != nil {
		t.Fatal(e)
	}
	changed := p
	changed.Challenge = packet
	ops := &bootstrapPrivateOperations{identity: owner}
	if _, e = CreateProofWithPrivateOperations(owner.Public(), ops, changed, time.Now()); e == nil || ops.decapsulates != 0 || ops.signs != 0 {
		t.Fatal("receipt used as challenge invoked private provider")
	}
	var envelope clientwire.Packet
	if json.Unmarshal(p.Challenge, &envelope) != nil {
		t.Fatal("decode fixture")
	}
	var signed e2ee.Envelope
	if json.Unmarshal(envelope.Envelope, &signed) != nil {
		t.Fatal("decode envelope")
	}
	signed.Signature[0] ^= 1
	envelope.Envelope, _ = json.Marshal(signed)
	changed = p
	changed.Challenge, _ = json.Marshal(envelope)
	ops = &bootstrapPrivateOperations{identity: owner}
	if _, e = CreateProofWithPrivateOperations(owner.Public(), ops, changed, time.Now()); e == nil || ops.decapsulates != 0 || ops.signs != 0 {
		t.Fatal("unauthenticated Hub challenge invoked private provider")
	}
}

func TestOwnerBootstrapSplitPrivateOperationsAuthenticateReviewThenSignOnce(t *testing.T) {
	hub, owner, p := syntheticPair(t)
	ops := &bootstrapPrivateOperations{identity: owner}
	possession, e := OpenChallengeWithPrivateOperations(owner.Public(), ops, p, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	defer clear(possession)
	if ops.decapsulates != 1 || ops.signs != 0 {
		t.Fatal("challenge opening signed before local approval")
	}
	if _, e = CreateProofFromPossessionWithPrivateOperations(owner.Public(), ops, p, append([]byte(" "), possession...), time.Now()); e == nil || ops.signs != 0 {
		t.Fatal("noncanonical possession reached the signer")
	}
	changed := p
	changed.Manifest.AccountID = "synthetic-other"
	if _, e = CreateProofFromPossessionWithPrivateOperations(owner.Public(), ops, changed, possession, time.Now()); e == nil || ops.signs != 0 {
		t.Fatal("changed reviewed scope reached the signer")
	}
	proof, e := CreateProofFromPossessionWithPrivateOperations(owner.Public(), ops, p, possession, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	if ops.decapsulates != 1 || ops.signs != 1 {
		t.Fatal("split proof repeated decapsulation or signing")
	}
	if _, e = VerifyProof(hub, p, proof, time.Now()); e != nil {
		t.Fatal(e)
	}
}
