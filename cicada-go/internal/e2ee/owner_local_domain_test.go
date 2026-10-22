package e2ee

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func syntheticLocalDomain(t *testing.T) (*Identity, *Identity, LocalDomainPolicy, OwnerAppNodeScope, time.Time) {
	t.Helper()
	owner, claims, now := syntheticNativePairClaims(t)
	node, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	scope, binding := claims[0].Scope.Actor, claims[0].Scope.Node
	binding.NodeName = "Synthetic local Node"
	binding.NodePublic = node.Public()
	p := LocalDomainPolicy{Version: 1, PolicyID: strings.Repeat("1", 32), Epoch: 1, Origin: scope.Origin, HubID: scope.HubID, HubFingerprint: scope.HubFingerprint, OwnerID: scope.OwnerID, OwnerPublic: owner.Public(), OwnerKeyVersion: scope.OwnerKeyVersion, Node: binding, NodeControlBindingVersion: 1, CredentialCommitment: strings.Repeat("a", 64), LocalUserScope: "uid:1000", NetworkID: "synthetic-local-network", NetworkName: "Synthetic local", CreateNetwork: true, GroupID: "synthetic-local-group", GroupName: "Synthetic local group", Rights: LocalDomainRights(), IssuedAt: now.Format(time.RFC3339Nano), PrepareRequestID: strings.Repeat("2", 32), PreparePacketDigest: strings.Repeat("b", 64), ServerNonce: strings.Repeat("c", 64)}
	return owner, node, p, scope, now
}

func TestLocalDomainPersistentPolicyAndShortRequestAreIndependent(t *testing.T) {
	owner, _, p, scope, now := syntheticLocalDomain(t)
	policyProof, err := SignOwnerLocalDomainPolicy(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyOwnerLocalDomainPolicy(owner.Public(), policyProof, now.AddDate(10, 0, 0))
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("persistent delegation depended on a login or fixed duration", err)
	}
	digest, _ := LocalDomainPolicyDigest(p)
	c := OwnerLocalDomainRequestClaims{Version: 1, Purpose: OwnerLocalDomainActivatePurpose, Scope: scope, RequestID: strings.Repeat("3", 32), Nonce: strings.Repeat("d", 64), IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), PolicyID: p.PolicyID, PolicyEpoch: p.Epoch, PolicyDigest: digest, ExpectedRevision: 1}
	raw, err := SignOwnerLocalDomainRequest(owner, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyOwnerLocalDomainRequest(owner.Public(), raw, OwnerLocalDomainActivatePurpose, now); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyOwnerLocalDomainRequest(owner.Public(), raw, OwnerLocalDomainActivatePurpose, now.Add(5*time.Minute)); err == nil {
		t.Fatal("short activation proof was admitted after expiry")
	}
	if _, err = VerifyOwnerLocalDomainRequest(owner.Public(), policyProof, OwnerLocalDomainActivatePurpose, now); err == nil {
		t.Fatal("persistent policy proof was accepted as short request proof")
	}
	if _, err = VerifyOwnerLocalDomainPolicy(owner.Public(), raw, now); err == nil {
		t.Fatal("short request became a persistent delegation")
	}
	p.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339Nano)
	raw, err = SignOwnerLocalDomainPolicy(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyOwnerLocalDomainPolicy(owner.Public(), raw, now.Add(time.Hour)); err == nil {
		t.Fatal("optional policy expiry was ignored")
	}
}

func TestLocalDomainDelegationCannotWidenOrImpersonateOwner(t *testing.T) {
	owner, node, p, _, now := syntheticLocalDomain(t)
	raw, err := SignOwnerLocalDomainPolicy(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*LocalDomainPolicy){
		func(c *LocalDomainPolicy) { c.LocalUserScope = "uid:1001" },
		func(c *LocalDomainPolicy) { c.NetworkID = "synthetic-other-network" },
		func(c *LocalDomainPolicy) { c.GroupID = "synthetic-other-group" },
		func(c *LocalDomainPolicy) { c.Node.NodeKeyEpoch++ },
		func(c *LocalDomainPolicy) { c.Epoch++ },
		func(c *LocalDomainPolicy) { c.Rights = append(c.Rights, "NETWORK_ADMIN") },
	} {
		var proof OwnerLocalDomainPolicyProof
		if json.Unmarshal(raw, &proof) != nil {
			t.Fatal("fixture decode")
		}
		change(&proof.Policy)
		tampered, _ := json.Marshal(proof)
		if _, err := VerifyOwnerLocalDomainPolicy(owner.Public(), tampered, now); err == nil {
			t.Fatal("tampered delegation was accepted")
		}
	}
	if _, err = SignOwnerLocalDomainPolicy(node, p); err == nil {
		t.Fatal("Node signed as Owner")
	}
	if _, err = VerifyOwnerNativePair(owner.Public(), raw, OwnerNativePairBootstrapCommit, now); err == nil {
		t.Fatal("domain delegation became Pair consent")
	}
	digest, _ := LocalDomainPolicyDigest(p)
	c := LocalDomainEndpointKeyClaims{Version: 1, Purpose: LocalDomainEndpointKeyPurpose, PolicyID: p.PolicyID, PolicyEpoch: p.Epoch, PolicyDigest: digest, MemberID: "synthetic-member", MemberRevision: 1, ManifestDigest: strings.Repeat("e", 64), CandidateBindingDigest: strings.Repeat("f", 64), IssuedAt: p.IssuedAt}
	keyProof, err := SignLocalDomainEndpointKey(node, p, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyLocalDomainEndpointKey(p, keyProof, now.AddDate(1, 0, 0)); err != nil {
		t.Fatal("persistent Node key certification expired with a request", err)
	}
	if _, err = SignLocalDomainEndpointKey(owner, p, c); err == nil {
		t.Fatal("wrong signer issued Node key certification")
	}
	p.Node.NodeKeyEpoch++
	if _, err = VerifyLocalDomainEndpointKey(p, keyProof, now); err == nil {
		t.Fatal("old Node key certification survived authority epoch change")
	}
}

func TestLocalDomainUserReportUsesExactNodeAndShortLifetime(t *testing.T) {
	_, node, p, _, now := syntheticLocalDomain(t)
	r := LocalDomainUserReport{Version: 1, Purpose: LocalDomainUserReportPurpose, HubID: p.HubID, OwnerID: p.OwnerID, NodeID: p.Node.NodeID, OwnerBindingID: p.Node.OwnerBindingID, NodeKeyEpoch: p.Node.NodeKeyEpoch, LocalUserScope: p.LocalUserScope, IssuedAt: p.IssuedAt, ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), Nonce: strings.Repeat("a", 64)}
	raw, err := SignLocalDomainUserReport(node, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyLocalDomainUserReport(p.Node, raw, now); err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyLocalDomainUserReport(p.Node, raw, now.Add(5*time.Minute)); err == nil {
		t.Fatal("stale user report admitted a new policy")
	}
	other := p.Node
	other.NodeID = "synthetic-other-node"
	if _, err = VerifyLocalDomainUserReport(other, raw, now); err == nil {
		t.Fatal("report moved to another Node")
	}
	other = p.Node
	other.NodeKeyEpoch++
	if _, err = VerifyLocalDomainUserReport(other, raw, now); err == nil {
		t.Fatal("report survived a Node key epoch change")
	}
	for _, s := range []string{"uid:01000", "uid:-1", "uid:4294967296", "uid:1000 ", "uid:", "1000"} {
		if ValidLocalDomainUserScope(s) {
			t.Fatalf("noncanonical user scope accepted: %s", s)
		}
	}
	if !ValidLocalDomainUserScope("uid:0") || !ValidLocalDomainUserScope("uid:1000") {
		t.Fatal("canonical user scope refused")
	}
}
