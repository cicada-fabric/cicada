package e2ee

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func syntheticEndpointGroup(t *testing.T) (*Identity, *Identity, EndpointGroupPolicy, OwnerAppNodeScope, time.Time) {
	t.Helper()
	owner, node, old, scope, now := syntheticLocalDomain(t)
	endpoint, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p := EndpointGroupPolicy{Version: 1, Purpose: OwnerEndpointGroupsPolicyPurpose, PolicyID: strings.Repeat("1", 32), Epoch: 1, Origin: old.Origin, HubID: old.HubID, HubFingerprint: old.HubFingerprint, OwnerID: old.OwnerID, OwnerPublic: old.OwnerPublic, OwnerKeyVersion: old.OwnerKeyVersion, Node: old.Node, LocalUserScope: old.LocalUserScope, NetworkID: old.NetworkID, GroupID: old.GroupID, EndpointID: "synthetic-endpoint", PrincipalID: "synthetic-agent", RegistrationDigest: strings.Repeat("2", 64), RegistrationRevision: 1, BindingID: "synthetic-original-binding", BindingEpoch: 1, EndpointKeyID: endpoint.Public().ID, EndpointPublic: endpoint.Public(), EndpointFingerprint: endpointGroupPeerFingerprint(endpoint.Public()), CandidateVersion: 1, CandidateProofDigest: strings.Repeat("3", 64), ExpectedOwnerControlDigest: strings.Repeat("4", 64), Rights: EndpointGroupRights(), IssuedAt: now.Format(time.RFC3339Nano), ReviewID: strings.Repeat("5", 32), ReviewDigest: strings.Repeat("6", 64), ServerNonce: strings.Repeat("7", 64)}
	return owner, node, p, scope, now
}

func TestOwnerEndpointGroupsProofFamiliesAndLifetime(t *testing.T) {
	owner, node, p, scope, now := syntheticEndpointGroup(t)
	policy, err := SignOwnerEndpointGroupPolicy(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyOwnerEndpointGroupPolicy(owner.Public(), policy, now.AddDate(10, 0, 0)); err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal("until-revoked policy depended on a request lifetime", err)
	}
	c := OwnerEndpointGroupsRequestClaims{Version: 1, Purpose: "owner-endpoint-groups-apply:v1", Scope: scope, RequestID: strings.Repeat("a", 32), Nonce: strings.Repeat("b", 64), IssuedAt: p.IssuedAt, ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano), BodyDigest: strings.Repeat("c", 64)}
	request, err := SignOwnerEndpointGroupsRequest(owner, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyOwnerEndpointGroupsRequest(owner.Public(), request, c.Purpose, now); err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []string{"owner-endpoint-groups-read:v1", OwnerLocalDomainActivatePurpose, OwnerEndpointGroupsPolicyPurpose, "owner-endpoint-groups-apply:v2"} {
		if _, err := VerifyOwnerEndpointGroupsRequest(owner.Public(), request, purpose, now); err == nil {
			t.Fatal("cross-purpose request accepted")
		}
	}
	if _, err = VerifyOwnerEndpointGroupsRequest(owner.Public(), request, c.Purpose, now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired request accepted")
	}
	if _, err = VerifyOwnerEndpointGroupPolicy(owner.Public(), request, now); err == nil {
		t.Fatal("request became policy")
	}
	if _, err = VerifyOwnerLocalDomainPolicy(owner.Public(), policy, now); err == nil {
		t.Fatal("new policy became legacy default authority")
	}
	if _, err = SignOwnerEndpointGroupPolicy(node, p); err == nil {
		t.Fatal("Node forged Owner signature")
	}
	if _, err = VerifyOwnerEndpointGroupPolicy(node.Public(), policy, now); err == nil {
		t.Fatal("arriving policy replaced independent Owner pin")
	}
	p.ExpiresAt = now.Add(24 * time.Hour).Format(time.RFC3339Nano)
	finite, err := SignOwnerEndpointGroupPolicy(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyOwnerEndpointGroupPolicy(owner.Public(), finite, now.Add(24*time.Hour)); err == nil {
		t.Fatal("finite policy outlived its exact expiry")
	}
	if _, err = VerifyOwnerEndpointGroupPolicy(owner.Public(), finite, time.Time{}); err != nil {
		t.Fatal("historical verification failed", err)
	}
}

func TestOwnerEndpointGroupsPolicyAndRequestStrictNegatives(t *testing.T) {
	owner, _, p, scope, now := syntheticEndpointGroup(t)
	raw, err := SignOwnerEndpointGroupPolicy(owner, p)
	if err != nil {
		t.Fatal(err)
	}
	changes := []func(*EndpointGroupPolicy){
		func(p *EndpointGroupPolicy) { p.Rights = append(p.Rights, "task.create") },
		func(p *EndpointGroupPolicy) { p.EndpointID = "synthetic-other-endpoint" },
		func(p *EndpointGroupPolicy) { p.BindingEpoch++ },
		func(p *EndpointGroupPolicy) { p.ExpectedDecisionRevision++ },
		func(p *EndpointGroupPolicy) { p.ExpectedOwnerControlDigest = strings.Repeat("a", 64) },
		func(p *EndpointGroupPolicy) { p.Node.NodeKeyEpoch++ },
		func(p *EndpointGroupPolicy) { p.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339Nano) },
		func(p *EndpointGroupPolicy) { p.Purpose = OwnerLocalDomainPolicyPurpose },
	}
	for i, change := range changes {
		var proof OwnerEndpointGroupPolicyProof
		json.Unmarshal(raw, &proof)
		change(&proof.Policy)
		tampered, _ := json.Marshal(proof)
		if _, err := VerifyOwnerEndpointGroupPolicy(owner.Public(), tampered, now); err == nil {
			t.Fatalf("tamper %d accepted", i)
		}
	}
	for _, change := range []func(*EndpointGroupPolicy){
		func(p *EndpointGroupPolicy) { p.Version = 2 }, func(p *EndpointGroupPolicy) { p.Epoch = 1 << 63 },
		func(p *EndpointGroupPolicy) { p.Rights = []string{"*"} }, func(p *EndpointGroupPolicy) { p.EndpointFingerprint = strings.Repeat("a", 64) },
		func(p *EndpointGroupPolicy) { p.LocalUserScope = "uid:01000" }, func(p *EndpointGroupPolicy) { p.IssuedAt = "2026-10-26T00:00:00+00:00" },
	} {
		cp := p
		change(&cp)
		if _, err := SignOwnerEndpointGroupPolicy(owner, cp); err == nil {
			t.Fatal("Owner signature admitted invalid/wider claims")
		}
	}
	for _, bad := range [][]byte{append(append([]byte(nil), raw...), ' '), []byte(strings.Replace(string(raw), `"purpose":`, `"unknown":0,"purpose":`, 1)), []byte(strings.Replace(string(raw), `"version":1`, `"version":1,"version":1`, 1)), []byte(strings.Replace(string(raw), `"epoch":1`, `"epoch":1.0`, 1)), append(raw, make([]byte, MaxEndpointGroupProofBytes)...)} {
		if _, err := VerifyOwnerEndpointGroupPolicy(owner.Public(), bad, now); err == nil {
			t.Fatal("noncanonical/unknown/oversized proof accepted")
		}
	}
	c := OwnerEndpointGroupsRequestClaims{Version: 1, Purpose: "owner-endpoint-groups-read:v1", Scope: scope, RequestID: strings.Repeat("a", 32), Nonce: strings.Repeat("b", 64), IssuedAt: p.IssuedAt, ExpiresAt: now.Add(301 * time.Second).Format(time.RFC3339Nano), BodyDigest: strings.Repeat("c", 64)}
	if _, err := SignOwnerEndpointGroupsRequest(owner, c); err == nil {
		t.Fatal("review proof lifetime widened")
	}
	// Existing finite Link consent still requires a real expiry. New optional
	// expiry is isolated in EndpointGroupPolicy/KeyClaims, never a legacy parser.
	if _, err := owner.SignOwnerLinkKeyGrant(p.OwnerID, "synthetic-link", strings.Repeat("a", 64), strings.Repeat("b", 64), 1, OwnerLinkGrantSideSource, now, time.Time{}); err == nil {
		t.Fatal("legacy finite Link consent accepted empty expiry")
	}
}

func TestEndpointGroupNodeProofBindsOwnerProjectionAndOriginalEpoch(t *testing.T) {
	owner, node, p, _, now := syntheticEndpointGroup(t)
	digest, _ := EndpointGroupPolicyDigest(p)
	c := EndpointGroupKeyClaims{Version: 1, Purpose: EndpointGroupKeyPurpose, HubID: p.HubID, NodeID: p.Node.NodeID, NodeKeyEpoch: p.Node.NodeKeyEpoch, PolicyID: p.PolicyID, PolicyEpoch: p.Epoch, PolicyDigest: digest, RegistrationDigest: p.RegistrationDigest, OwnerControlDigest: strings.Repeat("a", 64), RelationDigest: strings.Repeat("b", 64), ManifestDigest: strings.Repeat("c", 64), CandidateBindingDigest: strings.Repeat("d", 64), ChallengeID: strings.Repeat("e", 32), ChallengeDigest: strings.Repeat("f", 64), IssuedAt: p.IssuedAt}
	raw, err := SignEndpointGroupKey(node, p, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEndpointGroupKey(p, raw, now.AddDate(1, 0, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := SignEndpointGroupKey(owner, p, c); err == nil {
		t.Fatal("Owner forged Node proof")
	}
	for _, change := range []func(*EndpointGroupKeyClaims){func(c *EndpointGroupKeyClaims) { c.OwnerControlDigest = strings.Repeat("0", 64) }, func(c *EndpointGroupKeyClaims) { c.RelationDigest = strings.Repeat("0", 64) }, func(c *EndpointGroupKeyClaims) { c.ManifestDigest = strings.Repeat("0", 64) }, func(c *EndpointGroupKeyClaims) { c.ChallengeDigest = strings.Repeat("0", 64) }, func(c *EndpointGroupKeyClaims) { c.NodeKeyEpoch++ }} {
		var proof EndpointGroupKeyProof
		json.Unmarshal(raw, &proof)
		change(&proof.Claims)
		bad, _ := json.Marshal(proof)
		if _, err := VerifyEndpointGroupKey(p, bad, now); err == nil {
			t.Fatal("projected digest substitution accepted")
		}
	}
	p.BindingEpoch++
	if _, err := VerifyEndpointGroupKey(p, raw, now); err == nil {
		t.Fatal("old proof survived original binding epoch change")
	}
}

func TestEndpointGroupStableDenyIdentityAndOwnerControl(t *testing.T) {
	n := EndpointGroupNativeIdentity{HubID: "synthetic-hub", OwnerID: "synthetic-owner", NodeID: "synthetic-node", LocalUserScope: "uid:1000", Harness: "codex", NativeSessionID: "synthetic-original-sid", Workspace: "/synthetic/workspace"}
	digest, err := EndpointGroupNativeIdentityDigest(n)
	if err != nil {
		t.Fatal(err)
	}
	r := EndpointGroupRegistration{HubID: n.HubID, OwnerID: n.OwnerID, NodeID: n.NodeID, Harness: n.Harness, NativeSessionID: n.NativeSessionID, Workspace: n.Workspace, EndpointID: "synthetic-endpoint", PrincipalID: "synthetic-agent"}
	first, _ := EndpointGroupRegistrationDigest(r)
	r.EndpointID = "synthetic-alias"
	second, _ := EndpointGroupRegistrationDigest(r)
	if first == second {
		t.Fatal("registration did not bind Endpoint")
	}
	if again, _ := EndpointGroupNativeIdentityDigest(n); again != digest {
		t.Fatal("Endpoint replacement changed private native deny key")
	}
	initial := EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}
	removed := EndpointGroupOwnerControl{Mode: "OWNER", Revision: 1, DenyReason: "REMOVED"}
	a, _ := EndpointGroupOwnerControlDigest(digest, "synthetic-G1", initial)
	b, err := EndpointGroupOwnerControlDigest(digest, "synthetic-G1", removed)
	c, _ := EndpointGroupOwnerControlDigest(digest, "synthetic-G2", removed)
	if err != nil || a == b || b == c {
		t.Fatal("Owner-control digest omitted head/Group", err)
	}
	for _, h := range []EndpointGroupOwnerControl{{Mode: "DEFAULT", Revision: 1, DenyReason: "NONE"}, {Mode: "OWNER", Revision: 1, DenyReason: "NONE"}, {Mode: "OWNER", Revision: 1, DenyReason: "EXPIRED"}, {Mode: "OWNER", Revision: 1, DenyReason: "REMOVED", PolicyEpoch: 1}} {
		if ValidateEndpointGroupOwnerControl(h) == nil {
			t.Fatal("invalid Owner-control head accepted")
		}
	}
}
