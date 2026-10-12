package e2ee

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func tlsIPGrantFixture(t *testing.T) (OwnerTLSLeafGrantClaims, *Identity, *Identity, *Identity, time.Time) {
	t.Helper()
	create := func() *Identity {
		i, e := NewIdentity()
		if e != nil {
			t.Fatal(e)
		}
		return i
	}
	owner, node, hub := create(), create(), create()
	at := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	hash := strings.Repeat("a", 64)
	c := OwnerTLSLeafGrantClaims{Version: 2, RequestID: "SYNTHETIC-IP-TEST-ONLY", HubID: "synthetic-hub", NodeID: "synthetic-node", OwnerID: "synthetic-owner", OwnerKeyID: owner.Public().ID, OwnerKeyVersion: 1, ClientDeviceID: "synthetic-device", ClientDeviceVersion: 1, OwnerBindingID: "synthetic-binding", OwnerBindingVersion: 1, CredentialDigest: hash, CredentialVersion: 1, NodeControlKeyID: node.Public().ID, NodeControlKeyVersion: 1, NodeControlKeyEpoch: 1, NodeControlBindingVersion: 1, HubControlKeyID: hub.Public().ID, HubControlKeyVersion: 1, CSRDERHash: hash, SPKIDERHash: hash, IssuerSPKIHash: hash, IssuerDERHash: hash, RootDERHash: hash, IssuerGeneration: "synthetic-issuer", Role: "node", DNSName: "node.synthetic.invalid", Serial: strings.Repeat("0", 31) + "1", TLSEpoch: 1, NotBefore: at.Format(time.RFC3339), NotAfter: at.Add(time.Hour).Format(time.RFC3339), HubSPKIHash: hash, HubTrustAnchorDERHash: hash, HubPQOrigin: "https://hub.synthetic.invalid:7443", HubDialAddress: "192.0.2.1:7443", ApplicationOrigin: "https://192.0.2.1:8443", ApplicationProtocol: NodeTLSApplicationProtocol, PQProfile: NodeTLSPQProfile, IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339), Nonce: hash}
	return c, owner, node, hub, at
}
func TestOwnerTLSIPLocatorSignedAuthorityAndVersionDomains(t *testing.T) {
	c, owner, node, hub, at := tlsIPGrantFixture(t)
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			claims := c
			claims.Version = version
			if version == 1 {
				claims.HubDialAddress = ""
			}
			wire, e := SignOwnerTLSLeafGrant(owner, claims)
			if e != nil {
				t.Fatal(e)
			}
			if got, e := VerifyOwnerTLSLeafGrant(owner.Public(), at, wire); e != nil || got != claims {
				t.Fatal("approved exact grant rejected", e)
			}
			if version == 1 && bytes.Contains(wire, []byte("hub_dial_address")) {
				t.Fatal("old canonical proof gained a field")
			}
			ack := NodeTLSInstallAckClaims{Version: version, GrantClaims: claims, GrantDigest: NodeTLSAuthorityDigest(wire), ReservationVersion: 1, LeafDERHash: strings.Repeat("b", 64), IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt, Nonce: strings.Repeat("c", 64)}
			ackWire, e := SignNodeTLSInstallAck(node, ack)
			if e != nil {
				t.Fatal(e)
			}
			if got, e := VerifyNodeTLSInstallAck(node.Public(), at, ackWire); e != nil || got != ack {
				t.Fatal("exact ACK rejected", e)
			}
			active := NodeTLSActivationClaims{Version: version, InstallAckClaims: ack, InstallAckDigest: NodeTLSAuthorityDigest(ackWire), ActivationVersion: 5, IssuedAt: claims.IssuedAt, ExpiresAt: claims.ExpiresAt, Nonce: strings.Repeat("d", 64)}
			activeWire, e := SignNodeTLSActivation(hub, active)
			if e != nil {
				t.Fatal(e)
			}
			if got, e := VerifyNodeTLSActivation(hub.Public(), at, activeWire); e != nil || got != active {
				t.Fatal("exact activation rejected", e)
			}
			if version == 2 {
				// Structurally valid v2 claims signed under the original domains must fail.
				sig, e := tlsProofSignature(owner, claims.OwnerKeyID, ownerTLSLeafDomain, claims)
				if e != nil {
					t.Fatal(e)
				}
				oldDomain, _ := json.Marshal(OwnerTLSLeafGrant{claims, sig})
				if _, e := VerifyOwnerTLSLeafGrant(owner.Public(), at, oldDomain); e == nil {
					t.Fatal("v1 domain authorized v2 locator")
				}
				sig, e = tlsProofSignature(node, claims.NodeControlKeyID, nodeTLSInstallDomain, ack)
				if e != nil {
					t.Fatal(e)
				}
				oldDomain, _ = json.Marshal(NodeTLSInstallAck{ack, sig})
				if _, e := VerifyNodeTLSInstallAck(node.Public(), at, oldDomain); e == nil {
					t.Fatal("v1 domain authorized v2 ACK")
				}
				sig, e = tlsProofSignature(hub, claims.HubControlKeyID, nodeTLSActivationDomain, active)
				if e != nil {
					t.Fatal(e)
				}
				oldDomain, _ = json.Marshal(NodeTLSActivation{active, sig})
				if _, e := VerifyNodeTLSActivation(hub.Public(), at, oldDomain); e == nil {
					t.Fatal("v1 domain authorized v2 activation")
				}
				var proof OwnerTLSLeafGrant
				json.Unmarshal(wire, &proof)
				for name, mutate := range map[string]func(*OwnerTLSLeafGrantClaims){
					"ip":                func(v *OwnerTLSLeafGrantClaims) { v.HubDialAddress = "192.0.2.2:7443" },
					"port":              func(v *OwnerTLSLeafGrantClaims) { v.HubDialAddress = "192.0.2.1:7444" },
					"hub":               func(v *OwnerTLSLeafGrantClaims) { v.HubID = "foreign-hub" },
					"san":               func(v *OwnerTLSLeafGrantClaims) { v.HubPQOrigin = "https://foreign.synthetic.invalid:7443" },
					"pin":               func(v *OwnerTLSLeafGrantClaims) { v.HubSPKIHash = strings.Repeat("b", 64) },
					"epoch":             func(v *OwnerTLSLeafGrantClaims) { v.ExpectedTLSEpochFloor = 1; v.TLSEpoch = 2 },
					"version-downgrade": func(v *OwnerTLSLeafGrantClaims) { v.Version = 1; v.HubDialAddress = "" },
				} {
					t.Run(name, func(t *testing.T) {
						bad := proof
						mutate(&bad.Claims)
						changed, _ := json.Marshal(bad)
						if _, e := VerifyOwnerTLSLeafGrant(owner.Public(), at, changed); e == nil {
							t.Fatal("unsigned authority substitution accepted")
						}
					})
				}
				var a NodeTLSActivation
				json.Unmarshal(activeWire, &a)
				a.Claims.InstallAckClaims.GrantClaims.HubDialAddress = "192.0.2.2:7443"
				changed, _ := json.Marshal(a)
				if _, e := VerifyNodeTLSActivation(hub.Public(), at, changed); e == nil {
					t.Fatal("activation locator substituted")
				}
				var k NodeTLSInstallAck
				json.Unmarshal(ackWire, &k)
				k.Claims.GrantClaims.HubDialAddress = "192.0.2.2:7443"
				changed, _ = json.Marshal(k)
				if _, e := VerifyNodeTLSInstallAck(node.Public(), at, changed); e == nil {
					t.Fatal("ACK locator substituted")
				}
			}
		})
	}
	bad := c
	bad.Version = 1
	if ValidateOwnerTLSLeafGrantClaims(bad) == nil {
		t.Fatal("v1 reinterpreted IP field")
	}
	bad = c
	bad.HubDialAddress = ""
	if ValidateOwnerTLSLeafGrantClaims(bad) == nil {
		t.Fatal("v2 without exact locator accepted")
	}
	for _, addr := range []string{"[2001:db8::1]:7443", "127.0.0.1:443"} {
		bad = c
		bad.HubDialAddress = addr
		if ValidateOwnerTLSLeafGrantClaims(bad) != nil {
			t.Fatal("canonical locator rejected")
		}
	}
}

func TestOwnerTLSIPLocatorLegacyFixedProof(t *testing.T) {
	data, err := os.ReadFile("testdata/owner-tls-leaf-grant-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Notice, SourceCommit, At string
		Trusted                  PublicIdentity
		Proof                    json.RawMessage
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SourceCommit != "5fb93553e56f0f6308f8cf778c2ebe49e40e4585" || !strings.Contains(fixture.Notice, "SYNTHETIC") || bytes.Contains(fixture.Proof, []byte("hub_dial_address")) {
		t.Fatal("legacy fixture provenance changed")
	}
	at, err := time.Parse(time.RFC3339, fixture.At)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyOwnerTLSLeafGrant(fixture.Trusted, at, fixture.Proof)
	if err != nil || claims.Version != 1 || claims.HubDialAddress != "" {
		t.Fatal("original v1 signer proof no longer verifies", err)
	}
	var proof OwnerTLSLeafGrant
	if err := json.Unmarshal(fixture.Proof, &proof); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(proof)
	if err != nil || !bytes.Equal(canonical, fixture.Proof) {
		t.Fatal("legacy canonical signed bytes changed")
	}
	proof.Claims.Version = 2
	proof.Claims.HubDialAddress = "192.0.2.1:7443"
	rewritten, _ := json.Marshal(proof)
	if _, err := VerifyOwnerTLSLeafGrant(fixture.Trusted, at, rewritten); err == nil {
		t.Fatal("original v1 proof silently became v2 authority")
	}
}
