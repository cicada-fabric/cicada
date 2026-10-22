package nodekeys

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type localDomainKeyFixture struct {
	f       *nativePairStateFixture
	policy  e2ee.LocalDomainPolicy
	proof   []byte
	node    *e2ee.Identity
	grants  [2]wire.LocalDomainEndpointKeyGrant
	current wire.LocalDomainCurrent
}

func localDomainKeys(t *testing.T, trust bool) *localDomainKeyFixture {
	t.Helper()
	f := newNativePairStateFixture(t, trust)
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := f.scope.Node
	n.NodePublic = node.Public()
	n.NodeKeyFingerprint = nodewire.IdentityFingerprint(n.NodePublic)
	p := e2ee.LocalDomainPolicy{Version: 1, PolicyID: strings.Repeat("1", 32), Epoch: 1, Origin: f.scope.Actor.Origin, HubID: f.hub.HubID, HubFingerprint: f.scope.Actor.HubFingerprint, OwnerID: f.scope.Actor.OwnerID, OwnerPublic: f.owner.Public(), OwnerKeyVersion: f.scope.Actor.OwnerKeyVersion, Node: n, NodeControlBindingVersion: f.scope.NodeControlBindingVersion, CredentialCommitment: f.scope.CredentialCommitment, LocalUserScope: "uid:1000", NetworkID: f.evidence.Plan.NetworkID, NetworkName: "Synthetic domain Network", CreateNetwork: true, GroupID: f.evidence.Plan.GroupID, GroupName: "Synthetic domain Group", Rights: e2ee.LocalDomainRights(), IssuedAt: f.now.UTC().Format(time.RFC3339Nano), PrepareRequestID: strings.Repeat("2", 32), PreparePacketDigest: strings.Repeat("3", 64), ServerNonce: strings.Repeat("4", 64)}
	proof, err := e2ee.SignOwnerLocalDomainPolicy(f.owner, p)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := wire.LocalDomainSelectionForPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	x := &localDomainKeyFixture{f: f, policy: p, proof: proof, node: node}
	for i, slot := range []wire.NativePairSlot{f.evidence.Plan.SlotA, f.evidence.Plan.SlotB} {
		k := f.evidence.Plan.SlotAKeyManifest
		if i == 1 {
			k = f.evidence.Plan.SlotBKeyManifest
		}
		raw, _ := json.Marshal(k)
		var manifest wire.LocalDomainKeyManifest
		if json.Unmarshal(raw, &manifest) != nil {
			t.Fatal("synthetic manifest")
		}
		manifest.ExpiresAt = ""
		manifest.IssuedAt = p.IssuedAt
		manifest.CandidateBindingDigest, err = wire.LocalDomainGroupBindingDigest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Digest, err = wire.LocalDomainGroupManifestDigest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		m := wire.LocalDomainMember{MemberID: "synthetic-domain-member-" + slot.Slot, Selection: selection, Revision: 2, State: wire.LocalDomainMemberActive, NodeID: n.NodeID, LocalUserScope: p.LocalUserScope, NativeSessionID: slot.NativeSessionID, Runtime: "codex", Workspace: "/synthetic/domain/" + slot.Slot, EndpointID: slot.EndpointID, PrincipalID: slot.PrincipalID, BindingID: slot.BindingID, BindingEpoch: slot.BindingEpoch, NetworkAccessBindingID: slot.NetworkAccessBindingID, NetworkAccessEpoch: slot.NetworkAccessEpoch, NetworkMembershipRevision: slot.NetworkMembershipRevision, EndpointNetworkRevision: slot.EndpointNetworkRevision, MembershipRevision: uint64(manifest.MembershipRevision), EndpointJoinRevision: slot.EndpointJoinRevision, LeaseOwner: slot.LeaseOwner, CandidateVersion: uint64(manifest.CandidateVersion), CandidateKeyID: manifest.CandidateKeyID, CandidateFingerprint: manifest.CandidateFingerprint, CandidateProofDigest: manifest.CandidateProofDigest}
		memberDigest, err := wire.LocalDomainMemberDigest(m)
		if err != nil {
			t.Fatal(err)
		}
		c := e2ee.LocalDomainEndpointKeyClaims{Version: 1, Purpose: e2ee.LocalDomainEndpointKeyPurpose, PolicyID: p.PolicyID, PolicyEpoch: p.Epoch, PolicyDigest: selection.PolicyDigest, MemberID: m.MemberID, MemberRevision: m.Revision, MemberDigest: memberDigest, ManifestDigest: manifest.Digest, CandidateBindingDigest: manifest.CandidateBindingDigest, IssuedAt: manifest.IssuedAt}
		signature, e := e2ee.SignLocalDomainEndpointKey(node, p, c)
		if e != nil {
			t.Fatal(e)
		}
		x.grants[i] = wire.LocalDomainEndpointKeyGrant{ContractRevision: wire.LocalDomainContractRevision, Member: m, Manifest: manifest, PolicyProof: proof, NodeProof: signature}
		if _, e = wire.VerifyLocalDomainEndpointKeyGrant(x.grants[i], f.hub, p.OwnerID, f.owner.Public(), f.now); e != nil {
			t.Fatal("synthetic real delegated chain", e)
		}
	}
	x.current = wire.LocalDomainCurrent{ContractRevision: wire.LocalDomainContractRevision, Selection: selection, Revision: 2, State: "CURRENT", Operation: "peer_key", AttemptID: x.grants[0].Member.EndpointID + ":" + x.grants[1].Member.EndpointID, Sender: x.grants[0].Member, Receiver: x.grants[1].Member, ObservedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: f.now.Add(30 * time.Second).Format(time.RFC3339Nano)}
	return x
}

func (x *localDomainKeyFixture) require(t *testing.T) {
	t.Helper()
	if _, err := x.f.state.RequireLocalDomainPolicy(context.Background(), x.f.hub, x.policy, x.proof, x.f.now); err != nil {
		t.Fatal(err)
	}
}

func TestLocalDomainIndependentOwnerPinAndPersistentMarker(t *testing.T) {
	x := localDomainKeys(t, false)
	ctx := context.Background()
	if _, err := x.f.state.RequireLocalDomainPolicy(ctx, x.f.hub, x.policy, x.proof, x.f.now); !errors.Is(err, ErrLocalDomainPolicy) {
		t.Fatal("policy bootstrapped its own Owner trust", err)
	}
	if yes, err := x.f.state.LocalDomainPolicyRequired(ctx, x.policy.GroupID); err != nil || yes {
		t.Fatal("failed proof left authority marker", err)
	}
	fp, _ := PeerKeyFingerprint(x.f.owner.Public())
	if _, err := x.f.state.TrustOwnerApprovalKeyLocal(x.policy.OwnerID, x.policy.OwnerPublic.ID, x.f.owner.Public(), fp); err != nil {
		t.Fatal(err)
	}
	x.require(t)
	if required, err := x.f.state.VerifyLocalDomainGroupAuthorization(ctx, x.policy.GroupID, nil, nil, nil, "peer_key", x.current.AttemptID, x.f.now); !required || !errors.Is(err, ErrLocalDomainPolicy) {
		t.Fatal("omitted domain evidence downgraded to legacy", err)
	}
	if err := x.f.state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err := OpenCryptoState(x.f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	x.f.state = state
	if required, err := state.VerifyLocalDomainGroupAuthorization(ctx, x.policy.GroupID, &x.grants[0], &x.grants[1], &x.current, x.current.Operation, x.current.AttemptID, x.f.now); err != nil || !required {
		t.Fatal("persisted full chain did not recover", err)
	}
}

func TestLocalDomainNodePinChecksFullOwnerCurrentAndLocalRevokeRace(t *testing.T) {
	x := localDomainKeys(t, true)
	x.require(t)
	ctx := context.Background()
	s := x.f.state
	if _, err := s.VerifyLocalDomainGroupAuthorization(ctx, x.policy.GroupID, &x.grants[0], &x.grants[1], &x.current, "peer_key", x.current.AttemptID, x.f.now); err != nil {
		t.Fatal(err)
	}
	changed := x.current
	changed.AttemptID += "-different"
	if _, err := s.VerifyLocalDomainGroupAuthorization(ctx, x.policy.GroupID, &x.grants[0], &x.grants[1], &changed, "peer_key", x.current.AttemptID, x.f.now); err == nil {
		t.Fatal("Current reused for another operation/attempt")
	}
	if _, err := s.VerifyLocalDomainGroupAuthorization(ctx, x.policy.GroupID, &x.grants[0], &x.grants[1], &x.current, "peer_key", x.current.AttemptID, x.f.now.Add(31*time.Second)); err == nil {
		t.Fatal("expired Current remained authorized")
	}
	wrong, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bad := x.policy
	bad.OwnerPublic = wrong.Public()
	bad.OwnerPublic.ID = x.policy.OwnerPublic.ID
	if _, err = s.RequireLocalDomainPolicy(ctx, x.f.hub, bad, x.proof, x.f.now); err == nil {
		t.Fatal("same key ID with a different full Owner public key trusted")
	}
	trust, err := s.GetNodeOwnerKeyTrustLocal(x.policy.OwnerID, x.policy.OwnerPublic.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeNodeOwnerKeyTrustLocal(trust.OwnerID, trust.KeyID, trust.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PinLocalDomainPeer(ctx, x.grants[0].Member.EndpointID, x.grants[0], x.grants[1], x.current, "peer_key", x.current.AttemptID, x.f.now); err == nil {
		t.Fatal("local Owner revocation between verification and writer pin was ignored")
	}
	var count int
	if s.db.QueryRow(`SELECT count(*) FROM node_crypto_peer_pins`).Scan(&count) != nil || count != 0 {
		t.Fatal("revoked pin race partially committed peer trust")
	}
}

func TestLocalDomainPeerPinPreservesIdentityAndRejectsRollback(t *testing.T) {
	x := localDomainKeys(t, true)
	x.require(t)
	ctx := context.Background()
	s := x.f.state
	pin, err := s.PinLocalDomainPeer(ctx, x.grants[0].Member.EndpointID, x.grants[0], x.grants[1], x.current, "peer_key", x.current.AttemptID, x.f.now)
	if err != nil {
		t.Fatal(err)
	}
	if pin.Scope.LocalGroupID != x.policy.GroupID || pin.BindingEpoch != x.grants[1].Member.BindingEpoch || pin.Public.ID != x.grants[1].Manifest.CandidateKeyID {
		t.Fatal("pin replaced signed candidate scope")
	}
	if _, err = s.RevokePeerPin(ctx, pin.Scope, pin.Peer, pin.Version); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PinLocalDomainPeer(ctx, x.grants[0].Member.EndpointID, x.grants[0], x.grants[1], x.current, "peer_key", x.current.AttemptID, x.f.now); !errors.Is(err, ErrPeerPinRevoked) {
		t.Fatal("domain proof revived terminal peer-pin revocation", err)
	}
}

func TestLocalDomainCompleteMemberDigestRejectsIndependentCoordinateSubstitution(t *testing.T) {
	x := localDomainKeys(t, true)
	mutations := map[string]func(*wire.LocalDomainMember){
		"sid":                func(m *wire.LocalDomainMember) { m.NativeSessionID += "-other" },
		"cwd":                func(m *wire.LocalDomainMember) { m.Workspace += "/other" },
		"access-id":          func(m *wire.LocalDomainMember) { m.NetworkAccessBindingID += "-other" },
		"access-epoch":       func(m *wire.LocalDomainMember) { m.NetworkAccessEpoch++ },
		"network-membership": func(m *wire.LocalDomainMember) { m.NetworkMembershipRevision++ },
		"endpoint-network":   func(m *wire.LocalDomainMember) { m.EndpointNetworkRevision++ },
		"lease-owner":        func(m *wire.LocalDomainMember) { m.LeaseOwner += "-other" },
		"user":               func(m *wire.LocalDomainMember) { m.LocalUserScope = "uid:1001" },
	}
	for name, change := range mutations {
		t.Run(name, func(t *testing.T) {
			g := x.grants[0]
			change(&g.Member)
			if _, err := wire.VerifyLocalDomainEndpointKeyGrant(g, x.f.hub, x.policy.OwnerID, x.f.owner.Public(), x.f.now); err == nil {
				t.Fatal("member coordinate was not signed")
			}
		})
	}
	var signed e2ee.LocalDomainEndpointKeyProof
	if json.Unmarshal(x.grants[0].NodeProof, &signed) != nil {
		t.Fatal("original Node proof")
	}
	signed.Claims.MemberDigest = ""
	raw, _ := json.Marshal(signed)
	g := x.grants[0]
	g.NodeProof = raw
	if _, err := wire.VerifyLocalDomainEndpointKeyGrant(g, x.f.hub, x.policy.OwnerID, x.f.owner.Public(), x.f.now); err == nil {
		t.Fatal("missing complete member digest accepted")
	}
}
