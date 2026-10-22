package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

func validateLocalDomainZeroJoin(q wire.LocalDomainNodeJoin, j wire.LocalDomainNodeJoinResult, p nodekeys.LocalDomainPolicy) error {
	m, policy := j.Member, p.Policy
	if j.ContractRevision != wire.LocalDomainContractRevision || !reflect.DeepEqual(j.Description.Policy, policy) || !bytes.Equal(j.Description.PolicyProof, p.Proof) || j.Description.State != wire.LocalDomainActive || wire.ValidateLocalDomainDescription(j.Description, p.Hub, time.Now().UTC()) != nil || m.Selection != q.Selection || m.NodeID != policy.Node.NodeID || m.LocalUserScope != q.LocalUserScope || m.NativeSessionID != q.NativeSessionID || m.Runtime != q.Runtime || m.Workspace != q.Workspace || (m.State != wire.LocalDomainMemberJoinedZero && m.State != wire.LocalDomainMemberActive) || m.MemberID == "" || m.EndpointID == "" || m.PrincipalID == "" || m.BindingID == "" || m.BindingEpoch == 0 || m.NetworkAccessBindingID == "" || m.NetworkAccessEpoch == 0 || m.LeaseOwner == "" || j.Endpoint.EndpointID != m.EndpointID || j.Endpoint.Workspace != q.Workspace || j.NativeContextScope.HubID != policy.HubID || j.NativeContextScope.NetworkID != policy.NetworkID || j.NativeContextScope.GroupID != policy.GroupID {
		return nodekeys.ErrLocalDomainPolicy
	}
	return nil
}

func prepareLocalDomainCandidate(ctx context.Context, state *nodekeys.CryptoState, root string, p nodekeys.LocalDomainPolicy, m wire.LocalDomainMember) (nodekeys.GroupEndpointKeyCandidate, error) {
	var empty nodekeys.GroupEndpointKeyCandidate
	if err := state.CheckLocalDomainPolicy(ctx, p, time.Now().UTC()); err != nil {
		return empty, err
	}
	original, err := state.LocalDomainOriginalLocalKey(ctx, m.EndpointID)
	var expected *e2ee.PublicIdentity
	if err == nil {
		expected = &original
	} else if !errors.Is(err, nodekeys.ErrCryptoStateNotFound) {
		return empty, err
	}
	identity, err := loadNativePairPublicationIdentity(root, m.EndpointID, expected)
	if err != nil {
		return empty, err
	}
	retained, err := state.LocalDomainLocalAttestation(ctx, m.EndpointID, m.BindingID, m.BindingEpoch)
	if err == nil {
		if retained.PrincipalID != m.PrincipalID || retained.OwnerID != p.Policy.OwnerID || retained.NodeID != m.NodeID || retained.GroupID != p.Policy.GroupID || !machineSamePublicIdentity(retained.PublicIdentity, identity.Public()) {
			return empty, nodekeys.ErrLocalDomainConflict
		}
		return retained, nil
	}
	if !errors.Is(err, nodekeys.ErrCryptoStateNotFound) {
		return empty, err
	}
	proof, err := identity.SignEndpointKeyAttestation(m.EndpointID, m.PrincipalID, m.NodeID, m.BindingID, m.BindingEpoch)
	if err != nil {
		return empty, err
	}
	fingerprint, err := nodekeys.PeerKeyFingerprint(identity.Public())
	if err != nil {
		return empty, err
	}
	digest := sha256.Sum256(proof)
	c := nodekeys.GroupEndpointKeyCandidate{EndpointID: m.EndpointID, GroupID: p.Policy.GroupID, PrincipalID: m.PrincipalID, OwnerID: p.Policy.OwnerID, NodeID: m.NodeID, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch, KeyID: identity.Public().ID, KeyFingerprint: fingerprint, ProofDigest: hex.EncodeToString(digest[:]), PublicIdentity: identity.Public(), Attestation: proof}
	if err := state.RememberLocalDomainLocalAttestation(ctx, p.Policy.PolicyID, c, time.Now().UTC()); err != nil {
		return empty, err
	}
	return c, nil
}

func (b *machineAgentJoinBridge) publishLocalDomainCandidate(state *nodekeys.CryptoState, p nodekeys.LocalDomainPolicy, j wire.LocalDomainNodeJoinResult) (nodekeys.GroupEndpointKeyCandidate, error) {
	var empty nodekeys.GroupEndpointKeyCandidate
	card, err := b.verifyCurrentMCPBinding(j.SessionToken, p.Policy.GroupID)
	m := j.Member
	if err != nil {
		return empty, err
	}
	if card.EndpointID != m.EndpointID || card.PrincipalID != m.PrincipalID || card.BindingID != m.BindingID || card.BindingEpoch != m.BindingEpoch || card.NativeSessionID != m.NativeSessionID || card.Workspace != m.Workspace || card.NodeID != m.NodeID || card.GroupID != p.Policy.GroupID {
		return empty, nodekeys.ErrLocalDomainPolicy
	}
	c, err := prepareLocalDomainCandidate(b.ctx, state, machineNodeStateDir(b.stateDir, b.nodeID), p, m)
	if err != nil {
		return empty, err
	}
	body, err := json.Marshal(map[string]any{"attestation": json.RawMessage(c.Attestation)})
	if err != nil {
		return empty, err
	}
	raw, err := b.httpWithAuthorization(http.MethodPost, "/v2/fabric/endpoint-keys", body, "CicadaSession "+j.SessionToken, p.Policy.GroupID)
	if err != nil {
		return empty, err
	}
	var accepted store.EndpointKeyCandidate
	if decodeStrictBridgeJSON(raw, &accepted) != nil || validateMCPCurrentCandidate(accepted, card, p.Policy.OwnerID) != nil || accepted.Version <= 0 || !bytes.Equal(accepted.Proof, c.Attestation) || !machineSamePublicIdentity(accepted.Public, c.PublicIdentity) || accepted.ProofDigest != c.ProofDigest {
		return empty, nodekeys.ErrLocalDomainConflict
	}
	c.CandidateVersion = accepted.Version
	return c, nil
}

// This checks all original member coordinates and the retained public candidate
// before invoking the Node signer. A Hub-selected projected SID/cwd/access tuple
// or a substituted key cannot become an authentic delegated signature.
func validateLocalDomainKeyChallenge(p nodekeys.LocalDomainPolicy, original wire.LocalDomainMember, c nodekeys.GroupEndpointKeyCandidate, ch wire.LocalDomainKeyChallenge, now time.Time) error {
	if ch.ContractRevision != wire.LocalDomainContractRevision || !localContextHex(ch.ChallengeID, 32) || ch.ExpectedRevision != original.Revision || !now.Before(parseMachineNativePairTime(ch.ExpiresAt)) || parseMachineNativePairTime(ch.ExpiresAt).After(now.Add(e2ee.LocalDomainRequestLifetime)) || c.CandidateVersion <= 0 {
		return nodekeys.ErrLocalDomainPolicy
	}
	projected := original
	projected.Revision++
	projected.State = wire.LocalDomainMemberActive
	if original.State == wire.LocalDomainMemberJoinedZero {
		projected.MembershipRevision++
	}
	projected.CandidateVersion, projected.CandidateKeyID, projected.CandidateFingerprint, projected.CandidateProofDigest = uint64(c.CandidateVersion), c.KeyID, c.KeyFingerprint, c.ProofDigest
	if projected != ch.Member {
		return nodekeys.ErrLocalDomainConflict
	}
	k := ch.Manifest
	if k.CandidateVersion != c.CandidateVersion || k.CandidateKeyID != c.KeyID || k.CandidateFingerprint != c.KeyFingerprint || k.CandidateProofDigest != c.ProofDigest || !bytes.Equal(k.CandidateAttestation, c.Attestation) || !machineSamePublicIdentity(k.CandidatePublicIdentity, c.PublicIdentity) {
		return nodekeys.ErrLocalDomainConflict
	}
	g := wire.LocalDomainEndpointKeyGrant{ContractRevision: wire.LocalDomainContractRevision, Member: ch.Member, Manifest: k, PolicyProof: p.Proof}
	verified, err := wire.ValidateLocalDomainEndpointKeyProjection(g, p.Hub, p.Policy.OwnerID, p.Policy.OwnerPublic, now)
	if err != nil || !reflect.DeepEqual(verified, p.Policy) {
		return nodekeys.ErrLocalDomainPolicy
	}
	issued := parseMachineNativePairTime(k.IssuedAt)
	if issued.After(now.Add(30*time.Second)) || !now.Before(issued.Add(e2ee.LocalDomainRequestLifetime)) || parseMachineNativePairTime(ch.ExpiresAt).After(issued.Add(e2ee.LocalDomainRequestLifetime)) {
		return nodekeys.ErrLocalDomainPolicy
	}
	digest, err := wire.LocalDomainMemberDigest(ch.Member)
	if err != nil {
		return err
	}
	expected := e2ee.LocalDomainEndpointKeyClaims{Version: 1, Purpose: e2ee.LocalDomainEndpointKeyPurpose, PolicyID: p.Policy.PolicyID, PolicyEpoch: p.Policy.Epoch, PolicyDigest: original.Selection.PolicyDigest, MemberID: original.MemberID, MemberRevision: projected.Revision, MemberDigest: digest, ManifestDigest: k.Digest, CandidateBindingDigest: k.CandidateBindingDigest, IssuedAt: k.IssuedAt, ExpiresAt: p.Policy.ExpiresAt}
	if expected != ch.Claims {
		return nodekeys.ErrLocalDomainConflict
	}
	return nil
}

func localDomainFabricJoin(j wire.LocalDomainNodeJoinResult, p nodekeys.LocalDomainPolicy, card fabric.NetworkCard) *fabric.JoinResult {
	m := j.Member
	return &fabric.JoinResult{Endpoint: store.Endpoint{ID: m.EndpointID, PrincipalID: m.PrincipalID, Owner: p.Policy.OwnerID, GroupID: p.Policy.GroupID, MachineID: m.NodeID, Harness: m.Runtime, NativeSessionID: m.NativeSessionID, Workspace: m.Workspace, Name: j.Endpoint.Name, BindingID: m.BindingID, Status: card.Status, Visibility: "private", MigrationState: "READY"}, NetworkCard: card, SessionToken: j.SessionToken, BindingID: m.BindingID, BindingEpoch: m.BindingEpoch, LeaseExpiresAt: j.LeaseExpiresAt, Reused: j.Reused, NativeContextScope: store.NativeContextScopeMetadata{HubID: j.NativeContextScope.HubID, NetworkID: j.NativeContextScope.NetworkID, GroupID: j.NativeContextScope.GroupID, GroupContextPolicy: j.NativeContextScope.GroupContextPolicy, NetworkContextPolicy: j.NativeContextScope.NetworkContextPolicy}}
}
