package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type linkSealedSendTestOwner struct {
	identity       *e2ee.Identity
	ownerKeyID     string
	clientDeviceID string
	nodeCredential string
}

type linkSealedSendTestFixture struct {
	base              *externalThreadInviteTestFixture
	link              *CommunicationLink
	sourceNetworkID   string
	targetNetworkID   string
	sourceOwner       linkSealedSendTestOwner
	targetOwner       linkSealedSendTestOwner
	sourceEndpointKey *e2ee.Identity
	targetEndpointKey *e2ee.Identity
	manifest          *CommunicationLinkKeyManifest
	ciphertext        []byte
	messageID         string
	dataScope         string
}

func newLinkSealedSendTestFixture(t *testing.T, recordGrants bool) *linkSealedSendTestFixture {
	return newLinkSealedSendTestFixtureWithActions(t, recordGrants, []string{"send"})
}

func newLinkSealedSendTestFixtureWithActions(t *testing.T, recordGrants bool,
	actions []string) *linkSealedSendTestFixture {
	return newLinkSealedSendTestFixtureWithTopology(t, recordGrants, actions, "legacy", nil, nil)
}

func newLinkSealedSendTestFixtureWithTopology(t *testing.T, recordGrants bool,
	actions []string, topology string, sourceGrants, targetGrants []string) *linkSealedSendTestFixture {
	return newLinkSealedSendTestFixtureWithTopologyAndDirection(t, recordGrants,
		actions, topology, sourceGrants, targetGrants, "forward")
}

func newLinkSealedSendTestFixtureWithTopologyAndDirection(t *testing.T, recordGrants bool,
	actions []string, topology string, sourceGrants, targetGrants []string, direction string) *linkSealedSendTestFixture {
	t.Helper()
	base := newExternalThreadInviteTestFixture(t)
	sourceOwner := bindLinkSealedSendTestNode(t, base.store, base.source.ownerID, "node_source")
	targetOwner := bindLinkSealedSendTestNode(t, base.store, base.target.ownerID, "node_target")
	sourceNetworkID, targetNetworkID := "", ""
	if topology != "legacy" {
		var err error
		sourceNetworkID, targetNetworkID, err = configureLinkNetworkTopology(t, base,
			sourceOwner, targetOwner, topology, sourceGrants, targetGrants)
		if err != nil {
			t.Fatal(err)
		}
	}
	invite, err := base.store.CreateExternalThreadInvite(ExternalThreadInviteInput{
		OwnerID: base.source.ownerID, SourceEndpointID: base.source.endpointID,
		SourceGroupID: base.source.groupID, HubID: base.hubID,
		Direction: direction, Actions: actions, DataScopes: []string{"thread.message"},
		ExpiresAt: time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := base.store.AcceptExternalThreadInvite(invite.Token,
		base.target.ownerID, base.target.endpointID, base.target.groupID)
	if err != nil {
		t.Fatal(err)
	}
	link, err := base.store.GetCommunicationLinkForOwner(accepted.LinkID, base.source.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	sourceEndpointKey := registerLinkSealedSendEndpointKey(t, base.store, base.source.endpointID)
	targetEndpointKey := registerLinkSealedSendEndpointKey(t, base.store, base.target.endpointID)
	manifest, err := base.store.GetCommunicationLinkKeyManifest(link.ID, base.source.ownerID)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &linkSealedSendTestFixture{
		base: base, link: link, sourceOwner: sourceOwner, targetOwner: targetOwner,
		sourceNetworkID: sourceNetworkID, targetNetworkID: targetNetworkID,
		sourceEndpointKey: sourceEndpointKey, targetEndpointKey: targetEndpointKey,
		manifest: manifest, messageID: "msg_link_send_test", dataScope: "thread.message",
	}
	fixture.ciphertext = fixture.seal(t)
	if recordGrants {
		fixture.recordBothOwnerGrants(t)
	}
	return fixture
}

func configureLinkNetworkTopology(t *testing.T, base *externalThreadInviteTestFixture,
	sourceOwner, targetOwner linkSealedSendTestOwner, topology string,
	sourceGrants, targetGrants []string) (string, string, error) {
	t.Helper()
	if topology != "same" && topology != "cross" {
		return "", "", errors.New("invalid synthetic Link Network topology")
	}
	store := base.store
	for _, endpoint := range []externalThreadInviteTestEndpoint{base.source, base.target} {
		if _, err := store.db.Exec(`UPDATE fabric_endpoints SET owner=? WHERE id=?`, endpoint.ownerID, endpoint.endpointID); err != nil {
			return "", "", err
		}
	}
	sourceNetwork, err := store.CreateNetwork(Network{ID: "net_link_source", HubID: base.hubID,
		Name: "synthetic source Network", OwnerID: base.source.ownerID})
	if err != nil {
		return "", "", err
	}
	targetNetwork := sourceNetwork
	if topology == "cross" {
		targetNetwork, err = store.CreateNetwork(Network{ID: "net_link_target", HubID: base.hubID,
			Name: "synthetic target Network", OwnerID: base.target.ownerID})
		if err != nil {
			return "", "", err
		}
	}
	if err := acceptLinkFixtureNetworkJoin(t, base, sourceOwner, sourceNetwork.ID, sourceGrants,
		base.source.ownerID, "source"); err != nil {
		return "", "", err
	}
	if err := acceptLinkFixtureNetworkJoin(t, base, targetOwner, targetNetwork.ID, targetGrants,
		targetNetwork.OwnerID, "target"); err != nil {
		return "", "", err
	}
	for _, groupNetwork := range []struct{ groupID, networkID string }{
		{base.source.groupID, sourceNetwork.ID}, {base.target.groupID, targetNetwork.ID},
	} {
		group, err := store.GetGroup(groupNetwork.groupID)
		if err != nil {
			return "", "", err
		}
		if _, err := store.PrepareGroupNetworkMapping(group.ID, groupNetwork.networkID,
			"synthetic V77 Link test", group.Version); err != nil {
			return "", "", err
		}
		if err := store.ApproveGroupNetworkMapping(group.ID, groupNetwork.networkID, group.Version); err != nil {
			return "", "", err
		}
	}
	if err := store.ActivateNetworkMode(); err != nil {
		return "", "", err
	}
	return sourceNetwork.ID, targetNetwork.ID, nil
}

func acceptLinkFixtureNetworkJoin(t *testing.T, base *externalThreadInviteTestFixture,
	owner linkSealedSendTestOwner, networkID string, grants []string, issuerOwnerID, label string) error {
	t.Helper()
	grants = append([]string(nil), grants...)
	sort.Strings(grants)
	store := base.store
	endpoint := base.source
	nodeID := "node_source"
	nativeSessionID := "native_" + base.source.endpointID
	if label == "target" {
		endpoint = base.target
		nodeID = "node_target"
		nativeSessionID = "native_" + base.target.endpointID
	}
	token := "synthetic-v77-network-invite-" + label + "-" + NewID("nonce")
	if err := store.IssueNetworkInvitation(networkID, endpoint.ownerID, issuerOwnerID, token,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
		return fmt.Errorf("issue %s fixture Network invitation: %w", label, err)
	}
	issuedAt := time.Now().UTC().Add(-time.Minute)
	proofExpiry := time.Now().UTC().Add(45 * time.Minute)
	proof, err := owner.identity.SignOwnerNetworkJoinGrant(endpoint.ownerID, base.hubID,
		networkID, nodeID, nativeSessionID, NetworkInvitationDigest(token), owner.ownerKeyID,
		grants, false, issuedAt, proofExpiry)
	if err != nil {
		return err
	}
	var claims struct {
		Nonce     string `json:"nonce"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(proof, &claims); err != nil {
		return err
	}
	_, err = store.AcceptNetworkJoin(AcceptNetworkJoinInput{
		NetworkID: networkID, OwnerID: endpoint.ownerID, TrustDomainID: endpoint.ownerID,
		NodeID: nodeID, NativeSessionID: nativeSessionID, Harness: "codex",
		EndpointName: "synthetic " + label + " V77 Endpoint", InvitationToken: token,
		ProofNonce: claims.Nonce, ProofDigest: NetworkInvitationDigest(string(proof)),
		ProofExpiresAt: claims.ExpiresAt, OwnerKeyID: owner.ownerKeyID,
		OwnerJoinProof: string(proof), NodeCredentialHash: owner.nodeCredential,
		Grants: grants, CredentialHash: "synthetic-network-access-" + label,
		LeaseOwner:     "synthetic-v77-network-lease-" + label,
		LeaseExpiresAt: time.Now().UTC().Add(30 * time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		return fmt.Errorf("accept %s fixture Network join: %w", label, err)
	}
	return nil
}

func bindLinkSealedSendTestNode(t *testing.T, s *Store, ownerID, nodeID string) linkSealedSendTestOwner {
	t.Helper()
	ownerIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := s.RegisterOwnerApprovalKeyLocal(ownerID, ownerIdentity.Public())
	if err != nil {
		t.Fatal(err)
	}
	clientIdentity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "client_" + nodeID
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	deviceGrant, err := ownerIdentity.SignOwnerDeviceGrant(ownerID, deviceID,
		clientIdentity.Public(), hubID, e2ee.OwnerDevicePurposeControl,
		now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterClientDeviceFromOwnerGrant(RegisterClientDeviceInput{
		OwnerID: ownerID, OwnerKeyID: ownerKey.KeyID, DeviceID: deviceID,
		DevicePublic: clientIdentity.Public(), OwnerDeviceGrant: deviceGrant,
	}); err != nil {
		t.Fatal(err)
	}
	credentialDigest := nodeBindingTestCredentialDigest("node credential " + nodeID)
	codeSum := sha256.Sum256([]byte("node device code " + nodeID))
	codeDigest := hex.EncodeToString(codeSum[:])
	if _, err := s.CreatePendingNodeDeviceBinding(nodeID, nodeID, credentialDigest,
		codeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding(ownerID, deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	return linkSealedSendTestOwner{identity: ownerIdentity, ownerKeyID: ownerKey.KeyID,
		clientDeviceID: deviceID, nodeCredential: credentialDigest}
}

func registerLinkSealedSendEndpointKey(t *testing.T, s *Store, endpointID string) *e2ee.Identity {
	t.Helper()
	binding, err := s.GetSessionBindingForEndpoint(endpointID)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := identity.SignEndpointKeyAttestation(endpointID, binding.PrincipalID,
		binding.NodeID, binding.ID, binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterEndpointKeyCandidate(endpointID, binding.PrincipalID,
		binding.ID, binding.Epoch, proof); err != nil {
		t.Fatal(err)
	}
	return identity
}

func (f *linkSealedSendTestFixture) recordBothOwnerGrants(t *testing.T) {
	t.Helper()
	expiresAt, err := time.Parse(time.RFC3339, f.link.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range []struct {
		ownerID  string
		keyID    string
		identity *e2ee.Identity
		side     e2ee.OwnerLinkGrantSide
	}{
		{f.link.SourceOwnerID, f.sourceOwner.ownerKeyID, f.sourceOwner.identity, e2ee.OwnerLinkGrantSideSource},
		{f.link.TargetOwnerID, f.targetOwner.ownerKeyID, f.targetOwner.identity, e2ee.OwnerLinkGrantSideTarget},
	} {
		proof, err := grant.identity.SignOwnerLinkKeyGrant(grant.ownerID, f.link.ID,
			f.link.ContractDigest, f.manifest.Digest, uint64(f.link.Version), grant.side,
			time.Now().UTC().Add(-time.Minute), expiresAt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.RecordCommunicationLinkKeyGrant(grant.ownerID,
			f.link.ID, string(grant.side), grant.keyID, proof); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *linkSealedSendTestFixture) seal(t *testing.T) []byte {
	return f.sealDirection(t, false)
}

func (f *linkSealedSendTestFixture) sealDirection(t *testing.T, reverse bool) []byte {
	t.Helper()
	context := sealedLinkEndpointContext(f.link, f.manifest, f.messageID, "SEND", "", "", "", reverse)
	signer, recipient := f.sourceEndpointKey, f.manifest.Target.PublicIdentity
	if reverse {
		signer, recipient = f.targetEndpointKey, f.manifest.Source.PublicIdentity
	}
	wire, err := e2ee.SealEndpointMessage(signer, recipient,
		context, []byte("private endpoint message"), 1)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (f *linkSealedSendTestFixture) input() CommunicationLinkSealedSend {
	return f.inputDirection(false)
}

func (f *linkSealedSendTestFixture) inputDirection(reverse bool) CommunicationLinkSealedSend {
	credential := f.sourceOwner.nodeCredential
	if reverse {
		credential = f.targetOwner.nodeCredential
	}
	return CommunicationLinkSealedSend{NodeCredentialDigest: credential,
		LinkID: f.link.ID, MessageID: f.messageID, IdempotencyKey: "idem_link_send_1",
		DataScope: f.dataScope, Ciphertext: append([]byte(nil), f.ciphertext...)}
}

func TestCommunicationLinkBidirectionalSealedSendDerivesBothDirections(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		name := "forward"
		if reverse {
			name = "reverse"
		}
		t.Run(name, func(t *testing.T) {
			f := newLinkSealedSendTestFixtureWithTopologyAndDirection(t, true,
				[]string{"send", "ask", "reply"}, "cross",
				[]string{"direct.send", "direct.receive"},
				[]string{"direct.send", "direct.receive"}, "bidirectional")
			if f.link.Direction != "bidirectional" {
				t.Fatalf("fixture did not create a bidirectional Link: %#v", f.link)
			}
			f.messageID = "msg_link_bidir_send_" + name
			f.ciphertext = f.sealDirection(t, reverse)
			input := f.inputDirection(reverse)
			record, err := f.base.store.EnqueueCommunicationLinkSealedSend(input)
			if err != nil {
				t.Fatalf("bidirectional %s SEND was denied: %v", name, err)
			}
			sender, receiver := communicationLinkAskRoles(f.link, f.manifest, reverse)
			if record.Route.SenderEndpointID != sender.endpointID || record.Route.ReceiverEndpointID != receiver.endpointID {
				t.Fatalf("SEND route did not follow credential-derived %s direction: %#v", name, record.Route)
			}
			claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
				RecipientEndpointID: receiver.endpointID, ConsumerID: "bidir-" + name,
				BindingID: receiver.bindingID, BindingEpoch: receiver.bindingEpoch, Limit: 1,
			})
			if err != nil || len(claimed) != 1 || claimed[0].MessageID != input.MessageID {
				t.Fatalf("bidirectional %s SEND was not claimable by its exact receiver: %#v err=%v", name, claimed, err)
			}
			receiverCredential := f.targetOwner.nodeCredential
			if reverse {
				receiverCredential = f.sourceOwner.nodeCredential
			}
			if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
				receiverCredential, input.MessageID, claimed[0].AttemptID); err != nil {
				t.Fatalf("fresh %s receiver authorization rejected: %v", name, err)
			}
		})
	}
}

func TestCommunicationLinkReverseSendRequiresBidirectionalActionsAndNetworkGrants(t *testing.T) {
	t.Run("forward-only Link rejects reverse sender", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopologyAndDirection(t, true,
			[]string{"send"}, "cross", []string{"direct.send", "direct.receive"},
			[]string{"direct.send", "direct.receive"}, "forward")
		f.ciphertext = f.sealDirection(t, true)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.inputDirection(true)); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("forward-only Link accepted reverse SEND: %v", err)
		}
	})
	t.Run("Link without send action rejects reverse sender", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopologyAndDirection(t, true,
			[]string{"ask", "reply"}, "cross", []string{"direct.send", "direct.receive"},
			[]string{"direct.send", "direct.receive"}, "bidirectional")
		f.ciphertext = f.sealDirection(t, true)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.inputDirection(true)); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("Link without send action accepted reverse SEND: %v", err)
		}
	})
	t.Run("source direct.receive is required", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopologyAndDirection(t, true,
			[]string{"send"}, "cross", []string{"direct.send", "direct.receive"},
			[]string{"direct.send", "direct.receive"}, "bidirectional")
		if _, err := f.base.store.db.Exec(`UPDATE network_memberships_v2 SET grants_json='["direct.send"]',revision=revision+1
WHERE network_id=? AND principal_id=?`, f.sourceNetworkID, f.link.SourcePrincipalID); err != nil {
			t.Fatal(err)
		}
		f.ciphertext = f.sealDirection(t, true)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.inputDirection(true)); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("reverse SEND ignored missing receiver direct.receive grant: %v", err)
		}
	})
	t.Run("target direct.send is required", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopologyAndDirection(t, true,
			[]string{"send"}, "cross", []string{"direct.send", "direct.receive"},
			[]string{"direct.send", "direct.receive"}, "bidirectional")
		if _, err := f.base.store.db.Exec(`UPDATE network_memberships_v2 SET grants_json='["direct.receive"]',revision=revision+1
WHERE network_id=? AND principal_id=?`, f.targetNetworkID, f.link.TargetPrincipalID); err != nil {
			t.Fatal(err)
		}
		f.ciphertext = f.sealDirection(t, true)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.inputDirection(true)); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("reverse SEND ignored missing sender direct.send grant: %v", err)
		}
	})
	t.Run("source credential cannot impersonate target AAD", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopologyAndDirection(t, true,
			[]string{"send"}, "cross", []string{"direct.send", "direct.receive"},
			[]string{"direct.send", "direct.receive"}, "bidirectional")
		f.ciphertext = f.sealDirection(t, true)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.inputDirection(false)); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("source Node impersonated target-signed reverse SEND: %v", err)
		}
	})
}

func readKeyGrantForTest(t *testing.T, s *Store, linkID, side string) storedCommunicationLinkKeyGrant {
	t.Helper()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	grant, err := readStoredCommunicationLinkKeyGrant(tx, linkID, side)
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

func restoreKeyGrantForTest(t *testing.T, s *Store, grant storedCommunicationLinkKeyGrant) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE communication_link_key_grants_v2 SET nonce=?, signed_proof=?
WHERE link_id=? AND side=?`, grant.nonce, grant.proof, grant.linkID, grant.side); err != nil {
		t.Fatal(err)
	}
}

func TestCommunicationLinkSealedSendRequiresCurrentBilateralAuthorization(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, false)
	input := f.input()
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(input); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("one-owner Link consent was enough to enqueue: %v", err)
	}

	// A live, validly signed but expired proof is still not route authority.
	f.recordBothOwnerGrants(t)
	sourceGrant := readKeyGrantForTest(t, f.base.store, f.link.ID, CommunicationLinkGrantSource)
	expiredAt := time.Now().UTC().Add(-time.Minute)
	expiredProof, err := f.sourceOwner.identity.SignOwnerLinkKeyGrant(f.link.SourceOwnerID,
		f.link.ID, f.link.ContractDigest, f.manifest.Digest, uint64(f.link.Version),
		e2ee.OwnerLinkGrantSideSource, expiredAt.Add(-time.Minute), expiredAt)
	if err != nil {
		t.Fatal(err)
	}
	var expiredClaims e2ee.OwnerLinkKeyGrant
	if err := json.Unmarshal(expiredProof, &expiredClaims); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.db.Exec(`UPDATE communication_link_key_grants_v2
SET nonce=?, signed_proof=? WHERE link_id=? AND side=?`, expiredClaims.Nonce, expiredProof,
		f.link.ID, CommunicationLinkGrantSource); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(input); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("expired owner proof was accepted: %v", err)
	}
	restoreKeyGrantForTest(t, f.base.store, sourceGrant)

	// The target Node is authenticated, but a forward Link cannot authorize it
	// to impersonate the source Endpoint.
	spoofed := input
	spoofed.NodeCredentialDigest = f.targetOwner.nodeCredential
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(spoofed); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("target Node forged the Link source: %v", err)
	}

	plaintext := input
	plaintext.Ciphertext = []byte("this must never enter a sealed route")
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(plaintext); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("plaintext was accepted under SEALED_V1: %v", err)
	}

	wrongScope := input
	wrongScope.DataScope = "thread.private_history"
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(wrongScope); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("Link scope could be widened by the caller: %v", err)
	}

	if _, err := f.base.store.RevokeOwnerApprovalKeyLocal(f.link.TargetOwnerID,
		f.targetOwner.ownerKeyID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(input); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("revoked target owner key still authorized enqueue: %v", err)
	}
	var count int
	if err := f.base.store.db.QueryRow(`SELECT count(*) FROM fabric_messages WHERE id=?`, input.MessageID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("denied sends left a durable message row")
	}
}

func TestCommunicationLinkSealedSendPersistsExactSignedCiphertextAndClaimsOnce(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, true)
	created, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input())
	if err != nil {
		t.Fatal(err)
	}
	if created.PayloadMode != RelayPayloadModeSealedV1 || !bytes.Equal(created.Ciphertext, f.ciphertext) ||
		created.Route.SenderEndpointID != f.link.SourceEndpointID || created.Route.ReceiverEndpointID != f.link.TargetEndpointID ||
		created.Security.AuthorizationRef != communicationLinkAuthorizationRefPrefix+f.link.ID ||
		created.Security.SenderBindingID != f.manifest.Source.BindingID ||
		created.Security.ReceiverBindingID != f.manifest.Target.BindingID {
		t.Fatalf("authorized route was not derived from current Store state: %#v", created)
	}
	var body string
	var persisted []byte
	var mode string
	if err := f.base.store.db.QueryRow(`SELECT message.body, payload.ciphertext, payload.payload_mode
FROM fabric_messages message JOIN relay_v2_message_payloads payload ON payload.message_id=message.id
WHERE message.id=?`, f.messageID).Scan(&body, &persisted, &mode); err != nil {
		t.Fatal(err)
	}
	if body != "" || mode != RelayPayloadModeSealedV1 || !bytes.Equal(persisted, f.ciphertext) {
		t.Fatalf("store copied plaintext or altered the endpoint ciphertext: body=%q mode=%q", body, mode)
	}
	retry, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input())
	if err != nil || retry.Route.MessageID != created.Route.MessageID || retry.Sequence != created.Sequence {
		t.Fatalf("exact send retry was not idempotent: retry=%#v err=%v", retry, err)
	}
	claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 10,
	})
	if err != nil || len(claimed) != 1 || claimed[0].MessageID != f.messageID || !bytes.Equal(claimed[0].Ciphertext, f.ciphertext) {
		t.Fatalf("valid bilateral Link message could not be claimed: %#v err=%v", claimed, err)
	}
}

func TestCommunicationLinkSealedSendSameHubCrossNetworkLifecycle(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"send"}, "cross",
		[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
	created, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input())
	if err != nil {
		t.Fatalf("authorized same-Hub cross-Network send was denied: %v", err)
	}
	var sourceNetworkID, receiverNetworkID string
	var sourceMembershipRevision, receiverMembershipRevision int64
	if err := f.base.store.db.QueryRow(`SELECT network_id,receiver_network_id,
sender_membership_revision,receiver_membership_revision FROM network_message_enrollment_v2
WHERE message_id=?`, created.Route.MessageID).Scan(&sourceNetworkID, &receiverNetworkID,
		&sourceMembershipRevision, &receiverMembershipRevision); err != nil {
		t.Fatal(err)
	}
	if sourceNetworkID != f.sourceNetworkID || receiverNetworkID != f.targetNetworkID ||
		sourceNetworkID == receiverNetworkID || sourceMembershipRevision <= 0 || receiverMembershipRevision <= 0 {
		t.Fatalf("cross-Network enrollment did not capture both sides: source=%s receiver=%s revisions=%d/%d",
			sourceNetworkID, receiverNetworkID, sourceMembershipRevision, receiverMembershipRevision)
	}
	claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 10,
	})
	if err != nil || len(claimed) != 1 || claimed[0].MessageID != f.messageID {
		t.Fatalf("authorized cross-Network delivery was not claimable: %#v err=%v", claimed, err)
	}
	authorized, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, f.messageID, claimed[0].AttemptID)
	if err != nil || authorized == nil || authorized.EndpointID != f.link.TargetEndpointID {
		t.Fatalf("fresh Node injection authorization rejected cross-Network Link: %#v err=%v", authorized, err)
	}
}

func TestCommunicationLinkSealedSendActiveNetworkTopologyGuards(t *testing.T) {
	t.Run("same Network remains authorized", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"send"}, "same",
			[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); err != nil {
			t.Fatalf("same-Network Link regression: %v", err)
		}
		claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node",
			BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 10,
		})
		if err != nil || len(claimed) != 1 {
			t.Fatalf("same-Network Link was not claimable: %#v err=%v", claimed, err)
		}
	})

	t.Run("missing source send grant", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"send"}, "cross",
			[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
		if _, err := f.base.store.db.Exec(`UPDATE network_memberships_v2 SET grants_json='["direct.receive"]',revision=revision+1
WHERE network_id=? AND principal_id=?`, f.sourceNetworkID, f.link.SourcePrincipalID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("source Network direct.send was not required: %v", err)
		}
	})

	t.Run("missing receiver grant", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"send"}, "cross",
			[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
		if _, err := f.base.store.db.Exec(`UPDATE network_memberships_v2 SET grants_json='["direct.send"]',revision=revision+1
WHERE network_id=? AND principal_id=?`, f.targetNetworkID, f.link.TargetPrincipalID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("receiver Network direct.receive was not required: %v", err)
		}
	})

	for _, side := range []string{"source", "target"} {
		t.Run("paused "+side+" Network", func(t *testing.T) {
			f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"send"}, "cross",
				[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
			networkID := f.sourceNetworkID
			if side == "target" {
				networkID = f.targetNetworkID
			}
			if _, err := f.base.store.db.Exec(`UPDATE networks_v2 SET state='PAUSED' WHERE id=?`, networkID); err != nil {
				t.Fatal(err)
			}
			if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
				t.Fatalf("paused %s Network still authorized Link send: %v", side, err)
			}
		})
	}

	t.Run("different Network Hub", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"send"}, "cross",
			[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
		if _, err := f.base.store.db.Exec(`UPDATE networks_v2 SET hub_id='hub_other' WHERE id=?`, f.targetNetworkID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("different-Hub Network Link was accepted: %v", err)
		}
	})

	t.Run("different Link transport Hub", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"send"}, "cross",
			[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
		if _, err := f.base.store.db.Exec(`UPDATE communication_links_v2 SET transport_hub_id='hub_other' WHERE id=?`, f.link.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
			t.Fatalf("different Link transport Hub was accepted: %v", err)
		}
	})
}

func TestCommunicationLinkCrossNetworkAskReplyUsesExactReversePolicy(t *testing.T) {
	t.Run("authorized correlated reverse reply", func(t *testing.T) {
		f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"ask", "reply"}, "cross",
			[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
		ask := sealedAskInputForFixture(t, f)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(ask); err != nil {
			t.Fatalf("cross-Network forward Ask was denied: %v", err)
		}
		claimedAsk, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node",
			BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 1,
		})
		if err != nil || len(claimedAsk) != 1 || claimedAsk[0].RequestID != ask.RequestID {
			t.Fatalf("cross-Network Ask was not claimable: %#v err=%v", claimedAsk, err)
		}
		if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
			f.targetOwner.nodeCredential, ask.MessageID, claimedAsk[0].AttemptID); err != nil {
			t.Fatalf("fresh cross-Network Ask injection was denied: %v", err)
		}
		reply := sealedReplyInputForFixture(t, f, ask, "msg_link_cross_network_reply")
		if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(reply); err != nil {
			t.Fatalf("correlated reverse Reply with both Networks' reverse grants was denied: %v", err)
		}
		claimedReply, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.link.SourceEndpointID, ConsumerID: "source-node",
			BindingID: f.manifest.Source.BindingID, BindingEpoch: f.manifest.Source.BindingEpoch, Limit: 1,
		})
		if err != nil || len(claimedReply) != 1 || claimedReply[0].Route.Kind != "reply" {
			t.Fatalf("cross-Network reverse Reply was not claimable: %#v err=%v", claimedReply, err)
		}
		if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
			f.sourceOwner.nodeCredential, reply.MessageID, claimedReply[0].AttemptID); err != nil {
			t.Fatalf("fresh reverse Reply injection was denied: %v", err)
		}
	})

	for _, missing := range []string{"target direct.send", "source direct.receive"} {
		t.Run("missing "+missing, func(t *testing.T) {
			f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"ask", "reply"}, "cross",
				[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
			ask := sealedAskInputForFixture(t, f)
			if _, err := f.base.store.EnqueueCommunicationLinkSealedAsk(ask); err != nil {
				t.Fatal(err)
			}
			switch missing {
			case "target direct.send":
				_, err := f.base.store.db.Exec(`UPDATE network_memberships_v2 SET grants_json='["direct.receive"]',revision=revision+1
WHERE network_id=? AND principal_id=?`, f.targetNetworkID, f.link.TargetPrincipalID)
				if err != nil {
					t.Fatal(err)
				}
			case "source direct.receive":
				_, err := f.base.store.db.Exec(`UPDATE network_memberships_v2 SET grants_json='["direct.send"]',revision=revision+1
WHERE network_id=? AND principal_id=?`, f.sourceNetworkID, f.link.SourcePrincipalID)
				if err != nil {
					t.Fatal(err)
				}
			}
			reply := sealedReplyInputForFixture(t, f, ask, "msg_link_cross_network_reply_denied")
			if _, err := f.base.store.EnqueueCommunicationLinkSealedReply(reply); err == nil {
				t.Fatalf("reverse Reply was accepted without %s", missing)
			}
		})
	}
}

func TestCommunicationLinkCrossNetworkEnrollmentRevisionFencesRejoin(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"send"}, "cross",
		[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); err != nil {
		t.Fatal(err)
	}
	for _, side := range []struct{ networkID, principalID, endpointID string }{
		{f.sourceNetworkID, f.link.SourcePrincipalID, f.link.SourceEndpointID},
		{f.targetNetworkID, f.link.TargetPrincipalID, f.link.TargetEndpointID},
	} {
		membership, err := f.base.store.GetNetworkMembership(side.networkID, side.principalID)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.base.store.RevokeNetworkMembership(side.networkID, side.principalID, membership.Revision); err != nil {
			t.Fatal(err)
		}
		network, err := f.base.store.GetNetwork(side.networkID)
		if err != nil {
			t.Fatal(err)
		}
		owner := f.sourceOwner
		label := "source"
		grants := []string{"direct.receive", "direct.send"}
		if side.endpointID == f.link.TargetEndpointID {
			owner = f.targetOwner
			label = "target"
		}
		if err := acceptLinkFixtureNetworkJoin(t, f.base, owner, side.networkID, grants, network.OwnerID, label); err != nil {
			t.Fatalf("synthetic fresh %s Network rejoin failed: %v", label, err)
		}
		current, err := f.base.store.GetNetworkMembership(side.networkID, side.principalID)
		if err != nil || current.Status != "active" || current.Revision <= membership.Revision {
			t.Fatalf("fresh %s Network membership did not advance its revision: before=%#v after=%#v err=%v", label, membership, current, err)
		}
	}
	claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 10,
	})
	if err != nil || len(claimed) != 0 {
		t.Fatalf("freshly re-enrolled Network membership revived old ciphertext: %#v err=%v", claimed, err)
	}
	assertLinkSealedInboxFailed(t, f)
}

func TestCommunicationLinkCrossNetworkFreshInjectionGuardSeesRevisionChange(t *testing.T) {
	f := newLinkSealedSendTestFixtureWithTopology(t, true, []string{"send"}, "cross",
		[]string{"direct.receive", "direct.send"}, []string{"direct.receive", "direct.send"})
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); err != nil {
		t.Fatal(err)
	}
	claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node",
		BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 10,
	})
	if err != nil || len(claimed) != 1 {
		t.Fatalf("initial authorized claim failed: %#v err=%v", claimed, err)
	}
	if _, err := f.base.store.db.Exec(`UPDATE network_memberships_v2 SET revision=revision+1
WHERE network_id=? AND principal_id=?`, f.targetNetworkID, f.link.TargetPrincipalID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.db.Exec(`UPDATE endpoint_network_memberships_v2 SET revision=revision+1
WHERE network_id=? AND endpoint_id=?`, f.targetNetworkID, f.link.TargetEndpointID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.AuthorizeClaimedCommunicationLinkSealedSend(
		f.targetOwner.nodeCredential, f.messageID, claimed[0].AttemptID); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("stale cross-Network enrollment reached fresh injection authorization: %v", err)
	}
}

func TestCommunicationLinkSealedSendRejectsStaleSessionBinding(t *testing.T) {
	f := newLinkSealedSendTestFixture(t, true)
	if _, err := f.base.store.ReleaseSessionBindingLease(f.sourceOwnerBindingID(t), "lease_ep_source",
		f.manifest.Source.BindingEpoch); err != nil {
		t.Fatal(err)
	}
	if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); !errors.Is(err, ErrCommunicationLinkRelayDenied) {
		t.Fatalf("old source binding epoch remained authorized: %v", err)
	}
}

func (f *linkSealedSendTestFixture) sourceOwnerBindingID(t *testing.T) string {
	t.Helper()
	return f.base.source.bindingID
}

func TestCommunicationLinkSealedSendClaimRechecksRevocationAndKeyChanges(t *testing.T) {
	t.Run("link revoked", func(t *testing.T) {
		f := newLinkSealedSendTestFixture(t, true)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.RevokeCommunicationLink(f.link.ID, f.link.SourceOwnerID,
			f.link.Version, "revoked before claim"); err != nil {
			t.Fatal(err)
		}
		claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node",
			BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 10,
		})
		if err != nil || len(claimed) != 0 {
			t.Fatalf("revoked Link queued message was delivered: %#v err=%v", claimed, err)
		}
		assertLinkSealedInboxFailed(t, f)
	})

	t.Run("owner key revoked", func(t *testing.T) {
		f := newLinkSealedSendTestFixture(t, true)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); err != nil {
			t.Fatal(err)
		}
		if _, err := f.base.store.RevokeOwnerApprovalKeyLocal(f.targetOwnerForLink().ownerID,
			f.targetOwner.ownerKeyID, 1); err != nil {
			t.Fatal(err)
		}
		claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node",
			BindingID: f.manifest.Target.BindingID, BindingEpoch: f.manifest.Target.BindingEpoch, Limit: 10,
		})
		if err != nil || len(claimed) != 0 {
			t.Fatalf("revoked owner key still permitted queued delivery: %#v err=%v", claimed, err)
		}
		assertLinkSealedInboxFailed(t, f)
	})

	t.Run("binding epoch changed", func(t *testing.T) {
		f := newLinkSealedSendTestFixture(t, true)
		if _, err := f.base.store.EnqueueCommunicationLinkSealedSend(f.input()); err != nil {
			t.Fatal(err)
		}
		newBinding, err := f.base.store.ReleaseSessionBindingLease(f.base.target.bindingID,
			"lease_ep_target", f.manifest.Target.BindingEpoch)
		if err != nil {
			t.Fatal(err)
		}
		claimed, err := f.base.store.ClaimRelaySealedV1Inbox(RelayClaimInput{
			RecipientEndpointID: f.link.TargetEndpointID, ConsumerID: "target-node",
			BindingID: newBinding.ID, BindingEpoch: newBinding.Epoch, Limit: 10,
		})
		if err != nil || len(claimed) != 0 {
			t.Fatalf("old epoch ciphertext was delivered after binding release: %#v err=%v", claimed, err)
		}
		assertLinkSealedInboxFailed(t, f)
	})
}

func (f *linkSealedSendTestFixture) targetOwnerForLink() externalThreadInviteTestEndpoint {
	return f.base.target
}

func assertLinkSealedInboxFailed(t *testing.T, f *linkSealedSendTestFixture) {
	t.Helper()
	var inboxState, outboxState string
	if err := f.base.store.db.QueryRow(`SELECT inbox.state, outbox.state
FROM relay_v2_inbox inbox JOIN relay_v2_outbox outbox ON outbox.message_id=inbox.message_id
WHERE inbox.message_id=?`, f.messageID).Scan(&inboxState, &outboxState); err != nil {
		t.Fatal(err)
	}
	if inboxState != RelayInboxFailed || outboxState != RelayInboxFailed {
		t.Fatalf("invalid queued Link message remained retryable: inbox=%s outbox=%s", inboxState, outboxState)
	}
}
