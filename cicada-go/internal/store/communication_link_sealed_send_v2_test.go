package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	t.Helper()
	base := newExternalThreadInviteTestFixture(t)
	sourceOwner := bindLinkSealedSendTestNode(t, base.store, base.source.ownerID, "node_source")
	targetOwner := bindLinkSealedSendTestNode(t, base.store, base.target.ownerID, "node_target")
	invite, err := base.store.CreateExternalThreadInvite(ExternalThreadInviteInput{
		OwnerID: base.source.ownerID, SourceEndpointID: base.source.endpointID,
		SourceGroupID: base.source.groupID, HubID: base.hubID,
		Actions: actions, DataScopes: []string{"thread.message"},
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
		sourceEndpointKey: sourceEndpointKey, targetEndpointKey: targetEndpointKey,
		manifest: manifest, messageID: "msg_link_send_test", dataScope: "thread.message",
	}
	fixture.ciphertext = fixture.seal(t)
	if recordGrants {
		fixture.recordBothOwnerGrants(t)
	}
	return fixture
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
	t.Helper()
	context := e2ee.EndpointMessageContext{
		MessageID: f.messageID, Kind: "SEND",
		SenderEndpointID: f.link.SourceEndpointID, SenderPrincipalID: f.link.SourcePrincipalID,
		SenderOwnerID: f.link.SourceOwnerID, SenderGroupID: f.link.SourceGroupID,
		SenderMembershipRevision: f.link.ScopeSnapshot.SourceMembershipRevision,
		SenderBindingEpoch:       f.manifest.Source.BindingEpoch, SenderKeyID: f.manifest.Source.KeyID,
		ReceiverEndpointID: f.link.TargetEndpointID, ReceiverPrincipalID: f.link.TargetPrincipalID,
		ReceiverOwnerID: f.link.TargetOwnerID, ReceiverGroupID: f.link.TargetGroupID,
		ReceiverMembershipRevision: f.link.ScopeSnapshot.TargetMembershipRevision,
		ReceiverBindingEpoch:       f.manifest.Target.BindingEpoch, ReceiverKeyID: f.manifest.Target.KeyID,
		LinkID: f.link.ID, LinkRevision: f.link.Version, TransportHubID: f.link.TransportHubID,
	}
	wire, err := e2ee.SealEndpointMessage(f.sourceEndpointKey, f.manifest.Target.PublicIdentity,
		context, []byte("private endpoint message"), 1)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (f *linkSealedSendTestFixture) input() CommunicationLinkSealedSend {
	return CommunicationLinkSealedSend{NodeCredentialDigest: f.sourceOwner.nodeCredential,
		LinkID: f.link.ID, MessageID: f.messageID, IdempotencyKey: "idem_link_send_1",
		DataScope: f.dataScope, Ciphertext: append([]byte(nil), f.ciphertext...)}
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
