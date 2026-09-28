package store

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestNetworkDirectKeyGrantFirstAcceptancePersistsAndResignIsStable(t *testing.T) {
	s, owner, _, device := newClientDeviceFixture(t)
	if _, err := s.db.Exec(`UPDATE principals SET trust_domain_id='domain' WHERE id='owner_a'`); err != nil {
		t.Fatal(err)
	}
	const nodeID, nodeToken, nativeID = "node_network_direct", "synthetic-network-direct-node-token", "native_network_direct"
	credentialDigest := nodeBindingTestCredentialDigest(nodeToken)
	codeDigest := nodeBindingTestCodeDigest("synthetic-network-direct-code")
	bound, err := s.CreatePendingNodeDeviceBinding(nodeID, nodeID, credentialDigest,
		codeDigest, time.Now().UTC().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	confirmedBinding, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID, codeDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateNetwork(Network{ID: "net_direct", HubID: bound.HubID,
		Name: "Direct", OwnerID: "owner_a"}); err != nil {
		t.Fatal(err)
	}
	const invitation = "synthetic-direct-invitation-aaaaaaaaaaaaaaaaaaaaaaaa"
	grants := []string{"direct.receive", "direct.send"}
	if err := s.IssueNetworkInvitation("net_direct", "owner_a", "owner_a", invitation,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
		t.Fatal(err)
	}
	joinProof, err := owner.SignOwnerNetworkJoinGrant("owner_a", bound.HubID, "net_direct",
		nodeID, nativeID, NetworkInvitationDigest(invitation), owner.Public().ID,
		grants, false, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var joinClaims struct {
		Nonce     string `json:"nonce"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(joinProof, &joinClaims); err != nil {
		t.Fatal(err)
	}
	leaseExpiry := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	joined, err := s.AcceptNetworkJoin(AcceptNetworkJoinInput{
		NetworkID: "net_direct", OwnerID: "owner_a", TrustDomainID: "domain",
		NodeID: nodeID, NativeSessionID: nativeID, Harness: "codex", EndpointName: "direct-agent",
		InvitationToken: invitation, ProofNonce: joinClaims.Nonce,
		ProofDigest: NetworkInvitationDigest(string(joinProof)), ProofExpiresAt: joinClaims.ExpiresAt,
		OwnerKeyID: owner.Public().ID, OwnerJoinProof: string(joinProof),
		NodeCredentialHash: credentialDigest, Grants: grants, CredentialHash: "direct-access-hash",
		LeaseOwner: "direct-access-lease", LeaseExpiresAt: leaseExpiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := NetworkAccessScope{NetworkID: "net_direct", PrincipalID: joined.PrincipalID,
		EndpointID: joined.EndpointID, AccessSessionID: joined.AccessSessionID,
		AccessEpoch: joined.AccessSessionEpoch, LeaseOwner: "direct-access-lease",
		MembershipID: joined.MembershipID, MembershipRevision: joined.MembershipRevision,
		EndpointMembershipRevision: joined.EndpointRevision}
	binding, err := s.EnsureNetworkDirectNativeBinding(scope)
	if err != nil || binding.NativeSessionID != nativeID {
		t.Fatalf("native delivery binding: %#v %v", binding, err)
	}
	endpointKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := endpointKey.SignNetworkDirectKeyAttestation(bound.HubID, "net_direct",
		joined.EndpointID, joined.PrincipalID, nodeID, binding.ID, binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	first, err := s.RegisterNetworkDirectKeyCandidate(scope, proof)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := s.PreviewNetworkDirectKeyGrant("owner_a", "net_direct", joined.EndpointID, owner.Public().ID)
	if err != nil || manifest.Candidate.Version != first.Version || manifest.NativeSessionID != nativeID {
		t.Fatalf("owner manifest: %#v %v", manifest, err)
	}
	resigned, err := endpointKey.SignNetworkDirectKeyAttestation(bound.HubID, "net_direct",
		joined.EndpointID, joined.PrincipalID, nodeID, binding.ID, binding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.RegisterNetworkDirectKeyCandidate(scope, resigned)
	if err != nil || second.Version != first.Version {
		t.Fatalf("same claims rotated candidate: %#v %v", second, err)
	}
	still, err := s.PreviewNetworkDirectKeyGrant("owner_a", "net_direct", joined.EndpointID, owner.Public().ID)
	if err != nil || still.Digest != manifest.Digest {
		t.Fatalf("resign changed manifest: %#v %v", still, err)
	}
	ownerProof, err := owner.SignOwnerNetworkDirectKeyGrant(bound.HubID, "net_direct",
		joined.EndpointID, "owner_a", manifest.Digest,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := s.AcceptNetworkDirectKeyGrant("owner_a", "net_direct", joined.EndpointID, ownerProof)
	if err != nil || accepted.State != "active" || accepted.Revision != 1 {
		t.Fatalf("first grant not inserted: %#v %v", accepted, err)
	}
	retry, err := s.AcceptNetworkDirectKeyGrant("owner_a", "net_direct", joined.EndpointID, ownerProof)
	if err != nil || retry.Revision != accepted.Revision || retry.ProofDigest != accepted.ProofDigest {
		t.Fatalf("exact retry not idempotent: %#v %v", retry, err)
	}
	var path string
	if err := s.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name='main'`).Scan(&path); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current, err := reopened.GetNetworkDirectKeyGrant("owner_a", "net_direct", joined.EndpointID)
	if err != nil || current.State != "active" || current.ProofDigest != accepted.ProofDigest {
		t.Fatalf("reopened grant: %#v %v", current, err)
	}
	const secondInvitation = "synthetic-direct-invitation-bbbbbbbbbbbbbbbbbbbbbbbb"
	if err := s.IssueNetworkInvitation("net_direct", "owner_a", "owner_a", secondInvitation,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
		t.Fatal(err)
	}
	secondProof, err := owner.SignOwnerNetworkJoinGrant("owner_a", bound.HubID, "net_direct",
		nodeID, "native_network_direct_second", NetworkInvitationDigest(secondInvitation),
		owner.Public().ID, grants, false, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var secondClaims struct {
		Nonce     string `json:"nonce"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(secondProof, &secondClaims); err != nil {
		t.Fatal(err)
	}
	secondJoin, err := s.AcceptNetworkJoin(AcceptNetworkJoinInput{
		NetworkID: "net_direct", OwnerID: "owner_a", TrustDomainID: "domain",
		NodeID: nodeID, NativeSessionID: "native_network_direct_second", Harness: "codex",
		EndpointName: "direct-agent-second", InvitationToken: secondInvitation,
		ProofNonce: secondClaims.Nonce, ProofDigest: NetworkInvitationDigest(string(secondProof)),
		ProofExpiresAt: secondClaims.ExpiresAt, OwnerKeyID: owner.Public().ID,
		OwnerJoinProof: string(secondProof), NodeCredentialHash: credentialDigest,
		Grants: grants, CredentialHash: "direct-access-hash-second",
		LeaseOwner: "direct-access-lease-second", LeaseExpiresAt: leaseExpiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	secondScope := NetworkAccessScope{NetworkID: "net_direct", PrincipalID: secondJoin.PrincipalID,
		EndpointID: secondJoin.EndpointID, AccessSessionID: secondJoin.AccessSessionID,
		AccessEpoch: secondJoin.AccessSessionEpoch, LeaseOwner: "direct-access-lease-second",
		MembershipID: secondJoin.MembershipID, MembershipRevision: secondJoin.MembershipRevision,
		EndpointMembershipRevision: secondJoin.EndpointRevision}
	secondBinding, err := s.EnsureNetworkDirectNativeBinding(secondScope)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	secondAttestation, err := secondKey.SignNetworkDirectKeyAttestation(bound.HubID,
		"net_direct", secondJoin.EndpointID, secondJoin.PrincipalID, nodeID,
		secondBinding.ID, secondBinding.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterNetworkDirectKeyCandidate(secondScope, secondAttestation); err != nil {
		t.Fatal(err)
	}
	secondManifest, err := s.PreviewNetworkDirectKeyGrant("owner_a", "net_direct",
		secondJoin.EndpointID, owner.Public().ID)
	if err != nil {
		t.Fatal(err)
	}
	secondOwnerProof, err := owner.SignOwnerNetworkDirectKeyGrant(bound.HubID, "net_direct",
		secondJoin.EndpointID, "owner_a", secondManifest.Digest,
		time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AcceptNetworkDirectKeyGrant("owner_a", "net_direct", secondJoin.EndpointID,
		secondOwnerProof); err != nil {
		t.Fatal(err)
	}
	bundle, err := s.NetworkDirectPeerKey(scope, secondJoin.EndpointID)
	if err != nil || bundle.Sender.Manifest.NativeSessionID != "" ||
		bundle.Receiver.Manifest.NativeSessionID != "" {
		t.Fatalf("peer key bundle leaked native locator: %#v %v", bundle, err)
	}
	messageContext := networkDirectContext(bundle, "msg_synthetic_direct", "SEND", "", "")
	wire, err := e2ee.SealNetworkDirectMessage(endpointKey, secondKey.Public(),
		messageContext, []byte("private synthetic direct message"), 1)
	if err != nil {
		t.Fatal(err)
	}
	message, err := s.EnqueueNetworkDirectSealedSend(NetworkDirectSendInput{Scope: scope,
		TargetEndpointID: secondJoin.EndpointID, MessageID: messageContext.MessageID,
		IdempotencyKey: "once", Ciphertext: wire, NodeCredentialDigest: credentialDigest})
	if err != nil || message.PayloadMode != RelayPayloadModeSealedV1 || message.Route.MessageID != messageContext.MessageID {
		t.Fatalf("Network direct sealed enqueue: %#v %v", message, err)
	}
	if _, _, err := e2ee.OpenNetworkDirectMessage(secondKey, endpointKey.Public(),
		messageContext, message.Ciphertext); err != nil {
		t.Fatalf("queued ciphertext not openable by exact recipient: %v", err)
	}
	claimed, err := s.ClaimNetworkDirectSealedInbox(NetworkDirectClaimInput{
		NodeID: nodeID, ConsumerID: "synthetic-direct-consumer", Limit: 10,
		CredentialDigest: credentialDigest})
	if err != nil || len(claimed) != 1 || claimed[0].MessageID != messageContext.MessageID {
		t.Fatalf("Network direct claim: %#v %v", claimed, err)
	}
	authorized, err := s.AuthorizeClaimedNetworkDirectDelivery(credentialDigest,
		claimed[0].MessageID, claimed[0].AttemptID)
	if err != nil || authorized.NativeSessionID != "native_network_direct_second" ||
		authorized.Bundle.Sender.Manifest.NativeSessionID != "" {
		t.Fatalf("Network direct pre-injection authorization: %#v %v", authorized, err)
	}
	receipt := RelayReceipt{AttemptID: claimed[0].AttemptID,
		MessageID: claimed[0].MessageID, Digest: claimed[0].Digest,
		TargetEndpointID: claimed[0].RecipientEndpointID,
		BindingID:        claimed[0].BindingID, BindingEpoch: claimed[0].BindingEpoch,
		Layer: RelayReceiptNodeReceived}
	if _, err := s.RecordRelayReceipt(receipt); !errors.Is(err, ErrRelayInvalidReceipt) {
		t.Fatalf("generic receipt bypassed Network Node credential: %v", err)
	}
	if _, err := s.RecordNetworkDirectReceipt(credentialDigest, receipt); err != nil {
		t.Fatalf("current Node receipt: %v", err)
	}
	if duplicate, err := s.ClaimNetworkDirectSealedInbox(NetworkDirectClaimInput{
		NodeID: nodeID, ConsumerID: "other-synthetic-consumer", Limit: 10,
		CredentialDigest: credentialDigest}); err != nil || len(duplicate) != 0 {
		t.Fatalf("second consumer stole active attempt: %#v %v", duplicate, err)
	}
	requestID, askMessageID := "rq_synthetic_direct", "msg_synthetic_direct_ask"
	askContext := networkDirectContext(bundle, askMessageID, "REQUEST", requestID, "")
	askWire, err := e2ee.SealNetworkDirectMessage(endpointKey, secondKey.Public(),
		askContext, []byte("synthetic private request"), 2)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	askInput := NetworkDirectAskInput{NetworkDirectSendInput: NetworkDirectSendInput{
		Scope: scope, NodeCredentialDigest: credentialDigest,
		TargetEndpointID: secondJoin.EndpointID, MessageID: askMessageID,
		IdempotencyKey: "ask-once", Ciphertext: askWire},
		RequestID: requestID, ExpiresAt: deadline}
	ask, err := s.EnqueueNetworkDirectSealedAsk(askInput)
	if err != nil || ask.State != FabricRequestOpen {
		t.Fatalf("sealed ask: %#v %v", ask, err)
	}
	if retry, err := s.EnqueueNetworkDirectSealedAsk(askInput); err != nil ||
		retry.RequestID != ask.RequestID {
		t.Fatalf("sealed ask retry: %#v %v", retry, err)
	}
	route, err := s.NetworkDirectReplyPeerKey(secondScope, credentialDigest, requestID)
	if err != nil || route.RequestMessageID != askMessageID ||
		route.Bundle.Receiver.Manifest.EndpointID != joined.EndpointID {
		t.Fatalf("reply route: %#v %v", route, err)
	}
	replyMessageID := "msg_synthetic_direct_reply"
	replyContext := networkDirectContext(route.Bundle, replyMessageID,
		"REPLY", requestID, askMessageID)
	replyWire, err := e2ee.SealNetworkDirectMessage(secondKey, endpointKey.Public(),
		replyContext, []byte("synthetic private reply"), 1)
	if err != nil {
		t.Fatal(err)
	}
	replyInput := NetworkDirectReplyInput{Scope: secondScope,
		NodeCredentialDigest: credentialDigest, RequestID: requestID,
		MessageID: replyMessageID, IdempotencyKey: "reply-once", Ciphertext: replyWire}
	replied, err := s.EnqueueNetworkDirectSealedReply(replyInput)
	if err != nil || replied.State != FabricRequestReplied {
		t.Fatalf("sealed reply: %#v %v", replied, err)
	}
	if retryRoute, err := s.NetworkDirectReplyPeerKey(secondScope,
		credentialDigest, requestID); err != nil || retryRoute.RequestMessageID != askMessageID {
		t.Fatalf("reply route lost after accepted reply: %#v %v", retryRoute, err)
	}
	if retry, err := s.EnqueueNetworkDirectSealedReply(replyInput); err != nil ||
		retry.ReplyMessageID != replyMessageID {
		t.Fatalf("exact reply retry: %#v %v", retry, err)
	}
	badReply := replyInput
	badReply.MessageID = "msg_synthetic_second_reply"
	if _, err := s.EnqueueNetworkDirectSealedReply(badReply); !errors.Is(err, ErrRelayRequestTerminal) {
		t.Fatalf("second reply accepted: %v", err)
	}
	if status, err := s.NetworkDirectRequestStatus(scope, requestID); err != nil ||
		status.State != FabricRequestReplied {
		t.Fatalf("request status: %#v %v", status, err)
	}
	for sequence := 3; sequence <= networkDirectPendingSendsPerSender+2; sequence++ {
		messageID := NewID("direct-synthetic")
		context := networkDirectContext(bundle, messageID, "SEND", "", "")
		wire, err := e2ee.SealNetworkDirectMessage(endpointKey, secondKey.Public(),
			context, []byte("synthetic bounded SEND"), uint64(sequence))
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.EnqueueNetworkDirectSealedSend(NetworkDirectSendInput{Scope: scope,
			NodeCredentialDigest: credentialDigest, TargetEndpointID: secondJoin.EndpointID,
			MessageID: messageID, Ciphertext: wire})
		if sequence < networkDirectPendingSendsPerSender+2 && err != nil {
			t.Fatalf("SEND %d before pending bound: %v", sequence, err)
		}
		if sequence == networkDirectPendingSendsPerSender+2 &&
			!errors.Is(err, ErrRelayResourceExhausted) {
			t.Fatalf("pending SEND bound was bypassed: %v", err)
		}
	}
	receipt.Layer = RelayReceiptCodexQueueAccepted
	if _, err := s.RecordNetworkDirectReceipt(credentialDigest, receipt); err != nil {
		t.Fatalf("durable queue acceptance receipt: %v", err)
	}
	var stillClaimed string
	if err := s.db.QueryRow(`SELECT state FROM relay_v2_inbox WHERE message_id=?`,
		claimed[0].MessageID).Scan(&stillClaimed); err != nil || stillClaimed != RelayInboxClaimed {
		t.Fatalf("queue acceptance falsely marked consumption: %q %v", stillClaimed, err)
	}
	availableMessageID := NewID("direct-synthetic-after-queue")
	availableContext := networkDirectContext(bundle, availableMessageID, "SEND", "", "")
	availableWire, err := e2ee.SealNetworkDirectMessage(endpointKey, secondKey.Public(),
		availableContext, []byte("synthetic released transport slot"), 67)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueNetworkDirectSealedSend(NetworkDirectSendInput{Scope: scope,
		NodeCredentialDigest: credentialDigest, TargetEndpointID: secondJoin.EndpointID,
		MessageID: availableMessageID, Ciphertext: availableWire}); err != nil {
		t.Fatalf("queue-confirmed SEND did not release transport slot: %v", err)
	}
	renewed, err := s.RenewNetworkAccess(RenewNetworkAccessInput{NetworkID: "net_direct",
		EndpointID: joined.EndpointID, OwnerID: "owner_a", NodeID: nodeID,
		Harness: "codex", NativeSessionID: nativeID,
		NodeCredentialHash: credentialDigest, CredentialHash: "direct-access-hash-renewed",
		LeaseOwner: "direct-access-lease-renewed", LeaseExpiresAt: leaseExpiry})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueNetworkDirectSealedAsk(askInput); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old Network access scope retried accepted Ask: %v", err)
	}
	scope.AccessEpoch = renewed.AccessSessionEpoch
	scope.LeaseOwner = "direct-access-lease-renewed"
	askInput.Scope = scope
	if recovered, err := s.EnqueueNetworkDirectSealedAsk(askInput); err != nil ||
		recovered.RequestID != requestID {
		t.Fatalf("current access did not recover accepted Ask: %#v %v", recovered, err)
	}
	if _, err := s.CreateNetwork(Network{ID: "net_direct_other", HubID: bound.HubID,
		Name: "Independent direct scope", OwnerID: "owner_a"}); err != nil {
		t.Fatal(err)
	}
	joinOtherNetwork := func(nativeSessionID, accessHash, leaseOwner string,
		identity *e2ee.Identity, expectedEndpointID string) NetworkAccessScope {
		t.Helper()
		invitation := "synthetic-second-network-invitation-" + nativeSessionID
		if err := s.IssueNetworkInvitation("net_direct_other", "owner_a", "owner_a",
			invitation, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), grants); err != nil {
			t.Fatal(err)
		}
		proof, err := owner.SignOwnerNetworkJoinGrant("owner_a", bound.HubID,
			"net_direct_other", nodeID, nativeSessionID,
			NetworkInvitationDigest(invitation), owner.Public().ID, grants,
			false, time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Nonce     string `json:"nonce"`
			ExpiresAt string `json:"expires_at"`
		}
		if err := json.Unmarshal(proof, &claims); err != nil {
			t.Fatal(err)
		}
		joinedOther, err := s.AcceptNetworkJoin(AcceptNetworkJoinInput{
			NetworkID: "net_direct_other", OwnerID: "owner_a", TrustDomainID: "domain",
			NodeID: nodeID, NativeSessionID: nativeSessionID, Harness: "codex",
			EndpointName: "same stable Endpoint", InvitationToken: invitation,
			ProofNonce: claims.Nonce, ProofDigest: NetworkInvitationDigest(string(proof)),
			ProofExpiresAt: claims.ExpiresAt, OwnerKeyID: owner.Public().ID,
			OwnerJoinProof: string(proof), NodeCredentialHash: credentialDigest,
			Grants: grants, CredentialHash: accessHash, LeaseOwner: leaseOwner,
			LeaseExpiresAt: leaseExpiry})
		if err != nil || joinedOther.EndpointID != expectedEndpointID {
			t.Fatalf("second Network changed native Endpoint: %#v %v", joinedOther, err)
		}
		otherScope := NetworkAccessScope{NetworkID: "net_direct_other",
			PrincipalID: joinedOther.PrincipalID, EndpointID: joinedOther.EndpointID,
			AccessSessionID: joinedOther.AccessSessionID,
			AccessEpoch:     joinedOther.AccessSessionEpoch, LeaseOwner: leaseOwner,
			MembershipID:               joinedOther.MembershipID,
			MembershipRevision:         joinedOther.MembershipRevision,
			EndpointMembershipRevision: joinedOther.EndpointRevision}
		otherBinding, err := s.EnsureNetworkDirectNativeBinding(otherScope)
		if err != nil || otherBinding.ID != binding.ID && expectedEndpointID == joined.EndpointID ||
			otherBinding.ID != secondBinding.ID && expectedEndpointID == secondJoin.EndpointID {
			t.Fatalf("second Network rotated native writer: %#v %v", otherBinding, err)
		}
		candidateProof, err := identity.SignNetworkDirectKeyAttestation(bound.HubID,
			"net_direct_other", expectedEndpointID, joinedOther.PrincipalID,
			nodeID, otherBinding.ID, otherBinding.Epoch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.RegisterNetworkDirectKeyCandidate(otherScope, candidateProof); err != nil {
			t.Fatal(err)
		}
		manifest, err := s.PreviewNetworkDirectKeyGrant("owner_a", "net_direct_other",
			expectedEndpointID, owner.Public().ID)
		if err != nil {
			t.Fatal(err)
		}
		ownerProof, err := owner.SignOwnerNetworkDirectKeyGrant(bound.HubID,
			"net_direct_other", expectedEndpointID, "owner_a", manifest.Digest,
			time.Now().UTC().Add(-time.Minute), time.Now().UTC().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.AcceptNetworkDirectKeyGrant("owner_a", "net_direct_other",
			expectedEndpointID, ownerProof); err != nil {
			t.Fatal(err)
		}
		return otherScope
	}
	otherSource := joinOtherNetwork(nativeID, "direct-access-hash-other-a",
		"direct-access-lease-other-a", endpointKey, joined.EndpointID)
	joinOtherNetwork("native_network_direct_second", "direct-access-hash-other-b",
		"direct-access-lease-other-b", secondKey, secondJoin.EndpointID)
	otherBundle, err := s.NetworkDirectPeerKey(otherSource, secondJoin.EndpointID)
	if err != nil {
		t.Fatal(err)
	}
	otherMessageID := "msg_synthetic_direct_other_network"
	otherContext := networkDirectContext(otherBundle, otherMessageID, "SEND", "", "")
	otherWire, err := e2ee.SealNetworkDirectMessage(endpointKey, secondKey.Public(),
		otherContext, []byte("synthetic other Network message"), 67)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueNetworkDirectSealedSend(NetworkDirectSendInput{
		Scope: otherSource, NodeCredentialDigest: credentialDigest,
		TargetEndpointID: secondJoin.EndpointID, MessageID: otherMessageID,
		IdempotencyKey: "once", Ciphertext: otherWire}); err != nil {
		t.Fatalf("same caller idempotency key collided across Networks: %v", err)
	}
	oldCredentialDigest := credentialDigest
	rotatedCredentialDigest := nodeBindingTestCredentialDigest("synthetic-network-direct-node-token-rotated")
	rotatedCodeDigest := nodeBindingTestCodeDigest("synthetic-network-direct-code-rotated")
	if _, err := s.RevokeNodeDeviceBinding("owner_a", confirmedBinding.ID, confirmedBinding.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE node_device_binding_requests_v2 SET created_at=?
WHERE node_id=?`, time.Now().UTC().Add(-time.Hour).Format(time.RFC3339Nano), nodeID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePendingNodeDeviceBinding(nodeID, nodeID, rotatedCredentialDigest,
		rotatedCodeDigest, time.Now().UTC().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPendingNodeDeviceBinding("owner_a", device.DeviceID,
		rotatedCodeDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthorizeClaimedNetworkDirectDelivery(oldCredentialDigest,
		claimed[0].MessageID, claimed[0].AttemptID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old Node credential authorized current attempt: %v", err)
	}
	receipt.Layer = RelayReceiptNativeThreadResumed
	if _, err := s.RecordNetworkDirectReceipt(oldCredentialDigest, receipt); !errors.Is(err, ErrRelayStaleReceipt) {
		t.Fatalf("old Node credential advanced receipt: %v", err)
	}
	credentialDigest = rotatedCredentialDigest
	if _, err := s.AuthorizeClaimedNetworkDirectDelivery(credentialDigest,
		claimed[0].MessageID, claimed[0].AttemptID); err != nil {
		t.Fatalf("rotated current Node credential could not recover attempt: %v", err)
	}
	group, err := s.CreateGroup(Group{ID: "grp_synthetic_direct_conversion",
		NetworkID: "net_direct", Name: "explicit Group after Network-only Join",
		OwnerPrincipalID: "owner_a", TrustDomainID: "domain", State: GroupStateActive})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateMembership(Membership{ID: NewID("member"),
		PrincipalID: joined.PrincipalID, GroupID: group.ID, Role: "member",
		Status: MembershipStatusActive}); err != nil {
		t.Fatal(err)
	}
	groupBinding, err := s.CreateSessionBinding(SessionBinding{ID: NewID("bind"),
		EndpointID: joined.EndpointID, PrincipalID: joined.PrincipalID,
		GroupID: group.ID, NativeSessionID: nativeID, NodeID: nodeID,
		LeaseOwner: "synthetic-writer-one", LeaseExpiresAt: leaseExpiry,
		Status: SessionBindingStatusLeased})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AssociateEndpoint(joined.EndpointID, joined.PrincipalID,
		group.ID, groupBinding.ID); err != nil {
		t.Fatal(err)
	}
	groupClaim, err := s.ClaimRelaySealedV1Inbox(RelayClaimInput{
		RecipientEndpointID: joined.EndpointID, ConsumerID: "synthetic-group-consumer",
		BindingID: groupBinding.ID, BindingEpoch: groupBinding.Epoch, Limit: 10})
	if err != nil || len(groupClaim) != 0 {
		t.Fatalf("Group claim consumed Network direct reply: %#v %v", groupClaim, err)
	}
	if rebound, err := s.RebindPendingRelayInbox(joined.EndpointID, binding.ID,
		binding.Epoch, groupBinding.ID, groupBinding.Epoch); !errors.Is(err, ErrRelayBindingMismatch) || rebound != 0 {
		t.Fatalf("Group reconnect rebound immutable Network direct ciphertext: %d %v", rebound, err)
	}
	var replyBindingID string
	if err := s.db.QueryRow(`SELECT binding_id FROM relay_v2_inbox WHERE message_id=?`,
		replyMessageID).Scan(&replyBindingID); err != nil || replyBindingID != binding.ID {
		t.Fatalf("Network direct reply binding changed after Group rebind: %q %v", replyBindingID, err)
	}
	stableDirectBinding, err := s.EnsureNetworkDirectNativeBinding(scope)
	if err != nil || stableDirectBinding.Epoch != binding.Epoch ||
		stableDirectBinding.ID != binding.ID {
		t.Fatalf("adding Group changed Network native route: %#v %v", stableDirectBinding, err)
	}
	if _, err := s.db.Exec(`UPDATE session_bindings SET lease_owner=?,epoch=epoch+1,
		updated_at=? WHERE id=?`, "synthetic-writer-two", now(), groupBinding.ID); err != nil {
		t.Fatal(err)
	}
	takenOver, err := s.EnsureNetworkDirectNativeBinding(scope)
	if err != nil || takenOver.Epoch != binding.Epoch+1 || takenOver.ID != binding.ID {
		t.Fatalf("writer takeover did not fence direct native route: %#v %v", takenOver, err)
	}
	if _, err := s.AuthorizeClaimedNetworkDirectDelivery(credentialDigest,
		claimed[0].MessageID, claimed[0].AttemptID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("old direct attempt survived Group writer takeover: %v", err)
	}
	if err := s.LeaveEndpointNetwork("net_direct", joined.EndpointID, joined.EndpointRevision); err != nil {
		t.Fatal(err)
	}
	receipt.Layer = RelayReceiptApplicationAck
	if _, err := s.RecordNetworkDirectReceipt(credentialDigest, receipt); !errors.Is(err, ErrRelayStaleReceipt) {
		t.Fatalf("revoked claimed attempt ACK accepted: %v", err)
	}
	if _, err := s.AuthorizeClaimedNetworkDirectDelivery(credentialDigest,
		claimed[0].MessageID, claimed[0].AttemptID); !errors.Is(err, ErrNetworkPermission) {
		t.Fatalf("revoked source could inject claimed message: %v", err)
	}
	if err := s.db.QueryRow(`SELECT network_id FROM network_direct_message_routes_v2 WHERE message_id=?`,
		messageContext.MessageID).Scan(new(string)); err != nil {
		t.Fatalf("revocation deleted preserved ciphertext route: %v", err)
	}
	stale, err := reopened.GetNetworkDirectKeyGrant("owner_a", "net_direct", joined.EndpointID)
	if err != nil || stale.State != "stale" {
		t.Fatalf("leave retained direct key authority: %#v %v", stale, err)
	}
	if _, err := reopened.AcceptNetworkDirectKeyGrant("owner_a", "net_direct", joined.EndpointID, ownerProof); !errors.Is(err, ErrNetworkDirectKeyUnavailable) {
		t.Fatalf("old proof restored leave: %v", err)
	}
}
