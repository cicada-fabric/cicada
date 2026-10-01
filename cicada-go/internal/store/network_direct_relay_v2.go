package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const networkDirectAuthorizationPrefix = "network-direct.v1:"
const networkDirectPendingSendsPerSender = 64

// NetworkDirectPeerKeyEvidence carries only public key material and an
// owner-signed current manifest. NativeSessionID is removed before this can
// cross an Owner boundary. The receiving Node must compare OwnerPublic with
// its own independently pinned owner-key registry before trusting the proof.
type NetworkDirectPeerKeyEvidence struct {
	Manifest                NetworkDirectKeyManifest           `json:"manifest"`
	Grant                   OwnerNetworkDirectKeyGrant         `json:"grant"`
	GrantProof              []byte                             `json:"grant_proof"`
	CollaborationManifest   *NetworkCollaborationKeyManifest   `json:"collaboration_manifest,omitempty"`
	CollaborationGrant      *OwnerNetworkCollaborationKeyGrant `json:"collaboration_grant,omitempty"`
	CollaborationGrantProof []byte                             `json:"collaboration_grant_proof,omitempty"`
	OwnerPublic             e2ee.PublicIdentity                `json:"owner_public_identity"`
}

type NetworkDirectPeerBundle struct {
	HubID              string                       `json:"hub_id"`
	NetworkID          string                       `json:"network_id"`
	Purpose            string                       `json:"purpose,omitempty"`
	NativeContextScope NativeContextScopeMetadata   `json:"native_context_scope"`
	Sender             NetworkDirectPeerKeyEvidence `json:"sender"`
	Receiver           NetworkDirectPeerKeyEvidence `json:"receiver"`
}

// NetworkDirectDeliveryAuthorization is returned only for an exact claimed
// attempt after current Node, enrollment, key and native route checks.
type NetworkDirectDeliveryAuthorization struct {
	NetworkID            string                                   `json:"network_id"`
	NativeContextScope   NativeContextScopeMetadata               `json:"native_context_scope"`
	EndpointID           string                                   `json:"endpoint_id"`
	NativeSessionID      string                                   `json:"native_session_id"`
	BindingID            string                                   `json:"binding_id"`
	BindingEpoch         uint64                                   `json:"binding_epoch"`
	MessageID            string                                   `json:"message_id"`
	AttemptID            string                                   `json:"attempt_id"`
	Digest               string                                   `json:"digest"`
	Context              e2ee.NetworkDirectContext                `json:"context"`
	CollaborationContext *e2ee.NetworkCollaborationMessageContext `json:"collaboration_context,omitempty"`
	Bundle               NetworkDirectPeerBundle                  `json:"bundle"`
	NetworkTask          *NetworkTaskDeliveryAuthorization        `json:"network_task,omitempty"`
	NetworkBroadcast     *NetworkBroadcastDeliveryAuthorization   `json:"network_broadcast,omitempty"`
}

func networkDirectMembershipAllowsTx(tx *sql.Tx, networkID, endpointID,
	principalID, action string, at time.Time) error {
	if networkID == "" || endpointID == "" || principalID == "" || action == "" {
		return ErrNetworkPermission
	}
	var expiry string
	err := tx.QueryRow(`SELECT m.expires_at FROM networks_v2 n
JOIN network_memberships_v2 m ON m.network_id=n.id AND m.principal_id=? AND m.status='active'
JOIN endpoint_network_memberships_v2 en ON en.network_id=n.id AND en.endpoint_id=? AND en.status='active'
JOIN fabric_endpoints e ON e.id=en.endpoint_id AND e.principal_id=m.principal_id AND e.status!='left'
JOIN principals p ON p.id=e.principal_id AND p.status='active' AND p.owner_id=e.owner
WHERE n.id=? AND n.state='ACTIVE'
AND EXISTS(SELECT 1 FROM json_each(m.grants_json) WHERE value=?)`, principalID,
		endpointID, networkID, action).Scan(&expiry)
	if err != nil {
		return ErrNetworkPermission
	}
	if expiry != "" {
		deadline, err := time.Parse(time.RFC3339Nano, expiry)
		if err != nil || !deadline.After(at) {
			return ErrNetworkPermission
		}
	}
	return nil
}

func readNetworkDirectPeerKeyEvidenceTx(tx *sql.Tx, networkID, endpointID string,
	at time.Time) (NetworkDirectPeerKeyEvidence, error) {
	var ownerID string
	if err := tx.QueryRow(`SELECT owner FROM fabric_endpoints WHERE id=?`, endpointID).Scan(&ownerID); err != nil {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	manifest, err := readNetworkDirectKeyManifestTx(tx, ownerID, networkID, endpointID, at)
	if err != nil {
		return NetworkDirectPeerKeyEvidence{}, err
	}
	grant, proof, err := readOwnerNetworkDirectKeyGrantTx(tx, networkID, endpointID)
	if err != nil || grant.State != "active" || grant.OwnerID != ownerID ||
		grant.ManifestDigest != manifest.Digest {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	var ownerState, publicJSON string
	if err := tx.QueryRow(`SELECT state,public_identity_json FROM owner_approval_keys_v2
WHERE owner_id=? AND key_id=?`, ownerID, grant.OwnerKeyID).Scan(&ownerState, &publicJSON); err != nil ||
		ownerState != OwnerApprovalKeyActive {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	var ownerPublic e2ee.PublicIdentity
	if err := json.Unmarshal([]byte(publicJSON), &ownerPublic); err != nil {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	acceptedAt, err := time.Parse(time.RFC3339Nano, grant.AcceptedAt)
	if err != nil {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	expected := e2ee.OwnerNetworkDirectKeyGrant{HubID: manifest.HubID,
		NetworkID: networkID, EndpointID: endpointID, OwnerID: ownerID,
		ManifestDigest: manifest.Digest}
	verified, err := e2ee.VerifyOwnerNetworkDirectKeyGrant(proof, ownerPublic, expected, acceptedAt)
	hash := sha256.Sum256(proof)
	if err != nil || verified.Nonce != grant.Nonce || grant.ProofDigest != hex.EncodeToString(hash[:]) {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	manifest.NativeSessionID = ""
	return NetworkDirectPeerKeyEvidence{Manifest: *manifest, Grant: *grant,
		GrantProof: proof, OwnerPublic: ownerPublic}, nil
}

func readNetworkCollaborationPeerKeyEvidenceTx(tx *sql.Tx, networkID, endpointID,
	purpose string, at time.Time) (NetworkDirectPeerKeyEvidence, error) {
	var ownerID string
	if err := tx.QueryRow(`SELECT owner FROM fabric_endpoints WHERE id=?`, endpointID).Scan(&ownerID); err != nil {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	manifest, err := readNetworkCollaborationKeyManifestTx(tx, ownerID, networkID, endpointID, purpose, at)
	if err != nil {
		return NetworkDirectPeerKeyEvidence{}, err
	}
	grant, proof, err := readOwnerNetworkCollaborationKeyGrantTx(tx, purpose, networkID, endpointID)
	if err != nil || grant.State != "active" || grant.OwnerID != ownerID || grant.Purpose != purpose ||
		grant.ManifestDigest != manifest.Digest {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	var ownerState, publicJSON string
	if err := tx.QueryRow(`SELECT state,public_identity_json FROM owner_approval_keys_v2
WHERE owner_id=? AND key_id=?`, ownerID, grant.OwnerKeyID).Scan(&ownerState, &publicJSON); err != nil ||
		ownerState != OwnerApprovalKeyActive {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	var ownerPublic e2ee.PublicIdentity
	if err := json.Unmarshal([]byte(publicJSON), &ownerPublic); err != nil {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	acceptedAt, err := time.Parse(time.RFC3339Nano, grant.AcceptedAt)
	if err != nil {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	expected := e2ee.OwnerNetworkCollaborationKeyGrant{Purpose: purpose, HubID: manifest.Key.HubID,
		NetworkID: networkID, EndpointID: endpointID, OwnerID: ownerID,
		ManifestDigest: manifest.Digest}
	verified, err := e2ee.VerifyOwnerNetworkCollaborationKeyGrant(proof, ownerPublic, expected, acceptedAt)
	hash := sha256.Sum256(proof)
	if err != nil || verified.Nonce != grant.Nonce || grant.ProofDigest != hex.EncodeToString(hash[:]) {
		return NetworkDirectPeerKeyEvidence{}, ErrNetworkDirectKeyUnavailable
	}
	manifest.Key.NativeSessionID = ""
	manifest.Key.Digest = ""
	return NetworkDirectPeerKeyEvidence{Manifest: manifest.Key,
		CollaborationManifest: manifest, CollaborationGrant: grant,
		CollaborationGrantProof: proof, OwnerPublic: ownerPublic}, nil
}

func readNetworkDirectPeerBundleTx(tx *sql.Tx, scope NetworkAccessScope,
	targetEndpointID string, at time.Time) (*NetworkDirectPeerBundle, error) {
	if targetEndpointID == scope.EndpointID || targetEndpointID == "" {
		return nil, ErrNetworkPermission
	}
	if err := networkGuardAccessTx(tx, scope, "direct.send", at); err != nil {
		return nil, err
	}
	sender, err := readNetworkDirectPeerKeyEvidenceTx(tx, scope.NetworkID, scope.EndpointID, at)
	if err != nil || sender.Manifest.PrincipalID != scope.PrincipalID ||
		sender.Manifest.MembershipRevision != scope.MembershipRevision ||
		sender.Manifest.EndpointEnrollmentRevision != scope.EndpointMembershipRevision {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	receiver, err := readNetworkDirectPeerKeyEvidenceTx(tx, scope.NetworkID, targetEndpointID, at)
	if err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	if err := networkDirectMembershipAllowsTx(tx, scope.NetworkID, targetEndpointID,
		receiver.Manifest.PrincipalID, "direct.receive", at); err != nil {
		return nil, err
	}
	if receiver.Manifest.HubID != sender.Manifest.HubID {
		return nil, ErrNetworkPermission
	}
	contextScope, err := readNativeContextScopeForNetworkTx(tx, scope.NetworkID)
	if err != nil {
		return nil, ErrNetworkPermission
	}
	return &NetworkDirectPeerBundle{HubID: sender.Manifest.HubID,
		NetworkID: scope.NetworkID, NativeContextScope: contextScope,
		Sender: sender, Receiver: receiver}, nil
}

func collaborationRoleActions(purpose string) (senderActions, receiverActions []string) {
	switch purpose {
	case e2ee.NetworkCollaborationPurposeTask:
		return []string{"task.offer.publish", "task.offer.result"},
			[]string{"task.offer.list", "task.offer.accept"}
	case e2ee.NetworkCollaborationPurposeBroadcast:
		return []string{"broadcast.publish"}, []string{"broadcast.receive"}
	default:
		return nil, nil
	}
}

func networkAllowsAnyActionTx(tx *sql.Tx, networkID, endpointID,
	principalID string, actions []string, at time.Time) error {
	for _, action := range actions {
		if networkDirectMembershipAllowsTx(tx, networkID, endpointID, principalID, action, at) == nil {
			return nil
		}
	}
	return ErrNetworkPermission
}

func readNetworkCollaborationPeerBundleTx(tx *sql.Tx, scope NetworkAccessScope,
	targetEndpointID, purpose string, at time.Time) (*NetworkDirectPeerBundle, error) {
	if !collaborationPurposeValid(purpose) || targetEndpointID == "" || targetEndpointID == scope.EndpointID {
		return nil, ErrNetworkPermission
	}
	senderActions, receiverActions := collaborationRoleActions(purpose)
	if len(senderActions) == 0 {
		return nil, ErrNetworkPermission
	}
	if err := networkAllowsAnyActionTx(tx, scope.NetworkID, scope.EndpointID,
		scope.PrincipalID, senderActions, at); err != nil {
		return nil, err
	}
	sender, err := readNetworkCollaborationPeerKeyEvidenceTx(tx, scope.NetworkID,
		scope.EndpointID, purpose, at)
	if err != nil || sender.Manifest.PrincipalID != scope.PrincipalID ||
		sender.Manifest.MembershipRevision != scope.MembershipRevision ||
		sender.Manifest.EndpointEnrollmentRevision != scope.EndpointMembershipRevision {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	receiver, err := readNetworkCollaborationPeerKeyEvidenceTx(tx, scope.NetworkID,
		targetEndpointID, purpose, at)
	if err != nil {
		return nil, ErrNetworkDirectKeyUnavailable
	}
	if err := networkAllowsAnyActionTx(tx, scope.NetworkID, targetEndpointID,
		receiver.Manifest.PrincipalID, receiverActions, at); err != nil {
		return nil, err
	}
	if receiver.Manifest.HubID != sender.Manifest.HubID {
		return nil, ErrNetworkPermission
	}
	contextScope, err := readNativeContextScopeForNetworkTx(tx, scope.NetworkID)
	if err != nil {
		return nil, ErrNetworkPermission
	}
	return &NetworkDirectPeerBundle{HubID: sender.Manifest.HubID,
		NetworkID: scope.NetworkID, Purpose: purpose, NativeContextScope: contextScope,
		Sender: sender, Receiver: receiver}, nil
}

// NetworkCollaborationPeerKey supplies purpose-specific public key consent.
// `TASK` and `BROADCAST` evidence is separate from Direct v1 and cannot be
// used for ordinary direct traffic.
func (s *Store) NetworkCollaborationPeerKey(scope NetworkAccessScope,
	targetEndpointID, purpose string) (*NetworkDirectPeerBundle, error) {
	if !strings.HasPrefix(targetEndpointID, "ep_") || len(targetEndpointID) > 256 ||
		!collaborationPurposeValid(purpose) {
		return nil, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	bundle, err := readNetworkCollaborationPeerBundleTx(tx, scope, targetEndpointID,
		purpose, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return bundle, nil
}

// NetworkDirectPeerKey is an exact Endpoint lookup; nickname resolution still
// goes through the filtered directory and its ambiguity guard. The response
// contains public evidence only and no private Group or native locator.
func (s *Store) NetworkDirectPeerKey(scope NetworkAccessScope,
	targetEndpointID string) (*NetworkDirectPeerBundle, error) {
	if !strings.HasPrefix(targetEndpointID, "ep_") || len(targetEndpointID) > 256 {
		return nil, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	bundle, err := readNetworkDirectPeerBundleTx(tx, scope, targetEndpointID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return bundle, nil
}

func networkDirectContext(bundle *NetworkDirectPeerBundle, messageID, kind,
	requestID, replyTo string, parentRequestID ...string) e2ee.NetworkDirectContext {
	sender, receiver := bundle.Sender.Manifest, bundle.Receiver.Manifest
	parent := ""
	if len(parentRequestID) == 1 {
		parent = parentRequestID[0]
	} else if len(parentRequestID) > 1 {
		parent = "\x00"
	}
	return e2ee.NetworkDirectContext{
		HubID: bundle.HubID, NetworkID: bundle.NetworkID,
		MessageID: messageID, Kind: kind, RequestID: requestID, ReplyTo: replyTo,
		ParentRequestID:  parent,
		SenderEndpointID: sender.EndpointID, SenderPrincipalID: sender.PrincipalID,
		SenderOwnerID: sender.OwnerID, SenderMembershipRevision: sender.MembershipRevision,
		SenderEnrollmentRevision: sender.EndpointEnrollmentRevision,
		SenderBindingEpoch:       sender.BindingEpoch, SenderKeyID: sender.Candidate.Public.ID,
		ReceiverEndpointID: receiver.EndpointID, ReceiverPrincipalID: receiver.PrincipalID,
		ReceiverOwnerID: receiver.OwnerID, ReceiverMembershipRevision: receiver.MembershipRevision,
		ReceiverEnrollmentRevision: receiver.EndpointEnrollmentRevision,
		ReceiverBindingEpoch:       receiver.BindingEpoch, ReceiverKeyID: receiver.Candidate.Public.ID,
	}
}

func networkCollaborationContext(bundle *NetworkDirectPeerBundle, messageID string) (*e2ee.NetworkCollaborationMessageContext, error) {
	if bundle == nil || !collaborationPurposeValid(bundle.Purpose) {
		return nil, ErrNetworkPermission
	}
	return &e2ee.NetworkCollaborationMessageContext{Purpose: bundle.Purpose,
		Route: networkDirectContext(bundle, messageID, "SEND", "", "")}, nil
}

// NetworkDirectContext is the exact route builder shared by Node sealing and
// Hub admission. The Hub still derives its own Bundle and verifies the wire.
func NetworkDirectContext(bundle *NetworkDirectPeerBundle, messageID, kind,
	requestID, replyTo string, parentRequestID ...string) e2ee.NetworkDirectContext {
	return networkDirectContext(bundle, messageID, kind, requestID, replyTo, parentRequestID...)
}

type NetworkDirectSendInput struct {
	Scope                NetworkAccessScope
	NodeCredentialDigest string
	TargetEndpointID     string
	MessageID            string
	IdempotencyKey       string
	Ciphertext           []byte
}

type NetworkDirectAskInput struct {
	NetworkDirectSendInput
	RequestID       string
	ParentRequestID string
	ExpiresAt       string
}

type NetworkDirectReplyInput struct {
	Scope                NetworkAccessScope
	NodeCredentialDigest string
	RequestID            string
	MessageID            string
	IdempotencyKey       string
	Ciphertext           []byte
}

type NetworkDirectReplyRoute struct {
	RequestID        string                   `json:"request_id"`
	RequestMessageID string                   `json:"request_message_id"`
	ParentRequestID  string                   `json:"parent_request_id,omitempty"`
	Bundle           *NetworkDirectPeerBundle `json:"bundle"`
}

// NetworkDirectReplyPeerKey derives the peer from the current pending request
// under the receiver's authenticated Network scope. A model-supplied target
// is never an authority for REPLY.
func (s *Store) NetworkDirectReplyPeerKey(scope NetworkAccessScope,
	credentialDigest, requestID string) (*NetworkDirectReplyRoute, error) {
	if requestID == "" || !validNodeCredentialDigest(credentialDigest) {
		return nil, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := networkDirectSourceNodeCredentialTx(tx, scope, credentialDigest); err != nil {
		return nil, err
	}
	request, err := relayLoadRequestTx(tx, requestID)
	if err != nil || request == nil || request.ReceiverEndpointID != scope.EndpointID ||
		request.ReceiverPrincipalID != scope.PrincipalID ||
		request.AuthorizationRef != networkDirectAuthorizationPrefix+scope.NetworkID ||
		(request.State != FabricRequestOpen && request.State != FabricRequestReplied) {
		return nil, ErrNetworkPermission
	}
	if request.State == FabricRequestOpen && relayParseExpired(request.ExpiresAt, time.Now().UTC()) {
		return nil, ErrNetworkPermission
	}
	at := time.Now().UTC()
	if err := networkGuardDirectMessageTx(tx, request.MessageID, scope.NetworkID, at); err != nil {
		return nil, err
	}
	parentRequestID, err := relayParentRequestForSealedRouteTx(tx, RelaySealedV1Route{
		MessageID: request.MessageID, RequestID: request.RequestID, Kind: "ask",
	})
	if err != nil {
		return nil, ErrNetworkPermission
	}
	bundle, err := readNetworkDirectPeerBundleTx(tx, scope, request.SenderEndpointID, at)
	if err != nil || bundle.Receiver.Manifest.PrincipalID != request.SenderPrincipalID ||
		bundle.Receiver.Manifest.BindingID != request.SenderBindingID ||
		bundle.Receiver.Manifest.BindingEpoch != request.SenderBindingEpoch {
		return nil, ErrNetworkPermission
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &NetworkDirectReplyRoute{RequestID: requestID,
		RequestMessageID: request.MessageID, ParentRequestID: parentRequestID,
		Bundle: bundle}, nil
}

func networkDirectSourceNodeCredentialTx(tx *sql.Tx, scope NetworkAccessScope,
	credentialDigest string) error {
	return networkSourceNodeCredentialActionTx(tx, scope, credentialDigest, "direct.send")
}

func networkSourceNodeCredentialActionTx(tx *sql.Tx, scope NetworkAccessScope,
	credentialDigest, action string) error {
	if !validNodeCredentialDigest(credentialDigest) {
		return ErrNetworkPermission
	}
	if err := networkGuardAccessTx(tx, scope, action, time.Now().UTC()); err != nil {
		return err
	}
	var current int
	err := tx.QueryRow(`SELECT 1 FROM network_access_sessions_v2 access
JOIN networks_v2 network ON network.id=access.network_id AND network.state='ACTIVE'
JOIN fabric_endpoints endpoint ON endpoint.id=access.endpoint_id
  AND endpoint.principal_id=access.principal_id AND endpoint.machine_id=access.node_id
JOIN node_owner_bindings_v2 binding ON binding.node_id=access.node_id
  AND binding.owner_id=endpoint.owner AND binding.hub_id=network.hub_id
  AND binding.node_credential_digest=? AND binding.state='ACTIVE'
JOIN fabric_node_credentials credential ON credential.node_id=binding.node_id
  AND credential.credential_hash=binding.node_credential_digest
  AND credential.version=binding.node_credential_version AND credential.status='active'
WHERE access.id=? AND access.network_id=? AND access.endpoint_id=?
  AND access.principal_id=? AND access.status='active'`, credentialDigest,
		scope.AccessSessionID, scope.NetworkID, scope.EndpointID,
		scope.PrincipalID).Scan(&current)
	if err != nil {
		return ErrNetworkPermission
	}
	return nil
}

func networkDirectIdempotencyKey(networkID, key string) string {
	if key == "" {
		return ""
	}
	hash := sha256.Sum256([]byte("cicada/network/direct-idempotency/v1\x00" + networkID + "\x00" + key))
	return hex.EncodeToString(hash[:])
}

func insertNetworkDirectRouteTx(tx *sql.Tx, bundle *NetworkDirectPeerBundle,
	messageID string) error {
	sender, receiver := bundle.Sender, bundle.Receiver
	purpose := bundle.Purpose
	senderGrantRevision, receiverGrantRevision := sender.Grant.Revision, receiver.Grant.Revision
	if purpose != "" {
		purpose = bundle.Purpose
		if sender.CollaborationGrant == nil || receiver.CollaborationGrant == nil {
			return ErrNetworkDirectKeyUnavailable
		}
		senderGrantRevision, receiverGrantRevision = sender.CollaborationGrant.Revision,
			receiver.CollaborationGrant.Revision
	} else {
		purpose = "DIRECT"
	}
	_, err := tx.Exec(`INSERT INTO network_direct_message_routes_v2
(message_id,network_id,sender_endpoint_id,sender_principal_id,receiver_endpoint_id,
receiver_principal_id,sender_membership_revision,sender_enrollment_revision,
receiver_membership_revision,receiver_enrollment_revision,sender_binding_id,
sender_binding_epoch,receiver_binding_id,receiver_binding_epoch,
sender_key_grant_revision,receiver_key_grant_revision,sender_key_id,receiver_key_id,created_at,key_purpose)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, messageID, bundle.NetworkID,
		sender.Manifest.EndpointID, sender.Manifest.PrincipalID,
		receiver.Manifest.EndpointID, receiver.Manifest.PrincipalID,
		sender.Manifest.MembershipRevision, sender.Manifest.EndpointEnrollmentRevision,
		receiver.Manifest.MembershipRevision, receiver.Manifest.EndpointEnrollmentRevision,
		sender.Manifest.BindingID, sender.Manifest.BindingEpoch,
		receiver.Manifest.BindingID, receiver.Manifest.BindingEpoch,
		senderGrantRevision, receiverGrantRevision,
		sender.Manifest.Candidate.Public.ID, receiver.Manifest.Candidate.Public.ID, now(), purpose)
	return err
}

// EnqueueNetworkDirectSealedSend validates the current authenticated Network
// actor, both owner-approved keys and the sender's outer ML-DSA signature in
// one transaction before using the existing sealed Relay queue and receipt.
func (s *Store) EnqueueNetworkDirectSealedSend(input NetworkDirectSendInput) (*RelaySealedV1Record, error) {
	if input.MessageID == "" || input.TargetEndpointID == "" ||
		len(input.Ciphertext) == 0 || len(input.Ciphertext) > 256*1024 ||
		len(input.IdempotencyKey) > 256 {
		return nil, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := networkDirectSourceNodeCredentialTx(tx, input.Scope,
		input.NodeCredentialDigest); err != nil {
		return nil, err
	}
	bundle, err := readNetworkDirectPeerBundleTx(tx, input.Scope, input.TargetEndpointID,
		time.Now().UTC())
	if err != nil {
		return nil, err
	}
	record, reused, err := enqueueNetworkDirectPayloadTx(tx, bundle, "send", input.MessageID,
		"", "", input.IdempotencyKey, input.Ciphertext)
	if err != nil {
		return nil, err
	}
	if !reused {
		if err := networkDirectCheckSendQuotaTx(tx, bundle); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

type NetworkCollaborationSendInput struct {
	Scope                NetworkAccessScope
	NodeCredentialDigest string
	Purpose              string
	TargetEndpointID     string
	MessageID            string
	IdempotencyKey       string
	Ciphertext           []byte
}

// EnqueueNetworkCollaborationSealedSend admits one purpose-bound SEND with
// typed Owner key proofs and action grants. It uses the existing opaque Relay
// queue but writes `key_purpose`, immutable enrollment/key revisions, and a
// distinct sealed-envelope domain. Direct v1 authorization remains separate.
func (s *Store) EnqueueNetworkCollaborationSealedSend(input NetworkCollaborationSendInput) (*RelaySealedV1Record, error) {
	if !collaborationPurposeValid(input.Purpose) || input.MessageID == "" || input.TargetEndpointID == "" ||
		len(input.Ciphertext) == 0 || len(input.Ciphertext) > 256*1024 || len(input.IdempotencyKey) > 256 {
		return nil, ErrNetworkPermission
	}
	senderAction, receiverAction, err := networkCollaborationMessageActions(input.MessageID, input.Purpose)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := networkSourceNodeCredentialActionTx(tx, input.Scope,
		input.NodeCredentialDigest, senderAction); err != nil {
		return nil, err
	}
	if err := networkDirectMembershipAllowsTx(tx, input.Scope.NetworkID, input.TargetEndpointID,
		networkTaskPrincipalTx(tx, input.TargetEndpointID), receiverAction, time.Now().UTC()); err != nil {
		return nil, err
	}
	bundle, err := readNetworkCollaborationPeerBundleTx(tx, input.Scope,
		input.TargetEndpointID, input.Purpose, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	record, reused, err := enqueueNetworkDirectPayloadTx(tx, bundle, "send", input.MessageID,
		"", "", input.IdempotencyKey, input.Ciphertext)
	if err != nil {
		return nil, err
	}
	if !reused {
		if err := networkDirectCheckSendQuotaTx(tx, bundle); err != nil {
			return nil, err
		}
	} else if err := networkGuardCollaborationMessageTx(tx, record.Route.MessageID,
		input.Scope.NetworkID, input.Purpose, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

func networkCollaborationMessageActions(messageID, purpose string) (string, string, error) {
	switch purpose {
	case e2ee.NetworkCollaborationPurposeTask:
		taskID, suffix, reserved := networkTaskIDFromMessageID(messageID)
		if !reserved || taskID == "" {
			return "", "", ErrNetworkPermission
		}
		if strings.HasPrefix(suffix, "offer:") && len(suffix) > len("offer:") {
			return "task.offer.publish", "task.offer.list", nil
		}
		if strings.HasPrefix(suffix, "result:") {
			return "task.offer.result", "task.offer.accept", nil
		}
	case e2ee.NetworkCollaborationPurposeBroadcast:
		if broadcastID, reserved := networkBroadcastIDFromMessageID(messageID); reserved && broadcastID != "" {
			return "broadcast.publish", "broadcast.receive", nil
		}
	}
	return "", "", ErrNetworkPermission
}

func networkDirectCheckSendQuotaTx(tx *sql.Tx, bundle *NetworkDirectPeerBundle) error {
	var pending int
	err := tx.QueryRow(`SELECT count(*) FROM (SELECT 1 FROM network_direct_message_routes_v2 route
JOIN relay_v2_inbox inbox ON inbox.message_id=route.message_id
JOIN fabric_messages message ON message.id=route.message_id
WHERE route.network_id=? AND route.sender_endpoint_id=? AND message.kind='send'
	AND inbox.state IN ('READY','CLAIMED','INJECTED','INJECTION_UNCERTAIN')
	AND NOT (inbox.state IN ('CLAIMED','INJECTED') AND EXISTS (
	  SELECT 1 FROM relay_v2_receipts receipt
	  WHERE receipt.attempt_id=inbox.attempt_id AND receipt.layer IN (?,?)))
LIMIT ?)`,
		bundle.NetworkID, bundle.Sender.Manifest.EndpointID,
		RelayReceiptCodexQueueAccepted, RelayReceiptRuntimeInjected,
		networkDirectPendingSendsPerSender+1).Scan(&pending)
	if err != nil {
		return err
	}
	if pending > networkDirectPendingSendsPerSender {
		return &RelayAdmissionError{Scope: "network_direct_sender",
			Limit: networkDirectPendingSendsPerSender, Pending: pending,
			RetryAfter: time.Second, RetryAfterSeconds: 1}
	}
	return nil
}

func enqueueNetworkDirectPayloadTx(tx *sql.Tx, bundle *NetworkDirectPeerBundle,
	kind, messageID, requestID, replyTo, callerIdempotencyKey string,
	ciphertext []byte, parentRequestID ...string) (*RelaySealedV1Record, bool, error) {
	contextKind := map[string]string{"send": "SEND", "ask": "REQUEST", "reply": "REPLY"}[kind]
	if contextKind == "" || messageID == "" || len(ciphertext) == 0 || len(ciphertext) > 256*1024 {
		return nil, false, ErrNetworkPermission
	}
	if bundle.Purpose == "" {
		context := networkDirectContext(bundle, messageID, contextKind, requestID, replyTo, parentRequestID...)
		if err := e2ee.VerifyNetworkDirectMessage(bundle.Sender.Manifest.Candidate.Public,
			context, ciphertext); err != nil {
			return nil, false, ErrNetworkPermission
		}
	} else {
		context, err := networkCollaborationContext(bundle, messageID)
		if err != nil || context.Route.Kind != contextKind || context.Route.RequestID != requestID ||
			context.Route.ReplyTo != replyTo || e2ee.VerifyNetworkCollaborationMessage(
			bundle.Sender.Manifest.Candidate.Public, *context, ciphertext) != nil {
			return nil, false, ErrNetworkPermission
		}
	}
	idempotencyKey := networkDirectIdempotencyKey(bundle.NetworkID, callerIdempotencyKey)
	security := RelayMessageSecurity{MessageID: messageID,
		SenderEndpointID:     bundle.Sender.Manifest.EndpointID,
		SenderPrincipalID:    bundle.Sender.Manifest.PrincipalID,
		SenderBindingID:      bundle.Sender.Manifest.BindingID,
		SenderBindingEpoch:   bundle.Sender.Manifest.BindingEpoch,
		ReceiverEndpointID:   bundle.Receiver.Manifest.EndpointID,
		ReceiverPrincipalID:  bundle.Receiver.Manifest.PrincipalID,
		ReceiverBindingID:    bundle.Receiver.Manifest.BindingID,
		ReceiverBindingEpoch: bundle.Receiver.Manifest.BindingEpoch,
		IdempotencyKey:       idempotencyKey,
		VisibilityPolicyRef:  networkDirectAuthorizationPrefix + bundle.NetworkID,
		AuthorizationRef:     networkDirectAuthorizationPrefix + bundle.NetworkID}
	relayInput, err := relaySealedV1Message(RelaySealedV1Input{
		Route: RelaySealedV1Route{MessageID: messageID, RequestID: requestID,
			ReplyTo:            replyTo,
			SenderEndpointID:   security.SenderEndpointID,
			ReceiverEndpointID: security.ReceiverEndpointID, Kind: kind},
		Security: security, Ciphertext: ciphertext, IdempotencyKey: idempotencyKey})
	if err != nil {
		return nil, false, ErrNetworkPermission
	}
	relayInput.networkDirectAuthorized = true
	relayInput.sealedAskAuthorized = kind == "ask"
	relayInput.sealedReplyAuthorized = kind == "reply"
	accepted, reused, err := relayEnqueuePayloadTx(tx, relayInput,
		RelayPayloadModeSealedV1, ciphertext)
	if err != nil {
		return nil, false, err
	}
	if !reused {
		if err := insertNetworkDirectRouteTx(tx, bundle, accepted.Message.ID); err != nil {
			return nil, false, err
		}
	} else if bundle.Purpose == "" {
		if err := networkGuardDirectMessageTx(tx, accepted.Message.ID,
			bundle.NetworkID, time.Now().UTC()); err != nil {
			return nil, false, err
		}
	} else if err := networkGuardCollaborationMessageTx(tx, accepted.Message.ID,
		bundle.NetworkID, bundle.Purpose, time.Now().UTC()); err != nil {
		return nil, false, err
	}
	record, err := relaySealedV1RecordTx(tx, accepted.Message.ID)
	if err != nil {
		return nil, false, err
	}
	return record, reused, nil
}

func (s *Store) EnqueueNetworkDirectSealedAsk(input NetworkDirectAskInput) (*FabricRequest, error) {
	if input.MessageID == "" || input.RequestID == "" || input.RequestID == input.MessageID ||
		input.TargetEndpointID == "" || len(input.IdempotencyKey) > 256 {
		return nil, ErrNetworkPermission
	}
	expires, err := time.Parse(time.RFC3339Nano, input.ExpiresAt)
	if err != nil || expires.UTC().Format(time.RFC3339Nano) != input.ExpiresAt {
		return nil, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := relayAcquireAdmissionGuardTx(tx); err != nil {
		return nil, err
	}
	if err := networkDirectSourceNodeCredentialTx(tx, input.Scope,
		input.NodeCredentialDigest); err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	if previous, err := relayLoadRequestTx(tx, input.RequestID); err != nil {
		return nil, err
	} else if previous != nil {
		if previous.MessageID != input.MessageID ||
			previous.SenderEndpointID != input.Scope.EndpointID ||
			previous.SenderPrincipalID != input.Scope.PrincipalID ||
			previous.ReceiverEndpointID != input.TargetEndpointID ||
			previous.ParentRequestID != input.ParentRequestID ||
			previous.AuthorizationRef != networkDirectAuthorizationPrefix+input.Scope.NetworkID ||
			previous.ExpiresAt != input.ExpiresAt ||
			previous.IdempotencyKey != networkDirectIdempotencyKey(input.Scope.NetworkID,
				input.IdempotencyKey) {
			return nil, ErrRelayIdempotencyConflict
		}
		record, err := relaySealedV1RecordTx(tx, previous.MessageID)
		if err != nil || record.Route.Kind != "ask" ||
			record.Route.RequestID != input.RequestID ||
			!bytes.Equal(record.Ciphertext, input.Ciphertext) {
			return nil, ErrRelayIdempotencyConflict
		}
		if err := networkGuardDirectMessageTx(tx, previous.MessageID,
			input.Scope.NetworkID, at); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return previous, nil
	}
	if !expires.After(at) || expires.After(at.Add(MaxRelayAskLifetime)) {
		return nil, ErrNetworkPermission
	}
	bundle, err := readNetworkDirectPeerBundleTx(tx, input.Scope, input.TargetEndpointID, at)
	if err != nil {
		return nil, err
	}
	if previous, err := relayLoadRequestTx(tx, input.RequestID); err != nil {
		return nil, err
	} else if previous != nil && previous.MessageID != input.MessageID {
		return nil, ErrRelayIdempotencyConflict
	}
	record, reused, err := enqueueNetworkDirectPayloadTx(tx, bundle, "ask", input.MessageID,
		input.RequestID, "", input.IdempotencyKey, input.Ciphertext, input.ParentRequestID)
	if err != nil {
		return nil, err
	}
	if reused {
		previous, err := relayLoadRequestByMessageTx(tx, record.Route.MessageID)
		if err != nil || previous == nil || previous.RequestID != input.RequestID ||
			previous.ExpiresAt != input.ExpiresAt || previous.ParentRequestID != input.ParentRequestID {
			return nil, ErrRelayIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return previous, nil
	}
	limits, err := scanRelayAdmissionLimits(tx.QueryRow(`SELECT per_sender_principal,
per_sender_group,per_receiver,global_limit,retry_after_seconds
FROM relay_v2_admission_config WHERE id=1`))
	if err != nil {
		return nil, err
	}
	if err := relayCheckPendingAskQuotaTx(tx, record.Security, limits,
		at.Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}
	timestamp := now()
	request := &FabricRequest{RequestID: input.RequestID, MessageID: input.MessageID,
		ParentRequestID:      input.ParentRequestID,
		SenderEndpointID:     bundle.Sender.Manifest.EndpointID,
		SenderPrincipalID:    bundle.Sender.Manifest.PrincipalID,
		SenderBindingID:      bundle.Sender.Manifest.BindingID,
		SenderBindingEpoch:   bundle.Sender.Manifest.BindingEpoch,
		ReceiverEndpointID:   bundle.Receiver.Manifest.EndpointID,
		ReceiverPrincipalID:  bundle.Receiver.Manifest.PrincipalID,
		ReceiverBindingID:    bundle.Receiver.Manifest.BindingID,
		ReceiverBindingEpoch: bundle.Receiver.Manifest.BindingEpoch,
		Digest:               record.Security.Digest, IdempotencyKey: record.Security.IdempotencyKey,
		VisibilityPolicyRef: networkDirectAuthorizationPrefix + bundle.NetworkID,
		AuthorizationRef:    networkDirectAuthorizationPrefix + bundle.NetworkID,
		State:               FabricRequestOpen, ExpiresAt: input.ExpiresAt,
		CreatedAt: timestamp, UpdatedAt: timestamp}
	if err := relayDeriveCausalLineageTx(tx, request, at); err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO relay_v2_requests
(request_id,message_id,sender_endpoint_id,sender_principal_id,sender_group_id,
sender_binding_id,sender_binding_epoch,receiver_endpoint_id,receiver_principal_id,
receiver_group_id,receiver_binding_id,receiver_binding_epoch,digest,idempotency_key,
visibility_policy_ref,authorization_ref,state,expires_at,cancel_requested_at,
cancelled_at,expired_at,replied_at,late_result_at,reply_message_id,
late_result_message_id,created_at,updated_at,parent_request_id,
causal_root_request_id,causal_depth)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'','','','','','','',?,?,?,?,?)`,
		request.RequestID, request.MessageID, request.SenderEndpointID,
		request.SenderPrincipalID, request.SenderGroupID, request.SenderBindingID,
		request.SenderBindingEpoch, request.ReceiverEndpointID, request.ReceiverPrincipalID,
		request.ReceiverGroupID, request.ReceiverBindingID, request.ReceiverBindingEpoch,
		request.Digest, request.IdempotencyKey, request.VisibilityPolicyRef,
		request.AuthorizationRef, request.State, request.ExpiresAt, timestamp, timestamp,
		request.ParentRequestID, request.CausalRootRequestID, request.CausalDepth)
	if err != nil {
		return nil, err
	}
	if err := relayInsertEventTx(tx, request.RequestID, "REQUEST_CREATED", "",
		FabricRequestOpen, request.MessageID, "", timestamp); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

func (s *Store) EnqueueNetworkDirectSealedReply(input NetworkDirectReplyInput) (*FabricRequest, error) {
	if input.RequestID == "" || input.MessageID == "" || input.MessageID == input.RequestID ||
		len(input.IdempotencyKey) > 256 {
		return nil, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := relayAcquireWriteGuardTx(tx); err != nil {
		return nil, err
	}
	if err := networkDirectSourceNodeCredentialTx(tx, input.Scope,
		input.NodeCredentialDigest); err != nil {
		return nil, err
	}
	request, err := relayLoadRequestTx(tx, input.RequestID)
	if err != nil || request == nil || request.ReceiverEndpointID != input.Scope.EndpointID ||
		request.ReceiverPrincipalID != input.Scope.PrincipalID ||
		request.AuthorizationRef != networkDirectAuthorizationPrefix+input.Scope.NetworkID {
		return nil, ErrNetworkPermission
	}
	if err := networkGuardDirectMessageTx(tx, request.MessageID,
		input.Scope.NetworkID, time.Now().UTC()); err != nil {
		return nil, err
	}
	parentRequestID, err := relayParentRequestForSealedRouteTx(tx, RelaySealedV1Route{
		MessageID: request.MessageID, RequestID: request.RequestID, Kind: "ask",
	})
	if err != nil {
		return nil, ErrNetworkPermission
	}
	if request.State == FabricRequestReplied {
		if request.ReplyMessageID != input.MessageID {
			return nil, ErrRelayRequestTerminal
		}
		stored, err := relaySealedV1RecordTx(tx, input.MessageID)
		if err != nil || stored.Route.Kind != "reply" ||
			stored.Route.RequestID != input.RequestID ||
			stored.Route.ReplyTo != request.MessageID ||
			stored.Security.SenderEndpointID != input.Scope.EndpointID ||
			stored.Security.IdempotencyKey != networkDirectIdempotencyKey(
				input.Scope.NetworkID, input.IdempotencyKey) ||
			!bytes.Equal(stored.Ciphertext, input.Ciphertext) {
			return nil, ErrRelayIdempotencyConflict
		}
		if err := networkGuardDirectMessageTx(tx, stored.Route.MessageID,
			input.Scope.NetworkID, time.Now().UTC()); err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return request, nil
	}
	if request.State != FabricRequestOpen || relayParseExpired(request.ExpiresAt, time.Now().UTC()) {
		return nil, ErrRelayRequestTerminal
	}
	bundle, err := readNetworkDirectPeerBundleTx(tx, input.Scope, request.SenderEndpointID,
		time.Now().UTC())
	if err != nil || bundle.Receiver.Manifest.PrincipalID != request.SenderPrincipalID ||
		bundle.Receiver.Manifest.BindingID != request.SenderBindingID ||
		bundle.Receiver.Manifest.BindingEpoch != request.SenderBindingEpoch {
		return nil, ErrNetworkPermission
	}
	record, reused, err := enqueueNetworkDirectPayloadTx(tx, bundle, "reply", input.MessageID,
		input.RequestID, request.MessageID, input.IdempotencyKey, input.Ciphertext, parentRequestID)
	if err != nil {
		return nil, err
	}
	if reused {
		return nil, ErrRelayIdempotencyConflict
	}
	timestamp := now()
	updated, err := tx.Exec(`UPDATE relay_v2_requests SET state=?,reply_message_id=?,replied_at=?,updated_at=?
WHERE request_id=? AND state=?`, FabricRequestReplied, record.Route.MessageID,
		timestamp, timestamp, request.RequestID, FabricRequestOpen)
	if err != nil {
		return nil, err
	}
	changed, err := updated.RowsAffected()
	if err != nil || changed != 1 {
		return nil, ErrRelayRequestTerminal
	}
	if err := relayInsertEventTx(tx, request.RequestID, "REQUEST_REPLIED", FabricRequestOpen,
		FabricRequestReplied, record.Route.MessageID, "", timestamp); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	request.State, request.ReplyMessageID, request.RepliedAt, request.UpdatedAt =
		FabricRequestReplied, record.Route.MessageID, timestamp, timestamp
	return request, nil
}

func (s *Store) NetworkDirectRequestStatus(scope NetworkAccessScope,
	requestID string) (*FabricRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	request, err := networkDirectRequestForSenderTx(tx, scope, requestID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

func networkDirectRequestForSenderTx(tx *sql.Tx, scope NetworkAccessScope,
	requestID string, at time.Time) (*FabricRequest, error) {
	if err := networkGuardAccessTx(tx, scope, "direct.send", at); err != nil {
		return nil, err
	}
	request, err := relayLoadRequestTx(tx, requestID)
	if err != nil || request == nil || request.SenderEndpointID != scope.EndpointID ||
		request.SenderPrincipalID != scope.PrincipalID ||
		request.AuthorizationRef != networkDirectAuthorizationPrefix+scope.NetworkID {
		return nil, ErrNetworkPermission
	}
	if err := networkGuardDirectMessageTx(tx, request.MessageID, scope.NetworkID, at); err != nil {
		return nil, err
	}
	return request, nil
}

func (s *Store) CancelNetworkDirectRequest(scope NetworkAccessScope,
	requestID, reason string) (*FabricRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := networkDirectRequestForSenderTx(tx, scope, requestID, time.Now().UTC()); err != nil {
		return nil, err
	}
	request, err := relayMarkRequestCancellationTx(tx, requestID, FabricRequestCancelled,
		"REQUEST_CANCELLED", reason, now())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

// networkGuardDirectMessageTx checks saved enrollment/key revisions rather
// than timestamps. A revoke and fresh rejoin in the same second cannot revive
// an old queued ciphertext or claimed native delivery attempt.
func networkGuardDirectMessageTx(tx *sql.Tx, messageID, networkID string, at time.Time) error {
	var savedNetwork, senderID, receiverID, senderPrincipal, receiverPrincipal string
	var senderMemberRev, senderEnrollmentRev, receiverMemberRev, receiverEnrollmentRev int64
	var senderBindingID, receiverBindingID, senderKeyID, receiverKeyID string
	var senderBindingEpoch, receiverBindingEpoch uint64
	var senderGrantRev, receiverGrantRev int64
	var keyPurpose string
	err := tx.QueryRow(`SELECT network_id,sender_endpoint_id,sender_principal_id,
receiver_endpoint_id,receiver_principal_id,sender_membership_revision,
sender_enrollment_revision,receiver_membership_revision,receiver_enrollment_revision,
sender_binding_id,sender_binding_epoch,receiver_binding_id,receiver_binding_epoch,
sender_key_grant_revision,receiver_key_grant_revision,sender_key_id,receiver_key_id,key_purpose
FROM network_direct_message_routes_v2 WHERE message_id=?`, messageID).Scan(&savedNetwork,
		&senderID, &senderPrincipal, &receiverID, &receiverPrincipal, &senderMemberRev,
		&senderEnrollmentRev, &receiverMemberRev, &receiverEnrollmentRev,
		&senderBindingID, &senderBindingEpoch, &receiverBindingID, &receiverBindingEpoch,
		&senderGrantRev, &receiverGrantRev, &senderKeyID, &receiverKeyID, &keyPurpose)
	if err != nil || savedNetwork != networkID || keyPurpose != "DIRECT" {
		return ErrNetworkPermission
	}
	for _, endpointID := range []string{senderID, receiverID} {
		if err := guardDedicatedThreadNetworkTrafficTx(tx, endpointID, networkID, at); err != nil {
			return ErrNetworkPermission
		}
	}
	for _, side := range []struct {
		endpointID, principalID, action, bindingID, keyID string
		memberRevision, enrollmentRevision, grantRevision int64
		bindingEpoch                                      uint64
	}{
		{senderID, senderPrincipal, "direct.send", senderBindingID, senderKeyID,
			senderMemberRev, senderEnrollmentRev, senderGrantRev, senderBindingEpoch},
		{receiverID, receiverPrincipal, "direct.receive", receiverBindingID, receiverKeyID,
			receiverMemberRev, receiverEnrollmentRev, receiverGrantRev, receiverBindingEpoch},
	} {
		if err := networkDirectMembershipAllowsTx(tx, networkID, side.endpointID,
			side.principalID, side.action, at); err != nil {
			return err
		}
		var ownerID string
		if err := tx.QueryRow(`SELECT owner FROM fabric_endpoints WHERE id=?`,
			side.endpointID).Scan(&ownerID); err != nil {
			return ErrNetworkPermission
		}
		manifest, err := readNetworkDirectKeyManifestTx(tx, ownerID,
			networkID, side.endpointID, at)
		if err != nil || manifest.PrincipalID != side.principalID ||
			manifest.MembershipRevision != side.memberRevision ||
			manifest.EndpointEnrollmentRevision != side.enrollmentRevision ||
			manifest.BindingID != side.bindingID || manifest.BindingEpoch != side.bindingEpoch ||
			manifest.Candidate.Public.ID != side.keyID {
			return ErrNetworkPermission
		}
		grant, _, err := readOwnerNetworkDirectKeyGrantTx(tx, networkID, side.endpointID)
		if err != nil || grant.State != "active" || grant.Revision != side.grantRevision ||
			grant.ManifestDigest != manifest.Digest {
			return ErrNetworkPermission
		}
		var keyState string
		if err := tx.QueryRow(`SELECT state FROM owner_approval_keys_v2
WHERE owner_id=? AND key_id=?`, ownerID, grant.OwnerKeyID).Scan(&keyState); err != nil ||
			keyState != OwnerApprovalKeyActive {
			return ErrNetworkPermission
		}
	}
	return nil
}

func networkGuardStoredSealedMessageTx(tx *sql.Tx, messageID, networkID string, at time.Time) error {
	var purpose string
	if err := tx.QueryRow(`SELECT key_purpose FROM network_direct_message_routes_v2
WHERE message_id=? AND network_id=?`, messageID, networkID).Scan(&purpose); err != nil {
		return ErrNetworkPermission
	}
	if purpose == "DIRECT" {
		return networkGuardDirectMessageTx(tx, messageID, networkID, at)
	}
	return networkGuardCollaborationMessageTx(tx, messageID, networkID, purpose, at)
}

func networkGuardCollaborationMessageTx(tx *sql.Tx, messageID, networkID,
	purpose string, at time.Time) error {
	if !collaborationPurposeValid(purpose) {
		return ErrNetworkPermission
	}
	var savedNetwork, senderID, receiverID, senderPrincipal, receiverPrincipal string
	var senderMemberRev, senderEnrollmentRev, receiverMemberRev, receiverEnrollmentRev int64
	var senderBindingID, receiverBindingID, senderKeyID, receiverKeyID, keyPurpose string
	var senderBindingEpoch, receiverBindingEpoch uint64
	var senderGrantRev, receiverGrantRev int64
	err := tx.QueryRow(`SELECT network_id,sender_endpoint_id,sender_principal_id,
receiver_endpoint_id,receiver_principal_id,sender_membership_revision,
sender_enrollment_revision,receiver_membership_revision,receiver_enrollment_revision,
sender_binding_id,sender_binding_epoch,receiver_binding_id,receiver_binding_epoch,
sender_key_grant_revision,receiver_key_grant_revision,sender_key_id,receiver_key_id,key_purpose
FROM network_direct_message_routes_v2 WHERE message_id=?`, messageID).Scan(&savedNetwork,
		&senderID, &senderPrincipal, &receiverID, &receiverPrincipal, &senderMemberRev,
		&senderEnrollmentRev, &receiverMemberRev, &receiverEnrollmentRev,
		&senderBindingID, &senderBindingEpoch, &receiverBindingID, &receiverBindingEpoch,
		&senderGrantRev, &receiverGrantRev, &senderKeyID, &receiverKeyID, &keyPurpose)
	if err != nil || savedNetwork != networkID || keyPurpose != purpose {
		return ErrNetworkPermission
	}
	for _, endpointID := range []string{senderID, receiverID} {
		if err := guardDedicatedThreadNetworkTrafficTx(tx, endpointID, networkID, at); err != nil {
			return ErrNetworkPermission
		}
	}
	senderAction, receiverAction, err := networkCollaborationMessageActions(messageID, purpose)
	if err != nil {
		return err
	}
	for _, side := range []struct {
		endpointID, principalID, action, bindingID, keyID string
		memberRevision, enrollmentRevision, grantRevision int64
		bindingEpoch                                      uint64
	}{
		{senderID, senderPrincipal, senderAction, senderBindingID, senderKeyID,
			senderMemberRev, senderEnrollmentRev, senderGrantRev, senderBindingEpoch},
		{receiverID, receiverPrincipal, receiverAction, receiverBindingID, receiverKeyID,
			receiverMemberRev, receiverEnrollmentRev, receiverGrantRev, receiverBindingEpoch},
	} {
		if err := networkDirectMembershipAllowsTx(tx, networkID, side.endpointID,
			side.principalID, side.action, at); err != nil {
			return err
		}
		var ownerID string
		if err := tx.QueryRow(`SELECT owner FROM fabric_endpoints WHERE id=?`, side.endpointID).Scan(&ownerID); err != nil {
			return ErrNetworkPermission
		}
		manifest, err := readNetworkCollaborationKeyManifestTx(tx, ownerID,
			networkID, side.endpointID, purpose, at)
		if err != nil || manifest.Key.PrincipalID != side.principalID ||
			manifest.Key.MembershipRevision != side.memberRevision ||
			manifest.Key.EndpointEnrollmentRevision != side.enrollmentRevision ||
			manifest.Key.BindingID != side.bindingID || manifest.Key.BindingEpoch != side.bindingEpoch ||
			manifest.Key.Candidate.Public.ID != side.keyID {
			return ErrNetworkPermission
		}
		grant, proof, err := readOwnerNetworkCollaborationKeyGrantTx(tx, purpose,
			networkID, side.endpointID)
		if err != nil || grant.State != "active" || grant.Revision != side.grantRevision ||
			grant.ManifestDigest != manifest.Digest {
			return ErrNetworkPermission
		}
		var keyState, publicJSON string
		if err := tx.QueryRow(`SELECT state,public_identity_json FROM owner_approval_keys_v2
WHERE owner_id=? AND key_id=?`, ownerID, grant.OwnerKeyID).Scan(&keyState, &publicJSON); err != nil ||
			keyState != OwnerApprovalKeyActive {
			return ErrNetworkPermission
		}
		var ownerPublic e2ee.PublicIdentity
		if err := json.Unmarshal([]byte(publicJSON), &ownerPublic); err != nil {
			return ErrNetworkPermission
		}
		acceptedAt, err := time.Parse(time.RFC3339Nano, grant.AcceptedAt)
		if err != nil {
			return ErrNetworkPermission
		}
		expected := e2ee.OwnerNetworkCollaborationKeyGrant{Purpose: purpose,
			HubID: manifest.Key.HubID, NetworkID: networkID, EndpointID: side.endpointID,
			OwnerID: ownerID, ManifestDigest: manifest.Digest}
		verified, err := e2ee.VerifyOwnerNetworkCollaborationKeyGrant(proof,
			ownerPublic, expected, acceptedAt)
		hash := sha256.Sum256(proof)
		if err != nil || verified.Nonce != grant.Nonce || grant.ProofDigest != hex.EncodeToString(hash[:]) {
			return ErrNetworkPermission
		}
	}
	return nil
}

func isNetworkDirectMessageTx(tx *sql.Tx, messageID string) (bool, error) {
	var present int
	err := tx.QueryRow(`SELECT 1 FROM network_direct_message_routes_v2 WHERE message_id=?`,
		messageID).Scan(&present)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}
