package store

import (
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// CommunicationLinkSealedAsk has no caller-controlled sender or recipient.
// The Node credential and currently approved Link derive those identities.
type CommunicationLinkSealedAsk struct {
	NodeCredentialDigest string
	LinkID               string
	MessageID            string
	RequestID            string
	ParentRequestID      string
	IdempotencyKey       string
	DataScope            string
	ExpiresAt            string
	Ciphertext           []byte
}

// EnqueueCommunicationLinkSealedAsk atomically stores the ciphertext, Relay
// assignment, request lifecycle and accepted receipt. Its Node-only transport
// caller supplies a current Node credential; the Store derives both actors.
func (s *Store) EnqueueCommunicationLinkSealedAsk(input CommunicationLinkSealedAsk) (*FabricRequest, error) {
	input.NodeCredentialDigest = strings.TrimSpace(input.NodeCredentialDigest)
	input.LinkID = strings.TrimSpace(input.LinkID)
	input.MessageID = strings.TrimSpace(input.MessageID)
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.IdempotencyKey = strings.TrimSpace(input.IdempotencyKey)
	input.DataScope = strings.TrimSpace(input.DataScope)
	if input.ParentRequestID != "" && !validRelayCausalToken(input.ParentRequestID) {
		return nil, ErrCommunicationLinkRelayDenied
	}
	if !validNodeCredentialDigest(input.NodeCredentialDigest) || input.LinkID == "" || len(input.LinkID) > 256 ||
		input.MessageID == "" || len(input.MessageID) > 256 || input.RequestID == "" ||
		len(input.RequestID) > 256 || input.MessageID == input.RequestID ||
		(input.IdempotencyKey != "" && len(input.IdempotencyKey) > 256) ||
		input.DataScope == "" || len(input.DataScope) > 128 ||
		len(input.Ciphertext) == 0 || len(input.Ciphertext) > communicationLinkMaxSealedSendWire {
		return nil, ErrCommunicationLinkRelayDenied
	}
	expiry, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(input.ExpiresAt))
	if err != nil {
		return nil, ErrCommunicationLinkRelayDenied
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
	nowTime := time.Now().UTC()
	if !expiry.After(nowTime) || expiry.After(nowTime.Add(MaxRelayAskLifetime)) {
		return nil, ErrCommunicationLinkRelayDenied
	}
	link, manifest, reverse, err := authorizeCommunicationLinkSealedAskTx(tx,
		input.NodeCredentialDigest, input.LinkID, input.DataScope, nowTime)
	if err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}
	linkExpiry, err := time.Parse(time.RFC3339Nano, link.ExpiresAt)
	if err != nil || expiry.After(linkExpiry) {
		return nil, ErrCommunicationLinkRelayDenied
	}
	context := sealedLinkAskEndpointContext(link, manifest, input.MessageID,
		input.RequestID, input.ParentRequestID, reverse)
	var senderIdentity e2ee.PublicIdentity
	if reverse {
		senderIdentity = manifest.Target.PublicIdentity
	} else {
		senderIdentity = manifest.Source.PublicIdentity
	}
	if err := validateOpaqueEndpointMessage(input.Ciphertext, context, senderIdentity); err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}
	if previous, err := relayLoadRequestTx(tx, input.RequestID); err != nil {
		return nil, err
	} else if previous != nil && previous.MessageID != input.MessageID {
		return nil, ErrRelayIdempotencyConflict
	}
	sender, receiver := communicationLinkAskRoles(link, manifest, reverse)
	relayInput, err := relaySealedV1Message(RelaySealedV1Input{
		Route: RelaySealedV1Route{
			MessageID: input.MessageID, RequestID: input.RequestID,
			SenderEndpointID: sender.endpointID, ReceiverEndpointID: receiver.endpointID,
			Kind: "ask",
		},
		Security: RelayMessageSecurity{
			MessageID:        input.MessageID,
			SenderEndpointID: sender.endpointID, SenderPrincipalID: sender.principalID,
			SenderGroupID: sender.groupID, SenderBindingID: sender.bindingID,
			SenderBindingEpoch: sender.bindingEpoch,
			ReceiverEndpointID: receiver.endpointID, ReceiverPrincipalID: receiver.principalID,
			ReceiverGroupID: receiver.groupID, ReceiverBindingID: receiver.bindingID,
			ReceiverBindingEpoch: receiver.bindingEpoch,
			VisibilityPolicyRef:  input.DataScope,
			AuthorizationRef:     communicationLinkAuthorizationRefPrefix + link.ID,
		},
		Ciphertext: input.Ciphertext, IdempotencyKey: input.IdempotencyKey,
	})
	if err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}
	relayInput.communicationLinkAuthorized = true
	relayInput.sealedAskAuthorized = true
	accepted, reused, err := relayEnqueuePayloadTx(tx, relayInput,
		RelayPayloadModeSealedV1, input.Ciphertext)
	if err != nil {
		return nil, err
	}
	if accepted == nil {
		return nil, ErrRelayMessageNotFound
	}
	if reused {
		previous, err := relayLoadRequestByMessageTx(tx, accepted.Message.ID)
		if err != nil {
			return nil, err
		}
		if previous == nil || previous.RequestID != input.RequestID ||
			previous.ParentRequestID != input.ParentRequestID ||
			previous.SenderEndpointID != sender.endpointID || previous.ReceiverEndpointID != receiver.endpointID ||
			previous.ExpiresAt != expiry.Format(time.RFC3339Nano) {
			return nil, ErrRelayIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return previous, nil
	}
	limits, err := scanRelayAdmissionLimits(tx.QueryRow(`SELECT per_sender_principal,
per_sender_group, per_receiver, global_limit, retry_after_seconds
FROM relay_v2_admission_config WHERE id = 1`))
	if err != nil {
		return nil, err
	}
	if err := relayCheckPendingAskQuotaTx(tx, accepted.Security, limits, now()); err != nil {
		return nil, err
	}
	timestamp := now()
	request := FabricRequest{
		RequestID: input.RequestID, MessageID: input.MessageID,
		SenderEndpointID: sender.endpointID, SenderPrincipalID: sender.principalID,
		SenderGroupID: sender.groupID, SenderBindingID: sender.bindingID,
		SenderBindingEpoch: sender.bindingEpoch,
		ReceiverEndpointID: receiver.endpointID, ReceiverPrincipalID: receiver.principalID,
		ReceiverGroupID: receiver.groupID, ReceiverBindingID: receiver.bindingID,
		ReceiverBindingEpoch: receiver.bindingEpoch,
		Digest:               accepted.Security.Digest, IdempotencyKey: accepted.Security.IdempotencyKey,
		VisibilityPolicyRef: input.DataScope,
		AuthorizationRef:    communicationLinkAuthorizationRefPrefix + link.ID,
		ParentRequestID:     input.ParentRequestID,
		State:               FabricRequestOpen, ExpiresAt: expiry.Format(time.RFC3339Nano),
		CreatedAt: timestamp, UpdatedAt: timestamp,
	}
	if err := relayDeriveCausalLineageTx(tx, &request, nowTime); err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO relay_v2_requests
(request_id, message_id, sender_endpoint_id, sender_principal_id, sender_group_id,
 sender_binding_id, sender_binding_epoch, receiver_endpoint_id, receiver_principal_id,
 receiver_group_id, receiver_binding_id, receiver_binding_epoch, digest, idempotency_key,
 visibility_policy_ref, authorization_ref, state, expires_at, cancel_requested_at,
 cancelled_at, expired_at, replied_at, late_result_at, reply_message_id,
 late_result_message_id, created_at, updated_at, parent_request_id,
 causal_root_request_id, causal_depth)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', '', '', '', '', ?, ?, ?, ?, ?)`,
		request.RequestID, request.MessageID, request.SenderEndpointID,
		request.SenderPrincipalID, request.SenderGroupID, request.SenderBindingID,
		request.SenderBindingEpoch, request.ReceiverEndpointID, request.ReceiverPrincipalID,
		request.ReceiverGroupID, request.ReceiverBindingID, request.ReceiverBindingEpoch,
		request.Digest, request.IdempotencyKey, request.VisibilityPolicyRef,
		request.AuthorizationRef, request.State, request.ExpiresAt,
		request.CreatedAt, request.UpdatedAt, request.ParentRequestID,
		request.CausalRootRequestID, request.CausalDepth)
	if err != nil {
		return nil, err
	}
	if err := relayInsertEventTx(tx, request.RequestID, "REQUEST_CREATED", "",
		FabricRequestOpen, request.MessageID, "", timestamp); err != nil {
		return nil, err
	}
	record, err := relaySealedV1RecordTx(tx, request.MessageID)
	if err != nil {
		return nil, err
	}
	if err := ensureCommunicationLinkMessageReviewTx(tx, *link, record, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &request, nil
}

func sealedLinkForwardEndpointContext(link *CommunicationLink,
	manifest *CommunicationLinkKeyManifest, messageID, kind, requestID string) e2ee.EndpointMessageContext {
	return e2ee.EndpointMessageContext{
		MessageID: messageID, Kind: kind, RequestID: requestID,
		SenderEndpointID: link.SourceEndpointID, SenderPrincipalID: link.SourcePrincipalID,
		SenderOwnerID: link.SourceOwnerID, SenderGroupID: link.SourceGroupID,
		SenderMembershipRevision: link.ScopeSnapshot.SourceMembershipRevision,
		SenderBindingEpoch:       manifest.Source.BindingEpoch, SenderKeyID: manifest.Source.KeyID,
		ReceiverEndpointID: link.TargetEndpointID, ReceiverPrincipalID: link.TargetPrincipalID,
		ReceiverOwnerID: link.TargetOwnerID, ReceiverGroupID: link.TargetGroupID,
		ReceiverMembershipRevision: link.ScopeSnapshot.TargetMembershipRevision,
		ReceiverBindingEpoch:       manifest.Target.BindingEpoch, ReceiverKeyID: manifest.Target.KeyID,
		LinkID: link.ID, LinkRevision: link.Version, TransportHubID: link.TransportHubID,
	}
}
