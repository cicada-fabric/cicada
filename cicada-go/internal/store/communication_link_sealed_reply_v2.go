package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// CommunicationLinkSealedReply has no caller-controlled route or Link. The
// original sealed REQUEST determines the responder, requester, endpoint
// bindings, scope and reply correlation.
type CommunicationLinkSealedReply struct {
	NodeCredentialDigest string
	RequestID            string
	MessageID            string
	IdempotencyKey       string
	DataScope            string
	Ciphertext           []byte
}

// EnqueueCommunicationLinkSealedReply durably stores one reverse SEALED_V1
// REPLY and its request lifecycle transition in the same transaction. Only
// the original receiving Node can produce it, and only while both current
// owner grants still authorize the Link's ask+reply actions.
func (s *Store) EnqueueCommunicationLinkSealedReply(input CommunicationLinkSealedReply) (*FabricRequest, error) {
	input.NodeCredentialDigest = strings.TrimSpace(input.NodeCredentialDigest)
	input.RequestID = strings.TrimSpace(input.RequestID)
	input.MessageID = strings.TrimSpace(input.MessageID)
	input.IdempotencyKey = strings.TrimSpace(input.IdempotencyKey)
	input.DataScope = strings.TrimSpace(input.DataScope)
	if !validNodeCredentialDigest(input.NodeCredentialDigest) || input.RequestID == "" ||
		len(input.RequestID) > 256 || input.MessageID == "" || len(input.MessageID) > 256 ||
		input.MessageID == input.RequestID || (input.IdempotencyKey != "" && len(input.IdempotencyKey) > 256) ||
		input.DataScope == "" || len(input.DataScope) > 128 || len(input.Ciphertext) == 0 ||
		len(input.Ciphertext) > communicationLinkMaxSealedSendWire {
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
	request, _, link, manifest, err := sealedLinkAskForReplyTx(tx, input.RequestID, nowTime)
	if err != nil || request == nil || input.DataScope != request.VisibilityPolicyRef {
		return nil, ErrCommunicationLinkRelayDenied
	}
	nodeID, ownerID, hubID, err := readActiveOwnerBoundNodeTx(tx, input.NodeCredentialDigest)
	if err != nil || nodeID != link.TargetNodeID || ownerID != link.TargetOwnerID || hubID != link.TransportHubID {
		return nil, ErrCommunicationLinkRelayDenied
	}
	// A deadline reached before this transaction makes the result late without
	// changing the terminal request outcome back to OPEN.
	if (request.State == FabricRequestOpen || request.State == FabricRequestCancelRequested) &&
		relayParseExpired(request.ExpiresAt, nowTime) {
		if err := relayExpireRequestTx(tx, request.RequestID, "request deadline reached", nowTime.Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
		request, err = relayLoadRequestTx(tx, input.RequestID)
		if err != nil || request == nil {
			return nil, ErrCommunicationLinkRelayDenied
		}
	}

	terminalMessageID := ""
	switch request.State {
	case FabricRequestReplied:
		terminalMessageID = request.ReplyMessageID
	case FabricRequestLateResult:
		terminalMessageID = request.LateResultMessageID
	case FabricRequestOpen, FabricRequestCancelRequested, FabricRequestCancelled, FabricRequestExpired:
		// These states can accept the first response; all but OPEN become a
		// durable LATE_RESULT below.
	default:
		return nil, ErrRelayRequestTerminal
	}
	if terminalMessageID != "" {
		previous, err := relaySealedV1RecordTx(tx, terminalMessageID)
		if err != nil || previous == nil {
			return nil, ErrCommunicationLinkRelayDenied
		}
		if input.MessageID != terminalMessageID {
			return nil, ErrRelayRequestTerminal
		}
		if input.IdempotencyKey != "" && input.IdempotencyKey != previous.Security.IdempotencyKey {
			return nil, ErrRelayIdempotencyConflict
		}
		if previous.Route.RequestID != request.RequestID || previous.Route.ReplyTo != request.MessageID ||
			previous.Route.Kind != "reply" || !bytes.Equal(previous.Ciphertext, input.Ciphertext) {
			return nil, ErrRelayIdempotencyConflict
		}
		if err := validateOpaqueEndpointMessage(input.Ciphertext,
			sealedLinkReverseEndpointContext(link, manifest, input.MessageID,
				request.RequestID, request.MessageID), manifest.Target.PublicIdentity); err != nil {
			return nil, ErrCommunicationLinkRelayDenied
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return request, nil
	}
	if request.State != FabricRequestOpen && request.State != FabricRequestCancelRequested &&
		request.State != FabricRequestCancelled && request.State != FabricRequestExpired {
		return nil, ErrRelayRequestTerminal
	}
	if existing, err := relayLoadMessageTx(tx, input.MessageID); err != nil {
		return nil, err
	} else if existing != nil {
		return nil, ErrRelayMessageConflict
	}
	context := sealedLinkReverseEndpointContext(link, manifest, input.MessageID,
		request.RequestID, request.MessageID)
	if err := validateOpaqueEndpointMessage(input.Ciphertext, context, manifest.Target.PublicIdentity); err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}
	idempotencyKey := input.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = sealedReplyIdempotencyKey(request.RequestID)
	}
	relayInput, err := relaySealedV1Message(RelaySealedV1Input{
		Route: RelaySealedV1Route{
			MessageID: input.MessageID, RequestID: request.RequestID, ReplyTo: request.MessageID,
			SenderEndpointID: link.TargetEndpointID, ReceiverEndpointID: link.SourceEndpointID,
			Kind: "reply",
		},
		Security: RelayMessageSecurity{
			MessageID:        input.MessageID,
			SenderEndpointID: link.TargetEndpointID, SenderPrincipalID: link.TargetPrincipalID,
			SenderGroupID: link.TargetGroupID, SenderBindingID: manifest.Target.BindingID,
			SenderBindingEpoch: manifest.Target.BindingEpoch,
			ReceiverEndpointID: link.SourceEndpointID, ReceiverPrincipalID: link.SourcePrincipalID,
			ReceiverGroupID: link.SourceGroupID, ReceiverBindingID: manifest.Source.BindingID,
			ReceiverBindingEpoch: manifest.Source.BindingEpoch,
			VisibilityPolicyRef:  input.DataScope,
			AuthorizationRef:     communicationLinkAuthorizationRefPrefix + link.ID,
		},
		Ciphertext: input.Ciphertext, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}
	relayInput.sealedReplyAuthorized = true
	accepted, reused, err := relayEnqueuePayloadTx(tx, relayInput, RelayPayloadModeSealedV1, input.Ciphertext)
	if err != nil {
		return nil, err
	}
	if accepted == nil || reused {
		// A route admitted elsewhere cannot be adopted as this request's reply.
		return nil, ErrRelayMessageConflict
	}
	late := request.State != FabricRequestOpen
	timestamp := nowTime.Format(time.RFC3339Nano)
	if late {
		updated, err := tx.Exec(`UPDATE relay_v2_requests SET state=?, late_result_at=?,
late_result_message_id=?, updated_at=? WHERE request_id=? AND state IN (?, ?, ?, ?)`,
			FabricRequestLateResult, timestamp, accepted.Message.ID, timestamp, request.RequestID,
			FabricRequestCancelRequested, FabricRequestCancelled, FabricRequestExpired, FabricRequestLateResult)
		if err != nil {
			return nil, err
		}
		changed, err := updated.RowsAffected()
		if err != nil || changed != 1 {
			return nil, ErrRelayRequestTerminal
		}
		if err := relayInsertEventTx(tx, request.RequestID, "LATE_RESULT", request.State,
			FabricRequestLateResult, accepted.Message.ID, "sealed reply arrived after deadline or cancellation", timestamp); err != nil {
			return nil, err
		}
		// A late result is retained as encrypted evidence and lifecycle
		// metadata. It is deliberately not offered to the Node's ordinary
		// claim loop, which would inject it into and implicitly revive the
		// original native Thread.
		inboxUpdate, err := tx.Exec(`UPDATE relay_v2_inbox SET state=?, updated_at=?
WHERE message_id=? AND state=?`, RelayInboxExpired, timestamp, accepted.Message.ID, RelayInboxReady)
		if err != nil {
			return nil, err
		}
		inboxChanged, err := inboxUpdate.RowsAffected()
		if err != nil || inboxChanged != 1 {
			return nil, ErrRelayMessageNotFound
		}
		outboxUpdate, err := tx.Exec(`UPDATE relay_v2_outbox SET state=?, error=?, updated_at=? WHERE message_id=?`,
			RelayInboxExpired, "late result retained for request lifecycle review", timestamp, accepted.Message.ID)
		if err != nil {
			return nil, err
		}
		outboxChanged, err := outboxUpdate.RowsAffected()
		if err != nil || outboxChanged != 1 {
			return nil, ErrRelayMessageNotFound
		}
	} else {
		updated, err := tx.Exec(`UPDATE relay_v2_requests SET state=?, replied_at=?,
reply_message_id=?, updated_at=? WHERE request_id=? AND state=?`,
			FabricRequestReplied, timestamp, accepted.Message.ID, timestamp,
			request.RequestID, FabricRequestOpen)
		if err != nil {
			return nil, err
		}
		changed, err := updated.RowsAffected()
		if err != nil || changed != 1 {
			return nil, ErrRelayRequestTerminal
		}
		if err := relayInsertEventTx(tx, request.RequestID, "REQUEST_REPLIED", request.State,
			FabricRequestReplied, accepted.Message.ID, "", timestamp); err != nil {
			return nil, err
		}
	}
	request, err = relayLoadRequestTx(tx, input.RequestID)
	if err != nil || request == nil {
		return nil, ErrRelayRequestNotFound
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

func sealedReplyIdempotencyKey(requestID string) string {
	digest := sha256.Sum256([]byte(requestID))
	return "sealed-reply:" + hex.EncodeToString(digest[:])
}

// sealedLinkAskForReplyTx loads and revalidates the immutable forward REQUEST
// and current Link contract that authorize its one reverse response.
func sealedLinkAskForReplyTx(tx *sql.Tx, requestID string, at time.Time) (
	*FabricRequest, *RelaySealedV1Record, *CommunicationLink, *CommunicationLinkKeyManifest, error,
) {
	request, err := relayLoadRequestTx(tx, requestID)
	if err != nil || request == nil {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	ask, err := relaySealedV1RecordTx(tx, request.MessageID)
	if err != nil || ask == nil || ask.PayloadMode != RelayPayloadModeSealedV1 ||
		ask.Route.Kind != "ask" || ask.Route.MessageID != request.MessageID ||
		ask.Route.RequestID != request.RequestID || ask.Route.ReplyTo != "" ||
		request.RequestID != requestID || request.MessageID == "" ||
		!strings.HasPrefix(request.AuthorizationRef, communicationLinkAuthorizationRefPrefix) ||
		request.AuthorizationRef != ask.Security.AuthorizationRef || request.Digest != ask.Security.Digest ||
		request.VisibilityPolicyRef != ask.Security.VisibilityPolicyRef {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	linkID := strings.TrimPrefix(request.AuthorizationRef, communicationLinkAuthorizationRefPrefix)
	if linkID == "" {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id=?`, linkID))
	if err != nil || link == nil || link.State != CommunicationLinkProposed ||
		(link.Direction != "forward" && link.Direction != "bidirectional") ||
		link.SourceOwnerID == link.TargetOwnerID || link.SourceNodeID == link.TargetNodeID ||
		link.TransportHubID == "" || !containsWord(link.Actions, "ask") ||
		!containsWord(link.Actions, "reply") || !containsWord(link.DataScopes, request.VisibilityPolicyRef) {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	requestExpiry, requestExpiryErr := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	linkExpiry, linkExpiryErr := time.Parse(time.RFC3339Nano, link.ExpiresAt)
	if requestExpiryErr != nil || linkExpiryErr != nil || requestExpiry.After(linkExpiry) {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); err != nil ||
		hubID == "" || hubID != link.TransportHubID {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	if err := validateCurrentCommunicationLinkScope(tx, link, at); err != nil ||
		requireActiveOwnerBoundNodeTx(tx, link.SourceNodeID, link.SourceOwnerID, hubID) != nil ||
		requireActiveOwnerBoundNodeTx(tx, link.TargetNodeID, link.TargetOwnerID, hubID) != nil {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	manifest, err := readCommunicationLinkKeyManifest(tx, *link, at)
	if err != nil || !sealedRequestMatchesLink(request, ask, link, manifest) {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	if _, err := readCurrentCommunicationLinkAuthorizationProof(tx, *link, *manifest,
		CommunicationLinkGrantSource, at); err != nil {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	if _, err := readCurrentCommunicationLinkAuthorizationProof(tx, *link, *manifest,
		CommunicationLinkGrantTarget, at); err != nil {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	context := sealedLinkForwardEndpointContext(link, manifest, request.MessageID,
		"REQUEST", request.RequestID)
	if err := validateOpaqueEndpointMessage(ask.Ciphertext, context, manifest.Source.PublicIdentity); err != nil {
		return nil, nil, nil, nil, ErrCommunicationLinkRelayDenied
	}
	return request, ask, link, manifest, nil
}

func sealedRequestMatchesLink(request *FabricRequest, ask *RelaySealedV1Record,
	link *CommunicationLink, manifest *CommunicationLinkKeyManifest) bool {
	if request == nil || ask == nil || link == nil || manifest == nil {
		return false
	}
	security := ask.Security
	return request.SenderEndpointID == link.SourceEndpointID &&
		request.SenderPrincipalID == link.SourcePrincipalID && request.SenderGroupID == link.SourceGroupID &&
		request.SenderBindingID == manifest.Source.BindingID && request.SenderBindingEpoch == manifest.Source.BindingEpoch &&
		request.ReceiverEndpointID == link.TargetEndpointID &&
		request.ReceiverPrincipalID == link.TargetPrincipalID && request.ReceiverGroupID == link.TargetGroupID &&
		request.ReceiverBindingID == manifest.Target.BindingID && request.ReceiverBindingEpoch == manifest.Target.BindingEpoch &&
		security.MessageID == request.MessageID && security.SenderEndpointID == request.SenderEndpointID &&
		security.SenderPrincipalID == request.SenderPrincipalID && security.SenderGroupID == request.SenderGroupID &&
		security.SenderBindingID == request.SenderBindingID && security.SenderBindingEpoch == request.SenderBindingEpoch &&
		security.ReceiverEndpointID == request.ReceiverEndpointID &&
		security.ReceiverPrincipalID == request.ReceiverPrincipalID && security.ReceiverGroupID == request.ReceiverGroupID &&
		security.ReceiverBindingID == request.ReceiverBindingID && security.ReceiverBindingEpoch == request.ReceiverBindingEpoch &&
		security.IdempotencyKey == request.IdempotencyKey && security.VisibilityPolicyRef == request.VisibilityPolicyRef &&
		security.AuthorizationRef == request.AuthorizationRef &&
		ask.Route.SenderEndpointID == request.SenderEndpointID && ask.Route.ReceiverEndpointID == request.ReceiverEndpointID
}

func sealedLinkReverseEndpointContext(link *CommunicationLink,
	manifest *CommunicationLinkKeyManifest, messageID, requestID, replyTo string) e2ee.EndpointMessageContext {
	return e2ee.EndpointMessageContext{
		MessageID: messageID, Kind: "REPLY", RequestID: requestID, ReplyTo: replyTo,
		SenderEndpointID: link.TargetEndpointID, SenderPrincipalID: link.TargetPrincipalID,
		SenderOwnerID: link.TargetOwnerID, SenderGroupID: link.TargetGroupID,
		SenderMembershipRevision: link.ScopeSnapshot.TargetMembershipRevision,
		SenderBindingEpoch:       manifest.Target.BindingEpoch, SenderKeyID: manifest.Target.KeyID,
		ReceiverEndpointID: link.SourceEndpointID, ReceiverPrincipalID: link.SourcePrincipalID,
		ReceiverOwnerID: link.SourceOwnerID, ReceiverGroupID: link.SourceGroupID,
		ReceiverMembershipRevision: link.ScopeSnapshot.SourceMembershipRevision,
		ReceiverBindingEpoch:       manifest.Source.BindingEpoch, ReceiverKeyID: manifest.Source.KeyID,
		LinkID: link.ID, LinkRevision: link.Version, TransportHubID: link.TransportHubID,
	}
}

// validateQueuedCommunicationLinkSealedReplyTx is the claim and exact-attempt
// preflight gate. It recomputes the reverse destination from the stored Ask,
// requires the request's exact terminal reply ID, and verifies current grants,
// bindings, scope and endpoint signatures before claim or native injection.
func validateQueuedCommunicationLinkSealedReplyTx(tx *sql.Tx, record *RelaySealedV1Record, at time.Time) error {
	if record == nil || record.PayloadMode != RelayPayloadModeSealedV1 || record.Route.Kind != "reply" ||
		record.Route.RequestID == "" || record.Route.ReplyTo == "" ||
		record.Route.MessageID != record.Security.MessageID ||
		record.Security.Digest != relayCiphertextDigest(record.Ciphertext) {
		return ErrCommunicationLinkRelayDenied
	}
	request, _, link, manifest, err := sealedLinkAskForReplyTx(tx, record.Route.RequestID, at)
	if err != nil || request.MessageID != record.Route.ReplyTo ||
		(record.Route.RequestID != request.RequestID) ||
		request.State != FabricRequestReplied || request.ReplyMessageID != record.Route.MessageID {
		return ErrCommunicationLinkRelayDenied
	}
	security := record.Security
	if security.AuthorizationRef != communicationLinkAuthorizationRefPrefix+link.ID ||
		security.VisibilityPolicyRef != request.VisibilityPolicyRef ||
		security.SenderEndpointID != link.TargetEndpointID || security.SenderPrincipalID != link.TargetPrincipalID ||
		security.SenderGroupID != link.TargetGroupID || security.SenderBindingID != manifest.Target.BindingID ||
		security.SenderBindingEpoch != manifest.Target.BindingEpoch ||
		security.ReceiverEndpointID != link.SourceEndpointID || security.ReceiverPrincipalID != link.SourcePrincipalID ||
		security.ReceiverGroupID != link.SourceGroupID || security.ReceiverBindingID != manifest.Source.BindingID ||
		security.ReceiverBindingEpoch != manifest.Source.BindingEpoch ||
		record.Route.SenderEndpointID != link.TargetEndpointID ||
		record.Route.ReceiverEndpointID != link.SourceEndpointID {
		return ErrCommunicationLinkRelayDenied
	}
	context := sealedLinkReverseEndpointContext(link, manifest, record.Route.MessageID,
		request.RequestID, request.MessageID)
	if err := validateOpaqueEndpointMessage(record.Ciphertext, context, manifest.Target.PublicIdentity); err != nil {
		return ErrCommunicationLinkRelayDenied
	}
	return nil
}
