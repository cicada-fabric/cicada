package store

import (
	"database/sql"
	"errors"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

// NetworkDirectClaimInput is Node-scoped. No caller supplied Endpoint or
// Network selector can broaden the current credential's delivery scope.
type NetworkDirectClaimInput struct {
	NodeID           string
	ConsumerID       string
	Limit            int
	CredentialDigest string
}

type NetworkDirectClaimedDelivery struct {
	RelaySealedV1DeliveryAttempt
	NetworkID       string
	Harness         string
	NativeSessionID string
	NodeID          string
}

func directRecordValidForClaimTx(tx *sql.Tx, item *RelayInboxItem,
	record *RelaySealedV1Record, networkID string, at time.Time) error {
	if record == nil || record.Route.ReceiverEndpointID != item.RecipientEndpointID ||
		record.Route.RequestID != item.RequestID || record.Security.Digest != item.Digest ||
		record.Security.AuthorizationRef != networkDirectAuthorizationPrefix+networkID {
		return ErrNetworkPermission
	}
	if err := networkGuardStoredSealedMessageTx(tx, item.MessageID, networkID, at); err != nil {
		return err
	}
	if item.RequestID == "" {
		if record.Route.Kind != "send" {
			return ErrNetworkPermission
		}
		return nil
	}
	request, err := relayLoadRequestTx(tx, item.RequestID)
	if err != nil || request == nil || request.AuthorizationRef != networkDirectAuthorizationPrefix+networkID {
		return ErrNetworkPermission
	}
	switch record.Route.Kind {
	case "ask":
		if request.MessageID != item.MessageID || request.State != FabricRequestOpen ||
			relayParseExpired(request.ExpiresAt, at) {
			return ErrNetworkPermission
		}
	case "reply":
		if request.MessageID != record.Route.ReplyTo || request.State != FabricRequestReplied ||
			request.ReplyMessageID != item.MessageID {
			return ErrNetworkPermission
		}
	default:
		return ErrNetworkPermission
	}
	return nil
}

func networkDirectDeliveryContextTx(tx *sql.Tx, record *RelaySealedV1Record,
	networkID string, at time.Time) (*e2ee.NetworkDirectContext,
	*e2ee.NetworkCollaborationMessageContext, *NetworkDirectPeerBundle, error) {
	var purpose string
	if err := tx.QueryRow(`SELECT key_purpose FROM network_direct_message_routes_v2 WHERE message_id=?`,
		record.Route.MessageID).Scan(&purpose); err != nil {
		return nil, nil, nil, err
	}
	contextScope, err := readNativeContextScopeForNetworkTx(tx, networkID)
	if err != nil {
		return nil, nil, nil, err
	}
	var sender, receiver NetworkDirectPeerKeyEvidence
	bundle := &NetworkDirectPeerBundle{NetworkID: networkID, NativeContextScope: contextScope}
	if purpose == "DIRECT" {
		sender, err = readNetworkDirectPeerKeyEvidenceTx(tx, networkID, record.Route.SenderEndpointID, at)
		if err == nil {
			receiver, err = readNetworkDirectPeerKeyEvidenceTx(tx, networkID, record.Route.ReceiverEndpointID, at)
		}
	} else {
		sender, err = readNetworkCollaborationPeerKeyEvidenceTx(tx, networkID,
			record.Route.SenderEndpointID, purpose, at)
		if err == nil {
			receiver, err = readNetworkCollaborationPeerKeyEvidenceTx(tx, networkID,
				record.Route.ReceiverEndpointID, purpose, at)
		}
		bundle.Purpose = purpose
	}
	if err != nil {
		return nil, nil, nil, err
	}
	bundle.HubID, bundle.Sender, bundle.Receiver = sender.Manifest.HubID, sender, receiver
	if receiver.Manifest.HubID != bundle.HubID {
		return nil, nil, nil, ErrNetworkPermission
	}
	kind := map[string]string{"send": "SEND", "ask": "REQUEST", "reply": "REPLY"}[record.Route.Kind]
	if kind == "" {
		return nil, nil, nil, ErrNetworkPermission
	}
	parentRequestID, err := relayParentRequestForSealedRouteTx(tx, record.Route)
	if err != nil {
		return nil, nil, nil, ErrNetworkPermission
	}
	if bundle.Purpose == "" {
		context := networkDirectContext(bundle, record.Route.MessageID, kind,
			record.Route.RequestID, record.Route.ReplyTo, parentRequestID)
		if err := e2ee.VerifyNetworkDirectMessage(sender.Manifest.Candidate.Public,
			context, record.Ciphertext); err != nil {
			return nil, nil, nil, ErrNetworkPermission
		}
		return &context, nil, bundle, nil
	}
	context, err := networkCollaborationContext(bundle, record.Route.MessageID)
	if err != nil || context.Route.Kind != kind || context.Route.RequestID != record.Route.RequestID ||
		context.Route.ReplyTo != record.Route.ReplyTo || e2ee.VerifyNetworkCollaborationMessage(
		sender.Manifest.Candidate.Public, *context, record.Ciphertext) != nil {
		return nil, nil, nil, ErrNetworkPermission
	}
	return nil, context, bundle, nil
}

func (s *Store) ClaimNetworkDirectSealedInbox(input NetworkDirectClaimInput) ([]NetworkDirectClaimedDelivery, error) {
	if !validNodeCredentialDigest(input.CredentialDigest) || input.NodeID == "" ||
		input.ConsumerID == "" || len(input.ConsumerID) > 256 {
		return nil, ErrNetworkPermission
	}
	input.Limit = normalizeRelayLimit(input.Limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nodeID, ownerID, _, err := readActiveOwnerBoundNodeTx(tx, input.CredentialDigest)
	if err != nil || nodeID != input.NodeID {
		return nil, ErrNetworkPermission
	}
	// The candidate scan is bounded to this Node's indexed native bindings.
	// Revoked rows are made terminal, so successive claims always progress.
	rows, err := tx.Query(`SELECT i.message_id,route.network_id,
	  binding.native_session_id,endpoint.harness,endpoint.owner
FROM network_direct_native_bindings_v2 binding
JOIN fabric_endpoints endpoint ON endpoint.id=binding.endpoint_id
JOIN relay_v2_inbox i ON i.recipient_endpoint_id=binding.endpoint_id
JOIN network_direct_message_routes_v2 route ON route.message_id=i.message_id
JOIN relay_v2_message_payloads payload ON payload.message_id=i.message_id
JOIN fabric_messages f ON f.id=i.message_id
WHERE binding.node_id=? AND binding.status='active' AND i.state='READY'
  AND payload.payload_mode='SEALED_V1'
ORDER BY i.sequence LIMIT ?`, nodeID, input.Limit*4)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		messageID                             string
		networkID, nativeID, harness, ownerID string
	}
	var items []candidate
	for rows.Next() {
		var candidate candidate
		if err := rows.Scan(&candidate.messageID, &candidate.networkID, &candidate.nativeID,
			&candidate.harness, &candidate.ownerID); err != nil {
			rows.Close()
			return nil, err
		}
		items = append(items, candidate)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	result := make([]NetworkDirectClaimedDelivery, 0, input.Limit)
	for _, candidate := range items {
		item, err := scanRelayInboxItem(tx.QueryRow(`SELECT `+relayInboxColumns+`
FROM relay_v2_inbox i JOIN fabric_messages f ON f.id=i.message_id
WHERE i.message_id=?`, candidate.messageID))
		if err != nil || item == nil {
			return nil, ErrNetworkPermission
		}
		record, err := relaySealedV1RecordTx(tx, item.MessageID)
		if err != nil {
			return nil, err
		}
		legacyTaskRoute, err := networkTaskLegacyDirectRouteTx(tx,
			candidate.networkID, item.MessageID)
		if err != nil {
			return nil, err
		}
		if legacyTaskRoute {
			if err := failQueuedSameGroupSealedV1Tx(tx, item, record, at,
				"TASK_MIGRATION_BLOCKED"); err != nil {
				return nil, err
			}
			continue
		}
		if candidate.ownerID != ownerID || directRecordValidForClaimTx(tx, item,
			record, candidate.networkID, at) != nil {
			if err := failQueuedSameGroupSealedV1Tx(tx, item, record, at,
				"Network direct enrollment or route is no longer current"); err != nil {
				return nil, err
			}
			continue
		}
		_, taskErr := networkTaskDeliveryForRouteTx(tx, candidate.networkID,
			item.MessageID, record.Route.SenderEndpointID, record.Route.ReceiverEndpointID, at)
		if errors.Is(taskErr, ErrNetworkTaskPending) {
			// A task offer/result SEND is durably queued before its CAS metadata is
			// committed. Leave it READY with no attempt or receipt; Publish/Submit
			// emits a fresh Node wake after the metadata commit.
			continue
		}
		if taskErr != nil {
			reason := "Network Task route metadata is no longer valid"
			switch {
			case errors.Is(taskErr, ErrNetworkTaskMigrationBlocked):
				reason = "TASK_MIGRATION_BLOCKED"
			case errors.Is(taskErr, ErrNetworkTaskExpired):
				reason = "TASK_EXPIRED"
			case errors.Is(taskErr, ErrNetworkTaskAlreadyClaimed):
				reason = "TASK_ALREADY_CLAIMED"
			case errors.Is(taskErr, ErrNetworkTaskLeaseExpired):
				reason = "TASK_LEASE_EXPIRED"
			case errors.Is(taskErr, ErrNetworkTaskUnavailable):
				reason = "TASK_ROUTE_UNAVAILABLE"
			}
			if err := failQueuedSameGroupSealedV1Tx(tx, item, record, at, reason); err != nil {
				return nil, err
			}
			continue
		}
		_, broadcastErr := networkBroadcastDeliveryForRouteTx(tx,
			candidate.networkID, item.MessageID, record.Route.SenderEndpointID,
			record.Route.ReceiverEndpointID, at)
		if errors.Is(broadcastErr, ErrNetworkBroadcastPending) {
			// As with Task metadata, a fixed recipient snapshot may commit after the
			// per-reader sealed SEND. Keep the route READY until it does.
			continue
		}
		if broadcastErr != nil {
			reason := "BROADCAST_ROUTE_UNAVAILABLE"
			if errors.Is(broadcastErr, ErrNetworkBroadcastExpired) {
				reason = "BROADCAST_EXPIRED"
			}
			if err := failQueuedSameGroupSealedV1Tx(tx, item, record, at, reason); err != nil {
				return nil, err
			}
			continue
		}
		attemptID := NewID("attempt")
		stamp := at.Format(time.RFC3339Nano)
		updated, err := tx.Exec(`UPDATE relay_v2_inbox SET state=?,attempt_id=?,updated_at=?
WHERE recipient_endpoint_id=? AND sequence=? AND state=?`, RelayInboxClaimed,
			attemptID, stamp, item.RecipientEndpointID, item.Sequence, RelayInboxReady)
		if err != nil {
			return nil, err
		}
		changed, err := updated.RowsAffected()
		if err != nil {
			return nil, err
		}
		if changed != 1 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO relay_v2_delivery_attempts
(attempt_id,message_id,request_id,recipient_endpoint_id,sequence,digest,binding_id,
binding_epoch,consumer_id,state,failure,claimed_at,completed_at,created_at)
VALUES(?,?,?,?,?,?,?,?,?,?,'',?,'',?)`, attemptID, item.MessageID, item.RequestID,
			item.RecipientEndpointID, item.Sequence, item.Digest, item.BindingID,
			item.BindingEpoch, input.ConsumerID, RelayAttemptClaimed, stamp, stamp); err != nil {
			return nil, err
		}
		result = append(result, NetworkDirectClaimedDelivery{
			RelaySealedV1DeliveryAttempt: RelaySealedV1DeliveryAttempt{
				AttemptID: attemptID, MessageID: item.MessageID, RequestID: item.RequestID,
				Digest: item.Digest, RecipientEndpointID: item.RecipientEndpointID,
				BindingID: item.BindingID, BindingEpoch: item.BindingEpoch,
				Sequence: item.Sequence, ConsumerID: input.ConsumerID,
				State: RelayAttemptClaimed, ClaimedAt: stamp, CreatedAt: stamp,
				PayloadMode: RelayPayloadModeSealedV1, Route: record.Route,
				Security: record.Security, Ciphertext: record.Ciphertext},
			NetworkID: candidate.networkID, NativeSessionID: candidate.nativeID,
			Harness: candidate.harness, NodeID: nodeID})
		if len(result) == input.Limit {
			break
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// AuthorizeClaimedNetworkDirectDelivery is the last Hub-side check before
// local native injection. An old attempt cannot survive a leave/rejoin, Node
// credential rotation, key revocation, or native route epoch change.
func (s *Store) AuthorizeClaimedNetworkDirectDelivery(credentialDigest,
	messageID, attemptID string) (*NetworkDirectDeliveryAuthorization, error) {
	if !validNodeCredentialDigest(credentialDigest) || messageID == "" || attemptID == "" {
		return nil, ErrNetworkPermission
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nodeID, ownerID, _, err := readActiveOwnerBoundNodeTx(tx, credentialDigest)
	if err != nil {
		return nil, ErrNetworkPermission
	}
	attempt, err := relayGetAttemptTx(tx, attemptID)
	if err != nil || attempt == nil || attempt.MessageID != messageID ||
		attempt.State != RelayAttemptClaimed {
		return nil, ErrNetworkPermission
	}
	item, err := scanRelayInboxItem(tx.QueryRow(`SELECT `+relayInboxColumns+`
FROM relay_v2_inbox i JOIN fabric_messages f ON f.id=i.message_id
WHERE i.message_id=? AND i.recipient_endpoint_id=?`, messageID, attempt.RecipientEndpointID))
	if err != nil || item == nil || item.State != RelayInboxClaimed ||
		item.AttemptID != attemptID || item.Sequence != attempt.Sequence ||
		item.BindingID != attempt.BindingID || item.BindingEpoch != attempt.BindingEpoch ||
		item.Digest != attempt.Digest {
		return nil, ErrNetworkPermission
	}
	var networkID, bindingID, nativeID, bindingNode, endpointOwner string
	var bindingEpoch uint64
	err = tx.QueryRow(`SELECT route.network_id,binding.id,binding.native_session_id,
binding.node_id,endpoint.owner,binding.epoch
FROM network_direct_message_routes_v2 route
JOIN network_direct_native_bindings_v2 binding ON binding.endpoint_id=route.receiver_endpoint_id
JOIN fabric_endpoints endpoint ON endpoint.id=binding.endpoint_id
WHERE route.message_id=? AND binding.status='active'`, messageID).Scan(
		&networkID, &bindingID, &nativeID, &bindingNode, &endpointOwner, &bindingEpoch)
	if err != nil || bindingNode != nodeID || endpointOwner != ownerID ||
		bindingID != item.BindingID || bindingEpoch != item.BindingEpoch {
		return nil, ErrNetworkPermission
	}
	var laterReceipt int
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM relay_v2_receipts
WHERE attempt_id=? AND layer NOT IN (?,?,?,?))`, attemptID,
		RelayReceiptAccepted, RelayReceiptNodeReceived,
		RelayReceiptCodexQueueAccepted, RelayReceiptNativeThreadResumed).Scan(&laterReceipt); err != nil {
		return nil, err
	}
	if laterReceipt != 0 {
		return nil, ErrNetworkPermission
	}
	record, err := relaySealedV1RecordTx(tx, messageID)
	if err == nil {
		legacyTaskRoute, legacyErr := networkTaskLegacyDirectRouteTx(tx, networkID, messageID)
		if legacyErr != nil {
			return nil, legacyErr
		}
		if legacyTaskRoute {
			if failErr := failClaimedSameGroupSealedV1Tx(tx, item, attempt,
				time.Now().UTC(), "TASK_MIGRATION_BLOCKED"); failErr != nil {
				return nil, failErr
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return nil, ErrNetworkTaskMigrationBlocked
		}
	}
	if err != nil || directRecordValidForClaimTx(tx, item, record, networkID,
		time.Now().UTC()) != nil {
		if record != nil {
			if failErr := failClaimedSameGroupSealedV1Tx(tx, item, attempt,
				time.Now().UTC(), "Network direct authorization revoked before injection"); failErr != nil {
				return nil, failErr
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
		}
		return nil, ErrNetworkPermission
	}
	taskAuthorization, taskErr := networkTaskDeliveryForRouteTx(tx, networkID,
		messageID, record.Route.SenderEndpointID, record.Route.ReceiverEndpointID,
		time.Now().UTC())
	if errors.Is(taskErr, ErrNetworkTaskPending) {
		// This is a retryable commit-order race. Do not create a Node-visible
		// authorization until task metadata is durable.
		return nil, ErrNetworkTaskPending
	}
	if taskErr != nil {
		reason := "Network Task route metadata is no longer valid"
		switch {
		case errors.Is(taskErr, ErrNetworkTaskMigrationBlocked):
			reason = "TASK_MIGRATION_BLOCKED"
		case errors.Is(taskErr, ErrNetworkTaskExpired):
			reason = "TASK_EXPIRED"
		case errors.Is(taskErr, ErrNetworkTaskAlreadyClaimed):
			reason = "TASK_ALREADY_CLAIMED"
		case errors.Is(taskErr, ErrNetworkTaskLeaseExpired):
			reason = "TASK_LEASE_EXPIRED"
		case errors.Is(taskErr, ErrNetworkTaskUnavailable):
			reason = "TASK_ROUTE_UNAVAILABLE"
		}
		if failErr := failClaimedSameGroupSealedV1Tx(tx, item, attempt,
			time.Now().UTC(), reason); failErr != nil {
			return nil, failErr
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, ErrNetworkPermission
	}
	broadcastAuthorization, broadcastErr := networkBroadcastDeliveryForRouteTx(tx,
		networkID, messageID, record.Route.SenderEndpointID,
		record.Route.ReceiverEndpointID, time.Now().UTC())
	if errors.Is(broadcastErr, ErrNetworkBroadcastPending) {
		return nil, ErrNetworkBroadcastPending
	}
	if broadcastErr != nil {
		if failErr := failClaimedSameGroupSealedV1Tx(tx, item, attempt,
			time.Now().UTC(), "BROADCAST_ROUTE_UNAVAILABLE"); failErr != nil {
			return nil, failErr
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return nil, ErrNetworkPermission
	}
	context, collaborationContext, bundle, err := networkDirectDeliveryContextTx(tx, record,
		networkID, time.Now().UTC())
	if err != nil {
		return nil, ErrNetworkPermission
	}
	result := &NetworkDirectDeliveryAuthorization{NetworkID: networkID,
		NativeContextScope: bundle.NativeContextScope,
		EndpointID:         item.RecipientEndpointID, NativeSessionID: nativeID,
		BindingID: bindingID, BindingEpoch: bindingEpoch,
		MessageID: messageID, AttemptID: attemptID, Digest: item.Digest,
		NetworkTask: taskAuthorization, CollaborationContext: collaborationContext,
		NetworkBroadcast: broadcastAuthorization, Bundle: *bundle}
	if context != nil {
		result.Context = *context
	} else if collaborationContext != nil {
		result.Context = collaborationContext.Route
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func networkGuardDirectReceiptTx(tx *sql.Tx, credentialDigest string,
	receipt RelayReceipt, at time.Time) error {
	nodeID, ownerID, _, err := readActiveOwnerBoundNodeTx(tx, credentialDigest)
	if err != nil {
		return ErrNetworkPermission
	}
	var networkID, bindingID, bindingNode, endpointOwner, bindingStatus string
	var bindingEpoch uint64
	err = tx.QueryRow(`SELECT route.network_id,binding.id,binding.node_id,
endpoint.owner,binding.status,binding.epoch
FROM network_direct_message_routes_v2 route
JOIN network_direct_native_bindings_v2 binding ON binding.endpoint_id=route.receiver_endpoint_id
JOIN fabric_endpoints endpoint ON endpoint.id=binding.endpoint_id
WHERE route.message_id=? AND route.receiver_endpoint_id=?`, receipt.MessageID,
		receipt.TargetEndpointID).Scan(&networkID, &bindingID, &bindingNode,
		&endpointOwner, &bindingStatus, &bindingEpoch)
	if err != nil || bindingNode != nodeID || endpointOwner != ownerID ||
		bindingStatus != "active" || bindingID != receipt.BindingID ||
		bindingEpoch != receipt.BindingEpoch {
		return ErrNetworkPermission
	}
	if err := networkGuardStoredSealedMessageTx(tx, receipt.MessageID, networkID, at); err != nil {
		return err
	}
	if _, _, reserved := networkTaskIDFromMessageID(receipt.MessageID); reserved {
		var senderID, receiverID string
		if err := tx.QueryRow(`SELECT sender_endpoint_id,receiver_endpoint_id
FROM network_direct_message_routes_v2 WHERE message_id=? AND network_id=?`,
			receipt.MessageID, networkID).Scan(&senderID, &receiverID); err != nil {
			return ErrNetworkPermission
		}
		if _, err := networkTaskDeliveryForRouteTx(tx, networkID,
			receipt.MessageID, senderID, receiverID, at); err != nil {
			return err
		}
	}
	if _, reserved := networkBroadcastIDFromMessageID(receipt.MessageID); reserved {
		var senderID, receiverID string
		if err := tx.QueryRow(`SELECT sender_endpoint_id,receiver_endpoint_id
FROM network_direct_message_routes_v2 WHERE message_id=? AND network_id=?`,
			receipt.MessageID, networkID).Scan(&senderID, &receiverID); err != nil {
			return ErrNetworkPermission
		}
		if _, err := networkBroadcastDeliveryForRouteTx(tx, networkID,
			receipt.MessageID, senderID, receiverID, at); err != nil {
			return err
		}
	}
	return nil
}
