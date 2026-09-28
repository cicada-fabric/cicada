package store

import (
	"database/sql"
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
	if err := networkGuardDirectMessageTx(tx, item.MessageID, networkID, at); err != nil {
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
	networkID string, at time.Time) (*e2ee.NetworkDirectContext, *NetworkDirectPeerBundle, error) {
	sender, err := readNetworkDirectPeerKeyEvidenceTx(tx, networkID,
		record.Route.SenderEndpointID, at)
	if err != nil {
		return nil, nil, err
	}
	receiver, err := readNetworkDirectPeerKeyEvidenceTx(tx, networkID,
		record.Route.ReceiverEndpointID, at)
	if err != nil {
		return nil, nil, err
	}
	bundle := &NetworkDirectPeerBundle{HubID: sender.Manifest.HubID,
		NetworkID: networkID, Sender: sender, Receiver: receiver}
	if receiver.Manifest.HubID != bundle.HubID {
		return nil, nil, ErrNetworkPermission
	}
	kind := map[string]string{"send": "SEND", "ask": "REQUEST", "reply": "REPLY"}[record.Route.Kind]
	if kind == "" {
		return nil, nil, ErrNetworkPermission
	}
	context := networkDirectContext(bundle, record.Route.MessageID, kind,
		record.Route.RequestID, record.Route.ReplyTo)
	if err := e2ee.VerifyNetworkDirectMessage(sender.Manifest.Candidate.Public,
		context, record.Ciphertext); err != nil {
		return nil, nil, ErrNetworkPermission
	}
	return &context, bundle, nil
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
		if candidate.ownerID != ownerID || directRecordValidForClaimTx(tx, item,
			record, candidate.networkID, at) != nil {
			if err := failQueuedSameGroupSealedV1Tx(tx, item, record, at,
				"Network direct enrollment or route is no longer current"); err != nil {
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
	context, bundle, err := networkDirectDeliveryContextTx(tx, record,
		networkID, time.Now().UTC())
	if err != nil {
		return nil, ErrNetworkPermission
	}
	result := &NetworkDirectDeliveryAuthorization{NetworkID: networkID,
		EndpointID: item.RecipientEndpointID, NativeSessionID: nativeID,
		BindingID: bindingID, BindingEpoch: bindingEpoch,
		MessageID: messageID, AttemptID: attemptID, Digest: item.Digest,
		Context: *context, Bundle: *bundle}
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
	return networkGuardDirectMessageTx(tx, receipt.MessageID, networkID, at)
}
