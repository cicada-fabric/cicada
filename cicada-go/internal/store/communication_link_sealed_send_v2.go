package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	communicationLinkMaxSealedSendWire      = 256 * 1024
	communicationLinkAuthorizationRefPrefix = "communication-link.v2:"
)

var ErrCommunicationLinkRelayDenied = errors.New("communication link does not authorize this sealed send")

// CommunicationLinkSealedSend is the Node-authenticated Store input for one
// cross-Node, single-recipient SEND. Route identities, groups, owners, binding
// epochs and authorization metadata are deliberately absent: they are derived
// from the live Node credential and the persisted Link in the transaction.
// DataScope selects one scope already granted by the Link; it is not a claim
// that the Hub can inspect or validate the encrypted payload's meaning.
type CommunicationLinkSealedSend struct {
	NodeCredentialDigest string
	LinkID               string
	MessageID            string
	IdempotencyKey       string
	DataScope            string
	Ciphertext           []byte
}

// CommunicationLinkSealedDeliveryAuthorization binds a current bilateral
// authorization bundle to one claimed delivery attempt. It contains no
// ciphertext or plaintext. A Node must compare these coordinates with its
// durable inbox record and independently verify the owner signatures before
// opening the endpoint envelope or injecting it into a native session.
type CommunicationLinkSealedDeliveryAuthorization struct {
	AttemptID       string                               `json:"attempt_id"`
	MessageID       string                               `json:"message_id"`
	Digest          string                               `json:"digest"`
	EndpointID      string                               `json:"endpoint_id"`
	BindingID       string                               `json:"binding_id"`
	BindingEpoch    uint64                               `json:"binding_epoch"`
	NativeSessionID string                               `json:"native_session_id"`
	DataScope       string                               `json:"data_scope"`
	Route           RelaySealedV1Route                   `json:"route"`
	Bundle          CommunicationLinkAuthorizationBundle `json:"bundle"`
}

// AuthorizeClaimedCommunicationLinkSealedSend is the receive-side Guard for
// the narrow window immediately before native injection. Its historical name
// now covers both SEND and internally admitted REQUEST. It checks the live
// Node credential, the exact current Relay attempt, Link scope, both owner
// grants and both native bindings in one transaction. A previously claimed
// delivery cannot be injected after revocation or reassignment merely because
// its bytes were already stored by a Node.
func (s *Store) AuthorizeClaimedCommunicationLinkSealedSend(credentialDigest, messageID, attemptID string) (*CommunicationLinkSealedDeliveryAuthorization, error) {
	if !validNodeCredentialDigest(credentialDigest) || messageID == "" || len(messageID) > 256 ||
		strings.TrimSpace(messageID) != messageID || attemptID == "" || len(attemptID) > 256 ||
		strings.TrimSpace(attemptID) != attemptID {
		return nil, ErrCommunicationLinkRelayDenied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	nodeID, ownerID, hubID, err := readActiveOwnerBoundNodeTx(tx, credentialDigest)
	if err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}
	attempt, err := relayGetAttemptTx(tx, attemptID)
	if err != nil || attempt == nil || attempt.MessageID != messageID ||
		attempt.State != RelayAttemptClaimed || attempt.BindingID == "" || attempt.BindingEpoch == 0 {
		return nil, ErrCommunicationLinkRelayDenied
	}
	item, err := scanRelayInboxItem(tx.QueryRow(`SELECT `+relayInboxColumns+` FROM relay_v2_inbox i
JOIN fabric_messages f ON f.id=i.message_id
WHERE i.message_id=? AND i.recipient_endpoint_id=?`, messageID, attempt.RecipientEndpointID))
	if err != nil || item == nil || item.AttemptID != attemptID || item.State != RelayInboxClaimed ||
		item.BindingID != attempt.BindingID || item.BindingEpoch != attempt.BindingEpoch ||
		item.Sequence != attempt.Sequence || item.Digest != attempt.Digest {
		return nil, ErrCommunicationLinkRelayDenied
	}
	record, err := relaySealedV1RecordTx(tx, messageID)
	if err != nil || record == nil || record.PayloadMode != RelayPayloadModeSealedV1 ||
		(record.Route.Kind != "send" && record.Route.Kind != "ask" && record.Route.Kind != "reply") ||
		record.Route.RequestID != item.RequestID || record.Route.ReceiverEndpointID != item.RecipientEndpointID ||
		record.Security.Digest != item.Digest ||
		!strings.HasPrefix(record.Security.AuthorizationRef, communicationLinkAuthorizationRefPrefix) {
		return nil, ErrCommunicationLinkRelayDenied
	}
	linkID := strings.TrimPrefix(record.Security.AuthorizationRef, communicationLinkAuthorizationRefPrefix)
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id=?`, linkID))
	if err != nil || link == nil || link.TransportHubID != hubID {
		return nil, ErrCommunicationLinkRelayDenied
	}
	endpointID, expectedNodeID, expectedOwnerID := link.TargetEndpointID, link.TargetNodeID, link.TargetOwnerID
	if record.Route.Kind == "reply" {
		endpointID, expectedNodeID, expectedOwnerID = link.SourceEndpointID, link.SourceNodeID, link.SourceOwnerID
	}
	if nodeID != expectedNodeID || ownerID != expectedOwnerID || endpointID != item.RecipientEndpointID {
		return nil, ErrCommunicationLinkRelayDenied
	}
	if err := validateQueuedCommunicationLinkSealedSendTx(tx, record, time.Now().UTC()); err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}
	bundle, err := readCommunicationLinkAuthorizationBundle(tx, nodeID, ownerID, linkID)
	if err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}
	principalID := link.TargetPrincipalID
	if record.Route.Kind == "reply" {
		principalID = link.SourcePrincipalID
	}
	binding, err := readCommunicationLinkGrantBinding(tx, endpointID,
		principalID, nodeID, time.Now().UTC())
	if err != nil || binding.ID != item.BindingID || binding.Epoch != item.BindingEpoch {
		return nil, ErrCommunicationLinkRelayDenied
	}
	result := &CommunicationLinkSealedDeliveryAuthorization{
		AttemptID: attemptID, MessageID: messageID, Digest: item.Digest,
		EndpointID: item.RecipientEndpointID, BindingID: binding.ID,
		BindingEpoch: binding.Epoch, NativeSessionID: binding.NativeSessionID,
		DataScope: record.Security.VisibilityPolicyRef, Route: record.Route, Bundle: *bundle,
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// EnqueueCommunicationLinkSealedSend revalidates the sending Node, both
// owner-bound Nodes, the proposed cross-owner Link, the current binding/key
// candidate manifest and both independent key-bound owner grants in the same
// transaction that durably stores the exact SEALED_V1 BLOB and Relay inbox.
// It only accepts a source-to-target SEND over the currently configured Hub;
// same-Node links must use the local zero-Relay path.
func (s *Store) EnqueueCommunicationLinkSealedSend(input CommunicationLinkSealedSend) (*RelaySealedV1Record, error) {
	input.NodeCredentialDigest = strings.TrimSpace(input.NodeCredentialDigest)
	input.LinkID = strings.TrimSpace(input.LinkID)
	input.MessageID = strings.TrimSpace(input.MessageID)
	input.IdempotencyKey = strings.TrimSpace(input.IdempotencyKey)
	input.DataScope = strings.TrimSpace(input.DataScope)
	if !validNodeCredentialDigest(input.NodeCredentialDigest) || input.LinkID == "" ||
		len(input.LinkID) > 256 || input.MessageID == "" || len(input.MessageID) > 256 ||
		(input.IdempotencyKey != "" && len(input.IdempotencyKey) > 256) ||
		input.DataScope == "" || len(input.DataScope) > 128 ||
		len(input.Ciphertext) == 0 || len(input.Ciphertext) > communicationLinkMaxSealedSendWire {
		return nil, ErrCommunicationLinkRelayDenied
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now().UTC()
	link, manifest, err := authorizeCommunicationLinkSealedSourceTx(tx,
		input.NodeCredentialDigest, input.LinkID, input.DataScope, "send", now)
	if err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}

	context := sealedLinkForwardEndpointContext(link, manifest, input.MessageID, "SEND", "")
	if err := validateOpaqueEndpointMessage(input.Ciphertext, context, manifest.Source.PublicIdentity); err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}

	relayInput, err := relaySealedV1Message(RelaySealedV1Input{
		Route: RelaySealedV1Route{MessageID: input.MessageID,
			SenderEndpointID: link.SourceEndpointID, ReceiverEndpointID: link.TargetEndpointID, Kind: "send"},
		Security: RelayMessageSecurity{
			MessageID:        input.MessageID,
			SenderEndpointID: link.SourceEndpointID, SenderPrincipalID: link.SourcePrincipalID,
			SenderGroupID: link.SourceGroupID, SenderBindingID: manifest.Source.BindingID,
			SenderBindingEpoch: manifest.Source.BindingEpoch,
			ReceiverEndpointID: link.TargetEndpointID, ReceiverPrincipalID: link.TargetPrincipalID,
			ReceiverGroupID: link.TargetGroupID, ReceiverBindingID: manifest.Target.BindingID,
			ReceiverBindingEpoch: manifest.Target.BindingEpoch,
			VisibilityPolicyRef:  input.DataScope,
			AuthorizationRef:     communicationLinkAuthorizationRefPrefix + link.ID,
		}, Ciphertext: input.Ciphertext, IdempotencyKey: input.IdempotencyKey,
	})
	if err != nil {
		return nil, ErrCommunicationLinkRelayDenied
	}
	accepted, _, err := relayEnqueuePayloadTx(tx, relayInput, RelayPayloadModeSealedV1, input.Ciphertext)
	if err != nil {
		return nil, err
	}
	if accepted == nil {
		return nil, ErrRelayMessageNotFound
	}
	record, err := relaySealedV1RecordTx(tx, accepted.Message.ID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

// validateQueuedCommunicationLinkSealedSendTx is the second authorization
// gate, immediately before a Node can claim the opaque bytes. Rechecking the
// Link, request lifecycle (for ASK), and grants here prevents a queued message
// from surviving revocation, cancellation, key rotation, membership changes
// or a stale SessionBinding.
func validateQueuedCommunicationLinkSealedSendTx(tx *sql.Tx, record *RelaySealedV1Record, at time.Time) error {
	if record == nil {
		return ErrCommunicationLinkRelayDenied
	}
	// Claim and pre-injection authorization must pin the enrollment that
	// existed when this ciphertext was enqueued. Current Link grants alone
	// cannot make an old message valid after a revoked member joins again.
	if err := networkGuardRelayMessageTx(tx, record.Route.MessageID, record.Security.ReceiverGroupID, at); err != nil {
		return ErrCommunicationLinkRelayDenied
	}
	if record.Route.Kind == "reply" {
		return validateQueuedCommunicationLinkSealedReplyTx(tx, record, at)
	}
	if !strings.HasPrefix(record.Security.AuthorizationRef, communicationLinkAuthorizationRefPrefix) {
		return nil
	}
	linkID := strings.TrimPrefix(record.Security.AuthorizationRef, communicationLinkAuthorizationRefPrefix)
	if linkID == "" {
		return ErrCommunicationLinkRelayDenied
	}
	action, contextKind := "", ""
	switch record.Route.Kind {
	case "send":
		if record.Route.RequestID != "" || record.Route.ReplyTo != "" {
			return ErrCommunicationLinkRelayDenied
		}
		action, contextKind = "send", "SEND"
	case "ask":
		if record.Route.RequestID == "" || record.Route.ReplyTo != "" {
			return ErrCommunicationLinkRelayDenied
		}
		request, err := relayLoadRequestTx(tx, record.Route.RequestID)
		if err != nil || request == nil || request.State != FabricRequestOpen ||
			relayParseExpired(request.ExpiresAt, at) || request.MessageID != record.Route.MessageID ||
			request.Digest != record.Security.Digest ||
			request.SenderEndpointID != record.Security.SenderEndpointID ||
			request.SenderPrincipalID != record.Security.SenderPrincipalID ||
			request.SenderGroupID != record.Security.SenderGroupID ||
			request.SenderBindingID != record.Security.SenderBindingID ||
			request.SenderBindingEpoch != record.Security.SenderBindingEpoch ||
			request.ReceiverEndpointID != record.Security.ReceiverEndpointID ||
			request.ReceiverPrincipalID != record.Security.ReceiverPrincipalID ||
			request.ReceiverGroupID != record.Security.ReceiverGroupID ||
			request.ReceiverBindingID != record.Security.ReceiverBindingID ||
			request.ReceiverBindingEpoch != record.Security.ReceiverBindingEpoch ||
			request.AuthorizationRef != record.Security.AuthorizationRef ||
			request.VisibilityPolicyRef != record.Security.VisibilityPolicyRef {
			return ErrCommunicationLinkRelayDenied
		}
		action, contextKind = "ask", "REQUEST"
	default:
		return ErrCommunicationLinkRelayDenied
	}
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id=?`, linkID))
	if err != nil || link.State != CommunicationLinkProposed ||
		(link.Direction != "forward" && (action != "ask" || link.Direction != "bidirectional")) ||
		link.SourceOwnerID == link.TargetOwnerID || link.SourceNodeID == link.TargetNodeID ||
		link.TransportHubID == "" || !containsWord(link.Actions, action) ||
		!containsWord(link.DataScopes, record.Security.VisibilityPolicyRef) {
		return ErrCommunicationLinkRelayDenied
	}
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); err != nil ||
		hubID == "" || hubID != link.TransportHubID {
		return ErrCommunicationLinkRelayDenied
	}
	if err := validateCurrentCommunicationLinkScope(tx, link, at); err != nil {
		return ErrCommunicationLinkRelayDenied
	}
	if err := requireActiveOwnerBoundNodeTx(tx, link.SourceNodeID, link.SourceOwnerID, hubID); err != nil {
		return ErrCommunicationLinkRelayDenied
	}
	if err := requireActiveOwnerBoundNodeTx(tx, link.TargetNodeID, link.TargetOwnerID, hubID); err != nil {
		return ErrCommunicationLinkRelayDenied
	}
	manifest, err := readCommunicationLinkKeyManifest(tx, *link, at)
	if err != nil {
		return ErrCommunicationLinkRelayDenied
	}
	if _, err := readCurrentCommunicationLinkAuthorizationProof(tx, *link, *manifest,
		CommunicationLinkGrantSource, at); err != nil {
		return ErrCommunicationLinkRelayDenied
	}
	if _, err := readCurrentCommunicationLinkAuthorizationProof(tx, *link, *manifest,
		CommunicationLinkGrantTarget, at); err != nil {
		return ErrCommunicationLinkRelayDenied
	}
	security := record.Security
	if security.AuthorizationRef != communicationLinkAuthorizationRefPrefix+link.ID ||
		security.MessageID != record.Route.MessageID || security.SenderEndpointID != link.SourceEndpointID ||
		security.SenderPrincipalID != link.SourcePrincipalID || security.SenderGroupID != link.SourceGroupID ||
		security.SenderBindingID != manifest.Source.BindingID || security.SenderBindingEpoch != manifest.Source.BindingEpoch ||
		security.ReceiverEndpointID != link.TargetEndpointID || security.ReceiverPrincipalID != link.TargetPrincipalID ||
		security.ReceiverGroupID != link.TargetGroupID || security.ReceiverBindingID != manifest.Target.BindingID ||
		security.ReceiverBindingEpoch != manifest.Target.BindingEpoch ||
		record.Route.SenderEndpointID != link.SourceEndpointID ||
		record.Route.ReceiverEndpointID != link.TargetEndpointID {
		return ErrCommunicationLinkRelayDenied
	}
	context := sealedLinkForwardEndpointContext(link, manifest, security.MessageID,
		contextKind, record.Route.RequestID)
	if err := validateOpaqueEndpointMessage(record.Ciphertext, context, manifest.Source.PublicIdentity); err != nil {
		return ErrCommunicationLinkRelayDenied
	}
	return nil
}

func failQueuedSealedCommunicationLinkTx(tx *sql.Tx, item *RelayInboxItem, at, reason string) error {
	if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state=?, updated_at=?
WHERE recipient_endpoint_id=? AND sequence=? AND message_id=? AND state='READY'`,
		RelayInboxFailed, at, item.RecipientEndpointID, item.Sequence, item.MessageID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE relay_v2_outbox SET state=?, error=?, updated_at=? WHERE message_id=?`,
		RelayInboxFailed, reason, at, item.MessageID); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT OR IGNORE INTO relay_v2_receipts
(receipt_id, attempt_id, message_id, digest, target_endpoint_id, binding_id,
 binding_epoch, layer, error, created_at)
VALUES (?, '', ?, ?, ?, ?, ?, ?, ?, ?)`, NewID("rcpt"), item.MessageID, item.Digest,
		item.RecipientEndpointID, item.BindingID, item.BindingEpoch, RelayReceiptFailed, reason, at)
	return err
}

func failStaleQueuedCommunicationLinkSendsTx(tx *sql.Tx, endpointID string, at time.Time, limit int) error {
	rows, err := tx.Query(`SELECT `+relayInboxColumns+` FROM relay_v2_inbox i
JOIN fabric_messages f ON f.id=i.message_id
JOIN relay_v2_message_payloads payload ON payload.message_id=i.message_id
JOIN relay_v2_message_security security ON security.message_id=i.message_id
WHERE i.recipient_endpoint_id=? AND i.state='READY' AND payload.payload_mode='SEALED_V1'
  AND security.authorization_ref LIKE ? ORDER BY i.sequence LIMIT ?`, endpointID,
		communicationLinkAuthorizationRefPrefix+"%", limit)
	if err != nil {
		return err
	}
	items := make([]*RelayInboxItem, 0)
	for rows.Next() {
		item, err := scanRelayInboxItem(rows)
		if err != nil {
			_ = rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range items {
		record, err := relaySealedV1RecordTx(tx, item.MessageID)
		if err != nil {
			return err
		}
		if err := validateQueuedCommunicationLinkSealedSendTx(tx, record, at); err != nil {
			timestamp := at.UTC().Format(time.RFC3339Nano)
			reason := "communication link authorization is no longer current"
			if record.Route.Kind == "ask" {
				request, loadErr := relayLoadRequestTx(tx, record.Route.RequestID)
				if loadErr != nil {
					return loadErr
				}
				if request != nil && request.State == FabricRequestOpen {
					if relayParseExpired(request.ExpiresAt, at) {
						reason = "request deadline reached"
						if err := relayExpireRequestTx(tx, request.RequestID, reason, timestamp); err != nil {
							return err
						}
					} else if _, err := relayMarkRequestCancellationTx(tx, request.RequestID,
						FabricRequestCancelled, "REQUEST_AUTHORIZATION_REVOKED", reason, timestamp); err != nil {
						return err
					}
				}
			}
			if err := failQueuedSealedCommunicationLinkTx(tx, item, timestamp, reason); err != nil {
				return err
			}
		}
	}
	return nil
}

func readActiveOwnerBoundNodeTx(tx *sql.Tx, credentialDigest string) (nodeID, ownerID, hubID string, err error) {
	err = tx.QueryRow(`SELECT credential.node_id, binding.owner_id, binding.hub_id
FROM fabric_node_credentials credential
JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
  AND binding.node_credential_digest=credential.credential_hash
  AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
  AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
  AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
WHERE credential.credential_hash=? AND credential.status='active'`, credentialDigest).
		Scan(&nodeID, &ownerID, &hubID)
	return
}

func requireActiveOwnerBoundNodeTx(tx *sql.Tx, nodeID, ownerID, hubID string) error {
	var active int
	err := tx.QueryRow(`SELECT 1
FROM fabric_node_credentials credential
JOIN node_owner_bindings_v2 binding ON binding.node_id=credential.node_id
  AND binding.node_credential_digest=credential.credential_hash
  AND binding.node_credential_version=credential.version AND binding.state='ACTIVE'
JOIN client_device_hub_config_v2 hub ON hub.id=1 AND hub.hub_id=binding.hub_id
JOIN principals principal ON principal.id=binding.owner_id
  AND principal.kind='human' AND principal.status='active'
JOIN owner_approval_keys_v2 owner_key ON owner_key.owner_id=binding.owner_id
  AND owner_key.key_id=binding.owner_key_id AND owner_key.state='ACTIVE'
WHERE credential.node_id=? AND binding.owner_id=? AND binding.hub_id=? AND credential.status='active'`,
		nodeID, ownerID, hubID).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCommunicationLinkRelayDenied
	}
	return err
}

func validateOpaqueEndpointMessage(wire []byte, expected e2ee.EndpointMessageContext,
	expectedSender e2ee.PublicIdentity) error {
	if len(wire) == 0 || len(wire) > communicationLinkMaxSealedSendWire {
		return e2ee.ErrInvalidEnvelope
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var envelope e2ee.EndpointMessageEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return fmt.Errorf("decode endpoint envelope header: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("endpoint envelope has trailing data")
	}
	if envelope.Version != e2ee.EndpointEnvelopeVersion || envelope.Suite != e2ee.EndpointEnvelopeSuite ||
		envelope.Context != expected || len(envelope.Sealed) == 0 || len(envelope.Signature) == 0 ||
		!json.Valid(envelope.Sealed) {
		return e2ee.ErrInvalidEnvelope
	}
	if e2ee.ValidatePublicIdentity(expectedSender) != nil || expected.SenderKeyID != expectedSender.ID ||
		len(envelope.Signature) != mldsa65.SignatureSize {
		return e2ee.ErrInvalidEnvelope
	}
	signingKey := new(mldsa65.PublicKey)
	if err := signingKey.UnmarshalBinary(expectedSender.SigningPublic); err != nil {
		return e2ee.ErrInvalidEnvelope
	}
	outerUnsigned := envelope
	outerUnsigned.Signature = nil
	outerSignedBytes, err := json.Marshal(outerUnsigned)
	if err != nil || !mldsa65.Verify(signingKey, outerSignedBytes, nil, envelope.Signature) {
		return errors.New("endpoint route signature is invalid")
	}
	sealedDecoder := json.NewDecoder(bytes.NewReader(envelope.Sealed))
	sealedDecoder.DisallowUnknownFields()
	var sealed e2ee.Envelope
	if err := sealedDecoder.Decode(&sealed); err != nil {
		return fmt.Errorf("decode sealed PQ payload header: %w", err)
	}
	if err := sealedDecoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("sealed PQ payload has trailing data")
	}
	if sealed.Version != e2ee.ProtocolVersion || sealed.Algorithm != e2ee.Algorithm ||
		sealed.Sequence == 0 || len(sealed.KEMCiphertext) != mlkem768.CiphertextSize || len(sealed.Nonce) != 12 ||
		len(sealed.Ciphertext) == 0 || sealed.SenderID != expectedSender.ID ||
		!bytes.Equal(sealed.SenderSigningPublic, expectedSender.SigningPublic) ||
		len(sealed.Signature) != mldsa65.SignatureSize {
		return e2ee.ErrInvalidEnvelope
	}
	innerUnsigned := sealed
	innerUnsigned.Signature = nil
	innerSignedBytes, err := json.Marshal(innerUnsigned)
	if err != nil || !mldsa65.Verify(signingKey, innerSignedBytes, nil, sealed.Signature) {
		return errors.New("sealed PQ payload signature is invalid")
	}
	return nil
}

func containsWord(words []string, wanted string) bool {
	for _, word := range words {
		if word == wanted {
			return true
		}
	}
	return false
}
