package store

import (
	"database/sql"
	"strings"
	"time"
)

// GetCommunicationLinkSealedRequestForNodeCredential returns only request
// lifecycle metadata to one of the two Nodes bound to its original Link.
// It never exposes the ciphertext or routes through the legacy plaintext
// request reader. Historical status remains readable after Link revocation,
// provided the Node still belongs to the same owner.
func (s *Store) GetCommunicationLinkSealedRequestForNodeCredential(
	credentialDigest, requestID string) (*FabricRequest, error) {
	credentialDigest, requestID = strings.TrimSpace(credentialDigest), strings.TrimSpace(requestID)
	if !validNodeCredentialDigest(credentialDigest) || requestID == "" || len(requestID) > 256 {
		return nil, ErrRelayRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	request, err := authorizedCommunicationLinkSealedRequestTx(tx, credentialDigest, requestID, false)
	if err != nil {
		return nil, err
	}
	nowTime := time.Now().UTC()
	if (request.State == FabricRequestOpen || request.State == FabricRequestCancelRequested) &&
		relayParseExpired(request.ExpiresAt, nowTime) {
		if err := relayExpireRequestTx(tx, requestID, "request deadline reached", nowTime.Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
		request, err = relayLoadRequestTx(tx, requestID)
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

// RequestCommunicationLinkSealedAskCancellation is an intent to stop a
// pending request. It fences READY delivery and future exact-attempt
// authorization, but does not claim an already injected Runtime has stopped.
// Only the original sender's currently owner-bound Node may request it.
func (s *Store) RequestCommunicationLinkSealedAskCancellation(
	credentialDigest, requestID, reason string) (*FabricRequest, error) {
	credentialDigest, requestID = strings.TrimSpace(credentialDigest), strings.TrimSpace(requestID)
	reason = strings.TrimSpace(reason)
	if !validNodeCredentialDigest(credentialDigest) || requestID == "" || len(requestID) > 256 || len(reason) > 512 {
		return nil, ErrRelayRequestNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	request, err := authorizedCommunicationLinkSealedRequestTx(tx, credentialDigest, requestID, true)
	if err != nil {
		return nil, err
	}
	nowTime := time.Now().UTC()
	if relayParseExpired(request.ExpiresAt, nowTime) {
		if err := relayExpireRequestTx(tx, requestID, "request deadline reached", nowTime.Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
		request, err = relayLoadRequestTx(tx, requestID)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return request, nil
	}
	request, err = relayMarkRequestCancellationTx(tx, requestID,
		FabricRequestCancelRequested, "REQUEST_CANCEL_REQUESTED", reason,
		nowTime.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

func authorizedCommunicationLinkSealedRequestTx(tx *sql.Tx,
	credentialDigest, requestID string, senderOnly bool) (*FabricRequest, error) {
	nodeID, ownerID, hubID, err := readActiveOwnerBoundNodeTx(tx, credentialDigest)
	if err != nil {
		return nil, ErrRelayRequestNotFound
	}
	request, err := relayLoadRequestTx(tx, requestID)
	if err != nil {
		return nil, err
	}
	if request == nil || !strings.HasPrefix(request.AuthorizationRef, communicationLinkAuthorizationRefPrefix) {
		return nil, ErrRelayRequestNotFound
	}
	mode, err := relayPayloadModeTx(tx, request.MessageID)
	if err != nil || mode != RelayPayloadModeSealedV1 {
		return nil, ErrRelayRequestNotFound
	}
	linkID := strings.TrimPrefix(request.AuthorizationRef, communicationLinkAuthorizationRefPrefix)
	var link CommunicationLink
	linkPtr, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id=?`, linkID))
	if err != nil || linkPtr == nil {
		return nil, ErrRelayRequestNotFound
	}
	link = *linkPtr
	if link.TransportHubID != hubID || request.SenderEndpointID != link.SourceEndpointID ||
		request.SenderPrincipalID != link.SourcePrincipalID || request.SenderGroupID != link.SourceGroupID ||
		request.ReceiverEndpointID != link.TargetEndpointID ||
		request.ReceiverPrincipalID != link.TargetPrincipalID ||
		request.ReceiverGroupID != link.TargetGroupID ||
		(senderOnly && (nodeID != link.SourceNodeID || ownerID != link.SourceOwnerID)) ||
		(!senderOnly && !((nodeID == link.SourceNodeID && ownerID == link.SourceOwnerID) ||
			(nodeID == link.TargetNodeID && ownerID == link.TargetOwnerID))) {
		return nil, ErrRelayRequestNotFound
	}
	return request, nil
}
