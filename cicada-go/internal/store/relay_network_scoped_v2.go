package store

import (
	"database/sql"
	"time"
)

// The persisted request supplies its own message and Group; caller fields can
// identify a side, but cannot select a different saved route.
func loadScopedRelayRequestTx(tx *sql.Tx, requestID string, scope NativeActorScope) (*FabricRequest, error) {
	if requestID == "" || scope.PrincipalID == "" || scope.EndpointID == "" || scope.GroupID == "" {
		return nil, ErrRelayRequestNotFound
	}
	request, err := relayLoadRequestTx(tx, requestID)
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, ErrRelayRequestNotFound
	}
	var payloadMode string
	if err := tx.QueryRow(`SELECT COALESCE((SELECT payload_mode FROM relay_v2_message_payloads
WHERE message_id=?),'PLAINTEXT')`, request.MessageID).Scan(&payloadMode); err != nil || payloadMode != "PLAINTEXT" {
		return nil, ErrRelayRequestNotFound
	}
	actorIsSender := request.SenderPrincipalID == scope.PrincipalID &&
		request.SenderEndpointID == scope.EndpointID && request.SenderGroupID == scope.GroupID
	actorIsReceiver := request.ReceiverPrincipalID == scope.PrincipalID &&
		request.ReceiverEndpointID == scope.EndpointID && request.ReceiverGroupID == scope.GroupID
	if !actorIsSender && !actorIsReceiver {
		return nil, ErrRelayRequestNotFound
	}
	at := time.Now().UTC()
	if err := guardNativeActorTx(tx, scope, "", at); err != nil {
		return nil, err
	}
	if err := networkGuardRelayMessageTx(tx, request.MessageID, request.ReceiverGroupID, at); err != nil {
		return nil, err
	}
	return request, nil
}

// GetRelayFabricRequestForActor checks caller and the original enqueue
// enrollment in the same snapshot used to read lifecycle metadata.
func (s *Store) GetRelayFabricRequestForActor(requestID string, scope NativeActorScope) (*FabricRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	request, err := loadScopedRelayRequestTx(tx, relayString(requestID), scope)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

// RequestFabricRequestCancellationForActor performs the same current-scope
// check and the state transition in one write transaction.
func (s *Store) RequestFabricRequestCancellationForActor(requestID, reason string, scope NativeActorScope) (*FabricRequest, error) {
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
	request, err := loadScopedRelayRequestTx(tx, relayString(requestID), scope)
	if err != nil {
		return nil, err
	}
	if request.SenderPrincipalID != scope.PrincipalID ||
		request.SenderEndpointID != scope.EndpointID || request.SenderGroupID != scope.GroupID {
		return nil, ErrRelayRequestNotFound
	}
	updated, err := relayMarkRequestCancellationTx(tx, request.RequestID,
		FabricRequestCancelRequested, "REQUEST_CANCEL_REQUESTED", relayString(reason), now())
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return updated, nil
}
