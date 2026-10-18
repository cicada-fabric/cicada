package store

import "database/sql"

func sameGroupSealedV1PeerCarrierTx(tx *sql.Tx, pair sameGroupEndpointPair) (*SameGroupSealedV1PeerKey, error) {
	scope, err := readNativeContextScopeForEndpointTx(tx, pair.sender.EndpointID, pair.groupID)
	if err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	result := &SameGroupSealedV1PeerKey{HubID: pair.hubID, GroupID: pair.groupID, NativeContextScope: scope, Sender: pair.sender, Receiver: pair.receiver, NativePairEvidence: pair.nativeEvidence, NativePairCurrent: pair.nativeCurrent}
	// Preserve the established locator redaction. Current carries the separate
	// actual approved SID required by native-pair policy.
	result.Receiver.NativeSessionID = ""
	if err := nativePairCarrierTx(result, pair.nativeEvidence); err != nil {
		return nil, err
	}
	return result, nil
}

// Construct the identical complete typed carrier during claim preflight and
// final authorization, using the actual allocated attempt and durable route.
func sameGroupSealedV1DeliveryCarrierTx(tx *sql.Tx, pair sameGroupEndpointPair, record *RelaySealedV1Record, attemptID string, task *SealedTaskHandoffDeliveryAuthorization) (*SameGroupSealedV1DeliveryAuthorization, error) {
	parent, err := relayParentRequestForSealedRouteTx(tx, record.Route)
	if err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	scope, err := readNativeContextScopeForEndpointTx(tx, pair.receiver.EndpointID, record.Security.ReceiverGroupID)
	if err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	return sameGroupSealedV1DeliveryCarrier(pair, record, attemptID, parent, scope, task)
}

func sameGroupSealedV1DeliveryCarrier(pair sameGroupEndpointPair, record *RelaySealedV1Record, attemptID, parent string, scope NativeContextScopeMetadata, task *SealedTaskHandoffDeliveryAuthorization) (*SameGroupSealedV1DeliveryAuthorization, error) {
	result := &SameGroupSealedV1DeliveryAuthorization{AttemptID: attemptID, MessageID: record.Route.MessageID, Digest: record.Security.Digest, EndpointID: pair.receiver.EndpointID, NodeID: pair.receiver.NodeID, OwnerID: pair.receiver.OwnerID, BindingID: pair.receiver.BindingID, BindingEpoch: pair.receiver.BindingEpoch, NativeSessionID: pair.receiver.NativeSessionID, DataScope: record.Security.VisibilityPolicyRef, Route: record.Route, ParentRequestID: parent, NativeContextScope: scope, Sender: pair.sender, Receiver: pair.receiver, TaskHandoff: task, NativePairEvidence: pair.nativeEvidence, NativePairCurrent: pair.nativeCurrent}
	result.Sender.NativeSessionID = ""
	if err := nativePairCarrierTx(result, pair.nativeEvidence); err != nil {
		return nil, err
	}
	return result, nil
}
