package store

import (
	"bytes"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	SameGroupSealedV1DataScope           = "same-group.endpoint-message.v1"
	sameGroupSealedV1AuthorizationPrefix = "same-group-sealed.v2:"
)

var (
	ErrSameGroupSealedV1Denied   = errors.New("same-Group SEALED_V1 route is not currently authorized")
	ErrSameGroupSealedV1NotFound = errors.New("same-Group SEALED_V1 request not found or not authorized")
)

// SameGroupSealedV1EndpointEvidence is public key and route evidence for one
// endpoint. The candidate and signed grant contain public data only.
type SameGroupSealedV1EndpointEvidence struct {
	EndpointID           string                      `json:"endpoint_id"`
	PrincipalID          string                      `json:"principal_id"`
	OwnerID              string                      `json:"owner_id"`
	NodeID               string                      `json:"node_id"`
	GroupID              string                      `json:"group_id"`
	BindingID            string                      `json:"binding_id"`
	BindingEpoch         uint64                      `json:"binding_epoch"`
	NativeSessionID      string                      `json:"native_session_id"`
	GroupRevision        int64                       `json:"group_revision"`
	MembershipRevision   int64                       `json:"membership_revision"`
	EndpointJoinRevision int64                       `json:"endpoint_join_revision"`
	Candidate            EndpointKeyCandidate        `json:"candidate"`
	Grant                *OwnerGroupEndpointKeyGrant `json:"grant"`
}

// SameGroupSealedV1PeerKey lets an authenticated source Node pin and encrypt
// to the other current Endpoint. Both endpoint grants and the route snapshot
// are checked together before this public evidence is returned.
type SameGroupSealedV1PeerKey struct {
	HubID              string                            `json:"hub_id"`
	GroupID            string                            `json:"group_id"`
	NativeContextScope NativeContextScopeMetadata        `json:"native_context_scope"`
	Sender             SameGroupSealedV1EndpointEvidence `json:"sender"`
	Receiver           SameGroupSealedV1EndpointEvidence `json:"receiver"`
}

type SameGroupSealedV1Send struct {
	NodeCredentialDigest string
	GroupID              string
	SourceEndpointID     string
	TargetEndpointID     string
	MessageID            string
	IdempotencyKey       string
	DataScope            string
	Ciphertext           []byte
}

type SameGroupSealedV1Ask struct {
	NodeCredentialDigest string
	GroupID              string
	SourceEndpointID     string
	TargetEndpointID     string
	MessageID            string
	RequestID            string
	ParentRequestID      string
	IdempotencyKey       string
	DataScope            string
	ExpiresAt            string
	Ciphertext           []byte
}

type SameGroupSealedV1Reply struct {
	NodeCredentialDigest string
	RequestID            string
	MessageID            string
	IdempotencyKey       string
	Ciphertext           []byte
}

// SameGroupSealedV1DeliveryAuthorization is short-lived evidence for the
// exact claimed attempt. A Node must still verify the two public grants and
// endpoint attestations locally before opening or injecting the ciphertext.
type SameGroupSealedV1DeliveryAuthorization struct {
	AttemptID          string                                  `json:"attempt_id"`
	MessageID          string                                  `json:"message_id"`
	Digest             string                                  `json:"digest"`
	EndpointID         string                                  `json:"endpoint_id"`
	NodeID             string                                  `json:"node_id"`
	OwnerID            string                                  `json:"owner_id"`
	BindingID          string                                  `json:"binding_id"`
	BindingEpoch       uint64                                  `json:"binding_epoch"`
	NativeSessionID    string                                  `json:"native_session_id"`
	DataScope          string                                  `json:"data_scope"`
	ParentRequestID    string                                  `json:"parent_request_id,omitempty"`
	NativeContextScope NativeContextScopeMetadata              `json:"native_context_scope"`
	Route              RelaySealedV1Route                      `json:"route"`
	Sender             SameGroupSealedV1EndpointEvidence       `json:"sender"`
	Receiver           SameGroupSealedV1EndpointEvidence       `json:"receiver"`
	TaskHandoff        *SealedTaskHandoffDeliveryAuthorization `json:"task_handoff,omitempty"`
}

type sameGroupEndpointPair struct {
	hubID    string
	groupID  string
	sender   SameGroupSealedV1EndpointEvidence
	receiver SameGroupSealedV1EndpointEvidence
}

func validSameGroupSealedV1Token(value string) bool {
	return value != "" && len(value) <= 256 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, " \t\n\r/\\")
}

func validSameGroupSealedV1Input(inputCredential, groupID, sourceEndpointID,
	targetEndpointID, messageID, idempotencyKey, dataScope string, ciphertext []byte) bool {
	return validNodeCredentialDigest(inputCredential) &&
		validSameGroupSealedV1Token(groupID) && validSameGroupSealedV1Token(sourceEndpointID) &&
		validSameGroupSealedV1Token(targetEndpointID) && sourceEndpointID != targetEndpointID &&
		validSameGroupSealedV1Token(messageID) &&
		(idempotencyKey == "" || validSameGroupSealedV1Token(idempotencyKey)) &&
		dataScope == SameGroupSealedV1DataScope && len(ciphertext) > 0 &&
		len(ciphertext) <= communicationLinkMaxSealedSendWire
}

func readSameGroupSealedV1EndpointTx(tx *sql.Tx, groupID, endpointID string,
	at time.Time) (SameGroupSealedV1EndpointEvidence, error) {
	var ownerID string
	err := tx.QueryRow(`SELECT p.owner_id FROM fabric_endpoints e
JOIN principals p ON p.id=e.principal_id WHERE e.id=?`, endpointID).Scan(&ownerID)
	if errors.Is(err, sql.ErrNoRows) || ownerID == "" {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	if err != nil {
		return SameGroupSealedV1EndpointEvidence{}, err
	}
	grant, err := readLatestGroupEndpointKeyGrant(tx, ownerID, groupID, endpointID)
	if err != nil {
		if errors.Is(err, ErrGroupEndpointKeyGrantNotFound) {
			return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
		}
		return SameGroupSealedV1EndpointEvidence{}, err
	}
	if evaluateGroupEndpointKeyGrant(tx, grant, at) != GroupEndpointKeyGrantCurrent {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	manifest := grant.Manifest
	side, err := readCommunicationLinkKeySide(tx, endpointID, groupID,
		manifest.PrincipalID, ownerID, manifest.NodeID, manifest.BindingID, manifest.BindingEpoch)
	if err != nil || side.KeyID != manifest.CandidateKeyID ||
		side.CandidateVersion != manifest.CandidateVersion ||
		side.KeyFingerprint != manifest.CandidateFingerprint ||
		side.ProofDigest != manifest.CandidateProofDigest || side.PublicIdentity.ID != manifest.CandidatePublicIdentity.ID {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	var nativeSessionID string
	err = tx.QueryRow(`SELECT native_session_id FROM session_bindings
WHERE id=? AND endpoint_id=? AND principal_id=? AND node_id=? AND epoch=?`,
		manifest.BindingID, endpointID, manifest.PrincipalID, manifest.NodeID,
		manifest.BindingEpoch).Scan(&nativeSessionID)
	if errors.Is(err, sql.ErrNoRows) || nativeSessionID == "" {
		return SameGroupSealedV1EndpointEvidence{}, ErrSameGroupSealedV1Denied
	}
	if err != nil {
		return SameGroupSealedV1EndpointEvidence{}, err
	}
	grant.CurrentStatus = GroupEndpointKeyGrantCurrent
	candidate := EndpointKeyCandidate{
		EndpointID: side.EndpointID, PrincipalID: side.PrincipalID, OwnerID: side.OwnerID,
		NodeID: side.NodeID, Public: side.PublicIdentity, KeyID: side.KeyID,
		BindingID: side.BindingID, BindingEpoch: side.BindingEpoch,
		Proof: append([]byte(nil), side.Attestation...), ProofDigest: side.ProofDigest,
		State: EndpointKeyCandidateStateCandidate, Version: side.CandidateVersion,
	}
	return SameGroupSealedV1EndpointEvidence{
		EndpointID: side.EndpointID, PrincipalID: side.PrincipalID, OwnerID: ownerID,
		NodeID: side.NodeID, GroupID: groupID, BindingID: side.BindingID,
		BindingEpoch: side.BindingEpoch, NativeSessionID: nativeSessionID,
		GroupRevision: manifest.GroupRevision, MembershipRevision: manifest.MembershipRevision,
		EndpointJoinRevision: manifest.EndpointJoinRevision,
		Candidate:            candidate, Grant: grant,
	}, nil
}

func readSameGroupSealedV1PairTx(tx *sql.Tx, groupID, senderEndpointID,
	receiverEndpointID string, at time.Time) (sameGroupEndpointPair, error) {
	if !validSameGroupSealedV1Token(groupID) ||
		!validSameGroupSealedV1Token(senderEndpointID) ||
		!validSameGroupSealedV1Token(receiverEndpointID) || senderEndpointID == receiverEndpointID {
		return sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	sender, err := readSameGroupSealedV1EndpointTx(tx, groupID, senderEndpointID, at)
	if err != nil {
		return sameGroupEndpointPair{}, err
	}
	receiver, err := readSameGroupSealedV1EndpointTx(tx, groupID, receiverEndpointID, at)
	if err != nil {
		return sameGroupEndpointPair{}, err
	}
	var hubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&hubID); err != nil || hubID == "" {
		if err != nil {
			return sameGroupEndpointPair{}, err
		}
		return sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	if sender.GroupID != groupID || receiver.GroupID != groupID ||
		sender.OwnerID == "" || sender.OwnerID != receiver.OwnerID ||
		sender.NodeID == receiver.NodeID || sender.Grant.Manifest.HubID != hubID ||
		receiver.Grant.Manifest.HubID != hubID ||
		sender.Grant.Manifest.GroupRevision != receiver.Grant.Manifest.GroupRevision {
		return sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	for _, endpoint := range []SameGroupSealedV1EndpointEvidence{sender, receiver} {
		if err := networkGuardGroupEndpointTx(tx, endpoint.PrincipalID, endpoint.EndpointID, groupID, at); err != nil {
			return sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
		}
	}
	return sameGroupEndpointPair{hubID: hubID, groupID: groupID,
		sender: sender, receiver: receiver}, nil
}

func sameGroupSealedV1AuthorizationRef(groupID string) string {
	return sameGroupSealedV1AuthorizationPrefix + groupID
}

func sameGroupSealedV1Context(pair sameGroupEndpointPair, messageID, kind,
	requestID, replyTo string, parentRequestID ...string) e2ee.EndpointMessageContext {
	sender, receiver := pair.sender, pair.receiver
	parent := ""
	if len(parentRequestID) == 1 {
		parent = parentRequestID[0]
	} else if len(parentRequestID) > 1 {
		parent = "\x00"
	}
	return e2ee.EndpointMessageContext{
		MessageID: messageID, Kind: kind, RequestID: requestID, ReplyTo: replyTo,
		ParentRequestID:  parent,
		SenderEndpointID: sender.EndpointID, SenderPrincipalID: sender.PrincipalID,
		SenderOwnerID: sender.OwnerID, SenderGroupID: pair.groupID,
		SenderMembershipRevision: sender.MembershipRevision,
		SenderBindingEpoch:       sender.BindingEpoch, SenderKeyID: sender.Candidate.KeyID,
		ReceiverEndpointID: receiver.EndpointID, ReceiverPrincipalID: receiver.PrincipalID,
		ReceiverOwnerID: receiver.OwnerID, ReceiverGroupID: pair.groupID,
		ReceiverMembershipRevision: receiver.MembershipRevision,
		ReceiverBindingEpoch:       receiver.BindingEpoch, ReceiverKeyID: receiver.Candidate.KeyID,
		TransportHubID: pair.hubID,
	}
}

func sameGroupSealedV1PairForRecordTx(tx *sql.Tx, record *RelaySealedV1Record,
	at time.Time) (sameGroupEndpointPair, error) {
	if record == nil || record.PayloadMode != RelayPayloadModeSealedV1 ||
		record.Security.MessageID != record.Route.MessageID ||
		record.Security.Digest != relayCiphertextDigest(record.Ciphertext) ||
		record.Route.SenderEndpointID != record.Security.SenderEndpointID ||
		record.Route.ReceiverEndpointID != record.Security.ReceiverEndpointID ||
		record.Security.VisibilityPolicyRef != SameGroupSealedV1DataScope {
		return sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	groupID, ok := strings.CutPrefix(record.Security.AuthorizationRef,
		sameGroupSealedV1AuthorizationPrefix)
	if !ok || !validSameGroupSealedV1Token(groupID) ||
		record.Security.SenderGroupID != groupID || record.Security.ReceiverGroupID != groupID {
		return sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	pair, err := readSameGroupSealedV1PairTx(tx, groupID,
		record.Route.SenderEndpointID, record.Route.ReceiverEndpointID, at)
	if err != nil {
		return sameGroupEndpointPair{}, err
	}
	if !sameGroupSealedV1SecurityMatchesPair(record.Security, pair) {
		return sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	return pair, nil
}

func sameGroupSealedV1SecurityMatchesPair(security RelayMessageSecurity,
	pair sameGroupEndpointPair) bool {
	return security.AuthorizationRef == sameGroupSealedV1AuthorizationRef(pair.groupID) &&
		security.VisibilityPolicyRef == SameGroupSealedV1DataScope &&
		security.SenderEndpointID == pair.sender.EndpointID &&
		security.SenderPrincipalID == pair.sender.PrincipalID &&
		security.SenderGroupID == pair.groupID &&
		security.SenderBindingID == pair.sender.BindingID &&
		security.SenderBindingEpoch == pair.sender.BindingEpoch &&
		security.ReceiverEndpointID == pair.receiver.EndpointID &&
		security.ReceiverPrincipalID == pair.receiver.PrincipalID &&
		security.ReceiverGroupID == pair.groupID &&
		security.ReceiverBindingID == pair.receiver.BindingID &&
		security.ReceiverBindingEpoch == pair.receiver.BindingEpoch
}

func requireSameGroupSealedV1SourceTx(tx *sql.Tx, credentialDigest string,
	pair sameGroupEndpointPair) error {
	nodeID, ownerID, hubID, err := readActiveOwnerBoundNodeTx(tx, credentialDigest)
	if err != nil || nodeID != pair.sender.NodeID || ownerID != pair.sender.OwnerID || hubID != pair.hubID {
		return ErrSameGroupSealedV1Denied
	}
	return nil
}

func sealedRequestMatchesSameGroupAsk(request *FabricRequest,
	ask *RelaySealedV1Record, pair sameGroupEndpointPair) bool {
	if request == nil || ask == nil || ask.Route.Kind != "ask" ||
		ask.Route.RequestID != request.RequestID || ask.Route.MessageID != request.MessageID ||
		ask.Route.ReplyTo != "" || request.AuthorizationRef != sameGroupSealedV1AuthorizationRef(pair.groupID) ||
		request.VisibilityPolicyRef != SameGroupSealedV1DataScope ||
		!sameGroupSealedV1SecurityMatchesPair(ask.Security, pair) {
		return false
	}
	security := ask.Security
	return request.SenderEndpointID == pair.sender.EndpointID &&
		request.SenderPrincipalID == pair.sender.PrincipalID && request.SenderGroupID == pair.groupID &&
		request.SenderBindingID == pair.sender.BindingID && request.SenderBindingEpoch == pair.sender.BindingEpoch &&
		request.ReceiverEndpointID == pair.receiver.EndpointID &&
		request.ReceiverPrincipalID == pair.receiver.PrincipalID && request.ReceiverGroupID == pair.groupID &&
		request.ReceiverBindingID == pair.receiver.BindingID && request.ReceiverBindingEpoch == pair.receiver.BindingEpoch &&
		request.Digest == security.Digest && request.IdempotencyKey == security.IdempotencyKey &&
		request.AuthorizationRef == security.AuthorizationRef &&
		request.VisibilityPolicyRef == security.VisibilityPolicyRef
}

func sameGroupSealedV1AskForReplyTx(tx *sql.Tx, requestID string,
	at time.Time) (*FabricRequest, *RelaySealedV1Record, sameGroupEndpointPair, error) {
	request, err := relayLoadRequestTx(tx, requestID)
	if err != nil || request == nil {
		return nil, nil, sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	ask, err := relaySealedV1RecordTx(tx, request.MessageID)
	if err != nil || ask == nil || ask.Route.RequestID != requestID {
		return nil, nil, sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	pair, err := sameGroupSealedV1PairForRecordTx(tx, ask, at)
	if err != nil || !sealedRequestMatchesSameGroupAsk(request, ask, pair) {
		if err != nil {
			return nil, nil, sameGroupEndpointPair{}, err
		}
		return nil, nil, sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	expiresAt, expiryErr := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if expiryErr != nil || expiresAt.After(mustParseRFC3339Nano(pair.sender.Grant.Manifest.ExpiresAt)) ||
		expiresAt.After(mustParseRFC3339Nano(pair.receiver.Grant.Manifest.ExpiresAt)) {
		return nil, nil, sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	context := sameGroupSealedV1Context(pair, request.MessageID, "REQUEST", request.RequestID, "", request.ParentRequestID)
	if err := validateOpaqueEndpointMessage(ask.Ciphertext, context, pair.sender.Candidate.Public); err != nil {
		return nil, nil, sameGroupEndpointPair{}, ErrSameGroupSealedV1Denied
	}
	return request, ask, pair, nil
}

func mustParseRFC3339Nano(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed
}

// GetSameGroupSealedV1PeerKey exposes current public trust evidence only to
// the Node that currently owns the source Endpoint.
func (s *Store) GetSameGroupSealedV1PeerKey(credentialDigest, groupID,
	sourceEndpointID, targetEndpointID string) (*SameGroupSealedV1PeerKey, error) {
	if !validNodeCredentialDigest(credentialDigest) || !validSameGroupSealedV1Token(groupID) ||
		!validSameGroupSealedV1Token(sourceEndpointID) || !validSameGroupSealedV1Token(targetEndpointID) {
		return nil, ErrSameGroupSealedV1Denied
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	pair, err := readSameGroupSealedV1PairTx(tx, groupID, sourceEndpointID,
		targetEndpointID, time.Now().UTC())
	if err != nil || requireSameGroupSealedV1SourceTx(tx, credentialDigest, pair) != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	scope, err := readNativeContextScopeForEndpointTx(tx, sourceEndpointID, groupID)
	if err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// The source can verify and encrypt to the target's public key without
	// learning or storing the target's current native Session ID.
	pair.receiver.NativeSessionID = ""
	return &SameGroupSealedV1PeerKey{HubID: pair.hubID, GroupID: pair.groupID,
		NativeContextScope: scope,
		Sender:             pair.sender, Receiver: pair.receiver}, nil
}

// EnqueueSameGroupSealedV1Send derives every route identity from current
// Endpoint, binding, Group, Node credential and dual owner grants. It accepts
// only a cross-Node SEALED_V1 ciphertext on the fixed same-Group channel.
func (s *Store) EnqueueSameGroupSealedV1Send(input SameGroupSealedV1Send) (*RelaySealedV1Record, error) {
	if !validSameGroupSealedV1Input(input.NodeCredentialDigest, input.GroupID,
		input.SourceEndpointID, input.TargetEndpointID, input.MessageID,
		input.IdempotencyKey, input.DataScope, input.Ciphertext) {
		return nil, ErrSameGroupSealedV1Denied
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
	pair, err := readSameGroupSealedV1PairTx(tx, input.GroupID,
		input.SourceEndpointID, input.TargetEndpointID, time.Now().UTC())
	if err != nil || requireSameGroupSealedV1SourceTx(tx, input.NodeCredentialDigest, pair) != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	context := sameGroupSealedV1Context(pair, input.MessageID, "SEND", "", "")
	if err := validateOpaqueEndpointMessage(input.Ciphertext, context, pair.sender.Candidate.Public); err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	inputRelay, err := relaySealedV1Message(RelaySealedV1Input{
		Route: RelaySealedV1Route{MessageID: input.MessageID,
			SenderEndpointID: pair.sender.EndpointID, ReceiverEndpointID: pair.receiver.EndpointID, Kind: "send"},
		Security: sameGroupSealedV1Security(input.MessageID, input.IdempotencyKey,
			input.DataScope, pair), Ciphertext: input.Ciphertext, IdempotencyKey: input.IdempotencyKey,
	})
	if err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	accepted, _, err := relayEnqueuePayloadTx(tx, inputRelay, RelayPayloadModeSealedV1, input.Ciphertext)
	if err != nil {
		return nil, err
	}
	if accepted == nil {
		return nil, ErrRelayMessageNotFound
	}
	record, err := relaySealedV1RecordTx(tx, accepted.Message.ID)
	if err != nil || !bytes.Equal(record.Ciphertext, input.Ciphertext) ||
		!sameGroupSealedV1SecurityMatchesPair(record.Security, pair) || record.Route.Kind != "send" ||
		record.Route.MessageID != input.MessageID || record.Security.IdempotencyKey != input.IdempotencyKey ||
		record.Route.RequestID != "" || record.Route.ReplyTo != "" {
		return nil, ErrRelayIdempotencyConflict
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return record, nil
}

func sameGroupSealedV1Security(messageID, idempotencyKey, dataScope string,
	pair sameGroupEndpointPair) RelayMessageSecurity {
	return RelayMessageSecurity{
		MessageID: messageID, IdempotencyKey: idempotencyKey,
		SenderEndpointID: pair.sender.EndpointID, SenderPrincipalID: pair.sender.PrincipalID,
		SenderGroupID: pair.groupID, SenderBindingID: pair.sender.BindingID,
		SenderBindingEpoch: pair.sender.BindingEpoch,
		ReceiverEndpointID: pair.receiver.EndpointID, ReceiverPrincipalID: pair.receiver.PrincipalID,
		ReceiverGroupID: pair.groupID, ReceiverBindingID: pair.receiver.BindingID,
		ReceiverBindingEpoch: pair.receiver.BindingEpoch,
		VisibilityPolicyRef:  dataScope,
		AuthorizationRef:     sameGroupSealedV1AuthorizationRef(pair.groupID),
	}
}

// EnqueueSameGroupSealedV1Ask atomically stores the opaque REQUEST and its
// durable correlation row after verifying both current grants and the source
// Node credential. Its expiry cannot outlive either owner's Group grant.
func (s *Store) EnqueueSameGroupSealedV1Ask(input SameGroupSealedV1Ask) (*FabricRequest, error) {
	if !validSameGroupSealedV1Input(input.NodeCredentialDigest, input.GroupID,
		input.SourceEndpointID, input.TargetEndpointID, input.MessageID,
		input.IdempotencyKey, input.DataScope, input.Ciphertext) ||
		!validSameGroupSealedV1Token(input.RequestID) || input.RequestID == input.MessageID {
		return nil, ErrSameGroupSealedV1Denied
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(input.ExpiresAt))
	if err != nil || expiresAt.UTC().Format(time.RFC3339Nano) != input.ExpiresAt {
		return nil, ErrSameGroupSealedV1Denied
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
	if !expiresAt.After(nowTime) || expiresAt.After(nowTime.Add(MaxRelayAskLifetime)) {
		return nil, ErrSameGroupSealedV1Denied
	}
	pair, err := readSameGroupSealedV1PairTx(tx, input.GroupID,
		input.SourceEndpointID, input.TargetEndpointID, nowTime)
	if err != nil || requireSameGroupSealedV1SourceTx(tx, input.NodeCredentialDigest, pair) != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	if expiresAt.After(mustParseRFC3339Nano(pair.sender.Grant.Manifest.ExpiresAt)) ||
		expiresAt.After(mustParseRFC3339Nano(pair.receiver.Grant.Manifest.ExpiresAt)) {
		return nil, ErrSameGroupSealedV1Denied
	}
	context := sameGroupSealedV1Context(pair, input.MessageID, "REQUEST", input.RequestID, "", input.ParentRequestID)
	if err := validateOpaqueEndpointMessage(input.Ciphertext, context, pair.sender.Candidate.Public); err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	if previous, err := relayLoadRequestTx(tx, input.RequestID); err != nil {
		return nil, err
	} else if previous != nil && previous.MessageID != input.MessageID {
		return nil, ErrRelayIdempotencyConflict
	} else if previous != nil && previous.ParentRequestID != input.ParentRequestID {
		return nil, ErrRelayIdempotencyConflict
	}
	security := sameGroupSealedV1Security(input.MessageID, input.IdempotencyKey,
		input.DataScope, pair)
	inputRelay, err := relaySealedV1Message(RelaySealedV1Input{
		Route: RelaySealedV1Route{MessageID: input.MessageID, RequestID: input.RequestID,
			SenderEndpointID: pair.sender.EndpointID, ReceiverEndpointID: pair.receiver.EndpointID, Kind: "ask"},
		Security: security, Ciphertext: input.Ciphertext, IdempotencyKey: input.IdempotencyKey,
	})
	if err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	inputRelay.sealedAskAuthorized = true
	accepted, reused, err := relayEnqueuePayloadTx(tx, inputRelay, RelayPayloadModeSealedV1, input.Ciphertext)
	if err != nil {
		return nil, err
	}
	if accepted == nil {
		return nil, ErrRelayMessageNotFound
	}
	record, err := relaySealedV1RecordTx(tx, accepted.Message.ID)
	if err != nil || !bytes.Equal(record.Ciphertext, input.Ciphertext) ||
		!sameGroupSealedV1SecurityMatchesPair(record.Security, pair) ||
		record.Route.Kind != "ask" || record.Route.MessageID != input.MessageID ||
		record.Security.IdempotencyKey != input.IdempotencyKey || record.Route.RequestID != input.RequestID {
		return nil, ErrRelayIdempotencyConflict
	}
	if reused {
		previous, err := relayLoadRequestByMessageTx(tx, accepted.Message.ID)
		if err != nil {
			return nil, err
		}
		if previous == nil || previous.RequestID != input.RequestID ||
			previous.ParentRequestID != input.ParentRequestID ||
			previous.ExpiresAt != expiresAt.Format(time.RFC3339Nano) {
			return nil, ErrRelayIdempotencyConflict
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return previous, nil
	}
	limits, err := scanRelayAdmissionLimits(tx.QueryRow(`SELECT per_sender_principal,
per_sender_group, per_receiver, global_limit, retry_after_seconds
FROM relay_v2_admission_config WHERE id=1`))
	if err != nil {
		return nil, err
	}
	if err := relayCheckPendingAskQuotaTx(tx, accepted.Security, limits,
		nowTime.Format(time.RFC3339Nano)); err != nil {
		return nil, err
	}
	request, err := createSameGroupSealedV1RequestTx(tx, input, pair, accepted.Security.Digest,
		expiresAt.Format(time.RFC3339Nano), nowTime.Format(time.RFC3339Nano))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}

func createSameGroupSealedV1RequestTx(tx *sql.Tx, input SameGroupSealedV1Ask,
	pair sameGroupEndpointPair, digest, expiresAt, timestamp string) (*FabricRequest, error) {
	request := FabricRequest{
		RequestID: input.RequestID, MessageID: input.MessageID,
		ParentRequestID:  input.ParentRequestID,
		SenderEndpointID: pair.sender.EndpointID, SenderPrincipalID: pair.sender.PrincipalID,
		SenderGroupID: pair.groupID, SenderBindingID: pair.sender.BindingID,
		SenderBindingEpoch: pair.sender.BindingEpoch,
		ReceiverEndpointID: pair.receiver.EndpointID, ReceiverPrincipalID: pair.receiver.PrincipalID,
		ReceiverGroupID: pair.groupID, ReceiverBindingID: pair.receiver.BindingID,
		ReceiverBindingEpoch: pair.receiver.BindingEpoch,
		Digest:               digest, IdempotencyKey: input.IdempotencyKey,
		VisibilityPolicyRef: input.DataScope,
		AuthorizationRef:    sameGroupSealedV1AuthorizationRef(pair.groupID),
		State:               FabricRequestOpen, ExpiresAt: expiresAt,
		CreatedAt: timestamp, UpdatedAt: timestamp,
	}
	if err := relayDeriveCausalLineageTx(tx, &request, mustParseRFC3339Nano(timestamp)); err != nil {
		return nil, err
	}
	_, err := tx.Exec(`INSERT INTO relay_v2_requests
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
		request.AuthorizationRef, request.State, request.ExpiresAt, request.CreatedAt,
		request.UpdatedAt, request.ParentRequestID, request.CausalRootRequestID,
		request.CausalDepth)
	if err != nil {
		return nil, err
	}
	if err := relayInsertEventTx(tx, request.RequestID, "REQUEST_CREATED", "",
		FabricRequestOpen, request.MessageID, "", timestamp); err != nil {
		return nil, err
	}
	return &request, nil
}

func reverseSameGroupSealedV1Pair(pair sameGroupEndpointPair) sameGroupEndpointPair {
	return sameGroupEndpointPair{hubID: pair.hubID, groupID: pair.groupID,
		sender: pair.receiver, receiver: pair.sender}
}

func validateSameGroupSealedV1ReplyEnvelope(ciphertext []byte, messageID string,
	request *FabricRequest, ask *RelaySealedV1Record,
	pair sameGroupEndpointPair) error {
	if request == nil || ask == nil || request.VisibilityPolicyRef != SameGroupSealedV1DataScope {
		return ErrSameGroupSealedV1Denied
	}
	reverse := reverseSameGroupSealedV1Pair(pair)
	context := sameGroupSealedV1Context(reverse, messageID, "REPLY",
		request.RequestID, request.MessageID, request.ParentRequestID)
	if err := validateOpaqueEndpointMessage(ciphertext, context, reverse.sender.Candidate.Public); err != nil {
		return ErrSameGroupSealedV1Denied
	}
	return nil
}

// EnqueueSameGroupSealedV1Reply derives the reverse route from the original
// durable ASK and requires the current Node credential of its responder.
func (s *Store) EnqueueSameGroupSealedV1Reply(input SameGroupSealedV1Reply) (*FabricRequest, error) {
	if !validNodeCredentialDigest(input.NodeCredentialDigest) ||
		!validSameGroupSealedV1Token(input.RequestID) ||
		!validSameGroupSealedV1Token(input.MessageID) || input.MessageID == input.RequestID ||
		(input.IdempotencyKey != "" && !validSameGroupSealedV1Token(input.IdempotencyKey)) ||
		len(input.Ciphertext) == 0 || len(input.Ciphertext) > communicationLinkMaxSealedSendWire {
		return nil, ErrSameGroupSealedV1Denied
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
	request, ask, pair, err := sameGroupSealedV1AskForReplyTx(tx, input.RequestID, nowTime)
	if err != nil || request == nil || ask == nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	nodeID, ownerID, hubID, err := readActiveOwnerBoundNodeTx(tx, input.NodeCredentialDigest)
	if err != nil || nodeID != pair.receiver.NodeID || ownerID != pair.receiver.OwnerID || hubID != pair.hubID {
		return nil, ErrSameGroupSealedV1Denied
	}
	if (request.State == FabricRequestOpen || request.State == FabricRequestCancelRequested) &&
		relayParseExpired(request.ExpiresAt, nowTime) {
		if err := relayExpireRequestTx(tx, request.RequestID, "request deadline reached",
			nowTime.Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
		request, err = relayLoadRequestTx(tx, input.RequestID)
		if err != nil || request == nil {
			return nil, ErrSameGroupSealedV1Denied
		}
	}
	if err := validateSameGroupSealedV1ReplyEnvelope(input.Ciphertext,
		input.MessageID, request, ask, pair); err != nil {
		return nil, err
	}

	terminalMessageID := ""
	switch request.State {
	case FabricRequestReplied:
		terminalMessageID = request.ReplyMessageID
	case FabricRequestLateResult:
		terminalMessageID = request.LateResultMessageID
	case FabricRequestOpen, FabricRequestCancelRequested, FabricRequestCancelled, FabricRequestExpired:
		// A terminal request may retain one encrypted late result.
	default:
		return nil, ErrRelayRequestTerminal
	}
	if terminalMessageID != "" {
		previous, err := relaySealedV1RecordTx(tx, terminalMessageID)
		if err != nil || previous == nil || input.MessageID != terminalMessageID {
			return nil, ErrRelayRequestTerminal
		}
		if input.IdempotencyKey != "" && input.IdempotencyKey != previous.Security.IdempotencyKey {
			return nil, ErrRelayIdempotencyConflict
		}
		reverse := reverseSameGroupSealedV1Pair(pair)
		if previous.Route.Kind != "reply" || previous.Route.RequestID != request.RequestID ||
			previous.Route.ReplyTo != request.MessageID ||
			!sameGroupSealedV1SecurityMatchesPair(previous.Security, reverse) ||
			!bytes.Equal(previous.Ciphertext, input.Ciphertext) {
			return nil, ErrRelayIdempotencyConflict
		}
		if err := validateSameGroupSealedV1ReplyEnvelope(previous.Ciphertext,
			previous.Route.MessageID, request, ask, pair); err != nil {
			return nil, ErrSameGroupSealedV1Denied
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
	idempotencyKey := input.IdempotencyKey
	if idempotencyKey == "" {
		idempotencyKey = sealedReplyIdempotencyKey(request.RequestID)
	}
	reverse := reverseSameGroupSealedV1Pair(pair)
	security := sameGroupSealedV1Security(input.MessageID, idempotencyKey,
		SameGroupSealedV1DataScope, reverse)
	inputRelay, err := relaySealedV1Message(RelaySealedV1Input{
		Route: RelaySealedV1Route{MessageID: input.MessageID, RequestID: request.RequestID,
			ReplyTo: request.MessageID, SenderEndpointID: reverse.sender.EndpointID,
			ReceiverEndpointID: reverse.receiver.EndpointID, Kind: "reply"},
		Security: security, Ciphertext: input.Ciphertext, IdempotencyKey: idempotencyKey,
	})
	if err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	inputRelay.sealedReplyAuthorized = true
	accepted, reused, err := relayEnqueuePayloadTx(tx, inputRelay,
		RelayPayloadModeSealedV1, input.Ciphertext)
	if err != nil {
		return nil, err
	}
	if accepted == nil || reused {
		return nil, ErrRelayMessageConflict
	}
	record, err := relaySealedV1RecordTx(tx, accepted.Message.ID)
	if err != nil || !bytes.Equal(record.Ciphertext, input.Ciphertext) ||
		record.Route.Kind != "reply" || record.Route.RequestID != request.RequestID ||
		record.Route.MessageID != input.MessageID || record.Security.IdempotencyKey != idempotencyKey ||
		record.Route.ReplyTo != request.MessageID ||
		!sameGroupSealedV1SecurityMatchesPair(record.Security, reverse) {
		return nil, ErrRelayMessageConflict
	}
	late := request.State != FabricRequestOpen
	timestamp := nowTime.Format(time.RFC3339Nano)
	if late {
		updated, err := tx.Exec(`UPDATE relay_v2_requests SET state=?,late_result_at=?,
late_result_message_id=?,updated_at=? WHERE request_id=? AND state IN (?,?,?,?)`,
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
			FabricRequestLateResult, accepted.Message.ID,
			"sealed reply arrived after deadline or cancellation", timestamp); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state=?,updated_at=?
WHERE message_id=? AND state=?`, RelayInboxExpired, timestamp,
			accepted.Message.ID, RelayInboxReady); err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`UPDATE relay_v2_outbox SET state=?,error=?,updated_at=? WHERE message_id=?`,
			RelayInboxExpired, "late result retained for request lifecycle review", timestamp,
			accepted.Message.ID); err != nil {
			return nil, err
		}
	} else {
		updated, err := tx.Exec(`UPDATE relay_v2_requests SET state=?,replied_at=?,
reply_message_id=?,updated_at=? WHERE request_id=? AND state=?`,
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

func validateQueuedSameGroupSealedV1Tx(tx *sql.Tx, record *RelaySealedV1Record,
	at time.Time) (sameGroupEndpointPair, *FabricRequest, error) {
	if record == nil || record.PayloadMode != RelayPayloadModeSealedV1 ||
		record.Route.MessageID != record.Security.MessageID ||
		record.Security.Digest != relayCiphertextDigest(record.Ciphertext) ||
		record.Route.SenderEndpointID != record.Security.SenderEndpointID ||
		record.Route.ReceiverEndpointID != record.Security.ReceiverEndpointID {
		return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
	}
	// This specialized claim path does not pass through generic Relay claim.
	// Recheck the persisted route and its enrollment-time fence here so a
	// revoked member cannot revive a queued message by joining again.
	if err := networkGuardRelayMessageTx(tx, record.Route.MessageID, record.Security.ReceiverGroupID, at); err != nil {
		return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
	}
	switch record.Route.Kind {
	case "send":
		if record.Route.RequestID != "" || record.Route.ReplyTo != "" {
			return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
		}
		pair, err := sameGroupSealedV1PairForRecordTx(tx, record, at)
		if err != nil {
			return sameGroupEndpointPair{}, nil, err
		}
		context := sameGroupSealedV1Context(pair, record.Route.MessageID, "SEND", "", "")
		if err := validateOpaqueEndpointMessage(record.Ciphertext, context, pair.sender.Candidate.Public); err != nil {
			return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
		}
		return pair, nil, nil
	case "ask":
		if record.Route.RequestID == "" || record.Route.ReplyTo != "" {
			return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
		}
		request, ask, pair, err := sameGroupSealedV1AskForReplyTx(tx, record.Route.RequestID, at)
		if err != nil || request.MessageID != record.Route.MessageID ||
			request.State != FabricRequestOpen || relayParseExpired(request.ExpiresAt, at) ||
			ask.Security.Digest != record.Security.Digest || !bytes.Equal(ask.Ciphertext, record.Ciphertext) {
			if err != nil {
				return sameGroupEndpointPair{}, nil, err
			}
			return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
		}
		return pair, request, nil
	case "reply":
		if record.Route.RequestID == "" || record.Route.ReplyTo == "" {
			return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
		}
		request, ask, pair, err := sameGroupSealedV1AskForReplyTx(tx, record.Route.RequestID, at)
		if err != nil || request.MessageID != record.Route.ReplyTo ||
			request.State != FabricRequestReplied || request.ReplyMessageID != record.Route.MessageID {
			if err != nil {
				return sameGroupEndpointPair{}, nil, err
			}
			return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
		}
		reverse := reverseSameGroupSealedV1Pair(pair)
		if !sameGroupSealedV1SecurityMatchesPair(record.Security, reverse) {
			return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
		}
		if err := validateSameGroupSealedV1ReplyEnvelope(record.Ciphertext,
			record.Route.MessageID, request, ask, pair); err != nil {
			return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
		}
		return reverse, request, nil
	default:
		return sameGroupEndpointPair{}, nil, ErrSameGroupSealedV1Denied
	}
}

func failQueuedSameGroupSealedV1Tx(tx *sql.Tx, item *RelayInboxItem,
	record *RelaySealedV1Record, at time.Time, reason string) error {
	if item == nil {
		return ErrRelayMessageNotFound
	}
	timestamp := at.UTC().Format(time.RFC3339Nano)
	if record != nil && record.Route.Kind == "ask" && record.Route.RequestID != "" {
		request, err := relayLoadRequestTx(tx, record.Route.RequestID)
		if err != nil {
			return err
		}
		if request != nil && (request.State == FabricRequestOpen || request.State == FabricRequestCancelRequested) {
			if relayParseExpired(request.ExpiresAt, at) {
				if err := relayExpireRequestTx(tx, request.RequestID, "request deadline reached", timestamp); err != nil {
					return err
				}
			} else if _, err := relayMarkRequestCancellationTx(tx, request.RequestID,
				FabricRequestCancelled, "REQUEST_AUTHORIZATION_REVOKED", reason, timestamp); err != nil {
				return err
			}
		}
	}
	if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state=?,updated_at=?
WHERE recipient_endpoint_id=? AND sequence=? AND message_id=? AND state IN (?,?)`,
		RelayInboxFailed, timestamp, item.RecipientEndpointID, item.Sequence,
		item.MessageID, RelayInboxReady, RelayInboxClaimed); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE relay_v2_outbox SET state=?,error=?,updated_at=? WHERE message_id=?`,
		RelayInboxFailed, reason, timestamp, item.MessageID); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT OR IGNORE INTO relay_v2_receipts
(receipt_id,attempt_id,message_id,digest,target_endpoint_id,binding_id,binding_epoch,layer,error,created_at)
VALUES (?, '', ?, ?, ?, ?, ?, ?, ?, ?)`, NewID("rcpt"), item.MessageID,
		item.Digest, item.RecipientEndpointID, item.BindingID, item.BindingEpoch,
		RelayReceiptFailed, reason, timestamp)
	return err
}

// sweepSealedTaskHandoffInboxTx expires reserved handoff routes independently
// of metadata registration. Their deadline is carried in the signed message
// ID/AAD, so a SEND whose metadata transaction never commits cannot occupy a
// receiver inbox forever.
func sweepSealedTaskHandoffInboxTx(tx *sql.Tx, endpointID string, at time.Time, limit int) error {
	rows, err := tx.Query(`SELECT `+relayInboxColumns+` FROM relay_v2_inbox i
JOIN fabric_messages f ON f.id=i.message_id
WHERE i.recipient_endpoint_id=? AND i.state=? AND i.message_id LIKE ?
ORDER BY i.sequence LIMIT ?`, endpointID, RelayInboxReady, sealedTaskHandoffMessagePrefix+"%", limit)
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
		if item != nil {
			items = append(items, item)
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, item := range items {
		if !sealedTaskHandoffMessageIDExpired(item.MessageID, at) {
			continue
		}
		if handoff, err := loadSealedTaskHandoffByMessageTx(tx, item.MessageID); err == nil &&
			handoff.Status == SealedTaskHandoffProposed {
			if err := markSealedTaskHandoffTerminalTx(tx, handoff, SealedTaskHandoffExpired,
				"handoff route deadline elapsed before delivery", at.UTC().Format(time.RFC3339Nano)); err != nil {
				return err
			}
		}
		record, err := relaySealedV1RecordTx(tx, item.MessageID)
		if err != nil {
			return err
		}
		if err := failQueuedSameGroupSealedV1Tx(tx, item, record, at,
			"sealed task handoff route deadline elapsed"); err != nil {
			return err
		}
	}
	return nil
}

func failClaimedSameGroupSealedV1Tx(tx *sql.Tx, item *RelayInboxItem,
	attempt *RelayDeliveryAttempt, at time.Time, reason string) error {
	if item == nil || attempt == nil {
		return ErrRelayDeliveryNotFound
	}
	timestamp := at.UTC().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`UPDATE relay_v2_delivery_attempts SET state=?,failure=?,completed_at=?
WHERE attempt_id=? AND state=?`, RelayAttemptFailed, reason, timestamp,
		attempt.AttemptID, RelayAttemptClaimed); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE relay_v2_inbox SET state=?,updated_at=?
WHERE recipient_endpoint_id=? AND sequence=? AND message_id=? AND attempt_id=? AND state=?`,
		RelayInboxFailed, timestamp, item.RecipientEndpointID, item.Sequence,
		item.MessageID, attempt.AttemptID, RelayInboxClaimed); err != nil {
		return err
	}
	_, err := tx.Exec(`INSERT OR IGNORE INTO relay_v2_receipts
(receipt_id,attempt_id,message_id,digest,target_endpoint_id,binding_id,binding_epoch,layer,error,created_at)
VALUES (?,?,?,?,?,?,?,?,?,?)`, NewID("rcpt"), attempt.AttemptID, item.MessageID,
		item.Digest, item.RecipientEndpointID, item.BindingID, item.BindingEpoch,
		RelayReceiptFailed, reason, timestamp)
	return err
}

func readSameGroupSealedV1ClaimNodeTx(tx *sql.Tx, credentialDigest string,
	input RelayClaimInput, at time.Time) (bool, error) {
	nodeID, ownerID, _, err := readActiveOwnerBoundNodeTx(tx, credentialDigest)
	if err != nil {
		return false, ErrSameGroupSealedV1Denied
	}
	var endpointNodeID, endpointOwnerID, bindingID, bindingStatus, leaseExpiresAt string
	var bindingEpoch uint64
	err = tx.QueryRow(`SELECT e.machine_id,p.owner_id,COALESCE(b.id,''),COALESCE(b.epoch,0),
COALESCE(b.status,''),COALESCE(b.lease_expires_at,'')
FROM fabric_endpoints e JOIN principals p ON p.id=e.principal_id
LEFT JOIN session_bindings b ON b.id=e.binding_id AND b.endpoint_id=e.id
WHERE e.id=?`, input.RecipientEndpointID).Scan(&endpointNodeID, &endpointOwnerID,
		&bindingID, &bindingEpoch, &bindingStatus, &leaseExpiresAt)
	if errors.Is(err, sql.ErrNoRows) || endpointNodeID != nodeID || endpointOwnerID != ownerID {
		return false, ErrSameGroupSealedV1Denied
	}
	if err != nil {
		return false, err
	}
	deadline, deadlineErr := time.Parse(time.RFC3339Nano, leaseExpiresAt)
	active := bindingID != "" && bindingEpoch != 0 && bindingStatus == SessionBindingStatusLeased &&
		deadlineErr == nil && deadline.After(at)
	if active && (input.BindingID != bindingID || input.BindingEpoch != bindingEpoch) {
		return false, ErrRelayBindingMismatch
	}
	return active, nil
}

// ClaimSameGroupSealedV1Inbox is the only claim path for these rows. It checks
// the authenticated receiver and current bilateral grants in the same write
// transaction that creates each delivery attempt. Stale rows become terminal
// so a revoked request cannot block later messages.
func (s *Store) ClaimSameGroupSealedV1Inbox(credentialDigest string,
	input RelayClaimInput) ([]RelaySealedV1DeliveryAttempt, error) {
	input.RecipientEndpointID = relayString(input.RecipientEndpointID)
	input.ConsumerID = relayString(input.ConsumerID)
	input.BindingID = relayString(input.BindingID)
	if !validNodeCredentialDigest(credentialDigest) || input.RecipientEndpointID == "" ||
		input.ConsumerID == "" || input.BindingID == "" || input.BindingEpoch == 0 {
		return nil, ErrSameGroupSealedV1Denied
	}
	input.Limit = normalizeRelayLimit(input.Limit)
	if input.Cursor != "" {
		cursor, err := relayDecodeCursor(input.Cursor)
		if err != nil || cursor.RecipientEndpointID != input.RecipientEndpointID ||
			cursor.ConsumerID != input.ConsumerID || cursor.BindingID != input.BindingID {
			return nil, ErrRelayCursor
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	bindingCurrent, err := readSameGroupSealedV1ClaimNodeTx(tx, credentialDigest, input, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	nowTime := time.Now().UTC()
	if err := sweepSealedTaskHandoffInboxTx(tx, input.RecipientEndpointID, nowTime, input.Limit*8); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT `+relayInboxColumns+` FROM relay_v2_inbox i
JOIN fabric_messages f ON f.id=i.message_id
JOIN relay_v2_message_payloads payload ON payload.message_id=i.message_id
JOIN relay_v2_message_security security ON security.message_id=i.message_id
WHERE i.recipient_endpoint_id=? AND i.state=? AND payload.payload_mode=?
  AND security.authorization_ref GLOB 'same-group-sealed.v2:*'
  AND (i.message_id NOT LIKE ? OR EXISTS (
    SELECT 1 FROM shared_task_sealed_handoffs_v2 handoff
    WHERE handoff.message_id=i.message_id AND handoff.status IN (?,?)))
ORDER BY i.sequence LIMIT ?`, input.RecipientEndpointID, RelayInboxReady,
		RelayPayloadModeSealedV1, sealedTaskHandoffMessagePrefix+"%",
		SealedTaskHandoffProposed, SealedTaskHandoffTransferred, input.Limit)
	if err != nil {
		return nil, err
	}
	items := make([]*RelayInboxItem, 0, input.Limit)
	for rows.Next() {
		item, err := scanRelayInboxItem(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		if item != nil {
			items = append(items, item)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !bindingCurrent {
		for _, item := range items {
			record, err := relaySealedV1RecordTx(tx, item.MessageID)
			if err != nil {
				return nil, err
			}
			if err := failQueuedSameGroupSealedV1Tx(tx, item, record, nowTime,
				"same-Group endpoint binding is no longer active"); err != nil {
				return nil, err
			}
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return []RelaySealedV1DeliveryAttempt{}, nil
	}
	result := make([]RelaySealedV1DeliveryAttempt, 0, len(items))
	for _, item := range items {
		if item.BindingID != input.BindingID || item.BindingEpoch != input.BindingEpoch {
			record, err := relaySealedV1RecordTx(tx, item.MessageID)
			if err != nil {
				return nil, err
			}
			if err := failQueuedSameGroupSealedV1Tx(tx, item, record, nowTime,
				"same-Group delivery binding is no longer current"); err != nil {
				return nil, err
			}
			continue
		}
		record, err := relaySealedV1RecordTx(tx, item.MessageID)
		if err != nil {
			return nil, err
		}
		pair, request, authErr := validateQueuedSameGroupSealedV1Tx(tx, record, nowTime)
		if authErr != nil {
			if !errors.Is(authErr, ErrSameGroupSealedV1Denied) {
				return nil, authErr
			}
			reason := "same-Group grant or route snapshot is no longer current"
			if err := failQueuedSameGroupSealedV1Tx(tx, item, record, nowTime, reason); err != nil {
				return nil, err
			}
			continue
		}
		if pair.receiver.EndpointID != input.RecipientEndpointID || pair.receiver.NodeID == "" {
			if err := failQueuedSameGroupSealedV1Tx(tx, item, record, nowTime,
				"same-Group route no longer targets this Endpoint"); err != nil {
				return nil, err
			}
			continue
		}
		if record.Route.RequestID != item.RequestID || (record.Route.Kind == "ask" && request == nil) {
			if err := failQueuedSameGroupSealedV1Tx(tx, item, record, nowTime,
				"same-Group request correlation is invalid"); err != nil {
				return nil, err
			}
			continue
		}
		if strings.HasPrefix(item.MessageID, sealedTaskHandoffMessagePrefix) {
			handoff, handoffErr := loadSealedTaskHandoffByMessageTx(tx, item.MessageID)
			if errors.Is(handoffErr, ErrSealedTaskHandoffPending) {
				// The prior Relay SEND may have woken this Node before the
				// metadata-only proposal committed. Leave it READY for the
				// post-commit coalesced wake or bounded reconciliation.
				continue
			}
			if handoffErr != nil {
				if err := failQueuedSameGroupSealedV1Tx(tx, item, record, nowTime,
					"reserved task handoff message metadata is invalid"); err != nil {
					return nil, err
				}
				continue
			}
			if handoff.ToEndpointID != input.RecipientEndpointID || handoff.MessageDigest != item.Digest ||
				record.Route.SenderEndpointID != handoff.FromEndpointID ||
				record.Route.ReceiverEndpointID != handoff.ToEndpointID || handoff.GroupID != pair.groupID {
				err = ErrSealedTaskHandoffConflict
			} else {
				err = sealedTaskHandoffTaskMatchesTx(tx, handoff, nowTime)
			}
			if err != nil {
				if handoff.Status == SealedTaskHandoffProposed {
					status := SealedTaskHandoffCancelled
					if errors.Is(err, ErrSealedTaskHandoffExpired) {
						status = SealedTaskHandoffExpired
					}
					if terminalErr := markSealedTaskHandoffTerminalTx(tx, handoff, status,
						sealedTaskHandoffFailureReason(err), nowTime.Format(time.RFC3339Nano)); terminalErr != nil {
						return nil, terminalErr
					}
				}
				if err := failQueuedSameGroupSealedV1Tx(tx, item, record, nowTime,
					sealedTaskHandoffFailureReason(err)); err != nil {
					return nil, err
				}
				continue
			}
		}
		attemptID := NewID("attempt")
		timestamp := nowTime.Format(time.RFC3339Nano)
		updated, err := tx.Exec(`UPDATE relay_v2_inbox SET state=?,attempt_id=?,updated_at=?
WHERE recipient_endpoint_id=? AND sequence=? AND state=?`, RelayInboxClaimed,
			attemptID, timestamp, item.RecipientEndpointID, item.Sequence, RelayInboxReady)
		if err != nil {
			return nil, err
		}
		changed, err := updated.RowsAffected()
		if err != nil {
			return nil, err
		}
		if changed == 0 {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO relay_v2_delivery_attempts
(attempt_id,message_id,request_id,recipient_endpoint_id,sequence,digest,binding_id,
 binding_epoch,consumer_id,state,failure,claimed_at,completed_at,created_at)
VALUES (?,?,?,?,?,?,?,?,?,?, '', ?, '', ?)`, attemptID, item.MessageID,
			item.RequestID, item.RecipientEndpointID, item.Sequence, item.Digest,
			item.BindingID, item.BindingEpoch, input.ConsumerID, RelayAttemptClaimed,
			timestamp, timestamp); err != nil {
			return nil, err
		}
		result = append(result, RelaySealedV1DeliveryAttempt{
			AttemptID: attemptID, MessageID: item.MessageID, RequestID: item.RequestID,
			Digest: item.Digest, RecipientEndpointID: item.RecipientEndpointID,
			ReceiverGroupID: item.ReceiverGroupID, BindingID: item.BindingID,
			BindingEpoch: item.BindingEpoch, Sequence: item.Sequence,
			ConsumerID: input.ConsumerID, State: RelayAttemptClaimed,
			ClaimedAt: timestamp, CreatedAt: timestamp, PayloadMode: RelayPayloadModeSealedV1,
			Route: record.Route, Security: record.Security, Ciphertext: record.Ciphertext,
		})
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// AuthorizeClaimedSameGroupSealedV1Delivery rechecks the live Node credential,
// exact attempt, receipt state, Group grants, candidate keys and binding just
// before Node decryption or native-session injection.
func (s *Store) AuthorizeClaimedSameGroupSealedV1Delivery(credentialDigest,
	messageID, attemptID string) (*SameGroupSealedV1DeliveryAuthorization, error) {
	if !validNodeCredentialDigest(credentialDigest) || !validSameGroupSealedV1Token(messageID) ||
		!validSameGroupSealedV1Token(attemptID) {
		return nil, ErrSameGroupSealedV1Denied
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
		return nil, ErrSameGroupSealedV1Denied
	}
	attempt, err := relayGetAttemptTx(tx, attemptID)
	if err != nil || attempt == nil || attempt.MessageID != messageID ||
		attempt.State != RelayAttemptClaimed || attempt.BindingID == "" || attempt.BindingEpoch == 0 {
		return nil, ErrSameGroupSealedV1Denied
	}
	item, err := scanRelayInboxItem(tx.QueryRow(`SELECT `+relayInboxColumns+` FROM relay_v2_inbox i
JOIN fabric_messages f ON f.id=i.message_id
WHERE i.message_id=? AND i.recipient_endpoint_id=?`, messageID, attempt.RecipientEndpointID))
	if err != nil || item == nil || item.AttemptID != attemptID || item.State != RelayInboxClaimed ||
		item.BindingID != attempt.BindingID || item.BindingEpoch != attempt.BindingEpoch ||
		item.Sequence != attempt.Sequence || item.Digest != attempt.Digest {
		return nil, ErrSameGroupSealedV1Denied
	}
	var currentEndpointNodeID, currentEndpointOwnerID string
	err = tx.QueryRow(`SELECT e.machine_id,p.owner_id FROM fabric_endpoints e
JOIN principals p ON p.id=e.principal_id WHERE e.id=?`, item.RecipientEndpointID).
		Scan(&currentEndpointNodeID, &currentEndpointOwnerID)
	if errors.Is(err, sql.ErrNoRows) || currentEndpointNodeID != nodeID || currentEndpointOwnerID != ownerID {
		return nil, ErrSameGroupSealedV1Denied
	}
	if err != nil {
		return nil, err
	}
	var laterReceipt int
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM relay_v2_receipts
WHERE attempt_id=? AND layer NOT IN (?,?))`, attemptID,
		RelayReceiptAccepted, RelayReceiptNodeReceived).Scan(&laterReceipt); err != nil {
		return nil, err
	}
	if laterReceipt != 0 {
		return nil, ErrSameGroupSealedV1Denied
	}
	record, err := relaySealedV1RecordTx(tx, messageID)
	if err != nil || record.Route.RequestID != item.RequestID ||
		record.Route.ReceiverEndpointID != item.RecipientEndpointID || record.Security.Digest != item.Digest {
		return nil, ErrSameGroupSealedV1Denied
	}
	pair, _, authErr := validateQueuedSameGroupSealedV1Tx(tx, record, time.Now().UTC())
	if authErr != nil || pair.receiver.EndpointID != item.RecipientEndpointID ||
		pair.receiver.NodeID != nodeID || pair.receiver.OwnerID != ownerID ||
		pair.receiver.BindingID != item.BindingID || pair.receiver.BindingEpoch != item.BindingEpoch {
		if authErr != nil && !errors.Is(authErr, ErrSameGroupSealedV1Denied) {
			return nil, authErr
		}
		if authErr == nil || errors.Is(authErr, ErrSameGroupSealedV1Denied) {
			if err := failClaimedSameGroupSealedV1Tx(tx, item, attempt,
				time.Now().UTC(), "same-Group grant or binding was revoked before injection"); err != nil {
				return nil, err
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
		}
		return nil, ErrSameGroupSealedV1Denied
	}
	var taskHandoff *SealedTaskHandoffDeliveryAuthorization
	if strings.HasPrefix(messageID, sealedTaskHandoffMessagePrefix) {
		handoff, handoffErr := loadSealedTaskHandoffByMessageTx(tx, messageID)
		if handoffErr == nil && (handoff.ToEndpointID != item.RecipientEndpointID ||
			handoff.MessageDigest != item.Digest || handoff.GroupID != pair.groupID ||
			record.Route.Kind != "send" || record.Route.SenderEndpointID != handoff.FromEndpointID ||
			record.Route.ReceiverEndpointID != handoff.ToEndpointID) {
			handoffErr = ErrSealedTaskHandoffConflict
		}
		if handoffErr == nil {
			handoffErr = sealedTaskHandoffTaskMatchesTx(tx, handoff, time.Now().UTC())
		}
		if handoffErr != nil {
			if handoff != nil && handoff.Status == SealedTaskHandoffProposed {
				status := SealedTaskHandoffCancelled
				if errors.Is(handoffErr, ErrSealedTaskHandoffExpired) {
					status = SealedTaskHandoffExpired
				}
				if err := markSealedTaskHandoffTerminalTx(tx, handoff, status,
					sealedTaskHandoffFailureReason(handoffErr), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
					return nil, err
				}
			}
			if err := failClaimedSameGroupSealedV1Tx(tx, item, attempt,
				time.Now().UTC(), sealedTaskHandoffFailureReason(handoffErr)); err != nil {
				return nil, err
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return nil, ErrSameGroupSealedV1Denied
		}
		taskHandoff = sealedTaskHandoffDeliveryAuthorization(handoff)
	}
	parentRequestID, err := relayParentRequestForSealedRouteTx(tx, record.Route)
	if err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	scope, err := readNativeContextScopeForEndpointTx(tx, item.RecipientEndpointID,
		record.Security.ReceiverGroupID)
	if err != nil {
		return nil, ErrSameGroupSealedV1Denied
	}
	result := &SameGroupSealedV1DeliveryAuthorization{
		AttemptID: attemptID, MessageID: messageID, Digest: item.Digest,
		EndpointID: item.RecipientEndpointID, NodeID: pair.receiver.NodeID,
		OwnerID: pair.receiver.OwnerID, BindingID: pair.receiver.BindingID,
		BindingEpoch:    pair.receiver.BindingEpoch,
		NativeSessionID: pair.receiver.NativeSessionID,
		DataScope:       record.Security.VisibilityPolicyRef, Route: record.Route,
		ParentRequestID: parentRequestID, NativeContextScope: scope,
		Sender: pair.sender, Receiver: pair.receiver, TaskHandoff: taskHandoff,
	}
	// A receiver Node needs its own injection target, never the peer's local
	// Session ID.
	result.Sender.NativeSessionID = ""
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

func readSameGroupSealedV1HistoricalNodeTx(tx *sql.Tx, endpointID, principalID,
	bindingID string, bindingEpoch uint64) (nodeID, ownerID string, err error) {
	err = tx.QueryRow(`SELECT b.node_id,p.owner_id FROM session_bindings b
JOIN principals p ON p.id=b.principal_id
WHERE b.id=? AND b.endpoint_id=? AND b.principal_id=? AND b.epoch=?`,
		bindingID, endpointID, principalID, bindingEpoch).Scan(&nodeID, &ownerID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrSameGroupSealedV1NotFound
	}
	return
}

func authorizeSameGroupSealedV1RequestTx(tx *sql.Tx, credentialDigest,
	requestID string, senderOnly bool) (*FabricRequest, error) {
	nodeID, ownerID, _, err := readActiveOwnerBoundNodeTx(tx, credentialDigest)
	if err != nil {
		return nil, ErrSameGroupSealedV1NotFound
	}
	request, err := relayLoadRequestTx(tx, requestID)
	if err != nil || request == nil {
		return nil, ErrSameGroupSealedV1NotFound
	}
	groupID, ok := strings.CutPrefix(request.AuthorizationRef,
		sameGroupSealedV1AuthorizationPrefix)
	if !ok || !validSameGroupSealedV1Token(groupID) ||
		request.SenderGroupID != groupID || request.ReceiverGroupID != groupID ||
		request.VisibilityPolicyRef != SameGroupSealedV1DataScope {
		return nil, ErrSameGroupSealedV1NotFound
	}
	ask, err := relaySealedV1RecordTx(tx, request.MessageID)
	if err != nil || ask == nil || ask.Route.Kind != "ask" ||
		!sealedRequestMatchesStoredSameGroupAsk(request, ask, groupID) {
		return nil, ErrSameGroupSealedV1NotFound
	}
	senderNodeID, senderOwnerID, err := readSameGroupSealedV1HistoricalNodeTx(tx,
		request.SenderEndpointID, request.SenderPrincipalID,
		request.SenderBindingID, request.SenderBindingEpoch)
	if err != nil {
		return nil, ErrSameGroupSealedV1NotFound
	}
	receiverNodeID, receiverOwnerID, err := readSameGroupSealedV1HistoricalNodeTx(tx,
		request.ReceiverEndpointID, request.ReceiverPrincipalID,
		request.ReceiverBindingID, request.ReceiverBindingEpoch)
	if err != nil || senderOwnerID == "" || senderOwnerID != receiverOwnerID ||
		senderNodeID == receiverNodeID {
		return nil, ErrSameGroupSealedV1NotFound
	}
	if senderOnly {
		if nodeID != senderNodeID || ownerID != senderOwnerID {
			return nil, ErrSameGroupSealedV1NotFound
		}
	} else if ownerID != senderOwnerID || (nodeID != senderNodeID && nodeID != receiverNodeID) {
		return nil, ErrSameGroupSealedV1NotFound
	}
	return request, nil
}

func sealedRequestMatchesStoredSameGroupAsk(request *FabricRequest,
	ask *RelaySealedV1Record, groupID string) bool {
	if request == nil || ask == nil || ask.PayloadMode != RelayPayloadModeSealedV1 ||
		ask.Route.Kind != "ask" || ask.Route.RequestID != request.RequestID ||
		ask.Route.MessageID != request.MessageID || ask.Route.ReplyTo != "" ||
		ask.Security.MessageID != request.MessageID ||
		ask.Security.Digest != relayCiphertextDigest(ask.Ciphertext) ||
		ask.Security.AuthorizationRef != sameGroupSealedV1AuthorizationRef(groupID) ||
		ask.Security.VisibilityPolicyRef != SameGroupSealedV1DataScope ||
		request.AuthorizationRef != ask.Security.AuthorizationRef ||
		request.VisibilityPolicyRef != ask.Security.VisibilityPolicyRef ||
		request.Digest != ask.Security.Digest || request.IdempotencyKey != ask.Security.IdempotencyKey {
		return false
	}
	security := ask.Security
	return security.SenderGroupID == groupID && security.ReceiverGroupID == groupID &&
		security.SenderEndpointID == request.SenderEndpointID &&
		security.SenderPrincipalID == request.SenderPrincipalID &&
		security.SenderBindingID == request.SenderBindingID &&
		security.SenderBindingEpoch == request.SenderBindingEpoch &&
		security.ReceiverEndpointID == request.ReceiverEndpointID &&
		security.ReceiverPrincipalID == request.ReceiverPrincipalID &&
		security.ReceiverBindingID == request.ReceiverBindingID &&
		security.ReceiverBindingEpoch == request.ReceiverBindingEpoch &&
		ask.Route.SenderEndpointID == request.SenderEndpointID &&
		ask.Route.ReceiverEndpointID == request.ReceiverEndpointID
}

// GetSameGroupSealedV1RequestStatus returns lifecycle metadata only to one of
// the two original endpoint Nodes. It remains available after Group revocation
// so a Node can learn the terminal outcome without regaining delivery rights.
func (s *Store) GetSameGroupSealedV1RequestStatus(credentialDigest,
	requestID string) (*FabricRequest, error) {
	if !validNodeCredentialDigest(credentialDigest) || !validSameGroupSealedV1Token(requestID) {
		return nil, ErrSameGroupSealedV1NotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	request, err := authorizeSameGroupSealedV1RequestTx(tx, credentialDigest, requestID, false)
	if err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	if (request.State == FabricRequestOpen || request.State == FabricRequestCancelRequested) &&
		relayParseExpired(request.ExpiresAt, at) {
		if err := relayExpireRequestTx(tx, requestID, "request deadline reached",
			at.Format(time.RFC3339Nano)); err != nil {
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

// CancelSameGroupSealedV1Request fences work which has not begun. A claimed
// attempt remains visible until its exact receipt resolves the delivery.
func (s *Store) CancelSameGroupSealedV1Request(credentialDigest,
	requestID string) (*FabricRequest, error) {
	if !validNodeCredentialDigest(credentialDigest) || !validSameGroupSealedV1Token(requestID) {
		return nil, ErrSameGroupSealedV1NotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	request, err := authorizeSameGroupSealedV1RequestTx(tx, credentialDigest, requestID, true)
	if err != nil {
		return nil, err
	}
	at := time.Now().UTC()
	if relayParseExpired(request.ExpiresAt, at) {
		if err := relayExpireRequestTx(tx, requestID, "request deadline reached",
			at.Format(time.RFC3339Nano)); err != nil {
			return nil, err
		}
		request, err = relayLoadRequestTx(tx, requestID)
		if err != nil {
			return nil, err
		}
	} else {
		request, err = relayMarkRequestCancellationTx(tx, requestID,
			FabricRequestCancelRequested, "REQUEST_CANCEL_REQUESTED",
			"sender requested cancellation", at.Format(time.RFC3339Nano))
		if err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return request, nil
}
