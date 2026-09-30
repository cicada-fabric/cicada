package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

const (
	groupSpaceLocalProtocolVersion = 1
	groupSpaceHTTPMaxBytes         = 4 << 20
	groupSpaceUnixMaxBytes         = 2 << 20
	groupSpaceCacheMaxBytes        = 4 << 20
)

type groupSpaceLocalRequest struct {
	localSealedSendRequest
	OperationID          string                      `json:"operation_id,omitempty"`
	RecordID             string                      `json:"record_id,omitempty"`
	TopicID              string                      `json:"topic_id,omitempty"`
	CorrectsID           string                      `json:"corrects_id,omitempty"`
	ExpectedTopicVersion int64                       `json:"expected_topic_version,omitempty"`
	Status               string                      `json:"status,omitempty"`
	Cursor               string                      `json:"cursor,omitempty"`
	Limit                int                         `json:"limit,omitempty"`
	RecipientEndpointID  string                      `json:"recipient_endpoint_id,omitempty"`
	OwnerKeyID           string                      `json:"owner_key_id,omitempty"`
	OwnerProof           string                      `json:"owner_proof,omitempty"`
	AfterSeq             int64                       `json:"after_seq,omitempty"`
	ThroughSeq           int64                       `json:"through_seq,omitempty"`
	RegroupInput         *store.RegroupProposalInput `json:"regroup_input,omitempty"`
	ProposalID           string                      `json:"proposal_id,omitempty"`
	DelegationID         string                      `json:"delegation_id,omitempty"`
}

type groupSpacePublicRecord struct {
	RecordID            string `json:"record_id"`
	GroupID             string `json:"group_id"`
	Sequence            int64  `json:"sequence"`
	Kind                string `json:"kind"`
	TopicID             string `json:"topic_id,omitempty"`
	CorrectsID          string `json:"corrects_id,omitempty"`
	Status              string `json:"status,omitempty"`
	TopicVersion        int64  `json:"topic_version,omitempty"`
	CurrentTopicVersion int64  `json:"current_topic_version,omitempty"`
	CurrentTopicStatus  string `json:"current_topic_status,omitempty"`
	ProducerEndpoint    string `json:"producer_endpoint_id"`
	CreatedAt           string `json:"created_at"`
	ExpiresAt           string `json:"expires_at"`
	Body                string `json:"body"`
}

type groupSpaceLocalResult struct {
	Record          *groupSpacePublicRecord      `json:"record,omitempty"`
	Records         []groupSpacePublicRecord     `json:"records,omitempty"`
	NextCursor      string                       `json:"next_cursor,omitempty"`
	HistoryGrant    *e2ee.GroupSpaceHistoryGrant `json:"history_grant,omitempty"`
	Sync            *store.GroupSpaceSyncResult  `json:"sync,omitempty"`
	ReadState       *store.GroupSpaceReadState   `json:"read_state,omitempty"`
	RegroupProposal *store.RegroupProposal       `json:"regroup_proposal,omitempty"`
	RegroupApply    *store.RegroupApplyResult    `json:"regroup_apply,omitempty"`
}

func requestMachineAgentGroupSpace(socketPath string, request groupSpaceLocalRequest) (*groupSpaceLocalResult, error) {
	if strings.TrimSpace(socketPath) == "" {
		return nil, errLocalJoinBridgeUnavailable
	}
	conn, err := netDialLocalBridge(socketPath)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(35 * time.Second))
	request.Version = groupSpaceLocalProtocolVersion
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return nil, &localSealedSendError{message: "could not submit Group Space request to local Node", retryable: true}
	}
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := half.CloseWrite(); err != nil {
			return nil, &localSealedSendError{message: "could not finish Group Space request", retryable: true}
		}
	}
	dec := json.NewDecoder(io.LimitReader(conn, groupSpaceUnixMaxBytes))
	dec.DisallowUnknownFields()
	var response localJoinResponse
	if err := dec.Decode(&response); err != nil || response.Version != localJoinProtocolVersion {
		return nil, &localSealedSendError{message: "local Node returned invalid Group Space response", retryable: true}
	}
	if response.Error != "" {
		return nil, &localSealedSendError{message: response.Error, retryable: response.Retryable}
	}
	if response.GroupSpace == nil {
		return nil, errors.New("local Node omitted Group Space result")
	}
	return response.GroupSpace, nil
}

func (b *machineAgentJoinBridge) groupSpaceHTTP(sessionToken, route string, input any, output any) error {
	return b.groupSpaceHTTPWithContext(b.ctx, sessionToken, route, input, output)
}

func (b *machineAgentJoinBridge) groupSpaceHTTPWithContext(parent context.Context, sessionToken, route string, input any, output any) error {
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > groupSpaceHTTPMaxBytes {
		return errors.New("invalid bounded Group Space request")
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.baseURL+"/v2/fabric/node/spaces/"+route, bytes.NewReader(encoded))
	if err != nil {
		return errors.New("could not prepare Group Space request")
	}
	r.Header.Set("Authorization", "CicadaNode "+b.nodeToken)
	r.Header.Set("Cicada-Space-Session", "CicadaSession "+sessionToken)
	r.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 30 * time.Second, CheckRedirect: rejectNodeRedirect}).Do(r)
	if err != nil {
		return &localSealedSendError{message: "could not reach the authorized Hub Group Space", retryable: true}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, groupSpaceHTTPMaxBytes+1))
	if err != nil || len(data) > groupSpaceHTTPMaxBytes {
		return &localSealedSendError{message: "Hub returned oversized Group Space response", retryable: true}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &localSealedSendError{message: fmt.Sprintf("Group Space request failed with HTTP %d", response.StatusCode),
			retryable: response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500}
	}
	if err := decodeStrictBridgeJSON(data, output); err != nil {
		return errors.New("Hub returned invalid Group Space result")
	}
	return nil
}

func (b *machineAgentJoinBridge) verifyGroupSpaceSource(request groupSpaceLocalRequest) (store.GroupSpaceEndpointEvidence, error) {
	if request.Version != groupSpaceLocalProtocolVersion || request.SessionToken == "" ||
		request.GroupID == "" || request.EndpointID == "" || request.NodeID != b.nodeID ||
		request.BindingID == "" || request.BindingEpoch == 0 ||
		harness.Canonical(request.Harness) != "codex" {
		return store.GroupSpaceEndpointEvidence{}, errors.New("invalid current Group Space source")
	}
	if err := verifyCodexSessionRecord(request.NativeSessionID, request.Workspace); err != nil {
		return store.GroupSpaceEndpointEvidence{}, err
	}
	card, err := b.verifyCurrentMCPBinding(request.SessionToken, request.GroupID)
	if err != nil {
		return store.GroupSpaceEndpointEvidence{}, err
	}
	if card.EndpointID != request.EndpointID || card.GroupID != request.GroupID ||
		card.PrincipalID != request.PrincipalID || card.NodeID != b.nodeID ||
		card.BindingID != request.BindingID || card.BindingEpoch != request.BindingEpoch ||
		card.NativeSessionID != request.NativeSessionID ||
		filepathCleanIfSet(card.Workspace) != filepathCleanIfSet(request.Workspace) {
		return store.GroupSpaceEndpointEvidence{}, errors.New("current Group Space source does not match its native binding")
	}
	return store.GroupSpaceEndpointEvidence{EndpointID: card.EndpointID, PrincipalID: card.PrincipalID,
		OwnerID: request.OwnerID, NodeID: card.NodeID, BindingID: card.BindingID,
		BindingEpoch: card.BindingEpoch}, nil
}

type groupSpaceSealedCache struct {
	ReservationID     string                             `json:"reservation_id"`
	RecordID          string                             `json:"record_id"`
	OperationID       string                             `json:"operation_id"`
	GroupID           string                             `json:"group_id"`
	BodyDigest        string                             `json:"body_digest"`
	SnapshotDigest    string                             `json:"snapshot_digest"`
	ReaderCiphertexts []store.GroupSpaceReaderCiphertext `json:"reader_ciphertexts"`
}

func groupSpaceCachePath(stateDir, nodeID, groupID, operationID string) string {
	digest := sha256.Sum256([]byte(groupID + "\x00" + operationID))
	return filepath.Join(machineNodeStateDir(stateDir, nodeID), "group-spaces", hex.EncodeToString(digest[:])+".json")
}

func loadGroupSpaceCache(path string) (*groupSpaceSealedCache, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > groupSpaceCacheMaxBytes {
		return nil, errors.New("Group Space sealed cache is unsafe")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cache groupSpaceSealedCache
	if err := decodeStrictBridgeJSON(data, &cache); err != nil {
		return nil, errors.New("Group Space sealed cache is invalid")
	}
	return &cache, nil
}

func persistGroupSpaceCache(path string, value groupSpaceSealedCache) (*groupSpaceSealedCache, error) {
	if existing, err := loadGroupSpaceCache(path); err != nil || existing != nil {
		return existing, err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := pruneGroupSpaceCache(dir); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) > groupSpaceCacheMaxBytes {
		return nil, errors.New("Group Space sealed cache exceeds limit")
	}
	temp, err := os.CreateTemp(dir, ".sealed-*")
	if err != nil {
		return nil, err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return nil, err
	}
	if _, err := temp.Write(encoded); err != nil {
		_ = temp.Close()
		return nil, err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return nil, err
	}
	if err := temp.Close(); err != nil {
		return nil, err
	}
	if err := os.Link(temp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadGroupSpaceCache(path)
		}
		return nil, err
	}
	if folder, err := os.Open(dir); err == nil {
		_ = folder.Sync()
		_ = folder.Close()
	}
	return &value, nil
}

// Ciphertext retries remain available for the full maximum Hub retention.
// Opportunistic pruning then bounds this private Node cache without timers.
func pruneGroupSpaceCache(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var count int
	var total int64
	cutoff := time.Now().UTC().Add(-31 * 24 * time.Hour)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("Group Space cache contains an unsafe file")
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		count++
		total += info.Size()
	}
	if count >= 512 || total >= 128<<20 {
		return errors.New("Group Space durable cache quota is full")
	}
	return nil
}

func groupSpaceBodyDigest(body string) string {
	sum := sha256.Sum256([]byte("cicada/group-space/local-body/v1\x00" + body))
	return hex.EncodeToString(sum[:])
}

func groupSpaceCacheMatches(cache *groupSpaceSealedCache, snapshot store.GroupSpaceSnapshot,
	operationID, body string) bool {
	if cache == nil || cache.ReservationID != snapshot.ReservationID ||
		cache.RecordID != snapshot.RecordID || cache.OperationID != operationID ||
		cache.GroupID != snapshot.GroupID || cache.BodyDigest != groupSpaceBodyDigest(body) ||
		cache.SnapshotDigest != snapshot.ReaderSnapshotDigest ||
		len(cache.ReaderCiphertexts) != len(snapshot.Readers) {
		return false
	}
	readers := make(map[string]string, len(snapshot.Readers))
	for _, reader := range snapshot.Readers {
		readers[reader.EndpointID] = reader.KeyID
	}
	for _, sealed := range cache.ReaderCiphertexts {
		if readers[sealed.EndpointID] != sealed.KeyID || len(sealed.Wire) == 0 {
			return false
		}
		delete(readers, sealed.EndpointID)
	}
	return len(readers) == 0
}

func groupSpaceNodeEvidence(value store.GroupSpaceEndpointEvidence) (nodekeys.GroupSpaceEndpointEvidence, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nodekeys.GroupSpaceEndpointEvidence{}, err
	}
	var evidence nodekeys.GroupSpaceEndpointEvidence
	if err := json.Unmarshal(encoded, &evidence); err != nil {
		return nodekeys.GroupSpaceEndpointEvidence{}, err
	}
	return evidence, nil
}

func groupSpaceEvidenceDigestLocal(value store.GroupSpaceEndpointEvidence) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(append([]byte("cicada/group-space/recipient-evidence/v1\x00"), encoded...))
	return hex.EncodeToString(sum[:])
}

func (b *machineAgentJoinBridge) verifyGroupSpaceKey(state *nodekeys.CryptoState,
	snapshot store.GroupSpaceSnapshot, value store.GroupSpaceEndpointEvidence,
	at time.Time) (e2ee.PublicIdentity, error) {
	evidence, err := groupSpaceNodeEvidence(value)
	if err != nil {
		return e2ee.PublicIdentity{}, err
	}
	return state.VerifyGroupSpaceEndpointKey(b.ctx, snapshot.HubID, snapshot.GroupID, evidence, at)
}

func (b *machineAgentJoinBridge) groupSpace(request groupSpaceLocalRequest) (*groupSpaceLocalResult, error) {
	actor, err := b.verifyGroupSpaceSource(request)
	if err != nil {
		return nil, err
	}
	if request.Operation == "space_sync" || request.Operation == "space_read_state" || request.Operation == "space_mark_read" {
		return b.syncGroupSpace(request, actor)
	}
	if request.Operation == "space_regroup_propose" || request.Operation == "space_regroup_apply" {
		return b.regroupSpace(request)
	}
	stateDir := machineNodeStateDir(b.stateDir, b.nodeID)
	identity, err := nodekeys.LoadOrCreate(stateDir, actor.EndpointID)
	if err != nil {
		return nil, errors.New("could not load Node-local Group Space key")
	}
	cryptoState, err := nodekeys.OpenCryptoState(stateDir)
	if err != nil {
		return nil, errors.New("could not open Node-local Group Space trust")
	}
	defer cryptoState.Close()
	if request.Operation == "space_history_manifest" || request.Operation == "space_history_share" {
		return b.groupSpaceHistory(request, actor, identity, cryptoState)
	}
	if strings.HasSuffix(request.Operation, "_list") || strings.HasSuffix(request.Operation, "_get") {
		return b.readGroupSpace(request, actor, identity, cryptoState)
	}
	return b.writeGroupSpace(request, actor, identity, cryptoState)
}

func (b *machineAgentJoinBridge) syncGroupSpace(request groupSpaceLocalRequest,
	actor store.GroupSpaceEndpointEvidence) (*groupSpaceLocalResult, error) {
	result := &groupSpaceLocalResult{}
	switch request.Operation {
	case "space_sync":
		var value store.GroupSpaceSyncResult
		if err := b.groupSpaceHTTP(request.SessionToken, "sync", store.GroupSpaceSyncInput{
			GroupID: request.GroupID, AfterSeq: request.AfterSeq, Limit: request.Limit}, &value); err != nil {
			return nil, err
		}
		if value.GroupID != request.GroupID || value.NextSeq < request.AfterSeq || value.LatestSeq < value.NextSeq || len(value.Hints) > 16 {
			return nil, errors.New("Hub returned mismatched Group Space sync")
		}
		result.Sync = &value
		if err := b.rememberGroupSpaceSubscription(request, actor, &value); err != nil {
			return nil, err
		}
	case "space_read_state", "space_mark_read":
		var value store.GroupSpaceReadState
		var input any = store.GroupSpaceReadStateInput{GroupID: request.GroupID}
		route := "read-state"
		if request.Operation == "space_mark_read" {
			input = store.GroupSpaceMarkReadInput{GroupID: request.GroupID, ThroughSeq: request.ThroughSeq}
			route = "mark-read"
		}
		if err := b.groupSpaceHTTP(request.SessionToken, route, input, &value); err != nil {
			return nil, err
		}
		if value.GroupID != request.GroupID || value.ReadSeq > value.LatestSeq {
			return nil, errors.New("Hub returned mismatched Group Space read state")
		}
		result.ReadState = &value
	default:
		return nil, errors.New("invalid Group Space sync operation")
	}
	return result, nil
}

func groupSpaceWriteKind(operation string) string {
	switch operation {
	case "space_journal_append":
		return store.GroupSpaceKindJournal
	case "space_discussion_topic_create":
		return store.GroupSpaceKindTopic
	case "space_discussion_reply":
		return store.GroupSpaceKindReply
	case "space_discussion_resolve", "space_discussion_reopen":
		return store.GroupSpaceKindTopicStatus
	default:
		return ""
	}
}

func (b *machineAgentJoinBridge) writeGroupSpace(request groupSpaceLocalRequest,
	actor store.GroupSpaceEndpointEvidence, identity *e2ee.Identity,
	cryptoState *nodekeys.CryptoState) (*groupSpaceLocalResult, error) {
	kind := groupSpaceWriteKind(request.Operation)
	if kind == "" || request.OperationID == "" || (kind != store.GroupSpaceKindTopicStatus &&
		(request.Body == "" || len([]byte(request.Body)) > mcpGroupSpaceMaxBody)) {
		return nil, errors.New("invalid Group Space write")
	}
	if kind == store.GroupSpaceKindTopicStatus {
		if request.TopicID == "" || request.ExpectedTopicVersion <= 0 ||
			(request.Status != "OPEN" && request.Status != "RESOLVED") || request.Body != "" {
			return nil, errors.New("invalid Discussion state change")
		}
		request.Body = `{"status":"` + request.Status + `"}`
	}
	prepare := store.GroupSpacePrepareInput{GroupID: request.GroupID,
		OperationID: request.OperationID, Kind: kind, TopicID: request.TopicID,
		CorrectsID: request.CorrectsID, ExpectedTopicVersion: request.ExpectedTopicVersion,
		Status: request.Status, RetentionClass: "standard"}
	var snapshot store.GroupSpaceSnapshot
	if err := b.groupSpaceHTTP(request.SessionToken, "prepare", prepare, &snapshot); err != nil {
		return nil, err
	}
	expectedTopicID := request.TopicID
	if kind == store.GroupSpaceKindTopic {
		expectedTopicID = snapshot.RecordID
	}
	if snapshot.HubID == "" || snapshot.HubID != machinePinnedHubID(b.ctx) ||
		snapshot.NetworkID == "" || snapshot.GroupID != request.GroupID ||
		snapshot.OperationID != request.OperationID || snapshot.Kind != kind ||
		snapshot.TopicID != expectedTopicID || snapshot.CorrectsID != request.CorrectsID ||
		snapshot.ExpectedTopicVersion != request.ExpectedTopicVersion ||
		snapshot.Status != request.Status || snapshot.RecordID == "" ||
		snapshot.ReservationID == "" || snapshot.Sequence <= 0 ||
		snapshot.Producer.EndpointID != actor.EndpointID ||
		snapshot.Producer.PrincipalID != actor.PrincipalID ||
		snapshot.Producer.OwnerID != actor.OwnerID ||
		snapshot.Producer.NodeID != actor.NodeID ||
		snapshot.Producer.BindingID != actor.BindingID ||
		snapshot.Producer.BindingEpoch != actor.BindingEpoch ||
		len(snapshot.Readers) == 0 || len(snapshot.Readers) > store.GroupSpaceMaxReaders {
		return nil, errors.New("Hub returned a mismatched Group Space reservation")
	}
	if snapshot.Committed {
		var record store.GroupSpaceRecord
		if err := b.groupSpaceHTTP(request.SessionToken, "get", store.GroupSpaceGetInput{
			GroupID: request.GroupID, RecordID: snapshot.RecordID}, &record); err != nil {
			return nil, err
		}
		public, err := b.openGroupSpaceRecord(record, request.GroupID, actor.EndpointID, identity, cryptoState)
		if err != nil {
			return nil, err
		}
		if public.Body != request.Body {
			return nil, errors.New("Group Space idempotency key conflicts with the original body")
		}
		return &groupSpaceLocalResult{Record: &public}, nil
	}
	localPublic, err := b.verifyGroupSpaceKey(cryptoState, snapshot, snapshot.Producer, time.Now().UTC())
	if err != nil || !machineSamePublicIdentity(localPublic, identity.Public()) {
		return nil, fmt.Errorf("Group Space author key is not Owner-trusted for this native session: %v", err)
	}
	cachePath := groupSpaceCachePath(b.stateDir, b.nodeID, snapshot.GroupID, request.OperationID)
	cache, err := loadGroupSpaceCache(cachePath)
	if err != nil {
		return nil, err
	}
	if cache == nil {
		cache, err = b.sealGroupSpaceSnapshot(snapshot, request.Body, identity, cryptoState)
		if err != nil {
			return nil, err
		}
		cache, err = persistGroupSpaceCache(cachePath, *cache)
		if err != nil {
			return nil, err
		}
	}
	if !groupSpaceCacheMatches(cache, snapshot, request.OperationID, request.Body) {
		return nil, errors.New("Group Space idempotency key conflicts with the original sealed content")
	}
	var record store.GroupSpaceRecord
	if err := b.groupSpaceHTTP(request.SessionToken, "commit", store.GroupSpaceCommitInput{
		ReservationID: snapshot.ReservationID, ReaderCiphertexts: cache.ReaderCiphertexts}, &record); err != nil {
		return nil, err
	}
	public, err := b.openGroupSpaceRecord(record, request.GroupID, actor.EndpointID, identity, cryptoState)
	if err != nil {
		return nil, err
	}
	return &groupSpaceLocalResult{Record: &public}, nil
}

func (b *machineAgentJoinBridge) sealGroupSpaceSnapshot(snapshot store.GroupSpaceSnapshot,
	body string, identity *e2ee.Identity, cryptoState *nodekeys.CryptoState) (*groupSpaceSealedCache, error) {
	producerContext := store.GroupSpaceReaderContext(snapshot, snapshot.Producer)
	signedBody, err := e2ee.SignGroupSpaceBody(identity, producerContext, []byte(body))
	if err != nil {
		return nil, err
	}
	cache := &groupSpaceSealedCache{ReservationID: snapshot.ReservationID,
		RecordID: snapshot.RecordID, OperationID: snapshot.OperationID,
		GroupID: snapshot.GroupID, BodyDigest: groupSpaceBodyDigest(body),
		SnapshotDigest:    snapshot.ReaderSnapshotDigest,
		ReaderCiphertexts: make([]store.GroupSpaceReaderCiphertext, 0, len(snapshot.Readers))}
	seen := make(map[string]struct{}, len(snapshot.Readers))
	for _, reader := range snapshot.Readers {
		if reader.EndpointID == "" || reader.OwnerID != snapshot.Producer.OwnerID ||
			reader.KeyID == "" {
			return nil, errors.New("Group Space reader snapshot is invalid")
		}
		if _, exists := seen[reader.EndpointID]; exists {
			return nil, errors.New("Group Space reader snapshot repeats an Endpoint")
		}
		seen[reader.EndpointID] = struct{}{}
		verified, err := b.verifyGroupSpaceKey(cryptoState, snapshot, reader, time.Now().UTC())
		if err != nil || !machineSamePublicIdentity(verified, reader.PublicIdentity) {
			return nil, errors.New("Group Space reader key is not Owner-trusted")
		}
		context := store.GroupSpaceReaderContext(snapshot, reader)
		sequence, err := cryptoState.ReserveOutboundSequence(b.ctx,
			snapshot.Producer.EndpointID, identity.Public().ID)
		if err != nil {
			return nil, errors.New("could not reserve Group Space outbound crypto sequence")
		}
		wire, err := e2ee.SealGroupSpaceReader(identity, verified, context,
			signedBody, sequence)
		if err != nil {
			return nil, err
		}
		cache.ReaderCiphertexts = append(cache.ReaderCiphertexts,
			store.GroupSpaceReaderCiphertext{EndpointID: reader.EndpointID, KeyID: reader.KeyID, Wire: wire})
	}
	if _, exists := seen[snapshot.Producer.EndpointID]; !exists {
		return nil, errors.New("Group Space snapshot omits its author")
	}
	return cache, nil
}

func (b *machineAgentJoinBridge) readGroupSpace(request groupSpaceLocalRequest,
	actor store.GroupSpaceEndpointEvidence, identity *e2ee.Identity,
	cryptoState *nodekeys.CryptoState) (*groupSpaceLocalResult, error) {
	result := &groupSpaceLocalResult{}
	if strings.HasSuffix(request.Operation, "_get") {
		if request.RecordID == "" {
			return nil, errors.New("Group Space record ID is required")
		}
		var record store.GroupSpaceRecord
		if err := b.groupSpaceHTTP(request.SessionToken, "get", store.GroupSpaceGetInput{
			GroupID: request.GroupID, RecordID: request.RecordID}, &record); err != nil {
			return nil, err
		}
		public, err := b.openGroupSpaceRecord(record, request.GroupID, actor.EndpointID, identity, cryptoState)
		if err != nil {
			return nil, err
		}
		if (request.Operation == "space_journal_get") != (public.Kind == store.GroupSpaceKindJournal) {
			return nil, errors.New("Group Space record is outside the selected surface")
		}
		result.Record = &public
		return result, nil
	}
	if request.Limit < 0 || request.Limit > store.GroupSpaceMaxPage {
		return nil, errors.New("Group Space page limit is invalid")
	}
	kind := store.GroupSpaceKindJournal
	if request.Operation == "space_discussion_list" {
		kind = store.GroupSpaceKindTopic
		if request.TopicID != "" {
			kind = ""
		}
	}
	var page store.GroupSpacePage
	if err := b.groupSpaceHTTP(request.SessionToken, "list", store.GroupSpaceListInput{
		GroupID: request.GroupID, Kind: kind, TopicID: request.TopicID,
		Cursor: request.Cursor, Limit: request.Limit}, &page); err != nil {
		return nil, err
	}
	if len(page.Records) > store.GroupSpaceMaxPage {
		return nil, errors.New("Hub returned oversized Group Space page")
	}
	for _, record := range page.Records {
		public, err := b.openGroupSpaceRecord(record, request.GroupID, actor.EndpointID, identity, cryptoState)
		if err != nil {
			return nil, err
		}
		result.Records = append(result.Records, public)
	}
	result.NextCursor = page.NextCursor
	return result, nil
}

func (b *machineAgentJoinBridge) openGroupSpaceRecord(record store.GroupSpaceRecord,
	groupID, readerID string, identity *e2ee.Identity,
	cryptoState *nodekeys.CryptoState) (groupSpacePublicRecord, error) {
	value, _, err := b.openGroupSpaceRecordSigned(record, groupID, readerID, identity, cryptoState)
	return value, err
}

func (b *machineAgentJoinBridge) openGroupSpaceRecordSigned(record store.GroupSpaceRecord,
	groupID, readerID string, identity *e2ee.Identity,
	cryptoState *nodekeys.CryptoState) (groupSpacePublicRecord, []byte, error) {
	snapshot := record.Snapshot
	if snapshot.GroupID != groupID || snapshot.HubID == "" ||
		snapshot.HubID != machinePinnedHubID(b.ctx) ||
		snapshot.NetworkID == "" || snapshot.RecordID == "" || snapshot.Sequence <= 0 ||
		snapshot.Producer.EndpointID == "" || snapshot.ReaderSnapshotDigest == "" ||
		record.ReaderCiphertext.EndpointID != readerID ||
		record.ReaderCiphertext.KeyID != identity.Public().ID ||
		len(record.ReaderCiphertext.Wire) == 0 {
		return groupSpacePublicRecord{}, nil, errors.New("Hub returned a mismatched Group Space record")
	}
	reservedAt, err := time.Parse(time.RFC3339Nano, snapshot.ReservedAt)
	if err != nil || snapshot.ReservedAt != reservedAt.UTC().Format(time.RFC3339Nano) ||
		reservedAt.After(time.Now().UTC()) {
		return groupSpacePublicRecord{}, nil, errors.New("Hub returned an invalid Group Space reservation time")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, snapshot.ExpiresAt)
	if err != nil || snapshot.ExpiresAt != expiresAt.UTC().Format(time.RFC3339Nano) ||
		!expiresAt.After(time.Now().UTC()) || !expiresAt.After(reservedAt) {
		return groupSpacePublicRecord{}, nil, errors.New("Group Space record has expired")
	}
	producerEvidence, err := groupSpaceNodeEvidence(snapshot.Producer)
	if err != nil {
		return groupSpacePublicRecord{}, nil, errors.New("Group Space producer proof is invalid")
	}
	producerKey, err := cryptoState.VerifyGroupSpaceHistoricalEndpointKey(b.ctx,
		snapshot.HubID, snapshot.GroupID, producerEvidence, reservedAt)
	if err != nil {
		return groupSpacePublicRecord{}, nil, errors.New("Group Space producer proof is not trusted")
	}
	var reader store.GroupSpaceEndpointEvidence
	for _, candidate := range snapshot.Readers {
		if candidate.EndpointID == readerID {
			reader = candidate
			break
		}
	}
	if reader.EndpointID != readerID || reader.KeyID != identity.Public().ID {
		return groupSpacePublicRecord{}, nil, errors.New("Group Space reader proof is absent")
	}
	readerEvidence, err := groupSpaceNodeEvidence(reader)
	if err != nil {
		return groupSpacePublicRecord{}, nil, errors.New("Group Space reader proof is invalid")
	}
	proofAt := reservedAt
	if record.HistoryGrantID != "" {
		proofAt, err = time.Parse(time.RFC3339Nano, record.HistoryGrantedAt)
		if err != nil || record.HistoryGrantedAt != proofAt.UTC().Format(time.RFC3339Nano) ||
			proofAt.Before(reservedAt) || proofAt.After(time.Now().UTC()) {
			return groupSpacePublicRecord{}, nil, errors.New("Group Space history grant time is invalid")
		}
	}
	readerKey, err := cryptoState.VerifyGroupSpaceHistoricalEndpointKey(b.ctx,
		snapshot.HubID, snapshot.GroupID, readerEvidence, proofAt)
	if err != nil || !machineSamePublicIdentity(readerKey, identity.Public()) {
		return groupSpacePublicRecord{}, nil, errors.New("Group Space reader proof is not trusted")
	}
	context := store.GroupSpaceReaderContext(snapshot, reader)
	envelopeSigner := producerKey
	if record.HistoryGrantID != "" {
		grant := record.HistoryGrant
		if grant == nil || grant.ManifestID != record.HistoryGrantID ||
			grant.HubID != snapshot.HubID || grant.NetworkID != snapshot.NetworkID ||
			grant.GroupID != snapshot.GroupID || grant.RecordID != snapshot.RecordID ||
			grant.OriginalCiphertextDigest != record.CiphertextDigest ||
			grant.RecipientEndpointID != reader.EndpointID ||
			grant.RecipientKeyID != reader.KeyID ||
			grant.RecipientBindingID != reader.BindingID ||
			grant.RecipientBindingEpoch != reader.BindingEpoch ||
			grant.RecipientMembershipRevision != reader.MembershipRevision ||
			grant.RecipientJoinRevision != reader.JoinRevision ||
			grant.RecipientEvidenceDigest != groupSpaceEvidenceDigestLocal(reader) ||
			grant.OwnerID != reader.OwnerID ||
			record.EnvelopeSigner.EndpointID == "" ||
			!proofAt.Before(time.Now().UTC().Add(time.Second)) {
			return groupSpacePublicRecord{}, nil, errors.New("Group Space history grant scope is invalid")
		}
		trust, err := cryptoState.GetNodeOwnerKeyTrustLocal(grant.OwnerID, grant.OwnerKeyID)
		if err != nil || trust.State != nodekeys.NodeOwnerKeyTrustActive ||
			!machineSamePublicIdentity(trust.PublicIdentity, record.HistoryOwnerPublic) {
			return groupSpacePublicRecord{}, nil, errors.New("Group Space history Owner key is not trusted")
		}
		if _, err := e2ee.VerifyGroupSpaceHistoryGrant(record.HistoryOwnerProof,
			trust.PublicIdentity, *grant, proofAt); err != nil {
			return groupSpacePublicRecord{}, nil, errors.New("Group Space history Owner proof is invalid")
		}
		if _, err := e2ee.VerifyGroupSpaceHistoryGrant(record.HistoryOwnerProof,
			trust.PublicIdentity, *grant, time.Now().UTC()); err != nil {
			return groupSpacePublicRecord{}, nil, errors.New("Group Space history Owner proof is invalid")
		}
		signerEvidence, err := groupSpaceNodeEvidence(record.EnvelopeSigner)
		if err != nil {
			return groupSpacePublicRecord{}, nil, errors.New("Group Space history signer proof is invalid")
		}
		envelopeSigner, err = cryptoState.VerifyGroupSpaceHistoricalEndpointKey(b.ctx,
			snapshot.HubID, snapshot.GroupID, signerEvidence, proofAt)
		if err != nil {
			return groupSpacePublicRecord{}, nil, errors.New("Group Space history signer is not trusted")
		}
		context = store.GroupSpaceHistoryReaderContext(snapshot, reader, record.HistoryGrantID)
	} else if record.EnvelopeSigner.EndpointID != "" &&
		record.EnvelopeSigner.EndpointID != snapshot.Producer.EndpointID {
		return groupSpacePublicRecord{}, nil, errors.New("Group Space envelope signer is invalid")
	}
	body, signedBody, err := e2ee.OpenGroupSpaceReader(identity, envelopeSigner, producerKey,
		context, record.ReaderCiphertext.Wire)
	if err != nil {
		return groupSpacePublicRecord{}, nil, errors.New("Group Space ciphertext authentication failed")
	}
	return groupSpacePublicRecord{RecordID: snapshot.RecordID, GroupID: snapshot.GroupID,
		Sequence: snapshot.Sequence, Kind: snapshot.Kind, TopicID: snapshot.TopicID,
		CorrectsID: snapshot.CorrectsID, Status: snapshot.Status,
		TopicVersion: record.TopicVersion, ProducerEndpoint: snapshot.Producer.EndpointID,
		CurrentTopicVersion: record.CurrentTopicVersion,
		CurrentTopicStatus:  record.CurrentTopicStatus,
		CreatedAt:           record.CreatedAt, ExpiresAt: snapshot.ExpiresAt, Body: string(body)}, signedBody, nil
}
