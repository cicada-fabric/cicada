package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelocal"
	"github.com/cicada-ai/cicada/internal/store"
)

// New Task handoffs always use the existing sealed Hub Relay.
func (b *machineAgentJoinBridge) submitLocalSealedTaskHandoff(ledger *nodelocal.Ledger,
	request localGroupRequest) (*localGroupResult, error) {
	return nil, errGenericNativeDirectUnsupported
}

func (b *machineAgentJoinBridge) recordLocalNativeContext(authorization store.LocalDeliveryAuthorization,
	endpoint store.LocalDeliveryEndpointAuthorization, nativeHarness, nativeSessionID string) (*nodeinbox.NativeContextScopeDecision, error) {
	hub, ok := machineHubFrom(b.ctx)
	if !ok || strings.TrimSpace(hub.WriterRoot) == "" || strings.TrimSpace(hub.WriterScope) == "" || hub.NodeID != b.nodeID ||
		(hub.Origin != "" && strings.TrimRight(hub.Origin, "/") != strings.TrimRight(b.baseURL, "/")) ||
		(hub.HubID != "" && hub.HubID != authorization.HubID) || authorization.HubID == "" {
		return nil, errors.New("current Node Hub context is not pinned for native scope history")
	}
	policy, err := effectiveLocalNativeContextPolicy(endpoint.GroupContextPolicy, endpoint.NetworkContextPolicy)
	if err != nil {
		return nil, err
	}
	if endpoint.EndpointID == "" || endpoint.OwnerID == "" || endpoint.NetworkID != "" && len(endpoint.NetworkID) > 256 ||
		endpoint.BindingID == "" || endpoint.BindingEpoch == 0 || nativeSessionID == "" {
		return nil, errors.New("current local Endpoint lacks trusted native context scope")
	}
	registry, err := nodeinbox.OpenNativeContextRegistry(filepath.Join(hub.WriterRoot, "node-native-context-history.sqlite3"))
	if err != nil {
		return nil, fmt.Errorf("open shared Node native context history: %w", err)
	}
	defer registry.Close()
	decision, err := registry.CheckAndRecordNativeContext(b.ctx, nodeinbox.NativeContextScopeInput{
		AccountID: hub.WriterScope, Harness: nativeHarness, NativeSessionID: nativeSessionID,
		HubID: authorization.HubID, NetworkID: endpoint.NetworkID, GroupID: endpoint.GroupID,
		ContextPolicy: policy, EndpointID: endpoint.EndpointID,
		BindingID: endpoint.BindingID, BindingEpoch: endpoint.BindingEpoch,
	})
	if err != nil || decision == nil || !decision.Accepted {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("native context history rejected the current scope")
	}
	return decision, nil
}

func effectiveLocalNativeContextPolicy(groupPolicy, networkPolicy string) (string, error) {
	switch groupPolicy {
	case "", nodeinbox.NativeContextPolicyGroupScoped, nodeinbox.NativeContextPolicyDedicatedThread:
	default:
		return "", errors.New("current Group context policy is unknown")
	}
	switch networkPolicy {
	case "", nodeinbox.NativeContextPolicyDedicatedNetwork:
	default:
		return "", errors.New("current Network context policy is unknown")
	}
	if groupPolicy == nodeinbox.NativeContextPolicyDedicatedThread {
		return nodeinbox.NativeContextPolicyDedicatedThread, nil
	}
	if networkPolicy == nodeinbox.NativeContextPolicyDedicatedNetwork {
		return nodeinbox.NativeContextPolicyDedicatedNetwork, nil
	}
	if groupPolicy == nodeinbox.NativeContextPolicyGroupScoped {
		return nodeinbox.NativeContextPolicyGroupScoped, nil
	}
	return "", nil
}

// recoverLocalSealedTaskHandoff returns only the exact opaque digest recorded
// by this source Endpoint's Node-local ledger. It lets an MCP retry reconcile
// a Hub proposal after a lost response without resealing or inventing a new
// message ID/sequence.
func (b *machineAgentJoinBridge) recoverLocalSealedTaskHandoff(_ *nodelocal.Ledger,
	request localGroupRequest) (result *localGroupResult, recoverErr error) {
	path := machineLocalGroupLedgerPath(b.stateDir, b.nodeID)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		parent, parentErr := os.Lstat(filepath.Dir(path))
		if parentErr != nil || !parent.IsDir() || parent.Mode().Perm() != 0700 {
			return nil, errors.New("historical Task parent cannot prove absence")
		}
		for _, suffix := range []string{"-wal", "-shm"} {
			if _, sideErr := os.Lstat(path + suffix); !errors.Is(sideErr, os.ErrNotExist) {
				return nil, errors.New("historical Task main is missing with orphan or unreadable sidecars")
			}
		}
		return nil, nodelocal.ErrMessageNotFound
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("historical Task ledger is not a private regular file")
	}
	// SQLite read-only readers can change source WAL shared-memory read marks.
	// Read a private byte snapshot instead; fail closed if any source changes.
	scratch, err := os.MkdirTemp("", "cicada-task-history-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(scratch)
	type snapshotFile struct {
		info   os.FileInfo
		digest string
	}
	files := make(map[string]snapshotFile)
	const maxHistorySnapshotBytes int64 = 64 * 1024 * 1024
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		fileInfo, statErr := os.Lstat(path + suffix)
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			return nil, statErr
		}
		if !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0600 {
			return nil, errors.New("historical Task sidecar is not private and regular")
		}
		if fileInfo.Size() < 0 || fileInfo.Size() > maxHistorySnapshotBytes-total {
			return nil, errors.New("historical Task snapshot exceeds 64 MiB")
		}
		total += fileInfo.Size()
		input, openErr := os.Open(path + suffix)
		if openErr != nil {
			return nil, openErr
		}
		openedInfo, statErr := input.Stat()
		if statErr != nil || !os.SameFile(fileInfo, openedInfo) {
			input.Close()
			return nil, errors.New("historical Task source identity changed")
		}
		hash := sha256.New()
		var output *os.File
		var writer io.Writer = hash
		if suffix != "-shm" {
			output, err = os.OpenFile(filepath.Join(scratch, "history.sqlite3")+suffix, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				input.Close()
				return nil, err
			}
			writer = io.MultiWriter(hash, output)
		}
		n, copyErr := io.Copy(writer, io.LimitReader(input, fileInfo.Size()+1))
		closeErr := input.Close()
		if output != nil {
			if outErr := output.Close(); copyErr == nil {
				copyErr = outErr
			}
		}
		if copyErr != nil || closeErr != nil || n != fileInfo.Size() {
			return nil, errors.New("historical Task source changed while copying")
		}
		files[suffix] = snapshotFile{info: fileInfo, digest: hex.EncodeToString(hash.Sum(nil))}
	}
	validateSnapshot := func() error {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			fileInfo, statErr := os.Lstat(path + suffix)
			before, existed := files[suffix]
			if !existed && os.IsNotExist(statErr) {
				continue
			}
			if statErr != nil || !existed || !os.SameFile(before.info, fileInfo) || fileInfo.Mode() != before.info.Mode() || fileInfo.Size() != before.info.Size() {
				return errors.New("historical Task source changed during recovery")
			}
			input, openErr := os.Open(path + suffix)
			if openErr != nil {
				return openErr
			}
			hash := sha256.New()
			n, readErr := io.Copy(hash, io.LimitReader(input, fileInfo.Size()+1))
			closeErr := input.Close()
			if readErr != nil || closeErr != nil || n != fileInfo.Size() || hex.EncodeToString(hash.Sum(nil)) != before.digest {
				return errors.New("historical Task source changed during recovery")
			}
		}
		return nil
	}
	if err := validateSnapshot(); err != nil {
		return nil, err
	}
	defer func() {
		if err := validateSnapshot(); err != nil {
			result, recoverErr = nil, err
		}
	}()
	databaseURL := url.URL{Scheme: "file", Path: filepath.Join(scratch, "history.sqlite3"), RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", databaseURL.String())
	if err != nil {
		return nil, err
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRowContext(b.ctx, "PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return nil, errors.New("historical Task snapshot is corrupt")
	}
	var record nodelocal.MessageRecord
	var routeJSON string
	err = db.QueryRowContext(b.ctx, `SELECT message_id,kind,request_id,reply_to_message_id,lower(hex(digest)),route_json,ciphertext,delivery_state
 FROM node_local_messages WHERE message_id=?`, request.HandoffMessageID).Scan(&record.MessageID, &record.Kind,
		&record.RequestID, &record.ReplyToMessageID, &record.Digest, &routeJSON, &record.Ciphertext, &record.State)
	if errors.Is(err, sql.ErrNoRows) {
		if wal, exists := files["-wal"]; exists && wal.info.Size() > 0 {
			// SQLite can silently ignore a corrupt WAL and expose an older main
			// database. An absent row with any WAL is not proof of absent history.
			return nil, errors.New("historical Task absence is uncertain with an existing WAL")
		}
		return nil, nodelocal.ErrMessageNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := decodeStrictBridgeJSON([]byte(routeJSON), &record.Route); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(record.Ciphertext)
	if record.Digest != hex.EncodeToString(digest[:]) || record.Kind != nodelocal.KindSend ||
		record.RequestID != "" || record.ReplyToMessageID != "" ||
		record.Route.SourceEndpointID != request.EndpointID || record.Route.SourcePrincipalID != request.PrincipalID ||
		record.Route.SourceOwnerID != request.OwnerID || record.Route.SourceGroupID != request.GroupID ||
		record.Route.SourceNodeID != b.nodeID || record.Route.TargetNodeID != b.nodeID ||
		record.Route.SourceBindingID != request.BindingID || record.Route.SourceBindingEpoch != request.BindingEpoch ||
		record.Route.SourceSessionID != request.NativeSessionID {
		return nil, nodelocal.ErrMessageConflict
	}
	// Existing keys and pure cryptographic verification do not advance counters,
	// record native context or authorize a new delivery of historical content.
	source, err := nodekeys.LoadExisting(machineNodeStateDir(b.stateDir, b.nodeID), record.Route.SourceEndpointID)
	if err != nil {
		return nil, err
	}
	target, err := nodekeys.LoadExisting(machineNodeStateDir(b.stateDir, b.nodeID), record.Route.TargetEndpointID)
	if err != nil {
		return nil, err
	}
	if source.Public().ID != record.Route.SourceKeyID || target.Public().ID != record.Route.TargetKeyID {
		return nil, nodelocal.ErrMessageConflict
	}
	r := record.Route
	context := e2ee.EndpointMessageContext{MessageID: record.MessageID, Kind: "SEND",
		SenderEndpointID: r.SourceEndpointID, SenderPrincipalID: r.SourcePrincipalID, SenderOwnerID: r.SourceOwnerID,
		SenderGroupID: r.SourceGroupID, SenderMembershipRevision: int64(r.SourceMembershipRevision),
		SenderBindingEpoch: r.SourceBindingEpoch, SenderKeyID: r.SourceKeyID,
		ReceiverEndpointID: r.TargetEndpointID, ReceiverPrincipalID: r.TargetPrincipalID, ReceiverOwnerID: r.TargetOwnerID,
		ReceiverGroupID: r.TargetGroupID, ReceiverMembershipRevision: int64(r.TargetMembershipRevision),
		ReceiverBindingEpoch: r.TargetBindingEpoch, ReceiverKeyID: r.TargetKeyID}
	plaintext, _, err := e2ee.OpenEndpointMessage(target, source.Public(), context, record.Ciphertext)
	if err != nil {
		return nil, err
	}
	packet, err := decodeSealedTaskHandoffPayload(plaintext)
	if err != nil || packet.HandoffID != request.TaskHandoffID || packet.MessageID != record.MessageID {
		return nil, nodelocal.ErrMessageConflict
	}
	httpRequest, err := http.NewRequestWithContext(b.ctx, http.MethodGet,
		b.baseURL+"/v2/fabric/tasks/sealed-handoffs/"+url.PathEscape(request.TaskHandoffID), nil)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Set("Authorization", "CicadaSession "+request.SessionToken)
	httpRequest.Header.Set("Cicada-Group-Scope", request.GroupID)
	client, err := machineNodeHTTPClient(b.ctx, 30*time.Second)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("historical Task handoff read authorization rejected")
	}
	var handoff store.SealedSharedTaskHandoff
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024))
	if err := decoder.Decode(&handoff); err != nil {
		return nil, err
	}
	if handoff.Transport != "LOCAL_NODE" || handoff.LocalRoute == nil || handoff.ID != request.TaskHandoffID ||
		handoff.MessageID != record.MessageID || handoff.MessageDigest != record.Digest ||
		handoff.GroupID != r.SourceGroupID || handoff.GroupID != r.TargetGroupID ||
		handoff.FromPrincipalID != r.SourcePrincipalID || handoff.ToPrincipalID != r.TargetPrincipalID ||
		handoff.FromEndpointID != r.SourceEndpointID || handoff.ToEndpointID != r.TargetEndpointID ||
		handoff.LocalRoute.FromBindingID != r.SourceBindingID || handoff.LocalRoute.FromBindingEpoch != r.SourceBindingEpoch ||
		handoff.LocalRoute.ToBindingID != r.TargetBindingID || handoff.LocalRoute.ToBindingEpoch != r.TargetBindingEpoch ||
		handoff.LocalRoute.NodeID != b.nodeID || handoff.LocalRoute.FromMembershipRevision != int64(r.SourceMembershipRevision) ||
		handoff.LocalRoute.ToMembershipRevision != int64(r.TargetMembershipRevision) || handoff.LocalRoute.FromJoinRevision != int64(r.SourceJoinRevision) ||
		handoff.LocalRoute.ToJoinRevision != int64(r.TargetJoinRevision) || handoff.LocalRoute.FromKeyID != r.SourceKeyID ||
		handoff.LocalRoute.ToKeyID != r.TargetKeyID || handoff.LocalRoute.FromKeyVersion != int64(r.SourceCandidateVersion) ||
		handoff.LocalRoute.ToKeyVersion != int64(r.TargetCandidateVersion) || !validSHA256Hex(handoff.LocalRoute.SenderProofDigest) {
		return nil, nodelocal.ErrMessageConflict
	}
	a := &store.SealedTaskHandoffDeliveryAuthorization{HandoffID: handoff.ID, TaskID: handoff.TaskID,
		GroupID: handoff.GroupID, FromPrincipalID: handoff.FromPrincipalID, FromEndpointID: handoff.FromEndpointID,
		ToPrincipalID: handoff.ToPrincipalID, ToEndpointID: handoff.ToEndpointID, TaskRevision: handoff.TaskRevision,
		FromOwnerEpoch: handoff.FromOwnerEpoch, MessageID: handoff.MessageID, ExpiresAt: handoff.ExpiresAt,
		RequiredArtifactRefs: handoff.RequiredArtifactRefs, Transport: handoff.Transport, LocalRoute: handoff.LocalRoute}
	if err := matchSealedTaskHandoffPacket(a, record.MessageID, store.RelaySealedV1Route{
		MessageID: record.MessageID, Kind: "send", SenderEndpointID: r.SourceEndpointID, ReceiverEndpointID: r.TargetEndpointID}, plaintext); err != nil {
		return nil, err
	}
	return &localGroupResult{MessageID: record.MessageID, TargetEndpointID: r.TargetEndpointID,
		State: string(record.State), Delivery: "LOCAL_HISTORICAL", PayloadMode: "SEALED_V1", MessageDigest: record.Digest}, nil
}

func validateLocalTaskHandoffRefs(refs []store.SealedTaskHandoffArtifactRef) error {
	if len(refs) > 32 {
		return errors.New("local Task handoff has too many Artifact references")
	}
	normalized, err := store.SealedTaskHandoffArtifactRefsDigest(refs)
	if err != nil || normalized == "" {
		return errors.New("local Task handoff Artifact references are invalid")
	}
	return nil
}

func localTaskHandoffStoredRouteMatches(stored, expected nodelocal.Route) error {
	// Authorization expiry is intentionally renewed on revalidation; all
	// identity, key, revision, scope, and native-session coordinates must stay
	// byte-for-byte tied to the durable message.
	expected.AuthorizationValidUntil = stored.AuthorizationValidUntil
	if stored != expected {
		return nodelocal.ErrMessageConflict
	}
	return nil
}

func validateLocalTaskHandoffAuthorization(record nodelocal.MessageRecord,
	authorization store.LocalDeliveryAuthorization) error {
	if strings.HasPrefix(record.MessageID, "shared-task-handoff.v1:") {
		return errors.New("historical LOCAL_NODE Task handoffs cannot authorize new delivery")
	}
	if authorization.TaskHandoff != nil {
		return errors.New("ordinary local message unexpectedly has Task handoff authorization")
	}
	return nil
}

func localTaskHandoffPayloadMatches(record nodelocal.MessageRecord, authorization store.LocalDeliveryAuthorization,
	plaintext []byte) error {
	if strings.HasPrefix(record.MessageID, "shared-task-handoff.v1:") {
		return errors.New("historical LOCAL_NODE Task handoffs cannot authorize new delivery")
	}
	if authorization.TaskHandoff != nil {
		return errors.New("ordinary local message unexpectedly has Task handoff authorization")
	}
	return nil
}
