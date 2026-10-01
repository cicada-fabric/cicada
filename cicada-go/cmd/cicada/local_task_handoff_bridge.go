package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelocal"
	"github.com/cicada-ai/cicada/internal/store"
)

// submitLocalSealedTaskHandoff persists a normal opaque local SEND first,
// then returns only its digest and detached source Endpoint proof. The task
// prose and ciphertext never cross this Hub metadata proposal boundary.
func (b *machineAgentJoinBridge) submitLocalSealedTaskHandoff(ledger *nodelocal.Ledger,
	request localGroupRequest) (*localGroupResult, error) {
	authorization, err := b.fetchLocalGroupAuthorization(request.SessionToken,
		store.LocalDeliveryAuthorizationInput{GroupID: request.GroupID, Target: request.Target, Action: "message.send"})
	if err != nil {
		return nil, err
	}
	if err := validateLocalGroupAuthorizationForSource(authorization, request); err != nil {
		return nil, err
	}
	contextDecision, err := b.recordLocalNativeContext(*authorization, authorization.Source,
		request.Harness, request.NativeSessionID)
	if err != nil {
		return nil, err
	}
	targetContextDecision, err := b.recordLocalNativeContext(*authorization, authorization.Target,
		request.Harness, authorization.Target.NativeSessionID)
	if err != nil {
		return nil, err
	}
	if authorization.Target.EndpointID == authorization.Source.EndpointID ||
		authorization.Target.EndpointID == "" || authorization.Target.NodeID != b.nodeID {
		return nil, errors.New("local Task handoff target is not another Endpoint on this Node")
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.ExpiresAt)
	if err != nil || deadline.Nanosecond()%1_000_000 != 0 ||
		deadline.Format(time.RFC3339Nano) != request.ExpiresAt || !deadline.After(time.Now().UTC()) {
		return nil, errors.New("local Task handoff deadline is invalid or expired")
	}
	messageHandoffID, messageDeadline, ok := parseTaskHandoffMessageID(request.HandoffMessageID)
	if !ok || messageHandoffID != request.TaskHandoffID || messageDeadline != deadline {
		return nil, errors.New("local Task handoff message ID does not match its exact deadline")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, request.OperationCreatedAt)
	if err != nil || createdAt.UTC().Format(time.RFC3339Nano) != request.OperationCreatedAt ||
		createdAt.After(time.Now().UTC().Add(time.Minute)) || !deadline.After(createdAt) ||
		deadline.Sub(createdAt) > 24*time.Hour {
		return nil, errors.New("local Task handoff durable creation time is invalid")
	}
	if request.ExpectedRevision <= 0 || request.OwnerEpoch <= 0 {
		return nil, errors.New("local Task handoff needs a current task revision and owner epoch")
	}
	if err := validateLocalTaskHandoffRefs(request.RequiredArtifactRefs); err != nil {
		return nil, err
	}

	source, target, err := b.loadLocalGroupIdentities(*authorization)
	if err != nil {
		return nil, err
	}
	route := localGroupEndpointRoute(*authorization, request.HandoffMessageID, "SEND", "", "")
	ledgerRoute, err := localGroupLedgerRoute(*authorization, request.NativeSessionID)
	if err != nil {
		return nil, err
	}
	ledgerRoute.Action = "SEND"
	packet, err := marshalSealedTaskHandoffPayload(sealedTaskHandoffPayload{
		Type: sealedTaskHandoffPayloadType, Version: 1,
		HandoffID: request.TaskHandoffID, TaskID: request.TaskID, GroupID: request.GroupID,
		FromPrincipalID: authorization.Source.PrincipalID, FromEndpointID: authorization.Source.EndpointID,
		ToPrincipalID: authorization.Target.PrincipalID, ToEndpointID: authorization.Target.EndpointID,
		TaskRevision: request.ExpectedRevision, FromOwnerEpoch: request.OwnerEpoch,
		MessageID: request.HandoffMessageID, ExpiresAt: request.ExpiresAt,
		RequiredArtifactRefs: request.RequiredArtifactRefs, Body: request.Body,
	})
	if err != nil {
		return nil, err
	}

	var record nodelocal.MessageRecord
	record, err = ledger.GetMessage(b.ctx, request.HandoffMessageID)
	if err == nil {
		if record.Kind != nodelocal.KindSend || record.RequestID != "" || record.ReplyToMessageID != "" ||
			record.Route.SourceEndpointID != authorization.Source.EndpointID ||
			record.Route.TargetEndpointID != authorization.Target.EndpointID ||
			record.Route.SourceBindingID != authorization.Source.BindingID ||
			record.Route.SourceBindingEpoch != authorization.Source.BindingEpoch ||
			record.Route.TargetBindingID != authorization.Target.BindingID ||
			record.Route.TargetBindingEpoch != authorization.Target.BindingEpoch ||
			record.Route.SourceKeyID != authorization.SourceKey.KeyID ||
			record.Route.TargetKeyID != authorization.TargetKey.KeyID || record.Digest == "" {
			return nil, nodelocal.ErrMessageConflict
		}
	} else if !errors.Is(err, nodelocal.ErrMessageNotFound) {
		return nil, err
	} else {
		cryptoState, openErr := nodekeys.OpenCryptoState(machineNodeStateDir(b.stateDir, b.nodeID))
		if openErr != nil {
			return nil, openErr
		}
		outbound, sealErr := cryptoState.SealLocalSameGroupMessage(b.ctx, source, target,
			authorization.SourceKey.Public, authorization.TargetKey.Public, route, packet)
		closeErr := cryptoState.Close()
		if sealErr != nil || closeErr != nil {
			if sealErr != nil {
				return nil, sealErr
			}
			return nil, closeErr
		}
		accepted, acceptErr := ledger.AcceptSend(b.ctx, nodelocal.MessageInput{
			MessageID: request.HandoffMessageID, Route: ledgerRoute, Ciphertext: outbound.Envelope,
		})
		if acceptErr != nil {
			return nil, acceptErr
		}
		record, err = ledger.GetMessage(b.ctx, accepted.MessageID)
		if err != nil || record.Digest != accepted.Digest || record.Kind != nodelocal.KindSend {
			return nil, nodelocal.ErrMessageConflict
		}
	}
	if err := localTaskHandoffStoredRouteMatches(record.Route, ledgerRoute); err != nil {
		return nil, err
	}
	refsDigest, err := store.SealedTaskHandoffArtifactRefsDigest(request.RequiredArtifactRefs)
	if err != nil {
		return nil, err
	}
	claims := e2ee.LocalTaskHandoffProofClaims{
		Version: 1, Purpose: "LOCAL_NODE", HandoffID: request.TaskHandoffID, TaskID: request.TaskID,
		HubID: authorization.HubID, GroupID: request.GroupID,
		FromPrincipalID: authorization.Source.PrincipalID, FromOwnerID: authorization.Source.OwnerID,
		FromEndpointID: authorization.Source.EndpointID, FromBindingID: authorization.Source.BindingID,
		FromBindingEpoch:       authorization.Source.BindingEpoch,
		FromMembershipRevision: authorization.Source.MembershipRevision,
		FromJoinRevision:       authorization.Source.GroupJoinRevision,
		FromKeyID:              authorization.SourceKey.KeyID, FromKeyVersion: authorization.SourceKey.Version,
		ToPrincipalID: authorization.Target.PrincipalID, ToOwnerID: authorization.Target.OwnerID,
		ToEndpointID: authorization.Target.EndpointID, ToBindingID: authorization.Target.BindingID,
		ToBindingEpoch:       authorization.Target.BindingEpoch,
		ToMembershipRevision: authorization.Target.MembershipRevision,
		ToJoinRevision:       authorization.Target.GroupJoinRevision,
		ToKeyID:              authorization.TargetKey.KeyID, ToKeyVersion: authorization.TargetKey.Version,
		TaskRevision: request.ExpectedRevision, FromOwnerEpoch: request.OwnerEpoch,
		MessageID: request.HandoffMessageID, MessageDigest: record.Digest,
		ExpiresAt: request.ExpiresAt, RequiredArtifactRefsHash: refsDigest,
		IssuedAt: request.OperationCreatedAt,
	}
	proof, err := source.SignLocalTaskHandoffProof(claims)
	if err != nil {
		return nil, err
	}
	b.signalLocalGroupDelivery()
	return &localGroupResult{MessageID: record.MessageID, TargetEndpointID: authorization.Target.EndpointID,
		State: string(record.State), Delivery: "LOCAL_PERSISTED", PayloadMode: "SEALED_V1",
		MessageDigest: record.Digest, SenderProof: proof,
		SharedMemoryRisk: contextDecision.SharedMemoryRisk || targetContextDecision.SharedMemoryRisk}, nil
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
func (b *machineAgentJoinBridge) recoverLocalSealedTaskHandoff(ledger *nodelocal.Ledger,
	request localGroupRequest) (*localGroupResult, error) {
	record, err := ledger.GetMessage(b.ctx, request.HandoffMessageID)
	if err != nil {
		return nil, err
	}
	if record.Kind != nodelocal.KindSend || record.RequestID != "" || record.ReplyToMessageID != "" ||
		record.Route.SourceEndpointID != request.EndpointID || record.Route.SourcePrincipalID != request.PrincipalID ||
		record.Route.SourceOwnerID != request.OwnerID || record.Route.SourceGroupID != request.GroupID ||
		record.Route.SourceNodeID != b.nodeID || record.Route.SourceBindingID != request.BindingID ||
		record.Route.SourceBindingEpoch != request.BindingEpoch || record.Route.SourceSessionID != request.NativeSessionID ||
		record.Digest == "" {
		return nil, nodelocal.ErrMessageConflict
	}
	return &localGroupResult{MessageID: record.MessageID, TargetEndpointID: record.Route.TargetEndpointID,
		State: string(record.State), Delivery: "LOCAL_PERSISTED", PayloadMode: "SEALED_V1",
		MessageDigest: record.Digest}, nil
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
	reserved := strings.HasPrefix(record.MessageID, "shared-task-handoff.v1:")
	if !reserved {
		if authorization.TaskHandoff != nil {
			return errors.New("ordinary local message unexpectedly has Task handoff authorization")
		}
		return nil
	}
	a := authorization.TaskHandoff
	if authorization.Action != "message.send" || a == nil || a.Transport != "LOCAL_NODE" || a.LocalRoute == nil ||
		a.HandoffID == "" || a.TaskID == "" || a.Version <= 0 || a.Status != store.SealedTaskHandoffProposed ||
		a.MessageID != record.MessageID || a.MessageDigest != record.Digest ||
		a.GroupID != record.Route.TargetGroupID || a.FromPrincipalID != record.Route.SourcePrincipalID ||
		a.FromEndpointID != record.Route.SourceEndpointID || a.ToPrincipalID != record.Route.TargetPrincipalID ||
		a.ToEndpointID != record.Route.TargetEndpointID || a.LocalRoute.NodeID != record.Route.SourceNodeID ||
		a.LocalRoute.NodeID != record.Route.TargetNodeID || a.LocalRoute.SenderProofDigest == "" ||
		a.LocalRoute.FromBindingID != record.Route.SourceBindingID ||
		a.LocalRoute.FromBindingEpoch != record.Route.SourceBindingEpoch ||
		a.LocalRoute.ToBindingID != record.Route.TargetBindingID ||
		a.LocalRoute.ToBindingEpoch != record.Route.TargetBindingEpoch ||
		a.LocalRoute.FromMembershipRevision != int64(record.Route.SourceMembershipRevision) ||
		a.LocalRoute.ToMembershipRevision != int64(record.Route.TargetMembershipRevision) ||
		a.LocalRoute.FromJoinRevision != int64(record.Route.SourceJoinRevision) ||
		a.LocalRoute.ToJoinRevision != int64(record.Route.TargetJoinRevision) ||
		a.LocalRoute.FromKeyID != record.Route.SourceKeyID || a.LocalRoute.ToKeyID != record.Route.TargetKeyID {
		return errors.New("local Task handoff delivery authorization does not match the stored route")
	}
	handoffID, deadline, ok := parseTaskHandoffMessageID(record.MessageID)
	expires, err := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	if !ok || handoffID != a.HandoffID || err != nil || deadline != expires ||
		deadline.Format(time.RFC3339Nano) != a.ExpiresAt || !deadline.After(time.Now().UTC()) {
		return errors.New("local Task handoff authorization has an invalid or expired deadline")
	}
	return nil
}

func localTaskHandoffPayloadMatches(record nodelocal.MessageRecord, authorization store.LocalDeliveryAuthorization,
	plaintext []byte) error {
	a := authorization.TaskHandoff
	reserved := bytes.HasPrefix([]byte(record.MessageID), []byte("shared-task-handoff.v1:"))
	if !reserved {
		if a != nil {
			return errors.New("ordinary local message unexpectedly has Task handoff authorization")
		}
		return nil
	}
	if a == nil || a.Transport != "LOCAL_NODE" || a.LocalRoute == nil ||
		a.MessageID != record.MessageID || a.MessageDigest != record.Digest ||
		a.GroupID != record.Route.TargetGroupID || a.FromEndpointID != record.Route.SourceEndpointID ||
		a.ToEndpointID != record.Route.TargetEndpointID || a.Status != store.SealedTaskHandoffProposed ||
		a.HandoffID == "" || a.TaskID == "" || a.Version <= 0 || a.LocalRoute.NodeID != record.Route.SourceNodeID ||
		a.LocalRoute.FromBindingID != record.Route.SourceBindingID || a.LocalRoute.FromBindingEpoch != record.Route.SourceBindingEpoch ||
		a.LocalRoute.ToBindingID != record.Route.TargetBindingID || a.LocalRoute.ToBindingEpoch != record.Route.TargetBindingEpoch ||
		a.LocalRoute.FromMembershipRevision != int64(record.Route.SourceMembershipRevision) ||
		a.LocalRoute.ToMembershipRevision != int64(record.Route.TargetMembershipRevision) ||
		a.LocalRoute.FromJoinRevision != int64(record.Route.SourceJoinRevision) ||
		a.LocalRoute.ToJoinRevision != int64(record.Route.TargetJoinRevision) ||
		a.LocalRoute.FromKeyID != record.Route.SourceKeyID || a.LocalRoute.ToKeyID != record.Route.TargetKeyID {
		return errors.New("local Task handoff delivery authorization does not match the stored route")
	}
	deadline, err := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	messageID, messageDeadline, ok := parseTaskHandoffMessageID(record.MessageID)
	if err != nil || !ok || messageID != a.HandoffID || !deadline.After(time.Now().UTC()) ||
		messageDeadline != deadline || deadline.Format(time.RFC3339Nano) != a.ExpiresAt {
		return errors.New("local Task handoff authorization has an invalid deadline")
	}
	packet, err := decodeSealedTaskHandoffPayload(plaintext)
	if err != nil || packet.HandoffID != a.HandoffID || packet.TaskID != a.TaskID ||
		packet.GroupID != a.GroupID || packet.FromPrincipalID != a.FromPrincipalID ||
		packet.FromEndpointID != a.FromEndpointID || packet.ToPrincipalID != a.ToPrincipalID ||
		packet.ToEndpointID != a.ToEndpointID || packet.TaskRevision != a.TaskRevision ||
		packet.FromOwnerEpoch != a.FromOwnerEpoch || packet.MessageID != a.MessageID ||
		packet.ExpiresAt != a.ExpiresAt {
		return errors.New("decrypted local Task handoff differs from its current Hub authorization")
	}
	wantRefs, err := json.Marshal(a.RequiredArtifactRefs)
	if err != nil {
		return err
	}
	gotRefs, err := json.Marshal(packet.RequiredArtifactRefs)
	if err != nil || !bytes.Equal(wantRefs, gotRefs) {
		return errors.New("decrypted local Task handoff Artifact references differ from authorization")
	}
	return nil
}
