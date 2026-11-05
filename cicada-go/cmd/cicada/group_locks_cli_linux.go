//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/cicada-ai/cicada/internal/apppaths"
	"github.com/cicada-ai/cicada/internal/harness"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func groupLocksOperatorCommand(action string, args []string, out io.Writer) error {
	opts, err := parseGroupLocksCLIArguments(action, args)
	if err != nil {
		return err
	}
	path, workspace, err := nativeThreadOperatorRecord(opts.Thread)
	if err != nil {
		return err
	}
	root, err := apppaths.ResolveUserRoot(opts.UserRoot)
	if err != nil {
		return err
	}
	ctx := context.Background()
	selection := LocalNodeSelection{UserRoot: root, HubID: opts.HubID, NodeID: opts.NodeID}
	var alias *LocalNodeHubView
	if opts.HubAlias != "" {
		view, err := nativeThreadHubAlias(ctx, root, opts.HubAlias, opts.NodeID, ListLocalNodeHubConnections)
		if err != nil {
			return codexLocalNodeError(err)
		}
		alias = &view
		selection.HubID, selection.NodeID = view.HubID, view.NodeID
	}
	connection, err := ResolveLocalNodeConnection(ctx, selection, nil)
	if err != nil {
		return codexLocalNodeError(err)
	}
	if alias != nil && (connection.Pin.ConnectionID != alias.ConnectionID || connection.Pin.ConnectionEpoch != alias.LocalFence) {
		return codexLocalNodeError(ErrLocalNodeBindingChanged)
	}
	native := harness.SessionContext{Harness: "codex", NativeSessionID: opts.Thread, MachineID: connection.Pin.NodeID, Workspace: workspace}
	expectedScope, trusted, err := mcpSessionScope(connection.Pin.APIOrigin, native)
	if err != nil {
		return err
	}
	cached, err := newMCPSessionStateStore(connection.Pin.MCPSessionStateFile).load(connection.Pin.APIOrigin, native)
	if err != nil {
		return err
	}
	if err := validateCodexCachedArtifact(cached, &connection, ResolveAdoptedLocalNodeConnection, ValidateRetainedLocalNodeArtifacts); err != nil {
		return err
	}
	// Cache supplies a selector only. The private Node revalidates the exact
	// registration, Group authority and local access fence below.
	if opts.GroupID == "" && cached != nil {
		opts.GroupID = cached.GroupID
	}
	if opts.GroupID == "" {
		return errEndpointGroupsSelection
	}
	opts.Arguments["group_id"] = opts.GroupID
	raw, err := json.Marshal(opts.Arguments)
	if err != nil {
		return err
	}
	digest, err := codexArgumentsDigest(opts.Arguments)
	if err != nil {
		return err
	}
	var proof endpointGroupsOperatorContextProof
	binding, err := verifyCodexOperatorInvocationArguments(path, "", "", native, connection.Pin.APIOrigin, &connection, codexOperatorCommand{operation: opts.Operation}, opts.Arguments, &proof)
	if err != nil || binding.EndpointGroupsVersion != 1 {
		return errCodexMCPContext
	}
	q := localThreadCollaborationRequest{
		localEndpointGroupsRequest: localEndpointGroupsRequest{
			Version: localJoinProtocolVersion, Operation: opts.Operation, APIOrigin: connection.Pin.APIOrigin,
			Harness: native.Harness, NativeSessionID: native.NativeSessionID, Workspace: native.Workspace,
			ContextTicketID: proof.ContextTicketID, ConnectionNonce: proof.ContextConnectionNonce,
			ToolName: codexOperatorContextTool(opts.Operation), ArgumentsDigest: digest, Arguments: raw,
			GroupID: opts.GroupID, codexEndpointGroupsBinding: binding.codexEndpointGroupsBinding,
		},
		Operator: &proof,
	}
	var scope mcpOutboxScope
	var store *mcpOutboxStore
	var prior *mcpOutboxOperation
	if opts.Operation != wire.OperationGroupLocksRead {
		store, err = groupLocksOperatorOutbox(ctx, connection)
		if err != nil {
			return err
		}
		defer store.close()
		selector := mcpOutboxScope{APIOrigin: connection.Pin.APIOrigin, Scope: expectedScope, Harness: native.Harness, NativeSessionID: native.NativeSessionID, NodeID: native.MachineID, Workspace: native.Workspace, GroupID: opts.GroupID}
		prior, err = store.findGroupLockOperatorOriginal(selector, opts.Operation, opts.Key, opts.Intent.Slot, opts.Recover)
		if err != nil {
			return err
		}
		if opts.Recover && prior == nil {
			return errMCPOutboxNotFound
		}
	}
	if prior != nil {
		verified, _, err := readMCPFacadeOperation(connection.Pin, trusted, prior.OperationID)
		if err != nil || verified != *prior {
			return errMCPOutboxContext
		}
		scope = groupLockOriginalOutboxScope(*prior)
	} else {
		q, scope, err = prepareThreadCollaborationOutboxScope(ctx, connection.Pin.SocketPath, q)
		if err != nil {
			return err
		}
	}
	relation := scope.EndpointGroupAuthority.Relation
	if scope.APIOrigin != connection.Pin.APIOrigin || scope.Scope != expectedScope || scope.Harness != native.Harness || scope.NativeSessionID != native.NativeSessionID || scope.NodeID != native.MachineID || scope.Workspace != native.Workspace || scope.GroupID != opts.GroupID || scope.EndpointID == "" || scope.NetworkID != "" || scope.codexOutboxBinding.validate() != nil || scope.codexEndpointGroupsBinding != binding.codexEndpointGroupsBinding || relation.HubID != connection.Pin.HubID || relation.GroupID != opts.GroupID || relation.EndpointID != scope.EndpointID {
		return errCodexMCPContext
	}
	lockScope := wire.GroupLockScope{HubID: relation.HubID, NetworkID: relation.NetworkID, GroupID: relation.GroupID}
	if opts.Operation == wire.OperationGroupLocksRead {
		if err := freshGroupLocksOperatorRequest(&q, opts, path, native, &connection, binding); err != nil {
			return err
		}
		q.Scope = &lockScope
		result, err := requestMachineAgentThreadCollaboration(ctx, connection.Pin.SocketPath, q)
		if err != nil {
			return err
		}
		if result == nil || result.Operation != opts.Operation || result.Receipt != nil || result.Locks == nil || wire.ValidateGroupSlotView(*result.Locks) != nil || result.Locks.Scope != lockScope {
			return errCodexMCPContext
		}
		return json.NewEncoder(out).Encode(result.Locks)
	}
	opts.Intent.Scope = lockScope
	input := mcpOutboxInput{GroupLock: &opts.Intent}
	var op mcpOutboxOperation
	if prior != nil {
		if prior.IdempotencyKey == opts.Key {
			var saved mcpOutboxInput
			if json.Unmarshal([]byte(prior.InputJSON), &saved) != nil || !groupLockInputsEqual(saved, input) {
				return errMCPOutboxConflict
			}
		}
		op = *prior
		if !opts.Recover || op.Status == mcpOutboxStatusSent || op.Status == mcpOutboxStatusFailed {
			return json.NewEncoder(out).Encode(mcpOutboxPublicResult(op))
		}
	} else {
		var created bool
		op, created, err = store.prepare(scope, opts.Operation, opts.Key, input)
		if err != nil {
			return err
		}
		if !created {
			return json.NewEncoder(out).Encode(mcpOutboxPublicResult(op))
		}
	}
	if err := freshGroupLocksOperatorRequest(&q, opts, path, native, &connection, binding); err != nil {
		return err
	}
	op, err = store.markAttempt(scope, op.OperationID)
	if err != nil {
		if errors.Is(err, errMCPOutboxTerminal) {
			return json.NewEncoder(out).Encode(mcpOutboxPublicResult(op))
		}
		return err
	}
	result, err := sendGroupLockOutbox(ctx, connection.Pin.SocketPath, store, scope, op, q)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(result)
}

func freshGroupLocksOperatorRequest(q *localThreadCollaborationRequest, opts groupLocksCLIOptions, path string, native harness.SessionContext, connection *LocalNodeConnection, binding codexDomainBinding) error {
	currentPath, workspace, err := nativeThreadOperatorRecord(opts.Thread)
	if err != nil || currentPath != path || workspace != native.Workspace {
		return errCodexMCPContext
	}
	if err := revalidateCodexLocalNode(context.Background(), connection); err != nil {
		return err
	}
	var proof endpointGroupsOperatorContextProof
	verified, err := verifyCodexOperatorInvocationArguments(path, "", "", native, connection.Pin.APIOrigin, connection, codexOperatorCommand{operation: opts.Operation}, opts.Arguments, &proof)
	if err != nil || verified != binding {
		return errCodexMCPContext
	}
	if err := revalidateCodexLocalNode(context.Background(), connection); err != nil {
		return err
	}
	q.ContextOnly, q.ContextTicketID, q.ConnectionNonce, q.Operator = false, proof.ContextTicketID, proof.ContextConnectionNonce, &proof
	q.Scope, q.Acquire, q.Renew, q.Release = nil, nil, nil, nil
	return nil
}

func groupLocksOperatorOutbox(ctx context.Context, connection LocalNodeConnection) (*mcpOutboxStore, error) {
	store := newMCPOutbox(connection.Pin.MCPOutboxStateFile)
	store.connectionPin = &connection.Pin
	original, err := readCodexOriginalOutboxPin(store.path)
	if err != nil {
		return nil, err
	}
	if original != nil && !sameLocalNodeAuthority(*original, connection.Pin) {
		if err := validateCodexStoredArtifact(ctx, *original, connection.Pin, ResolveAdoptedLocalNodeConnection, ValidateRetainedLocalNodeArtifacts); err != nil {
			return nil, codexLocalNodeError(err)
		}
		store.connectionPin = original
	}
	return store, nil
}
