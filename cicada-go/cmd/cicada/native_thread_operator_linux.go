//go:build linux

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/apppaths"
	"github.com/cicada-ai/cicada/internal/harness"
)

// A Thread ID is a filename/header selector under the actual owned Runtime
// record root. Ancestry, ambient SID variables and model input never establish
// a caller. Only exact matching records are opened, not the history payload.
func nativeThreadOperatorRecord(sid string) (string, string, error) {
	if !localContextText(sid, 128) {
		return "", "", errCodexMCPContext
	}
	for _, c := range sid {
		if c != '-' && c != '_' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			return "", "", errCodexMCPContext
		}
	}
	root := strings.TrimSpace(os.Getenv("CODEX_HOME"))
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", "", err
		}
		root = filepath.Join(home, ".codex")
	}
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", "", errCodexMCPContext
	}
	paths, err := filepath.Glob(filepath.Join(root, "sessions", "*", "*", "*", "rollout-*-"+sid+".jsonl"))
	if err != nil || len(paths) != 1 {
		return "", "", errors.New("Thread selector needs one exact original owned Codex record")
	}
	path := paths[0]
	f, err := os.Open(path)
	if err != nil {
		return "", "", errCodexMCPContext
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 1<<20))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for line := 0; line < 8 && scanner.Scan(); line++ {
		var meta codexSessionRecordMeta
		if json.Unmarshal(scanner.Bytes(), &meta) != nil || meta.Type != "session_meta" {
			continue
		}
		if meta.Payload.ID != sid || meta.Payload.SessionID != "" && meta.Payload.SessionID != sid {
			return "", "", errCodexMCPContext
		}
		workspace, err := filepath.EvalSymlinks(meta.Payload.CWD)
		if err != nil || !filepath.IsAbs(workspace) || verifyCodexContextTranscriptProfile(path, sid, workspace, true) != nil {
			return "", "", errCodexMCPContext
		}
		return path, workspace, nil
	}
	return "", "", errCodexMCPContext
}

func nativeThreadOperatorCommand(action string, args []string, out io.Writer) error {
	return nativeThreadOperatorWithManager(action, args, out, ListLocalNodeHubConnections, ResolveAdoptedLocalNodeConnection, ValidateRetainedLocalNodeArtifacts)
}

type nativeThreadHubListFunc func(context.Context, string) (LocalNodeHubList, error)

func nativeThreadHubAlias(ctx context.Context, root, alias, node string, list nativeThreadHubListFunc) (LocalNodeHubView, error) {
	var zero LocalNodeHubView
	if list == nil || !localNodeHubText(alias, 128) {
		return zero, ErrLocalNodeHubConfig
	}
	view, err := list(ctx, root)
	if err != nil {
		return zero, err
	}
	raw, err := json.Marshal(view)
	if err != nil {
		return zero, ErrLocalNodeHubConfig
	}
	if _, err := DecodeLocalNodeHubList(raw); err != nil {
		return zero, err
	}
	var found *LocalNodeHubView
	for _, connection := range view.Connections {
		if !strings.EqualFold(connection.Alias, alias) {
			continue
		}
		if connection.DesiredState != "ENABLED" || connection.HubID == "" || node != "" && node != connection.NodeID {
			return zero, ErrLocalNodeNotReady
		}
		if found != nil {
			return zero, ErrLocalNodeSelectionAmbiguous
		}
		copy := connection
		found = &copy
	}
	if found == nil {
		return zero, ErrLocalNodeNotRunning
	}
	return *found, nil
}

func nativeThreadOperatorWithManager(action string, args []string, out io.Writer, list nativeThreadHubListFunc, adopt codexAdoptionResolver, validators ...codexArtifactValidator) error {
	if action != "join" && action != "leave" {
		return errors.New("unsupported Thread operator action")
	}
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	thread := flags.String("thread", "", "exact original Codex Thread ID selector")
	name := flags.String("name", "", "registration name")
	rootArg := flags.String("user-root", "", "selected Cicada user root")
	hubID := flags.String("hub-id", "", "exact Hub selection")
	hubAlias := flags.String("hub", "", "exact enabled Hub alias in this installation")
	nodeID := flags.String("node-id", "", "exact Node selection")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || *thread == "" || action == "leave" && *name != "" || action == "join" && (!localContextText(*name, 256) || strings.TrimSpace(*name) != *name) {
		return errors.New("usage: cicada join --thread ID --name NAME [--user-root ABS] [--hub ALIAS | --hub-id ID] [--node-id ID]; cicada leave --thread ID [same selection flags]")
	}
	selected := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { selected[f.Name] = true })
	if selected["hub"] && (selected["hub-id"] || !localNodeHubText(*hubAlias, 128)) {
		return ErrLocalNodeHubConfig
	}
	path, workspace, err := nativeThreadOperatorRecord(*thread)
	if err != nil {
		return err
	}
	root, err := apppaths.ResolveUserRoot(*rootArg)
	if err != nil {
		return err
	}
	selection := LocalNodeSelection{UserRoot: root, HubID: *hubID, NodeID: *nodeID}
	var alias *LocalNodeHubView
	if selected["hub"] {
		view, err := nativeThreadHubAlias(context.Background(), root, *hubAlias, *nodeID, list)
		if err != nil {
			return codexLocalNodeError(err)
		}
		alias = &view
		selection.HubID, selection.NodeID = view.HubID, view.NodeID
	}
	connection, err := ResolveLocalNodeConnection(context.Background(), selection, nil)
	if err != nil {
		return codexLocalNodeError(err)
	}
	if alias != nil && (connection.Pin.ConnectionID != alias.ConnectionID || connection.Pin.ConnectionEpoch != alias.LocalFence) {
		return codexLocalNodeError(ErrLocalNodeBindingChanged)
	}
	native := harness.SessionContext{Harness: "codex", NativeSessionID: *thread, MachineID: connection.Pin.NodeID, Workspace: workspace}
	scope, trusted, err := mcpSessionScope(connection.Pin.APIOrigin, native)
	if err != nil {
		return err
	}
	operation := "endpoint_register"
	if action == "leave" {
		operation = "endpoint_leave"
	}
	q := localEndpointRequest{Version: 1, Operation: operation, APIOrigin: connection.Pin.APIOrigin, Harness: "codex", NativeSessionID: *thread, Workspace: workspace, Name: *name}
	client, err := openCodexOperatorIntent(filepath.Join(filepath.Dir(connection.Pin.MCPSessionStateFile), "scopes", scope, "operator-intent.json"))
	if err != nil {
		return err
	}
	client.adoptConnection = adopt
	var retained codexArtifactValidator
	if len(validators) > 0 {
		retained = validators[0]
	}
	client.retainedArtifacts = retained
	client.retainedInvocation = nativeThreadRetainedIntentAuthorizer(*thread, path, workspace, operation, native)
	storagePin := &connection.Pin
	cached, err := newMCPSessionStateStore(connection.Pin.MCPSessionStateFile).load(q.APIOrigin, native)
	if err != nil {
		return err
	}
	if err := validateCodexCachedArtifact(cached, &connection, adopt, retained); err != nil {
		return err
	}
	if cached != nil && cached.ConnectionPin != nil {
		storagePin = cached.ConnectionPin
	}
	q, recovering, err := client.pendingDomainJoin(q, connection.Pin.NodeID, &connection.Pin)
	if err != nil {
		return err
	}
	var verified codexDomainBinding
	if !recovering {
		var proof endpointGroupsOperatorContextProof
		verified, err = verifyCodexOperatorInvocation(path, "", "", *name, native, q.APIOrigin, &connection, codexOperatorCommand{operation: operation, name: *name}, &proof)
		if err != nil {
			return err
		}
		if operation == "endpoint_register" {
			q.LocalDomainVersion, q.LocalDomain = verified.LocalDomainVersion, verified.LocalDomain
		}
		if verified.EndpointGroupsVersion == 1 {
			q.codexEndpointGroupsBinding = verified.codexEndpointGroupsBinding
			q.endpointGroupsOperatorContextProof = proof
		}
	}
	q, err = client.originalVerifiedCommand(q, connection.Pin.NodeID, &connection.Pin)
	if err != nil {
		return err
	}
	q, err = client.prepareForConnection(q, connection)
	if err != nil {
		return err
	}
	if err := revalidateCodexLocalNode(context.Background(), &connection); err != nil {
		return err
	}
	if q.EndpointGroupsVersion == 1 {
		q.InvocationProof, _ = endpointGroupsFreshOperatorProof(path, "", "", native, &connection, q)
	}
	result, err := client.callForConnection(q, connection)
	if err != nil {
		return err
	}
	if result == nil || result.State != "COMPLETED" {
		return errors.New("original Thread operation is unconfirmed; retry the exact command")
	}
	if result.Join != nil {
		if recovering {
			verified, _ = verifyCodexOperatorInvocation(path, "", "", *name, native, q.APIOrigin, &connection, codexOperatorCommand{operation: operation, name: *name}, nil)
		}
		if result.LocalDomain == nil || verified.LocalDomainVersion == q.LocalDomainVersion && verified.LocalDomain == q.LocalDomain {
			j := result.Join
			if err := newMCPSessionStateStore(connection.Pin.MCPSessionStateFile).save(mcpCachedSession{ConnectionPin: storagePin, Scope: scope, APIOrigin: q.APIOrigin, Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID, Workspace: trusted.Workspace, GroupID: j.Endpoint.GroupID, EndpointID: j.Endpoint.ID, OwnerID: j.Endpoint.Owner, BindingID: j.BindingID, BindingEpoch: j.BindingEpoch, LeaseExpiresAt: j.LeaseExpiresAt, SessionToken: j.SessionToken, codexDomainBinding: codexDomainBinding{LocalDomainVersion: q.LocalDomainVersion, LocalDomain: q.LocalDomain}}); err != nil {
				return err
			}
		}
	}
	if operation == "endpoint_leave" {
		if err := newMCPSessionStateStore(connection.Pin.MCPSessionStateFile).remove(scope); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(out, formatCodexOperatorResult(codexOperatorCommand{operation: operation}, result)); err != nil {
		return err
	}
	return client.ack(result.RequestID, result.IntentDigest)
}

// Only the terminal operator configures this private authorizer. Reading an
// old journal, UserPrompt or cached runtime frame cannot supply this identity.
func nativeThreadRetainedIntentAuthorizer(thread, path, workspace, operation string, native harness.SessionContext) codexRetainedIntentAuthorizer {
	return func(original localEndpointRequest, current LocalNodeConnection) (*endpointGroupsOperatorContextProof, error) {
		currentPath, currentWorkspace, err := nativeThreadOperatorRecord(thread)
		if err != nil || currentPath != path || currentWorkspace != workspace || original.Harness != native.Harness || original.NativeSessionID != native.NativeSessionID || original.Workspace != workspace || original.APIOrigin != current.Pin.APIOrigin || original.Operation != operation || current.Pin.NodeID != native.MachineID {
			return nil, errCodexMCPContext
		}
		return endpointGroupsFreshOperatorProof(currentPath, "", "", native, &current, original)
	}
}
