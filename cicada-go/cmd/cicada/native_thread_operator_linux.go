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
	if action != "join" && action != "leave" {
		return errors.New("unsupported Thread operator action")
	}
	flags := flag.NewFlagSet(action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	thread := flags.String("thread", "", "exact original Codex Thread ID selector")
	name := flags.String("name", "", "registration name")
	rootArg := flags.String("user-root", "", "selected Cicada user root")
	hubID := flags.String("hub-id", "", "exact Hub selection")
	nodeID := flags.String("node-id", "", "exact Node selection")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || *thread == "" || action == "leave" && *name != "" || action == "join" && (!localContextText(*name, 256) || strings.TrimSpace(*name) != *name) {
		return errors.New("usage: cicada join --thread ID --name NAME [--user-root ABS] [--hub-id ID] [--node-id ID]; cicada leave --thread ID [same selection flags]")
	}
	path, workspace, err := nativeThreadOperatorRecord(*thread)
	if err != nil {
		return err
	}
	root, err := apppaths.ResolveUserRoot(*rootArg)
	if err != nil {
		return err
	}
	connection, err := ResolveLocalNodeConnection(context.Background(), LocalNodeSelection{UserRoot: root, HubID: *hubID, NodeID: *nodeID}, nil)
	if err != nil {
		return codexLocalNodeError(err)
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
			if err := newMCPSessionStateStore(connection.Pin.MCPSessionStateFile).save(mcpCachedSession{ConnectionPin: &connection.Pin, Scope: scope, APIOrigin: q.APIOrigin, Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID, Workspace: trusted.Workspace, GroupID: j.Endpoint.GroupID, EndpointID: j.Endpoint.ID, OwnerID: j.Endpoint.Owner, BindingID: j.BindingID, BindingEpoch: j.BindingEpoch, LeaseExpiresAt: j.LeaseExpiresAt, SessionToken: j.SessionToken, codexDomainBinding: codexDomainBinding{LocalDomainVersion: q.LocalDomainVersion, LocalDomain: q.LocalDomain}}); err != nil {
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
