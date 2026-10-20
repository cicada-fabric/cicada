package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func syntheticCodexOperatorTemplate() localEndpointRequest {
	q := syntheticLocalEndpointRequest("endpoint_register")
	q.RequestID = ""
	q.IssuedAt = ""
	return q
}

func syntheticCodexOperatorResult(q localEndpointRequest, node string) *localEndpointResult {
	return &localEndpointResult{RequestID: q.RequestID, IntentDigest: codexOperatorDigest(q, false), HubID: "synthetic-hub", NodeID: node, Operation: q.Operation, State: "COMPLETED", Registration: &nodewire.EndpointRegistrationResult{EndpointID: "synthetic-endpoint", Workspace: q.Workspace, Name: q.Name, Presence: "offline", StateDigest: strings.Repeat("a", 64)}}
}

func TestCodexOperatorLostReplyRetainsOriginalAndAckCAS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope", "operator-intent.json")
	c, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	q := syntheticCodexOperatorTemplate()
	node := "synthetic-node"
	var requests []localEndpointRequest
	c.exchange = func(_ string, original localEndpointRequest) (*localEndpointResult, error) {
		requests = append(requests, original)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var disk codexOperatorIntentDisk
		if json.Unmarshal(data, &disk) != nil || disk.Pending == nil || disk.Pending.Request != original {
			t.Fatal("IPC preceded original request persistence")
		}
		return nil, errors.New("synthetic lost IPC reply")
	}
	if _, err := c.call("synthetic-socket", q, node); err == nil {
		t.Fatal("lost response became success")
	}
	if err := c.ack(requests[0].RequestID, codexOperatorDigest(requests[0], false)); err == nil {
		t.Fatal("unknown intent could be acknowledged")
	}
	freshID := q
	now := time.Now().UTC()
	freshID.RequestID, _ = newLocalEndpointRequestID(now)
	freshID.IssuedAt = now.Format(time.RFC3339Nano)
	if original, err := c.prepare(freshID, node); err != nil || original != requests[0] {
		t.Fatal("same command did not recover its original ID/time")
	}
	for _, change := range []func(*localEndpointRequest){func(q *localEndpointRequest) { q.Name = "different command" }, func(q *localEndpointRequest) { q.NativeSessionID = "synthetic-other-thread" }, func(q *localEndpointRequest) { q.Workspace = "/synthetic/other" }, func(q *localEndpointRequest) { q.APIOrigin = "https://other.invalid" }} {
		changed := q
		change(&changed)
		if _, err := c.prepare(changed, node); !errors.Is(err, errCodexOperatorIntentConflict) {
			t.Fatal("changed command overwrote pending original", err)
		}
	}
	if _, err := c.prepare(q, "synthetic-other-node"); !errors.Is(err, errCodexOperatorIntentConflict) {
		t.Fatal("changed Node overwrote original")
	}
	restarted, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	restarted.exchange = func(_ string, original localEndpointRequest) (*localEndpointResult, error) {
		requests = append(requests, original)
		return syntheticCodexOperatorResult(original, node), nil
	}
	result, err := restarted.call("synthetic-socket", q, node)
	if err != nil || result == nil || len(requests) != 2 || requests[0] != requests[1] {
		t.Fatal("restart changed original ID/time/intent", err)
	}
	again, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	again.exchange = func(string, localEndpointRequest) (*localEndpointResult, error) {
		t.Fatal("private completion receipt was redispatched")
		return nil, nil
	}
	if _, err := again.call("synthetic-socket", q, node); err != nil {
		t.Fatal(err)
	}
	if err := again.ack(result.RequestID, result.IntentDigest); err != nil {
		t.Fatal(err)
	}
	if err := again.ack(result.RequestID, result.IntentDigest); err != nil {
		t.Fatal("ack retry is not idempotent", err)
	}
	q.Name = "later explicit command"
	later, err := again.prepare(q, node)
	if err != nil {
		t.Fatal(err)
	}
	if err := again.ack(result.RequestID, result.IntentDigest); !errors.Is(err, errCodexOperatorIntentConflict) {
		t.Fatal("old ACK deleted a later command")
	}
	still, err := again.prepare(q, node)
	if err != nil || still != later {
		t.Fatal("later command was changed by stale ACK")
	}
}

func TestCodexOperatorPersistenceFailureDoesNotLoseIntent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scope", "operator-intent.json")
	c, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	q := syntheticCodexOperatorTemplate()
	node := "synthetic-node"
	posts := 0
	c.exchange = func(_ string, q localEndpointRequest) (*localEndpointResult, error) {
		posts++
		return syntheticCodexOperatorResult(q, node), nil
	}
	c.persist = func(string, []byte, string) error { return errors.New("synthetic durable-write failure") }
	if _, err := c.call("synthetic-socket", q, node); !errors.Is(err, errCodexOperatorIntentPersistence) || posts != 0 {
		t.Fatal("prepare failure still issued IPC", err)
	}
	c.persist = persistNodeSecretFile
	original, err := c.prepare(q, node)
	if err != nil {
		t.Fatal(err)
	}
	c.persist = func(string, []byte, string) error { return errors.New("synthetic completion-save failure") }
	if _, err := c.call("synthetic-socket", q, node); !errors.Is(err, errCodexOperatorIntentPersistence) || posts != 1 {
		t.Fatal("completion-save failure was hidden", err)
	}
	restarted, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := restarted.prepare(q, node)
	if err != nil || retained != original {
		t.Fatal("save failure lost original request")
	}
	if err := restarted.ack(original.RequestID, codexOperatorDigest(original, false)); err == nil {
		t.Fatal("unsaved result could be acknowledged")
	}
	restarted.exchange = func(_ string, q localEndpointRequest) (*localEndpointResult, error) {
		if q != original {
			t.Fatal("save failure regenerated request")
		}
		return syntheticCodexOperatorResult(q, node), nil
	}
	if _, err := restarted.call("synthetic-socket", q, node); err != nil {
		t.Fatal(err)
	}
}

func TestCodexOperatorReplyBindingAndMissingCredentialCannotAck(t *testing.T) {
	for _, kind := range []string{"node", "digest", "request", "operation", "hub", "missing_payload", "missing_credential", "unknown", "forged_refusal"} {
		t.Run(kind, func(t *testing.T) {
			c, err := openCodexOperatorIntent(filepath.Join(t.TempDir(), "scope", "operator-intent.json"))
			if err != nil {
				t.Fatal(err)
			}
			q := syntheticCodexOperatorTemplate()
			if kind == "missing_credential" {
				q.Operation = "native_pair_join_named"
				q.Name = ""
				q.PairLabel = "Synthetic pair"
				q.Slot = "A"
			}
			node := "synthetic-node"
			c.exchange = func(_ string, q localEndpointRequest) (*localEndpointResult, error) {
				r := syntheticCodexOperatorResult(q, node)
				switch kind {
				case "node":
					r.NodeID = "other"
				case "digest":
					r.IntentDigest = strings.Repeat("b", 64)
				case "request":
					r.RequestID = strings.Repeat("c", 32)
				case "operation":
					r.Operation = "endpoint_leave"
				case "hub":
					r.HubID = ""
				case "missing_payload":
					r.Registration = nil
				case "missing_credential":
					r.Registration = nil
					r.Join = &fabric.JoinResult{Endpoint: store.Endpoint{ID: "synthetic-endpoint", PrincipalID: "synthetic-principal", GroupID: "synthetic-group", MachineID: node, Harness: q.Harness, NativeSessionID: q.NativeSessionID, Workspace: q.Workspace}, BindingID: "synthetic-binding", BindingEpoch: 1}
				case "unknown":
					r.State = "UNKNOWN"
					return r, errors.New("synthetic uncertain")
				case "forged_refusal":
					r.State = "REFUSED"
					r.Registration = nil
					return r, errors.New("arbitrary unsigned HTTP error")
				}
				return r, nil
			}
			if _, err := c.call("synthetic-socket", q, node); err == nil {
				t.Fatal("invalid reply became completion")
			}
			original, err := c.prepare(q, node)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.ack(original.RequestID, codexOperatorDigest(original, false)); err == nil {
				t.Fatal("invalid/unknown reply could be acknowledged")
			}
		})
	}
}

func TestCodexOperatorPrivateFilesRejectAliasesAndTampering(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := openCodexOperatorIntent(filepath.Join(alias, "operator-intent.json")); err == nil {
		t.Fatal("symlink directory accepted")
	}
	path := filepath.Join(target, "operator-intent.json")
	c, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.prepare(syntheticCodexOperatorTemplate(), "synthetic-node"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := c.prepare(syntheticCodexOperatorTemplate(), "synthetic-node"); err == nil {
		t.Fatal("nonprivate original file accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var disk codexOperatorIntentDisk
	if json.Unmarshal(data, &disk) != nil {
		t.Fatal("invalid fixture")
	}
	disk.Pending.Request.Name = "tampered"
	data, _ = json.Marshal(disk)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.prepare(syntheticCodexOperatorTemplate(), "synthetic-node"); err == nil {
		t.Fatal("corrupted full intent hash accepted")
	}
}

func TestCodexOperatorProcessPrepare(t *testing.T) {
	if os.Getenv("CICADA_OPERATOR_INTENT_TEST_ROLE") != "child" {
		return
	}
	path := os.Getenv("CICADA_OPERATOR_INTENT_TEST_PATH")
	output := os.Getenv("CICADA_OPERATOR_INTENT_TEST_OUTPUT")
	c, err := openCodexOperatorIntent(path)
	if err != nil {
		t.Fatal(err)
	}
	var q localEndpointRequest
	for i := 0; i < 100; i++ {
		q, err = c.prepare(syntheticCodexOperatorTemplate(), "synthetic-node")
		if !errors.Is(err, errCodexOperatorIntentBusy) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(q)
	if err := os.WriteFile(output, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCodexOperatorTwoProcessesShareOneOriginal(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "scope", "operator-intent.json")
	outputs := []string{filepath.Join(root, "first.json"), filepath.Join(root, "second.json")}
	commands := make([]*exec.Cmd, 2)
	for i := range commands {
		commands[i] = exec.Command(os.Args[0], "-test.run=^TestCodexOperatorProcessPrepare$")
		commands[i].Env = append(os.Environ(), "CICADA_OPERATOR_INTENT_TEST_ROLE=child", "CICADA_OPERATOR_INTENT_TEST_PATH="+path, "CICADA_OPERATOR_INTENT_TEST_OUTPUT="+outputs[i])
		if err := commands[i].Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatal("synthetic process prepare failed", err)
		}
	}
	var first, second localEndpointRequest
	for i, q := range []*localEndpointRequest{&first, &second} {
		data, err := os.ReadFile(outputs[i])
		if err != nil || json.Unmarshal(data, q) != nil {
			t.Fatal("invalid child original")
		}
	}
	if first.RequestID == "" || first != second {
		t.Fatal("two processes allocated different original intents")
	}
}

func TestCodexOperatorActualIPCJoinSavedBeforeAck(t *testing.T) {
	f := newNativePairTCPConsumerFixture(t)
	ctx := harness.SessionContext{Harness: "codex", NativeSessionID: f.native[0], MachineID: f.nodeID, Workspace: f.workspace}
	scope, trusted, err := mcpSessionScope(f.server.URL, ctx)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(f.root, "mcp", "sessions.json")
	c, err := openCodexOperatorIntent(filepath.Join(filepath.Dir(base), "scopes", scope, "operator-intent.json"))
	if err != nil {
		t.Fatal(err)
	}
	q := localEndpointRequest{Version: 1, Operation: "native_pair_join_named", APIOrigin: f.server.URL, Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID, Workspace: trusted.Workspace, PairLabel: "Synthetic consumer pair", Slot: "A"}
	f.mu.Lock()
	f.dropJoin = 1
	f.mu.Unlock()
	if r, err := c.call(f.bridge.path, q, f.nodeID); err == nil || r == nil || r.State != "UNKNOWN" {
		t.Fatal("lost real Hub ACK became completion")
	}
	restarted, err := openCodexOperatorIntent(c.path)
	if err != nil {
		t.Fatal(err)
	}
	result, err := restarted.call(f.bridge.path, q, f.nodeID)
	if err != nil || result == nil || result.Join == nil {
		t.Fatal("actual original Join could not recover", err)
	}
	store := newMCPSessionStateStore(base)
	j := result.Join
	entry := mcpCachedSession{Scope: scope, APIOrigin: q.APIOrigin, Harness: q.Harness, NativeSessionID: q.NativeSessionID, NodeID: f.nodeID, Workspace: q.Workspace, GroupID: j.Endpoint.GroupID, EndpointID: j.Endpoint.ID, BindingID: j.BindingID, BindingEpoch: j.BindingEpoch, SessionToken: j.SessionToken}
	if err := store.save(entry); err != nil {
		t.Fatal(err)
	}
	if err := restarted.ack(result.RequestID, result.IntentDigest); err != nil {
		t.Fatal(err)
	}
	saved, err := store.load(q.APIOrigin, ctx)
	if err != nil || saved == nil || !reflect.DeepEqual(*saved, entry) {
		t.Fatal("ack preceded actual existing session-store persistence", err)
	}
}
