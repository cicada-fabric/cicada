package nodeinbox

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func nativeContextHistoryInput() NativeContextScopeInput {
	return NativeContextScopeInput{
		AccountID: "synthetic-account", Harness: "codex", NativeSessionID: "synthetic-thread",
		HubID: "hub-a", NetworkID: "network-a", GroupID: "group-a",
		ContextPolicy: NativeContextPolicyGroupScoped, EndpointID: "endpoint-a",
		BindingID: "binding-a", BindingEpoch: 1,
	}
}

func nativeContextHistoryTestPath(t *testing.T) string {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(directory, "native-context.sqlite3")
}

func TestNativeContextHistoryFreshScopeReportsCicadaOnlyCoverage(t *testing.T) {
	registry, err := OpenNativeContextRegistry(nativeContextHistoryTestPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()

	decision, err := registry.CheckAndRecordNativeContext(context.Background(), nativeContextHistoryInput())
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Accepted || decision.SharedMemoryRisk || decision.KnownScopeCount != 1 ||
		decision.NativeHistoryCoverage != NativeContextHistoryCoverageCicadaKnownOnly {
		t.Fatalf("fresh registry decision overstated native-history coverage: %#v", decision)
	}
	encoded, err := json.Marshal(decision)
	if err != nil {
		t.Fatal(err)
	}
	var projection map[string]any
	if err := json.Unmarshal(encoded, &projection); err != nil {
		t.Fatal(err)
	}
	if projection["native_history_coverage"] != NativeContextHistoryCoverageCicadaKnownOnly ||
		projection["shared_memory_risk"] != false {
		t.Fatalf("native context projection omitted its partial-knowledge status: %s", encoded)
	}
}

func TestNativeContextHistoryAcceptsGroupOnlyScopeWithoutNetworkID(t *testing.T) {
	for _, policy := range []string{
		NativeContextPolicyGroupScoped,
		NativeContextPolicyDedicatedThread,
	} {
		t.Run(policy, func(t *testing.T) {
			registry, err := OpenNativeContextRegistry(nativeContextHistoryTestPath(t))
			if err != nil {
				t.Fatal(err)
			}
			defer registry.Close()
			input := nativeContextHistoryInput()
			input.NetworkID = ""
			input.ContextPolicy = policy
			decision, err := registry.CheckAndRecordNativeContext(context.Background(), input)
			if err != nil || decision == nil || !decision.Accepted || decision.ContextPolicy != policy {
				t.Fatalf("Group-only scope with no Network was rejected: decision=%#v err=%v", decision, err)
			}
		})
	}
}

func TestNativeContextHistoryRequiresNetworkIDForNetworkOnlyAndDedicatedNetwork(t *testing.T) {
	t.Run("network-only scope", func(t *testing.T) {
		input := nativeContextHistoryInput()
		input.GroupID, input.NetworkID = "", ""
		if _, _, _, err := normalizeNativeContextScopeInput(input); !errors.Is(err, ErrNativeContextScopeInvalid) {
			t.Fatalf("scope without a Group or Network was accepted: %v", err)
		}
	})
	t.Run("dedicated Network", func(t *testing.T) {
		input := nativeContextHistoryInput()
		input.NetworkID = ""
		input.ContextPolicy = NativeContextPolicyDedicatedNetwork
		if _, _, _, err := normalizeNativeContextScopeInput(input); !errors.Is(err, ErrNativeContextScopeInvalid) {
			t.Fatalf("dedicated Network without a Network ID was accepted: %v", err)
		}
	})
}

func TestNativeContextHistoryDedicatedPoliciesAreSymmetricAndRetained(t *testing.T) {
	t.Run("dedicated thread survives leave and rebind", func(t *testing.T) {
		path := nativeContextHistoryTestPath(t)
		registry, err := OpenNativeContextRegistry(path)
		if err != nil {
			t.Fatal(err)
		}
		first := nativeContextHistoryInput()
		first.ContextPolicy = NativeContextPolicyDedicatedThread
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		if err := registry.Close(); err != nil {
			t.Fatal(err)
		}
		registry, err = OpenNativeContextRegistry(path)
		if err != nil {
			t.Fatal(err)
		}
		defer registry.Close()

		// A new Endpoint and binding after leaving the old Group must not erase
		// the durable dedicated Thread association.
		rebound := first
		rebound.GroupID, rebound.EndpointID, rebound.BindingID, rebound.BindingEpoch =
			"group-b", "endpoint-b", "binding-b", 2
		rebound.ContextPolicy = NativeContextPolicyGroupScoped
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), rebound); !errors.Is(err, ErrNativeContextScopeConflict) {
			t.Fatalf("leave/rebind bypassed prior dedicated Thread history: %v", err)
		}

		// Rebinding within the exact authorized scope is allowed, but does not
		// claim any broader knowledge of native Runtime history.
		sameScopeRebind := first
		sameScopeRebind.EndpointID, sameScopeRebind.BindingID, sameScopeRebind.BindingEpoch =
			"endpoint-rebound", "binding-rebound", 3
		sameScopeRebind.ContextPolicy = NativeContextPolicyGroupScoped
		decision, err := registry.CheckAndRecordNativeContext(context.Background(), sameScopeRebind)
		if err != nil || decision.NativeHistoryCoverage != NativeContextHistoryCoverageCicadaKnownOnly {
			t.Fatalf("same-scope rebind failed or overstated coverage: decision=%#v err=%v", decision, err)
		}
	})

	t.Run("current dedicated Thread rejects prior ordinary scope", func(t *testing.T) {
		registry, err := OpenNativeContextRegistry(nativeContextHistoryTestPath(t))
		if err != nil {
			t.Fatal(err)
		}
		defer registry.Close()
		first := nativeContextHistoryInput()
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		current := first
		current.GroupID, current.EndpointID, current.BindingID, current.BindingEpoch =
			"group-b", "endpoint-b", "binding-b", 2
		current.ContextPolicy = NativeContextPolicyDedicatedThread
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), current); !errors.Is(err, ErrNativeContextScopeConflict) {
			t.Fatalf("new dedicated Thread policy ignored prior ordinary scope: %v", err)
		}
	})

	t.Run("dedicated Network allows same Network but blocks another Network", func(t *testing.T) {
		registry, err := OpenNativeContextRegistry(nativeContextHistoryTestPath(t))
		if err != nil {
			t.Fatal(err)
		}
		defer registry.Close()
		first := nativeContextHistoryInput()
		first.ContextPolicy = NativeContextPolicyDedicatedNetwork
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		sameNetwork := first
		sameNetwork.GroupID, sameNetwork.EndpointID, sameNetwork.BindingID, sameNetwork.BindingEpoch =
			"group-b", "endpoint-b", "binding-b", 2
		sameNetwork.ContextPolicy = NativeContextPolicyGroupScoped
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), sameNetwork); err != nil {
			t.Fatalf("dedicated Network rejected another Group in its own Network: %v", err)
		}
		otherNetwork := sameNetwork
		otherNetwork.NetworkID, otherNetwork.GroupID = "network-b", "group-c"
		otherNetwork.EndpointID, otherNetwork.BindingID, otherNetwork.BindingEpoch = "endpoint-c", "binding-c", 3
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), otherNetwork); !errors.Is(err, ErrNativeContextScopeConflict) {
			t.Fatalf("dedicated Network allowed reuse in another Network: %v", err)
		}
	})

	t.Run("current dedicated Network rejects prior ordinary Network", func(t *testing.T) {
		registry, err := OpenNativeContextRegistry(nativeContextHistoryTestPath(t))
		if err != nil {
			t.Fatal(err)
		}
		defer registry.Close()
		first := nativeContextHistoryInput()
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		current := first
		current.NetworkID, current.GroupID = "network-b", "group-b"
		current.EndpointID, current.BindingID, current.BindingEpoch = "endpoint-b", "binding-b", 2
		current.ContextPolicy = NativeContextPolicyDedicatedNetwork
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), current); !errors.Is(err, ErrNativeContextScopeConflict) {
			t.Fatalf("current dedicated Network ignored prior ordinary scope in another Network: %v", err)
		}
	})

	t.Run("same trusted account and native identity conflict across Hubs", func(t *testing.T) {
		registry, err := OpenNativeContextRegistry(nativeContextHistoryTestPath(t))
		if err != nil {
			t.Fatal(err)
		}
		defer registry.Close()
		first := nativeContextHistoryInput()
		first.ContextPolicy = NativeContextPolicyDedicatedThread
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), first); err != nil {
			t.Fatal(err)
		}
		otherHub := first
		otherHub.HubID, otherHub.NetworkID, otherHub.GroupID = "hub-b", "network-b", "group-b"
		otherHub.EndpointID, otherHub.BindingID, otherHub.BindingEpoch = "endpoint-b", "binding-b", 2
		otherHub.ContextPolicy = NativeContextPolicyGroupScoped
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), otherHub); !errors.Is(err, ErrNativeContextScopeConflict) {
			t.Fatalf("same trusted account/native identity bypassed cross-Hub dedicated history: %v", err)
		}
	})
}

func TestNativeContextHistoryExactRetrySucceedsAtIdentityAndGlobalCaps(t *testing.T) {
	registry, err := openNativeContextRegistry(":memory:", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()

	input := nativeContextHistoryInput()
	first, err := registry.CheckAndRecordNativeContext(context.Background(), input)
	if err != nil || first.KnownScopeCount != 1 {
		t.Fatalf("insert at small test caps failed: decision=%#v err=%v", first, err)
	}
	retry, err := registry.CheckAndRecordNativeContext(context.Background(), input)
	if err != nil || retry.KnownScopeCount != 1 || retry.NativeHistoryCoverage != NativeContextHistoryCoverageCicadaKnownOnly {
		t.Fatalf("exact idempotent retry failed at full per-identity/global caps: decision=%#v err=%v", retry, err)
	}

	rebound := input
	rebound.EndpointID, rebound.BindingID, rebound.BindingEpoch = "endpoint-rebound", "binding-rebound", 2
	if _, err := registry.CheckAndRecordNativeContext(context.Background(), rebound); !errors.Is(err, ErrNativeContextHistoryAtLimit) {
		t.Fatalf("new per-identity history row bypassed the small identity cap: %v", err)
	}
	otherIdentity := input
	otherIdentity.NativeSessionID = "synthetic-other-thread"
	if _, err := registry.CheckAndRecordNativeContext(context.Background(), otherIdentity); !errors.Is(err, ErrNativeContextHistoryAtLimit) {
		t.Fatalf("new identity bypassed the small global cap: %v", err)
	}
}

func TestNetworkEnrollmentHistoryRetainsActualObservedEpochAcrossRenewal(t *testing.T) {
	registry, err := openNativeContextRegistry(":memory:", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	input := nativeContextHistoryInput()
	input.GroupID = ""
	input.ContextPolicy = ""
	input.BindingEpoch = 7
	if _, err := registry.CheckAndRecordNetworkEnrollmentContext(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	for epoch := uint64(8); epoch <= 100; epoch++ {
		input.BindingEpoch = epoch
		decision, err := registry.CheckAndRecordNetworkEnrollmentContext(context.Background(), input)
		if err != nil || !decision.Accepted || decision.KnownScopeCount != 1 {
			t.Fatalf("renewal epoch%d appended token history or lost scope: %v", epoch, err)
		}
	}
	var count int
	var observedEpoch uint64
	if err := registry.db.QueryRow(`SELECT count(*),min(binding_epoch) FROM node_native_context_history_v1`).Scan(&count, &observedEpoch); err != nil || count != 1 || observedEpoch != 7 {
		t.Fatalf("actual first observed epoch changed: count%d epoch%d err%v", count, observedEpoch, err)
	}
	newBinding := input
	newBinding.BindingID = "new-genuine-enrollment"
	if _, err := registry.CheckAndRecordNetworkEnrollmentContext(context.Background(), newBinding); !errors.Is(err, ErrNativeContextHistoryAtLimit) {
		t.Fatalf("new enrollment bypassed history cap: %v", err)
	}
	groupBinding := input
	groupBinding.GroupID = "group-actual-writer"
	if _, err := registry.CheckAndRecordNetworkEnrollmentContext(context.Background(), groupBinding); !errors.Is(err, ErrNativeContextScopeInvalid) {
		t.Fatalf("Group writer was treated as access credential rotation: %v", err)
	}
	if _, err := registry.CheckAndRecordNativeContext(context.Background(), input); !errors.Is(err, ErrNativeContextHistoryAtLimit) {
		t.Fatalf("ordinary binding history stopped recording genuine epochs: %v", err)
	}
}

func TestNetworkEnrollmentObservationRetainsHistoricalRowsAndDedicatedScopeGuard(t *testing.T) {
	registry, err := openNativeContextRegistry(":memory:", 3, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	input := nativeContextHistoryInput()
	input.GroupID = ""
	input.ContextPolicy = ""
	for epoch := uint64(3); epoch <= 5; epoch++ {
		input.BindingEpoch = epoch
		if _, err := registry.CheckAndRecordNativeContext(context.Background(), input); err != nil {
			t.Fatal(err)
		}
	}
	input.BindingEpoch = 100
	if _, err := registry.CheckAndRecordNetworkEnrollmentContext(context.Background(), input); err != nil {
		t.Fatal("preserved enrollment at full history cap stopped renewal", err)
	}
	var count int
	var first, last uint64
	if err := registry.db.QueryRow(`SELECT count(*),min(binding_epoch),max(binding_epoch) FROM node_native_context_history_v1`).Scan(&count, &first, &last); err != nil || count != 3 || first != 3 || last != 5 {
		t.Fatal("observation purged or rewrote historical provenance")
	}
	changedPolicy := input
	changedPolicy.ContextPolicy = NativeContextPolicyDedicatedNetwork
	if _, err := registry.CheckAndRecordNetworkEnrollmentContext(context.Background(), changedPolicy); !errors.Is(err, ErrNativeContextHistoryAtLimit) {
		t.Fatalf("new policy observation bypassed history cap: %v", err)
	}
	otherHub := input
	otherHub.HubID = "hub-different"
	otherHub.ContextPolicy = NativeContextPolicyDedicatedNetwork
	if _, err := registry.CheckAndRecordNetworkEnrollmentContext(context.Background(), otherHub); !errors.Is(err, ErrNativeContextScopeConflict) {
		t.Fatalf("dedicated Hub scope ignored preserved history: %v", err)
	}
	otherNetwork := input
	otherNetwork.NetworkID = "net-different"
	otherNetwork.ContextPolicy = NativeContextPolicyDedicatedNetwork
	if _, err := registry.CheckAndRecordNetworkEnrollmentContext(context.Background(), otherNetwork); !errors.Is(err, ErrNativeContextScopeConflict) {
		t.Fatalf("dedicated Network scope ignored preserved history: %v", err)
	}
}

// These children use the actual registry entrypoint in separate OS processes.
// The parent holds an existing private database lock and releases both children
// together; no test shim changes SQLite or the production open implementation.
func TestNativeContextHistoryCrossProcessOpenWaitsForLockAndPreservesHistory(t *testing.T) {
	if path := os.Getenv("CICADA_SYNTHETIC_NATIVE_CONTEXT_OPEN_CHILD"); path != "" {
		if _, err := fmt.Fprintln(os.Stdout, "READY"); err != nil {
			t.Fatal(err)
		}
		if _, err := bufio.NewReader(os.Stdin).ReadByte(); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(os.Stdout, "OPENING"); err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		registry, err := OpenNativeContextRegistry(path)
		if os.Getenv("CICADA_SYNTHETIC_NATIVE_CONTEXT_EXPECT_TIMEOUT") == "1" {
			if err == nil {
				registry.Close()
				t.Fatal("held exclusive lock incorrectly permitted registry open")
			}
			if !strings.Contains(err.Error(), "initialize shared Node context registry") || time.Since(started) < 4*time.Second || time.Since(started) > 8*time.Second {
				t.Fatalf("open did not fail within bounded busy timeout: %v duration %s", err, time.Since(started))
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		defer registry.Close()
		var rows int
		var epoch uint64
		if err = registry.db.QueryRow(`SELECT count(*),min(binding_epoch) FROM node_native_context_history_v1`).Scan(&rows, &epoch); err != nil || rows != 1 || epoch != 1 {
			t.Fatalf("parallel open lost retained history: rows%d epoch%d err%v", rows, epoch, err)
		}
		input := nativeContextHistoryInput()
		input.HubID = "foreign-hub"
		input.EndpointID = "foreign-endpoint"
		input.BindingID = "foreign-binding"
		if _, err = registry.CheckAndRecordNativeContext(context.Background(), input); !errors.Is(err, ErrNativeContextScopeConflict) {
			t.Fatalf("parallel reopen bypassed dedicated scope guard: %v", err)
		}
		return
	}
	for _, test := range []struct {
		name     string
		children int
		timeout  bool
	}{{"release-to-two-concurrent-processes", 2, false}, {"held-lock-fails-closed-within-budget", 1, true}} {
		t.Run(test.name, func(t *testing.T) {
			path := nativeContextHistoryTestPath(t)
			r, err := OpenNativeContextRegistry(path)
			if err != nil {
				t.Fatal(err)
			}
			input := nativeContextHistoryInput()
			input.ContextPolicy = NativeContextPolicyDedicatedThread
			if _, err = r.CheckAndRecordNativeContext(context.Background(), input); err != nil {
				t.Fatal(err)
			}
			if err = r.Close(); err != nil {
				t.Fatal(err)
			}
			locker, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer locker.Close()
			locker.SetMaxOpenConns(1)
			// DELETE mode makes an EXCLUSIVE lock deterministic before the child's
			// production journal_mode=WAL pragma. All files remain fixture-private.
			if _, err = locker.Exec(`PRAGMA journal_mode=DELETE; BEGIN EXCLUSIVE;`); err != nil {
				t.Fatal(err)
			}
			held := true
			defer func() {
				if held {
					_, _ = locker.Exec("ROLLBACK")
				}
			}()
			type child struct {
				cmd    *exec.Cmd
				input  io.WriteCloser
				output *bufio.Reader
				stderr *bytes.Buffer
				done   chan error
			}
			children := []*child{}
			for n := 0; n < test.children; n++ {
				ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestNativeContextHistoryCrossProcessOpenWaitsForLockAndPreservesHistory$")
				cmd.Env = append(os.Environ(), "CICADA_SYNTHETIC_NATIVE_CONTEXT_OPEN_CHILD="+path)
				if test.timeout {
					cmd.Env = append(cmd.Env, "CICADA_SYNTHETIC_NATIVE_CONTEXT_EXPECT_TIMEOUT=1")
				}
				stdout, err := cmd.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				stdin, err := cmd.StdinPipe()
				if err != nil {
					t.Fatal(err)
				}
				stderr := &bytes.Buffer{}
				cmd.Stderr = stderr
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				c := &child{cmd: cmd, input: stdin, output: bufio.NewReader(stdout), stderr: stderr, done: make(chan error, 1)}
				children = append(children, c)
				line, err := c.output.ReadString('\n')
				if err != nil || line != "READY\n" {
					t.Fatalf("child barrier unavailable: %q %v", line, err)
				}
			}
			for _, c := range children {
				if _, err = c.input.Write([]byte("x")); err != nil {
					t.Fatal(err)
				}
				c.input.Close()
			}
			for _, c := range children {
				line, err := c.output.ReadString('\n')
				if err != nil || line != "OPENING\n" {
					t.Fatalf("child did not enter production open: %q %v", line, err)
				}
				go func(c *child) { _, _ = io.Copy(io.Discard, c.output); c.done <- c.cmd.Wait() }(c)
			}
			if !test.timeout {
				for _, c := range children {
					select {
					case err := <-c.done:
						t.Fatalf("registry open ignored held lock: %v %s", err, c.stderr.String())
					case <-time.After(200 * time.Millisecond):
					}
				}
				if _, err = locker.Exec("COMMIT"); err != nil {
					t.Fatal(err)
				}
				held = false
			}
			for _, c := range children {
				if err = <-c.done; err != nil {
					t.Fatalf("cross-process production open: %v %s", err, c.stderr.String())
				}
			}
			if held {
				if _, err = locker.Exec("ROLLBACK"); err != nil {
					t.Fatal(err)
				}
				held = false
			}
			var rows int
			var epoch uint64
			if err = locker.QueryRow(`SELECT count(*),min(binding_epoch) FROM node_native_context_history_v1`).Scan(&rows, &epoch); err != nil || rows != 1 || epoch != 1 {
				t.Fatalf("open/timeout changed retained history: rows%d epoch%d err%v", rows, epoch, err)
			}
		})
	}
}

func TestNativeContextHistoryConcurrentProcessesRecordOneDedicatedScope(t *testing.T) {
	if path := os.Getenv("CICADA_SYNTHETIC_NATIVE_CONTEXT_RECORD_CHILD"); path != "" {
		registry, err := OpenNativeContextRegistry(path)
		if err != nil {
			t.Fatal(err)
		}
		defer registry.Close()
		fmt.Fprintln(os.Stdout, "READY")
		if _, err = bufio.NewReader(os.Stdin).ReadByte(); err != nil {
			t.Fatal(err)
		}
		input := nativeContextHistoryInput()
		input.ContextPolicy = NativeContextPolicyDedicatedThread
		input.HubID = os.Getenv("CICADA_SYNTHETIC_NATIVE_CONTEXT_CHILD_HUB")
		_, err = registry.CheckAndRecordNativeContext(context.Background(), input)
		if err == nil {
			fmt.Fprintln(os.Stdout, "ACCEPTED")
		} else if errors.Is(err, ErrNativeContextScopeConflict) {
			fmt.Fprintln(os.Stdout, "CONFLICT")
		} else {
			t.Fatalf("cross-process current-scope decision failed: %v", err)
		}
		return
	}
	path := nativeContextHistoryTestPath(t)
	registry, err := OpenNativeContextRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	registry.Close()
	type child struct {
		cmd    *exec.Cmd
		input  io.WriteCloser
		output *bufio.Reader
		stderr *bytes.Buffer
	}
	children := []child{}
	for _, hub := range []string{"hub-a", "hub-b"} {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestNativeContextHistoryConcurrentProcessesRecordOneDedicatedScope$")
		cmd.Env = append(os.Environ(), "CICADA_SYNTHETIC_NATIVE_CONTEXT_RECORD_CHILD="+path, "CICADA_SYNTHETIC_NATIVE_CONTEXT_CHILD_HUB="+hub)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stderr := &bytes.Buffer{}
		cmd.Stderr = stderr
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		c := child{cmd, stdin, bufio.NewReader(stdout), stderr}
		children = append(children, c)
		line, err := c.output.ReadString('\n')
		if err != nil || line != "READY\n" {
			t.Fatalf("recording child readiness: %q %v", line, err)
		}
	}
	locker, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	locker.SetMaxOpenConns(1)
	if _, err = locker.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	held := true
	defer func() {
		if held {
			_, _ = locker.Exec("ROLLBACK")
		}
	}()
	for _, c := range children {
		if _, err = c.input.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		c.input.Close()
	}
	// Hold the writer lock while both production check-and-record calls enter.
	// IMMEDIATE prevents either process from reading a stale pre-writer snapshot.
	time.Sleep(200 * time.Millisecond)
	if _, err = locker.Exec("COMMIT"); err != nil {
		t.Fatal(err)
	}
	held = false
	decisions := map[string]int{}
	for _, c := range children {
		line, err := c.output.ReadString('\n')
		if err != nil {
			t.Fatalf("decision output: %v %s", err, c.stderr.String())
		}
		decisions[strings.TrimSpace(line)]++
		_, _ = io.Copy(io.Discard, c.output)
		if err = c.cmd.Wait(); err != nil {
			t.Fatalf("recording subprocess: %v %s", err, c.stderr.String())
		}
	}
	if decisions["ACCEPTED"] != 1 || decisions["CONFLICT"] != 1 || len(decisions) != 2 {
		t.Fatalf("scope authority was not one-success/one-conflict: %v", decisions)
	}
	var rows int
	var policy string
	if err = locker.QueryRow(`SELECT count(*),min(context_policy) FROM node_native_context_history_v1`).Scan(&rows, &policy); err != nil || rows != 1 || policy != NativeContextPolicyDedicatedThread {
		t.Fatalf("concurrent scope lost/duplicated history: %d %s %v", rows, policy, err)
	}
}

func TestNativeContextHistoryEscapesPrivatePathAndKeepsMemoryIsolated(t *testing.T) {
	directory := filepath.Dir(nativeContextHistoryTestPath(t))
	path := filepath.Join(directory, "native ?#%&=history.sqlite3")
	r, err := OpenNativeContextRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.CheckAndRecordNativeContext(context.Background(), nativeContextHistoryInput()); err != nil {
		t.Fatal(err)
	}
	r.Close()
	if info, err := os.Stat(path); err != nil || info.Mode() != 0600 {
		t.Fatalf("escaped filename changed path/private mode: %v", err)
	}
	r, err = OpenNativeContextRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	var rows int
	if err = r.db.QueryRow("SELECT count(*) FROM node_native_context_history_v1").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("escaped path lost history: %d %v", rows, err)
	}
	first, err := OpenNativeContextRegistry(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenNativeContextRegistry(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if _, err = first.CheckAndRecordNativeContext(context.Background(), nativeContextHistoryInput()); err != nil {
		t.Fatal(err)
	}
	if err = second.db.QueryRow("SELECT count(*) FROM node_native_context_history_v1").Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("separate in-memory registry leaked history: %d %v", rows, err)
	}
}
