package harness_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestAdapterCapabilitiesCoverOperationsWithoutRuntimeVerification(t *testing.T) {
	wanted := []string{"discover_current_session", "join_existing_session", "start_new_session",
		"inject_existing_session", "resume_same_native_session", "queue_while_foreground_busy",
		"observe_consumption", "cancel_owned_turn", "collect_result", "run_on_remote_node"}
	reports := harness.LocalAdapterCapabilities()
	if len(reports) != 5 {
		t.Fatalf("built-in adapter count = %d", len(reports))
	}
	for name, report := range reports {
		t.Run(name, func(t *testing.T) {
			if report.Runtime != name || report.Platform == "" || report.RuntimeVersion != "unknown" ||
				report.VersionSource != "not_observed" || report.Authentication != "unknown" || report.Authority != "descriptive_only" {
				t.Fatalf("unsupported verification or authorization assertion: %#v", report)
			}
			if len(report.Operations) != len(wanted) {
				t.Fatalf("operation count = %d", len(report.Operations))
			}
			for _, operation := range wanted {
				value, exists := report.Operations[operation]
				if !exists || len(value.ValidationRefs) == 0 || value.Limit == "" {
					t.Fatalf("missing state/evidence/limit for %s", operation)
				}
				switch value.State {
				case harness.OperationPartial, harness.OperationUnsupported, harness.OperationNotTested:
				default:
					t.Fatalf("%s claims runtime verification without actual evidence: %s", operation, value.State)
				}
			}
		})
	}
	for _, name := range []string{"claude-code", "opencode", "happy-agent", "shell"} {
		for _, operation := range []string{"join_existing_session", "inject_existing_session", "resume_same_native_session", "queue_while_foreground_busy", "observe_consumption", "cancel_owned_turn"} {
			if reports[name].Operations[operation].State != harness.OperationUnsupported {
				t.Fatalf("%s falsely supports native operation %s", name, operation)
			}
		}
	}
	codex := reports["codex"].Operations
	if codex["inject_existing_session"].State != harness.OperationPartial || codex["resume_same_native_session"].State != harness.OperationPartial ||
		codex["queue_while_foreground_busy"].State != harness.OperationNotTested || codex["observe_consumption"].State != harness.OperationNotTested ||
		codex["cancel_owned_turn"].State != harness.OperationUnsupported {
		t.Fatal("queue acceptance or metadata was promoted to native consumption, memory, or cancellation")
	}
}

func TestAdapterExecutablePresenceDoesNotVerifyOrRunRuntime(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "must-not-run")
	binary := filepath.Join(dir, "codex")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\necho model_or_provider_execution > '"+marker+"'\necho codex-cli 9.9.9\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_CODEX_BIN", binary)
	t.Setenv("CICADA_RUNTIME_VERSION", "9.9.9")
	t.Setenv("CICADA_AUTHENTICATION", "approved")
	report := harness.DescribeLocalAdapter("codex")
	if report.Installation != "present" || report.InventorySource != "executable_lookup" ||
		report.RuntimeVersion != "unknown" || report.Authentication != "unknown" ||
		report.Operations["observe_consumption"].State != harness.OperationNotTested {
		t.Fatalf("executable presence/env promoted capability: %#v", report)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("inventory executed the Runtime: %v", err)
	}
	t.Setenv("CICADA_CODEX_BIN", filepath.Join(dir, "missing"))
	if report := harness.DescribeLocalAdapter("codex"); report.Installation != "not_found" {
		t.Fatalf("missing executable was reported installed: %#v", report)
	}
}

func TestAdapterCapabilitySessionMetadataDoesNotGrantAuthority(t *testing.T) {
	t.Setenv("CICADA_NATIVE_SESSION_ID", "synthetic-session-id")
	t.Setenv("CICADA_MACHINE_ID", "synthetic-machine")
	t.Setenv("CICADA_WORKSPACE", "/synthetic-workspace")
	t.Setenv("CICADA_ROLE", "owner")
	t.Setenv("CICADA_GROUP", "model-supplied-group")
	t.Setenv("CICADA_APPROVAL", "true")
	t.Setenv("CICADA_RUNTIME_VERSION", "0.160.0")
	t.Setenv("CICADA_API_TOKEN", "must-not-project")
	for _, name := range []string{"codex", "claude-code", "opencode", "happy-agent"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("CICADA_HARNESS", name)
			session, err := harness.DetectCurrentSession()
			if err != nil {
				t.Fatal(err)
			}
			if session.Harness != name || session.NativeSessionID != "synthetic-session-id" ||
				session.MachineID != "synthetic-machine" || session.Workspace != "/synthetic-workspace" || session.Capabilities["fabric_tools"] != true {
				t.Fatal("legacy Session metadata changed")
			}
			wake := "poll"
			if name == "codex" {
				wake = "codex_queue"
			}
			if session.Capabilities["wake"] != wake {
				t.Fatal("legacy wake route changed")
			}
			reports, ok := session.Capabilities["adapter_capabilities"].(map[string]harness.AdapterCapabilities)
			if !ok || len(reports) != 1 || !reflect.DeepEqual(reports[name], harness.DescribeLocalAdapter(name)) {
				t.Fatal("session did not publish its descriptive operation matrix")
			}
			encoded, err := json.Marshal(session.Capabilities)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"must-not-project", "synthetic-session-id", "model-supplied-group", `"role"`, `"approval"`, `"owner"`, `"verified"`} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("capability metadata contains untrusted authority or verification: %s", forbidden)
				}
			}
		})
	}
}

func TestAdapterCapabilitiesRemainBoundedAndUnknownRuntimeDoesNotEchoInput(t *testing.T) {
	encoded, err := json.Marshal(harness.LocalAdapterCapabilities())
	if err != nil || len(encoded) > 24*1024 {
		t.Fatalf("Machine operation metadata exceeds bounded budget: bytes=%d err=%v", len(encoded), err)
	}
	report := harness.DescribeLocalAdapter("model-secret-unsupported-runtime")
	encoded, err = json.Marshal(report)
	if err != nil || report.Runtime != "unknown" || report.Installation != "unknown" || strings.Contains(string(encoded), "model-secret") {
		t.Fatal("unknown Runtime claims installation or projects arbitrary input")
	}
	for _, operation := range report.Operations {
		if operation.State != harness.OperationUnsupported {
			t.Fatal("unknown Runtime gained an operation")
		}
	}
}

func TestAdapterCapabilityReportsHaveIndependentConcurrentState(t *testing.T) {
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			first := harness.LocalAdapterCapabilities()
			value := first["codex"].Operations["observe_consumption"]
			value.State = harness.OperationVerified
			value.ValidationRefs[0] = "foreign-model-assertion"
			first["codex"].Operations["observe_consumption"] = value
			second := harness.LocalAdapterCapabilities()["codex"].Operations["observe_consumption"]
			if second.State != harness.OperationNotTested || strings.Contains(second.ValidationRefs[0], "foreign") {
				t.Error("one caller mutated another caller's capability state/evidence")
			}
		}()
	}
	workers.Wait()
}

// JSON round-trip exercises the same recursive map keys seen by HTTP Join,
// rather than allowing Go structs to bypass the sensitive capability gate.
func TestAdapterDetectedSessionJoinsWithoutWeakeningSensitiveGate(t *testing.T) {
	t.Setenv("CICADA_HARNESS", "codex")
	t.Setenv("CICADA_NATIVE_SESSION_ID", "synthetic-detected-thread")
	t.Setenv("CICADA_MACHINE_ID", "synthetic-node")
	t.Setenv("CICADA_WORKSPACE", t.TempDir())
	t.Setenv("CICADA_ROLE", "owner")
	t.Setenv("CICADA_GROUP", "untrusted-group")
	t.Setenv("CICADA_APPROVAL", "true")
	session, err := harness.DetectCurrentSession()
	if err != nil {
		t.Fatal(err)
	}
	capabilities := func() map[string]any {
		t.Helper()
		encoded, err := json.Marshal(session.Capabilities)
		if err != nil {
			t.Fatal(err)
		}
		var result map[string]any
		if err := json.Unmarshal(encoded, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	plane, err := control.New(control.Config{StateDir: filepath.Join(t.TempDir(), "state"), WorkspaceRoot: session.Workspace})
	if err != nil {
		t.Fatal(err)
	}
	defer plane.Shutdown(context.Background())
	joinControl := func(caps map[string]any) error {
		endpoint, err := plane.JoinEndpoint(control.EndpointJoinInput{
			Harness: session.Harness, NativeSessionID: session.NativeSessionID, MachineID: session.MachineID,
			Workspace: session.Workspace, Owner: "untrusted-owner", Capabilities: caps,
		})
		if err == nil && endpoint.Owner != plane.Identity().ID {
			t.Fatal("descriptor or input granted foreign ownership")
		}
		return err
	}
	persistence, err := store.New(filepath.Join(t.TempDir(), "fabric.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	owner, err := persistence.CreatePrincipal(store.Principal{ID: "synthetic-owner", Kind: store.PrincipalKindHuman,
		OwnerID: "synthetic-owner", TrustDomainID: "synthetic-domain", Name: "owner", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(store.Group{Name: "synthetic-group", OwnerPrincipalID: owner.ID,
		TrustDomainID: "synthetic-domain", State: store.GroupStateActive, ContextPolicy: "group_scoped",
		IsolationProfile: "trusted_host", ExternalMode: "monitor_mediated"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(persistence, owner.ID, "synthetic-domain")
	if err != nil {
		t.Fatal(err)
	}
	joinFabric := func(caps map[string]any) error {
		joined, err := service.Join(fabric.JoinInput{GroupID: group.ID, Harness: session.Harness,
			NativeSessionID: session.NativeSessionID, NodeID: session.MachineID, Workspace: session.Workspace, Capabilities: caps})
		if err != nil {
			return err
		}
		actor, err := service.Authenticate(joined.SessionToken)
		if err != nil {
			t.Fatal(err)
		}
		membership, err := persistence.GetMembershipByPrincipalGroup(actor.PrincipalID, actor.GroupID)
		if err != nil || membership.Role != "member" || actor.GroupID != group.ID {
			t.Fatal("metadata promoted membership or selected untrusted group")
		}
		return nil
	}
	for _, gate := range []struct {
		name string
		join func(map[string]any) error
	}{{"control", joinControl}, {"fabric", joinFabric}} {
		t.Run(gate.name, func(t *testing.T) {
			if err := gate.join(capabilities()); err != nil {
				t.Fatalf("detected descriptive metadata rejected: %v", err)
			}
			for _, forbidden := range []string{"api_token", "credential", "private_key", "password"} {
				t.Run(forbidden, func(t *testing.T) {
					caps := capabilities()
					caps["adapter_capabilities"].(map[string]any)["codex"].(map[string]any)[forbidden] = "unknown"
					if err := gate.join(caps); err == nil {
						t.Fatal("sensitive key accepted even though its value says unknown")
					}
				})
			}
			caps := capabilities()
			caps["nested"] = []any{map[string]any{"api_key": "unknown"}}
			if err := gate.join(caps); err == nil {
				t.Fatal("nested array sensitive key accepted")
			}
		})
	}
}
