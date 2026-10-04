package harness

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// OperationState describes adapter implementation and evidence, never caller
// authorization. Installed executables and session environment variables cannot
// promote an operation to verified.
type OperationState string

const (
	OperationVerified    OperationState = "verified"
	OperationPartial     OperationState = "partial"
	OperationUnsupported OperationState = "unsupported"
	OperationNotTested   OperationState = "not_tested"
)

type OperationCapability struct {
	State          OperationState `json:"state"`
	ValidationRefs []string       `json:"validation_refs"`
	Limit          string         `json:"limit"`
}

// AdapterCapabilities contains no session ID, binary path, authentication
// material, role or membership. ValidationRefs identify implementation checks,
// not a receipt proving that this installed Runtime passed those checks.
type AdapterCapabilities struct {
	Runtime         string                         `json:"runtime"`
	Platform        string                         `json:"platform"`
	RuntimeVersion  string                         `json:"runtime_version"`
	VersionSource   string                         `json:"version_source"`
	Authentication  string                         `json:"authentication"`
	Installation    string                         `json:"installation"`
	InventorySource string                         `json:"inventory_source"`
	Authority       string                         `json:"authority"`
	Operations      map[string]OperationCapability `json:"operations"`
}

// DescribeLocalAdapter reuses executable lookup only. It never invokes a CLI,
// reads provider configuration, adopts a Thread, or probes a model. There is no
// trustworthy installed-binary version/authentication observation in this
// inventory; these remain explicitly unknown. An isolated protocol probe or
// resume/read metadata result is not current Runtime or memory verification.
func DescribeLocalAdapter(name string) AdapterCapabilities {
	name = Canonical(name)
	if name != "codex" && name != "shell" && !IsOptional(name) {
		name = "unknown"
	}
	report := AdapterCapabilities{
		Runtime: name, Platform: runtime.GOOS + "/" + runtime.GOARCH,
		RuntimeVersion: "unknown", VersionSource: "not_observed", Authentication: "unknown",
		Installation: "unknown", InventorySource: "not_observed", Authority: "descriptive_only",
		Operations: make(map[string]OperationCapability, 10),
	}
	for _, operation := range []string{
		"discover_current_session", "join_existing_session", "start_new_session",
		"inject_existing_session", "resume_same_native_session", "queue_while_foreground_busy",
		"observe_consumption", "cancel_owned_turn", "collect_result", "run_on_remote_node",
	} {
		report.Operations[operation] = OperationCapability{State: OperationUnsupported,
			ValidationRefs: []string{"internal/harness/adapter.go"}, Limit: "No native operation is exposed by this adapter."}
	}
	set := func(operation string, state OperationState, ref, limit string) {
		report.Operations[operation] = OperationCapability{State: state, ValidationRefs: []string{ref}, Limit: limit}
	}
	if name == "unknown" {
		return report
	}
	if name == "shell" {
		report.Installation, report.InventorySource = "not_applicable", "argv_executor"
		set("collect_result", OperationPartial, "cmd/cicada/machine_agent_test.go:TestRemoteMachineExecutesShellWithoutControlSecrets", "Bounded child stdout; no native Thread or conversation result.")
		set("run_on_remote_node", OperationPartial, "cmd/cicada/machine_agent_test.go:TestRemoteMachineExecutesShellWithoutControlSecrets", "Requires existing current Node authority; arbitrary argv does not imply resource isolation.")
		return report
	}
	binary := Binary(name)
	if name == "codex" {
		binary = strings.TrimSpace(os.Getenv("CICADA_CODEX_BIN"))
		if binary == "" {
			binary = "codex"
		}
	}
	report.Installation, report.InventorySource = "not_found", "executable_lookup"
	if _, err := exec.LookPath(binary); err == nil {
		report.Installation = "present"
	}
	set("discover_current_session", OperationPartial, "internal/harness/capabilities_test.go:TestAdapterCapabilitySessionMetadataDoesNotGrantAuthority", "Environment session metadata only; existing Join separately verifies identity and authority.")
	set("start_new_session", OperationPartial, "internal/harness/adapter_test.go:TestCommandDoesNotUseShell", "Bounded CLI launch implementation; this installation/version/authentication is not validated.")
	set("collect_result", OperationPartial, "internal/harness/adapter_test.go:TestCanonicalAndResult", "Bounded output parsing; returned session ID does not prove adoption or memory continuity.")
	set("run_on_remote_node", OperationPartial, "cmd/cicada/machine_agent_test.go:TestRemoteOptionalHarnessExecutesWithBoundedJSONResult", "Existing authenticated Node Worker path; current caller authorization remains separate.")
	if name != "codex" {
		return report
	}
	set("join_existing_session", OperationPartial, "cmd/cicada/local_join_bridge_test.go:TestMachineAgentJoinBridgeRejectsForgedIdentityFields", "Explicit Join, saved native record and current Node/Owner Guard required; metadata never joins.")
	set("start_new_session", OperationPartial, "cmd/cicada/machine_execution.go:executeMachineCodex", "Owned CLI/app-server execution; no verified claim for the current binary/version/authentication.")
	set("inject_existing_session", OperationPartial, "cmd/cicada/machine_native_outcome_test.go:TestMachineNativeQueueOutcomeSurvivesAttemptAndBlocksUncertainRetry", "Exact CLI queue and durable intent fence; acceptance does not prove wake or consumption; uncertain dispatch cannot be retried.")
	set("resume_same_native_session", OperationPartial, "cmd/cicada/machine_agent_test.go:TestRemoteCodexResumeRejectsDifferentNativeThread", "Exact returned Thread ID is checked; resume/read metadata does not verify model memory or cross-host restoration.")
	set("queue_while_foreground_busy", OperationNotTested, "docs/codex-native-wake-protocol-status.md", "Foreground typing/active-turn safety and unattended cold wake are not validated by queue acceptance.")
	set("observe_consumption", OperationNotTested, "internal/nodeinbox/inbox_test.go:TestCodexQueueAcceptedDoesNotClaimRuntimeInjection", "A queue receipt or read-only Thread metadata does not prove model consumption.")
	set("cancel_owned_turn", OperationUnsupported, "internal/codexapp/proxy_client.go:ProxyClient", "No exact original native-turn cancellation adapter; child-process cancellation is not a native stop proof.")
	set("collect_result", OperationPartial, "cmd/cicada/machine_execution.go:executeMachineCodex", "Owned Worker output collection; no general existing-TUI result or context-memory verification.")
	set("run_on_remote_node", OperationPartial, "cmd/cicada/machine_execution.go:executeMachineCodex", "Existing authenticated Node Worker path; same native Thread on another host is not verified.")
	return report
}

// LocalAdapterCapabilities describes all built-in adapters, including absent
// executables. It does not replace the legacy installed-harness scheduling list.
func LocalAdapterCapabilities() map[string]AdapterCapabilities {
	result := make(map[string]AdapterCapabilities, 5)
	for _, name := range append([]string{"codex", "shell"}, Names()...) {
		result[name] = DescribeLocalAdapter(name)
	}
	return result
}
