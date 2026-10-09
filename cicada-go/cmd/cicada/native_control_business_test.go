package main

import (
	"strings"
	"testing"
)

// Count attempts to the legacy Control surface and Manager endpoints even
// when the separate native Hub allowlist rejects them before dispatch.
func nativeManagementPathAttempt(path string) bool {
	return path == "/v1" || strings.HasPrefix(path, "/v1/") ||
		path == "/v2/management/endpoints" || strings.HasPrefix(path, "/v2/management/endpoints/") ||
		path == "/v2/client/rpc" || path == "/v2/client/rpc/recover" ||
		path == "/v2/control" || strings.HasPrefix(path, "/v2/control/")
}

func TestNativeManagementPathAttemptCountsControlRoutes(t *testing.T) {
	for _, path := range []string{
		"/v1", "/v1/goals", "/v1/goals/goal/events/stream", "/v1/workers", "/v1/approvals/approval", "/v1/connectors/events",
		"/v2/management/endpoints", "/v2/management/endpoints/endpoint", "/v2/control/goals",
		"/v2/client/rpc", "/v2/client/rpc/recover",
	} {
		if !nativeManagementPathAttempt(path) {
			t.Errorf("Control/Manager attempt %q was not counted", path)
		}
	}
	for _, path := range []string{
		"/v1-other/goals", "/v2/management/endpoints-other", "/v2/control-other", "/healthz",
		"/v2/client/rpc-other", "/v2/client/rpc/recover-other", "/v2/client/rpc/other",
		"/v2/fabric/join", "/v2/fabric/whoami", "/v2/artifacts",
		"/v2/relay/nodes/node/group/sealed/ask", "/v2/relay/nodes/node/group/sealed/reply",
	} {
		if nativeManagementPathAttempt(path) {
			t.Errorf("independent data-plane route %q was counted as Control/Manager", path)
		}
	}
}
