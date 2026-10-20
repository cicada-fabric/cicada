package nodewire

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestNodeOperatorCapabilityPinAndOldFormatRefusal(t *testing.T) {
	hub, _ := e2ee.NewIdentity()
	binding := Binding{HubID: "synthetic-hub", HubKey: hub.Public()}
	c := NodeOperatorCapabilities{Format: NodeOperatorCapabilitiesFormat, ContractRevision: NodeOperatorContractRevision, Available: true, HubID: binding.HubID,
		NodeControlFingerprint: IdentityFingerprint(binding.HubKey), Operations: NodeOperatorOperations(), MaxPageRows: 64, MaxPageBytes: MaxEndpointDirectoryBytes}
	raw, _ := json.Marshal(c)
	if parsed, err := ParseNodeOperatorCapabilities(append(raw, '\n'), binding); err != nil || !parsed.Available {
		t.Fatal("valid Node pin refused", err)
	}
	c.NodeControlFingerprint = strings.Repeat("a", 64)
	raw, _ = json.Marshal(c)
	if _, err := ParseNodeOperatorCapabilities(raw, binding); err == nil {
		t.Fatal("unapproved Node-Control replacement pin accepted")
	}
	if _, err := ParseNodeOperatorCapabilities([]byte(`{"format":"cicada.owner-endpoints-capabilities.v1"}`), binding); err == nil {
		t.Fatal("old profile enabled new pending request")
	}
	if _, err := ParseNodeOperatorCapabilities([]byte(strings.Repeat(" ", MaxNodeOperatorCapabilitiesBytes+1)), binding); err == nil {
		t.Fatal("unbounded capabilities accepted")
	}
}

func TestNodeEndpointDirectorySelfSelectorsAreExact(t *testing.T) {
	for _, q := range []EndpointDirectoryRequest{{Harness: "codex"}, {NativeSessionID: "synthetic"}, {Limit: 65}, {Harness: "codex", NativeSessionID: "synthetic", Cursor: "ep-x"}, {Harness: "codex", NativeSessionID: "synthetic", Limit: 2}} {
		if q.Validate() == nil {
			t.Fatal("partial/unbounded self selectors accepted")
		}
	}
	if (EndpointDirectoryRequest{Harness: "codex", NativeSessionID: "synthetic", Limit: 1}).Validate() != nil {
		t.Fatal("valid self selector refused")
	}
}
