package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func syntheticEndpointGroupsContext() localCodexContext {
	return localCodexContext{VerificationProfile: LocalCodexContextProfileEndpointGroups, EndpointGroupsVersion: 1, RegistrationDigest: strings.Repeat("a", 64), RegistrationRevision: 1, BindingID: "synthetic-original-binding", BindingEpoch: 7, NodeKeyEpoch: 2}
}

func TestEndpointGroupsConsumedContextRejectsPartialMixedAndLegacyFallback(t *testing.T) {
	valid := syntheticEndpointGroupsContext()
	binding, err := codexContextBinding(valid)
	if err != nil || binding.EndpointGroupsVersion != 1 || binding.LocalDomainVersion != 0 || binding.RegistrationBindingID != valid.BindingID || binding.RegistrationBindingEpoch != valid.BindingEpoch {
		t.Fatal("exact managed registration profile rejected", err)
	}
	if _, _, err := codexContextDomain(valid); err == nil {
		t.Fatal("new profile entered old domain/legacy-only consumer")
	}
	changes := []func(*localCodexContext){
		func(c *localCodexContext) { c.EndpointGroupsVersion = 0 },
		func(c *localCodexContext) { c.EndpointGroupsVersion = 2 },
		func(c *localCodexContext) { c.RegistrationDigest = "" },
		func(c *localCodexContext) { c.RegistrationRevision = 0 },
		func(c *localCodexContext) { c.BindingID = "" },
		func(c *localCodexContext) { c.BindingEpoch = 0 },
		func(c *localCodexContext) { c.NodeKeyEpoch = 0 },
		func(c *localCodexContext) { c.NodeKeyEpoch = 1 << 63 },
		func(c *localCodexContext) { c.VerificationProfile = "" },
		func(c *localCodexContext) { c.VerificationProfile = LocalCodexContextProfileLegacy },
		func(c *localCodexContext) { c.VerificationProfile = "FUTURE_MANAGED" },
		func(c *localCodexContext) {
			c.LocalDomainVersion = 1
			c.LocalDomain = wire.LocalDomainSelection{PolicyID: strings.Repeat("b", 32), PolicyEpoch: 1, PolicyDigest: strings.Repeat("c", 64)}
		},
	}
	for i, change := range changes {
		c := valid
		change(&c)
		if _, err := codexContextBinding(c); err == nil {
			t.Fatalf("mixed/partial managed profile %d accepted", i)
		}
	}
	legacyRaw, _ := json.Marshal(localCodexContext{})
	if strings.Contains(string(legacyRaw), "endpoint_groups") || strings.Contains(string(legacyRaw), "registration_") || strings.Contains(string(legacyRaw), "binding_") {
		t.Fatal("legacy context gained new optional fields")
	}
	stored := binding.stored()
	parsed, err := decodeCodexDomainBinding(stored)
	if err != nil || parsed != binding {
		t.Fatal("managed registration binding lost exact value across persistence", err)
	}
	if !strings.Contains(stored, `"registration_binding_id"`) || strings.Contains(stored, `"binding_id"`) {
		t.Fatal("private profile fence can shadow session binding_id")
	}
	outbox := codexOutboxBinding{codexDomainBinding: binding, NativeBindingID: valid.BindingID, NativeBindingEpoch: valid.BindingEpoch}
	outbox.EndpointGroupAuthority = syntheticEndpointGroupsAuthority(binding)
	if outbox.validate() != nil {
		t.Fatal("original managed native binding rejected")
	}
	outbox.NativeBindingEpoch++
	if outbox.validate() == nil {
		t.Fatal("outbox borrowed a replacement native epoch")
	}
}

func syntheticEndpointGroupsAuthority(b codexDomainBinding) wire.EndpointGroupCurrentEndpoint {
	return wire.EndpointGroupCurrentEndpoint{OwnerControl: e2ee.EndpointGroupOwnerControl{Mode: "DEFAULT", DenyReason: "NONE"}, Relation: wire.EndpointGroupRelation{EndpointID: "synthetic-endpoint", PrincipalID: "synthetic-agent", GroupID: "synthetic-group", RegistrationDigest: b.RegistrationDigest, RegistrationRevision: b.RegistrationRevision, BindingID: b.RegistrationBindingID, BindingEpoch: b.RegistrationBindingEpoch, Source: "DEFAULT_POLICY", AuthorityID: "synthetic-default-policy", AuthorityEpoch: 1, ContributionRevision: 1, State: "ACTIVE", OwnerControlDigest: strings.Repeat("b", 64)}}
}

func TestEndpointGroupsTicketAuthenticatesOriginalRegistrationCoordinates(t *testing.T) {
	var authority localCodexContextAuthority
	q := syntheticCodexContextIssue()
	now := time.Now().UTC()
	context := syntheticEndpointGroupsContext()
	context.Harness, context.NativeSessionID, context.Workspace, context.TurnID, context.ToolUseID = q.Harness, q.NativeSessionID, q.Workspace, q.TurnID, q.ToolUseID
	issued, err := authority.issueVerified(q, "synthetic-node-original-binding", now, context)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Split(issued.Ticket, ".")[0]
	original := authority.live[id]
	for i, change := range []func(*localCodexContext){
		func(c *localCodexContext) { c.RegistrationDigest = strings.Repeat("b", 64) },
		func(c *localCodexContext) { c.RegistrationRevision++ },
		func(c *localCodexContext) { c.BindingID = "synthetic-other-binding" },
		func(c *localCodexContext) { c.BindingEpoch++ },
		func(c *localCodexContext) { c.NodeKeyEpoch++ },
		func(c *localCodexContext) { c.VerificationProfile = LocalCodexContextProfileLegacy },
	} {
		changed := original
		change(&changed.Context)
		authority.live[id] = changed
		if _, err := authority.consume(syntheticCodexContextConsume(q, issued.Ticket), "synthetic-node-original-binding", now); err == nil {
			t.Fatalf("unsigned registration metadata change %d accepted", i)
		}
	}
	authority.live[id] = original
	consumed, err := authority.consume(syntheticCodexContextConsume(q, issued.Ticket), "synthetic-node-original-binding", now)
	if err != nil || consumed.Context != context {
		t.Fatal("invalid attempts consumed or altered the original ticket", err)
	}
	if _, err := authority.consume(syntheticCodexContextConsume(q, issued.Ticket), "synthetic-node-original-binding", now); err == nil {
		t.Fatal("managed registration ticket was reused")
	}
}
