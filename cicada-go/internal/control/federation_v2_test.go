package control

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func TestFederationProvisioningRequiresMonitorReadyMatchingEndpointAndContract(t *testing.T) {
	root := t.TempDir()
	manager, err := New(Config{StateDir: filepath.Join(root, "state"), WorkspaceRoot: filepath.Join(root, "workspace")})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Shutdown(context.Background())

	source, err := manager.CreateGroup(GroupCreateInput{Name: "source"})
	if err != nil {
		t.Fatal(err)
	}
	target, err := manager.CreateGroup(GroupCreateInput{Name: "target"})
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := manager.store.CreatePrincipal(store.Principal{
		ID: "monitor-principal", Kind: store.PrincipalKindAgent, OwnerID: manager.Identity().ID,
		TrustDomainID: manager.Identity().ID, Name: "monitor", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err := manager.store.CreateMembership(store.Membership{
		PrincipalID: monitor.ID, GroupID: source.ID, Role: "member", Roles: []string{"member"},
		Grants: []string{"directory.read", "message.receive"}, Status: store.MembershipStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	membership, err = manager.BindMembershipRole(source.ID, membership.ID, "monitor", membership.Version)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := manager.store.UpsertEndpoint(store.Endpoint{
		ID: "monitor-endpoint", Name: "monitor", Harness: "monitor", MachineID: "node",
		NativeSessionID: "monitor-session", Status: "online",
	})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err = manager.store.AssociateEndpoint(endpoint.ID, monitor.ID, source.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	contract, err := manager.CreateFederationContract(store.FederationContract{
		SourceGroupID: source.ID, TargetGroupID: target.ID, Capability: "benchmark.read",
		Scopes: []string{"public"}, ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.store.TouchEndpoint(endpoint.ID, "offline"); err != nil {
		t.Fatal(err)
	}
	assignment, err := manager.CreateRepresentativeAssignment(store.RepresentativeAssignment{
		GroupID: source.ID, PrincipalID: monitor.ID, EndpointID: endpoint.ID,
		ContractID: contract.ID, Scope: []string{"public"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if assignment.Status != store.RepresentativeAssignmentActive || assignment.GroupID != source.ID {
		t.Fatalf("unexpected representative assignment: %#v", assignment)
	}
	if _, err := manager.store.TouchEndpoint(endpoint.ID, "left"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreateRepresentativeAssignment(store.RepresentativeAssignment{
		GroupID: source.ID, PrincipalID: monitor.ID, EndpointID: endpoint.ID,
		ContractID: contract.ID, Scope: []string{"public"},
	}); !errors.Is(err, store.ErrGatewayAuthorization) {
		t.Fatalf("left representative was accepted: %v", err)
	}
	if _, err := manager.store.TouchEndpoint(endpoint.ID, "online"); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.CreateRepresentativeAssignment(store.RepresentativeAssignment{
		GroupID: target.ID, PrincipalID: monitor.ID, EndpointID: endpoint.ID, ContractID: contract.ID,
	}); err == nil {
		t.Fatal("accepted endpoint/group mismatch")
	}
	if _, err := manager.CreateRepresentativeAssignment(store.RepresentativeAssignment{
		GroupID: source.ID, PrincipalID: monitor.ID, EndpointID: endpoint.ID, ContractID: "missing-contract",
	}); !errors.Is(err, store.ErrFederationContractNotFound) {
		t.Fatalf("missing contract error=%v", err)
	}

	member, err := manager.store.CreatePrincipal(store.Principal{
		ID: "plain-principal", Kind: store.PrincipalKindAgent, OwnerID: manager.Identity().ID,
		TrustDomainID: manager.Identity().ID, Name: "plain", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.store.CreateMembership(store.Membership{PrincipalID: member.ID, GroupID: source.ID, Role: "member", Roles: []string{"member"}, Status: store.MembershipStatusActive}); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreateRepresentativeAssignment(store.RepresentativeAssignment{
		GroupID: source.ID, PrincipalID: member.ID, EndpointID: endpoint.ID, ContractID: contract.ID,
	}); err == nil {
		t.Fatal("accepted non-monitor representative")
	}
}
