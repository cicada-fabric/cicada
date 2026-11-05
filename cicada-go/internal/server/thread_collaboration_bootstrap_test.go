package server

import (
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"testing"
	"time"
)

func TestThreadCollaborationBootstrapClassifiesZeroBeforeGroupKeys(t *testing.T) {
	f := endpointGroupsRealHTTPBeforeKeys(t, func(f *endpointGroupsHTTPFixture, i int) {
		m := f.joins[i].Member
		if m.State != wire.LocalDomainMemberJoinedZero {
			t.Fatal("bootstrap did not retain zero-authority member", m.State)
		}
		var registration wire.EndpointGroupsNodeDescribeResult
		f.nodeHTTP(t, wire.OperationEndpointGroupsNodeDescribe, wire.EndpointGroupsNodeDescribe{EndpointID: m.EndpointID, NetworkID: f.domain.Policy.NetworkID, Limit: 64}, &registration)
		if registration.Registration.Registration.EndpointID != m.EndpointID || registration.Registration.BindingID != m.BindingID || len(registration.Authorities) != 0 {
			t.Fatal("zero member minted Group authority or replaced original")
		}
		var view wire.ThreadScopeView
		threadCollaborationNodeHTTP(t, f, wire.OperationThreadScopeRead, wire.ThreadScopeNodeRead{EndpointID: m.EndpointID, NetworkID: f.domain.Policy.NetworkID}, &view, "")
		if view.State != "CLASSIFICATION_REQUIRED" || view.ActiveGroupCount != 0 {
			t.Fatal("bare active join counted as effective authority", view.State, view.ActiveGroupCount)
		}
		_, result := threadCollaborationOwnerApply(t, f, wire.ThreadCollaborationOwnerPrepareBody{Action: wire.ThreadCollaborationSetClassification, Role: &wire.ThreadRoleChange{NetworkID: view.NetworkID, NodeID: view.NodeID, EndpointID: view.EndpointID, Source: view.Source, Classification: wire.ThreadClassificationWorker, ExpectedClassificationRevision: view.ClassificationRevision, ExpectedRelationsRevision: view.RelationsRevision, RegistrationDigest: view.RegistrationDigest}})
		if result.Thread == nil || result.Thread.ActiveGroupCount != 0 || result.Thread.Classification != wire.ThreadClassificationWorker {
			t.Fatal("explicit Owner zero-member classification failed")
		}
		if _, err := f.a.f.db.PreviewGroupEndpointKeyGrant(f.domain.Policy.OwnerID, f.domain.Policy.GroupID, m.EndpointID, f.a.owner.Public().ID, time.Now().UTC(), time.Now().UTC().Add(time.Minute)); err == nil {
			t.Fatal("ordinary snapshot bypassed zero-authority source")
		}
		threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRead, wire.GroupLocksNodeRead{EndpointID: m.EndpointID, Scope: wire.GroupLockScope{HubID: f.a.f.hub.HubID, NetworkID: f.domain.Policy.NetworkID, GroupID: f.domain.Policy.GroupID}}, nil, wire.ThreadCollaborationErrorAuthorizationRequired)
	})
	for i := range f.joins {
		var view wire.ThreadScopeView
		threadCollaborationNodeHTTP(t, f, wire.OperationThreadScopeRead, wire.ThreadScopeNodeRead{EndpointID: f.joins[i].Member.EndpointID, NetworkID: f.domain.Policy.NetworkID}, &view, "")
		if view.State != "CURRENT" || view.Classification != wire.ThreadClassificationWorker || view.ActiveGroupCount != 1 {
			t.Fatal("original zero registration did not activate its first Group")
		}
	}
}
