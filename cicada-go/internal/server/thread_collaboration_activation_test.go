package server

import (
	"database/sql"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestThreadCollaborationActivationAndCurrentWorkerCeiling(t *testing.T) {
	f := endpointGroupsRealHTTP(t) // real Owner explicitly classifies advisor before keys
	create, packet, _, review := f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsCreateGroup, Name: "Synthetic additional advisor Group"})
	_, _, _, created := f.apply(t, create, packet, review, nil)
	group := created.Operation.Target.GroupID
	first := f.activate(t, group, 0)
	f.activate(t, group, 1)
	var scope wire.ThreadScopeView
	threadCollaborationNodeHTTP(t, f, wire.OperationThreadScopeRead, wire.ThreadScopeNodeRead{EndpointID: f.joins[0].Member.EndpointID, NetworkID: f.domain.Policy.NetworkID}, &scope, "")
	if scope.Classification != wire.ThreadClassificationAdvisor || scope.ActiveGroupCount != 2 {
		t.Fatal("advisor failed to retain both effective sources", scope.ActiveGroupCount)
	}
	q, err := wire.NewThreadCollaborationOwnerPrepare(f.a.session, f.a.scope.Actor, wire.ThreadCollaborationOwnerPrepareBody{Action: wire.ThreadCollaborationSetClassification, Role: &wire.ThreadRoleChange{NetworkID: scope.NetworkID, NodeID: scope.NodeID, EndpointID: scope.EndpointID, Source: scope.Source, Classification: wire.ThreadClassificationWorker, ExpectedClassificationRevision: scope.ClassificationRevision, ExpectedRelationsRevision: scope.RelationsRevision, RegistrationDigest: scope.RegistrationDigest}}, f.a.owner, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	_, denied := threadCollaborationOwnerHTTP(t, f, q)
	if denied.State != "REJECTED" || denied.ErrorCode != wire.ThreadCollaborationErrorWorkerGroupLimit {
		t.Fatal("Owner downgrade silently evicted or over-admitted", denied.State, denied.ErrorCode)
	}
	service := f.a.f.http.Config.Handler.(*hubNodesHandler).base.fabricService
	actor, err := service.AuthenticateForGroup(f.joins[0].SessionToken, group)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an already persisted incompatible worker row in this disposable
	// database. Final use must independently refuse despite a previously valid Actor.
	db, err := sql.Open("sqlite", f.a.f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err = db.Exec(`UPDATE thread_classifications_v1 SET classification='worker',revision=revision+1 WHERE endpoint_id=?`, scope.EndpointID); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(service.Authorize(actor, "message.send"), fabric.ErrPermissionDenied) {
		t.Fatal("stale actor bypassed current worker quantity")
	}
	f.a.pairHTTP(t, http.MethodGet, endpointGroupsHTTPPeerPath(f, group), "CicadaNode "+f.a.nodeToken, "", nil, http.StatusNotFound)
	threadCollaborationNodeHTTP(t, f, wire.OperationGroupLocksRead, wire.GroupLocksNodeRead{EndpointID: scope.EndpointID, Scope: wire.GroupLockScope{HubID: scope.HubID, NetworkID: scope.NetworkID, GroupID: group}}, nil, wire.ThreadCollaborationErrorWorkerGroupLimit)
	remove, original, _, removal := f.prepare(t, wire.OwnerEndpointGroupsPrepareBody{Action: wire.OwnerEndpointGroupsRemoveEndpoint, GroupID: group, EndpointID: scope.EndpointID})
	head := first.OwnerControl
	f.apply(t, remove, original, removal, &head)
	threadCollaborationNodeHTTP(t, f, wire.OperationThreadScopeRead, wire.ThreadScopeNodeRead{EndpointID: scope.EndpointID, NetworkID: scope.NetworkID}, &scope, "")
	if scope.State != "CURRENT" || scope.ActiveGroupCount != 1 || scope.Classification != wire.ThreadClassificationWorker {
		t.Fatal("precise cleanup did not restore remaining worker source")
	}
	if _, err = service.AuthenticateForGroup(f.joins[0].SessionToken, f.domain.Policy.GroupID); err != nil {
		t.Fatal("precise cleanup evicted remaining original source", err)
	}
}
