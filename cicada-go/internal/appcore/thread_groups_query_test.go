package appcore

import (
	"bytes"
	"context"
	"testing"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestThreadGroupActorUnsettledOrWrongNodeQueryDoesNotPoisonCache(t *testing.T) {
	for _, kind := range []string{"nonterminal", "wrong-node"} {
		t.Run(kind, func(t *testing.T) {
			a := newThreadGroupActor(t)
			a.prepareCreate()
			a.drop = wire.OperationOwnerEndpointGroupsApply
			if a.apply() == nil {
				t.Fatal("lost apply was successful")
			}
			original := bytes.Clone(a.c.threadGroups.original.Packet)
			a.queryResult = func(r *wire.OwnerEndpointGroupsResult) {
				r.ReceiptPacket, r.Operation, r.CurrentRelation, r.CurrentGroup = nil, nil, nil, nil
				r.State, r.ErrorCode = "PREPARED", "OUTCOME_UNCERTAIN"
				if kind == "wrong-node" {
					r.State = "COMPLETED"
					r.NodeID = "synthetic-other-node"
				}
			}
			for attempt := 0; attempt < 2; attempt++ {
				if a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}) == nil {
					t.Fatal("query supplied original success")
				}
				if !a.c.hasThreadGroupPending() || !bytes.Equal(original, a.c.threadGroups.original.Packet) || a.c.threadGroups.recovery == nil || a.c.threadGroups.recoveryResponse != nil || a.c.threadGroups.response != nil {
					t.Fatal("invalid/nonterminal query changed original or poisoned durable response cache")
				}
			}
			posts := a.posts[wire.OperationOwnerEndpointGroupsReconcile]
			if len(posts) != 2 || !bytes.Equal(posts[0], posts[1]) {
				t.Fatal("unsettled query was not retried exactly")
			}
		})
	}
}

func TestThreadGroupActorEmptyStatusRequiresExactOriginal(t *testing.T) {
	a := newThreadGroupActor(t)
	a.prepareCreate()
	a.drop = wire.OperationOwnerEndpointGroupsApply
	if a.apply() == nil {
		t.Fatal("lost apply was successful")
	}
	original := a.c.threadGroups.original
	scope, err := a.c.localCollaborationActor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	owner, err := a.c.owner.E2EE()
	if err != nil {
		t.Fatal(err)
	}
	q, err := wire.NewOwnerEndpointGroupsStatus(a.c.nodeSession(), scope, original.Packet, owner, a.c.cfg.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	query, err := a.c.newThreadGroupRecord(q, original)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(query.Packet)
	defer clear(query.DTO)
	response := wire.OwnerEndpointGroupsResult{Format: wire.OwnerEndpointGroupsResultFormat, ContractRevision: wire.OwnerEndpointGroupsContractRevision, RequestID: query.Route.OperationID, RequestPacketDigest: query.Digest, HubID: query.Route.HubID, OwnerID: query.Route.OwnerID, DeviceID: query.Route.DeviceID, State: "COMPLETED", ErrorCode: "OUTCOME_UNCERTAIN", CapturedAt: query.CreatedAt, Freshness: "SNAPSHOT_ONLY"}
	raw, err := wire.SealResponse(a.local.n.n2.hubKey, a.c.device.Public(), query.Route, response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.openThreadGroupResult(query, raw, original); err != nil {
		t.Fatal("exact empty terminal status rejected", err)
	}
	wrong := *original
	wrong.Route.OperationID = "synthetic-other-operation"
	if _, err := a.c.openThreadGroupResult(query, raw, &wrong); err == nil {
		t.Fatal("status accepted a different original ID")
	}
	response.NodeID = "synthetic-other-node"
	raw, err = wire.SealResponse(a.local.n.n2.hubKey, a.c.device.Public(), query.Route, response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.c.openThreadGroupResult(query, raw, original); err == nil {
		t.Fatal("empty status accepted an unrelated Node")
	}
}

func TestThreadGroupActorChangedLoginCannotReplaceQueryWithoutMatchingSecurity(t *testing.T) {
	a := newThreadGroupActor(t)
	a.prepareCreate()
	a.drop = wire.OperationOwnerEndpointGroupsApply
	if a.apply() == nil {
		t.Fatal("lost apply was successful")
	}
	original := bytes.Clone(a.c.threadGroups.original.Packet)
	a.drop = wire.OperationOwnerEndpointGroupsReconcile
	if a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}) == nil {
		t.Fatal("lost query was successful")
	}
	query := bytes.Clone(a.c.threadGroups.recovery.Packet)
	// Scripted account observation only. Real password login and restart are
	// exercised separately through the actual TCP Router/Store fixture.
	a.c.session.SessionToken = bytes.Repeat([]byte{0x74}, len(a.c.session.SessionToken))
	a.c.sessionInspected, a.c.sessionNeedsCheck = false, true
	if a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}) == nil || !bytes.Equal(query, a.c.threadGroups.recovery.Packet) {
		t.Fatal("uninspected login replaced query")
	}
	a.c.sessionInspected, a.c.sessionNeedsCheck = true, false
	a.local.n.scope.AccountSessionID = "synthetic-new-query-session"
	a.local.n.scope.OwnerKeyVersion++
	a.local.n.token = bytes.Clone(a.c.session.SessionToken)
	before := len(a.local.n.posts[wire.OperationAppNodeStatus])
	if a.c.Dispatch(context.Background(), Action{Kind: ActionRecoverThreadGroup}) == nil {
		t.Fatal("changed Owner security coordinate replaced query")
	}
	if len(a.local.n.posts[wire.OperationAppNodeStatus]) != before+1 || len(a.posts[wire.OperationOwnerEndpointGroupsReconcile]) != 1 || !a.c.hasThreadGroupPending() || !bytes.Equal(original, a.c.threadGroups.original.Packet) || !bytes.Equal(query, a.c.threadGroups.recovery.Packet) {
		t.Fatal("scope mismatch bypassed independent recheck or changed pending bytes")
	}
}
