package hubaccountwire

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestThreadCollaborationOwnerPQCAndOriginalRecovery(t *testing.T) {
	f := localDomainCrypto(t).f
	body := ThreadCollaborationOwnerPrepareBody{Action: ThreadCollaborationCreateGroupWithPolicy, Policy: &GroupPolicyChange{NetworkID: "synthetic-network", Name: "Synthetic coordination", SlotCount: 8, Rights: GroupCoordinationRights()}}
	prepare, err := NewThreadCollaborationOwnerPrepare(f.session, f.scope, body, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := SealClientRequest(f.device, f.hub, prepare)
	if err != nil {
		t.Fatal("real PQC seal", err)
	}
	binding, route, err := NewClientRoute(f.hub, prepare, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var opened ThreadCollaborationOwnerPrepareRequest
	if OpenRequestAt(f.hubPrivate, &f.scope.DevicePublic, binding, route, original, &opened, f.now) != nil || !reflect.DeepEqual(opened, prepare) {
		t.Fatal("real PQC request did not open")
	}
	digest, _ := ThreadCollaborationOwnerBodyDigest(body)
	review := ThreadCollaborationOwnerReview{TargetGroupID: "synthetic-new-group", HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, PrepareRequestID: prepare.Context.RequestID, PreparePacketDigest: ThreadCollaborationOwnerPacketDigest(original), ObservedAt: formatUTC(f.now), ReviewID: strings.Repeat("a", 32), Action: body.Action, BodyDigest: digest, ExpiresAt: formatUTC(f.now.Add(time.Minute)), Prepared: body}
	if ValidateThreadCollaborationOwnerReview(prepare, original, review, f.hub, f.now) != nil {
		t.Fatal("review correlation")
	}
	result := ThreadCollaborationOwnerResult{Format: ThreadCollaborationOwnerResultFormat, ContractRevision: ThreadCollaborationContractRevision, RequestID: prepare.Context.RequestID, RequestPacketDigest: ThreadCollaborationOwnerPacketDigest(original), HubID: f.hub.HubID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, ObservedAt: formatUTC(f.now), OperationID: prepare.Context.RequestID, OriginalPacketDigest: ThreadCollaborationOwnerPacketDigest(original), State: "COMPLETED", Review: &review}
	response, err := SealResponse(f.hubPrivate, f.device.Public(), route, result)
	if err != nil {
		t.Fatal("real response seal", err)
	}
	var received ThreadCollaborationOwnerResult
	if OpenThreadCollaborationOwnerResponse(f.device, f.hub, original, response, &received) != nil || VerifyThreadCollaborationOwnerResult(prepare, original, received, f.hub) != nil {
		t.Fatal("real response verify")
	}
	wrong := review
	wrong.PreparePacketDigest = strings.Repeat("0", 64)
	if _, err := NewThreadCollaborationOwnerApply(f.session, f.scope, prepare, original, wrong, f.owner, f.now); err == nil {
		t.Fatal("substituted review became apply")
	}
	apply, err := NewThreadCollaborationOwnerApply(f.session, f.scope, prepare, original, review, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := SealClientRequest(f.device, f.hub, apply)
	if err != nil {
		t.Fatal(err)
	}
	status, err := NewThreadCollaborationOwnerStatus(f.session, f.scope, applied, f.owner, f.now)
	if err != nil || status.Body.OriginalPacketDigest != ThreadCollaborationOwnerPacketDigest(applied) || status.Body.OperationID != apply.Context.RequestID {
		t.Fatal("status lost original", err)
	}
	reconcile, err := NewThreadCollaborationOwnerReconcile(f.session, f.scope, applied, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	read, err := NewThreadCollaborationOwnerRead(f.session, f.scope, ThreadCollaborationOwnerReadBody{View: "THREADS", NetworkID: "synthetic-network"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []any{read, apply, status, reconcile} {
		raw, err := SealClientRequest(f.device, f.hub, q)
		b, r, e := NewClientRoute(f.hub, q, f.device.Public())
		if err != nil || e != nil || PreflightThreadCollaborationTest(raw, r.Operation) != nil {
			t.Fatal("new operation absent from carrier", err, e)
		}
		var out any
		switch q.(type) {
		case ThreadCollaborationOwnerReadRequest:
			out = &ThreadCollaborationOwnerReadRequest{}
		case ThreadCollaborationOwnerApplyRequest:
			out = &ThreadCollaborationOwnerApplyRequest{}
		case ThreadCollaborationOwnerStatusRequest:
			out = &ThreadCollaborationOwnerStatusRequest{}
		case ThreadCollaborationOwnerReconcileRequest:
			out = &ThreadCollaborationOwnerReconcileRequest{}
		}
		if OpenRequestAt(f.hubPrivate, &f.scope.DevicePublic, b, r, raw, out, f.now) != nil {
			t.Fatal("new operation could not PQC open")
		}
	}
	if _, err := NewThreadCollaborationOwnerRead(f.session, f.scope, read.Body, f.device, f.now); err == nil {
		t.Fatal("account device substituted for Owner root")
	}
}

func PreflightThreadCollaborationTest(raw []byte, op string) error {
	_, err := PreflightRequest(raw, op)
	return err
}
