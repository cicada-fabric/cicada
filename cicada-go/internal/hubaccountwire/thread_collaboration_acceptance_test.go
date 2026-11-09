package hubaccountwire

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

// These are independent checks of the frozen codec/PQC boundary. They do not
// claim that a decoder grants membership or that a Hub lease was acquired.
func acceptanceGroupLockRequest(t *testing.T) (GroupLockHolder, GroupLockAcquireRequest) {
	t.Helper()
	original, err := NewGroupLockOriginal(time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	holder := GroupLockHolder{NodeID: "SYNTHETIC-node", EndpointID: "SYNTHETIC-endpoint", PrincipalID: "SYNTHETIC-principal", Source: ThreadRegistrationSource{RegistrationID: "SYNTHETIC-registration", SourceEpoch: 1}}
	request := GroupLockAcquireRequest{Scope: GroupLockScope{HubID: "SYNTHETIC-hub", NetworkID: "SYNTHETIC-network", GroupID: "SYNTHETIC-group"}, Slot: 1, ExpectedVersion: 1, Original: original, Note: "SYNTHETIC protocol note"}
	return holder, request
}

func TestAcceptanceGroupLockOriginalDigestBindsAuthorityAndTTL(t *testing.T) {
	holder, original := acceptanceGroupLockRequest(t)
	digest, err := GroupLockRequestDigest(OperationGroupLocksAcquire, holder, original)
	if err != nil {
		t.Fatal(err)
	}
	original.Original.RequestDigest = digest
	if VerifyGroupLockRequestDigest(OperationGroupLocksAcquire, holder, original) != nil {
		t.Fatal("valid original digest refused")
	}
	for _, change := range []string{"hub", "network", "group", "slot", "version", "ttl-explicit-default", "ttl-other", "note", "operation-id", "idempotency-key", "node", "endpoint", "principal", "registration", "source-epoch"} {
		t.Run(change, func(t *testing.T) {
			caller, request := holder, original
			alternative, err := NewGroupLockOriginal(time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "hub":
				request.Scope.HubID += "-other"
			case "network":
				request.Scope.NetworkID += "-other"
			case "group":
				request.Scope.GroupID += "-other"
			case "slot":
				request.Slot = 8
			case "version":
				request.ExpectedVersion++
			case "ttl-explicit-default":
				n := uint32(300)
				request.TTLSeconds = &n
			case "ttl-other":
				n := uint32(3600)
				request.TTLSeconds = &n
			case "note":
				request.Note += " changed"
			case "operation-id":
				request.Original.OperationID = alternative.OperationID
			case "idempotency-key":
				request.Original.IdempotencyKey = alternative.IdempotencyKey
			case "node":
				caller.NodeID += "-other"
			case "endpoint":
				caller.EndpointID += "-other"
			case "principal":
				caller.PrincipalID += "-other"
			case "registration":
				caller.Source.RegistrationID += "-other"
			case "source-epoch":
				caller.Source.SourceEpoch++
			}
			changedDigest, err := GroupLockRequestDigest(OperationGroupLocksAcquire, caller, request)
			if err != nil {
				t.Fatal("altered request must remain legal before testing digest binding", err)
			}
			if changedDigest == digest {
				t.Fatal("altered legal authority/request kept original digest")
			}
			if VerifyGroupLockRequestDigest(OperationGroupLocksAcquire, caller, request) == nil {
				t.Fatal("old original digest accepted altered authority or request bytes")
			}
		})
	}
}

func TestAcceptanceGroupLockLeaseTimeAndHistoricalReceipt(t *testing.T) {
	observed := time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)
	for _, n := range []uint32{0, 1, 300, 3600} {
		var ttl *uint32
		want := uint32(300)
		if n != 0 {
			ttl, want = &n, n
		}
		expires, err := GroupLockLeaseExpiry(ttl, observed)
		if err != nil || expires != observed.Add(time.Duration(want)*time.Second).Format(time.RFC3339Nano) {
			t.Fatal("lease expiry was not anchored to original server observation", err)
		}
		retry, err := GroupLockLeaseExpiry(ttl, observed)
		if err != nil || retry != expires {
			t.Fatal("same original observation extended lease", err)
		}
	}
	holder, request := acceptanceGroupLockRequest(t)
	end := observed.Add(300 * time.Second).Format(time.RFC3339Nano)
	receipt := GroupLockReceipt{Format: GroupLockReceiptFormat, Scope: request.Scope, OperationID: request.Original.OperationID, RequestDigest: request.Original.RequestDigest, Slot: 1, AppliedVersion: 2, Generation: 1, Outcome: "ACQUIRED", ObservedAt: observed.Format(time.RFC3339Nano), ExpiresAt: end}
	if ValidateGroupLockReceipt(receipt) != nil {
		t.Fatal("historical success could not settle its original operation")
	}
	view := GroupSlotView{Format: GroupSlotViewFormat, Scope: request.Scope, ObservedAt: observed.Add(301 * time.Second).Format(time.RFC3339Nano), PolicyRevision: 1, PolicyState: "ENABLED"}
	for i := uint8(1); i <= 8; i++ {
		view.Slots = append(view.Slots, GroupLockSlot{Slot: i, State: "FREE", Version: 1})
	}
	view.Slots[0] = GroupLockSlot{Slot: 1, State: "HELD", Version: 2, Generation: 1, Holder: &holder, HolderNameState: "NOT_DISCLOSED", ExpiresAt: end}
	if ValidateGroupSlotView(view) == nil {
		t.Fatal("historical acquire was represented as a current expired hold")
	}
	view.Slots[0] = GroupLockSlot{Slot: 1, State: "FREE", Version: 3, Generation: 1}
	if ValidateGroupSlotView(view) != nil || ValidateGroupLockReceipt(receipt) != nil {
		t.Fatal("normalized current view and historical success were conflated")
	}
}

func TestAcceptanceGroupLockClosedNativeBodiesRejectInventedAuthority(t *testing.T) {
	holder, request := acceptanceGroupLockRequest(t)
	for _, ttl := range []*uint32{nil, func() *uint32 { n := uint32(1); return &n }(), func() *uint32 { n := uint32(3600); return &n }()} {
		request.TTLSeconds = ttl
		raw, _ := json.Marshal(GroupLocksNodeAcquire{EndpointID: holder.EndpointID, Request: request})
		if _, err := DecodeThreadCollaborationNodeBody(OperationGroupLocksAcquire, raw); err != nil {
			t.Fatal("valid explicit lease boundary refused", err)
		}
	}
	request.TTLSeconds = nil
	for _, field := range []string{"resource_id", "task_id", "holder_endpoint_id", "native_session_id", "account_id", "classification"} {
		t.Run(field, func(t *testing.T) {
			raw, _ := json.Marshal(GroupLocksNodeAcquire{EndpointID: holder.EndpointID, Request: request})
			// Inject inside the request object, keeping the surrounding real
			// carrier shape. A declared holder/class is never authentication.
			raw = append(raw[:len(raw)-2], []byte(`,"`+field+`":"SYNTHETIC-forged"}}`)...)
			if !json.Valid(raw) {
				t.Fatal("invalid QA attack fixture")
			}
			if _, err := DecodeThreadCollaborationNodeBody(OperationGroupLocksAcquire, raw); err == nil {
				t.Fatal("invented resource/task/native authority entered closed carrier")
			}
		})
	}
}

func TestAcceptanceThreadOwnerProofSurvivesRealDeviceEncryptionAttacks(t *testing.T) {
	f := localDomainCrypto(t).f
	body := ThreadCollaborationOwnerPrepareBody{Action: ThreadCollaborationCreateGroupWithPolicy, Policy: &GroupPolicyChange{NetworkID: "SYNTHETIC-network", Name: "SYNTHETIC coordination", SlotCount: 8, Rights: GroupCoordinationRights()}}
	request, err := NewThreadCollaborationOwnerPrepare(f.session, f.scope, body, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	binding, route, err := NewClientRoute(f.hub, request, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	valid, err := SealClientRequest(f.device, f.hub, request)
	if err != nil {
		t.Fatal(err)
	}
	var good ThreadCollaborationOwnerPrepareRequest
	if OpenRequestAt(f.hubPrivate, &f.scope.DevicePublic, binding, route, valid, &good, f.now) != nil || !reflect.DeepEqual(good, request) {
		t.Fatal("real PQC positive control failed")
	}
	if _, err := NewThreadCollaborationOwnerPrepare(f.session, f.scope, body, f.device, f.now); err == nil {
		t.Fatal("account device key became Owner authority")
	}
	for _, attack := range []string{"missing-proof", "changed-policy", "changed-network", "changed-owner-purpose", "corrupt-owner-signature"} {
		t.Run(attack, func(t *testing.T) {
			q := request
			policy := *request.Body.Policy
			q.Body.Policy = &policy
			var proof e2ee.OwnerEndpointGroupsRequestProof
			if json.Unmarshal(q.OwnerProof, &proof) != nil {
				t.Fatal("synthetic Owner proof unavailable")
			}
			switch attack {
			case "missing-proof":
				q.OwnerProof = nil
			case "changed-policy":
				q.Body.Policy.Name += "-changed"
			case "changed-network":
				q.Body.Policy.NetworkID += "-other"
			case "changed-owner-purpose":
				proof.Claims.Purpose = ThreadCollaborationOwnerPurpose(OperationThreadCollaborationOwnerRead)
				q.OwnerProof, err = e2ee.SignOwnerEndpointGroupsRequest(f.owner, proof.Claims)
				if err != nil {
					t.Fatal(err)
				}
			case "corrupt-owner-signature":
				proof.Signature[0] ^= 1
				q.OwnerProof, _ = json.Marshal(proof)
			}
			plain, err := json.Marshal(q)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(plain)
			// Deliberately bypass the convenience request validator as a real
			// malicious device can: make a correctly device-signed/encrypted
			// packet with invalid Owner authority using the production PQC.
			inner, err := clientwire.SealRequestWithLimits(f.device, f.hub.Public, binding, route, plain, maxBodyForOperation(route.Operation), innerLimitForOperation(route.Operation))
			if err != nil {
				t.Fatal(err)
			}
			var packet clientwire.Packet
			if json.Unmarshal(inner, &packet) != nil {
				t.Fatal("real inner packet decode")
			}
			raw, err := marshalPacket(Packet{Format: PacketFormat, Version: PacketVersion, SenderPublicIdentity: f.device.Public(), Packet: packet})
			if err != nil {
				t.Fatal(err)
			}
			var got ThreadCollaborationOwnerPrepareRequest
			if OpenRequestAt(f.hubPrivate, &f.scope.DevicePublic, binding, route, raw, &got, f.now) == nil {
				t.Fatal("valid device encryption bypassed exact Owner proof")
			}
		})
	}
}
