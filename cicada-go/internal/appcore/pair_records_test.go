package appcore

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// This fixture tests the real PQ envelopes and encrypted local CAS records.
// It does not create a real Pair domain, admit a Runtime, or run a model.
type pairRecordFixture struct {
	t     *testing.T
	n2    *activationActorFixture
	c     *nativeController
	root  string
	scope e2ee.OwnerNativePairScope
	id    string
}

func newPairRecordFixture(t *testing.T) *pairRecordFixture {
	t.Helper()
	f := &pairRecordFixture{t: t, n2: newActivationActorFixture(t), root: filepath.Join(t.TempDir(), "vaults"), id: strings.Repeat("a", 32)}
	f.c = f.n2.controller(t, f.root).(*nativeController)
	code, _ := wire.EncodeActivationCode(f.n2.material)
	for _, action := range []Action{{Kind: ActionConnect, ActivationCode: code}, {Kind: ActionGenerateOwner}} {
		if err := f.c.Dispatch(context.Background(), action); err != nil {
			t.Fatal(err)
		}
	}
	f.c.state.DeviceID = wire.AccountDeviceIDPrefix + strings.Repeat("2", 32)
	if err := f.c.persistState(); err != nil {
		t.Fatal(err)
	}
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	control, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	a := e2ee.OwnerAppNodeScope{Version: 1, Origin: f.c.connection.Origin, HubID: f.c.hub.HubID, HubFingerprint: f.c.connection.HubFingerprint,
		AccountID: f.c.state.AccountID, AccountSessionID: strings.Repeat("1", 64), AccountSessionExpiresAt: f.n2.now.Add(30 * time.Minute).Format(time.RFC3339Nano),
		OwnerID: f.c.state.OwnerID, OwnerPublic: f.c.owner.Public(), OwnerKeyVersion: 1, DeviceID: f.c.state.DeviceID, DevicePublic: f.c.device.Public(),
		AccountEpoch: 1, DeviceEpoch: 1, ClientSessionEpoch: 1, TransportPolicy: wire.AppNodeTransportHTTPS}
	f.scope = e2ee.OwnerNativePairScope{Actor: a, NodeControlBindingVersion: 1, CredentialCommitment: strings.Repeat("b", 64),
		Node: e2ee.OwnerAppNodeBinding{OwnerBindingID: "synthetic-pair-binding", OwnerID: a.OwnerID, HubID: a.HubID, NodeID: "synthetic-pair-node",
			NodeName: "Synthetic pair storage Node", ClientDeviceID: a.DeviceID, OwnerKeyID: a.OwnerPublic.ID, CredentialVersion: 1, BindingVersion: 1,
			NodePublic: node.Public(), NodeKeyFingerprint: nodewire.IdentityFingerprint(node.Public()), NodeKeyVersion: 1, NodeKeyEpoch: 1,
			HubNodeControlPublic: control.Public(), HubNodeControlFingerprint: nodewire.IdentityFingerprint(control.Public()), HubNodeControlKeyVersion: 1,
			ApprovedRequestID: "synthetic-pair-approved", ApprovedRequestVersion: 1, ApprovedCandidateDigest: strings.Repeat("c", 64),
			ApprovedAt: f.n2.now.Add(-time.Minute).Format(time.RFC3339Nano), State: "ACTIVE"}}
	f.scope.NodeTupleDigest, err = wire.NativePairNodeTupleDigest(f.scope)
	if err != nil || wire.ValidateNativePairScope(f.scope, f.c.hub) != nil {
		t.Fatal("invalid synthetic storage scope")
	}
	t.Cleanup(func() { _ = f.c.Close() })
	return f
}

func (f *pairRecordFixture) status() {
	f.t.Helper()
	ctx, err := f.c.pairRequestContext(f.scope, f.n2.now)
	if err != nil {
		f.t.Fatal(err)
	}
	q := wire.NativePairStatusRequest{Format: wire.NativePairFormat, Context: ctx, PairID: f.id}
	if err := f.c.beginPairOriginal(f.scope, f.id, q); err != nil {
		f.t.Fatal(err)
	}
}

func (f *pairRecordFixture) result(outcome string) []byte {
	f.t.Helper()
	r := f.c.pairOriginal
	result := wire.NativePairResult{Format: wire.NativePairFormat, Operation: r.Route.Operation, RequestID: r.Route.OperationID,
		RequestPacketDigest: r.Digest, PairID: f.id, State: wire.NativePairWaitingConsent, Outcome: outcome, ControlRevision: 1,
		SlotAState: wire.NativePairSlotReserved, SlotBState: wire.NativePairSlotReserved,
		PeerExpiresAt: f.n2.now.Add(time.Hour).Format(time.RFC3339Nano), ObservedAt: f.n2.now.Format(time.RFC3339Nano)}
	if outcome == "REJECTED_FENCED" {
		result.ErrorCode = "PAIR_STALE"
	}
	raw, err := wire.SealResponse(f.n2.hubKey, f.c.device.Public(), r.Route, result)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw
}

func (f *pairRecordFixture) reopen() {
	f.t.Helper()
	if err := f.c.Close(); err != nil {
		f.t.Fatal(err)
	}
	f.c = f.n2.controller(f.t, f.root).(*nativeController)
	resumeN2App(f.t, f.c)
	if err := f.c.loadPairState(); err != nil {
		f.t.Fatal(err)
	}
}

func TestPairRecordsReopenBetweenReceiptCASAndApplication(t *testing.T) {
	f := newPairRecordFixture(t)
	f.status()
	original := bytes.Clone(f.c.pairOriginal.Packet)
	dto := bytes.Clone(f.c.pairOriginal.DTO)
	defer clear(original)
	defer clear(dto)
	owner, device := f.c.owner.Public().ID, f.c.device.Public().ID
	raw := f.result("COMPLETED")
	if _, err := f.c.storePairResponse(pairOriginalResponseRecord, f.c.pairOriginal, raw, nil); err != nil {
		t.Fatal(err)
	}
	f.n2.now = f.n2.now.Add(2 * time.Hour)
	f.reopen()
	if f.c.hasPairPending() || !f.c.pairOriginal.Applied || !bytes.Equal(original, f.c.pairOriginal.Packet) || !bytes.Equal(dto, f.c.pairOriginal.DTO) ||
		f.c.pairOriginalResponse == nil || f.c.owner.Public().ID != owner || f.c.device.Public().ID != device || f.c.pair.View.AdministrativePermission {
		t.Fatal("reopen replaced the packet/keys or treated a saved receipt as live admission")
	}
}

func TestPairRecordRejectsForeignAndCorruptReceiptWithoutDiscardingOriginal(t *testing.T) {
	f := newPairRecordFixture(t)
	f.status()
	original := bytes.Clone(f.c.pairOriginal.Packet)
	defer clear(original)
	raw := f.result("COMPLETED")
	corrupt := bytes.Clone(raw)
	corrupt[len(corrupt)/2] ^= 1
	for _, response := range [][]byte{corrupt, []byte("synthetic unsigned HTTP failure")} {
		if _, err := f.c.storePairResponse(pairOriginalResponseRecord, f.c.pairOriginal, response, nil); err == nil {
			t.Fatal("unverified response became durable completion evidence")
		}
	}
	if !bytes.Equal(original, f.c.pairOriginal.Packet) || f.c.pairVersions[pairOriginalResponseRecord] != 0 || !f.c.hasPairPending() {
		t.Fatal("invalid response changed or discarded the original operation")
	}
	changed := *f.c.pairOriginal
	changed.Target.Vault.AccountID += "-other"
	if f.c.validatePairRequest(&changed, nil) == nil {
		t.Fatal("foreign vault scope was adopted")
	}
	changed = *f.c.pairOriginal
	changed.Target.Scope.Actor.AccountEpoch++
	if f.c.validatePairRequest(&changed, nil) == nil {
		t.Fatal("local DTO was relabelled with another account epoch")
	}
}

func TestPairRecoveryRenewsOnlyExpiredDiagnosticAndRejectsLateResponse(t *testing.T) {
	f := newPairRecordFixture(t)
	f.status()
	original := bytes.Clone(f.c.pairOriginal.Packet)
	defer clear(original)
	if err := f.c.beginPairRecovery(); err != nil {
		t.Fatal(err)
	}
	old := *f.c.pairRecovery
	old.Packet = bytes.Clone(old.Packet)
	defer clear(old.Packet)
	if f.c.beginPairRecovery() == nil {
		t.Fatal("live query was replaced")
	}
	f.n2.now = f.n2.now.Add(wire.MaxSessionRequestLifetime + time.Second)
	if err := f.c.beginPairRecovery(); err != nil {
		t.Fatal(err)
	}
	if f.c.pairRecovery.Route.OperationID == old.Route.OperationID || f.c.pairRecovery.Digest == old.Digest || !bytes.Equal(original, f.c.pairOriginal.Packet) || !reflect.DeepEqual(f.c.pairRecovery.Target, old.Target) {
		t.Fatal("diagnostic renewal altered the business original")
	}
	v := wire.NativePairReconciled{Format: wire.NativePairFormat, RequestID: old.Route.OperationID, RequestPacketDigest: old.Digest, PairID: f.id,
		OriginalOperation: f.c.pairOriginal.Route.Operation, OriginalRequestID: f.c.pairOriginal.Route.OperationID, OriginalPacketDigest: f.c.pairOriginal.Digest, State: "READ_EXPIRED", ObservedAt: f.n2.now.Format(time.RFC3339Nano)}
	raw, err := wire.SealResponse(f.n2.hubKey, f.c.device.Public(), old.Route, v)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.storePairResponse(pairRecoveryResponseRecord, f.c.pairRecovery, raw, f.c.pairOriginal); err == nil || !f.c.hasPairPending() || f.c.pairRecoveryResponse != nil {
		t.Fatal("late replaced-query reply completed the new query")
	}
}

func TestPairRecordCASConflictAndNamespaceBoundFailBeforeContinuation(t *testing.T) {
	f := newPairRecordFixture(t)
	f.status()
	raw, err := json.Marshal(f.c.pairOriginal)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	if _, err := f.c.vault.CompareAndSwapState(pairNamespaces[pairOriginalRecord], f.c.pairVersions[pairOriginalRecord], raw); err != nil {
		t.Fatal(err)
	}
	if err := f.c.persistPairRecord(pairOriginalRecord, f.c.pairOriginal); !errors.Is(err, appvault.ErrStateConflict) || !f.c.storageFault {
		t.Fatal("stale CAS allowed memory-only continuation")
	}
	f.c.storageFault = false // Test only the independent pre-serialization bound.
	if err := f.c.persistPairRecord(pairStateRecord, bytes.Repeat([]byte{0x53}, pairRecordLimit)); err == nil || f.c.pairVersions[pairStateRecord] != 0 || !f.c.storageFault {
		t.Fatal("oversized encoded record crossed the unchanged vault bound")
	}
}

func TestPairLargeResponseHasSeparateBoundedNamespace(t *testing.T) {
	f := newPairRecordFixture(t)
	f.status()
	// This is a storage-size probe, not an authenticated receipt. Crypto
	// acceptance is tested separately through storePairResponse.
	probe := pairResponseRecord{Format: "cicada.native-pair.response.v1", Target: f.c.pairOriginal.Target,
		RequestRoute: f.c.pairOriginal.Route, RequestDigest: f.c.pairOriginal.Digest,
		Packet: bytes.Repeat([]byte{0x53}, wire.MaxNativePairReconcilePacketBytes)}
	raw, err := json.Marshal(probe)
	if err != nil || len(raw) > pairRecordLimit {
		t.Fatal("bounded split record does not fit the existing vault")
	}
	defer clear(raw)
	if err := f.c.persistPairRecord(pairRecoveryResponseRecord, probe); err != nil {
		t.Fatal(err)
	}
	t.Logf("storage-only probe: response_bytes=%d encoded_namespace_bytes=%d limit=%d", len(probe.Packet), len(raw), pairRecordLimit)
	if _, err := f.c.storePairResponse(pairOriginalResponseRecord, f.c.pairOriginal, probe.Packet, nil); err == nil {
		t.Fatal("a storage-size probe was accepted as authenticated authority")
	}
}

func TestPairConsentPrepareFenceRecoversAcrossReconcileAndReopen(t *testing.T) {
	f := newPairRecordFixture(t)
	ctx, err := f.c.pairRequestContext(f.scope, f.n2.now)
	if err != nil {
		t.Fatal(err)
	}
	claims := e2ee.OwnerNativePairClaims{Version: 1, Purpose: e2ee.OwnerNativePairConsentPreview, Scope: f.scope,
		RequestID: ctx.RequestID, Nonce: hex.EncodeToString(ctx.ClientNonce), IssuedAt: ctx.IssuedAt,
		ExpiresAt: f.n2.now.Add(time.Minute).Format(time.RFC3339Nano), Consent: &e2ee.NativePairConsentClaims{PairID: f.id,
			ExpectedRevision: 1, SlotADigest: strings.Repeat("d", 64), SlotBDigest: strings.Repeat("e", 64), PeerExpiresAt: f.n2.now.Add(time.Hour).Format(time.RFC3339Nano)}}
	owner, _ := f.c.owner.E2EE()
	proof, err := e2ee.SignOwnerNativePair(owner, claims)
	if err != nil {
		t.Fatal(err)
	}
	q := wire.NativePairConsentPrepare{Format: wire.NativePairFormat, Context: ctx, SessionToken: bytes.Repeat([]byte{0x62}, 32), OwnerProof: proof}
	if err := f.c.beginPairOriginal(f.scope, f.id, q); err != nil {
		t.Fatal(err)
	}
	orig := f.c.pairOriginal
	fenced := wire.NativePairRejectionFence{Format: wire.NativePairFormat, Operation: orig.Route.Operation, RequestID: orig.Route.OperationID, RequestPacketDigest: orig.Digest, PairID: f.id, State: "REJECTED_FENCED", NoEffect: true, ErrorCode: "TARGET_UNAVAILABLE", ObservedAt: f.n2.now.Format(time.RFC3339Nano)}
	for _, field := range []string{"pair", "digest"} {
		bad := fenced
		if field == "pair" {
			bad.PairID = strings.Repeat("f", 32)
		} else {
			bad.RequestPacketDigest = strings.Repeat("f", 64)
		}
		raw, err := wire.SealResponse(f.n2.hubKey, f.c.device.Public(), orig.Route, bad)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.c.storePairResponse(pairOriginalResponseRecord, orig, raw, nil); err == nil || f.c.pairOriginalResponse != nil || !f.c.hasPairPending() {
			t.Fatal("foreign fence settled a local request")
		}
	}
	fence, err := wire.SealResponse(f.n2.hubKey, f.c.device.Public(), orig.Route, fenced)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := f.c.storePairResponse(pairOriginalResponseRecord, f.c.pairOriginal, fence, nil)
	if err != nil || opened.Plan != nil || opened.Rejection == nil {
		t.Fatal("signed no-effect prepare rejection was not retained as a fence")
	}
	if _, err := f.c.openPairReceipt(f.c.pairOriginal, f.result("COMPLETED"), nil); err == nil {
		t.Fatal("a generic success replaced the required exact consent plan")
	}
	if _, err := f.c.openPairReceipt(f.c.pairOriginal, f.result("REJECTED_FENCED"), nil); err == nil {
		t.Fatal("generic result replaced a dedicated no-effect fence")
	}
	if err := f.c.beginPairRecovery(); err != nil {
		t.Fatal(err)
	}
	r, original := f.c.pairRecovery, f.c.pairOriginal
	result := wire.NativePairReconciled{Format: wire.NativePairFormat, RequestID: r.Route.OperationID, RequestPacketDigest: r.Digest,
		PairID: f.id, OriginalOperation: original.Route.Operation, OriginalRequestID: original.Route.OperationID, OriginalPacketDigest: original.Digest,
		State: "REJECTED_FENCED", ReceiptPacket: fence, ObservedAt: f.n2.now.Format(time.RFC3339Nano)}
	wrongState := result
	wrongState.State = "COMPLETED"
	wrongRaw, err := wire.SealResponse(f.n2.hubKey, f.c.device.Public(), r.Route, wrongState)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.storePairResponse(pairRecoveryResponseRecord, r, wrongRaw, original); err == nil {
		t.Fatal("reconcile outcome contradicted its nested fence")
	}
	raw, err := wire.SealResponse(f.n2.hubKey, f.c.device.Public(), r.Route, result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.c.storePairResponse(pairRecoveryResponseRecord, r, raw, original); err != nil {
		t.Fatal(err)
	}
	f.n2.now = f.n2.now.Add(2 * time.Hour)
	f.reopen()
	if f.c.pairRecovery != nil || f.c.pairRecoveryResponse != nil || f.c.hasPairPending() || !f.c.pairOriginal.Applied || f.c.pair.View.AdministrativePermission {
		t.Fatal("reopen failed to settle the authenticated fence or enabled signing from expired history")
	}
}
