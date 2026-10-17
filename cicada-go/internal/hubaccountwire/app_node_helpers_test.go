package hubaccountwire

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
)

type appNodeCryptoFixture struct {
	hubPrivate, owner, device *e2ee.Identity
	hub                       HubIdentity
	session                   AppNodeSession
	scope                     e2ee.OwnerAppNodeScope
	claims                    e2ee.OwnerAppNodeGrantClaims
	now                       time.Time
}

func appNodeCrypto(t *testing.T) appNodeCryptoFixture {
	t.Helper()
	hub, _, _, _, ch, now := appNodeDraftFixture(t)
	var keys [3]*e2ee.Identity
	for i := range keys {
		var err error
		keys[i], err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
	}
	hub.Public = keys[0].Public()
	fp, err := HubFingerprint(hub)
	if err != nil {
		t.Fatal(err)
	}
	scope := ch.Claims.Scope
	scope.HeadVersion = 0
	scope.HubFingerprint = fp
	scope.OwnerPublic = keys[1].Public()
	scope.DevicePublic = keys[2].Public()
	session := AppNodeSession{Hub: hub, Origin: scope.Origin, AccountID: scope.AccountID, OwnerID: scope.OwnerID, DeviceID: scope.DeviceID, AccountEpoch: scope.AccountEpoch, DeviceEpoch: scope.DeviceEpoch, Token: bytes.Repeat([]byte{7}, MaxSessionTokenBytes)}
	return appNodeCryptoFixture{keys[0], keys[1], keys[2], hub, session, scope, ch.Claims, now}
}

func appNodePreparedCrypto(t *testing.T, f appNodeCryptoFixture) (AppNodePrepare, []byte, AppNodeChallenge) {
	t.Helper()
	p, err := NewAppNodePrepare(f.session, f.scope, AppNodePrepareTarget{Kind: AppNodeTargetInitial, Code: "2345-6789-ABCD"}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealClientRequest(f.device, f.hub, p)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := NewClientRoute(f.hub, p, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var opened AppNodePrepare
	pub := f.device.Public()
	if err := OpenRequestAt(f.hubPrivate, &pub, b, r, raw, &opened, f.now); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opened, p) {
		t.Fatal("prepare changed in real PQ envelope")
	}
	intent, err := e2ee.VerifyOwnerAppNodePreview(f.owner.Public(), p.OwnerIntent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	c := f.claims
	c.Scope = f.scope
	c.Scope.HeadVersion = 1
	c.ExpectedHeadVersion = 0
	c.GrantID = intent.GrantID
	c.PrepareRequestID = p.Context.RequestID
	c.PreparePacketDigest = AppNodePacketDigest(raw)
	c.PreviewProofDigest = AppNodeProofDigest(p.OwnerIntent)
	ch := AppNodeChallenge{Format: AppNodeChallengeFormat, RequestID: p.Context.RequestID, RequestPacketDigest: AppNodePacketDigest(raw), Claims: c, ObservedAt: formatUTC(f.now)}
	response, err := SealResponse(f.hubPrivate, pub, r, ch)
	if err != nil {
		t.Fatal(err)
	}
	var out AppNodeChallenge
	if err := OpenClientResponse(f.device, f.hub, raw, response, &out); err != nil {
		t.Fatal(err)
	}
	return p, raw, out
}

func TestAppNodeHelpersRealOwnerProofAndPQRoundTrip(t *testing.T) {
	f := appNodeCrypto(t)
	p, raw, ch := appNodePreparedCrypto(t, f)
	complete, err := NewAppNodeComplete(f.session, p, raw, ch, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := e2ee.VerifyOwnerAppNodeGrant(f.owner.Public(), complete.OwnerGrant, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(grant, ch.Claims) {
		t.Fatal("Owner signed a different exact target")
	}
	packet, err := SealClientRequest(f.device, f.hub, complete)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := NewClientRoute(f.hub, complete, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	var opened AppNodeComplete
	pub := f.device.Public()
	if err := OpenRequestAt(f.hubPrivate, &pub, b, r, packet, &opened, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opened, complete) {
		t.Fatal("complete changed")
	}
	if _, err := e2ee.VerifyOwnerAppNodeGrant(f.owner.Public(), complete.OwnerGrant, f.now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired proof admitted")
	}
	if _, err := e2ee.VerifyOwnerAppNodeGrant(f.owner.Public(), complete.OwnerGrant, time.Time{}); err != nil {
		t.Fatal("historical signature not recoverable")
	}
	if _, err := NewAppNodeComplete(f.session, p, raw, ch, f.owner, f.now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired challenge produced fresh completion")
	}
	if _, err := e2ee.VerifyOwnerAppNodePreview(f.owner.Public(), complete.OwnerGrant, f.now); err == nil {
		t.Fatal("grant crossed into preview domain")
	}
	if _, err := e2ee.VerifyOwnerAppNodeGrant(f.device.Public(), complete.OwnerGrant, f.now); err == nil {
		t.Fatal("foreign trusted signer accepted")
	}
	var altered e2ee.OwnerAppNodeGrant
	if err := json.Unmarshal(complete.OwnerGrant, &altered); err != nil {
		t.Fatal(err)
	}
	altered.Claims.Candidate.NodeName = "substituted"
	bad, _ := json.Marshal(altered)
	if _, err := e2ee.VerifyOwnerAppNodeGrant(f.owner.Public(), bad, f.now); err == nil {
		t.Fatal("changed signed target accepted")
	}
	if _, err := e2ee.VerifyOwnerAppNodeGrant(f.owner.Public(), append(complete.OwnerGrant, '\n'), f.now); err == nil {
		t.Fatal("noncanonical proof accepted")
	}
	if _, err := SealClientRequest(f.owner, f.hub, p); err == nil {
		t.Fatal("Owner key substituted for separate App key")
	}
}

func TestAppNodeHelpersOwnStatusCancelAndReadSettlement(t *testing.T) {
	f := appNodeCrypto(t)
	status, err := NewAppNodeStatus(f.session, "", f.now)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := SealClientRequest(f.device, f.hub, status)
	if err != nil {
		t.Fatal(err)
	}
	query, err := NewAppNodeReconcile(f.session, AppNodeOriginalAuthority, "", packet, f.now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SealClientRequest(f.device, f.hub, query)
	if err != nil {
		t.Fatal(err)
	}
	b, r, _ := NewClientRoute(f.hub, query, f.device.Public())
	pub := f.device.Public()
	var opened AppNodeReconcileRequest
	if err := OpenRequestAt(f.hubPrivate, &pub, b, r, raw, &opened, f.now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	result := AppNodeReconcileResult{Format: AppNodeReconciledFormat, Origin: f.scope.Origin, HubID: f.hub.HubID, AccountID: f.scope.AccountID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID,
		RequestID: query.Context.RequestID, RequestPacketDigest: AppNodePacketDigest(raw), OriginalKind: AppNodeOriginalAuthority, OriginalOperation: OperationAppNodeStatus, OriginalRequestID: status.Context.RequestID, OriginalPacketDigest: AppNodePacketDigest(packet),
		State: AppNodeReadExpired, AccountEpoch: 1, DeviceEpoch: 1, CurrentGrantState: AppNodeAbsent, ObservedAt: formatUTC(f.now.Add(2 * time.Minute))}
	response, err := SealResponse(f.hubPrivate, pub, r, result)
	if err != nil {
		t.Fatal(err)
	}
	var got AppNodeReconcileResult
	if err := OpenClientResponse(f.device, f.hub, raw, response, &got); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAppNodeReconcileTarget(got, AppNodeOriginalAuthority, packet); err != nil {
		t.Fatal(err)
	}
	got.OriginalPacketDigest = AppNodePacketDigest([]byte("synthetic-other"))
	if ValidateAppNodeReconcileTarget(got, AppNodeOriginalAuthority, packet) == nil {
		t.Fatal("wrong original digest settled")
	}
	if _, err := NewAppNodeCancel(f.session, "bad", 0, f.now); err == nil {
		t.Fatal("malformed cancel target accepted")
	}
	_, _, ch := appNodePreparedCrypto(t, f)
	cancel, err := NewAppNodeCancel(f.session, ch.Claims.GrantID, 0, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealClientRequest(f.device, f.hub, cancel); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAppNodeReconcile(f.session, AppNodeOriginalAuthority, "", raw, f.now); err == nil {
		t.Fatal("diagnostic request became recursive reconciliation target")
	}
}

func TestAppNodeHelpersReadExistingRealProofAndPQRoundTrip(t *testing.T) {
	f := appNodeCrypto(t)
	f.scope.HeadVersion = 2 // self-cancel advanced the published head
	previous := strings.Repeat("2", 32)
	p, err := NewAppNodePrepare(f.session, f.scope, AppNodePrepareTarget{Kind: AppNodeTargetPrevious, PreviousGrantID: previous}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := SealClientRequest(f.device, f.hub, p)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := e2ee.VerifyOwnerAppNodePreview(f.owner.Public(), p.OwnerIntent, f.now)
	if err != nil {
		t.Fatal(err)
	}
	c := f.claims
	n := c.Candidate
	c.Scope, c.ExpectedHeadVersion = f.scope, 2
	c.Scope.HeadVersion = 3
	c.GrantID, c.PrepareRequestID = intent.GrantID, p.Context.RequestID
	c.PreparePacketDigest, c.PreviewProofDigest = AppNodePacketDigest(original), AppNodeProofDigest(p.OwnerIntent)
	c.Purpose, c.Profile = e2ee.OwnerAppNodeStatusGrantPurpose, AppNodeProfileStatus
	c.PreviousGrantID, c.ConfirmationProvenanceID = previous, strings.Repeat("3", 32)
	c.AllowedOperations, c.ConfirmationLimit, c.Candidate = AppNodeStatusAllowedOperations(), 0, nil
	c.Binding = &e2ee.OwnerAppNodeBinding{OwnerBindingID: "synthetic-binding", OwnerID: c.Scope.OwnerID, HubID: c.Scope.HubID, NodeID: n.NodeID, NodeName: n.NodeName, ClientDeviceID: c.Scope.DeviceID, OwnerKeyID: c.Scope.OwnerPublic.ID,
		CredentialVersion: 1, BindingVersion: 1, NodePublic: n.NodePublic, NodeKeyFingerprint: n.NodeKeyFingerprint, NodeKeyVersion: 1, NodeKeyEpoch: n.NodeKeyEpoch,
		HubNodeControlPublic: n.HubNodeControlPublic, HubNodeControlFingerprint: n.HubNodeControlFingerprint, HubNodeControlKeyVersion: n.HubNodeControlKeyVersion,
		ApprovedRequestID: n.RequestID, ApprovedRequestVersion: n.Version, ApprovedCandidateDigest: n.CandidateDigest, ApprovedAt: formatUTC(f.now.Add(-time.Minute)), State: "ACTIVE"}
	ch := AppNodeChallenge{Format: AppNodeChallengeFormat, RequestID: p.Context.RequestID, RequestPacketDigest: AppNodePacketDigest(original), Claims: c, ObservedAt: formatUTC(f.now)}
	_, route, err := NewClientRoute(f.hub, p, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealResponse(f.hubPrivate, f.device.Public(), route, ch)
	if err != nil {
		t.Fatal(err)
	}
	var opened AppNodeChallenge
	if err := OpenClientResponse(f.device, f.hub, original, sealed, &opened); err != nil {
		t.Fatal(err)
	}
	complete, err := NewAppNodeComplete(f.session, p, original, opened, f.owner, f.now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := e2ee.VerifyOwnerAppNodeGrant(f.owner.Public(), complete.OwnerGrant, f.now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(verified, c) {
		t.Fatal("different status-only grant", err)
	}
	live := AppNodeResult{Format: AppNodeResultFormat, Operation: OperationAppNodeStatus, RequestID: p.Context.RequestID, RequestPacketDigest: AppNodePacketDigest(original), State: AppNodeCompleted, ObservedAt: formatUTC(f.now),
		Authority: AppNodeAuthoritySnapshot{Scope: c.Scope, GrantID: c.GrantID, Profile: c.Profile, State: AppNodeActive, CurrentHeadVersion: c.Scope.HeadVersion, LatestGrantID: c.GrantID, RootState: RootActiveState, AllowedOperations: []string{}, LeaseExpiresAt: c.LeaseExpiresAt, ConfirmationProvenanceID: c.ConfirmationProvenanceID, Counters: AppNodeClientCounters{SessionEpoch: c.Scope.ClientSessionEpoch, NextResponseSequence: 1}}}
	if err := ValidateAppNodeLiveResult(live, c, f.hub, f.now); err != nil {
		t.Fatal(err)
	}
	live.Authority.ConfirmationProvenanceID = strings.Repeat("5", 32)
	if ValidateAppNodeLiveResult(live, c, f.hub, f.now) == nil {
		t.Fatal("unrelated confirmation provenance replaced retained status grant")
	}
	if _, err := SealAppNodeConfirmation(f.device, f.hub, verified, "23456789ABCD", 1, f.now); err == nil {
		t.Fatal("status-only grant acquired confirmation permission")
	}
	opened.Claims.PreviousGrantID = strings.Repeat("4", 32)
	if _, err := NewAppNodeComplete(f.session, p, original, opened, f.owner, f.now); err == nil {
		t.Fatal("another confirmed parent replaced explicit consent")
	}
}

func TestAppNodeHelpersRejectSignedReadExpiredAuthorityAndBadLiveSnapshots(t *testing.T) {
	f := appNodeCrypto(t)
	_, _, ch := appNodePreparedCrypto(t, f)
	s, err := NewAppNodeStatus(f.session, ch.Claims.GrantID, f.now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := SealClientRequest(f.device, f.hub, s)
	if err != nil {
		t.Fatal(err)
	}
	b, r, err := NewClientRoute(f.hub, s, f.device.Public())
	if err != nil {
		t.Fatal(err)
	}
	a := AppNodeAuthoritySnapshot{Scope: ch.Claims.Scope, GrantID: ch.Claims.GrantID, State: AppNodeActive, Profile: AppNodeProfileInitial, CurrentHeadVersion: 1, LatestGrantID: ch.Claims.GrantID, RootState: RootActiveState,
		AllowedOperations: AppNodeAllowedOperations(), RemainingConfirmations: 1, LeaseExpiresAt: ch.Claims.LeaseExpiresAt, Counters: AppNodeClientCounters{SessionEpoch: 1, LastRequestSequence: 0, NextResponseSequence: 1}}
	base := AppNodeResult{Format: AppNodeResultFormat, Operation: OperationAppNodeStatus, RequestID: s.Context.RequestID, RequestPacketDigest: AppNodePacketDigest(original), State: AppNodeCompleted, Authority: a, ObservedAt: formatUTC(f.now)}
	sealUnchecked := func(v AppNodeResult) []byte {
		plain, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := clientwire.SealResponseWithLimits(f.hubPrivate, f.device.Public(), b, responseRoute(r), plain, MaxAppNodeBodyBytes, MaxAppNodeInnerPacketBytes)
		if err != nil {
			t.Fatal(err)
		}
		var p clientwire.Packet
		if err := json.Unmarshal(inner, &p); err != nil {
			t.Fatal(err)
		}
		outer, err := json.Marshal(Packet{Format: PacketFormat, Version: PacketVersion, SenderPublicIdentity: f.hub.Public, Packet: p})
		if err != nil {
			t.Fatal(err)
		}
		return outer
	}
	var valid AppNodeResult
	if err := OpenClientResponse(f.device, f.hub, original, sealUnchecked(base), &valid); err != nil {
		t.Fatal("valid live snapshot rejected", err)
	}
	cases := map[string]func(*AppNodeResult){
		"read-expired-keeps-confirm": func(v *AppNodeResult) { v.State = AppNodeReadExpired; v.ErrorCode = AppNodeReadExpired },
		"read-expired-keeps-budget": func(v *AppNodeResult) {
			v.State = AppNodeReadExpired
			v.ErrorCode = AppNodeReadExpired
			v.Authority.AllowedOperations = []string{}
		},
		"wrong-head":            func(v *AppNodeResult) { v.Authority.CurrentHeadVersion++ },
		"missing-session":       func(v *AppNodeResult) { v.Authority.Scope.AccountSessionID = "" },
		"wrong-latest-instance": func(v *AppNodeResult) { v.Authority.LatestGrantID = "" },
		"bad-counter-epoch":     func(v *AppNodeResult) { v.Authority.Counters.SessionEpoch++ },
		"zero-next-response":    func(v *AppNodeResult) { v.Authority.Counters.NextResponseSequence = 0 },
		"ended-bound-session":   func(v *AppNodeResult) { v.Authority.Scope.AccountSessionExpiresAt = formatUTC(f.now) },
		"ended-lease":           func(v *AppNodeResult) { v.Authority.LeaseExpiresAt = formatUTC(f.now) },
		"unknown-profile":       func(v *AppNodeResult) { v.Authority.Profile = "unbounded" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			copyRaw, _ := json.Marshal(base)
			var altered AppNodeResult
			_ = json.Unmarshal(copyRaw, &altered)
			change(&altered)
			var got AppNodeResult
			if OpenClientResponse(f.device, f.hub, original, sealUnchecked(altered), &got) == nil {
				t.Fatal("genuine Hub signature bypassed semantic guard")
			}
		})
	}
	readExpired := base
	readExpired.State = AppNodeReadExpired
	readExpired.ErrorCode = AppNodeReadExpired
	readExpired.Authority.AllowedOperations = []string{}
	readExpired.Authority.RemainingConfirmations = 0
	if err := OpenClientResponse(f.device, f.hub, original, sealUnchecked(readExpired), &valid); err != nil {
		t.Fatal("safe read settlement rejected", err)
	}
}
