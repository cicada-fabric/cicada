package hubaccountwire

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func installationInventory(t *testing.T) (installationWireFixture, InstallationConnectionsRead, []byte, InstallationConnectionsSnapshot) {
	t.Helper()
	f := installationWire(t)
	h := f.account(11, OperationOwnerConnectionsRead)
	q := e2ee.InstallationReadQuery{HubID: f.scope.HubID, AccountID: f.scope.AccountID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, AccountEpoch: f.scope.AccountEpoch, DeviceEpoch: f.scope.DeviceEpoch, RequestID: h.Account.RequestID, Nonce: fmt.Sprintf("%x", h.Account.ClientNonce), TargetKind: "INSTALLATIONS", PageSize: 50}
	d, _ := e2ee.InstallationReadQueryDigest(q)
	proof, err := e2ee.SignInstallationOwnerRead(f.owner, e2ee.InstallationOwnerReadClaims{Version: 1, Purpose: e2ee.InstallationReadPurpose, Scope: f.scope, RequestID: q.RequestID, Nonce: q.Nonce, QueryDigest: d, IssuedAt: formatUTC(f.now), ExpiresAt: formatUTC(f.now.Add(time.Minute))}, q)
	if err != nil {
		t.Fatal(err)
	}
	body := InstallationConnectionsRead{Format: InstallationFormat, SessionToken: bytes.Repeat([]byte{1}, 32), Query: q, Authorization: InstallationReadAuthorization{Kind: InstallationOwnerReadAuth, OwnerReadProof: proof}}
	raw, err := SealInstallationRequest(f.app, f.hub, h, body)
	if err != nil {
		t.Fatal(err)
	}
	s := InstallationConnectionsSnapshot{Format: InstallationFormat, RequestID: q.RequestID, RequestPacketDigest: e2ee.InstallationPacketDigest(raw), SnapshotRevision: 1, ActorScope: f.scope, Grants: []InstallationGrantRef{}, Parents: []InstallationParent{}, Subjects: []InstallationSubjectBinding{}, PendingAttempts: []InstallationPendingAttemptRef{}, Nodes: []AppNodeObservation{}, Pairs: []NativePairResult{}, ObservedAt: formatUTC(f.now)}
	return f, body, raw, s
}

func TestInstallationWireRevisedInventoryAndOwnContext(t *testing.T) {
	f, q, raw, s := installationInventory(t)
	parent := InstallationParent{InstallationID: f.candidate.Base.InstallationID, RegistrationID: strings.Repeat("45", 16), RegistrationEpoch: 1, AdmissionCredentialVersion: 1, OwnerID: f.scope.OwnerID, State: InstallationRegistered, Revision: 1}
	subject := InstallationSubjectBinding{SubjectRegistrationID: strings.Repeat("56", 16), SubjectRegistrationEpoch: 1, ParentRegistrationID: parent.RegistrationID, InstallationID: parent.InstallationID, OwnerID: parent.OwnerID, Kind: e2ee.InstallationAppSubject, InstanceID: "synthetic-recipient-app", Public: f.nc.Public(), State: InstallationRegistered, Revision: 1, AuthProvenance: InstallationNewRegisteredOnly}
	fp, _ := e2ee.OwnerDevicePublicKeyFingerprint(f.subject.Public())
	pending := InstallationPendingAttemptRef{AttemptID: f.candidate.Base.AttemptID, CandidateDigest: f.candidate.CandidateDigest, InstallationID: parent.InstallationID, SubjectKind: e2ee.InstallationNodeSubject, SubjectFingerprint: fp, State: InstallationPending, Revision: 1, ExpiresAt: f.candidate.Base.ExpiresAt}
	s.Parents, s.Subjects, s.PendingAttempts = []InstallationParent{parent}, []InstallationSubjectBinding{subject}, []InstallationPendingAttemptRef{pending}
	if ValidateInstallationSnapshotQuery(q.Query, q.Authorization, s) != nil {
		t.Fatal("Owner cannot discover actual subjects and pending references")
	}
	sealed, err := SealInstallationResponse(f.hubKey, f.hub, raw, s)
	if err != nil {
		t.Fatal(err)
	}
	var got InstallationConnectionsSnapshot
	if OpenInstallationResponse(f.app, f.hub, raw, sealed, &got) != nil || got.ActorScope.AccountSessionID != f.scope.AccountSessionID || got.Subjects[0].SubjectRegistrationID != subject.SubjectRegistrationID || got.PendingAttempts[0].CandidateDigest != pending.CandidateDigest {
		t.Fatal("inventory/context lost exact coordinates")
	}
	bad := installationWireClone(s)
	bad.ActorScope.DeviceID = "foreign-app"
	if _, err := SealInstallationResponse(f.hubKey, f.hub, raw, bad); err == nil {
		t.Fatal("snapshot context crossed original actor")
	}
	bad = installationWireClone(s)
	bad.ActorScope = e2ee.InstallationAccountScope{}
	if _, err := SealInstallationResponse(f.hubKey, f.hub, raw, bad); err == nil {
		t.Fatal("scope footer omitted")
	}
	recipient := InstallationReadAuthorization{Kind: InstallationRecipientGrantsAuth}
	if ValidateInstallationSnapshotQuery(q.Query, recipient, s) == nil {
		t.Fatal("recipient acquired Owner inventory")
	}
	own := installationWireClone(s)
	own.Parents = nil
	own.Subjects = nil
	own.PendingAttempts = nil
	ownQuery := q.Query
	ownQuery.TargetKind = "GRANTED"
	if ValidateInstallationSnapshotQuery(ownQuery, recipient, own) != nil || len(own.Grants) != 0 {
		t.Fatal("zero-grant account cannot discover its real context")
	}
	for _, kind := range []string{"INSTALLATIONS", "GRANTED", "NODE_STATUS", "PAIR_STATUS", "INVENTORY", "*"} {
		check := q.Query
		check.TargetKind = kind
		if kind == "NODE_STATUS" || kind == "PAIR_STATUS" {
			check.TargetIDs = []string{"synthetic-target"}
		}
		if (e2ee.ValidateInstallationReadQuery(check) == nil) != (kind != "INVENTORY" && kind != "*") {
			t.Fatal("query kind set changed")
		}
	}
	newNode := subject
	newNode.Kind = e2ee.InstallationNodeSubject
	newNode.Public = f.subject.Public()
	newNode.InstanceID = f.candidate.Base.Subject.Node.NodeID
	if ValidateInstallationSubjectBinding(newNode) != nil || newNode.NodeBinding != nil {
		t.Fatal("new Node required legacy binding")
	}
	newNode.NodeBinding = &e2ee.OwnerAppNodeBinding{}
	if ValidateInstallationSubjectBinding(newNode) == nil {
		t.Fatal("new Node claimed invented legacy binding")
	}
	n := AppNodeObservation{NodeID: subject.InstanceID, BindingID: subject.SubjectRegistrationID, BindingVersion: 1, NodeKeyID: subject.Public.ID, NodeKeyFingerprint: fp, NodeKeyEpoch: 1, BindingState: InstallationRegistered, Connectivity: "UNKNOWN", Stale: true, Source: InstallationHeartbeatSource, ObservedAt: formatUTC(f.now)}
	if ValidateInstallationNodeObservation(n) != nil || n.CredentialVersion != 0 {
		t.Fatal("new registration observation manufactured bearer")
	}
	n.CredentialVersion = 1
	if ValidateInstallationNodeObservation(n) == nil {
		t.Fatal("new registration observation advertised legacy credential")
	}
}

func TestInstallationWireMixedInventoryBytePagination(t *testing.T) {
	f, q, raw, s := installationInventory(t)
	parent := InstallationParent{InstallationID: f.candidate.Base.InstallationID, RegistrationID: strings.Repeat("45", 16), RegistrationEpoch: 1, AdmissionCredentialVersion: 1, OwnerID: f.scope.OwnerID, State: InstallationRegistered, Revision: 1}
	s.OwnParent = &parent
	s.OwnSubject = &InstallationSubjectBinding{SubjectRegistrationID: strings.Repeat("67", 16), SubjectRegistrationEpoch: 1, ParentRegistrationID: parent.RegistrationID, InstallationID: parent.InstallationID, OwnerID: parent.OwnerID, Kind: e2ee.InstallationAppSubject, InstanceID: f.scope.DeviceID, Public: f.app.Public(), State: InstallationRegistered, Revision: 1, AuthProvenance: InstallationNewRegisteredOnly}
	// These are real public-key shapes and actual PQ response bytes, not Store
	// enrollment/authorization evidence. Each subject has an independent key.
	s.NextCursor = strings.Repeat("<", 512)
	s.Truncated = true
	base, _ := json.Marshal(s)
	budget, err := InstallationResponsePlaintextBudget(f.hub, raw)
	if err != nil {
		t.Fatal(err)
	}
	used := len(base)
	counts := [3]int{}
	selected := 0
	for i := 0; i < 50; i++ {
		var row any
		kind := 1
		if i%5 == 0 {
			kind = 0
		} else if i%5 == 4 {
			kind = 2
		}
		switch kind {
		case 0:
			p := parent
			p.InstallationID = fmt.Sprintf("%032x", i+100)
			p.RegistrationID = fmt.Sprintf("%032x", i+200)
			row = p
		case 1:
			pub := installationWireKey(t).Public()
			row = InstallationSubjectBinding{SubjectRegistrationID: fmt.Sprintf("%032x", i+300), SubjectRegistrationEpoch: 1, ParentRegistrationID: parent.RegistrationID, InstallationID: parent.InstallationID, OwnerID: parent.OwnerID, Kind: e2ee.InstallationNodeSubject, InstanceID: strings.Repeat("n", 256), Public: pub, State: InstallationRegistered, Revision: 1, AuthProvenance: InstallationNewRegisteredOnly}
		case 2:
			fp, _ := e2ee.OwnerDevicePublicKeyFingerprint(f.subject.Public())
			row = InstallationPendingAttemptRef{AttemptID: fmt.Sprintf("%032x", i+400), CandidateDigest: strings.Repeat("78", 32), InstallationID: parent.InstallationID, SubjectKind: e2ee.InstallationNodeSubject, SubjectFingerprint: fp, State: InstallationPending, Revision: 1, ExpiresAt: f.candidate.Base.ExpiresAt}
		}
		b, _ := json.Marshal(row)
		extra := len(b)
		if counts[kind] > 0 {
			extra++
		}
		if used+extra > budget {
			break
		}
		used += extra
		counts[kind]++
		selected++
		switch v := row.(type) {
		case InstallationParent:
			s.Parents = append(s.Parents, v)
		case InstallationSubjectBinding:
			s.Subjects = append(s.Subjects, v)
		case InstallationPendingAttemptRef:
			s.PendingAttempts = append(s.PendingAttempts, v)
		}
	}
	if selected < 1 || selected >= 50 {
		t.Fatal("mixed legal rows did not exercise byte ceiling")
	}
	b, _ := json.Marshal(s)
	if len(b) != used {
		t.Fatal("footer, commas or row bytes excluded")
	}
	s.NextCursor = fmt.Sprintf("synthetic-kind-id-cursor-%d", selected)
	if ValidateInstallationSnapshotQuery(q.Query, q.Authorization, s) != nil {
		t.Fatal("valid mixed inventory projection")
	}
	actual, err := SealInstallationResponse(f.hubKey, f.hub, raw, s)
	if err != nil || len(actual) > MaxInstallationReceiptBytes {
		t.Fatal("mixed page could not seal once within complete limit", err)
	}
	n, err := InstallationResponseEncodedSize(f.hub, raw, s)
	if err != nil || n != len(actual) {
		t.Fatal("mixed page exact size model")
	}
	count := InstallationSnapshotRowCount(s)
	bad := installationWireClone(s)
	for InstallationSnapshotRowCount(bad) <= 50 {
		bad.PendingAttempts = append(bad.PendingAttempts, s.PendingAttempts[0])
	}
	if _, err := SealInstallationResponse(f.hubKey, f.hub, raw, bad); err == nil {
		t.Fatal("multi-list count overflow")
	}
	q.Query.PageSize = uint64(count - 1)
	if ValidateInstallationSnapshotQuery(q.Query, q.Authorization, s) == nil {
		t.Fatal("caller page size ignored")
	}
	t.Logf("actual mixed inventory parents=%d subjects=%d pending=%d rows=%d/50 complete_response=%d/%d plaintext_budget=%d own_scope_footer=%d; only DTO/crypto gate", len(s.Parents), len(s.Subjects), len(s.PendingAttempts), count, len(actual), MaxInstallationReceiptBytes, budget, len(base))
}

func TestInstallationWireSnapshotScopesAndExactTargets(t *testing.T) {
	f, request, raw, empty := installationInventory(t)
	p := InstallationParent{InstallationID: f.candidate.Base.InstallationID, RegistrationID: strings.Repeat("45", 16), RegistrationEpoch: 1, AdmissionCredentialVersion: 1, OwnerID: f.scope.OwnerID, State: InstallationRegistered, Revision: 1}
	app := InstallationSubjectBinding{SubjectRegistrationID: strings.Repeat("56", 16), SubjectRegistrationEpoch: 1, ParentRegistrationID: p.RegistrationID, InstallationID: p.InstallationID, OwnerID: p.OwnerID, Kind: e2ee.InstallationAppSubject, InstanceID: f.scope.DeviceID, Public: f.app.Public(), State: InstallationRegistered, Revision: 1, AuthProvenance: InstallationNewRegisteredOnly}
	empty.OwnParent = &p
	empty.OwnSubject = &app
	for name, mutate := range map[string]func(*InstallationConnectionsSnapshot){
		"foreign own Owner":      func(s *InstallationConnectionsSnapshot) { s.OwnParent.OwnerID = "synthetic-foreign-owner" },
		"foreign own device":     func(s *InstallationConnectionsSnapshot) { s.OwnSubject.InstanceID = "synthetic-foreign-app" },
		"foreign own key":        func(s *InstallationConnectionsSnapshot) { s.OwnSubject.Public = f.nc.Public() },
		"Node in App footer":     func(s *InstallationConnectionsSnapshot) { s.OwnSubject.Kind = e2ee.InstallationNodeSubject },
		"wrong own parent":       func(s *InstallationConnectionsSnapshot) { s.OwnSubject.ParentRegistrationID = strings.Repeat("67", 16) },
		"wrong own installation": func(s *InstallationConnectionsSnapshot) { s.OwnSubject.InstallationID = strings.Repeat("78", 16) },
		"orphan own subject":     func(s *InstallationConnectionsSnapshot) { s.OwnParent = nil },
	} {
		t.Run(name, func(t *testing.T) {
			bad := installationWireClone(empty)
			mutate(&bad)
			if ValidateInstallationSnapshotQuery(request.Query, request.Authorization, bad) == nil {
				t.Fatal("foreign own footer accepted")
			}
			if _, err := SealInstallationResponse(f.hubKey, f.hub, raw, bad); err == nil {
				t.Fatal("foreign footer sealed as own context")
			}
		})
	}
	q := request.Query
	q.TargetIDs = []string{p.InstallationID}
	s := installationWireClone(empty)
	s.Subjects = []InstallationSubjectBinding{app}
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) != nil {
		t.Fatal("independent subject-only page requires parent from previous page")
	}
	s.Subjects[0].InstallationID = strings.Repeat("89", 16)
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) == nil {
		t.Fatal("foreign installation subject returned")
	}
	s = installationWireClone(empty)
	s.Parents = []InstallationParent{p}
	s.Parents[0].InstallationID = strings.Repeat("89", 16)
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) == nil {
		t.Fatal("foreign installation parent returned")
	}
	fp, _ := e2ee.OwnerDevicePublicKeyFingerprint(f.subject.Public())
	s = installationWireClone(empty)
	s.PendingAttempts = []InstallationPendingAttemptRef{{AttemptID: f.candidate.Base.AttemptID, CandidateDigest: f.candidate.CandidateDigest, InstallationID: strings.Repeat("89", 16), SubjectKind: e2ee.InstallationNodeSubject, SubjectFingerprint: fp, State: InstallationPending, Revision: 1, ExpiresAt: f.candidate.Base.ExpiresAt}}
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) == nil {
		t.Fatal("foreign installation pending attempt returned")
	}
	n := AppNodeObservation{NodeID: f.candidate.Base.Subject.Node.NodeID, BindingID: strings.Repeat("9a", 16), BindingVersion: 1, NodeKeyID: f.subject.Public().ID, NodeKeyFingerprint: fp, NodeKeyEpoch: 1, BindingState: InstallationRegistered, Connectivity: "UNKNOWN", Stale: true, Source: InstallationHeartbeatSource, ObservedAt: formatUTC(f.now)}
	s = installationWireClone(empty)
	s.Nodes = []AppNodeObservation{n}
	q.TargetKind = "NODE_STATUS"
	q.TargetIDs = []string{n.BindingID}
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) != nil {
		t.Fatal("exact actual registration binding rejected")
	}
	q.TargetIDs = []string{n.NodeID}
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) == nil {
		t.Fatal("NodeID alias substituted for exact binding")
	}
	q.TargetIDs = []string{strings.Repeat("ab", 16)}
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) == nil {
		t.Fatal("foreign actual Node row returned")
	}
	pair := nativePairSizedFixture(t, true)
	s = installationWireClone(empty)
	s.Pairs = []NativePairResult{{Format: NativePairFormat, Operation: OperationNativePairStatus, RequestID: strings.Repeat("bc", 16), RequestPacketDigest: strings.Repeat("cd", 32), PairID: pair.plan.PairID, State: NativePairWaitingConsent, Outcome: InstallationCompleted, ControlRevision: 1, PeerExpiresAt: pair.plan.PeerExpiresAt, SlotA: &pair.plan.SlotA, SlotB: &pair.plan.SlotB, SlotAState: NativePairSlotCandidateReady, SlotBState: NativePairSlotCandidateReady, ObservedAt: formatUTC(f.now)}}
	q.TargetKind = "PAIR_STATUS"
	q.TargetIDs = []string{pair.plan.PairID}
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) != nil {
		t.Fatal("exact real Pair rejected")
	}
	q.TargetIDs = []string{strings.Repeat("de", 16)}
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) == nil {
		t.Fatal("foreign real Pair returned")
	}
	g := InstallationGrantRef{GrantID: strings.Repeat("ef", 16), OriginContract: InstallationContractRevision, Profile: e2ee.InstallationNodeReadProfile, SubjectRegistrationID: app.SubjectRegistrationID, RecipientDeviceID: app.InstanceID, Target: e2ee.InstallationAccessTarget{NodeBindingID: n.BindingID, NodeBindingVersion: 1, NodeKeyEpoch: 1}, State: "ACTIVE", Revision: 1, ExpiresAt: formatUTC(f.now.Add(15 * time.Minute))}
	s = installationWireClone(empty)
	s.Grants = []InstallationGrantRef{g}
	q.TargetKind = "GRANTED"
	q.TargetIDs = []string{app.SubjectRegistrationID}
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) != nil {
		t.Fatal("exact recipient grant filter rejected")
	}
	q.TargetIDs = []string{strings.Repeat("fa", 16)}
	if ValidateInstallationSnapshotQuery(q, request.Authorization, s) == nil {
		t.Fatal("Owner grant recipient filter ignored")
	}
	q.TargetIDs = nil
	auth := InstallationReadAuthorization{Kind: InstallationRecipientGrantsAuth}
	if ValidateInstallationSnapshotQuery(q, auth, s) != nil {
		t.Fatal("own effective grant rejected")
	}
	foreign := installationWireClone(s)
	foreign.Grants[0].RecipientDeviceID = "synthetic-other-app"
	foreign.Grants[0].SubjectRegistrationID = strings.Repeat("fa", 16)
	if ValidateInstallationSnapshotQuery(q, auth, foreign) == nil {
		t.Fatal("foreign recipient grant returned")
	}
	for name, mutate := range map[string]func(*InstallationGrantRef){"unknown profile": func(g *InstallationGrantRef) { g.Profile = "MANAGER" }, "unknown state": func(g *InstallationGrantRef) { g.State = "READY" }, "wrong origin": func(g *InstallationGrantRef) { g.OriginContract = "client-hub-v1.6.5" }, "unexpected Pair": func(g *InstallationGrantRef) { g.Target.PairID = pair.plan.PairID }} {
		t.Run(name, func(t *testing.T) {
			bad := g
			mutate(&bad)
			if ValidateInstallationGrantRef(bad) == nil {
				t.Fatal("unknown grant reference accepted")
			}
		})
	}
}
