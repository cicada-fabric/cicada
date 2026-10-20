package hubaccountwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

type installationWireFixture struct {
	now                                        time.Time
	hub                                        HubIdentity
	hubKey, owner, app, admission, subject, nc *e2ee.Identity
	scope                                      e2ee.InstallationAccountScope
	candidate                                  InstallationCandidate
	secret, ack, nodeToken                     []byte
}

func installationWireKey(t *testing.T) *e2ee.Identity {
	t.Helper()
	i, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func installationAccountScopeFixture(s e2ee.OwnerAppNodeScope) e2ee.InstallationAccountScope {
	return e2ee.InstallationAccountScope{Version: s.Version, Origin: s.Origin, HubID: s.HubID, HubFingerprint: s.HubFingerprint, AccountID: s.AccountID, AccountSessionID: s.AccountSessionID, AccountSessionExpiresAt: s.AccountSessionExpiresAt, OwnerID: s.OwnerID, OwnerPublic: s.OwnerPublic, OwnerKeyVersion: s.OwnerKeyVersion, DeviceID: s.DeviceID, DevicePublic: s.DevicePublic, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch, TransportPolicy: s.TransportPolicy}
}

func installationWire(t *testing.T) installationWireFixture {
	t.Helper()
	old := appNodeCrypto(t)
	f := installationWireFixture{now: time.Date(2026, 10, 20, 8, 0, 0, 123456789, time.UTC), hub: old.hub, hubKey: old.hubPrivate, owner: old.owner, app: old.device, scope: installationAccountScopeFixture(old.scope), secret: bytes.Repeat([]byte{0xa1}, 32), ack: bytes.Repeat([]byte{0xb2}, 32)}
	f.admission, f.subject, f.nc = installationWireKey(t), installationWireKey(t), installationWireKey(t)
	f.scope.Origin = "https://synthetic-registration.invalid"
	f.scope.AccountSessionExpiresAt = f.now.Add(15 * time.Minute).Format(time.RFC3339Nano)
	f.nodeToken = []byte("cicada_node_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xc3}, 32)))
	b := e2ee.InstallationCandidateBase{Format: InstallationFormat, Hub: e2ee.InstallationHubRef{Origin: f.scope.Origin, HubID: f.hub.HubID, Public: f.hub.Public, KeyVersion: f.hub.KeyVersion, Fingerprint: f.scope.HubFingerprint, TransportPolicy: AppNodeTransportHTTPS}, InstallationID: strings.Repeat("12", 16), AttemptID: strings.Repeat("23", 16), AdmissionPublic: f.admission.Public(), Components: []string{"APP", "HUB", "NODE"}, Subject: e2ee.InstallationSubject{Kind: e2ee.InstallationNodeSubject, Mode: e2ee.InstallationNewSubject, Node: &e2ee.InstallationNodeRef{NodeID: "synthetic-controlled-node", Public: f.subject.Public(), KeyVersion: 1, KeyEpoch: 1, HubNodeControlPublic: f.nc.Public(), HubNodeControlKeyVersion: 1, HubNodeControlFingerprint: nodewire.IdentityFingerprint(f.nc.Public())}}, Trust: e2ee.InstallationTrustSource{Kind: e2ee.InstallationFirstOOB}, IssuedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: f.now.Add(10 * time.Minute).Format(time.RFC3339Nano)}
	var err error
	f.candidate, err = e2ee.NewInstallationCandidate(b, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateInstallationCandidate(f.candidate, f.hub) != nil {
		t.Fatal("independent trusted Hub candidate")
	}
	return f
}

func installationWireClone[T any](v T) T {
	b, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(b, &out)
	return out
}

func (f installationWireFixture) self(id byte, op string) InstallationPacket {
	return InstallationPacket{Format: InstallationPacketFormat, Version: 1, Operation: op, SenderPublic: f.admission.Public(), Self: &InstallationSelfContext{HubID: f.hub.HubID, InstallationID: f.candidate.Base.InstallationID, AttemptID: f.candidate.Base.AttemptID, RequestID: strings.Repeat(fmt.Sprintf("%02x", id), 16), Nonce: bytes.Repeat([]byte{id}, 32), IssuedAt: f.now.Format(time.RFC3339Nano)}}
}

func (f installationWireFixture) account(id byte, op string) InstallationPacket {
	s := f.scope
	return InstallationPacket{Format: InstallationPacketFormat, Version: 1, Operation: op, SenderPublic: f.app.Public(), Account: &AppNodeRequestContext{Origin: s.Origin, HubID: s.HubID, AccountID: s.AccountID, OwnerID: s.OwnerID, DeviceID: s.DeviceID, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch, RequestID: strings.Repeat(fmt.Sprintf("%02x", id), 16), ClientNonce: bytes.Repeat([]byte{id}, 32), IssuedAt: f.now.Format(time.RFC3339Nano)}}
}

func (f installationWireFixture) approval(t *testing.T) InstallationApprovalBase {
	t.Helper()
	d, err := e2ee.InstallationSubjectDigest(f.candidate.Base.Subject)
	if err != nil {
		t.Fatal(err)
	}
	end := f.now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	return InstallationApprovalBase{Format: InstallationFormat, CandidateDigest: f.candidate.CandidateDigest, OOBCommitment: f.candidate.OOBCommitment, InstallationID: f.candidate.Base.InstallationID, AttemptID: f.candidate.Base.AttemptID, PossessionReceiptDigest: strings.Repeat("45", 32), Scope: f.scope, SubjectDigest: d, ExpectedRevision: 1, PrepareRequestID: strings.Repeat("56", 16), PreparePacketDigest: strings.Repeat("67", 32), PreviewProofDigest: strings.Repeat("78", 32), ServerNonce: strings.Repeat("89", 32), PreparedAt: f.now.Format(time.RFC3339Nano), AttemptExpiresAt: f.candidate.Base.ExpiresAt, ProofExpiresAt: end, AcceptBefore: end}
}

func (f installationWireFixture) start(t *testing.T) (InstallationPacket, InstallationStart, []byte) {
	t.Helper()
	h := f.self(1, OperationInstallationStart)
	s, err := SealInstallationStartSubject(f.subject, f.hub, *h.Self, f.candidate)
	if err != nil {
		t.Fatal(err)
	}
	q := InstallationStart{Format: InstallationFormat, Candidate: f.candidate, SubjectSignatureProof: s}
	if f.candidate.Base.Subject.Mode == e2ee.InstallationAdoptExisting {
		q.NodeCredential = append([]byte(nil), f.nodeToken...)
	}
	raw, err := SealInstallationRequest(f.admission, f.hub, h, q)
	if err != nil {
		t.Fatal(err)
	}
	return h, q, raw
}

func TestInstallationWireIssuanceSkewAndImmutableDeadlines(t *testing.T) {
	f := installationWire(t)
	_, _, start := f.start(t)
	startBefore := append([]byte(nil), start...)
	header := f.account(6, OperationOwnerConnectionsRead)
	q := e2ee.InstallationReadQuery{HubID: f.scope.HubID, AccountID: f.scope.AccountID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, AccountEpoch: f.scope.AccountEpoch, DeviceEpoch: f.scope.DeviceEpoch, RequestID: header.Account.RequestID, Nonce: hex.EncodeToString(header.Account.ClientNonce), TargetKind: "GRANTED", TargetIDs: []string{}, PageSize: 1}
	account, err := SealInstallationRequest(f.app, f.hub, header, InstallationConnectionsRead{Format: InstallationFormat, SessionToken: bytes.Repeat([]byte{9}, 32), Query: q, Authorization: InstallationReadAuthorization{Kind: InstallationRecipientGrantsAuth, GrantIDs: []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := EncodeInstallationTicket(f.candidate, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := DecodeInstallationTicket(token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ticket.OOBSecret)
	for _, tc := range []struct {
		name   string
		offset time.Duration
		ok     bool
	}{
		{"behind_1s", -time.Second, true},
		{"ahead_1s", time.Second, true},
		{"early_30s_inclusive", -30 * time.Second, true},
		{"future_beyond_30s", -30*time.Second - time.Nanosecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := f.now.Add(tc.offset)
			var got InstallationStart
			_, err := OpenInstallationRequest(f.hubKey, f.hub, start, &got, now)
			defer ClearInstallationRequestSecrets(&got)
			if (err == nil) != tc.ok {
				t.Fatal("fresh self header/Start issuance lower bound")
			}
			var read InstallationConnectionsRead
			_, err = OpenInstallationRequest(f.hubKey, f.hub, account, &read, now)
			defer ClearInstallationRequestSecrets(&read)
			if (err == nil) != tc.ok || (MatchInstallationTicket(ticket, f.candidate, f.hub, now) == nil) != tc.ok {
				t.Fatal("fresh account header/ticket issuance lower bound")
			}
		})
	}
	for _, now := range []time.Time{f.now.Add(time.Minute + time.Nanosecond), time.Time{}} {
		var got InstallationStart
		if _, err := OpenInstallationRequest(f.hubKey, f.hub, start, &got, now); err == nil {
			ClearInstallationRequestSecrets(&got)
			t.Fatal("issuance tolerance extended freshness or supplied zero clock")
		}
	}
	end, _ := parseCanonicalUTC(f.candidate.Base.ExpiresAt)
	if MatchInstallationTicket(ticket, f.candidate, f.hub, end) == nil || MatchInstallationTicket(ticket, f.candidate, f.hub, end.Add(time.Second)) == nil {
		t.Fatal("issuance tolerance extended ticket expiry")
	}
	if !bytes.Equal(start, startBefore) {
		t.Fatal("clock handling mutated original packet")
	}
}

func TestInstallationWireActualPQAndExactRecovery(t *testing.T) {
	f := installationWire(t)
	h, q, start := f.start(t)
	var got InstallationStart
	opened, err := OpenInstallationRequest(f.hubKey, f.hub, start, &got, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if OpenInstallationStartSubject(f.hubKey, f.hub, *opened.Self, got.Candidate, got.SubjectSignatureProof) != nil || got.NodeCredential != nil {
		t.Fatal("start did not bind original subject/bearer")
	}
	if bytes.Contains(start, f.nodeToken) {
		t.Fatal("raw Node bearer leaked to public packet")
	}
	ClearInstallationRequestSecrets(&got)
	if got.NodeCredential != nil {
		t.Fatal("transient Node bearer not cleared")
	}
	q.NodeCredential = append([]byte(nil), f.nodeToken...)
	if _, err := SealInstallationRequest(f.admission, f.hub, h, q); err == nil {
		t.Fatal("new Node created an unused legacy bearer")
	}
	approval := f.approval(t)
	proof, capsule, err := e2ee.SealInstallationOwnerApproval(f.owner, f.candidate, approval, f.secret, f.ack)
	if err != nil {
		t.Fatal(err)
	}
	oh := f.account(2, OperationOwnerInstallationComplete)
	complete, err := SealInstallationRequest(f.app, f.hub, oh, InstallationOwnerComplete{Format: InstallationFormat, SessionToken: bytes.Repeat([]byte{9}, 32), OwnerProof: proof, TrustCapsule: capsule})
	if err != nil {
		t.Fatal(err)
	}
	var completion InstallationOwnerComplete
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, complete, &completion, f.now); err != nil {
		t.Fatal(err)
	}
	defer ClearInstallationRequestSecrets(&completion)
	if _, err := e2ee.VerifyInstallationOwnerProof(f.owner.Public(), f.candidate, completion.OwnerProof, f.now); err != nil {
		t.Fatal(err)
	}
	result := InstallationResult{Format: InstallationFormat, Operation: OperationOwnerInstallationComplete, RequestID: oh.Account.RequestID, RequestPacketDigest: e2ee.InstallationPacketDigest(complete), AttemptID: f.candidate.Base.AttemptID, AttemptState: InstallationOwnerApproved, Revision: 2, Outcome: InstallationCompleted, Grants: []InstallationGrantRef{}, ObservedAt: f.now.Format(time.RFC3339Nano)}
	reply, err := SealInstallationResponse(f.hubKey, f.hub, complete, InstallationApproved{Result: result, OwnerProof: proof, TrustCapsule: capsule})
	if err != nil {
		t.Fatal(err)
	}
	var accepted InstallationApproved
	if OpenInstallationResponse(f.app, f.hub, complete, reply, &accepted) != nil {
		t.Fatal("Owner receipt authentication")
	}
	ph := f.self(15, OperationInstallationPoll)
	poll, err := SealInstallationRequest(f.admission, f.hub, ph, InstallationPoll{Format: InstallationFormat, CandidateDigest: f.candidate.CandidateDigest})
	if err != nil {
		t.Fatal(err)
	}
	polled := accepted
	polled.Result.Operation = OperationInstallationPoll
	polled.Result.RequestID = ph.Self.RequestID
	polled.Result.RequestPacketDigest = e2ee.InstallationPacketDigest(poll)
	pollReply, err := SealInstallationResponse(f.hubKey, f.hub, poll, polled)
	if err != nil {
		t.Fatal(err)
	}
	var delivered InstallationApproved
	if OpenInstallationResponse(f.admission, f.hub, poll, pollReply, &delivered) != nil || OpenInstallationResponse(f.admission, f.hub, poll, reply, &delivered) == nil {
		t.Fatal("admission Poll receipt replaced by Owner response")
	}
	local, err := e2ee.OpenInstallationTrustCapsuleFirstOOB(f.admission, f.candidate, polled.OwnerProof, polled.TrustCapsule, f.secret, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(local.OOBSecret)
	defer clear(local.ACKNonce)
	claims, err := e2ee.VerifyInstallationOwnerProof(f.owner.Public(), f.candidate, proof, f.now)
	if err != nil {
		t.Fatal(err)
	}
	ah := f.self(3, OperationInstallationAccept)
	sub, err := e2ee.SealInstallationSubjectAccept(f.subject, f.candidate, claims, proof, ah.Self.RequestID, local.ACKNonce)
	if err != nil {
		t.Fatal(err)
	}
	at, _ := e2ee.InstallationApprovalDigest(approval)
	ack, err := SealInstallationRequest(f.admission, f.hub, ah, InstallationAccept{Format: InstallationFormat, ApprovalReceiptDigest: e2ee.InstallationPacketDigest(pollReply), ApprovalDigest: at, CapsuleDigest: claims.CapsuleDigest, OwnerProofDigest: e2ee.InstallationPacketDigest(proof), ACKNonce: local.ACKNonce, SubjectAcceptance: sub})
	if err != nil {
		t.Fatal(err)
	}
	var ackBody InstallationAccept
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, ack, &ackBody, f.now); err != nil {
		t.Fatal(err)
	}
	defer ClearInstallationRequestSecrets(&ackBody)
	if ackBody.ApprovalReceiptDigest != e2ee.InstallationPacketDigest(pollReply) || ackBody.ApprovalReceiptDigest == e2ee.InstallationPacketDigest(reply) {
		t.Fatal("accept did not bind its actual Poll raw bytes")
	}
	if e2ee.VerifyInstallationACK(f.owner.Public(), f.candidate, proof, capsule, ackBody.ACKNonce, f.now) != nil {
		t.Fatal("private ACK nonce not bound")
	}
	if _, err := e2ee.OpenInstallationSubjectAccept(f.hubKey, f.owner.Public(), f.candidate, proof, capsule, ackBody.SubjectAcceptance, ah.Self.RequestID, f.now); err != nil {
		t.Fatal(err)
	}
	rh := f.account(4, OperationInstallationReconcile)
	rq := InstallationReconcile{Format: InstallationFormat, OriginalOperation: OperationOwnerInstallationComplete, OriginalRequestID: oh.Account.RequestID, OriginalPacketDigest: e2ee.InstallationPacketDigest(complete), OriginalPacket: complete}
	raw, err := SealInstallationRequest(f.app, f.hub, rh, rq)
	if err != nil {
		t.Fatal(err)
	}
	var read InstallationReconcile
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, raw, &read, f.now); err != nil {
		t.Fatal(err)
	}
	rr := InstallationReconciled{Format: InstallationFormat, RequestID: rh.Account.RequestID, RequestPacketDigest: e2ee.InstallationPacketDigest(raw), OriginalOperation: read.OriginalOperation, OriginalRequestID: read.OriginalRequestID, OriginalPacketDigest: read.OriginalPacketDigest, State: InstallationCompleted, ReceiptPacket: reply, ObservedAt: f.now.Format(time.RFC3339Nano)}
	recovered, err := SealInstallationResponse(f.hubKey, f.hub, raw, rr)
	if err != nil {
		t.Fatal(err)
	}
	var final InstallationReconciled
	if OpenInstallationResponse(f.app, f.hub, raw, recovered, &final) != nil || !bytes.Equal(final.ReceiptPacket, reply) || OpenInstallationResponse(f.app, f.hub, complete, final.ReceiptPacket, &accepted) != nil {
		t.Fatal("recovery did not bind exact original/receipt")
	}
	if raw[len(raw)-1] == '\n' || reply[len(reply)-1] == '\n' {
		t.Fatal("raw canonical carrier added LF")
	}
	t.Logf("synthetic-only actual PQ bytes start=%d owner_complete=%d approved_receipt=%d accept=%d reconcile_request=%d reconcile_response=%d", len(start), len(complete), len(reply), len(ack), len(raw), len(recovered))
}

func TestInstallationWireIndependentPinsAndClosedPackets(t *testing.T) {
	f := installationWire(t)
	for name, change := range map[string]func(*InstallationCandidate){"Hub public": func(c *InstallationCandidate) { c.Base.Hub.Public = f.nc.Public() }, "Hub fingerprint": func(c *InstallationCandidate) { c.Base.Hub.Fingerprint = strings.Repeat("aa", 32) }, "Node-Control public": func(c *InstallationCandidate) { c.Base.Subject.Node.HubNodeControlPublic = f.app.Public() }, "Node-Control fingerprint": func(c *InstallationCandidate) {
		c.Base.Subject.Node.HubNodeControlFingerprint = strings.Repeat("bb", 32)
	}} {
		t.Run(name, func(t *testing.T) {
			bad := installationWireClone(f.candidate)
			change(&bad)
			var err error
			bad, err = e2ee.NewInstallationCandidate(bad.Base, f.secret)
			if err == nil && ValidateInstallationCandidate(bad, f.hub) == nil {
				t.Fatal("untrusted public/pin replacement accepted")
			}
		})
	}
	h, q, raw := f.start(t)
	var packet InstallationPacket
	if json.Unmarshal(raw, &packet) != nil {
		t.Fatal("synthetic packet")
	}
	packet.Self.RequestID = strings.Repeat("fa", 16)
	changed, _ := json.Marshal(packet)
	var out InstallationStart
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, changed, &out, f.now); err == nil {
		t.Fatal("header request substitution")
	}
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, append(raw, '\n'), &out, f.now); err == nil {
		t.Fatal("noncanonical packet")
	}
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, raw, &out, f.now.Add(61*time.Second)); err == nil {
		t.Fatal("late fresh original")
	}
	h.Operation = "manager.rpc"
	if _, err := SealInstallationRequest(f.admission, f.hub, h, q); err == nil {
		t.Fatal("generic RPC accepted")
	}
	var nilBody *InstallationStart
	if ValidateInstallationRequest(f.self(1, OperationInstallationStart), nilBody, f.hub) == nil {
		t.Fatal("nil body accepted")
	}
	if InstallationPublicAvailable {
		t.Fatal("C0 advertised a production service")
	}
}

func TestInstallationWireTicketActualMaximumAndEscaping(t *testing.T) {
	f := installationWire(t)
	b := installationWireClone(f.candidate.Base)
	b.Hub.Origin = "https://" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 56)
	if len(b.Hub.Origin) != e2ee.MaxInstallationOriginBytes {
		t.Fatal("fixture not the declared legal origin maximum")
	}
	f.hub.HubID = strings.Repeat("h", e2ee.MaxInstallationHubIDBytes)
	b.Hub.HubID = f.hub.HubID
	b.Hub.Fingerprint, _ = HubFingerprint(f.hub)
	var err error
	c, err := e2ee.NewInstallationCandidate(b, f.secret)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateInstallationCandidate(c, f.hub) != nil {
		t.Fatal("max legal candidate")
	}
	token, err := EncodeInstallationTicket(c, f.secret)
	if err != nil {
		t.Fatal("maximum legal ticket rejected", err)
	}
	if len(token) > MaxInstallationTicketBytes {
		t.Fatal("ticket exceeds declared single-item bound")
	}
	decoded, err := DecodeInstallationTicket(token, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(decoded.OOBSecret)
	if MatchInstallationTicket(decoded, c, f.hub, f.now) != nil {
		t.Fatal("max ticket did not match independent candidate")
	}
	if strings.Contains(token, "kem_public") || strings.Contains(token, "signing_public") {
		t.Fatal("ticket contains PQ public keys")
	}
	for _, origin := range []string{"https://" + strings.Repeat("&", 248), "https://" + strings.Repeat("<", 248), "https://例子.invalid", "https://host?", "https://host/%26"} {
		bad := installationWireClone(b)
		bad.Hub.Origin = origin
		if _, err := e2ee.NewInstallationCandidate(bad, f.secret); err == nil {
			t.Fatal("escaping/invalid new origin was legal")
		}
	}
	if _, err := DecodeInstallationTicket(token+"=", f.now); err == nil {
		t.Fatal("noncanonical token padding")
	}
	if _, err := DecodeInstallationTicket(strings.Repeat("x", MaxInstallationTicketBytes+1), f.now); err == nil {
		t.Fatal("oversize ticket")
	}
	decoded.CandidateDigest = strings.Repeat("ff", 32)
	if MatchInstallationTicket(decoded, c, f.hub, f.now) == nil {
		t.Fatal("ticket candidate changed")
	}
	t.Logf("actual Go canonical maximum ticket=%d bytes <=%d; origin=%d HubID=%d full Node/CC pins=64+64 expiry=%d; DNS/IP-only policy rejects HTML/Unicode reg-names", len(token), MaxInstallationTicketBytes, len(b.Hub.Origin), len(b.Hub.HubID), len(b.ExpiresAt))
}

func TestInstallationWireOwnGrantDiscoveryAndParentModel(t *testing.T) {
	now := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	subject, other := strings.Repeat("12", 16), strings.Repeat("23", 16)
	refs := make([]InstallationGrantRef, 0)
	for i := 0; i < 30; i++ {
		refs = append(refs, InstallationGrantRef{GrantID: fmt.Sprintf("%032x", i+1), OriginContract: InstallationContractRevision, Profile: e2ee.InstallationNodeReadProfile, Target: e2ee.InstallationAccessTarget{NodeBindingID: "synthetic-original-binding", NodeBindingVersion: 1, NodeKeyEpoch: 1}, SubjectRegistrationID: subject, RecipientDeviceID: "synthetic-app-two", State: "ACTIVE", Revision: 1, ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339Nano)})
	}
	live := InstallationGrantRef{GrantID: strings.Repeat("34", 16), OriginContract: InstallationContractRevision, Profile: e2ee.InstallationNodeReadProfile, Target: e2ee.InstallationAccessTarget{NodeBindingID: "synthetic-original-binding", NodeBindingVersion: 1, NodeKeyEpoch: 1}, SubjectRegistrationID: subject, RecipientDeviceID: "synthetic-app-two", State: "ACTIVE", Revision: 1, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)}
	refs = append(refs, live)
	foreign := live
	foreign.GrantID = strings.Repeat("45", 16)
	foreign.SubjectRegistrationID = other
	foreign.RecipientDeviceID = "synthetic-app-one"
	refs = append(refs, foreign)
	got, err := SelectInstallationRecipientGrants(refs, subject, "synthetic-app-two", nil, now)
	if err != nil || len(got) != 1 || got[0].GrantID != live.GrantID {
		t.Fatal("empty grant IDs inherited foreign/history or permanent quota", err)
	}
	if _, err := SelectInstallationRecipientGrants(refs, subject, "synthetic-app-two", []string{foreign.GrantID}, now); err == nil {
		t.Fatal("foreign grant inherited")
	}
	got, err = SelectInstallationRecipientGrants(refs, strings.Repeat("56", 16), "synthetic-app-three", nil, now)
	if err != nil || len(got) != 0 {
		t.Fatal("zero grants became inventory authority")
	}
	if ValidateInstallationReadAuthorization(InstallationReadAuthorization{Kind: InstallationRecipientGrantsAuth}) != nil {
		t.Fatal("own grant auto-discovery unavailable")
	}
	for _, a := range []InstallationReadAuthorization{{}, {Kind: InstallationOwnerReadAuth}, {Kind: InstallationOwnerReadAuth, OwnerReadProof: []byte{1}, GrantIDs: []string{}}, {Kind: InstallationRecipientGrantsAuth, OwnerReadProof: []byte{1}}} {
		if ValidateInstallationReadAuthorization(a) == nil {
			t.Fatal("ambiguous/absent read authorization")
		}
	}
	previous := InstallationParent{InstallationID: strings.Repeat("67", 16), RegistrationID: strings.Repeat("78", 16), RegistrationEpoch: 1, AdmissionCredentialVersion: 1, OwnerID: "synthetic-owner", State: InstallationRegistered, Revision: 4}
	before, _ := json.Marshal(previous)
	r := InstallationResult{AttemptState: InstallationPending, Parent: &previous}
	if ValidateInstallationAppendProjection(previous, r) != nil {
		t.Fatal("new component downgraded parent")
	}
	bad := installationWireClone(previous)
	bad.State = InstallationPending
	r.Parent = &bad
	if ValidateInstallationAppendProjection(previous, r) == nil {
		t.Fatal("PENDING parent accepted")
	}
	after, _ := json.Marshal(previous)
	if !bytes.Equal(before, after) {
		t.Fatal("projection mutated existing parent")
	}
	if InstallationHeartbeatObservation(now.Add(-2*time.Minute).Format(time.RFC3339Nano), now) != "STALE" || InstallationHeartbeatObservation(now.Format(time.RFC3339Nano), now) != "CONNECTED" {
		t.Fatal("heartbeat observation changed")
	}
	if previous.State != InstallationRegistered || !bytes.Equal(before, after) {
		t.Fatal("stale heartbeat unregistered/renewed state")
	}
}

func TestInstallationWireLegacyCredentialRequiresCurrentBearer(t *testing.T) {
	f := installationWire(t)
	b := installationWireClone(f.candidate.Base)
	b.Subject.Mode = e2ee.InstallationAdoptExisting
	b.Subject.Node.CredentialCommitment = NativePairCredentialCommitment(string(f.nodeToken))
	b.Subject.Node.RequestID = "synthetic-original-request"
	b.Subject.Node.RequestVersion = 1
	b.Subject.Node.CandidateDigest = strings.Repeat("34", 32)
	b.Subject.Node.CandidateExpiresAt = ""
	b.Subject.Node.BindingID = "synthetic-original-binding"
	b.Subject.Node.BindingVersion = 3
	b.Subject.Node.CredentialVersion = 4
	b.Subject.Node.KeyEpoch = 2
	d, _ := e2ee.OwnerDevicePublicKeyFingerprint(f.owner.Public())
	b.Trust = e2ee.InstallationTrustSource{Kind: e2ee.InstallationExistingLocalPin, Existing: &e2ee.InstallationExistingTrust{Source: e2ee.InstallationLegacyNode, OwnerID: f.scope.OwnerID, OwnerKeyID: f.owner.Public().ID, OwnerPublicDigest: d, LocalTrustVersion: 1}}
	var err error
	f.candidate, err = e2ee.NewInstallationCandidate(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, body, raw := f.start(t)
	digest := sha256.Sum256(f.nodeToken)
	current := InstallationLegacyCurrent{OwnerID: f.scope.OwnerID, BindingState: "ACTIVE", CredentialState: "active", CredentialDigest: base64.RawURLEncoding.EncodeToString(digest[:]), Node: *b.Subject.Node}
	if ValidateInstallationLegacyCredential(f.candidate, body.NodeCredential, current) != nil {
		t.Fatal("current original bearer adoption failed")
	}
	if bytes.Contains(raw, f.nodeToken) {
		t.Fatal("bearer leaked outside encrypted start")
	}
	body.NodeCredential = nil
	if _, err := SealInstallationRequest(f.admission, f.hub, h, body); err == nil {
		t.Fatal("hash-only legacy possession accepted")
	}
	old := []byte("cicada_node_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xd4}, 32)))
	if ValidateInstallationLegacyCredential(f.candidate, old, current) == nil {
		t.Fatal("old bearer accepted by current tuple")
	}
	rotated := installationWireClone(current)
	rotated.Node.CredentialVersion++
	if ValidateInstallationLegacyCredential(f.candidate, f.nodeToken, rotated) == nil {
		t.Fatal("old key/current-looking hash bypassed credential version rotation")
	}
	rotated = current
	rotated.CredentialDigest = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	if ValidateInstallationLegacyCredential(f.candidate, f.nodeToken, rotated) == nil {
		t.Fatal("old bearer passed current Store digest")
	}
}

type installationPublicVector struct {
	ContractRevision string                `json:"contract_revision"`
	SyntheticOnly    bool                  `json:"synthetic_only"`
	Warning          string                `json:"warning"`
	Candidate        InstallationCandidate `json:"candidate"`
	OwnerProof       []byte                `json:"owner_proof"`
	Capsule          []byte                `json:"capsule"`
	ACKNonce         []byte                `json:"synthetic_ack_nonce"`
	OOBSecret        []byte                `json:"synthetic_oob_secret"`
	ApprovalDigest   string                `json:"approval_digest"`
	VerifiedAt       string                `json:"verified_at"`
}

func TestInstallationWireSyntheticPublicVector(t *testing.T) {
	path := os.Getenv("CICADA_INSTALLATION_VECTOR_OUTPUT")
	var vector installationPublicVector
	if path != "" {
		f := installationWire(t)
		a := f.approval(t)
		proof, capsule, err := e2ee.SealInstallationOwnerApproval(f.owner, f.candidate, a, f.secret, f.ack)
		if err != nil {
			t.Fatal(err)
		}
		d, _ := e2ee.InstallationApprovalDigest(a)
		vector = installationPublicVector{ContractRevision: InstallationContractRevision, SyntheticOnly: true, Warning: "SYNTHETIC PUBLIC CRYPTOGRAPHIC FIXTURE ONLY. NEVER INITIALIZE A DEPLOYMENT. NO PRIVATE KEYS.", Candidate: f.candidate, OwnerProof: proof, Capsule: capsule, ACKNonce: f.ack, OOBSecret: f.secret, ApprovalDigest: d, VerifiedAt: f.now.Format(time.RFC3339Nano)}
		b, err := json.MarshalIndent(vector, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		b, err := os.ReadFile("testdata/installation-registration-v1.1.json")
		if err != nil {
			t.Fatal("public fixture absent", err)
		}
		if json.Unmarshal(b, &vector) != nil {
			t.Fatal("public fixture encoding")
		}
	}
	if vector.ContractRevision != InstallationContractRevision || !vector.SyntheticOnly || !strings.Contains(vector.Warning, "NEVER INITIALIZE A DEPLOYMENT") || !strings.Contains(vector.Candidate.Base.Hub.Origin, ".invalid") {
		t.Fatal("fixture is not visibly synthetic")
	}
	var p e2ee.InstallationOwnerProof
	if json.Unmarshal(vector.OwnerProof, &p) != nil {
		t.Fatal("fixture proof")
	}
	now, err := time.Parse(time.RFC3339Nano, vector.VerifiedAt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e2ee.VerifyInstallationOwnerProof(p.Claims.Approval.Scope.OwnerPublic, vector.Candidate, vector.OwnerProof, now); err != nil {
		t.Fatal("fixture actual Owner signature", err)
	}
	if e2ee.VerifyInstallationACK(p.Claims.Approval.Scope.OwnerPublic, vector.Candidate, vector.OwnerProof, vector.Capsule, vector.ACKNonce, now) != nil {
		t.Fatal("fixture ACK")
	}
	d, err := e2ee.InstallationApprovalDigest(p.Claims.Approval)
	if err != nil || d != vector.ApprovalDigest {
		t.Fatal("fixture canonical approval digest")
	}
	o, err := e2ee.InstallationOOBCommitment(vector.Candidate.CandidateDigest, vector.OOBSecret)
	if err != nil || o != vector.Candidate.OOBCommitment {
		t.Fatal("fixture OOB digest")
	}
}

func TestInstallationWireMaximumLegalPQMetadataAndBounds(t *testing.T) {
	f := installationWire(t)
	b := installationWireClone(f.candidate.Base)
	b.Hub.Origin = "https://" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 56)
	f.hub.HubID = strings.Repeat("h", e2ee.MaxInstallationHubIDBytes)
	b.Hub.HubID = f.hub.HubID
	b.Hub.Fingerprint, _ = HubFingerprint(f.hub)
	f.scope.HubID = b.Hub.HubID
	f.scope.HubFingerprint = b.Hub.Fingerprint
	f.scope.Origin = b.Hub.Origin
	f.scope.AccountID = strings.Repeat("a", 128)
	f.scope.OwnerID = strings.Repeat("o", 128)
	f.scope.DeviceID = strings.Repeat("d", 128)
	f.scope.AccountSessionID = strings.Repeat("s", 256)
	b.Subject.Node.NodeID = strings.Repeat("n", 256)
	// NEW_SUBJECT has no legacy request coordinates, even at maximum size.
	var err error
	f.candidate, err = e2ee.NewInstallationCandidate(b, f.secret)
	if err != nil {
		t.Fatal("maximum legal candidate", err)
	}
	_, _, start := f.start(t)
	a := f.approval(t)
	proof, capsule, err := e2ee.SealInstallationOwnerApproval(f.owner, f.candidate, a, f.secret, f.ack)
	if err != nil {
		t.Fatal("maximum legal Owner proof", err)
	}
	h := f.account(7, OperationOwnerInstallationComplete)
	body := InstallationOwnerComplete{Format: InstallationFormat, SessionToken: bytes.Repeat([]byte{1}, 32), OwnerProof: proof, TrustCapsule: capsule}
	raw, err := SealInstallationRequest(f.app, f.hub, h, body)
	if err != nil {
		t.Fatal("legal metadata cannot fit reviewed packet bound", err)
	}
	var out InstallationOwnerComplete
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, raw, &out, f.now); err != nil {
		t.Fatal(err)
	}
	ClearInstallationRequestSecrets(&out)
	if len(start) > MaxInstallationPacketBytes || len(raw) > MaxInstallationPacketBytes || len(proof) > e2ee.MaxInstallationProofBytes || len(capsule) > MaxInstallationPacketBytes {
		t.Fatal("actual legal PQ bytes exceed bounds")
	}
	tooBig := installationWireClone(body)
	tooBig.OwnerProof = make([]byte, e2ee.MaxInstallationProofBytes)
	tooBig.TrustCapsule = make([]byte, MaxInstallationPacketBytes)
	if _, err := SealInstallationRequest(f.app, f.hub, h, tooBig); err == nil {
		t.Fatal("aggregate body overflow accepted")
	}
	oversize := append(append([]byte(nil), raw...), bytes.Repeat([]byte{' '}, MaxInstallationPacketBytes-len(raw)+1)...)
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, oversize, &out, f.now); err == nil {
		t.Fatal("packet overflow accepted")
	}
	rh := f.account(8, OperationInstallationReconcile)
	recon, err := SealInstallationRequest(f.app, f.hub, rh, InstallationReconcile{Format: InstallationFormat, OriginalOperation: h.Operation, OriginalRequestID: h.Account.RequestID, OriginalPacketDigest: e2ee.InstallationPacketDigest(raw), OriginalPacket: raw})
	if err != nil {
		t.Fatal("largest legal original cannot reconcile", err)
	}
	var recovered InstallationReconcile
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, recon, &recovered, f.now); err != nil {
		t.Fatal(err)
	}
	t.Logf("actual max metadata PQ bytes start=%d complete=%d proof=%d capsule=%d reconcile=%d; packet_limit=%d reconcile_limit=%d", len(start), len(raw), len(proof), len(capsule), len(recon), MaxInstallationPacketBytes, MaxInstallationReconcilePacketBytes)
}

func TestInstallationWireHistoricalOriginalDoesNotRenewFreshness(t *testing.T) {
	f := installationWire(t)
	_, _, original := f.start(t)
	later := f.now.Add(11 * time.Minute)
	var fresh InstallationStart
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, original, &fresh, later); err == nil {
		t.Fatal("expired original entered fresh dispatcher")
	}
	var old InstallationStart
	history, err := AuthenticateInstallationOriginal(f.hubKey, f.hub, original, &old)
	if err != nil {
		t.Fatal("authenticated original cannot converge to receipt/fence", err)
	}
	defer ClearInstallationRequestSecrets(&old)
	if history.PacketDigest != e2ee.InstallationPacketDigest(original) || history.Header.Operation != OperationInstallationStart {
		t.Fatal("historical original lost exact identity")
	}
	// Historical decoding cannot repair either expiry or local first-pin time.
	if e2ee.ValidateInstallationStartAt(old.Candidate.Base, later) == nil {
		t.Fatal("historical decoder renewed admission")
	}
	rh := f.self(9, OperationInstallationReconcile)
	rh.Self.IssuedAt = later.Format(time.RFC3339Nano)
	request := InstallationReconcile{Format: InstallationFormat, OriginalOperation: history.Header.Operation, OriginalRequestID: history.Header.Self.RequestID, OriginalPacketDigest: history.PacketDigest, OriginalPacket: original}
	reconcile, err := SealInstallationRequest(f.admission, f.hub, rh, request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded InstallationReconcile
	if _, err := OpenInstallationRequest(f.hubKey, f.hub, reconcile, &decoded, later); err != nil {
		t.Fatal("fresh reconciliation blocked by old original time", err)
	}
	bad := append([]byte(nil), original...)
	bad[len(bad)/2] ^= 1
	if _, err := AuthenticateInstallationOriginal(f.hubKey, f.hub, bad, &old); err == nil {
		t.Fatal("historical authentication skipped canonical/AEAD check")
	}
}

func TestInstallationWirePairSnapshotBytePagination(t *testing.T) {
	f := installationWire(t)
	pair := nativePairSizedFixture(t, true)
	for _, s := range []NativePairSlot{pair.plan.SlotA, pair.plan.SlotB} {
		if ValidateNativePairSlot(s, pair.scope, pair.plan.PeerExpiresAt) != nil {
			t.Fatal("maximum-field real PQ attestation fixture")
		}
	}
	h := f.account(10, OperationOwnerConnectionsRead)
	q := e2ee.InstallationReadQuery{HubID: f.scope.HubID, AccountID: f.scope.AccountID, OwnerID: f.scope.OwnerID, DeviceID: f.scope.DeviceID, AccountEpoch: f.scope.AccountEpoch, DeviceEpoch: f.scope.DeviceEpoch, RequestID: h.Account.RequestID, Nonce: fmt.Sprintf("%x", h.Account.ClientNonce), TargetKind: "PAIR_STATUS", TargetIDs: []string{pair.plan.PairID}, PageSize: 50}
	d, _ := e2ee.InstallationReadQueryDigest(q)
	readProof, err := e2ee.SignInstallationOwnerRead(f.owner, e2ee.InstallationOwnerReadClaims{Version: 1, Purpose: e2ee.InstallationReadPurpose, Scope: f.scope, RequestID: q.RequestID, Nonce: q.Nonce, QueryDigest: d, IssuedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: f.now.Add(time.Minute).Format(time.RFC3339Nano)}, q)
	if err != nil {
		t.Fatal(err)
	}
	request, err := SealInstallationRequest(f.app, f.hub, h, InstallationConnectionsRead{Format: InstallationFormat, SessionToken: bytes.Repeat([]byte{1}, 32), Query: q, Authorization: InstallationReadAuthorization{Kind: InstallationOwnerReadAuth, OwnerReadProof: readProof}})
	if err != nil {
		t.Fatal(err)
	}
	r := NativePairResult{Format: NativePairFormat, Operation: OperationNativePairStatus, RequestID: strings.Repeat("a1", 16), RequestPacketDigest: strings.Repeat("b2", 32), PairID: pair.plan.PairID, State: NativePairWaitingConsent, Outcome: "COMPLETED", ControlRevision: 2, PeerExpiresAt: pair.plan.PeerExpiresAt, SlotA: &pair.plan.SlotA, SlotB: &pair.plan.SlotB, SlotAState: NativePairSlotCandidateReady, SlotBState: NativePairSlotCandidateReady, ObservedAt: formatUTC(pair.f.now)}
	snapshot := InstallationConnectionsSnapshot{Format: InstallationFormat, RequestID: q.RequestID, RequestPacketDigest: e2ee.InstallationPacketDigest(request), SnapshotRevision: 1, ActorScope: f.scope, Subjects: []InstallationSubjectBinding{}, PendingAttempts: []InstallationPendingAttemptRef{}, Grants: []InstallationGrantRef{}, Parents: []InstallationParent{}, Nodes: []AppNodeObservation{}, Pairs: []NativePairResult{r}, ObservedAt: f.now.Format(time.RFC3339Nano)}
	actual, err := SealInstallationResponse(f.hubKey, f.hub, request, snapshot)
	if err != nil {
		t.Fatal("one maximum-field genuine PQ Pair cannot fit", err)
	}
	measured, err := InstallationResponseEncodedSize(f.hub, request, snapshot)
	if err != nil || measured != len(actual) {
		t.Fatal("size model differs from actual Seal", err)
	}
	// Separately cover the full 16KiB DTO byte cap for each attestation. These
	// are size-only buffers, explicitly not valid peer proofs or SQL state.
	upper := installationWireClone(r)
	upper.SlotA.CandidateAttestation = bytes.Repeat([]byte{0x5a}, 16*1024)
	upper.SlotB.CandidateAttestation = bytes.Repeat([]byte{0x5b}, 16*1024)
	budget, err := InstallationResponsePlaintextBudget(f.hub, request)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Pairs = []NativePairResult{}
	snapshot.NextCursor = strings.Repeat("<", 512)
	snapshot.Truncated = false
	base, _ := json.Marshal(snapshot)
	used := len(base)
	row, _ := json.Marshal(upper)
	selected := 0
	for i := 0; i < 16; i++ {
		extra := len(row)
		if selected > 0 {
			extra++
		}
		if used+extra > budget {
			break
		}
		used += extra
		selected++
		snapshot.Pairs = append(snapshot.Pairs, upper)
	}
	if selected < 1 || selected >= 16 {
		t.Fatal("byte pagination failed to bound multi-Pair response")
	}
	snapshot.NextCursor = fmt.Sprintf("synthetic-cursor-%d", selected)
	snapshot.Truncated = true
	page, err := SealInstallationResponse(f.hubKey, f.hub, request, snapshot)
	if err != nil || len(page) > MaxInstallationReceiptBytes {
		t.Fatal("byte-bounded page cannot seal once", err)
	}
	n, err := InstallationResponseEncodedSize(f.hub, request, snapshot)
	if err != nil || n != len(page) {
		t.Fatal("final page size prediction mismatch")
	}
	var opened InstallationConnectionsSnapshot
	if OpenInstallationResponse(f.app, f.hub, request, page, &opened) != nil || !opened.Truncated || opened.NextCursor == "" || len(opened.Pairs) != selected {
		t.Fatal("page/cursor lost actual contents")
	}
	t.Logf("actual maximum-field real PQ slot attestations=%d/%d one_pair_response=%d; 16KiB-cap size buffers fit %d/16 rows, plaintext_budget=%d final_actual_response=%d <=%d; no Store/Runtime claim", len(pair.plan.SlotA.CandidateAttestation), len(pair.plan.SlotB.CandidateAttestation), len(actual), selected, budget, len(page), MaxInstallationReceiptBytes)
}

func TestInstallationWireClosedDiscoveryAndEffectiveGrantLimit(t *testing.T) {
	c := InstallationCapabilities{Format: InstallationFormat, ContractRevision: InstallationContractRevision, Available: true, ServeMode: "--hub-nodes-only", TransportPolicy: AppNodeTransportHTTPS, Operations: InstallationOperations(), TrustModes: []string{e2ee.InstallationFirstOOB, e2ee.InstallationExistingLocalPin}, ReadProfiles: []string{e2ee.InstallationNodeReadProfile, e2ee.InstallationPairReadProfile}}
	raw, _ := json.Marshal(c)
	if _, err := DecodeInstallationCapabilities(raw); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*InstallationCapabilities){"unavailable": func(c *InstallationCapabilities) { c.Available = false }, "wrong composition": func(c *InstallationCapabilities) { c.ServeMode = "--hub" }, "extra operation": func(c *InstallationCapabilities) { c.Operations = append(c.Operations, "manager.rpc") }, "extra profile": func(c *InstallationCapabilities) { c.ReadProfiles = append(c.ReadProfiles, "CLIENT_CONTROL") }, "missing trust mode": func(c *InstallationCapabilities) { c.TrustModes = c.TrustModes[:1] }} {
		t.Run(name, func(t *testing.T) {
			bad := installationWireClone(c)
			change(&bad)
			b, _ := json.Marshal(bad)
			if _, err := DecodeInstallationCapabilities(b); err == nil {
				t.Fatal("unsupported discovery accepted")
			}
		})
	}
	now := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	subject := strings.Repeat("11", 16)
	refs := make([]InstallationGrantRef, 0)
	for i := 0; i < 16; i++ {
		refs = append(refs, InstallationGrantRef{GrantID: fmt.Sprintf("%032x", i+1), OriginContract: InstallationContractRevision, Profile: e2ee.InstallationNodeReadProfile, Target: e2ee.InstallationAccessTarget{NodeBindingID: "synthetic-original-binding", NodeBindingVersion: 1, NodeKeyEpoch: 1}, SubjectRegistrationID: subject, RecipientDeviceID: "synthetic-app", State: "ACTIVE", Revision: 1, ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano)})
	}
	if selected, err := SelectInstallationRecipientGrants(refs, subject, "synthetic-app", nil, now); err != nil || len(selected) != 16 {
		t.Fatal("effective 16-grant boundary", err)
	}
	extra := refs[0]
	extra.GrantID = strings.Repeat("22", 16)
	refs = append(refs, extra)
	if _, err := SelectInstallationRecipientGrants(refs, subject, "synthetic-app", nil, now); err == nil {
		t.Fatal("17 live grants silently admitted")
	}
	refs[0].ExpiresAt = now.Format(time.RFC3339Nano)
	if selected, err := SelectInstallationRecipientGrants(refs, subject, "synthetic-app", nil, now); err != nil || len(selected) != 16 {
		t.Fatal("expired history exhausted live quota", err)
	}
}
