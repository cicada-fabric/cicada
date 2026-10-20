package e2ee

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

type installationFixture struct {
	now                                     time.Time
	hub, owner, app, admission, subject, nc *Identity
	candidate                               InstallationCandidate
	secret, ack                             []byte
}

func installationIdentity(t *testing.T) *Identity {
	t.Helper()
	i, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func installationFixtureAt(t *testing.T) installationFixture {
	t.Helper()
	f := installationFixture{now: time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC), secret: bytes.Repeat([]byte{0xa1}, 32), ack: bytes.Repeat([]byte{0xb2}, 32)}
	f.hub, f.owner, f.app, f.admission, f.subject, f.nc = installationIdentity(t), installationIdentity(t), installationIdentity(t), installationIdentity(t), installationIdentity(t), installationIdentity(t)
	b := InstallationCandidateBase{Format: InstallationRegistrationFormat, Hub: InstallationHubRef{Origin: "https://synthetic-registration.invalid", HubID: "synthetic-hub", Public: f.hub.Public(), KeyVersion: 1, Fingerprint: strings.Repeat("11", 32), TransportPolicy: "HTTPS_APPLICATION_PQ"}, InstallationID: strings.Repeat("21", 16), AttemptID: strings.Repeat("31", 16), AdmissionPublic: f.admission.Public(), Components: []string{"APP", "NODE"}, Subject: InstallationSubject{Kind: InstallationAppSubject, Mode: InstallationNewSubject, App: &InstallationAppRef{DeviceID: "synthetic-app-two", Public: f.subject.Public(), KeyVersion: 1, DeviceEpoch: 1}}, Trust: InstallationTrustSource{Kind: InstallationFirstOOB}, IssuedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: f.now.Add(10 * time.Minute).Format(time.RFC3339Nano)}
	var err error
	f.candidate, err = NewInstallationCandidate(b, f.secret)
	if err != nil {
		t.Fatal("synthetic candidate", err)
	}
	return f
}

func (f installationFixture) scope() InstallationAccountScope {
	return InstallationAccountScope{Version: 1, Origin: f.candidate.Base.Hub.Origin, HubID: f.candidate.Base.Hub.HubID, HubFingerprint: f.candidate.Base.Hub.Fingerprint, AccountID: "synthetic-account", AccountSessionID: "synthetic-admin-session", AccountSessionExpiresAt: f.now.Add(15 * time.Minute).Format(time.RFC3339Nano), OwnerID: "synthetic-owner", OwnerPublic: f.owner.Public(), OwnerKeyVersion: 1, DeviceID: "synthetic-owner-app", DevicePublic: f.app.Public(), AccountEpoch: 1, DeviceEpoch: 1, TransportPolicy: "HTTPS_APPLICATION_PQ"}
}

func (f installationFixture) approval(t *testing.T) InstallationApprovalBase {
	t.Helper()
	s, err := InstallationSubjectDigest(f.candidate.Base.Subject)
	if err != nil {
		t.Fatal(err)
	}
	end := f.now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	a := InstallationApprovalBase{Format: InstallationRegistrationFormat, CandidateDigest: f.candidate.CandidateDigest, OOBCommitment: f.candidate.OOBCommitment, InstallationID: f.candidate.Base.InstallationID, AttemptID: f.candidate.Base.AttemptID, PossessionReceiptDigest: strings.Repeat("41", 32), Scope: f.scope(), SubjectDigest: s, ExpectedRevision: 1, PrepareRequestID: strings.Repeat("51", 16), PreparePacketDigest: strings.Repeat("61", 32), PreviewProofDigest: strings.Repeat("71", 32), ServerNonce: strings.Repeat("81", 32), PreparedAt: f.now.Format(time.RFC3339Nano), AttemptExpiresAt: f.candidate.Base.ExpiresAt, ProofExpiresAt: end, AcceptBefore: end}
	if ValidateInstallationApproval(a, f.candidate) != nil {
		t.Fatal("synthetic approval")
	}
	return a
}

func installationClone[T any](v T) T {
	b, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(b, &out)
	return out
}

func TestInstallationRegistrationIndependentAccountScope(t *testing.T) {
	f := installationFixtureAt(t)
	s := f.scope()
	if ValidateInstallationAccountScope(s) != nil {
		t.Fatal("actual independent account scope rejected")
	}
	for _, name := range []string{"ClientSessionEpoch", "HeadVersion"} {
		if _, found := reflect.TypeOf(s).FieldByName(name); found {
			t.Fatal("registration manufactured legacy Client/N3 context")
		}
	}
	for name, mutate := range map[string]func(*InstallationAccountScope){
		"unknown session":           func(s *InstallationAccountScope) { s.AccountSessionID = "" },
		"unknown Owner key version": func(s *InstallationAccountScope) { s.OwnerKeyVersion = 0 },
		"unknown account epoch":     func(s *InstallationAccountScope) { s.AccountEpoch = 0 },
		"unknown device epoch":      func(s *InstallationAccountScope) { s.DeviceEpoch = 0 },
		"same Owner and App":        func(s *InstallationAccountScope) { s.DevicePublic = s.OwnerPublic },
	} {
		t.Run(name, func(t *testing.T) {
			bad := installationClone(s)
			mutate(&bad)
			if ValidateInstallationAccountScope(bad) == nil {
				t.Fatal("invented or missing real context accepted")
			}
		})
	}
	q := InstallationReadQuery{HubID: s.HubID, AccountID: s.AccountID, OwnerID: s.OwnerID, DeviceID: s.DeviceID, AccountEpoch: s.AccountEpoch, DeviceEpoch: s.DeviceEpoch, RequestID: strings.Repeat("84", 16), Nonce: strings.Repeat("94", 32), TargetKind: "INSTALLATIONS", PageSize: 50}
	d, _ := InstallationReadQueryDigest(q)
	p, err := SignInstallationOwnerRead(f.owner, InstallationOwnerReadClaims{Version: 1, Purpose: InstallationReadPurpose, Scope: s, RequestID: q.RequestID, Nonce: q.Nonce, QueryDigest: d, IssuedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: f.now.Add(time.Minute).Format(time.RFC3339Nano)}, q)
	if err != nil {
		t.Fatal("Owner with no Client/N2/N3 may sign exact read", err)
	}
	if _, err := VerifyInstallationOwnerRead(f.owner.Public(), p, q, f.now); err != nil {
		t.Fatal(err)
	}
	// An old scope's extra legacy coordinate cannot silently enter this proof.
	old := bytes.Replace(p, []byte(`"scope":{`), []byte(`"scope":{"client_session_epoch":1,`), 1)
	if _, err := VerifyInstallationOwnerRead(f.owner.Public(), old, q, f.now); err == nil {
		t.Fatal("old scope interpreted as the revised contract")
	}
}

func TestInstallationRegistrationNewNodeIsItsOwnCandidate(t *testing.T) {
	f := installationFixtureAt(t)
	b := installationClone(f.candidate.Base)
	b.Subject = InstallationSubject{Kind: InstallationNodeSubject, Mode: InstallationNewSubject, Node: &InstallationNodeRef{NodeID: "synthetic-new-node", Public: f.subject.Public(), KeyVersion: 1, KeyEpoch: 1, HubNodeControlPublic: f.nc.Public(), HubNodeControlKeyVersion: 1, HubNodeControlFingerprint: strings.Repeat("13", 32)}}
	if _, err := NewInstallationCandidate(b, f.secret); err != nil {
		t.Fatal("new Node required fabricated legacy history", err)
	}
	for name, mutate := range map[string]func(*InstallationNodeRef){
		"request":            func(n *InstallationNodeRef) { n.RequestID = "fake-legacy-request" },
		"request version":    func(n *InstallationNodeRef) { n.RequestVersion = 1 },
		"candidate":          func(n *InstallationNodeRef) { n.CandidateDigest = strings.Repeat("24", 32) },
		"candidate expiry":   func(n *InstallationNodeRef) { n.CandidateExpiresAt = b.ExpiresAt },
		"binding":            func(n *InstallationNodeRef) { n.BindingID = "fake-legacy-binding" },
		"binding version":    func(n *InstallationNodeRef) { n.BindingVersion = 1 },
		"credential":         func(n *InstallationNodeRef) { n.CredentialCommitment = strings.Repeat("34", 32) },
		"credential version": func(n *InstallationNodeRef) { n.CredentialVersion = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := installationClone(b)
			mutate(bad.Subject.Node)
			if _, err := NewInstallationCandidate(bad, f.secret); err == nil {
				t.Fatal("new Node claimed nonexistent legacy history or bearer")
			}
		})
	}
}

func installationCheckIssuanceTimes(t *testing.T, issued, expiry time.Time, check func(time.Time) error) {
	t.Helper()
	for _, tc := range []struct {
		name string
		now  time.Time
		ok   bool
	}{
		{"clock_behind_1s", issued.Add(-time.Second), true},
		{"clock_ahead_1s", issued.Add(time.Second), true},
		{"early_30s_inclusive", issued.Add(-30 * time.Second), true},
		{"future_beyond_30s", issued.Add(-30*time.Second - time.Nanosecond), false},
		{"exact_expiry", expiry, false},
		{"after_expiry", expiry.Add(time.Second), false},
		{"no_clock", time.Time{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := check(tc.now); (err == nil) != tc.ok {
				t.Fatalf("issuance lower-bound tolerance or strict expiry: accepted=%v want=%v", err == nil, tc.ok)
			}
		})
	}
}

func TestInstallationRegistrationCrossIssuerTimes(t *testing.T) {
	f := installationFixtureAt(t)
	for _, offset := range []time.Duration{-time.Second, time.Second, -30 * time.Second, -30*time.Second - time.Nanosecond} {
		t.Run(offset.String(), func(t *testing.T) {
			at := f.now.Add(offset)
			challenge, _ := installationKEMPair(t, f)
			challenge.IssuedAt = at.Format(time.RFC3339Nano)
			challenge.ExpiresAt = at.Add(2 * time.Minute).Format(time.RFC3339Nano)
			packet, err := SealInstallationKEMChallenge(f.hub, f.candidate, challenge)
			want := offset >= -30*time.Second
			if (err == nil) != want {
				t.Fatal("cross-issuer KEM issuance order", err)
			}
			if want {
				opened, err := OpenInstallationKEMChallenge(f.admission, f.candidate, InstallationKEMHeader(challenge), packet, f.now)
				clear(opened.Nonce)
				if err != nil {
					t.Fatal("ordinary peer clock skew rejected KEM", err)
				}
			}
			a := f.approval(t)
			a.PreparedAt = at.Format(time.RFC3339Nano)
			a.ProofExpiresAt = at.Add(5 * time.Minute).Format(time.RFC3339Nano)
			a.AcceptBefore = a.ProofExpiresAt
			proof, capsule, err := SealInstallationOwnerApproval(f.owner, f.candidate, a, f.secret, f.ack)
			if (err == nil) != want {
				t.Fatal("cross-issuer approval preparation order", err)
			}
			if want {
				opened, err := OpenInstallationTrustCapsuleFirstOOB(f.admission, f.candidate, proof, capsule, f.secret, f.now)
				clear(opened.OOBSecret)
				clear(opened.ACKNonce)
				if err != nil {
					t.Fatal("ordinary peer clock skew rejected first pin", err)
				}
			}
		})
	}
}

func TestInstallationRegistrationFirstOOBAndPrivateACK(t *testing.T) {
	f := installationFixtureAt(t)
	a := f.approval(t)
	proof, capsule, err := SealInstallationOwnerApproval(f.owner, f.candidate, a, f.secret, f.ack)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("owner_proof_time", func(t *testing.T) {
		installationCheckIssuanceTimes(t, f.now, f.now.Add(5*time.Minute), func(now time.Time) error {
			_, err := VerifyInstallationOwnerProof(f.owner.Public(), f.candidate, proof, now)
			return err
		})
	})
	t.Run("first_pin_time", func(t *testing.T) {
		installationCheckIssuanceTimes(t, f.now, f.now.Add(5*time.Minute), func(now time.Time) error {
			opened, err := OpenInstallationTrustCapsuleFirstOOB(f.admission, f.candidate, proof, capsule, f.secret, now)
			clear(opened.OOBSecret)
			clear(opened.ACKNonce)
			return err
		})
	})
	t.Run("ack_time", func(t *testing.T) {
		installationCheckIssuanceTimes(t, f.now, f.now.Add(5*time.Minute), func(now time.Time) error {
			return VerifyInstallationACK(f.owner.Public(), f.candidate, proof, capsule, f.ack, now)
		})
	})
	claims, err := VerifyInstallationOwnerProof(f.owner.Public(), f.candidate, proof, f.now)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenInstallationTrustCapsuleFirstOOB(f.admission, f.candidate, proof, capsule, f.secret, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(opened.OOBSecret)
	defer clear(opened.ACKNonce)
	if !bytes.Equal(opened.ACKNonce, f.ack) || !bytes.Equal(opened.OOBSecret, f.secret) || VerifyInstallationACK(f.owner.Public(), f.candidate, proof, capsule, opened.ACKNonce, f.now) != nil {
		t.Fatal("capsule/ACK binding")
	}
	publicDigest, _ := hex.DecodeString(claims.CapsuleDigest)
	for name, nonce := range map[string][]byte{"public digest": publicDigest, "OOB secret": f.secret, "wrong nonce": bytes.Repeat([]byte{0xcc}, 32), "missing": nil} {
		t.Run(name, func(t *testing.T) {
			if VerifyInstallationACK(f.owner.Public(), f.candidate, proof, capsule, nonce, f.now) == nil {
				t.Fatal("public/wrong ACK accepted")
			}
		})
	}
	if _, err := OpenInstallationTrustCapsuleFirstOOB(f.admission, f.candidate, proof, capsule, bytes.Repeat([]byte{0xdd}, 32), f.now); err == nil {
		t.Fatal("Hub candidate alone installed trust")
	}
	if _, err := VerifyInstallationOwnerProof(f.app.Public(), f.candidate, proof, f.now); err == nil {
		t.Fatal("device signature substituted for Owner")
	}
	if _, err := OpenInstallationTrustCapsuleFirstOOB(f.admission, f.candidate, proof, capsule, f.secret, time.Time{}); err == nil {
		t.Fatal("zero time first admission")
	}
	if _, err := OpenInstallationTrustCapsuleFirstOOB(f.admission, f.candidate, proof, capsule, f.secret, f.now.Add(5*time.Minute)); err == nil {
		t.Fatal("expired proof accepted before ten-minute attempt end")
	}
	bad := append([]byte(nil), capsule...)
	bad[len(bad)/2] ^= 1
	if _, err := OpenInstallationTrustCapsuleFirstOOB(f.admission, f.candidate, proof, bad, f.secret, f.now); err == nil {
		t.Fatal("changed ciphertext accepted")
	}
	if _, err := VerifyInstallationOwnerProof(f.owner.Public(), f.candidate, append(proof, '\n'), f.now); err == nil {
		t.Fatal("noncanonical Owner proof accepted")
	}
	t.Logf("synthetic-only actual PQ Owner proof=%d capsule=%d bytes; no deployment state", len(proof), len(capsule))
}

func TestInstallationRegistrationHubCannotSelfCertifyOwner(t *testing.T) {
	f := installationFixtureAt(t)
	attacker := installationIdentity(t)
	a := f.approval(t)
	a.Scope.OwnerPublic = attacker.Public()
	wrongSecret := bytes.Repeat([]byte{0xee}, 32)
	plain, _ := json.Marshal(InstallationTrustCapsule{Format: InstallationRegistrationFormat, Approval: a, OwnerPublic: attacker.Public(), OOBSecret: wrongSecret, ACKNonce: f.ack})
	defer clear(plain)
	aad, _ := installationCapsuleAADBytes(a)
	capsule, err := Seal(attacker, f.admission.Public(), plain, aad, 1)
	if err != nil {
		t.Fatal(err)
	}
	ack, _ := InstallationACKCommitment(a, f.ack)
	proof, err := SignInstallationOwnerProof(attacker, f.candidate, InstallationOwnerClaims{Version: 1, Purpose: InstallationRegisterPurpose, Approval: a, CapsuleDigest: InstallationCapsuleDigest(capsule), ACKCommitment: ack})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInstallationTrustCapsuleFirstOOB(f.admission, f.candidate, proof, capsule, f.secret, f.now); err == nil {
		t.Fatal("Hub substituted its self-signed Owner key")
	}
}

func (f *installationFixture) useExistingParent(t *testing.T) InstallationLocalPin {
	t.Helper()
	b := installationClone(f.candidate.Base)
	d, err := OwnerDevicePublicKeyFingerprint(f.owner.Public())
	if err != nil {
		t.Fatal(err)
	}
	e := &InstallationExistingTrust{Source: InstallationRegisteredParent, ParentRegistrationID: strings.Repeat("91", 16), RegistrationEpoch: 3, AdmissionCredentialVersion: 4, OwnerID: "synthetic-owner", OwnerKeyID: f.owner.Public().ID, OwnerPublicDigest: d, LocalTrustVersion: 7}
	b.Trust = InstallationTrustSource{Kind: InstallationExistingLocalPin, Existing: e}
	f.candidate, err = NewInstallationCandidate(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	return InstallationLocalPin{Source: InstallationRegisteredParent, Hub: b.Hub, InstallationID: b.InstallationID, ParentRegistrationID: e.ParentRegistrationID, RegistrationEpoch: e.RegistrationEpoch, AdmissionCredentialVersion: e.AdmissionCredentialVersion, AdmissionPublic: f.admission.Public(), RegistrationState: "REGISTERED", OwnerID: e.OwnerID, OwnerPublic: f.owner.Public(), TrustState: "ACTIVE", TrustVersion: e.LocalTrustVersion}
}

func TestInstallationRegistrationExistingPinAppendWithoutNewOOB(t *testing.T) {
	f := installationFixtureAt(t)
	pin := f.useExistingParent(t)
	proof, capsule, err := SealInstallationOwnerApproval(f.owner, f.candidate, f.approval(t), nil, f.ack)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenInstallationTrustCapsuleExistingPin(f.admission, f.candidate, proof, capsule, pin, f.now)
	if err != nil || opened.OOBSecret != nil {
		t.Fatal("existing parent required another OOB secret", err)
	}
	clear(opened.ACKNonce)
	if _, _, err := SealInstallationOwnerApproval(f.owner, f.candidate, f.approval(t), f.secret, f.ack); err == nil {
		t.Fatal("OOB secret mixed into existing-pin capsule")
	}
	if _, err := OpenInstallationTrustCapsuleFirstOOB(f.admission, f.candidate, proof, capsule, f.secret, f.now); err == nil {
		t.Fatal("existing branch fell back to first OOB")
	}
	changes := map[string]func(*InstallationLocalPin){"missing": func(p *InstallationLocalPin) { *p = InstallationLocalPin{} }, "revoked Owner": func(p *InstallationLocalPin) { p.TrustState = "REVOKED" }, "revoked parent": func(p *InstallationLocalPin) { p.RegistrationState = "REVOKED" }, "old credential": func(p *InstallationLocalPin) { p.AdmissionCredentialVersion++ }, "pin version": func(p *InstallationLocalPin) { p.TrustVersion++ }, "other Owner key": func(p *InstallationLocalPin) { p.OwnerPublic = f.app.Public() }, "other parent": func(p *InstallationLocalPin) { p.ParentRegistrationID = strings.Repeat("92", 16) }}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			bad := installationClone(pin)
			change(&bad)
			if _, err := OpenInstallationTrustCapsuleExistingPin(f.admission, f.candidate, proof, capsule, bad, f.now); err == nil {
				t.Fatal("untrusted/changed local pin accepted")
			}
		})
	}
}

func TestInstallationRegistrationLegacyNodeAdoptionWithoutReinstall(t *testing.T) {
	f := installationFixtureAt(t)
	b := installationClone(f.candidate.Base)
	n := &InstallationNodeRef{NodeID: "synthetic-original-node", Public: f.subject.Public(), KeyVersion: 1, KeyEpoch: 3, HubNodeControlPublic: f.nc.Public(), HubNodeControlKeyVersion: 1, HubNodeControlFingerprint: strings.Repeat("13", 32), CredentialCommitment: strings.Repeat("23", 32), RequestID: "synthetic-original-approved-request", RequestVersion: 2, CandidateDigest: strings.Repeat("33", 32), BindingID: "synthetic-original-binding", BindingVersion: 4, CredentialVersion: 5}
	b.Subject = InstallationSubject{Kind: InstallationNodeSubject, Mode: InstallationAdoptExisting, Node: n}
	d, _ := OwnerDevicePublicKeyFingerprint(f.owner.Public())
	b.Trust = InstallationTrustSource{Kind: InstallationExistingLocalPin, Existing: &InstallationExistingTrust{Source: InstallationLegacyNode, OwnerID: "synthetic-owner", OwnerKeyID: f.owner.Public().ID, OwnerPublicDigest: d, LocalTrustVersion: 9}}
	var err error
	f.candidate, err = NewInstallationCandidate(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	pin := InstallationLocalPin{Source: InstallationLegacyNode, Hub: InstallationHubRef{Origin: b.Hub.Origin, HubID: b.Hub.HubID}, InstallationID: b.InstallationID, OwnerID: "synthetic-owner", OwnerPublic: f.owner.Public(), TrustState: "ACTIVE", TrustVersion: 9, LegacyNode: installationClone(n), LegacyNodeState: "ACTIVE"}
	before, _ := json.Marshal(pin.LegacyNode)
	proof, capsule, err := SealInstallationOwnerApproval(f.owner, f.candidate, f.approval(t), nil, f.ack)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenInstallationTrustCapsuleExistingPin(f.admission, f.candidate, proof, capsule, pin, f.now)
	if err != nil || opened.OOBSecret != nil {
		t.Fatal("legacy adoption demanded re-pair/OOB", err)
	}
	clear(opened.ACKNonce)
	after, _ := json.Marshal(pin.LegacyNode)
	if !bytes.Equal(before, after) || f.candidate.Base.Subject.Node.BindingID != n.BindingID || f.candidate.Base.Subject.Node.KeyEpoch != 3 || f.candidate.Base.Subject.Node.CredentialVersion != 5 {
		t.Fatal("legacy identities/credentials changed")
	}
	for name, change := range map[string]func(*InstallationLocalPin){"missing local legacy": func(p *InstallationLocalPin) { p.LegacyNode = nil }, "revoked original": func(p *InstallationLocalPin) { p.LegacyNodeState = "REVOKED" }, "different binding": func(p *InstallationLocalPin) { p.LegacyNode.BindingID = "synthetic-other-binding" }, "different credential": func(p *InstallationLocalPin) { p.LegacyNode.CredentialCommitment = strings.Repeat("24", 32) }, "Hub claimed registered": func(p *InstallationLocalPin) { p.RegistrationState = "REGISTERED" }, "untrusted Owner": func(p *InstallationLocalPin) { p.TrustState = "PENDING" }} {
		t.Run(name, func(t *testing.T) {
			bad := installationClone(pin)
			change(&bad)
			if _, err := OpenInstallationTrustCapsuleExistingPin(f.admission, f.candidate, proof, capsule, bad, f.now); err == nil {
				t.Fatal("legacy adoption lost independent trust")
			}
		})
	}
}

func TestInstallationRegistrationNoncyclicTimesAndOrigins(t *testing.T) {
	f := installationFixtureAt(t)
	t.Run("start_time", func(t *testing.T) {
		b := installationClone(f.candidate.Base)
		b.ExpiresAt = f.now.Add(time.Minute).Format(time.RFC3339Nano)
		installationCheckIssuanceTimes(t, f.now, f.now.Add(time.Minute), func(now time.Time) error {
			return ValidateInstallationStartAt(b, now)
		})
	})
	bType := reflect.TypeOf(InstallationCandidateBase{})
	for _, name := range []string{"CandidateDigest", "OOBCommitment", "CapsuleDigest", "ACKCommitment", "Signature"} {
		if _, found := bType.FieldByName(name); found {
			t.Fatal("self-containing base", name)
		}
	}
	aType := reflect.TypeOf(InstallationApprovalBase{})
	for _, name := range []string{"CapsuleDigest", "ACKCommitment", "ACKNonce", "Signature"} {
		if _, found := aType.FieldByName(name); found {
			t.Fatal("self-containing approval", name)
		}
	}
	if ValidateInstallationStartAt(f.candidate.Base, f.now) != nil || ValidateInstallationStartAt(f.candidate.Base, f.now.Add(61*time.Second)) == nil || ValidateInstallationStartAt(f.candidate.Base, f.now.Add(-InstallationIssuanceSkew-time.Nanosecond)) == nil {
		t.Fatal("immutable first start window")
	}
	for _, change := range []func(*InstallationApprovalBase){func(a *InstallationApprovalBase) {
		a.AttemptExpiresAt = f.now.Add(11 * time.Minute).Format(time.RFC3339Nano)
	}, func(a *InstallationApprovalBase) {
		a.AcceptBefore = f.now.Add(6 * time.Minute).Format(time.RFC3339Nano)
	}, func(a *InstallationApprovalBase) {
		a.ProofExpiresAt = f.now.Add(6 * time.Minute).Format(time.RFC3339Nano)
	}} {
		a := f.approval(t)
		change(&a)
		if ValidateInstallationApproval(a, f.candidate) == nil {
			t.Fatal("floating proof/attempt deadline")
		}
	}
	for _, origin := range []string{"https://a&b.invalid", "https://a<b.invalid", "https://a>b.invalid", "https://例子.invalid", "https://host?", "https://host/path", "https://host:000443", "https://-host.invalid"} {
		if ValidateInstallationOrigin(origin, "HTTPS_APPLICATION_PQ") == nil {
			t.Fatal("unbounded/noncanonical new origin accepted")
		}
	}
	for _, origin := range []string{"https://synthetic-registration.invalid", "https://127.0.0.1:8787", "https://[2001:db8::1]:443"} {
		if ValidateInstallationOrigin(origin, "HTTPS_APPLICATION_PQ") != nil {
			t.Fatal("valid IP/DNS origin rejected")
		}
	}
}

func installationKEMPair(t *testing.T, f installationFixture) (InstallationKEMChallenge, InstallationKEMChallenge) {
	t.Helper()
	base := InstallationKEMChallenge{Format: InstallationRegistrationFormat, CandidateDigest: f.candidate.CandidateDigest, OOBCommitment: f.candidate.OOBCommitment, HubID: f.candidate.Base.Hub.HubID, InstallationID: f.candidate.Base.InstallationID, AttemptID: f.candidate.Base.AttemptID, StartPacketDigest: strings.Repeat("45", 32), ChallengeID: strings.Repeat("55", 16), IssuedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: f.now.Add(2 * time.Minute).Format(time.RFC3339Nano)}
	a, s := base, base
	a.Purpose = InstallationAdmissionKEM
	a.RecipientKeyID = f.admission.Public().ID
	a.Nonce = bytes.Repeat([]byte{1}, 32)
	s.Purpose = InstallationSubjectKEM
	s.RecipientKeyID = f.subject.Public().ID
	s.Nonce = bytes.Repeat([]byte{2}, 32)
	return a, s
}

func TestInstallationRegistrationDualKEMAndSubjectACK(t *testing.T) {
	f := installationFixtureAt(t)
	a, s := installationKEMPair(t, f)
	ap, err := SealInstallationKEMChallenge(f.hub, f.candidate, a)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := SealInstallationKEMChallenge(f.hub, f.candidate, s)
	if err != nil {
		t.Fatal(err)
	}
	ad, err := OpenInstallationKEMChallenge(f.admission, f.candidate, InstallationKEMHeader(a), ap, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(ad.Nonce)
	su, err := OpenInstallationKEMChallenge(f.subject, f.candidate, InstallationKEMHeader(s), sp, f.now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(su.Nonce)
	req := strings.Repeat("65", 16)
	sr, err := SealInstallationKEMReceipt(f.subject, f.candidate, InstallationKEMReceipt{Format: InstallationRegistrationFormat, Challenge: su, ProveRequestID: req})
	if err != nil {
		t.Fatal(err)
	}
	ar, err := SealInstallationKEMReceipt(f.admission, f.candidate, InstallationKEMReceipt{Format: InstallationRegistrationFormat, Challenge: ad, ProveRequestID: req, SubjectReceiptDigest: InstallationPacketDigest(sr)})
	if err != nil {
		t.Fatal(err)
	}
	ah, _ := InstallationKEMNonceDigest(a)
	sh, _ := InstallationKEMNonceDigest(s)
	t.Run("challenge_time", func(t *testing.T) {
		installationCheckIssuanceTimes(t, f.now, f.now.Add(2*time.Minute), func(now time.Time) error {
			opened, err := OpenInstallationKEMChallenge(f.admission, f.candidate, InstallationKEMHeader(a), ap, now)
			clear(opened.Nonce)
			return err
		})
	})
	t.Run("receipt_time", func(t *testing.T) {
		installationCheckIssuanceTimes(t, f.now, f.now.Add(2*time.Minute), func(now time.Time) error {
			_, err := VerifyInstallationPossession(f.hub, f.candidate, InstallationKEMHeader(a), InstallationKEMHeader(s), req, ar, sr, ah, sh, now)
			return err
		})
	})
	p, err := VerifyInstallationPossession(f.hub, f.candidate, InstallationKEMHeader(a), InstallationKEMHeader(s), req, ar, sr, ah, sh, f.now)
	if err != nil || p.SubjectKeyID != f.subject.Public().ID || p.AdmissionKeyID != f.admission.Public().ID {
		t.Fatal("dual possession failed", err)
	}
	if _, err := VerifyInstallationPossession(f.hub, f.candidate, InstallationKEMHeader(a), InstallationKEMHeader(s), req, ar, sr, sh, ah, f.now); err == nil {
		t.Fatal("cross-purpose KEM nonce accepted")
	}
	if _, err := VerifyInstallationPossession(f.hub, f.candidate, InstallationKEMHeader(a), InstallationKEMHeader(s), strings.Repeat("66", 16), ar, sr, ah, sh, f.now); err == nil {
		t.Fatal("another prove ID accepted")
	}
	if _, err := OpenInstallationKEMChallenge(f.admission, f.candidate, InstallationKEMHeader(s), sp, f.now); err == nil {
		t.Fatal("admission key replaced subject KEM")
	}
	if _, err := OpenInstallationKEMChallenge(f.subject, f.candidate, InstallationKEMHeader(s), sp, f.now.Add(2*time.Minute)); err == nil {
		t.Fatal("late KEM challenge accepted")
	}
	approval := f.approval(t)
	proof, capsule, err := SealInstallationOwnerApproval(f.owner, f.candidate, approval, f.secret, f.ack)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := VerifyInstallationOwnerProof(f.owner.Public(), f.candidate, proof, f.now)
	if err != nil {
		t.Fatal(err)
	}
	acceptID := strings.Repeat("75", 16)
	ack, err := SealInstallationSubjectAccept(f.subject, f.candidate, claims, proof, acceptID, f.ack)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenInstallationSubjectAccept(f.hub, f.owner.Public(), f.candidate, proof, capsule, ack, acceptID, f.now)
	if err != nil || !bytes.Equal(opened.ACKNonce, f.ack) {
		t.Fatal("subject accept failed", err)
	}
	clear(opened.ACKNonce)
	if _, err := OpenInstallationSubjectAccept(f.hub, f.owner.Public(), f.candidate, proof, capsule, ack, strings.Repeat("76", 16), f.now); err == nil {
		t.Fatal("ACK changed accept original")
	}
	t.Logf("synthetic-only actual PQ KEM packets admission=%d subject=%d receipts=%d/%d subjectACK=%d", len(ap), len(sp), len(ar), len(sr), len(ack))
}

func TestInstallationRegistrationSigningDoesNotProveEitherKEM(t *testing.T) {
	for _, role := range []string{"admission", "subject"} {
		t.Run(role, func(t *testing.T) {
			f := installationFixtureAt(t)
			victim := installationIdentity(t)
			b := installationClone(f.candidate.Base)
			signer := f.admission
			mixed := f.admission.Public()
			if role == "subject" {
				signer = f.subject
				mixed = f.subject.Public()
			}
			mixed.KEMPublic = append([]byte(nil), victim.Public().KEMPublic...)
			mixed.ID = identityID(mixed.KEMPublic, mixed.SigningPublic)
			// Model a malicious signature holder advertising a public bundle whose
			// KEM key belongs to someone else. Its derived ID and signature are valid.
			mixedSigner := *signer
			mixedSigner.public = mixed
			signer = &mixedSigner
			if role == "admission" {
				b.AdmissionPublic = mixed
			} else {
				b.Subject.App.Public = mixed
			}
			var err error
			f.candidate, err = NewInstallationCandidate(b, f.secret)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte(f.candidate.CandidateDigest)
			signatureOnly, err := Seal(signer, f.hub.Public(), msg, []byte("synthetic signature-only probe"), 1)
			if err != nil {
				t.Fatal(err)
			}
			plain, _, err := Open(f.hub, mixed, signatureOnly, []byte("synthetic signature-only probe"))
			if err != nil || !bytes.Equal(plain, msg) {
				t.Fatal("attack did not exercise valid signature", err)
			}
			clear(plain)
			a, s := installationKEMPair(t, f)
			challenge := a
			if role == "subject" {
				challenge = s
			}
			challenge.RecipientKeyID = mixed.ID
			packet, err := SealInstallationKEMChallenge(f.hub, f.candidate, challenge)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := OpenInstallationKEMChallenge(signer, f.candidate, InstallationKEMHeader(challenge), packet, f.now); err == nil {
				t.Fatal("signature holder claimed someone else's KEM key")
			}
		})
	}
}

func TestInstallationRegistrationOwnerReadAndFiniteProfiles(t *testing.T) {
	f := installationFixtureAt(t)
	q := InstallationReadQuery{HubID: f.scope().HubID, AccountID: f.scope().AccountID, OwnerID: f.scope().OwnerID, DeviceID: f.scope().DeviceID, AccountEpoch: 1, DeviceEpoch: 1, RequestID: strings.Repeat("85", 16), Nonce: strings.Repeat("95", 32), TargetKind: "INSTALLATIONS", TargetIDs: []string{}, PageSize: 50}
	d, _ := InstallationReadQueryDigest(q)
	claims := InstallationOwnerReadClaims{Version: 1, Purpose: InstallationReadPurpose, Scope: f.scope(), RequestID: q.RequestID, Nonce: q.Nonce, QueryDigest: d, IssuedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: f.now.Add(time.Minute).Format(time.RFC3339Nano)}
	proof, err := SignInstallationOwnerRead(f.owner, claims, q)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("read_proof_time", func(t *testing.T) {
		installationCheckIssuanceTimes(t, f.now, f.now.Add(time.Minute), func(now time.Time) error {
			_, err := VerifyInstallationOwnerRead(f.owner.Public(), proof, q, now)
			return err
		})
	})
	if _, err := VerifyInstallationOwnerRead(f.owner.Public(), proof, q, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := SignInstallationOwnerRead(f.app, claims, q); err == nil {
		t.Fatal("App signature became Owner read proof")
	}
	for _, change := range []func(*InstallationReadQuery){func(q *InstallationReadQuery) { q.Cursor = "changed" }, func(q *InstallationReadQuery) { q.PageSize-- }, func(q *InstallationReadQuery) { q.DeviceID = "other-device" }, func(q *InstallationReadQuery) { q.TargetKind = "GRANTED" }} {
		bad := installationClone(q)
		change(&bad)
		if _, err := VerifyInstallationOwnerRead(f.owner.Public(), proof, bad, f.now); err == nil {
			t.Fatal("read query substitution")
		}
	}
	if _, err := VerifyInstallationOwnerRead(f.owner.Public(), proof, q, f.now.Add(time.Minute)); err == nil {
		t.Fatal("expired read proof revived by login")
	}
	grant := InstallationAccessClaims{Version: 1, Purpose: InstallationAccessPurpose, Scope: f.scope(), GrantID: strings.Repeat("a5", 16), Recipient: InstallationRecipient{SubjectRegistrationID: strings.Repeat("b5", 16), SubjectRegistrationEpoch: 1, DeviceID: "synthetic-app-two", DevicePublic: f.subject.Public(), DeviceEpoch: 1}, Profile: InstallationNodeReadProfile, Target: InstallationAccessTarget{NodeBindingID: "synthetic-binding", NodeBindingVersion: 1, NodeKeyEpoch: 1}, ExpectedRevision: 1, PrepareRequestID: strings.Repeat("c5", 16), PreparePacketDigest: strings.Repeat("d5", 32), ServerNonce: strings.Repeat("e5", 32), PreparedAt: f.now.Format(time.RFC3339Nano), ProofExpiresAt: f.now.Add(5 * time.Minute).Format(time.RFC3339Nano), ExpiresAt: f.now.Add(15 * time.Minute).Format(time.RFC3339Nano)}
	gp, err := SignInstallationAccess(f.owner, grant)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("grant_proof_time", func(t *testing.T) {
		installationCheckIssuanceTimes(t, f.now, f.now.Add(5*time.Minute), func(now time.Time) error {
			_, err := VerifyInstallationAccess(f.owner.Public(), gp, now)
			return err
		})
	})
	if _, err := VerifyInstallationAccess(f.owner.Public(), gp, f.now); err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"*", "CLIENT_CONTROL", "APP_MANAGER", "PAIR_ADMIN", "N3_NODE_STATUS_READ:*"} {
		bad := installationClone(grant)
		bad.Profile = profile
		if _, err := SignInstallationAccess(f.owner, bad); err == nil {
			t.Fatal("expanded read profile accepted")
		}
	}
	grant.Profile = InstallationPairReadProfile
	grant.Target.PairID = strings.Repeat("f5", 16)
	if _, err := SignInstallationAccess(f.owner, grant); err != nil {
		t.Fatal("bounded Pair observe unavailable", err)
	}
	grant.ExpiresAt = f.now.Add(15*time.Minute + time.Second).Format(time.RFC3339Nano)
	if _, err := SignInstallationAccess(f.owner, grant); err == nil {
		t.Fatal("grant auto extended")
	}
}

func TestInstallationRegistrationExactOwnerIntents(t *testing.T) {
	f := installationFixtureAt(t)
	for _, purpose := range []string{InstallationPreviewPurpose, InstallationRevokePurpose, InstallationAccessPreviewPurpose, InstallationAccessRevokePurpose} {
		t.Run(purpose, func(t *testing.T) {
			c := InstallationOwnerIntentClaims{Version: 1, Purpose: purpose, Scope: f.scope(), RequestID: strings.Repeat("a6", 16), Nonce: strings.Repeat("b6", 32), TargetID: strings.Repeat("c6", 16), TargetDigest: strings.Repeat("d6", 32), ExpectedRevision: 3, IssuedAt: f.now.Format(time.RFC3339Nano), ExpiresAt: f.now.Add(time.Minute).Format(time.RFC3339Nano)}
			p, err := SignInstallationOwnerIntent(f.owner, c)
			if err != nil {
				t.Fatal(err)
			}
			t.Run("intent_proof_time", func(t *testing.T) {
				installationCheckIssuanceTimes(t, f.now, f.now.Add(time.Minute), func(now time.Time) error {
					_, err := VerifyInstallationOwnerIntent(f.owner.Public(), p, purpose, c.TargetID, c.TargetDigest, 3, now)
					return err
				})
			})
			if _, err := VerifyInstallationOwnerIntent(f.owner.Public(), p, purpose, c.TargetID, c.TargetDigest, 3, f.now); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyInstallationOwnerIntent(f.owner.Public(), p, purpose, c.TargetID, c.TargetDigest, 4, f.now); err == nil {
				t.Fatal("intent changed revision")
			}
			if _, err := VerifyInstallationOwnerIntent(f.owner.Public(), p, purpose, c.TargetID, strings.Repeat("e6", 32), 3, f.now); err == nil {
				t.Fatal("intent changed target digest")
			}
			if _, err := VerifyInstallationOwnerIntent(f.owner.Public(), p, InstallationReadPurpose, c.TargetID, c.TargetDigest, 3, f.now); err == nil {
				t.Fatal("cross-purpose signature")
			}
			if _, err := VerifyInstallationOwnerIntent(f.owner.Public(), p, purpose, c.TargetID, c.TargetDigest, 3, f.now.Add(time.Minute)); err == nil {
				t.Fatal("expired intent accepted")
			}
			if _, err := SignInstallationOwnerIntent(f.app, c); err == nil {
				t.Fatal("device key signed as Owner")
			}
		})
	}
}
