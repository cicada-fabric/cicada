package e2ee

import (
	"bytes"
	"math"
	"net"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

// InstallationIssuanceSkew tolerates only a remote issuer's clock being ahead.
// It never extends an immutable expiry, accept deadline or freshness age.
const InstallationIssuanceSkew = 30 * time.Second

func installationPositive(n uint64) bool { return n > 0 && n < math.MaxInt64 }

func installationDistinct(a, b PublicIdentity) bool {
	return a.ID != b.ID && !bytes.Equal(a.KEMPublic, b.KEMPublic) && !bytes.Equal(a.SigningPublic, b.SigningPublic)
}

func installationWindow(issued, expires string, maximum time.Duration) (time.Time, time.Time, error) {
	i, err := parseCanonicalUTC(issued)
	e, ee := parseCanonicalUTC(expires)
	if err != nil || ee != nil || !e.After(i) || e.After(i.Add(maximum)) {
		return time.Time{}, time.Time{}, ErrInvalidEnvelope
	}
	return i, e, nil
}

func installationCurrent(i, e, now time.Time) error {
	if now.IsZero() || now.Before(i.Add(-InstallationIssuanceSkew)) || !now.Before(e) {
		return ErrInvalidEnvelope
	}
	return nil
}

func InstallationSubjectPublic(s InstallationSubject) (PublicIdentity, error) {
	switch s.Kind {
	case InstallationNodeSubject:
		if s.Node != nil && s.App == nil {
			return s.Node.Public, nil
		}
	case InstallationAppSubject:
		if s.App != nil && s.Node == nil {
			return s.App.Public, nil
		}
	}
	return PublicIdentity{}, ErrInvalidEnvelope
}

// The new bounded ticket supports ASCII DNS names and literal IPs, not
// arbitrary URI reg-names. This also bounds Go JSON escaping of the origin.
// Existing v1 origin validators and stored identities are not changed.
func ValidateInstallationOrigin(origin, policy string) error {
	u, err := url.Parse(origin)
	if err != nil || len(origin) > MaxInstallationOriginBytes || u.Host == "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != origin {
		return ErrInvalidEnvelope
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		name := strings.TrimSuffix(host, ".")
		if len(name) == 0 || len(name) > 253 {
			return ErrInvalidEnvelope
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return ErrInvalidEnvelope
			}
			for _, ch := range label {
				if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-') {
					return ErrInvalidEnvelope
				}
			}
		}
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return ErrInvalidEnvelope
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return ErrInvalidEnvelope
	}
	switch policy {
	case "HTTPS_APPLICATION_PQ":
		if u.Scheme != "https" {
			return ErrInvalidEnvelope
		}
	case "LOOPBACK_HTTP_TEST_ONLY":
		if u.Scheme != "http" || ip == nil || !ip.IsLoopback() {
			return ErrInvalidEnvelope
		}
	default:
		return ErrInvalidEnvelope
	}
	return nil
}

func ValidateInstallationBase(b InstallationCandidateBase) error {
	if b.Format != InstallationRegistrationFormat || !appNodeProofID(b.InstallationID) || !appNodeProofID(b.AttemptID) ||
		!tlsGrantToken(b.Hub.HubID) || len(b.Hub.HubID) > MaxInstallationHubIDBytes || ValidatePublicIdentity(b.Hub.Public) != nil || !installationPositive(b.Hub.KeyVersion) || !canonicalSHA256Hex(b.Hub.Fingerprint) ||
		ValidatePublicIdentity(b.AdmissionPublic) != nil || !installationDistinct(b.AdmissionPublic, b.Hub.Public) || len(b.Components) < 1 || len(b.Components) > 3 || !sort.StringsAreSorted(b.Components) {
		return ErrInvalidEnvelope
	}
	if ValidateInstallationOrigin(b.Hub.Origin, b.Hub.TransportPolicy) != nil {
		return ErrInvalidEnvelope
	}
	_, _, err := installationWindow(b.IssuedAt, b.ExpiresAt, 10*time.Minute)
	if err != nil {
		return err
	}
	wanted, present := "", false
	switch b.Subject.Kind {
	case InstallationNodeSubject:
		wanted = "NODE"
	case InstallationAppSubject:
		wanted = "APP"
	default:
		return ErrInvalidEnvelope
	}
	for i, component := range b.Components {
		if component != "APP" && component != "HUB" && component != "NODE" || i > 0 && component == b.Components[i-1] {
			return ErrInvalidEnvelope
		}
		present = present || component == wanted
	}
	public, err := InstallationSubjectPublic(b.Subject)
	if err != nil || !present || ValidatePublicIdentity(public) != nil || !installationDistinct(b.AdmissionPublic, public) || !installationDistinct(public, b.Hub.Public) {
		return ErrInvalidEnvelope
	}
	if b.Subject.Mode != InstallationNewSubject && b.Subject.Mode != InstallationAdoptExisting {
		return ErrInvalidEnvelope
	}
	switch b.Trust.Kind {
	case InstallationFirstOOB:
		if b.Trust.Existing != nil {
			return ErrInvalidEnvelope
		}
	case InstallationExistingLocalPin:
		e := b.Trust.Existing
		if e == nil || !tlsGrantToken(e.OwnerID) || !tlsGrantToken(e.OwnerKeyID) || !canonicalSHA256Hex(e.OwnerPublicDigest) || !installationPositive(e.LocalTrustVersion) {
			return ErrInvalidEnvelope
		}
		switch e.Source {
		case InstallationRegisteredParent:
			if !appNodeProofID(e.ParentRegistrationID) || !installationPositive(e.RegistrationEpoch) || !installationPositive(e.AdmissionCredentialVersion) {
				return ErrInvalidEnvelope
			}
		case InstallationLegacyNode:
			if e.ParentRegistrationID != "" || e.RegistrationEpoch != 0 || e.AdmissionCredentialVersion != 0 || b.Subject.Kind != InstallationNodeSubject || b.Subject.Mode != InstallationAdoptExisting {
				return ErrInvalidEnvelope
			}
		default:
			return ErrInvalidEnvelope
		}
	default:
		return ErrInvalidEnvelope
	}
	if n := b.Subject.Node; n != nil {
		if !tlsGrantToken(n.NodeID) || !installationPositive(n.KeyVersion) || !installationPositive(n.KeyEpoch) || ValidatePublicIdentity(n.HubNodeControlPublic) != nil ||
			!installationDistinct(n.Public, n.HubNodeControlPublic) || !installationPositive(n.HubNodeControlKeyVersion) || !canonicalSHA256Hex(n.HubNodeControlFingerprint) {
			return ErrInvalidEnvelope
		}
		if b.Subject.Mode == InstallationNewSubject {
			// This registration attempt is the real new candidate. No legacy
			// request, binding or bearer exists or may be manufactured for it.
			if n.KeyVersion != 1 || n.KeyEpoch != 1 || n.CredentialCommitment != "" || n.RequestID != "" || n.RequestVersion != 0 || n.CandidateDigest != "" || n.CandidateExpiresAt != "" || n.BindingID != "" || n.BindingVersion != 0 || n.CredentialVersion != 0 {
				return ErrInvalidEnvelope
			}
		} else if !canonicalSHA256Hex(n.CredentialCommitment) || !tlsGrantToken(n.RequestID) || !installationPositive(n.RequestVersion) || !canonicalSHA256Hex(n.CandidateDigest) || n.CandidateExpiresAt != "" || !tlsGrantToken(n.BindingID) || !installationPositive(n.BindingVersion) || !installationPositive(n.CredentialVersion) {
			return ErrInvalidEnvelope
		}
	} else {
		a := b.Subject.App
		if !tlsGrantToken(a.DeviceID) || !installationPositive(a.KeyVersion) || !installationPositive(a.DeviceEpoch) ||
			b.Subject.Mode == InstallationNewSubject && (a.KeyVersion != 1 || a.DeviceEpoch != 1) {
			return ErrInvalidEnvelope
		}
	}
	return nil
}

func ValidateInstallationCandidate(c InstallationCandidate) error {
	d, err := InstallationCandidateDigest(c.Base)
	if err != nil || d != c.CandidateDigest {
		return ErrInvalidEnvelope
	}
	if c.Base.Trust.Kind == InstallationFirstOOB {
		if !canonicalSHA256Hex(c.OOBCommitment) {
			return ErrInvalidEnvelope
		}
	} else if c.OOBCommitment != "" {
		return ErrInvalidEnvelope
	}
	return nil
}

// Start uses immutable local signed times. Only the issuance lower bound has
// bounded clock tolerance; fixing a larger skew never mutates the original.
func ValidateInstallationStartAt(b InstallationCandidateBase, now time.Time) error {
	if ValidateInstallationBase(b) != nil {
		return ErrInvalidEnvelope
	}
	i, e, _ := installationWindow(b.IssuedAt, b.ExpiresAt, 10*time.Minute)
	if installationCurrent(i, e, now) != nil || now.After(i.Add(time.Minute)) {
		return ErrInvalidEnvelope
	}
	return nil
}

func ValidateInstallationApproval(t InstallationApprovalBase, c InstallationCandidate) error {
	if ValidateInstallationBase(c.Base) != nil || t.Format != InstallationRegistrationFormat || ValidateInstallationAccountScope(t.Scope) != nil ||
		!canonicalSHA256Hex(t.CandidateDigest) || t.CandidateDigest != c.CandidateDigest || t.OOBCommitment != c.OOBCommitment ||
		t.InstallationID != c.Base.InstallationID || t.AttemptID != c.Base.AttemptID || !canonicalSHA256Hex(t.PossessionReceiptDigest) ||
		t.Scope.HubID != c.Base.Hub.HubID || t.Scope.Origin != c.Base.Hub.Origin || t.Scope.HubFingerprint != c.Base.Hub.Fingerprint || t.Scope.TransportPolicy != c.Base.Hub.TransportPolicy ||
		!installationPositive(t.ExpectedRevision) || !appNodeProofID(t.PrepareRequestID) || !canonicalSHA256Hex(t.PreparePacketDigest) || !canonicalSHA256Hex(t.PreviewProofDigest) || !canonicalSHA256Hex(t.ServerNonce) {
		return ErrInvalidEnvelope
	}
	if c.Base.Trust.Kind == InstallationFirstOOB {
		if !canonicalSHA256Hex(c.OOBCommitment) {
			return ErrInvalidEnvelope
		}
	} else {
		e := c.Base.Trust.Existing
		d, err := OwnerDevicePublicKeyFingerprint(t.Scope.OwnerPublic)
		if c.OOBCommitment != "" || err != nil || e.OwnerID != t.Scope.OwnerID || e.OwnerKeyID != t.Scope.OwnerPublic.ID || e.OwnerPublicDigest != d {
			return ErrInvalidEnvelope
		}
	}
	d, err := InstallationCandidateDigest(c.Base)
	subject, se := InstallationSubjectDigest(c.Base.Subject)
	if err != nil || se != nil || d != c.CandidateDigest || t.SubjectDigest != subject {
		return ErrInvalidEnvelope
	}
	i, end, err := installationWindow(t.PreparedAt, t.ProofExpiresAt, 5*time.Minute)
	baseStart, _ := parseCanonicalUTC(c.Base.IssuedAt)
	baseEnd, _ := parseCanonicalUTC(c.Base.ExpiresAt)
	session, serr := parseCanonicalUTC(t.Scope.AccountSessionExpiresAt)
	if err != nil || serr != nil || i.Before(baseStart.Add(-InstallationIssuanceSkew)) || !i.Before(baseEnd) || t.AttemptExpiresAt != c.Base.ExpiresAt || t.AcceptBefore != t.ProofExpiresAt || end.After(baseEnd) || end.After(session) {
		return ErrInvalidEnvelope
	}
	want := i.Add(5 * time.Minute)
	if baseEnd.Before(want) {
		want = baseEnd
	}
	if session.Before(want) {
		want = session
	}
	if !end.Equal(want) {
		return ErrInvalidEnvelope
	}
	return nil
}

func ValidateInstallationApprovalAt(t InstallationApprovalBase, c InstallationCandidate, now time.Time) error {
	if ValidateInstallationApproval(t, c) != nil {
		return ErrInvalidEnvelope
	}
	i, e, _ := installationWindow(t.PreparedAt, t.AcceptBefore, 5*time.Minute)
	return installationCurrent(i, e, now)
}

func ValidateInstallationReadQuery(q InstallationReadQuery) error {
	if !tlsGrantToken(q.HubID) || !tlsGrantToken(q.AccountID) || !tlsGrantToken(q.OwnerID) || !tlsGrantToken(q.DeviceID) || !installationPositive(q.AccountEpoch) || !installationPositive(q.DeviceEpoch) ||
		!appNodeProofID(q.RequestID) || !canonicalSHA256Hex(q.Nonce) || q.PageSize == 0 || q.PageSize > 50 || len(q.Cursor) > 512 || len(q.TargetIDs) > 50 || !sort.StringsAreSorted(q.TargetIDs) {
		return ErrInvalidEnvelope
	}
	switch q.TargetKind {
	case "INSTALLATIONS", "GRANTED":
		for _, id := range q.TargetIDs {
			if !appNodeProofID(id) {
				return ErrInvalidEnvelope
			}
		}
	case "NODE_STATUS", "PAIR_STATUS":
		if len(q.TargetIDs) == 0 {
			return ErrInvalidEnvelope
		}
	default:
		return ErrInvalidEnvelope
	}
	for i, id := range q.TargetIDs {
		if !tlsGrantToken(id) || i > 0 && id == q.TargetIDs[i-1] {
			return ErrInvalidEnvelope
		}
	}
	for _, ch := range q.Cursor {
		if ch < 33 || ch > 126 {
			return ErrInvalidEnvelope
		}
	}
	return nil
}

func validateInstallationReadClaims(c InstallationOwnerReadClaims, q InstallationReadQuery) error {
	if c.Version != 1 || c.Purpose != InstallationReadPurpose || ValidateInstallationAccountScope(c.Scope) != nil || ValidateInstallationReadQuery(q) != nil ||
		c.RequestID != q.RequestID || c.Nonce != q.Nonce || c.Scope.HubID != q.HubID || c.Scope.AccountID != q.AccountID || c.Scope.OwnerID != q.OwnerID || c.Scope.DeviceID != q.DeviceID || c.Scope.AccountEpoch != q.AccountEpoch || c.Scope.DeviceEpoch != q.DeviceEpoch {
		return ErrInvalidEnvelope
	}
	d, err := InstallationReadQueryDigest(q)
	i, e, we := installationWindow(c.IssuedAt, c.ExpiresAt, time.Minute)
	session, se := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	if err != nil || we != nil || se != nil || c.QueryDigest != d || e.After(session) || !session.After(i) {
		return ErrInvalidEnvelope
	}
	return nil
}

func validateInstallationAccessClaims(c InstallationAccessClaims) error {
	r := c.Recipient
	if c.Version != 1 || c.Purpose != InstallationAccessPurpose || ValidateInstallationAccountScope(c.Scope) != nil || !appNodeProofID(c.GrantID) || !appNodeProofID(r.SubjectRegistrationID) ||
		!installationPositive(r.SubjectRegistrationEpoch) || !tlsGrantToken(r.DeviceID) || ValidatePublicIdentity(r.DevicePublic) != nil || !installationPositive(r.DeviceEpoch) ||
		!installationDistinct(r.DevicePublic, c.Scope.OwnerPublic) || !installationPositive(c.ExpectedRevision) || !appNodeProofID(c.PrepareRequestID) || !canonicalSHA256Hex(c.PreparePacketDigest) || !canonicalSHA256Hex(c.ServerNonce) ||
		!tlsGrantToken(c.Target.NodeBindingID) || !installationPositive(c.Target.NodeBindingVersion) || !installationPositive(c.Target.NodeKeyEpoch) {
		return ErrInvalidEnvelope
	}
	switch c.Profile {
	case InstallationNodeReadProfile:
		if c.Target.PairID != "" {
			return ErrInvalidEnvelope
		}
	case InstallationPairReadProfile:
		if !appNodeProofID(c.Target.PairID) {
			return ErrInvalidEnvelope
		}
	default:
		return ErrInvalidEnvelope
	}
	i, e, err := installationWindow(c.PreparedAt, c.ProofExpiresAt, 5*time.Minute)
	session, se := parseCanonicalUTC(c.Scope.AccountSessionExpiresAt)
	grantEnd, ge := parseCanonicalUTC(c.ExpiresAt)
	if err != nil || se != nil || ge != nil || e.After(session) || !grantEnd.Equal(i.Add(15*time.Minute)) || !grantEnd.After(e) {
		return ErrInvalidEnvelope
	}
	return nil
}

func installationSamePublic(a, b PublicIdentity) bool { return reflect.DeepEqual(a, b) }
