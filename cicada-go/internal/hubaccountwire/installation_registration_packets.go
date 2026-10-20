package hubaccountwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const (
	installationPacketAAD       = "cicada/installation-registration/request-aad/v1\x00"
	installationStartSubjectAAD = "cicada/installation-registration/start-subject/v1\x00"
)

func installationLimit(operation string) (int, int) {
	if operation == OperationInstallationReconcile {
		return MaxInstallationReconcileBodyBytes, MaxInstallationReconcilePacketBytes
	}
	return MaxInstallationBodyBytes, MaxInstallationPacketBytes
}

func installationHeader(p InstallationPacket) InstallationPacket {
	p.Packet = nil
	return p
}

func installationRequestID(p InstallationPacket) string {
	if p.Self != nil {
		return p.Self.RequestID
	}
	if p.Account != nil {
		return p.Account.RequestID
	}
	return ""
}

func validateInstallationHeader(p InstallationPacket, trusted HubIdentity) error {
	if p.Format != InstallationPacketFormat || p.Version != 1 || e2ee.ValidatePublicIdentity(p.SenderPublic) != nil || InstallationHTTPPath(p.Operation) == "" {
		return ErrInvalid
	}
	if installationSelfOperation(p.Operation) && (p.Operation != OperationInstallationReconcile || p.Self != nil) {
		c := p.Self
		if c == nil || p.Account != nil || c.HubID != trusted.HubID || !isHex(c.InstallationID, RequestIDBytes) || c.AttemptID != "" && !isHex(c.AttemptID, RequestIDBytes) || !isHex(c.RequestID, RequestIDBytes) || len(c.Nonce) != NonceBytes || validateCanonicalTime(c.IssuedAt) != nil {
			return ErrInvalid
		}
		if c.AttemptID == "" && p.Operation != OperationInstallationSelf && p.Operation != OperationInstallationHeartbeat && p.Operation != OperationInstallationReconcile {
			return ErrInvalid
		}
		if c.ParentRegistrationID == "" {
			if c.AttemptID == "" || c.RegistrationEpoch != 0 || c.AdmissionCredentialVersion != 0 || p.Operation == OperationInstallationSelf || p.Operation == OperationInstallationHeartbeat {
				return ErrInvalid
			}
		} else if !isHex(c.ParentRegistrationID, RequestIDBytes) || !installationPositive(c.RegistrationEpoch) || !installationPositive(c.AdmissionCredentialVersion) {
			return ErrInvalid
		}
	} else {
		c := p.Account
		if c == nil || p.Self != nil || c.HubID != trusted.HubID || c.Origin == "" || !nativePairToken(c.AccountID) || !nativePairToken(c.OwnerID) || !nativePairToken(c.DeviceID) ||
			!installationPositive(c.AccountEpoch) || !installationPositive(c.DeviceEpoch) || !isHex(c.RequestID, RequestIDBytes) || len(c.ClientNonce) != NonceBytes || validateCanonicalTime(c.IssuedAt) != nil {
			return ErrInvalid
		}
		policy := AppNodeTransportHTTPS
		if strings.HasPrefix(c.Origin, "http://") {
			policy = AppNodeTransportLoopbackTest
		}
		if e2ee.ValidateInstallationOrigin(c.Origin, policy) != nil {
			return ErrInvalid
		}
	}
	return nil
}

func installationAADForHeader(p InstallationPacket, trusted HubIdentity) ([]byte, error) {
	fp, err := HubFingerprint(trusted)
	if err != nil || validateInstallationHeader(p, trusted) != nil {
		return nil, ErrInvalid
	}
	frame := struct {
		Header             InstallationPacket `json:"header"`
		HubFingerprint     string             `json:"hub_fingerprint"`
		ReceiverKeyID      string             `json:"receiver_key_id"`
		ReceiverKeyVersion uint64             `json:"receiver_key_version"`
	}{installationHeader(p), fp, trusted.Public.ID, trusted.KeyVersion}
	b, err := json.Marshal(frame)
	if err != nil {
		return nil, ErrInvalid
	}
	return append([]byte(installationPacketAAD), b...), nil
}

func installationBodyFormat(body any) string {
	v := reflect.ValueOf(installationBodyValue(body))
	if v.Kind() != reflect.Struct {
		return ""
	}
	f := v.FieldByName("Format")
	if !f.IsValid() || f.Kind() != reflect.String {
		return ""
	}
	return f.String()
}

func installationBodyValue(body any) any {
	v := reflect.ValueOf(body)
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return v.Elem().Interface()
	}
	return body
}

func ValidateInstallationRequest(p InstallationPacket, body any, trusted HubIdentity) error {
	if validateInstallationHeader(p, trusted) != nil || installationBodyFormat(body) != InstallationFormat {
		return ErrInvalid
	}
	proof := func(b []byte) bool { return len(b) > 0 && len(b) <= e2ee.MaxInstallationProofBytes }
	token := func(b []byte) bool { return len(b) == MaxSessionTokenBytes }
	valid := false
	switch v := installationBodyValue(body).(type) {
	case InstallationStart:
		valid = p.Operation == OperationInstallationStart && ValidateInstallationCandidate(v.Candidate, trusted) == nil && proof(v.SubjectSignatureProof)
		if valid {
			b := v.Candidate.Base
			valid = p.Self.InstallationID == b.InstallationID && p.Self.AttemptID == b.AttemptID && p.Self.IssuedAt == b.IssuedAt && reflect.DeepEqual(p.SenderPublic, b.AdmissionPublic)
			if b.Subject.Node != nil && b.Subject.Mode == e2ee.InstallationAdoptExisting {
				valid = valid && validInstallationNodeCredential(v.NodeCredential) && NativePairCredentialCommitment(string(v.NodeCredential)) == b.Subject.Node.CredentialCommitment
			} else {
				valid = valid && v.NodeCredential == nil
			}
			if b.Trust.Kind == e2ee.InstallationFirstOOB {
				valid = valid && p.Self.ParentRegistrationID == ""
			} else {
				e := b.Trust.Existing
				valid = valid && p.Self.ParentRegistrationID == e.ParentRegistrationID && p.Self.RegistrationEpoch == e.RegistrationEpoch && p.Self.AdmissionCredentialVersion == e.AdmissionCredentialVersion
			}
		}
	case InstallationProve:
		valid = p.Operation == OperationInstallationProve && isHex(v.ChallengeID, RequestIDBytes) && isHex(v.StartPacketDigest, 32) && proof(v.AdmissionReceipt) && proof(v.SubjectReceipt)
	case InstallationPoll:
		valid = p.Operation == OperationInstallationPoll && isHex(v.CandidateDigest, 32)
	case InstallationAccept:
		valid = p.Operation == OperationInstallationAccept && isHex(v.ApprovalReceiptDigest, 32) && isHex(v.ApprovalDigest, 32) && isHex(v.CapsuleDigest, 32) && isHex(v.OwnerProofDigest, 32) && len(v.ACKNonce) == 32 && proof(v.SubjectAcceptance)
	case InstallationSelfRequest:
		valid = p.Operation == OperationInstallationSelf
	case InstallationHeartbeat:
		valid = p.Operation == OperationInstallationHeartbeat
	case InstallationOwnerPrepare:
		valid = p.Operation == OperationOwnerInstallationPrepare && token(v.SessionToken) && isHex(v.AttemptID, RequestIDBytes) && isHex(v.CandidateDigest, 32) && proof(v.OwnerIntent)
	case InstallationOwnerComplete:
		valid = p.Operation == OperationOwnerInstallationComplete && token(v.SessionToken) && proof(v.OwnerProof) && len(v.TrustCapsule) > 0 && len(v.TrustCapsule) <= MaxInstallationPacketBytes
	case InstallationOwnerRevoke:
		valid = p.Operation == OperationOwnerInstallationRevoke && token(v.SessionToken) && isHex(v.ParentRegistrationID, RequestIDBytes) && (v.SubjectRegistrationID == "" || isHex(v.SubjectRegistrationID, RequestIDBytes)) && installationPositive(v.ExpectedRevision) && proof(v.OwnerProof)
	case InstallationAccessPrepare:
		valid = p.Operation == OperationOwnerAppAccessPrepare && token(v.SessionToken) && isHex(v.GrantID, RequestIDBytes) && ValidateInstallationGrantTarget(v.Target) == nil && proof(v.OwnerIntent)
	case InstallationAccessComplete:
		valid = p.Operation == OperationOwnerAppAccessComplete && token(v.SessionToken) && proof(v.OwnerProof)
	case InstallationAccessRevoke:
		valid = p.Operation == OperationOwnerAppAccessRevoke && token(v.SessionToken) && isHex(v.GrantID, RequestIDBytes) && installationPositive(v.ExpectedRevision) && proof(v.OwnerProof)
	case InstallationConnectionsRead:
		valid = p.Operation == OperationOwnerConnectionsRead && token(v.SessionToken) && e2ee.ValidateInstallationReadQuery(v.Query) == nil && ValidateInstallationReadAuthorization(v.Authorization) == nil
		if valid {
			q, a := v.Query, p.Account
			valid = q.HubID == a.HubID && q.AccountID == a.AccountID && q.OwnerID == a.OwnerID && q.DeviceID == a.DeviceID && q.AccountEpoch == a.AccountEpoch && q.DeviceEpoch == a.DeviceEpoch && q.RequestID == a.RequestID && q.Nonce == hex.EncodeToString(a.ClientNonce)
			if v.Authorization.Kind == InstallationRecipientGrantsAuth && q.TargetKind == "GRANTED" && len(q.TargetIDs) != 0 {
				valid = false
			}
		}
	case InstallationReconcile:
		valid = p.Operation == OperationInstallationReconcile && v.OriginalOperation != OperationInstallationReconcile && InstallationHTTPPath(v.OriginalOperation) != "" && isHex(v.OriginalRequestID, RequestIDBytes) && v.OriginalRequestID != installationRequestID(p) && len(v.OriginalPacket) > 0 && len(v.OriginalPacket) <= MaxInstallationOriginalBytes && v.OriginalPacketDigest == e2ee.InstallationPacketDigest(v.OriginalPacket)
		if valid {
			var original InstallationPacket
			valid = installationCanonical(v.OriginalPacket, &original, MaxInstallationOriginalBytes) == nil && validateInstallationHeader(original, trusted) == nil && original.Operation == v.OriginalOperation && installationRequestID(original) == v.OriginalRequestID && reflect.DeepEqual(original.SenderPublic, p.SenderPublic)
			if valid && p.Self != nil && original.Self != nil {
				valid = p.Self.InstallationID == original.Self.InstallationID && p.Self.AttemptID == original.Self.AttemptID && p.Self.ParentRegistrationID == original.Self.ParentRegistrationID && p.Self.RegistrationEpoch == original.Self.RegistrationEpoch && p.Self.AdmissionCredentialVersion == original.Self.AdmissionCredentialVersion
			} else if valid && p.Account != nil && original.Account != nil {
				a, b := p.Account, original.Account
				valid = a.HubID == b.HubID && a.Origin == b.Origin && a.AccountID == b.AccountID && a.OwnerID == b.OwnerID && a.DeviceID == b.DeviceID && a.AccountEpoch == b.AccountEpoch && a.DeviceEpoch == b.DeviceEpoch
			} else {
				valid = false
			}
		}
	}
	if !valid {
		return ErrInvalid
	}
	b, err := json.Marshal(body)
	maximum, _ := installationLimit(p.Operation)
	if err != nil || len(b) > maximum {
		return ErrInvalid
	}
	return nil
}

func SealInstallationRequest(sender *e2ee.Identity, trusted HubIdentity, header InstallationPacket, body any) ([]byte, error) {
	if sender == nil || !reflect.DeepEqual(sender.Public(), header.SenderPublic) || header.Packet != nil || ValidateInstallationRequest(header, body, trusted) != nil {
		return nil, ErrInvalid
	}
	aad, err := installationAADForHeader(header, trusted)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(body)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(plain)
	header.Packet, err = e2ee.Seal(sender, trusted.Public, plain, aad, 1)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(header)
	_, limit := installationLimit(header.Operation)
	if err != nil || len(out) > limit {
		return nil, ErrInvalid
	}
	return out, nil
}

func OpenInstallationRequest(receiver *e2ee.Identity, trusted HubIdentity, raw []byte, out any, now time.Time) (InstallationPacket, error) {
	return openInstallationRequest(receiver, trusted, raw, out, now, false)
}

// AuthenticateInstallationOriginal verifies only the old original's canonical
// encoding, exact route/header, key/AEAD and typed body. It deliberately has no
// caller-supplied historical clock. It cannot admit a fresh mutation or pin.
// A current authenticated reconciliation actor must independently match it;
// Store then returns a retained receipt or permanently fences an unadmitted ID.
func AuthenticateInstallationOriginal(receiver *e2ee.Identity, trusted HubIdentity, raw []byte, out any) (InstallationHistoricalOriginal, error) {
	if len(raw) > MaxInstallationOriginalBytes {
		return InstallationHistoricalOriginal{}, ErrInvalid
	}
	p, err := openInstallationRequest(receiver, trusted, raw, out, time.Time{}, true)
	if err != nil || p.Operation == OperationInstallationReconcile {
		return InstallationHistoricalOriginal{}, ErrInvalid
	}
	return InstallationHistoricalOriginal{Header: p, PacketDigest: e2ee.InstallationPacketDigest(raw)}, nil
}

func openInstallationRequest(receiver *e2ee.Identity, trusted HubIdentity, raw []byte, out any, now time.Time, historical bool) (InstallationPacket, error) {
	var p InstallationPacket
	if receiver == nil || !reflect.DeepEqual(receiver.Public(), trusted.Public) || installationCanonical(raw, &p, MaxInstallationReconcilePacketBytes) != nil || validateInstallationHeader(p, trusted) != nil {
		return InstallationPacket{}, ErrInvalid
	}
	_, limit := installationLimit(p.Operation)
	if len(raw) > limit || len(p.Packet) == 0 || !historical && now.IsZero() {
		return InstallationPacket{}, ErrInvalid
	}
	stamp := ""
	if p.Self != nil {
		stamp = p.Self.IssuedAt
	} else {
		stamp = p.Account.IssuedAt
	}
	if !historical {
		at, err := parseCanonicalUTC(stamp)
		if err != nil || now.Before(at.Add(-e2ee.InstallationIssuanceSkew)) || now.After(at.Add(time.Minute)) {
			return InstallationPacket{}, ErrInvalid
		}
	}
	aad, err := installationAADForHeader(p, trusted)
	if err != nil {
		return InstallationPacket{}, err
	}
	plain, seq, err := e2ee.Open(receiver, p.SenderPublic, p.Packet, aad)
	if err != nil || seq != 1 {
		clear(plain)
		return InstallationPacket{}, ErrInvalid
	}
	defer clear(plain)
	maximum, _ := installationLimit(p.Operation)
	if installationCanonical(plain, out, maximum) != nil || ValidateInstallationRequest(p, out, trusted) != nil {
		return InstallationPacket{}, ErrInvalid
	}
	if start, ok := installationBodyValue(out).(InstallationStart); !historical && ok && e2ee.ValidateInstallationStartAt(start.Candidate.Base, now) != nil {
		return InstallationPacket{}, ErrInvalid
	}
	return p, nil
}

type installationStartSubjectBinding struct {
	Format          string                  `json:"format"`
	Context         InstallationSelfContext `json:"context"`
	CandidateDigest string                  `json:"candidate_digest"`
	OOBCommitment   string                  `json:"oob_commitment"`
}

func SealInstallationStartSubject(subject *e2ee.Identity, trusted HubIdentity, context InstallationSelfContext, c InstallationCandidate) ([]byte, error) {
	public, err := e2ee.InstallationSubjectPublic(c.Base.Subject)
	if subject == nil || err != nil || !reflect.DeepEqual(subject.Public(), public) || ValidateInstallationCandidate(c, trusted) != nil || context.InstallationID != c.Base.InstallationID || context.AttemptID != c.Base.AttemptID {
		return nil, ErrInvalid
	}
	b, err := json.Marshal(installationStartSubjectBinding{InstallationFormat, context, c.CandidateDigest, c.OOBCommitment})
	if err != nil {
		return nil, ErrInvalid
	}
	return e2ee.Seal(subject, trusted.Public, b, []byte(installationStartSubjectAAD), 1)
}

func OpenInstallationStartSubject(hub *e2ee.Identity, trusted HubIdentity, context InstallationSelfContext, c InstallationCandidate, packet []byte) error {
	public, err := e2ee.InstallationSubjectPublic(c.Base.Subject)
	if hub == nil || err != nil || !reflect.DeepEqual(hub.Public(), trusted.Public) || ValidateInstallationCandidate(c, trusted) != nil {
		return ErrInvalid
	}
	plain, seq, err := e2ee.Open(hub, public, packet, []byte(installationStartSubjectAAD))
	if err != nil || seq != 1 {
		clear(plain)
		return ErrInvalid
	}
	defer clear(plain)
	want, _ := json.Marshal(installationStartSubjectBinding{InstallationFormat, context, c.CandidateDigest, c.OOBCommitment})
	if !bytes.Equal(plain, want) {
		return ErrInvalid
	}
	return nil
}

func installationTargetDigest(domain string, v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxInstallationBodyBytes {
		return "", ErrInvalid
	}
	h := sha256.New()
	_, _ = h.Write([]byte(domain))
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func InstallationGrantTargetDigest(t InstallationGrantTarget) (string, error) {
	return installationTargetDigest("cicada/installation-registration/grant-target/v1\x00", t)
}

func InstallationRevokeTargetDigest(parent, subject string, revision uint64) (string, error) {
	return installationTargetDigest("cicada/installation-registration/revoke-target/v1\x00", struct {
		ParentRegistrationID  string `json:"parent_registration_id"`
		SubjectRegistrationID string `json:"subject_registration_id"`
		ExpectedRevision      uint64 `json:"expected_revision"`
	}{parent, subject, revision})
}
