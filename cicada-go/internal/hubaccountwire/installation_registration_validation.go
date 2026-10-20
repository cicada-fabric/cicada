package hubaccountwire

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

func InstallationOperations() []string {
	return []string{OperationInstallationStart, OperationInstallationProve, OperationInstallationPoll, OperationInstallationAccept, OperationInstallationSelf, OperationInstallationHeartbeat, OperationInstallationReconcile,
		OperationOwnerInstallationPrepare, OperationOwnerInstallationComplete, OperationOwnerInstallationRevoke, OperationOwnerAppAccessPrepare, OperationOwnerAppAccessComplete, OperationOwnerAppAccessRevoke, OperationOwnerConnectionsRead}
}

func InstallationHTTPPath(operation string) string {
	switch operation {
	case OperationInstallationStart:
		return "/v2/installations/start"
	case OperationInstallationProve:
		return "/v2/installations/prove"
	case OperationInstallationPoll:
		return "/v2/installations/poll"
	case OperationInstallationAccept:
		return "/v2/installations/accept"
	case OperationInstallationSelf:
		return "/v2/installations/self"
	case OperationInstallationHeartbeat:
		return "/v2/installations/heartbeat"
	case OperationInstallationReconcile:
		return "/v2/installations/reconcile"
	case OperationOwnerInstallationPrepare:
		return "/v2/owner/installations/prepare"
	case OperationOwnerInstallationComplete:
		return "/v2/owner/installations/complete"
	case OperationOwnerInstallationRevoke:
		return "/v2/owner/installations/revoke"
	case OperationOwnerAppAccessPrepare:
		return "/v2/owner/app-access/prepare"
	case OperationOwnerAppAccessComplete:
		return "/v2/owner/app-access/complete"
	case OperationOwnerAppAccessRevoke:
		return "/v2/owner/app-access/revoke"
	case OperationOwnerConnectionsRead:
		return "/v2/owner/connections/read"
	}
	return ""
}

func InstallationIsRead(operation string) bool {
	return operation == OperationInstallationPoll || operation == OperationInstallationSelf || operation == OperationOwnerConnectionsRead
}

func installationSelfOperation(operation string) bool {
	switch operation {
	case OperationInstallationStart, OperationInstallationProve, OperationInstallationPoll, OperationInstallationAccept, OperationInstallationSelf, OperationInstallationHeartbeat, OperationInstallationReconcile:
		return true
	}
	return false
}

// trusted is an independently pinned full Client-Control Hub identity, never
// built from this candidate. Node-Control uses its existing fingerprint domain.
func ValidateInstallationCandidate(c InstallationCandidate, trusted HubIdentity) error {
	fp, err := HubFingerprint(trusted)
	if err != nil || e2ee.ValidateInstallationCandidate(c) != nil || c.Base.Hub.HubID != trusted.HubID || c.Base.Hub.KeyVersion != trusted.KeyVersion ||
		c.Base.Hub.Fingerprint != fp || !reflect.DeepEqual(c.Base.Hub.Public, trusted.Public) {
		return ErrInvalid
	}
	if n := c.Base.Subject.Node; n != nil && n.HubNodeControlFingerprint != nodewire.IdentityFingerprint(n.HubNodeControlPublic) {
		return ErrInvalid
	}
	return nil
}

func ValidateInstallationReadAuthorization(a InstallationReadAuthorization) error {
	switch a.Kind {
	case InstallationOwnerReadAuth:
		if len(a.OwnerReadProof) == 0 || len(a.OwnerReadProof) > e2ee.MaxInstallationProofBytes || a.GrantIDs != nil {
			return ErrInvalid
		}
	case InstallationRecipientGrantsAuth:
		if a.OwnerReadProof != nil || len(a.GrantIDs) > MaxInstallationEffectiveGrants {
			return ErrInvalid
		}
		seen := map[string]bool{}
		for _, id := range a.GrantIDs {
			if !isHex(id, RequestIDBytes) || seen[id] {
				return ErrInvalid
			}
			seen[id] = true
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ValidateInstallationGrantTarget(t InstallationGrantTarget) error {
	r := t.Recipient
	if !isHex(r.SubjectRegistrationID, RequestIDBytes) || !installationPositive(r.SubjectRegistrationEpoch) || !nativePairToken(r.DeviceID) || e2ee.ValidatePublicIdentity(r.DevicePublic) != nil || !installationPositive(r.DeviceEpoch) ||
		!installationPositive(t.ExpectedRevision) || !nativePairToken(t.Target.NodeBindingID) || !installationPositive(t.Target.NodeBindingVersion) || !installationPositive(t.Target.NodeKeyEpoch) {
		return ErrInvalid
	}
	switch t.Profile {
	case e2ee.InstallationNodeReadProfile:
		if t.Target.PairID != "" {
			return ErrInvalid
		}
	case e2ee.InstallationPairReadProfile:
		if !isHex(t.Target.PairID, RequestIDBytes) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func DecodeInstallationCapabilities(raw []byte) (InstallationCapabilities, error) {
	var c InstallationCapabilities
	if installationCanonical(raw, &c, 8*1024) != nil || c.Format != InstallationFormat || c.ContractRevision != InstallationContractRevision || !c.Available || c.ServeMode != "--hub-nodes-only" ||
		c.TransportPolicy != AppNodeTransportHTTPS && c.TransportPolicy != AppNodeTransportLoopbackTest || !reflect.DeepEqual(c.Operations, InstallationOperations()) ||
		!reflect.DeepEqual(c.TrustModes, []string{e2ee.InstallationFirstOOB, e2ee.InstallationExistingLocalPin}) || !reflect.DeepEqual(c.ReadProfiles, []string{e2ee.InstallationNodeReadProfile, e2ee.InstallationPairReadProfile}) {
		return InstallationCapabilities{}, ErrInvalid
	}
	return c, nil
}

func installationPositive(n uint64) bool { return n > 0 && n < math.MaxInt64 }

func ValidateInstallationParent(p InstallationParent) error {
	if !isHex(p.InstallationID, RequestIDBytes) || !isHex(p.RegistrationID, RequestIDBytes) || !installationPositive(p.RegistrationEpoch) || !installationPositive(p.AdmissionCredentialVersion) ||
		!nativePairToken(p.OwnerID) || !installationPositive(p.Revision) || p.State != InstallationRegistered && p.State != InstallationRevoked {
		return ErrInvalid
	}
	return nil
}

// This validates a projection; it never mutates the parent or grants. An added
// subject attempt cannot publish PENDING as the registered installation state.
func ValidateInstallationAppendProjection(previous InstallationParent, result InstallationResult) error {
	if ValidateInstallationParent(previous) != nil || result.Parent == nil || ValidateInstallationParent(*result.Parent) != nil ||
		result.Parent.InstallationID != previous.InstallationID || result.Parent.RegistrationID != previous.RegistrationID || result.Parent.OwnerID != previous.OwnerID ||
		result.Parent.RegistrationEpoch != previous.RegistrationEpoch || result.Parent.AdmissionCredentialVersion != previous.AdmissionCredentialVersion || result.Parent.Revision < previous.Revision {
		return ErrInvalid
	}
	if result.AttemptState == InstallationPending || result.AttemptState == InstallationOwnerApproved {
		if previous.State != InstallationRegistered || result.Parent.State != InstallationRegistered {
			return ErrInvalid
		}
	}
	if previous.State == InstallationRevoked && result.Parent.State != InstallationRevoked {
		return ErrInvalid
	}
	return nil
}

// Select from verified Store projections only. This is not grant verification
// or authorization: H2 still checks stored signatures, current epochs and scope.
// Empty requested IDs means this recipient's live grants, never Owner-wide.
func SelectInstallationRecipientGrants(refs []InstallationGrantRef, subjectID, deviceID string, requested []string, now time.Time) ([]InstallationGrantRef, error) {
	if !isHex(subjectID, RequestIDBytes) || !nativePairToken(deviceID) || now.IsZero() || len(refs) > 1024 || len(requested) > MaxInstallationEffectiveGrants {
		return nil, ErrInvalid
	}
	available := map[string]InstallationGrantRef{}
	ordered := make([]InstallationGrantRef, 0)
	for _, g := range refs {
		if g.SubjectRegistrationID != subjectID || g.RecipientDeviceID != deviceID || g.State != "ACTIVE" {
			continue
		}
		end, err := parseCanonicalUTC(g.ExpiresAt)
		if err != nil || !isHex(g.GrantID, RequestIDBytes) || !installationPositive(g.Revision) {
			return nil, ErrInvalid
		}
		if !now.Before(end) {
			continue
		}
		if _, exists := available[g.GrantID]; exists {
			return nil, ErrInvalid
		}
		if g.OriginContract != InstallationContractRevision || g.Profile != e2ee.InstallationNodeReadProfile && g.Profile != e2ee.InstallationPairReadProfile {
			return nil, ErrInvalid
		}
		available[g.GrantID] = g
		ordered = append(ordered, g)
	}
	if len(available) > MaxInstallationEffectiveGrants {
		return nil, ErrInvalid
	}
	if len(requested) == 0 {
		return ordered, nil
	}
	out := make([]InstallationGrantRef, 0, len(requested))
	seen := map[string]bool{}
	for _, id := range requested {
		g, exists := available[id]
		if !exists || seen[id] {
			return nil, ErrInvalid
		}
		seen[id] = true
		out = append(out, g)
	}
	return out, nil
}

func InstallationHeartbeatObservation(last string, now time.Time) string {
	at, err := parseCanonicalUTC(last)
	if err != nil || now.IsZero() || now.Before(at) {
		return "UNKNOWN"
	}
	if !now.Before(at.Add(2 * time.Minute)) {
		return "STALE"
	}
	return "CONNECTED"
}

func installationCanonical(raw []byte, out any, maximum int) error {
	if len(raw) == 0 || len(raw) > maximum {
		return ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return ErrInvalid
	}
	canonical, err := json.Marshal(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrInvalid
	}
	return nil
}
