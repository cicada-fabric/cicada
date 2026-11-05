package hubaccountwire

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func ThreadCollaborationProfiles() []string {
	return []string{ThreadCollaborationProfileScopeRole, ThreadCollaborationProfileGroupLocks}
}

func ThreadCollaborationOwnerOperations() []string {
	return []string{OperationThreadCollaborationOwnerRead, OperationThreadCollaborationOwnerPrepare, OperationThreadCollaborationOwnerApply, OperationThreadCollaborationOwnerStatus, OperationThreadCollaborationOwnerReconcile}
}
func ThreadCollaborationNativeOperations() []string {
	return []string{OperationThreadScopeRead, OperationGroupLocksRead, OperationGroupLocksAcquire, OperationGroupLocksRenew, OperationGroupLocksRelease}
}
func ThreadCollaborationHTTPPath(operation string) string {
	switch operation {
	case OperationThreadCollaborationOwnerRead:
		return "/v2/owner/thread-collaboration/read"
	case OperationThreadCollaborationOwnerPrepare:
		return "/v2/owner/thread-collaboration/prepare"
	case OperationThreadCollaborationOwnerApply:
		return "/v2/owner/thread-collaboration/apply"
	case OperationThreadCollaborationOwnerStatus:
		return "/v2/owner/thread-collaboration/status"
	case OperationThreadCollaborationOwnerReconcile:
		return "/v2/owner/thread-collaboration/reconcile"
	}
	return ""
}

func threadCollaborationRevision(v uint64) bool { return v > 0 && v < 1<<63 }
func threadCollaborationSource(v ThreadRegistrationSource) bool {
	return validID(v.RegistrationID) && threadCollaborationRevision(v.SourceEpoch)
}
func threadCollaborationScope(v GroupLockScope) bool {
	return validID(v.HubID) && validID(v.NetworkID) && validID(v.GroupID)
}
func threadCollaborationHolder(v GroupLockHolder) bool {
	return validID(v.NodeID) && validID(v.EndpointID) && validID(v.PrincipalID) && threadCollaborationSource(v.Source)
}
func threadCollaborationOriginal(v ThreadCollaborationOriginal) bool {
	a, e := GroupLockOriginalTime(v.OperationID)
	b, be := GroupLockOriginalTime(v.IdempotencyKey)
	return e == nil && be == nil && a.Equal(b) && isHex(v.RequestDigest, 32)
}

// A 48-bit millisecond prefix makes bounded recovery explicit without keeping
// an unbounded ID tombstone set. The remaining 80 bits are independently random.
func NewGroupLockOriginal(at time.Time) (ThreadCollaborationOriginal, error) {
	if at.IsZero() || at.UnixMilli() <= 0 || at.UnixMilli() >= 1<<48 {
		return ThreadCollaborationOriginal{}, ErrInvalid
	}
	a, err := NewRequestID()
	if err != nil {
		return ThreadCollaborationOriginal{}, err
	}
	b, err := NewRequestID()
	if err != nil {
		return ThreadCollaborationOriginal{}, err
	}
	prefix := fmt.Sprintf("%012x", at.UnixMilli())
	return ThreadCollaborationOriginal{OperationID: prefix + a[12:], IdempotencyKey: prefix + b[12:], RequestDigest: strings.Repeat("0", 64)}, nil
}
func GroupLockOriginalTime(id string) (time.Time, error) {
	if !isHex(id, 16) {
		return time.Time{}, ErrInvalid
	}
	ms, err := strconv.ParseInt(id[:12], 16, 64)
	if err != nil || ms <= 0 {
		return time.Time{}, ErrInvalid
	}
	return time.UnixMilli(ms).UTC(), nil
}
func ValidateGroupLockOriginalWindow(v ThreadCollaborationOriginal, at time.Time) error {
	if !threadCollaborationOriginal(v) || at.IsZero() {
		return ErrInvalid
	}
	created, _ := GroupLockOriginalTime(v.OperationID)
	if created.After(at.Add(30*time.Second)) || !at.Before(created.Add(GroupLockOriginalRecoverySeconds*time.Second)) {
		return fmt.Errorf("%s", ThreadCollaborationErrorReceiptUnavailable)
	}
	return nil
}
func ThreadCollaborationClassifications() []string {
	return []string{ThreadClassificationWorker, ThreadClassificationAdvisor, ThreadClassificationManager}
}
func threadCollaborationClassification(value string) bool {
	for _, v := range ThreadCollaborationClassifications() {
		if value == v {
			return true
		}
	}
	return false
}
func GroupCoordinationRights() []string {
	return []string{OperationGroupLocksRead, OperationGroupLocksAcquire, OperationGroupLocksRenew, OperationGroupLocksRelease}
}

func ValidateThreadCollaborationCapabilities(v ThreadCollaborationCapabilities) error {
	if v.Format != ThreadCollaborationCapabilitiesFormat || v.ContractRevision != ThreadCollaborationContractRevision || !validID(v.HubID) || !isHex(v.HubFingerprint, 32) || v.SlotCount != GroupLockSlotCount || (v.ServeMode != "--hub-nodes-only" && v.ServeMode != "full") || v.DisconnectPolicy != GroupLockDisconnectPolicyFiniteLease || v.DefaultTTLSeconds != GroupLockDefaultTTLSeconds || v.MinTTLSeconds != GroupLockMinTTLSeconds || v.MaxTTLSeconds != GroupLockMaxTTLSeconds {
		return ErrInvalid
	}
	return nil
}

// Availability stays false until the complete configured service enables it.
func NewThreadCollaborationCapabilities(hub HubIdentity, serveMode string) (ThreadCollaborationCapabilities, error) {
	fp, err := HubFingerprint(hub)
	if err != nil {
		return ThreadCollaborationCapabilities{}, ErrInvalid
	}
	v := ThreadCollaborationCapabilities{Format: ThreadCollaborationCapabilitiesFormat, ContractRevision: ThreadCollaborationContractRevision, HubID: hub.HubID, HubFingerprint: fp, ServeMode: serveMode, DisconnectPolicy: GroupLockDisconnectPolicyFiniteLease, SlotCount: GroupLockSlotCount, DefaultTTLSeconds: GroupLockDefaultTTLSeconds, MinTTLSeconds: GroupLockMinTTLSeconds, MaxTTLSeconds: GroupLockMaxTTLSeconds}
	return v, ValidateThreadCollaborationCapabilities(v)
}
func DecodeThreadCollaborationCapabilities(raw []byte, hub HubIdentity) (ThreadCollaborationCapabilities, error) {
	var v ThreadCollaborationCapabilities
	if len(raw) > 4096 {
		return v, ErrInvalid
	}
	raw = bytes.TrimSpace(raw)
	fp, err := HubFingerprint(hub)
	if err != nil || decodeCanonical(raw, 4096, &v) != nil || ValidateThreadCollaborationCapabilities(v) != nil || v.HubID != hub.HubID || v.HubFingerprint != fp {
		return v, ErrInvalid
	}
	return v, nil
}

func ValidateGroupLockReceipt(v GroupLockReceipt) error {
	if v.Format != GroupLockReceiptFormat || !threadCollaborationScope(v.Scope) || !validID(v.OperationID) || !isHex(v.RequestDigest, 32) || v.Slot < 1 || v.Slot > GroupLockSlotCount || !threadCollaborationRevision(v.AppliedVersion) || !threadCollaborationRevision(v.Generation) {
		return ErrInvalid
	}
	observed, err := parseCanonicalUTC(v.ObservedAt)
	if err != nil {
		return ErrInvalid
	}
	switch v.Outcome {
	case "ACQUIRED", "RENEWED":
		expires, err := parseCanonicalUTC(v.ExpiresAt)
		if err != nil || !expires.After(observed) || expires.Sub(observed) > GroupLockMaxTTLSeconds*time.Second {
			return ErrInvalid
		}
	case "RELEASED", "OWNER_CLEARED":
		if v.ExpiresAt != "" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ValidateThreadScopeView(v ThreadScopeView) error {
	if v.Format != ThreadScopeFormat || !validID(v.NodeID) || v.HistoryCoverage != "CICADA_KNOWN_ONLY" || v.ActiveGroupIDs == nil || len(v.ActiveGroupIDs) > MaxThreadCollaborationPageRows || v.ActiveGroupCount >= 1<<63 || uint64(len(v.ActiveGroupIDs)) > v.ActiveGroupCount || len(v.GroupsCursor) > 1024 || uint64(len(v.ActiveGroupIDs)) < v.ActiveGroupCount && v.GroupsCursor == "" {
		return ErrInvalid
	}
	noRegistration := v.RegistrationDigest == "" && v.EndpointID == "" && v.Source == (ThreadRegistrationSource{}) && v.Classification == "" && v.ClassificationRevision == 0 && v.RelationsRevision == 0 && len(v.ActiveGroupIDs) == 0 && v.ActiveGroupCount == 0 && v.GroupsCursor == ""
	switch v.State {
	case "UNASSIGNED":
		if !validID(v.HubID) || v.NetworkID != "" || v.ScopeRevision != 0 || v.ReservationID != "" || v.Conflict != nil || !noRegistration {
			return ErrInvalid
		}
		return nil
	case "RESERVED", "UNRESOLVED":
		if !validID(v.HubID) || !validID(v.NetworkID) || !threadCollaborationRevision(v.ScopeRevision) || !validID(v.ReservationID) || v.Conflict != nil || !noRegistration {
			return ErrInvalid
		}
		return nil
	case "NETWORK_CONFLICT":
		if v.HubID != "" || v.NetworkID != "" || !threadCollaborationRevision(v.ScopeRevision) || v.ReservationID != "" || !noRegistration || v.Conflict == nil || v.Conflict.KnownNetworkCount >= 1<<63 {
			return ErrInvalid
		}
		switch v.Conflict.Kind {
		case "MULTIPLE_NETWORKS":
			if v.Conflict.KnownNetworkCount < 2 {
				return ErrInvalid
			}
		case "UNRESOLVED_HISTORY":
		default:
			return ErrInvalid
		}
		return nil
	case "CURRENT", "CLASSIFICATION_REQUIRED", "GROUP_CONFLICT":
	default:
		return ErrInvalid
	}
	if !validID(v.HubID) || !validID(v.NetworkID) || !validID(v.EndpointID) || !isHex(v.RegistrationDigest, 32) || !threadCollaborationSource(v.Source) || !threadCollaborationRevision(v.ScopeRevision) || v.ReservationID != "" || v.Conflict != nil || v.RelationsRevision >= 1<<63 {
		return ErrInvalid
	}
	if v.Classification == "" {
		if v.ClassificationRevision != 0 || v.State != "CLASSIFICATION_REQUIRED" {
			return ErrInvalid
		}
	} else if !threadCollaborationClassification(v.Classification) || !threadCollaborationRevision(v.ClassificationRevision) || v.State == "CLASSIFICATION_REQUIRED" {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, g := range v.ActiveGroupIDs {
		if !validID(g) || seen[g] {
			return ErrInvalid
		}
		seen[g] = true
	}
	if v.State == "CURRENT" && v.Classification == ThreadClassificationWorker && v.ActiveGroupCount > 1 {
		return ErrInvalid
	}
	if v.State == "GROUP_CONFLICT" && (v.Classification != ThreadClassificationWorker || v.ActiveGroupCount < 2) {
		return ErrInvalid
	}
	return nil
}

func ValidateGroupCoordinationPolicy(v GroupCoordinationPolicy) error {
	if v.Format != GroupCoordinationPolicyFormat || !threadCollaborationScope(GroupLockScope{v.HubID, v.NetworkID, v.GroupID}) || !validID(v.PolicyID) || !threadCollaborationRevision(v.Revision) || v.SlotCount != GroupLockSlotCount || !reflect.DeepEqual(v.Rights, GroupCoordinationRights()) || !isHex(v.OwnerConsentDigest, 32) {
		return ErrInvalid
	}
	switch v.State {
	case "ENABLED", "DISABLED", "REVOKED":
		return nil
	}
	return ErrInvalid
}

func ValidateGroupSlotView(v GroupSlotView) error {
	if v.Format != GroupSlotViewFormat || !threadCollaborationScope(v.Scope) || !threadCollaborationRevision(v.PolicyRevision) || len(v.Slots) != GroupLockSlotCount {
		return ErrInvalid
	}
	observed, err := parseCanonicalUTC(v.ObservedAt)
	if err != nil {
		return ErrInvalid
	}
	switch v.PolicyState {
	case "ENABLED", "DISABLED", "REVOKED":
	default:
		return ErrInvalid
	}
	for i, s := range v.Slots {
		if int(s.Slot) != i+1 || !threadCollaborationRevision(s.Version) || s.Generation >= 1<<63 || len(s.Note) > MaxGroupLockNoteBytes || !utf8.ValidString(s.Note) || strings.ContainsRune(s.Note, 0) {
			return ErrInvalid
		}
		switch s.State {
		case "FREE":
			if s.Holder != nil || s.Note != "" || s.ExpiresAt != "" || s.HolderName != "" || s.HolderNameState != "" {
				return ErrInvalid
			}
		case "HELD":
			if s.Generation == 0 || s.Holder == nil || !threadCollaborationHolder(*s.Holder) {
				return ErrInvalid
			}
			expires, err := parseCanonicalUTC(s.ExpiresAt)
			if err != nil || !expires.After(observed) || !ownerEndpointGroupsText(s.HolderName, 128) && s.HolderNameState == "VISIBLE" || s.HolderNameState != "VISIBLE" && (s.HolderNameState != "NOT_DISCLOSED" || s.HolderName != "") {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	raw, err := json.Marshal(v)
	if err != nil || len(raw) > MaxThreadCollaborationViewBytes {
		return ErrInvalid
	}
	return nil
}

func ValidateGroupLockAcquireRequest(v GroupLockAcquireRequest) error {
	if !threadCollaborationScope(v.Scope) || v.Slot < 1 || v.Slot > GroupLockSlotCount || !threadCollaborationRevision(v.ExpectedVersion) || !threadCollaborationOriginal(v.Original) || len(v.Note) > MaxGroupLockNoteBytes || !utf8.ValidString(v.Note) || strings.ContainsRune(v.Note, 0) || !groupLockTTLValid(v.TTLSeconds) {
		return ErrInvalid
	}
	return nil
}
func groupLockTTLValid(v *uint32) bool {
	return v == nil || *v >= GroupLockMinTTLSeconds && *v <= GroupLockMaxTTLSeconds
}

// Expiry is anchored to this operation's original server time, not its retry or
// the previous lease end. Only an explicit AI Renew calls this for a live hold.
func GroupLockLeaseExpiry(ttl *uint32, observed time.Time) (string, error) {
	if !groupLockTTLValid(ttl) || observed.IsZero() {
		return "", ErrInvalid
	}
	seconds := uint32(GroupLockDefaultTTLSeconds)
	if ttl != nil {
		seconds = *ttl
	}
	return formatUTC(observed.Add(time.Duration(seconds) * time.Second)), nil
}
func ValidateGroupLockRenewRequest(v GroupLockRenewRequest) error {
	if ValidateGroupLockReleaseRequest(GroupLockReleaseRequest{Scope: v.Scope, Slot: v.Slot, ExpectedVersion: v.ExpectedVersion, Generation: v.Generation, Original: v.Original}) != nil || !groupLockTTLValid(v.TTLSeconds) {
		return ErrInvalid
	}
	return nil
}
func ValidateGroupLockReleaseRequest(v GroupLockReleaseRequest) error {
	if !threadCollaborationScope(v.Scope) || v.Slot < 1 || v.Slot > GroupLockSlotCount || !threadCollaborationRevision(v.ExpectedVersion) || !threadCollaborationRevision(v.Generation) || !threadCollaborationOriginal(v.Original) {
		return ErrInvalid
	}
	return nil
}

// Shape/purpose check only. currentCaller must come from current authenticated
// Host/Node scope; this helper is not an authorization or Store transaction.
func ValidateGroupLockReleaseHolder(scope GroupLockScope, currentCaller GroupLockHolder, slot GroupLockSlot, request GroupLockReleaseRequest) error {
	if scope != request.Scope || ValidateGroupLockReleaseRequest(request) != nil || !threadCollaborationHolder(currentCaller) || slot.State != "HELD" || slot.Holder == nil || *slot.Holder != currentCaller || slot.Slot != request.Slot || slot.Version != request.ExpectedVersion || slot.Generation != request.Generation {
		return ErrInvalid
	}
	return nil
}

func DecodeGroupSlotView(raw []byte) (GroupSlotView, error) {
	var v GroupSlotView
	if decodeCanonical(raw, MaxThreadCollaborationViewBytes, &v) != nil || ValidateGroupSlotView(v) != nil {
		return v, ErrInvalid
	}
	return v, nil
}

func DecodeThreadScopeView(raw []byte) (ThreadScopeView, error) {
	var v ThreadScopeView
	if decodeCanonical(raw, MaxThreadCollaborationViewBytes, &v) != nil || ValidateThreadScopeView(v) != nil {
		return v, ErrInvalid
	}
	return v, nil
}
func DecodeGroupLockAcquireRequest(raw []byte) (GroupLockAcquireRequest, error) {
	var v GroupLockAcquireRequest
	if decodeCanonical(raw, MaxThreadCollaborationNodeBodyBytes, &v) != nil || explicitNullTTL(raw) || ValidateGroupLockAcquireRequest(v) != nil {
		return v, ErrInvalid
	}
	return v, nil
}
func explicitNullTTL(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return true
	}
	v, ok := fields["ttl_seconds"]
	return ok && string(v) == "null"
}
func DecodeGroupLockRenewRequest(raw []byte) (GroupLockRenewRequest, error) {
	var v GroupLockRenewRequest
	if decodeCanonical(raw, MaxThreadCollaborationNodeBodyBytes, &v) != nil || explicitNullTTL(raw) || ValidateGroupLockRenewRequest(v) != nil {
		return v, ErrInvalid
	}
	return v, nil
}
func DecodeGroupLockReleaseRequest(raw []byte) (GroupLockReleaseRequest, error) {
	var v GroupLockReleaseRequest
	if decodeCanonical(raw, MaxThreadCollaborationNodeBodyBytes, &v) != nil || ValidateGroupLockReleaseRequest(v) != nil {
		return v, ErrInvalid
	}
	return v, nil
}

func ValidateThreadCollaborationOwnerReadBody(v ThreadCollaborationOwnerReadBody) error {
	if !validID(v.NetworkID) || v.Limit > MaxThreadCollaborationPageRows || len(v.Cursor) > 1024 || !utf8.ValidString(v.Cursor) {
		return ErrInvalid
	}
	switch v.View {
	case "THREADS":
		if v.EndpointID != "" || v.GroupID != "" || v.NodeID != "" && !validID(v.NodeID) {
			return ErrInvalid
		}
	case "THREAD_SCOPE":
		if !validID(v.NodeID) || !validID(v.EndpointID) || v.GroupID != "" || v.Cursor != "" || v.Limit != 0 {
			return ErrInvalid
		}
	case "GROUP_LOCKS":
		if !validID(v.GroupID) || v.NodeID != "" || v.EndpointID != "" || v.Cursor != "" || v.Limit != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func ValidateThreadCollaborationOwnerPrepareBody(v ThreadCollaborationOwnerPrepareBody) error {
	count := 0
	if v.Role != nil {
		count++
	}
	if v.Policy != nil {
		count++
	}
	if v.Clear != nil {
		count++
	}
	if count != 1 {
		return ErrInvalid
	}
	switch v.Action {
	case ThreadCollaborationSetClassification:
		if v.Role == nil {
			return ErrInvalid
		}
		r := v.Role
		if !validID(r.NetworkID) || !validID(r.NodeID) || !validID(r.EndpointID) || !threadCollaborationSource(r.Source) || !threadCollaborationClassification(r.Classification) || r.ExpectedClassificationRevision >= 1<<63 || r.ExpectedRelationsRevision >= 1<<63 || !isHex(r.RegistrationDigest, 32) {
			return ErrInvalid
		}
	case ThreadCollaborationCreateGroupWithPolicy, ThreadCollaborationEnableGroupPolicy, ThreadCollaborationRevokeGroupPolicy:
		if v.Policy == nil {
			return ErrInvalid
		}
		p := v.Policy
		if !validID(p.NetworkID) || p.SlotCount != GroupLockSlotCount || !reflect.DeepEqual(p.Rights, GroupCoordinationRights()) || p.ExpectedPolicyRevision >= 1<<63 {
			return ErrInvalid
		}
		if v.Action == ThreadCollaborationCreateGroupWithPolicy {
			if p.GroupID != "" || p.Name == "" || len(p.Name) > 128 || !utf8.ValidString(p.Name) || p.ExpectedGroupVersion != 0 || p.ExpectedPolicyRevision != 0 {
				return ErrInvalid
			}
		} else if !validID(p.GroupID) || p.Name != "" || !threadCollaborationRevision(p.ExpectedGroupVersion) || v.Action == ThreadCollaborationRevokeGroupPolicy && p.ExpectedPolicyRevision == 0 {
			return ErrInvalid
		}
	case ThreadCollaborationClearOneSlot:
		if v.Clear == nil {
			return ErrInvalid
		}
		c := v.Clear
		if !threadCollaborationScope(c.Scope) || c.Slot < 1 || c.Slot > GroupLockSlotCount || !threadCollaborationRevision(c.ExpectedVersion) || !threadCollaborationRevision(c.Generation) || !threadCollaborationHolder(c.ExpectedHolder) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func DecodeThreadCollaborationOwnerReadBody(raw []byte) (ThreadCollaborationOwnerReadBody, error) {
	var v ThreadCollaborationOwnerReadBody
	if decodeCanonical(raw, MaxThreadCollaborationOwnerBodyBytes, &v) != nil || ValidateThreadCollaborationOwnerReadBody(v) != nil {
		return v, ErrInvalid
	}
	return v, nil
}
func DecodeThreadCollaborationOwnerPrepareBody(raw []byte) (ThreadCollaborationOwnerPrepareBody, error) {
	var v ThreadCollaborationOwnerPrepareBody
	if decodeCanonical(raw, MaxThreadCollaborationOwnerBodyBytes, &v) != nil || ValidateThreadCollaborationOwnerPrepareBody(v) != nil {
		return v, ErrInvalid
	}
	return v, nil
}

// Recompute on the server from authenticated caller + the typed original body.
// The incoming digest is excluded from its own preimage; operation ID and
// idempotency key are included. An assertion from JSON cannot replace this.
func GroupLockRequestDigest(operation string, caller GroupLockHolder, request any) (string, error) {
	if !threadCollaborationHolder(caller) {
		return "", ErrInvalid
	}
	var body any
	switch v := dereference(request).(type) {
	case GroupLockAcquireRequest:
		if operation != OperationGroupLocksAcquire {
			return "", ErrInvalid
		}
		v.Original.RequestDigest = strings.Repeat("0", 64)
		if ValidateGroupLockAcquireRequest(v) != nil {
			return "", ErrInvalid
		}
		v.Original.RequestDigest = ""
		body = v
	case GroupLockReleaseRequest:
		if operation != OperationGroupLocksRelease {
			return "", ErrInvalid
		}
		v.Original.RequestDigest = strings.Repeat("0", 64)
		if ValidateGroupLockReleaseRequest(v) != nil {
			return "", ErrInvalid
		}
		v.Original.RequestDigest = ""
		body = v
	case GroupLockRenewRequest:
		if operation != OperationGroupLocksRenew {
			return "", ErrInvalid
		}
		v.Original.RequestDigest = strings.Repeat("0", 64)
		if ValidateGroupLockRenewRequest(v) != nil {
			return "", ErrInvalid
		}
		v.Original.RequestDigest = ""
		body = v
	default:
		return "", ErrInvalid
	}
	raw, err := json.Marshal(struct {
		Operation string          `json:"operation"`
		Caller    GroupLockHolder `json:"caller"`
		Body      any             `json:"body"`
	}{operation, caller, body})
	if err != nil || len(raw) > MaxThreadCollaborationNodeBodyBytes {
		return "", ErrInvalid
	}
	h := sha256.Sum256(append([]byte("cicada/group-lock/original/v1\x00"), raw...))
	return hex.EncodeToString(h[:]), nil
}
func VerifyGroupLockRequestDigest(operation string, caller GroupLockHolder, request any) error {
	var supplied string
	switch v := dereference(request).(type) {
	case GroupLockAcquireRequest:
		supplied = v.Original.RequestDigest
	case GroupLockReleaseRequest:
		supplied = v.Original.RequestDigest
	case GroupLockRenewRequest:
		supplied = v.Original.RequestDigest
	default:
		return ErrInvalid
	}
	actual, err := GroupLockRequestDigest(operation, caller, request)
	if err != nil || len(supplied) != 64 || subtle.ConstantTimeCompare([]byte(actual), []byte(supplied)) != 1 {
		return ErrInvalid
	}
	return nil
}

func ThreadCollaborationOwnerBodyDigest(body ThreadCollaborationOwnerPrepareBody) (string, error) {
	if ValidateThreadCollaborationOwnerPrepareBody(body) != nil {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(body)
	if err != nil || len(raw) > MaxThreadCollaborationOwnerBodyBytes {
		return "", ErrInvalid
	}
	h := sha256.Sum256(append([]byte("cicada/thread-collaboration/owner-body/v1\x00"), raw...))
	return hex.EncodeToString(h[:]), nil
}

func ThreadCollaborationOwnerReviewDigest(review ThreadCollaborationOwnerReview) (string, error) {
	if !isHex(review.ReviewID, 16) || !validID(review.HubID) || !validID(review.OwnerID) || !validDeviceID(review.DeviceID) || !isHex(review.PrepareRequestID, 16) || !isHex(review.PreparePacketDigest, 32) || review.Action != review.Prepared.Action {
		return "", ErrInvalid
	}
	body, err := ThreadCollaborationOwnerBodyDigest(review.Prepared)
	if err != nil || body != review.BodyDigest {
		return "", ErrInvalid
	}
	if p := review.Prepared.Policy; p != nil {
		if !validID(review.TargetGroupID) || review.Prepared.Action != ThreadCollaborationCreateGroupWithPolicy && review.TargetGroupID != p.GroupID {
			return "", ErrInvalid
		}
	} else if c := review.Prepared.Clear; c != nil {
		if review.TargetGroupID != c.Scope.GroupID {
			return "", ErrInvalid
		}
	} else if review.TargetGroupID != "" {
		return "", ErrInvalid
	}
	observed, err := parseCanonicalUTC(review.ObservedAt)
	end, ee := parseCanonicalUTC(review.ExpiresAt)
	if err != nil || ee != nil || !end.After(observed) || end.Sub(observed) > 5*time.Minute {
		return "", ErrInvalid
	}
	raw, err := json.Marshal(review)
	if err != nil || len(raw) > MaxThreadCollaborationOwnerBodyBytes {
		return "", ErrInvalid
	}
	h := sha256.Sum256(append([]byte("cicada/thread-collaboration/owner-review/v1\x00"), raw...))
	return hex.EncodeToString(h[:]), nil
}
