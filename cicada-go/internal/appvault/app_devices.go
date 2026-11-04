package appvault

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/cicada-ai/cicada/internal/appkeys"
)

// A full history refuses further re-enrollment; it never evicts keys or receipts.
// All generations share the existing 4 MiB plaintext and 8 MiB file ceilings.
const maxRetiredAppDevices = 4

// StateGuard identifies bytes already committed to this vault. The controller
// authenticates Hub receipts first; the vault checks storage, not Hub authority.
type StateGuard struct {
	Namespace string `json:"namespace"`
	Version   uint64 `json:"version"`
	SHA256    string `json:"sha256"`
}

func NewStateGuard(namespace string, version uint64, payload []byte) StateGuard {
	digest := sha256.Sum256(payload)
	return StateGuard{Namespace: namespace, Version: version, SHA256: hex.EncodeToString(digest[:])}
}

// AppDeviceCandidate contains public metadata only. Its private key remains in
// the encrypted vault; preparing the same ceremony after restart reuses it.
type AppDeviceCandidate struct {
	KeyID      string `json:"key_id"`
	Generation uint64 `json:"generation"`
}

type RetiredAppDeviceInfo struct {
	KeyID      string
	Generation uint64
}

type AppDeviceStatus struct {
	CurrentKeyID string
	Generation   uint64
	Candidate    *AppDeviceCandidate
	Retired      []RetiredAppDeviceInfo
}

// AppDevicePromotion atomically replaces only the App-device entry and current
// state. ExpectedVersions must cover every current namespace and every update.
// All old states are archived verbatim. Unlisted updates become CAS tombstones;
// in particular the session namespace must be explicitly tombstoned. The new
// account state must describe the new key with no inherited leases or session.
type AppDevicePromotion struct {
	CurrentKeyID     string
	Candidate        AppDeviceCandidate
	Completion       StateGuard
	ExpectedVersions map[string]uint64
	Updates          map[string][]byte
	SessionNamespace string
}

type pendingAppDevice struct {
	Candidate AppDeviceCandidate `json:"candidate"`
	Unbound   StateGuard         `json:"unbound"`
	Private   []byte             `json:"private_identity"`
}

type retiredAppDevice struct {
	Generation uint64      `json:"generation"`
	Device     diskEntry   `json:"device"`
	Unbound    StateGuard  `json:"unbound"`
	Completion StateGuard  `json:"completion"`
	States     []diskState `json:"states"`
}

type appDeviceLifecycle struct {
	Generation   uint64             `json:"generation"`
	CurrentKeyID string             `json:"current_key_id"`
	Pending      *pendingAppDevice  `json:"pending,omitempty"`
	Retired      []retiredAppDevice `json:"retired,omitempty"`
}

func (v *Vault) AppDeviceStatus() (AppDeviceStatus, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return AppDeviceStatus{}, err
	}
	status := AppDeviceStatus{CurrentKeyID: v.entries[PurposeAppDevice].KeyID, Generation: 1}
	if v.appDevices != nil {
		status.Generation = v.appDevices.Generation
		if v.appDevices.Pending != nil {
			candidate := v.appDevices.Pending.Candidate
			status.Candidate = &candidate
		}
		for _, old := range v.appDevices.Retired {
			status.Retired = append(status.Retired, RetiredAppDeviceInfo{KeyID: old.Device.KeyID, Generation: old.Generation})
		}
	}
	return status, nil
}

// StateVersions takes a detached CAS snapshot, including versioned tombstones.
func (v *Vault) StateVersions() (map[string]uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return nil, err
	}
	versions := make(map[string]uint64, len(v.states))
	for name, state := range v.states {
		versions[name] = state.version
	}
	return versions, nil
}

// PrepareAppDevice stages one key after a controller-verified terminal unbind
// receipt has been committed. It never changes the current key or any state.
// The caller must settle every uncertain write before initiating unbinding.
func (v *Vault) PrepareAppDevice(currentKeyID string, unbound StateGuard) (AppDeviceCandidate, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return AppDeviceCandidate{}, err
	}
	if v.entries[PurposeAppDevice].KeyID != currentKeyID || !validKeyID(currentKeyID) || v.entries[PurposeOwnerSigner].KeyID == "" {
		return AppDeviceCandidate{}, ErrScopeMismatch
	}
	if !matchesStateGuard(v.states, unbound) {
		return AppDeviceCandidate{}, ErrStateConflict
	}
	if v.appDevices != nil && v.appDevices.Pending != nil {
		if v.appDevices.Pending.Unbound != unbound {
			return AppDeviceCandidate{}, ErrStateConflict
		}
		return v.appDevices.Pending.Candidate, nil
	}
	if err := v.checkAppDeviceTransition(nil, nil); err != nil {
		return AppDeviceCandidate{}, err
	}
	identity, err := appkeys.Generate()
	if err != nil {
		return AppDeviceCandidate{}, err
	}
	defer identity.Close()
	private, err := identity.MarshalBinary()
	if err != nil {
		return AppDeviceCandidate{}, err
	}
	defer clear(private)
	devices := v.cloneOrInitialAppDevices()
	defer clearAppDeviceLifecycle(devices)
	candidate := AppDeviceCandidate{KeyID: identity.Public().ID, Generation: devices.Generation + 1}
	devices.Pending = &pendingAppDevice{Candidate: candidate, Unbound: unbound, Private: append([]byte(nil), private...)}
	if err := v.persistGeneration(v.entries, v.states, devices, false); err != nil {
		return AppDeviceCandidate{}, err
	}
	clearAppDeviceLifecycle(v.appDevices)
	v.appDevices = cloneAppDeviceLifecycle(devices)
	return candidate, nil
}

// OpenPendingAppDevice returns an opaque handle for the bounded re-enrollment
// ceremony. Ordinary business writes continue to use only PurposeAppDevice.
func (v *Vault) OpenPendingAppDevice(candidate AppDeviceCandidate) (*appkeys.Identity, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return nil, err
	}
	if v.appDevices == nil || v.appDevices.Pending == nil || v.appDevices.Pending.Candidate != candidate {
		return nil, ErrScopeMismatch
	}
	return appkeys.ParseIdentity(v.appDevices.Pending.Private)
}

// CheckAppDeviceTransition checks both staging and atomic promotion budgets.
// retiringUpdates project exact originals plus worst-case authenticated receipt
// and recovery bytes that must fit BEFORE sending. currentUpdates project the
// fresh generation's account state; all remaining current records are tombstones.
// This check grants no permission and reserves no bytes. Callers repeat it before
// network writes and still persist the exact original first.
func (v *Vault) CheckAppDeviceTransition(retiringUpdates, currentUpdates map[string][]byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return err
	}
	return v.checkAppDeviceTransition(retiringUpdates, currentUpdates)
}

func (v *Vault) checkAppDeviceTransition(retiringUpdates, currentUpdates map[string][]byte) error {
	devices := v.cloneOrInitialAppDevices()
	defer clearAppDeviceLifecycle(devices)
	if !validKeyID(devices.CurrentKeyID) {
		return ErrInvalidVault
	}
	if len(devices.Retired) >= maxRetiredAppDevices {
		return ErrAppDeviceHistoryFull
	}
	states := cloneStates(v.states)
	defer clearStates(states)
	if err := projectStates(states, retiringUpdates); err != nil {
		return err
	}
	for name, state := range states {
		if state.version == ^uint64(0) {
			return ErrStateConflict
		}
		// Reserve the largest decimal CAS encoding across intermediate saves.
		state.version = ^uint64(0) - 1
		states[name] = state
	}
	guard := StateGuard{Namespace: strings.Repeat("x", 64), Version: ^uint64(0), SHA256: strings.Repeat("a", 64)}
	// Admission uses the maximum accepted identity size, never a generated key.
	// These bytes are used only for sizing and are never persisted.
	if devices.Pending != nil {
		clear(devices.Pending.Private)
	}
	devices.Pending = &pendingAppDevice{Candidate: AppDeviceCandidate{KeyID: devices.CurrentKeyID, Generation: devices.Generation + 1}, Unbound: guard, Private: make([]byte, maxIdentityBytes)}
	encoded, err := encodePayload(v.entries, states, devices)
	clear(encoded)
	if err != nil {
		return err
	}
	devices.Retired = append(devices.Retired, retiredAppDevice{Generation: devices.Generation,
		Device: cloneDeviceEntry(v.entries[PurposeAppDevice]), Unbound: guard, Completion: guard, States: snapshotStates(states)})
	clear(devices.Pending.Private)
	devices.Pending = nil
	devices.Generation++
	for name, state := range states {
		if state.version == ^uint64(0) {
			return ErrStateConflict
		}
		clear(state.payload)
		states[name] = stateValue{version: state.version + 1}
	}
	if err := projectStates(states, currentUpdates); err != nil {
		return err
	}
	for name, state := range states {
		state.version = ^uint64(0)
		states[name] = state
	}
	entries := cloneEntries(v.entries)
	defer clearEntries(entries)
	entry := entries[PurposeAppDevice]
	clear(entry.Private)
	entry.Private = make([]byte, maxIdentityBytes)
	entries[PurposeAppDevice] = entry
	encoded, err = encodePayload(entries, states, devices)
	clear(encoded)
	return err
}

// PromoteAppDevice requires a separately persisted, controller-authenticated
// completion receipt and an exact CAS snapshot. One atomic encrypted write
// archives the old key and state, promotes the candidate and tombstones old
// authority. ErrCommitUncertain requires closing/reopening and inspecting the
// actual generation; callers must never generate another key in that condition.
func (v *Vault) PromoteAppDevice(change AppDevicePromotion) (map[string]uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return nil, err
	}
	if v.appDevices == nil || v.appDevices.Pending == nil || v.entries[PurposeAppDevice].KeyID != change.CurrentKeyID ||
		v.appDevices.Pending.Candidate != change.Candidate {
		return nil, ErrScopeMismatch
	}
	pending := v.appDevices.Pending
	if !matchesStateGuard(v.states, pending.Unbound) || !matchesStateGuard(v.states, change.Completion) || pending.Unbound == change.Completion {
		return nil, ErrStateConflict
	}
	if !validNamespace(change.SessionNamespace) {
		return nil, ErrInvalidVault
	}
	if payload, ok := change.Updates[change.SessionNamespace]; !ok || payload != nil {
		return nil, ErrInvalidVault
	}
	for name, state := range v.states {
		expected, ok := change.ExpectedVersions[name]
		if !ok || state.version != expected || expected == ^uint64(0) {
			return nil, ErrStateConflict
		}
	}
	for name, expected := range change.ExpectedVersions {
		if !validNamespace(name) || expected != v.states[name].version || expected == ^uint64(0) {
			return nil, ErrStateConflict
		}
		if _, exists := v.states[name]; !exists {
			if _, updated := change.Updates[name]; !updated {
				return nil, ErrStateConflict
			}
		}
	}
	for name, payload := range change.Updates {
		if !validNamespace(name) || len(payload) > maxStateBytes {
			return nil, ErrInvalidVault
		}
		if _, ok := change.ExpectedVersions[name]; !ok {
			return nil, ErrStateConflict
		}
	}
	devices := cloneAppDeviceLifecycle(v.appDevices)
	defer clearAppDeviceLifecycle(devices)
	if len(devices.Retired) >= maxRetiredAppDevices {
		return nil, ErrAppDeviceHistoryFull
	}
	devices.Retired = append(devices.Retired, retiredAppDevice{Generation: devices.Generation,
		Device: cloneDeviceEntry(v.entries[PurposeAppDevice]), Unbound: pending.Unbound,
		Completion: change.Completion, States: snapshotStates(v.states)})
	devices.Generation = pending.Candidate.Generation
	devices.CurrentKeyID = pending.Candidate.KeyID
	entries := cloneEntries(v.entries)
	defer clearEntries(entries)
	oldEntry := entries[PurposeAppDevice]
	clear(oldEntry.Private)
	entries[PurposeAppDevice] = diskEntry{Purpose: PurposeAppDevice, KeyID: pending.Candidate.KeyID, Private: append([]byte(nil), pending.Private...)}
	clear(devices.Pending.Private)
	devices.Pending = nil
	states := make(map[string]stateValue, len(change.ExpectedVersions))
	defer clearStates(states)
	versions := make(map[string]uint64, len(change.ExpectedVersions))
	for name, expected := range change.ExpectedVersions {
		versions[name] = expected + 1
		states[name] = stateValue{version: expected + 1, payload: append([]byte(nil), change.Updates[name]...)}
	}
	if err := v.persistGeneration(entries, states, devices, false); err != nil {
		return nil, err
	}
	clearEntries(v.entries)
	clearStates(v.states)
	clearAppDeviceLifecycle(v.appDevices)
	v.entries = cloneEntries(entries)
	v.states = cloneStates(states)
	v.appDevices = cloneAppDeviceLifecycle(devices)
	return versions, nil
}

// LoadRetiredAppDeviceState exposes only a detached historical record. Retired
// keys have no Get/Put/signing API and old grants cannot become current state.
func (v *Vault) LoadRetiredAppDeviceState(generation uint64, namespace string) ([]byte, uint64, bool, error) {
	if !validNamespace(namespace) {
		return nil, 0, false, ErrInvalidVault
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireOpen(); err != nil {
		return nil, 0, false, err
	}
	if v.appDevices != nil {
		for _, retired := range v.appDevices.Retired {
			if retired.Generation == generation {
				for _, state := range retired.States {
					if state.Namespace == namespace {
						return append([]byte(nil), state.Payload...), state.Version, true, nil
					}
				}
			}
		}
	}
	return nil, 0, false, nil
}

func validStateGuard(guard StateGuard) bool {
	return validNamespace(guard.Namespace) && guard.Version > 0 && len(guard.SHA256) == 64 && isLowerHex(guard.SHA256)
}

func matchesStateGuard(states map[string]stateValue, guard StateGuard) bool {
	state, ok := states[guard.Namespace]
	return ok && len(state.payload) > 0 && validStateGuard(guard) && NewStateGuard(guard.Namespace, state.version, state.payload) == guard
}

func projectStates(states map[string]stateValue, updates map[string][]byte) error {
	for name, payload := range updates {
		if !validNamespace(name) || len(payload) > maxStateBytes {
			return ErrInvalidVault
		}
		state := states[name]
		if state.version == 0 {
			state.version = 1
		}
		clear(state.payload)
		state.payload = append([]byte(nil), payload...)
		states[name] = state
	}
	if len(states) > maxStateRecords {
		return ErrInvalidVault
	}
	return nil
}

func snapshotStates(states map[string]stateValue) []diskState {
	var snapshot []diskState
	for name, state := range states {
		snapshot = append(snapshot, diskState{Namespace: name, Version: state.version, Payload: append([]byte(nil), state.payload...)})
	}
	sort.Slice(snapshot, func(i, j int) bool { return snapshot[i].Namespace < snapshot[j].Namespace })
	return snapshot
}

func cloneDeviceEntry(entry diskEntry) diskEntry {
	entry.Private = append([]byte(nil), entry.Private...)
	return entry
}

func (v *Vault) cloneOrInitialAppDevices() *appDeviceLifecycle {
	if v.appDevices != nil {
		return cloneAppDeviceLifecycle(v.appDevices)
	}
	return &appDeviceLifecycle{Generation: 1, CurrentKeyID: v.entries[PurposeAppDevice].KeyID}
}

func cloneAppDeviceLifecycle(source *appDeviceLifecycle) *appDeviceLifecycle {
	if source == nil {
		return nil
	}
	result := &appDeviceLifecycle{Generation: source.Generation, CurrentKeyID: source.CurrentKeyID}
	if source.Pending != nil {
		pending := *source.Pending
		pending.Private = append([]byte(nil), pending.Private...)
		result.Pending = &pending
	}
	for _, sourceOld := range source.Retired {
		old := sourceOld
		old.Device = cloneDeviceEntry(sourceOld.Device)
		old.States = nil
		for _, state := range sourceOld.States {
			old.States = append(old.States, diskState{Namespace: state.Namespace, Version: state.Version, Payload: append([]byte(nil), state.Payload...)})
		}
		result.Retired = append(result.Retired, old)
	}
	return result
}

func clearAppDeviceLifecycle(devices *appDeviceLifecycle) {
	if devices == nil {
		return
	}
	if devices.Pending != nil {
		clear(devices.Pending.Private)
		devices.Pending.Private = nil
	}
	for i := range devices.Retired {
		clear(devices.Retired[i].Device.Private)
		for j := range devices.Retired[i].States {
			clear(devices.Retired[i].States[j].Payload)
		}
	}
}

func validateAppDeviceLifecycle(devices *appDeviceLifecycle, entries map[Purpose]diskEntry) error {
	if devices == nil {
		return nil
	}
	if devices.Generation == 0 || devices.Generation > maxRetiredAppDevices+1 || uint64(len(devices.Retired))+1 != devices.Generation ||
		!validKeyID(devices.CurrentKeyID) || devices.CurrentKeyID != entries[PurposeAppDevice].KeyID || entries[PurposeOwnerSigner].KeyID == "" {
		return ErrInvalidVault
	}
	seen := map[string]bool{devices.CurrentKeyID: true}
	for i, old := range devices.Retired {
		if old.Generation != uint64(i+1) || old.Device.Purpose != PurposeAppDevice || seen[old.Device.KeyID] ||
			!validStateGuard(old.Unbound) || !validStateGuard(old.Completion) || old.Unbound == old.Completion || len(old.States) > maxStateRecords {
			return ErrInvalidVault
		}
		if err := validateDevicePrivate(old.Device.KeyID, old.Device.Private); err != nil {
			return err
		}
		seen[old.Device.KeyID] = true
		states := make(map[string]stateValue, len(old.States))
		lastName := ""
		for _, state := range old.States {
			if !validNamespace(state.Namespace) || state.Namespace <= lastName || state.Version == 0 || len(state.Payload) > maxStateBytes {
				return ErrInvalidVault
			}
			lastName = state.Namespace
			states[state.Namespace] = stateValue{version: state.Version, payload: state.Payload}
		}
		if !matchesStateGuard(states, old.Unbound) || !matchesStateGuard(states, old.Completion) {
			return ErrInvalidVault
		}
	}
	if pending := devices.Pending; pending != nil {
		if pending.Candidate.Generation != devices.Generation+1 || len(devices.Retired) >= maxRetiredAppDevices || seen[pending.Candidate.KeyID] || !validStateGuard(pending.Unbound) {
			return ErrInvalidVault
		}
		return validateDevicePrivate(pending.Candidate.KeyID, pending.Private)
	}
	return nil
}

func validateDevicePrivate(keyID string, private []byte) error {
	if !validKeyID(keyID) || len(private) == 0 || len(private) > maxIdentityBytes {
		return ErrInvalidVault
	}
	identity, err := appkeys.ParseIdentity(private)
	if err != nil {
		return ErrInvalidVault
	}
	defer identity.Close()
	if identity.Public().ID != keyID {
		return ErrInvalidVault
	}
	return nil
}
