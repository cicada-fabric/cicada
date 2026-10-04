package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// When filesystem failure prevents a durable fail-closed fence, these exact
// directory leases remain strongly reachable for the process lifetime. Local
// variables alone are insufficient: os.File finalizers can release flock.
var hubRestoreRetainedLeases struct {
	sync.Mutex
	pairs []hubRestoreRetainedLeasePair
}

type hubRestoreRetainedLeasePair struct{ authority, target *StateMaintenanceLease }

func retainHubRestoreFailedActivationLeases(authority, target *StateMaintenanceLease) {
	hubRestoreRetainedLeases.Lock()
	hubRestoreRetainedLeases.pairs = append(hubRestoreRetainedLeases.pairs, hubRestoreRetainedLeasePair{authority, target})
	hubRestoreRetainedLeases.Unlock()
}

type HubRestoreActivationReport struct {
	Authority      *HubRestoreAuthority `json:"authority"`
	Activated      bool                 `json:"activated"`
	TargetStateDir string               `json:"target_state_dir"`
	ReceiptSHA256  string               `json:"receipt_sha256"`
}
type hubRestoreForwardReceipt struct {
	FormatVersion         int                          `json:"format_version"`
	AuthorityID           string                       `json:"authority_id"`
	Epoch                 uint64                       `json:"expected_epoch"`
	SourceStorage         HubRestoreStorageIncarnation `json:"source_retired"`
	TargetStorage         HubRestoreStorageIncarnation `json:"target_storage_incarnation"`
	ParkedStorage         HubRestoreStorageIncarnation `json:"parked_storage_incarnation"`
	ParkedStateDir        string                       `json:"parked_state_dir"`
	BaseManifestSHA256    string                       `json:"base_manifest_sha256"`
	CapsuleManifestSHA256 string                       `json:"capsule_manifest_sha256"`
	InventorySHA256       string                       `json:"inventory_sha256"`
	HoldSHA256            string                       `json:"hold_sha256"`
	CoverageSHA256        string                       `json:"coverage_digest"`
	UnknownSHA256         string                       `json:"unknown_digest"`
}
type hubRestoreActivationReceipt struct {
	FormatVersion         int                          `json:"format_version"`
	AuthorityID           string                       `json:"authority_id"`
	ExpectedEpoch         uint64                       `json:"expected_epoch"`
	CommittedEpoch        uint64                       `json:"committed_epoch"`
	TargetStorage         HubRestoreStorageIncarnation `json:"target_storage_incarnation"`
	SourceStorage         HubRestoreStorageIncarnation `json:"source_retired"`
	ForwardReceiptSHA256  string                       `json:"forward_receipt_sha256"`
	BaseManifestSHA256    string                       `json:"base_manifest_sha256"`
	CapsuleManifestSHA256 string                       `json:"capsule_manifest_sha256"`
	HoldSHA256            string                       `json:"hold_sha256"`
	CoverageSHA256        string                       `json:"coverage_digest"`
	UnknownSHA256         string                       `json:"unknown_digest"`
}

func hubRestoreForwardReceiptPath(path string, a *HubRestoreAuthority) string {
	return fmt.Sprintf("%s.forward-%d.json", path, a.AuthorityEpoch)
}
func hubRestoreActivationReceiptPath(path string, epoch uint64) string {
	return fmt.Sprintf("%s.activation-%d.json", path, epoch)
}
func hubRestoreFailurePath(path string, epoch uint64) string {
	return fmt.Sprintf("%s.failed-%d.json", path, epoch)
}
func hubRestoreReadForwardReceipt(path string, a *HubRestoreAuthority) (*hubRestoreForwardReceipt, error) {
	var r hubRestoreForwardReceipt
	if _, e := hubRestoreReadJSON(hubRestoreForwardReceiptPath(path, a), &r); e != nil {
		return nil, e
	}
	if r.FormatVersion != 1 || r.AuthorityID != a.AuthorityID || r.Epoch != a.AuthorityEpoch || r.SourceStorage != a.SourceStorage || r.BaseManifestSHA256 != a.BaseManifestSHA256 || r.CapsuleManifestSHA256 != a.CapsuleManifestSHA256 || r.InventorySHA256 != a.InventorySHA256 || r.CoverageSHA256 != a.CoverageSHA256 || r.UnknownSHA256 != a.UnknownSHA256 || r.TargetStorage.CanonicalCoordinate != a.TargetStateDir || r.ParkedStorage.CanonicalCoordinate != r.ParkedStateDir {
		return nil, ErrHubRestoreAuthorityUnproven
	}
	return &r, nil
}
func hubRestoreVerifyPayload(root string, manifest *StateBackupManifest, hold []byte) error {
	files, e := collectStateFilesAllowlist(root, map[string]string{stateRestoreMarker: hubRestoreHash(hold)})
	if e != nil {
		return e
	}
	if e = compareStateFileInventory(files, manifest.Files); e != nil {
		return e
	}
	for _, expected := range manifest.Files {
		p := filepath.Join(root, filepath.FromSlash(expected.Path))
		i, e := os.Lstat(p)
		if e != nil || !i.Mode().IsRegular() || i.Size() != expected.Size || i.Mode() != os.FileMode(expected.Mode) {
			return ErrHubRestoreCoverage
		}
		digest, e := hashFile(context.Background(), p)
		if e != nil || digest != expected.SHA256 {
			return ErrHubRestoreCoverage
		}
	}
	return nil
}
func hubRestoreVerifyForward(target string, hold []byte, manifest *StateBackupManifest, r *hubRestoreForwardReceipt) error {
	if hubRestoreHash(hold) != r.HoldSHA256 || !hubRestoreIncarnationMatches(r.TargetStorage, target) || !hubRestoreIncarnationMatches(r.ParkedStorage, r.ParkedStateDir) {
		return ErrHubRestoreAuthorityUnproven
	}
	oldhold, e := hubRestoreReadPrivateFile(filepath.Join(r.ParkedStateDir, stateRestoreMarker))
	if e != nil || hubRestoreHash(oldhold) != r.HoldSHA256 {
		return ErrHubRestoreAuthorityUnproven
	}
	return hubRestoreVerifyPayload(target, manifest, hold)
}

// Reconcile atomically exchanges the complete current capsule into T, retaining
// the exact B marker, external hold and the parked old B directory. It does not
// issue a startup permit or dispatch anything.
func ReconcileHubRestoreHandover(ctx context.Context, o HubRestoreOperationOptions) (*HubRestoreReconciliationReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	source, e := canonicalRestoreTarget(o.SourceStateDir)
	if e != nil {
		return nil, e
	}
	target, e := canonicalRestoreTarget(o.TargetStateDir)
	if e != nil {
		return nil, e
	}
	o.SourceStateDir = source
	o.TargetStateDir = target
	path, e := hubRestoreLocate(source)
	if e != nil {
		return nil, e
	}
	al, e := acquireStateMaintenance(filepath.Dir(path), true, false)
	if e != nil {
		return nil, e
	}
	defer al.Close()
	old, e := acquireStateMaintenance(target, true, false)
	if e != nil {
		return nil, e
	}
	defer old.Close()
	a, e := hubRestoreReadAuthority(path)
	if e != nil {
		return nil, e
	}
	report, e := hubRestoreReconcileReadOnly(o, a, path)
	if e != nil {
		return nil, e
	}
	if report.ForwardInstalled {
		return report, nil
	}
	hold, e := hubRestorePairedHold(target, a.BaseManifestSHA256)
	if e != nil {
		return nil, e
	}
	cm, e := VerifyStateBackup(a.CapsuleDir)
	if e != nil {
		return nil, e
	}
	locatorPath := hubRestoreTargetLocatorPath(target)
	loc := hubRestoreLocator{1, path, a.AuthorityID, a.SourceStorage.RegistrationNonce}
	if _, e = os.Lstat(locatorPath); errors.Is(e, os.ErrNotExist) {
		if e = writePrivateJSON(locatorPath, loc); e != nil {
			return nil, e
		}
		if e = syncDirectory(filepath.Dir(locatorPath)); e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	} else {
		var existing hubRestoreLocator
		if _, e = hubRestoreReadJSON(locatorPath, &existing); e != nil || existing != loc {
			return nil, ErrHubRestoreAuthorityUnproven
		}
	}
	stage, e := os.MkdirTemp(filepath.Dir(target), ".hub-forward-parked-")
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(stage, 0700); e != nil {
		return nil, e
	}
	// Even pre-publication partials are retained privately as held evidence.
	replacement, e := acquireStateMaintenance(stage, true, false)
	if e != nil {
		return nil, e
	}
	defer replacement.Close()
	f, e := os.OpenFile(filepath.Join(stage, stateRestoreMarker), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return nil, e
	}
	_, e = f.Write(hold)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return nil, e
	}
	for _, file := range cm.Files {
		destination := filepath.Join(stage, filepath.FromSlash(file.Path))
		if e = ensurePrivateParentDirs(stage, filepath.Dir(destination)); e != nil {
			return nil, e
		}
		if _, e = copyExactStateFile(ctx, filepath.Join(a.CapsuleDir, stateBackupPayloadName, filepath.FromSlash(file.Path)), destination, file); e != nil {
			return nil, e
		}
	}
	if e = hubRestoreSyncTree(stage); e != nil {
		return nil, e
	}
	if e = hubRestoreVerifyPayload(stage, cm, hold); e != nil {
		return nil, e
	}
	if e = syncDirectory(stage); e != nil {
		return nil, e
	}
	if e = old.validate(target); e != nil {
		return nil, e
	}
	if e = replacement.validate(stage); e != nil {
		return nil, e
	}
	before, e := hubRestoreIncarnation(target, a.SourceStorage.RegistrationNonce)
	if e != nil {
		return nil, e
	}
	nonce, e := hubRestoreNonce()
	if e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = hubRestoreDirectoryExchange(target, stage); e != nil {
		return nil, fmt.Errorf("atomic Hub forward exchange unsupported or failed: %w", e)
	}
	// Both directory fds stay locked. Unlike empty restore, neither inode is unlinked.
	if e = replacement.validate(target); e != nil {
		return nil, e
	}
	if e = old.validate(stage); e != nil {
		return nil, e
	}
	if e = syncDirectory(filepath.Dir(target)); e != nil {
		return nil, e
	}
	current, e := hubRestoreIncarnation(target, nonce)
	if e != nil {
		return nil, e
	}
	parked, e := hubRestoreIncarnation(stage, before.RegistrationNonce)
	if e != nil {
		return nil, e
	}
	if parked.Device != before.Device || parked.Inode != before.Inode {
		return nil, ErrStateBackupPathUnsafe
	}
	r := &hubRestoreForwardReceipt{1, a.AuthorityID, a.AuthorityEpoch, a.SourceStorage, current, parked, stage, a.BaseManifestSHA256, a.CapsuleManifestSHA256, a.InventorySHA256, hubRestoreHash(hold), a.CoverageSHA256, a.UnknownSHA256}
	if e = hubRestoreVerifyForward(target, hold, cm, r); e != nil {
		return nil, e
	}
	if e = writePrivateJSON(hubRestoreForwardReceiptPath(path, a), r); e != nil {
		return nil, e
	}
	if e = syncDirectory(filepath.Dir(path)); e != nil {
		return nil, e
	}
	report.ForwardInstalled = true
	report.ParkedStateDir = stage
	return report, nil
}

// hook is per-call, test-only; production has no fault-control API.
type hubRestoreActivationFault func(phase string) error

func ActivateHubRestoreHandover(ctx context.Context, o HubRestoreOperationOptions) (*HubRestoreActivationReport, error) {
	return activateHubRestoreHandover(ctx, o, nil)
}
func activateHubRestoreHandover(ctx context.Context, o HubRestoreOperationOptions, hook hubRestoreActivationFault) (*HubRestoreActivationReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	source, e := canonicalRestoreTarget(o.SourceStateDir)
	if e != nil {
		return nil, e
	}
	target, e := canonicalRestoreTarget(o.TargetStateDir)
	if e != nil {
		return nil, e
	}
	o.SourceStateDir = source
	o.TargetStateDir = target
	path, e := hubRestoreLocate(source)
	if e != nil {
		return nil, e
	}
	al, e := acquireStateMaintenance(filepath.Dir(path), true, false)
	if e != nil {
		return nil, e
	}
	lease, e := acquireStateMaintenance(target, true, false)
	if e != nil {
		al.Close()
		return nil, e
	}
	release := true
	defer func() {
		if release {
			lease.Close()
			al.Close()
		}
	}()
	a, e := hubRestoreReadAuthority(path)
	if e != nil {
		return nil, e
	}
	if a.State == "ACTIVE_TARGET" {
		if a.SourceStorage.CanonicalCoordinate != source {
			return nil, ErrHubRestoreAuthorityUnproven
		}
		if e = hubRestoreVerifyStartupAuthority(target, a, path); e != nil {
			return nil, e
		}
		return &HubRestoreActivationReport{a, true, target, a.ActivationReceiptSHA256}, nil
	}
	report, e := hubRestoreReconcileReadOnly(o, a, path)
	if e != nil {
		return nil, e
	}
	if !report.ForwardInstalled {
		return nil, fmt.Errorf("reconcile full current capsule before activation: %w", ErrStateRestoreQuarantined)
	}
	fr, e := hubRestoreReadForwardReceipt(path, a)
	if e != nil {
		return nil, e
	}
	if e = lease.validate(target); e != nil {
		return nil, e
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if _, e = os.Lstat(hubRestoreFailurePath(path, a.AuthorityEpoch+1)); !errors.Is(e, os.ErrNotExist) {
		return nil, ErrHubRestoreAuthorityUnproven
	}
	forwardBytes, e := hubRestoreReadPrivateFile(hubRestoreForwardReceiptPath(path, a))
	if e != nil {
		return nil, e
	}
	ar := &hubRestoreActivationReceipt{1, a.AuthorityID, a.AuthorityEpoch, a.AuthorityEpoch + 1, fr.TargetStorage, a.SourceStorage, hubRestoreHash(forwardBytes), a.BaseManifestSHA256, a.CapsuleManifestSHA256, fr.HoldSHA256, a.CoverageSHA256, a.UnknownSHA256}
	rp := hubRestoreActivationReceiptPath(path, ar.CommittedEpoch)
	if e = writePrivateJSON(rp, ar); e != nil {
		return nil, e
	}
	if e = syncDirectory(filepath.Dir(rp)); e != nil {
		return nil, e
	}
	receiptBytes, e := hubRestoreReadPrivateFile(rp)
	if e != nil {
		return nil, e
	}
	authorityBytes, e := hubRestoreReadPrivateFile(path)
	if e != nil {
		return nil, e
	}
	prior := *a
	next := *a
	next.State = "ACTIVE_TARGET"
	next.AuthorityEpoch = ar.CommittedEpoch
	next.TargetStorage = &fr.TargetStorage
	next.HoldSHA256 = fr.HoldSHA256
	next.ActivationReceiptSHA256 = hubRestoreHash(receiptBytes)
	next.PriorRecordSHA256 = hubRestoreHash(authorityBytes)
	// An after-rename failure must revoke the visible permit, too. The persistent
	// failure latch is checked before any constructor opens writable state. If
	// even fail-closed fencing cannot be written, retain both exclusive leases.
	e = hubRestoreWriteActivationAuthority(path, &next, hook)
	if e != nil {
		latchErr := writePrivateJSON(hubRestoreFailurePath(path, next.AuthorityEpoch), map[string]any{"format_version": 1, "authority_id": a.AuthorityID, "epoch": next.AuthorityEpoch, "state": "FAILED_ACTIVATION_HELD"})
		if latchErr == nil {
			latchErr = syncDirectory(filepath.Dir(path))
		}
		rollbackErr := hubRestoreWriteAtomic(path, &prior)
		if latchErr != nil || rollbackErr != nil {
			retainHubRestoreFailedActivationLeases(al, lease)
			release = false
		}
		return nil, fmt.Errorf("activation publication failed; held: %w", e)
	}
	return &HubRestoreActivationReport{&next, true, target, next.ActivationReceiptSHA256}, nil
}
func hubRestoreWriteActivationAuthority(path string, a *HubRestoreAuthority, hook hubRestoreActivationFault) error {
	// Same private writer, with a narrowly placed fault between actual rename
	// and actual directory fsync so the failure oracle tests a visible permit.
	b, e := hubRestoreEncodeAuthority(a)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".activation-partial-")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	if e = os.Rename(tmp, path); e != nil {
		return e
	}
	if hook != nil {
		if e = hook("authority_renamed_before_directory_sync"); e != nil {
			return e
		}
	}
	return syncDirectory(filepath.Dir(path))
}
func VerifyHubActivationReceipt(target, path string, a *HubRestoreAuthority) error {
	if _, e := os.Lstat(hubRestoreFailurePath(path, a.AuthorityEpoch)); !errors.Is(e, os.ErrNotExist) {
		return ErrHubRestoreAuthorityUnproven
	}
	var r hubRestoreActivationReceipt
	receiptBytes, e := hubRestoreReadJSON(hubRestoreActivationReceiptPath(path, a.AuthorityEpoch), &r)
	if e != nil {
		return ErrHubRestoreAuthorityUnproven
	}
	if r.FormatVersion != 1 || r.AuthorityID != a.AuthorityID || r.CommittedEpoch != a.AuthorityEpoch || r.ExpectedEpoch+1 != r.CommittedEpoch || r.TargetStorage != *a.TargetStorage || r.SourceStorage != a.SourceStorage || r.BaseManifestSHA256 != a.BaseManifestSHA256 || r.CapsuleManifestSHA256 != a.CapsuleManifestSHA256 || r.CoverageSHA256 != a.CoverageSHA256 || r.UnknownSHA256 != a.UnknownSHA256 || hubRestoreHash(receiptBytes) != a.ActivationReceiptSHA256 {
		return ErrHubRestoreAuthorityUnproven
	}
	prior := *a
	prior.AuthorityEpoch = r.ExpectedEpoch
	fr, e := hubRestoreReadForwardReceipt(path, &prior)
	forwardBytes, readErr := hubRestoreReadPrivateFile(hubRestoreForwardReceiptPath(path, &prior))
	if e != nil || readErr != nil || hubRestoreHash(forwardBytes) != r.ForwardReceiptSHA256 || fr.TargetStorage != r.TargetStorage || fr.HoldSHA256 != r.HoldSHA256 {
		return ErrHubRestoreAuthorityUnproven
	}
	hold, e := hubRestorePairedHold(target, a.BaseManifestSHA256)
	if e != nil || hubRestoreHash(hold) != r.HoldSHA256 || r.HoldSHA256 != a.HoldSHA256 {
		return ErrHubRestoreAuthorityUnproven
	}
	fps, e := hubRestoreIdentityFingerprints(target)
	if e != nil || hubRestoreDigest(fps) != hubRestoreDigest(a.TrustPin.IdentityFingerprints) {
		return ErrHubRestoreAuthorityUnproven
	}
	// No initial DB checksum here: legitimate counters and revocations advance.
	return nil
}

func hubRestoreEncodeAuthority(a *HubRestoreAuthority) ([]byte, error) {
	b, e := json.MarshalIndent(a, "", "  ")
	return append(b, '\n'), e
}

func hubRestoreSyncTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return ErrStateBackupPathUnsafe
		}
		if entry.IsDir() {
			i, e := os.Lstat(path)
			if e != nil || !stateRestorePrivateDirectory(i) {
				return ErrStateBackupPathUnsafe
			}
			return syncDirectory(path)
		}
		return nil
	})
}
