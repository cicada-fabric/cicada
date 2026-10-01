package nodebackup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	sharedWriterRootFormatVersion = 1
	sharedPayloadName             = "shared"
	sharedWriterRootMarkerName    = ".writer-root-recovery-pending.json"
	sharedBundleRecordName        = ".writer-root-restored-bundle.json"
	sharedWriterRootMaxFiles      = 50000
	sharedWriterRootMaxBytes      = int64(512 << 20)
)

var ErrSharedFencesUnavailable = errors.New("shared WriterRoot fencing state is missing or unavailable")

// SharedWriterRootManifest describes the durable Node-wide fences shared by
// Hub contexts. Paths are relative to WriterRoot; file bytes remain private
// in the archive payload and are never placed in the manifest.
type SharedWriterRootManifest struct {
	Version      int              `json:"version"`
	BundleSHA256 string           `json:"bundle_sha256"`
	Directories  []string         `json:"directories"`
	Files        []FileEntry      `json:"files"`
	Databases    []DatabaseEntry  `json:"databases"`
	Sidecars     []OmittedSidecar `json:"omitted_sqlite_sidecars,omitempty"`
}

type sharedWriterSnapshot struct {
	root      string
	inventory treeInventory
	dbPaths   []string
	databases map[string]DatabaseEntry
	snapshots map[string]*sqliteSnapshot
	omitted   map[string]struct{}
	manifest  SharedWriterRootManifest
	copyPaths []string
	closed    bool
}

type sharedWriterRecoveryMarker struct {
	Version              int    `json:"version"`
	Status               string `json:"status"`
	BundleSHA256         string `json:"bundle_sha256,omitempty"`
	BackupManifestSHA256 string `json:"backup_manifest_sha256"`
	NodeID               string `json:"node_id"`
	CreatedAt            string `json:"created_at"`
}

// captureSharedWriterRoot checkpoints each authoritative shared SQLite
// ledger while the caller holds WriterRoot's exclusive maintenance lock.
// Native writer epochs/operation files and physical-resource markers are
// copied under the same lock, giving one cross-Hub quiescent snapshot.
func captureSharedWriterRoot(root string) (*sharedWriterSnapshot, error) {
	root, err := canonicalPath(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("shared WriterRoot must be a real private directory")
	}
	if active, err := WriterRootRecoveryQuarantineActive(root); err != nil {
		return nil, err
	} else if active {
		return nil, ErrSharedFencesUnavailable
	}
	inventory, err := inventorySharedWriterRoot(root)
	if err != nil {
		return nil, err
	}
	dbPaths, err := discoverSQLiteFiles(root, inventory)
	if err != nil {
		return nil, err
	}
	for _, required := range []string{"node-provider-admission.sqlite3", "node-native-context-history.sqlite3"} {
		if !containsString(dbPaths, required) {
			return nil, fmt.Errorf("required shared WriterRoot database %s: %w", required, ErrSharedFencesUnavailable)
		}
	}
	snapshot := &sharedWriterSnapshot{root: root, inventory: inventory, dbPaths: dbPaths,
		databases: make(map[string]DatabaseEntry, len(dbPaths)), snapshots: make(map[string]*sqliteSnapshot, len(dbPaths))}
	cleanup := func(err error) (*sharedWriterSnapshot, error) {
		_ = snapshot.Close()
		return nil, err
	}
	for _, rel := range dbPaths {
		db, err := checkpointSQLite(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return cleanup(fmt.Errorf("checkpoint shared WriterRoot SQLite database %s: %w", rel, err))
		}
		snapshot.snapshots[rel] = db
		snapshot.databases[rel] = DatabaseEntry{Path: rel, SQLiteVersion: db.info.sqliteVersion,
			JournalMode: db.info.journalMode, Integrity: "ok"}
	}
	inventory, err = inventorySharedWriterRoot(root)
	if err != nil {
		return cleanup(err)
	}
	snapshot.inventory = inventory
	sidecars, err := validateCheckpointedSidecars(inventory, dbPaths)
	if err != nil {
		return cleanup(err)
	}
	copyPaths, omitted, err := filesForBackup(inventory, dbPaths)
	if err != nil {
		return cleanup(err)
	}
	snapshot.copyPaths, snapshot.omitted = copyPaths, omitted
	manifest := SharedWriterRootManifest{Version: sharedWriterRootFormatVersion,
		Directories: append([]string(nil), inventory.dirs...), Sidecars: sidecars}
	for _, rel := range dbPaths {
		manifest.Databases = append(manifest.Databases, snapshot.databases[rel])
	}
	snapshot.manifest = manifest
	return snapshot, nil
}

func (s *sharedWriterSnapshot) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	var result error
	for _, snapshot := range s.snapshots {
		result = errors.Join(result, snapshot.Close())
	}
	return result
}

func inventorySharedWriterRoot(root string) (treeInventory, error) {
	var out treeInventory
	for _, database := range []string{"node-provider-admission.sqlite3", "node-native-context-history.sqlite3"} {
		path := filepath.Join(root, database)
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return treeInventory{}, fmt.Errorf("required shared WriterRoot database %s: %w", database, ErrSharedFencesUnavailable)
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return treeInventory{}, fmt.Errorf("shared WriterRoot database %s is unsafe: %w", database, ErrUnsafeNodeFile)
		}
		out.files = append(out.files, diskEntry{path: database, mode: info.Mode().Perm(), info: info})
	}
	for _, rel := range []string{".native-writers", "nodes/.locks"} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if rel == "nodes/.locks" {
			parentInfo, parentErr := os.Lstat(filepath.Join(root, "nodes"))
			if parentErr == nil && (parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() || parentInfo.Mode().Perm()&0o077 != 0) {
				return treeInventory{}, fmt.Errorf("shared WriterRoot nodes directory is unsafe: %w", ErrUnsafeNodeFile)
			}
			if parentErr != nil && !errors.Is(parentErr, os.ErrNotExist) {
				return treeInventory{}, parentErr
			}
		}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return treeInventory{}, fmt.Errorf("shared WriterRoot directory %s is unsafe: %w", rel, ErrUnsafeNodeFile)
		}
		out.dirs = append(out.dirs, rel)
		if rel == "nodes/.locks" {
			out.dirs = append(out.dirs, "nodes")
		}
		tree, err := collectSharedTree(path)
		if err != nil {
			return treeInventory{}, fmt.Errorf("inventory shared WriterRoot directory %s: %w", rel, err)
		}
		for _, dir := range tree.dirs {
			out.dirs = append(out.dirs, filepath.ToSlash(filepath.Join(filepath.FromSlash(rel), filepath.FromSlash(dir))))
		}
		for _, entry := range tree.files {
			entry.path = filepath.ToSlash(filepath.Join(filepath.FromSlash(rel), filepath.FromSlash(entry.path)))
			out.files = append(out.files, entry)
		}
	}
	for _, db := range []string{"node-provider-admission.sqlite3", "node-native-context-history.sqlite3"} {
		for _, suffix := range []string{"-wal", "-shm", "-journal"} {
			rel := db + suffix
			path := filepath.Join(root, rel)
			info, err := os.Lstat(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
				return treeInventory{}, fmt.Errorf("shared WriterRoot SQLite sidecar %s is unsafe: %w", rel, ErrUnsafeNodeFile)
			}
			out.files = append(out.files, diskEntry{path: rel, mode: info.Mode().Perm(), info: info})
		}
	}
	for _, dir := range out.dirs {
		if !allowedSharedWriterPath(dir, true) {
			return treeInventory{}, fmt.Errorf("unexpected shared WriterRoot directory %s: %w", dir, ErrUnsafeNodeFile)
		}
	}
	for _, file := range out.files {
		if !allowedSharedWriterPath(file.path, false) {
			return treeInventory{}, fmt.Errorf("unexpected shared WriterRoot file %s: %w", file.path, ErrUnsafeNodeFile)
		}
	}
	sort.Strings(out.dirs)
	sort.Slice(out.files, func(i, j int) bool { return out.files[i].path < out.files[j].path })
	if len(out.files) > sharedWriterRootMaxFiles {
		return treeInventory{}, fmt.Errorf("shared WriterRoot has too many files: %w", ErrBackupInvalid)
	}
	return out, nil
}

func collectSharedTree(root string) (treeInventory, error) {
	var inventory treeInventory
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if err := validateRelativePath(rel); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeNamedPipe != 0 || info.Mode()&os.ModeDevice != 0 || info.Mode()&os.ModeSocket != 0 {
			return fmt.Errorf("unsafe shared WriterRoot entry %s: %w", rel, ErrUnsafeNodeFile)
		}
		if info.IsDir() {
			if info.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("shared WriterRoot directory %s is not private: %w", rel, ErrUnsafeNodeFile)
			}
			inventory.dirs = append(inventory.dirs, rel)
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("shared WriterRoot file %s is not private and regular: %w", rel, ErrUnsafeNodeFile)
		}
		// Flock files carry no durable ownership state. Recreate them only when
		// the live service next acquires its lock; never archive a fake lock.
		if strings.HasSuffix(filepath.Base(rel), ".lock") {
			return nil
		}
		inventory.files = append(inventory.files, diskEntry{path: rel, mode: info.Mode().Perm(), info: info})
		return nil
	})
	if err != nil {
		return treeInventory{}, err
	}
	sort.Strings(inventory.dirs)
	sort.Slice(inventory.files, func(i, j int) bool { return inventory.files[i].path < inventory.files[j].path })
	return inventory, nil
}

func writeSharedWriterSnapshot(snapshot *sharedWriterSnapshot, destination string) (SharedWriterRootManifest, error) {
	if snapshot == nil {
		return SharedWriterRootManifest{}, ErrSharedFencesUnavailable
	}
	rootInfo, err := os.Lstat(destination)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return SharedWriterRootManifest{}, errors.New("shared backup payload root is invalid")
	}
	for _, rel := range snapshot.inventory.dirs {
		if err := os.MkdirAll(filepath.Join(destination, filepath.FromSlash(rel)), privateDirMode); err != nil {
			return SharedWriterRootManifest{}, err
		}
	}
	manifest := snapshot.manifest
	manifest.Files = nil
	for _, rel := range snapshot.copyPaths {
		entry, err := copyPrivateFile(filepath.Join(snapshot.root, filepath.FromSlash(rel)), filepath.Join(destination, filepath.FromSlash(rel)))
		if err != nil {
			return SharedWriterRootManifest{}, fmt.Errorf("copy shared WriterRoot file %s: %w", rel, err)
		}
		entry.Path = rel
		manifest.Files = append(manifest.Files, entry)
	}
	for index := range manifest.Databases {
		db := &manifest.Databases[index]
		file, ok := fileEntryAt(manifest.Files, db.Path)
		if !ok {
			return SharedWriterRootManifest{}, fmt.Errorf("shared SQLite database %s was not copied", db.Path)
		}
		db.SHA256 = file.SHA256
		copyInfo, err := checkSQLite(filepath.Join(destination, filepath.FromSlash(db.Path)))
		if err != nil || copyInfo.integrity != "ok" || copyInfo.sqliteVersion != db.SQLiteVersion {
			return SharedWriterRootManifest{}, fmt.Errorf("verify copied shared SQLite database %s: %w", db.Path, ErrBackupInvalid)
		}
	}
	var total int64
	for _, entry := range manifest.Files {
		total += entry.Size
	}
	if len(manifest.Files) > sharedWriterRootMaxFiles || total > sharedWriterRootMaxBytes {
		return SharedWriterRootManifest{}, fmt.Errorf("shared WriterRoot exceeds archive bounds: %w", ErrBackupInvalid)
	}
	finalInventory, err := inventorySharedWriterRoot(snapshot.root)
	if err != nil || !sameTreePaths(snapshot.inventory, finalInventory) {
		return SharedWriterRootManifest{}, errors.New("shared WriterRoot inventory changed during backup")
	}
	for _, expected := range manifest.Files {
		digest, size, err := hashFile(filepath.Join(snapshot.root, filepath.FromSlash(expected.Path)))
		if err != nil || digest != expected.SHA256 || size != expected.Size {
			return SharedWriterRootManifest{}, fmt.Errorf("shared WriterRoot file %s changed during backup", expected.Path)
		}
	}
	manifest.BundleSHA256 = digestSharedWriterRoot(manifest)
	return manifest, nil
}

func digestSharedWriterRoot(manifest SharedWriterRootManifest) string {
	manifest.BundleSHA256 = ""
	data, _ := json.Marshal(manifest)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validateSharedWriterRootManifest(manifest *SharedWriterRootManifest) error {
	if manifest == nil || manifest.Version != sharedWriterRootFormatVersion || !validSHA256(manifest.BundleSHA256) ||
		manifest.BundleSHA256 != digestSharedWriterRoot(*manifest) || len(manifest.Files) > sharedWriterRootMaxFiles {
		return ErrBackupInvalid
	}
	for i, dir := range manifest.Directories {
		if !allowedSharedWriterPath(dir, true) || (i > 0 && manifest.Directories[i-1] >= dir) {
			return ErrBackupInvalid
		}
	}
	var total int64
	for i, file := range manifest.Files {
		if !allowedSharedWriterPath(file.Path, false) || file.Size < 0 || file.Mode != uint32(privateFileMode.Perm()) ||
			!validSHA256(file.SHA256) || (i > 0 && manifest.Files[i-1].Path >= file.Path) {
			return ErrBackupInvalid
		}
		total += file.Size
	}
	if total > sharedWriterRootMaxBytes {
		return ErrBackupInvalid
	}
	seen := map[string]bool{}
	for i, db := range manifest.Databases {
		if !allowedSharedWriterPath(db.Path, false) || db.SQLiteVersion == "" || db.Integrity != "ok" ||
			!validSHA256(db.SHA256) || (i > 0 && manifest.Databases[i-1].Path >= db.Path) {
			return ErrBackupInvalid
		}
		file, ok := fileEntryAt(manifest.Files, db.Path)
		if !ok || file.SHA256 != db.SHA256 {
			return ErrBackupInvalid
		}
		seen[db.Path] = true
	}
	if !seen["node-provider-admission.sqlite3"] || !seen["node-native-context-history.sqlite3"] {
		return fmt.Errorf("shared WriterRoot archive omits required fences: %w", ErrBackupInvalid)
	}
	for i, sidecar := range manifest.Sidecars {
		if !allowedSharedWriterPath(sidecar.Path, false) || !isSQLiteSidecar(sidecar.Path) || sidecar.Reason == "" ||
			(i > 0 && manifest.Sidecars[i-1].Path >= sidecar.Path) {
			return ErrBackupInvalid
		}
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(sidecar.Path, "-wal"), "-shm"), "-journal")
		if !seen[base] || strings.HasSuffix(sidecar.Path, "-journal") ||
			strings.HasSuffix(sidecar.Path, "-wal") && sidecar.Reason != "empty_after_checkpoint" ||
			strings.HasSuffix(sidecar.Path, "-shm") && sidecar.Reason != "reconstructible_after_checkpoint" {
			return ErrBackupInvalid
		}
	}
	if err := validateSharedPathRelationships(manifest); err != nil {
		return err
	}
	return nil
}

func allowedSharedWriterPath(path string, directory bool) bool {
	if validateRelativePath(path) != nil {
		return false
	}
	if isSQLiteSidecar(path) && !directory {
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(path, "-wal"), "-shm"), "-journal")
		if base == "node-provider-admission.sqlite3" || base == "node-native-context-history.sqlite3" {
			return true
		}
	}
	if path == "node-provider-admission.sqlite3" || path == "node-native-context-history.sqlite3" {
		return !directory
	}
	if directory {
		if path == "nodes" || path == "nodes/.locks" || path == ".native-writers" {
			return true
		}
		if strings.HasPrefix(path, ".native-writers/") && strings.HasSuffix(path, ".lock.operations") {
			return validHexDigest(strings.TrimSuffix(strings.TrimPrefix(path, ".native-writers/"), ".lock.operations"))
		}
		return false
	}
	if strings.HasPrefix(path, ".native-writers/") {
		rel := strings.TrimPrefix(path, ".native-writers/")
		if strings.HasSuffix(rel, ".lock.epoch") {
			return validHexDigest(strings.TrimSuffix(rel, ".lock.epoch"))
		}
		parts := strings.Split(rel, "/")
		return len(parts) == 2 && strings.HasSuffix(parts[0], ".lock.operations") &&
			validHexDigest(strings.TrimSuffix(parts[0], ".lock.operations")) && strings.HasSuffix(parts[1], ".json") &&
			validHexDigest(strings.TrimSuffix(parts[1], ".json"))
	}
	if strings.HasPrefix(path, "nodes/.locks/resource-") && strings.HasSuffix(path, ".execution.json") {
		return validHexDigest(strings.TrimSuffix(strings.TrimPrefix(path, "nodes/.locks/resource-"), ".execution.json"))
	}
	return false
}

func validHexDigest(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validateSharedPathRelationships(manifest *SharedWriterRootManifest) error {
	dirs := map[string]bool{}
	files := map[string]bool{}
	for _, dir := range manifest.Directories {
		dirs[dir] = true
	}
	for _, file := range manifest.Files {
		files[file.Path] = true
		for parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(file.Path))); parent != "."; parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(parent))) {
			if !dirs[parent] {
				return ErrBackupInvalid
			}
		}
	}
	for _, dir := range manifest.Directories {
		if files[dir] {
			return ErrBackupInvalid
		}
		for parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(dir))); parent != "."; parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(parent))) {
			if !dirs[parent] {
				return ErrBackupInvalid
			}
		}
	}
	return nil
}

func verifySharedPayload(root string, manifest *SharedWriterRootManifest) error {
	if err := validateSharedWriterRootManifest(manifest); err != nil {
		return err
	}
	if err := verifyPayloadInventory(root, &Manifest{FormatVersion: FormatVersion,
		Complete: true, NodeID: "shared-validation-node", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Directories: manifest.Directories, Files: manifest.Files, Databases: manifest.Databases, Sidecars: manifest.Sidecars}); err != nil {
		return err
	}
	return nil
}

func containsString(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}

// WriterRootRecoveryQuarantineActive reports whether a restored common root
// is pending fencing-state verification. Malformed marker files also hold the
// root closed.
func WriterRootRecoveryQuarantineActive(writerRoot string) (bool, error) {
	root, err := canonicalPath(writerRoot)
	if err != nil {
		return false, err
	}
	path := filepath.Join(root, sharedWriterRootMarkerName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != privateFileMode.Perm() || info.Size() > 16*1024 {
		return true, ErrBackupInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return true, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var marker sharedWriterRecoveryMarker
	if err := decoder.Decode(&marker); err != nil {
		return true, ErrBackupInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || marker.Version != 1 ||
		(marker.Status != "pending" && marker.Status != "shared_fences_missing") ||
		!validSHA256(marker.BackupManifestSHA256) || marker.NodeID == "" {
		return true, ErrBackupInvalid
	}
	if marker.Status == "pending" && !validSHA256(marker.BundleSHA256) ||
		marker.Status == "shared_fences_missing" && marker.BundleSHA256 != "" {
		return true, ErrBackupInvalid
	}
	if _, err := time.Parse(time.RFC3339Nano, marker.CreatedAt); err != nil {
		return true, ErrBackupInvalid
	}
	return true, nil
}

// installSharedWriterRoot installs a verified archive's fence subset without
// replacing pre-existing WriterRoot state. Its durable marker is written
// before the first file so crashes leave every Hub fail-closed.
func installSharedWriterRoot(writerRoot, backupDir string, manifest *Manifest) error {
	rootInfo, err := os.Lstat(writerRoot)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || rootInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("shared WriterRoot restore target must be a real private directory")
	}
	backupDigest := digestManifest(*manifest)
	markerPath := filepath.Join(writerRoot, sharedWriterRootMarkerName)
	marker, exists, err := readSharedWriterRecoveryMarker(markerPath)
	if err != nil {
		return err
	}
	if manifest.FormatVersion != CurrentFormatVersion || manifest.SharedWriterRoot == nil {
		if exists {
			if marker.Status == "shared_fences_missing" && marker.BackupManifestSHA256 == backupDigest {
				return nil
			}
			return fmt.Errorf("WriterRoot already has a different recovery quarantine: %w", ErrRestoreTargetBusy)
		}
		present, err := sharedFencePathsPresent(writerRoot)
		if err != nil {
			return err
		}
		if present {
			return fmt.Errorf("legacy archive cannot establish shared WriterRoot fencing history: %w", ErrSharedFencesUnavailable)
		}
		marker = sharedWriterRecoveryMarker{Version: 1, Status: "shared_fences_missing",
			BackupManifestSHA256: backupDigest, NodeID: manifest.NodeID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		return createSharedWriterRecoveryMarker(markerPath, marker)
	}
	shared := manifest.SharedWriterRoot
	if err := validateSharedWriterRootManifest(shared); err != nil {
		return err
	}
	if exists {
		if marker.Status != "pending" || marker.BundleSHA256 != shared.BundleSHA256 {
			return fmt.Errorf("WriterRoot is quarantined for another or incomplete fence bundle: %w", ErrRestoreTargetBusy)
		}
	} else {
		present, err := sharedFencePathsPresent(writerRoot)
		if err != nil {
			return err
		}
		if present {
			return fmt.Errorf("WriterRoot has existing shared state without a matching recovery record: %w", ErrRestoreTargetBusy)
		}
		marker = sharedWriterRecoveryMarker{Version: 1, Status: "pending", BundleSHA256: shared.BundleSHA256,
			BackupManifestSHA256: backupDigest, NodeID: manifest.NodeID, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
		if err := createSharedWriterRecoveryMarker(markerPath, marker); err != nil {
			return err
		}
	}
	if err := installSharedPayload(filepath.Join(backupDir, sharedPayloadName), shared, writerRoot); err != nil {
		return err
	}
	if err := syncTreeDirectories(writerRoot, shared.Directories); err != nil {
		return fmt.Errorf("sync restored shared WriterRoot directories: %w", err)
	}
	if err := syncDirectory(writerRoot); err != nil {
		return fmt.Errorf("sync restored shared WriterRoot: %w", err)
	}
	if err := sharedRootMatchesManifest(writerRoot, shared); err != nil {
		return fmt.Errorf("restored shared WriterRoot does not match verified bundle: %w", err)
	}
	return nil
}

func readSharedWriterRecoveryMarker(path string) (sharedWriterRecoveryMarker, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return sharedWriterRecoveryMarker{}, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != privateFileMode.Perm() || info.Size() > 16*1024 {
		return sharedWriterRecoveryMarker{}, true, ErrBackupInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return sharedWriterRecoveryMarker{}, true, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var marker sharedWriterRecoveryMarker
	if err := decoder.Decode(&marker); err != nil {
		return sharedWriterRecoveryMarker{}, true, ErrBackupInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || marker.Version != 1 || marker.NodeID == "" ||
		(marker.Status != "pending" && marker.Status != "shared_fences_missing") || !validSHA256(marker.BackupManifestSHA256) {
		return sharedWriterRecoveryMarker{}, true, ErrBackupInvalid
	}
	if marker.Status == "pending" && !validSHA256(marker.BundleSHA256) ||
		marker.Status == "shared_fences_missing" && marker.BundleSHA256 != "" {
		return sharedWriterRecoveryMarker{}, true, ErrBackupInvalid
	}
	if _, err := time.Parse(time.RFC3339Nano, marker.CreatedAt); err != nil {
		return sharedWriterRecoveryMarker{}, true, ErrBackupInvalid
	}
	return marker, true, nil
}

func createSharedWriterRecoveryMarker(path string, marker sharedWriterRecoveryMarker) error {
	if err := writePrivateJSON(path, marker); err != nil {
		return fmt.Errorf("write shared WriterRoot recovery quarantine: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func sharedFencePathsPresent(root string) (bool, error) {
	for _, rel := range []string{"node-provider-admission.sqlite3", "node-native-context-history.sqlite3",
		"node-provider-admission.sqlite3-wal", "node-provider-admission.sqlite3-shm", "node-provider-admission.sqlite3-journal",
		"node-native-context-history.sqlite3-wal", "node-native-context-history.sqlite3-shm", "node-native-context-history.sqlite3-journal"} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel))); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
	}
	for _, rel := range []string{".native-writers", "nodes/.locks"} {
		path := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
			return false, fmt.Errorf("shared WriterRoot lock directory %s is unsafe: %w", rel, ErrUnsafeNodeFile)
		}
		// Node maintenance/Agent/resource lock files are ephemeral flock state.
		// Their presence is expected while this restore holds the per-Node lock,
		// and copying them would falsely restore live lock ownership. Any other
		// regular file is durable fence state or unknown state and blocks replace.
		durable, err := sharedFenceDirectoryHasDurableState(path, rel)
		if err != nil {
			return false, err
		}
		if durable {
			return true, nil
		}
	}
	return false, nil
}

func sharedFenceDirectoryHasDurableState(root, relativeRoot string) (bool, error) {
	durable := false
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeNamedPipe != 0 || info.Mode()&os.ModeDevice != 0 || info.Mode()&os.ModeSocket != 0 {
			return fmt.Errorf("unsafe shared WriterRoot lock entry: %w", ErrUnsafeNodeFile)
		}
		if info.IsDir() {
			if info.Mode().Perm()&0o077 != 0 {
				return fmt.Errorf("shared WriterRoot lock subdirectory is not private: %w", ErrUnsafeNodeFile)
			}
			// Only the two top-level directories can be created by a transient
			// lock acquisition. Any nested directory is either durable operation
			// history or unknown state and therefore blocks a fresh restore.
			durable = true
			return nil
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("shared WriterRoot lock entry is not a private regular file: %w", ErrUnsafeNodeFile)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if !isTransientSharedLock(filepath.ToSlash(filepath.Join(filepath.FromSlash(relativeRoot), filepath.FromSlash(rel)))) {
			durable = true
		}
		return nil
	})
	return durable, err
}

func isTransientSharedLock(path string) bool {
	base := filepath.Base(filepath.FromSlash(path))
	switch {
	case strings.HasPrefix(path, ".native-writers/"):
		return strings.HasSuffix(base, ".lock") && validHexDigest(strings.TrimSuffix(base, ".lock"))
	case strings.HasPrefix(path, "nodes/.locks/"):
		if strings.HasPrefix(base, "node-") && (strings.HasSuffix(base, ".maintenance.lock") || strings.HasSuffix(base, ".agent.lock")) {
			return !strings.ContainsAny(base, "/\\\x00\r\n")
		}
		if strings.HasPrefix(base, "resource-") && strings.HasSuffix(base, ".execution.lock") {
			return validHexDigest(strings.TrimSuffix(strings.TrimPrefix(base, "resource-"), ".execution.lock"))
		}
	}
	return false
}

func installSharedPayload(source string, manifest *SharedWriterRootManifest, writerRoot string) error {
	for _, rel := range manifest.Directories {
		if err := ensureSharedPrivateDirectory(writerRoot, rel); err != nil {
			return err
		}
	}
	for _, entry := range manifest.Files {
		destination := filepath.Join(writerRoot, filepath.FromSlash(entry.Path))
		if info, err := os.Lstat(destination); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != privateFileMode.Perm() {
				return fmt.Errorf("existing shared fence %s is unsafe: %w", entry.Path, ErrRestoreTargetBusy)
			}
			digest, size, hashErr := hashFile(destination)
			if hashErr != nil || digest != entry.SHA256 || size != entry.Size {
				return fmt.Errorf("existing shared fence %s differs from archive: %w", entry.Path, ErrRestoreTargetBusy)
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(entry.Path)))
		if parent != "." {
			if err := ensureSharedPrivateDirectory(writerRoot, parent); err != nil {
				return err
			}
		}
		if err := copyVerifiedFile(filepath.Join(source, filepath.FromSlash(entry.Path)), destination, entry); err != nil {
			return fmt.Errorf("restore shared WriterRoot fence %s: %w", entry.Path, err)
		}
	}
	return nil
}

func ensureSharedPrivateDirectory(root, relative string) error {
	if !allowedSharedWriterPath(relative, true) {
		return ErrBackupInvalid
	}
	current := root
	for _, part := range strings.Split(filepath.FromSlash(relative), string(filepath.Separator)) {
		current = filepath.Join(current, part)
		if err := os.Mkdir(current, privateDirMode); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != privateDirMode.Perm() {
			return fmt.Errorf("shared WriterRoot directory %s is unsafe: %w", relative, ErrRestoreTargetBusy)
		}
	}
	return nil
}

func sharedWriterBundleRecordPath(writerRoot string) string {
	return filepath.Join(writerRoot, sharedBundleRecordName)
}

func sharedRootMatchesManifest(writerRoot string, manifest *SharedWriterRootManifest) error {
	if err := validateSharedWriterRootManifest(manifest); err != nil {
		return err
	}
	actual, err := inventorySharedWriterRoot(writerRoot)
	if err != nil {
		return err
	}
	mainFiles := make([]diskEntry, 0, len(actual.files))
	for _, file := range actual.files {
		if !isSQLiteSidecar(file.path) {
			mainFiles = append(mainFiles, file)
		}
	}
	databasePaths, err := discoverSQLiteFiles(writerRoot, actual)
	if err != nil {
		return err
	}
	if _, err := validateCheckpointedSidecars(actual, databasePaths); err != nil {
		return err
	}
	if !sameStrings(actual.dirs, manifest.Directories) {
		return fmt.Errorf("shared WriterRoot directory inventory differs: got %v want %v: %w", actual.dirs, manifest.Directories, ErrBackupInvalid)
	}
	if len(mainFiles) != len(manifest.Files) {
		return fmt.Errorf("shared WriterRoot file count differs: got %d want %d: %w", len(mainFiles), len(manifest.Files), ErrBackupInvalid)
	}
	for i, file := range mainFiles {
		expected := manifest.Files[i]
		if file.path != expected.Path || file.info.Size() != expected.Size || file.info.Mode().Perm() != privateFileMode.Perm() {
			return fmt.Errorf("shared WriterRoot file metadata differs at %s: %w", expected.Path, ErrBackupInvalid)
		}
		digest, size, err := hashFile(filepath.Join(writerRoot, filepath.FromSlash(file.path)))
		if err != nil || digest != expected.SHA256 || size != expected.Size {
			return fmt.Errorf("shared WriterRoot file digest differs at %s: %w", expected.Path, ErrBackupInvalid)
		}
	}
	for _, database := range manifest.Databases {
		info, err := checkSQLite(filepath.Join(writerRoot, filepath.FromSlash(database.Path)))
		if err != nil || info.integrity != "ok" || info.sqliteVersion != database.SQLiteVersion {
			return fmt.Errorf("shared SQLite metadata differs at %s: got %#v err=%v want %#v: %w", database.Path, info, err, database, ErrBackupInvalid)
		}
	}
	return nil
}
