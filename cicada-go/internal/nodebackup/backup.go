// Package nodebackup provides a private, offline copy of one Node-owned state
// subtree. It deliberately does not include the Hub StateDir or files stored
// beside the Node subtree, such as MCP session/outbox state and native Codex
// records. A successful restore is quarantined until a separate reconciliation
// step confirms binding epochs, crypto counters, and uncertain native work.
package nodebackup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/nodelock"
	_ "modernc.org/sqlite"
)

const (
	FormatVersion   = 1
	manifestName    = "manifest.json"
	payloadName     = "payload"
	recoveryMarker  = "recovery-pending.json"
	privateFileMode = os.FileMode(0o600)
	privateDirMode  = os.FileMode(0o700)
	maxManifestSize = 8 << 20
)

var (
	ErrBusy              = nodelock.ErrBusy
	ErrBackupExists      = errors.New("Node backup destination already exists")
	ErrBackupInvalid     = errors.New("Node backup is incomplete or invalid")
	ErrNodeStateMissing  = errors.New("Node state subtree does not exist")
	ErrRestoreTargetBusy = errors.New("Node restore target is not new or empty")
	ErrUnsafeNodeFile    = errors.New("Node state contains an unsafe file type or path")
)

// Manifest contains only recovery metadata. File contents, key material,
// credentials, ciphertext, and message data are never serialized here.
type Manifest struct {
	FormatVersion    int                   `json:"format_version"`
	Complete         bool                  `json:"complete"`
	NodeID           string                `json:"node_id"`
	CreatedAt        string                `json:"created_at"`
	Directories      []string              `json:"directories"`
	Files            []FileEntry           `json:"files"`
	Databases        []DatabaseEntry       `json:"databases"`
	Sidecars         []OmittedSidecar      `json:"omitted_sqlite_sidecars,omitempty"`
	RuntimeOmissions []OmittedRuntimeEntry `json:"omitted_runtime_entries,omitempty"`
}

// FileEntry describes one copied file. File bytes are always stored with
// owner-only permissions, regardless of the source mode.
type FileEntry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

// DatabaseEntry records integrity metadata for a checkpointed SQLite file.
type DatabaseEntry struct {
	Path          string `json:"path"`
	SQLiteVersion string `json:"sqlite_version"`
	JournalMode   string `json:"journal_mode"`
	Integrity     string `json:"integrity_check"`
	SHA256        string `json:"sha256"`
}

// OmittedSidecar records a transient SQLite file omitted after a successful
// checkpoint. WAL content is never omitted unless SQLite reports it fully
// checkpointed and the WAL is absent or empty.
type OmittedSidecar struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type OmittedRuntimeEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Reason string `json:"reason"`
}

type BackupReport struct {
	BackupDir string   `json:"backup_dir"`
	Manifest  Manifest `json:"manifest"`
}

type RestoreReport struct {
	NodeID      string   `json:"node_id"`
	NodeState   string   `json:"node_state_dir"`
	Quarantined bool     `json:"quarantined"`
	Manifest    Manifest `json:"manifest"`
}

type diskEntry struct {
	path string
	mode os.FileMode
	info os.FileInfo
}

// Backup creates and atomically publishes a private backup of one Node
// subtree. The Node maintenance lock covers SQLite checkpointing and every
// copied file so Agent and direct Node writers cannot split the snapshot.
func Backup(stateDir, nodeID, destinationDir string) (_ *BackupReport, retErr error) {
	stateRoot, err := canonicalPath(stateDir)
	if err != nil {
		return nil, err
	}
	nodeID = strings.TrimSpace(nodeID)
	if err := validateNodeID(nodeID); err != nil {
		return nil, err
	}
	destinationDir, err = canonicalPath(destinationDir)
	if err != nil {
		return nil, err
	}
	nodeDir := nodeStatePath(stateRoot, nodeID)
	if pathWithin(nodeDir, destinationDir) {
		return nil, errors.New("Node backup destination must be outside the Node state subtree")
	}
	lock, err := nodelock.AcquireMaintenanceExclusive(stateRoot, nodeID)
	if err != nil {
		if errors.Is(err, nodelock.ErrBusy) {
			return nil, fmt.Errorf("Node %q is busy: %w", nodeID, err)
		}
		return nil, fmt.Errorf("acquire exclusive Node maintenance lock: %w", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release Node maintenance lock: %w", closeErr))
		}
	}()
	if err := verifyNodeStateDirectory(stateRoot, nodeDir); err != nil {
		return nil, err
	}
	if err := ensureDestinationIsNew(destinationDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(destinationDir), privateDirMode); err != nil {
		return nil, fmt.Errorf("create backup parent: %w", err)
	}

	initial, err := inventoryNodeTree(nodeDir)
	if err != nil {
		return nil, err
	}
	databasePaths, err := discoverSQLiteFiles(nodeDir, initial)
	if err != nil {
		return nil, err
	}
	checkpointed := make(map[string]DatabaseEntry, len(databasePaths))
	snapshots := make(map[string]*sqliteSnapshot, len(databasePaths))
	defer func() {
		for _, snapshot := range snapshots {
			if closeErr := snapshot.Close(); closeErr != nil {
				retErr = errors.Join(retErr, closeErr)
			}
		}
	}()
	for _, rel := range databasePaths {
		snapshot, err := checkpointSQLite(filepath.Join(nodeDir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("checkpoint Node SQLite database %s: %w", rel, err)
		}
		snapshots[rel] = snapshot
		checkpointed[rel] = DatabaseEntry{Path: rel, SQLiteVersion: snapshot.info.sqliteVersion,
			JournalMode: snapshot.info.journalMode, Integrity: "ok"}
	}

	entries, err := inventoryNodeTree(nodeDir)
	if err != nil {
		return nil, err
	}
	sidecars, err := validateCheckpointedSidecars(entries, databasePaths)
	if err != nil {
		return nil, err
	}
	copyEntries, omittedPaths, err := filesForBackup(entries, databasePaths)
	if err != nil {
		return nil, err
	}
	if len(copyEntries) == 0 && len(entries.dirs) == 0 {
		return nil, errors.New("Node state subtree is empty")
	}

	temporary, err := os.MkdirTemp(filepath.Dir(destinationDir), filepath.Base(destinationDir)+".partial-")
	if err != nil {
		return nil, fmt.Errorf("create private backup staging directory: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, privateDirMode); err != nil {
		return nil, fmt.Errorf("protect backup staging directory: %w", err)
	}
	payloadRoot := filepath.Join(temporary, payloadName)
	if err := os.Mkdir(payloadRoot, privateDirMode); err != nil {
		return nil, fmt.Errorf("create backup payload directory: %w", err)
	}
	for _, rel := range entries.dirs {
		if err := os.MkdirAll(filepath.Join(payloadRoot, filepath.FromSlash(rel)), privateDirMode); err != nil {
			return nil, fmt.Errorf("create backup directory %s: %w", rel, err)
		}
	}

	manifest := Manifest{FormatVersion: FormatVersion, Complete: true, NodeID: nodeID,
		CreatedAt:   time.Now().UTC().Format(time.RFC3339Nano),
		Directories: append([]string(nil), entries.dirs...),
		Sidecars:    sidecars, RuntimeOmissions: append([]OmittedRuntimeEntry(nil), entries.runtime...)}
	for _, rel := range copyEntries {
		destination := filepath.Join(payloadRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(destination), privateDirMode); err != nil {
			return nil, fmt.Errorf("create backup parent for %s: %w", rel, err)
		}
		entry, err := copyPrivateFile(filepath.Join(nodeDir, filepath.FromSlash(rel)), destination)
		if err != nil {
			return nil, fmt.Errorf("copy Node state file %s: %w", rel, err)
		}
		entry.Path = rel
		manifest.Files = append(manifest.Files, entry)
	}
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Path < manifest.Files[j].Path })
	for _, rel := range databasePaths {
		if _, omitted := omittedPaths[rel]; omitted {
			continue
		}
		database := checkpointed[rel]
		file, ok := fileEntryAt(manifest.Files, rel)
		if !ok {
			return nil, fmt.Errorf("SQLite database %s was not copied", rel)
		}
		database.SHA256 = file.SHA256
		sourceDigest, sourceSize, err := hashFile(filepath.Join(nodeDir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("recheck source SQLite database %s: %w", rel, err)
		}
		if sourceDigest != file.SHA256 || sourceSize != file.Size {
			return nil, fmt.Errorf("SQLite database %s changed during backup", rel)
		}
		copiedInfo, err := checkSQLite(filepath.Join(payloadRoot, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("verify copied SQLite database %s: %w", rel, err)
		}
		if copiedInfo.integrity != "ok" || copiedInfo.sqliteVersion != database.SQLiteVersion {
			return nil, fmt.Errorf("copied SQLite database %s metadata mismatch: source version=%s journal=%s integrity=%s; copy version=%s journal=%s integrity=%s",
				rel, database.SQLiteVersion, database.JournalMode, database.Integrity,
				copiedInfo.sqliteVersion, copiedInfo.journalMode, copiedInfo.integrity)
		}
		manifest.Databases = append(manifest.Databases, database)
	}
	sort.Slice(manifest.Databases, func(i, j int) bool { return manifest.Databases[i].Path < manifest.Databases[j].Path })
	if err := validateTreeMatch(entries, manifest.Files, manifest.Directories, omittedPaths, manifest.RuntimeOmissions); err != nil {
		return nil, fmt.Errorf("Node state changed during backup: %w", err)
	}
	finalInventory, err := inventoryNodeTree(nodeDir)
	if err != nil {
		return nil, fmt.Errorf("recheck Node state inventory before publishing: %w", err)
	}
	if !sameTreePaths(entries, finalInventory) {
		return nil, errors.New("Node state inventory changed during backup")
	}
	for _, expected := range manifest.Files {
		digest, size, err := hashFile(filepath.Join(nodeDir, filepath.FromSlash(expected.Path)))
		if err != nil {
			return nil, fmt.Errorf("recheck source Node file %s: %w", expected.Path, err)
		}
		if digest != expected.SHA256 || size != expected.Size {
			return nil, fmt.Errorf("Node state file %s changed during backup", expected.Path)
		}
	}
	if err := writePrivateJSON(filepath.Join(temporary, manifestName), manifest); err != nil {
		return nil, fmt.Errorf("write Node backup manifest: %w", err)
	}
	if err := syncTreeDirectories(payloadRoot, manifest.Directories); err != nil {
		return nil, fmt.Errorf("sync Node backup payload: %w", err)
	}
	if err := syncDirectory(temporary); err != nil {
		return nil, fmt.Errorf("sync Node backup staging directory: %w", err)
	}
	if err := publishNewDirectory(temporary, destinationDir); err != nil {
		return nil, err
	}
	published = true
	return &BackupReport{BackupDir: destinationDir, Manifest: manifest}, nil
}

// Verify checks the private manifest, exact payload inventory, per-file
// SHA-256 hashes, and integrity of every SQLite database listed in the
// manifest. It is read-only and does not need a live Node lock.
func Verify(backupDir string) (*Manifest, error) {
	backupDir, err := canonicalPath(backupDir)
	if err != nil {
		return nil, err
	}
	if err := verifyPrivateDirectory(backupDir); err != nil {
		return nil, fmt.Errorf("inspect Node backup directory: %w", err)
	}
	manifestPath := filepath.Join(backupDir, manifestName)
	manifest, err := readManifest(manifestPath)
	if err != nil {
		return nil, err
	}
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	rootEntries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil, fmt.Errorf("inspect Node backup contents: %w", err)
	}
	if len(rootEntries) != 2 || rootEntries[0].Name() != manifestName || rootEntries[1].Name() != payloadName {
		return nil, ErrBackupInvalid
	}
	payloadRoot := filepath.Join(backupDir, payloadName)
	if err := verifyPrivateDirectory(payloadRoot); err != nil {
		return nil, fmt.Errorf("inspect Node backup payload: %w", err)
	}
	if err := verifyPayloadInventory(payloadRoot, manifest); err != nil {
		return nil, err
	}
	for i, database := range manifest.Databases {
		if i > 0 && manifest.Databases[i-1].Path >= database.Path {
			return nil, ErrBackupInvalid
		}
	}
	for _, database := range manifest.Databases {
		info, err := checkSQLite(filepath.Join(payloadRoot, filepath.FromSlash(database.Path)))
		if err != nil {
			return nil, fmt.Errorf("verify SQLite database %s: %w", database.Path, err)
		}
		entry, _ := fileEntryAt(manifest.Files, database.Path)
		if info.integrity != database.Integrity || info.integrity != "ok" ||
			info.sqliteVersion != database.SQLiteVersion || entry.SHA256 != database.SHA256 {
			return nil, fmt.Errorf("SQLite metadata mismatch for %s: %w", database.Path, ErrBackupInvalid)
		}
	}
	return manifest, nil
}

// Restore verifies a backup, copies it into a new/empty Node subtree, writes
// a recovery-pending marker, verifies the staged databases, and atomically
// publishes the quarantined subtree under the target StateDir.
func Restore(backupDir, targetStateDir string) (_ *RestoreReport, retErr error) {
	return restoreWithPublisher(backupDir, targetStateDir, publishRestoreDirectory)
}

// restoreWithPublisher keeps the filesystem publication boundary injectable so
// tests can exercise failures after the recovery registry has been created.
func restoreWithPublisher(backupDir, targetStateDir string,
	publish func(source, destination string) (bool, error)) (_ *RestoreReport, retErr error) {
	if publish == nil {
		return nil, errors.New("Node restore publisher is required")
	}
	backupDir, err := canonicalPath(backupDir)
	if err != nil {
		return nil, err
	}
	manifest, err := Verify(backupDir)
	if err != nil {
		return nil, err
	}
	stateRoot, err := canonicalPath(targetStateDir)
	if err != nil {
		return nil, err
	}
	nodeDir := nodeStatePath(stateRoot, manifest.NodeID)
	if pathWithin(backupDir, nodeDir) || pathWithin(nodeDir, backupDir) {
		return nil, errors.New("Node restore target must be outside the backup directory")
	}
	lock, err := nodelock.AcquireMaintenanceExclusive(stateRoot, manifest.NodeID)
	if err != nil {
		if errors.Is(err, nodelock.ErrBusy) {
			return nil, fmt.Errorf("Node %q is busy: %w", manifest.NodeID, err)
		}
		return nil, fmt.Errorf("acquire exclusive Node maintenance lock: %w", err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("release Node maintenance lock: %w", closeErr))
		}
	}()

	if err := ensureRestoreTargetNewOrEmpty(nodeDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(nodeDir), privateDirMode); err != nil {
		return nil, fmt.Errorf("create Node restore parent: %w", err)
	}
	staging, err := os.MkdirTemp(filepath.Dir(nodeDir), filepath.Base(nodeDir)+".restore-")
	if err != nil {
		return nil, fmt.Errorf("create private Node restore staging directory: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(staging)
		}
	}()
	if err := os.Chmod(staging, privateDirMode); err != nil {
		return nil, fmt.Errorf("protect Node restore staging directory: %w", err)
	}
	for _, rel := range manifest.Directories {
		if err := os.MkdirAll(filepath.Join(staging, filepath.FromSlash(rel)), privateDirMode); err != nil {
			return nil, fmt.Errorf("create restored Node directory %s: %w", rel, err)
		}
	}
	payloadRoot := filepath.Join(backupDir, payloadName)
	for _, entry := range manifest.Files {
		if err := validateRelativePath(entry.Path); err != nil {
			return nil, err
		}
		destination := filepath.Join(staging, filepath.FromSlash(entry.Path))
		if err := os.MkdirAll(filepath.Dir(destination), privateDirMode); err != nil {
			return nil, fmt.Errorf("create restored Node parent for %s: %w", entry.Path, err)
		}
		if err := copyVerifiedFile(filepath.Join(payloadRoot, filepath.FromSlash(entry.Path)), destination, entry); err != nil {
			return nil, fmt.Errorf("restore Node state file %s: %w", entry.Path, err)
		}
	}
	if _, ok := fileEntryAt(manifest.Files, recoveryMarker); ok {
		if err := os.Remove(filepath.Join(staging, recoveryMarker)); err != nil {
			return nil, fmt.Errorf("replace prior recovery marker: %w", err)
		}
	}
	for _, rel := range manifest.Directories {
		if rel == recoveryMarker {
			return nil, errors.New("backup uses the reserved recovery marker path as a directory")
		}
	}
	marker, err := json.MarshalIndent(recoveryPendingManifest{Version: 1, NodeID: manifest.NodeID,
		Status: "pending", BackupManifestSHA256: digestManifest(*manifest),
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Reason:    recoveryPendingReason}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Node recovery marker: %w", err)
	}
	marker = append(marker, '\n')
	markerPath := filepath.Join(staging, recoveryMarker)
	if err := writePrivateFile(markerPath, marker); err != nil {
		return nil, fmt.Errorf("write Node recovery quarantine marker: %w", err)
	}
	for _, database := range manifest.Databases {
		info, err := checkSQLite(filepath.Join(staging, filepath.FromSlash(database.Path)))
		if err != nil {
			return nil, fmt.Errorf("verify restored SQLite database %s: %w", database.Path, err)
		}
		if info.integrity != "ok" {
			return nil, fmt.Errorf("restored SQLite database %s failed integrity check", database.Path)
		}
	}
	if err := syncTreeDirectories(staging, manifest.Directories); err != nil {
		return nil, fmt.Errorf("sync restored Node staging directory: %w", err)
	}

	registryCreated, err := ensureRecoveryRegistration(stateRoot, manifest)
	if registryCreated {
		defer func() {
			if published {
				return
			}
			if cleanupErr := removeRecoveryRegistration(stateRoot, manifest.NodeID); cleanupErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("remove failed Node recovery registration: %w", cleanupErr))
			}
		}()
	}
	if err != nil {
		return nil, fmt.Errorf("register Node recovery quarantine: %w", err)
	}
	didPublish, publishErr := publish(staging, nodeDir)
	published = didPublish
	if publishErr != nil {
		return nil, publishErr
	}
	if !didPublish {
		return nil, errors.New("Node restore publisher returned without publishing the staged subtree")
	}
	return &RestoreReport{NodeID: manifest.NodeID, NodeState: nodeDir, Quarantined: true, Manifest: *manifest}, nil
}

type recoveryPendingManifest struct {
	Version              int    `json:"version"`
	NodeID               string `json:"node_id"`
	Status               string `json:"recovery_status"`
	BackupManifestSHA256 string `json:"backup_manifest_sha256"`
	CreatedAt            string `json:"created_at"`
	Reason               string `json:"reason"`
}

func digestManifest(manifest Manifest) string {
	data, _ := json.Marshal(manifest)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

type sqliteInfo struct {
	sqliteVersion string
	journalMode   string
	integrity     string
}

type sqliteSnapshot struct {
	db   *sql.DB
	conn *sql.Conn
	info sqliteInfo
	once sync.Once
	err  error
}

func (s *sqliteSnapshot) Close() error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		if s.conn != nil {
			_, rollbackErr := s.conn.ExecContext(context.Background(), `ROLLBACK`)
			if rollbackErr != nil && !strings.Contains(strings.ToLower(rollbackErr.Error()), "no transaction") {
				s.err = errors.Join(s.err, rollbackErr)
			}
			s.err = errors.Join(s.err, s.conn.Close())
		}
		if s.db != nil {
			s.err = errors.Join(s.err, s.db.Close())
		}
	})
	return s.err
}

func checkpointSQLite(path string) (*sqliteSnapshot, error) {
	db, err := openSQLite(path, "mode=rw")
	if err != nil {
		return nil, err
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("acquire SQLite connection: %w", err)
	}
	snapshot := &sqliteSnapshot{db: db, conn: conn}
	cleanup := func(err error) (*sqliteSnapshot, error) {
		_ = snapshot.Close()
		return nil, err
	}
	if _, err := conn.ExecContext(context.Background(), `PRAGMA busy_timeout = 250`); err != nil {
		return cleanup(fmt.Errorf("set SQLite busy timeout: %w", err))
	}
	var journalMode string
	if err := conn.QueryRowContext(context.Background(), `PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		return cleanup(fmt.Errorf("read SQLite journal mode: %w", err))
	}
	var busy, logFrames, checkpointed int
	if err := conn.QueryRowContext(context.Background(), `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed); err != nil {
		return cleanup(fmt.Errorf("checkpoint SQLite WAL: %w", err))
	}
	if busy != 0 || logFrames >= 0 && checkpointed < logFrames {
		return cleanup(errors.New("SQLite WAL could not be fully checkpointed"))
	}
	// The checkpoint leaves no committed frames in the WAL. BEGIN EXCLUSIVE
	// then prevents a writer from changing the main database while the byte
	// snapshot is copied. In WAL mode this is SQLite's immediate-writer lock.
	if _, err := conn.ExecContext(context.Background(), `BEGIN EXCLUSIVE`); err != nil {
		return cleanup(fmt.Errorf("lock checkpointed SQLite database: %w", err))
	}
	var version string
	if err := conn.QueryRowContext(context.Background(), `SELECT sqlite_version()`).Scan(&version); err != nil {
		return cleanup(fmt.Errorf("read SQLite version: %w", err))
	}
	integrity, err := sqliteIntegrity(conn)
	if err != nil {
		return cleanup(err)
	}
	if integrity != "ok" {
		return cleanup(fmt.Errorf("SQLite integrity_check returned %q", integrity))
	}
	snapshot.info = sqliteInfo{sqliteVersion: version, journalMode: journalMode, integrity: integrity}
	return snapshot, nil
}

func checkSQLite(path string) (sqliteInfo, error) {
	// All backup databases were checkpointed before publication. immutable=1
	// keeps a read-only verification from creating transient -shm/-wal files.
	db, err := openSQLite(path, "mode=ro&immutable=1")
	if err != nil {
		return sqliteInfo{}, err
	}
	defer db.Close()
	var journalMode, version string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		return sqliteInfo{}, fmt.Errorf("read SQLite journal mode: %w", err)
	}
	if err := db.QueryRow(`SELECT sqlite_version()`).Scan(&version); err != nil {
		return sqliteInfo{}, fmt.Errorf("read SQLite version: %w", err)
	}
	integrity, err := sqliteIntegrity(db)
	if err != nil {
		return sqliteInfo{}, err
	}
	return sqliteInfo{sqliteVersion: version, journalMode: journalMode, integrity: integrity}, nil
}

func openSQLite(path, mode string) (*sql.DB, error) {
	uri := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: mode}).String()
	db, err := sql.Open("sqlite", uri)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	return db, nil
}

type sqliteQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func sqliteIntegrity(db sqliteQueryer) (string, error) {
	rows, err := db.QueryContext(context.Background(), `PRAGMA integrity_check`)
	if err != nil {
		return "", fmt.Errorf("run SQLite integrity_check: %w", err)
	}
	defer rows.Close()
	count := 0
	result := "ok"
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return "", fmt.Errorf("read SQLite integrity_check: %w", err)
		}
		count++
		if value != "ok" {
			result = value
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("read SQLite integrity_check: %w", err)
	}
	if count == 0 {
		return "", errors.New("SQLite integrity_check returned no result")
	}
	return result, nil
}

func canonicalPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is required")
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve path: %w", err)
	}
	volume := filepath.VolumeName(absolute)
	remainder := strings.TrimPrefix(absolute, volume)
	current := volume + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimLeft(remainder, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil {
			return "", fmt.Errorf("inspect path component: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("path contains a symbolic link: %s", current)
		}
	}
	return absolute, nil
}

func validateNodeID(nodeID string) error {
	if nodeID == "" || strings.TrimSpace(nodeID) != nodeID || strings.ContainsRune(nodeID, '\x00') || len(nodeID) > 512 {
		return errors.New("Node ID must be a non-empty canonical identifier")
	}
	return nil
}

func nodeStatePath(stateRoot, nodeID string) string {
	return filepath.Join(stateRoot, "nodes", "node-"+url.PathEscape(nodeID))
}

func verifyNodeStateDirectory(stateRoot, nodeDir string) error {
	rootInfo, err := os.Lstat(stateRoot)
	if err != nil {
		return fmt.Errorf("inspect StateDir: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return errors.New("StateDir must be a real directory")
	}
	nodesInfo, err := os.Lstat(filepath.Join(stateRoot, "nodes"))
	if err != nil {
		return fmt.Errorf("inspect Node state root: %w", err)
	}
	if nodesInfo.Mode()&os.ModeSymlink != 0 || !nodesInfo.IsDir() {
		return errors.New("Node state root must be a real directory")
	}
	nodeInfo, err := os.Lstat(nodeDir)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNodeStateMissing
	}
	if err != nil {
		return fmt.Errorf("inspect Node state subtree: %w", err)
	}
	if nodeInfo.Mode()&os.ModeSymlink != 0 || !nodeInfo.IsDir() {
		return errors.New("Node state subtree must be a real directory")
	}
	return nil
}

func ensureDestinationIsNew(destination string) error {
	if info, err := os.Lstat(destination); err == nil {
		_ = info
		return ErrBackupExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect backup destination: %w", err)
	}
	return nil
}

func ensureRestoreTargetNewOrEmpty(target string) error {
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect Node restore target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrRestoreTargetBusy
	}
	contents, err := os.ReadDir(target)
	if err != nil {
		return fmt.Errorf("read Node restore target: %w", err)
	}
	if len(contents) != 0 {
		return ErrRestoreTargetBusy
	}
	return nil
}

func inventoryNodeTree(root string) (treeInventory, error) {
	return collectTree(root, true)
}

type treeInventory struct {
	dirs    []string
	files   []diskEntry
	runtime []OmittedRuntimeEntry
}

func collectTree(root string, sourceTree bool) (treeInventory, error) {
	var inventory treeInventory
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("inspect Node state entry: %w", walkErr)
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("resolve Node state path: %w", err)
		}
		rel = filepath.ToSlash(rel)
		if err := validateRelativePath(rel); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect Node state path %s: %w", rel, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeNamedPipe != 0 || info.Mode()&os.ModeDevice != 0 {
			return fmt.Errorf("%w: %s", ErrUnsafeNodeFile, rel)
		}
		if info.Mode()&os.ModeSocket != 0 {
			if sourceTree && rel == "join.sock" {
				inventory.runtime = append(inventory.runtime, OmittedRuntimeEntry{Path: rel, Type: "unix_socket",
					Reason: "stale_runtime_socket_skipped_under_exclusive_lock"})
				return nil
			}
			return fmt.Errorf("%w: %s", ErrUnsafeNodeFile, rel)
		}
		if info.IsDir() {
			inventory.dirs = append(inventory.dirs, rel)
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: %s", ErrUnsafeNodeFile, rel)
		}
		if !sourceTree && isSQLiteSidecar(rel) {
			return fmt.Errorf("unexpected SQLite sidecar in backup payload: %s: %w", rel, ErrBackupInvalid)
		}
		inventory.files = append(inventory.files, diskEntry{path: rel, mode: info.Mode().Perm(), info: info})
		return nil
	})
	if err != nil {
		return treeInventory{}, err
	}
	sort.Strings(inventory.dirs)
	sort.Slice(inventory.files, func(i, j int) bool { return inventory.files[i].path < inventory.files[j].path })
	sort.Slice(inventory.runtime, func(i, j int) bool { return inventory.runtime[i].Path < inventory.runtime[j].Path })
	return inventory, nil
}

func discoverSQLiteFiles(root string, inventory treeInventory) ([]string, error) {
	files := make(map[string]diskEntry, len(inventory.files))
	for _, entry := range inventory.files {
		files[entry.path] = entry
	}
	var databases []string
	for rel := range files {
		if isKnownNodeDatabase(filepath.Base(rel)) {
			databases = append(databases, rel)
			continue
		}
		file, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, fmt.Errorf("inspect Node file signature %s: %w", rel, err)
		}
		var signature [16]byte
		_, readErr := io.ReadFull(file, signature[:])
		closeErr := file.Close()
		if closeErr != nil {
			return nil, fmt.Errorf("close Node file %s: %w", rel, closeErr)
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("read Node file signature %s: %w", rel, readErr)
		}
		if string(signature[:]) == "SQLite format 3\x00" {
			databases = append(databases, rel)
		}
	}
	for _, rel := range inventory.dirs {
		if isKnownNodeDatabase(filepath.Base(rel)) {
			return nil, fmt.Errorf("Node SQLite path is a directory: %s", rel)
		}
	}
	sort.Strings(databases)
	return databases, nil
}

func isKnownNodeDatabase(base string) bool {
	switch base {
	case "inbox.sqlite", "local-inbox.sqlite3", "local-messages.sqlite3", "node-crypto-state.sqlite":
		return true
	default:
		return false
	}
}

func isSQLiteSidecar(rel string) bool {
	return strings.HasSuffix(rel, "-wal") || strings.HasSuffix(rel, "-shm") || strings.HasSuffix(rel, "-journal")
}

func validateCheckpointedSidecars(entries treeInventory, databasePaths []string) ([]OmittedSidecar, error) {
	dbSet := make(map[string]struct{}, len(databasePaths))
	for _, database := range databasePaths {
		dbSet[database] = struct{}{}
	}
	var result []OmittedSidecar
	for _, entry := range entries.files {
		if !isSQLiteSidecar(entry.path) {
			continue
		}
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(entry.path, "-wal"), "-shm"), "-journal")
		if _, exists := dbSet[base]; !exists {
			return nil, fmt.Errorf("orphan or unknown SQLite sidecar %s: %w", entry.path, ErrUnsafeNodeFile)
		}
		if strings.HasSuffix(entry.path, "-journal") {
			return nil, fmt.Errorf("SQLite rollback journal remains after exclusive checkpoint: %s", entry.path)
		}
		if strings.HasSuffix(entry.path, "-wal") && entry.info.Size() != 0 {
			return nil, fmt.Errorf("SQLite WAL still contains frames after checkpoint: %s", entry.path)
		}
		reason := "empty_after_checkpoint"
		if strings.HasSuffix(entry.path, "-shm") {
			reason = "reconstructible_after_checkpoint"
		}
		result = append(result, OmittedSidecar{Path: entry.path, Reason: reason})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Path < result[j].Path })
	return result, nil
}

func filesForBackup(entries treeInventory, databases []string) ([]string, map[string]struct{}, error) {
	knownFiles := make(map[string]struct{}, len(entries.files))
	var result []string
	omitted := make(map[string]struct{})
	for _, entry := range entries.files {
		knownFiles[entry.path] = struct{}{}
		if isSQLiteSidecar(entry.path) {
			omitted[entry.path] = struct{}{}
			continue
		}
		result = append(result, entry.path)
	}
	for _, path := range databases {
		if _, found := knownFiles[path]; !found {
			return nil, nil, fmt.Errorf("Node SQLite database was omitted: %s", path)
		}
	}
	sort.Strings(result)
	return result, omitted, nil
}

func validateTreeMatch(source treeInventory, copied []FileEntry, directories []string, omitted map[string]struct{}, runtimeOmissions []OmittedRuntimeEntry) error {
	var sourceFiles []string
	for _, entry := range source.files {
		if _, skip := omitted[entry.path]; skip {
			continue
		}
		sourceFiles = append(sourceFiles, entry.path)
	}
	var copiedFiles []string
	for _, entry := range copied {
		copiedFiles = append(copiedFiles, entry.Path)
	}
	if !sameStrings(sourceFiles, copiedFiles) || !sameStrings(source.dirs, directories) || !sameRuntimeOmissions(source.runtime, runtimeOmissions) {
		return errors.New("source inventory changed or a file was omitted")
	}
	return nil
}

func sameTreePaths(a, b treeInventory) bool {
	if !sameStrings(a.dirs, b.dirs) || !sameRuntimeOmissions(a.runtime, b.runtime) || len(a.files) != len(b.files) {
		return false
	}
	for i := range a.files {
		if a.files[i].path != b.files[i].path {
			return false
		}
	}
	return true
}

func sameRuntimeOmissions(a, b []OmittedRuntimeEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func copyPrivateFile(source, destination string) (FileEntry, error) {
	before, err := os.Lstat(source)
	if err != nil {
		return FileEntry{}, err
	}
	if !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return FileEntry{}, ErrUnsafeNodeFile
	}
	input, err := os.Open(source)
	if err != nil {
		return FileEntry{}, err
	}
	opened, err := input.Stat()
	if err != nil {
		_ = input.Close()
		return FileEntry{}, err
	}
	if !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		_ = input.Close()
		return FileEntry{}, errors.New("Node file changed while opening")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, privateFileMode)
	if err != nil {
		_ = input.Close()
		return FileEntry{}, err
	}
	if err := output.Chmod(privateFileMode); err != nil {
		_ = output.Close()
		_ = input.Close()
		return FileEntry{}, err
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	closeInErr := input.Close()
	if copyErr != nil {
		_ = output.Close()
		return FileEntry{}, copyErr
	}
	if closeInErr != nil {
		_ = output.Close()
		return FileEntry{}, closeInErr
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return FileEntry{}, err
	}
	if err := output.Close(); err != nil {
		return FileEntry{}, err
	}
	after, err := os.Lstat(source)
	if err != nil {
		return FileEntry{}, err
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || count != after.Size() {
		return FileEntry{}, errors.New("Node file changed while copying")
	}
	return FileEntry{Size: count, Mode: uint32(privateFileMode.Perm()), SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func copyVerifiedFile(source, destination string, expected FileEntry) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ErrUnsafeNodeFile
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	opened, err := input.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return errors.New("backup file changed while opening")
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, privateFileMode)
	if err != nil {
		return err
	}
	if err := output.Chmod(privateFileMode); err != nil {
		_ = output.Close()
		return err
	}
	hash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	if copyErr != nil {
		_ = output.Close()
		return copyErr
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	if count != expected.Size || hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return ErrBackupInvalid
	}
	return nil
}

func writePrivateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writePrivateFile(path, append(data, '\n'))
}

func writePrivateFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, privateFileMode)
	if err != nil {
		return err
	}
	if err := file.Chmod(privateFileMode); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func readManifest(path string) (*Manifest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("read Node backup manifest: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != privateFileMode.Perm() || info.Size() > maxManifestSize {
		return nil, ErrBackupInvalid
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Node backup manifest: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("decode Node backup manifest: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("Node backup manifest has trailing data")
	}
	return &manifest, nil
}

func validateManifest(manifest *Manifest) error {
	if manifest == nil || manifest.FormatVersion != FormatVersion || !manifest.Complete || validateNodeID(manifest.NodeID) != nil {
		return ErrBackupInvalid
	}
	if _, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil {
		return ErrBackupInvalid
	}
	for i, dir := range manifest.Directories {
		if err := validateRelativePath(dir); err != nil || (i > 0 && manifest.Directories[i-1] >= dir) {
			return ErrBackupInvalid
		}
	}
	for i, entry := range manifest.Files {
		if err := validateRelativePath(entry.Path); err != nil || entry.Size < 0 || entry.Mode != uint32(privateFileMode.Perm()) || !validSHA256(entry.SHA256) || (i > 0 && manifest.Files[i-1].Path >= entry.Path) {
			return ErrBackupInvalid
		}
	}
	databaseSet := make(map[string]struct{}, len(manifest.Databases))
	for i, database := range manifest.Databases {
		if err := validateRelativePath(database.Path); err != nil || database.SQLiteVersion == "" || database.Integrity != "ok" || !validSHA256(database.SHA256) || (i > 0 && manifest.Databases[i-1].Path >= database.Path) {
			return ErrBackupInvalid
		}
		file, ok := fileEntryAt(manifest.Files, database.Path)
		if !ok || file.SHA256 != database.SHA256 {
			return ErrBackupInvalid
		}
		databaseSet[database.Path] = struct{}{}
	}
	for i, sidecar := range manifest.Sidecars {
		if err := validateRelativePath(sidecar.Path); err != nil || !isSQLiteSidecar(sidecar.Path) || sidecar.Reason == "" || (i > 0 && manifest.Sidecars[i-1].Path >= sidecar.Path) {
			return ErrBackupInvalid
		}
		base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(sidecar.Path, "-wal"), "-shm"), "-journal")
		if _, ok := databaseSet[base]; !ok {
			return ErrBackupInvalid
		}
		if strings.HasSuffix(sidecar.Path, "-journal") || strings.HasSuffix(sidecar.Path, "-wal") && sidecar.Reason != "empty_after_checkpoint" || strings.HasSuffix(sidecar.Path, "-shm") && sidecar.Reason != "reconstructible_after_checkpoint" {
			return ErrBackupInvalid
		}
	}
	for i, omitted := range manifest.RuntimeOmissions {
		if omitted.Path != "join.sock" || omitted.Type != "unix_socket" ||
			omitted.Reason != "stale_runtime_socket_skipped_under_exclusive_lock" ||
			(i > 0 && manifest.RuntimeOmissions[i-1].Path >= omitted.Path) {
			return ErrBackupInvalid
		}
	}
	if err := validateManifestPathRelationships(manifest); err != nil {
		return err
	}
	return nil
}

func validateManifestPathRelationships(manifest *Manifest) error {
	dirs := make(map[string]struct{}, len(manifest.Directories))
	files := make(map[string]struct{}, len(manifest.Files))
	for _, dir := range manifest.Directories {
		dirs[dir] = struct{}{}
	}
	for _, file := range manifest.Files {
		files[file.Path] = struct{}{}
		for parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(file.Path))); parent != "."; parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(parent))) {
			if _, ok := dirs[parent]; !ok {
				return ErrBackupInvalid
			}
		}
	}
	for _, dir := range manifest.Directories {
		if _, ok := files[dir]; ok {
			return ErrBackupInvalid
		}
		for parent := filepath.ToSlash(filepath.Dir(filepath.FromSlash(dir))); parent != "."; parent = filepath.ToSlash(filepath.Dir(filepath.FromSlash(parent))) {
			if _, ok := dirs[parent]; !ok {
				return ErrBackupInvalid
			}
		}
	}
	return nil
}

func verifyPayloadInventory(root string, manifest *Manifest) error {
	actual, err := collectTree(root, false)
	if err != nil {
		return fmt.Errorf("inspect Node backup payload: %w", err)
	}
	if !sameStrings(actual.dirs, manifest.Directories) || len(actual.files) != len(manifest.Files) {
		return ErrBackupInvalid
	}
	for _, rel := range actual.dirs {
		info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != privateDirMode.Perm() {
			return ErrBackupInvalid
		}
	}
	for index, actualFile := range actual.files {
		expected := manifest.Files[index]
		if actualFile.path != expected.Path || actualFile.info.Size() != expected.Size || actualFile.info.Mode().Perm() != privateFileMode.Perm() {
			return ErrBackupInvalid
		}
		digest, size, err := hashFile(filepath.Join(root, filepath.FromSlash(actualFile.path)))
		if err != nil {
			return err
		}
		if digest != expected.SHA256 || size != expected.Size {
			return fmt.Errorf("checksum mismatch for %s: %w", expected.Path, ErrBackupInvalid)
		}
	}
	databasePaths, err := discoverSQLiteFiles(root, actual)
	if err != nil {
		return err
	}
	manifestDatabasePaths := make([]string, 0, len(manifest.Databases))
	for _, database := range manifest.Databases {
		manifestDatabasePaths = append(manifestDatabasePaths, database.Path)
	}
	if !sameStrings(databasePaths, manifestDatabasePaths) {
		return ErrBackupInvalid
	}
	return nil
}

func verifyPrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != privateDirMode.Perm() {
		return errors.New("directory must be a real private 0700 directory")
	}
	return nil
}

func validateRelativePath(path string) error {
	if path == "" || strings.ContainsRune(path, '\x00') || strings.Contains(path, `\`) || strings.HasPrefix(path, "/") || filepath.IsAbs(filepath.FromSlash(path)) {
		return ErrBackupInvalid
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean != path || clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return ErrBackupInvalid
	}
	return nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}

func fileEntryAt(files []FileEntry, path string) (FileEntry, bool) {
	index := sort.Search(len(files), func(i int) bool { return files[i].Path >= path })
	if index >= len(files) || files[index].Path != path {
		return FileEntry{}, false
	}
	return files[index], true
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	hash := sha256.New()
	count, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if copyErr != nil {
		return "", 0, copyErr
	}
	if closeErr != nil {
		return "", 0, closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), count, nil
}

func pathWithin(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	return err == nil && (rel == "." || rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// File fsync alone does not persist the directory entries for files in nested
// Node subdirectories. Sync children before parents, then the published root.
func syncTreeDirectories(root string, directories []string) error {
	for i := len(directories) - 1; i >= 0; i-- {
		if err := syncDirectory(filepath.Join(root, filepath.FromSlash(directories[i]))); err != nil {
			return fmt.Errorf("sync Node directory %s: %w", directories[i], err)
		}
	}
	return syncDirectory(root)
}
