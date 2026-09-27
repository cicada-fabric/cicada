package store

// This file contains the deliberately small, offline StateDir backup and
// restore primitive used by the v2 migration work.  It is a byte preserving
// copy of a quiesced StateDir, not a database migration and not a replacement
// for SQLite's online backup protocol.  Callers must stop every process which
// can write the StateDir before calling BackupStateDir.  The source database
// is additionally held under BEGIN EXCLUSIVE while its files are copied; the
// lock catches a concurrent writer and keeps the main database/WAL/SHM set at
// one SQLite snapshot.
//
// The manifest contains only metadata, checksums, schema inventory and
// aggregate contact/replay summaries.  Private key bytes, ratchet keys,
// opaque envelopes and message/body columns are copied as payload but never
// serialized into the manifest.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// StateBackupFormatVersion changes when the on-disk payload or manifest
	// contract changes in an incompatible way.
	StateBackupFormatVersion = 1
	stateDatabaseName        = "cicada.sqlite3"
	stateBackupManifestName  = "manifest.json"
	stateBackupPayloadName   = "payload"
	stateBackupFileMode      = fs.FileMode(0o600)
	stateBackupDirMode       = fs.FileMode(0o700)
)

var (
	ErrStateBackupSourceRequired      = errors.New("state backup requires a source StateDir")
	ErrStateBackupDestinationRequired = errors.New("state backup requires a destination directory")
	ErrStateBackupDestinationExists   = errors.New("state backup destination already exists")
	ErrStateBackupSourceBusy          = errors.New("state database is busy; stop all writers and retry the offline backup")
	ErrStateBackupIncomplete          = errors.New("state backup is incomplete or has an invalid manifest")
	ErrStateRestoreTargetNotEmpty     = errors.New("state restore target must be new or empty")
	ErrStateBackupPathUnsafe          = errors.New("state backup contains an unsafe path")
)

// StateBackupOptions identifies an offline source and a new backup directory.
// Both paths are required.  The source is never migrated or modified by the
// helper; the SQLite lock is only held long enough to establish a stable copy.
type StateBackupOptions struct {
	SourceStateDir string
	DestinationDir string
}

// StateRestoreOptions identifies a verified backup and a new/empty target.
// Restore copies the original identity/key files verbatim and never generates
// or rotates a replacement identity.
type StateRestoreOptions struct {
	BackupDir      string
	TargetStateDir string
}

// StateBackupFile records one private payload file without exposing its bytes.
type StateBackupFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
	SHA256 string `json:"sha256"`
}

// StateBackupTable is a schema inventory entry.  It intentionally contains no
// row values or SQL text.
type StateBackupTable struct {
	Name string `json:"name"`
	Rows int64  `json:"rows"`
}

// StateBackupDatabase contains the checks performed on the SQLite snapshot.
// IntegrityCheck and ForeignKeyCheck are "ok" only after all corresponding
// rows have been read and found clean.
type StateBackupDatabase struct {
	CopyMode          string             `json:"copy_mode"`
	SQLiteVersion     string             `json:"sqlite_version"`
	JournalMode       string             `json:"journal_mode"`
	IntegrityCheck    string             `json:"integrity_check"`
	ForeignKeyCheck   string             `json:"foreign_key_check"`
	SchemaFingerprint string             `json:"schema_fingerprint"`
	Checksum          string             `json:"checksum"`
	Tables            []StateBackupTable `json:"tables"`
}

// StateBackupContacts is an aggregate continuity check.  Digests are hashes
// of stable row coordinates and key/envelope hashes; they are not the rows.
// ReplaySequences and the counter totals make accidental rollback visible
// even if an implementation later changes the row hashing projection.
type StateBackupContacts struct {
	Contacts          int64  `json:"contacts"`
	PeerSessions      int64  `json:"peer_sessions"`
	PeerMessages      int64  `json:"peer_messages"`
	ReplaySequences   int64  `json:"replay_sequences"`
	SendSequenceTotal uint64 `json:"send_sequence_total"`
	ReceiveCountTotal uint64 `json:"receive_count_total"`
	SendCountTotal    uint64 `json:"send_count_total"`
	ContactDigest     string `json:"contact_digest"`
	PeerSessionDigest string `json:"peer_session_digest"`
	PeerMessageDigest string `json:"peer_message_digest"`
	Digest            string `json:"digest"`
}

// StateBackupManifest is the only metadata file written at the root of a
// backup.  Complete is written true only after the payload has been copied,
// reopened, and checked against the source snapshot.
type StateBackupManifest struct {
	FormatVersion int                 `json:"format_version"`
	Complete      bool                `json:"complete"`
	CreatedAt     string              `json:"created_at"`
	Database      StateBackupDatabase `json:"database"`
	Contacts      StateBackupContacts `json:"contacts"`
	Files         []StateBackupFile   `json:"files"`
}

// StateRestoreReport is returned after the target has been atomically
// installed.  The embedded manifest is the verified source of truth.
type StateRestoreReport struct {
	TargetStateDir string              `json:"target_state_dir"`
	Verified       bool                `json:"verified"`
	Manifest       StateBackupManifest `json:"manifest"`
}

// BackupStateDir creates a complete offline backup in destinationDir.  The
// destination must not already exist; publishing is atomic, so a failed copy
// does not leave a directory which a later restore could mistake for a valid
// backup.
func BackupStateDir(sourceStateDir, destinationDir string) (*StateBackupManifest, error) {
	return BackupStateDirWithContext(context.Background(), StateBackupOptions{
		SourceStateDir: sourceStateDir,
		DestinationDir: destinationDir,
	})
}

// BackupStateDirWithContext is the context-aware form used by a CLI or a
// migration driver.
func BackupStateDirWithContext(ctx context.Context, options StateBackupOptions) (*StateBackupManifest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	sourceDir, destinationDir, sourceDB, err := validateBackupPaths(options)
	if err != nil {
		return nil, err
	}
	if err := ensureBackupDestinationIsNew(destinationDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(destinationDir), stateBackupDirMode); err != nil {
		return nil, fmt.Errorf("create backup parent: %w", err)
	}

	lockDB, err := openSQLiteForOfflineBackup(sourceDB)
	if err != nil {
		if errors.Is(err, ErrStateBackupSourceBusy) {
			return nil, err
		}
		return nil, fmt.Errorf("acquire offline SQLite snapshot lock: %w", err)
	}
	defer func() {
		_, _ = lockDB.Exec(`ROLLBACK`)
		_ = lockDB.Close()
	}()

	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	sourceDatabase, sourceContacts, err := inspectSQLiteSnapshot(lockDB, sourceDB)
	if err != nil {
		return nil, fmt.Errorf("validate source SQLite snapshot: %w", err)
	}
	sourceFiles, err := collectStateFiles(sourceDir)
	if err != nil {
		return nil, fmt.Errorf("inventory source StateDir: %w", err)
	}
	if err := requireDatabaseFiles(sourceFiles); err != nil {
		return nil, err
	}
	if err := validateSQLiteSidecars(sourceFiles); err != nil {
		return nil, err
	}

	temporary, err := os.MkdirTemp(filepath.Dir(destinationDir), filepath.Base(destinationDir)+".partial-")
	if err != nil {
		return nil, fmt.Errorf("create temporary backup directory: %w", err)
	}
	temporaryPublished := false
	defer func() {
		if !temporaryPublished {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, stateBackupDirMode); err != nil {
		return nil, fmt.Errorf("protect temporary backup directory: %w", err)
	}
	payloadRoot := filepath.Join(temporary, stateBackupPayloadName)
	if err := os.Mkdir(payloadRoot, stateBackupDirMode); err != nil {
		return nil, fmt.Errorf("create backup payload directory: %w", err)
	}

	files := make([]StateBackupFile, 0, len(sourceFiles))
	for _, sourceFile := range sourceFiles {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		rel := sourceFile.Path
		destination := filepath.Join(payloadRoot, filepath.FromSlash(rel))
		if err := ensurePrivateParentDirs(payloadRoot, filepath.Dir(destination)); err != nil {
			return nil, fmt.Errorf("create payload parent for %s: %w", rel, err)
		}
		copied, err := copyStableStateFile(ctx, filepath.Join(sourceDir, filepath.FromSlash(rel)), destination)
		if err != nil {
			return nil, fmt.Errorf("copy StateDir file %s: %w", rel, err)
		}
		copied.Path = rel
		files = append(files, copied)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	stagedDatabase, stagedContacts, err := inspectSQLiteSnapshot(nil, filepath.Join(payloadRoot, stateDatabaseName))
	if err != nil {
		return nil, fmt.Errorf("validate copied SQLite snapshot: %w", err)
	}
	if err := compareSQLiteSnapshots(sourceDatabase, sourceContacts, stagedDatabase, stagedContacts); err != nil {
		return nil, fmt.Errorf("copied SQLite snapshot differs from source: %w", err)
	}
	if err := compareStateFileInventory(sourceFiles, files); err != nil {
		return nil, fmt.Errorf("copied StateDir file inventory differs from source: %w", err)
	}
	if err := validateSQLiteSidecarsFromManifest(files); err != nil {
		return nil, err
	}

	manifest := &StateBackupManifest{
		FormatVersion: StateBackupFormatVersion,
		Complete:      true,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Database:      sourceDatabase,
		Contacts:      sourceContacts,
		Files:         files,
	}
	manifest.Database.Checksum = stateBackupDatabaseChecksum(manifest.Database, manifest.Contacts)
	if err := writePrivateJSON(filepath.Join(temporary, stateBackupManifestName), manifest); err != nil {
		return nil, fmt.Errorf("write backup manifest: %w", err)
	}
	if err := syncDirectory(payloadRoot); err != nil {
		return nil, fmt.Errorf("sync backup payload directory: %w", err)
	}
	if err := syncDirectory(temporary); err != nil {
		return nil, fmt.Errorf("sync backup directory: %w", err)
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	if err := publishNewDirectory(temporary, destinationDir); err != nil {
		return nil, err
	}
	temporaryPublished = true
	return manifest, nil
}

// VerifyStateBackup validates the manifest, every payload checksum, SQLite
// integrity/FK state, and the contact/session continuity digest without
// writing to the backup directory.
func VerifyStateBackup(backupDir string) (*StateBackupManifest, error) {
	backupDir = strings.TrimSpace(backupDir)
	if backupDir == "" {
		return nil, errors.New("verify requires a backup directory")
	}
	var err error
	backupDir, err = filepath.Abs(backupDir)
	if err != nil {
		return nil, fmt.Errorf("resolve backup directory: %w", err)
	}
	manifest, err := readStateBackupManifest(backupDir)
	if err != nil {
		return nil, err
	}
	payloadRoot := filepath.Join(backupDir, stateBackupPayloadName)
	if err := verifyPayloadInventory(payloadRoot, manifest.Files); err != nil {
		return nil, err
	}
	if err := validateSQLiteSidecarsFromManifest(manifest.Files); err != nil {
		return nil, err
	}
	database, contacts, err := inspectSQLiteSnapshot(nil, filepath.Join(payloadRoot, stateDatabaseName))
	if err != nil {
		return nil, fmt.Errorf("validate backup SQLite payload: %w", err)
	}
	if err := compareManifestSnapshot(manifest, database, contacts); err != nil {
		return nil, fmt.Errorf("backup manifest does not match payload: %w", err)
	}
	return manifest, nil
}

// RestoreStateDir verifies backupDir and atomically installs it into a new or
// empty targetStateDir.  Existing non-empty targets are rejected before any
// target write.  A failed validation removes only the private temporary
// staging directory and leaves both the backup and target untouched.
func RestoreStateDir(backupDir, targetStateDir string) (*StateRestoreReport, error) {
	return RestoreStateDirWithContext(context.Background(), StateRestoreOptions{
		BackupDir:      backupDir,
		TargetStateDir: targetStateDir,
	})
}

// RestoreStateDirWithContext is the context-aware restore form.
func RestoreStateDirWithContext(ctx context.Context, options StateRestoreOptions) (*StateRestoreReport, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	backupDir, targetDir, err := validateRestorePaths(options)
	if err != nil {
		return nil, err
	}
	if err := ensureRestoreTargetIsNewOrEmpty(targetDir); err != nil {
		return nil, err
	}
	manifest, err := VerifyStateBackup(backupDir)
	if err != nil {
		return nil, err
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}

	parent := filepath.Dir(targetDir)
	if err := os.MkdirAll(parent, stateBackupDirMode); err != nil {
		return nil, fmt.Errorf("create restore parent: %w", err)
	}
	temporary, err := os.MkdirTemp(parent, filepath.Base(targetDir)+".restore-")
	if err != nil {
		return nil, fmt.Errorf("create temporary restore directory: %w", err)
	}
	temporaryPublished := false
	defer func() {
		if !temporaryPublished {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, stateBackupDirMode); err != nil {
		return nil, fmt.Errorf("protect temporary restore directory: %w", err)
	}
	payloadRoot := filepath.Join(backupDir, stateBackupPayloadName)
	for _, file := range manifest.Files {
		if err := contextErr(ctx); err != nil {
			return nil, err
		}
		rel := file.Path
		destination := filepath.Join(temporary, filepath.FromSlash(rel))
		if err := ensurePrivateParentDirs(temporary, filepath.Dir(destination)); err != nil {
			return nil, fmt.Errorf("create restore parent for %s: %w", rel, err)
		}
		copied, err := copyExactStateFile(ctx, filepath.Join(payloadRoot, filepath.FromSlash(rel)), destination, file)
		if err != nil {
			return nil, fmt.Errorf("restore StateDir file %s: %w", rel, err)
		}
		if copied.SHA256 != file.SHA256 || copied.Size != file.Size {
			return nil, fmt.Errorf("restored StateDir file %s failed checksum verification", rel)
		}
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	restoredDatabase, restoredContacts, err := inspectSQLiteSnapshot(nil, filepath.Join(temporary, stateDatabaseName))
	if err != nil {
		return nil, fmt.Errorf("validate restored SQLite payload: %w", err)
	}
	if err := compareManifestSnapshot(manifest, restoredDatabase, restoredContacts); err != nil {
		return nil, fmt.Errorf("restored SQLite payload differs from backup manifest: %w", err)
	}
	if err := verifyRestoredStateInventory(temporary, manifest); err != nil {
		return nil, err
	}
	if err := installRestoreTarget(temporary, targetDir); err != nil {
		return nil, err
	}
	temporaryPublished = true
	return &StateRestoreReport{TargetStateDir: targetDir, Verified: true, Manifest: *manifest}, nil
}

func validateBackupPaths(options StateBackupOptions) (string, string, string, error) {
	source := strings.TrimSpace(options.SourceStateDir)
	destination := strings.TrimSpace(options.DestinationDir)
	if source == "" {
		return "", "", "", ErrStateBackupSourceRequired
	}
	if destination == "" {
		return "", "", "", ErrStateBackupDestinationRequired
	}
	source, err := filepath.Abs(source)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve source StateDir: %w", err)
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return "", "", "", fmt.Errorf("resolve backup destination: %w", err)
	}
	info, err := os.Lstat(source)
	if err != nil {
		return "", "", "", fmt.Errorf("stat source StateDir: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", "", fmt.Errorf("source StateDir is not a directory: %s", source)
	}
	if statePathsOverlap(source, destination) {
		return "", "", "", fmt.Errorf("backup destination must not overlap source StateDir: %w", ErrStateBackupPathUnsafe)
	}
	database := filepath.Join(source, stateDatabaseName)
	dbInfo, err := os.Lstat(database)
	if err != nil {
		return "", "", "", fmt.Errorf("stat source SQLite database: %w", err)
	}
	if !dbInfo.Mode().IsRegular() || dbInfo.Mode()&os.ModeSymlink != 0 {
		return "", "", "", fmt.Errorf("source SQLite database is not a regular file: %s", database)
	}
	return source, destination, database, nil
}

func validateRestorePaths(options StateRestoreOptions) (string, string, error) {
	backup := strings.TrimSpace(options.BackupDir)
	target := strings.TrimSpace(options.TargetStateDir)
	if backup == "" {
		return "", "", fmt.Errorf("restore requires a backup directory")
	}
	if target == "" {
		return "", "", fmt.Errorf("restore requires a target StateDir")
	}
	backup, err := filepath.Abs(backup)
	if err != nil {
		return "", "", fmt.Errorf("resolve backup directory: %w", err)
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return "", "", fmt.Errorf("resolve restore target: %w", err)
	}
	info, err := os.Lstat(backup)
	if err != nil {
		return "", "", fmt.Errorf("stat backup directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", "", fmt.Errorf("backup path is not a directory: %s", backup)
	}
	if statePathsOverlap(backup, target) {
		return "", "", fmt.Errorf("restore target must not overlap backup directory: %w", ErrStateBackupPathUnsafe)
	}
	return backup, target, nil
}

func ensureBackupDestinationIsNew(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup destination is a symlink: %w", ErrStateBackupDestinationExists)
		}
		return fmt.Errorf("backup destination %s already exists: %w", path, ErrStateBackupDestinationExists)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect backup destination: %w", err)
	}
	return nil
}

func ensureRestoreTargetIsNewOrEmpty(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect restore target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("restore target must be a directory: %w", ErrStateRestoreTargetNotEmpty)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("inspect restore target: %w", err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("restore target %s is not empty: %w", path, ErrStateRestoreTargetNotEmpty)
	}
	return nil
}

func statePathsOverlap(first, second string) bool {
	first = filepath.Clean(first)
	second = filepath.Clean(second)
	rel, err := filepath.Rel(first, second)
	if err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))) {
		return true
	}
	rel, err = filepath.Rel(second, first)
	return err == nil && (rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))))
}

func openSQLiteForOfflineBackup(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", sqliteFileURI(path, "mode=rw"))
	if err != nil {
		return nil, fmt.Errorf("open SQLite source read-write for offline lock: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure SQLite busy timeout: %w", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure SQLite foreign keys: %w", err)
	}
	if _, err := db.Exec(`BEGIN EXCLUSIVE`); err != nil {
		_ = db.Close()
		if isSQLiteBusy(err) {
			return nil, ErrStateBackupSourceBusy
		}
		return nil, fmt.Errorf("begin SQLite exclusive snapshot: %w", err)
	}
	return db, nil
}

func openSQLiteReadOnly(path string) (*sql.DB, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("SQLite payload is not a regular file: %s", path)
	}
	db, err := sql.Open("sqlite", sqliteFileURI(path, "mode=ro"))
	if err != nil {
		return nil, fmt.Errorf("open SQLite read-only: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure SQLite read-only busy timeout: %w", err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configure SQLite read-only foreign keys: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping SQLite read-only: %w", err)
	}
	return db, nil
}

func sqliteFileURI(path, query string) string {
	abs, _ := filepath.Abs(path)
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}).String() + "?" + query
}

func inspectSQLiteSnapshot(lockedDB *sql.DB, path string) (StateBackupDatabase, StateBackupContacts, error) {
	var db *sql.DB
	closeDB := false
	if lockedDB != nil {
		db = lockedDB
	} else {
		var err error
		db, err = openSQLiteReadOnly(path)
		if err != nil {
			return StateBackupDatabase{}, StateBackupContacts{}, err
		}
		closeDB = true
	}
	if closeDB {
		defer db.Close()
	}
	version, err := sqliteScalarString(db, `SELECT sqlite_version()`)
	if err != nil {
		return StateBackupDatabase{}, StateBackupContacts{}, fmt.Errorf("read SQLite version: %w", err)
	}
	journal, err := sqliteScalarString(db, `PRAGMA journal_mode`)
	if err != nil {
		return StateBackupDatabase{}, StateBackupContacts{}, fmt.Errorf("read SQLite journal mode: %w", err)
	}
	integrity, err := sqliteIntegrityCheck(db)
	if err != nil {
		return StateBackupDatabase{}, StateBackupContacts{}, err
	}
	foreignKeys, err := sqliteForeignKeyCheck(db)
	if err != nil {
		return StateBackupDatabase{}, StateBackupContacts{}, err
	}
	if integrity != "ok" {
		return StateBackupDatabase{}, StateBackupContacts{}, fmt.Errorf("PRAGMA integrity_check returned %q", integrity)
	}
	if foreignKeys != "ok" {
		return StateBackupDatabase{}, StateBackupContacts{}, fmt.Errorf("PRAGMA foreign_key_check found %s", foreignKeys)
	}
	fingerprint, err := sqliteSchemaFingerprint(db)
	if err != nil {
		return StateBackupDatabase{}, StateBackupContacts{}, err
	}
	tables, err := sqliteTableInventory(db)
	if err != nil {
		return StateBackupDatabase{}, StateBackupContacts{}, err
	}
	contacts, err := sqliteContactSummary(db)
	if err != nil {
		return StateBackupDatabase{}, StateBackupContacts{}, err
	}
	return StateBackupDatabase{
		CopyMode:          "offline-byte-copy",
		SQLiteVersion:     version,
		JournalMode:       strings.ToLower(journal),
		IntegrityCheck:    integrity,
		ForeignKeyCheck:   foreignKeys,
		SchemaFingerprint: fingerprint,
		Tables:            tables,
	}, contacts, nil
}

func sqliteScalarString(db *sql.DB, query string) (string, error) {
	var value string
	if err := db.QueryRow(query).Scan(&value); err != nil {
		return "", err
	}
	return value, nil
}

func sqliteIntegrityCheck(db *sql.DB) (string, error) {
	rows, err := db.Query(`PRAGMA integrity_check`)
	if err != nil {
		return "", fmt.Errorf("run PRAGMA integrity_check: %w", err)
	}
	defer rows.Close()
	result := ""
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return "", fmt.Errorf("read PRAGMA integrity_check: %w", err)
		}
		if result == "" {
			result = value
		} else if value != "ok" {
			result += "; " + value
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("read PRAGMA integrity_check: %w", err)
	}
	if result == "" {
		return "", errors.New("PRAGMA integrity_check returned no result")
	}
	return result, nil
}

func sqliteForeignKeyCheck(db *sql.DB) (string, error) {
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		return "", fmt.Errorf("run PRAGMA foreign_key_check: %w", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var table, rowID, parent, foreignKey any
		if err := rows.Scan(&table, &rowID, &parent, &foreignKey); err != nil {
			return "", fmt.Errorf("read PRAGMA foreign_key_check: %w", err)
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("read PRAGMA foreign_key_check: %w", err)
	}
	if count != 0 {
		return fmt.Sprintf("%d violation(s)", count), nil
	}
	return "ok", nil
}

func sqliteSchemaFingerprint(db *sql.DB) (string, error) {
	rows, err := db.Query(`SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master WHERE type IN ('table', 'index', 'trigger', 'view') ORDER BY type, name`)
	if err != nil {
		return "", fmt.Errorf("read SQLite schema fingerprint: %w", err)
	}
	defer rows.Close()
	h := sha256.New()
	for rows.Next() {
		var kind, name, tableName, definition string
		if err := rows.Scan(&kind, &name, &tableName, &definition); err != nil {
			return "", fmt.Errorf("scan SQLite schema fingerprint: %w", err)
		}
		writeHashFields(h, kind, name, tableName, definition)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("read SQLite schema fingerprint: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sqliteTableInventory(db *sql.DB) ([]StateBackupTable, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list SQLite tables: %w", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("read SQLite table: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read SQLite tables: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close SQLite table inventory: %w", err)
	}
	var tables []StateBackupTable
	for _, name := range names {
		var count int64
		if err := db.QueryRow(`SELECT count(*) FROM ` + quoteStateIdentifier(name)).Scan(&count); err != nil {
			return nil, fmt.Errorf("count SQLite table %s: %w", name, err)
		}
		tables = append(tables, StateBackupTable{Name: name, Rows: count})
	}
	return tables, nil
}

func quoteStateIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func sqliteContactSummary(db *sql.DB) (StateBackupContacts, error) {
	result := StateBackupContacts{}
	contactDigest, contactCount, replayCount, sendTotal, err := sqliteContactsDigest(db)
	if err != nil {
		return result, err
	}
	peerSessionDigest, peerSessionCount, sendCountTotal, receiveCountTotal, err := sqlitePeerSessionsDigest(db)
	if err != nil {
		return result, err
	}
	peerMessageDigest, peerMessageCount, err := sqlitePeerMessagesDigest(db)
	if err != nil {
		return result, err
	}
	result.Contacts = contactCount
	result.PeerSessions = peerSessionCount
	result.PeerMessages = peerMessageCount
	result.ReplaySequences = replayCount
	result.SendSequenceTotal = sendTotal
	result.SendCountTotal = sendCountTotal
	result.ReceiveCountTotal = receiveCountTotal
	result.ContactDigest = contactDigest
	result.PeerSessionDigest = peerSessionDigest
	result.PeerMessageDigest = peerMessageDigest
	h := sha256.New()
	writeHashFields(h, contactDigest, peerSessionDigest, peerMessageDigest)
	result.Digest = hex.EncodeToString(h.Sum(nil))
	return result, nil
}

func sqliteContactsDigest(db *sql.DB) (string, int64, int64, uint64, error) {
	h := sha256.New()
	if !sqliteTableExists(db, "contacts") {
		return emptyDigest(), 0, 0, 0, nil
	}
	columns, err := sqliteTableColumns(db, "contacts")
	if err != nil {
		return "", 0, 0, 0, err
	}
	selectExpr := func(name, fallback string) string {
		if columns[name] {
			return quoteStateIdentifier(name)
		}
		return fallback
	}
	query := `SELECT ` + selectExpr("id", `CAST(rowid AS TEXT)`) + `, ` +
		selectExpr("remote_id", `''`) + `, ` + selectExpr("identity_json", `''`) + `, ` +
		selectExpr("status", `''`) + `, ` + selectExpr("send_sequence", `0`) + `, ` +
		selectExpr("received_sequences_json", `'[]'`) + ` FROM ` + quoteStateIdentifier("contacts") +
		` ORDER BY ` + selectExpr("id", `rowid`)
	rows, err := db.Query(query)
	if err != nil {
		return "", 0, 0, 0, fmt.Errorf("read contact continuity state: %w", err)
	}
	defer rows.Close()
	var count, replayCount int64
	var sendTotal uint64
	for rows.Next() {
		var id, remoteID, identityJSON, status, receivedJSON sql.NullString
		var sendSequence sql.NullInt64
		if err := rows.Scan(&id, &remoteID, &identityJSON, &status, &sendSequence, &receivedJSON); err != nil {
			return "", 0, 0, 0, fmt.Errorf("scan contact continuity state: %w", err)
		}
		if sendSequence.Valid && sendSequence.Int64 < 0 {
			return "", 0, 0, 0, fmt.Errorf("contact %s has a negative send sequence", id.String)
		}
		sequence := uint64(0)
		if sendSequence.Valid {
			sequence = uint64(sendSequence.Int64)
		}
		if ^uint64(0)-sendTotal < sequence {
			return "", 0, 0, 0, errors.New("contact send sequence total overflow")
		}
		sendTotal += sequence
		var received []uint64
		if strings.TrimSpace(receivedJSON.String) != "" {
			if err := json.Unmarshal([]byte(receivedJSON.String), &received); err != nil {
				return "", 0, 0, 0, fmt.Errorf("decode replay sequence state for contact %s: %w", id.String, err)
			}
		}
		if int64(len(received)) > (1<<63-1)-replayCount {
			return "", 0, 0, 0, errors.New("replay sequence count overflow")
		}
		replayCount += int64(len(received))
		identityHash := sha256.Sum256([]byte(identityJSON.String))
		replayHash := sha256.Sum256([]byte(receivedJSON.String))
		writeHashFields(h, "contact", id.String, remoteID.String, status.String, fmt.Sprint(sequence), hex.EncodeToString(identityHash[:]), hex.EncodeToString(replayHash[:]))
		count++
	}
	if err := rows.Err(); err != nil {
		return "", 0, 0, 0, fmt.Errorf("read contact continuity state: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), count, replayCount, sendTotal, nil
}

func sqlitePeerSessionsDigest(db *sql.DB) (string, int64, uint64, uint64, error) {
	h := sha256.New()
	if !sqliteTableExists(db, "peer_sessions") {
		return emptyDigest(), 0, 0, 0, nil
	}
	columns, err := sqliteTableColumns(db, "peer_sessions")
	if err != nil {
		return "", 0, 0, 0, err
	}
	selectExpr := func(name, fallback string) string {
		if columns[name] {
			return quoteStateIdentifier(name)
		}
		return fallback
	}
	query := `SELECT ` + selectExpr("contact_id", `CAST(rowid AS TEXT)`) + `, ` +
		selectExpr("epoch", `0`) + `, ` + selectExpr("root_key", `NULL`) + `, ` +
		selectExpr("send_chain_key", `NULL`) + `, ` + selectExpr("receive_chain_key", `NULL`) + `, ` +
		selectExpr("send_count", `0`) + `, ` + selectExpr("receive_count", `0`) + `, ` +
		selectExpr("pending_offer", `NULL`) + `, ` + selectExpr("status", `''`) +
		` FROM ` + quoteStateIdentifier("peer_sessions") + ` ORDER BY ` + selectExpr("contact_id", `rowid`)
	rows, err := db.Query(query)
	if err != nil {
		return "", 0, 0, 0, fmt.Errorf("read peer session continuity state: %w", err)
	}
	defer rows.Close()
	var count int64
	var sendTotal, receiveTotal uint64
	for rows.Next() {
		var contactID, status sql.NullString
		var epoch, sendCount, receiveCount sql.NullInt64
		var rootKey, sendChainKey, receiveChainKey, pendingOffer []byte
		if err := rows.Scan(&contactID, &epoch, &rootKey, &sendChainKey, &receiveChainKey, &sendCount, &receiveCount, &pendingOffer, &status); err != nil {
			return "", 0, 0, 0, fmt.Errorf("scan peer session continuity state: %w", err)
		}
		if (epoch.Valid && epoch.Int64 < 0) || (sendCount.Valid && sendCount.Int64 < 0) || (receiveCount.Valid && receiveCount.Int64 < 0) {
			return "", 0, 0, 0, fmt.Errorf("peer session %s has a negative epoch or counter", contactID.String)
		}
		send := uint64(0)
		if sendCount.Valid {
			send = uint64(sendCount.Int64)
		}
		receive := uint64(0)
		if receiveCount.Valid {
			receive = uint64(receiveCount.Int64)
		}
		if ^uint64(0)-sendTotal < send || ^uint64(0)-receiveTotal < receive {
			return "", 0, 0, 0, errors.New("peer session counter total overflow")
		}
		sendTotal += send
		receiveTotal += receive
		rootHash := sha256.Sum256(rootKey)
		sendHash := sha256.Sum256(sendChainKey)
		receiveHash := sha256.Sum256(receiveChainKey)
		offerHash := sha256.Sum256(pendingOffer)
		writeHashFields(h, "peer_session", contactID.String, fmt.Sprint(epoch.Int64), status.String,
			hex.EncodeToString(rootHash[:]), hex.EncodeToString(sendHash[:]),
			hex.EncodeToString(receiveHash[:]), fmt.Sprint(send), fmt.Sprint(receive),
			hex.EncodeToString(offerHash[:]))
		count++
	}
	if err := rows.Err(); err != nil {
		return "", 0, 0, 0, fmt.Errorf("read peer session continuity state: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), count, sendTotal, receiveTotal, nil
}

func sqlitePeerMessagesDigest(db *sql.DB) (string, int64, error) {
	h := sha256.New()
	if !sqliteTableExists(db, "peer_messages") {
		return emptyDigest(), 0, nil
	}
	columns, err := sqliteTableColumns(db, "peer_messages")
	if err != nil {
		return "", 0, err
	}
	selectExpr := func(name, fallback string) string {
		if columns[name] {
			return quoteStateIdentifier(name)
		}
		return fallback
	}
	query := `SELECT ` + selectExpr("id", `CAST(rowid AS TEXT)`) + `, ` +
		selectExpr("transport_id", `''`) + `, ` + selectExpr("contact_id", `''`) + `, ` +
		selectExpr("direction", `''`) + `, ` + selectExpr("sender_id", `''`) + `, ` +
		selectExpr("recipient_id", `''`) + `, ` + selectExpr("sequence", `0`) + `, ` +
		selectExpr("envelope_json", `''`) + `, ` + selectExpr("aad", `''`) + `, ` +
		selectExpr("status", `''`) + ` FROM ` + quoteStateIdentifier("peer_messages") +
		` ORDER BY ` + selectExpr("id", `rowid`)
	rows, err := db.Query(query)
	if err != nil {
		return "", 0, fmt.Errorf("read peer message continuity state: %w", err)
	}
	defer rows.Close()
	var count int64
	for rows.Next() {
		var id, transportID, contactID, direction, senderID, recipientID, envelope, aad, status sql.NullString
		var sequence sql.NullInt64
		if err := rows.Scan(&id, &transportID, &contactID, &direction, &senderID, &recipientID, &sequence, &envelope, &aad, &status); err != nil {
			return "", 0, fmt.Errorf("scan peer message continuity state: %w", err)
		}
		if sequence.Valid && sequence.Int64 < 0 {
			return "", 0, fmt.Errorf("peer message %s has a negative sequence", id.String)
		}
		envelopeHash := sha256.Sum256([]byte(envelope.String))
		aadHash := sha256.Sum256([]byte(aad.String))
		writeHashFields(h, "peer_message", id.String, transportID.String, contactID.String, direction.String, senderID.String, recipientID.String,
			fmt.Sprint(sequence.Int64), hex.EncodeToString(envelopeHash[:]), hex.EncodeToString(aadHash[:]), status.String)
		count++
	}
	if err := rows.Err(); err != nil {
		return "", 0, fmt.Errorf("read peer message continuity state: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), count, nil
}

func sqliteTableExists(db *sql.DB, name string) bool {
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&count); err != nil {
		return false
	}
	return count != 0
}

func sqliteTableColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query(`PRAGMA table_info(` + quoteStateIdentifier(table) + `)`)
	if err != nil {
		return nil, fmt.Errorf("read columns for %s: %w", table, err)
	}
	defer rows.Close()
	columns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, fmt.Errorf("scan columns for %s: %w", table, err)
		}
		columns[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read columns for %s: %w", table, err)
	}
	return columns, nil
}

func emptyDigest() string {
	sum := sha256.Sum256(nil)
	return hex.EncodeToString(sum[:])
}

func writeHashFields(h hash.Hash, values ...string) {
	for _, value := range values {
		_, _ = fmt.Fprintf(h, "%d:", len(value))
		_, _ = io.WriteString(h, value)
		_, _ = io.WriteString(h, "\x00")
	}
}

func compareSQLiteSnapshots(source StateBackupDatabase, sourceContacts StateBackupContacts, copied StateBackupDatabase, copiedContacts StateBackupContacts) error {
	if source.SQLiteVersion != copied.SQLiteVersion || source.JournalMode != copied.JournalMode {
		return fmt.Errorf("SQLite metadata changed (version %s/%s, journal %s/%s)", source.SQLiteVersion, copied.SQLiteVersion, source.JournalMode, copied.JournalMode)
	}
	if source.IntegrityCheck != copied.IntegrityCheck || source.ForeignKeyCheck != copied.ForeignKeyCheck || source.SchemaFingerprint != copied.SchemaFingerprint {
		return errors.New("SQLite integrity, foreign-key, or schema fingerprint changed")
	}
	if !equalStateBackupTables(source.Tables, copied.Tables) {
		return errors.New("SQLite table inventory changed")
	}
	if sourceContacts != copiedContacts {
		return errors.New("contact, peer-session, replay, or opaque-message continuity changed")
	}
	return nil
}

func compareManifestSnapshot(manifest *StateBackupManifest, database StateBackupDatabase, contacts StateBackupContacts) error {
	if manifest == nil || manifest.FormatVersion != StateBackupFormatVersion || !manifest.Complete {
		return ErrStateBackupIncomplete
	}
	if database.CopyMode != "offline-byte-copy" {
		return fmt.Errorf("unsupported backup database copy mode %q", database.CopyMode)
	}
	if err := compareSQLiteSnapshots(manifest.Database, manifest.Contacts, database, contacts); err != nil {
		return err
	}
	if manifest.Database.Checksum != stateBackupDatabaseChecksum(manifest.Database, manifest.Contacts) {
		return errors.New("manifest database checksum is invalid")
	}
	return nil
}

func stateBackupDatabaseChecksum(database StateBackupDatabase, contacts StateBackupContacts) string {
	h := sha256.New()
	writeHashFields(h, database.CopyMode, database.SQLiteVersion, database.JournalMode,
		database.IntegrityCheck, database.ForeignKeyCheck, database.SchemaFingerprint,
		contacts.Digest)
	for _, table := range database.Tables {
		writeHashFields(h, table.Name, fmt.Sprint(table.Rows))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func equalStateBackupTables(first, second []StateBackupTable) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range first {
		if first[i] != second[i] {
			return false
		}
	}
	return true
}

type sourceStateFile struct {
	Path string
}

func collectStateFiles(sourceDir string) ([]sourceStateFile, error) {
	var files []sourceStateFile
	err := filepath.WalkDir(sourceDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == sourceDir {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink is not allowed in StateDir: %s", path)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("non-regular StateDir entry is not supported: %s", path)
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		files = append(files, sourceStateFile{Path: filepath.ToSlash(filepath.Clean(rel))})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files, nil
}

func requireDatabaseFiles(files []sourceStateFile) error {
	for _, file := range files {
		if file.Path == stateDatabaseName {
			return nil
		}
	}
	return fmt.Errorf("source StateDir does not contain %s", stateDatabaseName)
}

func validateSQLiteSidecars(files []sourceStateFile) error {
	set := make(map[string]bool, len(files))
	for _, file := range files {
		set[file.Path] = true
	}
	if set[stateDatabaseName+"-wal"] && !set[stateDatabaseName+"-shm"] {
		return errors.New("SQLite WAL exists without its SHM sidecar; refusing an inconsistent offline backup")
	}
	return nil
}

func validateSQLiteSidecarsFromManifest(files []StateBackupFile) error {
	set := make(map[string]bool, len(files))
	for _, file := range files {
		set[file.Path] = true
	}
	if set[stateDatabaseName+"-wal"] && !set[stateDatabaseName+"-shm"] {
		return errors.New("copied SQLite WAL exists without its SHM sidecar")
	}
	return nil
}

func compareStateFileInventory(source []sourceStateFile, copied []StateBackupFile) error {
	if len(source) != len(copied) {
		return fmt.Errorf("file count differs (%d/%d)", len(source), len(copied))
	}
	for i := range source {
		if source[i].Path != copied[i].Path {
			return fmt.Errorf("file %d differs (%s/%s)", i, source[i].Path, copied[i].Path)
		}
	}
	return nil
}

func copyStableStateFile(ctx context.Context, source, destination string) (StateBackupFile, error) {
	before, err := os.Lstat(source)
	if err != nil {
		return StateBackupFile{}, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return StateBackupFile{}, fmt.Errorf("source is not a regular file")
	}
	input, err := os.Open(source)
	if err != nil {
		return StateBackupFile{}, err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stateBackupFileMode)
	if err != nil {
		return StateBackupFile{}, err
	}
	h := sha256.New()
	_, copyErr := copyWithContext(ctx, output, io.TeeReader(input, h))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil {
		return StateBackupFile{}, copyErr
	}
	if syncErr != nil {
		return StateBackupFile{}, syncErr
	}
	if closeErr != nil {
		return StateBackupFile{}, closeErr
	}
	after, err := os.Lstat(source)
	if err != nil {
		return StateBackupFile{}, err
	}
	if !sameStableFile(before, after) {
		return StateBackupFile{}, errors.New("source changed while it was being copied")
	}
	firstDigest := hex.EncodeToString(h.Sum(nil))
	secondDigest, err := hashFile(ctx, source)
	if err != nil {
		return StateBackupFile{}, err
	}
	if firstDigest != secondDigest {
		return StateBackupFile{}, errors.New("source checksum changed while it was being copied")
	}
	if err := os.Chmod(destination, stateBackupFileMode); err != nil {
		return StateBackupFile{}, err
	}
	return StateBackupFile{Path: "", Size: before.Size(), Mode: uint32(stateBackupFileMode.Perm()), SHA256: firstDigest}, nil
}

func copyExactStateFile(ctx context.Context, source, destination string, expected StateBackupFile) (StateBackupFile, error) {
	info, err := os.Lstat(source)
	if err != nil {
		return StateBackupFile{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return StateBackupFile{}, errors.New("backup payload file is not regular")
	}
	if info.Size() != expected.Size {
		return StateBackupFile{}, fmt.Errorf("size %d does not match manifest size %d", info.Size(), expected.Size)
	}
	return copyFileWithDigest(ctx, source, destination, expected.Path)
}

func copyFileWithDigest(ctx context.Context, source, destination, relativePath string) (StateBackupFile, error) {
	input, err := os.Open(source)
	if err != nil {
		return StateBackupFile{}, err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stateBackupFileMode)
	if err != nil {
		return StateBackupFile{}, err
	}
	h := sha256.New()
	_, copyErr := copyWithContext(ctx, output, io.TeeReader(input, h))
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil {
		return StateBackupFile{}, copyErr
	}
	if syncErr != nil {
		return StateBackupFile{}, syncErr
	}
	if closeErr != nil {
		return StateBackupFile{}, closeErr
	}
	info, err := os.Stat(destination)
	if err != nil {
		return StateBackupFile{}, err
	}
	if err := os.Chmod(destination, stateBackupFileMode); err != nil {
		return StateBackupFile{}, err
	}
	return StateBackupFile{Path: relativePath, Size: info.Size(), Mode: uint32(info.Mode().Perm()), SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

func copyWithContext(ctx context.Context, destination io.Writer, source io.Reader) (int64, error) {
	buffer := make([]byte, 128*1024)
	var total int64
	for {
		if err := contextErr(ctx); err != nil {
			return total, err
		}
		read, readErr := source.Read(buffer)
		if read > 0 {
			written, writeErr := destination.Write(buffer[:read])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != read {
				return total, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

func hashFile(ctx context.Context, path string) (string, error) {
	input, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer input.Close()
	h := sha256.New()
	if _, err := copyWithContext(ctx, io.Discard, io.TeeReader(input, h)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sameStableFile(first, second fs.FileInfo) bool {
	return first.Size() == second.Size() && first.Mode().Perm() == second.Mode().Perm() && first.ModTime() == second.ModTime() && os.SameFile(first, second)
}

func ensurePrivateParentDirs(root, directory string) error {
	rel, err := filepath.Rel(root, directory)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ErrStateBackupPathUnsafe
	}
	if rel == "." {
		return nil
	}
	parts := strings.Split(rel, string(filepath.Separator))
	current := root
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.Mkdir(current, stateBackupDirMode); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("path component is not a private directory: %s", current)
		}
		if err := os.Chmod(current, stateBackupDirMode); err != nil {
			return err
		}
	}
	return nil
}

func writePrivateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, stateBackupFileMode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func readStateBackupManifest(backupDir string) (*StateBackupManifest, error) {
	info, err := os.Lstat(backupDir)
	if err != nil {
		return nil, fmt.Errorf("stat backup directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode()&0077 != 0 {
		return nil, fmt.Errorf("backup directory must be private (0700): %s", backupDir)
	}
	manifestPath := filepath.Join(backupDir, stateBackupManifestName)
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read backup manifest: %w", err)
	}
	if manifestInfo.Mode()&os.ModeSymlink != 0 || !manifestInfo.Mode().IsRegular() || manifestInfo.Mode().Perm()&0077 != 0 {
		return nil, errors.New("backup manifest must be a private regular file")
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read backup manifest: %w", err)
	}
	var manifest StateBackupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("decode backup manifest: %w", err)
	}
	if manifest.FormatVersion != StateBackupFormatVersion || !manifest.Complete {
		return nil, ErrStateBackupIncomplete
	}
	if err := validateManifestFiles(manifest.Files); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func validateManifestFiles(files []StateBackupFile) error {
	seen := make(map[string]struct{}, len(files))
	databaseFound := false
	for _, file := range files {
		clean, err := cleanStateRelativePath(file.Path)
		if err != nil || clean != filepath.ToSlash(filepath.Clean(file.Path)) {
			return fmt.Errorf("manifest file path %q: %w", file.Path, ErrStateBackupPathUnsafe)
		}
		if _, exists := seen[clean]; exists {
			return fmt.Errorf("manifest contains duplicate file %q", clean)
		}
		seen[clean] = struct{}{}
		if clean == stateDatabaseName {
			databaseFound = true
		}
		if file.Size < 0 || file.Mode != uint32(stateBackupFileMode.Perm()) || len(file.SHA256) != sha256.Size*2 {
			return fmt.Errorf("manifest file %q has invalid size or checksum", clean)
		}
	}
	if !databaseFound {
		return errors.New("manifest does not contain cicada.sqlite3")
	}
	return nil
}

func cleanStateRelativePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" || filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return "", ErrStateBackupPathUnsafe
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", ErrStateBackupPathUnsafe
	}
	return clean, nil
}

func verifyPayloadInventory(payloadRoot string, manifestFiles []StateBackupFile) error {
	info, err := os.Lstat(payloadRoot)
	if err != nil {
		return fmt.Errorf("stat backup payload: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode()&0077 != 0 {
		return fmt.Errorf("backup payload directory must be private (0700): %s", payloadRoot)
	}
	if err := validateManifestFiles(manifestFiles); err != nil {
		return err
	}
	expected := make(map[string]StateBackupFile, len(manifestFiles))
	for _, file := range manifestFiles {
		expected[file.Path] = file
	}
	actual := make(map[string]struct{}, len(manifestFiles))
	err = filepath.WalkDir(payloadRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == payloadRoot {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("backup payload contains a symlink: %s", path)
		}
		if entry.IsDir() {
			if info, err := entry.Info(); err != nil {
				return err
			} else if info.Mode().Perm()&0077 != 0 {
				return fmt.Errorf("backup payload directory is not private: %s", path)
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("backup payload contains a non-regular file: %s", path)
		}
		rel, err := filepath.Rel(payloadRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(filepath.Clean(rel))
		file, exists := expected[rel]
		if !exists {
			return fmt.Errorf("backup payload contains an unlisted file %q", rel)
		}
		actual[rel] = struct{}{}
		if entryInfo, err := entry.Info(); err != nil {
			return err
		} else if entryInfo.Mode().Perm()&0077 != 0 || entryInfo.Size() != file.Size {
			return fmt.Errorf("backup payload file %q has unexpected mode or size", rel)
		}
		digest, err := hashFile(context.Background(), path)
		if err != nil {
			return fmt.Errorf("hash backup payload file %q: %w", rel, err)
		}
		if digest != file.SHA256 {
			return fmt.Errorf("backup payload checksum mismatch for %q", rel)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return errors.New("backup payload is missing one or more manifest files")
	}
	return nil
}

func verifyRestoredStateInventory(targetDir string, manifest *StateBackupManifest) error {
	files, err := collectStateFiles(targetDir)
	if err != nil {
		return fmt.Errorf("inventory restored StateDir: %w", err)
	}
	converted := make([]sourceStateFile, 0, len(files))
	for _, file := range manifest.Files {
		converted = append(converted, sourceStateFile{Path: file.Path})
	}
	sort.Slice(converted, func(i, j int) bool { return converted[i].Path < converted[j].Path })
	if err := compareStateFileInventory(converted, filesToBackupFiles(files)); err != nil {
		return fmt.Errorf("restored StateDir file inventory differs: %w", err)
	}
	return nil
}

func filesToBackupFiles(files []sourceStateFile) []StateBackupFile {
	result := make([]StateBackupFile, 0, len(files))
	for _, file := range files {
		result = append(result, StateBackupFile{Path: file.Path})
	}
	return result
}

func installRestoreTarget(temporary, target string) error {
	info, err := os.Lstat(target)
	if errors.Is(err, fs.ErrNotExist) {
		if err := os.Rename(temporary, target); err != nil {
			return fmt.Errorf("publish restored StateDir: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("recheck restore target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrStateRestoreTargetNotEmpty
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return fmt.Errorf("recheck restore target: %w", err)
	}
	if len(entries) != 0 {
		return ErrStateRestoreTargetNotEmpty
	}
	if err := os.Remove(target); err != nil {
		return fmt.Errorf("remove empty restore target placeholder: %w", err)
	}
	if err := os.Rename(temporary, target); err != nil {
		return fmt.Errorf("publish restored StateDir: %w", err)
	}
	return nil
}

func publishNewDirectory(temporary, destination string) error {
	if _, err := os.Lstat(destination); err == nil {
		return fmt.Errorf("backup destination appeared during copy: %w", ErrStateBackupDestinationExists)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("recheck backup destination: %w", err)
	}
	if err := os.Rename(temporary, destination); err != nil {
		return fmt.Errorf("publish backup directory: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func contextErr(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func isSQLiteBusy(err error) bool {
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database is locked") || strings.Contains(message, "database table is locked") || strings.Contains(message, "busy")
}
