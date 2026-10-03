package nodebackup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// TLSFormatVersion adds a separate private TLS payload. Older readers reject
// this version rather than silently ignoring security state outside nodes/.
const TLSFormatVersion = 3
const tlsPayloadName = "tls"
const tlsMaterialName = ".node-tls"
const tlsFloorName = ".node-tls-floors"
const maxTLSFiles = 4096
const maxTLSFileBytes int64 = 256 << 10
const maxTLSBytes int64 = 64 << 20

var ErrTLSFencesUnavailable = errors.New("Node TLS retained fencing state is missing or conflicting; recovery remains held")

// TLSMaterialManifest contains inventory metadata only. Floors in the archive
// are witnesses, never installable replacements for independently retained state.
type TLSMaterialManifest struct {
	Version     int                `json:"version"`
	Scopes      []TLSMaterialScope `json:"scopes"`
	Directories []string           `json:"directories"`
	Files       []FileEntry        `json:"files"`
	Floors      []FileEntry        `json:"floor_witnesses"`
}
type TLSMaterialScope struct {
	HubID  string `json:"hub_id"`
	NodeID string `json:"node_id"`
	Bucket string `json:"bucket"`
}
type tlsInventory struct {
	manifest              TLSMaterialManifest
	stateRoot, writerRoot string
}

// Match D1's on-disk floor encoding without importing nodetransport, which
// itself imports nodebackup. Parsing is structural, not proof authentication.
type tlsFloorWitness struct {
	Version                                     int
	HubID, NodeID                               string
	Epoch                                       uint64
	GrantDigest, ActivationDigest, ConfigDigest string
	Activation                                  []byte
}

func tlsScopeBucket(hubID, nodeID string) string {
	h := sha256.Sum256([]byte(hubID + "\x00" + nodeID))
	return hex.EncodeToString(h[:])
}
func tlsPrivatePath(path string, directory bool) error {
	if _, err := canonicalPath(path); err != nil {
		return err
	}
	s, err := os.Lstat(path)
	if err != nil {
		return err
	}
	v := reflect.ValueOf(s.Sys())
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return ErrUnsafeNodeFile
	}
	uid := v.Elem().FieldByName("Uid")
	if !uid.IsValid() || !uid.CanUint() || uid.Uint() != uint64(os.Geteuid()) {
		return ErrUnsafeNodeFile
	}
	want := privateFileMode
	if directory {
		want = privateDirMode
	}
	if s.Mode()&os.ModeSymlink != 0 || s.Mode().Perm() != want.Perm() || directory != s.IsDir() || !directory && !s.Mode().IsRegular() {
		return ErrUnsafeNodeFile
	}
	return nil
}
func tlsBoundedRead(path string) ([]byte, error) {
	if err := tlsPrivatePath(path, false); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s, err := f.Stat()
	if err != nil {
		return nil, err
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(s, current) {
		return nil, ErrUnsafeNodeFile
	}
	b, err := io.ReadAll(io.LimitReader(f, maxTLSFileBytes+1))
	if err != nil || int64(len(b)) > maxTLSFileBytes {
		return nil, ErrBackupInvalid
	}
	return b, nil
}
func readTLSFloor(path, bucket string) (tlsFloorWitness, error) {
	var w tlsFloorWitness
	b, err := tlsBoundedRead(path)
	if err != nil {
		return w, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&w) != nil {
		return w, ErrBackupInvalid
	}
	var extra any
	encoded, _ := json.Marshal(w)
	if !errors.Is(d.Decode(&extra), io.EOF) || !bytes.Equal(encoded, b) || w.Version != 1 || w.HubID == "" || validateNodeID(w.NodeID) != nil || w.Epoch == 0 || tlsScopeBucket(w.HubID, w.NodeID) != bucket || !validSHA256(w.GrantDigest) || !validSHA256(w.ConfigDigest) || !validSHA256(w.ActivationDigest) {
		return w, ErrBackupInvalid
	}
	h := sha256.Sum256(w.Activation)
	if hex.EncodeToString(h[:]) != w.ActivationDigest {
		return w, ErrBackupInvalid
	}
	return w, nil
}
func tlsFileEntry(root, rel string) (FileEntry, error) {
	b, err := tlsBoundedRead(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return FileEntry{}, err
	}
	h := sha256.Sum256(b)
	return FileEntry{Path: rel, Size: int64(len(b)), Mode: uint32(privateFileMode), SHA256: hex.EncodeToString(h[:])}, nil
}
func allowedTLSPath(rel string, directory bool) bool {
	if validateRelativePath(rel) != nil {
		return false
	}
	p := strings.Split(rel, "/")
	if len(p) == 0 || !validHexDigest(p[0]) {
		return false
	}
	if len(p) == 1 {
		return directory
	}
	if len(p) == 2 {
		if directory {
			return p[1] == "prepared" || p[1] == "epochs"
		}
		return p[1] == "active.json" || strings.HasPrefix(p[1], ".pending-") && validHexDigest(strings.TrimPrefix(p[1], ".pending-"))
	}
	if p[1] != "prepared" && p[1] != "epochs" {
		return false
	}
	if p[1] == "prepared" && !validHexDigest(p[2]) {
		return false
	}
	if p[1] == "epochs" {
		parts := strings.SplitN(p[2], "-", 2)
		if len(parts) != 2 || !validHexDigest(parts[1]) {
			return false
		}
		n, e := strconv.ParseUint(parts[0], 10, 64)
		if e != nil || n == 0 || strconv.FormatUint(n, 10) != parts[0] {
			return false
		}
	}
	if len(p) == 3 {
		return directory
	}
	if len(p) != 4 || directory {
		return false
	}
	if strings.HasPrefix(p[3], ".pending-") {
		return validHexDigest(strings.TrimPrefix(p[3], ".pending-"))
	}
	if p[1] == "prepared" {
		return p[3] == "key.pem" || p[3] == "csr.pem" || p[3] == "preparation.json"
	}
	switch p[3] {
	case "key.pem", "csr.pem", "leaf.pem", "issuer-chain.pem", "root.pem", "hub-trust.pem", "chain.pem", "stage.json":
		return true
	}
	return false
}

// Scope anchors only select files; their claims are not promoted to authority.
func tlsScopeFromAnchor(path string) (TLSMaterialScope, error) {
	var scope TLSMaterialScope
	b, err := tlsBoundedRead(path)
	if err != nil {
		return scope, err
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(b, &object) != nil {
		return scope, ErrBackupInvalid
	}
	var anchor struct {
		HubID  string `json:"hub_id"`
		NodeID string `json:"node_id"`
	}
	switch filepath.Base(path) {
	case "active.json":
		var cfg struct {
			Identity json.RawMessage `json:"identity"`
		}
		if json.Unmarshal(b, &cfg) != nil || json.Unmarshal(cfg.Identity, &anchor) != nil {
			return scope, ErrBackupInvalid
		}
	case "stage.json":
		if json.Unmarshal(object["Claims"], &anchor) != nil {
			return scope, ErrBackupInvalid
		}
	case "preparation.json":
		var preparation struct {
			Binding struct{ Control json.RawMessage }
		}
		if json.Unmarshal(b, &preparation) != nil || json.Unmarshal(preparation.Binding.Control, &anchor) != nil {
			return scope, ErrBackupInvalid
		}
	default:
		return scope, ErrBackupInvalid
	}
	if anchor.HubID == "" || len(anchor.HubID) > 256 || validateNodeID(anchor.NodeID) != nil {
		return scope, ErrBackupInvalid
	}
	scope = TLSMaterialScope{HubID: anchor.HubID, NodeID: anchor.NodeID, Bucket: tlsScopeBucket(anchor.HubID, anchor.NodeID)}
	return scope, nil
}

// inventoryTLSMaterial is called only with the existing exclusive maintenance
// locks held. It makes no directories, keys, floors or proof callbacks.
func inventoryTLSMaterial(stateRoot, nodeID, writerRoot string) (*tlsInventory, error) {
	inv := &tlsInventory{stateRoot: stateRoot, writerRoot: writerRoot, manifest: TLSMaterialManifest{Version: 1}}
	scopes := map[string]TLSMaterialScope{}
	material := filepath.Join(stateRoot, tlsMaterialName)
	if _, err := os.Lstat(material); err == nil {
		if err := tlsPrivatePath(material, true); err != nil {
			return nil, err
		}
		buckets, err := os.ReadDir(material)
		if err != nil {
			return nil, err
		}
		for _, bucket := range buckets {
			if !validHexDigest(bucket.Name()) {
				return nil, ErrUnsafeNodeFile
			}
			root := filepath.Join(material, bucket.Name())
			if err := tlsPrivatePath(root, true); err != nil {
				return nil, err
			}
			tree, err := collectTree(root, false)
			if err != nil {
				return nil, err
			}
			var bound *TLSMaterialScope
			for _, f := range tree.files {
				rel := bucket.Name() + "/" + f.path
				if !allowedTLSPath(rel, false) {
					return nil, ErrUnsafeNodeFile
				}
				if err := tlsPrivatePath(filepath.Join(root, filepath.FromSlash(f.path)), false); err != nil {
					return nil, err
				}
				switch filepath.Base(f.path) {
				case "active.json", "preparation.json", "stage.json":
					s, err := tlsScopeFromAnchor(filepath.Join(root, filepath.FromSlash(f.path)))
					if err != nil || s.Bucket != bucket.Name() {
						return nil, ErrBackupInvalid
					}
					if bound != nil && *bound != s {
						return nil, ErrBackupInvalid
					}
					bound = &s
				}
			}
			for _, dir := range tree.dirs {
				if !allowedTLSPath(bucket.Name()+"/"+dir, true) {
					return nil, ErrUnsafeNodeFile
				}
				if err := tlsPrivatePath(filepath.Join(root, filepath.FromSlash(dir)), true); err != nil {
					return nil, err
				}
			}
			// A partially written unidentified scope cannot safely be assigned to a Node.
			if bound == nil {
				return nil, ErrBackupInvalid
			}
			if bound.NodeID != nodeID {
				continue
			}
			scopes[bound.Bucket] = *bound
			inv.manifest.Directories = append(inv.manifest.Directories, bucket.Name())
			for _, dir := range tree.dirs {
				inv.manifest.Directories = append(inv.manifest.Directories, bucket.Name()+"/"+dir)
			}
			for _, f := range tree.files {
				entry, err := tlsFileEntry(material, bucket.Name()+"/"+f.path)
				if err != nil {
					return nil, err
				}
				inv.manifest.Files = append(inv.manifest.Files, entry)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if writerRoot != "" {
		floors := filepath.Join(writerRoot, tlsFloorName)
		if _, err := os.Lstat(floors); err == nil {
			if err := tlsPrivatePath(floors, true); err != nil {
				return nil, err
			}
			files, err := os.ReadDir(floors)
			if err != nil {
				return nil, err
			}
			for _, f := range files {
				bucket := strings.TrimSuffix(f.Name(), ".json")
				if !strings.HasSuffix(f.Name(), ".json") || !validHexDigest(bucket) {
					return nil, ErrUnsafeNodeFile
				}
				w, err := readTLSFloor(filepath.Join(floors, f.Name()), bucket)
				if err != nil {
					return nil, err
				}
				if w.NodeID != nodeID {
					continue
				}
				s := TLSMaterialScope{HubID: w.HubID, NodeID: w.NodeID, Bucket: bucket}
				if previous, ok := scopes[bucket]; ok && previous != s {
					return nil, ErrBackupInvalid
				}
				scopes[bucket] = s
				entry, err := tlsFileEntry(floors, f.Name())
				if err != nil {
					return nil, err
				}
				inv.manifest.Floors = append(inv.manifest.Floors, entry)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	if len(scopes) == 0 {
		return nil, nil
	}
	if writerRoot == "" {
		return nil, ErrTLSFencesUnavailable
	}
	for _, s := range scopes {
		if _, ok := fileEntryAt(inv.manifest.Floors, s.Bucket+".json"); !ok {
			return nil, ErrTLSFencesUnavailable
		}
		inv.manifest.Scopes = append(inv.manifest.Scopes, s)
	}
	sort.Slice(inv.manifest.Scopes, func(a, b int) bool { return inv.manifest.Scopes[a].Bucket < inv.manifest.Scopes[b].Bucket })
	sort.Strings(inv.manifest.Directories)
	sort.Slice(inv.manifest.Files, func(a, b int) bool { return inv.manifest.Files[a].Path < inv.manifest.Files[b].Path })
	if err := validateTLSManifest(&inv.manifest, nodeID); err != nil {
		return nil, err
	}
	return inv, nil
}
func validateTLSManifest(m *TLSMaterialManifest, nodeID string) error {
	if m == nil || m.Version != 1 || len(m.Scopes) == 0 || len(m.Files)+len(m.Floors) > maxTLSFiles {
		return ErrBackupInvalid
	}
	scopes := map[string]bool{}
	for i, s := range m.Scopes {
		if s.HubID == "" || len(s.HubID) > 256 || s.NodeID != nodeID || s.Bucket != tlsScopeBucket(s.HubID, s.NodeID) || i > 0 && m.Scopes[i-1].Bucket >= s.Bucket {
			return ErrBackupInvalid
		}
		scopes[s.Bucket] = true
	}
	dirs := map[string]bool{}
	for i, p := range m.Directories {
		if !allowedTLSPath(p, true) || !scopes[strings.Split(p, "/")[0]] || i > 0 && m.Directories[i-1] >= p {
			return ErrBackupInvalid
		}
		dirs[p] = true
	}
	var total int64
	for kind, files := range [][]FileEntry{m.Files, m.Floors} {
		for i, f := range files {
			if f.Size < 0 || f.Size > maxTLSFileBytes || f.Mode != uint32(privateFileMode) || !validSHA256(f.SHA256) || i > 0 && files[i-1].Path >= f.Path {
				return ErrBackupInvalid
			}
			total += f.Size
			if kind == 0 {
				if !allowedTLSPath(f.Path, false) || !scopes[strings.Split(f.Path, "/")[0]] {
					return ErrBackupInvalid
				}
				for parent := filepath.ToSlash(filepath.Dir(f.Path)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
					if !dirs[parent] {
						return ErrBackupInvalid
					}
				}
			} else {
				if !strings.HasSuffix(f.Path, ".json") || !scopes[strings.TrimSuffix(f.Path, ".json")] {
					return ErrBackupInvalid
				}
			}
		}
	}
	for p := range dirs {
		for parent := filepath.ToSlash(filepath.Dir(p)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			if !dirs[parent] {
				return ErrBackupInvalid
			}
		}
	}
	if total > maxTLSBytes {
		return ErrBackupInvalid
	}
	return nil
}
func writeTLSInventory(inv *tlsInventory, destination, nodeID string) (*TLSMaterialManifest, error) {
	if err := os.Mkdir(destination, privateDirMode); err != nil {
		return nil, err
	}
	for _, part := range []string{"material", "floors"} {
		if err := os.Mkdir(filepath.Join(destination, part), privateDirMode); err != nil {
			return nil, err
		}
	}
	for _, dir := range inv.manifest.Directories {
		if err := os.MkdirAll(filepath.Join(destination, "material", filepath.FromSlash(dir)), privateDirMode); err != nil {
			return nil, err
		}
	}
	for kind, files := range [][]FileEntry{inv.manifest.Files, inv.manifest.Floors} {
		root, part := filepath.Join(inv.stateRoot, tlsMaterialName), "material"
		if kind == 1 {
			root, part = filepath.Join(inv.writerRoot, tlsFloorName), "floors"
		}
		for _, entry := range files {
			if err := copyVerifiedFile(filepath.Join(root, filepath.FromSlash(entry.Path)), filepath.Join(destination, part, filepath.FromSlash(entry.Path)), entry); err != nil {
				return nil, err
			}
		}
	}
	again, err := inventoryTLSMaterial(inv.stateRoot, nodeID, inv.writerRoot)
	if err != nil || again == nil {
		return nil, ErrBackupInvalid
	}
	a, _ := json.Marshal(inv.manifest)
	b, _ := json.Marshal(again.manifest)
	if !bytes.Equal(a, b) {
		return nil, errors.New("Node TLS inventory changed during backup")
	}
	if err := syncTreeDirectories(filepath.Join(destination, "material"), inv.manifest.Directories); err != nil {
		return nil, err
	}
	for _, p := range []string{"floors", "material", ""} {
		if err := syncDirectory(filepath.Join(destination, p)); err != nil {
			return nil, err
		}
	}
	return &inv.manifest, nil
}
func verifyTLSArchive(root string, m *TLSMaterialManifest, nodeID string) error {
	if err := validateTLSManifest(m, nodeID); err != nil {
		return err
	}
	if err := tlsPrivatePath(root, true); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 2 || entries[0].Name() != "floors" || entries[1].Name() != "material" {
		return ErrBackupInvalid
	}
	for kind, files := range [][]FileEntry{m.Files, m.Floors} {
		part := "material"
		var dirs []string
		if kind == 0 {
			dirs = m.Directories
		} else {
			part = "floors"
		}
		payload := filepath.Join(root, part)
		if err := tlsPrivatePath(payload, true); err != nil {
			return err
		}
		if err := verifyPayloadInventory(payload, &Manifest{Directories: dirs, Files: files}); err != nil {
			return err
		}
		for _, entry := range files {
			if err := tlsPrivatePath(filepath.Join(payload, filepath.FromSlash(entry.Path)), false); err != nil {
				return err
			}
		}
	}
	if err := verifyTLSScopeAnchors(filepath.Join(root, "material"), m); err != nil {
		return err
	}
	for _, entry := range m.Floors {
		if _, err := readTLSFloor(filepath.Join(root, "floors", entry.Path), strings.TrimSuffix(entry.Path, ".json")); err != nil {
			return err
		}
	}
	return nil
}

// validateRetainedTLSFloors does not acquire locks or mutate paths. An archived
// floor can never create a retained fence, including after an interrupted restore.
// Archive hashes alone cannot assign one Node's private key to another scope.
// Recheck each existing anchor against the declared Hub/Node/path coordinates.
func verifyTLSScopeAnchors(root string, m *TLSMaterialManifest) error {
	for _, scope := range m.Scopes {
		if !containsString(m.Directories, scope.Bucket) {
			continue
		}
		anchored := false
		for _, file := range m.Files {
			if !strings.HasPrefix(file.Path, scope.Bucket+"/") {
				continue
			}
			switch filepath.Base(file.Path) {
			case "active.json", "preparation.json", "stage.json":
				actual, err := tlsScopeFromAnchor(filepath.Join(root, filepath.FromSlash(file.Path)))
				if err != nil || actual != scope {
					return ErrBackupInvalid
				}
				anchored = true
			}
		}
		if !anchored {
			return ErrBackupInvalid
		}
	}
	return nil
}

func validateRetainedTLSFloors(backupDir, writerRoot string, m *TLSMaterialManifest) error {
	if writerRoot == "" {
		return ErrTLSFencesUnavailable
	}
	root := filepath.Join(writerRoot, tlsFloorName)
	if err := tlsPrivatePath(root, true); err != nil {
		return ErrTLSFencesUnavailable
	}
	for _, scope := range m.Scopes {
		rel := scope.Bucket + ".json"
		entry, ok := fileEntryAt(m.Floors, rel)
		if !ok {
			return ErrTLSFencesUnavailable
		}
		archived, err := readTLSFloor(filepath.Join(backupDir, tlsPayloadName, "floors", rel), scope.Bucket)
		if err != nil || archived.NodeID != scope.NodeID || archived.HubID != scope.HubID {
			return ErrTLSFencesUnavailable
		}
		retained, err := readTLSFloor(filepath.Join(root, rel), scope.Bucket)
		if err != nil || retained.NodeID != scope.NodeID || retained.HubID != scope.HubID || retained.Epoch < archived.Epoch {
			return ErrTLSFencesUnavailable
		}
		if retained.Epoch == archived.Epoch {
			actual, err := tlsFileEntry(root, rel)
			if err != nil || actual.SHA256 != entry.SHA256 || actual.Size != entry.Size {
				return ErrTLSFencesUnavailable
			}
		}
	}
	return nil
}
func restoredTLSMatches(stateRoot string, m *TLSMaterialManifest) error {
	root := filepath.Join(stateRoot, tlsMaterialName)
	for _, scope := range m.Scopes {
		prefix := scope.Bucket + "/"
		var dirs []string
		var files []FileEntry
		// A floor-only scope has no installable material.
		if !containsString(m.Directories, scope.Bucket) {
			continue
		}
		for _, p := range m.Directories {
			if strings.HasPrefix(p, prefix) {
				dirs = append(dirs, strings.TrimPrefix(p, prefix))
			}
		}
		for _, f := range m.Files {
			if strings.HasPrefix(f.Path, prefix) {
				f.Path = strings.TrimPrefix(f.Path, prefix)
				files = append(files, f)
			}
		}
		path := filepath.Join(root, scope.Bucket)
		if err := tlsPrivatePath(path, true); err != nil {
			return err
		}
		if err := verifyPayloadInventory(path, &Manifest{Directories: dirs, Files: files}); err != nil {
			return err
		}
		for _, file := range files {
			if err := tlsPrivatePath(filepath.Join(path, filepath.FromSlash(file.Path)), false); err != nil {
				return err
			}
		}
	}
	return nil
}

// installTLSMaterial runs under caller-held locks and durable Node recovery
// registration. Existing scopes must be complete byte-identical snapshots;
// incomplete scopes are held, never repaired from an old archive.
func installTLSMaterial(backupDir, stateRoot string, m *TLSMaterialManifest) error {
	root := filepath.Join(stateRoot, tlsMaterialName)
	if len(m.Directories) == 0 {
		return nil
	}
	if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, privateDirMode); err != nil {
			return err
		}
		if err := syncDirectory(stateRoot); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := tlsPrivatePath(root, true); err != nil {
		return err
	}
	for _, scope := range m.Scopes {
		if !containsString(m.Directories, scope.Bucket) {
			continue
		}
		target := filepath.Join(root, scope.Bucket)
		if _, err := os.Lstat(target); err == nil {
			one := *m
			one.Scopes = []TLSMaterialScope{scope}
			if err := restoredTLSMatches(stateRoot, &one); err != nil {
				return ErrRestoreTargetBusy
			}
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		tmp, err := os.MkdirTemp(root, ".restore-")
		if err != nil {
			return err
		}
		cleanup := func() { _ = os.RemoveAll(tmp) }
		prefix := scope.Bucket + "/"
		var dirs []string
		for _, dir := range m.Directories {
			if strings.HasPrefix(dir, prefix) {
				rel := strings.TrimPrefix(dir, prefix)
				dirs = append(dirs, rel)
				if err := os.MkdirAll(filepath.Join(tmp, filepath.FromSlash(rel)), privateDirMode); err != nil {
					cleanup()
					return err
				}
			}
		}
		for _, entry := range m.Files {
			if strings.HasPrefix(entry.Path, prefix) {
				if err := copyVerifiedFile(filepath.Join(backupDir, tlsPayloadName, "material", filepath.FromSlash(entry.Path)), filepath.Join(tmp, filepath.FromSlash(strings.TrimPrefix(entry.Path, prefix))), entry); err != nil {
					cleanup()
					return err
				}
			}
		}
		if err := syncTreeDirectories(tmp, dirs); err != nil {
			cleanup()
			return err
		}
		if err := publishNewDirectory(tmp, target); err != nil {
			cleanup()
			return err
		}
	}
	return restoredTLSMatches(stateRoot, m)
}

func tlsRecoveryCheck(backupDir, stateRoot, writerRoot string, m *TLSMaterialManifest) string {
	if m == nil {
		return "legacy_archive_tls_not_inventoried"
	}
	if restoredTLSMatches(stateRoot, m) != nil {
		return "tls_material_missing_or_changed"
	}
	if validateRetainedTLSFloors(backupDir, writerRoot, m) != nil {
		return "tls_retained_floor_missing_or_conflicting"
	}
	return "material_and_retained_floor_checked_hub_authority_not_checked"
}
