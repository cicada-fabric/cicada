//go:build windows

package appvault

// Explicit native acceptance only. No App profile, Owner key, or Hub is opened.
// The PowerShell runner selects these tests individually and rejects skips.
import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const n2NativeFormat = "cicada.n2.windows.synthetic-dpapi.v1"

var n2NativeHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
var n2NativeHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type n2NativeActor struct {
	SID           string `json:"sid"`
	MachineSHA256 string `json:"machine_sha256"`
	WindowsBuild  string `json:"windows_build"`
	OrdinaryUser  bool   `json:"ordinary_user"`
}

type n2NativeACE struct {
	SID   string `json:"sid"`
	Type  uint8  `json:"type"`
	Mask  uint32 `json:"mask"`
	Flags uint8  `json:"flags"`
}

type n2NativeACL struct {
	Object    string        `json:"object"`
	Owner     string        `json:"owner"`
	Protected bool          `json:"protected"`
	Directory bool          `json:"directory"`
	SDDL      string        `json:"sddl"`
	Entries   []n2NativeACE `json:"entries"`
}

type n2NativeReceipt struct {
	Schema string `json:"schema"`
	Test   string `json:"test"`
	RunID  string `json:"run_id"`
	n2NativeActor
	Assertions      []string      `json:"assertions"`
	ACLs            []n2NativeACL `json:"acls,omitempty"`
	FixtureSHA256   string        `json:"fixture_sha256,omitempty"`
	EntropySHA256   string        `json:"entropy_sha256,omitempty"`
	ProducerSID     string        `json:"producer_sid,omitempty"`
	UnwrapAttempted bool          `json:"unwrap_attempted,omitempty"`
}

type n2NativeTransfer struct {
	Format        string `json:"format"`
	RunID         string `json:"run_id"`
	ProducerSID   string `json:"producer_sid"`
	MachineSHA256 string `json:"machine_sha256"`
	Entropy       []byte `json:"entropy"`
	Wrapped       []byte `json:"wrapped"`
	KeySHA256     string `json:"key_sha256"`
}

func n2NativeRun(t *testing.T) string {
	t.Helper()
	id := os.Getenv("CICADA_N2_NATIVE_RUN_ID")
	if id == "" {
		t.Skip("NOT_RUN: use the explicit synthetic Windows acceptance runner")
	}
	if !n2NativeHex32.MatchString(id) {
		t.Fatal("invalid synthetic run ID")
	}
	return id
}

func n2NativeHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func n2NativeActorInfo(t *testing.T) n2NativeActor {
	t.Helper()
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatal("native token user unavailable")
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		t.Fatal("native token groups unavailable")
	}
	ordinary := !token.IsElevated()
	for _, g := range groups.AllGroups() {
		// Include deny-only administrator membership; an unelevated admin is
		// not the ordinary second account required by this acceptance.
		if g.Sid.String() == "S-1-5-32-544" {
			ordinary = false
		}
	}
	for _, sid := range []string{"S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-7"} {
		if user.User.Sid.String() == sid {
			ordinary = false
		}
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		t.Fatal("native machine identifier unavailable")
	}
	id, _, err := k.GetStringValue("MachineGuid")
	k.Close()
	if err != nil || strings.TrimSpace(id) == "" {
		t.Fatal("native machine identifier unavailable")
	}
	v := windows.RtlGetVersion()
	return n2NativeActor{user.User.Sid.String(), n2NativeHash([]byte(strings.ToLower(id))), fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber), ordinary}
}

func n2NativeEmit(t *testing.T, r n2NativeReceipt) {
	t.Helper()
	if t.Failed() {
		return
	}
	r.Schema, r.Test, r.RunID = "cicada.n2.windows.native-result.v1", t.Name(), n2NativeRun(t)
	r.n2NativeActor = n2NativeActorInfo(t)
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal("native result encoding failed")
	}
	fmt.Printf("N2_NATIVE_RESULT %s\n", raw)
}

func n2NativeEntropy(id string) []byte { return []byte("CICADA-N2-SYNTHETIC-DPAPI-v1\x00" + id) }

func n2NativeRoundTrip(t *testing.T, entropy []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("synthetic randomness unavailable")
	}
	defer clear(key)
	p, err := NewPlatformProtector()
	if err != nil || p.ID() != "WINDOWS-DPAPI-CURRENT-USER-v1" {
		t.Fatal("actual current-user DPAPI protector unavailable")
	}
	wrapped, err := p.WrapKey(entropy, key)
	if err != nil || len(wrapped) == 0 {
		t.Fatal("actual current-user DPAPI wrapping failed")
	}
	defer clear(wrapped)
	other, err := NewPlatformProtector()
	if err != nil {
		t.Fatal("fresh native protector unavailable")
	}
	plain, err := other.UnwrapKey(entropy, wrapped)
	defer clear(plain)
	if err != nil || !bytes.Equal(plain, key) {
		t.Fatal("actual same-user DPAPI unwrapping failed")
	}
	wrong := bytes.Clone(entropy)
	wrong[0] ^= 1
	if out, err := p.UnwrapKey(wrong, wrapped); err == nil || len(out) != 0 {
		clear(out)
		t.Fatal("wrong DPAPI entropy accepted")
	}
	bad := bytes.Clone(wrapped)
	bad[len(bad)-1] ^= 1
	if out, err := p.UnwrapKey(entropy, bad); err == nil || len(out) != 0 {
		clear(out)
		t.Fatal("corrupted synthetic DPAPI blob accepted")
	}
}

func TestN2NativeWindowsContext(t *testing.T) {
	n2NativeRun(t)
	n2NativeEmit(t, n2NativeReceipt{Assertions: []string{"native-token-and-machine-context"}})
}

func TestN2NativeWindowsProtectorRoundTrip(t *testing.T) {
	id := n2NativeRun(t)
	n2NativeRoundTrip(t, n2NativeEntropy(id))
	n2NativeEmit(t, n2NativeReceipt{Assertions: []string{"actual-platform-protector", "same-user-wrap-unwrap", "wrong-entropy-rejected", "corrupt-blob-rejected"}})
}

func n2NativeScope(id string) Scope {
	return Scope{HubID: "hub_synthetic_" + id, HubFingerprint: n2NativeHash([]byte("synthetic-hub/" + id)), Origin: "https://synthetic-n2.invalid", AccountID: "account_synthetic_" + id, OwnerID: "owner_synthetic_" + id}
}

func n2NativeVault(t *testing.T) (string, Scope) {
	t.Helper()
	id := n2NativeRun(t)
	// Leave the leaf absent: production Create must establish the Windows
	// security descriptor itself. POSIX Mkdir/Chmod is not an ACL fixture.
	path := filepath.Join(t.TempDir(), "cicada-n2-synthetic-private-"+id, "synthetic.vault")
	p, err := NewPlatformProtector()
	if err != nil {
		t.Fatal("platform protector unavailable")
	}
	scope := n2NativeScope(id)
	v, err := Create(path, scope, p)
	if err != nil {
		t.Fatal("native synthetic vault creation failed")
	}
	_, putErr := v.CompareAndSwapState("n2.synthetic", 0, []byte("SYNTHETIC native marker/"+id))
	closeErr := v.Close()
	if putErr != nil || closeErr != nil {
		t.Fatal("native synthetic vault persistence failed")
	}
	return path, scope
}

// Independently inspect the named object's native security descriptor. This
// does not call production verifyVaultACL or privateSecurityAttributes.
func n2NativeInspectACL(t *testing.T, path, label string) n2NativeACL {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("synthetic ACL object unavailable or linked")
	}
	attr, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil || attr&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		t.Fatal("synthetic ACL object is a reparse point")
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal("independent native ACL inspection failed")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		t.Fatal("independent native ACL owner unavailable")
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatal("independent native ACL control unavailable")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil || acl.AceCount > 32 {
		t.Fatal("independent native DACL unavailable or excessive")
	}
	out := n2NativeACL{Object: label, Owner: owner.String(), Protected: control&windows.SE_DACL_PROTECTED != 0, Directory: info.IsDir(), SDDL: sd.String()}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(acl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatal("synthetic ACL contains an unexpected ACE type")
		}
		sid := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart)))
		out.Entries = append(out.Entries, n2NativeACE{sid.String(), ace.Header.AceType, uint32(ace.Mask), ace.Header.AceFlags})
	}
	return out
}

func n2NativeACLValid(a n2NativeACL, sid string) bool {
	if a.Owner != sid || !a.Protected || len(a.Entries) != 2 {
		return false
	}
	seen := map[string]bool{}
	flags := uint8(0)
	if a.Directory {
		flags = 3 // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
	}
	for _, ace := range a.Entries {
		if (ace.SID != sid && ace.SID != "S-1-5-18") || seen[ace.SID] || ace.Type != 0 || ace.Mask != 0x1f01ff || ace.Flags != flags {
			return false
		}
		seen[ace.SID] = true
	}
	return seen[sid] && seen["S-1-5-18"]
}

func TestN2NativeWindowsVaultAndACL(t *testing.T) {
	path, scope := n2NativeVault(t)
	sid := n2NativeActorInfo(t).SID
	var acls []n2NativeACL
	for _, object := range []struct{ path, label string }{{filepath.Dir(path), "directory"}, {path, "vault"}, {path + ".lock", "lock"}} {
		a := n2NativeInspectACL(t, object.path, object.label)
		if !n2NativeACLValid(a, sid) {
			t.Fatal("native synthetic vault ACL invariant failed")
		}
		acls = append(acls, a)
	}
	p, _ := NewPlatformProtector()
	v, err := Open(path, scope, p)
	if err != nil {
		t.Fatal("same-user native vault reopen failed")
	}
	defer v.Close()
	data, version, found, err := v.LoadState("n2.synthetic")
	defer clear(data)
	if err != nil || !found || version != 1 || string(data) != "SYNTHETIC native marker/"+n2NativeRun(t) {
		t.Fatal("native reopened synthetic state differs")
	}
	if _, err := Open(path, scope, p); !errors.Is(err, ErrVaultBusy) {
		t.Fatal("native vault concurrent writer was not fenced")
	}
	n2NativeEmit(t, n2NativeReceipt{Assertions: []string{"actual-native-vault-create-reopen", "synthetic-state-roundtrip", "independent-owner-protected-dacl-two-aces", "directory-vault-lock-inspected", "concurrent-writer-fenced"}, ACLs: acls})
}

func TestN2NativeWindowsACLRejectsTampering(t *testing.T) {
	n2NativeRun(t)
	for _, mode := range []string{"directory-extra-ace", "vault-extra-ace", "lock-extra-ace", "directory-inheritance"} {
		t.Run(mode, func(t *testing.T) {
			path, scope := n2NativeVault(t)
			actor := n2NativeActorInfo(t)
			object, flags := path, ""
			if strings.HasPrefix(mode, "directory-") {
				object, flags = filepath.Dir(path), "OICI"
			} else if mode == "lock-extra-ace" {
				object = path + ".lock"
			}
			if !n2NativeACLValid(n2NativeInspectACL(t, object, mode), actor.SID) {
				t.Fatal("tamper fixture did not begin with a valid native ACL")
			}
			protection := windows.SECURITY_INFORMATION(windows.PROTECTED_DACL_SECURITY_INFORMATION)
			sddl := "D:P(A;" + flags + ";FA;;;" + actor.SID + ")(A;" + flags + ";FA;;;SY)"
			if mode == "directory-inheritance" {
				protection = windows.UNPROTECTED_DACL_SECURITY_INFORMATION
			} else {
				sddl += "(A;" + flags + ";FR;;;BU)"
			}
			sd, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatal("synthetic tamper ACL construction failed")
			}
			acl, _, err := sd.DACL()
			if err != nil || windows.SetNamedSecurityInfo(object, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.SECURITY_INFORMATION(protection), nil, nil, acl, nil) != nil {
				t.Fatal("owned synthetic ACL tamper failed")
			}
			before := n2NativeInspectACL(t, object, mode)
			if n2NativeACLValid(before, actor.SID) {
				t.Fatal("synthetic ACL tamper did not violate the invariant")
			}
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal("owned synthetic ciphertext unavailable")
			}
			cipherHash := n2NativeHash(contents)
			clear(contents)
			p, _ := NewPlatformProtector()
			opened, err := Open(path, scope, p)
			if opened != nil {
				opened.Close()
			}
			if !errors.Is(err, ErrInvalidVault) {
				t.Fatal("production vault accepted a tampered native ACL")
			}
			after := n2NativeInspectACL(t, object, mode)
			contents, err = os.ReadFile(path)
			if err != nil || before.SDDL != after.SDDL || n2NativeHash(contents) != cipherHash {
				t.Fatal("ACL rejection repaired permissions or changed ciphertext")
			}
			clear(contents)
			n2NativeEmit(t, n2NativeReceipt{Assertions: []string{"owned-synthetic-acl-tampered", "production-open-rejected", "no-acl-repair-or-ciphertext-change"}, ACLs: []n2NativeACL{before, after}})
		})
	}
	n2NativeEmit(t, n2NativeReceipt{Assertions: []string{"four-native-acl-negative-cases"}})
}

func n2NativeTransferPath(t *testing.T) string {
	t.Helper()
	id := n2NativeRun(t)
	path := os.Getenv("CICADA_N2_NATIVE_TRANSFER")
	volume := filepath.VolumeName(path)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(volume) != 2 || volume[1] != ':' || filepath.Base(path) != "n2-native-synthetic-"+id+".json" || filepath.Base(filepath.Dir(path)) != "cicada-n2-native-synthetic-"+id {
		t.Fatal("only the named local synthetic transfer fixture is allowed")
	}
	if rejectReparseComponents(path) != nil {
		t.Fatal("synthetic transfer path contains a reparse component")
	}
	return path
}

func n2NativePublish(t *testing.T, path string, raw []byte) {
	t.Helper()
	sid := n2NativeActorInfo(t).SID
	// Intentionally readable by authenticated users, never writable by them:
	// this encrypted synthetic blob separates DPAPI rejection from ACL denial.
	attributes := func(directory bool) *windows.SecurityAttributes {
		flags, rights := "", "FR"
		if directory {
			flags, rights = "OICI", "FRFX"
		}
		sd, err := windows.SecurityDescriptorFromString("O:" + sid + "D:P(A;" + flags + ";FA;;;" + sid + ")(A;" + flags + ";FA;;;SY)(A;" + flags + ";" + rights + ";;;AU)")
		if err != nil {
			t.Fatal("synthetic transfer security descriptor failed")
		}
		return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	}
	dirName, err := windows.UTF16PtrFromString(filepath.Dir(path))
	if err != nil || windows.CreateDirectory(dirName, attributes(true)) != nil {
		t.Fatal("synthetic transfer directory must be newly created")
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("synthetic transfer file name invalid")
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, attributes(false), windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal("new synthetic transfer creation failed")
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		windows.CloseHandle(handle)
		t.Fatal("synthetic transfer handle unavailable")
	}
	err = writeAll(f, raw)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		t.Fatal("synthetic transfer persistence failed")
	}
}

func TestN2NativeWindowsCrossUserProduce(t *testing.T) {
	id := n2NativeRun(t)
	if os.Getenv("CICADA_N2_NATIVE_PHASE") != "A" {
		t.Skip("NOT_RUN: producer requires explicit phase A")
	}
	actor := n2NativeActorInfo(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal("synthetic key generation failed")
	}
	defer clear(key)
	entropy := n2NativeEntropy(id)
	p, _ := NewPlatformProtector()
	wrapped, err := p.WrapKey(entropy, key)
	if err != nil {
		t.Fatal("synthetic transfer wrapping failed")
	}
	defer clear(wrapped)
	plain, err := p.UnwrapKey(entropy, wrapped)
	defer clear(plain)
	if err != nil || !bytes.Equal(plain, key) {
		t.Fatal("producer DPAPI control failed")
	}
	fixture := n2NativeTransfer{n2NativeFormat, id, actor.SID, actor.MachineSHA256, entropy, wrapped, n2NativeHash(key)}
	raw, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal("synthetic transfer encoding failed")
	}
	n2NativePublish(t, n2NativeTransferPath(t), raw)
	n2NativeEmit(t, n2NativeReceipt{Assertions: []string{"fresh-synthetic-dpapi-only-no-owner-vault", "producer-same-user-control", "new-readable-transfer-published"}, FixtureSHA256: n2NativeHash(raw), EntropySHA256: n2NativeHash(entropy), ProducerSID: actor.SID})
}

func n2NativeReadTransfer(t *testing.T) (n2NativeTransfer, string) {
	t.Helper()
	path := n2NativeTransferPath(t)
	expected := os.Getenv("CICADA_N2_NATIVE_FIXTURE_SHA256")
	if !n2NativeHex64.MatchString(expected) {
		t.Fatal("trusted producer fixture digest is required")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal("synthetic transfer read failed; ACL denial is not DPAPI evidence")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8192 {
		t.Fatal("synthetic transfer is not a bounded regular file")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(raw) > 8192 || n2NativeHash(raw) != expected {
		t.Fatal("readable synthetic transfer digest differs from producer")
	}
	var fixture n2NativeTransfer
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&fixture) != nil {
		t.Fatal("synthetic transfer framing invalid")
	}
	canonical, _ := json.Marshal(fixture)
	if !bytes.Equal(canonical, raw) || fixture.Format != n2NativeFormat || fixture.RunID != n2NativeRun(t) || fixture.ProducerSID == "" || fixture.MachineSHA256 != n2NativeActorInfo(t).MachineSHA256 || !bytes.Equal(fixture.Entropy, n2NativeEntropy(fixture.RunID)) || len(fixture.Wrapped) == 0 || len(fixture.Wrapped) > 4096 || !n2NativeHex64.MatchString(fixture.KeySHA256) {
		t.Fatal("synthetic transfer scope, host, entropy or DPAPI input invalid")
	}
	return fixture, n2NativeHash(raw)
}

func TestN2NativeWindowsCrossUserVerifyA(t *testing.T) {
	n2NativeRun(t)
	if os.Getenv("CICADA_N2_NATIVE_PHASE") != "A" {
		t.Skip("NOT_RUN: producer verification requires explicit phase A")
	}
	fixture, digest := n2NativeReadTransfer(t)
	if fixture.ProducerSID != n2NativeActorInfo(t).SID {
		t.Fatal("producer verification is under another SID")
	}
	p, _ := NewPlatformProtector()
	plain, err := p.UnwrapKey(fixture.Entropy, fixture.Wrapped)
	defer clear(plain)
	if err != nil || len(plain) != 32 || n2NativeHash(plain) != fixture.KeySHA256 {
		t.Fatal("separate-process producer verification failed")
	}
	n2NativeEmit(t, n2NativeReceipt{Assertions: []string{"exact-transfer-bytes-read-and-hashed", "same-entropy", "same-host", "separate-process-producer-decrypt"}, FixtureSHA256: digest, EntropySHA256: n2NativeHash(fixture.Entropy), ProducerSID: fixture.ProducerSID, UnwrapAttempted: true})
}

func TestN2NativeWindowsCrossUserRejectB(t *testing.T) {
	n2NativeRun(t)
	if os.Getenv("CICADA_N2_NATIVE_PHASE") != "B" || !n2NativeActorInfo(t).OrdinaryUser {
		t.Skip("NOT_RUN: a distinct ordinary Windows consumer account is required")
	}
	fixture, digest := n2NativeReadTransfer(t)
	if fixture.ProducerSID == n2NativeActorInfo(t).SID {
		t.Fatal("cross-user phase is running under the producer SID")
	}
	n2NativeRoundTrip(t, n2NativeEntropy(n2NativeRun(t)))
	p, _ := NewPlatformProtector()
	plain, err := p.UnwrapKey(fixture.Entropy, fixture.Wrapped)
	defer clear(plain)
	if !errors.Is(err, ErrInvalidVault) || len(plain) != 0 {
		t.Fatal("another ordinary Windows user could unwrap producer DPAPI data")
	}
	n2NativeEmit(t, n2NativeReceipt{Assertions: []string{"exact-transfer-bytes-read-and-hashed", "same-entropy", "same-host", "different-ordinary-user-sid", "consumer-own-dpapi-control", "actual-producer-unwrap-rejected"}, FixtureSHA256: digest, EntropySHA256: n2NativeHash(fixture.Entropy), ProducerSID: fixture.ProducerSID, UnwrapAttempted: true})
}
