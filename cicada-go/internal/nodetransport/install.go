package nodetransport

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodebackup"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

var ErrTLSInstall = errors.New("Node TLS installation rejected")
var ErrTLSRecoveryQuarantine = errors.New("Node TLS installation blocked by recovery quarantine")
var ErrTLSCurrentAuthorityUnavailable = errors.New("current Node TLS Hub authority is unavailable")

// TLSLocalBinding is independently trusted local state. Its versions describe
// the Hub authority, not the separate local Owner trust record's version.
type TLSLocalBinding struct {
	Control                              store.NodeControlKeyBinding
	OwnerKeyVersion, ClientDeviceVersion uint64
}

// LocalTLSInstaller is an offline library, with no reload, dial, or CLI path.
// Roots must already exist and be owned private real directories. Callbacks
// must read independently installed local state, never keys from a bundle.
// KnownApplicationPublicKeys must include ALL locally known application signing
// keys, including historical/revoked Owner, Control and Endpoint keys.
type LocalTLSInstaller struct {
	StateRoot, WriterRoot, HubID, NodeID string
	CurrentBinding                       func() (TLSLocalBinding, error)
	// Independently reads the actual current Hub Store ACTIVE row. A signed
	// receipt prepared before its activation CAS commits is insufficient. This
	// trusted offline integration must never echo a caller-provided bundle.
	CurrentActiveAuthority     func() (*store.NodeTLSAuthoritySnapshot, error)
	OwnerTrust                 *nodekeys.CryptoState
	NodeControlIdentity        *e2ee.Identity
	KnownApplicationPublicKeys func() ([][]byte, error)
	// An instance-local fault point is only set by in-package disposable tests.
	fault func(string) error
}

// These coordinates are fixed locally before any Owner grant is received.
type TLSPreparationRequest struct {
	RequestID, DNSName, HubDNSName, HubPQOrigin, ApplicationOrigin string
	HubSPKIHash, HubTrustAnchorDERHash                             string
	IssuerGeneration, IssuerSPKIHash, IssuerDERHash, RootDERHash   string
}
type TLSPreparedCandidate struct {
	RequestID                  string
	CSRPEM                     []byte
	CSRDERHash, SPKIDERHash    string
	LocalAcceptedTLSEpochFloor uint64
}
type tlsPreparation struct {
	Version                 int
	Request                 TLSPreparationRequest
	Binding                 TLSLocalBinding
	CredentialDigest        string
	CSRDERHash, SPKIDERHash string
	Floor                   uint64
}
type tlsFloor struct {
	Version                                     int
	HubID, NodeID                               string
	Epoch                                       uint64
	GrantDigest, ActivationDigest, ConfigDigest string
	Activation                                  []byte
}
type tlsStage struct {
	Version     int
	Claims      e2ee.OwnerTLSLeafGrantClaims
	Grant, Ack  []byte
	LeafDERHash string
	Config      Config
}

func tlsHash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func tlsHex(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s && !bytes.Equal(b, make([]byte, 32))
}
func tlsNonce() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return hex.EncodeToString(b), nil
}
func tlsSecond(at time.Time) bool {
	return !at.IsZero() && at.Location() == time.UTC && at.Nanosecond() == 0
}
func sameTLSIdentity(a, b e2ee.PublicIdentity) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func tlsOwned(info os.FileInfo) bool {
	// Avoid OS-specific imports so unavailable builds retain this fail-closed API.
	v := reflect.ValueOf(info.Sys())
	if !v.IsValid() || v.Kind() != reflect.Pointer || v.IsNil() {
		return false
	}
	uid := v.Elem().FieldByName("Uid")
	return uid.IsValid() && uid.CanUint() && uid.Uint() == uint64(os.Geteuid())
}
func tlsPath(path string, directory bool) error {
	absolute, e := filepath.Abs(path)
	if e != nil || absolute != path || filepath.Clean(path) != path {
		return ErrTLSInstall
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, current), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, e := os.Lstat(current)
		if e != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrTLSInstall
		}
		if current != path {
			if !info.IsDir() {
				return ErrTLSInstall
			}
			continue
		}
		if directory != info.IsDir() || !directory && !info.Mode().IsRegular() || !tlsOwned(info) || info.Mode().Perm() != map[bool]os.FileMode{true: 0700, false: 0600}[directory] {
			return ErrTLSInstall
		}
	}
	return nil
}
func (i *LocalTLSInstaller) base() string {
	return filepath.Join(i.StateRoot, ".node-tls", tlsHash([]byte(i.HubID+"\x00"+i.NodeID)))
}
func (i *LocalTLSInstaller) floorPath() string {
	return filepath.Join(i.WriterRoot, ".node-tls-floors", tlsHash([]byte(i.HubID+"\x00"+i.NodeID))+".json")
}
func (i *LocalTLSInstaller) prepPath(request string) string {
	return filepath.Join(i.base(), "prepared", tlsHash([]byte(request)))
}
func (i *LocalTLSInstaller) epochPath(c e2ee.OwnerTLSLeafGrantClaims, grant []byte) string {
	return filepath.Join(i.base(), "epochs", strconv.FormatUint(c.TLSEpoch, 10)+"-"+e2ee.NodeTLSAuthorityDigest(grant))
}

// quarantine is read-only, including the all-Node external WriterRoot registry.
func (i *LocalTLSInstaller) quarantine() error {
	for _, root := range []string{i.StateRoot, i.WriterRoot} {
		q, e := nodebackup.RecoveryQuarantineActive(root, i.NodeID)
		if e != nil || q {
			return ErrTLSRecoveryQuarantine
		}
	}
	q, e := nodebackup.WriterRootRecoveryQuarantineActive(i.WriterRoot)
	if e != nil || q {
		return ErrTLSRecoveryQuarantine
	}
	registry := filepath.Join(i.WriterRoot, "nodes", ".recovery-pending")
	info, e := os.Lstat(registry)
	if errors.Is(e, os.ErrNotExist) {
		// A missing registry beneath an abnormal existing parent is not absence.
		parent := filepath.Dir(registry)
		pi, pe := os.Lstat(parent)
		if pe == nil && (!pi.IsDir() || pi.Mode()&os.ModeSymlink != 0) || pe != nil && !errors.Is(pe, os.ErrNotExist) {
			return ErrTLSRecoveryQuarantine
		}
		return nil
	}
	if e != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !tlsOwned(info) {
		return ErrTLSRecoveryQuarantine
	}
	entries, e := os.ReadDir(registry)
	if e != nil || len(entries) != 0 {
		return ErrTLSRecoveryQuarantine
	}
	return nil
}
func (i *LocalTLSInstaller) lock() (func(), error) {
	if i == nil || i.HubID == "" || i.NodeID == "" || len(i.NodeID) > 256 || i.CurrentBinding == nil || i.OwnerTrust == nil || i.NodeControlIdentity == nil || i.KnownApplicationPublicKeys == nil {
		return nil, ErrTLSInstall
	}
	if tlsPath(i.StateRoot, true) != nil || tlsPath(i.WriterRoot, true) != nil {
		return nil, ErrTLSInstall
	}
	if e := i.quarantine(); e != nil {
		return nil, e
	}
	writer, e := nodelock.AcquireWriterRootExclusive(i.WriterRoot)
	if e != nil {
		return nil, e
	}
	node, e := nodelock.AcquireMaintenanceExclusive(i.StateRoot, i.NodeID)
	if e != nil {
		writer.Close()
		return nil, e
	}
	release := func() { node.Close(); writer.Close() }
	if e := i.quarantine(); e != nil {
		release()
		return nil, e
	}
	return release, nil
}
func (i *LocalTLSInstaller) beforeWrite() error { return i.quarantine() }
func (i *LocalTLSInstaller) makeDir(path string) error {
	if e := i.beforeWrite(); e != nil {
		return e
	}
	if e := os.Mkdir(path, 0700); e != nil {
		if !errors.Is(e, os.ErrExist) {
			return e
		}
		return tlsPath(path, true)
	}
	return tlsSync(filepath.Dir(path))
}
func tlsSync(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func (i *LocalTLSInstaller) writeNew(path string, b []byte) error {
	if tlsPath(filepath.Dir(path), true) != nil {
		return ErrTLSInstall
	}
	if e := i.beforeWrite(); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return tlsSync(filepath.Dir(path))
}
func tlsRead(path string, limit int64) ([]byte, error) {
	if tlsPath(path, false) != nil {
		return nil, ErrTLSInstall
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	before, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	opened, e := f.Stat()
	if e != nil || !os.SameFile(before, opened) {
		return nil, ErrTLSInstall
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if e != nil || int64(len(b)) > limit {
		return nil, ErrTLSInstall
	}
	return b, nil
}
func tlsJSON(path string, target any) error {
	b, e := tlsRead(path, 256<<10)
	if e != nil {
		return e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrTLSInstall
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		return ErrTLSInstall
	}
	c, e := json.Marshal(target)
	if e != nil || !bytes.Equal(b, c) {
		return ErrTLSInstall
	}
	return nil
}
func (i *LocalTLSInstaller) replace(path string, b []byte) error {
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() || tlsPath(path, false) != nil {
			return ErrTLSInstall
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return ErrTLSInstall
	}
	n, e := tlsNonce()
	if e != nil {
		return e
	}
	temporary := filepath.Join(filepath.Dir(path), ".pending-"+n)
	if e = i.writeNew(temporary, b); e != nil {
		return e
	}
	if e = i.beforeWrite(); e != nil {
		return e
	}
	if e = os.Rename(temporary, path); e != nil {
		return e
	}
	return tlsSync(filepath.Dir(path))
}
func (i *LocalTLSInstaller) initDirs() error {
	for _, p := range []string{filepath.Join(i.StateRoot, ".node-tls"), i.base(), filepath.Join(i.base(), "prepared"), filepath.Join(i.base(), "epochs"), filepath.Dir(i.floorPath())} {
		if e := i.makeDir(p); e != nil {
			return e
		}
	}
	return nil
}
func (i *LocalTLSInstaller) readFloor(requireActive bool) (tlsFloor, error) {
	var f tlsFloor
	e := tlsJSON(i.floorPath(), &f)
	if errors.Is(e, os.ErrNotExist) { // tlsRead deliberately classifies absence below.
		return f, e
	}
	if _, statErr := os.Lstat(i.floorPath()); errors.Is(statErr, os.ErrNotExist) {
		if _, ae := os.Lstat(filepath.Join(i.base(), "active.json")); !errors.Is(ae, os.ErrNotExist) {
			return f, ErrTLSInstall
		}
		return f, nil
	}
	if e != nil || f.Version != 1 || f.HubID != i.HubID || f.NodeID != i.NodeID || f.Epoch == 0 || !tlsHex(f.GrantDigest) || !tlsHex(f.ActivationDigest) || !tlsHex(f.ConfigDigest) || tlsHash(f.Activation) != f.ActivationDigest {
		return tlsFloor{}, ErrTLSInstall
	}
	if requireActive {
		b, e := tlsRead(filepath.Join(i.base(), "active.json"), 128<<10)
		if e != nil || tlsHash(b) != f.ConfigDigest {
			return tlsFloor{}, ErrTLSInstall
		}
		var c Config
		if tlsJSON(filepath.Join(i.base(), "active.json"), &c) != nil || c.Identity.HubID != i.HubID || c.Identity.NodeID != i.NodeID || c.Identity.TLSEpoch != f.Epoch {
			return tlsFloor{}, ErrTLSInstall
		}
	}
	return f, nil
}
func (i *LocalTLSInstaller) local(c *e2ee.OwnerTLSLeafGrantClaims) (TLSLocalBinding, *nodekeys.OwnerKeyTrust, error) {
	b, e := i.CurrentBinding()
	if e != nil {
		return b, nil, ErrTLSInstall
	}
	v := b.Control
	if v.State != "ACTIVE" || v.HubID != i.HubID || v.NodeID != i.NodeID || b.OwnerKeyVersion == 0 || b.ClientDeviceVersion == 0 || e2ee.ValidatePublicIdentity(v.NodePublicIdentity) != nil || e2ee.ValidatePublicIdentity(v.HubPublicIdentity) != nil || !sameTLSIdentity(i.NodeControlIdentity.Public(), v.NodePublicIdentity) {
		return b, nil, ErrTLSInstall
	}
	trust, e := i.OwnerTrust.GetNodeOwnerKeyTrustLocal(v.OwnerID, v.OwnerKeyID)
	if e != nil || trust.State != nodekeys.NodeOwnerKeyTrustActive {
		return b, nil, ErrTLSInstall
	}
	if c != nil && (c.HubID != v.HubID || c.NodeID != v.NodeID || c.OwnerID != v.OwnerID || c.OwnerKeyID != v.OwnerKeyID || c.OwnerKeyVersion != b.OwnerKeyVersion || c.ClientDeviceID != v.ClientDeviceID || c.ClientDeviceVersion != b.ClientDeviceVersion || c.OwnerBindingID != v.OwnerBindingID || c.OwnerBindingVersion != v.BindingVersion || c.CredentialDigest != v.CredentialDigest || c.CredentialVersion != v.NodeCredentialVersion || c.NodeControlKeyID != v.NodeKeyID || c.NodeControlKeyVersion != v.NodeKeyVersion || c.NodeControlKeyEpoch != v.NodeKeyEpoch || c.NodeControlBindingVersion != v.Version || c.HubControlKeyID != v.HubKeyID || c.HubControlKeyVersion != v.HubKeyVersion) {
		return b, nil, ErrTLSInstall
	}
	return b, trust, nil
}
func (i *LocalTLSInstaller) separated(csr []byte, p pqtls.TLSCSRParameters, b TLSLocalBinding, t *nodekeys.OwnerKeyTrust) error {
	keys, e := i.KnownApplicationPublicKeys()
	if e != nil || len(keys) == 0 {
		return ErrTLSInstall
	}
	keys = append(append([][]byte(nil), keys...), t.PublicIdentity.SigningPublic, b.Control.NodePublicIdentity.SigningPublic, b.Control.HubPublicIdentity.SigningPublic)
	unique := make(map[string]bool)
	list := make([][]byte, 0)
	for _, key := range keys {
		if len(key) != 1952 {
			return ErrTLSInstall
		}
		if !unique[string(key)] {
			unique[string(key)] = true
			list = append(list, key)
			if len(list) > pqtls.MaxTLSApplicationSigningPublicKeys {
				return ErrTLSInstall
			}
		}
	}
	return pqtls.CheckTLSCSRApplicationKeySeparation(csr, p, list)
}

func validPreparation(r TLSPreparationRequest) bool {
	if r.RequestID == "" || len(r.RequestID) > 256 || r.IssuerGeneration == "" || len(r.IssuerGeneration) > 256 || r.ApplicationOrigin == "" {
		return false
	}
	for _, s := range []string{r.HubSPKIHash, r.HubTrustAnchorDERHash, r.IssuerSPKIHash, r.IssuerDERHash, r.RootDERHash} {
		if !tlsHex(s) {
			return false
		}
	}
	u, e := ParseOrigin(r.HubPQOrigin)
	if e != nil || u.Hostname() != r.HubDNSName {
		return false
	}
	c := Config{Version: 1, Role: "node", Origin: r.HubPQOrigin, ApplicationOrigin: r.ApplicationOrigin, Identity: Identity{Kind: "node", HubID: "placeholder", NodeID: "placeholder", TLSEpoch: 1, DNSName: r.DNSName}, Peers: []Approval{{Identity: Identity{Kind: "hub", HubID: "placeholder", DNSName: r.HubDNSName}, PinKind: "spki-sha256", PinSHA256: r.HubSPKIHash}}}
	return c.Validate("node") == nil
}

// Prepare persists a newly generated TLS key and CSR under both exclusive locks.
// Incomplete existing candidates are rejected, never overwritten or repaired by
// generating another key under the same request identity.
func (i *LocalTLSInstaller) Prepare(r TLSPreparationRequest, at time.Time) (TLSPreparedCandidate, error) {
	var result TLSPreparedCandidate
	if !tlsSecond(at) || !validPreparation(r) {
		return result, ErrTLSInstall
	}
	release, e := i.lock()
	if e != nil {
		return result, e
	}
	defer release()
	f, e := i.readFloor(true)
	if e != nil {
		return result, e
	}
	b, t, e := i.local(nil)
	if e != nil {
		return result, e
	}
	if _, e := os.Lstat(i.prepPath(r.RequestID)); !errors.Is(e, os.ErrNotExist) {
		return result, ErrTLSInstall
	}
	key, csr, e := pqtls.GenerateTLSCSR(pqtls.TLSCSRParameters{Role: "node", DNSName: r.DNSName})
	if e != nil {
		return result, e
	}
	defer key.Destroy()
	if e = i.separated(csr.CSRPEM, csr.Parameters, b, t); e != nil {
		return result, e
	}
	secret, e := key.ExportPEM()
	if e != nil {
		return result, e
	}
	defer clear(secret)
	record := tlsPreparation{Version: 1, Request: r, Binding: b, CredentialDigest: b.Control.CredentialDigest, CSRDERHash: hex.EncodeToString(csr.CSRDERHash[:]), SPKIDERHash: hex.EncodeToString(csr.SPKIDERHash[:]), Floor: f.Epoch}
	recordJSON, e := json.Marshal(record)
	if e != nil {
		return result, e
	}
	if e = i.initDirs(); e != nil {
		return result, e
	}
	if e = i.beforeWrite(); e != nil {
		return result, e
	}
	if e = os.Mkdir(i.prepPath(r.RequestID), 0700); e != nil {
		return result, e
	}
	if e = tlsSync(filepath.Dir(i.prepPath(r.RequestID))); e != nil {
		return result, e
	}
	for _, file := range []struct {
		name string
		data []byte
	}{{"key.pem", secret}, {"csr.pem", csr.CSRPEM}, {"preparation.json", recordJSON}} {
		if e = i.writeNew(filepath.Join(i.prepPath(r.RequestID), file.name), file.data); e != nil {
			return result, e
		}
	}
	var read tlsPreparation
	if e = tlsJSON(filepath.Join(i.prepPath(r.RequestID), "preparation.json"), &read); e != nil {
		return result, e
	}
	persisted, e := tlsRead(filepath.Join(i.prepPath(r.RequestID), "csr.pem"), 32<<10)
	if e != nil {
		return result, e
	}
	check, e := pqtls.InspectTLSCSR(persisted, csr.Parameters)
	if e != nil || hex.EncodeToString(check.CSRDERHash[:]) != record.CSRDERHash || hex.EncodeToString(check.SPKIDERHash[:]) != record.SPKIDERHash {
		return result, ErrTLSInstall
	}
	return TLSPreparedCandidate{r.RequestID, persisted, record.CSRDERHash, record.SPKIDERHash, f.Epoch}, nil
}

func preparationMatches(p tlsPreparation, c e2ee.OwnerTLSLeafGrantClaims) bool {
	r := p.Request
	v := p.Binding.Control
	exactBinding := c.HubID == v.HubID && c.NodeID == v.NodeID && c.OwnerID == v.OwnerID && c.OwnerKeyID == v.OwnerKeyID && c.OwnerKeyVersion == p.Binding.OwnerKeyVersion && c.ClientDeviceID == v.ClientDeviceID && c.ClientDeviceVersion == p.Binding.ClientDeviceVersion && c.OwnerBindingID == v.OwnerBindingID && c.OwnerBindingVersion == v.BindingVersion && c.CredentialDigest == p.CredentialDigest && c.CredentialVersion == v.NodeCredentialVersion && c.NodeControlKeyID == v.NodeKeyID && c.NodeControlKeyVersion == v.NodeKeyVersion && c.NodeControlKeyEpoch == v.NodeKeyEpoch && c.NodeControlBindingVersion == v.Version && c.HubControlKeyID == v.HubKeyID && c.HubControlKeyVersion == v.HubKeyVersion
	return exactBinding && p.Version == 1 && r.RequestID == c.RequestID && r.DNSName == c.DNSName && r.HubPQOrigin == c.HubPQOrigin && r.ApplicationOrigin == c.ApplicationOrigin && r.HubSPKIHash == c.HubSPKIHash && r.HubTrustAnchorDERHash == c.HubTrustAnchorDERHash && r.IssuerGeneration == c.IssuerGeneration && r.IssuerSPKIHash == c.IssuerSPKIHash && r.IssuerDERHash == c.IssuerDERHash && r.RootDERHash == c.RootDERHash && p.CSRDERHash == c.CSRDERHash && p.SPKIDERHash == c.SPKIDERHash && c.ExpectedTLSEpochFloor >= p.Floor && c.TLSEpoch > p.Floor
}
func leafParameters(c e2ee.OwnerTLSLeafGrantClaims) pqtls.TLSLeafParameters {
	p := pqtls.TLSLeafParameters{TLSCSRParameters: pqtls.TLSCSRParameters{Role: c.Role, DNSName: c.DNSName}}
	serial, _ := hex.DecodeString(c.Serial)
	copy(p.Serial[:], serial)
	hash, _ := hex.DecodeString(c.SPKIDERHash)
	copy(p.ExpectedSPKIHash[:], hash)
	p.NotBefore, _ = time.Parse(time.RFC3339, c.NotBefore)
	p.NotAfter, _ = time.Parse(time.RFC3339, c.NotAfter)
	return p
}
func tlsRootHash(root []byte) string {
	b, rest := pem.Decode(root)
	if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return ""
	}
	return tlsHash(b.Bytes)
}
func tlsOfficialIssuerHash(chain []byte) string {
	h, e := pqtls.TLSIssuerSigningSPKIHash(chain)
	if e != nil {
		return ""
	}
	return hex.EncodeToString(h[:])
}
func (i *LocalTLSInstaller) point(name string) error {
	if i.fault != nil {
		return i.fault(name)
	}
	return nil
}

func (i *LocalTLSInstaller) activeAuthority(s store.NodeTLSAuthoritySnapshot) error {
	if i.CurrentActiveAuthority == nil {
		return ErrTLSCurrentAuthorityUnavailable
	}
	current, e := i.CurrentActiveAuthority()
	if e != nil || current == nil {
		return ErrTLSCurrentAuthorityUnavailable
	}
	if current.State != store.NodeTLSActive || current.RowVersion != s.RowVersion || current.ReservationVersion != s.ReservationVersion || current.Claims != s.Claims || current.LeafDERHash != s.LeafDERHash || !bytes.Equal(current.Grant, s.Grant) || !bytes.Equal(current.InstallAck, s.InstallAck) || !bytes.Equal(current.Activation, s.Activation) || !bytes.Equal(current.CSRPEM, s.CSRPEM) || !bytes.Equal(current.IssuerChainPEM, s.IssuerChainPEM) || !bytes.Equal(current.TrustAnchorPEM, s.TrustAnchorPEM) || !bytes.Equal(current.LeafCertificatePEM, s.LeafCertificatePEM) {
		return ErrTLSInstall
	}
	return nil
}

// Stage inspects the exact Owner-approved leaf and rereads all persisted
// material before signing an ACK with the current application NodeControl key.
// Public chains/trust are transport material, never proof-key sources.
func (i *LocalTLSInstaller) Stage(s store.NodeTLSAuthoritySnapshot, issuerChain, root, hubTrust []byte, at time.Time) ([]byte, error) {
	if !tlsSecond(at) || s.State != store.NodeTLSSigned || s.RowVersion == 0 || s.ReservationVersion != 1 || !bytes.Equal(issuerChain, s.IssuerChainPEM) || !bytes.Equal(root, s.TrustAnchorPEM) {
		return nil, ErrTLSInstall
	}
	release, e := i.lock()
	if e != nil {
		return nil, e
	}
	defer release()
	b, t, e := i.local(&s.Claims)
	if e != nil {
		return nil, e
	}
	c, e := e2ee.VerifyOwnerTLSLeafGrant(t.PublicIdentity, at, s.Grant)
	if e != nil || c != s.Claims {
		return nil, ErrTLSInstall
	}
	f, e := i.readFloor(true)
	if e != nil || c.ExpectedTLSEpochFloor < f.Epoch || c.TLSEpoch <= f.Epoch {
		return nil, ErrTLSInstall
	}
	var prep tlsPreparation
	if tlsJSON(filepath.Join(i.prepPath(c.RequestID), "preparation.json"), &prep) != nil || !preparationMatches(prep, c) || f.Epoch != prep.Floor {
		return nil, ErrTLSInstall
	}
	csr, e := tlsRead(filepath.Join(i.prepPath(c.RequestID), "csr.pem"), 32<<10)
	if e != nil {
		return nil, e
	}
	if !bytes.Equal(csr, s.CSRPEM) {
		return nil, ErrTLSInstall
	}
	if e = i.separated(csr, leafParameters(c).TLSCSRParameters, b, t); e != nil {
		return nil, e
	}
	inspect, e := pqtls.InspectTLSCSR(csr, leafParameters(c).TLSCSRParameters)
	if e != nil || hex.EncodeToString(inspect.CSRDERHash[:]) != c.CSRDERHash || hex.EncodeToString(inspect.SPKIDERHash[:]) != c.SPKIDERHash {
		return nil, ErrTLSInstall
	}
	leaf, e := pqtls.InspectTLSLeaf(s.LeafCertificatePEM, issuerChain, root, leafParameters(c), at)
	if e != nil || hex.EncodeToString(leaf.CertificateDERHash[:]) != s.LeafDERHash || hex.EncodeToString(leaf.IssuerCertificateHash[:]) != c.IssuerDERHash || tlsOfficialIssuerHash(issuerChain) != c.IssuerSPKIHash || hex.EncodeToString(leaf.TrustAnchorDERHash[:]) != c.RootDERHash || tlsRootHash(hubTrust) != c.HubTrustAnchorDERHash {
		return nil, ErrTLSInstall
	}
	dir := i.epochPath(c, s.Grant)
	if _, e := os.Lstat(dir); e == nil {
		staged, e := i.verifyStage(dir, at)
		if e != nil || !bytes.Equal(staged.Grant, s.Grant) || staged.LeafDERHash != s.LeafDERHash {
			return nil, ErrTLSInstall
		}
		return bytes.Clone(staged.Ack), nil
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, ErrTLSInstall
	}
	secret, e := tlsRead(filepath.Join(i.prepPath(c.RequestID), "key.pem"), 16<<10)
	if e != nil {
		return nil, e
	}
	defer clear(secret)
	if e = i.beforeWrite(); e != nil {
		return nil, e
	}
	if e = os.Mkdir(dir, 0700); e != nil {
		return nil, e
	}
	if e = tlsSync(filepath.Dir(dir)); e != nil {
		return nil, e
	}
	cfg := Config{Version: 1, Role: "node", Origin: c.HubPQOrigin, ApplicationOrigin: prep.Request.ApplicationOrigin, CertificateFile: filepath.Join(dir, "chain.pem"), PrivateKeyFile: filepath.Join(dir, "key.pem"), TrustFile: filepath.Join(dir, "hub-trust.pem"), Identity: Identity{Kind: "node", HubID: c.HubID, NodeID: c.NodeID, TLSEpoch: c.TLSEpoch, DNSName: c.DNSName}, Peers: []Approval{{Identity: Identity{Kind: "hub", HubID: c.HubID, DNSName: prep.Request.HubDNSName}, PinKind: "spki-sha256", PinSHA256: c.HubSPKIHash}}}
	for _, file := range []struct {
		name string
		data []byte
	}{{"key.pem", secret}, {"csr.pem", csr}, {"leaf.pem", s.LeafCertificatePEM}, {"issuer-chain.pem", issuerChain}, {"root.pem", root}, {"hub-trust.pem", hubTrust}, {"chain.pem", append(append([]byte(nil), s.LeafCertificatePEM...), issuerChain...)}} {
		if e = i.writeNew(filepath.Join(dir, file.name), file.data); e != nil {
			return nil, e
		}
	}
	if e = i.verifyDiskMaterial(dir, c, s.LeafDERHash, cfg, at, b, t); e != nil {
		return nil, e
	}
	if e = i.point("stage-material"); e != nil {
		return nil, e
	}
	nonce, e := tlsNonce()
	if e != nil {
		return nil, e
	}
	ackClaims := e2ee.NodeTLSInstallAckClaims{Version: 1, GrantClaims: c, GrantDigest: e2ee.NodeTLSAuthorityDigest(s.Grant), ReservationVersion: s.ReservationVersion, LeafDERHash: s.LeafDERHash, IssuedAt: at.Format(time.RFC3339), ExpiresAt: c.ExpiresAt, Nonce: nonce}
	// Recheck independently held application authority immediately before proof.
	if _, _, e = i.local(&c); e != nil {
		return nil, e
	}
	ack, e := e2ee.SignNodeTLSInstallAck(i.NodeControlIdentity, ackClaims)
	if e != nil {
		return nil, e
	}
	staged := tlsStage{1, c, bytes.Clone(s.Grant), ack, s.LeafDERHash, cfg}
	wire, e := json.Marshal(staged)
	if e != nil {
		return nil, e
	}
	if e = i.writeNew(filepath.Join(dir, "stage.json"), wire); e != nil {
		return nil, e
	}
	checked, e := i.verifyStage(dir, at)
	if e != nil {
		return nil, e
	}
	return bytes.Clone(checked.Ack), nil
}

func (i *LocalTLSInstaller) verifyStage(dir string, at time.Time) (tlsStage, error) {
	var s tlsStage
	if e := tlsJSON(filepath.Join(dir, "stage.json"), &s); e != nil {
		return s, e
	}
	c := s.Claims
	b, t, e := i.local(&c)
	if e != nil {
		return s, e
	}
	g, e := e2ee.VerifyOwnerTLSLeafGrant(t.PublicIdentity, at, s.Grant)
	if e != nil || g != c || dir != i.epochPath(c, s.Grant) || s.Version != 1 {
		return s, ErrTLSInstall
	}
	ack, e := e2ee.VerifyNodeTLSInstallAck(b.Control.NodePublicIdentity, at, s.Ack)
	if e != nil || ack.GrantClaims != c || ack.GrantDigest != e2ee.NodeTLSAuthorityDigest(s.Grant) || ack.ReservationVersion != 1 || ack.LeafDERHash != s.LeafDERHash {
		return s, ErrTLSInstall
	}
	var prep tlsPreparation
	if tlsJSON(filepath.Join(i.prepPath(c.RequestID), "preparation.json"), &prep) != nil || !preparationMatches(prep, c) {
		return s, ErrTLSInstall
	}
	cfg := s.Config
	if cfg.Validate("node") != nil || cfg.CertificateFile != filepath.Join(dir, "chain.pem") || cfg.PrivateKeyFile != filepath.Join(dir, "key.pem") || cfg.TrustFile != filepath.Join(dir, "hub-trust.pem") || cfg.Identity != (Identity{Kind: "node", HubID: c.HubID, NodeID: c.NodeID, TLSEpoch: c.TLSEpoch, DNSName: c.DNSName}) || cfg.Origin != c.HubPQOrigin || cfg.ApplicationOrigin != prep.Request.ApplicationOrigin || cfg.Peers[0] != (Approval{Identity: Identity{Kind: "hub", HubID: c.HubID, DNSName: prep.Request.HubDNSName}, PinKind: "spki-sha256", PinSHA256: c.HubSPKIHash}) {
		return s, ErrTLSInstall
	}
	if e = i.verifyDiskMaterial(dir, c, s.LeafDERHash, cfg, at, b, t); e != nil {
		return s, e
	}
	return s, nil
}

func (i *LocalTLSInstaller) verifyDiskMaterial(dir string, c e2ee.OwnerTLSLeafGrantClaims, leafHash string, cfg Config, at time.Time, b TLSLocalBinding, t *nodekeys.OwnerKeyTrust) error {
	files := map[string][]byte{}
	for _, name := range []string{"csr.pem", "leaf.pem", "issuer-chain.pem", "root.pem", "hub-trust.pem", "chain.pem"} {
		data, e := tlsRead(filepath.Join(dir, name), 128<<10)
		if e != nil {
			return e
		}
		files[name] = data
	}
	if !bytes.Equal(files["chain.pem"], append(append([]byte(nil), files["leaf.pem"]...), files["issuer-chain.pem"]...)) || tlsRootHash(files["hub-trust.pem"]) != c.HubTrustAnchorDERHash || tlsOfficialIssuerHash(files["issuer-chain.pem"]) != c.IssuerSPKIHash {
		return ErrTLSInstall
	}
	csr, e := pqtls.InspectTLSCSR(files["csr.pem"], leafParameters(c).TLSCSRParameters)
	if e != nil || hex.EncodeToString(csr.CSRDERHash[:]) != c.CSRDERHash || hex.EncodeToString(csr.SPKIDERHash[:]) != c.SPKIDERHash {
		return ErrTLSInstall
	}
	if e = i.separated(files["csr.pem"], csr.Parameters, b, t); e != nil {
		return e
	}
	leaf, e := pqtls.InspectTLSLeaf(files["leaf.pem"], files["issuer-chain.pem"], files["root.pem"], leafParameters(c), at)
	if e != nil || hex.EncodeToString(leaf.CertificateDERHash[:]) != leafHash || hex.EncodeToString(leaf.IssuerCertificateHash[:]) != c.IssuerDERHash || hex.EncodeToString(leaf.TrustAnchorDERHash[:]) != c.RootDERHash {
		return ErrTLSInstall
	}
	if tlsPath(cfg.PrivateKeyFile, false) != nil {
		return ErrTLSInstall
	}
	_, e = pqtls.NewClient(cfg.TLSConfig())
	return e
}

// Apply verifies the exact HubControl proof and ACK before advancing the
// independent floor. The single regular active config is replaced only after
// the floor+receipt is durable. A crash between them blocks normal reads; only
// this same signed activation can finish repair. Never rolls back a floor.
func (i *LocalTLSInstaller) Apply(s store.NodeTLSAuthoritySnapshot, at time.Time) (*Config, error) {
	if !tlsSecond(at) || s.State != store.NodeTLSActive || s.ReservationVersion != 1 {
		return nil, ErrTLSInstall
	}
	release, e := i.lock()
	if e != nil {
		return nil, e
	}
	defer release()
	if e = i.activeAuthority(s); e != nil {
		return nil, e
	}
	b, _, e := i.local(&s.Claims)
	if e != nil {
		return nil, e
	}
	activation, e := e2ee.VerifyNodeTLSActivation(b.Control.HubPublicIdentity, at, s.Activation)
	if e != nil || activation.ActivationVersion != s.RowVersion || activation.InstallAckClaims.GrantClaims != s.Claims || activation.InstallAckDigest != e2ee.NodeTLSAuthorityDigest(s.InstallAck) {
		return nil, ErrTLSInstall
	}
	staged, e := i.verifyStage(i.epochPath(s.Claims, s.Grant), at)
	if e != nil || !bytes.Equal(staged.Grant, s.Grant) || !bytes.Equal(staged.Ack, s.InstallAck) || staged.LeafDERHash != s.LeafDERHash {
		return nil, ErrTLSInstall
	}
	for _, file := range []struct {
		name     string
		expected []byte
	}{{"csr.pem", s.CSRPEM}, {"issuer-chain.pem", s.IssuerChainPEM}, {"root.pem", s.TrustAnchorPEM}, {"leaf.pem", s.LeafCertificatePEM}} {
		actual, e := tlsRead(filepath.Join(i.epochPath(s.Claims, s.Grant), file.name), 128<<10)
		if e != nil || !bytes.Equal(actual, file.expected) {
			return nil, ErrTLSInstall
		}
	}
	ack, e := e2ee.VerifyNodeTLSInstallAck(b.Control.NodePublicIdentity, at, s.InstallAck)
	if e != nil || ack != activation.InstallAckClaims {
		return nil, ErrTLSInstall
	}
	if e = i.activeAuthority(s); e != nil {
		return nil, e
	}
	if e = runtimeCheckAgentMetadata(i); e != nil {
		return nil, e
	}
	cfgJSON, e := json.Marshal(staged.Config)
	if e != nil {
		return nil, e
	}
	next := tlsFloor{Version: 1, HubID: i.HubID, NodeID: i.NodeID, Epoch: s.Claims.TLSEpoch, GrantDigest: e2ee.NodeTLSAuthorityDigest(s.Grant), ActivationDigest: e2ee.NodeTLSAuthorityDigest(s.Activation), ConfigDigest: tlsHash(cfgJSON), Activation: bytes.Clone(s.Activation)}
	current, e := i.readFloor(false)
	if e != nil {
		return nil, e
	}
	if current.Epoch == next.Epoch {
		if current.GrantDigest != next.GrantDigest || current.ActivationDigest != next.ActivationDigest || current.ConfigDigest != next.ConfigDigest {
			return nil, ErrTLSInstall
		}
	} else {
		if s.Claims.ExpectedTLSEpochFloor < current.Epoch || next.Epoch <= current.Epoch {
			return nil, ErrTLSInstall
		}
		if current.Epoch != 0 {
			if _, e = i.readFloor(true); e != nil {
				return nil, e
			}
		}
		if _, _, e = i.local(&s.Claims); e != nil {
			return nil, e
		}
		if e = i.activeAuthority(s); e != nil {
			return nil, e
		}
		wire, e := json.Marshal(next)
		if e != nil {
			return nil, e
		}
		if e = i.replace(i.floorPath(), wire); e != nil {
			return nil, e
		}
	}
	if e = i.point("floor-durable"); e != nil {
		return nil, e
	}
	if _, _, e = i.local(&s.Claims); e != nil {
		return nil, e
	}
	if e = i.activeAuthority(s); e != nil {
		return nil, e
	}
	if e = runtimeProvisionAgentLock(i); e != nil {
		return nil, e
	}
	if e = i.replace(filepath.Join(i.base(), "active.json"), cfgJSON); e != nil {
		return nil, e
	}
	if e = i.point("active-durable"); e != nil {
		return nil, e
	}
	if _, e = i.readFloor(true); e != nil {
		return nil, e
	}
	return &staged.Config, nil
}

// LoadActive is the checked startup primitive, intentionally not wired into
// product startup in D1. Calling legacy Load directly bypasses this local floor.
func (i *LocalTLSInstaller) LoadActive(at time.Time) (*Config, error) {
	if !tlsSecond(at) {
		return nil, ErrTLSInstall
	}
	release, e := i.lock()
	if e != nil {
		return nil, e
	}
	defer release()
	f, e := i.readFloor(true)
	if e != nil || f.Epoch == 0 {
		return nil, ErrTLSInstall
	}
	var proof e2ee.NodeTLSActivation
	if json.Unmarshal(f.Activation, &proof) != nil {
		return nil, ErrTLSInstall
	}
	b, _, e := i.local(&proof.Claims.InstallAckClaims.GrantClaims)
	if e != nil {
		return nil, e
	}
	if _, e = e2ee.VerifyNodeTLSActivation(b.Control.HubPublicIdentity, at, f.Activation); e != nil {
		return nil, e
	}
	// The directory is keyed by exact grant digest, already committed in floor.
	s, e := i.verifyStage(filepath.Join(i.base(), "epochs", fmt.Sprintf("%d-%s", f.Epoch, f.GrantDigest)), at)
	configWire, marshalErr := json.Marshal(s.Config)
	if e != nil || marshalErr != nil || tlsHash(configWire) != f.ConfigDigest || s.Claims != proof.Claims.InstallAckClaims.GrantClaims || e2ee.NodeTLSAuthorityDigest(s.Grant) != f.GrantDigest || e2ee.NodeTLSAuthorityDigest(s.Ack) != proof.Claims.InstallAckDigest {
		return nil, ErrTLSInstall
	}
	expected := store.NodeTLSAuthoritySnapshot{State: store.NodeTLSActive, RowVersion: proof.Claims.ActivationVersion, ReservationVersion: 1, Claims: s.Claims, Grant: s.Grant, InstallAck: s.Ack, Activation: f.Activation, LeafDERHash: s.LeafDERHash}
	dir := i.epochPath(s.Claims, s.Grant)
	for _, file := range []struct {
		name   string
		target *[]byte
	}{{"csr.pem", &expected.CSRPEM}, {"issuer-chain.pem", &expected.IssuerChainPEM}, {"root.pem", &expected.TrustAnchorPEM}, {"leaf.pem", &expected.LeafCertificatePEM}} {
		data, err := tlsRead(filepath.Join(dir, file.name), 128<<10)
		if err != nil {
			return nil, err
		}
		*file.target = data
	}
	if err := i.activeAuthority(expected); err != nil {
		return nil, err
	}
	return &s.Config, nil
}
