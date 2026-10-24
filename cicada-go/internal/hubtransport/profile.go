package hubtransport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/gofrs/flock"
)

const profileName = "profile.json"
const maxProfileBytes = 64 * 1024

// Profile retains only the service signer needed by a running TLS listener.
// The CA private key remains in the private file and is loaded only for local
// initialization/leaf renewal. All three application keys remain independent.
type Profile struct {
	text        string
	stateDir    string
	mu          sync.Mutex
	certificate *tls.Certificate
	nextRefresh time.Time
}

func (*Profile) String() string           { return "hubtransport.Profile[redacted]" }
func (*Profile) GoString() string         { return "hubtransport.Profile[redacted]" }
func (p *Profile) DescriptorText() string { return p.text }
func (p *Profile) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: p.getCertificate}
}

func (p *Profile) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	at := time.Now()
	if p.certificate == nil || p.certificate.Leaf == nil || at.Before(p.certificate.Leaf.NotBefore) {
		return nil, ErrInvalid
	}
	if !p.certificate.Leaf.NotAfter.After(at.Add(7*24*time.Hour)) && !at.Before(p.nextRefresh) {
		current, err := LoadProfile(p.stateDir, p.text)
		if err != nil {
			return nil, err
		}
		p.certificate = current.certificate
		p.nextRefresh = at.Add(time.Hour)
	}
	if !at.Before(p.certificate.Leaf.NotAfter) {
		return nil, ErrInvalid
	}
	return p.certificate, nil
}

type privateProfile struct {
	Version       int    `json:"version"`
	Descriptor    string `json:"descriptor"`
	CAKeyDER      []byte `json:"ca_key_der"`
	ServiceKeyDER []byte `json:"service_key_der"`
	LeafDER       []byte `json:"leaf_der"`
}

func (p *privateProfile) clear() { clear(p.CAKeyDER); clear(p.ServiceKeyDER) }

// ProfilePresent detects even an interrupted initialization directory. Callers
// also check the independent Store pin so deleting this directory cannot reset
// a prior installation. This function never creates or repairs state.
func ProfilePresent(stateDir string) (bool, error) {
	_, err := os.Lstat(filepath.Join(stateDir, "native-tls"))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func profileDirectory(stateDir string, create bool) (string, error) {
	state, err := filepath.Abs(stateDir)
	if err != nil {
		return "", ErrInvalid
	}
	resolved, err := filepath.EvalSymlinks(state)
	if err != nil || resolved != state {
		return "", ErrInvalid
	}
	dir := filepath.Join(state, "native-tls")
	if create {
		err = os.Mkdir(dir, 0700)
		if err != nil && !errors.Is(err, os.ErrExist) {
			return "", err
		}
		if err == nil {
			parent, e := os.Open(state)
			if e != nil {
				return "", e
			}
			if e = errors.Join(parent.Sync(), parent.Close()); e != nil {
				return "", e
			}
		}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
		return "", ErrInvalid
	}
	return dir, nil
}

func profileLock(dir string, create bool) (*flock.Flock, error) {
	path := filepath.Join(dir, ".lock")
	if create {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			err = f.Close()
		}
		if err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	if _, err := clientoperator.ReadPrivateFileAllowEmpty(path); err != nil {
		return nil, ErrInvalid
	}
	l := flock.New(path, flock.SetFlag(os.O_RDONLY))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ok, err := l.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil || !ok {
		l.Close()
		return nil, ErrInvalid
	}
	held, err := l.Stat()
	current, e := os.Lstat(path)
	if err != nil || e != nil || !os.SameFile(held, current) || !current.Mode().IsRegular() || current.Mode().Perm() != 0600 {
		l.Close()
		return nil, ErrInvalid
	}
	return l, nil
}

// InitializeProfile is a controlled local operation under the caller's existing
// StateDir guard. pinned is the permanent Store descriptor, or empty only for
// first initialization. Existing material is never regenerated. A completed
// file left before Store pin commit resumes exactly; leaf renewal preserves
// CA, service key, signed descriptor, SPKI and transport epoch.
func InitializeProfile(stateDir string, hub *e2ee.Identity, identity wire.HubIdentity, node e2ee.PublicIdentity, origin, pinned string) (*Profile, error) {
	if hub == nil || !reflect.DeepEqual(hub.Public(), identity.Public) {
		return nil, ErrInvalid
	}
	if _, err := urlHostname(origin); err != nil {
		return nil, ErrInvalid
	}
	if _, err := wire.HubFingerprint(identity); err != nil {
		return nil, ErrInvalid
	}
	if e2ee.ValidatePublicIdentity(node) != nil || node.ID == identity.Public.ID {
		return nil, ErrInvalid
	}
	present, err := ProfilePresent(stateDir)
	if err != nil || (pinned != "" && !present) {
		return nil, ErrInvalid
	}
	dir, err := profileDirectory(stateDir, true)
	if err != nil {
		return nil, err
	}
	lock, err := profileLock(dir, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		if lock != nil {
			lock.Close()
		}
	}()
	path := filepath.Join(dir, profileName)
	_, statErr := os.Lstat(path)
	// A concurrent pristine creator may have made the directory but not yet
	// acquired this lock. Let it publish its original bundle; callers that saw
	// an existing empty directory never generate a substitute identity.
	deadline := time.Now().Add(10 * time.Second)
	for present && pinned == "" && errors.Is(statErr, os.ErrNotExist) && time.Now().Before(deadline) {
		lock.Close()
		time.Sleep(10 * time.Millisecond)
		lock, err = profileLock(dir, false)
		if err != nil {
			return nil, err
		}
		_, statErr = os.Lstat(path)
	}
	var data privateProfile
	if errors.Is(statErr, os.ErrNotExist) {
		if pinned != "" || present {
			return nil, ErrInvalid
		}
		data, err = newPrivateProfile(hub, identity, node, origin, time.Now())
		if err != nil {
			return nil, err
		}
		defer data.clear()
		if err = saveProfile(path, data, false); err != nil {
			return nil, err
		}
	} else {
		if statErr != nil {
			return nil, ErrInvalid
		}
		raw, err := clientoperator.ReadPrivateFile(path, maxProfileBytes)
		if err != nil {
			return nil, ErrInvalid
		}
		defer clear(raw)
		if readProfileJSON(raw, &data) != nil {
			return nil, ErrInvalid
		}
		defer data.clear()
	}
	d, err := DecodeDescriptor(data.Descriptor)
	if err != nil || (pinned != "" && pinned != data.Descriptor) || d.Claims.Origin != origin || !reflect.DeepEqual(d.Claims.Hub, identity) || !reflect.DeepEqual(d.Claims.NodeControl, node) {
		return nil, ErrInvalid
	}
	return refreshPrivateProfile(stateDir, path, &data)
}

func urlHostname(origin string) (string, error) {
	canonical, err := ownerbootstrap.CanonicalOrigin(origin, false)
	u, parseErr := url.Parse(origin)
	if err != nil || parseErr != nil || canonical != origin {
		return "", ErrInvalid
	}
	return u.Hostname(), nil
}

func LoadProfile(stateDir, pinned string) (*Profile, error) {
	if pinned == "" {
		return nil, ErrInvalid
	}
	dir, err := profileDirectory(stateDir, false)
	if err != nil {
		return nil, err
	}
	lock, err := profileLock(dir, false)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	raw, err := clientoperator.ReadPrivateFile(filepath.Join(dir, profileName), maxProfileBytes)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(raw)
	var data privateProfile
	if readProfileJSON(raw, &data) != nil {
		return nil, ErrInvalid
	}
	defer data.clear()
	if data.Descriptor != pinned {
		return nil, ErrInvalid
	}
	return refreshPrivateProfile(stateDir, filepath.Join(dir, profileName), &data)
}

// The caller holds the independent exclusive profile lock. Renewal never
// re-signs the randomized descriptor signature or creates another private key.
func refreshPrivateProfile(stateDir, path string, data *privateProfile) (*Profile, error) {
	p, caKey, serviceKey, err := checkPrivateProfile(*data, time.Time{})
	if err != nil {
		return nil, err
	}
	d, err := DecodeDescriptor(data.Descriptor)
	at := time.Now()
	if err != nil || ValidateDescriptor(d, at) != nil {
		return nil, ErrInvalid
	}
	leaf := p.certificate.Leaf
	root, err := x509.ParseCertificate(d.Claims.RootCertificateDER)
	if err != nil {
		return nil, ErrInvalid
	}
	if !leaf.NotAfter.After(at.Add(7*24*time.Hour)) && !leaf.NotAfter.Equal(root.NotAfter) {
		data.LeafDER, err = issueServiceLeaf(root, caKey, serviceKey, d.Claims.ServerName, at)
		if err != nil {
			return nil, err
		}
		if err = saveProfile(path, *data, true); err != nil {
			return nil, err
		}
	}
	p, _, _, err = checkPrivateProfile(*data, at)
	if err != nil {
		return nil, err
	}
	p.stateDir = stateDir
	return p, nil
}

func readProfileJSON(raw []byte, data *privateProfile) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(data) != nil {
		return ErrInvalid
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		return ErrInvalid
	}
	canonical, err := json.Marshal(data)
	defer clear(canonical)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrInvalid
	}
	return nil
}

func parsePrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	value, err := x509.ParsePKCS8PrivateKey(raw)
	key, ok := value.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, ErrInvalid
	}
	return key, nil
}

func checkPrivateProfile(data privateProfile, at time.Time) (*Profile, *ecdsa.PrivateKey, *ecdsa.PrivateKey, error) {
	bad := func() (*Profile, *ecdsa.PrivateKey, *ecdsa.PrivateKey, error) { return nil, nil, nil, ErrInvalid }
	d, err := DecodeDescriptor(data.Descriptor)
	if err != nil || data.Version != Version || ValidateDescriptor(d, at) != nil {
		return bad()
	}
	caKey, err := parsePrivateKey(data.CAKeyDER)
	if err != nil {
		return bad()
	}
	serviceKey, err := parsePrivateKey(data.ServiceKeyDER)
	if err != nil {
		return bad()
	}
	root, err := x509.ParseCertificate(d.Claims.RootCertificateDER)
	if err != nil || !reflect.DeepEqual(root.PublicKey, &caKey.PublicKey) || reflect.DeepEqual(caKey.PublicKey, serviceKey.PublicKey) {
		return bad()
	}
	leaf, err := x509.ParseCertificate(data.LeafDER)
	if err != nil || leaf.IsCA || !reflect.DeepEqual(leaf.PublicKey, &serviceKey.PublicKey) {
		return bad()
	}
	pin := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(pin[:]) != d.Claims.ServerSPKISHA256 {
		return bad()
	}
	when := at
	if when.IsZero() {
		when = leaf.NotBefore.Add(time.Second)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: d.Claims.ServerName, CurrentTime: when, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return bad()
	}
	return &Profile{text: data.Descriptor, certificate: &tls.Certificate{Certificate: [][]byte{bytes.Clone(data.LeafDER), bytes.Clone(d.Claims.RootCertificateDER)}, PrivateKey: serviceKey, Leaf: leaf}}, caKey, serviceKey, nil
}

func newPrivateProfile(hub *e2ee.Identity, identity wire.HubIdentity, node e2ee.PublicIdentity, origin string, at time.Time) (privateProfile, error) {
	var data privateProfile
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return data, err
	}
	serviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return data, err
	}
	serial, err := profileSerial()
	if err != nil {
		return data, err
	}
	at = at.UTC().Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Cicada private installation CA"}, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: at.Add(-5 * time.Minute), NotAfter: at.AddDate(10, 0, 0)}
	rootDER, err := x509.CreateCertificate(rand.Reader, template, template, &caKey.PublicKey, caKey)
	if err != nil {
		return data, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return data, err
	}
	fp, err := wire.HubFingerprint(identity)
	if err != nil {
		return data, err
	}
	name, err := urlHostname(origin)
	if err != nil {
		return data, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&serviceKey.PublicKey)
	if err != nil {
		return data, err
	}
	pin := sha256.Sum256(spki)
	d, err := SignDescriptor(hub, Claims{Format: DescriptorFormat, Version: Version, Origin: origin, Hub: identity, HubFingerprint: fp, NodeControl: node, NodeControlKeyVersion: 1,
		TransportEpoch: 1, ServerName: name, RootCertificateDER: rootDER, ServerSPKISHA256: hex.EncodeToString(pin[:])})
	if err != nil {
		return data, err
	}
	text, err := EncodeDescriptor(d)
	if err != nil {
		return data, err
	}
	data = privateProfile{Version: Version, Descriptor: text}
	data.CAKeyDER, err = x509.MarshalPKCS8PrivateKey(caKey)
	if err != nil {
		return data, err
	}
	data.ServiceKeyDER, err = x509.MarshalPKCS8PrivateKey(serviceKey)
	if err != nil {
		data.clear()
		return privateProfile{}, err
	}
	data.LeafDER, err = issueServiceLeaf(root, caKey, serviceKey, name, at)
	if err != nil {
		data.clear()
		return privateProfile{}, err
	}
	return data, nil
}

func issueServiceLeaf(root *x509.Certificate, caKey, serviceKey *ecdsa.PrivateKey, name string, at time.Time) ([]byte, error) {
	serial, err := profileSerial()
	if err != nil {
		return nil, err
	}
	at = at.UTC().Truncate(time.Second)
	until := at.Add(90 * 24 * time.Hour)
	if root.NotAfter.Before(until) {
		until = root.NotAfter
	}
	if !until.After(at.Add(time.Hour)) {
		return nil, ErrInvalid
	}
	before := at.Add(-5 * time.Minute)
	if root.NotBefore.After(before) {
		before = root.NotBefore
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Cicada Hub service"}, NotBefore: before, NotAfter: until,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(name); ip != nil {
		leaf.IPAddresses = []net.IP{ip}
	} else {
		leaf.DNSNames = []string{name}
	}
	return x509.CreateCertificate(rand.Reader, leaf, root, &serviceKey.PublicKey, caKey)
}

func profileSerial() (*big.Int, error) {
	for {
		n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil || n.Sign() > 0 {
			return n, err
		}
	}
}

func saveProfile(path string, data privateProfile, replace bool) error {
	raw, err := json.Marshal(data)
	if err != nil || len(raw) > maxProfileBytes {
		return ErrInvalid
	}
	defer clear(raw)
	f, err := os.CreateTemp(filepath.Dir(path), ".profile-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if replace {
		err = os.Rename(temporary, path)
	} else {
		err = os.Link(temporary, path)
	}
	if err != nil {
		return err
	}
	if err = os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(dir.Sync(), dir.Close())
}
