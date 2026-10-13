// Package clientoperator implements a bounded, independently pinned management
// Client. It never receives an Owner private key or a Node credential.
package clientoperator

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/gofrs/flock"
)

const Suite = "ML-KEM-768+ML-DSA-65+AES-256-GCM"

var ErrBusy = errors.New("Client profile is already in use")
var ErrPending = errors.New("recover or retry the saved Client operation before starting another")
var ErrUncertain = errors.New("Node confirmation outcome is uncertain; inspect authoritative Node list; new confirmations are fenced")

// HubIdentity is the complete public document supplied through an independent
// trusted channel. Fetching a document from the target Hub does not establish it.
type HubIdentity struct {
	Contract   string              `json:"contract"`
	HubID      string              `json:"hub_id"`
	Public     e2ee.PublicIdentity `json:"control_public_identity"`
	KeyVersion uint64              `json:"control_key_version"`
	Suite      string              `json:"suite"`
}

type EnrollmentManifest struct {
	Format               string              `json:"format"`
	HubID                string              `json:"hub_id"`
	OwnerID              string              `json:"owner_id"`
	OwnerKeyID           string              `json:"owner_key_id"`
	DeviceID             string              `json:"device_id"`
	DeviceKeyFingerprint string              `json:"device_key_fingerprint"`
	Purpose              string              `json:"purpose"`
	DevicePublicIdentity e2ee.PublicIdentity `json:"device_public_identity"`
}

type pending struct {
	Packet           []byte           `json:"packet"`
	Route            clientwire.Route `json:"route"`
	ResponseSequence uint64           `json:"response_sequence"`
}
type enrollment struct {
	Body        []byte    `json:"body"`
	ValidatedAt time.Time `json:"validated_at"`
}
type state struct {
	Version           int                 `json:"version"`
	Origin            string              `json:"origin"`
	AllowLoopbackHTTP bool                `json:"allow_loopback_http"`
	Hub               HubIdentity         `json:"hub"`
	OwnerID           string              `json:"owner_id"`
	OwnerPublic       e2ee.PublicIdentity `json:"owner_public"`
	DeviceID          string              `json:"device_id"`
	Private           []byte              `json:"device_private"`
	Binding           *clientwire.Binding `json:"binding,omitempty"`
	NextRequest       uint64              `json:"next_request"`
	NextResponse      uint64              `json:"next_response"`
	Enrollment        *enrollment         `json:"enrollment,omitempty"`
	Pending           *pending            `json:"pending,omitempty"`
	Review            *NodeReview         `json:"node_review,omitempty"`
	Uncertain         bool                `json:"uncertain_confirmation"`
}

type Profile struct {
	dir      string
	lock     *flock.Flock
	state    state
	identity *e2ee.Identity
	client   *http.Client
	broken   bool
}

func canonicalOrigin(raw string, allowHTTP bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		u.ForceQuery || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", errors.New("Client origin must be an HTTPS origin without userinfo, path, query or fragment")
	}
	if u.Scheme != "https" {
		ip := net.ParseIP(u.Hostname())
		if u.Scheme != "http" || !allowHTTP || ip == nil || !ip.IsLoopback() {
			return "", errors.New("HTTPS is required; explicit development HTTP accepts only literal loopback addresses")
		}
	}
	return u.Scheme + "://" + u.Host, nil
}

func privateDirectory(dir string) (string, error) {
	if runtime.GOOS == "windows" {
		return "", errors.New("Client private custody requires Unix permissions; Windows ACL custody is not implemented")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return "", errors.New("Client profile directory must exist without symlink components")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return "", errors.New("Client profile directory must have mode 0700")
	}
	return abs, nil
}

func ReadPrivateFile(path string, max int64) ([]byte, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil || resolved != abs {
		return nil, errors.New("private input must not contain symlinks")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("private input must be a regular mode 0600 file")
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, errors.New("private input changed during open")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || len(b) == 0 || int64(len(b)) > max {
		return nil, errors.New("private input has invalid size")
	}
	return b, nil
}

func strictJSON(data []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func acquire(dir string) (*Profile, error) {
	dir, err := privateDirectory(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, ".client.lock")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		err = f.Close()
	} else if errors.Is(err, os.ErrExist) {
		_, err = ReadPrivateFileAllowEmpty(path)
	}
	if err != nil {
		return nil, err
	}
	l := flock.New(path, flock.SetPermissions(0600))
	ok, err := l.TryLock()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrBusy
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &Profile{dir: dir, lock: l, client: &http.Client{Timeout: 20 * time.Second, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Client redirects are forbidden") }}}, nil
}

func ReadPrivateFileAllowEmpty(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("Client lock must be a private regular file")
	}
	return info, nil
}

func (p *Profile) Close() error {
	if p == nil || p.lock == nil {
		return nil
	}
	p.client.CloseIdleConnections()
	return p.lock.Unlock()
}

func (p *Profile) save() error {
	if p.broken {
		return errors.New("Client profile persistence previously failed; reopen before continuing")
	}
	data, err := json.Marshal(p.state)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(p.dir, ".client-state-*")
	if err != nil {
		p.broken = true
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil {
		err = os.Rename(name, filepath.Join(p.dir, "client.json"))
	}
	if err == nil {
		var d *os.File
		d, err = os.Open(p.dir)
		if err == nil {
			err = errors.Join(d.Sync(), d.Close())
		}
	}
	if err != nil {
		p.broken = true
	}
	return err
}

func Prepare(dir, origin, ownerID string, hub HubIdentity, owner e2ee.PublicIdentity, allowHTTP bool) (*Profile, error) {
	origin, err := canonicalOrigin(origin, allowHTTP)
	if err != nil {
		return nil, err
	}
	if hub.Contract != "android-hub-v1" || hub.HubID == "" || hub.KeyVersion != 1 || hub.Suite != Suite ||
		e2ee.ValidatePublicIdentity(hub.Public) != nil || e2ee.ValidatePublicIdentity(owner) != nil ||
		strings.TrimSpace(ownerID) != ownerID || ownerID == "" || len(ownerID) > 256 || strings.ContainsAny(ownerID, " /\\\t\n\r") {
		return nil, errors.New("invalid independently supplied Hub or Owner identity")
	}
	p, err := acquire(dir)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			p.Close()
		}
	}()
	if _, err := os.Lstat(filepath.Join(p.dir, "client.json")); !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("Client profile already exists or cannot be inspected")
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		return nil, err
	}
	private, err := identity.MarshalBinary()
	if err != nil {
		return nil, err
	}
	p.identity = identity
	p.state = state{Version: 1, Origin: origin, AllowLoopbackHTTP: allowHTTP, Hub: hub, OwnerID: ownerID, OwnerPublic: owner,
		DeviceID: "operator-" + strings.TrimPrefix(identity.Public().ID, "pq1-"), Private: private, NextRequest: 1, NextResponse: 1}
	if err = p.save(); err != nil {
		return nil, err
	}
	ok = true
	return p, nil
}

func Open(dir string) (*Profile, error) {
	p, err := acquire(dir)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			p.Close()
		}
	}()
	data, err := ReadPrivateFile(filepath.Join(p.dir, "client.json"), 1024*1024)
	if err != nil {
		return nil, err
	}
	if err = strictJSON(data, &p.state); err != nil {
		return nil, errors.New("invalid Client profile")
	}
	s := p.state
	origin, err := canonicalOrigin(s.Origin, s.AllowLoopbackHTTP)
	if err != nil || origin != s.Origin || s.Version != 1 || s.NextRequest == 0 || s.NextResponse == 0 ||
		s.Hub.KeyVersion != 1 || s.Hub.Contract != "android-hub-v1" || s.Hub.Suite != Suite || s.Hub.HubID == "" ||
		e2ee.ValidatePublicIdentity(s.Hub.Public) != nil || e2ee.ValidatePublicIdentity(s.OwnerPublic) != nil {
		return nil, errors.New("invalid Client profile identity or counters")
	}
	p.identity, err = e2ee.UnmarshalIdentity(s.Private)
	if err != nil {
		return nil, errors.New("invalid Client private identity")
	}
	if s.DeviceID != "operator-"+strings.TrimPrefix(p.identity.Public().ID, "pq1-") {
		return nil, errors.New("Client profile device identity changed")
	}
	if s.Binding != nil && (s.Binding.HubID != s.Hub.HubID || s.Binding.OwnerID != s.OwnerID || s.Binding.DeviceID != s.DeviceID || s.Binding.SessionEpoch == 0 || s.Binding.HubKeyVersion != 1 || s.Binding.DeviceKeyVersion != 1) {
		return nil, errors.New("Client profile binding changed")
	}
	if s.Pending != nil && (s.Binding == nil || s.Pending.Route.Sequence != s.NextRequest || s.Pending.ResponseSequence != s.NextResponse) {
		return nil, errors.New("Client pending counters changed")
	}
	ok = true
	return p, nil
}

func (p *Profile) Manifest() EnrollmentManifest {
	fingerprint, _ := e2ee.OwnerDevicePublicKeyFingerprint(p.identity.Public())
	return EnrollmentManifest{Format: "cicada.owner-device-enrollment.v1", HubID: p.state.Hub.HubID, OwnerID: p.state.OwnerID,
		OwnerKeyID: p.state.OwnerPublic.ID, DeviceID: p.state.DeviceID, DeviceKeyFingerprint: fingerprint,
		Purpose: e2ee.OwnerDevicePurposeControl, DevicePublicIdentity: p.identity.Public()}
}

func (p *Profile) WriteManifest() (string, error) {
	if err := p.requireUsable(); err != nil {
		return "", err
	}
	path := filepath.Join(p.dir, "enrollment-public.json")
	data, err := json.MarshalIndent(p.Manifest(), "", "  ")
	if err != nil {
		return "", err
	}
	data = append(data, '\n')
	if _, err := os.Lstat(path); err == nil {
		existing, err := ReadPrivateFile(path, 65536)
		if err != nil || !bytes.Equal(existing, data) {
			return "", errors.New("existing public manifest differs from this Client profile")
		}
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	f, err := os.CreateTemp(p.dir, ".client-manifest-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil {
		err = os.Rename(name, path)
	}
	if err == nil {
		d, openErr := os.Open(p.dir)
		if openErr != nil {
			err = openErr
		} else {
			err = errors.Join(d.Sync(), d.Close())
		}
	}
	return path, err
}

func (p *Profile) requireUsable() error {
	if p.broken {
		return fmt.Errorf("Client profile requires reopen after persistence failure")
	}
	return nil
}
