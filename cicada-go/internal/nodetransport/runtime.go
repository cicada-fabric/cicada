package nodetransport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
	"github.com/gofrs/flock"
)

var ErrTLSRuntimeClosed = errors.New("checked Node TLS runtime is closed")

// RuntimeOptions is a trusted local integration boundary, not a wire input.
// OpenLocal must only read independently accepted local binding, identities,
// Owner trust and the complete retained public-key inventory. It runs while
// the maintenance/lifetime locks are held and must not create or chmod keys.
// QueryCurrent performs a new authenticated read of the actual Hub committed
// ACTIVE authority for every invocation. Its temporary transport is private to
// that bounded read-only query; it must never publish Relay or job traffic.
type RuntimeOptions struct {
	StateRoot, WriterRoot, HubID, NodeID, ApplicationOrigin, ConfigPath string
	OpenLocal                                                           func() (*LocalTLSInstaller, func(), error)
	QueryCurrent                                                        func(context.Context, *Config) (*store.NodeTLSAuthoritySnapshot, error)
}

// Runtime is one stable per-Hub transport and lifetime lock owner. v0.1 has no
// reload or maintenance-Apply method: stop, maintain offline, checked restart.
type Runtime struct {
	state *runtimeState
}

type runtimeState struct {
	mu         sync.Mutex
	closed     bool
	base       http.RoundTripper
	ctx        context.Context
	cancel     context.CancelFunc
	bodies     map[*runtimeBody]struct{}
	requests   sync.WaitGroup
	once       sync.Once
	closeLocal func()
	locks      []*runtimeHeldLock
}

func runtimeCoordinates(o RuntimeOptions) *LocalTLSInstaller {
	return &LocalTLSInstaller{StateRoot: o.StateRoot, WriterRoot: o.WriterRoot, HubID: o.HubID, NodeID: o.NodeID}
}

// ReadAcceptedTLSRuntimeBinding is called by the trusted local reader while
// OpenRuntime owns its locks. The source is the original independently
// accepted Prepare record, not grant claims. Existing application state and
// Owner trust must still independently match it before it can be used.
func ReadAcceptedTLSRuntimeBinding(stateRoot, writerRoot, hubID, nodeID string) (TLSLocalBinding, error) {
	i := &LocalTLSInstaller{StateRoot: stateRoot, WriterRoot: writerRoot, HubID: hubID, NodeID: nodeID}
	if err := i.quarantine(); err != nil {
		return TLSLocalBinding{}, err
	}
	return readAcceptedTLSBinding(i)
}
func readAcceptedTLSBinding(i *LocalTLSInstaller) (TLSLocalBinding, error) {
	stateRoot, writerRoot, hubID, nodeID := i.StateRoot, i.WriterRoot, i.HubID, i.NodeID
	var zero TLSLocalBinding
	if tlsPath(stateRoot, true) != nil || tlsPath(writerRoot, true) != nil {
		return zero, ErrTLSInstall
	}
	f, err := i.readFloor(true)
	if err != nil || f.Epoch == 0 {
		return zero, ErrTLSInstall
	}
	var proof e2ee.NodeTLSActivation
	if json.Unmarshal(f.Activation, &proof) != nil {
		return zero, ErrTLSInstall
	}
	c := proof.Claims.InstallAckClaims.GrantClaims
	if e2ee.ValidateOwnerTLSLeafGrantClaims(c) != nil || c.HubID != hubID || c.NodeID != nodeID || c.TLSEpoch != f.Epoch {
		return zero, ErrTLSInstall
	}
	var prep tlsPreparation
	if tlsJSON(filepath.Join(i.prepPath(c.RequestID), "preparation.json"), &prep) != nil || prep.Version != 1 || !preparationMatches(prep, c) || prep.CredentialDigest == "" {
		return zero, ErrTLSInstall
	}
	b := prep.Binding
	b.Control.CredentialDigest = prep.CredentialDigest
	if b.Control.HubID != hubID || b.Control.NodeID != nodeID || b.Control.State != "ACTIVE" {
		return zero, ErrTLSInstall
	}
	return b, nil
}

// ReadRetainedTLSPreparationSigningPublicKeys includes independently accepted
// historical NodeControl/HubControl publics still present in prepared records.
// It never treats TLS keys or certificate keys as application proof keys.
func ReadRetainedTLSPreparationSigningPublicKeys(stateRoot, writerRoot, hubID, nodeID string) ([][]byte, error) {
	i := &LocalTLSInstaller{StateRoot: stateRoot, WriterRoot: writerRoot, HubID: hubID, NodeID: nodeID}
	if err := i.quarantine(); err != nil {
		return nil, err
	}
	return readRetainedTLSPreparationKeys(i)
}
func readRetainedTLSPreparationKeys(i *LocalTLSInstaller) ([][]byte, error) {
	hubID, nodeID := i.HubID, i.NodeID
	dir := filepath.Join(i.base(), "prepared")
	if tlsPath(dir, true) != nil {
		return nil, ErrTLSInstall
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > 1024 {
		return nil, ErrTLSInstall
	}
	out := make([][]byte, 0, len(entries)*2)
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if !entry.IsDir() || !tlsHex(entry.Name()) || tlsPath(path, true) != nil {
			return nil, ErrTLSInstall
		}
		var prep tlsPreparation
		if tlsJSON(filepath.Join(path, "preparation.json"), &prep) != nil || prep.Version != 1 || !validPreparation(prep.Request) || path != i.prepPath(prep.Request.RequestID) || prep.Binding.Control.HubID != hubID || prep.Binding.Control.NodeID != nodeID {
			return nil, ErrTLSInstall
		}
		for _, p := range []e2ee.PublicIdentity{prep.Binding.Control.NodePublicIdentity, prep.Binding.Control.HubPublicIdentity} {
			if e2ee.ValidatePublicIdentity(p) != nil {
				return nil, ErrTLSInstall
			}
			out = append(out, append([]byte(nil), p.SigningPublic...))
		}
	}
	return out, nil
}

func runtimeLocal(o RuntimeOptions) (*LocalTLSInstaller, func(), error) {
	i, closeLocal, err := o.OpenLocal()
	if err != nil {
		return nil, nil, err
	}
	if closeLocal == nil {
		closeLocal = func() {}
	}
	if i == nil || i.StateRoot != o.StateRoot || i.WriterRoot != o.WriterRoot || i.HubID != o.HubID || i.NodeID != o.NodeID || i.CurrentBinding == nil || i.OwnerTrust == nil || i.NodeControlIdentity == nil || i.KnownApplicationPublicKeys == nil {
		closeLocal()
		return nil, nil, ErrTLSInstall
	}
	return i, closeLocal, nil
}

// runtimeExistingLock never creates or repairs coordination metadata. Both
// pre- and post-acquisition checks bind a real owned private existing inode.
type runtimeHeldLock struct {
	file *flock.Flock
	path string
	info os.FileInfo
}

func runtimeExistingLock(path string, shared bool, busy error) (*runtimeHeldLock, error) {
	if tlsPath(filepath.Dir(path), true) != nil || tlsPath(path, false) != nil {
		return nil, ErrTLSInstall
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, ErrTLSInstall
	}
	lock := flock.New(path, flock.SetFlag(os.O_RDONLY))
	var held bool
	if shared {
		held, err = lock.TryRLock()
	} else {
		held, err = lock.TryLock()
	}
	if err != nil {
		lock.Close()
		return nil, err
	}
	if !held {
		lock.Close()
		return nil, busy
	}
	after, err := os.Lstat(path)
	if err != nil || tlsPath(path, false) != nil || !os.SameFile(before, after) {
		lock.Close()
		return nil, ErrTLSInstall
	}
	return &runtimeHeldLock{file: lock, path: path, info: before}, nil
}
func runtimeLockPaths(o RuntimeOptions) (string, string, string) {
	node := filepath.Join(o.StateRoot, "nodes", ".locks", "node-"+url.PathEscape(o.NodeID))
	return filepath.Join(o.WriterRoot, ".writer-root.maintenance.lock"), node + ".maintenance.lock", node + ".agent.lock"
}
func runtimeCloseLocks(locks []*runtimeHeldLock) {
	for n := len(locks) - 1; n >= 0; n-- {
		locks[n].file.Close()
	}
}
func runtimeCheckLocks(locks []*runtimeHeldLock) error {
	for _, held := range locks {
		info, err := os.Lstat(held.path)
		if err != nil || tlsPath(held.path, false) != nil || !os.SameFile(held.info, info) {
			return ErrTLSInstall
		}
	}
	return nil
}
func runtimeAcquireShared(o RuntimeOptions) ([]*runtimeHeldLock, error) {
	writer, node, agent := runtimeLockPaths(o)
	var locks []*runtimeHeldLock
	for _, v := range []struct {
		path   string
		shared bool
		busy   error
	}{{writer, true, nodelock.ErrBusy}, {node, true, nodelock.ErrBusy}, {agent, false, nodelock.ErrAgentRunning}} {
		lock, err := runtimeExistingLock(v.path, v.shared, v.busy)
		if err != nil {
			runtimeCloseLocks(locks)
			return nil, err
		}
		locks = append(locks, lock)
	}
	return locks, nil
}

// OpenRuntime holds WriterRoot shared, Node maintenance shared and Agent
// singleton locks, then performs two complete independently fresh checks.
// Different Hub/Node runtimes may coexist; maintenance remains exclusive.
func OpenRuntime(ctx context.Context, o RuntimeOptions) (*Runtime, error) {
	i := runtimeCoordinates(o)
	if ctx == nil || o.HubID == "" || o.NodeID == "" || len(o.NodeID) > 256 || o.ApplicationOrigin == "" || tlsPath(o.StateRoot, true) != nil || tlsPath(o.WriterRoot, true) != nil || filepath.Clean(o.ConfigPath) != filepath.Join(i.base(), "active.json") {
		return nil, ErrTLSInstall
	}
	if err := i.quarantine(); err != nil {
		return nil, err
	}
	if o.OpenLocal == nil || o.QueryCurrent == nil {
		return nil, ErrTLSCurrentAuthorityUnavailable
	}
	if err := pqtls.Available(); err != nil {
		return nil, err
	}
	locks, err := runtimeAcquireShared(o)
	if err != nil {
		return nil, err
	}
	cleanup := func() { runtimeCloseLocks(locks) }
	if err := i.quarantine(); err != nil {
		cleanup()
		return nil, err
	}
	// First reader is closed; the second reconstructs independent local trust
	// and repeats all crypto/material checks and a new remote conversation.
	err = func() error {
		local, closeLocal, err := runtimeLocal(o)
		if err != nil {
			return err
		}
		defer closeLocal()
		_, err = runtimeLoadActive(ctx, local, o)
		return err
	}()
	if err != nil {
		cleanup()
		return nil, err
	}
	local, closeLocal, err := runtimeLocal(o)
	if err != nil {
		cleanup()
		return nil, err
	}
	cfg, err := runtimeLoadActive(ctx, local, o)
	if err != nil {
		closeLocal()
		cleanup()
		return nil, err
	}
	if err := i.quarantine(); err != nil {
		closeLocal()
		cleanup()
		return nil, err
	}
	base, err := NewTransport(cfg)
	if err != nil {
		closeLocal()
		cleanup()
		return nil, err
	}
	if err := runtimeCheckLocks(locks); err != nil {
		closeLocal()
		cleanup()
		return nil, err
	}
	lifetime, cancel := context.WithCancel(ctx)
	return &Runtime{state: &runtimeState{base: base, ctx: lifetime, cancel: cancel, bodies: make(map[*runtimeBody]struct{}), closeLocal: closeLocal, locks: locks}}, nil
}

// Called only while OpenRuntime owns maintenance or lifetime locks. Kept here
// because D1's public offline LoadActive always acquires exclusive locks.
func runtimeLoadActive(ctx context.Context, i *LocalTLSInstaller, o RuntimeOptions) (*Config, error) {
	return runtimeCheckedActive(ctx, i, o, i.quarantine)
}
func runtimeCheckedActive(ctx context.Context, i *LocalTLSInstaller, o RuntimeOptions, fence func() error) (*Config, error) {
	at := time.Now().UTC().Truncate(time.Second)
	f, err := i.readFloor(true)
	if err != nil || f.Epoch == 0 {
		return nil, ErrTLSInstall
	}
	var proof e2ee.NodeTLSActivation
	if json.Unmarshal(f.Activation, &proof) != nil {
		return nil, ErrTLSInstall
	}
	b, _, err := i.local(&proof.Claims.InstallAckClaims.GrantClaims)
	if err != nil {
		return nil, err
	}
	if _, err = e2ee.VerifyNodeTLSActivation(b.Control.HubPublicIdentity, at, f.Activation); err != nil {
		return nil, err
	}
	s, err := i.verifyStage(filepath.Join(i.base(), "epochs", fmt.Sprintf("%d-%s", f.Epoch, f.GrantDigest)), at)
	configWire, marshalErr := json.Marshal(s.Config)
	if err != nil || marshalErr != nil || tlsHash(configWire) != f.ConfigDigest || s.Claims != proof.Claims.InstallAckClaims.GrantClaims || e2ee.NodeTLSAuthorityDigest(s.Grant) != f.GrantDigest || e2ee.NodeTLSAuthorityDigest(s.Ack) != proof.Claims.InstallAckDigest || s.Config.LogicalOrigin() != o.ApplicationOrigin {
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
	query, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	current, err := o.QueryCurrent(query, &s.Config)
	if err != nil || current == nil {
		return nil, ErrTLSCurrentAuthorityUnavailable
	}
	// The callback must independently read actual Hub state; it cannot echo
	// expected or use the precommit signed activation as a current response.
	check := *i
	check.CurrentActiveAuthority = func() (*store.NodeTLSAuthoritySnapshot, error) { return current, nil }
	if err := check.activeAuthority(expected); err != nil {
		return nil, err
	}
	if err := fence(); err != nil {
		return nil, err
	}
	return &s.Config, nil
}

func (r *Runtime) RoundTrip(req *http.Request) (*http.Response, error) {
	if r == nil || r.state == nil {
		return nil, ErrTLSRuntimeClosed
	}
	s := r.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrTLSRuntimeClosed
	}
	s.requests.Add(1)
	s.mu.Unlock()
	ctx, cancel := context.WithCancel(req.Context())
	stop := context.AfterFunc(s.ctx, cancel)
	resp, err := s.base.RoundTrip(req.Clone(ctx))
	if err != nil {
		stop()
		cancel()
		s.requests.Done()
		return nil, err
	}
	body := &runtimeBody{ReadCloser: resp.Body, done: func() { stop(); cancel(); s.requests.Done() }, owner: s}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		body.Close()
		return nil, ErrTLSRuntimeClosed
	}
	s.bodies[body] = struct{}{}
	resp.Body = body
	s.mu.Unlock()
	return resp, nil
}

type runtimeBody struct {
	io.ReadCloser
	once  sync.Once
	done  func()
	owner *runtimeState
}

func (b *runtimeBody) Close() error {
	var err error
	b.once.Do(func() {
		err = b.ReadCloser.Close()
		b.owner.mu.Lock()
		delete(b.owner.bodies, b)
		b.owner.mu.Unlock()
		b.done()
	})
	return err
}
func (r *Runtime) CloseIdleConnections() {
	if r == nil || r.state == nil {
		return
	}
	if closer, ok := r.state.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
func (r *Runtime) Close() error {
	if r == nil || r.state == nil {
		return nil
	}
	s := r.state
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		bodies := make([]*runtimeBody, 0, len(s.bodies))
		for b := range s.bodies {
			bodies = append(bodies, b)
		}
		s.mu.Unlock()
		for _, b := range bodies {
			b.Close()
		}
		s.requests.Wait()
		r.CloseIdleConnections()
		if s.closeLocal != nil {
			s.closeLocal()
		}
		runtimeCloseLocks(s.locks)
	})
	return nil
}

// Called only by Apply while its existing WriterRoot/Node exclusive locks
// are held and all exact Owner/material/ACK/current ACTIVE checks have passed.
// This initializes only absent advisory Agent lock metadata. It never repairs
// an existing file, changes application state, or weakens recovery quarantine.
func runtimeCheckAgentMetadata(i *LocalTLSInstaller) error {
	_, _, path := runtimeLockPaths(RuntimeOptions{StateRoot: i.StateRoot, WriterRoot: i.WriterRoot, HubID: i.HubID, NodeID: i.NodeID})
	if tlsPath(filepath.Dir(path), true) != nil {
		return ErrTLSInstall
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return ErrTLSInstall
	}
	return tlsPath(path, false)
}
func runtimeProvisionAgentLock(i *LocalTLSInstaller) error {
	if err := i.quarantine(); err != nil {
		return err
	}
	_, _, path := runtimeLockPaths(RuntimeOptions{StateRoot: i.StateRoot, WriterRoot: i.WriterRoot, HubID: i.HubID, NodeID: i.NodeID})
	if tlsPath(filepath.Dir(path), true) != nil {
		return ErrTLSInstall
	}
	if _, err := os.Lstat(path); err == nil {
		return tlsPath(path, false)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrTLSInstall
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if errors.Is(err, os.ErrExist) {
		return tlsPath(path, false)
	}
	if err != nil {
		return err
	}
	before, statErr := file.Stat()
	after, pathErr := os.Lstat(path)
	if statErr != nil || pathErr != nil || !os.SameFile(before, after) || tlsPath(path, false) != nil {
		file.Close()
		return ErrTLSInstall
	}
	err = errors.Join(file.Sync(), file.Close())
	if err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}

// TLSMaintenanceRead owns genuine existing WriterRoot and Node exclusive
// locks. Copies share a single closed state. It never publishes a Runtime or
// general HTTP client, and does not clear recovery markers.
type TLSMaintenanceRead struct{ state *tlsMaintenanceReadState }
type tlsMaintenanceReadState struct {
	mu     sync.Mutex
	closed bool
	once   sync.Once
	uses   sync.WaitGroup
	scope  RuntimeOptions
	locks  []*runtimeHeldLock
}

func AcquireTLSMaintenanceRead(stateRoot, writerRoot, hubID, nodeID string) (*TLSMaintenanceRead, error) {
	o := RuntimeOptions{StateRoot: stateRoot, WriterRoot: writerRoot, HubID: hubID, NodeID: nodeID}
	if hubID == "" || nodeID == "" || len(nodeID) > 256 || tlsPath(stateRoot, true) != nil || tlsPath(writerRoot, true) != nil {
		return nil, ErrTLSInstall
	}
	writer, node, _ := runtimeLockPaths(o)
	var locks []*runtimeHeldLock
	for _, path := range []string{writer, node} {
		lock, err := runtimeExistingLock(path, false, nodelock.ErrBusy)
		if err != nil {
			runtimeCloseLocks(locks)
			return nil, err
		}
		locks = append(locks, lock)
	}
	return &TLSMaintenanceRead{state: &tlsMaintenanceReadState{scope: o, locks: locks}}, nil
}
func (c *TLSMaintenanceRead) enter(o RuntimeOptions) (func(), error) {
	if c == nil || c.state == nil {
		return nil, ErrTLSRuntimeClosed
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrTLSRuntimeClosed
	}
	if o.StateRoot != s.scope.StateRoot || o.WriterRoot != s.scope.WriterRoot || o.HubID != s.scope.HubID || o.NodeID != s.scope.NodeID {
		return nil, ErrTLSInstall
	}
	// Held files must still be the private existing coordination paths. Their
	// flock ownership is released only after every entered read has joined.
	if err := runtimeCheckLocks(s.locks); err != nil {
		return nil, err
	}
	s.uses.Add(1)
	return s.uses.Done, nil
}
func (c *TLSMaintenanceRead) Close() error {
	if c == nil || c.state == nil {
		return nil
	}
	s := c.state
	s.once.Do(func() { s.mu.Lock(); s.closed = true; s.mu.Unlock(); s.uses.Wait(); runtimeCloseLocks(s.locks) })
	return nil
}
func (c *TLSMaintenanceRead) ReadAcceptedBinding(stateRoot, writerRoot, hubID, nodeID string) (TLSLocalBinding, error) {
	o := RuntimeOptions{StateRoot: stateRoot, WriterRoot: writerRoot, HubID: hubID, NodeID: nodeID}
	done, err := c.enter(o)
	if err != nil {
		return TLSLocalBinding{}, err
	}
	defer done()
	return readAcceptedTLSBinding(runtimeCoordinates(o))
}
func (c *TLSMaintenanceRead) ReadRetainedSigningPublicKeys(stateRoot, writerRoot, hubID, nodeID string) ([][]byte, error) {
	o := RuntimeOptions{StateRoot: stateRoot, WriterRoot: writerRoot, HubID: hubID, NodeID: nodeID}
	done, err := c.enter(o)
	if err != nil {
		return nil, err
	}
	defer done()
	return readRetainedTLSPreparationKeys(runtimeCoordinates(o))
}

// ReadCurrentAuthority returns public current metadata only. It verifies the
// full local installation and independent Owner/application trust before the
// fresh query. No general transport or decrypted application data is exposed.
func (c *TLSMaintenanceRead) ReadCurrentAuthority(ctx context.Context, o RuntimeOptions) (*store.NodeTLSAuthoritySnapshot, error) {
	done, err := c.enter(o)
	if err != nil {
		return nil, err
	}
	defer done()
	if ctx == nil || filepath.Clean(o.ConfigPath) != filepath.Join(runtimeCoordinates(o).base(), "active.json") {
		return nil, ErrTLSInstall
	}
	if o.OpenLocal == nil || o.QueryCurrent == nil {
		return nil, ErrTLSCurrentAuthorityUnavailable
	}
	local, closeLocal, err := runtimeLocal(o)
	if err != nil {
		return nil, err
	}
	defer closeLocal()
	if err := pqtls.Available(); err != nil {
		return nil, errors.Join(ErrTLSCurrentAuthorityUnavailable, err)
	}
	var current *store.NodeTLSAuthoritySnapshot
	checked := o
	checked.QueryCurrent = func(ctx context.Context, cfg *Config) (*store.NodeTLSAuthoritySnapshot, error) {
		snapshot, err := o.QueryCurrent(ctx, cfg)
		if err == nil {
			current = snapshot
		}
		return snapshot, err
	}
	_, err = runtimeCheckedActive(ctx, local, checked, func() error {
		d, err := c.enter(o)
		if d != nil {
			d()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return current, nil
}

// QueryRecovery is the sole maintenance transport entry. It first obtains a
// new authenticated current ACTIVE proof and checks every installed material,
// then sends only one authenticated read-only recovery packet to the fixed
// RPC path. Quarantine remains present; no Relay/job traffic is admitted.
func (c *TLSMaintenanceRead) QueryRecovery(ctx context.Context, o RuntimeOptions, token string, packet []byte) ([]byte, error) {
	done, err := c.enter(o)
	if err != nil {
		return nil, err
	}
	defer done()
	if ctx == nil || filepath.Clean(o.ConfigPath) != filepath.Join(runtimeCoordinates(o).base(), "active.json") {
		return nil, ErrTLSInstall
	}
	if o.OpenLocal == nil || o.QueryCurrent == nil {
		return nil, ErrTLSCurrentAuthorityUnavailable
	}
	if err := pqtls.Available(); err != nil {
		return nil, errors.Join(ErrTLSCurrentAuthorityUnavailable, err)
	}
	p, err := nodewire.DecodePacket(packet)
	if err != nil || len(packet) > nodewire.MaxRecoveryPacketBytes || p.Route.Operation != nodewire.RecoveryOperation || p.Route.Direction != nodewire.DirectionRequest || p.Route.Sequence != 1 {
		return nil, ErrTLSInstall
	}
	local, closeLocal, err := runtimeLocal(o)
	if err != nil {
		return nil, err
	}
	defer closeLocal()
	cfg, err := runtimeCheckedActive(ctx, local, o, func() error {
		d, err := c.enter(o)
		if d != nil {
			d()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	b, err := local.CurrentBinding()
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(token))
	if len(packet) > nodewire.MaxRecoveryPacketBytes || base64.RawURLEncoding.EncodeToString(digest[:]) != b.Control.CredentialDigest || p.Route.Operation != nodewire.RecoveryOperation || p.Route.Direction != nodewire.DirectionRequest || p.Route.Sequence != 1 || p.Route.HubID != o.HubID || p.Route.NodeID != o.NodeID || p.Route.BindingID != b.Control.OwnerBindingID || p.Route.BindingVersion != b.Control.BindingVersion || p.Route.NodeKeyEpoch != b.Control.NodeKeyEpoch || p.Route.SenderKeyID != b.Control.NodeKeyID || p.Route.SenderKeyVersion != b.Control.NodeKeyVersion || p.Route.ReceiverKeyID != b.Control.HubKeyID || p.Route.ReceiverKeyVersion != b.Control.HubKeyVersion {
		return nil, ErrTLSInstall
	}
	transport, err := NewTransport(cfg)
	if err != nil {
		return nil, err
	}
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, o.ApplicationOrigin+"/v2/node/control/rpc", bytes.NewReader(packet))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "CicadaNode "+token)
	request.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrTLSInstall }}
	response, err := client.Do(request)
	if err != nil {
		return nil, ErrTLSCurrentAuthorityUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrTLSCurrentAuthorityUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, nodewire.MaxRecoveryPacketBytes+1))
	if err != nil || len(data) > nodewire.MaxRecoveryPacketBytes {
		return nil, ErrTLSCurrentAuthorityUnavailable
	}
	return data, nil
}
