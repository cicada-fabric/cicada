package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

func TestNodeHubBusinessPairOriginalACKAndCandidateScopeReservation(t *testing.T) {
	// Real PQ/codecs with the existing scripted responder; consumer only.
	f := newNodePairScopedConsumerFixture(t)
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal(err)
	}
	c, s := f.load(t)
	defer clear(s.Secret)
	keyBefore, _ := c.identity.MarshalBinary()
	defer clear(keyBefore)
	f.approve(t, s)
	f.mu.Lock()
	f.drop[wire.OperationNodePairTrustScopedACK] = 1
	f.mu.Unlock()
	if err := f.run(t); !errors.Is(err, errMachineNodePairPending) {
		t.Fatal("lost ACK did not remain pending", err)
	}
	c, pending := f.load(t)
	defer clear(pending.Secret)
	original := bytes.Clone(pending.PendingPacket)
	defer clear(original)
	if c.state.BindingID != "" {
		t.Fatal("unconfirmed private ACK installed binding")
	}
	root, entries := nodeHubTestRegistry(t, 2)
	e := entries[0]
	_, err := mutateNodeHubRegistry(context.Background(), root, func(_ *os.Root, r *nodeHubRegistry) error {
		r.WriterRoot = f.f.state
		for i := range r.Connections {
			r.Connections[i].WriterRoot = f.f.state
			r.Connections[i].HubID = ""
			r.Connections[i].Origin = ""
		}
		e = r.Connections[0]
		e.StateDir = f.f.state
		e.NodeID = f.f.node
		e.HubAddress = f.f.address
		r.Connections[0] = e
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	machineNodeControlClients.Delete(c.statePath)
	ctx := context.WithValue(context.Background(), nodeHubOperationHooksKey{}, nodeHubOperationHooks{Output: io.Discard})
	settled, err := pairNodeHubEntry(ctx, root, e)
	if err != nil {
		t.Fatal("original ACK cold retry failed", err)
	}
	c, done := f.load(t)
	defer clear(done.Secret)
	keyAfter, _ := c.identity.MarshalBinary()
	defer clear(keyAfter)
	if done.Stage != wire.NodePairTrustScopedACKed || !bytes.Equal(done.ACKPacket, original) || !bytes.Equal(keyBefore, keyAfter) || settled.HubID != f.f.native.d.Claims.Hub.HubID {
		t.Fatal("pair replaced identity/original ACK or claimed premature readiness")
	}
	f.mu.Lock()
	requests := f.requests[wire.OperationNodePairTrustScopedACK]
	f.mu.Unlock()
	if len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) {
		t.Fatal("private ACK retry bytes changed")
	}
	r, _, err := nodeHubRoot(ctx, root, false)
	if err != nil {
		t.Fatal(err)
	}
	reg, _, err := readNodeHubRegistry(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if reg.Connections[0].HubID != settled.HubID {
		t.Fatal("candidate Hub not reserved before private ACK")
	}
	// Public add waits for the exact local worker after the private ACK, then
	// remove/re-add reuses the retained state with a fresh admission epoch.
	var ready atomic.Bool
	driver := nodeHubTestDriver()
	driver.RetainedReady = nodeHubRetainedReady
	driver.Ready = func(context.Context, nodeHubRegistryEntry) error {
		if ready.Load() {
			return nil
		}
		return errNodeHubNotReady
	}
	nodeHubTestStart(t, root, driver)
	short, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	if _, err = AddLocalNodeHubConnection(short, LocalNodeHubAddInput{UserRoot: root, ConnectionID: e.ConnectionID}); err == nil {
		cancel()
		t.Fatal("add succeeded before local worker ready")
	}
	cancel()
	ready.Store(true)
	added, err := AddLocalNodeHubConnection(ctx, LocalNodeHubAddInput{UserRoot: root, ConnectionID: e.ConnectionID})
	if err != nil || added.RuntimeState != "RUNNING" {
		t.Fatal("ACKed add did not wait for worker", err)
	}
	removed, err := RemoveLocalNodeHubConnection(ctx, LocalNodeHubSelection{UserRoot: root, Alias: e.Alias})
	if err != nil || removed.State != "LOCAL_STOPPED" {
		t.Fatal("ACKed entry did not locally retire", err)
	}
	readded, err := AddLocalNodeHubConnection(ctx, LocalNodeHubAddInput{UserRoot: root, Alias: e.Alias, HubAddress: e.HubAddress})
	if err != nil || readded.ConnectionID != e.ConnectionID || readded.LocalFence != 3 {
		t.Fatal("re-add replaced retained identity or epoch", err)
	}
	if _, err = currentNodeHubFence(ctx, root, e.ConnectionID, 1); err == nil {
		t.Fatal("old admission epoch revived after re-add")
	}
	stale := machineHubContext{HubID: settled.HubID, Origin: settled.Origin, NodeID: e.NodeID, StateDir: e.StateDir, WriterRoot: e.WriterRoot, ManagedUserRoot: root, ManagedConnectionID: e.ConnectionID, ManagedConnectionEpoch: 1}
	if err = installNodeHubStateReference(ctx, &stale); err == nil {
		t.Fatal("stale worker startup upgraded its own managed epoch")
	}
	r, _, err = nodeHubRoot(ctx, root, false)
	if err != nil {
		t.Fatal(err)
	}
	reg, _, err = readNodeHubRegistry(r)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, saved := range reg.Connections {
		if saved.ConnectionID == e.ConnectionID && (saved.StateDir != e.StateDir || saved.WriterRoot != e.WriterRoot || saved.MCPSessionStateFile != e.MCPSessionStateFile || saved.MCPOutboxStateFile != e.MCPOutboxStateFile) {
			t.Fatal("cold registry changed original state references")
		}
	}
	// A second locator to the same trusted descriptor must fail before creating
	// a fresh control key; current pending identity remains the only scope.
	otherIndex := 0
	for i, candidate := range reg.Connections {
		if candidate.ConnectionID != e.ConnectionID {
			otherIndex = i
		}
	}
	other := reg.Connections[otherIndex]
	proxy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go func() {
		for {
			in, err := proxy.Accept()
			if err != nil {
				return
			}
			go func() {
				defer in.Close()
				out, err := net.Dial("tcp", f.f.address)
				if err != nil {
					return
				}
				defer out.Close()
				copied := make(chan struct{})
				go func() { io.Copy(out, in); out.Close(); close(copied) }()
				io.Copy(in, out)
				in.Close()
				<-copied
			}()
		}
	}()
	other.HubAddress = proxy.Addr().String()
	if _, err = mutateNodeHubRegistry(ctx, root, func(_ *os.Root, r *nodeHubRegistry) error { r.Connections[otherIndex] = other; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = pairNodeHubEntry(ctx, root, other); !errors.Is(err, errNodeHubConflict) {
		t.Fatal("same Hub candidate admitted a second identity", err)
	}
	identity, _ := machineNodeControlPaths(other.StateDir, other.NodeID)
	if _, err = os.Stat(identity); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("conflicting candidate initialized control identity")
	}
	t.Log("scripted_consumer=PASS real_PQ=true real_Store_carrier=NOT_RUN original_private_ACK=true")
}

func TestNodeHubBusinessStoppedServiceAdoptionPreservesOriginalAndExactPin(t *testing.T) {
	f := newNodeLifecycleFixture(t)
	// Match externally installed Codex: same-UID link under a 775 directory.
	bin := filepath.Join(f.c.UserRoot, "external-bin")
	if err := os.Mkdir(bin, 0775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0775); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(bin, "codex")
	if err := os.Symlink("/usr/bin/true", link); err != nil {
		t.Fatal(err)
	}
	f.c.CodexBin = link
	f.save(t)
	oldPin, err := nodeHubOriginalPin(f.c, f.s)
	if err != nil {
		t.Fatal(err)
	}
	// Opaque persisted artifacts are referenced in place, never decoded/copied.
	for _, path := range []string{f.s.session, f.s.outbox} {
		if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, []byte("SYNTHETIC opaque original\x00bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	keyPath, _ := machineNodeControlPaths(f.s.state, f.s.id)
	keyBefore, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyBefore)
	originalRaw, err := os.ReadFile(filepath.Join(f.c.UserRoot, nodeServiceConfigName))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(originalRaw)
	var cancel context.CancelFunc
	var managerDone <-chan error
	defer func() {
		if cancel != nil {
			cancel()
			<-managerDone
		}
	}()
	driver := nodeHubTestDriver()
	driver.Ready = nodeHubProductionDriver(f.c.UserRoot).Ready
	driver.Run = func(ctx context.Context, e nodeHubRegistryEntry) error {
		lock, err := nodelock.AcquireAgent(e.StateDir, e.NodeID)
		if err != nil {
			return err
		}
		defer lock.Close()
		h := f.hub
		h.ManagedUserRoot = f.c.UserRoot
		h.ManagedConnectionID = e.ConnectionID
		h.ManagedConnectionEpoch = e.LocalFence
		bridge, err := startMachineAgentJoinBridge(withMachineHubContext(ctx, h), e.StateDir, e.Origin, e.NodeID, h.Token)
		if err != nil {
			return err
		}
		defer bridge.Close()
		if err = startLocalNodeDiscovery(bridge, localNodePublishConfig{f.c.UserRoot, e.MCPSessionStateFile, e.MCPOutboxStateFile}); err != nil {
			return err
		}
		<-ctx.Done()
		return nil
	}
	foreign := false
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		if strings.Join(args, " ") == "--user show --property=Version --value" {
			return "255.4\n", nil
		}
		if name == "/usr/bin/systemd-run" {
			managerCtx, stop := context.WithCancel(context.Background())
			cancel = stop
			done := make(chan error, 1)
			managerDone = done
			go func() { done <- serveNodeHubManager(managerCtx, f.c.UserRoot, driver) }()
			return "", nil
		}
		if len(args) > 1 && args[1] == "show" {
			unit := args[2]
			if unit == nodeServiceUnit(f.c, f.s) {
				if foreign {
					return "LoadState=loaded\nActiveState=active\nMainPID=123\nTransient=yes\nDescription=SYNTHETIC foreign\n", nil
				}
				return "LoadState=not-found\nActiveState=inactive\nMainPID=0\n", errors.New("not found")
			}
			if cancel == nil {
				return "LoadState=not-found\nActiveState=inactive\nMainPID=0\n", errors.New("not found")
			}
			raw, err := os.ReadFile(filepath.Join(f.c.UserRoot, nodeServiceConfigName))
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("LoadState=loaded\nActiveState=active\nMainPID=%d\nTransient=yes\nDescription=%s\n", os.Getpid(), nodeHubServiceOwner(raw)), nil
		}
		return "", errors.New("unexpected test service command")
	}
	ctx := context.WithValue(context.Background(), nodeHubOperationHooksKey{}, nodeHubOperationHooks{ServiceRunner: run})
	foreign = true
	if _, err = adoptNodeHubFromService(ctx, LocalNodeHubAddInput{UserRoot: f.c.UserRoot, Alias: "original", FromService: true}); err == nil {
		t.Fatal("unowned active process adopted")
	}
	foreign = false
	v, err := adoptNodeHubFromService(ctx, LocalNodeHubAddInput{UserRoot: f.c.UserRoot, Alias: "original", FromService: true})
	if err != nil {
		t.Fatal("stopped original adoption failed", err)
	}
	if v.LocalFence != 1 || v.HubID != oldPin.HubID || v.HubOnline != "UNKNOWN" {
		t.Fatal("adoption changed remote identity/online claim")
	}
	nodeHubTestWait(t, func() bool {
		return driver.Ready(context.Background(), nodeHubRegistryEntry{ConnectionID: v.ConnectionID, LocalFence: 1, HubID: oldPin.HubID, NodeID: oldPin.NodeID, StateDir: oldPin.StateDir, WriterRoot: oldPin.WriterRoot, MCPSessionStateFile: oldPin.MCPSessionStateFile, MCPOutboxStateFile: oldPin.MCPOutboxStateFile}) == nil
	})
	connection, err := ResolveAdoptedLocalNodeConnection(context.Background(), oldPin)
	if err != nil || connection.Pin.ConnectionID != v.ConnectionID || connection.Pin.ConnectionEpoch != 1 {
		t.Fatal("exact original Pin0 adoption mapping rejected", err)
	}
	forged := oldPin
	forged.MCPOutboxStateFile = filepath.Join(f.c.UserRoot, "different-outbox")
	if _, err = ResolveAdoptedLocalNodeConnection(context.Background(), forged); err == nil {
		t.Fatal("altered cached Pin0 mapped")
	}
	r, _, err := nodeHubRoot(context.Background(), f.c.UserRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	saved, _, err := readNodeHubService(r, f.c.UserRoot)
	r.Close()
	if err != nil || saved.OriginalServiceDigest != hex.EncodeToString(digest[:]) || saved.OriginalService.CodexBin != link {
		t.Fatal("original config/digest/path not preserved", err)
	}
	keyAfter, err := os.ReadFile(keyPath)
	if err != nil || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("adoption rewrote original identity", err)
	}
	defer clear(keyAfter)
	for _, path := range []string{f.s.session, f.s.outbox} {
		b, err := os.ReadFile(path)
		if err != nil || string(b) != "SYNTHETIC opaque original\x00bytes\n" {
			t.Fatal("adoption rewrote opaque original", err)
		}
	}
	// Exact replay never reacquires an identity or advances the epoch.
	replay, err := adoptNodeHubFromService(ctx, LocalNodeHubAddInput{UserRoot: f.c.UserRoot, Alias: "original", FromService: true})
	if err != nil || replay.ConnectionID != v.ConnectionID || replay.LocalFence != 1 {
		t.Fatal("adoption response-loss replay changed scope", err)
	}
}
