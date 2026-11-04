package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

const nodeHubManagerLocatorName = "node-hub-manager.json"

type nodeHubManagerLocator struct {
	Format     string `json:"format"`
	InstanceID string `json:"instance_id"`
	PID        int    `json:"pid"`
	SocketPath string `json:"socket_path"`
}

type nodeHubRuntimeDriver struct {
	Run             func(context.Context, nodeHubRegistryEntry) error
	Ready           func(context.Context, nodeHubRegistryEntry) error
	RetainedReady   func(nodeHubRegistryEntry) error
	ShutdownTimeout time.Duration
}
type nodeHubWorker struct {
	entry  nodeHubRegistryEntry
	cancel context.CancelFunc
	done   chan struct{}
	state  string
}
type nodeHubRuntime struct {
	ctx      context.Context
	root     string
	instance string
	driver   nodeHubRuntimeDriver
	mu       sync.Mutex
	workers  map[string]*nodeHubWorker
	stopping bool
}

func newNodeHubRuntime(ctx context.Context, root string, driver nodeHubRuntimeDriver) (*nodeHubRuntime, error) {
	id, err := nodeHubID()
	if err != nil {
		return nil, err
	}
	if driver.Run == nil || driver.Ready == nil {
		return nil, ErrLocalNodeHubConfig
	}
	if driver.RetainedReady == nil {
		driver.RetainedReady = nodeHubRetainedReady
	}
	return &nodeHubRuntime{ctx: ctx, root: root, instance: id, driver: driver, workers: map[string]*nodeHubWorker{}}, nil
}

func (m *nodeHubRuntime) reconcile() error {
	root, _, err := nodeHubRoot(m.ctx, m.root, false)
	if err != nil {
		return err
	}
	r, _, err := readNodeHubRegistry(root)
	root.Close()
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopping {
		return errNodeHubUnavailable
	}
	wanted := map[string]nodeHubRegistryEntry{}
	for _, e := range r.Connections {
		if e.DesiredState == "ENABLED" {
			wanted[e.ConnectionID] = e
		}
	}
	for id, w := range m.workers {
		e, ok := wanted[id]
		if !ok || e != w.entry {
			w.cancel()
			select {
			case <-w.done:
				delete(m.workers, id)
			default:
				w.state = "STOPPING"
			}
		}
	}
	for id, e := range wanted {
		if _, exists := m.workers[id]; exists {
			continue
		}
		// Startup never performs enrollment. A pending/new/unknown entry waits
		// for its explicit add command to finish original NPT/private ACK.
		if m.driver.RetainedReady(e) != nil {
			continue
		}
		ctx, cancel := context.WithCancel(m.ctx)
		w := &nodeHubWorker{entry: e, cancel: cancel, done: make(chan struct{}), state: "STARTING"}
		m.workers[id] = w
		go m.run(ctx, w)
	}
	return nil
}

func (m *nodeHubRuntime) run(ctx context.Context, w *nodeHubWorker) {
	finished := make(chan error, 1)
	go func() { finished <- m.driver.Run(ctx, w.entry) }()
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-finished:
			m.mu.Lock()
			if ctx.Err() != nil {
				w.state = "STOPPED"
			} else if err != nil {
				w.state = "FAILED"
			} else {
				w.state = "STOPPED"
			}
			close(w.done)
			m.mu.Unlock()
			return
		case <-ticker.C:
			m.mu.Lock()
			starting := w.state == "STARTING"
			m.mu.Unlock()
			if !starting {
				continue
			}
			probe, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			err := m.driver.Ready(probe, w.entry)
			cancel()
			if err == nil {
				m.mu.Lock()
				if w.state == "STARTING" {
					w.state = "RUNNING"
				}
				m.mu.Unlock()
			}
		}
	}
}

func (m *nodeHubRuntime) list() (LocalNodeHubList, error) {
	root, _, err := nodeHubRoot(m.ctx, m.root, false)
	if err != nil {
		return LocalNodeHubList{}, err
	}
	r, _, err := readNodeHubRegistry(root)
	root.Close()
	if err != nil {
		return LocalNodeHubList{}, err
	}
	out := LocalNodeHubList{Format: LocalNodeHubsFormat, Revision: r.Revision, ManagerState: "RUNNING", Connections: []LocalNodeHubView{}}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range r.Connections {
		v := nodeHubEntryView(e)
		v.RuntimeState = "STOPPED"
		if m.driver.RetainedReady(e) == nil {
			v.PairingState = "READY"
		} else {
			v.PairingState = "PENDING"
		}
		if w := m.workers[e.ConnectionID]; w != nil && w.entry.LocalFence <= e.LocalFence {
			v.RuntimeState = w.state
			if e.DesiredState == "REMOVING" && v.RuntimeState != "STOPPED" && v.RuntimeState != "FAILED" {
				v.RuntimeState = "STOPPING"
			}
		}
		out.Connections = append(out.Connections, v)
	}
	return out, nil
}

func (m *nodeHubRuntime) stop(ctx context.Context) error {
	m.mu.Lock()
	m.stopping = true
	var workers []*nodeHubWorker
	for _, w := range m.workers {
		w.cancel()
		workers = append(workers, w)
	}
	m.mu.Unlock()
	for _, w := range workers {
		select {
		case <-w.done:
		case <-ctx.Done():
			return errNodeHubPending
		}
	}
	return nil
}

func nodeHubSocketPeer(connection *net.UnixConn) (*syscall.Ucred, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return nil, err
	}
	var peer *syscall.Ucred
	var inner error
	if err = raw.Control(func(fd uintptr) {
		peer, inner = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	return peer, inner
}

func nodeHubManagerIPC(ctx context.Context, userRoot, operation string, revision uint64) (LocalNodeHubList, error) {
	return nodeHubManagerIPCForPID(ctx, userRoot, operation, revision, 0)
}

func nodeHubManagerIPCForPID(ctx context.Context, userRoot, operation string, revision uint64, expectedPID int) (LocalNodeHubList, error) {
	root, _, err := nodeHubRoot(ctx, userRoot, false)
	if err != nil {
		return LocalNodeHubList{}, err
	}
	defer root.Close()
	b, _, err := readLocalNodeFile(root, nodeHubManagerLocatorName, 4096)
	if errors.Is(err, os.ErrNotExist) {
		return LocalNodeHubList{}, errNodeHubUnavailable
	}
	var l nodeHubManagerLocator
	if err != nil || decodeLocalNodeJSON(b, &l) != nil || l.Format != "cicada.node-hub-manager-locator.v1" || !localContextHex(l.InstanceID, 32) || l.PID <= 0 || !localNodePath(l.SocketPath) {
		return LocalNodeHubList{}, ErrLocalNodeHubConfig
	}
	if validateMachineAgentJoinSocketForDial(l.SocketPath) != nil {
		return LocalNodeHubList{}, errNodeHubUnavailable
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(call, "unix", l.SocketPath)
	if err != nil {
		return LocalNodeHubList{}, errNodeHubUnavailable
	}
	defer c.Close()
	u, ok := c.(*net.UnixConn)
	if !ok {
		return LocalNodeHubList{}, ErrLocalNodeHubConfig
	}
	peer, err := nodeHubSocketPeer(u)
	if err != nil || peer.Uid != uint32(os.Geteuid()) || int(peer.Pid) != l.PID || expectedPID > 0 && l.PID != expectedPID {
		return LocalNodeHubList{}, ErrLocalNodeHubConfig
	}
	stop := context.AfterFunc(call, func() { c.Close() })
	defer stop()
	if end, ok := call.Deadline(); ok {
		c.SetDeadline(end)
	}
	nonce, err := nodeHubID()
	if err != nil {
		return LocalNodeHubList{}, err
	}
	request := nodeHubControlRequest{"cicada.node-hub-control.v1", operation, nonce, l.InstanceID, revision}
	if err = json.NewEncoder(c).Encode(request); err != nil {
		return LocalNodeHubList{}, errNodeHubUnavailable
	}
	u.CloseWrite()
	b, err = io.ReadAll(io.LimitReader(c, MaxLocalNodeHubListBytes+1025))
	if err != nil {
		return LocalNodeHubList{}, errNodeHubUnavailable
	}
	reply, err := decodeNodeHubControlReply(b, request)
	if err != nil {
		return LocalNodeHubList{}, err
	}
	return reply.Result, nil
}

func serveNodeHubManager(ctx context.Context, userRoot string, driver nodeHubRuntimeDriver) (result error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m, err := newNodeHubRuntime(ctx, userRoot, driver)
	if err != nil {
		return err
	}
	root, path, err := nodeHubRoot(ctx, userRoot, false)
	if err != nil {
		return err
	}
	delayedCleanup := false
	defer func() {
		if !delayedCleanup {
			root.Close()
		}
	}()
	// A separate stable daemon lock, not the short registry mutation lock.
	lock, err := lockNodeHubDaemon(root)
	if err != nil {
		return err
	}
	defer func() {
		if !delayedCleanup {
			lock.Close()
		}
	}()
	socket, err := machineAgentJoinSocketPathChecked(path, "local-hub-manager")
	if err != nil {
		return err
	}
	if err = prepareLocalJoinSocket(socket); err != nil {
		return err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return errNodeHubConflict
	}
	l.SetUnlinkOnClose(false)
	defer l.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return err
	}
	socketInfo, err := os.Lstat(socket)
	if err != nil {
		return err
	}
	cleanSocket := func() {
		if now, e := os.Lstat(socket); e == nil && os.SameFile(now, socketInfo) {
			os.Remove(socket)
		}
	}
	defer func() {
		if !delayedCleanup {
			cleanSocket()
		}
	}()
	locator := nodeHubManagerLocator{"cicada.node-hub-manager-locator.v1", m.instance, os.Getpid(), socket}
	b, _ := json.Marshal(locator)
	old, _, err := readLocalNodeFile(root, nodeHubManagerLocatorName, 4096)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrLocalNodeHubConfig
	}
	if errors.Is(err, os.ErrNotExist) {
		old = nil
	}
	if err = writeNodeHubAtomic(root, nodeHubManagerLocatorName, append(b, '\n'), old); err != nil {
		return err
	}
	cleanLocator := func() {
		current, _, e := readLocalNodeFile(root, nodeHubManagerLocatorName, 4096)
		if e == nil {
			var v nodeHubManagerLocator
			if decodeLocalNodeJSON(current, &v) == nil && v.InstanceID == m.instance {
				root.Remove(nodeHubManagerLocatorName)
			}
		}
	}
	defer func() {
		if !delayedCleanup {
			cleanLocator()
		}
	}()
	stopped := context.AfterFunc(ctx, func() { l.Close() })
	defer stopped()
	if err = m.reconcile(); err != nil {
		return err
	}
	var handlers sync.WaitGroup
	defer func() {
		timeout := driver.ShutdownTimeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		shutdown, stopCancel := context.WithTimeout(context.Background(), timeout)
		stopErr := m.stop(shutdown)
		stopCancel()
		handlers.Wait()
		if stopErr != nil {
			result = errors.Join(result, stopErr)
			delayedCleanup = true
			// Keep the original daemon gate and instance marker until every
			// child actually retires; a timeout is not proof of quiescence.
			go func() { m.stop(context.Background()); cleanLocator(); cleanSocket(); lock.Close(); root.Close() }()
		}
	}()
	reconciler := make(chan struct{})
	go func() {
		defer close(reconciler)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.reconcile()
			}
		}
	}()
	defer func() { cancel(); <-reconciler }()
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errNodeHubUnavailable
		}
		handlers.Add(1)
		go func() {
			defer handlers.Done()
			defer c.Close()
			c.SetDeadline(time.Now().Add(2 * time.Second))
			peer, err := nodeHubSocketPeer(c)
			if err != nil || peer.Uid != uint32(os.Geteuid()) {
				return
			}
			raw, err := io.ReadAll(io.LimitReader(c, 1025))
			if err != nil {
				return
			}
			q, err := decodeNodeHubControlRequest(raw)
			if err != nil || q.InstanceID != m.instance {
				return
			}
			if q.Operation == "RECONCILE" {
				if m.reconcile() != nil {
					return
				}
			}
			result, err := m.list()
			if err != nil || result.Revision < q.Revision {
				return
			}
			json.NewEncoder(c).Encode(nodeHubControlReply{"cicada.node-hub-control-reply.v1", q.Operation, q.Nonce, m.instance, result.Revision, result})
		}()
	}
}

func lockNodeHubDaemon(root *os.Root) (*os.File, error) {
	const name = "node-hub-manager.lock"
	f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		info, e := root.Lstat(name)
		if e != nil || !localNodePrivate(info, false) {
			return nil, ErrLocalNodeHubConfig
		}
		f, err = root.OpenFile(name, os.O_RDWR, 0)
	}
	if err != nil {
		return nil, errNodeHubConflict
	}
	info, e := root.Lstat(name)
	opened, se := f.Stat()
	if e != nil || se != nil || !localNodePrivate(info, false) || !os.SameFile(info, opened) || syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		f.Close()
		return nil, errNodeHubConflict
	}
	return f, nil
}

func nodeHubRetainedReady(e nodeHubRegistryEntry) error {
	client, _, err := loadMachineRecoveryClient(e.StateDir, e.NodeID)
	if err != nil || client.state.HubID != e.HubID || client.state.HubOrigin != e.Origin || !client.bindingReady() {
		return errNodeHubNotReady
	}
	if requireMachineNodePairAdmission(e.StateDir, e.NodeID) != nil {
		return errNodeHubNotReady
	}
	return nil
}

func nodeHubProductionDriver(root string) nodeHubRuntimeDriver {
	return nodeHubRuntimeDriver{
		Run: func(ctx context.Context, e nodeHubRegistryEntry) error {
			if err := nodeHubRetainedReady(e); err != nil {
				return err
			}
			h := machineHubContext{HubID: e.HubID, Origin: e.Origin, NodeID: e.NodeID, StateDir: e.StateDir, WriterRoot: e.WriterRoot, WriterScope: machineNativeWriterScope(), MultiHub: true, ManagedUserRoot: root, ManagedConnectionID: e.ConnectionID, ManagedConnectionEpoch: e.LocalFence}
			args := []string{"--id", e.NodeID, "--name", e.NodeName, "--control-url", e.Origin, "--state-dir", e.StateDir, "--relay-only", "--user-root", root, "--mcp-session-state-file", e.MCPSessionStateFile, "--mcp-outbox-state-file", e.MCPOutboxStateFile}
			// Preserve the original service's validated scheduling interval for
			// its adopted state; no arbitrary original argument is forwarded.
			if saved, _, openErr := nodeHubRoot(ctx, root, false); openErr == nil {
				c, _, readErr := readNodeHubService(saved, root)
				saved.Close()
				if readErr == nil && c.OriginalService != nil {
					if s, ve := validateNodeServiceConfig(*c.OriginalService, root, ""); ve == nil && s.state == e.StateDir && s.id == e.NodeID {
						for i, arg := range c.OriginalService.AgentArgs {
							if arg == "--interval" && i+1 < len(c.OriginalService.AgentArgs) {
								args = append(args, "--interval", c.OriginalService.AgentArgs[i+1])
							}
						}
					}
				}
			}
			return runMachineAgentWithContext(ctx, args, &h)
		},
		Ready: func(ctx context.Context, e nodeHubRegistryEntry) error {
			connection, err := ResolveLocalNodeConnection(ctx, LocalNodeSelection{UserRoot: root, HubID: e.HubID, NodeID: e.NodeID}, nil)
			if err != nil {
				return err
			}
			p := connection.Pin
			if p.ConnectionID != e.ConnectionID || p.ConnectionEpoch != e.LocalFence || p.StateDir != e.StateDir || p.WriterRoot != e.WriterRoot || p.MCPSessionStateFile != e.MCPSessionStateFile || p.MCPOutboxStateFile != e.MCPOutboxStateFile {
				return errNodeHubConflict
			}
			return nil
		},
	}
}

func inspectNodeHubDaemonGate(root *os.Root) (bool, error) {
	const name = "node-hub-manager.lock"
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !localNodePrivate(before, false) {
		return false, ErrLocalNodeHubConfig
	}
	f, err := root.OpenFile(name, os.O_RDWR, 0)
	if err != nil {
		return false, ErrLocalNodeHubConfig
	}
	defer f.Close()
	held, err := f.Stat()
	if err != nil || !os.SameFile(before, held) {
		return false, ErrLocalNodeHubConfig
	}
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return true, nil
	}
	if err != nil {
		return false, ErrLocalNodeHubConfig
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	after, err := root.Lstat(name)
	if err != nil || !os.SameFile(before, after) {
		return false, ErrLocalNodeHubConfig
	}
	return false, nil
}
