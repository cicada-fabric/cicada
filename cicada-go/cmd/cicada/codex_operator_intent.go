package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cicada-ai/cicada/internal/apppaths"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/gofrs/flock"
)

const maxCodexOperatorIntentBytes = 1 << 20

var errCodexOperatorIntentPersistence = errors.New("CODEX_OPERATOR_INTENT_PERSISTENCE: original command retained; no new intent may replace it")
var errCodexOperatorIntentConflict = errors.New("CODEX_OPERATOR_INTENT_CONFLICT: original command requires its exact retry or acknowledgment")
var errCodexOperatorIntentBusy = errors.New("CODEX_OPERATOR_INTENT_BUSY: another local command is updating this scope")
var errCodexOperatorIntentResponse = errors.New("CODEX_OPERATOR_INTENT_RESPONSE_INVALID: original command retained")

type codexOperatorIntentClient struct {
	path     string
	mu       sync.Mutex
	exchange func(string, localEndpointRequest) (*localEndpointResult, error)
	persist  func(string, []byte, string) error
}

type codexOperatorIntentDisk struct {
	Version int                   `json:"version"`
	Pending *codexOperatorPending `json:"pending,omitempty"`
	LastAck *codexOperatorAck     `json:"last_ack,omitempty"`
}

type codexOperatorPending struct {
	ConnectionPin  *LocalNodeConnectionPin `json:"connection_pin,omitempty"`
	NodeID         string                  `json:"node_id"`
	SemanticDigest string                  `json:"semantic_digest"`
	IntentDigest   string                  `json:"intent_digest"`
	Request        localEndpointRequest    `json:"request"`
	Result         *localEndpointResult    `json:"result,omitempty"`
	ResponseError  string                  `json:"response_error,omitempty"`
}

type codexOperatorAck struct {
	RequestID    string `json:"request_id"`
	IntentDigest string `json:"intent_digest"`
}

// path is selected by the consumer from the existing MCP session-state root:
// scopes/<mcpSessionScope>/operator-intent.json. This helper never discovers a
// native SID, parses a prompt, or consults a different default/legacy root.
func openCodexOperatorIntent(path string) (*codexOperatorIntentClient, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." {
		return nil, errCodexOperatorIntentPersistence
	}
	c := &codexOperatorIntentClient{path: path, exchange: requestMachineAgentEndpoint, persist: persistNodeSecretFile}
	if err := c.privateDirectory(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *codexOperatorIntentClient) privateDirectory() error {
	if _, err := apppaths.ResolveUserRoot(filepath.Dir(c.path)); err != nil {
		return errCodexOperatorIntentPersistence
	}
	if err := ensureMCPPrivateDir(filepath.Dir(c.path)); err != nil {
		return errCodexOperatorIntentPersistence
	}
	return nil
}

func codexOperatorPrivateFile(path string, missingOK bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && missingOK {
		return nil, nil
	}
	if err != nil {
		return nil, errCodexOperatorIntentPersistence
	}
	uid, err := machineAgentJoinSocketCurrentUID()
	owner, ok := machineAgentJoinSocketOwner(info)
	if err != nil || !ok || owner != uid || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return nil, errCodexOperatorIntentPersistence
	}
	return info, nil
}

func (c *codexOperatorIntentClient) withLocked(fn func(*codexOperatorIntentDisk) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.privateDirectory(); err != nil {
		return err
	}
	lockPath := c.path + ".lock"
	if _, err := codexOperatorPrivateFile(lockPath, true); err != nil {
		return err
	}
	f, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		if err := f.Close(); err != nil {
			return errCodexOperatorIntentPersistence
		}
	} else if !errors.Is(err, os.ErrExist) {
		return errCodexOperatorIntentPersistence
	}
	if _, err := codexOperatorPrivateFile(lockPath, false); err != nil {
		return err
	}
	lock := flock.New(lockPath, flock.SetPermissions(0o600))
	locked, err := lock.TryLock()
	if err != nil {
		return errCodexOperatorIntentPersistence
	}
	if !locked {
		return errCodexOperatorIntentBusy
	}
	defer lock.Unlock() // Keep the lock inode; never unlink a live lock path.
	if _, err := codexOperatorPrivateFile(lockPath, false); err != nil {
		return err
	}
	disk, err := c.readLocked()
	if err != nil {
		return err
	}
	return fn(&disk)
}

func codexOperatorDigest(q localEndpointRequest, semantic bool) string {
	q.InvocationProof = nil
	if semantic {
		q.RequestID = ""
		q.IssuedAt = ""
		q.endpointGroupsOperatorContextProof = endpointGroupsOperatorContextProof{}
	}
	data, _ := json.Marshal(q)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (c *codexOperatorIntentClient) readLocked() (codexOperatorIntentDisk, error) {
	disk := codexOperatorIntentDisk{Version: 1}
	before, err := codexOperatorPrivateFile(c.path, true)
	if err != nil || before == nil {
		return disk, err
	}
	f, err := os.Open(c.path)
	if err != nil {
		return disk, errCodexOperatorIntentPersistence
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return disk, errCodexOperatorIntentPersistence
	}
	data, err := io.ReadAll(io.LimitReader(f, maxCodexOperatorIntentBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxCodexOperatorIntentBytes || decodeLocalBridgeRequest(data, &disk) != nil || disk.Version != 1 {
		return disk, errCodexOperatorIntentPersistence
	}
	if p := disk.Pending; p != nil {
		if p.Request.InvocationProof != nil {
			return disk, errCodexOperatorIntentPersistence
		}
		if p.Request.validate() != nil || !localContextText(p.NodeID, 256) || p.SemanticDigest != codexOperatorDigest(p.Request, true) || p.IntentDigest != codexOperatorDigest(p.Request, false) {
			return disk, errCodexOperatorIntentPersistence
		}
		if p.ConnectionPin != nil && (validateLocalNodePin(*p.ConnectionPin) != nil || p.ConnectionPin.NodeID != p.NodeID || p.ConnectionPin.APIOrigin != p.Request.APIOrigin) {
			return disk, errCodexOperatorIntentPersistence
		}
		if p.Result != nil {
			if validateCodexOperatorResult(*p, p.Result, codexOperatorStoredError(p)) != nil {
				return disk, errCodexOperatorIntentPersistence
			}
		}
	}
	if a := disk.LastAck; a != nil && (!localContextHex(a.RequestID, 32) || !localContextHex(a.IntentDigest, 64)) {
		return disk, errCodexOperatorIntentPersistence
	}
	return disk, nil
}

func (c *codexOperatorIntentClient) writeLocked(disk *codexOperatorIntentDisk) error {
	if _, err := codexOperatorPrivateFile(c.path, true); err != nil {
		return err
	}
	data, err := json.Marshal(disk)
	if err != nil || len(data)+1 > maxCodexOperatorIntentBytes {
		return errCodexOperatorIntentPersistence
	}
	if err := c.persist(c.path, append(data, '\n'), ".operator-intent-*"); err != nil {
		return errCodexOperatorIntentPersistence
	}
	return nil
}

func (c *codexOperatorIntentClient) prepare(q localEndpointRequest, nodeID string) (localEndpointRequest, error) {
	return c.prepareWithConnectionPin(q, nodeID, nil)
}
func (c *codexOperatorIntentClient) prepareForConnection(q localEndpointRequest, connection LocalNodeConnection) (localEndpointRequest, error) {
	if err := c.validateConnectionPath(connection); err != nil {
		return localEndpointRequest{}, err
	}
	return c.prepareWithConnectionPin(q, connection.Pin.NodeID, &connection.Pin)
}

// The Hook calls this after fresh Node context or an exact pendingDomainJoin
// match. A changed current policy cannot replace the original selector of an
// uncertain command. Recovery sends the complete original request; it does not
// authorize a new request under the old policy.
func (c *codexOperatorIntentClient) originalVerifiedCommand(q localEndpointRequest, nodeID string, pin *LocalNodeConnectionPin) (localEndpointRequest, error) {
	if q.Version == 0 {
		q.Version = localJoinProtocolVersion
	}
	original := q
	err := c.withLocked(func(disk *codexOperatorIntentDisk) error {
		p := disk.Pending
		if p == nil {
			return nil
		}
		if p.NodeID != nodeID || !sameCodexOperatorConnectionPin(pin, p.ConnectionPin) {
			return errCodexOperatorIntentConflict
		}
		old, current := p.Request, q
		old.LocalDomainVersion, current.LocalDomainVersion = 0, 0
		old.LocalDomain, current.LocalDomain = wire.LocalDomainSelection{}, wire.LocalDomainSelection{}
		old.codexEndpointGroupsBinding, current.codexEndpointGroupsBinding = codexEndpointGroupsBinding{}, codexEndpointGroupsBinding{}
		if codexOperatorDigest(old, true) != codexOperatorDigest(current, true) {
			return errCodexOperatorIntentConflict
		}
		original = p.Request
		return nil
	})
	return original, err
}

// Only a previously persisted, pinned domain Join carries every coordinate
// needed for recovery before fresh context issuance. This returns no new
// request and does not infer coordinates for Pair, directory or legacy intents.
func (c *codexOperatorIntentClient) pendingDomainJoin(q localEndpointRequest, nodeID string, pin *LocalNodeConnectionPin) (localEndpointRequest, bool, error) {
	original, found := q, false
	if q.Operation != "endpoint_register" || pin == nil {
		return original, false, nil
	}
	if info, err := codexOperatorPrivateFile(c.path, true); err != nil || info == nil {
		return original, false, err
	}
	err := c.withLocked(func(disk *codexOperatorIntentDisk) error {
		p := disk.Pending
		if p == nil || (p.Request.LocalDomainVersion != 1 && p.Request.EndpointGroupsVersion != 1) || p.Request.Operation != "endpoint_register" {
			return nil
		}
		if p.NodeID != nodeID || !sameCodexOperatorConnectionPin(pin, p.ConnectionPin) {
			return errCodexOperatorIntentConflict
		}
		old, current := p.Request, q
		old.LocalDomainVersion, current.LocalDomainVersion = 0, 0
		old.LocalDomain, current.LocalDomain = wire.LocalDomainSelection{}, wire.LocalDomainSelection{}
		old.codexEndpointGroupsBinding, current.codexEndpointGroupsBinding = codexEndpointGroupsBinding{}, codexEndpointGroupsBinding{}
		if codexOperatorDigest(old, true) != codexOperatorDigest(current, true) {
			return errCodexOperatorIntentConflict
		}
		original, found = p.Request, true
		return nil
	})
	return original, found, err
}

func (c *codexOperatorIntentClient) validateConnectionPath(connection LocalNodeConnection) error {
	p := connection.Pin
	if validateLocalNodePin(p) != nil || !localContextHex(connection.InstanceID, 32) || !localContextHex(connection.LocatorDigest, 64) {
		return ErrLocalNodeDiscoveryInvalid
	}
	if filepath.Base(c.path) != "operator-intent.json" || filepath.Dir(filepath.Dir(c.path)) != filepath.Join(filepath.Dir(p.MCPSessionStateFile), "scopes") || !localContextHex(filepath.Base(filepath.Dir(c.path)), 64) {
		return ErrLocalNodeBindingChanged
	}
	return nil
}
func (c *codexOperatorIntentClient) prepareWithConnectionPin(q localEndpointRequest, nodeID string, pin *LocalNodeConnectionPin) (localEndpointRequest, error) {
	q.InvocationProof = nil
	var original localEndpointRequest
	if q.Version == 0 {
		q.Version = localJoinProtocolVersion
	}
	if q.Version != localJoinProtocolVersion {
		return original, nodewire.ErrEndpointContext
	}
	origin, err := normalizeMCPAPIOrigin(q.APIOrigin)
	if err != nil || origin != q.APIOrigin || !localContextText(nodeID, 256) {
		return original, nodewire.ErrEndpointContext
	}
	if pin != nil && (q.APIOrigin != pin.APIOrigin || nodeID != pin.NodeID) {
		return original, ErrLocalNodeBindingChanged
	}
	semantic := codexOperatorDigest(q, true)
	err = c.withLocked(func(disk *codexOperatorIntentDisk) error {
		if p := disk.Pending; p != nil {
			if pin != nil && p.ConnectionPin == nil {
				return ErrLocalNodeConfigRequired
			}
			if (pin == nil) != (p.ConnectionPin == nil) || pin != nil && !sameLocalNodeAuthority(*pin, *p.ConnectionPin) {
				return ErrLocalNodeBindingChanged
			}
			if p.NodeID != nodeID || p.SemanticDigest != semantic {
				return errCodexOperatorIntentConflict
			}
			original = p.Request
			return nil
		}
		if (q.RequestID == "") != (q.IssuedAt == "") {
			return nodewire.ErrEndpointContext
		}
		if q.RequestID == "" {
			now := time.Now().UTC()
			id, err := newLocalEndpointRequestID(now)
			if err != nil {
				return err
			}
			q.RequestID = id
			q.IssuedAt = now.Format(time.RFC3339Nano)
		}
		if q.validate() != nil {
			return nodewire.ErrEndpointContext
		}
		if disk.LastAck != nil && disk.LastAck.RequestID == q.RequestID {
			return errCodexOperatorIntentConflict
		}
		disk.Pending = &codexOperatorPending{ConnectionPin: pin, NodeID: nodeID, SemanticDigest: semantic, IntentDigest: codexOperatorDigest(q, false), Request: q}
		if err := c.writeLocked(disk); err != nil {
			return err
		}
		original = q
		return nil
	})
	return original, err
}

func codexOperatorStoredError(p *codexOperatorPending) error {
	if p.ResponseError == "" {
		return nil
	}
	return errors.New(p.ResponseError)
}

func validateCodexOperatorResult(p codexOperatorPending, r *localEndpointResult, responseErr error) error {
	q := p.Request
	if r == nil || r.RequestID != q.RequestID || r.IntentDigest != p.IntentDigest || r.Operation != q.Operation || r.NodeID != p.NodeID || !localContextText(r.HubID, 256) {
		return errCodexOperatorIntentResponse
	}
	if p.ConnectionPin != nil && r.HubID != p.ConnectionPin.HubID {
		return errCodexOperatorIntentResponse
	}
	if q.EndpointGroupsVersion == 1 {
		return validateEndpointGroupsOperatorResult(p, r, responseErr)
	}
	if r.EndpointGroups != nil {
		return errCodexOperatorIntentResponse
	}
	if q.LocalDomainVersion != 0 && r.State == "COMPLETED" {
		return validateCodexDomainOperatorResult(p, r, responseErr)
	}
	if r.LocalDomain != nil {
		return errCodexOperatorIntentResponse
	}
	payloads := 0
	if r.Registration != nil {
		payloads++
	}
	if r.Directory != nil {
		payloads++
	}
	if r.Pairs != nil {
		payloads++
	}
	if r.Join != nil {
		payloads++
	}
	if r.State == "REFUSED" {
		if payloads != 0 || r.NativeContextScope != nil || responseErr == nil {
			return errCodexOperatorIntentResponse
		}
		if q.Operation == "native_pair_join_named" && responseErr.Error() == errNativePairNodeRejected.Error() {
			return nil
		}
		if q.Operation != "native_pair_join_named" {
			switch responseErr.Error() {
			case nodewire.ErrEndpointContext.Error(), nodewire.ErrEndpointConflict.Error(), nodewire.ErrEndpointUnavailable.Error():
				return nil
			}
		}
		return errCodexOperatorIntentResponse
	}
	if r.State != "COMPLETED" || responseErr != nil || payloads != 1 {
		return errCodexOperatorIntentResponse
	}
	switch q.Operation {
	case "endpoint_register", "endpoint_leave":
		if r.Registration == nil || r.NativeContextScope != nil || !localContextText(r.Registration.EndpointID, 256) || !localContextHex(r.Registration.StateDigest, 64) || r.Registration.Workspace != q.Workspace || (q.Operation == "endpoint_leave" && r.Registration.Presence != "left") {
			return errCodexOperatorIntentResponse
		}
	case "endpoint_directory":
		if r.Directory == nil || r.NativeContextScope != nil || r.Directory.NodeID != p.NodeID || r.Directory.Freshness != "SNAPSHOT_ONLY" || len(r.Directory.Endpoints) > 64 {
			return errCodexOperatorIntentResponse
		}
	case "native_pair_available":
		if r.Pairs == nil || r.NativeContextScope != nil || len(r.Pairs.Pairs) > 64 {
			return errCodexOperatorIntentResponse
		}
	case "native_pair_join_named":
		j := r.Join
		if j == nil || !localContextText(j.SessionToken, 512) || j.BindingID == "" || j.BindingEpoch == 0 || j.Endpoint.ID == "" || j.Endpoint.GroupID == "" || j.Endpoint.PrincipalID == "" || j.Endpoint.MachineID != p.NodeID || j.Endpoint.Harness != q.Harness || j.Endpoint.NativeSessionID != q.NativeSessionID || j.Endpoint.Workspace != q.Workspace {
			return errCodexOperatorIntentResponse
		}
	default:
		return errCodexOperatorIntentResponse
	}
	return nil
}

// call always persists/reloads the exact original before IPC. A verified result
// is kept privately until the consumer stores its Join session or emits its
// successful output and explicitly acknowledges. It is historical completion,
// not fresh evidence of a current lease or permission.
func (c *codexOperatorIntentClient) call(socketPath string, q localEndpointRequest, nodeID string) (*localEndpointResult, error) {
	return c.callWithConnectionPin(socketPath, q, nodeID, nil)
}
func (c *codexOperatorIntentClient) callForConnection(q localEndpointRequest, connection LocalNodeConnection) (*localEndpointResult, error) {
	if err := c.validateConnectionPath(connection); err != nil {
		return nil, err
	}
	return c.callWithConnectionPin(connection.Pin.SocketPath, q, connection.Pin.NodeID, &connection.Pin)
}
func (c *codexOperatorIntentClient) callWithConnectionPin(socketPath string, q localEndpointRequest, nodeID string, pin *LocalNodeConnectionPin) (*localEndpointResult, error) {
	invocation := q.InvocationProof
	q.InvocationProof = nil
	original, err := c.prepareWithConnectionPin(q, nodeID, pin)
	if err != nil {
		return nil, err
	}
	var cached *localEndpointResult
	var cachedErr error
	err = c.withLocked(func(disk *codexOperatorIntentDisk) error {
		p := disk.Pending
		if p == nil || p.Request != original || p.NodeID != nodeID || !sameCodexOperatorConnectionPin(pin, p.ConnectionPin) {
			return errCodexOperatorIntentConflict
		}
		cached, cachedErr = p.Result, codexOperatorStoredError(p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if cached != nil {
		return cached, cachedErr
	}
	request := original
	request.InvocationProof = invocation
	result, callErr := c.exchange(socketPath, request)
	p := codexOperatorPending{ConnectionPin: pin, NodeID: nodeID, Request: original, IntentDigest: codexOperatorDigest(original, false)}
	if validateCodexOperatorResult(p, result, callErr) != nil {
		if result != nil && result.RequestID == original.RequestID && result.IntentDigest == p.IntentDigest && result.Operation == original.Operation && result.NodeID == nodeID && result.HubID != "" && (pin == nil || result.HubID == pin.HubID) && result.State == "UNKNOWN" && callErr != nil {
			return result, callErr
		}
		if result == nil && callErr != nil {
			return nil, callErr
		}
		return nil, errCodexOperatorIntentResponse
	}
	err = c.withLocked(func(disk *codexOperatorIntentDisk) error {
		p := disk.Pending
		if p == nil || p.Request != original || p.NodeID != nodeID || p.IntentDigest != result.IntentDigest || !sameCodexOperatorConnectionPin(pin, p.ConnectionPin) {
			return errCodexOperatorIntentConflict
		}
		if p.Result != nil {
			old, _ := json.Marshal(p.Result)
			next, _ := json.Marshal(result)
			if string(old) != string(next) || p.ResponseError != errorStringCodexOperator(callErr) {
				return errCodexOperatorIntentResponse
			}
			return nil
		}
		p.Result = result
		p.ResponseError = errorStringCodexOperator(callErr)
		return c.writeLocked(disk)
	})
	if err != nil {
		return nil, err
	}
	return result, callErr
}

func errorStringCodexOperator(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (c *codexOperatorIntentClient) ack(requestID, intentDigest string) error {
	return c.withLocked(func(disk *codexOperatorIntentDisk) error {
		if p := disk.Pending; p != nil {
			if p.Request.RequestID != requestID || p.IntentDigest != intentDigest || p.Result == nil || validateCodexOperatorResult(*p, p.Result, codexOperatorStoredError(p)) != nil {
				return errCodexOperatorIntentConflict
			}
			disk.LastAck = &codexOperatorAck{requestID, intentDigest}
			disk.Pending = nil
			return c.writeLocked(disk)
		}
		if disk.LastAck != nil && disk.LastAck.RequestID == requestID && disk.LastAck.IntentDigest == intentDigest {
			return nil
		}
		return errCodexOperatorIntentConflict
	})
}

func sameCodexOperatorConnectionPin(a, b *LocalNodeConnectionPin) bool {
	return a == nil && b == nil || a != nil && b != nil && sameLocalNodeAuthority(*a, *b)
}
