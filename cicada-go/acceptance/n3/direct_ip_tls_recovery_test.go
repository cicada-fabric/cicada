package n3_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
)

// Qualify the opaque negative fault itself before the Node-dependent committed
// recovery gate. This synthetic endpoint creates no Hub/App authority. The
// observer must distinguish arming from a durably-pending signal and retain
// verified TLS end to end; it never parses or terminates the TLS stream.
func TestN3DirectIPTLSCipherFaultFixture(t *testing.T) {
	a := newDirectIPTLSAdversary(t)
	now := time.Now().UTC()
	leaf := a.leaf(t, a.descriptor.Claims.ServerName, now.Add(-time.Hour), now.Add(time.Hour), a.serviceKey)
	target := newDirectIPTLSTrap(t, http.StatusNoContent, "", leaf)
	var pending atomic.Bool
	fault := newDirectIPCipherFault(t, target.server.Listener.Addr().String(), pending.Load)
	client := must(hubtransport.NewHTTPClient(a.descriptor, fault.listener.Addr().String(), 5*time.Second))
	t.Cleanup(client.CloseIdleConnections)
	for _, armed := range []bool{false, true} {
		fault.armed.Store(armed)
		response, err := directIPTLSRequest(t, client, a.descriptor.Claims.Origin+"/synthetic-negative-control", nil)
		if err != nil || response.StatusCode != http.StatusNoContent || fault.dropped.Load() {
			t.Fatal("opaque fault broke verified TLS or dropped without pending evidence")
		}
	}
	pending.Store(true)
	_, err := directIPTLSRequest(t, client, a.descriptor.Claims.Origin+"/synthetic-negative-commit", nil)
	if err == nil || !fault.dropped.Load() || fault.bytes.Load() == 0 || target.posts.Load() != 3 {
		t.Fatal("opaque response loss did not follow an observed synthetic endpoint request")
	}
	client.CloseIdleConnections()
	fault.armed.Store(false)
	pending.Store(false)
	response, err := directIPTLSRequest(t, client, a.descriptor.Claims.Origin+"/synthetic-negative-reconnect", nil)
	if err != nil || response.StatusCode != http.StatusNoContent || target.posts.Load() != 4 {
		t.Fatal("opaque fault did not permit a fresh verified TLS connection after loss")
	}
}

// Negative fault lane only. This peer forwards opaque TCP bytes; TLS is still
// terminated by the actual Hub. It never holds a TLS key, reads HTTP or acts as
// a trusted frontend in any positive installation/MCP acceptance case.
type directIPCipherFault struct {
	listener net.Listener
	armed    atomic.Bool
	dropped  atomic.Bool
	bytes    atomic.Int64
	cuts     atomic.Int64
	mu       sync.Mutex
	stopped  bool
	conns    []net.Conn
	wg       sync.WaitGroup
}

func newDirectIPCipherFault(t *testing.T, target string, pending func() bool) *directIPCipherFault {
	t.Helper()
	return newDirectIPCipherFaultDirection(t, target, pending, false, false)
}

// The new pairing fault also cuts the client direction before forwarding, and
// can keep cutting only the same durably pending original until its separately
// persisted reconcile exists. The predicate observes owned state, never TLS
// record counts, HTTP, plaintext or keys.
func newDirectIPCipherFaultDirection(t *testing.T, target string, pending func() bool, clientSide, repeat bool) *directIPCipherFault {
	t.Helper()
	f := &directIPCipherFault{listener: must(net.Listen("tcp", "127.0.0.1:0"))}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			client, err := f.listener.Accept()
			if err != nil {
				return
			}
			server, err := net.DialTimeout("tcp", target, 3*time.Second)
			if err != nil {
				client.Close()
				continue
			}
			f.mu.Lock()
			if f.stopped {
				f.mu.Unlock()
				client.Close()
				server.Close()
				return
			}
			f.conns = append(f.conns, client, server)
			f.mu.Unlock()
			f.wg.Add(2)
			copyDirection := func(destination, source net.Conn, canCut bool) {
				defer f.wg.Done()
				defer client.Close()
				defer server.Close()
				buffer := make([]byte, 32*1024)
				for {
					n, err := source.Read(buffer)
					if n > 0 {
						// The Controller durably saves its original request before
						// sending it. Observing that coherent encrypted vault image
						// here distinguishes the secret POST from capability GETs;
						// record boundaries and packet timing are never guessed.
						if canCut && f.armed.Load() && (repeat || !f.dropped.Load()) && pending() && (repeat || f.dropped.CompareAndSwap(false, true)) {
							f.dropped.Store(true)
							f.bytes.Add(int64(n))
							f.cuts.Add(1)
							return
						}
						if _, writeErr := destination.Write(buffer[:n]); writeErr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}
			go copyDirection(server, client, clientSide)
			go copyDirection(client, server, !clientSide)
		}
	}()
	t.Cleanup(func() {
		f.listener.Close()
		f.mu.Lock()
		f.stopped = true
		for _, conn := range f.conns {
			conn.Close()
		}
		f.mu.Unlock()
		done := make(chan struct{})
		go func() { f.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("owned opaque TCP fault did not close all workers")
		}
	})
	return f
}

type directIPReadOperation struct {
	Applied   bool                           `json:"applied"`
	Operation string                         `json:"operation"`
	Request   []byte                         `json:"request"`
	Response  []byte                         `json:"response"`
	Read      *wire.OwnerEndpointReadRequest `json:"owner_endpoint_read"`
}

type directIPNodeImage struct {
	Pending   *directIPReadOperation `json:"pending"`
	Directory *directIPReadOperation `json:"owner_directory"`
}

func directIPScope(f *directIPHub) appvault.Scope {
	m := f.material
	return appvault.Scope{HubID: m.HubID, HubFingerprint: m.HubFingerprint, Origin: m.Origin, AccountID: m.AccountID, OwnerID: m.OwnerID}
}

func directIPRetainedState(t *testing.T, f *directIPHub, appDir string) map[string]string {
	t.Helper()
	vault := must(syntheticVaultOpener(filepath.Join(appDir, "home", ".cicada", "app", "vaults"))(context.Background(), directIPScope(f), false))
	defer vault.Close()
	raw, _, found, err := vault.LoadState("appcore.state.v1")
	if err != nil || !found {
		t.Fatal("original encrypted App state unavailable")
	}
	defer clear(raw)
	var record map[string]json.RawMessage
	if json.Unmarshal(raw, &record) != nil {
		t.Fatal("original encrypted App state is invalid")
	}
	defer func() {
		for _, value := range record {
			clear(value)
		}
	}()
	out := make(map[string]string)
	for _, name := range []string{"scope", "transport", "pending", "recovery"} {
		out[name] = hash(record[name])
	}
	return out
}

// Only copy a coherent atomic encrypted image to a different owned path.
// Respect the live original vault lock. No signing key is retrieved here.
func directIPCopiedNodeImage(f *directIPHub, appDir string) (*directIPNodeImage, error) {
	scope := directIPScope(f)
	rawScope, err := json.Marshal(scope)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(appDir, "home", ".cicada", "app", "vaults", hash(rawScope)+".vault")
	image, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(image)
	if len(image) > harnessPacketLimit {
		return nil, wire.ErrInvalid
	}
	dir, err := os.MkdirTemp(f.dir, "private-vault-image-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	copyPath := filepath.Join(dir, "snapshot.vault")
	if err = os.WriteFile(copyPath, image, 0600); err != nil {
		return nil, err
	}
	protector, err := appvault.NewPasswordProtector([]byte("Synthetic N3 acceptance vault passphrase"))
	if err != nil {
		return nil, err
	}
	vault, err := appvault.Open(copyPath, scope, protector)
	if err != nil {
		protector.Close()
		return nil, err
	}
	defer vault.Close()
	raw, _, found, err := vault.LoadState("appcore.node.v1")
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	if !found {
		return &directIPNodeImage{}, nil
	}
	var out directIPNodeImage
	if err = json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func clearDirectIPRead(op *directIPReadOperation) {
	if op == nil {
		return
	}
	clear(op.Request)
	clear(op.Response)
	if op.Read != nil {
		clear(op.Read.SessionToken)
		clear(op.Read.OwnerProof)
	}
}

type directIPCachedRead struct {
	operation, digest, state string
	response                 []byte
	count                    int
}

func directIPCachedResult(t *testing.T, f *directIPHub, request *wire.OwnerEndpointReadRequest) directIPCachedRead {
	t.Helper()
	u := &url.URL{Scheme: "file", Path: filepath.Join(f.state, "cicada.sqlite3"), RawQuery: "mode=ro"}
	db := must(sql.Open("sqlite", u.String()))
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out directIPCachedRead
	c := request.Context
	if db.QueryRowContext(ctx, `SELECT operation,request_digest,state,response_packet FROM hub_app_node_reads_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`,
		c.OwnerID, c.DeviceID, c.RequestID).Scan(&out.operation, &out.digest, &out.state, &out.response) != nil ||
		db.QueryRowContext(ctx, `SELECT count(*) FROM hub_app_node_reads_v1 WHERE owner_id=? AND device_id=? AND operation_id=?`, c.OwnerID, c.DeviceID, c.RequestID).Scan(&out.count) != nil {
		t.Fatal("read-only Hub database did not retain the exact committed original read")
	}
	return out
}

func directIPOriginalRecovery(t *testing.T) {
	v := newDirectIPNodeFixture(t, "127.0.0.1")
	current := v.do(t, appcore.Action{Kind: appcore.ActionRefreshNode})
	action := ownerDirectoryReadAction(t, current)
	v.app.command(t, directIPAppCommand{Close: true})
	appDir := v.app.dir
	fault := newDirectIPCipherFault(t, v.hub.address, func() bool {
		image, err := directIPCopiedNodeImage(v.hub, appDir)
		if err != nil {
			return false
		}
		defer clearDirectIPRead(image.Pending)
		defer clearDirectIPRead(image.Directory)
		return image.Pending != nil && image.Pending.Operation == wire.OperationOwnerEndpointRead && len(image.Pending.Request) > 0 && len(image.Pending.Response) == 0
	})
	v.app = startDirectIPApp(t, appDir)
	profiles := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionDiscoverProfiles}})
	if profiles.ActionFailed || len(profiles.Snapshot.Profiles) != 1 {
		t.Fatal("original encrypted profile unavailable before opaque network fault")
	}
	resumed := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: profiles.Snapshot.Profiles[0].ID,
		HubAddress: fault.listener.Addr().String()}})
	if resumed.ActionFailed || !resumed.Snapshot.Hub.Verified {
		t.Fatal("end-to-end native TLS did not verify through the negative opaque-byte fault peer")
	}
	// Use the current review after resume; a locator is not application scope.
	action = ownerDirectoryReadAction(t, resumed.Snapshot)
	fault.armed.Store(true)
	failed := v.app.command(t, directIPAppCommand{Action: &action})
	fault.armed.Store(false)
	if !failed.ActionFailed || !failed.Snapshot.OwnerEndpoints.Pending || !fault.dropped.Load() || fault.bytes.Load() == 0 {
		t.Fatal("actual lost response did not retain an uncertain original directory read")
	}
	v.app.command(t, directIPAppCommand{Close: true})
	image := must(directIPCopiedNodeImage(v.hub, appDir))
	defer clearDirectIPRead(image.Pending)
	defer clearDirectIPRead(image.Directory)
	original := image.Pending
	if original == nil || original.Read == nil || original.Operation != wire.OperationOwnerEndpointRead || len(original.Response) != 0 || len(original.Request) == 0 {
		t.Fatal("lost response lacks its authentic durable original request")
	}
	cached := directIPCachedResult(t, v.hub, original.Read)
	defer clear(cached.response)
	if cached.operation != wire.OperationOwnerEndpointRead || cached.digest != wire.AppNodePacketDigest(original.Request) || cached.state != wire.AppNodeCompleted || cached.count != 1 || len(cached.response) == 0 {
		state := "OTHER"
		if cached.state == wire.AppNodeCompleted {
			state = "COMPLETED"
		}
		if cached.state == wire.AppNodeReadExpired {
			state = "READ_EXPIRED"
		}
		t.Fatalf("response loss lacks exact committed result: operation_match=%t domain_digest_match=%t state=%s rows=%d response_present=%t", cached.operation == wire.OperationOwnerEndpointRead, cached.digest == wire.AppNodePacketDigest(original.Request), state, cached.count, len(cached.response) > 0)
	}
	v.hub.hub.kill(t)
	v.hub.start(t)
	v.app = startDirectIPApp(t, appDir)
	profiles = v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionDiscoverProfiles}})
	if profiles.ActionFailed || len(profiles.Snapshot.Profiles) != 1 {
		t.Fatal("original profile unavailable after actual Hub/App restart")
	}
	recovered := v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionResumeProfile, ProfileID: profiles.Snapshot.Profiles[0].ID,
		HubAddress: v.hub.address}})
	if recovered.ActionFailed {
		t.Fatal("original direct profile did not resume after response loss")
	}
	if recovered.Snapshot.OwnerEndpoints.Pending {
		recovered = v.app.command(t, directIPAppCommand{Action: &appcore.Action{Kind: appcore.ActionRecoverOwnerEndpoints}})
	}
	if recovered.ActionFailed || recovered.Snapshot.OwnerEndpoints.Pending || recovered.Snapshot.OwnerEndpoints.State != "SNAPSHOT_ONLY" ||
		recovered.Snapshot.Account.DeviceID != v.original.Account.DeviceID || recovered.Snapshot.Account.LocalOwnerKeyID != v.original.Account.LocalOwnerKeyID ||
		recovered.Snapshot.Hub.Fingerprint != v.original.Hub.Fingerprint || recovered.Snapshot.Management != appcore.ManagementUnavailable {
		t.Fatal("actual original recovery changed identity, lost its signed result or created management authority")
	}
	v.app.command(t, directIPAppCommand{Close: true})
	settled := must(directIPCopiedNodeImage(v.hub, appDir))
	defer clearDirectIPRead(settled.Pending)
	defer clearDirectIPRead(settled.Directory)
	directoryExact := settled.Directory != nil && settled.Directory.Applied && bytes.Equal(settled.Directory.Request, original.Request) && bytes.Equal(settled.Directory.Response, cached.response)
	// afterNodeRecovery performs an authenticated read-only Node status
	// refresh. It may retain that applied status operation in the serialized
	// outbox; the original directory packet/receipt remains in OwnerDirectory.
	pendingSettled := settled.Pending == nil || settled.Pending.Applied &&
		(settled.Pending.Operation == wire.OperationOwnerEndpointRead && bytes.Equal(settled.Pending.Request, original.Request) && bytes.Equal(settled.Pending.Response, cached.response) ||
			settled.Pending.Operation == wire.OperationAppNodeStatus && len(settled.Pending.Request) > 0 && len(settled.Pending.Response) > 0)
	if !directoryExact || !pendingSettled {
		t.Fatalf("recovery did not retain exact applied ciphertext: directory_exact=%t pending_absent_or_authenticated_applied_read=%t", directoryExact, pendingSettled)
	}
	// Independently authenticate with the original scoped App-device key. The
	// parent never retrieves an Owner signing key or produces an Owner proof.
	vault := must(syntheticVaultOpener(filepath.Join(appDir, "home", ".cicada", "app", "vaults"))(context.Background(), directIPScope(v.hub), false))
	defer vault.Close()
	verified := false
	for _, entry := range must(vault.List()) {
		if entry.Purpose != appvault.PurposeAppDevice {
			continue
		}
		key := must(vault.Get(entry.Purpose, entry.KeyID))
		device := must(key.E2EE())
		var result wire.OwnerEndpointReadResult
		verified = wire.OpenClientResponse(device, v.hub.descriptor.Claims.Hub, original.Request, cached.response, &result) == nil &&
			wire.VerifyOwnerEndpointReadResult(result, *original.Read, original.Request) == nil && result.State == wire.AppNodeCompleted && result.Freshness == "SNAPSHOT_ONLY"
		if settled.Pending != nil && settled.Pending.Operation == wire.OperationAppNodeStatus {
			var status wire.AppNodeResult
			verified = verified && wire.OpenClientResponse(device, v.hub.descriptor.Claims.Hub, settled.Pending.Request, settled.Pending.Response, &status) == nil
		}
		key.Close()
	}
	final := directIPCachedResult(t, v.hub, original.Read)
	defer clear(final.response)
	if !verified || final.count != 1 || final.digest != cached.digest || !bytes.Equal(final.response, cached.response) {
		t.Fatal("exact recovery failed independent crypto or duplicated the committed request")
	}
	t.Logf("DIRECT_IP_RECOVERY request_packet_digest=%s response_sha256=%s actual_Hub_readonly_cache_rows=1 dropped_TLS_cipher_bytes=%d", cached.digest, hash(cached.response), fault.bytes.Load())
	directIPFacts(t, "DIP12_OriginalPacketRecovery", map[string]bool{"actual_end_to_end_TLS_response_loss": true, "Hub_commit_independently_observed": true,
		"actual_Hub_App_restart": true, "original_request_and_response_bytes": true, "original_device_crypto_verified": true, "exact_cache_row_one": true, "Owner_private_key_not_retrieved": true})
}
