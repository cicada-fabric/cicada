package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

func nodeTLSRecoveryNativeRequired(t *testing.T) bool {
	t.Helper()
	if err := pqtls.Available(); err != nil {
		if os.Getenv("PQTLS_TEST_OPENSSL") != "" || !errors.Is(err, pqtls.ErrUnavailable) {
			t.Fatal("requested native TLS recovery provider unavailable")
		}
		t.Log("NOT_RUN native TLS recovery: typed unavailable")
		return false
	}
	return true
}

func TestNodeTLSRecoveryMissingTransportAndProvider(t *testing.T) {
	persistence, err := store.New(filepath.Join(t.TempDir(), "synthetic-default.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer persistence.Close()
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(persistence, hubID, hubID)
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	reader := func(string, string, []byte) ([]byte, error) {
		calls.Add(1)
		return nil, errors.New("unexpected provider dispatch")
	}
	packet := func(operation string) []byte {
		wire, err := json.Marshal(nodewire.Packet{Route: nodewire.Route{Operation: operation, OperationID: "synthetic-default-only", NodeID: "synthetic-node"}, Envelope: []byte("synthetic invalid envelope; transport gate only")})
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	for _, test := range []struct {
		name      string
		handler   http.Handler
		operation string
		want      int
	}{
		{"legacy-fabric-no-provider", NewFabricHandler(service, ""), nodewire.RecoveryOperation, http.StatusServiceUnavailable},
		{"current-only-no-recovery", NewFabricHandlerWithNodeTLSCurrent(service, "", reader), nodewire.RecoveryOperation, http.StatusServiceUnavailable},
		{"dedicated-recovery-no-native", NewFabricHandlerWithNodeTLSReaders(service, "", reader, reader), nodewire.RecoveryOperation, http.StatusForbidden},
		{"ordinary-business-still-control-gated", NewFabricHandlerWithNodeTLSReaders(service, "", reader, reader), "node.heartbeat", http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.handler.(*Handler).control != nil {
				t.Fatal("Fabric-only construction created Control business")
			}
			req := httptest.NewRequest(http.MethodPost, "https://hub.synthetic.invalid/v2/node/control/rpc", bytes.NewReader(packet(test.operation)))
			req.Header.Set("Authorization", "CicadaNode "+token)
			response := httptest.NewRecorder()
			test.handler.ServeHTTP(response, req)
			if response.Code != test.want || calls.Load() != 0 {
				t.Fatal("missing authority reached a provider or ordinary Control business")
			}
		})
	}
}

type nodeTLSRecoveryFixture struct {
	process     nodeTLSProcessFixture
	persistence *store.Store
	service     *fabric.Service
	node, hub   *e2ee.Identity
	binding     *store.NodeControlKeyBinding
	wire        nodewire.Binding
	current     *store.NodeTLSAuthoritySnapshot
	query       nodewire.RecoveryRequest
	packet      []byte
}

func newNodeTLSRecoveryFixture(t *testing.T) *nodeTLSRecoveryFixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	process, node, hub := nodeTLSCurrentBuild(t, dir)
	persistence, err := store.New(process.DBPath)
	if err != nil {
		t.Fatal(err)
	}
	// Listener cleanup is registered later and therefore runs before Store close.
	t.Cleanup(func() {
		if err := persistence.Close(); err != nil {
			t.Error(err)
		}
	})
	status, err := persistence.ReadNodeTLSAuthorityRecoveryLocal(store.NodeTLSAuthorityStatusInput{NodeID: process.NodeConfig.Identity.NodeID, CredentialDigest: fabric.HashSessionCredential(process.NodeToken)})
	if err != nil || status.CurrentActive == nil || status.CurrentActiveState != store.NodeTLSAuthorityCurrentVerified {
		t.Fatal("real Owner-approved D1 fixture was not independently current")
	}
	// Exercise the production existing-identity reader with only synthetic keys.
	identityPath := filepath.Join(dir, "synthetic-existing-hub-control.json")
	secret, err := hub.MarshalBinary()
	if err != nil {
		t.Fatal("marshal synthetic existing Hub identity")
	}
	nodeTLSProcessWrite(t, identityPath, secret)
	clear(secret)
	hub, err = control.LoadExistingNodeTLSHubIdentity(identityPath)
	if err != nil {
		t.Fatal("read existing synthetic Hub identity")
	}
	b := status.CurrentBinding
	wire := nodewire.Binding{HubID: b.HubID, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, HubKeyVersion: b.HubKeyVersion, NodeKeyVersion: b.NodeKeyVersion, NodeKey: b.NodePublicIdentity, HubKey: b.HubPublicIdentity}
	service, err := fabric.NewService(persistence, b.HubID, b.HubID)
	if err != nil {
		t.Fatal(err)
	}
	f := &nodeTLSRecoveryFixture{process: process, persistence: persistence, service: service, node: node, hub: hub, binding: b, wire: wire, current: status.CurrentActive}
	f.query = nodewire.RecoveryRequest{Nonce: make([]byte, 32), Origin: process.NodeConfig.LogicalOrigin(), CredentialDigest: b.CredentialDigest, RestoreDigest: nodewire.RecoveryDigest([]byte("SYNTHETIC TLS RESTORE ONLY")), PlanDigest: nodewire.RecoveryDigest([]byte("SYNTHETIC IMMUTABLE RECOVERY PLAN ONLY"))}
	if _, err := rand.Read(f.query.Nonce); err != nil {
		t.Fatal(err)
	}
	// Admit fixture metadata through current-fenced Store APIs. No business
	// operation is dispatched: these are visibly synthetic recovery ledger rows.
	for i, state := range []string{store.NodeControlRPCComplete, store.NodeControlRPCProcessing, store.NodeControlRPCUncertain} {
		sequence := uint64(40 + i)
		route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: wire.HubID, NodeID: wire.NodeID, BindingID: wire.BindingID, BindingVersion: wire.BindingVersion, NodeKeyEpoch: wire.NodeKeyEpoch, Sequence: sequence, OperationID: fmt.Sprintf("synthetic_tls_recovery_%d", i), Operation: "node.binding.status", SenderKeyID: wire.NodeKey.ID, SenderKeyVersion: wire.NodeKeyVersion, ReceiverKeyID: wire.HubKey.ID, ReceiverKeyVersion: wire.HubKeyVersion}
		packet, err := nodewire.SealRequest(node, wire.HubKey, wire, route, []byte(`{}`))
		if err != nil {
			t.Fatal("seal synthetic ledger request")
		}
		input := store.NodeControlRPCInput{CredentialDigest: b.CredentialDigest, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyID: b.NodeKeyID, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: sequence, OperationID: route.OperationID, Operation: route.Operation, RequestDigest: nodewire.RecoveryDigest(packet)}
		if _, retry, err := persistence.BeginNodeControlRPC(input); err != nil || retry {
			t.Fatal("current-fenced synthetic metadata admission")
		}
		if state == store.NodeControlRPCComplete {
			route.Direction = nodewire.DirectionResponse
			route.SenderKeyID, route.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
			route.SenderKeyVersion, route.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
			reply, err := nodewire.SealResponse(hub, wire.NodeKey, wire, route, []byte(`{"synthetic_metadata_only":true}`))
			if err != nil || persistence.CompleteNodeControlRPC(store.NodeControlRPCCompletion{NodeControlRPCInput: input, ResponsePacket: reply}) != nil {
				t.Fatal("synthetic exact metadata completion")
			}
		} else if state == store.NodeControlRPCUncertain {
			if err := persistence.MarkNodeControlRPCUncertain(input); err != nil {
				t.Fatal(err)
			}
		}
		f.query.Operations = append(f.query.Operations, nodewire.RecoveryOperationQuery{OperationID: input.OperationID, Sequence: sequence, RequestDigest: input.RequestDigest})
	}
	f.query.Operations = append(f.query.Operations, nodewire.RecoveryOperationQuery{OperationID: "synthetic_never_admitted", Sequence: 1, RequestDigest: nodewire.RecoveryDigest([]byte("synthetic unknown operation"))})
	f.packet, err = nodewire.SealRecoveryRequest(node, wire, f.query)
	if err != nil {
		t.Fatal("real independent Node recovery proof")
	}
	return f
}

// Hash exact RPC ledgers and business tables without exposing their contents.
// The test only reads this independent SQL handle and never seeds authorization.
func nodeTLSRecoveryReadOnlyDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := sha256.New()
	for _, table := range []string{"node_control_rpc_sequences_v1", "node_control_rpc_inbox_v1", "machines", "goals", "workers", "intents", "commands"} {
		fmt.Fprintln(h, table)
		rows, err := db.Query(`SELECT * FROM ` + table + ` ORDER BY rowid`)
		if err != nil {
			t.Fatal("read immutable metadata/business snapshot")
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(columns))
			targets := make([]any, len(columns))
			for i := range values {
				targets[i] = &values[i]
			}
			if err := rows.Scan(targets...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if err := json.NewEncoder(h).Encode(values); err != nil {
				rows.Close()
				t.Fatal(err)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

type nodeTLSRecoveryHTTPResult struct {
	code   int
	body   []byte
	header http.Header
	err    error
}
type nodeTLSRecoveryEndpoint struct {
	client  *http.Client
	address string
}

func (e nodeTLSRecoveryEndpoint) post(packet []byte, bearer string) nodeTLSRecoveryHTTPResult {
	req, err := http.NewRequest(http.MethodPost, e.address+"/v2/node/control/rpc", bytes.NewReader(packet))
	if err != nil {
		return nodeTLSRecoveryHTTPResult{err: err}
	}
	req.Header.Set("Authorization", "CicadaNode "+bearer)
	response, err := e.client.Do(req)
	if err != nil {
		return nodeTLSRecoveryHTTPResult{err: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, nodewire.MaxRecoveryPacketBytes+1))
	if len(body) > nodewire.MaxRecoveryPacketBytes {
		err = errors.New("oversized recovery response")
	}
	return nodeTLSRecoveryHTTPResult{code: response.StatusCode, body: body, header: response.Header.Clone(), err: err}
}

func nodeTLSRecoveryServeNative(t *testing.T, f *nodeTLSRecoveryFixture, handler http.Handler, strict bool, hubCfg, nodeCfg nodetransport.Config) nodeTLSRecoveryEndpoint {
	t.Helper()
	listener, err := pqtls.Listen("tcp", "127.0.0.1:0", hubCfg.TLSConfig())
	if err != nil {
		t.Fatal("actual synthetic native Hub listener")
	}
	if strict {
		handler = WithNodePQTransport(handler, f.service, &hubCfg, true)
	}
	server := &http.Server{Handler: handler, ConnContext: pqtls.HTTPConnContext}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Error("native recovery listener exit")
			}
		case <-ctx.Done():
			t.Error("native recovery listener did not join")
		}
	})
	pq, err := pqtls.NewClient(nodeCfg.TLSConfig())
	if err != nil {
		t.Fatal("actual synthetic native Node client")
	}
	transport, err := pq.HTTPTransport(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	return nodeTLSRecoveryEndpoint{client: &http.Client{Transport: transport, Timeout: 10 * time.Second}, address: "https://" + listener.Addr().String()}
}

func TestNodeTLSRecoveryNativeReadOnlyAndExactProofs(t *testing.T) {
	if !nodeTLSRecoveryNativeRequired(t) {
		return
	}
	f := newNodeTLSRecoveryFixture(t)
	var calls atomic.Int32
	handler := NewFabricHandlerWithNodeTLSReaders(f.service, "", func(credential, node string, packet []byte) ([]byte, error) {
		return control.ReadNodeTLSCurrentPacket(f.persistence, f.hub, credential, node, packet)
	}, func(credential, node string, packet []byte) ([]byte, error) {
		calls.Add(1)
		return control.ReadNodeTLSRecoveryPacket(f.persistence, f.hub, credential, node, packet)
	})
	if handler.(*Handler).control != nil {
		t.Fatal("native Fabric-only query constructed Control business")
	}
	endpoint := nodeTLSRecoveryServeNative(t, f, handler, true, f.process.HubConfig, f.process.NodeConfig)
	before := nodeTLSRecoveryReadOnlyDigest(t, f.process.DBPath)
	var reply []byte
	t.Run("all-metadata-states-and-exact-read-retry", func(t *testing.T) {
		for attempt := 0; attempt < 2; attempt++ {
			result := endpoint.post(f.packet, f.process.NodeToken)
			if result.err != nil || result.code != http.StatusOK || result.header.Get("Cache-Control") != "no-store" {
				t.Fatal("actual native recovery read refused")
			}
			status, err := nodewire.OpenRecoveryResponse(f.node, f.wire, f.query, f.packet, result.body)
			if err != nil || status.AcceptedHighwater != 42 || len(status.Operations) != 4 {
				t.Fatal("native sealed recovery metadata mismatch")
			}
			for i, want := range []string{"COMPLETE", "PROCESSING", "UNCERTAIN", "NOT_RECORDED"} {
				if status.Operations[i].State != want || status.Operations[i].RecoveryOperationQuery != f.query.Operations[i] {
					t.Fatal("exact operation metadata mismatch")
				}
			}
			reply = result.body
		}
	})
	for _, kind := range []string{"nonce", "origin", "request-packet"} {
		t.Run("reply-bound-"+kind, func(t *testing.T) {
			q, packet := f.query, f.packet
			switch kind {
			case "nonce":
				q.Nonce = bytes.Repeat([]byte{0x71}, 32)
			case "origin":
				q.Origin = "https://other.synthetic.invalid"
			case "request-packet":
				packet = append(bytes.Clone(packet), ' ')
			}
			if _, err := nodewire.OpenRecoveryResponse(f.node, f.wire, q, packet, reply); err == nil {
				t.Fatal("old reply escaped exact recovery conversation")
			}
		})
	}
	for _, kind := range []string{"application-key", "key-epoch", "credential", "logical-origin"} {
		t.Run("reject-"+kind, func(t *testing.T) {
			node, binding, q := f.node, f.wire, f.query
			switch kind {
			case "application-key":
				var err error
				node, err = e2ee.NewIdentity()
				if err != nil {
					t.Fatal(err)
				}
				binding.NodeKey = node.Public()
			case "key-epoch":
				binding.NodeKeyEpoch++
			case "credential":
				q.CredentialDigest = fabric.HashSessionCredential("SYNTHETIC OTHER CREDENTIAL ONLY")
			case "logical-origin":
				q.Origin = "https://other.synthetic.invalid"
			}
			packet, err := nodewire.SealRecoveryRequest(node, binding, q)
			if err != nil {
				t.Fatal("seal explicit negative recovery packet")
			}
			result := endpoint.post(packet, f.process.NodeToken)
			if result.err != nil || result.code != http.StatusForbidden {
				t.Fatal("foreign recovery proof was accepted")
			}
		})
	}
	t.Run("wrong-bearer-before-provider", func(t *testing.T) {
		wrongToken, _, err := fabric.NewNodeCredential()
		if err != nil {
			t.Fatal(err)
		}
		before := calls.Load()
		result := endpoint.post(f.packet, wrongToken)
		if result.err != nil || result.code != http.StatusUnauthorized || calls.Load() != before {
			t.Fatal("wrong bearer reached recovery reader")
		}
	})
	t.Run("ordinary-business-remains-control-gated", func(t *testing.T) {
		p, err := nodewire.DecodePacket(f.packet)
		if err != nil {
			t.Fatal(err)
		}
		p.Route.Operation, p.Route.OperationID = "node.heartbeat", "synthetic_ordinary_no_dispatch"
		packet, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		before := calls.Load()
		result := endpoint.post(packet, f.process.NodeToken)
		if result.err != nil || result.code != http.StatusServiceUnavailable || calls.Load() != before {
			t.Fatal("ordinary RPC escaped Control gate")
		}
	})
	t.Run("plaintext-frontdoor-before-provider", func(t *testing.T) {
		front := httptest.NewServer(WithNodePQTransport(handler, f.service, &f.process.HubConfig, false))
		defer front.Close()
		before := calls.Load()
		result := (nodeTLSRecoveryEndpoint{client: front.Client(), address: front.URL}).post(f.packet, f.process.NodeToken)
		if result.err != nil || result.code != http.StatusForbidden || calls.Load() != before {
			t.Fatal("plaintext frontdoor reached TLS recovery reader")
		}
	})
	t.Run("native-without-current-policy", func(t *testing.T) {
		unwrapped := nodeTLSRecoveryServeNative(t, f, handler, false, f.process.HubConfig, f.process.NodeConfig)
		before := calls.Load()
		result := unwrapped.post(f.packet, f.process.NodeToken)
		if result.err != nil || result.code != http.StatusForbidden || calls.Load() != before {
			t.Fatal("native ConnContext replaced actual current policy")
		}
	})
	t.Run("native-with-nil-current-policy", func(t *testing.T) {
		nilPolicy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handler.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nodeTransportCheckKey{}, nodeTransportCheck(nil))))
		})
		endpoint := nodeTLSRecoveryServeNative(t, f, nilPolicy, true, f.process.HubConfig, f.process.NodeConfig)
		before := calls.Load()
		result := endpoint.post(f.packet, f.process.NodeToken)
		if result.err != nil || result.code != http.StatusForbidden || calls.Load() != before {
			t.Fatal("typed nil policy reached recovery reader")
		}
	})
	t.Run("wrong-hub-pin", func(t *testing.T) {
		cfg := f.process.NodeConfig
		cfg.Peers = append([]nodetransport.Approval(nil), cfg.Peers...)
		cfg.Peers[0].PinSHA256 = strings.Repeat("a", 64)
		wrong := nodeTLSRecoveryServeNative(t, f, handler, true, f.process.HubConfig, cfg)
		before := calls.Load()
		if result := wrong.post(f.packet, f.process.NodeToken); result.err == nil || calls.Load() != before {
			t.Fatal("wrong actual Hub TLS pin reached recovery reader")
		}
	})
	t.Run("wrong-certificate-epoch", func(t *testing.T) {
		cfg := f.process.HubConfig
		cfg.Peers = append([]nodetransport.Approval(nil), cfg.Peers...)
		cfg.Peers[0].Identity.TLSEpoch++
		wrong := nodeTLSRecoveryServeNative(t, f, handler, true, cfg, f.process.NodeConfig)
		before := calls.Load()
		// Native TLS verifies the unchanged certificate pin/SAN. Its approved
		// epoch is informational; the actual current Store Guard must reject
		// this configuration-only epoch change before provider dispatch.
		result := wrong.post(f.packet, f.process.NodeToken)
		if result.err != nil || result.code != http.StatusUnauthorized || calls.Load() != before {
			t.Fatal("configured Node TLS epoch mismatch bypassed current Guard")
		}
		if _, err := nodewire.OpenRecoveryResponse(f.node, f.wire, f.query, f.packet, result.body); err == nil {
			t.Fatal("configured epoch refusal exposed sealed recovery metadata")
		}
	})
	if nodeTLSRecoveryReadOnlyDigest(t, f.process.DBPath) != before {
		t.Fatal("recovery read or refusal mutated RPC counter/inbox or business state")
	}
}

func TestNodeTLSRecoveryNativeReadThenRevokeBeforeWrite(t *testing.T) {
	if !nodeTLSRecoveryNativeRequired(t) {
		return
	}
	for _, kind := range []string{"tls-grant", "owner-device"} {
		t.Run(kind, func(t *testing.T) {
			f := newNodeTLSRecoveryFixture(t)
			ready, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			var calls atomic.Int32
			handler := NewFabricHandlerWithNodeTLSReaders(f.service, "", nil, func(credential, node string, packet []byte) ([]byte, error) {
				calls.Add(1)
				reply, err := control.ReadNodeTLSRecoveryPacket(f.persistence, f.hub, credential, node, packet)
				if err != nil {
					return nil, err
				}
				close(ready)
				// Barrier is before returning to the production response writer.
				// The real metadata/authentication reader has already completed.
				select {
				case <-release:
				case <-time.After(15 * time.Second):
					return nil, errors.New("synthetic recovery read barrier expired")
				}
				return reply, nil
			})
			endpoint := nodeTLSRecoveryServeNative(t, f, handler, true, f.process.HubConfig, f.process.NodeConfig)
			defer unblock() // Failure cleanup releases an owned barrier before listener join.
			before := nodeTLSRecoveryReadOnlyDigest(t, f.process.DBPath)
			result := make(chan nodeTLSRecoveryHTTPResult, 1)
			go func() { result <- endpoint.post(f.packet, f.process.NodeToken) }()
			select {
			case <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("actual reader did not reach pre-write barrier")
			}
			if kind == "tls-grant" {
				if err := f.persistence.RevokeNodeTLSGrantLocal(f.process.RequestID, f.current.RowVersion); err != nil {
					t.Fatal(err)
				}
			} else {
				device, err := f.persistence.GetClientDevice(f.binding.OwnerID, f.binding.ClientDeviceID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := f.persistence.RevokeClientDevice(device.OwnerID, device.DeviceID, device.Version); err != nil {
					t.Fatal(err)
				}
			}
			unblock()
			select {
			case response := <-result:
				if response.err != nil || response.code != http.StatusForbidden || calls.Load() != 1 {
					t.Fatal("read-before-revoke emitted an authorized recovery response")
				}
				if _, err := nodewire.OpenRecoveryResponse(f.node, f.wire, f.query, f.packet, response.body); err == nil {
					t.Fatal("revoked pre-write response exposed sealed metadata")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("revoked recovery response did not finish")
			}
			if nodeTLSRecoveryReadOnlyDigest(t, f.process.DBPath) != before {
				t.Fatal("post-read refusal admitted work or changed recovery counters")
			}
			beforeCalls := calls.Load()
			after := endpoint.post(f.packet, f.process.NodeToken)
			if after.err != nil || after.code != http.StatusUnauthorized || calls.Load() != beforeCalls {
				t.Fatal("later request bypassed committed revocation")
			}
		})
	}
}
