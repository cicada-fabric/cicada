package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/clientcontract"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/store"
)

const maxFixturePacket = 256 * 1024

// linkFaultProxy transports opaque packets only. It has no device/Owner private
// key, cannot inspect a grant result, and never supplies approval or authority.
type linkFaultProxy struct {
	mu                                                 sync.Mutex
	dbPath, origin, ownerID, deviceID, operation, mode string
	hubID                                              string
	client                                             *http.Client
	events                                             *json.Encoder
	used                                               bool
	original                                           []byte
}

func loopbackOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
		return "", errors.New("upstream must be a numeric loopback HTTP origin")
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return "", errors.New("upstream must be a numeric loopback HTTP origin with port")
	}
	return strings.TrimSuffix(raw, "/"), nil
}

func dedicatedLinkOperation(operation string) bool {
	if !clientcontract.Allows(clientcontract.RoleExternal, operation) || clientcontract.CatalogDefinition().RPCRoute != "/v2/client/rpc" {
		return false
	}
	switch operation {
	case "link.key_manifest", "link.key_grants", "link.key_grant", "link.review_policy_preview", "link.review_policy_grant":
		return true
	}
	return false
}

func fixtureReadOperation(operation string) bool {
	if !clientcontract.Allows(clientcontract.RoleExternal, operation) {
		return false
	}
	switch operation {
	case "session.capabilities", "status.snapshot", "link.list", "link.key_manifest", "link.key_grants", "link.review_policy_preview", "link.review_policy_status":
		return true
	}
	return false
}

func newLinkFaultProxy(dbPath, origin, ownerID, deviceID, operation, mode string, output io.Writer) (*linkFaultProxy, error) {
	if !dedicatedLinkOperation(operation) || ownerID == "" || deviceID == "" {
		return nil, errors.New("select one dedicated Link operation and an exact enrolled owner/device")
	}
	if mode != "response-loss" && mode != "processing" && mode != "uncertain" && mode != "legacy" {
		return nil, errors.New("invalid Link fault mode")
	}
	if err := requireDisposableDatabase(dbPath); err != nil {
		return nil, err
	}
	origin, err := loopbackOrigin(origin)
	if err != nil {
		return nil, err
	}
	p := &linkFaultProxy{dbPath: dbPath, origin: origin, ownerID: ownerID, deviceID: deviceID, operation: operation, mode: mode,
		client: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, events: json.NewEncoder(output)}
	db, err := store.New(dbPath)
	if err != nil {
		return nil, err
	}
	p.hubID, err = db.GetClientHubID()
	closeErr := db.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	status, body, err := p.forward(context.Background(), http.MethodGet, "/v2/client/identity", nil)
	var identity struct {
		HubID string `json:"hub_id"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(body, &identity) != nil || identity.HubID != p.hubID {
		return nil, errors.New("upstream identity does not match disposable database")
	}
	status, body, err = p.forward(context.Background(), http.MethodGet, "/v2/client/capabilities", nil)
	var capabilities struct {
		Revision      string `json:"contract_revision"`
		Catalog       string `json:"catalog_sha256"`
		ExternalLinks *bool  `json:"external_thread_links"`
	}
	if err != nil || status != http.StatusOK || json.Unmarshal(body, &capabilities) != nil ||
		capabilities.Revision != clientcontract.ContractRevision || capabilities.Catalog != clientcontract.CatalogSHA256() || capabilities.ExternalLinks == nil || *capabilities.ExternalLinks {
		return nil, errors.New("upstream catalog mismatch or ordinary external links enabled")
	}
	return p, nil
}

func packetDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func requestCoordinates(packet clientwire.Packet, body []byte) store.AcceptClientRequestInput {
	r := packet.Route
	return store.AcceptClientRequestInput{OwnerID: r.OwnerID, DeviceID: r.DeviceID, SessionEpoch: r.SessionEpoch,
		Sequence: r.Sequence, OperationID: r.OperationID, CiphertextDigest: packetDigest(body)}
}

func (p *linkFaultProxy) forward(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	r, err := http.NewRequestWithContext(ctx, method, p.origin+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(r)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxFixturePacket+1))
	if err != nil || len(data) > maxFixturePacket {
		return 0, nil, errors.New("invalid upstream response size")
	}
	return response.StatusCode, data, nil
}

func (p *linkFaultProxy) event(event string, fields map[string]any) error {
	if fields == nil {
		fields = make(map[string]any)
	}
	fields["event"], fields["mode"], fields["operation"] = event, p.mode, p.operation
	return p.events.Encode(fields)
}

// prepareFault deliberately separates a completed real handler response from
// synthetic outer-ledger interruption. A HTTP 200 alone says nothing about the
// encrypted business result; the Client must decrypt and independently reconcile.
func (p *linkFaultProxy) prepareFault(ctx context.Context, packet clientwire.Packet, body []byte) (map[string]any, error) {
	if err := requireDisposableDatabase(p.dbPath); err != nil {
		return nil, err
	}
	db, err := store.New(p.dbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	if _, err := db.GetClientRequestByOperationID(packet.Route.OwnerID, packet.Route.DeviceID, packet.Route.OperationID); !errors.Is(err, store.ErrClientRequestNotFound) {
		return nil, errors.New("fault requires a fresh operation")
	}
	fields := map[string]any{"request_sha256": packetDigest(body), "request_sequence": packet.Route.Sequence,
		"business_outcome": "UNKNOWN", "handler_executed": false, "scope": "OUTER_RPC_LEDGER_ONLY"}
	if p.mode == "response-loss" {
		status, response, err := p.forward(ctx, http.MethodPost, "/v2/client/rpc", body)
		if err != nil || status != http.StatusOK {
			return nil, errors.New("real Hub RPC did not return HTTP 200")
		}
		state, err := db.LookupClientRequestRecovery(requestCoordinates(packet, body))
		if err != nil || state.Request.Status != store.ClientRequestCompleted || !bytes.Equal(state.Request.ResponsePacket, response) {
			return nil, errors.New("real Hub response does not match durable COMPLETED packet")
		}
		fields["response_sha256"], fields["handler_executed"], fields["scope"] = packetDigest(response), true, "REAL_HANDLER_COMPLETED_TRANSPORT"
		fields["request_status"] = store.ClientRequestCompleted
		fields["reserved_response_sequence"] = state.ReservedResponseSequence
		return fields, nil
	}
	// Authenticating through the real Hub avoids accepting forged envelopes via
	// the local test producer. A fresh authenticated packet has no recovery row.
	status, response, err := p.forward(ctx, http.MethodPost, "/v2/client/rpc/recover", body)
	var rejected struct {
		Code string `json:"code"`
	}
	if err != nil || status != http.StatusConflict || json.Unmarshal(response, &rejected) != nil || rejected.Code != "RECOVERY_REJECTED" {
		return nil, errors.New("fresh packet was not authenticated by Hub recovery ingress")
	}
	if err := run([]string{"--db", p.dbPath, "--mode", p.mode}, bytes.NewReader(body)); err != nil {
		return nil, err
	}
	state, err := db.LookupClientRequestRecovery(requestCoordinates(packet, body))
	if err != nil {
		return nil, err
	}
	fields["request_status"], fields["reserved_response_sequence"] = state.Request.Status, state.ReservedResponseSequence
	fields["restart_required"] = p.mode == "uncertain"
	return fields, nil
}

func (p *linkFaultProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Small dedicated fixture: serialize ingress, including the fault transition,
	// so retries cannot run while durable state/FAULT_READY is being established.
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.URL.RawQuery != "" || r.URL.RawPath != "" {
		http.Error(w, "fixture path denied", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodGet && (r.URL.Path == "/v2/client/identity" || r.URL.Path == "/v2/client/capabilities" || r.URL.Path == "/healthz") {
		p.relay(w, r, nil)
		return
	}
	if r.Method != http.MethodPost || (r.URL.Path != "/v2/client/rpc" && r.URL.Path != "/v2/client/rpc/recover") {
		http.Error(w, "fixture path denied", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFixturePacket+1))
	var packet clientwire.Packet
	if err != nil || len(body) == 0 || len(body) > maxFixturePacket || json.Unmarshal(body, &packet) != nil ||
		packet.Route.Version != clientwire.Version || packet.Route.Direction != clientwire.DirectionRequest || len(packet.Envelope) == 0 || packet.Route.HubID != p.hubID {
		http.Error(w, "invalid fixture packet", http.StatusBadRequest)
		return
	}
	if packet.Route.OwnerID != p.ownerID || packet.Route.DeviceID != p.deviceID {
		http.Error(w, "fixture device denied", http.StatusForbidden)
		return
	}
	selected := packet.Route.Operation == p.operation
	if r.URL.Path == "/v2/client/rpc/recover" {
		if !p.used || len(p.original) == 0 || !bytes.Equal(p.original, body) {
			http.Error(w, "fixture requires the exact original packet", http.StatusConflict)
			return
		}
		p.relay(w, r, body)
		return
	}
	if selected && !p.used {
		p.used = true // A failed/partial attempt remains fenced; never auto retry.
		p.original = append([]byte(nil), body...)
		fields, err := p.prepareFault(r.Context(), packet, body)
		if err != nil {
			if eventErr := p.event("FAULT_FAILED", map[string]any{"request_sha256": packetDigest(body), "business_outcome": "UNKNOWN"}); eventErr != nil {
				http.Error(w, "fixture evidence write failed", http.StatusInternalServerError)
				return
			}
			http.Error(w, "fault preparation failed; preserve original pending", http.StatusBadGateway)
			return
		}
		if err := p.event("FAULT_READY", fields); err != nil {
			http.Error(w, "fixture evidence write failed", http.StatusInternalServerError)
			return
		}
		// Closing without response is the actual response-loss entrypoint. No
		// synthetic error/HTTP success is substituted for the lost ciphertext.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "fixture requires HTTP/1 connection", http.StatusInternalServerError)
			return
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		connection.Close()
		return
	}
	if selected || !fixtureReadOperation(packet.Route.Operation) {
		http.Error(w, "fixture write fence; use original recovery", http.StatusConflict)
		return
	}
	// Recovery of UNCERTAIN requires this request to remain the latest on its
	// device. Fresh reconciliation uses another session directly on the Hub.
	if p.used {
		http.Error(w, "fixture new packet denied after fault", http.StatusConflict)
		return
	}
	p.relay(w, r, body)
}

func (p *linkFaultProxy) relay(w http.ResponseWriter, r *http.Request, body []byte) {
	status, data, err := p.forward(r.Context(), r.Method, r.URL.Path, body)
	if err != nil {
		http.Error(w, "fixture upstream unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(data); err != nil {
		return
	}
}

func serveLink(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("serve-link", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	db := flags.String("db", "", "marked disposable Hub database")
	origin := flags.String("hub-url", "", "fixed numeric loopback HTTP Hub origin")
	listen := flags.String("listen", "127.0.0.1:0", "numeric loopback listen address")
	owner := flags.String("owner-id", "", "exact enrolled synthetic owner")
	device := flags.String("device-id", "", "exact enrolled test device")
	operation := flags.String("operation", "", "one of five dedicated Link operations")
	mode := flags.String("mode", "", "response-loss, processing, uncertain, legacy")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("invalid serve-link arguments")
	}
	if _, err := loopbackOrigin("http://" + *listen); err != nil && !strings.HasSuffix(*listen, ":0") {
		return errors.New("listen must be numeric loopback")
	}
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("listen must be numeric loopback")
	}
	p, err := newLinkFaultProxy(*db, *origin, *owner, *device, *operation, *mode, output)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer p.client.CloseIdleConnections()
	server := &http.Server{Handler: p, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	if err := p.event("READY", map[string]any{"listen": listener.Addr().String(), "contract_revision": clientcontract.ContractRevision, "catalog_sha256": clientcontract.CatalogSHA256(), "wire_version": clientwire.Version}); err != nil {
		server.Close()
		return err
	}
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			server.Close()
			return fmt.Errorf("proxy shutdown: %w", err)
		}
	}
	return p.event("CLEANUP", map[string]any{"scope": "PROXY_ONLY", "database_deleted": false})
}
