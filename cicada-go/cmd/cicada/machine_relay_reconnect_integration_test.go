package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

// TestMachineRelayReconnectClaimsDurableOfflineMessage exercises the production
// Node SSE reconnect loop and claim/inbox path against a real TLS HTTP Hub
// handler backed by SQLite. The Codex queue executable is intentionally fake;
// this verifies transport, persistence, and one-time queue acceptance, not a
// real native Runtime or model consumption. It exercises the legacy PLAINTEXT
// Ask/claim route and does not validate sealed or Hub-blind E2EE delivery.
func TestMachineRelayReconnectClaimsDurableOfflineMessage(t *testing.T) {
	root := t.TempDir()
	storePath := filepath.Join(root, "hub.sqlite3")
	persistence, err := store.New(storePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = persistence.Close() })

	owner, err := persistence.CreatePrincipal(store.Principal{
		ID: "reconnect-owner", Kind: store.PrincipalKindHuman, OwnerID: "reconnect-owner",
		TrustDomainID: "reconnect-domain", Name: "synthetic reconnect owner", Status: store.PrincipalStatusActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	group, err := persistence.CreateGroup(store.Group{
		Name: "synthetic reconnect group", OwnerPrincipalID: owner.ID,
		TrustDomainID: owner.TrustDomainID, State: store.GroupStateActive,
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := fabric.NewService(persistence, owner.ID, owner.TrustDomainID)
	if err != nil {
		t.Fatal(err)
	}
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	registeredOwnerKey, err := persistence.RegisterOwnerApprovalKeyLocal(owner.ID, ownerKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	ownerDevice, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := "synthetic-reconnect-owner-device"
	grant, err := ownerKey.SignOwnerDeviceGrant(owner.ID, deviceID, ownerDevice.Public(), hubID,
		e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{
		OwnerID: owner.ID, OwnerKeyID: registeredOwnerKey.KeyID, DeviceID: deviceID,
		DevicePublic: ownerDevice.Public(), OwnerDeviceGrant: grant,
	}); err != nil {
		t.Fatal(err)
	}
	nodeToken, nodeCredentialDigest, err := fabric.NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	codeBytes := sha256.Sum256([]byte("synthetic reconnect device code"))
	codeDigest := hex.EncodeToString(codeBytes[:])
	if _, err := persistence.CreatePendingNodeDeviceBinding("node-reconnect", "synthetic reconnect Node",
		nodeCredentialDigest, codeDigest, time.Now().Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := persistence.ConfirmPendingNodeDeviceBinding(owner.ID, deviceID, codeDigest); err != nil {
		t.Fatal(err)
	}
	join := func(name, nodeID string) (*fabric.JoinResult, fabric.Actor) {
		t.Helper()
		joined, joinErr := service.Join(fabric.JoinInput{
			GroupID: group.ID, PrincipalName: name, EndpointName: name, Harness: "codex",
			NativeSessionID: "synthetic-native-" + name, NodeID: nodeID,
		})
		if joinErr != nil {
			t.Fatal(joinErr)
		}
		actor, authErr := service.Authenticate(joined.SessionToken)
		if authErr != nil {
			t.Fatal(authErr)
		}
		return joined, actor
	}
	_, sender := join("synthetic-sender", "node-sender")
	receiver, _ := join("synthetic-receiver", "node-reconnect")
	inbox, err := nodeinbox.Open(machineNodeInboxPath(root, "node-reconnect"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inbox.Close() })

	queueCountPath := filepath.Join(root, "fake-codex-queue-count")
	codexPath := filepath.Join(root, "fake-codex")
	codexScript := "#!/bin/sh\n[ \"$1\" = queue ] || exit 21\nprintf 'queued\\n' >> \"" + queueCountPath + "\"\n"
	if err := os.WriteFile(codexPath, []byte(codexScript), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CICADA_NODE_TOKEN", nodeToken)
	t.Setenv("CICADA_NODE_TOKEN_FILE", "")
	t.Setenv("CICADA_CODEX_BIN", codexPath)
	t.Setenv("CICADA_API_TOKEN", "")

	hubHandler := server.NewFabricHandler(service, "synthetic-management-token")
	type eventConnection struct {
		RemoteAddr string
	}
	arrivals := make(chan eventConnection, 8)
	departures := make(chan struct{}, 8)
	reconnectGate := make(chan struct{})
	var eventRequestCount atomic.Int32
	wrappedHandler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/v2/relay/nodes/node-reconnect/events" {
			requestNumber := eventRequestCount.Add(1)
			select {
			case arrivals <- eventConnection{RemoteAddr: request.RemoteAddr}:
			default:
			}
			defer func() {
				select {
				case departures <- struct{}{}:
				default:
				}
			}()
			if requestNumber > 1 {
				select {
				case <-reconnectGate:
				case <-request.Context().Done():
					return
				}
			}
		}
		hubHandler.ServeHTTP(response, request)
	})
	hub := httptest.NewTLSServer(wrappedHandler)
	t.Cleanup(hub.Close)
	roots := x509.NewCertPool()
	roots.AddCert(hub.Certificate())
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	originalTransport := http.DefaultTransport
	http.DefaultTransport = transport
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		http.DefaultTransport = originalTransport
	})

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	wake := make(chan struct{}, 4)
	revoked := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMachineRelayEventStream(ctx, hub.URL, "node-reconnect", wake, revoked)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Node SSE reconnect loop did not stop after cancellation")
		}
	})

	awaitSignal := func(label string, channel <-chan struct{}) {
		t.Helper()
		select {
		case <-channel:
		case err := <-revoked:
			t.Fatalf("Node SSE authorization was revoked while waiting for %s: %v", label, err)
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", label)
		}
	}
	var firstConnection eventConnection
	select {
	case firstConnection = <-arrivals:
	case err := <-revoked:
		t.Fatalf("Node SSE authorization was revoked on initial connect: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for initial live TLS SSE connection")
	}
	awaitSignal("initial ready wake", wake)
	select {
	case <-departures:
		t.Fatal("SSE stream ended immediately after ready instead of remaining live")
	case <-time.After(150 * time.Millisecond):
	}

	// Force-close the real TCP/TLS stream. The next request must be initiated by
	// the Node loop; the test Hub has no Node address or callback route.
	hub.CloseClientConnections()
	awaitSignal("SSE disconnect", departures)

	accepted, err := service.Ask(sender, fabric.AskInput{
		Target: receiver.Endpoint.ID, Question: "synthetic message accepted while the Node stream is down",
		IdempotencyKey: "synthetic-offline-reconnect-ask",
	})
	if err != nil {
		t.Fatalf("durably accept message during stream outage: %v", err)
	}
	persisted, err := persistence.GetRelayFabricRequest(accepted.RequestID)
	if err != nil || persisted == nil || persisted.RequestID != accepted.RequestID ||
		persisted.State != store.FabricRequestOpen {
		t.Fatalf("offline accepted message was not present in the Hub Store: request=%#v err=%v", persisted, err)
	}
	persistedMessage, err := persistence.GetRelayMessage(persisted.MessageID)
	if err != nil || persistedMessage == nil || persistedMessage.Message.Body != "synthetic message accepted while the Node stream is down" {
		t.Fatalf("offline accepted payload was not present in the Hub Store: message=%#v err=%v", persistedMessage, err)
	}

	var reconnected eventConnection
	select {
	case reconnected = <-arrivals:
	case err := <-revoked:
		t.Fatalf("Node SSE authorization was revoked during reconnect: %v", err)
	case <-ctx.Done():
		t.Fatal("timed out waiting for Node-initiated SSE reconnection")
	}
	if reconnected.RemoteAddr == firstConnection.RemoteAddr {
		t.Fatalf("SSE reconnect reused the closed TCP peer address %q", reconnected.RemoteAddr)
	}
	// The test handler holds this new request before subscribing to Hub events.
	// While that reconnect is gated, the accepted message must still be durable
	// and the Node queue must remain untouched.
	if _, err := os.Stat(queueCountPath); !os.IsNotExist(err) {
		t.Fatalf("offline message reached fake Codex before the reconnect ready event: stat err=%v", err)
	}
	close(reconnectGate)
	awaitSignal("ready reconciliation wake after reconnect", wake)
	if err := processMachineFabricDeliveriesV2(ctx, hub.URL, "node-reconnect", inbox, root); err != nil {
		t.Fatalf("claim and queue offline message after reconnect: %v", err)
	}
	queued, err := os.ReadFile(queueCountPath)
	if err != nil || string(queued) != "queued\n" {
		t.Fatalf("message was not queued exactly once after reconnect: queue log=%q err=%v", queued, err)
	}

	// An idempotent sender retry still raises a wake, but it must not create a
	// second logical delivery or execute a second native queue operation.
	retry, err := service.Ask(sender, fabric.AskInput{
		Target: receiver.Endpoint.ID, Question: "synthetic message accepted while the Node stream is down",
		IdempotencyKey: "synthetic-offline-reconnect-ask",
	})
	if err != nil || retry.RequestID != accepted.RequestID {
		t.Fatalf("same-key Ask retry changed durable request identity: first=%#v retry=%#v err=%v", accepted, retry, err)
	}
	awaitSignal("duplicate idempotent wake", wake)
	if err := processMachineFabricDeliveriesV2(ctx, hub.URL, "node-reconnect", inbox, root); err != nil {
		t.Fatalf("process duplicate wake: %v", err)
	}
	queued, err = os.ReadFile(queueCountPath)
	if err != nil || string(queued) != "queued\n" {
		t.Fatalf("duplicate wake consumed the message twice: queue log=%q err=%v", queued, err)
	}

	select {
	case <-done:
		t.Fatal("Node SSE stream ended before the test cancelled it")
	default:
	}
}
