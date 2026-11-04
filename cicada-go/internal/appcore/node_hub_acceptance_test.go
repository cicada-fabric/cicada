//go:build cicada_scoped_app_integration

package appcore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/nodelock"
)

// This prepares actual current NPT/Group/TLS actors using existing fixtures.
// Registry add/remove and App-facade actions must be attached only after their
// closed interfaces are reviewed. Helpers alone establish no product PASS.
// Native coordinates are synthetic; no provider or native Runtime is started.
type nodeHubAcceptanceFixture struct {
	t          *testing.T
	hubs       [2]*nodeHubAcceptanceHub
	writerRoot string
}

type nodeHubAcceptanceHub struct {
	web     *scopedAppHTTPFixture
	traffic *appUnbindTraffic
	pins    nodeHubAcceptancePins
}

// Public pins and a credential digest only; never serialize private material.
type nodeHubAcceptancePins struct {
	hub                        wire.HubIdentity
	owner, device, node        e2ee.PublicIdentity
	deviceID, nodeID           string
	descriptor, credentialHash string
}

func newNodeHubAcceptanceFixture(t *testing.T) *nodeHubAcceptanceFixture {
	t.Helper()
	f := &nodeHubAcceptanceFixture{t: t, writerRoot: t.TempDir()}
	for i := range f.hubs {
		f.hubs[i] = &nodeHubAcceptanceHub{web: newScopedAppHTTPFixture(t)}
	}
	a, b := f.hubs[0].web, f.hubs[1].web
	if a.hub.HubID == b.hub.HubID || a.origin == b.origin || a.dial == b.dial || a.root == b.root ||
		reflect.DeepEqual(a.hub.Public, b.hub.Public) || reflect.DeepEqual(a.c.device.Public(), b.c.device.Public()) ||
		reflect.DeepEqual(a.c.owner.Public(), b.c.owner.Public()) {
		t.Fatal("independent synthetic Hub/account/Owner/device scopes collided")
	}
	return f
}

// Both helpers deliberately use the same synthetic Node/native-session/name
// labels across independent Hubs. Keys, approvals, Endpoint credentials and
// generated Network/Group IDs remain independently authenticated. Exact raw-ID
// selector collisions belong to the forthcoming facade boundary, not SQL edits
// to an already Owner-signed policy.
func (f *nodeHubAcceptanceFixture) pairCurrentHub(index int) *nodeHubAcceptanceHub {
	f.t.Helper()
	if index < 0 || index >= len(f.hubs) {
		f.t.Fatal("synthetic Hub index out of range")
	}
	h := f.hubs[index]
	if h.traffic != nil {
		f.t.Fatal("synthetic Hub was already paired")
	}
	h.traffic = newAppUnbindTraffic(f.t, h.web)
	h.pins = h.currentPins()
	if other := f.hubs[1-index]; other.traffic != nil {
		if h.traffic.node.binding.NodeID != other.traffic.node.binding.NodeID ||
			h.traffic.sender.member.NativeSessionID != other.traffic.sender.member.NativeSessionID ||
			reflect.DeepEqual(h.pins.node, other.pins.node) || h.pins.credentialHash == other.pins.credentialHash ||
			h.traffic.domain.Policy.NetworkID == other.traffic.domain.Policy.NetworkID || h.traffic.domain.Policy.GroupID == other.traffic.domain.Policy.GroupID {
			f.t.Fatal("synthetic same-Node labels lost their independent Hub crypto scopes")
		}
	}
	return h
}

func (h *nodeHubAcceptanceHub) currentPins() nodeHubAcceptancePins {
	h.web.t.Helper()
	if h.traffic == nil || h.traffic.node.binding == nil || h.web.c.owner == nil || h.web.c.device == nil {
		h.web.t.Fatal("current synthetic Hub is not paired")
	}
	return nodeHubAcceptancePins{hub: h.web.hub, owner: h.web.c.owner.Public(), device: h.web.c.device.Public(), node: h.traffic.node.key.Public(),
		deviceID: h.web.c.state.DeviceID, nodeID: h.traffic.node.binding.NodeID,
		descriptor: wire.NodePairTrustScopedDescriptorDigest(h.web.descriptorText), credentialHash: digestNodeHubAcceptance([]byte(h.traffic.node.token))}
}

func digestNodeHubAcceptance(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func (h *nodeHubAcceptanceHub) assertPinsAndFreshTraffic(label string) {
	h.web.t.Helper()
	if !reflect.DeepEqual(h.pins, h.currentPins()) {
		h.web.t.Fatal("another Hub operation changed existing public pins or Node credential")
	}
	if !h.traffic.nodeCurrent(http.StatusOK) || !h.traffic.heartbeat(http.StatusNoContent) {
		h.web.t.Fatal("current synthetic Node binding/heartbeat failed")
	}
	h.traffic.sendAndOpen("SYNTHETIC Node Hub acceptance " + label)
}

func (h *nodeHubAcceptanceHub) rejectForeignCredential(other *nodeHubAcceptanceHub) {
	t := h.web.t
	t.Helper()
	if h.traffic == nil || other.traffic == nil || h.pins.credentialHash == other.pins.credentialHash {
		t.Fatal("foreign-credential negative control lacks independent NPT actors")
	}
	nodeID := h.traffic.node.binding.NodeID
	before, err := h.web.db.GetMachine(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	h.traffic.http(http.MethodPost, "/v2/relay/nodes/"+url.PathEscape(nodeID)+"/heartbeat", "CicadaNode "+other.traffic.node.token, "", struct{}{}, http.StatusUnauthorized)
	after, err := h.web.db.GetMachine(nodeID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("foreign Hub credential changed the original Node projection", err)
	}
}

type nodeHubAcceptanceUnknown struct {
	packet, saved []byte
	version       uint64
	pins          nodeHubAcceptancePins
}

// Retain a genuine current-Group read whose committed response was lost. The
// pending bytes/CAS can be checked around later B operations without injecting
// a success state or replacing A's original with a new request.
func (h *nodeHubAcceptanceHub) parkUnknownGroupRead() nodeHubAcceptanceUnknown {
	t, web := h.web.t, h.web
	t.Helper()
	path := wire.LocalDomainHTTPPath(wire.OperationLocalDomainStatus)
	web.dropOperation, web.dropHTTPStatus = path, http.StatusForbidden
	if err := web.c.Dispatch(context.Background(), Action{Kind: ActionRefreshLocalCollaboration}); err == nil || !web.c.hasLocalDomainPending() {
		t.Fatal("lost current Group response did not preserve an uncertain original")
	}
	original := web.c.localDomain.original
	if original == nil || original.Applied || len(original.Packet) == 0 || !bytes.Equal(original.Packet, web.droppedPacket) {
		t.Fatal("uncertain Group original differs from the actual sent packet")
	}
	raw, version, found, err := web.c.vault.LoadState(localDomainNamespaces[localDomainOriginal])
	if err != nil || !found || version == 0 {
		t.Fatal("uncertain original was not durable before transmission", err)
	}
	snapshot := nodeHubAcceptanceUnknown{packet: bytes.Clone(original.Packet), saved: raw, version: version, pins: h.currentPins()}
	t.Cleanup(func() { clear(snapshot.packet); clear(snapshot.saved) })
	return snapshot
}

func (h *nodeHubAcceptanceHub) assertUnknownRetained(snapshot nodeHubAcceptanceUnknown) {
	t, web := h.web.t, h.web
	t.Helper()
	raw, version, found, err := web.c.vault.LoadState(localDomainNamespaces[localDomainOriginal])
	defer clear(raw)
	if err != nil || !found || version != snapshot.version || !bytes.Equal(raw, snapshot.saved) ||
		!web.c.hasLocalDomainPending() || web.c.localDomain.original == nil || !bytes.Equal(web.c.localDomain.original.Packet, snapshot.packet) ||
		!reflect.DeepEqual(snapshot.pins, h.currentPins()) {
		t.Fatal("another Hub changed the unknown original, CAS version or original key scope", err)
	}
}

func (h *nodeHubAcceptanceHub) offline() {
	h.web.client.CloseIdleConnections()
	h.web.http.Close()
}

func (h *nodeHubAcceptanceHub) reopenHub() {
	appUnbindRestartHub(h.web)
}

// Connect this assertion to the reviewed facade's ACTUAL shared WriterRoot.
// It exercises the real lock/epoch files; it is not native Runtime execution.
func (f *nodeHubAcceptanceFixture) assertSingleWriter(writerRoot, account, nativeID string) {
	t := f.t
	t.Helper()
	if filepath.Clean(writerRoot) != filepath.Clean(f.writerRoot) {
		t.Fatal("facade did not use the fixture's shared synthetic WriterRoot")
	}
	first, err := nodelock.AcquireNativeWriter(context.Background(), writerRoot, account, "codex", nativeID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if second, err := nodelock.AcquireNativeWriter(ctx, writerRoot, account, "codex", nativeID); !errors.Is(err, context.DeadlineExceeded) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("two Hub contexts acquired the same physical native writer", err)
	}
	previous := first.Epoch
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := nodelock.AcquireNativeWriter(context.Background(), writerRoot, account, "codex", nativeID)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if second.Epoch != previous+1 || !errors.Is(first.CheckCurrent(), nodelock.ErrNativeWriterStale) {
		t.Fatal("Hub takeover reset the writer epoch or accepted the retired writer")
	}
}
