package main

// Fault controls and independent synthetic trust fixtures live only in the test
// binary. The production command cannot generate a current-source trust pin.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

type hubForwardSynthetic struct {
	Binding        clientwire.Binding  `json:"binding"`
	HubPublic      e2ee.PublicIdentity `json:"hub_public"`
	DevicePrivate  []byte              `json:"device_private"`
	RevokedBinding clientwire.Binding  `json:"revoked_binding"`
	RevokedPrivate []byte              `json:"revoked_private"`
	UnknownBinding clientwire.Binding  `json:"unknown_binding"`
	UnknownPrivate []byte              `json:"unknown_private"`
	UnknownPacket  []byte              `json:"unknown_packet"`
}

func hubForwardConfig(state string) control.Config {
	return control.Config{StateDir: state, WorkspaceRoot: filepath.Join(filepath.Dir(state), "synthetic-workspace"), APIToken: "synthetic-hub-forward-only"}
}
func hubForwardControl(t *testing.T, state string) *control.Control {
	t.Helper()
	c, err := control.New(hubForwardConfig(state))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := c.Shutdown(ctx); err != nil {
			t.Error(err)
		}
	})
	return c
}
func hubForwardPrivateJSON(t *testing.T, path string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func hubForwardSyntheticRead(t *testing.T, root string) hubForwardSynthetic {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, "synthetic-client.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture hubForwardSynthetic
	if err = json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}
func hubForwardPacket(t *testing.T, fixture hubForwardSynthetic, seq uint64, opID string, revoked bool) []byte {
	t.Helper()
	binding, private := fixture.Binding, fixture.DevicePrivate
	if revoked {
		binding, private = fixture.RevokedBinding, fixture.RevokedPrivate
	}
	key, err := e2ee.UnmarshalIdentity(private)
	if err != nil {
		t.Fatal(err)
	}
	route := clientwire.Route{Version: clientwire.Version, Direction: clientwire.DirectionRequest, HubID: binding.HubID, OwnerID: binding.OwnerID, DeviceID: binding.DeviceID, SessionEpoch: binding.SessionEpoch, Sequence: seq, OperationID: opID, Operation: "session.capabilities", SenderKeyID: key.Public().ID, SenderKeyVersion: binding.DeviceKeyVersion, ReceiverKeyID: fixture.HubPublic.ID, ReceiverKeyVersion: binding.HubKeyVersion}
	packet, err := clientwire.SealRequest(key, fixture.HubPublic, binding, route, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	return packet
}
func hubForwardPost(t *testing.T, origin, path string, packet []byte, want int) []byte {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Post(origin+path, "application/json", bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 300000))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != want {
		t.Fatalf("synthetic metadata HTTP status=%d want=%d (payload withheld)", response.StatusCode, want)
	}
	return data
}
func hubForwardInit(t *testing.T, root, source string) {
	t.Helper()
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(hubForwardConfig(source).WorkspaceRoot, 0700); err != nil {
		t.Fatal(err)
	}
	c := hubForwardControl(t, source)
	s, err := store.New(filepath.Join(source, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	owner := c.Identity().ID
	ownerKey, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterOwnerApprovalKeyLocal(owner, ownerKey.Public()); err != nil {
		t.Fatal(err)
	}
	hubID, err := s.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	fixture := hubForwardSynthetic{HubPublic: c.ClientControlPublicIdentity()}
	for i, name := range []string{"synthetic-active-device", "synthetic-revoked-device", "synthetic-unknown-device"} {
		key, err := e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		grant, err := ownerKey.SignOwnerDeviceGrant(owner, name, key.Public(), hubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		device, err := s.RegisterClientDeviceFromOwnerGrant(store.RegisterClientDeviceInput{OwnerID: owner, OwnerKeyID: ownerKey.Public().ID, DeviceID: name, DevicePublic: key.Public(), OwnerDeviceGrant: grant})
		if err != nil {
			t.Fatal(err)
		}
		binding := clientwire.Binding{HubID: hubID, OwnerID: owner, DeviceID: name, SessionEpoch: device.SessionEpoch, HubKeyVersion: 1, DeviceKeyVersion: device.KeyVersion}
		private, err := key.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			fixture.Binding, fixture.DevicePrivate = binding, private
		} else if i == 1 {
			fixture.RevokedBinding, fixture.RevokedPrivate = binding, private
		} else {
			fixture.UnknownBinding, fixture.UnknownPrivate = binding, private
		}
	}
	tcp := httptest.NewServer(server.NewHandler(c))
	defer tcp.Close()
	hubForwardPost(t, tcp.URL, "/v2/client/rpc", hubForwardPacket(t, fixture, 1, "synthetic-metadata-before-B", false), 200)
	// A durable UNKNOWN exists in B as well as C. Reservation burns the response
	// sequence; the forward path must preserve both, without business execution.
	hubForwardPost(t, tcp.URL, "/v2/client/rpc", hubForwardPacket(t, fixture, 2, "synthetic-metadata-before-B-next", false), 200)
	unknownFixture := fixture
	unknownFixture.Binding, unknownFixture.DevicePrivate = fixture.UnknownBinding, fixture.UnknownPrivate
	hubForwardPost(t, tcp.URL, "/v2/client/rpc", hubForwardPacket(t, unknownFixture, 1, "synthetic-unknown-device-metadata", false), 200)
	fixture.UnknownPacket = hubForwardPacket(t, unknownFixture, 2, "synthetic-unknown-original", false)
	digest := sha256.Sum256(fixture.UnknownPacket)
	input := store.AcceptClientRequestInput{OwnerID: owner, DeviceID: fixture.UnknownBinding.DeviceID, SessionEpoch: fixture.UnknownBinding.SessionEpoch, Sequence: 2, OperationID: "synthetic-unknown-original", CiphertextDigest: hex.EncodeToString(digest[:])}
	if _, err = s.AcceptClientRequest(input); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReserveClientRequestResponseSequence(input); err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpdateClientRequestStatus(owner, fixture.UnknownBinding.DeviceID, input.OperationID, store.ClientRequestUncertain); err != nil {
		t.Fatal(err)
	}
	hubForwardPrivateJSON(t, filepath.Join(root, "synthetic-client.json"), fixture)
	// The independent pin is captured while SOURCE is the original live directory,
	// before any B backup. Only the test fixture has a pin initializer.
	hubForwardWriteEstablishedPin(t, root, source)
}
func hubForwardWriteEstablishedPin(t *testing.T, root, source string) {
	t.Helper()
	cp, err := store.InspectHubRestoreCheckpointReadOnly(source)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(source)
	if err != nil {
		t.Fatal(err)
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("synthetic pin requires Linux filesystem identity")
	}
	nonce := sha256.Sum256([]byte("SYNTHETIC original source registration; nonce is not freshness"))
	reference := sha256.Sum256([]byte("SYNTHETIC independent established deployment reference; never initialize deployment"))
	pin := store.HubRestoreTrustPin{FormatVersion: 1, HubID: cp.HubID, SourceStorage: store.HubRestoreStorageIncarnation{CanonicalCoordinate: source, Device: uint64(native.Dev), Inode: native.Ino, RegistrationNonce: hex.EncodeToString(nonce[:])}, IdentityFingerprints: cp.IdentityFingerprints, SchemaFingerprint: cp.SchemaFingerprint, TrustReferenceSHA256: hex.EncodeToString(reference[:])}
	hubForwardPrivateJSON(t, filepath.Join(root, "synthetic-established-pin.json"), pin)
}
func hubForwardSyntheticFault(t *testing.T, state, mode string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(state, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if mode == "lost-unknown" {
		if _, err = db.Exec(`DELETE FROM client_device_request_recovery_v2 WHERE request_id IN (SELECT id FROM client_device_requests_v2 WHERE operation_id='synthetic-unknown-original')`); err != nil {
			t.Fatal(err)
		}
		if _, err = db.Exec(`DELETE FROM client_device_requests_v2 WHERE operation_id='synthetic-unknown-original'`); err != nil {
			t.Fatal(err)
		}
	} else if mode == "pending" {
		if _, err = db.Exec(`UPDATE client_device_requests_v2 SET status='PROCESSING' WHERE operation_id='synthetic-unknown-original'`); err != nil {
			t.Fatal(err)
		}
	} else {
		t.Fatal("unknown synthetic fault")
	}
}
func hubForwardHeldConstructors(t *testing.T, state string) {
	t.Helper()
	before := hubForwardTreeDigest(t, state)
	if _, err := control.New(hubForwardConfig(state)); !errors.Is(err, store.ErrStateRestoreQuarantined) {
		t.Fatalf("unpermitted Full constructor: %v", err)
	}
	if err := serveFabricOnly("127.0.0.1", 65536, hubForwardConfig(state)); !errors.Is(err, store.ErrStateRestoreQuarantined) {
		t.Fatalf("unpermitted Fabric constructor: %v", err)
	}
	if after := hubForwardTreeDigest(t, state); before != after {
		t.Fatal("held constructors changed source or target state")
	}
}
func hubForwardAdvance(t *testing.T, root, source string) {
	t.Helper()
	fixture := hubForwardSyntheticRead(t, root)
	c := hubForwardControl(t, source)
	tcp := httptest.NewServer(server.NewHandler(c))
	defer tcp.Close()
	hubForwardPost(t, tcp.URL, "/v2/client/rpc", hubForwardPacket(t, fixture, 3, "synthetic-metadata-after-B", false), 200)
	s, err := store.New(filepath.Join(source, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	device, err := s.GetClientDevice(fixture.RevokedBinding.OwnerID, fixture.RevokedBinding.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.RevokeClientDevice(device.OwnerID, device.DeviceID, device.Version); err != nil {
		t.Fatal(err)
	}
}
func hubForwardProbe(t *testing.T, root, origin string, next uint64) {
	t.Helper()
	fixture := hubForwardSyntheticRead(t, root)
	body := hubForwardPost(t, origin, "/v2/client/rpc", hubForwardPacket(t, fixture, next, fmt.Sprintf("synthetic-post-forward-%d", next), false), 200)
	device, err := e2ee.UnmarshalIdentity(fixture.DevicePrivate)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := clientwire.OpenResponse(device, fixture.HubPublic, fixture.Binding, body)
	if err != nil {
		t.Fatal("metadata response did not retain original key")
	}
	var result struct {
		OK bool `json:"ok"`
	}
	if err = json.Unmarshal(opened.Plaintext, &result); err != nil || !result.OK {
		t.Fatal("metadata response failed")
	}
	hubForwardPost(t, origin, "/v2/client/rpc", hubForwardPacket(t, fixture, 1, "synthetic-stale-different-operation", false), 409)
	hubForwardPost(t, origin, "/v2/client/rpc", hubForwardPacket(t, fixture, 1, "synthetic-current-revocation", true), 403)
	hubForwardPost(t, origin, "/v2/client/rpc", fixture.UnknownPacket, 409)
	unknown := hubForwardPost(t, origin, "/v2/client/rpc/recover", fixture.UnknownPacket, 200)
	unknownDevice, err := e2ee.UnmarshalIdentity(fixture.UnknownPrivate)
	if err != nil {
		t.Fatal(err)
	}
	opened, err = clientwire.OpenResponse(unknownDevice, fixture.HubPublic, fixture.UnknownBinding, unknown)
	if err != nil {
		t.Fatal("unknown recovery identity changed")
	}
	if !bytes.Contains(opened.Plaintext, []byte("OUTCOME_UNCERTAIN")) {
		t.Fatal("original UNKNOWN was not retained")
	}
	responseDigest := sha256.Sum256(unknown)
	digestPath := filepath.Join(root, "synthetic-unknown-response.sha256")
	if next == 4 {
		if err = os.WriteFile(digestPath, []byte(hex.EncodeToString(responseDigest[:])), 0600); err != nil {
			t.Fatal(err)
		}
	} else {
		prior, err := os.ReadFile(digestPath)
		if err != nil || string(prior) != hex.EncodeToString(responseDigest[:]) {
			t.Fatal("restart changed cached original sealed UNKNOWN response")
		}
	}
}
func hubForwardInspect(t *testing.T, state string, floor uint64) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(state, "cicada.sqlite3")+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var current uint64
	if err = db.QueryRow(`SELECT last_request_sequence FROM client_devices_v2 WHERE device_id='synthetic-active-device'`).Scan(&current); err != nil || current != floor {
		t.Fatalf("request floor %d want %d: %v", current, floor, err)
	}
	var n int
	if err = db.QueryRow(`SELECT count(*) FROM client_devices_v2 WHERE device_id='synthetic-revoked-device' AND state='REVOKED'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("current revocation missing")
	}
	if err = db.QueryRow(`SELECT count(*) FROM client_device_requests_v2 WHERE operation_id='synthetic-unknown-original' AND status='UNCERTAIN'`).Scan(&n); err != nil || n != 1 {
		t.Fatal("original UNKNOWN missing")
	}
	if err = db.QueryRow(`SELECT count(*) FROM client_devices_v2 WHERE device_id='synthetic-unknown-device' AND last_request_sequence=2 AND next_response_sequence=3`).Scan(&n); err != nil || n != 1 {
		t.Fatal("UNKNOWN device replay or response floor changed")
	}
	if err = db.QueryRow(`SELECT count(*) FROM client_device_request_recovery_v2 WHERE reserved_response_sequence=2 AND request_id IN (SELECT id FROM client_device_requests_v2 WHERE operation_id='synthetic-unknown-original')`).Scan(&n); err != nil || n != 1 {
		t.Fatal("burned original response reservation missing")
	}
}

func TestHubForwardConstructorsKeepUnprovenRestoreHeld(t *testing.T) {
	root := t.TempDir()
	source, backup, target := filepath.Join(root, "source"), filepath.Join(root, "B"), filepath.Join(root, "T")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := store.New(filepath.Join(source, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = store.BackupStateDir(source, backup); err != nil {
		t.Fatal(err)
	}
	if _, err = store.RestoreStateDir(backup, target); err != nil {
		t.Fatal(err)
	}
	before := hubForwardTreeDigest(t, target)
	if _, err = control.New(hubForwardConfig(target)); !errors.Is(err, store.ErrStateRestoreQuarantined) {
		t.Fatalf("Full constructor bypassed hold: %v", err)
	}
	if err = serveFabricOnly("127.0.0.1", 65536, hubForwardConfig(target)); !errors.Is(err, store.ErrStateRestoreQuarantined) {
		t.Fatalf("Fabric-only constructor bypassed hold: %v", err)
	}
	if after := hubForwardTreeDigest(t, target); before != after {
		t.Fatal("denied constructors mutated restored state")
	}
}
func hubForwardTreeDigest(t *testing.T, root string) [32]byte {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%s:%d\n", path, info.Mode())
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		h.Write(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// Selected explicitly by the Docker driver; ordinary go test runs the bounded
// constructor test and never claims that the opt-in TCP gate ran.
func TestHubRestoreForwardDisposableFixture(t *testing.T) {
	mode := os.Getenv("CICADA_SYNTHETIC_HUB_FORWARD_MODE")
	if mode == "" {
		return
	}
	syscall.Umask(0077)
	root, state := os.Getenv("CICADA_SYNTHETIC_HUB_FORWARD_ROOT"), os.Getenv("CICADA_SYNTHETIC_HUB_FORWARD_STATE")
	if root == "" || state == "" || !strings.Contains(root, "synthetic") {
		t.Fatal("explicit visibly synthetic root and state required")
	}
	switch mode {
	case "init":
		hubForwardInit(t, root, state)
	case "advance":
		hubForwardAdvance(t, root, state)
	case "lost-unknown", "pending":
		hubForwardSyntheticFault(t, state, mode)
	case "held-constructor":
		hubForwardHeldConstructors(t, state)
	case "serve":
		c := hubForwardControl(t, state)
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		t.Fatal(http.ListenAndServe(":8787", server.NewHandler(c)))
	case "probe":
		var next uint64
		if _, err := fmt.Sscan(os.Getenv("CICADA_SYNTHETIC_HUB_FORWARD_NEXT"), &next); err != nil || next < 4 {
			t.Fatal("explicit current next sequence required")
		}
		hubForwardProbe(t, root, os.Getenv("CICADA_SYNTHETIC_HUB_FORWARD_ORIGIN"), next)
	case "inspect":
		var floor uint64
		if _, err := fmt.Sscan(os.Getenv("CICADA_SYNTHETIC_HUB_FORWARD_NEXT"), &floor); err != nil {
			t.Fatal(err)
		}
		hubForwardInspect(t, state, floor)
	case "fabric-constructor":
		err := serveFabricOnly("127.0.0.1", 65536, hubForwardConfig(state))
		if err == nil || errors.Is(err, store.ErrStateRestoreQuarantined) || !strings.Contains(err.Error(), "invalid port") {
			t.Fatalf("activated Fabric constructor did not reach listener validation: %v", err)
		}
	default:
		t.Fatal("unknown synthetic fixture mode")
	}
}
