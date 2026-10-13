package clientoperator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

type operatorFixture struct {
	p       *Profile
	hub     *control.Control
	handler http.Handler
	http    *httptest.Server
	owner   *e2ee.Identity
	config  control.Config
}

func newOperatorFixture(t *testing.T) *operatorFixture {
	t.Helper()
	root := t.TempDir()
	config := control.Config{StateDir: filepath.Join(root, "hub"), WorkspaceRoot: filepath.Join(root, "workspace")}
	hub, err := control.New(config)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.New(filepath.Join(config.StateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.RegisterOwnerApprovalKeyLocal(hub.Identity().ID, owner.Public()); err != nil {
		t.Fatal(err)
	}
	hubID, err := db.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	db.Close()
	f := &operatorFixture{hub: hub, owner: owner, config: config}
	f.handler = server.NewHandler(hub)
	f.http = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.handler.ServeHTTP(w, r) }))
	f.p, err = Prepare(privateTempDir(t), f.http.URL, hub.Identity().ID, HubIdentity{Contract: "android-hub-v1", HubID: hubID, Public: hub.ClientControlPublicIdentity(), KeyVersion: 1, Suite: Suite}, owner.Public(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.p.Close()
		f.http.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		f.hub.Shutdown(ctx)
	})
	return f
}
func (f *operatorFixture) grant(t *testing.T, expires time.Time) []byte {
	t.Helper()
	g, err := f.owner.SignOwnerDeviceGrant(f.p.state.OwnerID, f.p.state.DeviceID, f.p.identity.Public(), f.p.state.Hub.HubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), expires)
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func (f *operatorFixture) enroll(t *testing.T) {
	t.Helper()
	if err := f.p.Enroll(context.Background(), f.grant(t, time.Now().Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
}
func (f *operatorFixture) reopen(t *testing.T) {
	t.Helper()
	dir := f.p.dir
	f.p.Close()
	p, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	f.p = p
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func dropAfterCommit(p *Profile, path string) {
	base := p.client.Transport
	once := true
	p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		reply, err := base.RoundTrip(r)
		if err == nil && r.URL.Path == path && once {
			once = false
			reply.Body.Close()
			return nil, errors.New("synthetic lost response")
		}
		return reply, err
	})
}

func TestOperatorEnrollmentLostResponseAndExpiredExactRetry(t *testing.T) {
	f := newOperatorFixture(t)
	expires := time.Now().Add(2 * time.Second)
	grant := f.grant(t, expires)
	dropAfterCommit(f.p, "/v2/client/devices/enroll")
	if err := f.p.Enroll(context.Background(), grant); err == nil {
		t.Fatal("lost response appeared successful")
	}
	original := append([]byte(nil), f.p.state.Enrollment.Body...)
	device := f.p.Manifest().DeviceID
	f.reopen(t)
	time.Sleep(time.Until(expires) + 10*time.Millisecond)
	if err := f.p.Enroll(context.Background(), append(grant, '\n')); err == nil {
		t.Fatal("replaced pending canonical Grant")
	}
	if !bytes.Equal(original, f.p.state.Enrollment.Body) {
		t.Fatal("retry changed enrollment")
	}
	if err := f.p.Enroll(context.Background(), grant); err != nil {
		t.Fatal(err)
	}
	if f.p.Manifest().DeviceID != device {
		t.Fatal("retry rotated Client")
	}
	r, err := f.p.Capabilities(context.Background())
	if err != nil || !r.OK {
		t.Fatalf("encrypted binding proof: %v", err)
	}
}

func TestOperatorEncryptedPendingExactRetryAndHubRestart(t *testing.T) {
	f := newOperatorFixture(t)
	f.enroll(t)
	dropAfterCommit(f.p, "/v2/client/rpc")
	if _, err := f.p.Capabilities(context.Background()); err == nil {
		t.Fatal("lost encrypted response appeared successful")
	}
	original := append([]byte(nil), f.p.state.Pending.Packet...)
	operation := f.p.state.Pending.Route.OperationID
	if _, err := f.p.Nodes(context.Background()); !errors.Is(err, ErrPending) {
		t.Fatalf("accepted another operation: %v", err)
	}
	f.reopen(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := f.hub.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	var err error
	f.hub, err = control.New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	f.handler = server.NewHandler(f.hub)
	if !bytes.Equal(original, f.p.state.Pending.Packet) {
		t.Fatal("restart changed pending ciphertext")
	}
	r, err := f.p.Recover(context.Background())
	if err != nil || !r.OK || r.OperationID != operation {
		t.Fatalf("original recovery: %v", err)
	}
	if f.p.state.NextRequest != 2 || f.p.state.NextResponse != 2 {
		t.Fatal("wrong recovered counters")
	}
	r, err = f.p.Nodes(context.Background())
	if err != nil || !r.OK {
		t.Fatalf("next encrypted operation: %v", err)
	}
}

func (f *operatorFixture) nodeCode(t *testing.T) *control.NodeControlDeviceCode {
	return f.nodeCodeMode(t, false)
}

func (f *operatorFixture) nodeCodeMode(t *testing.T, upgrade bool) *control.NodeControlDeviceCode {
	t.Helper()
	hub, err := f.hub.NodeControlPublicIdentity()
	if err != nil {
		t.Fatal(err)
	}
	node, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	credential := fabric.HashSessionCredential("cicada_node_synthetic_operator_do_not_deploy")
	nonce := bytes.Repeat([]byte{0x53}, 32)
	transcript, err := nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: hub.HubID, NodeID: "synthetic-operator-node", RequestNonce: nonce, CredentialDigest: credential, NodePublicIdentity: node.Public(), HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := e2ee.Seal(node, hub.PublicIdentity, transcript, nodewire.PairingProofAAD(), 1)
	if err != nil {
		t.Fatal(err)
	}
	input := control.NodeControlDeviceCodeInput{NodeID: "synthetic-operator-node", NodeName: "Synthetic headless Node", CredentialDigest: credential, RequestNonce: nonce, NodePublicIdentity: node.Public(), NodeFingerprint: nodewire.IdentityFingerprint(node.Public()), ProofPacket: proof, HubID: hub.HubID, HubPublicIdentity: hub.PublicIdentity, HubKeyVersion: hub.KeyVersion, HubFingerprint: hub.Fingerprint}
	var code *control.NodeControlDeviceCode
	if upgrade {
		code, err = f.hub.StartNodeControlKeyUpgrade("cicada_node_synthetic_operator_do_not_deploy", input)
	} else {
		code, err = f.hub.StartNodeControlDeviceBinding(input)
	}
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestOperatorExactNodePreviewConfirmationAndRecovery(t *testing.T) {
	f := newOperatorFixture(t)
	f.enroll(t)
	code := f.nodeCode(t)
	r, err := f.p.PreviewNode(context.Background(), code.UserCode)
	if err != nil || !r.OK {
		t.Fatalf("preview: %v", err)
	}
	candidate, err := f.p.NodeReview()
	if err != nil {
		t.Fatal(err)
	}
	changed := candidate
	changed.NodeID = "foreign-node"
	if _, err = f.p.ConfirmNode(context.Background(), changed); err == nil {
		t.Fatal("accepted changed reviewed tuple")
	}
	dropAfterCommit(f.p, "/v2/client/rpc")
	if _, err = f.p.ConfirmNode(context.Background(), candidate); err == nil {
		t.Fatal("lost confirmation response appeared successful")
	}
	original := append([]byte(nil), f.p.state.Pending.Packet...)
	f.reopen(t)
	if !bytes.Equal(original, f.p.state.Pending.Packet) {
		t.Fatal("confirmation ciphertext changed")
	}
	r, err = f.p.Retry(context.Background())
	if err != nil || !r.OK {
		t.Fatalf("confirmation retry: %v", err)
	}
	var binding store.NodeControlKeyBinding
	if err = json.Unmarshal(r.Result, &binding); err != nil || binding.NodeID != candidate.NodeID || binding.ApprovedCandidateDigest != candidate.CandidateDigest || binding.ApprovedOwnerDeviceID != f.p.state.DeviceID {
		t.Fatalf("wrong exact Node binding: %v", err)
	}
	r, err = f.p.Nodes(context.Background())
	if err != nil || !r.OK {
		t.Fatalf("list: %v", err)
	}
}

func TestOperatorUncertainConfirmationFencesNewMutation(t *testing.T) {
	f := newOperatorFixture(t)
	f.enroll(t)
	code := f.nodeCode(t)
	if r, err := f.p.PreviewNode(context.Background(), code.UserCode); err != nil || !r.OK {
		t.Fatal(err)
	}
	candidate, _ := f.p.NodeReview()
	real := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/client/rpc" && f.p.state.Pending != nil && f.p.state.Pending.Route.Operation == "nodes.confirm" {
			q := f.p.state.Pending
			digest := sha256.Sum256(q.Packet)
			_, err := f.hub.AcceptClientControlRequest(store.AcceptClientRequestInput{OwnerID: f.p.state.OwnerID, DeviceID: f.p.state.DeviceID, SessionEpoch: q.Route.SessionEpoch, Sequence: q.Route.Sequence, OperationID: q.Route.OperationID, RouteOperation: q.Route.Operation, CiphertextDigest: hex.EncodeToString(digest[:])})
			if err != nil {
				t.Error(err)
			}
			_, err = f.hub.MarkClientControlRequestUncertain(f.p.state.OwnerID, f.p.state.DeviceID, q.Route.OperationID)
			if err != nil {
				t.Error(err)
			}
			w.WriteHeader(http.StatusConflict)
			return
		}
		real.ServeHTTP(w, r)
	})
	if _, err := f.p.ConfirmNode(context.Background(), candidate); err == nil {
		t.Fatal("synthetic uncertainty appeared successful")
	}
	f.handler = real
	r, err := f.p.Recover(context.Background())
	if err != nil || r.ErrorCode != "OUTCOME_UNCERTAIN" {
		t.Fatalf("uncertainty recovery: %v", err)
	}
	f.reopen(t)
	if _, err = f.p.ConfirmNode(context.Background(), candidate); !errors.Is(err, ErrUncertain) {
		t.Fatalf("uncertainty fence: %v", err)
	}
	if r, err = f.p.Nodes(context.Background()); err != nil || !r.OK {
		t.Fatalf("read-only reconciliation: %v", err)
	}
}

func TestOperatorFullPinRedirectAndResponseCorrelation(t *testing.T) {
	f := newOperatorFixture(t)
	f.enroll(t)
	f.p.state.Hub.Public.KEMPublic = append([]byte(nil), f.p.state.Hub.Public.KEMPublic...)
	f.p.state.Hub.Public.KEMPublic[0] ^= 1
	if _, err := f.p.Capabilities(context.Background()); err == nil {
		t.Fatal("accepted changed full key under same ID")
	}
	f.p.state.Hub.Public = f.hub.ClientControlPublicIdentity()
	real := f.handler
	f.handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/stolen", http.StatusTemporaryRedirect)
	})
	if _, err := f.p.Capabilities(context.Background()); err == nil {
		t.Fatal("followed redirect")
	}
	f.handler = real
	base := f.p.client.Transport
	f.p.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		response, err := base.RoundTrip(r)
		if err != nil || r.URL.Path != "/v2/client/rpc" {
			return response, err
		}
		response.Body.Close()
		saved := f.p.state.Pending
		route := saved.Route
		route.Direction = clientwire.DirectionResponse
		route.Sequence = saved.ResponseSequence + 1
		route.SenderKeyID, route.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
		route.SenderKeyVersion, route.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
		body, _ := json.Marshal(Response{RequestID: "synthetic", OperationID: route.OperationID, OK: true, Result: json.RawMessage(`{}`)})
		packet, err := f.hub.SealClientControlResponse(f.p.identity.Public(), *f.p.state.Binding, route, body)
		if err != nil {
			return nil, err
		}
		response.Body = ioNopCloser{bytes.NewReader(packet)}
		return response, nil
	})
	if _, err := f.p.Capabilities(context.Background()); err == nil {
		t.Fatal("accepted wrong response sequence")
	}
	if f.p.state.Pending == nil || f.p.state.NextRequest != 1 {
		t.Fatal("invalid response consumed pending request")
	}
}

type ioNopCloser struct{ *bytes.Reader }

func (ioNopCloser) Close() error { return nil }

func TestOperatorMissingUpgradeTargetFailsBeforeMutationReservation(t *testing.T) {
	f := newOperatorFixture(t)
	f.enroll(t)
	code := f.nodeCode(t)
	if r, err := f.p.PreviewNode(context.Background(), code.UserCode); err != nil || !r.OK {
		t.Fatal(err)
	}
	candidate, _ := f.p.NodeReview()
	if r, err := f.p.ConfirmNode(context.Background(), candidate); err != nil || !r.OK {
		t.Fatal(err)
	}
	// Advance only this synthetic request's churn timestamp instead of sleeping
	// through the production per-Node reissue cooldown. Signed claims are intact.
	db, err := sql.Open("sqlite", filepath.Join(f.config.StateDir, "cicada.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`UPDATE node_control_key_requests_v1 SET created_at=? WHERE node_id=?`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano), candidate.NodeID)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	upgrade := f.nodeCodeMode(t, true)
	if r, err := f.p.PreviewNode(context.Background(), upgrade.UserCode); err != nil || !r.OK {
		t.Fatal(err)
	}
	candidate, err = f.p.NodeReview()
	if err != nil {
		t.Fatal(err)
	}
	if candidate.Mode != "UPGRADE" || candidate.BindingID != "" || candidate.BindingVersion != 0 {
		t.Fatal("fixture no longer reflects current missing upgrade target")
	}
	sequence := f.p.state.NextRequest
	if _, err = f.p.ConfirmNode(context.Background(), candidate); !errors.Is(err, ErrUpgradeReview) {
		t.Fatalf("missing upgrade target: %v", err)
	}
	if f.p.state.Pending != nil || f.p.state.NextRequest != sequence {
		t.Fatal("unsupported upgrade reserved mutation")
	}
}

func TestOperatorRejectsWrongGrantRevocationAndCancelledBeforeSend(t *testing.T) {
	f := newOperatorFixture(t)
	wrong, err := f.owner.SignOwnerDeviceGrant(f.p.state.OwnerID, "foreign-device", f.p.identity.Public(), f.p.state.Hub.HubID, e2ee.OwnerDevicePurposeControl, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = f.p.Enroll(context.Background(), wrong); err == nil {
		t.Fatal("accepted wrong-device Grant")
	}
	if f.p.state.Enrollment != nil {
		t.Fatal("persisted invalid Grant")
	}
	f.enroll(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = f.p.Capabilities(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request: %v", err)
	}
	if f.p.state.Pending != nil || f.p.state.NextRequest != 1 {
		t.Fatal("cancelled-before-send request reserved pending state")
	}
	if _, err = f.hub.RevokeClientDevice(f.p.state.OwnerID, f.p.state.DeviceID, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Capabilities(context.Background()); err == nil {
		t.Fatal("revoked Client admitted")
	}
	if f.p.state.Pending == nil {
		t.Fatal("revoked operation silently discarded")
	}
	if _, err = f.p.Recover(context.Background()); err == nil {
		t.Fatal("revoked Client recovery admitted")
	}
}
