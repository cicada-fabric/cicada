//go:build cicada_scoped_app_integration

package appcore

import (
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
	"github.com/cicada-ai/cicada/internal/hubnodes"
	"github.com/cicada-ai/cicada/internal/hubowner"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/ownerbootstrap"
	"github.com/cicada-ai/cicada/internal/server"
	"github.com/cicada-ai/cicada/internal/store"
)

func appUnbindRows(f *scopedAppHTTPFixture) map[string]int64 {
	f.t.Helper()
	dsn := (&url.URL{Scheme: "file", Path: filepath.Join(f.root, "SYNTHETIC-hub.sqlite3"), RawQuery: "mode=ro"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		f.t.Fatal(err)
	}
	defer db.Close()
	counts := map[string]int64{}
	for _, table := range []string{"hub_app_binding_prepares_v1", "hub_app_binding_operations_v1", "hub_app_unbound_v1", "hub_app_rebound_v1", "hub_account_sessions_v1", "client_devices_v2"} {
		var count int64
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil {
			f.t.Fatal("read-only synthetic effect inventory", err)
		}
		counts[table] = count
	}
	for name, query := range map[string]string{
		"account_epoch":           "SELECT epoch FROM hub_account_config_v1 WHERE id=1",
		"active_account_sessions": "SELECT count(*) FROM hub_account_sessions_v1 WHERE state='ACTIVE'",
		"active_account_devices":  "SELECT count(*) FROM hub_account_devices_v1 WHERE status='ACTIVE'",
	} {
		var value int64
		if err := db.QueryRow(query).Scan(&value); err != nil {
			f.t.Fatal("read-only synthetic authority inventory", err)
		}
		counts[name] = value
	}
	var deviceEpoch, credentialVersion int64
	if err := db.QueryRow("SELECT epoch FROM hub_account_devices_v1 WHERE account_id=? AND owner_id=? AND device_id=?", f.c.connection.AccountID, f.c.connection.OwnerID, f.c.state.DeviceID).Scan(&deviceEpoch); err != nil {
		f.t.Fatal(err)
	}
	if err := db.QueryRow("SELECT version FROM hub_account_credentials_v1 WHERE account_id=? AND owner_id=?", f.c.connection.AccountID, f.c.connection.OwnerID).Scan(&credentialVersion); err != nil {
		f.t.Fatal(err)
	}
	counts["device_epoch"], counts["credential_version"] = deviceEpoch, credentialVersion
	return counts
}

// An arbitrary caller can construct a valid PQ proof of its own fake Owner
// key without ever receiving a Hub challenge. No admitted prepare or trusted
// Root exists for this forged target. Even a permanent negative receipt would
// be an unauthorized durable write and an unbounded storage admission path.
func TestAppUnbindForgedOwnerWithoutPrepareCannotAllocateReceipt(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	before := appUnbindRows(f)
	old, err := f.db.GetClientDevice(f.c.connection.OwnerID, f.c.state.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	device, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	suffix, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	session := *f.c.session
	session.DeviceID, session.DeviceKeyID = wire.AccountDeviceIDPrefix+suffix, device.Public().ID
	session.DeviceKeyFingerprint, err = e2ee.OwnerDevicePublicKeyFingerprint(device.Public())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	prepare, err := wire.NewAppUnbindPrepare(session, owner.Public(), now)
	if err != nil {
		t.Fatal(err)
	}
	original, err := wire.SealClientRequest(device, f.hub, prepare)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := wire.HubFingerprint(f.hub)
	if err != nil {
		t.Fatal(err)
	}
	binding := wire.AppBinding{Format: wire.AppBindingFormat, Purpose: wire.AppBindingPurposeUnbind, Origin: f.origin, HubID: f.hub.HubID, HubFingerprint: fingerprint, AccountID: session.AccountID, OwnerID: session.OwnerID, OwnerPublic: owner.Public(), OwnerKeyVersion: 1, AccountEpoch: session.AccountEpoch, CredentialVersion: 1, DeviceID: session.DeviceID, DevicePublic: device.Public(), DeviceEpoch: session.DeviceEpoch, ClientDeviceVersion: 1, ClientSessionEpoch: 1, SessionID: "SYNTHETIC-no-prepare-session", PrepareRequestID: prepare.RequestID, PreparePacketDigest: wire.AppBindingPacketDigest(original), IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(wire.MaxAppBindingChallengeLifetime).Format(time.RFC3339Nano)}
	pair := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: binding.Origin, Hub: f.hub, Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: binding.AccountID, OwnerID: binding.OwnerID, HubID: binding.HubID, AuthorityID: binding.PrepareRequestID, OperationID: binding.Digest(), CandidatePublic: owner.Public(), CandidateFingerprint: ownerbootstrap.Fingerprint(owner.Public()), ExpiresAt: binding.ExpiresAt}}
	nonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	possession, err := json.Marshal(ownerbootstrap.Possession{Format: ownerbootstrap.Format, Manifest: pair.Manifest, Nonce: nonce})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(possession)
	proof, err := ownerbootstrap.CreateProofFromPossessionWithPrivateOperations(owner.Public(), owner, pair, possession, now)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(proof)
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	clientNonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	serverNonce, err := wire.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	complete := wire.AppBindingComplete{Format: wire.AppBindingCompleteFormat, Binding: binding, PreparePacket: original, ServerNonce: serverNonce, OwnerProof: proof, RequestID: id, ClientNonce: clientNonce, IssuedAt: now.Format(time.RFC3339Nano)}
	packet, err := wire.SealClientRequest(device, f.hub, complete)
	if err != nil {
		t.Fatal(err)
	}
	// Prove the negative actor's crypto is well formed before asking the actual
	// server to reject its absent trusted Owner, rather than a malformed packet.
	ids, err := hubidentity.LoadOrCreate(filepath.Join(f.root, "SYNTHETIC-hub-keys"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownerbootstrap.VerifyProof(ids.ClientControl, pair, proof, now); err != nil {
		t.Fatal("forged Owner negative control lacks a valid PQ proof", err)
	}
	appUnbindPostPacket(f, wire.OperationAppUnbindComplete, packet, http.StatusForbidden)
	after, err := f.db.GetClientDevice(f.c.connection.OwnerID, f.c.state.DeviceID)
	if err != nil || !reflect.DeepEqual(before, appUnbindRows(f)) || after.Version != old.Version || after.SessionEpoch != old.SessionEpoch || after.State != old.State {
		t.Fatal("forged Owner allocated durable state or changed the real App", err)
	}
}

func appUnbindPostPacket(f *scopedAppHTTPFixture, operation string, packet []byte, want int) []byte {
	f.t.Helper()
	req, err := http.NewRequest(http.MethodPost, f.origin+wire.AppBindingHTTPPath(operation), bytes.NewReader(packet))
	if err != nil {
		f.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.origin)
	if err = f.pace(req.Context()); err != nil {
		f.t.Fatal(err)
	}
	response, err := f.client.Do(req)
	if err != nil {
		f.t.Fatal("actual App binding HTTP transport", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 || response.StatusCode != want {
		f.t.Fatalf("actual App binding %s status=%d want=%d read=%v", operation, response.StatusCode, want, err)
	}
	return raw
}

func appUnbindRejectChangedComplete(f *scopedAppHTTPFixture, original, receipt []byte) {
	f.t.Helper()
	before := appUnbindRows(f)
	operation := wire.OperationAppUnbindComplete
	p, err := wire.PreflightRequest(original, operation)
	if err != nil {
		f.t.Fatal(err)
	}
	public := f.c.device.Public()
	binding, route, err := wire.RequestRoute(f.hub, f.c.connection.OwnerID, p.Packet.Route.DeviceID, p.Packet.Route.OperationID, operation, wire.HandshakeEpoch, public)
	if err != nil {
		f.t.Fatal(err)
	}
	ids, err := hubidentity.LoadOrCreate(filepath.Join(f.root, "SYNTHETIC-hub-keys"), "")
	if err != nil {
		f.t.Fatal(err)
	}
	var complete wire.AppBindingComplete
	if wire.OpenRequestAt(ids.ClientControl, &public, binding, route, original, &complete, time.Time{}) != nil {
		f.t.Fatal("original Complete negative-control opening failed")
	}
	defer clear(complete.OwnerProof)
	complete.RequestID, err = wire.NewRequestID()
	if err != nil {
		f.t.Fatal(err)
	}
	complete.ClientNonce, err = wire.NewNonce()
	if err != nil {
		f.t.Fatal(err)
	}
	key, err := f.c.device.E2EE()
	if err != nil {
		f.t.Fatal(err)
	}
	changed, err := wire.SealClientRequest(key, f.hub, complete)
	if err != nil || bytes.Equal(changed, original) {
		f.t.Fatal("changed-ID/digest proof replay was not constructed", err)
	}
	appUnbindPostPacket(f, operation, changed, http.StatusForbidden)
	if !reflect.DeepEqual(before, appUnbindRows(f)) {
		f.t.Fatal("reusing one binding proof with a fresh Complete ID allocated permanent state")
	}
	exact := appUnbindPostPacket(f, operation, original, http.StatusOK)
	if !bytes.Equal(exact, receipt) || !reflect.DeepEqual(before, appUnbindRows(f)) {
		f.t.Fatal("original exact replay did not return its immutable terminal receipt")
	}
}

// The trusted Store clock admits a genuine historical prepare/challenge. The
// expiry verdict below is then obtained from today's real HTTP writer clock.
// No SQL edits, forged Hub challenge, synthetic terminal or wall-clock sleep.
func appUnbindStoreInput(f *scopedAppHTTPFixture, operation string, body any, packet []byte, at time.Time) store.HubAppBindingInput {
	f.t.Helper()
	ids, err := hubidentity.LoadOrCreate(filepath.Join(f.root, "SYNTHETIC-hub-keys"), "")
	if err != nil {
		f.t.Fatal(err)
	}
	binding, route, err := wire.NewClientRoute(f.hub, body, f.c.device.Public())
	if err != nil {
		f.t.Fatal(err)
	}
	var opened any
	switch body.(type) {
	case wire.AppUnbindPrepare:
		opened = &wire.AppUnbindPrepare{}
	case wire.AppBindingComplete:
		opened = &wire.AppBindingComplete{}
	default:
		f.t.Fatal("unsupported controlled Store input")
	}
	public := f.c.device.Public()
	if wire.OpenRequestAt(ids.ClientControl, &public, binding, route, packet, opened, time.Time{}) != nil || !reflect.DeepEqual(reflect.ValueOf(opened).Elem().Interface(), body) {
		f.t.Fatal("controlled Store input did not match the actual authenticated packet")
	}
	return store.HubAppBindingInput{Hub: f.hub, DevicePublic: f.c.device.Public(), Operation: operation, Body: body, Packet: packet, Now: func() time.Time { return at },
		Seal: func(response any) ([]byte, error) {
			return wire.SealResponse(ids.ClientControl, f.c.device.Public(), route, response)
		},
		VerifyProof: func(pair ownerbootstrap.PairingFile, proof []byte, now time.Time) (string, error) {
			return ownerbootstrap.VerifyProof(ids.ClientControl, pair, proof, now)
		},
		Challenge: func(binding wire.AppBinding, clientNonce []byte, now time.Time) (wire.AppBindingChallenge, string, error) {
			pair := ownerbootstrap.PairingFile{Format: ownerbootstrap.Format, Origin: binding.Origin, Hub: f.hub, Manifest: ownerbootstrap.Manifest{Version: 1, Purpose: ownerbootstrap.Purpose, AccountID: binding.AccountID, OwnerID: binding.OwnerID, HubID: binding.HubID, AuthorityID: binding.PrepareRequestID, OperationID: binding.Digest(), CandidatePublic: binding.OwnerPublic, CandidateFingerprint: ownerbootstrap.Fingerprint(binding.OwnerPublic), ExpiresAt: binding.ExpiresAt}}
			pair, ownerNonce, err := ownerbootstrap.CreateChallenge(ids.ClientControl, pair, now)
			if err != nil {
				return wire.AppBindingChallenge{}, "", err
			}
			nonce, err := wire.NewNonce()
			if err != nil {
				return wire.AppBindingChallenge{}, "", err
			}
			return wire.AppBindingChallenge{Format: wire.AppBindingChallengeFormat, Operation: operation, RequestID: binding.PrepareRequestID, RequestPacketDigest: binding.PreparePacketDigest, Binding: binding, ClientNonce: clientNonce, ServerNonce: nonce, Proof: pair}, ownerNonce, nil
		},
	}
}

func appUnbindHistoricalComplete(f *scopedAppHTTPFixture, at time.Time) (wire.AppBindingComplete, []byte, appBindingRecord) {
	f.t.Helper()
	key, err := f.c.device.E2EE()
	if err != nil {
		f.t.Fatal(err)
	}
	prepare, err := wire.NewAppUnbindPrepare(*f.c.session, f.c.owner.Public(), at)
	if err != nil {
		f.t.Fatal(err)
	}
	original, err := wire.SealClientRequest(key, f.hub, prepare)
	if err != nil {
		f.t.Fatal(err)
	}
	response, err := f.db.ProcessHubAppBinding(appUnbindStoreInput(f, wire.OperationAppUnbindPrepare, prepare, original, at))
	if err != nil {
		f.t.Fatal("genuine historical Store prepare", err)
	}
	var challenge wire.AppBindingChallenge
	if wire.OpenClientResponse(key, f.hub, original, response, &challenge) != nil || wire.ValidateAppBindingPreparedResponse(prepare, original, challenge, f.hub, at) != nil {
		f.t.Fatal("historical prepare did not produce a genuine authenticated Hub challenge")
	}
	owner, err := f.c.owner.E2EE()
	if err != nil {
		f.t.Fatal(err)
	}
	proof, err := ownerbootstrap.CreateProof(owner, challenge.Proof, at)
	if err != nil {
		f.t.Fatal(err)
	}
	defer clear(proof)
	complete, err := wire.NewAppBindingComplete(original, challenge, proof, at.Add(wire.MaxAppBindingChallengeLifetime-time.Second))
	if err != nil {
		f.t.Fatal(err)
	}
	packet, err := wire.SealClientRequest(key, f.hub, complete)
	if err != nil {
		f.t.Fatal(err)
	}
	record := appBindingRecord{Format: appBindingRecordFormat, Scope: cardScope(f.c.connection), DeviceKeyID: key.Public().ID, Generation: 1, Unbind: &prepare, PreparePacket: original, ChallengePacket: response, CompletePacket: packet}
	return complete, packet, record
}

func TestAppUnbindExpiredCompleteAuthenticatesTerminalWithoutNewProofReceipts(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	old, err := f.db.GetClientDevice(f.c.connection.OwnerID, f.c.state.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC().Add(-wire.MaxAppBindingChallengeLifetime - 5*time.Second).Truncate(time.Second)
	for _, fraction := range []time.Duration{0, 123456789 * time.Nanosecond} {
		t.Run(fraction.String(), func(t *testing.T) {
			parent := f.t
			f.t = t
			defer func() { f.t = parent }()
			complete, packet, record := appUnbindHistoricalComplete(f, base.Add(fraction))
			defer clear(complete.OwnerProof)
			before := appUnbindRows(f)
			// Install only a genuine historical pending request fixture. Its
			// challenge and exact ciphertext were created and authenticated above;
			// no result or terminal state is injected into the Core or database.
			if err := f.c.persistAppBindingRecord(&record); err != nil {
				t.Fatal(err)
			}
			f.c.appBinding.unbind, f.c.appBinding.unbindRejected = &record, false
			f.c.publish()
			posts := f.posts[wire.AppBindingHTTPPath(wire.OperationAppUnbindComplete)]
			if err := f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverAppBinding}); err == nil || f.c.Snapshot().AppBinding.Pending || !f.c.appBinding.unbindRejected {
				t.Fatal("Core did not settle the actual authenticated expired Complete as rejected")
			}
			saved, _ := appUnbindSaved(f, appUnbindNamespace)
			raw := saved.ResultPacket
			key, err := f.c.device.E2EE()
			var result wire.AppBindingResult
			if err != nil || wire.OpenClientResponse(key, f.hub, packet, raw, &result) != nil || wire.ValidateAppBindingResultTarget(result, packet, complete.Binding) != nil ||
				result.State != wire.AppBindingRejected || result.ErrorCode != "EXPIRED" {
				t.Fatal("actual expired Complete did not return its authenticated EXPIRED terminal", err)
			}
			if !bytes.Equal(saved.CompletePacket, packet) || f.posts[wire.AppBindingHTTPPath(wire.OperationAppUnbindComplete)] != posts+1 {
				t.Fatal("Core replaced the historical Complete or posted it more than once")
			}
			after := appUnbindRows(f)
			before["hub_app_binding_operations_v1"]++
			if !reflect.DeepEqual(before, after) {
				t.Fatal("expired Complete produced effects beyond its single terminal floor")
			}
			appUnbindRejectChangedComplete(f, packet, raw)
		})
	}
	current, err := f.db.GetClientDevice(f.c.connection.OwnerID, f.c.state.DeviceID)
	if err != nil || current.Version != old.Version || current.SessionEpoch != old.SessionEpoch || current.State != old.State || f.c.session == nil {
		t.Fatal("authenticated expiry changed live App authority or local custody", err)
	}
	f.restart()
	posts := f.posts[wire.AppBindingHTTPPath(wire.OperationAppUnbindComplete)]
	if f.c.Snapshot().AppBinding.Pending || f.c.Dispatch(context.Background(), Action{Kind: ActionRecoverAppBinding}) == nil ||
		f.posts[wire.AppBindingHTTPPath(wire.OperationAppUnbindComplete)] != posts || f.c.session == nil {
		t.Fatal("cold authenticated rejection resumed an endless recovery loop or erased the old session")
	}
}

func TestAppUnbindTrustedWriterDeadlineIsStrictWithFractionalTimestamps(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	base := time.Now().UTC().Add(-wire.MaxAppBindingChallengeLifetime - 5*time.Second).Truncate(time.Second)
	cases := []struct {
		name     string
		fraction time.Duration
		delta    time.Duration
		state    string
	}{
		{"integral_at_deadline", 0, 0, wire.AppBindingRejected},
		{"fractional_at_deadline", 123456789 * time.Nanosecond, 0, wire.AppBindingRejected},
		{"fractional_after_deadline", 123456789 * time.Nanosecond, time.Nanosecond, wire.AppBindingRejected},
		{"fractional_before_deadline", 123456789 * time.Nanosecond, -time.Nanosecond, wire.AppBindingUnbound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := f.t
			f.t = t
			defer func() { f.t = parent }()
			at := base.Add(tc.fraction)
			complete, packet, _ := appUnbindHistoricalComplete(f, at)
			defer clear(complete.OwnerProof)
			deadline, err := time.Parse(time.RFC3339Nano, complete.Binding.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := f.db.ProcessHubAppBinding(appUnbindStoreInput(f, wire.OperationAppUnbindComplete, complete, packet, deadline.Add(tc.delta)))
			if err != nil {
				t.Fatal("trusted Store deadline boundary", err)
			}
			key, err := f.c.device.E2EE()
			var result wire.AppBindingResult
			if err != nil || wire.OpenClientResponse(key, f.hub, packet, raw, &result) != nil || wire.ValidateAppBindingResultTarget(result, packet, complete.Binding) != nil ||
				result.State != tc.state || tc.state == wire.AppBindingRejected && result.ErrorCode != "EXPIRED" {
				t.Fatal("trusted writer did not use strict chronological expiry", err)
			}
			if !bytes.Equal(raw, appUnbindPostPacket(f, wire.OperationAppUnbindComplete, packet, http.StatusOK)) {
				t.Fatal("actual HTTP recovery changed the trusted-clock terminal result")
			}
		})
	}
}

// RFC3339Nano omits a zero fraction and trailing zeros: lexical SQL ordering
// misclassifies both "...00Z" and "...00.1Z" against their +1ns successors.
// Capacity admission must reclaim expiry using chronological time instead.
func TestAppUnbindPrepareCapacityReclaimsChronologicalDeadline(t *testing.T) {
	for _, fraction := range []time.Duration{0, 100 * time.Millisecond} {
		t.Run(fraction.String(), func(t *testing.T) {
			f := newScopedAppHTTPFixture(t)
			base := time.Now().UTC().Add(-wire.MaxAppBindingChallengeLifetime - 5*time.Second).Truncate(time.Second).Add(fraction)
			key, err := f.c.device.E2EE()
			if err != nil {
				t.Fatal(err)
			}
			prepareAt := func(at time.Time) store.HubAppBindingInput {
				prepare, err := wire.NewAppUnbindPrepare(*f.c.session, f.c.owner.Public(), at)
				if err != nil {
					t.Fatal(err)
				}
				packet, err := wire.SealClientRequest(key, f.hub, prepare)
				if err != nil {
					t.Fatal(err)
				}
				return appUnbindStoreInput(f, wire.OperationAppUnbindPrepare, prepare, packet, at)
			}
			for i := 0; i < 4; i++ {
				if _, err := f.db.ProcessHubAppBinding(prepareAt(base)); err != nil {
					t.Fatal("finite per-device prepare quota setup", err)
				}
			}
			deadline := base.Add(wire.MaxAppBindingChallengeLifetime)
			before := appUnbindRows(f)
			if _, err := f.db.ProcessHubAppBinding(prepareAt(deadline.Add(-time.Nanosecond))); !errors.Is(err, store.ErrHubOwnerDiagnosticsFull) || !reflect.DeepEqual(before, appUnbindRows(f)) {
				t.Fatal("prepare quota admitted a fifth still-live challenge or mutated a refusal", err)
			}
			if _, err := f.db.ProcessHubAppBinding(prepareAt(deadline.Add(time.Nanosecond))); err != nil {
				t.Fatal("chronologically expired prepares blocked finite admission", err)
			}
			after := appUnbindRows(f)
			before["hub_app_binding_prepares_v1"] = 1
			if !reflect.DeepEqual(before, after) {
				t.Fatal("expiry GC did not retain exactly the single newly admitted prepare")
			}
			nextDeadline := deadline.Add(time.Nanosecond).Add(wire.MaxAppBindingChallengeLifetime)
			if _, err := f.db.ProcessHubAppBinding(prepareAt(nextDeadline)); err != nil || appUnbindRows(f)["hub_app_binding_prepares_v1"] != 1 {
				t.Fatal("prepare at the exact chronological deadline failed to reclaim the old challenge", err)
			}
		})
	}
}

func appUnbindConfirm(f *scopedAppHTTPFixture, kind ActionKind) Action {
	f.t.Helper()
	s := f.c.Snapshot().AppBinding
	if s.ReviewID == "" || s.Pending {
		f.t.Fatal("no current explicit App binding review")
	}
	return Action{Kind: kind, AppBinding: AppBindingAction{ReviewID: s.ReviewID, Confirm: true}}
}

func appUnbindSaved(f *scopedAppHTTPFixture, namespace string) (appBindingRecord, uint64) {
	f.t.Helper()
	raw, version, found, err := f.c.vault.LoadState(namespace)
	defer clear(raw)
	var record appBindingRecord
	if err != nil || !found || version == 0 || decodeStateJSON(raw, &record) != nil {
		f.t.Fatal("encrypted App binding record missing or invalid", err)
	}
	return record, version
}

func TestAppUnbindRejectsExistingUncertainScopedOriginal(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	consent := appUnbindConfirm(f, ActionUnbindApp)
	n := f.startNode("SYNTHETIC-unbind-prior-pending")
	f.dispatch(Action{Kind: ActionReviewNodePairing, DevicePairingCode: n.code})
	f.dropOperation = wire.AppNodeScopedHTTPPath(wire.OperationAppNodeScopedComplete)
	f.dropHTTPStatus = http.StatusForbidden
	if f.c.Dispatch(context.Background(), Action{Kind: ActionApproveNodePairing, NodePairingReviewID: f.c.Snapshot().Node.Pairing.ReviewID, ConfirmNodePairing: true}) == nil || !f.c.scopedPending() {
		t.Fatal("synthetic lost prior original did not remain uncertain")
	}
	original := bytes.Clone(f.c.scoped.original.Packet)
	if !bytes.Equal(original, f.droppedPacket) {
		t.Fatal("prior original was replaced before the refusal probe")
	}
	if f.c.Dispatch(context.Background(), consent) == nil || f.posts[wire.AppBindingHTTPPath(wire.OperationAppUnbindPrepare)] != 0 ||
		!f.c.scopedPending() || !bytes.Equal(f.c.scoped.original.Packet, original) {
		t.Fatal("unbind admitted or discarded a pre-existing uncertain scoped write")
	}
	f.restart()
	if !f.c.scopedPending() || !bytes.Equal(f.c.scoped.original.Packet, original) {
		t.Fatal("refused unbind or cold reopen changed the prior original")
	}
	f.dispatch(Action{Kind: ActionRecoverNodePairing})
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	f.ackNode(n)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	if f.c.scopedBusy() || !bytes.Equal(f.c.scoped.original.Packet, original) || f.posts[wire.AppNodeScopedHTTPPath(wire.OperationAppNodeScopedComplete)] != 1 {
		t.Fatal("prior original was not settled through its exact recovery and ACK")
	}
	if f.c.Snapshot().AppBinding.State != AppBindingBound || f.c.Snapshot().AppBinding.ReviewID == "" {
		t.Fatal("settled prior operation did not permit a fresh unbind review")
	}
}

func TestAppUnbindLostCompleteColdRecoveryKeepsTrafficUntilSecurityRevoke(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	a := newAppUnbindTraffic(t, f)
	if !a.heartbeat(http.StatusOK) {
		t.Fatal("original Node heartbeat denied before voluntary unbind")
	}
	a.sendAndOpen("before voluntary unbind")
	oldOwner, oldDevice, oldKey := f.c.owner.Public(), f.c.state.DeviceID, f.c.device.Public()
	completePath := wire.AppBindingHTTPPath(wire.OperationAppUnbindComplete)
	f.dropOperation, f.dropHTTPStatus = completePath, http.StatusForbidden
	if f.c.Dispatch(context.Background(), appUnbindConfirm(f, ActionUnbindApp)) == nil || !f.c.Snapshot().AppBinding.Pending {
		t.Fatal("unsigned lost-complete response settled voluntary unbind")
	}
	saved, _ := appUnbindSaved(f, appUnbindNamespace)
	original := bytes.Clone(saved.CompletePacket)
	if len(original) == 0 || !bytes.Equal(original, f.droppedPacket) || len(saved.ResultPacket) != 0 {
		t.Fatal("lost unbind Complete did not preserve its exact unresolved original")
	}
	appUnbindRestartHub(f)
	f.restart()
	saved, _ = appUnbindSaved(f, appUnbindNamespace)
	if !bytes.Equal(saved.CompletePacket, original) || !f.c.Snapshot().AppBinding.Pending {
		t.Fatal("Hub/App cold reopen lost the uncertain unbind original")
	}
	f.dispatch(Action{Kind: ActionRecoverAppBinding})
	saved, _ = appUnbindSaved(f, appUnbindNamespace)
	_, result, err := f.c.openAppBindingRecord(&saved)
	if err != nil || result == nil || result.State != wire.AppBindingUnbound || !bytes.Equal(saved.CompletePacket, original) ||
		f.posts[completePath] != 2 || f.posts[wire.AppBindingHTTPPath(wire.OperationAppUnbindPrepare)] != 1 {
		t.Fatal("cold recovery did not authenticate exactly one original unbind", err)
	}
	if s := f.c.Snapshot(); s.AppBinding.State != AppBindingUnbound || s.AppBinding.Pending || s.Account.DeviceEnrolled || s.Authorization.Confirmed ||
		f.c.session != nil || f.c.state.RootState != RootStateActive || !reflect.DeepEqual(f.c.owner.Public(), oldOwner) || !reflect.DeepEqual(f.c.device.Public(), oldKey) {
		t.Fatal("authenticated unbind changed Owner custody or retained live App authority")
	}
	appUnbindRejectChangedComplete(f, original, saved.ResultPacket)
	if f.c.Dispatch(context.Background(), Action{Kind: ActionLogin, Username: "synthetic-scoped-app", Password: n2SyntheticPassword}) == nil {
		t.Fatal("old unbound App admitted a new account login")
	}
	f.restart()
	if f.c.session != nil || f.c.Snapshot().AppBinding.State != AppBindingUnbound {
		t.Fatal("cold unbound fence resurrected the historical session")
	}
	if !a.heartbeat(http.StatusOK) {
		t.Fatal("same original Node heartbeat denied after voluntary unbind")
	}
	peer := a.sendAndOpen("after voluntary unbind and restart")
	device, err := f.db.GetClientDevice(a.ownerID, oldDevice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.RevokeClientDevice(a.ownerID, oldDevice, device.Version); err != nil {
		t.Fatal("genuine existing security revocation failed", err)
	}
	a.heartbeat(http.StatusForbidden)
	a.http(http.MethodGet, a.peerPath(), "CicadaNode "+a.node.token, "", nil, http.StatusNotFound)
	fresh, _, _ := a.message(peer, "fresh after security revoke")
	a.http(http.MethodPost, a.base()+"send", "CicadaNode "+a.node.token, "", fresh, http.StatusForbidden)
}

// Restart the disposable Hub on its original numeric TCP address, with only
// the existing durable SQLite and protected synthetic keys/profile as inputs.
func appUnbindRestartHub(f *scopedAppHTTPFixture) {
	t := f.t
	t.Helper()
	f.client.CloseIdleConnections()
	f.http.Close()
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	var err error
	f.db, err = store.New(filepath.Join(f.root, "SYNTHETIC-hub.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	ids, err := hubidentity.LoadOrCreate(filepath.Join(f.root, "SYNTHETIC-hub-keys"), "")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := hubowner.NewService(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := hubauth.NewServiceWithScopedNodeAuthority(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	hub, err := auth.HubIdentity()
	if err != nil || !reflect.DeepEqual(hub, f.hub) {
		t.Fatal("reopened Hub changed its independent original pin", err)
	}
	nodes, err := hubnodes.NewService(f.db, ids)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := hubtransport.LoadProfile(filepath.Join(f.root, "SYNTHETIC-hub-keys"), f.descriptorText)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", f.dial)
	if err != nil {
		t.Fatal("reopen owned synthetic TCP address", err)
	}
	f.http = httptest.NewUnstartedServer(server.NewHubNodesHandler(owner, auth, nodes))
	_ = f.http.Listener.Close()
	f.http.Listener = listener
	f.http.TLS = profile.TLSConfig()
	f.http.TLS.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return profile.TLSConfig(), nil }
	f.http.StartTLS()
}

type appUnbindPromotionProtector struct {
	*appvault.PasswordProtector
	armed, tripped bool
	writes         int
	candidate      appvault.AppDeviceCandidate
	complete       []byte
	result         []byte
}

// Discovery opens and closes the same fixture protector before profile resume.
// Its synthetic passphrase is owned and cleared by the test's final cleanup.
func (*appUnbindPromotionProtector) Close() {}

func (p *appUnbindPromotionProtector) ID() string {
	if p.armed {
		p.writes++
		if p.writes >= 2 {
			p.tripped = true
			return ""
		}
	}
	return p.PasswordProtector.ID()
}

type appUnbindPromotionHTTP struct {
	f         *scopedAppHTTPFixture
	base      *scopedAppHTTPProbe
	protector *appUnbindPromotionProtector
}

func (p *appUnbindPromotionHTTP) CloseIdleConnections() { p.base.CloseIdleConnections() }
func (p *appUnbindPromotionHTTP) Do(req *http.Request) (*http.Response, error) {
	response, err := p.base.Do(req)
	if err != nil || req.URL.Path != wire.AppBindingHTTPPath(wire.OperationAppRebindComplete) || response.StatusCode != http.StatusOK {
		return response, err
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	_ = response.Body.Close()
	if err != nil || len(raw) > 1<<20 {
		p.f.t.Fatal("actual rebind Complete response read failed", err)
	}
	response.Body = io.NopCloser(bytes.NewReader(raw))
	record := p.f.c.appBinding.rebind
	challenge, _, err := p.f.c.openAppBindingRecord(record)
	if err != nil {
		p.f.t.Fatal(err)
	}
	key, err := p.f.c.appBindingKey(record).E2EE()
	var result wire.AppBindingResult
	if err != nil || wire.OpenClientResponse(key, p.f.hub, record.CompletePacket, raw, &result) != nil ||
		wire.ValidateAppBindingResultTarget(result, record.CompletePacket, challenge.Binding) != nil || result.State != wire.AppBindingBoundZero {
		p.f.t.Fatal("promotion fault was not preceded by a genuine authenticated BOUND_ZERO response")
	}
	p.protector.candidate = p.f.c.appBinding.candidate
	p.protector.complete = bytes.Clone(record.CompletePacket)
	p.protector.result = bytes.Clone(raw)
	p.protector.armed = true
	return response, nil
}

func TestAppUnbindSoleOwnerRebindSavedCompletionColdPromotionWithoutPOST(t *testing.T) {
	f := newScopedAppHTTPFixture(t)
	oldOwner, oldDevice, oldKey := f.c.owner.Public(), f.c.state.DeviceID, f.c.device.Public()
	f.dispatch(appUnbindConfirm(f, ActionUnbindApp))
	if f.c.Snapshot().AppBinding.State != AppBindingUnbound || f.c.session != nil {
		t.Fatal("sole Owner did not reach authenticated UNBOUND")
	}
	if err := f.c.Close(); err != nil {
		t.Fatal(err)
	}
	password, err := appvault.NewPasswordProtector([]byte("SYNTHETIC scoped vault passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(password.Close)
	protector := &appUnbindPromotionProtector{PasswordProtector: password}
	defer func() { clear(protector.complete); clear(protector.result) }()
	root := filepath.Join(f.root, "SYNTHETIC-app-vault")
	controller, err := NewController(Config{OpenVault: func(_ context.Context, scope appvault.Scope, create bool) (*appvault.Vault, error) {
		if create {
			t.Fatal("promotion fault must reopen the existing protected vault")
		}
		path, err := scopeVaultPath(root, scope)
		if err != nil {
			return nil, err
		}
		return appvault.Open(path, scope, protector)
	}, DiscoverVaults: NewProfileDiscovery(root), DirectHTTPFactory: func(d hubtransport.Descriptor, dial string, timeout time.Duration) (HTTPDoer, error) {
		client, err := hubtransport.NewHTTPClient(d, dial, timeout)
		if err != nil {
			return nil, err
		}
		return &appUnbindPromotionHTTP{f: f, base: &scopedAppHTTPProbe{f: f, client: client}, protector: protector}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	f.c = controller.(*nativeController)
	f.dispatch(Action{Kind: ActionDiscoverProfiles})
	profiles := f.c.Snapshot().Profiles
	if len(profiles) != 1 {
		t.Fatal("sole unbound profile missing before promotion fault")
	}
	f.dispatch(Action{Kind: ActionResumeProfile, ProfileID: profiles[0].ID})
	if err := f.c.Dispatch(context.Background(), appUnbindConfirm(f, ActionRebindApp)); err == nil || !protector.tripped {
		t.Fatal("saved-completion-before-promotion fault did not fire")
	}
	posts := 0
	for _, count := range f.posts {
		posts += count
	}
	// Production storage failure closes the vault. Inspect durable state only
	// after a normal protected cold reopen; never depend on its RAM snapshot.
	f.restart()
	saved, _ := appUnbindSaved(f, appRebindNamespace)
	_, result, err := f.c.openAppBindingRecord(&saved)
	status, statusErr := f.c.vault.AppDeviceStatus()
	if err != nil || statusErr != nil || result == nil || result.State != wire.AppBindingBoundZero || status.Candidate == nil ||
		status.CurrentKeyID != oldKey.ID || status.Generation != 1 || status.Candidate.KeyID != saved.DeviceKeyID || status.Candidate.Generation != 2 ||
		*status.Candidate != protector.candidate || !bytes.Equal(saved.CompletePacket, protector.complete) || !bytes.Equal(saved.ResultPacket, protector.result) ||
		f.c.state.DeviceID != oldDevice || !reflect.DeepEqual(f.c.device.Public(), oldKey) {
		t.Fatal("fault did not retain the real saved completion, old current identity and same candidate", err, statusErr)
	}
	candidate := *status.Candidate
	complete := bytes.Clone(saved.CompletePacket)
	resultPacket := bytes.Clone(saved.ResultPacket)
	f.dispatch(Action{Kind: ActionRecoverAppBinding})
	status, err = f.c.vault.AppDeviceStatus()
	afterPosts := 0
	for _, count := range f.posts {
		afterPosts += count
	}
	if err != nil || afterPosts != posts || status.Generation != 2 || status.CurrentKeyID != candidate.KeyID || status.Candidate != nil ||
		len(status.Retired) != 1 || status.Retired[0].KeyID != oldKey.ID || !reflect.DeepEqual(f.c.owner.Public(), oldOwner) ||
		f.c.state.DeviceID == oldDevice || f.c.state.RootState != RootStateActive || f.c.session != nil || f.c.nodeConfirmation != nil || len(f.c.localTargets().Nodes) != 0 ||
		f.c.Snapshot().AppBinding.State != AppBindingBoundZero || f.c.Snapshot().Authorization.Confirmed {
		t.Fatal("cold promotion inherited authority, changed Owner or sent another POST", err)
	}
	archived, _, found, err := f.c.vault.LoadRetiredAppDeviceState(1, appRebindNamespace)
	defer clear(archived)
	var history appBindingRecord
	if err != nil || !found || decodeStateJSON(archived, &history) != nil || !bytes.Equal(history.CompletePacket, complete) || !bytes.Equal(history.ResultPacket, resultPacket) {
		t.Fatal("atomic promotion did not archive the exact saved completion", err)
	}
	f.restart()
	if f.c.session != nil || f.c.Snapshot().AppBinding.State != AppBindingBoundZero || f.c.device.Public().ID != candidate.KeyID {
		t.Fatal("cold BOUND_ZERO reopened old session or device generation")
	}
}

// These actors retain independent synthetic Endpoint private keys. They use
// real TLS, durable SQLite and current scoped NPT ACK; no Runtime is started.
type appUnbindEndpoint struct {
	key    *e2ee.Identity
	member wire.LocalDomainMember
}

type appUnbindTraffic struct {
	f           *scopedAppHTTPFixture
	node        *scopedAppNodeActor
	domain      wire.LocalDomainDescription
	ownerID     string
	ownerPublic e2ee.PublicIdentity
	sender      appUnbindEndpoint
	receiver    appUnbindEndpoint
	sequence    uint64
}

func newAppUnbindTraffic(t *testing.T, f *scopedAppHTTPFixture) *appUnbindTraffic {
	t.Helper()
	n := f.startNode("SYNTHETIC-unbind-existing-Node")
	f.approveNode(n)
	f.ackNode(n)
	f.dispatch(Action{Kind: ActionRefreshNodePairing})
	if n.binding == nil || f.c.scopedBusy() || f.c.nodeConfirmation != nil || f.c.Snapshot().Targets.SelectedNodeID != n.binding.NodeID {
		t.Fatal("current scoped Node ACK did not settle")
	}
	f.reportNodeUser(n)
	f.dispatch(Action{Kind: ActionRefreshLocalCollaboration})
	f.dispatch(Action{Kind: ActionPrepareLocalCollaboration, LocalCollaboration: LocalCollaborationAction{NewNetworkName: "SYNTHETIC unbind Network", GroupName: "SYNTHETIC existing Group"}})
	f.dispatch(Action{Kind: ActionActivateLocalCollaboration, LocalCollaboration: LocalCollaborationAction{ReviewID: f.c.Snapshot().LocalCollaboration.ReviewID, ConfirmActivation: true}})
	if f.c.localDomain.state.Description == nil {
		t.Fatal("real App did not retain the activated Group")
	}
	a := &appUnbindTraffic{f: f, node: n, domain: *f.c.localDomain.state.Description, ownerID: f.c.connection.OwnerID, ownerPublic: f.c.owner.Public()}
	a.sender = a.join("A")
	a.receiver = a.join("B")
	if a.sender.member.EndpointID == a.receiver.member.EndpointID || a.sender.member.NativeSessionID == a.receiver.member.NativeSessionID || reflect.DeepEqual(a.sender.key.Public(), a.receiver.key.Public()) {
		t.Fatal("synthetic independent Endpoint actors collided")
	}
	return a
}

func (a *appUnbindTraffic) join(label string) appUnbindEndpoint {
	t, f := a.f.t, a.f
	t.Helper()
	selection, err := wire.LocalDomainSelectionForPolicy(a.domain.Policy)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	var joined wire.LocalDomainNodeJoinResult
	f.nodeDomain(a.node, wire.OperationLocalDomainNodeJoin, wire.LocalDomainNodeJoin{ContractRevision: wire.LocalDomainContractRevision, Selection: selection, LocalUserScope: "uid:1000", AttemptID: attempt, Runtime: "codex", NativeSessionID: "SYNTHETIC-unbind-session-" + label, Workspace: "/SYNTHETIC-unbind-" + label, EndpointName: "SYNTHETIC unbind " + label}, &joined)
	key, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	m := joined.Member
	attestation, err := key.SignEndpointKeyAttestation(m.EndpointID, m.PrincipalID, m.NodeID, m.BindingID, m.BindingEpoch)
	if err != nil {
		t.Fatal(err)
	}
	a.http(http.MethodPost, "/v2/fabric/endpoint-keys", "CicadaSession "+joined.SessionToken, a.domain.Policy.GroupID, map[string]any{"attestation": json.RawMessage(attestation)}, http.StatusOK)
	var challenge wire.LocalDomainKeyChallenge
	f.nodeDomain(a.node, wire.OperationLocalDomainNodeKeyPrepare, wire.LocalDomainNodeKeyPrepare{ContractRevision: wire.LocalDomainContractRevision, Selection: selection, MemberID: m.MemberID, ExpectedRevision: m.Revision}, &challenge)
	proof, err := e2ee.SignLocalDomainEndpointKey(a.node.key, a.domain.Policy, challenge.Claims)
	if err != nil {
		t.Fatal(err)
	}
	var ready wire.LocalDomainNodeKeyResult
	f.nodeDomain(a.node, wire.OperationLocalDomainNodeKeyComplete, wire.LocalDomainNodeKeyComplete{ContractRevision: wire.LocalDomainContractRevision, Selection: selection, MemberID: m.MemberID, ExpectedRevision: m.Revision, ChallengeID: challenge.ChallengeID, NodeProof: proof}, &ready)
	if _, err = wire.VerifyLocalDomainEndpointKeyGrant(ready.Grant, f.hub, a.ownerID, a.ownerPublic, time.Now().UTC()); err != nil || ready.Member.EndpointID != m.EndpointID || ready.Member.State != wire.LocalDomainMemberActive || ready.Member.CandidateKeyID != key.Public().ID {
		t.Fatal("actual independent Endpoint grant", err)
	}
	return appUnbindEndpoint{key: key, member: ready.Member}
}

// Expected security denials are explicit HTTP statuses; a timeout, rate limit
// or malformed body cannot satisfy a denial assertion. Never log payloads.
func (a *appUnbindTraffic) http(method, path, authorization, group string, body any, want int) []byte {
	t, f := a.f.t, a.f
	t.Helper()
	var encoded []byte
	var err error
	if body != nil {
		encoded, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, f.origin+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Origin", f.origin)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if group != "" {
		req.Header.Set("Cicada-Group-Scope", group)
	}
	if err = f.pace(req.Context()); err != nil {
		t.Fatal(err)
	}
	response, err := f.client.Do(req)
	if err != nil {
		t.Fatal("actual synthetic traffic transport", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 || response.StatusCode != want {
		t.Fatalf("actual synthetic traffic %s status=%d want=%d read=%v", req.URL.Path, response.StatusCode, want, err)
	}
	return raw
}

func (a *appUnbindTraffic) base() string {
	return "/v2/relay/nodes/" + url.PathEscape(a.node.binding.NodeID) + "/group/sealed/"
}

func (a *appUnbindTraffic) peerPath() string {
	query := url.Values{"group_id": {a.domain.Policy.GroupID}, "source_endpoint_id": {a.sender.member.EndpointID}, "target_endpoint_id": {a.receiver.member.EndpointID}}
	return a.base() + "peer-key?" + query.Encode()
}

func (a *appUnbindTraffic) verifyEvidence(sender, receiver store.SameGroupSealedV1EndpointEvidence, current *wire.LocalDomainCurrent, operation, attempt string) {
	t := a.f.t
	t.Helper()
	if current == nil || sender.LocalDomainGrant == nil || receiver.LocalDomainGrant == nil || sender.EndpointID != a.sender.member.EndpointID || receiver.EndpointID != a.receiver.member.EndpointID ||
		!reflect.DeepEqual(sender.LocalDomainGrant.Member, a.sender.member) || !reflect.DeepEqual(receiver.LocalDomainGrant.Member, a.receiver.member) ||
		!reflect.DeepEqual(sender.LocalDomainGrant.Manifest.CandidatePublicIdentity, a.sender.key.Public()) || !reflect.DeepEqual(receiver.LocalDomainGrant.Manifest.CandidatePublicIdentity, a.receiver.key.Public()) {
		t.Fatal("actual current traffic evidence changed original Endpoint/key scope")
	}
	now := time.Now().UTC()
	for _, grant := range []*wire.LocalDomainEndpointKeyGrant{sender.LocalDomainGrant, receiver.LocalDomainGrant} {
		policy, err := wire.VerifyLocalDomainEndpointKeyGrant(*grant, a.f.hub, a.ownerID, a.ownerPublic, now)
		if err != nil || !reflect.DeepEqual(policy, a.domain.Policy) {
			t.Fatal("actual traffic grant failed the independent original Owner pin", err)
		}
	}
	if err := wire.ValidateLocalDomainCurrent(*current, a.domain.Policy, a.sender.member, a.receiver.member, operation, attempt, now); err != nil {
		t.Fatal("actual traffic current authorization", err)
	}
}

func (a *appUnbindTraffic) message(peer store.SameGroupSealedV1PeerKey, label string) (fabric.NodeSameGroupSealedV1SendInput, e2ee.EndpointMessageContext, []byte) {
	t := a.f.t
	t.Helper()
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	c := e2ee.EndpointMessageContext{MessageID: id, Kind: "SEND", SenderEndpointID: peer.Sender.EndpointID, SenderPrincipalID: peer.Sender.PrincipalID, SenderOwnerID: peer.Sender.OwnerID, SenderGroupID: a.domain.Policy.GroupID, SenderMembershipRevision: peer.Sender.MembershipRevision, SenderBindingEpoch: peer.Sender.BindingEpoch, SenderKeyID: a.sender.key.Public().ID, ReceiverEndpointID: peer.Receiver.EndpointID, ReceiverPrincipalID: peer.Receiver.PrincipalID, ReceiverOwnerID: peer.Receiver.OwnerID, ReceiverGroupID: a.domain.Policy.GroupID, ReceiverMembershipRevision: peer.Receiver.MembershipRevision, ReceiverBindingEpoch: peer.Receiver.BindingEpoch, ReceiverKeyID: a.receiver.key.Public().ID, TransportHubID: a.f.hub.HubID}
	plain := []byte("SYNTHETIC unbind acceptance SEND " + label)
	a.sequence++
	ciphertext, err := e2ee.SealEndpointMessage(a.sender.key, a.receiver.key.Public(), c, plain, a.sequence)
	if err != nil {
		t.Fatal(err)
	}
	return fabric.NodeSameGroupSealedV1SendInput{GroupID: a.domain.Policy.GroupID, SourceEndpointID: peer.Sender.EndpointID, TargetEndpointID: peer.Receiver.EndpointID, MessageID: id, DataScope: store.SameGroupSealedV1DataScope, Ciphertext: ciphertext}, c, plain
}

// Each call obtains fresh peer/current evidence, seals a new message, claims
// actual stored ciphertext and validates the exact delivery before decrypting.
func (a *appUnbindTraffic) sendAndOpen(label string) store.SameGroupSealedV1PeerKey {
	t := a.f.t
	t.Helper()
	auth := "CicadaNode " + a.node.token
	var peer store.SameGroupSealedV1PeerKey
	if json.Unmarshal(a.http(http.MethodGet, a.peerPath(), auth, "", nil, http.StatusOK), &peer) != nil || peer.NativePairEvidence != nil || peer.EndpointGroupCurrent != nil {
		t.Fatal("actual existing Group peer response")
	}
	a.verifyEvidence(peer.Sender, peer.Receiver, peer.LocalDomainCurrent, "peer_key", a.sender.member.EndpointID+":"+a.receiver.member.EndpointID)
	input, context, plain := a.message(peer, label)
	a.http(http.MethodPost, a.base()+"send", auth, "", input, http.StatusAccepted)
	var claimed struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	if json.Unmarshal(a.http(http.MethodPost, a.base()+"claim", auth, "", fabric.NodeClaimInput{ConsumerID: "SYNTHETIC-unbind-consumer", Limit: 16}, http.StatusOK), &claimed) != nil {
		t.Fatal("actual existing Group claim response")
	}
	var delivery *fabric.NodeSealedDelivery
	for i := range claimed.Deliveries {
		if claimed.Deliveries[i].MessageID == input.MessageID {
			if delivery != nil {
				t.Fatal("duplicate actual message claim")
			}
			delivery = &claimed.Deliveries[i]
		}
	}
	if delivery == nil || delivery.AttemptID == "" || delivery.RecipientEndpointID != a.receiver.member.EndpointID || !bytes.Equal(delivery.Ciphertext, input.Ciphertext) {
		t.Fatal("fresh actual ciphertext was not claimed by the original receiver")
	}
	path := a.base() + "deliveries/" + url.PathEscape(input.MessageID) + "/authorization?attempt_id=" + url.QueryEscape(delivery.AttemptID)
	var authorized store.SameGroupSealedV1DeliveryAuthorization
	if json.Unmarshal(a.http(http.MethodGet, path, auth, "", nil, http.StatusOK), &authorized) != nil || authorized.MessageID != input.MessageID || authorized.AttemptID != delivery.AttemptID || authorized.Digest != delivery.Digest {
		t.Fatal("actual final delivery authorization changed the original claim")
	}
	a.verifyEvidence(authorized.Sender, authorized.Receiver, authorized.LocalDomainCurrent, "native_delivery", delivery.AttemptID)
	opened, sequence, err := e2ee.OpenEndpointMessage(a.receiver.key, a.sender.key.Public(), context, delivery.Ciphertext)
	if err != nil || sequence != a.sequence || !bytes.Equal(opened, plain) {
		t.Fatal("actual claimed ciphertext did not decrypt under original Endpoint keys", err)
	}
	return peer
}

// Unlike nodeDomain, heartbeat is not a LocalDomain typed operation. Use the
// real SDK carrier and advance this original Node's replay sequence normally.
func (a *appUnbindTraffic) heartbeat(wantHTTP int) bool {
	t, f, n := a.f.t, a.f, a.node
	t.Helper()
	b := n.binding
	binding := nodewire.Binding{HubID: b.HubID, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, HubKeyVersion: b.HubNodeControlKeyVersion, NodeKeyVersion: b.NodeKeyVersion, NodeKey: b.NodePublic, HubKey: b.HubNodeControlPublic}
	id, err := wire.NewRequestID()
	if err != nil {
		t.Fatal(err)
	}
	n.sequence++
	route := nodewire.Route{Version: nodewire.Version, Direction: nodewire.DirectionRequest, HubID: b.HubID, NodeID: b.NodeID, BindingID: b.OwnerBindingID, BindingVersion: b.BindingVersion, NodeKeyEpoch: b.NodeKeyEpoch, Sequence: n.sequence, OperationID: id, Operation: "node.heartbeat", SenderKeyID: binding.NodeKey.ID, SenderKeyVersion: binding.NodeKeyVersion, ReceiverKeyID: binding.HubKey.ID, ReceiverKeyVersion: binding.HubKeyVersion}
	packet, err := nodewire.SealRequest(n.key, binding.HubKey, binding, route, []byte(`{"status":"ready"}`))
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, f.origin+"/v2/node/control/rpc", bytes.NewReader(packet))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.origin)
	req.Header.Set("Authorization", "CicadaNode "+n.token)
	if err := f.pace(req.Context()); err != nil {
		t.Fatal(err)
	}
	response, err := f.client.Do(req)
	if err != nil {
		t.Fatal("actual fresh Node heartbeat transport", err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil || len(raw) > 1<<20 || response.StatusCode != wantHTTP {
		t.Fatalf("actual fresh Node heartbeat status=%d want=%d read=%v", response.StatusCode, wantHTTP, err)
	}
	if wantHTTP != http.StatusOK {
		return false
	}
	opened, err := nodewire.OpenResponse(n.key, binding.HubKey, binding, raw)
	if err != nil {
		t.Fatal("actual Node heartbeat authentication", err)
	}
	want := route
	want.Direction = nodewire.DirectionResponse
	want.SenderKeyID, want.ReceiverKeyID = route.ReceiverKeyID, route.SenderKeyID
	want.SenderKeyVersion, want.ReceiverKeyVersion = route.ReceiverKeyVersion, route.SenderKeyVersion
	var reply struct {
		OK          bool   `json:"ok"`
		ErrorCode   string `json:"error_code"`
		OperationID string `json:"operation_id"`
		Sequence    uint64 `json:"sequence"`
	}
	if opened.Route != want || json.Unmarshal(opened.Plaintext, &reply) != nil || reply.OperationID != id || reply.Sequence != n.sequence {
		t.Fatal("actual fresh Node heartbeat reply target")
	}
	return reply.OK
}
