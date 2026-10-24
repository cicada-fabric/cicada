package n3_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

type nodePairUnapproved struct {
	key     *e2ee.Identity
	context wire.NodePairTrustContext
	start   wire.NodePairTrustStart
	packet  []byte
	o       string
}

// An independent unapproved protocol adversary, never an actual-Node positive
// onboarding substitute. It signs real possession and uses actual Hub TCP.
func nodePairUnapprovedStart(t *testing.T, v *nodePairFixture, client *http.Client, id string, lifetime time.Duration) (*nodePairUnapproved, int) {
	t.Helper()
	key := must(e2ee.NewIdentity())
	now := time.Now().UTC()
	d := v.hub.descriptor.Claims
	body := wire.NodePairTrustStart{Format: wire.NodePairTrustFormat, Hub: d.Hub, Origin: d.Origin,
		DescriptorDigest: wire.NodePairTrustDescriptorDigest(must(hubtransportText(v))), NodeID: id, NodeName: "SYNTHETIC unapproved " + strings.Repeat("<", 100),
		CredentialDigest: base64.RawURLEncoding.EncodeToString(must(wire.NewNonce())), RequestNonce: must(wire.NewNonce()),
		HubNodeControlPublic: d.NodeControl, HubNodeControlKeyVersion: d.NodeControlKeyVersion,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(lifetime).Format(time.RFC3339Nano)}
	transcript := must(nodewire.PairingProofTranscript(nodewire.PairingProofContext{HubID: d.Hub.HubID, NodeID: id, RequestNonce: body.RequestNonce,
		CredentialDigest: body.CredentialDigest, NodePublicIdentity: key.Public(), HubPublicIdentity: d.NodeControl, HubKeyVersion: d.NodeControlKeyVersion}))
	body.PairingProof = must(e2ee.Seal(key, d.NodeControl, transcript, nodewire.PairingProofAAD(), 1))
	header := wire.NodePairTrustPacket{Operation: wire.OperationNodePairTrustStart, RequestID: must(wire.NewRequestID()), AttemptID: must(wire.NewRequestID())}
	packet := must(wire.SealNodePairTrustRequest(key, d.Hub, header, body, now))
	result := nodePairHTTP(client, d.Origin, wire.NodePairTrustHTTPPath(header.Operation), packet)
	defer clear(result.response)
	if result.err != nil {
		clear(packet)
		t.Fatal("owned unapproved actor did not receive a bounded real TCP outcome")
	}
	if result.status != http.StatusOK {
		return &nodePairUnapproved{key: key, start: body, packet: packet}, result.status
	}
	opened := must(wire.OpenNodePairTrustResponse(key, d.Hub, packet, result.response, body))
	if opened.Context == nil || opened.State != wire.NodePairTrustPending || opened.ErrorCode != "" {
		clear(packet)
		t.Fatal("unapproved actor received an unauthenticated or nonpending actual context")
	}
	secret := must(wire.NewNonce())
	defer clear(secret)
	o := must(wire.NodePairTrustOOBCommitment(must(wire.NodePairTrustContextDigest(*opened.Context)), secret))
	return &nodePairUnapproved{key: key, context: *opened.Context, start: body, packet: packet, o: o}, result.status
}

func hubtransportText(v *nodePairFixture) (string, error) {
	return hubtransport.EncodeDescriptor(v.hub.descriptor)
}

func nodePairUnapprovedRequest(t *testing.T, v *nodePairFixture, client *http.Client, a *nodePairUnapproved, op string) (wireHTTPResult, wire.NodePairTrustCommit, []byte) {
	t.Helper()
	body := wire.NodePairTrustCommit{Format: wire.NodePairTrustFormat, Context: a.context, OOBCommitment: a.o, IssuedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	packet := must(wire.SealNodePairTrustRequest(a.key, v.hub.descriptor.Claims.Hub,
		wire.NodePairTrustPacket{Operation: op, RequestID: must(wire.NewRequestID()), AttemptID: a.context.AttemptID}, body, time.Now().UTC()))
	return nodePairHTTP(client, a.context.Origin, wire.NodePairTrustHTTPPath(op), packet), body, packet
}

func nodePairResourceBudget(t *testing.T, v *nodePairFixture) (int, int, int, int) {
	t.Helper()
	db := nodePairReadOnlyDB(t, filepath.Join(v.hub.state, "cicada.sqlite3"))
	defer db.Close()
	var anonymous, anonymousBytes, reads, readBytes int
	if db.QueryRow(`SELECT anonymous_rows,anonymous_bytes,read_rows,read_bytes FROM hub_node_pair_trust_budget_v1 WHERE id=1`).Scan(&anonymous, &anonymousBytes, &reads, &readBytes) != nil ||
		anonymous < 0 || anonymous > 512 || anonymousBytes < 0 || anonymousBytes > 16<<20 || reads < 0 || reads > 4096 || readBytes < 0 || readBytes > 16<<20 {
		t.Fatal("actual unapproved/read resource classes escaped their delivered hard bounds")
	}
	return anonymous, anonymousBytes, reads, readBytes
}

func nodePairApprovedACKUnderPressure(t *testing.T) {
	v := newNodePairFixture(t, "127.0.0.1")
	v.node.kill(t)
	v.approve(t)
	v.app.command(t, directIPAppCommand{Close: true})
	before := v.admission(t)
	// Restore inspection must fail closed with real NPT state, not silently
	// treat reservations/receipts as an already reviewed schema-68 restore.
	v.hub.hub.kill(t)
	path := filepath.Join(v.hub.state, "cicada.sqlite3")
	dbBefore := must(os.ReadFile(path))
	dbHash := hash(dbBefore)
	clear(dbBefore)
	checkpoint, err := store.InspectHubRestoreCheckpointReadOnly(v.hub.state)
	if checkpoint != nil || !errors.Is(err, store.ErrHubRestoreCoverage) {
		t.Fatal("real nonempty NPT state escaped the deliberately unreviewed restore fence")
	}
	dbAfter := must(os.ReadFile(path))
	unchanged := hash(dbAfter) == dbHash
	clear(dbAfter)
	if !unchanged || v.admission(t) != before {
		t.Fatal("read-only unsupported restore inspection changed original state/counters/receipts")
	}
	v.hub.start(t)
	client := v.protocolClient(t)
	deadline := time.Now().Add(200 * time.Second)
	requests, subjects, refused := 0, 0, false
	for subjects < 700 && time.Now().Before(deadline) {
		// Honor the unchanged global account service bucket (4/s). Fresh
		// unapproved START receipts live with their immutable candidate window,
		// so real bounded storage can fill without bypassing that rate guard
		// or racing the two-minute ordinary-poll cache GC.
		time.Sleep(260 * time.Millisecond)
		a, status := nodePairUnapprovedStart(t, v, client, fmt.Sprintf("synthetic-owned-pressure-%02d", subjects), 10*time.Minute)
		requests++
		if status != http.StatusOK {
			defer clear(a.packet)
			anonymous, anonymousBytes, reads, readBytes := nodePairResourceBudget(t, v)
			if status == http.StatusForbidden {
				// The retained Node candidate writer has an earlier 256-create
				// window bound. Observe that exact production bound instead of
				// bypassing it to force the newer, higher storage limits.
				db := nodePairReadOnlyDB(t, path)
				var creates int
				if db.QueryRow(`SELECT count(*) FROM node_control_key_requests_v1 WHERE created_at>=?`, time.Now().UTC().Add(-10*time.Minute).Format(time.RFC3339Nano)).Scan(&creates) != nil || creates != 256 || subjects != 255 {
					t.Fatalf("unapproved START refusal did not reach the actual creation-window bound: HTTP=%d creates=%d subjects=%d", status, creates, subjects)
				}
				// Separate a persistent hard bound from the unchanged 4/s
				// service bucket, retrying exactly the refused original packet.
				time.Sleep(1100 * time.Millisecond)
				retry := nodePairHTTP(client, v.hub.material.Origin, wire.NodePairTrustHTTPPath(wire.OperationNodePairTrustStart), a.packet)
				requests++
				clear(retry.response)
				if retry.err != nil || retry.status != http.StatusForbidden {
					t.Fatal("creation-window hard bound was only a transient service-rate refusal")
				}
				t.Log("NODE_PAIR_RESOURCE_BOUND actual_legacy_create_window=256 exact_original_after_quiet_refused=true newer_storage_budgets_within_limits=true")
			} else if status != http.StatusServiceUnavailable || (anonymous < 500 && anonymousBytes < 15<<20 && reads < 4000 && readBytes < 15<<20) {
				t.Fatalf("unapproved pressure stopped without observing an actual hard bound: HTTP=%d anonymous=%d anonymous_bytes=%d reads=%d read_bytes=%d", status, anonymous, anonymousBytes, reads, readBytes)
			}
			refused = true
			break
		}
		subjects++
		clear(a.packet)
		nodePairResourceBudget(t, v)
	}
	if !refused || requests < 100 || subjects < 2 || v.admission(t) != before {
		t.Fatal("owned pressure did not reach its actual bound while preserving the approved original")
	}
	_, _, reads, readBytes := nodePairResourceBudget(t, v)
	v.start(t) // The real Node, not a wire actor, must settle under the pressure.
	v.awaitHubACK(t)
	v.assertAutomaticOwnerPin(t, v.original)
	after := v.admission(t)
	if after.ownerBindings != 1 || after.keyBindings != 1 || after.remaining != 0 || after.slotState != "DONE" ||
		after.lastRequest != before.lastRequest+1 || after.nextResponse != before.nextResponse+1 || after.slotDigest != before.slotDigest {
		t.Fatal("approved actual Node ACK was blocked by unapproved reads or duplicated original settlement")
	}
	t.Logf("NODE_PAIR_RESOURCE_PRESSURE owned_requests=%d owned_subjects=%d bounded_read_rows=%d bounded_read_bytes=%d approved_actual_Node_ACK=true", requests, subjects, reads, readBytes)
}

func nodePairStrictExpiry(t *testing.T) {
	v := newNodePairFixture(t, "127.0.0.1")
	v.node.kill(t)
	client := v.protocolClient(t)
	// The actual legacy candidate writer requires at least one minute; keep
	// that production guard and wait for the real original deadline.
	a, status := nodePairUnapprovedStart(t, v, client, "synthetic-short-expiry-protocol-actor", 65*time.Second)
	if status != http.StatusOK || a == nil {
		t.Fatalf("short-expiry protocol adversary could not create its real original candidate: HTTP=%d", status)
	}
	defer clear(a.packet)
	commit, _, raw := nodePairUnapprovedRequest(t, v, client, a, wire.OperationNodePairTrustCommit)
	clear(raw)
	clear(commit.response)
	if commit.err != nil || commit.status != http.StatusOK {
		t.Fatal("short-expiry candidate could not commit its own O before expiry")
	}
	end := must(time.Parse(time.RFC3339Nano, a.context.ExpiresAt))
	if wait := time.Until(end.Add(30 * time.Millisecond)); wait > 0 {
		time.Sleep(wait)
	}
	result, body, packet := nodePairUnapprovedRequest(t, v, client, a, wire.OperationNodePairTrustPoll)
	defer clear(packet)
	defer clear(result.response)
	if result.err != nil || result.status != http.StatusOK {
		t.Fatal("fresh historical-context poll could not observe strict current expiry")
	}
	opened := must(wire.OpenNodePairTrustResponse(a.key, v.hub.descriptor.Claims.Hub, packet, result.response, body))
	if opened.State != wire.NodePairTrustExpired || opened.Binding != nil || len(opened.TrustCapsule) != 0 {
		t.Fatal("expired original candidate retained fresh admission rights")
	}
	// A new envelope under the same attempt cannot renew its original times.
	renewed := a.start
	renewed.IssuedAt = time.Now().UTC().Format(time.RFC3339Nano)
	renewed.ExpiresAt = time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano)
	changed := must(wire.SealNodePairTrustRequest(a.key, renewed.Hub, wire.NodePairTrustPacket{Operation: wire.OperationNodePairTrustStart,
		RequestID: must(wire.NewRequestID()), AttemptID: a.context.AttemptID}, renewed, time.Now().UTC()))
	defer clear(changed)
	refused := nodePairHTTP(client, renewed.Origin, wire.NodePairTrustHTTPPath(wire.OperationNodePairTrustStart), changed)
	defer clear(refused.response)
	if refused.err != nil || refused.status != http.StatusForbidden {
		t.Fatal("same attempt reissued a fresh deadline/selector after strict expiry")
	}
	db := nodePairReadOnlyDB(t, filepath.Join(v.hub.state, "cicada.sqlite3"))
	var saved []byte
	if db.QueryRow(`SELECT context_json FROM hub_node_pair_trust_v1 WHERE attempt_id=?`, a.context.AttemptID).Scan(&saved) != nil || !bytes.Equal(saved, must(json.Marshal(a.context))) {
		t.Fatal("strict expiry/retry replaced the immutable original context")
	}
}

func nodePairCurrentRevocationFence(t *testing.T, epoch bool) {
	v := newNodePairFixture(t, "127.0.0.1")
	v.node.kill(t)
	v.approve(t)
	v.app.command(t, directIPAppCommand{Close: true})
	original, _ := v.side(t)
	before := v.admission(t)
	v.hub.hub.kill(t)
	db := must(store.New(filepath.Join(v.hub.state, "cicada.sqlite3")))
	device := must(db.GetClientDevice(v.original.Account.OwnerID, v.original.Account.DeviceID))
	if epoch {
		must(db.AdvanceClientDeviceSessionEpoch(device.OwnerID, device.DeviceID, device.SessionEpoch))
	} else {
		must(db.RevokeClientDevice(device.OwnerID, device.DeviceID, device.Version))
	}
	db.Close()
	v.hub.start(t)
	v.start(t)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		current, state := v.side(t)
		if !reflect.DeepEqual(current, original) {
			t.Fatal("revocation/epoch fence regenerated the original candidate or deadline")
		}
		if state == wire.NodePairTrustRevoked {
			break
		}
		if state != wire.NodePairTrustOwnerApproved || !v.node.running() {
			t.Fatal("actual Node failed before observing the current revocation fence")
		}
		time.Sleep(20 * time.Millisecond)
	}
	after := v.admission(t)
	if after.state != wire.NodePairTrustRevoked || after.ownerBindings != 0 || after.keyBindings != 0 || after.required != 1 ||
		after.clientRows != before.clientRows || !epoch && (after.lastRequest != before.lastRequest || after.nextResponse != before.nextResponse) {
		t.Fatal("current revoked device/stale epoch allowed original Node admission or Client receipt effects")
	}
}

func nodePairCodeLimitsExpiryRevocation(t *testing.T) {
	nodePairStrictExpiry(t)
	nodePairCurrentRevocationFence(t, false)
	nodePairCurrentRevocationFence(t, true)
	nodePairApprovedACKUnderPressure(t)
	nodePairFacts(t, "NPT06_CodeLimitsExpiryRevocation", map[string]bool{"bounded_attempts_and_resources": true,
		"approved_ACK_settles_under_unapproved_pressure": true, "strict_immutable_expiry": true,
		"current_revocation_and_epoch_fences": true, "restore_unknown_no_ACK_bypass": true, "no_deadline_renewal": true})
}
