package n3_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubauth"
	"github.com/cicada-ai/cicada/internal/hubidentity"
)

// These tests validate fault/process infrastructure using frozen N2 packets.
// They make no claims about pending N3 protocol, production App or Node actors.
func preparationPacket(t *testing.T, f *hubFixture) (*e2ee.Identity, []byte) {
	t.Helper()
	device, owner := must(e2ee.NewIdentity()), must(e2ee.NewIdentity())
	now := time.Now().UTC()
	id := wire.AccountDeviceIDPrefix + must(wire.NewRequestID())
	grant := must(owner.SignOwnerDeviceGrant(f.cfg.Material.OwnerID, id, device.Public(), f.cfg.Hub.HubID, e2ee.OwnerDevicePurposeControl, now, now.Add(5*time.Minute)))
	request := must(wire.NewActivationPrepare(f.cfg.Material, f.cfg.Hub, device.Public(), owner.Public(), id, grant, now))
	packet := must(wire.SealClientRequest(device, f.cfg.Hub, request))
	atomicPrivate(t, filepath.Join(f.dir, "synthetic-request.packet"), packet)
	return device, packet
}

func checkpoint(t *testing.T, f *hubFixture, name, path string) (packetCheckpoint, []byte, int) {
	t.Helper()
	marker := filepath.Join(f.dir, name+".json")
	p := startPacketProcess(t, f, f.proxy.server.URL, path, marker)
	awaitMarker(t, p, marker)
	pid := p.cmd.Process.Pid
	p.kill(t)
	var got packetCheckpoint
	readJSON(t, marker, &got)
	if got.TransportError {
		return got, nil, pid
	}
	return got, readPrivate(t, filepath.Join(f.dir, "synthetic-response.packet")), pid
}

func TestN3HarnessRealHubReplyRecovery(t *testing.T) {
	for _, mode := range []string{"before-forward", "drop-after-response", "unsigned-403", "corrupt-response"} {
		t.Run(mode, func(t *testing.T) {
			f := newHubFixture(t)
			device, original := preparationPacket(t, f)
			defer clear(original)
			path := wire.ActivationHTTPPath(wire.OperationActivationPrepare)
			f.proxy.arm(path, mode, 1)
			first, badResponse, firstPID := checkpoint(t, f, "first", path)
			defer clear(badResponse)
			trace := f.proxy.snapshot()
			if len(trace) != 1 || first.PacketSHA256 != hash(original) || trace[0].RequestSHA256 != hash(original) {
				t.Fatal("fault did not target the exact persisted encrypted request")
			}
			if mode == "before-forward" && trace[0].Forwarded {
				t.Fatal("before-forward fault reached Hub")
			}
			if mode != "before-forward" && (!trace[0].Forwarded || trace[0].Status != 200) {
				t.Fatal("response fault did not follow a successful actual Hub response")
			}
			var untrusted wire.ActivationChallenge
			if !first.TransportError && first.Status == 200 && wire.OpenClientResponse(device, f.cfg.Hub, original, badResponse, &untrusted) == nil {
				t.Fatal("corrupt response remained authenticated")
			}
			oldHubPID := f.hub.cmd.Process.Pid
			f.hub.kill(t)
			db := f.db(t)
			activation := must(db.HubActivation(f.cfg.Material.ActivationID))
			want := wire.ActivationPrepared
			if mode == "before-forward" {
				want = wire.ActivationIssued
			}
			setup, _, err := db.HubAccountSetup()
			if err != nil || activation == nil || activation.State != want || setup.RootEverEstablished {
				t.Fatal("actual persisted Hub effect differs from fault position")
			}
			db.Close()
			f.start(t)
			second, response, secondPID := checkpoint(t, f, "second", path)
			defer clear(response)
			if firstPID == secondPID || oldHubPID == f.hub.cmd.Process.Pid || second.TransportError || second.Status != 200 {
				t.Fatal("real child-process kill/restart/recovery did not complete")
			}
			pending := readPrivate(t, filepath.Join(f.dir, "synthetic-pending.packet"))
			defer clear(pending)
			if !bytes.Equal(pending, original) || second.PacketSHA256 != hash(original) {
				t.Fatal("restarted packet harness replaced its pending original")
			}
			var challenge wire.ActivationChallenge
			if wire.OpenClientResponse(device, f.cfg.Hub, original, response, &challenge) != nil {
				t.Fatal("recovered Hub response failed real PQ authentication")
			}
			if mode != "before-forward" && !bytes.Equal(trace[0].response, response) {
				t.Fatal("committed response was regenerated rather than recovered exactly")
			}
			t.Logf("HARNESS_ONLY realHub=true packetClientIsApp=false request_sha256=%s response_sha256=%s", hash(original), hash(response))
		})
	}
}

func TestN3HarnessDelayedPacketCancellation(t *testing.T) {
	f := newHubFixture(t)
	device, original := preparationPacket(t, f)
	defer clear(original)
	path := wire.ActivationHTTPPath(wire.OperationActivationPrepare)
	entered, release := f.proxy.arm(path, "hold-before-forward", 1)
	defer release()
	marker := filepath.Join(f.dir, "delayed.json")
	packetProcess := startPacketProcess(t, f, f.proxy.server.URL, path, marker)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("delayed original never reached the controlled barrier")
	}
	f.hub.kill(t)
	db := f.db(t)
	ids := must(hubidentity.LoadOrCreate(filepath.Join(f.dir, "synthetic-hub"), ""))
	auth := must(hubauth.NewService(db, ids))
	must(auth.IssueActivationLocal(wire.PurposeInitialActivation, "", "", true))
	db.Close()
	f.start(t)
	release()
	awaitMarker(t, packetProcess, marker)
	packetProcess.kill(t)
	var checkpoint packetCheckpoint
	readJSON(t, marker, &checkpoint)
	response := readPrivate(t, filepath.Join(f.dir, "synthetic-response.packet"))
	defer clear(response)
	var cancelled wire.ActivationResult
	if checkpoint.Status != 200 || wire.OpenClientResponse(device, f.cfg.Hub, original, response, &cancelled) != nil || cancelled.State != wire.ActivationCancelled {
		t.Fatal("late N2 original crossed its durable cancellation after Hub restart")
	}
	f.hub.kill(t)
	db = f.db(t)
	defer db.Close()
	state := must(db.HubActivation(f.cfg.Material.ActivationID))
	setup, _, err := db.HubAccountSetup()
	if err != nil || state.State != wire.ActivationCancelled || setup.RootEverEstablished {
		t.Fatal("delayed packet changed authority after cancellation")
	}
	t.Logf("HARNESS_ONLY delayed_original=true N2_material_cancellation_not_N3_fence=true request_sha256=%s response_sha256=%s", hash(original), hash(response))
}

func TestN3HarnessCommitBeforeReplyCrashWindow(t *testing.T) {
	f := newHubFixture(t)
	device, original := preparationPacket(t, f)
	defer clear(original)
	path := wire.ActivationHTTPPath(wire.OperationActivationPrepare)
	entered, release := f.proxy.arm(path, "hold-after-response", 1)
	defer release()
	marker := filepath.Join(f.dir, "must-not-receive.json")
	client := startPacketProcess(t, f, f.proxy.server.URL, path, marker)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("actual Hub response never reached the pre-delivery barrier")
	}
	// Hub has committed and supplied its response to the proxy, but the packet
	// sender has received no response and written no result checkpoint.
	client.kill(t)
	f.hub.kill(t)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("packet sender observed a response before the crash window")
	}
	db := f.db(t)
	state := must(db.HubActivation(f.cfg.Material.ActivationID))
	if state == nil || state.State != wire.ActivationPrepared {
		t.Fatal("pre-reply crash window lacked a real committed Hub effect")
	}
	db.Close()
	trace := f.proxy.snapshot()
	if len(trace) != 1 || !trace[0].Forwarded || trace[0].Status != 200 {
		t.Fatal("pre-reply crash window did not capture the real response")
	}
	release()
	f.start(t)
	got, response, _ := checkpoint(t, f, "crash-recovered", path)
	defer clear(response)
	var challenge wire.ActivationChallenge
	if got.TransportError || got.Status != 200 || !bytes.Equal(response, trace[0].response) ||
		wire.OpenClientResponse(device, f.cfg.Hub, original, response, &challenge) != nil {
		t.Fatal("post-crash exact receipt recovery failed")
	}
	t.Logf("HARNESS_ONLY committed_before_delivery=true actualHubKilled=true packetClientIsApp=false request_sha256=%s response_sha256=%s", hash(original), hash(response))
}
