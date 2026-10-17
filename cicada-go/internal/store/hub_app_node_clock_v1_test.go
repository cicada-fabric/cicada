package store

import (
	"bytes"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestN3StoreQueuedOwnerPreviewUsesTransactionTime(t *testing.T) {
	f := n3Fixture(t, true)
	arrival := time.Now().UTC()
	p, err := wire.NewAppNodePrepare(f.session, f.scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: f.code}, f.owner, arrival)
	if err != nil {
		t.Fatal(err)
	}
	var intent e2ee.OwnerAppNodePreview
	if err = json.Unmarshal(p.OwnerIntent, &intent); err != nil {
		t.Fatal(err)
	}
	deadline := arrival.Add(time.Second)
	intent.Claims.ExpiresAt = appNodeStamp(deadline)
	p.OwnerIntent, err = e2ee.SignOwnerAppNodePreview(f.owner, intent.Claims)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := f.input(t, p, arrival)
	in.Now = time.Now
	type response struct {
		packet []byte
		err    error
	}
	done := make(chan response, 1)
	started := make(chan struct{})
	f.db.mu.Lock()
	go func() {
		close(started)
		packet, err := f.db.ProcessHubAppNodeAuthority(in, seal)
		done <- response{packet, err}
	}()
	<-started
	time.Sleep(time.Until(deadline.Add(10 * time.Millisecond)))
	f.db.mu.Unlock()
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	out, err := wire.OpenAppNodeResponse(f.device, f.hub, in.Packet, got.packet)
	if err != nil {
		t.Fatal(err)
	}
	if out.Challenge != nil || out.Result == nil || out.Result.State != wire.AppNodeRejectedFenced {
		t.Fatal("queued expired Owner preview was admitted after its deadline")
	}
	observed, err := time.Parse(time.RFC3339Nano, out.Result.ObservedAt)
	if err != nil || observed.Before(deadline) {
		t.Fatal("admission used pre-writer time", err)
	}
	var grants int
	if err = f.db.db.QueryRow(`SELECT count(*) FROM hub_app_node_grants_v1`).Scan(&grants); err != nil || grants != 0 {
		t.Fatal("expired preview created authority", err)
	}
	retry, err := f.db.ProcessHubAppNodeAuthority(in, seal)
	if err != nil || !bytes.Equal(got.packet, retry) {
		t.Fatal("expired preview rejection was not durable exact retry", err)
	}
}

func TestN3StoreQueuedClientUsesTransactionSessionAndLease(t *testing.T) {
	for _, kind := range []string{"session", "lease"} {
		t.Run(kind, func(t *testing.T) {
			f := n3Fixture(t, true)
			admission := f.now.Add(16 * time.Minute)
			want := "AUTHORITY_EXPIRED"
			if kind == "session" {
				f.scope.AccountSessionExpiresAt = appNodeStamp(f.now.Add(4 * time.Second))
				if _, err := f.db.db.Exec(`UPDATE hub_account_sessions_v1 SET expires_at=?`, f.scope.AccountSessionExpiresAt); err != nil {
					t.Fatal(err)
				}
				admission, want = f.now.Add(5*time.Second), "SESSION_REQUIRED"
			}
			g := f.activate(t)
			in := f.client(t, g, 1, f.now.Add(2*time.Second))
			var released atomic.Bool
			in.Now = func() time.Time {
				if !released.Load() {
					return time.Time{}
				}
				return admission
			}
			type response struct {
				packet []byte
				err    error
			}
			done, started := make(chan response, 1), make(chan struct{})
			f.db.mu.Lock()
			go func() {
				close(started)
				packet, err := f.db.ProcessHubAppNodeClient(in)
				done <- response{packet, err}
			}()
			<-started
			released.Store(true)
			f.db.mu.Unlock()
			got := <-done
			if got.err != nil {
				t.Fatal(got.err)
			}
			out, err := wire.OpenAppNodeConfirmationResponse(f.device, f.hub, g, in.Packet, got.packet, 1)
			if err != nil || out.OK || out.Binding != nil || out.Error != want {
				t.Fatal("queued confirmation ignored transaction deadline", out.Error, err)
			}
			var bindings, remaining int
			if err = f.db.db.QueryRow(`SELECT count(*) FROM node_owner_bindings_v2`).Scan(&bindings); err != nil || bindings != 0 {
				t.Fatal("expired admission created Node effect", err)
			}
			if err = f.db.db.QueryRow(`SELECT remaining FROM hub_app_node_grants_v1 WHERE grant_id=?`, g.GrantID).Scan(&remaining); err != nil || remaining != 1 {
				t.Fatal("expired admission consumed success budget", err)
			}
			retry, err := f.db.ProcessHubAppNodeClient(in)
			if err != nil || !bytes.Equal(got.packet, retry) {
				t.Fatal("queued denial lost exact sealed retry", err)
			}
			device, err := f.db.GetClientDevice(f.scope.OwnerID, f.scope.DeviceID)
			if err != nil || device.LastRequestSeq != 1 || device.NextResponseSeq != 2 {
				t.Fatal("denial retry consumed another counter", err)
			}
		})
	}
}

func TestN3StoreTransactionClockZeroFailsClosed(t *testing.T) {
	f := n3Fixture(t, true)
	p, err := wire.NewAppNodePrepare(f.session, f.scope, wire.AppNodePrepareTarget{Kind: wire.AppNodeTargetInitial, Code: f.code}, f.owner, f.now)
	if err != nil {
		t.Fatal(err)
	}
	in, seal := f.input(t, p, f.now)
	in.Now = func() time.Time { return time.Time{} }
	if _, err = f.db.ProcessHubAppNodeAuthority(in, seal); err == nil {
		t.Fatal("zero transaction clock admitted Owner preview")
	}
	g := f.activate(t)
	client := f.client(t, g, 1, f.now.Add(2*time.Second))
	client.Now = in.Now
	if _, err = f.db.ProcessHubAppNodeClient(client); err == nil {
		t.Fatal("zero transaction clock admitted Node confirmation")
	}
}
