package appcore

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodekeys"
)

func TestOwnerPublicExportUsesLocalKeysAndPreservesExistingFile(t *testing.T) {
	f := newNodeActorFixture(t)
	path := filepath.Join(t.TempDir(), "owner-public.json")
	public := f.c.owner.Public()
	fingerprint, err := nodekeys.PeerKeyFingerprint(public)
	if err != nil {
		t.Fatal(err)
	}
	s := f.c.Snapshot()
	if s.Account.LocalOwnerKeyID != public.ID || s.Account.OwnerPeerFingerprint != fingerprint || !containsAction(s.AvailableActions, ActionExportOwnerPublic) {
		t.Fatal("local Owner pin unavailable")
	}
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionExportOwnerPublic, PublicExportPath: path}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	var got e2ee.PublicIdentity
	if json.Unmarshal(raw, &got) != nil || !reflect.DeepEqual(got, public) {
		t.Fatal("export was not the local original public identity")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != 3 || fields["id"] == nil || fields["kem_public"] == nil || fields["signing_public"] == nil {
		t.Fatal("export contained extra state")
	}
	if err := f.c.Dispatch(context.Background(), Action{Kind: ActionExportOwnerPublic, PublicExportPath: path}); err == nil {
		t.Fatal("export replaced an existing user file")
	}
	again, _ := os.ReadFile(path)
	defer clear(again)
	if !bytes.Equal(raw, again) {
		t.Fatal("existing file changed")
	}
	f.n2.now = f.n2.now.Add(20 * time.Minute)
	other := filepath.Join(t.TempDir(), "expired.json")
	if f.c.Dispatch(context.Background(), Action{Kind: ActionExportOwnerPublic, PublicExportPath: other}) == nil {
		t.Fatal("expired session exported identity")
	}
	if _, err := os.Stat(other); !os.IsNotExist(err) {
		t.Fatal("expired action created a file")
	}
}

func TestOwnerPublicFingerprintMatchesNodePinAndRejectsMalformedIdentity(t *testing.T) {
	key, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	public := key.Public()
	for _, p := range []e2ee.PublicIdentity{public, {}, {ID: public.ID, KEMPublic: public.KEMPublic[:1], SigningPublic: public.SigningPublic}, {ID: public.ID, KEMPublic: public.KEMPublic, SigningPublic: public.SigningPublic[:1]}} {
		got, err := ownerPeerKeyFingerprint(p)
		want, oracleErr := nodekeys.PeerKeyFingerprint(p)
		if (err == nil) != (oracleErr == nil) || got != want {
			t.Fatal("App fingerprint differs from the existing Node pin implementation")
		}
	}
}
