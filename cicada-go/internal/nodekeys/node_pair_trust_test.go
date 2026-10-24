package nodekeys

import (
	"errors"
	"sync"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func TestNodePairOwnerTrustRejectsEveryOtherKeyIDAndRevocation(t *testing.T) {
	state, err := OpenCryptoState(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	a, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	afp, _ := PeerKeyFingerprint(a.Public())
	bfp, _ := PeerKeyFingerprint(b.Public())
	first, err := state.TrustOwnerApprovalKeyForPairLocal("SYNTHETIC-owner", a.Public().ID, a.Public(), afp)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := state.TrustOwnerApprovalKeyForPairLocal("SYNTHETIC-owner", a.Public().ID, a.Public(), afp)
	if err != nil || retry.Version != first.Version {
		t.Fatal("exact trust changed", err)
	}
	if _, err := state.TrustOwnerApprovalKeyForPairLocal("SYNTHETIC-owner", b.Public().ID, b.Public(), bfp); !errors.Is(err, ErrNodeOwnerKeyTrustConflict) {
		t.Fatal("new key ID bypassed active Owner pin", err)
	}
	if _, err := state.RevokeNodeOwnerKeyTrustLocal("SYNTHETIC-owner", a.Public().ID, first.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := state.TrustOwnerApprovalKeyForPairLocal("SYNTHETIC-owner", a.Public().ID, a.Public(), afp); !errors.Is(err, ErrNodeOwnerKeyTrustRevoked) {
		t.Fatal("exact revoked key reopened", err)
	}
	if _, err := state.TrustOwnerApprovalKeyForPairLocal("SYNTHETIC-owner", b.Public().ID, b.Public(), bfp); !errors.Is(err, ErrNodeOwnerKeyTrustConflict) {
		t.Fatal("different key ID bypassed Owner tombstone", err)
	}
}

func TestNodePairOwnerTrustConcurrentDifferentKeysHaveOneWinner(t *testing.T) {
	root := t.TempDir()
	a, err := OpenCryptoState(root)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenCryptoState(root)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var keys [2]*e2ee.Identity
	var fps [2]string
	for i := range keys {
		keys[i], err = e2ee.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		fps[i], _ = PeerKeyFingerprint(keys[i].Public())
	}
	states := []*CryptoState{a, b}
	var errs [2]error
	var wg sync.WaitGroup
	for i := range states {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = states[i].TrustOwnerApprovalKeyForPairLocal("SYNTHETIC-race-owner", keys[i].Public().ID, keys[i].Public(), fps[i])
		}(i)
	}
	wg.Wait()
	winners := 0
	for _, e := range errs {
		if e == nil {
			winners++
		} else if !errors.Is(e, ErrNodeOwnerKeyTrustConflict) {
			t.Fatal(e)
		}
	}
	if winners != 1 {
		t.Fatal("concurrent first trust had multiple keys")
	}
}
