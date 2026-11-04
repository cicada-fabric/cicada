package appvault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/appkeys"
)

func deviceTransitionVault(t *testing.T) *Vault {
	t.Helper()
	v, err := Create(filepath.Join(privateTestDir(t), "app.vault"), testScope(), testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	for _, purpose := range []Purpose{PurposeOwnerSigner, PurposeAppDevice} {
		id, err := appkeys.Generate()
		if err != nil {
			t.Fatal(err)
		}
		err = v.Put(purpose, id)
		id.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string][]byte{
		"account": []byte("SYNTHETIC_OLD_ACCOUNT"), "session": []byte("SYNTHETIC_OLD_SESSION"),
		"node.work": []byte("SYNTHETIC_OLD_NODE_ORIGINAL_AND_RECEIPT"), "group.grant": []byte("SYNTHETIC_OLD_GROUP_GRANT"),
		"profile": []byte("SYNTHETIC_PROFILE_PRESENT"),
	} {
		if _, err := v.CompareAndSwapState(name, 0, data); err != nil {
			t.Fatal(err)
		}
	}
	return v
}

func saveDeviceTestReceipt(t *testing.T, v *Vault, name string) StateGuard {
	t.Helper()
	_, version, _, err := v.LoadState(name)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("SYNTHETIC_AUTHENTICATED_ORIGINAL_AND_RECEIPT_" + name)
	version, err = v.CompareAndSwapState(name, version, data)
	if err != nil {
		t.Fatal(err)
	}
	return NewStateGuard(name, version, data)
}

func deviceTestPromotion(t *testing.T, v *Vault) AppDevicePromotion {
	t.Helper()
	status, err := v.AppDeviceStatus()
	if err != nil {
		t.Fatal(err)
	}
	unbound := saveDeviceTestReceipt(t, v, "account.unbound")
	candidate, err := v.PrepareAppDevice(status.CurrentKeyID, unbound)
	if err != nil {
		t.Fatal(err)
	}
	completion := saveDeviceTestReceipt(t, v, "account.rebound")
	versions, err := v.StateVersions()
	if err != nil {
		t.Fatal(err)
	}
	return AppDevicePromotion{CurrentKeyID: status.CurrentKeyID, Candidate: candidate, Completion: completion,
		ExpectedVersions: versions, SessionNamespace: "session", Updates: map[string][]byte{
			"account": []byte("SYNTHETIC_NEW_ACCOUNT_WITHOUT_SESSION_" + candidate.KeyID), "session": nil,
			"profile": []byte("SYNTHETIC_PROFILE_PRESENT"),
		}}
}

func reopenDeviceTestVault(t *testing.T, v *Vault) *Vault {
	t.Helper()
	path, scope := v.path, v.scope
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(path, scope, testProtector(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	return opened
}

func TestAppDeviceCandidateSurvivesRestartWithoutChangingCurrentKey(t *testing.T) {
	v := deviceTransitionVault(t)
	unbound := saveDeviceTestReceipt(t, v, "account.unbound")
	old := v.entries[PurposeAppDevice].KeyID
	beforeVersions, _ := v.StateVersions()
	candidate, err := v.PrepareAppDevice(old, unbound)
	if err != nil || candidate.Generation != 2 || candidate.KeyID == old {
		t.Fatalf("candidate generation=%d error=%v", candidate.Generation, err)
	}
	if v.entries[PurposeAppDevice].KeyID != old {
		t.Fatal("staging changed current device")
	}
	for name, version := range beforeVersions {
		if v.states[name].version != version {
			t.Fatal("staging advanced a protocol CAS generation")
		}
	}
	handle, err := v.OpenPendingAppDevice(candidate)
	if err != nil || handle.Public().ID != candidate.KeyID {
		t.Fatal("candidate is not available through an opaque crypto handle", err)
	}
	handle.Close()
	if _, err := v.Get(PurposeAppDevice, candidate.KeyID); !errors.Is(err, ErrStateNotFound) {
		t.Fatal("pending device became an ordinary business key", err)
	}
	v = reopenDeviceTestVault(t, v)
	again, err := v.PrepareAppDevice(old, unbound)
	if err != nil || again != candidate {
		t.Fatal("restart regenerated candidate", err)
	}
	status, err := v.AppDeviceStatus()
	if err != nil || status.CurrentKeyID != old || status.Generation != 1 || status.Candidate == nil || *status.Candidate != candidate {
		t.Fatal("reopened candidate/current metadata mismatch", err)
	}
	wrong := unbound
	wrong.SHA256 = strings.Repeat("b", 64)
	if _, err := v.PrepareAppDevice(old, wrong); !errors.Is(err, ErrStateConflict) {
		t.Fatal("changed ceremony accepted", err)
	}
	if _, err := v.OpenPendingAppDevice(AppDeviceCandidate{KeyID: candidate.KeyID, Generation: 3}); !errors.Is(err, ErrScopeMismatch) {
		t.Fatal("wrong candidate generation accepted", err)
	}
}

func TestAppDevicePromotionAtomicallyArchivesGenerationAndPreservesOwner(t *testing.T) {
	v := deviceTransitionVault(t)
	owner := cloneDeviceEntry(v.entries[PurposeOwnerSigner])
	defer clear(owner.Private)
	change := deviceTestPromotion(t, v)
	oldStates := cloneStates(v.states)
	defer clearStates(oldStates)
	newVersions, err := v.PromoteAppDevice(change)
	if err != nil {
		t.Fatal(err)
	}
	if v.entries[PurposeOwnerSigner].KeyID != owner.KeyID || !bytes.Equal(v.entries[PurposeOwnerSigner].Private, owner.Private) {
		t.Fatal("Owner identity changed")
	}
	if v.entries[PurposeAppDevice].KeyID != change.Candidate.KeyID || v.appDevices.Pending != nil || v.appDevices.Generation != 2 {
		t.Fatal("new current device was not promoted")
	}
	for name, state := range oldStates {
		current, version, found, err := v.LoadState(name)
		if err != nil || !found || version != state.version+1 || version != newVersions[name] || !bytes.Equal(current, change.Updates[name]) {
			t.Fatalf("current namespace=%s version=%d err=%v", name, version, err)
		}
		old, version, found, err := v.LoadRetiredAppDeviceState(1, name)
		if err != nil || !found || version != state.version || !bytes.Equal(old, state.payload) {
			t.Fatalf("retired namespace=%s lost original/version: %v", name, err)
		}
		if len(old) > 0 {
			old[0] ^= 0xff
			again, _, _, _ := v.LoadRetiredAppDeviceState(1, name)
			if !bytes.Equal(again, state.payload) {
				t.Fatal("historical state did not return a detached copy")
			}
		}
	}
	if _, err := v.Get(PurposeAppDevice, change.CurrentKeyID); !errors.Is(err, ErrStateNotFound) {
		t.Fatal("retired device remains usable for business signing", err)
	}
	if _, err := v.OpenPendingAppDevice(change.Candidate); !errors.Is(err, ErrScopeMismatch) {
		t.Fatal("promoted candidate remains pending", err)
	}
	v = reopenDeviceTestVault(t, v)
	if v.entries[PurposeAppDevice].KeyID != change.Candidate.KeyID || !bytes.Equal(v.entries[PurposeOwnerSigner].Private, owner.Private) {
		t.Fatal("key/state promotion did not survive restart")
	}
	for _, name := range []string{"session", "group.grant", "node.work"} {
		data, version, found, err := v.LoadState(name)
		if err != nil || !found || len(data) != 0 || version != oldStates[name].version+1 {
			t.Fatal("old business authority survived as current state", name, err)
		}
	}
	status, err := v.AppDeviceStatus()
	if err != nil || len(status.Retired) != 1 || status.Retired[0].KeyID != change.CurrentKeyID {
		t.Fatal("retired metadata mismatch", err)
	}
	entries, err := v.List()
	if err != nil || len(entries) != 2 {
		t.Fatal("candidate/history expanded ordinary purpose entries", err)
	}
	sealed, err := os.ReadFile(v.path)
	if err != nil || bytes.Contains(sealed, owner.Private) || bytes.Contains(sealed, []byte("SYNTHETIC_OLD_GROUP_GRANT")) {
		t.Fatal("history or key material escaped encrypted envelope", err)
	}
}

func TestAppDevicePromotionRejectsMismatchedProofCASAndSessionWithoutWriting(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Vault, *AppDevicePromotion)
	}{
		{"old-key", func(_ *Vault, c *AppDevicePromotion) { c.CurrentKeyID = c.Candidate.KeyID }},
		{"candidate-generation", func(_ *Vault, c *AppDevicePromotion) { c.Candidate.Generation++ }},
		{"receipt-digest", func(_ *Vault, c *AppDevicePromotion) { c.Completion.SHA256 = strings.Repeat("b", 64) }},
		{"same-receipt", func(v *Vault, c *AppDevicePromotion) { c.Completion = v.appDevices.Pending.Unbound }},
		{"missing-snapshot", func(_ *Vault, c *AppDevicePromotion) { delete(c.ExpectedVersions, "node.work") }},
		{"stale-cas", func(_ *Vault, c *AppDevicePromotion) { c.ExpectedVersions["account"]-- }},
		{"missing-update-cas", func(_ *Vault, c *AppDevicePromotion) { c.Updates["new.record"] = []byte("SYNTHETIC") }},
		{"unused-new-cas", func(_ *Vault, c *AppDevicePromotion) { c.ExpectedVersions["unknown"] = 0 }},
		{"missing-session", func(_ *Vault, c *AppDevicePromotion) { delete(c.Updates, "session") }},
		{"inherited-session", func(_ *Vault, c *AppDevicePromotion) { c.Updates["session"] = []byte("SYNTHETIC_OLD_SESSION") }},
		{"oversize-state", func(_ *Vault, c *AppDevicePromotion) { c.Updates["account"] = make([]byte, maxStateBytes+1) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := deviceTransitionVault(t)
			change := deviceTestPromotion(t, v)
			before, err := os.ReadFile(v.path)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(v, &change)
			if _, err := v.PromoteAppDevice(change); err == nil {
				t.Fatal("invalid promotion accepted")
			}
			after, err := os.ReadFile(v.path)
			if err != nil || !bytes.Equal(before, after) || v.entries[PurposeAppDevice].KeyID != change.CurrentKeyID && tc.name != "old-key" {
				t.Fatal("rejected promotion changed disk/current device", err)
			}
		})
	}
}

func TestAppDeviceTransitionsFencePostPublicationFailure(t *testing.T) {
	for _, phase := range []string{"stage", "promote"} {
		t.Run(phase, func(t *testing.T) {
			v := deviceTransitionVault(t)
			oldKey := v.entries[PurposeAppDevice].KeyID
			var change AppDevicePromotion
			var unbound StateGuard
			if phase == "stage" {
				unbound = saveDeviceTestReceipt(t, v, "account.unbound")
			} else {
				change = deviceTestPromotion(t, v)
			}
			oldSync := syncVaultParentDirectory
			t.Cleanup(func() { syncVaultParentDirectory = oldSync })
			syncVaultParentDirectory = func(string) error { return errors.New("SYNTHETIC_POST_PUBLICATION_FAILURE") }
			var err error
			if phase == "stage" {
				_, err = v.PrepareAppDevice(oldKey, unbound)
			} else {
				_, err = v.PromoteAppDevice(change)
			}
			syncVaultParentDirectory = oldSync
			if !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("post-publication failure did not require reopen", err)
			}
			if _, err := v.AppDeviceStatus(); !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("poisoned vault exposed old generation", err)
			}
			if _, err := v.PrepareAppDevice(oldKey, unbound); !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("poisoned vault allowed replacement/regeneration", err)
			}
			v = reopenDeviceTestVault(t, v)
			status, err := v.AppDeviceStatus()
			if err != nil {
				t.Fatal(err)
			}
			if phase == "stage" {
				if status.Candidate == nil || status.CurrentKeyID != oldKey || status.Generation != 1 {
					t.Fatal("reopen lost actual staged key")
				}
				again, err := v.PrepareAppDevice(oldKey, unbound)
				if err != nil || again != *status.Candidate {
					t.Fatal("reopen regenerated an uncertain candidate", err)
				}
			} else if status.Candidate != nil || status.CurrentKeyID != change.Candidate.KeyID || status.Generation != 2 {
				t.Fatal("reopen did not recover the atomically promoted generation")
			} else {
				data, _, _, err := v.LoadState("session")
				if err != nil || len(data) != 0 {
					t.Fatal("post-publication failure resurrected old session", err)
				}
			}
		})
	}
}

func TestAppDeviceAdmissionIncludesCandidateHistoryAndFutureReceipts(t *testing.T) {
	v := deviceTransitionVault(t)
	before, err := os.ReadFile(v.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.CheckAppDeviceTransition(map[string][]byte{"account": make([]byte, maxStateBytes+1)}, nil); !errors.Is(err, ErrInvalidVault) {
		t.Fatal("oversize future receipt admitted", err)
	}
	// The ordinary current-only admission fits, but retirement plus fresh
	// generation duplicates the account bytes and must be refused before send.
	retiring := map[string][]byte{"account": make([]byte, maxStateBytes), "future.receipt": make([]byte, maxStateBytes)}
	if err := v.CheckStateUpdates(retiring); err != nil {
		t.Fatal("fixture does not fit ordinary current budget", err)
	}
	if err := v.CheckAppDeviceTransition(retiring, map[string][]byte{"account": make([]byte, maxStateBytes)}); !errors.Is(err, ErrInvalidVault) {
		t.Fatal("retained/candidate/new-account budget was not checked", err)
	}
	if err := v.CheckAppDeviceTransition(map[string][]byte{"account": make([]byte, 200<<10)}, map[string][]byte{"account": make([]byte, 200<<10)}); err != nil {
		t.Fatal("bounded transition incorrectly refused", err)
	}
	after, err := os.ReadFile(v.path)
	if err != nil || !bytes.Equal(before, after) || v.appDevices != nil {
		t.Fatal("capacity preflight mutated keys/state/disk", err)
	}
}

func TestAppDevicePreparationRequiresCommittedMatchingTerminalRecord(t *testing.T) {
	v := deviceTransitionVault(t)
	old := v.entries[PurposeAppDevice].KeyID
	before, _ := os.ReadFile(v.path)
	missing := NewStateGuard("account.unbound", 1, []byte("SYNTHETIC_UNSAVED_RECEIPT"))
	if _, err := v.PrepareAppDevice(old, missing); !errors.Is(err, ErrStateConflict) {
		t.Fatal("uncommitted terminal receipt allowed key generation", err)
	}
	after, _ := os.ReadFile(v.path)
	if !bytes.Equal(before, after) || v.appDevices != nil {
		t.Fatal("rejected preparation changed storage")
	}
	guard := saveDeviceTestReceipt(t, v, "account.unbound")
	if _, err := v.PrepareAppDevice(v.entries[PurposeOwnerSigner].KeyID, guard); !errors.Is(err, ErrScopeMismatch) {
		t.Fatal("foreign current identity accepted", err)
	}
	guard.Version++
	if _, err := v.PrepareAppDevice(old, guard); !errors.Is(err, ErrStateConflict) {
		t.Fatal("unsaved future CAS accepted", err)
	}
}

func TestAppDevicePrePublicationFailurePreservesOldGeneration(t *testing.T) {
	v := deviceTransitionVault(t)
	change := deviceTestPromotion(t, v)
	before, _ := os.ReadFile(v.path)
	// A missing trusted file fails before publication. Restore only this
	// disposable synthetic fixture, then inspect its original bytes.
	moved := v.path + ".synthetic-moved"
	if err := os.Rename(v.path, moved); err != nil {
		t.Fatal(err)
	}
	_, err := v.PromoteAppDevice(change)
	if restoreErr := os.Rename(moved, v.path); restoreErr != nil {
		t.Fatal(restoreErr)
	}
	if !errors.Is(err, ErrInvalidVault) || v.poisoned {
		t.Fatal("pre-publication failure changed certainty", err)
	}
	after, _ := os.ReadFile(v.path)
	if !bytes.Equal(before, after) {
		t.Fatal("pre-publication failure modified file")
	}
	v = reopenDeviceTestVault(t, v)
	status, err := v.AppDeviceStatus()
	if err != nil || status.CurrentKeyID != change.CurrentKeyID || status.Candidate == nil || *status.Candidate != change.Candidate || len(status.Retired) != 0 {
		t.Fatal("pre-publication failure retired/promoted keys", err)
	}
}

func TestAppDeviceTransitionKeepsExistingNamespaceCeiling(t *testing.T) {
	v := deviceTransitionVault(t)
	for len(v.states) < maxStateRecords {
		name := "synthetic." + strings.Repeat("x", len(v.states))
		if _, err := v.CompareAndSwapState(name, 0, []byte("SYNTHETIC_RETAINED")); err != nil {
			t.Fatal(err)
		}
	}
	if err := v.CheckAppDeviceTransition(map[string][]byte{"new.original": []byte("SYNTHETIC")}, nil); !errors.Is(err, ErrInvalidVault) {
		t.Fatal("transition exceeded existing current namespace bound", err)
	}
	if err := v.CheckAppDeviceTransition(nil, map[string][]byte{"new.account": []byte("SYNTHETIC")}); !errors.Is(err, ErrInvalidVault) {
		t.Fatal("new generation exceeded existing namespace bound", err)
	}
}

func TestAppDeviceHistoryBoundRefusesWithoutEvictionOrPutReplacement(t *testing.T) {
	v := deviceTransitionVault(t)
	for i := 0; i < maxRetiredAppDevices; i++ {
		change := deviceTestPromotion(t, v)
		if _, err := v.PromoteAppDevice(change); err != nil {
			t.Fatal(err)
		}
		v = reopenDeviceTestVault(t, v)
	}
	guard := saveDeviceTestReceipt(t, v, "account.unbound")
	before, _ := os.ReadFile(v.path)
	if _, err := v.PrepareAppDevice(v.entries[PurposeAppDevice].KeyID, guard); !errors.Is(err, ErrAppDeviceHistoryFull) {
		t.Fatal("full history did not refuse further enrollment", err)
	}
	if err := v.CheckAppDeviceTransition(nil, nil); !errors.Is(err, ErrAppDeviceHistoryFull) {
		t.Fatal("full history did not fail preflight", err)
	}
	other, err := appkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := v.Put(PurposeAppDevice, other); !errors.Is(err, ErrKeyExists) {
		t.Fatal("ordinary Put replaced current identity", err)
	}
	after, _ := os.ReadFile(v.path)
	if !bytes.Equal(before, after) || len(v.appDevices.Retired) != maxRetiredAppDevices {
		t.Fatal("history exhaustion evicted/replaced data")
	}
	if data, _, found, err := v.LoadRetiredAppDeviceState(1, "node.work"); err != nil || !found || string(data) != "SYNTHETIC_OLD_NODE_ORIGINAL_AND_RECEIPT" {
		t.Fatal("oldest history no longer retained", err)
	}
}

func TestAppDeviceLifecycleRejectsMalformedEncryptedPayload(t *testing.T) {
	v := deviceTransitionVault(t)
	change := deviceTestPromotion(t, v)
	if _, err := v.PromoteAppDevice(change); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*appDeviceLifecycle)
	}{
		{"generation", func(d *appDeviceLifecycle) { d.Generation++ }},
		{"current-id", func(d *appDeviceLifecycle) { d.CurrentKeyID = d.Retired[0].Device.KeyID }},
		{"private-key", func(d *appDeviceLifecycle) { d.Retired[0].Device.Private[0] ^= 0xff }},
		{"receipt-digest", func(d *appDeviceLifecycle) { d.Retired[0].Completion.SHA256 = strings.Repeat("b", 64) }},
		{"duplicated-state", func(d *appDeviceLifecycle) { d.Retired[0].States = append(d.Retired[0].States, d.Retired[0].States[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			devices := cloneAppDeviceLifecycle(v.appDevices)
			defer clearAppDeviceLifecycle(devices)
			tc.mutate(devices)
			encoded, err := encodePayload(v.entries, v.states, devices)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(encoded)
			decoded := &Vault{entries: make(map[Purpose]diskEntry), states: make(map[string]stateValue)}
			defer clearEntries(decoded.entries)
			defer clearStates(decoded.states)
			if err := decoded.decodePayload(encoded); !errors.Is(err, ErrInvalidVault) {
				t.Fatal("malformed lifecycle accepted", err)
			}
		})
	}
}
