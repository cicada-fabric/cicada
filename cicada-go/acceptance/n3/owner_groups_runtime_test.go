package n3_test

import (
	"os"
	"testing"
)

// This is the actual product parent selected by --owner-endpoint-groups in the
// existing driver. Missing real capability skips before any scenario is run.
// The evidence gate independently requires every M1-M8 case/fact, M5 real lease
// and final identity witness: a partial parent cannot produce SCOPED_PASS.
func TestN3OwnerEndpointGroupsAcceptance(t *testing.T) {
	if os.Getenv("CICADA_N3_OWNER_ENDPOINT_GROUPS") != "1" {
		t.Skip("OWNER_GROUPS_NOT_RUN opt in through the isolated native-pair driver")
	}
	v := newCodexProductFixture(t, "1s")
	registerOwnerGroupsProtocolAudit(t, v)
	requireOwnerGroupsAvailable(t, v)
	actors := prepareNativePeerActors(t, v, "owner-groups", []string{"a", "b", "c", "d"})
	host, _ := startOwnerGroupsHost(t, v, actors)
	original := ownerGroupsOriginalActors(t, v, actors, host)
	var g2 string
	var denied ownerGroupsDeniedDelivery
	if !t.Run("M1_G2OriginalMutation", func(t *testing.T) {
		g2 = exerciseOwnerGroupsM1(t, v, actors, host, original)
	}) {
		return
	}
	if !t.Run("M2_ExactMultiGroup", func(t *testing.T) {
		exerciseOwnerGroupsM2(t, v, actors, host, original, g2)
	}) {
		return
	}
	if !t.Run("M3_RemoveOnlyD", func(t *testing.T) {
		denied = exerciseOwnerGroupsM3(t, v, actors, host, original, g2)
	}) {
		return
	}
	for _, scene := range []struct {
		name string
		run  func(*testing.T, *codexProductFixture, nativePeerActors, *ownerGroupsHost, []ownerGroupsIdentity, string, ownerGroupsDeniedDelivery)
	}{
		{"M4_PermanentOwnerControl", exerciseOwnerGroupsM4},
		{"M5_IndependentRealLease", exerciseOwnerGroupsM5},
		{"M6_LastGroupRetainsIdentity", exerciseOwnerGroupsM6},
		{"M8_OriginalScopeRecovery", exerciseOwnerGroupsM8},
	} {
		if !t.Run(scene.name, func(t *testing.T) { scene.run(t, v, actors, host, original, g2, denied) }) {
			return
		}
	}
	// Retain the four originals across every Group operation. M7 uses fresh
	// independent baselines for intentional key/binding revocation afterward.
	observeOwnerGroupsIdentities(t, original, ownerGroupsStoredIdentities(t, v, actors, host.originalSIDs))
	host.finish(t)
	if !t.Run("M7_TrueAuthorityRevocation", exerciseOwnerGroupsM7) {
		return
	}
}

// A narrow diagnostic entry reuses both original independent M7 baselines.
// Its separate evidence scope cannot close the complete M1-M8 acceptance gate.
func TestN3OwnerEndpointGroupsM7Only(t *testing.T) {
	if os.Getenv("CICADA_N3_OWNER_ENDPOINT_GROUPS") != "1" {
		t.Skip("OWNER_GROUPS_NOT_RUN opt in through the isolated native-pair driver")
	}
	t.Run("M7_TrueAuthorityRevocation", exerciseOwnerGroupsM7)
}
