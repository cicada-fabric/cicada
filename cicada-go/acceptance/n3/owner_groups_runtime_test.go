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
	requireOwnerGroupsAvailable(t, v)
	actors := prepareNativePeerActors(t, v, "owner-groups", []string{"a", "b", "c", "d"})
	host, _ := startOwnerGroupsHost(t, v, actors)
	original := ownerGroupsOriginalActors(t, v, actors, host)
	var g2 string
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
	host.finish(t)
	// Do not fabricate missing cases, set their observation booleans or emit the
	// final pre-revocation identity witness early. The full evidence gate fails
	// closed until M3-M8 have actual executable adapters and measured results.
	t.Log("OWNER_GROUPS_INCOMPLETE M3_M8_NOT_RUN final_identity_and_real_lease_witness_NOT_RUN")
}
