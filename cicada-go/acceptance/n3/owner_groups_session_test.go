package n3_test

import (
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/appcore"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// Management reads need a current account session. Business grants and the
// original Node/Owner/device are independent of this real account login.
// Call only at a fresh-read boundary, never during an original pending/review.
func ownerGroupsFreshAppSession(t *testing.T, v *codexProductFixture, network string) appcore.Snapshot {
	t.Helper()
	checkpoint := v.command(t, appActorCommand{})
	if checkpoint.ClockMode != "WALL_CLOCK" {
		t.Fatal("Group management session used a substituted App clock")
	}
	s := checkpoint.Current
	checkedAt := time.Now().UTC()
	if s.ThreadGroups.Pending || s.ThreadGroups.Review != nil {
		t.Fatal("fresh management login cannot replace an original pending request or review")
	}
	deadline, err := time.Parse(time.RFC3339Nano, s.Account.SessionExpiresAt)
	if err != nil && s.Account.SessionExpiresAt != "" {
		t.Fatal("actual App account deadline is malformed")
	}
	// Leave room for the existing bounded native Host/fault steps, without
	// changing any account, consent, business-policy or native-writer deadline.
	if err == nil && checkedAt.Add(time.Minute).Before(deadline) {
		return s
	}
	assertOwnerDirectoryIdentity(t, v.endpointSecurityFixture, s)
	if s.Node.Binding == nil || s.Node.Binding.ID != v.bound.BindingID || s.Node.Binding.NodeID != v.actualNode.id {
		t.Fatal("management login lacks its original Node binding")
	}
	binding := *s.Node.Binding
	from := len(v.f.proxy.snapshot())
	t.Logf("OWNER_GROUPS_ACCOUNT_SESSION_PRECONDITION state=%s checked_at=%s expires_at=%s pending=false review=false", s.Account.State, checkedAt.Format(time.RFC3339Nano), s.Account.SessionExpiresAt)
	if time.Now().Before(deadline) {
		logout := appcore.Action{Kind: appcore.ActionLogout}
		reply := v.command(t, appActorCommand{Action: &logout})
		if reply.ActionFailed || reply.ClockMode != "WALL_CLOCK" {
			t.Fatal("original App could not normally leave its near-expiry account session")
		}
	}
	loginAt := time.Now().UTC()
	login := appcore.Action{Kind: appcore.ActionLogin, Username: v.original.Account.Username, Password: syntheticPassword}
	reply := v.command(t, appActorCommand{Action: &login})
	after := reply.Current
	assertOwnerDirectoryIdentity(t, v.endpointSecurityFixture, after)
	newDeadline, parseErr := time.Parse(time.RFC3339Nano, after.Account.SessionExpiresAt)
	if reply.ActionFailed || reply.ClockMode != "WALL_CLOCK" || after.Account.State != appcore.AccountStateOwnerReady ||
		after.Account.RootState != appcore.RootStateActive || parseErr != nil || !time.Now().Add(time.Minute).Before(newDeadline) ||
		after.Node.Binding == nil || after.Node.Binding.ID != binding.ID || after.Node.Binding.Version != binding.Version ||
		after.Node.Binding.NodeID != binding.NodeID ||
		after.ThreadGroups.NodeID != v.actualNode.id || after.ThreadGroups.NetworkID != network ||
		after.ThreadGroups.Pending || after.ThreadGroups.Review != nil {
		t.Fatal("real account login did not retain the original identity and fresh management scope")
	}
	readAvailable := false
	for _, action := range after.AvailableActions {
		readAvailable = readAvailable || action == appcore.ActionReadThreadGroups
	}
	if !readAvailable {
		t.Fatal("original App has no fresh private Thread read after real login")
	}
	for _, ex := range v.f.proxy.snapshot()[from:] {
		if ex.Path == wire.OwnerEndpointGroupsHTTPPath(wire.OperationOwnerEndpointGroupsApply) ||
			ex.Path == wire.ActivationHTTPPath(wire.OperationActivationComplete) ||
			ex.Path == wire.AppNodeHTTPPath(wire.OperationAppNodeComplete) {
			t.Fatal("account reauthentication dispatched a new business or Root/Node approval")
		}
	}
	// Authorized projects the old N3 read grant, which a new login does not
	// renew. Persistent binding identity is the ID/NodeID/Version checked above.
	t.Logf("OWNER_GROUPS_ACCOUNT_SESSION previous_state=%s previous_expires_at=%s login_at=%s expires_at=%s original_Owner_device_binding=true new_business_apply_posts=0 previous_read_authorized=%t read_authorized=%t", s.Account.State, s.Account.SessionExpiresAt, loginAt.Format(time.RFC3339Nano), after.Account.SessionExpiresAt, binding.Authorized, after.Node.Binding.Authorized)
	return after
}
