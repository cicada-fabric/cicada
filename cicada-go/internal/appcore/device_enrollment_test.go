package appcore

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cicada-ai/cicada/internal/appkeys"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func TestForeignAccountResponseCannotEstablishLocalDeviceEnrollment(t *testing.T) {
	c, _ := NewController(Config{})
	defer c.Close()
	n := c.(*nativeController)
	device, err := appkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	n.device = device
	n.connection = HubConnectionCard{Origin: "https://hub.synthetic.invalid", HubID: "hub_synthetic", AccountID: "account_synthetic", OwnerID: "owner_synthetic"}
	n.state.DeviceID = "accountdev_synthetic"
	// These are inputs to the already-authenticated body's scope validator,
	// not cryptographic interoperability vectors.
	for _, body := range []any{
		&wire.ClaimReceipt{Origin: n.connection.Origin, HubID: n.connection.HubID, AccountID: "foreign_synthetic", OwnerID: n.connection.OwnerID, DeviceID: n.state.DeviceID, DeviceKeyID: device.Public().ID},
		&wire.LoginChallenge{Origin: n.connection.Origin, HubID: n.connection.HubID, AccountID: "foreign_synthetic", OwnerID: n.connection.OwnerID, DeviceID: n.state.DeviceID, DeviceKeyID: device.Public().ID},
		&wire.SessionReceipt{Origin: n.connection.Origin, HubID: n.connection.HubID, AccountID: "foreign_synthetic", OwnerID: n.connection.OwnerID, DeviceID: n.state.DeviceID, DeviceKeyID: device.Public().ID},
	} {
		if err := n.validateAccountResponseScope(body); err == nil || n.state.AccountDeviceEnrolled {
			t.Fatal("foreign authenticated account coordinates polluted enrollment state")
		}
	}
}

func TestOldN2ProfileRestoresEnrollmentFromAuthenticatedCompletion(t *testing.T) {
	f := newActivationActorFixture(t)
	root := filepath.Join(t.TempDir(), "vaults")
	c := f.controller(t, root)
	ctx := context.Background()
	code, _ := wire.EncodeActivationCode(f.material)
	if err := c.Dispatch(ctx, Action{Kind: ActionConnect, ActivationCode: code}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionGenerateOwner}); err != nil {
		t.Fatal(err)
	}
	if err := c.Dispatch(ctx, Action{Kind: ActionActivateApp, ConfirmLimitedAuthorization: true, Username: "native-migration", Password: n2SyntheticPassword}); err != nil {
		t.Fatal(err)
	}
	n := c.(*nativeController)
	owner, device, id := n.owner.Public(), n.device.Public(), n.state.DeviceID
	// Omit the new optional field, as in the previous committed N2 producer.
	n.state.AccountDeviceEnrolled = false
	if err := n.persistState(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c = f.controller(t, root)
	defer c.Close()
	resumeN2App(t, c)
	n = c.(*nativeController)
	if !c.Snapshot().Account.DeviceEnrolled || !containsAction(c.Snapshot().AvailableActions, ActionLogin) ||
		!reflect.DeepEqual(owner, n.owner.Public()) || !reflect.DeepEqual(device, n.device.Public()) || n.state.DeviceID != id {
		t.Fatal("old completed profile required new keys or a new activation code")
	}
}
