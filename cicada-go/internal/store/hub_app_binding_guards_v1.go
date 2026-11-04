package store

import (
	"database/sql"
	"encoding/json"
	"reflect"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// This exception authenticates historical Node provenance only. No App writer,
// new approval, enrollment or management path may use it as caller authority.
func appBindingHistoricalSource(tx *sql.Tx, owner, device, root, hub string) bool {
	u, err := appBindingUnbound(tx, owner, device)
	if err != nil || u.state != "UNBOUND" {
		return false
	}
	b := u.binding
	if b.Purpose != wire.AppBindingPurposeUnbind || b.OwnerID != owner || b.DeviceID != device || b.OwnerPublic.ID != root || b.HubID != hub || u.deviceEpoch != b.DeviceEpoch+1 || u.version != b.ClientDeviceVersion+1 || u.epoch != b.ClientSessionEpoch+1 {
		return false
	}
	setup, err := hubOwnerSetup(tx)
	if err != nil || setup == nil || setup.State != HubOwnerReady || setup.HubID != hub || setup.OwnerID != owner || setup.AccountID != b.AccountID || setup.Origin != b.Origin {
		return false
	}
	var currentEpoch, credential int64
	var receipt, localHub string
	if tx.QueryRow(`SELECT epoch,restore_receipt FROM hub_account_config_v1 WHERE id=1`).Scan(&currentEpoch, &receipt) != nil || uint64(currentEpoch) != b.AccountEpoch || receipt != u.restore || tx.QueryRow(`SELECT version FROM hub_account_credentials_v1 WHERE account_id=? AND owner_id=?`, b.AccountID, owner).Scan(&credential) != nil || uint64(credential) != b.CredentialVersion || tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&localHub) != nil || localHub != hub {
		return false
	}
	key, err := appBindingRoot(tx, owner, b.OwnerPublic)
	if err != nil || uint64(key.Version) != b.OwnerKeyVersion {
		return false
	}
	client, err := scanClientDevice(tx.QueryRow(clientDeviceSelect+` WHERE owner_id=? AND device_id=?`, owner, device))
	if err != nil || client.State != ClientDeviceRevoked || client.OwnerKeyID != root || uint64(client.Version) != u.version || client.SessionEpoch != u.epoch || !reflect.DeepEqual(client.Public, b.DevicePublic) {
		return false
	}
	var public, status string
	var de uint64
	var p e2ee.PublicIdentity
	return tx.QueryRow(`SELECT public_identity_json,status,epoch FROM hub_account_devices_v1 WHERE account_id=? AND owner_id=? AND device_id=?`, b.AccountID, owner, device).Scan(&public, &status, &de) == nil && status == "REVOKED" && de == u.deviceEpoch && json.Unmarshal([]byte(public), &p) == nil && reflect.DeepEqual(p, b.DevicePublic)
}

func nodeHistoricalAppSourceTx(tx *sql.Tx, owner, device, root, hub string) bool {
	var state string
	if tx.QueryRow(`SELECT state FROM client_devices_v2 WHERE owner_id=? AND device_id=? AND owner_key_id=?`, owner, device, root).Scan(&state) != nil {
		return false
	}
	return state == ClientDeviceActive || (state == ClientDeviceRevoked && appBindingHistoricalSource(tx, owner, device, root, hub))
}

// Existing LocalDomain policies and bound heartbeat writers were already
// independent of an inactive creator App. Preserve that contract. Both use
// this current provenance fence only for this protocol's own tombstones.
func appBindingLocalDomainSource(tx *sql.Tx, owner, device, root, hub string) bool {
	var count int
	if tx.QueryRow(`SELECT count(*) FROM hub_app_unbound_v1 WHERE owner_id=? AND device_id=?`, owner, device).Scan(&count) != nil {
		return false
	}
	return count == 0 || appBindingHistoricalSource(tx, owner, device, root, hub)
}

func appBindingManaged(q hubOwnerQuerier, owner, device string) bool {
	var count int
	// Registry read failures must not reopen the legacy unrestricted path.
	return q.QueryRow(`SELECT count(*) FROM hub_app_rebound_v1 WHERE owner_id=? AND device_id=?`, owner, device).Scan(&count) != nil || count != 0
}

// A replacement is a valid source for a later, separately Owner-proved N3
// authorization flow. This grants no session, lease, business operation or
// inherited authorization by itself.
func appBindingReboundSource(tx *sql.Tx, scope e2ee.OwnerAppNodeScope, client *ClientDevice, ad *HubAccountDevice) bool {
	var raw, receipt string
	if tx.QueryRow(`SELECT binding_json,restore_receipt FROM hub_app_rebound_v1 WHERE owner_id=? AND device_id=?`, scope.OwnerID, scope.DeviceID).Scan(&raw, &receipt) != nil {
		return false
	}
	var b wire.AppBinding
	var currentReceipt string
	if json.Unmarshal([]byte(raw), &b) != nil || tx.QueryRow(`SELECT restore_receipt FROM hub_account_config_v1 WHERE id=1`).Scan(&currentReceipt) != nil || currentReceipt != receipt {
		return false
	}
	var credential uint64
	if tx.QueryRow(`SELECT version FROM hub_account_credentials_v1 WHERE account_id=? AND owner_id=?`, b.AccountID, b.OwnerID).Scan(&credential) != nil || credential != b.CredentialVersion {
		return false
	}
	return b.Purpose == wire.AppBindingPurposeRebind && b.HubID == scope.HubID && b.HubFingerprint == scope.HubFingerprint && b.Origin == scope.Origin && b.AccountID == scope.AccountID && b.OwnerID == scope.OwnerID && b.DeviceID == scope.DeviceID && b.AccountEpoch == scope.AccountEpoch && b.DeviceEpoch == scope.DeviceEpoch && b.OwnerKeyVersion == scope.OwnerKeyVersion && reflect.DeepEqual(b.OwnerPublic, scope.OwnerPublic) && reflect.DeepEqual(b.DevicePublic, scope.DevicePublic) && ad.State == "ACTIVE" && client.State == ClientDeviceActive && client.OwnerKeyID == b.OwnerPublic.ID && client.KeyVersion == 1 && client.SessionEpoch == 1 && client.Version == 1
}
