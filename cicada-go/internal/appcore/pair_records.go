package appcore

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const pairRecordLimit = 1 << 20 // Existing vault namespace bound; never widened.

const (
	pairOriginalRecord = iota
	pairOriginalResponseRecord
	pairRecoveryRecord
	pairRecoveryResponseRecord
	pairStateRecord
	pairReviewRecordIndex
)

var pairNamespaces = [...]string{
	"appcore.pair-original.v1", "appcore.pair-response.v1",
	"appcore.pair-recovery.v1", "appcore.pair-recovery-response.v1",
	"appcore.pair.v1", "appcore.pair-review.v1",
}

// The original scope remains historical during detached recovery. Current
// account sessions or Node bindings never replace the target of these bytes.
type pairPacketTarget struct {
	Vault          appvault.Scope            `json:"vault_scope"`
	DeviceID       string                    `json:"device_id"`
	DeviceKeyID    string                    `json:"device_key_id"`
	OwnerKeyID     string                    `json:"owner_key_id"`
	Scope          e2ee.OwnerNativePairScope `json:"scope"`
	PairID         string                    `json:"pair_id,omitempty"`
	OriginalRoute  clientwire.Route          `json:"original_route"`
	OriginalDigest string                    `json:"original_digest"`
}

// Typed local DTO bytes are retained only where target review needs them.
// Recovery reuses the original record instead of persisting another decoded
// copy of the nested original packet.
type pairRequestRecord struct {
	Format    string           `json:"format"`
	Target    pairPacketTarget `json:"target"`
	Route     clientwire.Route `json:"route"`
	Digest    string           `json:"digest"`
	Packet    []byte           `json:"packet"`
	DTO       json.RawMessage  `json:"local_dto,omitempty"`
	CreatedAt string           `json:"created_at"`
	Applied   bool             `json:"applied"`
}

// A large reconcile response occupies its own namespace. It is never retained
// both as raw ciphertext and as a second decoded giant receipt in this record.
type pairResponseRecord struct {
	Format        string           `json:"format"`
	Target        pairPacketTarget `json:"target"`
	RequestRoute  clientwire.Route `json:"request_route"`
	RequestDigest string           `json:"request_digest"`
	Packet        []byte           `json:"packet"`
}

type pairRecordVersions [len(pairNamespaces)]uint64

func (c *nativeController) persistPairRecord(index int, value any) error {
	if index < 0 || index >= len(pairNamespaces) || c.vault == nil {
		c.storageFault = true
		return appvault.ErrClosed
	}
	var raw []byte
	var err error
	if value != nil {
		raw, err = json.Marshal(value)
		if err != nil || len(raw) > pairRecordLimit {
			c.storageFault = true
			return errors.New("native pair record exceeds the existing vault bound")
		}
	}
	defer clear(raw)
	version, err := c.vault.CompareAndSwapState(pairNamespaces[index], c.pairVersions[index], raw)
	if err != nil {
		c.storageFault = true
		return err
	}
	c.pairVersions[index] = version
	return nil
}

func (c *nativeController) loadPairRecord(index int, out any) (bool, error) {
	if index < 0 || index >= len(pairNamespaces) || c.vault == nil {
		return false, appvault.ErrClosed
	}
	raw, version, found, err := c.vault.LoadState(pairNamespaces[index])
	defer clear(raw)
	if err != nil {
		return false, err
	}
	c.pairVersions[index] = version
	if !found || len(raw) == 0 {
		return false, nil
	}
	if len(raw) > pairRecordLimit || decodeStateJSON(raw, out) != nil {
		return false, errors.New("invalid encrypted native pair record")
	}
	return true, nil
}

func (c *nativeController) pairTargetMatchesIdentity(t pairPacketTarget) bool {
	a := t.Scope.Actor
	return c.vault != nil && c.device != nil && t.Vault == c.vault.Scope() && t.Vault == cardScope(c.connection) &&
		t.DeviceID == c.state.DeviceID && t.DeviceKeyID == c.device.Public().ID && t.OwnerKeyID == c.state.OwnerKeyID &&
		a.Origin == t.Vault.Origin && a.HubID == t.Vault.HubID && a.HubFingerprint == t.Vault.HubFingerprint &&
		a.AccountID == t.Vault.AccountID && a.OwnerID == t.Vault.OwnerID && a.DeviceID == t.DeviceID &&
		a.OwnerPublic.ID == t.OwnerKeyID && reflect.DeepEqual(a.DevicePublic, c.device.Public()) &&
		t.OriginalRoute.HubID == a.HubID && t.OriginalRoute.OwnerID == a.OwnerID && t.OriginalRoute.DeviceID == a.DeviceID &&
		t.OriginalRoute.SenderKeyID == t.DeviceKeyID && t.OriginalRoute.ReceiverKeyID == c.hub.Public.ID
}

func (c *nativeController) validatePairRequest(r *pairRequestRecord, original *pairRequestRecord) error {
	if r == nil || r.Format != "cicada.native-pair.request.v1" || !c.pairTargetMatchesIdentity(r.Target) || len(r.Packet) == 0 {
		return appvault.ErrScopeMismatch
	}
	created, err := time.Parse(time.RFC3339Nano, r.CreatedAt)
	if err != nil || created.UTC().Format(time.RFC3339Nano) != r.CreatedAt {
		return appvault.ErrScopeMismatch
	}
	p, err := wire.DecodeNativePairPacket(r.Packet)
	if err != nil || p.Packet.Route != r.Route || r.Route.Direction != clientwire.DirectionRequest || r.Digest != wire.NativePairPacketDigest(r.Packet) ||
		!reflect.DeepEqual(p.SenderPublicIdentity, c.device.Public()) || r.Route.HubID != r.Target.Vault.HubID || r.Route.OwnerID != r.Target.Vault.OwnerID ||
		r.Route.DeviceID != r.Target.DeviceID || r.Route.SenderKeyID != r.Target.DeviceKeyID || r.Route.ReceiverKeyID != c.hub.Public.ID {
		return appvault.ErrScopeMismatch
	}
	if original == nil {
		if r.Route.Operation == wire.OperationNativePairReconcile || len(r.Packet) > wire.MaxNativePairOriginalBytes ||
			r.Route != r.Target.OriginalRoute || r.Digest != r.Target.OriginalDigest {
			return appvault.ErrScopeMismatch
		}
		if err := validatePairDTO(r); err != nil {
			return err
		}
	} else if r.Route.Operation != wire.OperationNativePairReconcile || len(r.DTO) != 0 || !reflect.DeepEqual(r.Target, original.Target) {
		return appvault.ErrScopeMismatch
	}
	if len(r.DTO) > wire.MaxNativePairBodyBytes {
		return appvault.ErrInvalidVault
	}
	return nil
}

// This checks the durable linkage only. The protocol response must additionally
// be opened against r.Packet with the retained device and pinned Hub before any
// business state is applied or any pending record is marked Applied.
func validatePairResponseLink(v *pairResponseRecord, r *pairRequestRecord, recovery bool) error {
	limit := wire.MaxNativePairReceiptBytes
	if recovery {
		limit = wire.MaxNativePairReconcilePacketBytes
	}
	if v == nil || r == nil || v.Format != "cicada.native-pair.response.v1" || !reflect.DeepEqual(v.Target, r.Target) ||
		v.RequestRoute != r.Route || v.RequestDigest != r.Digest || len(v.Packet) == 0 || len(v.Packet) > limit {
		return appvault.ErrScopeMismatch
	}
	return nil
}
