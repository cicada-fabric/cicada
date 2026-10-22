package appcore

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const localDomainRecordLimit = 1 << 20 // Existing vault bound, never widened.
const (
	localDomainOriginal = iota
	localDomainResponse
	localDomainRecovery
	localDomainRecoveryResponse
	localDomainState
)

var localDomainNamespaces = [...]string{
	"appcore.local-domain-original.v1", "appcore.local-domain-response.v1",
	"appcore.local-domain-recovery.v1", "appcore.local-domain-recovery-response.v1",
	"appcore.local-domain-state.v1",
}

// Packet bytes follow a bounded JSON header inside one encrypted vault CAS.
// Keeping ciphertext raw avoids base64 overflow at the reconcile frame limit.
type localDomainRecord struct {
	Format        string                  `json:"format"`
	Vault         appvault.Scope          `json:"vault"`
	DeviceKeyID   string                  `json:"device_key_id"`
	OwnerKeyID    string                  `json:"owner_key_id"`
	NodeID        string                  `json:"node_id"`
	Route         clientwire.Route        `json:"request_route"`
	Digest        string                  `json:"packet_digest"`
	RequestDigest string                  `json:"request_digest,omitempty"`
	DTO           json.RawMessage         `json:"local_dto,omitempty"`
	PolicyTarget  *e2ee.LocalDomainPolicy `json:"policy_target,omitempty"`
	CreatedAt     string                  `json:"created_at"`
	Applied       bool                    `json:"applied"`
	Packet        []byte                  `json:"-"`
}

type localDomainSavedState struct {
	Format      string                       `json:"format"`
	Vault       appvault.Scope               `json:"vault"`
	DeviceKeyID string                       `json:"device_key_id"`
	OwnerKeyID  string                       `json:"owner_key_id"`
	NodeID      string                       `json:"node_id"`
	View        LocalCollaborationSnapshot   `json:"view"`
	Description *wire.LocalDomainDescription `json:"description,omitempty"`
}

type localDomainRuntime struct {
	versions                                                                       [len(localDomainNamespaces)]uint64
	loaded                                                                         bool
	state                                                                          localDomainSavedState
	original, response, recovery, recoveryResponse, reviewOriginal, reviewResponse *localDomainRecord
	available, discoveryTried                                                      bool
	checkedTarget, errorCode                                                       string
}

// State and both small prepare-review frames share one atomic namespace. The
// full App remains within its existing sixteen-record vault ceiling.
type localDomainStateBundle struct {
	State          localDomainSavedState `json:"state"`
	ReviewOriginal *localDomainRecord    `json:"review_original,omitempty"`
	ReviewResponse *localDomainRecord    `json:"review_response,omitempty"`
	OriginalBytes  int                   `json:"original_bytes"`
	ResponseBytes  int                   `json:"response_bytes"`
}

func encodeLocalDomainRecord(record *localDomainRecord) ([]byte, error) {
	header, err := json.Marshal(record)
	if err != nil || len(header) > 256<<10 || len(header)+len(record.Packet)+8 > localDomainRecordLimit {
		return nil, appvault.ErrInvalidVault
	}
	defer clear(header)
	raw := make([]byte, 8+len(header)+len(record.Packet))
	copy(raw, "CLD1")
	binary.BigEndian.PutUint32(raw[4:8], uint32(len(header)))
	copy(raw[8:], header)
	copy(raw[8+len(header):], record.Packet)
	return raw, nil
}

func decodeLocalDomainRecord(raw []byte) (*localDomainRecord, error) {
	if len(raw) < 9 || len(raw) > localDomainRecordLimit || string(raw[:4]) != "CLD1" {
		return nil, appvault.ErrInvalidVault
	}
	n := int(binary.BigEndian.Uint32(raw[4:8]))
	if n < 1 || n > 256<<10 || n > len(raw)-8 {
		return nil, appvault.ErrInvalidVault
	}
	var record localDomainRecord
	if decodeStateJSON(raw[8:8+n], &record) != nil {
		return nil, appvault.ErrInvalidVault
	}
	record.Packet = append([]byte(nil), raw[8+n:]...)
	return &record, nil
}

func cloneLocalDomainRecord(record *localDomainRecord) (*localDomainRecord, error) {
	raw, err := encodeLocalDomainRecord(record)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return decodeLocalDomainRecord(raw)
}

func (c *nativeController) persistLocalDomain(index int, record *localDomainRecord) error {
	var raw []byte
	var err error
	if record != nil {
		raw, err = encodeLocalDomainRecord(record)
		if err != nil {
			return c.failLocalDomainStorage(err)
		}
	}
	defer clear(raw)
	return c.writeLocalDomainState(index, raw)
}

func (c *nativeController) writeLocalDomainState(index int, raw []byte) error {
	if c.vault == nil || index < 0 || index >= len(localDomainNamespaces) || len(raw) > localDomainRecordLimit {
		return c.failLocalDomainStorage(appvault.ErrInvalidVault)
	}
	version, err := c.vault.CompareAndSwapState(localDomainNamespaces[index], c.localDomain.versions[index], raw)
	if err != nil {
		return c.failLocalDomainStorage(err)
	}
	c.localDomain.versions[index] = version
	return nil
}

func (c *nativeController) persistLocalDomainView() error {
	bundle := localDomainStateBundle{State: c.localDomain.state, ReviewOriginal: c.localDomain.reviewOriginal, ReviewResponse: c.localDomain.reviewResponse}
	var original, response []byte
	if bundle.ReviewOriginal != nil {
		original = bundle.ReviewOriginal.Packet
		bundle.OriginalBytes = len(original)
	}
	if bundle.ReviewResponse != nil {
		response = bundle.ReviewResponse.Packet
		bundle.ResponseBytes = len(response)
	}
	header, err := json.Marshal(bundle)
	if err != nil {
		return c.failLocalDomainStorage(err)
	}
	defer clear(header)
	if len(header) > 256<<10 || len(header)+len(original)+len(response)+8 > localDomainRecordLimit {
		return c.failLocalDomainStorage(appvault.ErrInvalidVault)
	}
	raw := make([]byte, 8+len(header)+len(original)+len(response))
	defer clear(raw)
	copy(raw, "CLS1")
	binary.BigEndian.PutUint32(raw[4:8], uint32(len(header)))
	offset := 8 + copy(raw[8:], header)
	offset += copy(raw[offset:], original)
	copy(raw[offset:], response)
	return c.writeLocalDomainState(localDomainState, raw)
}

func (c *nativeController) localDomainIdentity(vault appvault.Scope, device, owner string) bool {
	return c.device != nil && c.owner != nil && reflect.DeepEqual(vault, cardScope(c.connection)) && device == c.state.DeviceKeyID && owner == c.state.OwnerKeyID
}

func (c *nativeController) validateLocalDomainRequest(record *localDomainRecord, original *localDomainRecord) error {
	if record == nil || record.Format != "cicada.app-local-domain.request.v1" || !c.localDomainIdentity(record.Vault, record.DeviceKeyID, record.OwnerKeyID) || record.NodeID == "" || len(record.Packet) == 0 {
		return appvault.ErrScopeMismatch
	}
	packet, err := wire.DecodeLocalDomainPacket(record.Packet)
	if err != nil || packet.Packet.Route != record.Route || record.Route.Direction != clientwire.DirectionRequest || wire.LocalDomainPacketDigest(record.Packet) != record.Digest ||
		!reflect.DeepEqual(packet.SenderPublicIdentity, c.device.Public()) || record.Route.HubID != c.hub.HubID || record.Route.OwnerID != c.state.OwnerID || record.Route.DeviceID != c.state.DeviceID ||
		record.Route.SenderKeyID != c.state.DeviceKeyID || record.Route.ReceiverKeyID != c.hub.Public.ID {
		return appvault.ErrScopeMismatch
	}
	created, err := time.Parse(time.RFC3339Nano, record.CreatedAt)
	if err != nil || created.UTC().Format(time.RFC3339Nano) != record.CreatedAt {
		return appvault.ErrScopeMismatch
	}
	if record.Route.Operation == wire.OperationLocalDomainReconcile {
		if original == nil || record.RequestDigest != original.Digest || record.NodeID != original.NodeID {
			return appvault.ErrScopeMismatch
		}
	} else if original != nil || len(record.Packet) > wire.MaxLocalDomainOriginalBytes {
		return appvault.ErrScopeMismatch
	}
	_, err = c.localDomainDTO(record, original)
	return err
}

func (c *nativeController) ensureLocalDomainLoaded() error {
	if c.localDomain.loaded {
		return nil
	}
	if c.vault == nil || c.device == nil || c.owner == nil {
		return ErrInvalidAction
	}
	for _, entry := range []struct {
		index int
		dst   **localDomainRecord
	}{{localDomainOriginal, &c.localDomain.original}, {localDomainResponse, &c.localDomain.response}, {localDomainRecovery, &c.localDomain.recovery}, {localDomainRecoveryResponse, &c.localDomain.recoveryResponse}} {
		raw, version, found, err := c.vault.LoadState(localDomainNamespaces[entry.index])
		c.localDomain.versions[entry.index] = version
		if err != nil {
			clear(raw)
			return c.failLocalDomainStorage(err)
		}
		if found && len(raw) > 0 {
			*entry.dst, err = decodeLocalDomainRecord(raw)
		}
		clear(raw)
		if err != nil {
			return c.failLocalDomainStorage(err)
		}
	}
	raw, version, found, err := c.vault.LoadState(localDomainNamespaces[localDomainState])
	c.localDomain.versions[localDomainState] = version
	defer clear(raw)
	if err != nil {
		return c.failLocalDomainStorage(err)
	}
	if found && len(raw) > 0 {
		if len(raw) < 9 || len(raw) > localDomainRecordLimit || string(raw[:4]) != "CLS1" {
			return c.failLocalDomainStorage(appvault.ErrInvalidVault)
		}
		n := int(binary.BigEndian.Uint32(raw[4:8]))
		if n < 1 || n > 256<<10 || n > len(raw)-8 {
			return c.failLocalDomainStorage(appvault.ErrInvalidVault)
		}
		var bundle localDomainStateBundle
		if decodeStateJSON(raw[8:8+n], &bundle) != nil || bundle.OriginalBytes < 0 || bundle.ResponseBytes < 0 || bundle.OriginalBytes > len(raw)-8-n || bundle.ResponseBytes != len(raw)-8-n-bundle.OriginalBytes {
			return c.failLocalDomainStorage(appvault.ErrInvalidVault)
		}
		c.localDomain.state = bundle.State
		c.localDomain.reviewOriginal, c.localDomain.reviewResponse = bundle.ReviewOriginal, bundle.ReviewResponse
		if (bundle.ReviewOriginal == nil) != (bundle.ReviewResponse == nil) || (bundle.ReviewOriginal == nil) != (bundle.OriginalBytes == 0) || (bundle.ReviewResponse == nil) != (bundle.ResponseBytes == 0) {
			return c.failLocalDomainStorage(appvault.ErrInvalidVault)
		}
		if bundle.ReviewOriginal != nil {
			bundle.ReviewOriginal.Packet = append([]byte(nil), raw[8+n:8+n+bundle.OriginalBytes]...)
		}
		if bundle.ReviewResponse != nil {
			bundle.ReviewResponse.Packet = append([]byte(nil), raw[8+n+bundle.OriginalBytes:]...)
		}
		if c.localDomain.state.Format != "cicada.app-local-domain.state.v1" || !c.localDomainIdentity(c.localDomain.state.Vault, c.localDomain.state.DeviceKeyID, c.localDomain.state.OwnerKeyID) {
			return c.failLocalDomainStorage(appvault.ErrScopeMismatch)
		}
		if d := c.localDomain.state.Description; d != nil {
			if wire.ValidateLocalDomainDescription(*d, c.hub, time.Time{}) != nil || d.Policy.Node.NodeID != c.localDomain.state.NodeID || d.Policy.OwnerID != c.state.OwnerID || !reflect.DeepEqual(d.Policy.OwnerPublic, c.owner.Public()) {
				return c.failLocalDomainStorage(appvault.ErrScopeMismatch)
			}
		}
		c.localDomain.state.View.Current = false
		c.localDomain.state.View.StateReviewID = ""
	}
	for _, entry := range []struct{ request, original *localDomainRecord }{{c.localDomain.original, nil}, {c.localDomain.recovery, c.localDomain.original}, {c.localDomain.reviewOriginal, nil}} {
		if entry.request != nil {
			if err := c.validateLocalDomainRequest(entry.request, entry.original); err != nil {
				return c.failLocalDomainStorage(err)
			}
		}
	}
	for _, entry := range []struct{ request, response, original *localDomainRecord }{{c.localDomain.original, c.localDomain.response, nil}, {c.localDomain.recovery, c.localDomain.recoveryResponse, c.localDomain.original}, {c.localDomain.reviewOriginal, c.localDomain.reviewResponse, nil}} {
		if entry.response == nil {
			continue
		}
		if entry.request == nil || entry.response.Format != "cicada.app-local-domain.response.v1" || !c.localDomainIdentity(entry.response.Vault, entry.response.DeviceKeyID, entry.response.OwnerKeyID) || entry.response.RequestDigest != entry.request.Digest || entry.response.Route != entry.request.Route || entry.response.NodeID != entry.request.NodeID || entry.response.Digest != wire.LocalDomainPacketDigest(entry.response.Packet) {
			return c.failLocalDomainStorage(appvault.ErrScopeMismatch)
		}
		created, err := time.Parse(time.RFC3339Nano, entry.response.CreatedAt)
		if err != nil || created.UTC().Format(time.RFC3339Nano) != entry.response.CreatedAt {
			return c.failLocalDomainStorage(appvault.ErrScopeMismatch)
		}
		if _, err := c.openLocalDomainReceipt(entry.request, entry.response.Packet, entry.original); err != nil {
			return c.failLocalDomainStorage(err)
		}
	}
	c.localDomain.loaded = true
	return nil
}

func (c *nativeController) hasLocalDomainPending() bool {
	return c.localDomain.original != nil && !c.localDomain.original.Applied
}

func (c *nativeController) failLocalDomainStorage(err error) error {
	return c.failStorage("APP_LOCAL_COLLABORATION_COMMIT_FAILED", err)
}

func (c *nativeController) clearLocalDomainRuntime() {
	for _, r := range []*localDomainRecord{c.localDomain.original, c.localDomain.response, c.localDomain.recovery, c.localDomain.recoveryResponse, c.localDomain.reviewOriginal, c.localDomain.reviewResponse} {
		if r != nil {
			clear(r.Packet)
			clear(r.DTO)
		}
	}
	if d := c.localDomain.state.Description; d != nil {
		clear(d.PolicyProof)
	}
	c.localDomain = localDomainRuntime{}
}

var errLocalDomainUnconfirmed = errors.New("local collaboration request outcome is unconfirmed; original packet retained")
