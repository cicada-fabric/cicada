package appcore

import (
	"encoding/binary"
	"encoding/json"
	"reflect"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const threadGroupRecordLimit = 1 << 20 // The vault per-record byte cap is unchanged.

const (
	threadGroupOriginal = iota
	threadGroupResponse
	threadGroupRecovery
	threadGroupRecoveryResponse
	threadGroupState
)

var threadGroupNamespaces = [...]string{
	"appcore.endpoint-groups-original.v1", "appcore.endpoint-groups-response.v1",
	"appcore.endpoint-groups-recovery.v1", "appcore.endpoint-groups-recovery-response.v1",
	"appcore.endpoint-groups-state.v1",
}

// These are App storage headers, not wire DTOs. Ciphertext is appended raw so
// the bounded recovery envelope is not expanded by another layer of base64.
type threadGroupRecord struct {
	Format         string
	Vault          appvault.Scope
	DeviceKeyID    string
	OwnerKeyID     string
	NodeID         string
	NetworkID      string
	NetworkName    string
	LocalUserScope string
	Route          clientwire.Route
	Digest         string
	ParentDigest   string
	DTO            json.RawMessage
	CreatedAt      string
	Applied        bool
	Review         *wire.OwnerEndpointGroupsReview
	ExpectedHead   *e2ee.EndpointGroupOwnerControl
	Binding        *e2ee.OwnerAppNodeBinding
	Thread         *wire.OwnerEndpointGroupsThreadCard
	Group          *wire.OwnerEndpointGroupsGroupCard
	Relation       *wire.OwnerEndpointGroupsRelationCard
	Packet         []byte `json:"-"`
}

type threadGroupSavedReview struct {
	Format        string
	Vault         appvault.Scope
	DeviceKeyID   string
	OwnerKeyID    string
	Original      *threadGroupRecord
	Response      *threadGroupRecord
	OriginalBytes int
	ResponseBytes int
}

type threadGroupsRuntime struct {
	versions                                       [len(threadGroupNamespaces)]uint64
	loaded, available, discoveryTried              bool
	nativeSelfGroups                               bool
	view                                           ThreadGroupsSnapshot
	original, response, recovery, recoveryResponse *threadGroupRecord
	reviewOriginal, reviewResponse                 *threadGroupRecord
	threads                                        []wire.OwnerEndpointGroupsThreadCard
	selected                                       *wire.OwnerEndpointGroupsThreadCard
	candidates                                     []wire.OwnerEndpointGroupsGroupCard
	selectedRelations                              []wire.OwnerEndpointGroupsRelationCard
	listingRevision                                uint64
	viewSessionDigest                              string
	review                                         *wire.OwnerEndpointGroupsReview
}

func encodeThreadGroupFrame(magic string, header any, packets ...[]byte) ([]byte, error) {
	metadata, err := json.Marshal(header)
	if err != nil {
		return nil, err
	}
	defer clear(metadata)
	total := 8 + len(metadata)
	for _, packet := range packets {
		if len(packet) > threadGroupRecordLimit-total {
			return nil, appvault.ErrInvalidVault
		}
		total += len(packet)
	}
	if len(magic) != 4 || len(metadata) > 256<<10 || total > threadGroupRecordLimit {
		return nil, appvault.ErrInvalidVault
	}
	raw := make([]byte, total)
	copy(raw, magic)
	binary.BigEndian.PutUint32(raw[4:8], uint32(len(metadata)))
	offset := 8 + copy(raw[8:], metadata)
	for _, packet := range packets {
		offset += copy(raw[offset:], packet)
	}
	return raw, nil
}

func decodeThreadGroupFrame(raw []byte, magic string, header any) ([]byte, error) {
	if len(raw) < 9 || len(raw) > threadGroupRecordLimit || len(magic) != 4 || string(raw[:4]) != magic {
		return nil, appvault.ErrInvalidVault
	}
	n := int(binary.BigEndian.Uint32(raw[4:8]))
	if n < 1 || n > 256<<10 || n > len(raw)-8 || decodeStateJSON(raw[8:8+n], header) != nil {
		return nil, appvault.ErrInvalidVault
	}
	return raw[8+n:], nil
}

func encodeThreadGroupRecord(record *threadGroupRecord) ([]byte, error) {
	return encodeThreadGroupFrame("CEG1", record, record.Packet)
}

func decodeThreadGroupRecord(raw []byte) (*threadGroupRecord, error) {
	var record threadGroupRecord
	packet, err := decodeThreadGroupFrame(raw, "CEG1", &record)
	if err != nil {
		return nil, err
	}
	record.Packet = append([]byte(nil), packet...)
	return &record, nil
}

func cloneThreadGroupRecord(record *threadGroupRecord) (*threadGroupRecord, error) {
	if record == nil {
		return nil, nil
	}
	raw, err := encodeThreadGroupRecord(record)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return decodeThreadGroupRecord(raw)
}

func (c *nativeController) threadGroupReviewBytes(original, response *threadGroupRecord) ([]byte, error) {
	state := threadGroupSavedReview{Format: "cicada.app-endpoint-groups.state.v1", Vault: cardScope(c.connection), DeviceKeyID: c.state.DeviceKeyID, OwnerKeyID: c.state.OwnerKeyID, Original: original, Response: response}
	if (original == nil) != (response == nil) {
		return nil, appvault.ErrInvalidVault
	}
	if original == nil {
		return encodeThreadGroupFrame("CEGS", state)
	}
	state.OriginalBytes, state.ResponseBytes = len(original.Packet), len(response.Packet)
	return encodeThreadGroupFrame("CEGS", state, original.Packet, response.Packet)
}

func (c *nativeController) persistThreadGroupReview(original, response *threadGroupRecord) error {
	original, err := cloneThreadGroupRecord(original)
	if err != nil {
		return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
	}
	response, err = cloneThreadGroupRecord(response)
	if err != nil {
		return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
	}
	raw, err := c.threadGroupReviewBytes(original, response)
	if err != nil {
		return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
	}
	defer clear(raw)
	if err := c.writeThreadGroupSlot(threadGroupState, raw); err != nil {
		return err
	}
	for _, old := range []*threadGroupRecord{c.threadGroups.reviewOriginal, c.threadGroups.reviewResponse} {
		if old != nil {
			clear(old.Packet)
			clear(old.DTO)
		}
	}
	c.threadGroups.reviewOriginal, c.threadGroups.reviewResponse = original, response
	return nil
}

func (c *nativeController) ensureThreadGroupsLoaded() error {
	if c.threadGroups.loaded {
		return nil
	}
	if c.vault == nil {
		return appvault.ErrClosed
	}
	for _, entry := range []struct {
		index int
		dst   **threadGroupRecord
	}{{threadGroupOriginal, &c.threadGroups.original}, {threadGroupResponse, &c.threadGroups.response}, {threadGroupRecovery, &c.threadGroups.recovery}, {threadGroupRecoveryResponse, &c.threadGroups.recoveryResponse}} {
		raw, version, found, err := c.vault.LoadState(threadGroupNamespaces[entry.index])
		c.threadGroups.versions[entry.index] = version
		if err == nil && found && len(raw) != 0 {
			*entry.dst, err = decodeThreadGroupRecord(raw)
		}
		clear(raw)
		if err != nil {
			return err
		}
	}
	raw, version, found, err := c.vault.LoadState(threadGroupNamespaces[threadGroupState])
	c.threadGroups.versions[threadGroupState] = version
	defer clear(raw)
	if err != nil {
		return err
	}
	if found && len(raw) != 0 {
		var state threadGroupSavedReview
		packets, err := decodeThreadGroupFrame(raw, "CEGS", &state)
		if err != nil || state.Format != "cicada.app-endpoint-groups.state.v1" || state.Vault != cardScope(c.connection) || state.DeviceKeyID != c.state.DeviceKeyID || state.OwnerKeyID != c.state.OwnerKeyID ||
			(state.Original == nil) != (state.Response == nil) || state.OriginalBytes < 0 || state.ResponseBytes < 0 || state.OriginalBytes > len(packets) || state.ResponseBytes != len(packets)-state.OriginalBytes {
			return appvault.ErrScopeMismatch
		}
		if state.Original != nil {
			if state.OriginalBytes == 0 || state.ResponseBytes == 0 {
				return appvault.ErrInvalidVault
			}
			state.Original.Packet = append([]byte(nil), packets[:state.OriginalBytes]...)
			state.Response.Packet = append([]byte(nil), packets[state.OriginalBytes:]...)
			c.threadGroups.reviewOriginal, c.threadGroups.reviewResponse = state.Original, state.Response
		} else if len(packets) != 0 {
			return appvault.ErrInvalidVault
		}
	}
	for _, pair := range []struct{ request, response, original *threadGroupRecord }{
		{c.threadGroups.original, c.threadGroups.response, nil}, {c.threadGroups.recovery, c.threadGroups.recoveryResponse, c.threadGroups.original},
		{c.threadGroups.reviewOriginal, c.threadGroups.reviewResponse, nil},
	} {
		if pair.request == nil {
			if pair.response != nil {
				return appvault.ErrInvalidVault
			}
			continue
		}
		if c.device == nil || c.owner == nil || c.validateThreadGroupRecord(pair.request, pair.original) != nil {
			return appvault.ErrScopeMismatch
		}
		if pair.response != nil {
			r := pair.response
			if r.Format != "cicada.app-endpoint-groups.response.v1" || r.Vault != pair.request.Vault || r.DeviceKeyID != pair.request.DeviceKeyID || r.OwnerKeyID != pair.request.OwnerKeyID ||
				r.NodeID != pair.request.NodeID || r.NetworkID != pair.request.NetworkID || !reflect.DeepEqual(r.Route, pair.request.Route) || r.ParentDigest != pair.request.Digest || r.Digest != wire.OwnerEndpointGroupsPacketDigest(r.Packet) {
				return appvault.ErrScopeMismatch
			}
			result, err := c.openThreadGroupResult(pair.request, r.Packet, pair.original)
			if err != nil || pair.request.Applied && !threadGroupResultSettles(pair.request, result) {
				return appvault.ErrInvalidVault
			}
			if pair.request == c.threadGroups.reviewOriginal {
				if result.Review == nil || !threadGroupReviewCASMatches(pair.request, *result.Review) {
					return appvault.ErrInvalidVault
				}
				c.threadGroups.review = result.Review
			}
		}
	}
	c.threadGroups.loaded = true
	return nil
}

func (c *nativeController) hasThreadGroupPending() bool {
	return c.threadGroups.original != nil && !c.threadGroups.original.Applied
}

func (c *nativeController) writeThreadGroupSlot(index int, raw []byte) error {
	if c.vault == nil || index < 0 || index >= len(threadGroupNamespaces) || len(raw) > threadGroupRecordLimit {
		return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", appvault.ErrInvalidVault)
	}
	version, err := c.vault.CompareAndSwapState(threadGroupNamespaces[index], c.threadGroups.versions[index], raw)
	if err != nil {
		return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
	}
	c.threadGroups.versions[index] = version
	return nil
}

func (c *nativeController) persistThreadGroupRecord(index int, record *threadGroupRecord) error {
	var raw []byte
	var err error
	if record != nil {
		raw, err = encodeThreadGroupRecord(record)
		if err != nil {
			return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
		}
	}
	defer clear(raw)
	return c.writeThreadGroupSlot(index, raw)
}

func (c *nativeController) preflightThreadGroups(updates map[int][]byte) error {
	if c.vault == nil {
		return appvault.ErrClosed
	}
	names := make(map[string][]byte, len(updates))
	for index, raw := range updates {
		if index < 0 || index >= len(threadGroupNamespaces) || len(raw) > threadGroupRecordLimit {
			return appvault.ErrInvalidVault
		}
		names[threadGroupNamespaces[index]] = raw
	}
	return c.vault.CheckStateUpdates(names)
}

func (c *nativeController) clearThreadGroupsRuntime() {
	for _, record := range []*threadGroupRecord{c.threadGroups.original, c.threadGroups.response, c.threadGroups.recovery, c.threadGroups.recoveryResponse, c.threadGroups.reviewOriginal, c.threadGroups.reviewResponse} {
		if record != nil {
			clear(record.Packet)
			clear(record.DTO)
		}
	}
	c.threadGroups = threadGroupsRuntime{}
}
