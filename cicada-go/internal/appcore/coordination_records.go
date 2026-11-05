package appcore

import (
	"encoding/json"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// These are local encrypted-vault carriers. They do not define a Hub request,
// proof, result or retry policy. The approved wire codec validates those bytes.
const (
	coordinationOriginal = iota
	coordinationResponse
	coordinationQuery
	coordinationQueryResponse
	coordinationReview
)

var coordinationNamespaces = [...]string{
	"appcore.thread-collaboration-original.v1",
	"appcore.thread-collaboration-response.v1",
	"appcore.thread-collaboration-query.v1",
	"appcore.thread-collaboration-query-response.v1",
	"appcore.thread-collaboration-review.v1",
}

type coordinationRecord struct {
	Format       string
	Vault        appvault.Scope
	DeviceKeyID  string
	OwnerKeyID   string
	Route        clientwire.Route
	Digest       string
	ParentDigest string
	DTO          json.RawMessage
	CreatedAt    string
	Applied      bool
	DisplayName  string
	HolderName   string
	Review       *wire.ThreadCollaborationOwnerReview
	Packet       []byte `json:"-"`
}

type coordinationObservation struct {
	Read           wire.ThreadCollaborationOwnerReadResult
	SessionDigest  string
	FreshUntil     string
	TargetEndpoint string
}

type coordinationRuntime struct {
	versions                                                                 [len(coordinationNamespaces)]uint64
	loaded, discoveryTried, rolesAvailable, locksAvailable                   bool
	original, response, query, queryResponse, reviewOriginal, reviewResponse *coordinationRecord
	review                                                                   *wire.ThreadCollaborationOwnerReview
	observations                                                             []coordinationObservation
	view                                                                     CoordinationSnapshot
}

func (c *nativeController) hasCoordinationPending() bool {
	return c.coordination.original != nil && !c.coordination.original.Applied
}

func (c *nativeController) persistCoordinationSlot(index int, raw []byte) error {
	if c.vault == nil || index < 0 || index >= len(coordinationNamespaces) || len(raw) > threadGroupRecordLimit {
		return c.failStorage("APP_COORDINATION_STORAGE_FAILED", appvault.ErrInvalidVault)
	}
	version, err := c.vault.CompareAndSwapState(coordinationNamespaces[index], c.coordination.versions[index], raw)
	if err != nil {
		return c.failStorage("APP_COORDINATION_STORAGE_FAILED", err)
	}
	c.coordination.versions[index] = version
	return nil
}

func (c *nativeController) persistCoordinationRecord(index int, record *coordinationRecord) error {
	raw, err := encodeCoordinationRecord(record)
	if err != nil {
		return c.failStorage("APP_COORDINATION_STORAGE_FAILED", err)
	}
	defer clear(raw)
	return c.persistCoordinationSlot(index, raw)
}

func (c *nativeController) ensureCoordinationLoaded() error {
	g := &c.coordination
	if g.loaded {
		return nil
	}
	if c.vault == nil {
		return appvault.ErrClosed
	}
	for _, pair := range []struct {
		index int
		dst   **coordinationRecord
	}{{coordinationOriginal, &g.original}, {coordinationResponse, &g.response}, {coordinationQuery, &g.query}, {coordinationQueryResponse, &g.queryResponse}} {
		raw, version, found, err := c.vault.LoadState(coordinationNamespaces[pair.index])
		g.versions[pair.index] = version
		if err == nil && found && len(raw) > 0 {
			*pair.dst, err = decodeCoordinationRecord(raw)
		}
		clear(raw)
		if err != nil {
			return err
		}
	}
	raw, version, found, err := c.vault.LoadState(coordinationNamespaces[coordinationReview])
	g.versions[coordinationReview] = version
	if err == nil && found && len(raw) > 0 {
		g.reviewOriginal, g.reviewResponse, err = decodeCoordinationReview(raw)
	}
	clear(raw)
	if err != nil {
		return err
	}
	for _, record := range []*coordinationRecord{g.original, g.query, g.reviewOriginal} {
		if record != nil && c.validateCoordinationRecord(record) != nil {
			return appvault.ErrScopeMismatch
		}
	}
	for _, pair := range []struct{ request, response *coordinationRecord }{{g.original, g.response}, {g.reviewOriginal, g.reviewResponse}, {g.query, g.queryResponse}} {
		if pair.response == nil {
			if pair.request == g.reviewOriginal && pair.request != nil {
				return appvault.ErrInvalidVault
			}
			continue
		}
		if pair.request == nil || c.validateCoordinationResponse(pair.request, pair.response) != nil {
			return appvault.ErrScopeMismatch
		}
		result, err := c.openCoordinationResult(pair.request, pair.response.Packet)
		if err != nil {
			return err
		}
		if pair.request == g.reviewOriginal {
			if result.Review == nil {
				return appvault.ErrInvalidVault
			}
			g.review = result.Review
		}
		if pair.request == g.query && result.State != "ORIGINAL_NOT_APPLIED" {
			return appvault.ErrInvalidVault
		}
		if pair.request.Applied && !coordinationResultSettles(result) {
			return appvault.ErrInvalidVault
		}
	}
	g.loaded = true
	return nil
}

func (c *nativeController) clearCoordinationRuntime() {
	g := &c.coordination
	for _, record := range []*coordinationRecord{g.original, g.response, g.query, g.queryResponse, g.reviewOriginal, g.reviewResponse} {
		clearCoordinationRecord(record)
	}
	c.coordination = coordinationRuntime{}
}

type coordinationSavedReview struct {
	Format        string
	Original      *coordinationRecord
	Response      *coordinationRecord
	OriginalBytes int
	ResponseBytes int
}

func encodeCoordinationRecord(record *coordinationRecord) ([]byte, error) {
	if record == nil {
		return nil, nil
	}
	return encodeThreadGroupFrame("CTC1", record, record.Packet)
}

func decodeCoordinationRecord(raw []byte) (*coordinationRecord, error) {
	var record coordinationRecord
	packet, err := decodeThreadGroupFrame(raw, "CTC1", &record)
	if err != nil || len(packet) == 0 {
		return nil, appvault.ErrInvalidVault
	}
	record.Packet = append([]byte(nil), packet...)
	return &record, nil
}

// Both reviewed packets change in one vault CAS. A restart cannot combine an
// old prepare with another review, including after an interrupted replacement.
func encodeCoordinationReview(original, response *coordinationRecord) ([]byte, error) {
	if original == nil || response == nil || len(original.Packet) == 0 || len(response.Packet) == 0 {
		return nil, appvault.ErrInvalidVault
	}
	header := coordinationSavedReview{Format: "cicada.app-thread-collaboration.review.v1", Original: original, Response: response,
		OriginalBytes: len(original.Packet), ResponseBytes: len(response.Packet)}
	return encodeThreadGroupFrame("CTCR", header, original.Packet, response.Packet)
}

func decodeCoordinationReview(raw []byte) (*coordinationRecord, *coordinationRecord, error) {
	var header coordinationSavedReview
	packets, err := decodeThreadGroupFrame(raw, "CTCR", &header)
	if err != nil || header.Format != "cicada.app-thread-collaboration.review.v1" || header.Original == nil || header.Response == nil ||
		header.OriginalBytes < 1 || header.OriginalBytes > len(packets) || header.ResponseBytes < 1 || header.ResponseBytes != len(packets)-header.OriginalBytes {
		return nil, nil, appvault.ErrInvalidVault
	}
	header.Original.Packet = append([]byte(nil), packets[:header.OriginalBytes]...)
	header.Response.Packet = append([]byte(nil), packets[header.OriginalBytes:]...)
	return header.Original, header.Response, nil
}

func clearCoordinationRecord(record *coordinationRecord) {
	if record != nil {
		clear(record.DTO)
		clear(record.Packet)
	}
}
