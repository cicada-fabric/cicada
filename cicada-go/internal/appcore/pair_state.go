package appcore

import (
	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

type pairAuthorityState struct {
	Format            string            `json:"format"`
	Vault             appvault.Scope    `json:"vault_scope"`
	DeviceID          string            `json:"device_id"`
	DeviceKeyID       string            `json:"device_key_id"`
	OwnerKeyID        string            `json:"owner_key_id"`
	BootstrapProof    []byte            `json:"bootstrap_proof,omitempty"`
	LastAppliedDigest string            `json:"last_applied_digest,omitempty"`
	View              PairSetupSnapshot `json:"view"`
}

// Only the ordinary prepare/challenge pair required for exact target review is
// retained here. A decoded reconcile envelope is never stored as review data.
type pairReviewRecord struct {
	Format   string             `json:"format"`
	Original pairRequestRecord  `json:"original"`
	Response pairResponseRecord `json:"response"`
}

func (c *nativeController) newPairState() pairAuthorityState {
	return pairAuthorityState{Format: "cicada.native-pair.state.v1", Vault: cardScope(c.connection),
		DeviceID: c.state.DeviceID, DeviceKeyID: c.state.DeviceKeyID, OwnerKeyID: c.state.OwnerKeyID}
}

func (c *nativeController) hasPairPending() bool {
	return c.pairOriginal != nil && !c.pairOriginal.Applied || c.pairRecovery != nil
}

func (c *nativeController) loadPairState() error {
	c.clearPairRuntime()
	c.pair = c.newPairState()
	if found, err := c.loadPairRecord(pairStateRecord, &c.pair); err != nil {
		return err
	} else if found && (c.pair.Format != "cicada.native-pair.state.v1" || c.pair.Vault != c.vault.Scope() ||
		c.pair.DeviceID != c.state.DeviceID || c.pair.DeviceKeyID != c.state.DeviceKeyID || c.pair.OwnerKeyID != c.state.OwnerKeyID) {
		return appvault.ErrScopeMismatch
	}
	c.pair.View.Current, c.pair.View.AdministrativePermission = false, false
	var original, recovery pairRequestRecord
	if found, err := c.loadPairRecord(pairOriginalRecord, &original); err != nil {
		return err
	} else if found {
		if err := c.validatePairRequest(&original, nil); err != nil {
			return err
		}
		c.pairOriginal = &original
	}
	if found, err := c.loadPairRecord(pairRecoveryRecord, &recovery); err != nil {
		return err
	} else if found {
		if c.pairOriginal == nil || c.validatePairRequest(&recovery, c.pairOriginal) != nil {
			return appvault.ErrScopeMismatch
		}
		c.pairRecovery = &recovery
	}
	for _, entry := range []struct {
		index    int
		request  *pairRequestRecord
		response **pairResponseRecord
		recovery bool
	}{{pairOriginalResponseRecord, c.pairOriginal, &c.pairOriginalResponse, false}, {pairRecoveryResponseRecord, c.pairRecovery, &c.pairRecoveryResponse, true}} {
		var response pairResponseRecord
		found, err := c.loadPairRecord(entry.index, &response)
		if err != nil {
			return err
		}
		if !found {
			continue
		}
		if validatePairResponseLink(&response, entry.request, entry.recovery) != nil {
			return appvault.ErrScopeMismatch
		}
		var target *pairRequestRecord
		if entry.recovery {
			target = c.pairOriginal
		}
		if _, err := c.openPairReceipt(entry.request, response.Packet, target); err != nil {
			return err
		}
		*entry.response = &response
	}
	var review pairReviewRecord
	if found, err := c.loadPairRecord(pairReviewRecordIndex, &review); err != nil {
		return err
	} else if found {
		if review.Format != "cicada.native-pair.review.v1" || c.validatePairRequest(&review.Original, nil) != nil ||
			validatePairResponseLink(&review.Response, &review.Original, false) != nil ||
			(review.Original.Route.Operation != wire.OperationNativePairBootstrapPrepare && review.Original.Route.Operation != wire.OperationNativePairConsentPrepare) {
			return appvault.ErrScopeMismatch
		}
		if _, err := c.openPairReceipt(&review.Original, review.Response.Packet, nil); err != nil {
			return err
		}
		c.pairReview = &review
	}
	return nil
}

func (c *nativeController) preservePairReview() error {
	if c.pairOriginal == nil || c.pairOriginalResponse == nil {
		return ErrInvalidAction
	}
	request, response := *c.pairOriginal, *c.pairOriginalResponse
	request.Packet, request.DTO = append([]byte(nil), request.Packet...), append([]byte(nil), request.DTO...)
	response.Packet = append([]byte(nil), response.Packet...)
	review := &pairReviewRecord{Format: "cicada.native-pair.review.v1", Original: request, Response: response}
	if err := c.persistPairRecord(pairReviewRecordIndex, review); err != nil {
		return err
	}
	c.pairReview = review
	return nil
}

func (c *nativeController) clearPairRuntime() {
	for _, r := range []*pairRequestRecord{c.pairOriginal, c.pairRecovery} {
		if r != nil {
			clear(r.Packet)
			clear(r.DTO)
		}
	}
	for _, r := range []*pairResponseRecord{c.pairOriginalResponse, c.pairRecoveryResponse} {
		if r != nil {
			clear(r.Packet)
		}
	}
	if c.pairReview != nil {
		clear(c.pairReview.Original.Packet)
		clear(c.pairReview.Original.DTO)
		clear(c.pairReview.Response.Packet)
	}
	clear(c.pair.BootstrapProof)
	c.pair, c.pairVersions = pairAuthorityState{}, pairRecordVersions{}
	c.pairOriginal, c.pairRecovery, c.pairReview = nil, nil, nil
	c.pairOriginalResponse, c.pairRecoveryResponse, c.pairCurrent = nil, nil, nil
	c.pairAvailable, c.pairDiscoveryTried, c.pairError = false, false, ""
}
