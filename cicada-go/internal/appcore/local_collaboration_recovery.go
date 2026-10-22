package appcore

import (
	"context"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) recoverLocalCollaboration(ctx context.Context) error {
	if err := c.ensureLocalDomainLoaded(); err != nil {
		return err
	}
	if !c.hasLocalDomainPending() {
		return ErrInvalidAction
	}
	original := c.localDomain.original
	var receipt localDomainReceipt
	var err error
	if c.localDomain.response != nil {
		receipt, err = c.openLocalDomainReceipt(original, c.localDomain.response.Packet, nil)
		if err != nil {
			return c.failLocalDomainStorage(err)
		}
	} else {
		if c.localDomain.recovery == nil {
			request, err := wire.NewLocalDomainReconcile(c.nodeSession(), original.Packet, c.cfg.Now().UTC())
			if err != nil {
				return err
			}
			record, err := c.newLocalDomainRequest(original.NodeID, request)
			if err != nil {
				return err
			}
			record.RequestDigest = original.Digest
			if err := c.validateLocalDomainRequest(record, original); err != nil {
				return err
			}
			if err := c.persistLocalDomain(localDomainRecovery, record); err != nil {
				return err
			}
			c.localDomain.recovery = record
		}
		recovery := c.localDomain.recovery
		var opened localDomainReceipt
		if c.localDomain.recoveryResponse != nil {
			opened, err = c.openLocalDomainReceipt(recovery, c.localDomain.recoveryResponse.Packet, original)
		} else {
			raw, postErr := c.postLocalDomainPacket(ctx, recovery)
			if postErr != nil {
				return c.failLocalCollaboration("APP_LOCAL_COLLABORATION_UNKNOWN", postErr)
			}
			defer clear(raw)
			opened, err = c.openLocalDomainReceipt(recovery, raw, original)
			if err == nil {
				c.localDomain.recoveryResponse, err = c.saveLocalDomainResponse(localDomainRecoveryResponse, recovery, raw)
			}
		}
		if err != nil {
			return c.failLocalCollaboration("APP_LOCAL_COLLABORATION_RESPONSE_UNCONFIRMED", errLocalDomainUnconfirmed)
		}
		if opened.Recovery == nil || opened.Nested == nil {
			return wire.ErrInvalid
		}
		receipt = *opened.Nested
		c.localDomain.response, err = c.saveLocalDomainResponse(localDomainResponse, original, opened.Recovery.ReceiptPacket)
		if err != nil {
			return err
		}
	}
	// Historical receipts restore durable outcomes. Only an independently
	// validated, still-live prepare review can offer a new explicit activation;
	// mutation receipts themselves never restore current management authority.
	if err := c.applyLocalDomainReceipt(original, receipt); err != nil {
		return err
	}
	copy := *original
	copy.Applied = true
	if err := c.persistLocalDomain(localDomainOriginal, &copy); err != nil {
		return err
	}
	c.localDomain.original = &copy
	if recovery := c.localDomain.recovery; recovery != nil {
		copy := *recovery
		copy.Applied = true
		if err := c.persistLocalDomain(localDomainRecovery, &copy); err != nil {
			return err
		}
		c.localDomain.recovery = &copy
	}
	c.localDomain.errorCode = ""
	c.localDomain.checkedTarget = ""
	c.publish()
	if receipt.Challenge == nil && c.nodeAccountReady() && c.localCollaborationNodeID() == original.NodeID {
		return c.refreshLocalCollaboration(ctx)
	}
	return nil
}
