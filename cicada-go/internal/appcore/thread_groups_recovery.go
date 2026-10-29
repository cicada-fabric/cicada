package appcore

import (
	"context"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) recoverThreadGroup(ctx context.Context) error {
	if err := c.ensureThreadGroupsLoaded(); err != nil {
		return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
	}
	if !c.hasThreadGroupPending() || !c.ownerAccountReady() || c.hasNodePending() || c.nodePairTrustBusy() || !canBeginOperation(c.state.Pending) || c.state.Recovery != nil {
		return ErrInvalidAction
	}
	g := &c.threadGroups
	original := g.original
	if g.response != nil {
		result, err := c.openThreadGroupResult(original, g.response.Packet, nil)
		if err != nil {
			return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
		}
		if threadGroupResultSettles(original, result) {
			return c.finishThreadGroup(original, result, false)
		}
	}
	if err := c.refreshThreadGroupQuerySession(ctx); err != nil {
		return err
	}
	if g.recovery == nil {
		scope, err := c.localCollaborationActor(ctx)
		if err != nil {
			return err
		}
		recovery, err := c.makeThreadGroupRecovery(original, scope)
		if err != nil {
			return err
		}
		if err := c.validateThreadGroupRecord(recovery, original); err != nil {
			clear(recovery.Packet)
			clear(recovery.DTO)
			return err
		}
		if err := c.threadGroupBudget(original, recovery); err != nil {
			clear(recovery.Packet)
			clear(recovery.DTO)
			return c.failThreadGroups("APP_THREAD_GROUP_STORAGE_BUDGET", err)
		}
		if err := c.persistThreadGroupRecord(threadGroupRecovery, recovery); err != nil {
			return err
		}
		g.recovery = recovery
	}
	recovery := g.recovery
	if g.recoveryResponse == nil {
		if err := c.threadGroupBudget(original, recovery); err != nil {
			return c.failThreadGroups("APP_THREAD_GROUP_STORAGE_BUDGET", err)
		}
		// Within one verified login a lost response retries this same wrapper.
		// A raw HTTP error never settles or replaces the business original.
		raw, err := c.postThreadGroupPacket(ctx, recovery)
		if err != nil {
			return c.failThreadGroups("OUTCOME_UNCERTAIN", err)
		}
		defer clear(raw)
		opened, err := c.openThreadGroupResult(recovery, raw, original)
		if err != nil {
			return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
		}
		if len(opened.ReceiptPacket) != 0 {
			nested, err := c.openThreadGroupResult(original, opened.ReceiptPacket, nil)
			if err != nil || !threadGroupResultSettles(original, nested) {
				return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
			}
			return c.acceptThreadGroupRecoveredReceipt(original, opened.ReceiptPacket, nested)
		} else if !c.threadGroupEmptyTerminalQuery(recovery, opened, original) {
			// A nonterminal query cannot become a permanent response cache.
			// Keep and retry the exact wrapper; it supplies no original outcome.
			return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
		}
		// The authenticated empty observation settles only this read-only query.
		// A crash before its retirement retries the exact saved query; no outer
		// response cache is needed, and the business original remains untouched.
		return c.retireThreadGroupEmptyQuery()
	}
	result, err := c.openThreadGroupResult(recovery, g.recoveryResponse.Packet, original)
	if err != nil {
		return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
	}
	if len(result.ReceiptPacket) != 0 {
		nested, err := c.openThreadGroupResult(original, result.ReceiptPacket, nil)
		if err != nil {
			return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
		}
		if !threadGroupResultSettles(original, nested) {
			return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
		}
		return c.acceptThreadGroupRecoveredReceipt(original, result.ReceiptPacket, nested)
	}
	if c.threadGroupEmptyTerminalQuery(recovery, result, original) {
		return c.retireThreadGroupEmptyQuery()
	}
	return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
}

func (c *nativeController) retireThreadGroupEmptyQuery() error {
	g := &c.threadGroups
	// Retain support for an authenticated response cached by an earlier App.
	if g.recoveryResponse != nil {
		if err := c.persistThreadGroupRecord(threadGroupRecoveryResponse, nil); err != nil {
			return err
		}
		clear(g.recoveryResponse.Packet)
		g.recoveryResponse = nil
	}
	if err := c.persistThreadGroupRecord(threadGroupRecovery, nil); err != nil {
		return err
	}
	clear(g.recovery.Packet)
	clear(g.recovery.DTO)
	g.recovery = nil
	return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
}

// The exact original receipt has been authenticated against its own request,
// after the wrapper authenticated its association. Retiring the settled query
// observation cannot execute or replace the retained business original. A crash
// before saving the inner receipt can repeat the same read-only query.
func (c *nativeController) acceptThreadGroupRecoveredReceipt(original *threadGroupRecord, packet []byte, result *wire.OwnerEndpointGroupsResult) error {
	g := &c.threadGroups
	if err := c.threadGroupBudget(original, g.recovery); err != nil {
		return c.failThreadGroups("APP_THREAD_GROUP_STORAGE_BUDGET", err)
	}
	if g.recoveryResponse != nil {
		if err := c.persistThreadGroupRecord(threadGroupRecoveryResponse, nil); err != nil {
			return err
		}
		clear(g.recoveryResponse.Packet)
		g.recoveryResponse = nil
	}
	response, err := c.saveThreadGroupResponse(threadGroupResponse, original, packet)
	if err != nil {
		return err
	}
	g.response = response
	return c.finishThreadGroup(original, result, false)
}
