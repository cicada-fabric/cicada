package appcore

import "context"

func (c *nativeController) recoverThreadGroup(ctx context.Context) error {
	if err := c.ensureThreadGroupsLoaded(); err != nil {
		return c.failStorage("APP_THREAD_GROUP_STORAGE_FAILED", err)
	}
	if !c.hasThreadGroupPending() || !c.pairAccountReady() || c.hasNodePending() || c.nodePairTrustBusy() || !canBeginOperation(c.state.Pending) || c.state.Recovery != nil {
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
		} else if !c.threadGroupEmptyTerminalQuery(recovery, opened, original) {
			// A nonterminal query cannot become a permanent response cache.
			// Keep and retry the exact wrapper; it supplies no original outcome.
			return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
		}
		g.recoveryResponse, err = c.saveThreadGroupResponse(threadGroupRecoveryResponse, recovery, raw)
		if err != nil {
			return err
		}
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
		g.response, err = c.saveThreadGroupResponse(threadGroupResponse, original, result.ReceiptPacket)
		if err != nil {
			return err
		}
		return c.finishThreadGroup(original, nested, false)
	}
	if c.threadGroupEmptyTerminalQuery(recovery, result, original) {
		// This wrapper has an authenticated terminal read outcome, while its
		// business original remains unknown. Release only the settled wrapper
		// so a later login can make a fresh query for the same original bytes.
		if err := c.persistThreadGroupRecord(threadGroupRecoveryResponse, nil); err != nil {
			return err
		}
		if err := c.persistThreadGroupRecord(threadGroupRecovery, nil); err != nil {
			return err
		}
		clear(g.recovery.Packet)
		clear(g.recovery.DTO)
		clear(g.recoveryResponse.Packet)
		g.recovery, g.recoveryResponse = nil, nil
	}
	return c.failThreadGroups("OUTCOME_UNCERTAIN", errThreadGroupUnconfirmed)
}
