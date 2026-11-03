package appcore

import "context"

// Arrange historical legacy states through private methods. Public enrollment
// now accepts only scoped codes; these fixtures remain storage/recovery controls.
func legacyFixtureDispatch(controller Controller, ctx context.Context, a Action) (err error) {
	c := controller.(*nativeController)
	defer func() {
		if err == nil {
			c.publish()
		}
	}()
	switch a.Kind {
	case ActionPreviewNode:
		return c.previewNode(ctx, a.NodeCode, false)
	case ActionReauthorizeNodeStatus:
		return c.previewNode(ctx, "", true)
	case ActionApproveNode:
		return c.approveNode(ctx, a)
	case ActionReviewNodePairing:
		return c.reviewNodePairing(ctx, a.DevicePairingCode)
	case ActionApproveNodePairing:
		return c.approveNodePairing(ctx, a.NodePairingReviewID, a.ConfirmNodePairing)
	case ActionRefreshNodePairing:
		if f := c.node.PairTrust; f != nil && (f.Stage == "LOOKUP" || f.Stage == "APPROVING") && c.nodePairTrustMayContinue() {
			return c.continueNodePairing(ctx)
		}
	}
	return c.Dispatch(ctx, a)
}

// Inspect historical consent eligibility separately from the current product's
// AvailableActions, which must never advertise a legacy grant or enrollment.
func legacyFixtureSnapshot(controller Controller) Snapshot {
	c := controller.(*nativeController)
	s := c.Snapshot()
	if c.nodeAccountReady() {
		if c.nodeCanStartInitial() {
			s.AvailableActions = append(s.AvailableActions, ActionPreviewNode)
		}
		if c.nodeProposalReviewable() {
			s.AvailableActions = append(s.AvailableActions, ActionApproveNode)
		}
		if c.nodeCanReauthorizeStatus() {
			s.AvailableActions = append(s.AvailableActions, ActionReauthorizeNodeStatus)
		}
		if c.nodePairingReviewable() {
			s.AvailableActions = append(s.AvailableActions, ActionApproveNodePairing)
		}
	}
	return s
}
