package appcore

import (
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func (c *nativeController) openNodeAuthorityResponse(p *nodeOperation, raw []byte) (any, error) {
	if p.Operation == wire.OperationOwnerEndpointRead {
		return c.openOwnerEndpointResponse(p, raw)
	}
	device, err := c.device.E2EE()
	if err != nil {
		return nil, err
	}
	if p.Operation == wire.OperationAppNodePrepare {
		var challenge wire.AppNodeChallenge
		if wire.OpenClientResponse(device, c.hub, p.Request, raw, &challenge) == nil {
			proposal := c.node.Proposal
			if proposal == nil || !reflect.DeepEqual(proposal.PreparePacket, p.Request) {
				return nil, wire.ErrInvalid
			}
			intent, err := e2ee.VerifyOwnerAppNodePreview(c.owner.Public(), proposal.Prepare.OwnerIntent, time.Time{})
			if err != nil || wire.ValidateAppNodePreparedResponse(challenge, intent, proposal.Prepare.OwnerIntent, p.Request, c.hub, time.Time{}) != nil ||
				!c.nodeScopeMatches(challenge.Claims.Scope) || (challenge.Claims.Profile == wire.AppNodeProfileStatus && !c.nodeExistingTargetMatches(challenge.Claims)) {
				return nil, wire.ErrInvalid
			}
			return &challenge, nil
		}
	}
	var result wire.AppNodeResult
	if wire.OpenClientResponse(device, c.hub, p.Request, raw, &result) != nil || !c.nodeScopeIdentityMatches(result.Authority.Scope) {
		return nil, wire.ErrInvalid
	}
	if result.ErrorCode == "COUNTER_CONFLICT" {
		return nil, errors.New("Client counter conflict remains unresolved")
	}
	if result.State == wire.AppNodeReadExpired && p.Operation != wire.OperationAppNodeStatus {
		return nil, wire.ErrInvalid
	}
	return &result, nil
}

func (c *nativeController) verifyNodeResponse(p *nodeOperation, raw []byte) error {
	if p.Kind == wire.AppNodeOriginalClient {
		if p.GrantClaims == nil {
			return wire.ErrInvalid
		}
		device, err := c.device.E2EE()
		if err != nil {
			return err
		}
		_, err = wire.OpenAppNodeConfirmationResponse(device, c.hub, *p.GrantClaims, p.Request, raw, p.ExpectedResponseSequence)
		return err
	}
	_, err := c.openNodeAuthorityResponse(p, raw)
	return err
}

func (c *nativeController) applyNodeResponse(p *nodeOperation, fresh bool) error {
	if p == nil || len(p.Response) == 0 {
		return ErrInvalidAction
	}
	if p.Applied {
		return nil
	}
	if p.Kind == wire.AppNodeOriginalClient {
		return c.applyNodeConfirmation(p)
	}
	value, err := c.openNodeAuthorityResponse(p, p.Response)
	if err != nil {
		return err
	}
	switch result := value.(type) {
	case *wire.OwnerEndpointReadResult:
		return c.applyOwnerEndpointResponse(p, result)
	case *wire.AppNodeChallenge:
		c.node.Proposal.Challenge = result
		c.nodeError = ""
	case *wire.AppNodeResult:
		freshResult := fresh && p.Operation == wire.OperationAppNodeStatus && result.State == wire.AppNodeCompleted && result.ErrorCode == "" &&
			result.RequestID == c.nodeReadRequestID && c.freshObservation(result.ObservedAt)
		if freshResult {
			if err := c.observeNodeEpochs(result.Authority.Scope.AccountEpoch, result.Authority.Scope.DeviceEpoch); err != nil {
				return err
			}
		}
		isFreshRead := freshResult && result.Authority.RootState == wire.RootActiveState && !result.Authority.LoginRequired
		if err := c.acceptNodeCounters(*result, isFreshRead); err != nil {
			c.node.Client.Conflict, c.nodeContextChecked, isFreshRead = true, false, false
			c.nodeError = "APP_NODE_COUNTER_CONFLICT"
		}
		a := result.Authority
		if a.CurrentHeadVersion >= c.node.HighestHead {
			c.node.HighestHead = a.CurrentHeadVersion
			c.node.LatestGrantID = a.LatestGrantID
			if c.nodeConfirmation != nil && a.ConfirmationProvenanceID != "" {
				c.node.ProvenanceID = a.ConfirmationProvenanceID
			}
		}
		if p.Operation == wire.OperationAppNodeStatus && p.GrantID == "" {
			c.node.Context = result
			c.nodeContextChecked = isFreshRead && !a.LoginRequired && c.nodeScopeMatches(a.Scope) && c.nodeAccountReady() &&
				a.Scope.AccountEpoch == c.session.AccountEpoch && a.Scope.DeviceEpoch == c.session.DeviceEpoch && a.Scope.AccountSessionExpiresAt == c.session.ExpiresAt
		} else if a.GrantID == p.GrantID && a.CurrentHeadVersion >= c.node.HighestHead {
			c.node.Current = result
			c.nodeChecked = isFreshRead && c.node.Grant != nil && a.GrantID == c.node.Grant.Claims.GrantID &&
				wire.ValidateAppNodeLiveResult(*result, c.node.Grant.Claims, c.hub, c.cfg.Now().UTC()) == nil
		}
		if result.ErrorCode != "" {
			c.nodeError = "APP_NODE_" + result.ErrorCode
		} else if c.node.Client.Conflict {
			c.nodeError = "APP_NODE_COUNTER_CONFLICT"
		} else {
			c.nodeError = ""
		}
		if p.Operation == wire.OperationAppNodePrepare && result.State == wire.AppNodeRejectedFenced {
			c.node.Proposal = nil
		}
		if p.Operation == wire.OperationAppNodeComplete && result.ErrorCode == "" && a.State == wire.AppNodeActive {
			proposal := c.node.Proposal
			if proposal == nil || proposal.Challenge == nil || proposal.Challenge.Claims.GrantID != p.GrantID || !reflect.DeepEqual(a.Scope, proposal.Challenge.Claims.Scope) {
				return wire.ErrInvalid
			}
			grant := *proposal.Challenge
			c.node.Grant = &grant
			if grant.Claims.Profile == wire.AppNodeProfileStatus {
				c.node.Proposal = nil
			}
			c.nodeChecked = false
		}
		if p.Operation == wire.OperationAppNodeCancel && result.ErrorCode == "" && a.State == wire.AppNodeCancelled {
			if c.node.Proposal != nil && c.node.Proposal.Challenge != nil && c.node.Proposal.Challenge.Claims.GrantID == p.GrantID {
				c.node.Proposal = nil
			}
			if c.node.Grant != nil && c.node.Grant.Claims.GrantID == p.GrantID {
				c.node.SelfCancelledGrantID = p.GrantID
			}
		}
		if freshResult && c.node.Proposal != nil && c.node.Proposal.Challenge != nil && c.node.Proposal.Challenge.Claims.GrantID == a.GrantID &&
			(a.State == wire.AppNodeExpired || a.State == wire.AppNodeCancelled || a.State == wire.AppNodeRevoked || a.State == wire.AppNodeSessionEnded) {
			c.node.Proposal = nil
		}
	default:
		return wire.ErrInvalid
	}
	p.Applied = true
	return c.persistNode()
}

func (c *nativeController) observeNodeEpochs(account, device uint64) error {
	oldAccount, oldDevice := c.state.ObservedAccountEpoch, c.state.ObservedDeviceEpoch
	c.observeEpochs(account, device)
	if c.session != nil && (c.session.AccountEpoch < c.state.ObservedAccountEpoch || c.session.DeviceEpoch < c.state.ObservedDeviceEpoch) {
		if err := c.clearPersistedSession(); err != nil {
			return err
		}
		c.clearSession()
		c.state.AccountState = AccountStateLoginRequired
	}
	if oldAccount != c.state.ObservedAccountEpoch || oldDevice != c.state.ObservedDeviceEpoch {
		return c.persistState()
	}
	return nil
}

func (c *nativeController) applyNodeConfirmation(p *nodeOperation) error {
	if p.GrantClaims == nil {
		return wire.ErrInvalid
	}
	device, err := c.device.E2EE()
	if err != nil {
		return err
	}
	reply, err := wire.OpenAppNodeConfirmationResponse(device, c.hub, *p.GrantClaims, p.Request, p.Response, p.ExpectedResponseSequence)
	if err != nil {
		return err
	}
	var packet clientwire.Packet
	if json.Unmarshal(p.Request, &packet) != nil {
		return wire.ErrInvalid
	}
	// A crash may leave the receipt durable before counter advancement. An
	// already applied receipt is idempotent; it cannot advance the slot twice.
	client := c.node.Client
	if !client.Initialized || client.Epoch != packet.Route.SessionEpoch {
		return wire.ErrInvalid
	}
	apply := client.NextRequest == packet.Route.Sequence && client.NextResponse == p.ExpectedResponseSequence
	already := client.NextRequest == packet.Route.Sequence+1 && client.NextResponse == p.ExpectedResponseSequence+1
	if !apply && !already {
		return errors.New("saved Client receipt cannot skip counters")
	}
	if reply.OK {
		if reply.Binding == nil {
			return wire.ErrInvalid
		}
		if c.nodeConfirmation != nil && !reflect.DeepEqual(c.nodeConfirmation.Binding, *reply.Binding) {
			return wire.ErrInvalid
		}
		c.nodeConfirmation = &nodeConfirmationRecord{Scope: c.node.Scope, Operation: *p, Binding: *reply.Binding}
		if err := c.persistNodeConfirmation(); err != nil {
			return err
		}
		c.node.Proposal = nil
		c.nodeError = ""
	} else {
		c.nodeError = "APP_NODE_CONFIRM_REJECTED"
	}
	if apply {
		c.node.Client.NextRequest++
		c.node.Client.NextResponse++
	}
	p.Applied = true
	c.nodeChecked, c.nodeReadRequestID = false, ""
	return c.persistNode()
}
