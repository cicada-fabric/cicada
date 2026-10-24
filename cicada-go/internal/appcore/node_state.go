package appcore

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/appvault"
	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const (
	nodeStateNamespace        = "appcore.node.v1"
	nodeRecoveryNamespace     = "appcore.node-recovery.v1"
	nodeConfirmationNamespace = "appcore.node-confirmation.v1"
	nodeStateFormat           = "cicada.native-node-state.v1"
	maxNodeStateRecordBytes   = 1 << 20
)

// Each record is encrypted by the existing vault. Recovery and the immutable
// successful INITIAL confirmation have separate records so a legal 128 KiB
// original plus its nested receipt never exhausts a single vault-state slot.
// Recovery is persisted before applying its outcome; startup can idempotently
// finish either side of an interrupted record update.
type nodeAuthorityState struct {
	Format                string                       `json:"format"`
	Scope                 appvault.Scope               `json:"scope"`
	DeviceID              string                       `json:"device_id"`
	DeviceKeyID           string                       `json:"device_key_id"`
	OwnerKeyID            string                       `json:"owner_key_id"`
	PairTrust             *nodePairTrustState          `json:"pair_trust,omitempty"`
	Proposal              *nodeProposal                `json:"proposal,omitempty"`
	Grant                 *wire.AppNodeChallenge       `json:"grant,omitempty"`
	Pending               *nodeOperation               `json:"pending,omitempty"`
	Current               *wire.AppNodeResult          `json:"current,omitempty"`
	Context               *wire.AppNodeResult          `json:"context,omitempty"`
	HighestHead           uint64                       `json:"highest_head"`
	LatestGrantID         string                       `json:"latest_grant_id,omitempty"`
	ProvenanceID          string                       `json:"provenance_id,omitempty"`
	Client                nodeClientState              `json:"client"`
	LastSettlementDigest  string                       `json:"last_settlement_digest,omitempty"`
	LastSettlement        string                       `json:"last_settlement,omitempty"`
	SelfCancelledGrantID  string                       `json:"self_cancelled_grant_id,omitempty"`
	Diagnostics           *wire.AppNodeReconcileResult `json:"diagnostics,omitempty"`
	OwnerDirectory        *nodeOperation               `json:"owner_directory,omitempty"`
	OwnerDirectoryUnknown []ownerEndpointUnknownRecord `json:"owner_directory_unknown,omitempty"`
}

type nodeProposal struct {
	Prepare       wire.AppNodePrepare    `json:"prepare"`
	PreparePacket []byte                 `json:"prepare_packet"`
	Challenge     *wire.AppNodeChallenge `json:"challenge,omitempty"`
}

type nodeClientState struct {
	Initialized  bool   `json:"initialized"`
	Epoch        uint64 `json:"epoch"`
	NextRequest  uint64 `json:"next_request"`
	NextResponse uint64 `json:"next_response"`
	Conflict     bool   `json:"conflict"`
}

type nodeOperation struct {
	PairTrustRecovery        *nodePairTrustRecoveryRecord   `json:"pair_trust_recovery,omitempty"`
	Kind                     string                         `json:"kind"`
	Operation                string                         `json:"operation"`
	GrantID                  string                         `json:"grant_id"`
	Request                  []byte                         `json:"request"`
	Response                 []byte                         `json:"response,omitempty"`
	CreatedAt                string                         `json:"created_at"`
	ExpectedResponseSequence uint64                         `json:"expected_response_sequence,omitempty"`
	Settlement               string                         `json:"settlement,omitempty"`
	Applied                  bool                           `json:"applied"`
	GrantClaims              *e2ee.OwnerAppNodeGrantClaims  `json:"grant_claims,omitempty"`
	OwnerEndpointRead        *wire.OwnerEndpointReadRequest `json:"owner_endpoint_read,omitempty"`
}

type nodeConfirmationRecord struct {
	Scope     appvault.Scope           `json:"scope"`
	Operation nodeOperation            `json:"operation"`
	Binding   e2ee.OwnerAppNodeBinding `json:"binding"`
}

func (p *nodeOperation) unresolved() bool {
	return p != nil && !p.Applied
}

func (c *nativeController) hasNodePending() bool {
	return c.node.Pending.unresolved() || c.nodeRecovery != nil
}

func (c *nativeController) newNodeState() nodeAuthorityState {
	return nodeAuthorityState{Format: nodeStateFormat, Scope: cardScope(c.connection), DeviceID: c.state.DeviceID,
		DeviceKeyID: c.state.DeviceKeyID, OwnerKeyID: c.state.OwnerKeyID}
}

func (c *nativeController) persistNodeRecord(namespace string, version *uint64, value any) error {
	if c.vault == nil {
		c.storageFault = true
		return appvault.ErrClosed
	}
	var data []byte
	var err error
	if value != nil {
		data, err = json.Marshal(value)
		if err != nil || len(data) > maxNodeStateRecordBytes {
			c.storageFault = true
			return errors.New("encrypted Node state exceeds its bound")
		}
	}
	defer clear(data)
	v, err := c.vault.CompareAndSwapState(namespace, *version, data)
	if err != nil {
		c.storageFault = true
		return err
	}
	*version = v
	return nil
}

func (c *nativeController) restoreNodeReceipts() error {
	if c.nodeRecovery != nil && len(c.nodeRecovery.Response) != 0 {
		return c.applyNodeReconciliation()
	}
	if p := c.node.Pending; p.unresolved() && len(p.Response) != 0 {
		return c.applyNodeResponse(p, false)
	}
	return nil
}

func (c *nativeController) persistNode() error {
	return c.persistNodeRecord(nodeStateNamespace, &c.nodeVer, c.node)
}

func (c *nativeController) persistNodeRecovery() error {
	if t := c.node.PairTrust; t != nil && t.Recovery != nil {
		return ErrInvalidAction
	}
	var value any
	if c.nodeRecovery != nil {
		value = c.nodeRecovery
	}
	return c.persistNodeRecord(nodeRecoveryNamespace, &c.nodeRecoveryVer, value)
}

func (c *nativeController) persistNodeConfirmation() error {
	return c.persistNodeRecord(nodeConfirmationNamespace, &c.nodeConfirmationVer, c.nodeConfirmation)
}

func (c *nativeController) loadNodeRecord(namespace string, version *uint64, out any) (bool, error) {
	data, v, found, err := c.vault.LoadState(namespace)
	defer clear(data)
	if err != nil {
		return false, err
	}
	*version = v
	if !found || len(data) == 0 {
		return false, nil
	}
	if decodeStateJSON(data, out) != nil {
		return false, errors.New("invalid encrypted Node record")
	}
	return true, nil
}

func (c *nativeController) loadNodeState() error {
	c.node, c.nodeRecovery, c.nodeConfirmation = c.newNodeState(), nil, nil
	c.nodeChecked, c.nodeReadRequestID = false, ""
	found, err := c.loadNodeRecord(nodeStateNamespace, &c.nodeVer, &c.node)
	if err != nil {
		return err
	}
	if found && (c.node.Format != nodeStateFormat || c.node.Scope != cardScope(c.connection) || c.node.DeviceID != c.state.DeviceID ||
		c.node.DeviceKeyID != c.state.DeviceKeyID || c.node.OwnerKeyID != c.state.OwnerKeyID || c.node.HighestHead > math.MaxInt64) {
		return appvault.ErrScopeMismatch
	}
	if p := c.node.Proposal; p != nil {
		if p.Prepare.Context.Origin != c.connection.Origin || p.Prepare.Context.HubID != c.connection.HubID ||
			p.Prepare.Context.AccountID != c.connection.AccountID || p.Prepare.Context.OwnerID != c.connection.OwnerID || p.Prepare.Context.DeviceID != c.state.DeviceID ||
			c.validateNodeStoredPacket(&nodeOperation{Kind: wire.AppNodeOriginalAuthority, Operation: wire.OperationAppNodePrepare, Request: p.PreparePacket, CreatedAt: p.Prepare.Context.IssuedAt}) != nil {
			return appvault.ErrScopeMismatch
		}
		if p.Challenge != nil && !c.nodeScopeMatches(p.Challenge.Claims.Scope) {
			return appvault.ErrScopeMismatch
		}
	}
	if c.node.Grant != nil && (!c.nodeScopeMatches(c.node.Grant.Claims.Scope) || wire.ValidateAppNodeGrantClaims(c.node.Grant.Claims, c.hub, time.Time{}) != nil) {
		return appvault.ErrScopeMismatch
	}
	for _, result := range []*wire.AppNodeResult{c.node.Current, c.node.Context} {
		if result != nil && result.Authority.Scope.Version != 0 && !c.nodeScopeIdentityMatches(result.Authority.Scope) {
			return appvault.ErrScopeMismatch
		}
	}
	if c.validateNodeStoredPacket(c.node.Pending) != nil {
		return appvault.ErrScopeMismatch
	}
	if s := c.node.Client; s.Initialized && (s.Epoch == 0 || s.NextRequest == 0 || s.NextResponse == 0 || s.Epoch > math.MaxInt64) {
		return appvault.ErrScopeMismatch
	}
	var recovery nodeOperation
	if ok, err := c.loadNodeRecord(nodeRecoveryNamespace, &c.nodeRecoveryVer, &recovery); err != nil {
		return err
	} else if ok {
		if recovery.PairTrustRecovery != nil {
			if err := c.restoreNodePairRecovery(recovery); err != nil {
				return err
			}
		} else if recovery.Operation != wire.OperationAppNodeReconcile || c.validateNodeStoredPacket(&recovery) != nil {
			return appvault.ErrScopeMismatch
		} else {
			c.nodeRecovery = &recovery
		}
	}
	var confirmation nodeConfirmationRecord
	if ok, err := c.loadNodeRecord(nodeConfirmationNamespace, &c.nodeConfirmationVer, &confirmation); err != nil {
		return err
	} else if ok {
		if confirmation.Scope != c.node.Scope || confirmation.Operation.Kind != wire.AppNodeOriginalClient || len(confirmation.Operation.Response) == 0 ||
			c.validateNodeStoredPacket(&confirmation.Operation) != nil {
			return appvault.ErrScopeMismatch
		}
		c.nodeConfirmation = &confirmation
		device, err := c.device.E2EE()
		if err != nil || confirmation.Operation.GrantClaims == nil {
			return appvault.ErrScopeMismatch
		}
		verified, err := wire.OpenAppNodeConfirmationResponse(device, c.hub, *confirmation.Operation.GrantClaims, confirmation.Operation.Request, confirmation.Operation.Response, confirmation.Operation.ExpectedResponseSequence)
		if err != nil || !verified.OK || verified.Binding == nil || !reflect.DeepEqual(*verified.Binding, confirmation.Binding) {
			return appvault.ErrScopeMismatch
		}
	}
	if err := c.restoreOwnerDirectory(); err != nil {
		return err
	}
	if err := c.restoreNodePairTrust(); err != nil {
		return err
	}
	return c.restoreNodeReceipts()
}

func (c *nativeController) nodeScopeMatches(s e2ee.OwnerAppNodeScope) bool {
	return wire.ValidateAppNodeScope(s, c.hub) == nil && c.nodeScopeIdentityMatches(s)
}

func (c *nativeController) nodeScopeIdentityMatches(s e2ee.OwnerAppNodeScope) bool {
	fp, err := wire.HubFingerprint(c.hub)
	return err == nil && s.Version == 1 && s.HubID == c.hub.HubID && s.HubFingerprint == fp && c.owner != nil && c.device != nil && s.Origin == c.connection.Origin &&
		s.AccountID == c.connection.AccountID && s.OwnerID == c.connection.OwnerID && s.DeviceID == c.state.DeviceID &&
		reflect.DeepEqual(s.OwnerPublic, c.owner.Public()) && reflect.DeepEqual(s.DevicePublic, c.device.Public())
}

func (c *nativeController) validateNodeStoredPacket(p *nodeOperation) error {
	if p == nil {
		return nil
	}
	if p.PairTrustRecovery != nil {
		return wire.ErrInvalid
	}
	limit := wire.MaxAppNodeOriginalBytes
	if p.Operation == wire.OperationAppNodeReconcile {
		limit = wire.MaxPacketBytes
	}
	if len(p.Request) == 0 || len(p.Request) > limit || len(p.Response) > wire.MaxPacketBytes || parseExpiry(p.CreatedAt).IsZero() {
		return wire.ErrInvalid
	}
	var route clientwire.Route
	if p.Kind == wire.AppNodeOriginalAuthority {
		packet, err := wire.DecodePacket(p.Request)
		if err != nil || nodePacketHTTPPath(p.Operation) == "" || packet.Packet.Route.Operation != p.Operation ||
			c.device == nil || !reflect.DeepEqual(packet.SenderPublicIdentity, c.device.Public()) {
			return wire.ErrInvalid
		}
		route = packet.Packet.Route
	} else if p.Kind == wire.AppNodeOriginalClient {
		var packet clientwire.Packet
		if decodeStateJSON(p.Request, &packet) != nil || p.Operation != "nodes.confirm" || packet.Route.Operation != p.Operation || p.ExpectedResponseSequence == 0 {
			return wire.ErrInvalid
		}
		grantID, _, err := wire.ParseAppNodeBusinessOperationID(packet.Route.OperationID)
		if err != nil || grantID != p.GrantID {
			return wire.ErrInvalid
		}
		route = packet.Route
	} else {
		return wire.ErrInvalid
	}
	if route.Direction != clientwire.DirectionRequest || route.HubID != c.connection.HubID || route.OwnerID != c.connection.OwnerID ||
		route.DeviceID != c.state.DeviceID || route.SenderKeyID != c.state.DeviceKeyID || route.ReceiverKeyID != c.hub.Public.ID {
		return wire.ErrInvalid
	}
	if p.Operation == wire.OperationOwnerEndpointRead {
		return c.validateOwnerEndpointOperation(p)
	}
	if p.OwnerEndpointRead != nil {
		return wire.ErrInvalid
	}
	return nil
}

func (c *nativeController) clearNodeRuntime() {
	c.clearNodePairTrust()
	operations := []*nodeOperation{c.node.Pending, c.nodeRecovery, c.node.OwnerDirectory}
	for i := range c.node.OwnerDirectoryUnknown {
		operations = append(operations, &c.node.OwnerDirectoryUnknown[i].Original)
	}
	for _, p := range operations {
		if p != nil {
			clear(p.Request)
			clear(p.Response)
			if p.OwnerEndpointRead != nil {
				clear(p.OwnerEndpointRead.SessionToken)
				clear(p.OwnerEndpointRead.OwnerProof)
			}
		}
	}
	if p := c.node.Proposal; p != nil {
		clear(p.PreparePacket)
		clear(p.Prepare.OwnerIntent)
		clear(p.Prepare.SessionToken)
	}
	if p := c.nodeConfirmation; p != nil {
		clear(p.Operation.Request)
		clear(p.Operation.Response)
	}
	c.node, c.nodeRecovery, c.nodeConfirmation = nodeAuthorityState{}, nil, nil
	c.nodeVer, c.nodeRecoveryVer, c.nodeConfirmationVer = 0, 0, 0
	c.nodeAvailable, c.nodeChecked, c.nodeContextChecked, c.nodeDiscoveryTried = false, false, false, false
	c.nodeReadRequestID, c.nodeError = "", ""
	c.ownerEndpointResult, c.ownerEndpointAvailable, c.ownerEndpointError = nil, false, ""
}

func earlierNodeDeadline(values ...string) string {
	var earliest time.Time
	for _, value := range values {
		t := parseExpiry(value)
		if t.IsZero() {
			return ""
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	if earliest.IsZero() {
		return ""
	}
	return earliest.Format(time.RFC3339Nano)
}
