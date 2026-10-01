package store

import (
	"database/sql"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

type communicationLinkEndpointRole struct {
	endpointID         string
	principalID        string
	ownerID            string
	nodeID             string
	groupID            string
	bindingID          string
	bindingEpoch       uint64
	keyID              string
	membershipRevision int64
}

func communicationLinkAskRoles(link *CommunicationLink,
	manifest *CommunicationLinkKeyManifest, reverse bool) (communicationLinkEndpointRole, communicationLinkEndpointRole) {
	source := communicationLinkEndpointRole{
		endpointID: link.SourceEndpointID, principalID: link.SourcePrincipalID,
		ownerID: link.SourceOwnerID, nodeID: link.SourceNodeID, groupID: link.SourceGroupID,
		bindingID: manifest.Source.BindingID, bindingEpoch: manifest.Source.BindingEpoch,
		keyID:              manifest.Source.KeyID,
		membershipRevision: link.ScopeSnapshot.SourceMembershipRevision,
	}
	target := communicationLinkEndpointRole{
		endpointID: link.TargetEndpointID, principalID: link.TargetPrincipalID,
		ownerID: link.TargetOwnerID, nodeID: link.TargetNodeID, groupID: link.TargetGroupID,
		bindingID: manifest.Target.BindingID, bindingEpoch: manifest.Target.BindingEpoch,
		keyID:              manifest.Target.KeyID,
		membershipRevision: link.ScopeSnapshot.TargetMembershipRevision,
	}
	if reverse {
		return target, source
	}
	return source, target
}

func sealedLinkAskEndpointContext(link *CommunicationLink,
	manifest *CommunicationLinkKeyManifest, messageID, requestID, parentRequestID string,
	reverse bool) e2ee.EndpointMessageContext {
	return sealedLinkEndpointContext(link, manifest, messageID, "REQUEST", requestID, "", parentRequestID, reverse)
}

func sealedLinkEndpointContext(link *CommunicationLink, manifest *CommunicationLinkKeyManifest,
	messageID, kind, requestID, replyTo, parentRequestID string, reverse bool) e2ee.EndpointMessageContext {
	sender, receiver := communicationLinkAskRoles(link, manifest, reverse)
	return e2ee.EndpointMessageContext{
		MessageID: messageID, Kind: kind, RequestID: requestID, ReplyTo: replyTo,
		ParentRequestID:  parentRequestID,
		SenderEndpointID: sender.endpointID, SenderPrincipalID: sender.principalID,
		SenderOwnerID: sender.ownerID, SenderGroupID: sender.groupID,
		SenderMembershipRevision: sender.membershipRevision,
		SenderBindingEpoch:       sender.bindingEpoch, SenderKeyID: sender.keyID,
		ReceiverEndpointID: receiver.endpointID, ReceiverPrincipalID: receiver.principalID,
		ReceiverOwnerID: receiver.ownerID, ReceiverGroupID: receiver.groupID,
		ReceiverMembershipRevision: receiver.membershipRevision,
		ReceiverBindingEpoch:       receiver.bindingEpoch, ReceiverKeyID: receiver.keyID,
		LinkID: link.ID, LinkRevision: link.Version, TransportHubID: link.TransportHubID,
	}
}

func sealedLinkReplyEndpointContext(link *CommunicationLink,
	manifest *CommunicationLinkKeyManifest, request *FabricRequest,
	messageID string) e2ee.EndpointMessageContext {
	// A reply reverses the exact ASK direction. Link roles remain immutable;
	// this derives the reply route from the persisted request instead of a
	// caller-provided source/target selector.
	reverseAsk := request.SenderEndpointID == link.TargetEndpointID
	return sealedLinkEndpointContext(link, manifest, messageID, "REPLY", request.RequestID,
		request.MessageID, request.ParentRequestID, !reverseAsk)
}

// authorizeCommunicationLinkSealedAskTx chooses the only ask direction
// permitted by the live Node credential. Source Nodes retain the existing
// forward route; target Nodes can initiate only under the already signed
// bidirectional Link contract. No caller route fields or membership aliases
// can select the opposite direction.
func authorizeCommunicationLinkSealedAskTx(tx *sql.Tx, credentialDigest,
	linkID, dataScope string, at time.Time) (*CommunicationLink, *CommunicationLinkKeyManifest, bool, error) {
	return authorizeCommunicationLinkSealedActionTx(tx, credentialDigest, linkID, dataScope, "ask", at)
}

func authorizeCommunicationLinkSealedActionTx(tx *sql.Tx, credentialDigest,
	linkID, dataScope, action string, at time.Time) (*CommunicationLink, *CommunicationLinkKeyManifest, bool, error) {
	if action != "ask" && action != "send" {
		return nil, nil, false, ErrCommunicationLinkRelayDenied
	}
	callerNodeID, callerOwnerID, callerHubID, err := readActiveOwnerBoundNodeTx(tx, credentialDigest)
	if err != nil {
		return nil, nil, false, ErrCommunicationLinkRelayDenied
	}
	link, err := scanCommunicationLink(tx.QueryRow(`SELECT `+communicationLinkColumns+`
FROM communication_links_v2 WHERE id=?`, linkID))
	if err != nil || link == nil || link.State != CommunicationLinkProposed ||
		link.SourceOwnerID == link.TargetOwnerID || link.SourceNodeID == link.TargetNodeID ||
		link.TransportHubID == "" || callerHubID != link.TransportHubID ||
		(link.Direction != "forward" && link.Direction != "bidirectional") ||
		!containsWord(link.Actions, action) ||
		!containsWord(link.DataScopes, dataScope) {
		return nil, nil, false, ErrCommunicationLinkRelayDenied
	}
	reverse := false
	switch {
	case callerNodeID == link.SourceNodeID && callerOwnerID == link.SourceOwnerID:
		reverse = false
	case link.Direction == "bidirectional" && callerNodeID == link.TargetNodeID && callerOwnerID == link.TargetOwnerID:
		reverse = true
	default:
		return nil, nil, false, ErrCommunicationLinkRelayDenied
	}
	var configuredHubID string
	if err := tx.QueryRow(`SELECT hub_id FROM client_device_hub_config_v2 WHERE id=1`).Scan(&configuredHubID); err != nil ||
		configuredHubID == "" || configuredHubID != link.TransportHubID {
		return nil, nil, false, ErrCommunicationLinkRelayDenied
	}
	if err := validateCurrentCommunicationLinkScope(tx, link, at); err != nil ||
		requireActiveOwnerBoundNodeTx(tx, link.SourceNodeID, link.SourceOwnerID, configuredHubID) != nil ||
		requireActiveOwnerBoundNodeTx(tx, link.TargetNodeID, link.TargetOwnerID, configuredHubID) != nil {
		return nil, nil, false, ErrCommunicationLinkRelayDenied
	}
	manifest, err := readCommunicationLinkKeyManifest(tx, *link, at)
	if err != nil {
		return nil, nil, false, ErrCommunicationLinkRelayDenied
	}
	if _, err := readCurrentCommunicationLinkAuthorizationProof(tx, *link, *manifest,
		CommunicationLinkGrantSource, at); err != nil {
		return nil, nil, false, ErrCommunicationLinkRelayDenied
	}
	if _, err := readCurrentCommunicationLinkAuthorizationProof(tx, *link, *manifest,
		CommunicationLinkGrantTarget, at); err != nil {
		return nil, nil, false, ErrCommunicationLinkRelayDenied
	}
	if err := networkGuardCommunicationLinkDirectionTx(tx, link, reverse, at); err != nil {
		return nil, nil, false, ErrCommunicationLinkRelayDenied
	}
	return link, manifest, reverse, nil
}

func communicationLinkAskDirection(link *CommunicationLink, senderEndpointID, receiverEndpointID string) (bool, bool) {
	if link == nil {
		return false, false
	}
	if senderEndpointID == link.SourceEndpointID && receiverEndpointID == link.TargetEndpointID {
		return false, true
	}
	if senderEndpointID == link.TargetEndpointID && receiverEndpointID == link.SourceEndpointID &&
		link.Direction == "bidirectional" {
		return true, true
	}
	return false, false
}

func communicationLinkAskParentCompatible(parent, child *FabricRequest) bool {
	if parent == nil || child == nil || parent.ReceiverEndpointID != child.SenderEndpointID ||
		parent.ReceiverPrincipalID != child.SenderPrincipalID ||
		parent.ReceiverBindingID == "" || child.SenderBindingID == "" ||
		parent.ReceiverBindingEpoch == 0 || parent.ReceiverBindingID != child.SenderBindingID ||
		parent.ReceiverBindingEpoch != child.SenderBindingEpoch {
		return false
	}
	parentLink := strings.HasPrefix(parent.AuthorizationRef, communicationLinkAuthorizationRefPrefix)
	childLink := strings.HasPrefix(child.AuthorizationRef, communicationLinkAuthorizationRefPrefix)
	if childLink {
		if parentLink {
			// A separate Link remains independently authorized by its own guards;
			// ancestry itself never transfers either Link's consent.
			return true
		}
		return parent.SenderGroupID != "" && parent.SenderGroupID == parent.ReceiverGroupID &&
			parent.ReceiverGroupID == child.SenderGroupID
	}
	if parentLink {
		return child.SenderGroupID != "" && child.SenderGroupID == child.ReceiverGroupID &&
			parent.ReceiverGroupID == child.SenderGroupID
	}
	return false
}
