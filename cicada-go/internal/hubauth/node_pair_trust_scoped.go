package hubauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodebinding"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func (s *Service) openNodePairTrustScoped(raw []byte, op string, hub wire.HubIdentity) (store.HubNodePairTrustScopedInput, error) {
	body := wire.NewNodePairTrustScopedRequestBody(op)
	if body == nil {
		return store.HubNodePairTrustScopedInput{}, ErrAuthentication
	}
	var h wire.NodePairTrustScopedPacket
	var err error
	if op == wire.OperationNodePairTrustScopedReconcile {
		h, err = wire.OpenNodePairTrustScopedRequest(s.ids.ClientControl, hub, raw, op, body, s.requestTime())
	} else {
		var historical wire.NodePairTrustScopedHistoricalOriginal
		historical, err = wire.AuthenticateNodePairTrustScopedOriginal(s.ids.ClientControl, hub, raw, body)
		h = historical.Header
		if h.Operation != op {
			err = ErrAuthentication
		}
	}
	if err != nil {
		return store.HubNodePairTrustScopedInput{}, ErrAuthentication
	}
	value := reflect.ValueOf(body).Elem().Interface()
	in := store.HubNodePairTrustScopedInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), Header: h, Body: value, Packet: raw, Now: s.requestTime,
		Seal: func(result wire.NodePairTrustScopedResult) ([]byte, error) {
			return wire.SealNodePairTrustScopedResponse(s.ids.ClientControl, hub, raw, value, result)
		},
		OpenConfirmation: func(packet []byte, device e2ee.PublicIdentity) (store.HubAppNodeClientInput, error) {
			return s.openAppNodeScopedClient(packet, hub, device)
		},
	}
	return in, nil
}

func clearNodePairScopedBody(body any) {
	switch b := body.(type) {
	case wire.NodePairTrustScopedOwnerLookup:
		clear(b.SessionToken)
	case wire.NodePairTrustScopedOwnerPrepare:
		clear(b.SessionToken)
	case wire.NodePairTrustScopedOwnerComplete:
		clear(b.SessionToken)
	case wire.NodePairTrustScopedOwnerStatus:
		clear(b.SessionToken)
	case wire.NodePairTrustScopedACK:
		clear(b.ACKNonce)
	}
}

func (s *Service) HandleNodePairTrustScoped(ctx context.Context, operation string, raw []byte) ([]byte, error) {
	if !s.ScopedNodeAuthorityEnabled() || wire.NodePairTrustScopedHTTPPath(operation) == "" || len(raw) == 0 || len(raw) > wire.MaxNodePairTrustScopedReconcilePacketBytes {
		return nil, ErrAuthentication
	}
	release, err := s.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	text, err := s.NodePairTrustDescriptor()
	if err != nil {
		return nil, err
	}
	d, err := hubtransport.DecodeDescriptor(text)
	if err != nil {
		return nil, ErrAuthentication
	}
	hub := d.Claims.Hub
	in, err := s.openNodePairTrustScoped(raw, operation, hub)
	if err != nil {
		return nil, err
	}
	defer clearNodePairScopedBody(in.Body)
	match := func(c wire.NodePairTrustScopedContext) bool {
		return reflect.DeepEqual(c.Hub, hub) && c.Origin == d.Claims.Origin && c.DescriptorDigest == wire.NodePairTrustScopedDescriptorDigest(text)
	}
	switch b := in.Body.(type) {
	case wire.NodePairTrustScopedStart:
		if b.Origin != d.Claims.Origin || b.DescriptorDigest != wire.NodePairTrustScopedDescriptorDigest(text) || !reflect.DeepEqual(b.HubNodeControlPublic, s.ids.NodeControl.Public()) || wire.ValidateNodePairTrustScopedStartProof(s.ids.NodeControl, in.Header.SenderPublic, b) != nil {
			return nil, ErrAuthentication
		}
		const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
		var random [12]byte
		if _, err = rand.Read(random[:]); err != nil {
			return nil, ErrAuthentication
		}
		var code [12]byte
		for i := range code {
			code[i] = alphabet[int(random[i])%len(alphabet)]
		}
		in.Selector = string(code[:4]) + "-" + string(code[4:8]) + "-" + string(code[8:])
		expiry, err := time.Parse(time.RFC3339Nano, b.ExpiresAt)
		if err != nil {
			return nil, ErrAuthentication
		}
		in.Start = &store.NodeControlKeyRequestInput{Mode: store.NodeControlPairingInitial, NodeID: b.NodeID, NodeName: b.NodeName, CredentialDigest: b.CredentialDigest, CodeDigest: nodebinding.CodeDigest(hub.HubID, string(code[:])), NodePublicIdentity: in.Header.SenderPublic, NodeFingerprint: nodewire.IdentityFingerprint(in.Header.SenderPublic), ProofPacket: b.PairingProof, HubPublicIdentity: s.ids.NodeControl.Public(), HubKeyVersion: 1, HubFingerprint: nodewire.IdentityFingerprint(s.ids.NodeControl.Public()), ExpiresAt: expiry}
	case wire.NodePairTrustScopedExistingStart:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustScopedCommit:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustScopedACK:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustScopedOwnerPrepare:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustScopedOwnerComplete:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustScopedOwnerStatus:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustScopedReconcile:
		var original wire.NodePairTrustScopedPacket
		if json.Unmarshal(b.OriginalPacket, &original) != nil || original.Operation == wire.OperationNodePairTrustScopedReconcile {
			return nil, ErrAuthentication
		}
		old, err := s.openNodePairTrustScoped(b.OriginalPacket, original.Operation, hub)
		if err != nil {
			return nil, err
		}
		defer clearNodePairScopedBody(old.Body)
		in.Original = &old
	}
	packet, err := s.db.ProcessHubNodePairTrustScoped(in)
	if errors.Is(err, store.ErrNodePairTrustCapacity) {
		return nil, ErrBusy
	}
	if errors.Is(err, store.ErrNodePairTrustACKRequired) {
		return nil, ErrNodePairTrustACKRequired
	}
	if err != nil {
		return nil, ErrAuthentication
	}
	return packet, nil
}

func NodePairTrustScopedOperationForPath(path string) string {
	for _, op := range wire.NodePairTrustScopedContractCapabilities().Operations {
		if wire.NodePairTrustScopedHTTPPath(op) == path {
			return op
		}
	}
	return ""
}

func (s *Service) NodePairTrustScopedCapabilities() (wire.NodePairTrustScopedCapabilities, error) {
	if s == nil || !s.appNodeAuthority {
		return wire.NodePairTrustScopedCapabilities{}, ErrAuthentication
	}
	caps := wire.NodePairTrustScopedContractCapabilities()
	if s.ScopedNodeAuthorityEnabled() {
		if _, err := s.NodePairTrustDescriptor(); err != nil {
			return wire.NodePairTrustScopedCapabilities{}, err
		}
		caps.Available = true
	}
	return caps, nil
}
