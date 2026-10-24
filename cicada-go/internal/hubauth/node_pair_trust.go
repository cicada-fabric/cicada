package hubauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodebinding"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func (s *Service) NodePairTrustDescriptor() (string, error) {
	if s == nil || !s.appNodeAuthority {
		return "", ErrAuthentication
	}
	text, err := s.db.HubNativeTLSDescriptor()
	if err != nil || text == "" {
		return "", ErrAuthentication
	}
	d, err := hubtransport.DecodeDescriptor(text)
	hub, e := s.HubIdentity()
	origin, oe := s.ExpectedOrigin()
	if err != nil || e != nil || oe != nil || hubtransport.ValidateDescriptor(d, s.requestTime()) != nil || !reflect.DeepEqual(d.Claims.Hub, hub) || d.Claims.Origin != origin || hubtransport.MatchNodeControl(d, hub.HubID, s.ids.NodeControl.Public(), 1, nodewire.IdentityFingerprint(s.ids.NodeControl.Public())) != nil {
		return "", ErrAuthentication
	}
	return text, nil
}
func (s *Service) NodePairTrustCapabilities() (wire.NodePairTrustCapabilities, error) {
	if _, err := s.NodePairTrustDescriptor(); err != nil {
		return wire.NodePairTrustCapabilities{}, err
	}
	return wire.NodePairTrustContractCapabilities(), nil
}

func (s *Service) openNodePairTrust(raw []byte, op string, hub wire.HubIdentity) (store.HubNodePairTrustInput, error) {
	body := wire.NewNodePairTrustRequestBody(op)
	if body == nil {
		return store.HubNodePairTrustInput{}, ErrAuthentication
	}
	var h wire.NodePairTrustPacket
	var err error
	if op == wire.OperationNodePairTrustReconcile {
		h, err = wire.OpenNodePairTrustRequest(s.ids.ClientControl, hub, raw, op, body, s.requestTime())
	} else {
		var historical wire.NodePairTrustHistoricalOriginal
		historical, err = wire.AuthenticateNodePairTrustOriginal(s.ids.ClientControl, hub, raw, body)
		h = historical.Header
		if h.Operation != op {
			err = ErrAuthentication
		}
	}
	if err != nil {
		return store.HubNodePairTrustInput{}, ErrAuthentication
	}
	value := reflect.ValueOf(body).Elem().Interface()
	in := store.HubNodePairTrustInput{Hub: hub, NodeControlPublic: s.ids.NodeControl.Public(), Header: h, Body: value, Packet: raw, Now: s.requestTime,
		Seal: func(result wire.NodePairTrustResult) ([]byte, error) {
			return wire.SealNodePairTrustResponse(s.ids.ClientControl, hub, raw, value, result)
		},
		OpenConfirmation: func(packet []byte, device e2ee.PublicIdentity) (store.HubAppNodeClientInput, error) {
			return s.openAppNodeClient(packet, hub, device)
		},
	}
	return in, nil
}

func clearNodePairBody(body any) {
	switch b := body.(type) {
	case wire.NodePairTrustOwnerLookup:
		clear(b.SessionToken)
	case wire.NodePairTrustOwnerPrepare:
		clear(b.SessionToken)
	case wire.NodePairTrustOwnerComplete:
		clear(b.SessionToken)
	case wire.NodePairTrustOwnerStatus:
		clear(b.SessionToken)
	case wire.NodePairTrustACK:
		clear(b.ACKNonce)
	}
}

func (s *Service) HandleNodePairTrust(ctx context.Context, operation string, raw []byte) ([]byte, error) {
	if s == nil || !s.appNodeAuthority || wire.NodePairTrustHTTPPath(operation) == "" || len(raw) == 0 || len(raw) > wire.MaxNodePairTrustReconcilePacketBytes {
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
	in, err := s.openNodePairTrust(raw, operation, hub)
	if err != nil {
		return nil, err
	}
	defer clearNodePairBody(in.Body)
	match := func(c wire.NodePairTrustContext) bool {
		return reflect.DeepEqual(c.Hub, hub) && c.Origin == d.Claims.Origin && c.DescriptorDigest == wire.NodePairTrustDescriptorDigest(text)
	}
	switch b := in.Body.(type) {
	case wire.NodePairTrustStart:
		if b.Origin != d.Claims.Origin || b.DescriptorDigest != wire.NodePairTrustDescriptorDigest(text) || !reflect.DeepEqual(b.HubNodeControlPublic, s.ids.NodeControl.Public()) || wire.ValidateNodePairTrustStartProof(s.ids.NodeControl, in.Header.SenderPublic, b) != nil {
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
	case wire.NodePairTrustExistingStart:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustCommit:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustACK:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustOwnerPrepare:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustOwnerComplete:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustOwnerStatus:
		if !match(b.Context) {
			return nil, ErrAuthentication
		}
	case wire.NodePairTrustReconcile:
		var original wire.NodePairTrustPacket
		if json.Unmarshal(b.OriginalPacket, &original) != nil || original.Operation == wire.OperationNodePairTrustReconcile {
			return nil, ErrAuthentication
		}
		old, err := s.openNodePairTrust(b.OriginalPacket, original.Operation, hub)
		if err != nil {
			return nil, err
		}
		defer clearNodePairBody(old.Body)
		in.Original = &old
	}
	packet, err := s.db.ProcessHubNodePairTrust(in)
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

func NodePairTrustOperationForPath(path string) string {
	for _, op := range wire.NodePairTrustContractCapabilities().Operations {
		if wire.NodePairTrustHTTPPath(op) == path {
			return op
		}
	}
	return ""
}

// Header-only admission rejects credentials before reading a pairing body.
func NodePairTrustCredentialsAbsent(authorization, cookie string) bool {
	return strings.TrimSpace(authorization) == "" && cookie == ""
}
