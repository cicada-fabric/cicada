package nodewire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

func tlsCurrentFixture(t *testing.T) (*e2ee.Identity, *e2ee.Identity, Binding, TLSCurrentRequest, TLSCurrentStatus, time.Time) {
	t.Helper()
	node, hub, b, _ := testBinding(t)
	at := time.Now().UTC().Truncate(time.Second)
	q := TLSCurrentRequest{Nonce: bytes.Repeat([]byte{0x31}, 32), Origin: "https://hub.synthetic.invalid", CredentialDigest: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x52}, 32)), IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(TLSCurrentLifetime).Format(time.RFC3339)}
	hash := strings.Repeat("a", 64)
	c := e2ee.OwnerTLSLeafGrantClaims{Version: 1, RequestID: "synthetic-request", HubID: b.HubID, NodeID: b.NodeID, OwnerID: "synthetic-owner", OwnerKeyID: "synthetic-owner-key", OwnerKeyVersion: 1, ClientDeviceID: "synthetic-device", ClientDeviceVersion: 1, OwnerBindingID: b.BindingID, OwnerBindingVersion: b.BindingVersion, CredentialDigest: q.CredentialDigest, CredentialVersion: 1, NodeControlKeyID: b.NodeKey.ID, NodeControlKeyVersion: b.NodeKeyVersion, NodeControlKeyEpoch: b.NodeKeyEpoch, NodeControlBindingVersion: 1, HubControlKeyID: b.HubKey.ID, HubControlKeyVersion: b.HubKeyVersion, CSRDERHash: hash, SPKIDERHash: hash, IssuerSPKIHash: hash, IssuerDERHash: hash, RootDERHash: hash, IssuerGeneration: "synthetic-issuer", Role: "node", DNSName: "node.synthetic.invalid", Serial: "00000000000000000000000000000001", TLSEpoch: 1, NotBefore: at.Format(time.RFC3339), NotAfter: at.Add(time.Hour).Format(time.RFC3339), HubSPKIHash: hash, HubTrustAnchorDERHash: hash, HubPQOrigin: q.Origin, ApplicationOrigin: q.Origin, ApplicationProtocol: e2ee.NodeTLSApplicationProtocol, PQProfile: e2ee.NodeTLSPQProfile, IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(time.Hour).Format(time.RFC3339), Nonce: hash}
	// These bytes only exercise the sealed current-query domain. The runtime
	// independently verifies real Owner/ACK/activation and certificate material.
	public := []byte("visibly synthetic public material")
	s := TLSCurrentStatus{CurrentBinding: json.RawMessage(`{"synthetic":true}`), OwnerKeyVersion: 1, ClientDeviceVersion: 1, ReadAt: q.IssuedAt, ExpiresAt: q.ExpiresAt, CurrentAuthority: TLSCurrentAuthority{State: "ACTIVE", RowVersion: 5, ReservationVersion: 1, Claims: c, Grant: public, CSRPEM: public, IssuerChainPEM: public, TrustAnchorPEM: public, LeafCertificatePEM: public, LeafDERHash: hash, InstallAck: public, Activation: public}}
	return node, hub, b, q, s, at
}

func TestNodeTLSCurrentNonceRequestAndDomain(t *testing.T) {
	node, hub, b, q, s, at := tlsCurrentFixture(t)
	packet, err := SealTLSCurrentRequest(node, b, q, at)
	if err != nil {
		t.Fatal("seal synthetic fresh request", err)
	}
	opened, err := OpenTLSCurrentRequest(hub, b, packet, at)
	if err != nil || !bytes.Equal(opened.Nonce, q.Nonce) {
		t.Fatal("fresh request authentication")
	}
	if _, err = OpenRequest(hub, node.Public(), b, packet); err == nil {
		t.Fatal("current query accepted as ordinary RPC")
	}
	reply, err := SealTLSCurrentResponse(hub, b, q, packet, s, at)
	if err != nil {
		t.Fatal("seal synthetic current reply", err)
	}
	if _, err = OpenTLSCurrentResponse(node, b, q, packet, reply, at); err != nil {
		t.Fatal("open synthetic current reply", err)
	}
	for _, kind := range []string{"nonce", "origin", "credential", "request-bytes", "expired", "future", "binding"} {
		t.Run(kind, func(t *testing.T) {
			changed := q
			request := packet
			binding := b
			now := at
			switch kind {
			case "nonce":
				changed.Nonce = bytes.Repeat([]byte{0x32}, 32)
			case "origin":
				changed.Origin = "https://other.synthetic.invalid"
			case "credential":
				changed.CredentialDigest = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x53}, 32))
			case "request-bytes":
				request = append(append([]byte(nil), packet...), ' ')
			case "expired":
				now = at.Add(TLSCurrentLifetime)
			case "future":
				now = at.Add(-time.Second)
			case "binding":
				binding.NodeKeyEpoch++
			}
			if _, err := OpenTLSCurrentResponse(node, binding, changed, request, reply, now); err == nil {
				t.Fatal("stale or mismatched fresh reply accepted")
			}
		})
	}
}

func TestNodeTLSCurrentBoundsAndCurrentShape(t *testing.T) {
	node, hub, b, q, s, at := tlsCurrentFixture(t)
	if _, err := OpenTLSCurrentRequest(hub, b, make([]byte, MaxTLSCurrentPacketBytes+1), at); err == nil {
		t.Fatal("oversized query accepted")
	}
	for _, kind := range []string{"short-nonce", "noncanonical-time", "long-window", "noncurrent", "version", "missing-material"} {
		t.Run(kind, func(t *testing.T) {
			request := q
			status := s
			switch kind {
			case "short-nonce":
				request.Nonce = request.Nonce[:31]
			case "noncanonical-time":
				request.IssuedAt = at.Format("2006-01-02T15:04:05+00:00")
			case "long-window":
				request.ExpiresAt = at.Add(time.Minute).Format(time.RFC3339)
			case "noncurrent":
				status.CurrentAuthority.State = "INSTALLED"
			case "version":
				status.OwnerKeyVersion++
			case "missing-material":
				status.CurrentAuthority.CSRPEM = nil
			}
			packet, err := SealTLSCurrentRequest(node, b, request, at)
			if err == nil {
				_, err = SealTLSCurrentResponse(hub, b, request, packet, status, at)
			}
			if err == nil {
				t.Fatal("invalid fresh query/authority accepted")
			}
		})
	}
}
