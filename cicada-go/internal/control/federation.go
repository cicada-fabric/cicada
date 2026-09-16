package control

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// FederationReceipt is safe to return through an untrusted relay: it reports
// durable receipt without returning decrypted peer content.
type FederationReceipt struct {
	TransportID string `json:"transport_id"`
	MessageID   string `json:"message_id"`
	SenderID    string `json:"sender_id"`
	RecipientID string `json:"recipient_id"`
	Sequence    uint64 `json:"sequence"`
	Status      string `json:"status"`
	Duplicate   bool   `json:"duplicate"`
}

// ReceiveFederatedPeerMessage maps transport identity IDs to the receiver's
// local Contact ID, authenticates/decrypts the envelope, and atomically stores
// it. The returned receipt intentionally contains no plaintext.
func (c *Control) ReceiveFederatedPeerMessage(transportID, senderID, recipientID string, claimedSequence uint64, envelope, aad []byte) (*FederationReceipt, error) {
	transportID = strings.TrimSpace(transportID)
	senderID = strings.TrimSpace(senderID)
	recipientID = strings.TrimSpace(recipientID)
	if transportID == "" || senderID == "" || recipientID == "" {
		return nil, errors.New("transport_id, sender_id, and recipient_id are required")
	}
	local := c.Identity()
	if local.ID == "" || recipientID != local.ID {
		return nil, errors.New("federation message recipient does not match this Control")
	}
	aadEncoded := base64.RawStdEncoding.EncodeToString(aad)
	existing, err := c.store.GetPeerMessageByTransportID(senderID, transportID)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		if existing.RecipientID != recipientID || existing.Sequence != claimedSequence || existing.AAD != aadEncoded {
			return nil, errors.New("peer transport id was reused with different routing")
		}
		return &FederationReceipt{
			TransportID: transportID, MessageID: existing.ID, SenderID: senderID,
			RecipientID: recipientID, Sequence: existing.Sequence, Status: "received", Duplicate: true,
		}, nil
	}
	contact, err := c.store.GetContactByRemoteID(senderID)
	if err != nil {
		return nil, err
	}
	if contact == nil {
		return nil, os.ErrNotExist
	}
	if contact.Identity.ID != senderID {
		return nil, errors.New("federation sender identity mismatch")
	}
	if contact.Status != "trusted" {
		return nil, fmt.Errorf("contact is not trusted: %s", contact.Status)
	}
	if _, permissionErr := c.CheckPermission("contact", contact.ID, "peer.receive", ""); permissionErr != nil {
		return nil, permissionErr
	}
	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	_, sequence, err := c.openPeerEnvelope(contact, envelope, aad)
	if err != nil {
		return nil, err
	}
	if claimedSequence == 0 || claimedSequence != sequence {
		return nil, errors.New("federation sequence does not match authenticated envelope")
	}
	stored, created, err := c.store.AcceptInboundPeerMessage(store.PeerMessage{
		TransportID: transportID, ContactID: contact.ID, Direction: "inbound",
		SenderID: senderID, RecipientID: recipientID, Sequence: sequence,
		Envelope: envelope, AAD: aadEncoded, Status: "received",
	})
	if err != nil {
		return nil, err
	}
	if created {
		c.notify("", "peer.message", "P2", "New peer message", "An encrypted message was received from "+contact.Label+".")
	}
	return &FederationReceipt{
		TransportID: transportID, MessageID: stored.ID, SenderID: senderID,
		RecipientID: recipientID, Sequence: sequence, Status: "received", Duplicate: !created,
	}, nil
}
