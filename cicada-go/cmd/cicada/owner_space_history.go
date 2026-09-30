package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const ownerSpaceUsage = "usage: cicada owner space-history-sign --private FILE --manifest FILE --expect-owner-id ID --expect-record-id ID --expect-recipient-endpoint-id ID"

// The Owner's private key is read only by this offline command. Neither the
// MCP process nor the Node bridge ever receives it.
func ownerSpaceCommand(args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "space-history-sign" || output == nil {
		return errors.New(ownerSpaceUsage)
	}
	flags := flag.NewFlagSet("owner space-history-sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privatePath := flags.String("private", "", "existing 0600 Owner private key")
	manifestPath := flags.String("manifest", "", "reviewed Group Space history manifest JSON")
	expectOwner := flags.String("expect-owner-id", "", "expected Owner ID")
	expectRecord := flags.String("expect-record-id", "", "expected original record ID")
	expectRecipient := flags.String("expect-recipient-endpoint-id", "", "expected recipient Endpoint ID")
	if flags.Parse(args[1:]) != nil || len(flags.Args()) != 0 ||
		*privatePath == "" || *manifestPath == "" || *expectOwner == "" ||
		*expectRecord == "" || *expectRecipient == "" {
		return errors.New(ownerSpaceUsage)
	}
	privateInfo, err := os.Lstat(*privatePath)
	if err != nil || !privateInfo.Mode().IsRegular() || privateInfo.Mode().Perm() != 0o600 {
		return errors.New("Owner private key must be an existing regular 0600 file")
	}
	private, err := os.ReadFile(*privatePath)
	if err != nil || len(private) == 0 || len(private) > 32768 {
		return errors.New("Owner private key has invalid size")
	}
	identity, err := e2ee.UnmarshalIdentity(private)
	if err != nil {
		return errors.New("Owner private key is invalid")
	}
	manifestInfo, err := os.Lstat(*manifestPath)
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() <= 0 || manifestInfo.Size() > 32768 {
		return errors.New("history manifest must be a bounded regular file")
	}
	data, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	var envelope struct {
		Grant        e2ee.GroupSpaceHistoryGrant `json:"grant"`
		HistoryGrant e2ee.GroupSpaceHistoryGrant `json:"history_grant"`
	}
	if err := decodeStrictBridgeJSON(data, &envelope); err != nil {
		// A raw Grant file is also accepted for scripted review.
		if err := decodeStrictBridgeJSON(data, &envelope.Grant); err != nil {
			return errors.New("history manifest JSON is invalid")
		}
	}
	grant := envelope.Grant
	if grant.ManifestID == "" {
		grant = envelope.HistoryGrant
	}
	if grant.OwnerID != strings.TrimSpace(*expectOwner) ||
		grant.RecordID != strings.TrimSpace(*expectRecord) ||
		grant.RecipientEndpointID != strings.TrimSpace(*expectRecipient) ||
		grant.OwnerKeyID != identity.Public().ID || grant.IssuedAt != "" ||
		grant.Nonce != "" || len(grant.Signature) != 0 {
		return errors.New("history manifest differs from the reviewed Owner decision")
	}
	proof, err := identity.SignGroupSpaceHistoryGrant(grant)
	if err != nil {
		return err
	}
	// The output can be passed verbatim as owner_proof to the MCP share tool;
	// the signed ManifestID is parsed by Node, with no request ID to retype.
	return json.NewEncoder(output).Encode(struct {
		OwnerProof string `json:"owner_proof"`
	}{OwnerProof: base64.StdEncoding.EncodeToString(bytes.TrimSpace(proof))})
}
