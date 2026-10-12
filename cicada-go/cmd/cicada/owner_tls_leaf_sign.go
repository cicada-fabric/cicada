package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
)

const ownerTLSLeafSignUsage = "usage: cicada owner tls-leaf-grant-sign --private FILE --claims FILE --expect-claims-sha256 SHA256 --expect-owner-id ID --expect-owner-key-id ID --expect-hub-id ID --expect-node-id ID --output FILE"

// The complete reserved claims are reviewed on the independent Owner signing
// machine. A CSR, pairing code or Hub supplied public key cannot supply approval.
// This process never opens the Hub Store or transmits an Owner private key.
func ownerTLSLeafGrantSignCommand(args []string, output io.Writer) error {
	f := flag.NewFlagSet("owner tls-leaf-grant-sign", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	private := f.String("private", "", "existing private Owner identity")
	claimsPath := f.String("claims", "", "complete reviewed reserved claims JSON")
	digest := f.String("expect-claims-sha256", "", "independently reviewed exact claims file SHA256")
	ownerID := f.String("expect-owner-id", "", "independently reviewed Owner ID")
	keyID := f.String("expect-owner-key-id", "", "independently pinned Owner key ID")
	hubID := f.String("expect-hub-id", "", "independently pinned Hub ID")
	nodeID := f.String("expect-node-id", "", "independently reviewed Node ID")
	destination := f.String("output", "", "new private canonical proof file")
	if f.Parse(args) != nil || len(f.Args()) != 0 || output == nil || *private == "" || *claimsPath == "" || *digest == "" || *ownerID == "" || *keyID == "" || *hubID == "" || *nodeID == "" || *destination == "" {
		return errors.New(ownerTLSLeafSignUsage)
	}
	secret, err := readOwnerNetworkKeyFile(*private, 32768, true)
	if err != nil {
		return err
	}
	defer clear(secret)
	identity, err := e2ee.UnmarshalIdentity(secret)
	if err != nil || identity.Public().ID != *keyID {
		return errors.New("Owner signing key differs from independently pinned identity")
	}
	data, err := readOwnerNetworkKeyFile(*claimsPath, e2ee.MaxNodeTLSProofBytes, false)
	if err != nil {
		return err
	}
	if e2ee.NodeTLSAuthorityDigest(data) != *digest {
		return errors.New("TLS claims differ from the reviewed exact file")
	}
	var claims e2ee.OwnerTLSLeafGrantClaims
	if decodeStrictBridgeJSON(data, &claims) != nil || e2ee.ValidateOwnerTLSLeafGrantClaims(claims) != nil || claims.OwnerID != *ownerID || claims.OwnerKeyID != *keyID || claims.HubID != *hubID || claims.NodeID != *nodeID {
		return errors.New("TLS grant scope differs from independently reviewed identities")
	}
	at := time.Now().UTC().Truncate(time.Second)
	issued, _ := time.Parse(time.RFC3339, claims.IssuedAt)
	expires, _ := time.Parse(time.RFC3339, claims.ExpiresAt)
	if at.Before(issued) || !at.Before(expires) {
		return errors.New("TLS reservation grant window is not current")
	}
	proof, err := e2ee.SignOwnerTLSLeafGrant(identity, claims)
	if err != nil {
		return err
	}
	if err := tlsProvisionWriteNew(*destination, proof); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		RequestID    string `json:"request_id"`
		ClaimsSHA256 string `json:"claims_sha256"`
		ProofSHA256  string `json:"proof_sha256"`
	}{claims.RequestID, *digest, e2ee.NodeTLSAuthorityDigest(proof)})
}
