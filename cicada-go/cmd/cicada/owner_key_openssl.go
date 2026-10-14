package main

import (
	"encoding/asn1"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/publicidentity"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const ownerKeyFromOpenSSLUsage = "usage: cicada owner-key from-openssl --kem-public SPKI_PEM --signing-public SPKI_PEM --output NEW_PUBLIC_JSON"

// NIST algorithm identifiers, also defined by OpenSSL 3.5.9 objects.txt:
// https://github.com/openssl/openssl/blob/openssl-3.5.9/crypto/objects/objects.txt
var ownerMLKEM768OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 2}
var ownerMLDSA65OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}

type ownerPublicKeyInfo struct {
	Algorithm struct {
		OID        asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	PublicKey asn1.BitString
}

func parseOwnerOpenSSLPublic(data []byte, oid asn1.ObjectIdentifier, size int) ([]byte, error) {
	if oid.Equal(ownerMLKEM768OID) && size == mlkem768.PublicKeySize {
		return publicidentity.ParseOpenSSLSPKIPublic(data, publicidentity.MLKEM768)
	}
	if oid.Equal(ownerMLDSA65OID) && size == mldsa65.PublicKeySize {
		return publicidentity.ParseOpenSSLSPKIPublic(data, publicidentity.MLDSA65)
	}
	return nil, errors.New("unsupported OpenSSL SPKI algorithm or key size")
}

func ownerKeyFromOpenSSLCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("owner-key from-openssl", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	kemPath := flags.String("kem-public", "", "OpenSSL ML-KEM-768 SPKI public PEM")
	signingPath := flags.String("signing-public", "", "OpenSSL ML-DSA-65 SPKI public PEM")
	outputPath := flags.String("output", "", "new Cicada public identity JSON")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || output == nil ||
		*kemPath == "" || *signingPath == "" || *outputPath == "" {
		return errors.New(ownerKeyFromOpenSSLUsage)
	}
	kemPEM, err := readOfflineOwnerPublicFile(*kemPath, 16*1024)
	if err != nil {
		return err
	}
	signingPEM, err := readOfflineOwnerPublicFile(*signingPath, 16*1024)
	if err != nil {
		return err
	}
	public, err := publicidentity.ParseOpenSSLIdentity(kemPEM, signingPEM)
	if err != nil {
		return fmt.Errorf("OpenSSL public keys do not form a valid Cicada identity: %w", err)
	}
	data, err := json.Marshal(public)
	if err != nil {
		return err
	}
	if err := writeOfflineOwnerFile(*outputPath, append(data, '\n'), 0o644); err != nil {
		return err
	}
	fingerprint, err := e2ee.OwnerDevicePublicKeyFingerprint(public)
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(struct {
		KeyID                     string `json:"key_id"`
		PublicIdentityFingerprint string `json:"public_identity_fingerprint"`
		PublicPath                string `json:"public_path"`
	}{public.ID, fingerprint, *outputPath})
}

// Only public inputs use this reader. The encrypted private PEM is opened
// exclusively by OpenSSL; this process never reads or converts it.
func readOfflineOwnerPublicFile(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > max {
		return nil, errors.New("public input must be a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || len(data) == 0 || int64(len(data)) > max {
		return nil, errors.New("public input must be a bounded regular file")
	}
	return data, nil
}

func readOfflineOwnerIdentity(path string) (e2ee.PublicIdentity, error) {
	data, err := readOfflineOwnerPublicFile(path, 16*1024)
	if err != nil {
		return e2ee.PublicIdentity{}, err
	}
	var public e2ee.PublicIdentity
	if err := decodeStrictBridgeJSON(data, &public); err != nil {
		return e2ee.PublicIdentity{}, errors.New("public identity JSON is invalid")
	}
	if err := e2ee.ValidatePublicIdentity(public); err != nil {
		return e2ee.PublicIdentity{}, errors.New("public identity keys or ID are invalid")
	}
	return public, nil
}

func writeOfflineOwnerFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create offline Owner output without overwrite: %w", err)
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("could not persist offline Owner output")
	}
	return nil
}
