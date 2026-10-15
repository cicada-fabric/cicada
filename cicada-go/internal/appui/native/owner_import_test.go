package native

import "testing"

func TestOwnerPEMHeaderFilterMatchesUnencryptedPKCS8Parser(t *testing.T) {
	if !validPEMType("PRIVATE KEY", true) || !validPEMType("PUBLIC KEY", false) {
		t.Fatal("PKCS#8/SPKI PEM headers were rejected")
	}
	for _, blockType := range []string{
		"ENCRYPTED PRIVATE KEY",
		"ML-KEM-768 PRIVATE KEY",
		"ML-DSA-65 PRIVATE KEY",
		"RSA PRIVATE KEY",
		"EC PRIVATE KEY",
		"PUBLIC KEY",
	} {
		if validPEMType(blockType, true) {
			t.Errorf("private PEM filter accepts unsupported type %q", blockType)
		}
	}
	for _, blockType := range []string{
		"PRIVATE KEY",
		"ENCRYPTED PRIVATE KEY",
		"RSA PUBLIC KEY",
	} {
		if validPEMType(blockType, false) {
			t.Errorf("public PEM filter accepts unsupported type %q", blockType)
		}
	}
}
