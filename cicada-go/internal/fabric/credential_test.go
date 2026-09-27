package fabric

import "testing"

func TestSessionCredentialStoredAsDigest(t *testing.T) {
	token, digest, err := NewSessionCredential()
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || digest == "" || token == digest {
		t.Fatalf("credential was not separated from its digest")
	}
	if err := ValidateSessionCredential(token, digest); err != nil {
		t.Fatalf("validate issued credential: %v", err)
	}
	if err := ValidateSessionCredential(token+"x", digest); err == nil {
		t.Fatal("altered credential was accepted")
	}
}

func TestSessionCredentialAuthorizationSchemeIsExplicit(t *testing.T) {
	token, _, err := NewSessionCredential()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := SessionCredentialFromAuthorization("CicadaSession " + token)
	if err != nil || parsed != token {
		t.Fatalf("parse credential: token=%q err=%v", parsed, err)
	}
	for _, value := range []string{"Bearer " + token, token, "CicadaSession"} {
		if _, err := SessionCredentialFromAuthorization(value); err == nil {
			t.Fatalf("accepted invalid authorization value %q", value)
		}
	}
}

func TestNodeCredentialAuthorizationSchemeIsSeparate(t *testing.T) {
	token, digest, err := NewNodeCredential()
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || digest == "" || token == digest {
		t.Fatalf("node credential was not generated safely")
	}
	parsed, err := NodeCredentialFromAuthorization("CicadaNode " + token)
	if err != nil || parsed != token {
		t.Fatalf("node credential authorization failed: parsed=%q err=%v", parsed, err)
	}
	if _, err := NodeCredentialFromAuthorization("Bearer " + token); err == nil {
		t.Fatal("management bearer scheme authenticated as a Node")
	}
}
