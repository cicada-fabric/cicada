package e2ee

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type observedPrivateOperations struct {
	identity            *Identity
	signs, decapsulates int
	sign                func([]byte) ([]byte, error)
	decapsulate         func([]byte) ([]byte, error)
}

func (o *observedPrivateOperations) Sign(message []byte) ([]byte, error) {
	o.signs++
	if o.sign != nil {
		return o.sign(message)
	}
	return o.identity.Sign(message)
}

func (o *observedPrivateOperations) MLKEMDecapsulate(ciphertext []byte) ([]byte, error) {
	o.decapsulates++
	if o.decapsulate != nil {
		return o.decapsulate(ciphertext)
	}
	return o.identity.MLKEMDecapsulate(ciphertext)
}

func TestPrivateOperationsKeepExistingEnvelopeInteroperability(t *testing.T) {
	sender, e := NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	recipient, e := NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	message, aad := []byte("synthetic callback transport"), []byte("synthetic scoped AAD")
	ops := &observedPrivateOperations{identity: sender}
	packet, e := SealWithPrivateOperations(sender.Public(), ops, recipient.Public(), message, aad, 7)
	if e != nil {
		t.Fatal(e)
	}
	opened, seq, e := Open(recipient, sender.Public(), packet, aad)
	if e != nil || seq != 7 || !bytes.Equal(opened, message) || ops.signs != 1 {
		t.Fatalf("external seal/ordinary open mismatch: %v", e)
	}
	packet, e = Seal(sender, recipient.Public(), message, aad, 8)
	if e != nil {
		t.Fatal(e)
	}
	var returnedSecret []byte
	receiver := &observedPrivateOperations{identity: recipient, decapsulate: func(ciphertext []byte) ([]byte, error) {
		returnedSecret, e = recipient.MLKEMDecapsulate(ciphertext)
		return returnedSecret, e
	}}
	opened, seq, e = OpenWithPrivateOperations(recipient.Public(), receiver, sender.Public(), packet, aad)
	if e != nil || seq != 8 || !bytes.Equal(opened, message) || receiver.decapsulates != 1 {
		t.Fatalf("ordinary seal/external open mismatch: %v", e)
	}
	if len(returnedSecret) != 32 || !bytes.Equal(returnedSecret, make([]byte, 32)) {
		t.Fatal("provider result retained the shared secret after opening")
	}
}

func TestPrivateOperationsRejectUntrustedEnvelopeBeforeDecapsulation(t *testing.T) {
	sender, e := NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	recipient, e := NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	packet, e := Seal(sender, recipient.Public(), []byte("synthetic"), nil, 1)
	if e != nil {
		t.Fatal(e)
	}
	var original Envelope
	if json.Unmarshal(packet, &original) != nil {
		t.Fatal("decode fixture")
	}
	for _, change := range []func(*Envelope){
		func(e *Envelope) { e.Version++ }, func(e *Envelope) { e.Algorithm = "synthetic wrong suite" },
		func(e *Envelope) { e.SenderID = "synthetic other sender" }, func(e *Envelope) { e.Nonce = nil },
		func(e *Envelope) { e.Signature = append([]byte(nil), e.Signature...); e.Signature[0] ^= 1 },
		func(e *Envelope) { e.KEMCiphertext = append([]byte(nil), e.KEMCiphertext...); e.KEMCiphertext[0] ^= 1 },
		func(e *Envelope) { e.Ciphertext = append([]byte(nil), e.Ciphertext...); e.Ciphertext[0] ^= 1 },
	} {
		changed := original
		change(&changed)
		data, _ := json.Marshal(changed)
		ops := &observedPrivateOperations{identity: recipient}
		if _, _, e = OpenWithPrivateOperations(recipient.Public(), ops, sender.Public(), data, nil); e == nil || ops.decapsulates != 0 || ops.signs != 0 {
			t.Fatal("untrusted envelope invoked private provider")
		}
	}
}

func TestPrivateOperationsValidateResultsAndSanitizeFailures(t *testing.T) {
	sender, e := NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	recipient, e := NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	other, e := NewIdentity()
	if e != nil {
		t.Fatal(e)
	}
	for _, sign := range []func([]byte) ([]byte, error){
		func([]byte) ([]byte, error) { return nil, errors.New("SENSITIVE_PROVIDER_DETAIL") },
		func([]byte) ([]byte, error) { return []byte("wrong size"), nil },
		other.Sign,
		func(message []byte) ([]byte, error) { message[0] ^= 1; return sender.Sign(message) },
	} {
		ops := &observedPrivateOperations{identity: sender, sign: sign}
		if _, e = SealWithPrivateOperations(sender.Public(), ops, recipient.Public(), []byte("synthetic"), nil, 1); e == nil || strings.Contains(e.Error(), "SENSITIVE_PROVIDER_DETAIL") {
			t.Fatal("invalid signer result accepted or private error leaked")
		}
	}
	packet, e := Seal(sender, recipient.Public(), []byte("synthetic"), nil, 1)
	if e != nil {
		t.Fatal(e)
	}
	for _, decapsulate := range []func([]byte) ([]byte, error){
		func([]byte) ([]byte, error) { return nil, errors.New("SENSITIVE_PROVIDER_DETAIL") },
		func([]byte) ([]byte, error) { return make([]byte, 31), nil },
		func([]byte) ([]byte, error) { return make([]byte, 33), nil },
		func([]byte) ([]byte, error) { return make([]byte, 32), nil },
		other.MLKEMDecapsulate,
	} {
		ops := &observedPrivateOperations{identity: recipient, decapsulate: decapsulate}
		if _, _, e = OpenWithPrivateOperations(recipient.Public(), ops, sender.Public(), packet, nil); e == nil || strings.Contains(e.Error(), "SENSITIVE_PROVIDER_DETAIL") {
			t.Fatal("invalid decapsulation result accepted or private error leaked")
		}
	}
}

// Compare the ordinary opaque-key path with the explicitly checked provider
// path. Key creation and frame preparation are outside timed loops.
func BenchmarkPrivateOperationsEnvelope(b *testing.B) {
	sender, err := NewIdentity()
	if err != nil {
		b.Fatal(err)
	}
	receiver, err := NewIdentity()
	if err != nil {
		b.Fatal(err)
	}
	senderPublic, receiverPublic := sender.Public(), receiver.Public()
	message, associated := bytes.Repeat([]byte("x"), 512), []byte("synthetic benchmark")
	packet, err := Seal(sender, receiverPublic, message, associated, 1)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("SealOpaque", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := Seal(sender, receiverPublic, message, associated, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("SealExternalChecked", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := SealWithPrivateOperations(senderPublic, sender, receiverPublic, message, associated, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("OpenOpaque", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, _, err := Open(receiver, senderPublic, packet, associated); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("OpenExternalChecked", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, _, err := OpenWithPrivateOperations(receiverPublic, receiver, senderPublic, packet, associated); err != nil {
				b.Fatal(err)
			}
		}
	})
}
