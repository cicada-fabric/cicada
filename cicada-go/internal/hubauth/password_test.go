package hubauth

import (
	"bytes"
	"strings"
	"testing"
)

func TestAccountPasswordPolicyAndFixedVerifier(t *testing.T) {
	for _, pw := range []string{"short", "1234567890", "password123", "syntheticuser2026", strings.Repeat("x", 1025), string([]byte{0xff})} {
		if ValidatePassword("syntheticuser", "Synthetic Owner", pw) == nil {
			t.Fatal("weak/invalid password accepted")
		}
	}
	for _, pw := range []string{"abcdefghij", "这是十个以上的测试密码文字", "long spaces are allowed"} {
		if err := ValidatePassword("syntheticuser", "Synthetic Owner", pw); err != nil {
			t.Fatal(err)
		}
	}
	salt := bytes.Repeat([]byte{0x53}, PasswordSaltSize)
	v, err := DerivePassword("public synthetic password", salt)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 32 || !CheckPassword("public synthetic password", salt, v) || CheckPassword("changed synthetic password", salt, v) {
		t.Fatal("verifier mismatch")
	}
	other, err := DerivePassword("public synthetic password", bytes.Repeat([]byte{0x54}, 32))
	if err != nil || bytes.Equal(v, other) {
		t.Fatal("salt not independent")
	}
	if _, err := DerivePassword("public synthetic password", nil); err == nil {
		t.Fatal("bad salt accepted")
	}
}
func BenchmarkAccountPasswordProfile(b *testing.B) {
	salt := bytes.Repeat([]byte{0x53}, 32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		v, err := DerivePassword("public synthetic password", salt)
		if err != nil {
			b.Fatal(err)
		}
		clear(v)
	}
}
