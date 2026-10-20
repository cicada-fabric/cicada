package apppaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUserRootPrecedenceAndNoCreation(t *testing.T) {
	parent := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(parent, 0700); err != nil {
			t.Fatal(err)
		}
	}
	home := filepath.Join(parent, "home")
	environment := filepath.Join(parent, "environment")
	explicit := filepath.Join(parent, "chosen")
	for _, tc := range []struct{ explicit, environment, want string }{
		{"", "", filepath.Join(home, ".cicada")},
		{"", environment, environment},
		{explicit, environment, explicit},
	} {
		got, err := resolveUserRoot(tc.explicit, tc.environment, home)
		if err != nil || got != tc.want {
			t.Fatalf("root=%q err=%v want=%q", got, err, tc.want)
		}
		if _, err := os.Lstat(got); !os.IsNotExist(err) {
			t.Fatalf("resolver created or changed a directory: %v", err)
		}
	}
}

func TestUserRootRejectsAliasesAndDoesNotFallBackFromInvalidChoice(t *testing.T) {
	parent := t.TempDir()
	for _, invalid := range []string{"relative", "~/.cicada", " " + parent, parent + " ", filepath.Join(parent, "x") + string(filepath.Separator) + "..", parent + "\nchild", string([]byte{0xff})} {
		if got, err := resolveUserRoot(invalid, parent, parent); err == nil || got != "" {
			t.Fatalf("invalid root %q accepted as %q", invalid, got)
		}
	}
	if got, err := resolveUserRoot("", "relative", parent); err == nil || got != "" {
		t.Fatal("invalid explicit environment fell back to another identity location")
	}
}

func TestUserRootRefusesLinkedOrUnprotectedLocations(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes/symlinks; Windows ACL runtime is a separate native gate")
	}
	parent := t.TempDir()
	private := filepath.Join(parent, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(parent, "linked")
	if err := os.Symlink(private, linked); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{linked, filepath.Join(linked, "child")} {
		if _, err := resolveUserRoot(p, "", parent); err == nil {
			t.Fatal("linked root accepted")
		}
	}
	shared := filepath.Join(parent, "shared")
	if err := os.Mkdir(shared, 0777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0777); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{shared, filepath.Join(shared, "child")} {
		if _, err := resolveUserRoot(p, "", parent); err == nil {
			t.Fatal("other-user writable location accepted")
		}
	}
}
